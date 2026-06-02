There exists a remotely exploitable Denial of Service vulnerability in Nginx HTTP/2 HPACK implementation. Three compounding weaknesses allow an unauthenticated attacker to exhaust an Nginx worker's memory against any HTTP/2 endpoint — including one that returns only 404 errors:

1. **HPACK Indexed Reference Bomb (~70:1 memory amplification)** — a single dynamic table entry referenced 32,000 times per request costs 1 byte per reference on the wire but allocates ~59 bytes of server pool memory. Each stream consumes ~2.2 MB from ~33 KB of wire data. Pool block overhead brings the measured ratio to **~70:1**.
2. **HTTP/2 Window Stall** — by sending `SETTINGS` with `INITIAL_WINDOW_SIZE=0`, the attacker prevents the server from sending response DATA frames (HEADERS frames are not flow-controlled). Request pools are held while the response body remains unsent, and periodic 1-byte `WINDOW_UPDATE` drips reset the `send_timeout` timer, holding memory indefinitely.
3. **Complete Flood Detection Blindness** — the HPACK bomb traffic consists entirely of valid HPACK-encoded request headers. The overhead ratio is 1.001:1, far below the 8:1 flood detection threshold. The attack is architecturally invisible to the built-in flood check.

This issue has a wide impact, affecting all Nginx deployments with HTTP/2 enabled. No downloadable content is required — any reachable endpoint (including non-existent paths returning 404) is sufficient.

50 connections sending 196 MB of HPACK bomb headers consumed **~14 GB** of server memory in under 7 seconds. The connections were never disconnected, no flood check triggered, and memory could be held via window stalls.

**Attachments**: [Demo Video](https://drive.google.com/file/d/1w1qjUh2tF3GqGJzBzNsmBbqsm_em277N/view?usp=sharing), [PoC Artifacts](https://github.com/user-attachments/files/26475219/poc_hpack.zip)

(Note that the exact math may not match across run but estimated values should be roughly correct)

---

## Table of Contents

1. [Vulnerability Findings](#vulnerability-findings)
2. [Amplification Factors](#amplification-factors)
3. [Constraints and Mitigating Factors](#constraints-and-mitigating-factors)
4. [Effective Memory Bounds Per Connection](#effective-memory-bounds-per-connection)
5. [Attack Scenarios](#attack-scenarios)
6. [Reproduction](#reproduction)
7. [Recommended Code Fixes](#recommended-code-fixes)
8. [References](#references)

---

## 1. Vulnerability Findings

### 1.1 HPACK Indexed Reference Memory Amplification

#### Background

In HTTP/2, HPACK (RFC 7541) allows a client to insert entries into a dynamic table and later reference them by index. Each indexed reference is a single byte on the wire, but the server must allocate fresh copies of the name and value for every reference. There is no limit on the **number** of headers per request — only a cumulative byte size limit (`large_client_header_buffers`, default 32 KB).

#### Root Cause

When a client references an HPACK dynamic table entry, `ngx_http_v2_get_indexed_header()` allocates fresh copies of both the name and value from the per-request pool (`ngx_http_v2_table.c`):

```c
p = ngx_pnalloc(h2c->state.pool, entry->name.len + 1);  // name copy
h2c->state.header.name.data = p;
// ... copy from circular buffer ...

p = ngx_pnalloc(h2c->state.pool, entry->value.len + 1);  // value copy
h2c->state.header.value.data = p;
```

Each decoded header is then pushed into the request's header list as a `ngx_table_elt_t` (56 bytes) via `ngx_list_push()` (`ngx_http_v2.c`):

```c
h = ngx_list_push(&r->headers_in.headers);  // 56 bytes per header, no count limit
```

The only limit on header count is `header_limit` (`ngx_http_v2.c`), which deducts `name.len + value.len` per header:

```c
h2c->state.header_limit = cscf->large_client_header_buffers.size
                          * cscf->large_client_header_buffers.num;
// default: 4 × 8192 = 32768 bytes

len = header->name.len + header->value.len;
if (len > h2c->state.header_limit) {
    // reject
}
h2c->state.header_limit -= len;
```

With a 1-byte name and 0-byte value, each reference costs only 1 byte of the 32 KB budget, allowing **32,000 headers per request** — each allocating ~59 bytes of server memory from 1 byte on the wire.

### 1.2 HTTP/2 Window Stall (Indefinite Resource Hold)

#### Background

In HTTP/2, DATA frames are subject to flow control via per-stream and per-connection windows. HEADERS frames are not flow-controlled. The client controls the initial stream window size via `SETTINGS_INITIAL_WINDOW_SIZE`.

#### Root Cause

When a stream has queued output frames, `ngx_http_v2_close_stream()` defers cleanup (`ngx_http_v2.c`):

```c
if (stream->queued) {
    fc->error = 1;
    fc->write->handler = ngx_http_v2_retry_close_stream_handler;
    fc->read->handler = ngx_http_v2_retry_close_stream_handler;
    return;  // pool NOT destroyed
}
```

When the server generates a response, the HEADERS frame is sent immediately (not flow-controlled), but the DATA frame cannot be sent because `stream->send_window = 0`. The body filter detects this (`ngx_http_v2_filter_module.c`):

```c
if (stream->send_window <= 0) {
    stream->exhausted = 1;
    return NGX_DECLINED;
}
```

The body data remains buffered. `ngx_http_writer()` (`ngx_http_request.c`) sees unsent data and sets `send_timeout` (default 60 seconds):

```c
if (r->buffered || r->postponed || (r == r->main && c->buffered)) {
    ngx_add_timer(wev, clcf->send_timeout);
}
```

When the attacker sends a 1-byte `WINDOW_UPDATE`, the stream's write handler is triggered via `ngx_http_v2_adjust_windows()`:

```c
stream->send_window += delta;   // 0 + 1 = 1

if (stream->send_window > 0 && stream->exhausted) {
    stream->exhausted = 0;
    wev->handler(wev);           // triggers ngx_http_writer
}
```

`ngx_http_writer` retries the body filter, sends 1 byte of response data, and re-sets `send_timeout`. The attacker repeats every ~50 seconds, holding the pool indefinitely. The hold duration is bounded only by the response body size (one byte consumed per drip). A default 404 body (~150 bytes) provides ~2.3 hours of hold per connection.

### 1.3 Flood Detection Blindness

#### The Flood Check

Nginx limits protocol overhead via (`ngx_http_v2.c`):

```c
h2c->total_bytes += n;

if (h2c->total_bytes / 8 > h2c->payload_bytes + 1048576) {
    ngx_log_error(NGX_LOG_INFO, c->log, 0, "http2 flood detected");
    ngx_http_v2_finalize_connection(h2c, NGX_HTTP_V2_NO_ERROR);
}
```

#### Why It Doesn't Trigger

The HPACK bomb consists entirely of valid HEADERS frames. The raw wire bytes are the request payload itself:

- `total_bytes` ≈ 4 MB (128 streams × 33 KB)
- `payload_bytes` ≈ 4 MB (each request's `request_length` is added at `ngx_http_v2_run_request`)

```
Check: 4,200,000 / 8  >  4,194,304 + 1,048,576?
       525,000         >  5,242,880?
       NO → passes
```

The overhead ratio is 1.001:1. The flood check is architecturally incapable of detecting this attack because it cannot distinguish between "legitimate large headers" and "HPACK bomb headers."

---

## 2. Amplification Factors

### Per-Header Memory Breakdown

For each indexed reference to a 1-byte-name, 0-byte-value dynamic table entry:

| Allocation | Size | Pool |
|-----------|------|------|
| Name copy (`ngx_pnalloc`) | 2 bytes | `state.pool` |
| Value copy (`ngx_pnalloc`) | 1 byte | `state.pool` |
| `ngx_table_elt_t` (`ngx_list_push`) | 56 bytes | `r->pool` |
| **Total per reference** | **~59 bytes** | |

### Per-Stream

| Component | System Memory |
|-----------|---------------|
| `state.pool`: 32,000 × 3 bytes + pool block overhead | **~106 KB** |
| `r->pool`: 32,000 `ngx_table_elt_t` + list parts, in 4 KB pool blocks | **~2,140 KB** |
| `r->pool`: request struct, variables, ctx, buffers | **~8 KB** |
| **Total per stream** | **~2.2 MB** |

### Amplification Ratios

| Ratio | Theoretical | Measured |
|-------|-------------|----------|
| Wire → server memory (per reference) | 1 byte → 59 bytes = 59:1 | — |
| Wire → server memory (per stream) | 33 KB → 2.2 MB = 68:1 | — |
| Wire → server memory (per connection) | 4 MB → 284 MB = 71:1 | **4 MB → 284 MB** |
| 15 connections → worker RSS | 59 MB → 4.2 GB | **59 MB → 4.2 GB** |
| 50 connections → worker RSS | 196 MB → 14.2 GB | **196 MB → 14.0 GB** |

### glibc Allocator Retention (Permanent RSS Inflation)

When nginx destroys request pools via `ngx_destroy_pool()`, it calls `free()` on each 4 KB pool block. However, these blocks are allocated via `brk()`/`sbrk()` (below glibc's 128 KB `M_MMAP_THRESHOLD`), and glibc's `ptmalloc` retains them in its arena free lists rather than returning memory to the OS. The `brk()` pointer can only be lowered from the **top** of the heap — any live allocation above the freed blocks (glibc metadata, nginx's persistent `recv_buffer`, etc.) pins everything below.

**Measured behavior:**
- 5 connections → 1.41 GB RSS → all connections closed → RSS stays at **1.13 GB** permanently
- Subsequent requests reuse the freed chunks (no RSS growth) but the OS sees the inflated RSS
- Only worker restart reclaims the memory; `nginx -s reload` does NOT help (same worker PIDs)

This means the attack has a **fire-and-forget** property: a single burst permanently degrades the worker even without maintaining connections.

---

## 3. Constraints and Mitigating Factors

| Constraint | Default Value | Effect on Attack |
|---|---|---|
| `large_client_header_buffers` | 4 × 8 KB = 32 KB | Limits total decoded header bytes → max ~32,000 headers |
| `http2_max_concurrent_streams` | 128 | Max 128 streams per connection |
| `send_timeout` | 60 seconds | Governs timeout between drips; reset by each WINDOW_UPDATE |
| `new_streams` per read event | 256 | 128 accepted + 128 refused (refused don't allocate `r->pool`) |
| Flood detection ratio | `total_bytes/8 > payload_bytes + 1MB` | **Does not trigger** — attack IS payload |
| Frame allocation cap | 10,000 | Irrelevant — bomb uses HEADERS frames, not output frames |
| HPACK dynamic table size | 4,096 bytes | One 33-byte entry sufficient for the bomb |
| INITIAL_WINDOW_SIZE=0 | Valid per RFC 7540 §6.5.2 | nginx accepts it (only rejects > 2^31-1) |

---

## 4. Effective Memory Bounds Per Connection

With default configuration (32 KB `header_limit`, 128 `concurrent_streams`):

```
Per stream:     ~32,000 headers × 59 bytes × 1.17 overhead ≈ 2.2 MB
Per connection: 128 streams × 2.2 MB                       ≈ 284 MB
```

Hold duration per connection (with WINDOW_UPDATE drip at 50-second intervals):

| Response Type | Body Size | Hold Time |
|---|---|---|
| Default 404 page | ~150 bytes | ~2.3 hours |
| Custom error page | ~1 KB | ~15 hours |
| Small static file (4 KB) | 4,096 bytes | ~62 hours |

Drip bandwidth during hold: 129 × 13 bytes per 50 seconds ≈ **34 bytes/sec per connection**.

---

## 5. Attack Scenarios

The most devastating variant uses the HTTP/2 Window Stall. The attacker establishes all TLS connections in parallel while the server is idle, then simultaneously fires 128 HPACK bomb streams per connection and drip-feeds 1-byte `WINDOW_UPDATE` frames to hold memory indefinitely.

No downloadable content is required. Any HTTP/2 endpoint — even returning 404 — is sufficient.

| Connections | Upload (burst) | Server Memory | Sustained BW (hold) |
|---|---|---|---|
| 1 | 4 MB | **285 MB** | 34 bytes/sec |
| 5 | 20 MB | **1.4 GB** | 170 bytes/sec |
| 15 | 60 MB | **4.2 GB** | 510 bytes/sec |
| 50 | 196 MB | **14.0 GB** | 1.7 KB/sec |
| 120 | 480 MB | **33.6 GB** | 4 KB/sec |

Using 50 connections, an attacker consumed **14 GB** of a single nginx worker's memory with a **196 MB burst upload completed in ~7 seconds**. The attack requires only a standard laptop on a broadband connection.

### Attack Steps

1. **Establish connections (parallel):** Open N TCP connections with TLS + ALPN `h2`. All connections are established in parallel while the server is idle — this avoids the CPU bottleneck that would block TLS handshakes if bombs were sent simultaneously.
2. **Send SETTINGS:** On each connection, send `SETTINGS` with `INITIAL_WINDOW_SIZE=0`. The server's `h2c->init_window` is set to 0; new streams cannot send DATA.
3. **Blast bombs (parallel):** Simultaneously send 128 HEADERS frames per connection (stream IDs 1, 3, 5, ..., 255), each with `END_STREAM | END_HEADERS`. Each header block contains:
   - 4 mandatory pseudo-headers via static table references (4 bytes).
   - 1 literal-with-incremental-indexing insert: name `"a"`, value `""` (4 bytes).
   - ~32,000 indexed references to dynamic entry 62 (`0xBE` × 32,000).
4. **Server processes:** The server decodes all requests, generating ~2.2 MB of pool memory per stream. Response HEADERS frames are sent (not flow-controlled). Response DATA frames cannot be sent (`send_window = 0`). Body data is buffered; `send_timeout` is set.
5. **Drip (optional):** Every ~50 seconds, send a 1-byte `WINDOW_UPDATE` for each stream and for the connection. This lets the server send 1 byte of response body, resetting `send_timeout`. Cost: 129 × 13 = 1,677 bytes per connection per drip.
6. **Respond to PINGs** to keep TCP connections healthy.
7. **Alternatively (fire-and-forget):** Skip the drip phase entirely. After `send_timeout` (60s), nginx closes the streams and destroys the pools — but glibc retains the RSS permanently. The worker is degraded until restart.

## 6. Reproduction

### 6.1 Environment

| Component | Version / Detail |
|---|---|
| nginx | 1.29.7 (official Docker image `nginx:latest`) |
| Container | Docker, `--memory=16g`, single worker process |
| Attacker tool | `/usr/bin/python3`, zero dependencies (`poc_hpack/hpack_bomb.py`) |
| Measurement | `poc_hpack/monitor_rss.py` — RSS sampling inside container |
| Host | Linux 6.18, localhost (TCP) |

Nginx config with simple HTTP serving, HTTP/2 enabled, no extra modules, all defaults:

```
worker_processes 1;
error_log /var/log/nginx/error.log info;

events {
    worker_connections 512;
}

http {
    server {
        listen 443 ssl http2;

        ssl_certificate     /etc/nginx/server.crt;
        ssl_certificate_key /etc/nginx/server.key;
        ssl_protocols       TLSv1.2 TLSv1.3;

        root /srv;

        location / {
            try_files $uri $uri/ =404;
        }
    }
}
```

### 6.2 Quick Reproduction

```bash
cd poc_hpack/

# Build image (uses official nginx:latest)
./run.sh build

# Start the container (16 GB memory cap)
./run.sh start

# Check memory usage of nginx worker with htop, e.g.:
htop -p $(pgrep -d ',' 'nginx')                                     

# Run the attack
./run.sh attack50 # or ./run.sh attack15 if you want smaller attack scenario

```

---

## 7. Recommended Code Fixes

### Fix 1 (Preferred): Count-Based Header Limit

Add an explicit limit on the **number** of headers per request, independent of cumulative byte size. This directly neutralizes the HPACK bomb:

```c
// In ngx_http_v2_state_process_header():

if (++h2c->state.header_count > h2scf->max_headers_per_request) {
    ngx_log_error(NGX_LOG_INFO, h2c->connection->log, 0,
                  "client sent too many headers");
    return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
}
```

### Fix 2 (Defence-in-Depth): Limit Decoded-to-Wire Ratio

Track the ratio of decoded header bytes to wire bytes and reject requests where HPACK compression yields excessive expansion:

```c
// Track wire bytes consumed by header block
h2c->state.header_wire_bytes += consumed;

// After header block is complete:
if (h2c->state.header_wire_bytes * 10 < total_decoded_bytes) {
    // Decoded size > 10× wire size — likely HPACK bomb
    return ngx_http_v2_connection_error(h2c, NGX_HTTP_V2_ENHANCE_YOUR_CALM);
}
```

This directly detects the amplification pattern without restricting legitimate use.

### Fix 3 (Defence-in-Depth): Minimum INITIAL_WINDOW_SIZE

Enforce a minimum `INITIAL_WINDOW_SIZE` (e.g., 1024 bytes) to prevent pure window stall attacks. While this doesn't fix the amplification, it forces the server to send response data and reclaim stream resources more quickly:

```c
case NGX_HTTP_V2_INIT_WINDOW_SIZE_SETTING:
    if (value > NGX_HTTP_V2_MAX_WINDOW) {
        return ngx_http_v2_connection_error(h2c,
                                            NGX_HTTP_V2_FLOW_CTRL_ERROR);
    }
    if (value < 1024) {
        value = 1024;  // floor
    }
    window_delta = value - h2c->init_window;
    break;
```

## 8. References

- [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) — HPACK: Header Compression for HTTP/2
- [RFC 7540 §6.5.2](https://www.rfc-editor.org/rfc/rfc7540#section-6.5.2) — `SETTINGS_INITIAL_WINDOW_SIZE`
- [RFC 7540 §6.9](https://www.rfc-editor.org/rfc/rfc7540#section-6.9) — Flow Control
