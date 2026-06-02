# HTTP/2 Bomb

Companion repo for the blog post [HTTP/2 Bomb](blog.md).

A remote denial-of-service against HTTP/2 servers that pairs an HPACK indexed-reference bomb with a flow-control window stall. One byte on the wire becomes one full header allocation on the server, repeated thousands of times per request, and a zero-byte `INITIAL_WINDOW_SIZE` keeps the server from ever freeing any of it.

## Per-server PoCs

Each directory is self-contained: build the target, start it under a memory cap, run the bomb, watch RSS.

| Target | Variant | Amplification | Directory |
|---|---|---|---|
| Envoy 1.37.2 | fat `cookie` crumbs | ~5,700:1 | [`envoy/`](envoy) |
| Apache httpd 2.4.67 | empty `cookie` crumbs | ~4,000:1 | [`httpd/`](httpd) |
| nginx 1.29.7 | tiny `a:` header | ~70:1 | [`nginx/`](nginx) |
| Microsoft IIS (Windows Server 2025) | tiny header, 900 refs | ~68:1 | [`microsoft-iis/`](microsoft-iis) |
| Cloudflare Pingora 0.8.0 | tiny `a:` header | ~62:1 | [`pingora/`](pingora) |

Please don't point these at infrastructure you don't own.

## Disclosure

- nginx: fixed in 1.29.8 via the [`max_headers` directive](https://github.com/nginx/nginx/commit/365694160a85229a7cb006738de9260d49ff5fa2).
- Apache httpd: fixed in mod_http2 v2.0.41 via [cookie accounting against `LimitRequestFields`](https://github.com/apache/httpd/commit/47d3100b252dc6668a9e46ae885242be9eeca9cd).
- Microsoft IIS, Envoy, Cloudflare Pingora: reported May 2026, fix status unknown at time of writing.

## Notes on the artifacts

The per-server write-ups and PoCs in this directory are AI-generated and kept as-is, as a historical artifact of what AI vulnerability research looked like in 2026. The exploits are verified by us. They work.
