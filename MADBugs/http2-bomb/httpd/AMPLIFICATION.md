# Apache httpd mod_http2 Amplification Notes

This repro targets the HTTP/2 cookie crumbling path in `mod_http2`.

## Why `cookie` Is Different

Default `LimitRequestFields 100` blocks a generic repeated `a:` HPACK indexed-reference bomb. Repeated `cookie:` fields are special-cased: HTTP/2 cookie crumbs are merged into a single `Cookie` header with `"; "`.

In `h2_req_add_header()`, the first cookie creates the table entry. Later cookie crumbs hit the existing-cookie branch and call:

```c
apr_table_setn(headers, "Cookie",
               apr_psprintf(pool, "%s; %.*s", existing,
                            (int)nv->valuelen, nv->value));
return APR_SUCCESS;
```

That path returns before `*pwas_added = 1`, so duplicate cookie crumbs do not count against `LimitRequestFields`.

## Default Bound

With `LimitRequestFieldSize 8190` and an empty HPACK dynamic `cookie:` entry:

- HPACK insert: `cookie: ""`
- Indexed reference: dynamic index `62`, one byte on the wire: `0xbe`
- Accepted duplicate refs: about `4091`
- Final coalesced cookie value: `4091 * 2 = 8182` bytes
- Repro header block: about `4.1 KiB`

Each merge allocates a new pool string and leaves the previous merged string live until stream cleanup:

```text
sum_{i=1..4091} (2*i + 1) = 16,748,463 bytes
```

That is about `15.97 MiB` of cookie merge-string allocation per stream from about `4.1 KiB` of HPACK payload, or roughly `~4000:1` lower-bound amplification before APR/pool overhead and request structures.

With default `H2MaxSessionStreams 100`, the source-level upper bound is about:

```text
100 streams * 15.97 MiB = 1.56 GiB per HTTP/2 connection
```

## Flow-Control Hold

The repro sends `SETTINGS_INITIAL_WINDOW_SIZE=0`. Response HEADERS can be emitted, but response DATA is flow-control blocked. The stream pool is held until the response body/EOS path can complete or the connection times out. Optional 1-byte `WINDOW_UPDATE` drips can keep the server making progress slowly.
