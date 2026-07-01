# `vtc/` — vinyltest reproducers

Four Varnish test-case (`.vtc`) files that reproduce the exploit and its
supporting measurements using the project's built-in `vinyltest` harness
(= upstream Varnish's `vtest2`). These are the canonical, deterministic
proofs of the bug; each one passes when run against the vulnerable Varnish
source in this repository.

The Docker demo in the parent directory is the user-facing story; these
vtc files are the minimal-dependency, byte-exact proofs that ship with the
report.

| File | What it proves |
|---|---|
| `h2_empty_hdr_crlf.vtc`       | A single H/2 request with `:a: xx` produces a bare `\r\n` mid-headers on the bereq wire. The backend receives only the pre-`:a` headers (33 bytes), the rest is consumed as body. |
| `h2_smuggle_probe.vtc`        | Measures the post-`:a` leftover length on a given Varnish build. Emits the exact leftover text so downstream scripts can size the smuggled Content-Length correctly. |
| `h2_smuggle_colon_a.vtc`      | The full exploit chain: attacker smuggles `POST /api/review` via H/2 `:a`, victim's H/1.1 request is consumed as body of the smuggled request, victim receives the smuggled response. Uses a one-line `sub vcl_recv { return (pass); }` VCL. |
| `h2_smuggle_default_vcl.vtc`  | **Same end-to-end exploit but against the shipped `builtin.vcl`** — no user VCL involved. This is the "reachable on a default-config Varnish" proof. |

## Running

From the repository root (`/Users/calif/CTFs/misc/vinyl-cache`):

```bash
ulimit -n 1024
./bin/vinyltest/vinyltest -i -v UNPATCHED_vinyl_skip/vtc/h2_smuggle_default_vcl.vtc
```

`-i` tells the harness to find `vinyld` (the project's `varnishd` rebrand)
and the built VMODs in the in-tree build directory. `-v` prints the full
execution trace including Varnish's VSL log.

Successful output ends with:

```
*    top   TEST h2_smuggle_default_vcl.vtc completed
#    top  TEST h2_smuggle_default_vcl.vtc passed (2.447)
```

The `BereqHeader` log shows the empty-header row that is the wire signature
of the bug (a blank line between the header name and value of two
otherwise-normal headers).

## Why four files

`h2_empty_hdr_crlf.vtc` isolates the primitive — the Varnish-side parse of
`:a` produces an empty `hp->hd[]` entry and `HTTP1_Write` emits it as a bare
CRLF. Nothing depends on ordering, on `content-length`, on backend parsing
behaviour. Just Varnish bytes.

`h2_smuggle_probe.vtc` is the measurement tool that the Docker demo's
attacker script automates. Makes the length-of-leftover value visible and
reproducible.

`h2_smuggle_colon_a.vtc` and `h2_smuggle_default_vcl.vtc` are the full
exploit in two VCL configurations — one with a minimal user VCL, one
against just `builtin.vcl`. Both pass. Both demonstrate cross-client data
exposure: the `c2` (victim) client receives the response to the `c1`
(attacker) client's smuggled `/smuggled` URL, confirmed by
`expect resp.http.X-Which == "smuggled"`.
