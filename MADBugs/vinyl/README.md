# MAD Bugs: My Cousin Vinyl (CVE-2026-50052)

So the story went like this: [Squid was bleeding](https://blog.calif.io/p/squidbleed) from a 29-year-old heap overread in her default config. Naturally, she did the only sensible thing: she called her cousin, [Vinyl](https://vinyl-cache.org/).

![My Cousin Vinyl](img/cousin.jpg)

Squid and Vinyl are family: both are HTTP caching proxies written in C. Vinyl wasn't leaking memory, but he had a family problem of his own.

Vinyl speaks two versions of HTTP at once: HTTP/1.1, whose headers are plain text terminated by `\r\n`, and HTTP/2, whose headers are binary and length-prefixed. Translating between the two is no mean feat, and it only takes a tiny mistake for Vinyl and the backend to disagree about where one request ends and the next begins.

That disagreement is the essence of HTTP request smuggling.

James Kettle's [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2) (2021) showed just how fertile this attack surface is. Five years later, researchers are still finding new ways to confuse these protocol translators.

For Vinyl, all it takes is a two-byte HPACK pseudo-header, `:a`, to desynchronize the translation layer and smuggle arbitrary HTTP requests through the proxy, enabling cache poisoning, XSS, credential theft, and more.

This is the story of how we found it.

## The target: Vinyl Cache

Vinyl Cache ([renamed](https://vinyl-cache.org/organization/20-years.html) from Varnish Cache in 2026) is an open-source HTTP accelerator that sits in front of origin servers and serves cached responses straight from memory. Since its launch in 2006 it has grown into one of the most widely deployed self-hosted caches on the web: technology surveys detect it on [hundreds of thousands of live sites](https://www.wappalyzer.com/technologies/caching/varnish/), it is the recommended full-page cache for Adobe Commerce (Magento), and Fastly built its CDN on a heavily customized fork of it.

Part of what makes it fast is connection pooling: many short-lived client connections can be served by a small pool of reused backend TCP connections. This eliminates TCP handshake overhead, but it also means that poisoning a single backend connection affects whichever client happens to land on it next.

## Finding the bug

We started with Claude Opus 4.7:

> Analyze this project and determine the pre-auth attack surface

Claude spawned subagents to audit the HPACK decoder, the HTTP/1.1 parser, and the HTTP/2 frame layer.

One of those subagents looked directly at [`h2h_addhdr`](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/src/commit/613a9bec/bin/vinyld/http2/cache_http2_hpack.c#L137-L261), the function that dispatches HTTP/2 pseudo-headers during HPACK decoding.

The HPACK decoder writes each header into a buffer (`d->out`) as `name: value`. Two pointer pairs track the result: `nm` spans the name, and `hdr` (with `hdr.b` for the start, `hdr.e` for the end) spans the full header. The function matches `nm` against the four pseudo-header names to decide how to handle it.

```c
// include/vdef.h
#define Tstrcmp(t, s)  (strncmp((t).b, (s), Tlen(t)))
```

```c
// cache_http2_hpack.c - h2h_addhdr()

if (!Tstrcmp(nm, ":method")) {
    ...
}
else if (!Tstrcmp(nm, ":path")) {
    ...
}
else if (!Tstrcmp(nm, ":scheme")) {
    ...
}
else if (!Tstrcmp(nm, ":authority")) {
    memcpy(d->out + 6, "host", 4);
    hdr.b += 6;
}
```

The `:authority` branch is where Vinyl rewrites the HTTP/2 pseudo-header into an HTTP/1.1 `host` header. For maximum efficiency, Vinyl does this in-place, avoiding a costly heap allocation.

Normally, `d->out` contains something like `:authority: example.com`. The `memcpy` splices `"host"` over `"rity"` at offset 6, and `hdr.b += 6` advances the start pointer past `:autho` so the result begins at `host:`:

![Normal :authority rewrite](img/splice-normal.gif)

Unfortunately, this clever optimization is responsible for the bug we're talking about today.

Spotted it yet? The bug is in [`Tstrcmp`](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/src/commit/613a9bec/include/vdef.h#L288). It uses `Tlen(t)` as the comparison length, which is the length of the *decoded* header name, not the target string. So `Tstrcmp(":a", ":authority")` compiles into `strncmp(":a", ":authority", 2)`, which examines only the first two bytes, finds them equal, and returns 0. Thus, any prefix of `:authority` matches.

The first subagent didn't catch this. It saw the `memcpy` and assumed `Tstrcmp` was a proper equality check without looking inside. A second subagent caught the real semantics when the parser unexpectedly failed an assertion:

```
Tstrcmp uses only Tlen(t), so any prefix of ":authority" matches,
e.g. ":a", ":au", ... ":authorit".

hdr.b = d->out+6, hdr.e = d->out+4, so b > e. The next code path
that evaluates Tlen(hp->hd[n]) hits assert(b <= e) and aborts the
worker.
```

Since `hdr.b` must never be past `hdr.e`, this is an instant crash. A DoS that automatically recovers is interesting, but has little real world impact. We switched to Claude Mythos Preview to dig deeper:

> Read the research conducted previously and use your higher intelligence to do better than them. I want you to find a bug that can be exploited unauthenticated and either result in memory corruption, or exposure of client data.

Mythos tried a two-byte value instead of an empty one. With an empty value, `hdr.b` overshoots `hdr.e` and the assertion kills the worker. But with exactly two bytes of value, the total header `:a: xx` is 6 bytes, so `hdr.b += 6` lands exactly on `hdr.e`:

![Attack: :a produces zero-length header](img/splice-attack.gif)

This avoids the crash. Instead, a zero-length header is quietly stored into the header array. What could possibly go wrong?

### Zero bytes, one CRLF, two requests

When Vinyl forwards the request to the backend, it translates back to HTTP/1.1 text. [`HTTP1_Write`](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/src/commit/613a9bec/bin/vinyld/http1/cache_http1_proto.c#L500-L516) walks the header array and calls `http1_WrTxt` once per slot, passing `"\r\n"` as the suffix:

```c
unsigned
HTTP1_Write(struct v1l *v1l, const struct http *hp, const int *hf)
{
    ...
    l = http1_WrTxt(v1l, &hp->hd[hf[0]], " ");      // METHOD + " "
    l += http1_WrTxt(v1l, &hp->hd[hf[1]], " ");     // URL    + " "
    l += http1_WrTxt(v1l, &hp->hd[hf[2]], "\r\n");  // PROTO  + "\r\n"

    for (u = HTTP_HDR_FIRST; u < hp->nhd; u++)
        l += http1_WrTxt(v1l, &hp->hd[u], "\r\n");  // each header + "\r\n"
    l += V1L_Write(v1l, "\r\n", -1);                 // final end-of-headers
    return (l);
}
```

`http1_WrTxt` writes the header content, then the suffix. For our zero-length header, the content write is zero bytes and only the `"\r\n"` suffix hits the wire.

### The `content-length` trick

A bare CRLF now sits in the middle of the backend request's header block. In HTTP/1.1, that's the end-of-headers marker, so the backend stops parsing right there, even though Vinyl thinks it's still writing headers.

Without a `content-length`, the backend sees a request with no body. The leftover headers after the bare CRLF sit on the wire as garbage, and the backend tries to parse them as the start of the next request. It fails, returns a 400, and closes the connection.

But if the attacker can get a `content-length` header *before* the bare CRLF, the backend reads the leftover as body instead of rejecting it. Vinyl does not enforce pseudo-header ordering ([RFC 9113 section 8.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3)), so this is allowed.

![Backend wire view](img/backend-wire.gif)

Because `content-length` appears before the truncation point, the backend sees it as a real header and reads exactly 109 bytes of body from the wire, consuming Vinyl's leftover headers. The attacker's HTTP/2 DATA frame (which must also be exactly 109 bytes to pass Vinyl's own HTTP/2 validation) lands immediately after, and the backend parses it as a brand new HTTP/1.1 request on the same pooled connection.

### Swallowing the victim

At this point, the attacker has injected a request onto the pooled backend connection. This smuggled request can exploit the `content-length` trick a second time: it declares a `content-length` much larger than its own body, so the backend keeps reading. When Vinyl reuses the connection for a victim's request, the backend reads it as the *body* of the attacker's POST:

![Victim request swallowed](img/victim-swallow.gif)

The victim's complete request, including `Authorization` and `Cookie`, is delivered to whatever endpoint the attacker chose. If that endpoint stores or echoes its body (a review system, a logging pipeline, a webhook forwarder), the attacker reads the credentials back.

## Proof of concept

To demonstrate the full chain, the [PoC](poc/) sets up a Docker Compose environment around a simple Flask-based webstore with HTTP Basic auth. It has a public `POST /api/review` endpoint that stores raw request bodies as reviews, which serves as the exfiltration channel. Vinyl Cache 7.6 sits in front with `feature=+http2` and no user VCL, behind hitch for TLS termination with ALPN `h2, http/1.1`.

The attacker script (`attack.py`) first probes the post-`:a` leftover length (which varies by deployment), then sends attack requests while polling `/reviews` for captured credentials.

Within seconds of the victim browsing the store:

```
[!!] CAPTURED victim HTTP request (7.3s, smuggle #2)
------------------------------------------------------------------------
AAAAAAAAAAAAAAAAAAAAAAGET /account HTTP/1.1
Host: groove-therapy.local
Authorization: Basic YWxpY2U6aV9sb3ZlX2NfcHJvZ3JhbW1pbmc=
------------------------------------------------------------------------
    -> decoded:     alice:i_love_c_programming
```

PoC video: https://www.youtube.com/watch?v=Oc91MacYL8w

## From `Tstrcmp` to `Tstreq`

Fixed versions were released on 2026-05-18: Vinyl Cache 9.0.1, Varnish Cache 9.0.3, 8.0.2, and 6.0.18.

The fix swaps each `!Tstrcmp` for `Tstreq`:

```diff
-  if (!Tstrcmp(nm, ":method")) {
+  if (Tstreq(nm, ":method")) {
       ...
-  } else if (!Tstrcmp(nm, ":authority")) {
+  } else if (Tstreq(nm, ":authority")) {
```

`Tstreq` checks length before content, which is what makes it symmetric:

```c
#define Tstreq(t, s) (Tlen(t) == strlen(s) && !strncmp((t).b, (s), Tlen(t)))
```

With this change, `:a` and every other prefix of `:authority` fall through to the unknown-pseudo-header catch-all and are rejected with `H2SE_PROTOCOL_ERROR`.

## From bug to vulnerability

It might surprise you to learn that we were not the first to find the bug. The three patch commits were authored back in 2025:

| Commit | Authored | Subject |
|---|---|---|
| [`613a9bec`](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/commit/613a9bec) | 2025-01-22 | vdef: Test equality between txt and string |
| [`dfc27fb4`](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/commit/dfc27fb4) | 2025-09-18 | http2_hpack: Check pseudo-header names with Tstreq() |
| [`84e2de41`](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/commit/84e2de41) | 2025-09-18 | vdef: Retire Tstrcmp() macro |

Dridi Boukelmoune, one of the core maintainers, had written the `Tstreq` macro in January 2025 and the caller migration in September 2025, seven months before our report. So why are we even talking about this issue, when it should have been fixed long ago?

While the patch had landed in an internal downstream project, nobody there connected it to a security impact. Nobody thought it was serious enough to check whether Vinyl had to be patched too.

Interestingly, we saw the same human-like mistake while working through it with Claude: the first subagent missed the bug, the second found it but wrote it off as an unexploitable DoS, and Mythos turned it into request smuggling.

Finding the bug was the easy part. Realizing the full impact of the vulnerability is much harder and often requires a fresh pair of eyes, in this case Claude's.

## Disclosure timeline
- 2025-09-18: Bug independently found by Dridi Boukelmoune
- 2026-04-21: Initial report by Lam Jun Rong of Calif.io
- 2026-04-22: Confirmed by Vinyl Cache Security team
- 2026-05-18: [VSV00019](https://vinyl-cache.org/security/VSV00019.html) published; fixed releases: Vinyl Cache 9.0.1, Varnish Cache 9.0.3, 8.0.2, 6.0.18
- 2026-05-27: Debian stable-security update (varnish 7.7.0-3+deb13u1)
- 2026-06-03: [CVE-2026-50052](https://cve.threatint.eu/CVE/CVE-2026-50052) published
- 2026-07-01: This blog post published
