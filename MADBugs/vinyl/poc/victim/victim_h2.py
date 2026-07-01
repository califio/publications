#!/usr/bin/env python3
"""
Alternative victim that speaks HTTP/2 to hitch over TLS, mirroring the
production shape where every public client is H/2-over-TLS.

Uses the `httpx` HTTP client with `http2=True`. Simulates a realistic
browser session (Chrome User-Agent, Sec-* headers, Accept-Language,
Accept-Encoding) so the bereq Varnish produces is approximately the same
size as the Playwright-Chromium victim's, keeping the attacker's
Content-Length sizing valid. Cert verification is disabled (`verify=False`)
to accept the demo's self-signed hitch cert.
"""
from __future__ import annotations

import argparse
import sys
import time

try:
    import httpx  # pip install httpx[http2]
except ImportError:
    print("this victim needs httpx[http2]. install with:", file=sys.stderr)
    print("    pip install 'httpx[http2]'", file=sys.stderr)
    sys.exit(2)


# Browser-representative headers so the H/1 bereq Varnish sends to the
# backend is the same shape as a real browser's (this matters for the
# attacker's Content-Length sizing).
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    ),
    "sec-ch-ua": '"Chromium";v="125", "Not.A/Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Linux"',
    "Upgrade-Insecure-Requests": "1",
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
}


def run(url: str, pause: float) -> int:
    # http2=True over TLS → HTTP/2 negotiated via ALPN (the production shape).
    # http1=False keeps httpx from falling back, so the run fails loudly if
    # something downgrades instead of silently serving H/1.1.
    # httpx.BasicAuth sends `Authorization: Basic <base64(user:pass)>` on
    # every authenticated request — the same header a real browser sends
    # after it caches credentials from its native Basic Auth dialog.
    with httpx.Client(
        http2=True, http1=False, verify=False, timeout=10.0,
        auth=httpx.BasicAuth("alice", "i_love_c_programming"),
    ) as client:
        print(f"[victim-h2] opening {url} over HTTP/2 …")
        r = client.get(url + "/", headers=BROWSER_HEADERS)
        print(f"    → {r.http_version} {r.status_code}")
        time.sleep(pause)

        print("[victim-h2] browsing a record …")
        r = client.get(url + "/record/rum", headers=BROWSER_HEADERS)
        print(f"    → {r.http_version} {r.status_code}")
        time.sleep(pause)

        print("[victim-h2] loading Your account — bereq carries Authorization …")
        r = client.get(url + "/account", headers=BROWSER_HEADERS)
        print(f"    → {r.http_version} {r.status_code}")
        time.sleep(pause)

        for i in range(6):
            print(f"[victim-h2] browsing … ({i + 1}/6)")
            client.get(url + "/store", headers=BROWSER_HEADERS)
            time.sleep(pause)
            client.get(url + "/account", headers=BROWSER_HEADERS)
            time.sleep(pause)

        print("[victim-h2] done.")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="https://groove-therapy.local")
    ap.add_argument("--pause", type=float, default=0.6)
    args = ap.parse_args()
    try:
        sys.exit(run(args.url, args.pause))
    except Exception as e:
        print(f"[victim-h2] error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
