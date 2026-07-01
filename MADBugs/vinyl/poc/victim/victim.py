#!/usr/bin/env python3
"""
Victim browser session.

Opens a real Chromium window, walks through the Groove Therapy shop like a
normal customer would:
  • browses the homepage
  • clicks Log in
  • signs in as alice / i_love_c_programming
  • visits Your account (this request carries the session cookie through
    Varnish to the backend — which is what the attacker intercepts)

The browser is run in headed mode by default so the demo is visible. Pass
--headless to run without a window. The browser does *not* know it is being
proxied through Varnish or that anything is wrong; it opens
https://groove-therapy.local/ over TLS and sees a normal e-commerce site.
The self-signed cert is accepted via the Playwright context's
ignore_https_errors flag.
"""
from __future__ import annotations

import argparse
import sys
import time

from playwright.sync_api import sync_playwright


def run(url: str, *, headless: bool, pause: float) -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        # http_credentials makes Playwright auto-answer Basic Auth 401
        # challenges on this origin with these credentials — the same as
        # a human typing into the browser's native sign-in dialog. Every
        # authenticated request thereafter carries
        #     Authorization: Basic <base64(user:pass)>
        # which the attacker can decode to plaintext.
        ctx = browser.new_context(
            viewport={"width": 1280, "height": 840},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
            http_credentials={
                "username": "alice",
                "password": "i_love_c_programming",
            },
        )
        page = ctx.new_page()

        print(f"[victim] opening {url} …")
        page.goto(url, wait_until="domcontentloaded")
        time.sleep(pause)

        print("[victim] browsing a record …")
        page.click('a[href="/record/rum"]', timeout=5000)
        time.sleep(pause)

        print("[victim] signing in — browser answers the 401 automatically …")
        page.goto(url + "/account", wait_until="domcontentloaded")
        time.sleep(pause)

        # Keep making authenticated requests — each bereq carries the
        # Authorization: Basic header. Every one is a chance for the
        # attacker's poisoned backend connection to fire.
        for i in range(6):
            print(f"[victim] browsing … ({i + 1}/6)")
            page.goto(url + "/store", wait_until="domcontentloaded")
            time.sleep(pause)
            page.goto(url + "/account", wait_until="domcontentloaded")
            time.sleep(pause)

        print("[victim] done. closing browser.")
        ctx.close()
        browser.close()
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", default="https://groove-therapy.local",
                    help="shop URL (default: https://groove-therapy.local)")
    ap.add_argument("--headless", action="store_true",
                    help="run Chromium headless (default: headed)")
    ap.add_argument("--pause", type=float, default=1.2,
                    help="seconds to pause between actions (default: 1.2)")
    args = ap.parse_args()

    try:
        rc = run(args.url, headless=args.headless, pause=args.pause)
    except Exception as e:
        print(f"[victim] error: {e}", file=sys.stderr)
        rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
