# Heap-Buffer-Overflow RCE in objdump via FR30 ELF Relocations

## Summary

A heap-buffer-overflow WRITE vulnerability in BFD's `fr30_elf_i32_reloc()` function allows arbitrary code execution when `objdump -g` processes a crafted FR30 ELF32 relocatable file. The exploit achieves 100% reliable RCE with full ASLR enabled, using 0 bits of entropy (no brute-forcing).

**Affected function:** `bfd/elf32-fr30.c:309` in GNU Binutils  
**Platform:** aarch64 / Ubuntu 24.04 / glibc 2.39  
**Mitigations bypassed:** Full RELRO, PIE, ASLR, NX, glibc vtable checks

## The Vulnerability

In `fr30_elf_i32_reloc()`, the relocation handler writes a 4-byte value at an attacker-controlled offset from the section data buffer with no bounds checking:

```c
// elf32-fr30.c:309
bfd_put_32(abfd, srel, (bfd_byte *) data + octets);
// where octets = reloc_entry->address + 2
// and srel = symbol->value + reloc_entry->addend
```

Both `reloc_entry->address` (the offset) and `srel` (the value) are fully controlled from the ELF file's relocation entries and symbol table. This gives us an arbitrary 4-byte write primitive relative to the `.debug_info` heap buffer.

## Exploit Architecture

The exploit uses three complementary primitives built from the OOB write:

### Primitive 1: Wrapping Writes (negative offsets)

The arelent struct's `address` field is 64-bit on the host but populated from a 32-bit ELF r_offset. By using earlier relocations to write `0xFFFFFFFF` into the upper 32 bits of a later arelent's address field, we can create wrapping addresses that reach heap memory *before* the data buffer. This lets us write to the BFD struct (at a constant negative offset from data).

### Primitive 2: Byte-Order Switch

The BFD struct's `xvec` pointer determines byte order for `bfd_put_32`. A 2-byte partial overwrite of xvec's lower 16 bits (0 entropy due to 64KB PIE alignment) redirects it from the FR30 target vector to a little-endian target vector at a known offset in `.data.rel.ro`. All subsequent writes use LE byte order, matching the host's native format.

### Primitive 3: Partial-Inplace (PI) Relocations

By overwriting the lower 16 bits of an arelent's `howto` pointer, we redirect it from the FR30 howto table to the **`R_386_PC32`** entry in the i386 `elf_howto_table` (`elf32-i386.c`), which sits at a nearby address in `.data.rel.ro` (lower 16 bits = `0xb820`). This howto has `partial_inplace=1`, `pc_relative=1`, `pcrel_offset=1`, and `src_mask=dst_mask=0xFFFFFFFF`.

When `bfd_perform_relocation` processes a relocation with this howto, it computes a delta from the symbol value and relocation address, then calls `apply_reloc` (`bfd/reloc.c:612`):

```c
static void
apply_reloc (bfd *abfd, bfd_byte *data, reloc_howto_type *howto,
             bfd_vma relocation)
{
  bfd_vma val = read_reloc (abfd, data, howto);       // read existing 32-bit value
  val = ((val & ~howto->dst_mask)
       | (((val & howto->src_mask) + relocation) & howto->dst_mask));
  write_reloc (abfd, val, data, howto);               // write result back
}
```

With `src_mask = dst_mask = 0xFFFFFFFF`, this simplifies to `val = read_32(target) + delta; write_32(target, val)` — a read-modify-write that adds an attacker-controlled constant to whatever value is already in memory. This is the pointer-arithmetic primitive: it adjusts existing heap pointers by constant deltas without knowing their absolute addresses.

Since PI preserves the upper 32 bits of a 64-bit pointer while adding a 32-bit delta to the lower 32, we can adjust any pointer within its ASLR region:
- **libc pointers** on the heap (e.g., FILE `__pad5` = `&_IO_list_all`) can be PI-adjusted to `system()` using the constant delta `system - &_IO_list_all`.
- **Heap pointers** (e.g., FILE `_lock`, `_wide_data`) can be PI-adjusted to point to fake structures at known heap offsets.

## The House of Apple 2 Chain

The FSOP target is the `FILE` struct at `abfd->iostream` — a standard glibc `FILE` allocated on the heap by `fopen()` during `bfd_fopen()` (`bfd/opncls.c:259`). It sits at a constant offset (`+160` bytes) after the `.debug_info` data buffer in the heap layout, making it reachable via the OOB write primitive. The exploit corrupts this FILE struct using FR30 OOB writes and PI relocations to set up a House of Apple 2 attack:

### Fake Structure Layout

```
fake_wide_data (fp-88)          fake_vtable (fp+80)          FILE struct (fp)
+0:  _IO_read_ptr  = ?         +0:   0 (lock word)          +0:   " (gnome-calculator&)"
+24: _IO_write_base = 0  ← key +104: system()  ← PI'd      +32:  write_base = 1
+48: _IO_buf_base  = 0  ← key                               +40:  write_ptr = 2
+224: _wide_vtable = fp+80 ──────────────────────────────┐    +80:  0 (fake_vtable start)
         ↑                                               │    +104: _chain = 0 (zeroed)
         │ PI'd from _lock                               │    +136: _lock → fp+80 (PI'd)
         └───────── _wide_data → fp-88 (PI'd) ──────────│    +160: _wide_data → fp-88 (PI'd)
                                                         │    +184: __pad5 → system() (PI'd)
                                                         └──→ +216: vtable → _IO_wfile_jumps (PI'd)
```

### PI Relocations (4 total, all 0 entropy)

| Target | From | To | Delta |
|--------|------|----|-------|
| `fp+216` (vtable) | `_IO_file_jumps` | `_IO_wfile_jumps` | +504 (constant in libc) |
| `fp+136` (_lock) | lock object | `fp+80` (fake vtable) | `(IO+80) - LV` (constant heap delta) |
| `fp+160` (_wide_data) | wide_data struct | `fp-88` (fake wide_data) | `(IO-88) - WV` (constant heap delta) |
| `fp+184` (__pad5) | `&_IO_list_all` | `system()` | `DS + 8` (constant libc delta) |

### The Trigger

1. The exploit sets `iostream = NULL` via wrapping write to the BFD struct, preventing `fclose()` during `bfd_close()`. The FILE remains linked in `_IO_list_all`.
2. During `exit()`, glibc's `_IO_cleanup()` calls `_IO_flush_all_lockp()`, which iterates `_IO_list_all`.
3. Our FILE has `write_ptr (2) > write_base (1)` → `_IO_OVERFLOW(fp, EOF)` is called.
4. The vtable was PI'd to `_IO_wfile_jumps` (passes glibc's vtable validation since it's within `__libc_IO_vtables`), so `__overflow` dispatches to `_IO_wfile_overflow()`.
5. `_IO_CURRENTLY_PUTTING` is set (byte 1 of flags = `'('` = 0x28, bit 3 = 1), so the code checks `wide_data->_IO_write_base`:
   ```asm
   ldr  x1, [x4, #24]     ; x1 = wide_data->_IO_write_base
   tbnz w0, #11, +200      ; PUTTING set → jump
   cbnz x1, +124           ; if write_base != 0 → skip (!)
   ; fall through to _IO_wdoallocbuf...
   ```
6. `_IO_write_base = 0` (at `fp-88+24`, zeroed/stable) → falls through.
7. `_IO_wdoallocbuf()` checks `_IO_buf_base == NULL` (at `fp-88+48`, zeroed) → calls `_IO_WDOALLOCATE(fp)`.
8. `_IO_WDOALLOCATE` reads from the **unchecked** `_wide_vtable->__doallocate` (at fake_vtable+104 = `fp+184` = `system()`).
9. **`system(fp)`** is called with `fp` pointing to the command string `" (gnome-calculator&)"`.

### The dsz=144 Trick

The most subtle part of the exploit is choosing `debug_info_size = 144` bytes for the `.debug_info` section. This shifts the heap layout so that the fake `_wide_data` fields at `fp-88+24` (write_base) and `fp-88+48` (buf_base) land in memory that remains zero through the exit trigger.

With the default `dsz=48`, a 64-byte chunk immediately before the FILE struct gets freed during BFD cleanup, and glibc's tcache writes a `PROTECT_PTR` fd pointer over `write_base`, making it non-zero and blocking the chain. With `dsz=144`, the heap geometry shifts enough that these fields avoid all freed-chunk metadata and locale string allocations that occur between relocation processing and the exit flush.

## Flag Byte Constraints

The FILE `_flags` field (first 4 bytes at `fp`) doubles as the shell command string. The following glibc flag bits must be satisfied:

| Bit | Flag | Required | Constraint on command byte |
|-----|------|----------|---------------------------|
| 1 | `_IO_UNBUFFERED` | 0 | byte[0] bit 1 clear: `' '`(0x20) works |
| 3 | `_IO_NO_WRITES` | 0 | byte[0] bit 3 clear: `' '`(0x20) works |
| 11 | `_IO_CURRENTLY_PUTTING` | 1 | byte[1] bit 3 set: `'('`(0x28) works |

The pattern `" (cmd)"` satisfies all constraints while being a valid shell command (runs `cmd` in a subshell).

## Running the Exploit

```bash
# Build the exploit ELF
python3 -c "import solve_rce; open('poc_rce.bin','wb').write(solve_rce.build('local'))"

# Trigger RCE (pops gnome-calculator)
./objdump -g poc_rce.bin
```

## Reliability

- **ASLR:** 0 entropy. All pointer adjustments use constant deltas within the same ASLR region (libc→libc or heap→heap). The xvec partial overwrite has 0 entropy due to 64KB PIE page alignment.
- **Success rate:** 100% (20/20 in testing with ASLR enabled, both pipe and TTY modes).
- **No assumptions:** The exploit does not require any files to exist on the filesystem. The entire payload is self-contained in the crafted ELF.
