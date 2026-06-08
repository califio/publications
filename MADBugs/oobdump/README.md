# OOBdump: Relocation Oriented Programming

A missing bounds check in BFD's FR30 relocation handler (`fr30_elf_i32_reloc`, `bfd/elf32-fr30.c`) gives an out-of-bounds heap write when `objdump -g` parses a crafted FR30 ELF object file. We turn that single primitive into a 100% reliable, single-shot RCE that defeats ASLR, PIE, and heap hardening with no information leak, using a [House of Apple 2](blog.md) FSOP chain.

The bug only affects builds that enable the FR30 backend (`--enable-targets=all` and friends). Per the binutils security policy, issues in rarely-built targets like this are disclosed publicly rather than treated as embargoed vulnerabilities. We followed that process, and the issue was fixed promptly.

| File | What |
|---|---|
| [`blog.md`](blog.md) | Blog post |
| [`WRITEUP.md`](WRITEUP.md) | Technical write-up (AI-generated) |
| [`solve_rce.py`](solve_rce.py) | PoC: builds the malicious FR30 ELF object |
| [`calibrate.py`](calibrate.py) | Helper that auto-calibrates the heap offsets via gdb |
| [`poc_rce.bin`](poc_rce.bin) | Prebuilt malicious object file |
| `objdump` | The vulnerable `--enable-targets=all` build used for testing |

## Running the exploit

```bash
# Build the exploit ELF
python3 -c "import solve_rce; open('poc_rce.bin','wb').write(solve_rce.build('local'))"

# Trigger RCE
./objdump -g poc_rce.bin
```

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
