# radare2 RCE via PDB Section Header Command Injection

A command injection vulnerability in radare2's PDB parser allows arbitrary code execution when a user opens a PE binary whose PDB file carries a crafted section header. It is **distinct from — and survives — the fix for** [issue #25730 / PR #25731](https://github.com/radareorg/radare2/pull/25731), the first PDB RCE we disclosed in the [previous MAD Bugs post](https://blog.calif.io/p/mad-bugs-discovering-a-0-day-in-zero).

Reported upstream as [radare2#25752](https://github.com/radareorg/radare2/issues/25752) and fixed in the same day.

### Summary

When PDB global symbols are emitted in RAD mode, the raw PE section header name (`sctn_header->name[8]`) from PDB binary data is interpolated into an `f` (flag) command via `%.*s` without sanitization. Because the standard `idp` command internally executes `.idpi*` (which runs RAD output as r2 commands), an attacker-crafted PDB file can achieve arbitrary command execution.

The injection point is *different* from the previous bug — section header name vs. symbol name, `f` flag command vs. `fN` rename command — so the base64/sanitization fix shipped for #25730 does not close this path.

### Root cause

`libr/bin/format/pdb/pdb.c` lines 1451–1460:

```c
filtered_name = r_name_filter_dup (r_str_trim_head_ro (name));          // line 1451
pdb->cb_printf ("f pdb.%s = 0x%" PFMT64x " # %d %.*s\n",                // line 1452
    filtered_name,                                                       // line 1453
    (ut64) (img_base + omap_remap ((omap)? (omap->stream): 0,           // line 1454
        gdata->offset + sctn_header->virtual_address)),
    gdata->symtype,                                                      // line 1455
    PDB_SIZEOF_SECTION_NAME,                                             // line 1456
    sctn_header->name);          // <-- NOT sanitized, VULNERABILITY     // line 1457
char *b64name = r_base64_encode_dyn ((const ut8 *)name, strlen (name));  // line 1458
if (b64name) {                                                           // line 1459
    pdb->cb_printf ("fN pdb.%s base64:%s\n", filtered_name, b64name);   // line 1460 -- SAFE (#25731)
```

`sctn_header->name` is an 8-byte array copied verbatim from the PDB's PE section header stream (`stream_pe.c:31`) with no sanitization. A `\n` (0x0A) byte in the section name terminates the `#` comment on the `f` command line and starts a new r2 command line. By crafting a PDB with a section header name containing newlines, the `f` command can be escaped, resulting in arbitrary command execution when the result of `idpi*` is executed.

Each injected line is limited to 7 characters by the 8-byte section name field, but arbitrary-length commands are achieved using a staged hex-encoding technique (inspired by HITCON CTF 2017 "BabyFirst Revenge") that writes hex-encoded command fragments to files, then decodes and executes them via `xxd`.

### PoC

[`poc.py`](poc.py) generates both a PE executable and a matching PDB file. Running:

```bash
python3 poc.py 'open -a Calculator'
# [+] Writing /tmp/payload.pdb
# [+] Writing /tmp/payload.exe
```

then, as the victim:

```bash
r2 /tmp/payload.exe
[0x140001000]> idp
# Calculator.app pops
```

### Impact

Same as the prior PDB bug: attacker-controlled PDB file alongside a PE binary causes arbitrary command execution when the user runs `idp` (or any command that routes through `.idpi*`) in radare2. Default configuration, no user interaction beyond opening the binary and loading its PDB symbols — the normal workflow for anyone reverse-engineering a Windows binary.

### Suggested fix (merged)

Sanitize `sctn_header->name` before interpolation by replacing non-printable bytes. The maintainers applied an equivalent fix the same morning. See radare2 commit history for details.

### Environment

```
radare2 6.1.3 +1 abi:82 @ linux-x86_64
birth: git.6.1.3 2026-04-08__02:44:23
commit: 4191e273095e1745d898f8b52ec63de414e663d7
options: gpl -O? cs:5 cl:2 make
Linux x86_64
```

### Reporter

Hung Nguyen (mov) of Calif.io

### Timeline

- 2026-04-08 03:28 UTC: Reported as [radare2#25752](https://github.com/radareorg/radare2/issues/25752)
- 2026-04-08 13:54 UTC: Maintainer (@trufae) acknowledged — *"yeah as said the previous fix was wrong and incomplete, i just fixed it in a PR."*
- 2026-04-08 (same day): Fix merged upstream


## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
