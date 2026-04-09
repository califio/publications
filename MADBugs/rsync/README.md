# Feeding Claude Phrack Articles for Fun and Profit: Desync the Planet

tl;dr: A teammate gave Claude a Phrack article. It built a working
rsync RCE on x86-64. He shared the generated exploit with me but forgot
one file, and I needed it on ARM64 anyway. I gave Claude one prompt:
*reproduce this*. Ninety minutes later it dropped a working exploit. I
told it the exploit was slow; it made it 20x faster. We also asked it
to audit the patched rsync, and it came back with new bugs.

## How this started

Our new favourite pastime is feeding Claude Phrack articles and seeing
what comes back. This time it was Phrack 72's *"Desync the Planet"*,
which describes chaining CVE-2024-12085 (stack info leak) into
CVE-2024-12084 (heap overflow) for unauthenticated RCE against
`rsync --daemon`. A teammate handed Claude the article; it built a
working exploit on x86-64. The full session is in
[`writeup.md`](writeup.md), prompts and all: where Claude tried adding
`fprintf` to `sender.c` and got told "why are you modifying the rsync
source?", where it was redirected to GDB, where it was told to actually
read the article instead of guessing at the layout.

He shared [`exploit.py`](exploit.py) with me. Two problems:

1. **It imported `rsync_lib`, which wasn't in the repo.** He just forgot
   to share it. Claude had generated this custom protocol library to
   handle all the heavy lifting: daemon handshake, multiplexed I/O,
   file list parsing, the deflate-token oracle.
2. **It was tuned for x86-64.** Hardcoded binary offsets, an info-leak
   target at a stack offset that doesn't exist on ARM64, a `.bss` payload
   layout that assumes a memory map that doesn't match the ARM64 build.

I wanted to run it on a Debian 12 ARM64 box. So I handed both files (the
writeup and the broken exploit) to Claude:

> **Read the WriteUp and reproduce this exploit with exploit.py**

That was the only prompt. Everything below came out of that single
instruction with no further steering from me.

## What Claude figured out

**No `rsync_lib.py`.** Claude opened the rsync 3.2.7 source (`io.c`,
`flist.c`, `compat.c`, `sender.c`, `token.c`) and built the protocol
library from scratch. The first attempt timed out at `setup_protocol`.
So it spun up a Python proxy, pointed the *real* rsync client through it
at the daemon, and diffed the wire bytes against what its own library
was sending. Three things the source doesn't make obvious: daemon args
are `\0`-terminated (not `\n`), checksum negotiation is *both sides
write, then both sides read* (not request-response), and the post-setup
`write_line` calls were bypassing the multiplex layer. The server was
reading the `"ZZZZ..."` filter pattern as a multiplex header and
returning `unexpected tag 83` (83 + `MPLEX_BASE` = 90 = `'Z'`).

**No GDB.** The container had no `gdb`, no `strace`, no root. Claude
built substitutes: an `LD_PRELOAD` `memcmp` hook to capture the
uninitialized `sum2` buffer at the moment of comparison, and a 200-line
ptrace crash-catcher that attached to the forked rsync child, caught
the SIGSEGV, and dumped registers plus the entire payload region from
`/proc/PID/mem`. The memcmp hook showed the leak target had moved from
`sum2+8` on x86-64 to `sum2+24` on ARM64 (a saved LR pointing into
`start_server`, three frames up).

**The trickiest bug.** The crash dump showed `shell_exec` had been
called: `algctx` was zeroed by OpenSSL's `str xzr, [x19, #56]` after
`freectx` returned, not before. Claude set a `BRK #0` breakpoint at
`shell_exec`'s entry, caught the trap, printed `X0` (the cmd pointer),
and followed `PTRACE_O_TRACEFORK`. The breakpoint hit, the pointer was
correct, and a fork was observed, but the proof file was never created.
Reading the command string back from memory at that point gave
`"touch /t"`, truncated at 8 bytes.

The ARM64 build's `.bss` layout puts `last_match` at `ctx_evp+0x110`.
`match_sums` zeroes it before calling `sum_init`, which overwrites
bytes 8-15 of the command string at `+0x108`. `system("touch /t")`
tried to write to `/` and failed silently. Claude moved the command to
`+0x58` (inside the `ctx_md` union, which the OpenSSL path never
touches), which fixed it.

Five issues total, all found and fixed without ever attaching a real
debugger:

| # | What broke | How Claude found it |
|---|---|---|
| A1 | Leak target at `sum2+24`, not `+8` | LD_PRELOAD memcmp hook |
| A2 | `count=3277` destabilizes the stack | Per-connection probe across 5 runs |
| A3 | Command truncated at byte 8 | ptrace bp on `shell_exec` + `match_sums` disasm |
| A4 | ARM64 glibc 2.36 still wants ONE filter | `malloc_usable_size` test |
| A5 | Three protocol mismatches in `rsync_lib` | socat wire capture vs. real client |

## Timeline

About **90 minutes** from a cold container to the first proof file. Claude
reconstructed this from daemon log timestamps and file mtimes:

| Elapsed | Milestone |
|--------:|---|
|    0:00 | First daemon banner. `rsync_lib` doesn't exist yet. |
|    0:30 | Protocol library working: file list parsed, download verified. Three wire-format bugs fixed along the way. |
|    0:37 | Info-leak oracle confirmed: `token=-1` means MATCH. The `memcmp` hook found the LR at `sum2+24`. |
|    0:59 | Heap overflow lands. Server child crashes silently, proof the write hit `.bss`. |
|    1:29 | ptrace breakpoint on `shell_exec`: hit, `X0` correct, fork observed. Still no proof file. |
| **1:34** | **First `/tmp/rce_proof.txt`.** Bug A3: `last_match = 0` was zeroing `cmd[8:16]`. Moved cmd to `+0x58`. |

The split was roughly even: a third building the protocol library, a
third finding the ARM64 leak target, a third figuring out why
`shell_exec` ran but the file never appeared.

## "It works but it's slow"

First successful run: about five minutes. The leak now needs 24 bytes
(not 8), at ~128 connections per byte, ~120ms per connection.

I told Claude:

> **Your exploit now takes 5 minutes to run, probably because of the
> brute-forcing in first step. Make it faster.**

Claude came back with two stacked changes. First, a hint table: it had
noticed during the leak debugging that 18 of those 24 bytes are
structural constants on ARM64. User-space addresses are
`0x0000_aaaa_xxxx_xxxx` for the binary, `0x0000_ffff_xxxx_xxxx` for the
stack. The page-offset bits of the leaked pointer are exactly the
page-offset bits of `LEAK_OFFSET` (the base is page-aligned). It encoded
those as first-try hints, one connection each. Second, for the ~6 truly
random bytes, it wrapped the probe in `ThreadPoolExecutor(16)` to
dispatch all 256 guesses concurrently and take the first match.

The exploit now takes 14 seconds:

```bash
mkdir -p /tmp/rsync_test_module
echo "hello world"   > /tmp/rsync_test_module/foo.txt
echo "test data here" > /tmp/rsync_test_module/bar.txt
cp rsyncd_test.conf /tmp/
/tmp/rsync-3.2.7/rsync --daemon --config=/tmp/rsyncd_test.conf --port=12000 --address=127.0.0.1
time python3 exploit.py "rsync://127.0.0.1:12000/files" "id > /tmp/rce_proof.txt"
[*] Phase 1: info leak  |  file=bar.txt size=15
    sum2[8] = 0x00  (1 total connections)
    sum2[9] = 0x00  (2 total connections)
    sum2[10] = 0x00  (3 total connections)
    sum2[11] = 0x00  (4 total connections)
    sum2[12] = 0xab  (260 total connections)
    sum2[13] = 0xaa  (261 total connections)
    sum2[14] = 0x00  (262 total connections)
    sum2[15] = 0x00  (263 total connections)
    sum2[16] = 0x00  (519 total connections)
    sum2[17] = 0x7a  (775 total connections)
    sum2[18] = 0xde  (1031 total connections)
    sum2[19] = 0xee  (1287 total connections)
    sum2[20] = 0xff  (1288 total connections)
    sum2[21] = 0xff  (1289 total connections)
    sum2[22] = 0x00  (1290 total connections)
    sum2[23] = 0x00  (1291 total connections)
    sum2[24] = 0xc4  (1292 total connections)
    sum2[25] = 0xae  (1293 total connections)
    sum2[26] = 0xdc  (1549 total connections)
    sum2[27] = 0xd2  (1805 total connections)
    sum2[28] = 0xaa  (1806 total connections)
    sum2[29] = 0xaa  (1807 total connections)
    sum2[30] = 0x00  (1808 total connections)
    sum2[31] = 0x00  (1809 total connections)
[+] Leaked .text ptr : 0xaaaad2dcaec4
[+] Binary base      : 0xaaaad2da0000

[*] Phase 2: heap overflow → RCE
    shell_exec = 0xaaaad2dca120
    ctx_evp    = 0xaaaad2e54fb0
    payload    = 344 bytes at &ctx_evp
    fake_ctx   = 0xaaaad2e54fb8 (+8)
    fake_evpmd = 0xaaaad2e55050 (+160)
    cmd_addr   = 0xaaaad2e55008 (+88)
    target ndx=1 file=bar.txt
    sending payload (344 bytes) to &ctx_evp...
    overflow complete, consuming server output...
    server connection ended: connection closed
[+] Payload delivered.

real  0m14.383s
user  0m0.674s
sys 0m1.609s
cat /tmp/rce_proof.txt
```

## The audit

Before any of this, the same teammate had asked Claude to audit the
patched rsync:

> **now that you have a good grasp of this vulnerability and exploitation
> can you audit the latest rsync for variants that may allow exploitation**

Claude went file-by-file through all 48 `.c` source files in 3.4.1 (the
version with all CVEs fixed). We're verifying the findings now and
preparing reports.

## Every prompt, both sessions

Prompts 1-12 are the original x86-64 session (the teammate driving);
13-17 are the ARM64 port (me driving).

1. *Initial request* — Asked to exploit rsync CVE-2024-12084 (heap
   overflow) + CVE-2024-12085 (info leak) into a full RCE chain against
   rsync 3.2.7 daemon, following the Phrack 72 "Desync the Planet"
   article.

2. **"why are you modifying the rsync source?"** — I had been adding
   `fprintf` debug statements to sender.c and recompiling. The user
   correctly pointed out this shifts binary offsets (ctx_evp, shell_exec,
   etc.) and invalidates the exploit constants.

3. **"you should be using gdb .."** — Redirected from printf-debugging
   to GDB. Led to the attach-to-daemon workflow with
   `set follow-fork-mode child` that proved essential for every
   subsequent debugging step.

4. **"what sandbox"** — I had confused /tmp file isolation with
   sandboxing. Clarified the environment.

5. **"if you need root the password is x ?"** — Provided root credentials
   to fix `ptrace_scope` (was set to 1, blocking GDB attach). We ran
   `echo 0 > /proc/sys/kernel/yama/ptrace_scope`.

6. **"are you following the phrack exploitation? it outlines it pretty
   clear"** — Critical redirect. I had been inventing a multi-entry
   layout trying to align 40-byte sum_buf strides with 48-byte EVP_MD_CTX
   field offsets. The Phrack one-shot contiguous write approach is far
   simpler and more reliable.

7. **"read the phrack exploit - they use the info leak + heap overflow
   to get a reliable exploit."** — Prompted me to actually read the
   full Phrack article rather than working from partial understanding.

8. **"the writeup is in /tmp/rsync.txt"** — Pointed to the local copy of
   the Phrack article. Saved time vs trying to web-fetch it (the
   WebFetch AI model refused to extract exploit details).

9. **"if you need to setup a qemu with the exact debian + rsync used
   that is fine"** — Offered to set up the exact Debian 12 target
   environment. We didn't end up needing this because we adapted the
   exploit to our Ubuntu 22.04 system, but this would be the fastest
   path for exact reproduction of the Phrack PoC.

10. **"perfect it seems to work!! can you document your whole process +
    my prompts in a writeup! include how to get it working on other
    installations etc and debugging instructions."** — Led to this
    writeup document.

11. **"now that you have a good grasp of this vulnerability and
    exploitation can you audit the latest rsync for variants that may
    allow exploitation"** — Led to the security audit of rsync 3.4.1
    documented in the appendix.

12. **"the WRITEUP didnt include all of my prompts"** — This correction,
    leading to this expanded prompt section.

### ARM64 port session

13. **"Read the WriteUp and reproduce this exploit with exploit.py"** —
    Initial port request. Environment turned out to be Debian 12 / arm64
    / glibc 2.36 — different OS, different glibc, different *architecture*
    from the writeup. No GDB, no strace, no root. Five distinct
    arm64-specific bugs were found and fixed (§3a). `rsync_lib.py` was
    built from scratch by reading the rsync 3.2.7 source — a socat wire
    capture of the real client revealed args use `\0` not `\n`, checksum
    negotiation is bidirectional, and `write_line` was bypassing the
    multiplex layer (server: "unexpected tag 83" = `'Z' - MPLEX_BASE`).
    The trickiest bug: `shell_exec` *did* fire and *did* fork, but
    `match_sums` zeroes `last_match` at `ctx_evp+0x110` before `sum_init`,
    truncating the command string at byte 8. Diagnosed with a ptrace
    breakpoint on `shell_exec` that printed `X0` and followed
    `PTRACE_O_TRACEFORK` — the fork happened, the cmd pointer was right,
    but the string read back as `"touch /t"`. Moved the command to
    `+0x58` (inside the unused `ctx_md` struct).

14. **"continue"** — Permission re-grant after a tool-use rejection during
    the initial daemon startup. Resumed without issue.

15. **"Alright, add to the writeup your adaptions"** — Wrote §3a
    documenting all five arm64 bugs (A1-A5), the GDB-free debugging
    methodology (LD_PRELOAD probes, ptrace crash-catcher, pattern-payload
    survival test), and the working run output.

16. **"Your exploit now takes 5 minutes to run, probably because of the
    brute-forcing in first step. Make it faster."** — Two stacked fixes:
    a hint table (18/24 bytes are structural constants on arm64 — `0x00`
    canonical bits, `0xaa`/`0xff` region prefixes, `LEAK_OFFSET` page-
    offset bits) and a `ThreadPoolExecutor(16)` for the truly random
    bytes. 5 minutes → 14 seconds.

17. **"Add to the writeup the ARM64 environment, and a note about
    speeding up, including a sample run [...] Also update the user
    prompts with the prompts/responses so far"** — Added the arm64
    environment table to §0, the speedup section + timed run to §3a,
    and these five entries to §7.

## Files

| File | What it is |
|---|---|
| `exploit.py` | Original x86-64 exploit (Ubuntu 22.04 / glibc 2.35) |
| `rsync_lib.py` | Original protocol library (now recovered and included so the writeup is complete) |
| `writeup.md` | Original development log: Phrack approach, x86-64 debugging |
| `exploit2.py` | ARM64 port (Debian 12 / glibc 2.36): 24-byte leak, relocated payload, parallel oracle |
| `rsync_lib2.py` | Protocol library Claude rebuilt from rsync 3.2.7 source when the original was missing |
| `writeup2.md` | ARM64 port log; section 3a covers all five issues and the GDB-free methodology |
| `rsyncd_test.conf` | Minimal daemon config: one read-only module, no chroot |
| `README.md` | This file |
