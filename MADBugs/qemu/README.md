# QEMU and UTM Escape via virtio-gpu (ZDI-CAN-27578)

An integer overflow in QEMU's `virtio-gpu` device (`hw/display/virtio-gpu.c:calc_image_hostmem`) lets a guest create a 2D resource whose pixman buffer is a few hundred bytes while `res->width` is `0x40000001`, giving forward OOB read/write up to ~4 GB past the buffer. The read primitive is novel: the guest points the active scanout at host memory via `set_scanout`, connects to QEMU's own VNC server through SLIRP loopback (`10.0.2.2:5900`), and reads QEMU's address space back as pixel data. The write primitive then hijacks pixman's `_global_implementation` (or QEMU's `__la_symbol_ptr[g_free]` on UTM's memfd layout) to call `system()`.

End result: a single static aarch64 binary inside an unprivileged guest process opens Calculator on the macOS host.

PoC video: https://www.youtube.com/watch?v=WWfxGyWoXrc

| | |
|---|---|
| **Affected** | QEMU 8.1.0 – 10.2.3 (all builds with `virtio-gpu-pci`); UTM ≤ 4.7.5 |
| **Fixed in** | QEMU 11.0.0 ([`c035d5ea`](https://github.com/qemu/qemu/commit/c035d5eadf400670593a76778f98f052d7482968)), **not backported to 10.x** |
| **ZDI** | ZDI-CAN-27578 |
| **Tested on** | QEMU 10.0.2, UTM 4.7.5, macOS 26.4.1 (Tahoe), Apple Silicon |
| **Prerequisite** | VNC reachable from guest (default on Proxmox/libvirt/OpenStack; one-line config on UTM) |

## Artifacts

| | |
|---|---|
| [`blog.md`](blog.md) | the [MAD Bugs blog post](https://blog.calif.io/t/madbugs) |
| [`WRITEUP.md`](WRITEUP.md) | full technical advisory: vuln details, five-phase chain, UTM SPICE-safe variant, memfd-layout `g_free` fallback, offsets, prompt log |
| [`chain.svg`](chain.svg) | annotated diagram of the five-phase chain |
| [`exploit.c`](exploit.c) | standalone QEMU PoC (homebrew pixman, no SPICE) |
| [`exploit_utm.c`](exploit_utm.c) | UTM.app PoC (SPICE-safe, pixman + QEMU fingerprints, `g_free` fallback) |
| [`exploit_linux.c`](exploit_linux.c) | Linux aarch64 host variant |
| [`run_poc_macos.sh`](run_poc_macos.sh) | one-shot: build vulnerable QEMU 10.0.2 + HVF, build exploit, pop calc |
| [`run_poc_utm.sh`](run_poc_utm.sh) | UTM.app VM provisioner + launcher |
| [`run_poc_linux.sh`](run_poc_linux.sh) | same, Linux host |

## Quick start

macOS arm64, Homebrew installed:

```bash
./run_poc_macos.sh        # ~5 min: deps, QEMU 10.0.2, exploit, initramfs
./run_poc_macos.sh run    # ~30 s from boot to Calculator
```

UTM.app (requires `-vnc :0` in the VM's QEMU arguments):

```bash
./run_poc_utm.sh          # build exploit, provision 'exploit-test' VM
./run_poc_utm.sh run      # start via utmctl; watch the serial console in UTM
```

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
