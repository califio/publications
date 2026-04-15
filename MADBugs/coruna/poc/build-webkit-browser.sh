#!/bin/bash
# Build vulnerable WebKit with browser frontend (MiniBrowser).
#
# The existing build at jsc-vuln/WebKit/WebKitBuild/Release/bin/jsc is JSCOnly
# (PORT=JSCOnly, ENABLE_MINIBROWSER=OFF). To run the HTML PoC you need WebCore +
# WebKit + MiniBrowser, which means the Mac port build via Xcode.
#
# PREREQUISITE: Xcode must be installed and selected. The system currently only
# has CommandLineTools. Get Xcode from the App Store, then:
#
#   sudo xcode-select -s /Applications/Xcode.app
#   sudo xcodebuild -license accept
#
# Then run this script. Build takes ~1-2hr on M-series.

set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WEBKIT="${WEBKIT:-$ROOT/jsc-vuln/WebKit}"
cd "$WEBKIT"

# Verify we're at the vulnerable commit
COMMIT=$(git rev-parse HEAD)
if [[ "$COMMIT" != "cbe051a9a3765825ccb92c790ec0e50c66c6bc51" ]]; then
    echo "ERROR: HEAD is $COMMIT, expected cbe051a9a376..."
    echo "Run: git checkout WebKit-7617.1.17.13.7"
    exit 1
fi

# Verify Xcode is selected (not just CommandLineTools)
if ! /usr/bin/xcodebuild -version >/dev/null 2>&1; then
    echo "ERROR: xcodebuild not found. Xcode is not installed or not selected."
    echo ""
    echo "Install Xcode from the App Store, then:"
    echo "  sudo xcode-select -s /Applications/Xcode.app"
    echo "  sudo xcodebuild -license accept"
    exit 1
fi
echo "Xcode: $(/usr/bin/xcodebuild -version | head -1)"

# Xcode 26 unbundled the Metal compiler. ANGLE needs it for mtl_internal_shaders.
if ! xcrun -find metal >/dev/null 2>&1; then
    echo "ERROR: Metal toolchain not installed (unbundled in Xcode 26+)."
    echo "Run: sudo xcodebuild -downloadComponent MetalToolchain"
    exit 1
fi
echo "Metal: $(xcrun metal --version 2>&1 | head -1)"

# This checkout (Nov 2023) only ships additions-SDK shims up to macosx14.0.
# Building against the macOS 26 SDK looks for macosx26.0-additions.sdk.
# The 14.0 shim is forward-compatible (SPI .tbd stubs). Symlink it.
SDKDIR="$WEBKIT/WebKitLibraries/SDKs"
SDKVER=$(xcrun --show-sdk-version | cut -d. -f1)
if [[ ! -e "$SDKDIR/macosx${SDKVER}.0-additions.sdk" ]]; then
    echo "Linking macosx${SDKVER}.0-additions.sdk → macosx14.0-additions.sdk"
    ln -sf macosx14.0-additions.sdk "$SDKDIR/macosx${SDKVER}.0-additions.sdk"
fi

# Verify vulnerability marker
if [[ -f Source/JavaScriptCore/dfg/DFGDesiredObjectProperties.cpp ]]; then
    echo "ERROR: DFGDesiredObjectProperties.cpp exists — this checkout is PATCHED."
    exit 1
fi
echo "Vulnerable: DFGDesiredObjectProperties.cpp absent ✓"

# The Mac port build outputs to WebKitBuild/Release/ (Xcode layout, not CMake).
# It will overwrite the existing JSCOnly build's WebKitBuild/Release/ directory.
# Move the JSCOnly build aside first.
if [[ -f WebKitBuild/Release/bin/jsc ]] && ! [[ -d WebKitBuild/Release/WebKit.framework ]]; then
    echo "Moving existing JSCOnly build aside → WebKitBuild/Release-jsconly"
    mv WebKitBuild/Release WebKitBuild/Release-jsconly
fi

# Xcode 26's parallel scheduler races WebInspectorUI ahead of JSC's derived-sources
# phase (WebInspectorUI shows "no dependencies" in the dep graph). Its resource-copy
# script dies on missing InspectorBackendCommands.js, killing the whole build before
# any real compilation. Stub the file; JSC overwrites it with the real one when it
# actually builds, and WebInspectorUI's copy phase re-runs every build anyway.
JSCPRIVHDR="$WEBKIT/WebKitBuild/Release/JavaScriptCore.framework/Versions/A/PrivateHeaders"
mkdir -p "$JSCPRIVHDR"
[[ -f "$JSCPRIVHDR/InspectorBackendCommands.js" ]] || \
    echo "// stub for build-order race" > "$JSCPRIVHDR/InspectorBackendCommands.js"

# Build. --release because Debug builds add assertion overhead that shifts the
# race window (see REPRODUCING.md). Mac port autodetected on Darwin.
echo ""
echo "Building... (output → build-webkit.log)"
# Bypass build-webkit and call xcodebuild directly. Two reasons:
#
# 1. Xcode 26's parallel scheduler ignores workspace project order. JSC's
#    "Generate Unified Sources" target has (no dependencies) declared, but it
#    needs WTF's wtf/Scripts/generate-unified-source-bundles.rb (installed by
#    WTF's Copy Headers phase). Old Xcode honored project order; Xcode 26 does
#    pure graph parallelism and races JSC ahead of WTF. Same disease as the
#    WebInspectorUI race above. So: build WTF scheme first.
#
# 2. build-webkit hardcodes scheme "Everything up to WebKit + Tools". We want
#    "Everything up to MiniBrowser" — skips TestWebKitAPI/DumpRenderTree/etc.
#    Less to build, less old-WebKit-vs-new-Xcode breakage to babysit.
#
# WK_RELOCATABLE_FRAMEWORKS=NO sidesteps a -dyld_env-in-OTHER_LDFLAGS construct
# (BaseXPCService.xcconfig:56) that Xcode 26 warns on. The baked-in dyld env is
# redundant: webkitdirs.pm sets DYLD_FRAMEWORK_PATH and __XPC_DYLD_FRAMEWORK_PATH
# at launch via run-minibrowser/run-safari.

XCBARGS=(
    -UseSanitizedBuildSystemEnvironment=YES
    -ShowBuildOperationDuration=YES
    -workspace "$WEBKIT/WebKit.xcworkspace"
    -configuration Release
    SYMROOT="$WEBKIT/WebKitBuild"
    OBJROOT="$WEBKIT/WebKitBuild"
    SHARED_PRECOMPS_DIR="$WEBKIT/WebKitBuild/PrecompiledHeaders"
    ARCHS=arm64
    SDKROOT=macosx
    WK_RELOCATABLE_FRAMEWORKS=NO
    # macOS 26 SDK libc++ removed _LIBCPP_ENABLE_ASSERTIONS (#error in
    # __configuration/hardening.h:25). CommonBase.xcconfig:71 sets it for
    # macOS 14+. _LIBCPP_HARDENING_MODE_FAST is the migration target.
    # Keeping hardening ON: production iOS 17 had it, so the exploit's
    # PIVOT was tuned against it.
    "WK_LIBCPP_ASSERTIONS_CFLAGS=-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST"
    # 2023 code + 2026 clang = a parade of -Wdeprecated-* (literal-operator
    # whitespace, etc.). These are warnings, not bugs. WTF/Configurations/
    # Base.xcconfig:70 sets GCC_TREAT_WARNINGS_AS_ERRORS=YES which makes them
    # fatal. Disable it; real errors are still errors.
    GCC_TREAT_WARNINGS_AS_ERRORS=NO
    # JSC links with -no_inits (zero static initializers, startup hygiene).
    # Xcode 26 clang/LTO codegen emits one (ltmp8 in a unified source bundle)
    # where 2023 clang didn't. It's a perf rule, not a correctness one. Drop it.
    WK_NO_STATIC_INITIALIZERS=
    # Xcode 26 ld refuses to let dyld-shared-cache-eligible dylibs (WebCore is one;
    # it ships in Safari) link to ineligible ones (our locally-built libANGLE-shared).
    # We're not building for the system cache. Opt out.
    LD_SHARED_CACHE_ELIGIBLE=NO
)

{
    echo "=== Phase 1: WTF (populates wtf/Scripts/ and wtf/*.h for JSC) ==="
    xcodebuild -scheme WTF "${XCBARGS[@]}"
    echo ""
    echo "=== Phase 2: Everything up to MiniBrowser ==="
    xcodebuild -scheme "Everything up to MiniBrowser" "${XCBARGS[@]}"
} 2>&1 | tee ../build-webkit.log

# Verify. Check for the actual binary, not the directory; xcodebuild creates
# empty bundle skeletons during "Create Product Structure" before any compile.
if [[ -f WebKitBuild/Release/MiniBrowser.app/Contents/MacOS/MiniBrowser ]]; then
    echo ""
    echo "✓ Build complete."
    echo ""
    echo "Run the HTML PoC:"
    echo "  Tools/Scripts/run-minibrowser --release file://$PWD/../../poc/cve-2024-23222.html"
    echo ""
    echo "Or with run-safari (uses your real Safari with the built WebKit):"
    echo "  Tools/Scripts/run-safari --release"
    echo "  # then navigate to file://$ROOT/poc/cve-2024-23222.html"
else
    echo "✗ Build failed — check ../build-webkit.log"
    exit 1
fi
