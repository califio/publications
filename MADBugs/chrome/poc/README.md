# Chrome Renderer Exploit (Maglev Write-Barrier Elision + JSPI UAF)

Proof-of-concept files for a Chrome renderer exploit chain combining a
Maglev `BuildCheckSmi` write-barrier elision (type confusion where a
`HeapNumber` is truncated to a `Smi`-tagged compressed pointer) with a
JSPI cross-suspender stack UAF for code execution.

| File | Description |
|------|-------------|
| `poc0.js`, `poc1.js`, `poc2.js` | Minimal d8 repros of the trigger. Fires the bug but builds no usable primitives on its own. |
| `poc3.js` | The four memory primitives (`addrOf`, `fakeObj`, caged read, caged write) built step by step in one file, each checked against `%DebugPrint`. |
| `primitives/` | The same build-up, one file per primitive. See [`primitives/README.md`](primitives/README.md). |
| `poc.html` | The full renderer exploit chain for Chrome 146.0.7680.208 (Windows x64). |

> **Note**: **`DOUBLE_MAP` is per-build.** `HN_MAP`/`EMPTY_FA` are ReadOnlySpace and constant, but
> `DOUBLE_MAP` (the `PACKED_DOUBLE_ELEMENTS` JSArray map) lives in the startup snapshot and
> shifts per target/toolchain, so rederive it for your binary with
> `d8 --allow-natives-syntax -e '%DebugPrint([1.1])'` (low 32 bits of the map line). Known
> values: `0x1032999` for `poc.html`'s Chrome-for-testing 146.0.7680.208; `0x0100cf51` for
> release d8 on macOS arm64 / Linux x64; `0x0100cd59` for release d8 on Windows x64.

## Building V8

Target: **V8 14.6.202.33** - commit [`f09a912`](https://chromium.googlesource.com/v8/v8/+/f09a91282a26caa91d016c962d785d852cfdec36).

### Prerequisites

```sh
# Install depot_tools (if you don't have it already)
git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
export PATH="$PWD/depot_tools:$PATH"
```

### Fetch and build

```sh
fetch v8
cd v8
git checkout f09a91282a26caa91d016c962d785d852cfdec36
gclient sync

# Debug build (includes graph tracing, slow but useful for analysis)
./tools/dev/gm.py x64.debug

# Release build (fast, closer to Chrome's production config)
./tools/dev/gm.py x64.release
```

### Run the PoC

Every script needs `--allow-natives-syntax --maglev --no-turbofan`. The trigger
repros (`poc0`-`poc2`) are best read on a **debug** build; the primitives
(`poc3.js` and `primitives/`) must run on a **release** build, because a debug
build aborts at the write-barrier DCHECK before any primitive is built.

```sh
# Trigger on a debug build: Maglev graph shows the elided write barrier
./out/x64.debug/d8 --allow-natives-syntax --maglev --no-turbofan \
    --trace-maglev-graph-building --print-maglev-graph poc0.js

# poc2 on a debug build aborts fatally on the missing barrier (the bug's proof):
#   Fatal error in ../../src/heap/heap.cc ... Check failed: !WriteBarrier::IsRequired
./out/x64.debug/d8 --allow-natives-syntax --maglev --no-turbofan poc2.js

# Primitives on a release build: forges the fake array and self-checks
# addrOf / fakeObj / caged read / caged write against %DebugPrint
./out/x64.release/d8 --allow-natives-syntax --maglev --no-turbofan poc3.js
```

Set `DOUBLE_MAP` for your build first (see the note above). The reclaim in
`poc3.js` and `primitives/` is GC-timing dependent: an occasional run prints
`[FAIL]` and exits cleanly, so just re-run it.
