# CVE-2024-23222 PoC files

**TL;DR: just run `cve-2024-23222-rw.js`.** Everything else is a predecessor,
a debugging variant, or supporting infrastructure.

```bash
jsc-vuln/WebKit/WebKitBuild/Release/jsc cve-2024-23222-rw.js
# <0.2s/shot, ~89% on idle M-series at PIVOT=178000 (drops under load)
./retry-race.sh   # loop until hit
```

Full setup, build instructions, and expected output are in
[`REPRODUCING.md`](REPRODUCING.md). This file just tells you which JS does what.

---

## The lineage

The `cve-2024-23222-*.js` files are the **same trigger** at different points
in its evolution. They share ~400 lines and differ in defaults, instrumentation,
and how far past the type confusion they go. We kept the intermediate stages
because each one is the canonical input for a different debugging workflow.

```
cve-2024-23222-addrof-fakeobj.js   ← BASE: faithful cassowary extraction
  │                                   iPhone defaults (PIVOT=131072,
  │                                   WARMUP=16.7M). ~1% hit on M-series.
  │
  ├─→ cve-2024-23222-instrumented.js
  │     base + marker() calls bracketing the delete and the swap.
  │     For correlating main-thread events against the [tgcp] ring
  │     buffer printed by the JSC patch. Same iPhone defaults.
  │
  ├─→ cve-2024-23222-graphdump.js
  │     base + markers + isFinalTier() spin loop. With
  │     JSC_dumpGraphAtEachPhase=1 the FTL compile is ~100× slower,
  │     so PIVOT timing is meaningless; this version spins until
  │     the FTL actually installs before swapping. Use under
  │     TGCP_REPLAY_FIRST_FTL=1 (deterministic). This is what
  │     produced ftl-disasm-{safe,buggy}.log.
  │
  ├─→ cve-2024-23222-tuned.js
  │     base + M-series defaults (PIVOT=167000, WARMUP=250K, ~66×
  │     faster than cassowary's 16.7M busy-wait) + craftHeader()
  │     machinery so the fake object at phantom+16 has a valid
  │     JSCell header and can be safely addressOf()'d. 36 padding
  │     loops/side, ~73% hit rate. Stops at addrof/fakeobj.
  │
  └─→ cve-2024-23222-rw.js                                  ← USE THIS
        Full chain: addrof → fakeobj → heap groom → butterfly
        corruption → read64/write64. 47 padding loops/side widens
        the CFA→CFold gap to ~2000 ticks; PIVOT=178000, WARMUP=250K.
        ~89% idle / load-dependent. Self-tests by reading a JSCell header
        and round-tripping a write through scratch[0].
        │
        └─→ cve-2024-23222-rw-browser.html
              Same chain wrapped in a Worker and a <pre>. Run under
              MiniBrowser via run-minibrowser-poc.sh. Browser timing
              is noisier (event loop, DOM layout) so PIVOT shifts and
              hit rate drops to roughly 5/6. Auto-reloads on miss.
```

All four take the same positional args, so you can override defaults on any of
them: `$JSC <file>.js <warmup> <pivot> <gc_flush>`.

---

## Per-file table

| File | Purpose | Needs JSC patch | Defaults |
|---|---|---|---|
| **`cve-2024-23222-rw.js`** | **The PoC. Run this.** Full chain through read64/write64. | no | M-series, PIVOT=178K |
| **`cve-2024-23222-rw-browser.html`** | rw.js in a Worker, for MiniBrowser. Auto-reloads on miss. Use `run-minibrowser-poc.sh`. | no | M-series |
| `cve-2024-23222-tuned.js` | Stage 1 only (addrof/fakeobj). Smaller; useful when iterating on the trigger itself. 36 loops, narrower window. | no | M-series, PIVOT=167K |
| `cve-2024-23222-browser.js` + `.html` | Stage-1-only browser harness. No `describe()`/`addressOf()`; crafted header uses cassowary's hardcoded `[201527, 16783110]`. Verifies addrof via heap-pointer heuristic. 19/20 at PIVOT=150K (lighter top-level → less scheduler jitter). Superseded by `-rw-browser.html` for the full chain. | no | M-series, PIVOT=150K |
| `cve-2024-23222-addrof-fakeobj.js` | Faithful cassowary extraction. The historical baseline; what everything above was forked from. | no | iPhone (~1% on Mac) |
| `cve-2024-23222-instrumented.js` | base + `marker()` calls. Run alongside `JSC_TGCP_SLEEP_US=1` to interleave main-thread markers with `[tgcp]` ring-buffer prints from the patched JSC. | yes (`[tgcp]` prints) | iPhone |
| `cve-2024-23222-graphdump.js` | base + markers + `isFinalTier()` spin. For capturing FTL disasm under `JSC_dumpFTLDisassembly=1`. Spins instead of timing because graph-dumping makes compiles 100× slower. | yes (`TGCP_REPLAY_FIRST_FTL`) | irrelevant |
| `cve-2024-23222-tgcp-reach.js` | **Different.** Doesn't try to win the race. Just demonstrates that `tryGetConstantProperty` is reached with `set.size > 1` (the precondition). Three-phase IC training, then `optimizeNextInvocation()`. Watch stderr for `[tgcp] >>> MULTI-STRUCTURE FOLD <<<`. | yes (`[tgcp]` prints) | n/a |
| `probe-fakeobj.js` | One-off debugging tool. The original fakeobj verification was taking the wrong branch despite `typeof` printing `"object"`; this probes the fake without calling `addressOf()` on it (which dereferences whatever bytes happen to be at phantom+16 if the header isn't crafted). Superseded by `craftHeader()`. | no | — |
| `wasm-instance-probe.{js,lldb}` | Probes Wasm::Instance allocation sizes for the Stage 2 externref-padding investigation. The .lldb script's approach didn't work (see header); use the attach-to-PID method described in the .js header. | no | — |

---

## Support files

| | |
|---|---|
| `dfg-race-widen.patch` | JSC source patch against `cbe051a9a37`. Adds: (1) `JSC_TGCP_SLEEP_US=N` — `usleep(N)` after the cellLock release in `tryGetConstantProperty`, plus `[tgcp]` stderr prints; (2) `TGCP_REPLAY_FIRST_FTL=1` — record the first FTL compile's CFA-vs-CFold tgcp outcome and replay it deterministically on subsequent compiles, so the race "wins" every time without timing. (3) `marker()` builtin — main-thread checkpoint into a ring buffer the compiler thread also writes to. |
| `tgcp-instrumentation.patch` | Larger JSC patch: `mach_absolute_time()` ring buffer covering every tgcp call site (CFA, CFold, AI), dumped at exit. This is what produced the timing measurements quoted in the writeup (the ~1700-tick window, the σ ≈ 1200 jitter). |
| `retry-race.sh` | Process-relaunch loop. Each `jsc` process is a fresh JIT state, so retrying the race means relaunching. Defaults to `cve-2024-23222-rw.js` with M-series constants. |
| `ftl-disasm-safe.log` | FTL disassembly of `trigger()`, race **lost**. Captured with `PIVOT=50000` (delete fires way too early, both passes see S₃). `grep -c CheckArray` → 2. `valuesAtHead[D@569]` at BB#8 = `(HeapTop, TOP, TOP)`. The 4-instruction guard at offset 188 catches `trapArray` and OSR-exits. |
| `ftl-disasm-buggy.log` | Same function, race **won**. Captured under `TGCP_REPLAY_FIRST_FTL=1`. `grep -c CheckArray` → 0. `valuesAtHead[D@569]` at BB#8 = `(Array, ArrayWithDouble, Object: 0x1110903c8)`. `ldur Q0,[x0,#8]` at offset 204 is the addrof, `stur d0,[x0,#8]` at offset 264 is the fakeobj. 7 fewer instructions in BB#6 than the safe log (4 from D@614, 3 from D@621). |
| `REPRODUCING.md` | Full build-and-run doc. Build instructions for the vulnerable JSC, patch application, expected output, PIVOT sweep script. |
| `SAFARI-NOTES.md` | Why you can't run this against stock Safari on a current Mac (SIP, no archived installers). The realistic option is a macOS 14.2 VM with re-swept PIVOT. |
| `build-webkit-browser.sh` | Mac-port WebKit build (MiniBrowser, run-safari). **Needs full Xcode**; script checks and bails with instructions. Documented inline workarounds for 2026 toolchain vs. 2023 source (warning promotions, libc++ assertion macro renames, missing SDK shim). |
| `run-minibrowser-poc.sh` | Launches MiniBrowser at `cve-2024-23222-rw-browser.html`. Sets `DYLD_FRAMEWORK_PATH` and the `__XPC_*` mirrors so the WebContent child process inherits the build's frameworks instead of the system ones. |

---

## Why so many variants

Each one was the right tool for one question we had to answer along the way:

| Question | File that answered it |
|---|---|
| "Does tgcp even fire on this code shape?" | `tgcp-reach.js` — yes, `set.size=3` |
| "Does the race win ever?" | `addrof-fakeobj.js` + `retry-race.sh` — yes, ~1% |
| "When does the delete land relative to CFA/CFold?" | `instrumented.js` — `marker(10)/marker(11)` bracket the delete, ring buffer shows where it fell vs. `[CFA OK]`/`[CFold STRUCT-MISS]` |
| "What does the bad code actually look like?" | `graphdump.js` → `ftl-disasm-buggy.log` — `grep CheckArray` returns nothing |
| "Why is the fakeobj verification flaky?" | `probe-fakeobj.js` — `addressOf()` on the fake dereferences uncrafted bytes at phantom+16 |
| "How do I get this to 73% on a MacBook?" | `tuned.js` — PIVOT=167000, plus `craftHeader()` for clean verification |
| "How do I get past addrof/fakeobj to actual r/w?" | `rw.js` — heap groom for 32-byte adjacency, butterfly-points-at-butterfly, steerable pointer. 47 loops/side widened the gap to ~89% reliability. |
| "How do I run this in a browser?" | `rw-browser.html` (full chain, Worker) or `browser.js` + `.html` (stage 1 only). Discovered along the way: PIVOT is sensitive to *everything* before init(); a `describe()` host call adds enough scheduler perturbation to shift the window 17K iterations. |
