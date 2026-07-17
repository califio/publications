// poc1.js — Step 2: plant the "constant" fact (CheckSmi gone, new deopt)
//
// Blog section: "The Trigger -> Building facts around x" / "Overcome CheckSmiUntag".
// Storing x into the kConst ContextCell `bT` gives x a constant alternative,
// which defeats the CheckSmi. But the kConst store now compares x against the
// constant 11, and to do so it emits CheckedSmiUntag, which demands x be a
// *physical* Smi. We trigger with a HeapNumber, so this deopts instead.
//
// Run:
//   d8 --print-bytecode --allow-natives-syntax --print-maglev-graph \
//      --trace-maglev-graph-building --trace-deopt poc1.js
//
// Expected: no CheckSmi, but an eager deopt at CheckedSmiUntag
//   "[bailout (kind: deopt-eager, reason: not a Smi) ...]".

const f64src = new Float64Array(1);
f64src[0] = 11.0;

let bT = 11;
var cT = 0;
cT = 1;

function bt_ct(x) {
  bT = x;
  cT = x;
}

%PrepareFunctionForOptimization(bt_ct);
bt_ct(11);
bt_ct(11);
%OptimizeMaglevOnNextCall(bt_ct);
bt_ct(f64src[0]);
