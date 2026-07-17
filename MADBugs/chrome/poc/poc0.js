// poc0.js — Step 1: the naive store (does NOT trigger yet)
//
// Blog section: "The Trigger -> Naively store a HeapNumber".
// A bare `cT = x` store. `x` arrives as a fresh tagged parameter with no
// facts attached, so Maglev cannot extract an int32 constant from it and
// keeps the CheckSmi guard. The bug does not fire.
//
// Run:
//   d8 --allow-natives-syntax --maglev --no-turbofan \
//      --trace-maglev-graph-building --print-maglev-graph poc0.js
//
// Expected: the graph still contains `CheckSmi [n2]` before the store.
// This is the baseline we have to defeat.

const f64src = new Float64Array(1);
f64src[0] = 11.0; // Get a HeapNumber

var cT = 0; cT = 1; // Get cT to be a Smi

function ct_only(x) {
  cT = x;
}

%PrepareFunctionForOptimization(ct_only);
ct_only(11);
ct_only(11);
%OptimizeMaglevOnNextCall(ct_only);
ct_only(f64src[0]);
