// Probe for Wasm::Instance allocation sizing.
//
// Creates three modules: cassowary's full module (8 globals + 1 table),
// a trimmed one (3 globals, no externref padding, no table), and a middle
// one (3 globals, 1 table — keeps the table, drops the externrefs). Prints
// JSWebAssemblyInstance addresses so the paired lldb script can walk
// JSWebAssemblyInstance → m_instance → malloc_size().
//
// Run under lldb:
//   lldb -s poc/wasm-instance-probe.lldb -- jsc-vuln/WebKit/WebKitBuild/Release/jsc poc/wasm-instance-probe.js

// — cassowary's module verbatim —
//   sections: type, func, table(1×externref min=1), memory, global(8), export, code
//   globals: v128(0x33×16), i64(0xabcdabcdabcdabcd), v128(0x33×16), 5×externref(null)
//   exports: edfy(global 1), memory, btl(func 0: global.get 1), alt(func 1: global.set 1)
const CASSOWARY = new Uint8Array([
  0,97,115,109, 1,0,0,0,
  1,9,2, 96,0,1,126, 96,1,126,0,                       // type: ()→i64, (i64)→()
  3,3,2,0,1,                                            // func: type 0, type 1
  4,4,1,111,0,1,                                        // table: 1× externref, min 1
  5,3,1,0,1,                                            // memory: 1 page
  6,82,8,                                               // global: 8 entries, 82 bytes
    123,1, 253,12, 51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51, 11,  // v128 mut = 0x33×16
    126,1, 66, 205,215,182,222,218,249,234,230,171,127, 11,              // i64  mut = 0xabcd…abcd
    123,1, 253,12, 51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51, 11,  // v128 mut = 0x33×16
    111,1, 208,111, 11,                                 // externref mut = null
    111,1, 208,111, 11,
    111,1, 208,111, 11,
    111,1, 208,111, 11,
    111,1, 208,111, 11,
  7,29,4,                                               // export: 4 entries
    4,101,100,102,121, 3,1,                             //   "edfy" → global 1
    6,109,101,109,111,114,121, 2,0,                     //   "memory" → memory 0
    3,98,116,108, 0,0,                                  //   "btl" → func 0
    3,97,108,116, 0,1,                                  //   "alt" → func 1
  10,13,2,                                              // code: 2 funcs
    4,0, 35,1, 11,                                      //   func 0: global.get 1
    6,0, 32,0, 36,1, 11,                                //   func 1: local.get 0; global.set 1
]);

// — trimmed: no table, only the 3 working globals, same exports/funcs —
const TRIMMED = new Uint8Array([
  0,97,115,109, 1,0,0,0,
  1,9,2, 96,0,1,126, 96,1,126,0,
  3,3,2,0,1,
  // (no table section)
  5,3,1,0,1,
  6,57,3,                                               // global: 3 entries, 57 bytes
    123,1, 253,12, 51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51, 11,
    126,1, 66, 205,215,182,222,218,249,234,230,171,127, 11,
    123,1, 253,12, 51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51, 11,
  7,29,4,
    4,101,100,102,121, 3,1,
    6,109,101,109,111,114,121, 2,0,
    3,98,116,108, 0,0,
    3,97,108,116, 0,1,
  10,13,2,
    4,0, 35,1, 11,
    6,0, 32,0, 36,1, 11,
]);

// — middle: keep the table, drop the externrefs —
const MID = new Uint8Array([
  0,97,115,109, 1,0,0,0,
  1,9,2, 96,0,1,126, 96,1,126,0,
  3,3,2,0,1,
  4,4,1,111,0,1,                                        // table kept
  5,3,1,0,1,
  6,57,3,
    123,1, 253,12, 51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51, 11,
    126,1, 66, 205,215,182,222,218,249,234,230,171,127, 11,
    123,1, 253,12, 51,51,51,51,51,51,51,51,51,51,51,51,51,51,51,51, 11,
  7,29,4,
    4,101,100,102,121, 3,1,
    6,109,101,109,111,114,121, 2,0,
    3,98,116,108, 0,0,
    3,97,108,116, 0,1,
  10,13,2,
    4,0, 35,1, 11,
    6,0, 32,0, 36,1, 11,
]);

// addressOf() in stock jsc.cpp returns the address as a Number (the bits
// reinterpreted as an IEEE-754 double). Pun it back through a typed-array
// overlay.
let _f64 = new Float64Array(1), _u64 = new BigUint64Array(_f64.buffer);
let addr = (o) => { _f64[0] = addressOf(o); return _u64[0]; };
let hex  = (n) => (BigInt.asUintN(64, BigInt(n))).toString(16).padStart(12, '0');

function inst(name, bytes, expectGlobals, expectTables) {
  let mod = new WebAssembly.Module(bytes);
  let i = new WebAssembly.Instance(mod, {});
  // sanity: btl() returns the i64 init constant (as a signed BigInt)
  let v = i.exports.btl();
  print(`[${name}]  globals=${expectGlobals} tables=${expectTables}  ` +
        `JSWebAssemblyInstance @ 0x${hex(addr(i))}  btl()=0x${hex(v)}`);
  return i;
}

print("--- module instantiation ---");
let cass = inst("cassowary", CASSOWARY, 8, 1);
let mid  = inst("mid      ", MID,       3, 1);
let trim = inst("trimmed  ", TRIMMED,   3, 0);

// keep refs alive past the breakpoint
globalThis.__keep = [cass, mid, trim];
print("--- ready for lldb inspection ---");
// readline() blocks so lldb can attach/inspect at leisure
if (typeof readline === "function") readline();
