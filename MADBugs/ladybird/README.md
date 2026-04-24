# Ladybird Browser RCE via WebAssembly Shared Memory UAF

A use-after-free in Ladybird's WebAssembly shared-memory implementation gives any web page a 64 KiB read/write window over freed heap, which we extend into full arbitrary read/write and a native function-pointer hijack in the WebContent process. WebContent is not sandboxed in the default build, so this is user-level code execution on page load: the end-to-end exploit calls `uname(2)` and renders the kernel version string back onto the attacking page, with `system()` available the same way for arbitrary shell commands.

PoC video: https://youtu.be/NQxvMRqS_9o

Reported to the Ladybird maintainers on 2026-04-21 and, at their request, filed publicly as [LadybirdBrowser/ladybird#9062](https://github.com/LadybirdBrowser/ladybird/issues/9062) on 2026-04-23 (their security policy treats pre-release bugs as openly disclosable). The bug is unpatched in master as of [`36e6323d`](https://github.com/LadybirdBrowser/ladybird/commit/36e6323d1f2248a21f5b1a69790c1a06f1d97cd9) (2026-04-23).

### Artifacts

| | |
|---|---|
| [`README.md`](README.md) | this advisory |
| [`WRITEUP.html`](WRITEUP.html) | long-form teaching walkthrough of the full chain, with diagrams and a §11 mapping each stage to the Safari/Chrome mitigation that would stop it |
| [`blog.md`](blog.md) | the [MAD Bugs blog post](https://blog.calif.io/t/madbugs) draft |
| [`bug1-minimal.html`](bug1-minimal.html) | minimal UAF reproducer (two grows + reclaim-and-compare) |
| [`bug1-wasm-shared-uaf-ptrleak.html`](bug1-wasm-shared-uaf-ptrleak.html) | UAF + ASLR defeat (leaks GC-heap pointers through the dangling view) |
| [`bug1-rce-uname.html`](bug1-rce-uname.html) | full RCE chain: UAF → addrof/fakeobj → arb R/W → `uname(2)` rendered on the page |
| [`bug1-rce-calc.html`](bug1-rce-calc.html) | same chain ending in `system("open -a Calculator")` |

A separate long-form walkthrough of every step in the exploit, written for systems programmers who have not done JS-engine work before, is in [`WRITEUP.html`](WRITEUP.html). Its [§11](WRITEUP.html#s11) maps each stage of this chain onto the mitigation that would stop it in current Safari (Gigacage, arm64e PAC, sandbox) and Chrome (V8 heap sandbox, code-pointer indirection, sandbox); the absence of those layers is exactly what makes Ladybird a clean target for learning the textbook primitive ladder before tackling production-engine bypasses.

### Summary

A `Uint32Array` created over the `SharedArrayBuffer` returned by a shared `WebAssembly.Memory` keeps a stale cached data pointer after the memory is grown twice. The asm-interpreter fast path for `array[i]` and `array[i] = v` dereferences that cached pointer with only an `index < length` bounds check, so the page reads and writes a freed 128 KiB mimalloc block at will.

```js
const mem  = new WebAssembly.Memory({initial: 1, maximum: 1000, shared: true});
const view = new Uint32Array(mem.buffer);
mem.grow(1);     // view's cached pointer refreshed; m_buffer replaced
mem.grow(100);   // only the *new* buffer's views refreshed; ByteBuffer reallocates; view dangling
view[0];                       // UAF read
view[0] = 0x41414141|0;        // UAF write
```

Ladybird does not gate `shared: true` behind cross-origin isolation, so the trigger is reachable from any origin with no special headers.

### Root cause

The `TypedArrayBase` cell caches a raw `m_data = buffer.data() + byte_offset` for views on fixed-length buffers ([`Libraries/LibJS/Runtime/TypedArray.h:92-110`](https://github.com/LadybirdBrowser/ladybird/blob/36e6323d1f2248a21f5b1a69790c1a06f1d97cd9/Libraries/LibJS/Runtime/TypedArray.h#L92-L110)), and the asm interpreter uses it directly:

```
.try_typed_array:
    load64 t5, [t3, TYPED_ARRAY_CACHED_DATA_PTR]   ; m_data, +104
    branch_zero t5, .try_typed_array_slow
    load32 t0, [t3, TYPED_ARRAY_ARRAY_LENGTH_VALUE]
    branch_ge_unsigned t4, t0, .slow               ; index < length, nothing else
    load8  t0, [t3, TYPED_ARRAY_KIND]
    ...
```
([`Libraries/LibJS/Bytecode/AsmInterpreter/asmint.asm:1481-1495`](https://github.com/LadybirdBrowser/ladybird/blob/36e6323d1f2248a21f5b1a69790c1a06f1d97cd9/Libraries/LibJS/Bytecode/AsmInterpreter/asmint.asm#L1481-L1495), and the matching load path at [`:1720-1740`](https://github.com/LadybirdBrowser/ladybird/blob/36e6323d1f2248a21f5b1a69790c1a06f1d97cd9/Libraries/LibJS/Bytecode/AsmInterpreter/asmint.asm#L1720-L1740))

When a wasm `Memory` grows, `MemoryInstance::grow` calls `ByteBuffer::try_resize` ([`Libraries/LibWasm/AbstractMachine/AbstractMachine.h:487-504`](https://github.com/LadybirdBrowser/ladybird/blob/36e6323d1f2248a21f5b1a69790c1a06f1d97cd9/Libraries/LibWasm/AbstractMachine/AbstractMachine.h#L487-L504)), which may free the old block and allocate a new one. The grow callback then runs `Memory::refresh_the_memory_buffer`:

```cpp
auto& buffer = memory.value()->m_buffer;
if (buffer->is_fixed_length()) {
    if (!buffer->is_shared_array_buffer()) {
        MUST(JS::detach_array_buffer(vm, *buffer, ...));
    } else {
        buffer->refresh_cached_typed_array_view_data_pointers();   // <-- only for *current* m_buffer
    }
    buffer = create_a_fixed_length_memory_buffer(vm, realm, address, ...);   // <-- then replace it
}
```
([`Libraries/LibWeb/WebAssembly/Memory.cpp:200-225`](https://github.com/LadybirdBrowser/ladybird/blob/36e6323d1f2248a21f5b1a69790c1a06f1d97cd9/Libraries/LibWeb/WebAssembly/Memory.cpp#L200-L225))

For a non-shared memory, the old buffer is detached, which nulls every view's `m_data`. For a shared memory the spec forbids detaching, so [`d8aee7f1e6`](https://github.com/LadybirdBrowser/ladybird/commit/d8aee7f1e6d59b958833425067086defa00b7f4c) (2026-04-20) added the `refresh_cached_typed_array_view_data_pointers()` call instead. The refresh walks `m_cached_views` on the `ArrayBuffer` it is called on ([`Libraries/LibJS/Runtime/ArrayBuffer.cpp:264-273`](https://github.com/LadybirdBrowser/ladybird/blob/36e6323d1f2248a21f5b1a69790c1a06f1d97cd9/Libraries/LibJS/Runtime/ArrayBuffer.cpp#L264-L273)), but the very next line replaces `m_buffer` with a fresh wrapper, so on the *next* grow only that fresh wrapper's (empty) view set is walked. Any view created on the original buffer is never refreshed again, while the `ByteBuffer` it points into has moved.

Before `d8aee7f1e6` there was no refresh call at all and a single `grow()` was sufficient; that commit fixed the one-grow case while leaving the two-grow case open.

The old `SharedArrayBuffer` itself remains correct (it wraps a `ByteBuffer*`, not a raw data pointer), so slow-path accesses through `viewed_array_buffer()->buffer().data()` see the right bytes. Only the cached `m_data` is stale, and the asm fast path is the only consumer that trusts it without re-deriving.

A consequence worth noting: **AddressSanitizer does not detect this bug.** ASAN instruments compiler-emitted loads and stores; the dereference of `m_data` happens in hand-written assembly at `asmint.asm:1724`, which has no shadow-memory check. Every C++ path (`TypedArray.prototype.slice`, `Atomics.load`, the `GetByValue` slow helper) goes through `viewed_array_buffer()->buffer().data()` and correctly resolves to the relocated storage, so there is no instrumented access to the freed block at all. Under the `Sanitizer` preset the [`bug1-minimal.html`](bug1-minimal.html) trigger reads quarantine garbage and ASAN stays silent; the reclaim-and-compare in that PoC is the way to demonstrate the UAF.

### From UAF to renderer code execution

The UAF window is at an unknown address X, the freed block is in mimalloc's 128 KiB large-object bin, and packed JS array growth never produces an allocation in that bin (1.5x growth: 8, 12, 18 ... 11623, 17434), so the textbook "spray `[obj, obj, ...]` and read NaN-boxed pointers" reclaim does not work here. The chain we actually use:

1. **`addrof` / `fakeobj`.** `Function.prototype.apply(thisArg, proxy)` with a `Proxy` whose `length` is 16384 routes through `create_list_from_array_like`, which does `RootVector<Value>::ensure_capacity(16384)` → `mi_malloc(131072)`, reclaiming X. The Proxy `get` trap then runs once per index *while the Vector backing aliases `viewA`*: reading `viewA[2*i..2*i+1]` after returning an object yields its NaN-boxed address (`addrof`), and overwriting `viewA[0..1]` on the final iteration plants a forged Value into `arguments[0]` of the callee (`fakeobj`).

2. **1-byte arbitrary R/W.** `fakeobj(addrof(holder)+16)` for two adjacent 64-byte `{}` cells. The asm `GetByValue`/`PutByValue` typed-array fast path checks one bit at `+10` then trusts four fields; with this 16-byte misalignment those fields resolve as: flags = byte 2 of `holder.m_named_properties` (need bit 19 of `holder`'s address set; spray pairs across HeapBlocks until one satisfies it), `array_length` = bytes 4-7 of `next.m_shape` (= 1 on this platform), `kind` = byte 4 of `next.m_private_elements` (= 0 = `Uint8`), and `m_data` = `next.inline[1]`, which JS can retarget per access via `next.b = bitsToDouble(addr)`. `fake[0]` then reads or writes one byte at any 48-bit address.

3. **Stable arbitrary R/W.** The 1-byte primitive is GC-unsafe (the forged pointer is misaligned inside a cell), so it is used exactly once, in an allocation-free burst, to corrupt two real `Uint32Array`s: `rw1.m_data = addrof(rw2)`, both lengths set to `0x7FFFFFFF`. From then on `rw1[26..27]` retargets `rw2.m_data` and `rw2[0]` is a clean 32-bit read/write at any address, with both arrays remaining valid GC cells.

4. **Native call.** Read `viewA`'s vtable to derive the `liblagom-js` base, read `getenv` from its `__got`, and compute `uname` (and `system`) in the dyld shared cache. Locate `VM*` via `HeapBlock::m_heap` (`addrof(obj) & ~0x3FFF` → `Heap*` → `VM*`). Overwrite `Array.isArray.m_native_function` (offset 96 in the `RawNativeFunction` cell) with `&uname`. The asm `Call` handler's `.enter_raw_native` path is `mov x0, x20 /*VM*/; blr m_native_function`, so `Array.isArray(0)` invokes `uname(VM*)`. `uname` writes a `struct utsname` (1280 bytes) into the VM object and returns with `x1 = 0`, which the asm interprets as a normal (non-throwing) return without touching the clobbered region. Read the five 256-byte fields back via `r32`, restore `VM[0..1279]` and `m_native_function`, and print the result to the page.

`system()` is reached the same way: write the command string at `VM[0]`, swap the function pointer, call `Array.isArray(0)`.

The reliability work that took this from "works under lldb" to 20/20 in headless mode (allocation ordering before the UAF, splitting stage 1 / stage 2 across `<script>` tags so the bytecode constant pool does not steal X, the `fakeobj` retry-on-miss check, post-exploit pointer cleanup so VM teardown does not fault) is covered step by step in [`WRITEUP.html`](WRITEUP.html) §4.3-§8.

### PoC

[`bug1-minimal.html`](bug1-minimal.html) is the smallest reproducer: trigger the UAF, reclaim the freed block with `new ArrayBuffer(131072)`, and show the dangling view aliasing it.

```
view[0] = 0xdeadbeef
>>> UAF CONFIRMED: dangling view aliases the reclaiming ArrayBuffer <<<
reclaim[0] after write-through-view = 0x41414141
```

[`bug1-wasm-shared-uaf-ptrleak.html`](bug1-wasm-shared-uaf-ptrleak.html) demonstrates the UAF and ASLR defeat alone:

```
Created viewA on shared wasm memory bufA (64 KiB)
Grew memory 1->2->102 pages; viewA.cached_data_ptr now dangling over freed 128 KiB block
...
  [1] 0xfff900014b78c300  -> OBJECT @ 0x14b78c300
  [2] 0xfff900014b78c340  -> OBJECT @ 0x14b78c340
>>> ASLR DEFEAT: leaked 15 GC heap pointers <<<
```

[`bug1-rce-uname.html`](bug1-rce-uname.html) is the full chain. Loading it in a release build of Ladybird produces, on the page itself:

```
[attempt 1] addrof stable: 0x14d338380
holder@0x14deb0040 next@0x14deb0080 fake@0x14deb0050 (adj=122)
rw1@0x14dea40b0 rw2@0x14dea4120 viewA@0x14dea4200 Array.isArray@0x14dd9b238
viewA vtable = 0x105d92300
viewA.m_data = 0x415aabb0000

>>> ARBITRARY R/W ACHIEVED <<<
HeapBlock@0x14deb0000 -> Heap@0x8a10e0970
VM @ 0x8a10dd000 (heap_off=14704, refcount=2, running_ec=0x14ca785a8)
liblagom-js base = 0x10596c000
Mach-O magic = 0xfeedfacf (expect 0xfeedfacf)
getenv = 0x1848e6eb8
uname  = 0x1848fa000  insn[0]=0xd503237f
system = 0x18495c438  insn[0]=0xd503237f
Array.isArray @ 0x14dd9b238  m_native_function=0x1059d44fc
  flags = 0x83

======== uname -a ========
Darwin mac.lan 25.4.0 Darwin Kernel Version 25.4.0: Thu Mar 19 19:26:07 PDT 2026; root:xnu-12377.101.15~1/RELEASE_ARM64_T6031 arm64
==========================
```

20/20 runs reach the `uname` output. The exploit retries the UAF in-process if the `RootVector` reclaim misses (pinning the wrong slot with a held `ArrayBuffer(131072)` so the next attempt gets a different free block), but on the test build every run succeeded on the first attempt. The WebContent process occasionally faults during teardown after the page has already rendered; this is cosmetic.

To reproduce:

```bash
git clone https://github.com/LadybirdBrowser/ladybird.git
cd ladybird && git checkout 36e6323d
./Meta/ladybird.py build
./Meta/ladybird.py run Ladybird --headless=text \
    file:///path/to/MADBugs/ladybird/bug1-rce-uname.html
```

The exploit hard-codes three build-specific constants in stage 2: the `Uint32Array` vtable's distance from the dylib base (`0x426300`), the `__got` slot for `getenv` (`0x3FCE68`), and the `getenv`/`uname`/`system` deltas in the dyld shared cache. The first two move with every Ladybird rebuild; the comments in the PoC show the `nm`/`dyld_info` one-liners to recompute them. If they are wrong the Mach-O magic check fails and the PoC aborts before the native call. Everything else (object field offsets, `VM*` location, `m_native_function` offset) is resolved at runtime.

### Impact

**Vulnerability type:** use-after-free read/write in the WebContent renderer process, reachable from untrusted web content with no user interaction beyond page load and no special HTTP headers.

**Affected:** Ladybird master from at least [`d8aee7f1e6`](https://github.com/LadybirdBrowser/ladybird/commit/d8aee7f1e6d59b958833425067086defa00b7f4c) (2026-04-20) onward in the two-grow form shown here, and earlier builds (back to the introduction of the shared-memory fixed-length path) in the simpler one-grow form. There is no shipping Ladybird release yet, so the practical exposure is developers, nightly users, and downstream embedders of LibWeb/LibJS.

**What an attacker gets:** arbitrary native code execution as the WebContent process. The PoC stops at `uname` for demonstration purposes; `system()` is computed alongside it and works identically. Ladybird's WebContent process is not sandboxed on macOS in the default build, so this is effectively user-level code execution on page visit.

### Suggested fix

The narrow fix is to keep refreshing every `SharedArrayBuffer` that has ever wrapped this memory's data, not just the current `m_buffer`. Because each grow creates a new `SharedArrayBuffer` and the old ones remain reachable from script indefinitely, `Memory` should hold a weak set of all buffers it has handed out and walk every entry's `refresh_cached_typed_array_view_data_pointers()` after the underlying `ByteBuffer` moves.

A more robust alternative is to stop creating a fresh fixed-length `SharedArrayBuffer` per grow and instead keep a single growable `SharedArrayBuffer` whose `[[ArrayBufferData]]` is updated in place, which is what the `else` branch at [`Memory.cpp:226-235`](https://github.com/LadybirdBrowser/ladybird/blob/36e6323d1f2248a21f5b1a69790c1a06f1d97cd9/Libraries/LibWeb/WebAssembly/Memory.cpp#L226-L235) already does for the resizable case. That removes the "which buffer's views do we refresh" question entirely.

Independently, Ladybird should gate `WebAssembly.Memory({shared: true})` and `SharedArrayBuffer` behind cross-origin isolation (`Cross-Origin-Opener-Policy` + `Cross-Origin-Embedder-Policy`). That would not fix this bug, but it is the standard mitigation surface that other engines rely on and it would have kept the trigger off the open web.

### Disclosure timeline

- 2026-04-21: Reported to the Ladybird maintainers with PoCs
- 2026-04-23: Filed publicly at maintainers' request as [ladybird#9062](https://github.com/LadybirdBrowser/ladybird/issues/9062)
- 2026-04-24: Published as part of MAD Bugs
