<?php
// Vulnerable endpoint for the remote PoC. CachedData::unserialize() is one
// statement: deserialize an inner payload, set one property on the result.
// With an attacker-crafted inner payload of O:8:"stdClass":8:{...}, that
// single write triggers the nTableSize 8→16 resize and frees the property
// arData buffer that the outer var_hash still indexes into.

error_reporting(0);

class CachedData implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        unserialize($data)->x = 0;
    }
}

echo serialize(@unserialize($_REQUEST['cook']));
