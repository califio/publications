#!/usr/bin/env python3
import argparse
import pathlib
import subprocess
import time


def container_pid(name: str) -> int:
    out = subprocess.check_output(
        ["podman", "inspect", "--format", "{{.State.Pid}}", name],
        text=True,
    ).strip()
    return int(out)


def read_rss_kb(pid: int) -> int:
    status = pathlib.Path(f"/proc/{pid}/status").read_text()
    for line in status.splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", default="httpd-hpack-cookie")
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()

    pid = container_pid(args.name)
    print(f"container={args.name} pid={pid}")
    start = time.monotonic()
    while True:
        rss_kb = read_rss_kb(pid)
        print(f"{time.monotonic() - start:8.3f}s rss={rss_kb / 1024:10.1f} MiB", flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
