#!/usr/bin/env python3
"""
Monitor the Pingora lab process RSS from inside the container.

Run via:
  docker exec pingora_hpack_lab python3 /poc/monitor_rss.py
"""
import os
import subprocess
import time


def find_pid():
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as f:
                comm = f.read().strip()
            if "pingora-hpack" in comm:
                return pid
        except OSError:
            pass
    return "1"


def rss_kib(pid):
    with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def cgroup_current():
    for path in ("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory/memory.usage_in_bytes"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return int(f.read().strip())
        except OSError:
            pass
    return None


def main():
    pid = find_pid()
    print(f"Monitoring Pingora PID {pid} (Ctrl-C to stop)", flush=True)
    peak = 0
    while True:
        rss = rss_kib(pid)
        peak = max(peak, rss)
        cg = cgroup_current()
        cg_text = "" if cg is None else f" cgroup={cg / 1024 / 1024:.1f}MiB"
        print(
            f"rss={rss / 1024:.1f}MiB peak={peak / 1024:.1f}MiB{cg_text}",
            flush=True,
        )
        time.sleep(1)


if __name__ == "__main__":
    main()
