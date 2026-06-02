#!/usr/bin/env /usr/bin/python3
"""
Monitor nginx worker RSS from inside the container.
Run via: docker exec nginx-h2-poc /usr/bin/python3 /poc/monitor_rss.py
"""
import subprocess
import time
import sys


def get_worker_pid():
    out = subprocess.check_output(
        ["pgrep", "-f", "nginx: worker"], text=True
    ).strip().split("\n")
    return out[0]


def main():
    pid = get_worker_pid()
    print(f"Monitoring nginx worker PID {pid}")
    peak = 0
    t0 = time.monotonic()
    while True:
        try:
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                        rss_mb = rss_kb / 1024
                        peak = max(peak, rss_mb)
                        elapsed = time.monotonic() - t0
                        print(f"[{elapsed:7.1f}s] RSS: {rss_mb:8.1f} MB  "
                              f"(peak: {peak:.1f} MB)")
                        break
            time.sleep(0.5)
        except (FileNotFoundError, ProcessLookupError):
            print(f"\nWorker process {pid} exited (likely OOM-killed)")
            print(f"Peak RSS observed: {peak:.1f} MB")
            sys.exit(0)
        except KeyboardInterrupt:
            print(f"\nPeak RSS observed: {peak:.1f} MB")
            sys.exit(0)


if __name__ == "__main__":
    main()
