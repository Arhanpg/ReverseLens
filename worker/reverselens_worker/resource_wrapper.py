from __future__ import annotations

import json
import os
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    args = sys.argv[1:]
    try:
        metrics_path = Path(args[args.index("--metrics") + 1])
        timeout = int(args[args.index("--timeout") + 1])
        command = args[args.index("--") + 1:]
    except (ValueError, IndexError):
        print("resource_wrapper: invalid arguments", file=sys.stderr)
        return 2
    if not command:
        print("resource_wrapper: command is empty", file=sys.stderr)
        return 2

    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, errors="replace", start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    metrics = {
        "cpu_time_ms": max(0, int((usage.ru_utime + usage.ru_stime) * 1000)),
        "peak_rss_bytes": max(0, int(usage.ru_maxrss * 1024)),
        "user_cpu_ms": max(0, int(usage.ru_utime * 1000)),
        "system_cpu_ms": max(0, int(usage.ru_stime * 1000)),
        "wall_time_ms": max(0, int((time.monotonic() - started) * 1000)),
        "timed_out": timed_out,
        "exit_code": 124 if timed_out else (process.returncode or 0),
    }
    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    if stdout:
        sys.stdout.write(stdout)
    if stderr:
        sys.stderr.write(stderr)
    return 124 if timed_out else (process.returncode or 0)


if __name__ == "__main__":
    raise SystemExit(main())
