#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
N="${1:-10}"
if [ ! -x ./seccage ] || [ ! -x /tmp/test_static ]; then
  echo "Build first and compile/copy test_static to /tmp/test_static."
  exit 1
fi
python3 - "$N" <<'PY'
import statistics, subprocess, sys, time
n=int(sys.argv[1])
def measure(cmd):
    vals=[]
    for _ in range(n):
        t=time.perf_counter()
        p=subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        vals.append((time.perf_counter()-t)*1000)
        if p.returncode not in (0, -31, 159):
            # SecCage may return zero while reporting target termination; keep recording elapsed time.
            pass
    return statistics.median(vals), min(vals), max(vals)
plain=measure(["/tmp/test_static"])
boxed=measure(["./seccage","policies/compute-only.policy","/tmp/test_static"])
print(f"Runs per mode: {n}")
print(f"Direct target median: {plain[0]:.3f} ms (min {plain[1]:.3f}, max {plain[2]:.3f})")
print(f"SecCage end-to-end median: {boxed[0]:.3f} ms (min {boxed[1]:.3f}, max {boxed[2]:.3f})")
print(f"Difference in median wall time: {boxed[0]-plain[0]:.3f} ms")
print("Note: this measures end-to-end launcher/setup overhead, not isolated per-syscall overhead.")
PY
