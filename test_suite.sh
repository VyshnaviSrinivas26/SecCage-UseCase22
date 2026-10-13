#!/usr/bin/env bash
set -u
cd "$(dirname "$0")"
mkdir -p logs
echo "[1/8] Build SecCage and static test targets"
make clean >/dev/null 2>&1 || true
if ! make; then echo "BUILD_FAIL"; exit 1; fi
for spec in "test:test.c" "file_test:file_test.c" "network_test:network_test.c" "cpu_test:cpu_test.c" "memory_test:memory_test.c" "fd_limit_test:fd_limit_test.c" "identity_test:identity_test.c" "cap_test:cap_test.c" "netns_test:netns_test.c" "escape_test:escape_test.c"; do
  out="${spec%%:*}"; file="${spec#*:}"
  gcc -static "src/$file" -o "${out}_static" || { echo "Static build failed: $file"; exit 1; }
done
cp *_static /tmp/ 2>/dev/null || true

run_case() {
  name="$1"; shift
  echo "=== $name ==="
  set +e
  "$@" >"logs/$name.log" 2>&1
  rc=$?
  set -e
  cat "logs/$name.log"
  echo "[case exit code=$rc]"
}
set -e
run_case compute ./seccage policies/compute-only.policy /tmp/test_static
run_case file_denied ./seccage policies/compute-only.policy /tmp/file_test_static
run_case network_denied ./seccage policies/compute-only.policy /tmp/network_test_static
run_case cpu_limit ./seccage policies/compute-only.policy /tmp/cpu_test_static
run_case memory_limit ./seccage policies/compute-only.policy /tmp/memory_test_static
run_case fd_limit ./seccage policies/compute-only.policy /tmp/fd_limit_test_static
run_case identity ./seccage policies/compute-only.policy /tmp/identity_test_static
run_case capability_regain ./seccage policies/compute-only.policy /tmp/escape_test_static
run_case file_profile ./seccage policies/file-processing.policy /tmp/file_test_static
echo "Tests completed. Logs are in logs/; review each result rather than relying only on the wrapper exit code."
