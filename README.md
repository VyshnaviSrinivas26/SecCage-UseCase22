# SecCage — Syscall Sandbox (Use Case 22)

## Build and extract
Extract the project folder, then run:
```bash
cd SecCage_UseCase22_Updated
make clean
make
make tests
```
If your extracted folder has another name, `cd` into that folder instead.

## Run tests
The recommended test script builds the launcher and static test programs, runs representative cases, and saves output logs:
```bash
./test_suite.sh
```
If the environment blocks network namespace creation, the sandbox exits during setup. This is an environment permission limitation, not a successful test; use a Linux VM where unshare is allowed or report the limitation.

## Main manual commands
```bash
./seccage policies/compute-only.policy /tmp/test_static
./seccage policies/compute-only.policy /tmp/file_test_static
./seccage policies/compute-only.policy /tmp/network_test_static
./seccage policies/compute-only.policy /tmp/memory_test_static
./seccage policies/compute-only.policy /tmp/fd_limit_test_static
./seccage policies/compute-only.policy /tmp/identity_test_static
./seccage policies/compute-only.policy /tmp/escape_test_static
./seccage policies/file-processing.policy /tmp/file_test_static
```
Compile/copy static binaries to `/tmp` if needed:
```bash
make tests
cp *_static /tmp/
```

## Measure end-to-end overhead
```bash
./benchmark.sh 10
```
This reports median/min/max elapsed wall time for direct target execution versus running through SecCage. It measures launcher and setup overhead, not isolated syscall overhead.

## Evidence to capture (8 points)
1. Launcher, profiles, denial logger: `make`, `ls policies`, then a denied-call run showing `[SecCage DENY-LOG]`.
2. Test suite: `./test_suite.sh` and review `logs/`.
3. Design/threat model: `cat DESIGN.md` plus relevant source/config output.
4. Overhead measurement: `./benchmark.sh 10`.
5. Compute-only profile: run benign, file and network test programs.
6. Denied call and logging: run file/network denied tests; show the parent SIGSYS denial log. It identifies the termination, not exact syscall number.
7. Resource limits: run CPU and memory tests separately.
8. Privilege drop/irreversibility: run identity and escape test.

Keep the command and its output visible in each screenshot. Do not edit terminal output or claim a feature passed if the test did not pass.

## Scope and limitations
The launcher uses seccomp-BPF, CPU/address-space/file-descriptor limits, a network namespace, capability bounding-set drop, and UID/GID 65534. Detailed exact-syscall logging, PID/mount namespaces, argument-level filtering, and ptrace fallback are not complete. See `DESIGN.md`.
