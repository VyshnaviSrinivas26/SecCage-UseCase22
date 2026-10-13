# SecCage — Syscall Sandbox (Use Case 22)

## 1. Build and Extract

Clone the GitHub repository and enter the project directory:

```bash
git clone https://github.com/VyshnaviSrinivas26/SecCage-UseCase22.git
cd SecCage-UseCase22
```

Build the project and test programs:

```bash
make clean
make
make tests
```

If a build command fails, check the error message and the targets available in the `Makefile`.

## 2. Run Tests

The recommended test script builds the launcher and static test programs, runs representative cases, and saves output logs.

```bash
./test_suite.sh
```

Review the generated logs in `logs/` to determine which tests passed or failed.

**Environment limitation:** If the environment blocks network namespace creation, the sandbox may exit during setup. This is an environment permission limitation, not a successful test. Use a Linux VM where `unshare` is permitted, or report the limitation.

## 3. Main Manual Commands

Build the static test binaries and copy them to `/tmp` if needed:

```bash
make tests
cp *_static /tmp/
```

Run the benign computation test:

```bash
./seccage policies/compute-only.policy /tmp/test_static
```

Run the file test with the compute-only profile:

```bash
./seccage policies/compute-only.policy /tmp/file_test_static
```

Run the network test with the compute-only profile:

```bash
./seccage policies/compute-only.policy /tmp/network_test_static
```

Run the memory test:

```bash
./seccage policies/compute-only.policy /tmp/memory_test_static
```

Run the file-descriptor-limit test:

```bash
./seccage policies/compute-only.policy /tmp/fd_limit_test_static
```

Run the identity test:

```bash
./seccage policies/compute-only.policy /tmp/identity_test_static
```

Run the escape test:

```bash
./seccage policies/compute-only.policy /tmp/escape_test_static
```

Run the file test with the file-processing profile:

```bash
./seccage policies/file-processing.policy /tmp/file_test_static
```

These commands assume the specified binaries exist in `/tmp`. Run each test separately and inspect its actual output.

## 4. Measure End-to-End Overhead

Run the benchmark:

```bash
./benchmark.sh 10
```

This reports median, minimum, and maximum elapsed wall time for direct target execution versus execution through SecCage. It measures launcher and setup overhead, not isolated per-system-call overhead.

## 5. Evidence to Capture (8 Points)

1. **Launcher and policy profiles:** Run `make` and `ls policies`, then perform a denied-call test.
2. **Denial logger:** Capture a denied-call run showing `[SecCage DENY-LOG]`, if produced by the test.
3. **Test suite:** Run `./test_suite.sh` and review `logs/`.
4. **Design and threat model:** Display `cat DESIGN.md` and relevant source or configuration output.
5. **Overhead measurement:** Run `./benchmark.sh 10` and record the actual results.
6. **Compute-only profile and denied calls:** Run benign, file, and network tests and document their observed behavior. The current denial logger reports termination after a seccomp trap; it does not identify the exact syscall number or name.
7. **Resource limits:** Run the CPU and memory tests separately and capture their outputs.
8. **Privilege drop and irreversibility:** Run the identity and escape tests and capture their outputs.

Keep the command and its output visible in every screenshot. Do not edit terminal output or claim a feature passed if the test did not pass.

## 6. Scope and Limitations

The launcher uses seccomp-BPF, CPU/address-space/file-descriptor limits, a network namespace, capability bounding-set dropping, and UID/GID 65534.

The following features are not fully implemented:

- Detailed logging of the exact denied system call.
- PID and mount namespace isolation.
- Argument-level system-call filtering.
- Ptrace fallback.

See `DESIGN.md` for the design and threat model. The project should not be described as a complete security boundary for arbitrary untrusted code.

## 7. Project Files

- `src/` — C source files and test programs.
- `policies/` — system-call policy profiles.
- `Makefile` — build instructions.
- `test_suite.sh` — test-suite script.
- `benchmark.sh` — end-to-end overhead benchmark.
- `DESIGN.md` — design, threat model, and limitations.
- `README.md` — project documentation.

## Repository

[SecCage-UseCase22 on GitHub](https://github.com/VyshnaviSrinivas26/SecCage-UseCase22)
