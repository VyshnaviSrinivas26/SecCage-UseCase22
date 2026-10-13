# SecCage Design Note: Filter, Privilege Ordering, and Threat Model

## 1. Purpose
SecCage is a Linux C prototype that launches a target under a syscall policy and selected resource/privilege controls.

## 2. Filter design
The policy file contains one syscall/action pair per line (`read allow`, `openat deny`). The parser validates rule shape and action. The launcher maps known syscall names to syscall numbers and generates a seccomp-BPF filter. Explicit allow rules return `SECCOMP_RET_ALLOW`; explicit deny rules return `SECCOMP_RET_TRAP`; unmatched calls return `SECCOMP_RET_ERRNO | EPERM`. The current syscall-name mapping is intentionally limited to the names implemented in `src/seccage.c`.

## 3. Control ordering
1. Parse and validate the policy before forking.
2. Fork a child process.
3. Apply CPU, address-space memory, and file-descriptor limits.
4. Enter a network namespace (requires the host/WSL configuration to permit it).
5. Drop the capability bounding set while the process still has the required privilege.
6. Clear supplementary groups and switch to UID/GID 65534.
7. Set `PR_SET_NO_NEW_PRIVS` and install seccomp-BPF.
8. Execute the target; parent waits and reports normal exit or signal termination.

Any failed security setup step should prevent the target from running. `NO_NEW_PRIVS` prevents privilege gains through exec of set-user-ID/set-group-ID programs, but this is not a complete substitute for containers, mount/PID namespaces, or a hardened VM.

## 4. Denial observability
A target terminated by `SIGSYS` is logged by the parent as a seccomp-trapped denial. This confirms that a denied syscall caused termination, but the parent-side message does **not** identify the exact syscall number. Detailed per-syscall logging via a persistent supervisor, seccomp user notification, or ptrace remains future work.

## 5. Threat model
In scope: accidental or untrusted test programs attempting syscalls excluded by the policy or consuming more than the configured CPU, address-space, or file-descriptor limits.
Out of scope: kernel vulnerabilities, malicious host/root users, side-channel attacks, filesystem isolation without a mount namespace, PID isolation, path/argument-specific rules, and comprehensive escape resistance. Run untrusted workloads in a disposable VM/container with additional restrictions; do not treat this student prototype as a production security boundary.

## 6. Validation and measurement
`./test_suite.sh` compiles test programs and records output under `logs/`. `./benchmark.sh 10` measures direct versus SecCage end-to-end wall time. Record machine/WSL version and repeat counts when reporting measurements. The benchmark includes setup costs and is not a per-syscall microbenchmark.

## 7. Known limits
- Namespace creation may fail if the environment disallows `unshare(CLONE_NEWNET)`.
- The syscall map currently supports only a fixed list of syscall names.
- Denied-call log reports SIGSYS termination but does not recover the exact syscall number.
- PID and mount namespace isolation, argument-level filtering, ptrace fallback, and detailed supervisor logging are not implemented.
