#define _GNU_SOURCE

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <signal.h>
#include <errno.h>
#include <grp.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/capability.h>

#include "policy.h"
#include "limits.h"

/* Create a separate network namespace. */
void setup_network_namespace(void)
{
    if (unshare(CLONE_NEWNET) == -1) {
        perror("[SecCage] Network namespace failed");
        _exit(1);
    }

    printf("[SecCage] Network namespace created.\n");
}

/* Drop capabilities from the capability bounding set. */
void drop_capabilities(void)
{
    int cap;

    for (cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == -1 &&
            errno != EINVAL && errno != EPERM) {
            perror("[SecCage] Capability drop failed");
            _exit(1);
        }
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL,
              0, 0, 0) == -1 && errno != EINVAL) {
        perror("[SecCage] Clearing ambient capabilities failed");
        _exit(1);
    }

    printf("[SecCage] Linux capabilities dropped.\n");
}

/* Drop root privileges to UID/GID 65534. */
void drop_privileges(void)
{
    if (geteuid() == 0) {
        if (setgroups(0, NULL) == -1) {
            perror("[SecCage] setgroups failed");
            _exit(1);
        }

        if (setgid(65534) == -1) {
            perror("[SecCage] setgid failed");
            _exit(1);
        }

        if (setuid(65534) == -1) {
            perror("[SecCage] setuid failed");
            _exit(1);
        }
    }

    if (getuid() == 0 || geteuid() == 0) {
        fprintf(stderr, "[SecCage] Refusing to run as root.\n");
        _exit(1);
    }

    printf("[SecCage] Privileges dropped to UID %d (nobody).\n",
           (int)getuid());
}

/* Translate supported syscall names into syscall numbers. */
int get_syscall_number(const char *name)
{
    if (strcmp(name, "read") == 0) return SYS_read;
    if (strcmp(name, "write") == 0) return SYS_write;
    if (strcmp(name, "exit") == 0) return SYS_exit;
    if (strcmp(name, "exit_group") == 0) return SYS_exit_group;
    if (strcmp(name, "execve") == 0) return SYS_execve;
    if (strcmp(name, "brk") == 0) return SYS_brk;
    if (strcmp(name, "mmap") == 0) return SYS_mmap;
    if (strcmp(name, "munmap") == 0) return SYS_munmap;
    if (strcmp(name, "mprotect") == 0) return SYS_mprotect;
    if (strcmp(name, "arch_prctl") == 0) return SYS_arch_prctl;
    if (strcmp(name, "set_tid_address") == 0) return SYS_set_tid_address;
    if (strcmp(name, "set_robust_list") == 0) return SYS_set_robust_list;
    if (strcmp(name, "rseq") == 0) return SYS_rseq;
    if (strcmp(name, "getuid") == 0) return SYS_getuid;
    if (strcmp(name, "geteuid") == 0) return SYS_geteuid;
    if (strcmp(name, "getgid") == 0) return SYS_getgid;
    if (strcmp(name, "getegid") == 0) return SYS_getegid;
    if (strcmp(name, "dup") == 0) return SYS_dup;
    if (strcmp(name, "dup2") == 0) return SYS_dup2;
    if (strcmp(name, "openat") == 0) return SYS_openat;
    if (strcmp(name, "socket") == 0) return SYS_socket;
    if (strcmp(name, "connect") == 0) return SYS_connect;

    return -1;
}

/* Install the seccomp-BPF filter from the loaded policy. */
void install_seccomp(PolicyRule rules[], int rule_count)
{
    struct sock_filter filter[MAX_RULES * 2 + 5];
    int filter_count = 0;

    if (rule_count < 0 || rule_count > MAX_RULES) {
        fprintf(stderr, "[SecCage] Invalid policy rule count.\n");
        _exit(1);
    }

    /* Check the CPU architecture. This filter targets x86-64 Linux. */
    filter[filter_count++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, arch));

    filter[filter_count++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64, 1, 0);

    filter[filter_count++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* Load the syscall number. */
    filter[filter_count++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, nr));

    for (int i = 0; i < rule_count; i++) {
        int syscall_nr = get_syscall_number(rules[i].syscall_name);

        if (syscall_nr == -1) {
            printf("[SecCage] Warning: unknown syscall %s\n",
                   rules[i].syscall_name);
            continue;
        }

        filter[filter_count++] = (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K,
            (unsigned int)syscall_nr, 0, 1);

        if (rules[i].action == ACTION_ALLOW) {
            filter[filter_count++] = (struct sock_filter)BPF_STMT(
                BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        } else {
            filter[filter_count++] = (struct sock_filter)BPF_STMT(
                BPF_RET | BPF_K, SECCOMP_RET_TRAP);
        }
    }

    /* Unlisted syscalls return EPERM. */
    filter[filter_count++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K,
        SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));

    struct sock_fprog program = {
        .len = (unsigned short)filter_count,
        .filter = filter
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("[SecCage] NO_NEW_PRIVS failed");
        _exit(1);
    }

    printf("[SecCage] Installing seccomp-BPF...\n");

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == -1) {
        perror("[SecCage] Seccomp installation failed");
        _exit(1);
    }

    printf("[SecCage] Seccomp filter installed.\n");
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <policy-file> <program>\n", argv[0]);
        return 1;
    }

    PolicyRule rules[MAX_RULES];
    int rule_count = 0;

    if (load_policy(argv[1], rules, &rule_count) != 0) {
        fprintf(stderr, "[SecCage] Failed to load policy.\n");
        return 1;
    }

    printf("[SecCage] Policy loaded: %d rules\n", rule_count);
    printf("[SecCage] Starting sandbox...\n");

    pid_t pid = fork();

    if (pid == -1) {
        perror("[SecCage] fork failed");
        return 1;
    }

    if (pid == 0) {
        printf("[SecCage] Child process created.\n");

        if (apply_cpu_limit(2) != 0 ||
            apply_memory_limit(64) != 0 ||
            apply_file_limit(16) != 0) {
            _exit(1);
        }

        setup_network_namespace();
        drop_capabilities();
        drop_privileges();
        install_seccomp(rules, rule_count);

        printf("[SecCage] Executing target: %s\n", argv[2]);

        char *args[] = { argv[2], NULL };
        execvp(argv[2], args);

        perror("[SecCage] execvp failed");
        _exit(127);
    }

    printf("[SecCage] Waiting for target...\n");

    int status = 0;
    pid_t waited;

    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);

    if (waited == -1) {
        perror("[SecCage] waitpid failed");
        return 1;
    }

    /* Parent-side log when a target is terminated by SIGSYS. */
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
        fprintf(stderr,
                "[SecCage DENY-LOG] Target terminated after "
                "a seccomp trap (SIGSYS).\n");
    }

    if (WIFEXITED(status)) {
        printf("[SecCage] Target exited with status %d\n",
               WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("[SecCage] Target terminated by signal %d\n",
               WTERMSIG(status));
    }

    return 0;
}
