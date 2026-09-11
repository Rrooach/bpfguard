// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include "exclusive-credentials.h"

#if defined(__x86_64__)
#define OBSERVER_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define OBSERVER_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "exclusive workload seccomp supports only x86-64 and arm64"
#endif

#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif
#ifndef __NR_open
#define __NR_open 0xffffffffU
#endif
#ifndef __NR_fork
#define __NR_fork 0xffffffffU
#endif
#ifndef __NR_vfork
#define __NR_vfork 0xffffffffU
#endif

#define SECCOMP_DENY (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
#define DENY_SYSCALL(number)                                                \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1),                \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_DENY)
#define ALLOW_SYSCALL(number)                                               \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1),                \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int install_exclusive_noop_seccomp(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, OBSERVER_AUDIT_ARCH,
			 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),

		/* No bpf command is valid for a no-op workload. */
		DENY_SYSCALL(__NR_bpf),
		DENY_SYSCALL(__NR_socket),
		DENY_SYSCALL(__NR_socketpair),
		DENY_SYSCALL(__NR_sendmsg),
		DENY_SYSCALL(__NR_recvmsg),
		DENY_SYSCALL(__NR_sendmmsg),
		DENY_SYSCALL(__NR_recvmmsg),
		DENY_SYSCALL(__NR_pidfd_getfd),
		DENY_SYSCALL(__NR_mmap),
		DENY_SYSCALL(__NR_mremap),
		DENY_SYSCALL(__NR_io_uring_setup),
		DENY_SYSCALL(__NR_io_uring_enter),
		DENY_SYSCALL(__NR_io_uring_register),
		DENY_SYSCALL(__NR_clone),
		DENY_SYSCALL(__NR_fork),
		DENY_SYSCALL(__NR_vfork),
		DENY_SYSCALL(__NR_open),
		DENY_SYSCALL(__NR_openat),
		DENY_SYSCALL(__NR_openat2),
		DENY_SYSCALL(__NR_mount),
		DENY_SYSCALL(__NR_setns),
		DENY_SYSCALL(__NR_unshare),

		/* Returning from main only needs process termination. */
		ALLOW_SYSCALL(__NR_exit),
		ALLOW_SYSCALL(__NR_exit_group),
		ALLOW_SYSCALL(__NR_rt_sigreturn),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_DENY),
	};
	struct sock_fprog program = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		return -1;
	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s [--exclusive-contract]\n", program);
	fprintf(stderr,
		"       installs a no-BPF exclusive seccomp contract and exits\n");
}

int main(int argc, char **argv)
{
	int exclusive_contract = argc == 2 &&
		!strcmp(argv[1], "--exclusive-contract");

	if (argc > 2 ||
	    (argc == 2 && strcmp(argv[1], "--exclusive-contract") != 0)) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	if (exclusive_contract && assert_exclusive_credentials(0) < 0) {
		perror("exclusive credential contract");
		return EXIT_FAILURE;
	}
	if (install_exclusive_noop_seccomp() < 0) {
		perror("install exclusive no-op seccomp contract");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
