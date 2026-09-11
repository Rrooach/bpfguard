// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "exclusive-credentials.h"

#if defined(__x86_64__)
#define OBSERVER_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define OBSERVER_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "exclusive workload seccomp supports only x86-64 and arm64"
#endif

/* Ubuntu's libc headers can predate these architecture-generic syscall IDs. */
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

static int install_exclusive_seccomp(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, OBSERVER_AUDIT_ARCH,
			 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),

		/* Permit only the bpf commands required by this fixture. */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BPF_MAP_CREATE, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BPF_MAP_UPDATE_ELEM,
			 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_DENY),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		/* Explicitly excluded FD, namespace, process and async paths. */
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

		/* Everything else is denied after the minimal fixture runtime. */
		ALLOW_SYSCALL(__NR_write),
		ALLOW_SYSCALL(__NR_close),
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

static int sys_bpf(enum bpf_cmd command, union bpf_attr *attr)
{
	return (int)syscall(__NR_bpf, command, attr, sizeof(*attr));
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s [--ephemeral | --transient-restore] "
		"[--freeze] [--pin PATH] [--exclusive-contract] "
		"[--ready-file PATH --release-file PATH]\n",
		program);
	fprintf(stderr,
		"       --exclusive-contract permits only BPF_MAP_CREATE and "
		"BPF_MAP_UPDATE_ELEM and is incompatible with --freeze/--pin\n");
}

static void fail(const char *operation)
{
	fprintf(stderr, "%s: %s\n", operation, strerror(errno));
	exit(EXIT_FAILURE);
}

static void rendezvous(const char *ready_path, const char *release_path)
{
	struct timespec delay = {
		.tv_sec = 0,
		.tv_nsec = 10 * 1000 * 1000,
	};
	int ready_fd;

	if (!ready_path && !release_path)
		return;
	if (!ready_path || !release_path) {
		errno = EINVAL;
		fail("both --ready-file and --release-file are required");
	}

	/* The observer moves this process into the exact run cgroup before exec.
	 * Publishing this file therefore gives the VM harness a deterministic
	 * point at which to issue an out-of-cgroup negative-control bpf() call.
	 */
	ready_fd = open(ready_path,
			O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (ready_fd < 0)
		fail("open(--ready-file)");
	if (dprintf(ready_fd, "%ld\n", (long)getpid()) < 0)
		fail("write(--ready-file)");
	if (close(ready_fd) < 0)
		fail("close(--ready-file)");

	while (access(release_path, F_OK) < 0) {
		if (errno != ENOENT)
			fail("access(--release-file)");
		if (nanosleep(&delay, NULL) < 0 && errno != EINTR)
			fail("nanosleep(--release-file)");
	}
}

int main(int argc, char **argv)
{
	const char *pin_path = NULL;
	const char *ready_path = NULL;
	const char *release_path = NULL;
	int freeze_map = 0;
	int transient_restore = 0;
	int exclusive_contract = 0;
	uint32_t key = 7;
	const uint64_t initial_value = 0x1122334455667788ULL;
	const uint64_t transient_value = 0x8877665544332211ULL;
	uint64_t value = initial_value;
	union bpf_attr attr;
	int map_fd;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--ephemeral")) {
			pin_path = NULL;
		} else if (!strcmp(argv[i], "--transient-restore")) {
			transient_restore = 1;
		} else if (!strcmp(argv[i], "--freeze")) {
			freeze_map = 1;
		} else if (!strcmp(argv[i], "--pin") && i + 1 < argc) {
			pin_path = argv[++i];
		} else if (!strcmp(argv[i], "--ready-file") && i + 1 < argc) {
			ready_path = argv[++i];
		} else if (!strcmp(argv[i], "--release-file") && i + 1 < argc) {
			release_path = argv[++i];
		} else if (!strcmp(argv[i], "--exclusive-contract")) {
			exclusive_contract = 1;
		} else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (transient_restore && (freeze_map || pin_path)) {
		errno = EINVAL;
		fail("--transient-restore is incompatible with --freeze/--pin");
	}
	if (exclusive_contract && (freeze_map || pin_path)) {
		errno = EINVAL;
		fail("--exclusive-contract is incompatible with --freeze/--pin");
	}
	if (exclusive_contract &&
	    assert_exclusive_credentials(UINT64_C(1) << CAP_BPF) < 0)
		fail("exclusive credential contract");
	rendezvous(ready_path, release_path);
	if (exclusive_contract && install_exclusive_seccomp() < 0)
		fail("install exclusive seccomp contract");

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(key);
	attr.value_size = sizeof(value);
	attr.max_entries = 4;
	memcpy(attr.map_name, "obs_fixture", sizeof("obs_fixture"));
	map_fd = sys_bpf(BPF_MAP_CREATE, &attr);
	if (map_fd < 0)
		fail("BPF_MAP_CREATE");

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = (uint32_t)map_fd;
	attr.key = (uint64_t)(uintptr_t)&key;
	attr.value = (uint64_t)(uintptr_t)&value;
	attr.flags = BPF_ANY;
	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0)
		fail("BPF_MAP_UPDATE_ELEM");
	if (transient_restore) {
		value = transient_value;
		if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0)
			fail("BPF_MAP_UPDATE_ELEM(transient)");
		value = initial_value;
		if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0)
			fail("BPF_MAP_UPDATE_ELEM(restore)");
	}

	if (freeze_map) {
		memset(&attr, 0, sizeof(attr));
		attr.map_fd = (uint32_t)map_fd;
		if (sys_bpf(BPF_MAP_FREEZE, &attr) < 0)
			fail("BPF_MAP_FREEZE");
	}

	if (pin_path) {
		memset(&attr, 0, sizeof(attr));
		attr.pathname = (uint64_t)(uintptr_t)pin_path;
		attr.bpf_fd = (uint32_t)map_fd;
		attr.file_flags = 0;
		if (sys_bpf(BPF_OBJ_PIN, &attr) < 0)
			fail("BPF_OBJ_PIN");
	}

	if (!exclusive_contract)
		printf("map_fd=%d pin=%s frozen=%s transient_restore=%s\n",
			map_fd, pin_path ? pin_path : "none",
			freeze_map ? "yes" : "no",
			transient_restore ? "yes" : "no");

	if (close(map_fd) < 0)
		fail("close(map_fd)");

	return EXIT_SUCCESS;
}
