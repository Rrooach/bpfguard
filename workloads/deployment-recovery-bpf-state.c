// SPDX-License-Identifier: GPL-2.0-only

/*
 * Disposable-VM A/B/C fixture: leave one pinned cgroup-SKB Program and Link.
 * The program permits egress and has no side effect.  Its only purpose is to
 * give the BPF Program/Link state confirmer a bounded, reversible difference.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include "../../../../tools/include/uapi/linux/bpf.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *operation)
{
	fprintf(stderr, "%s: %s\n", operation, strerror(errno));
	exit(EXIT_FAILURE);
}

static int bpf_command(enum bpf_cmd command, union bpf_attr *attributes)
{
	return (int)syscall(__NR_bpf, command, attributes, sizeof(*attributes));
}

static void pin_fd(int descriptor, const char *path)
{
	union bpf_attr pin = { 0 };

	pin.bpf_fd = (uint32_t)descriptor;
	pin.pathname = (uint64_t)(uintptr_t)path;
	if (bpf_command(BPF_OBJ_PIN, &pin) != 0)
		fail("BPF_OBJ_PIN");
}

int main(int argc, char **argv)
{
	static const struct bpf_insn allow_egress[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 1 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	static const char license[] = "GPL";
	union bpf_attr load = { 0 };
	union bpf_attr attach = { 0 };
	int target_fd;
	int program_fd;
	int link_fd;

	if (argc != 4) {
		fprintf(stderr, "usage: %s CGROUP-DIR PROGRAM-PIN LINK-PIN\n", argv[0]);
		return EXIT_FAILURE;
	}
	target_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (target_fd < 0)
		fail("open cgroup target");
	load.prog_type = BPF_PROG_TYPE_CGROUP_SKB;
	load.expected_attach_type = BPF_CGROUP_INET_EGRESS;
	load.insn_cnt = sizeof(allow_egress) / sizeof(allow_egress[0]);
	load.insns = (uint64_t)(uintptr_t)allow_egress;
	load.license = (uint64_t)(uintptr_t)license;
	memcpy(load.prog_name, "abc_egress", sizeof("abc_egress"));
	program_fd = bpf_command(BPF_PROG_LOAD, &load);
	if (program_fd < 0)
		fail("BPF_PROG_LOAD");
	attach.link_create.prog_fd = (uint32_t)program_fd;
	attach.link_create.target_fd = (uint32_t)target_fd;
	attach.link_create.attach_type = BPF_CGROUP_INET_EGRESS;
	link_fd = bpf_command(BPF_LINK_CREATE, &attach);
	if (link_fd < 0)
		fail("BPF_LINK_CREATE");
	pin_fd(program_fd, argv[2]);
	pin_fd(link_fd, argv[3]);
	if (close(link_fd) != 0 || close(program_fd) != 0 || close(target_fd) != 0)
		fail("close BPF fixture descriptor");
	puts("{\"deployment_recovery_bpf_state\":\"ok\"}");
	return EXIT_SUCCESS;
}
