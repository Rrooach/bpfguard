// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
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

int main(int argc, char **argv)
{
	static const char payload[] = "deployment endpoint state changed\n";
	union bpf_attr create = { 0 };
	union bpf_attr update = { 0 };
	union bpf_attr pin = { 0 };
	uint32_t key = 7;
	uint64_t value = UINT64_C(0xb0f5e2e);
	int file_fd;
	int map_fd;

	if (argc != 3) {
		fprintf(stderr, "usage: %s MARKER-FILE BPFFS-PIN\n", argv[0]);
		return EXIT_FAILURE;
	}
	file_fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (file_fd < 0)
		fail("create endpoint marker");
	if (write(file_fd, payload, sizeof(payload)) != (ssize_t)sizeof(payload))
		fail("write endpoint marker");
	if (fsync(file_fd) != 0 || close(file_fd) != 0)
		fail("persist endpoint marker");

	create.map_type = BPF_MAP_TYPE_HASH;
	create.key_size = sizeof(key);
	create.value_size = sizeof(value);
	create.max_entries = 16;
	memcpy(create.map_name, "deploy_state", sizeof("deploy_state"));
	map_fd = bpf_command(BPF_MAP_CREATE, &create);
	if (map_fd < 0)
		fail("BPF_MAP_CREATE");
	update.map_fd = (uint32_t)map_fd;
	update.key = (uint64_t)(uintptr_t)&key;
	update.value = (uint64_t)(uintptr_t)&value;
	update.flags = BPF_ANY;
	if (bpf_command(BPF_MAP_UPDATE_ELEM, &update) != 0)
		fail("BPF_MAP_UPDATE_ELEM");
	pin.bpf_fd = (uint32_t)map_fd;
	pin.pathname = (uint64_t)(uintptr_t)argv[2];
	if (bpf_command(BPF_OBJ_PIN, &pin) != 0)
		fail("BPF_OBJ_PIN");
	if (close(map_fd) != 0)
		fail("close pinned map descriptor");

	puts("{\"deployment_endpoint_state_change\":\"ok\"}");
	return EXIT_SUCCESS;
}
