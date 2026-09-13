// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static void fail(const char *operation)
{
	perror(operation);
	exit(EXIT_FAILURE);
}

static void make_path(char *output, size_t capacity, const char *directory,
		      const char *name)
{
	int count = snprintf(output, capacity, "%s/%s", directory, name);

	if (count < 0 || (size_t)count >= capacity) {
		errno = ENAMETOOLONG;
		fail("construct fixture path");
	}
}

int main(int argc, char **argv)
{
	char first[4096], second[4096];
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_port = htons(9),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	static const char payload[] = "system-effect-smoke\n";
	int fd, socket_fd;
	long bpf_result;

	if (argc != 2) {
		fprintf(stderr, "usage: %s NEW-DIRECTORY\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (mkdir(argv[1], 0700) != 0)
		fail("mkdir");
	make_path(first, sizeof(first), argv[1], "before.txt");
	make_path(second, sizeof(second), argv[1], "after.txt");

	fd = open(first, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (fd < 0)
		fail("open");
	if (write(fd, payload, sizeof(payload) - 1) !=
	    (ssize_t)(sizeof(payload) - 1))
		fail("write");
	if (ftruncate(fd, 7) != 0)
		fail("ftruncate");
	if (close(fd) != 0)
		fail("close");
	if (rename(first, second) != 0)
		fail("rename");

	socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (socket_fd < 0)
		fail("socket");
	/* The service is intentionally absent. Both success and refusal are valid
	 * evidence: the fixture checks observation, not network availability.
	 */
	if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0 &&
	    errno != ECONNREFUSED && errno != EINPROGRESS)
		fail("connect");
	if (close(socket_fd) != 0)
		fail("close socket");

	errno = 0;
	bpf_result = syscall(SYS_bpf, BPF_MAP_CREATE, NULL, 0);
	if (bpf_result != -1 || errno == 0) {
		errno = EPROTO;
		fail("harmless bpf failure");
	}

	if (unlink(second) != 0)
		fail("unlink");
	if (rmdir(argv[1]) != 0)
		fail("rmdir");
	puts("{\"system_effects_smoke\":\"ok\",\"final_filesystem_state\":\"restored\"}");
	return EXIT_SUCCESS;
}
