#define _GNU_SOURCE

#include <asm/unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#ifndef __NR_openat2
#define __NR_openat2 437
#endif

struct open_how {
	uint64_t flags;
	uint64_t mode;
	uint64_t resolve;
};

int main(int argc, char **argv)
{
	struct open_how how = {
		.flags = O_PATH | O_CLOEXEC,
	};
	int fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s PATH\n", argv[0]);
		return 2;
	}

	fd = (int)syscall(__NR_openat2, AT_FDCWD, argv[1], &how, sizeof(how));
	if (fd < 0) {
		perror("openat2 O_PATH");
		return 1;
	}
	if (close(fd) != 0) {
		perror("close");
		return 1;
	}

	return 0;
}
