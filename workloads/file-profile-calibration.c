// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

struct worker { const char *path; size_t bytes; int error; };
static void *read_worker(void *arg)
{
	struct worker *worker = arg;
	int fd = open(worker->path, O_RDONLY);
	char buf[128];
	if (fd < 0) { worker->error = 1; return NULL; }
	for (int i = 0; i < 2; ++i) {
		ssize_t n = pread(fd, buf, sizeof(buf), i * sizeof(buf));
		if (n != sizeof(buf)) worker->error = 1;
		else worker->bytes += n;
	}
	close(fd);
	return NULL;
}
int main(int argc, char **argv)
{
	if (argc != 3) return 2;
	int unsupported = 0;
	if (getenv("ALLOX_FILE_PROFILE_ABI_NEGATIVE")) {
#if defined(__x86_64__)
		long result;
		/* IA32 syscall19 is lseek, not native readv; invalid fd has no
		 * filesystem side effect. The collector must not alias the ABI. */
		__asm__ volatile("int $0x80" : "=a"(result)
			: "0"(19), "b"(-1), "c"(0), "d"(0) : "memory");
		if (result != -EBADF) return 15;
		errno = 0;
		if (syscall(0x40000000L | 19, -1, NULL, 0) != -1 ||
		    (errno != ENOSYS && errno != EBADF)) return 16;
		unsupported = 2;
#else
		return 17;
#endif
	}
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) return 3;
	struct stat st;
	if (fstat(fd, &st) || st.st_size < 4096) return 4;
	char buffer[128], one[20], two[12];
	struct iovec vector[2] = {{one, sizeof(one)}, {two, sizeof(two)}};
	size_t bytes = 0;
	ssize_t n = read(fd, buffer, 128);
	if (n != 128) return 5;
	bytes += n;
	n = pread(fd, buffer, 64, 256);
	if (n != 64) return 6;
	bytes += n;
	n = readv(fd, vector, 2);
	if (n != 32) return 7;
	bytes += n;
	n = preadv(fd, vector, 2, 320);
	if (n != 32) return 8;
	bytes += n;
	n = preadv2(fd, vector, 2, 384, 0);
	if (n != 32) return 9;
	bytes += n;
	void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) return 10;
	volatile char observed = ((char *)map)[0];
	(void)observed;
	munmap(map, 4096);
	errno = 0;
	map = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd, 0);
	if (map != MAP_FAILED || errno != EACCES) return 14;
	close(fd);
	DIR *directory = opendir(argv[2]);
	if (!directory) return 11;
	while (readdir(directory)) {}
	closedir(directory);
	pthread_t threads[2];
	struct worker workers[2] = {{argv[1], 0, 0}, {argv[1], 0, 0}};
	for (int i = 0; i < 2; ++i) if (pthread_create(&threads[i], NULL, read_worker, &workers[i])) return 12;
	for (int i = 0; i < 2; ++i) {
		pthread_join(threads[i], NULL);
		if (workers[i].error) return 13;
		bytes += workers[i].bytes;
	}
	printf("{\"returned_file_bytes\":%zu,\"readv_calls\":3,\"mmap_calls\":2,\"mmap_success\":1,\"mmap_errors\":1,\"worker_threads\":2,\"unsupported_abi_attempts\":%d}\n", bytes, unsupported);
	return 0;
}
