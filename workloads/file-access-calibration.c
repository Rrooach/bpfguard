// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

static int fixture_fd;
static void *thread_read(void *argument)
{
	char bytes[17];
	off_t offset = (off_t)(long)argument;
	if (pread(fixture_fd, bytes, sizeof(bytes), offset) != (ssize_t)sizeof(bytes))
		return (void *)1;
	return NULL;
}

int main(int argc, char **argv)
{
	if (argc != 2) return 2;
	fixture_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (fixture_fd < 0) return 3;
	struct stat info;
	if (fstat(fixture_fd, &info) || info.st_size != 16384) return 4;
	char bytes[256];
	if (read(fixture_fd, bytes, 97) != 97 || pread(fixture_fd, bytes, 193, 1024) != 193)
		return 5;
	struct iovec vec[2] = {{bytes, 33}, {bytes + 64, 44}};
	if (readv(fixture_fd, vec, 2) != 77) return 6;
	vec[0].iov_len = 5; vec[1].iov_len = 6;
	if (preadv(fixture_fd, vec, 2, 2048) != 11) return 7;
	vec[0].iov_len = 7; vec[1].iov_len = 8;
	if (preadv2(fixture_fd, vec, 2, 3072, 0) != 15) return 8;
	pthread_t workers[2];
	for (long index = 0; index < 2; ++index)
		if (pthread_create(&workers[index], NULL, thread_read, (void *)(4096 + index * 17)))
			return 9;
	for (int index = 0; index < 2; ++index) {
		void *result = NULL;
		if (pthread_join(workers[index], &result) || result) return 10;
	}
	if (pread(fixture_fd, bytes, 1, info.st_size) != 0) return 11;
	errno = 0;
	if (read(-1, bytes, 1) != -1 || errno != EBADF) return 12;
	int alias = dup(fixture_fd);
	if (alias < 0 || pread(alias, bytes, 11, 8192) != 11 || close(alias)) return 13;
	/* Each separate one-page VMA must actually fault. Retry attempts may add
	 * calls; the observer must not call each filemap_fault attempt a page. */
	if (posix_fadvise(fixture_fd, 0, info.st_size, POSIX_FADV_DONTNEED)) return 14;
	unsigned int checksum = 0;
	for (off_t offset = 0; offset < info.st_size; offset += 4096) {
		volatile unsigned char *page = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fixture_fd, offset);
		if (page == MAP_FAILED) return 15;
		checksum += page[0];
		if (munmap((void *)page, 4096)) return 16;
	}
	if (close(fixture_fd)) return 17;
	printf("{\"fixture_bytes_returned\":438,\"fixture_vfs_read_calls\":9,"
	       "\"file_mapping_page_touches\":4,\"checksum\":%u,"
	       "\"invalid_fd_reads\":1,\"reader_threads\":3}\n", checksum);
	return 0;
}
