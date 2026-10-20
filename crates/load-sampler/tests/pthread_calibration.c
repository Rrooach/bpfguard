// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static int cpu_work;
static int syscall_work;
static pid_t workload_pid;
static int memory_work, lock_work, reclaim_work, shared_fd = -1;
static const char *reclaim_path;
static unsigned long long ns(clockid_t clock)
{
	struct timespec value;
	if (clock_gettime(clock, &value)) abort();
	return (unsigned long long)value.tv_sec * 1000000000ULL + value.tv_nsec;
}
static void *worker(void *argument)
{
	long index = (long)argument;
	unsigned long long started = ns(CLOCK_THREAD_CPUTIME_ID), wall = ns(CLOCK_MONOTONIC);
	unsigned int getpid_completed = 0;
	struct rusage usage_before, usage_after;
	if (getrusage(RUSAGE_THREAD, &usage_before)) abort();
	if (memory_work || lock_work || reclaim_work) {
		struct timespec hold = { .tv_sec = 0, .tv_nsec = 100000000 };
		nanosleep(&hold, NULL); /* make critical TIDs observable, not a speed benchmark */
	}
	if (memory_work) {
		size_t size = 128ULL * 1024 * 1024;
		volatile unsigned char *region = mmap(NULL, size, PROT_READ | PROT_WRITE,
						    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (region == MAP_FAILED) abort();
		if (madvise((void *)region, size, MADV_NOHUGEPAGE)) {
			if (errno != EINVAL) abort();
			fprintf(stderr, "MADV_NOHUGEPAGE unavailable; use actual rusage fault truth (Guest config disables THP)\n");
		}
		for (int pass = 0; pass < 2; pass++) {
			for (size_t offset = 0; offset < size; offset += 4096) region[offset] = 1;
			if (pass == 0 && madvise((void *)region, size, MADV_DONTNEED)) abort();
		}
		if (munmap((void *)region, size)) abort();
	} else if (lock_work || reclaim_work) {
		size_t block_size = reclaim_work ? 1024 * 1024 : 256 * 1024;
		char *buffer = malloc(block_size);
		if (!buffer) abort();
		memset(buffer, 'x', block_size);
		for (int i = 0; i < (reclaim_work ? 64 : 600); i++) {
			off_t offset = reclaim_work ? (off_t)i * block_size : 0;
			if (pwrite(shared_fd, buffer, block_size, offset) != (ssize_t)block_size) abort();
		}
		free(buffer);
		if (reclaim_work) {
			if (fsync(shared_fd)) abort();
			int fd = open(reclaim_path, O_WRONLY | O_CLOEXEC);
			if (fd < 0) abort();
			ssize_t result = write(fd, "33554432\n", 9);
			if (result != 9 && errno != EAGAIN) abort();
			close(fd);
		}
	} else if (syscall_work) {
		for (unsigned int i = 0; i < 100000; i++) {
			if (syscall(SYS_getpid) != workload_pid) abort();
			getpid_completed++;
		}
	} else if (cpu_work) {
		volatile unsigned long long value = 1;
		while (ns(CLOCK_THREAD_CPUTIME_ID) - started < 400000000ULL)
			for (int i = 0; i < 1024; i++) value = value * 1664525 + 1013904223;
	} else {
		struct timespec duration = { .tv_sec = 0, .tv_nsec = 800000000 };
		while (nanosleep(&duration, &duration) && errno == EINTR) {}
	}
	if (getrusage(RUSAGE_THREAD, &usage_after)) abort();
	printf("{\"pid\":%d,\"tid\":%ld,\"worker\":%ld,\"cpu_ns\":%llu,\"wall_ns\":%llu,\"getpid_completed\":%u,\"minor_faults\":%ld,\"major_faults\":%ld}\n",
	       workload_pid, syscall(SYS_gettid), index, ns(CLOCK_THREAD_CPUTIME_ID) - started,
	       ns(CLOCK_MONOTONIC) - wall, getpid_completed,
	       usage_after.ru_minflt - usage_before.ru_minflt, usage_after.ru_majflt - usage_before.ru_majflt);
	fflush(stdout);
	return NULL;
}
int main(int argc, char **argv)
{
	pthread_t threads[4];
	if (argc < 2) return 2;
	cpu_work = argv[1][0] == 'c';
	syscall_work = argv[1][0] == 'g';
	memory_work = argv[1][0] == 'f';
	lock_work = argv[1][0] == 'l';
	reclaim_work = argv[1][0] == 'r';
	if (lock_work || reclaim_work) {
		if (argc < 3 || (reclaim_work && argc < 4)) return 2;
		shared_fd = open(argv[2], O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
		if (shared_fd < 0) return 5;
		if (reclaim_work) reclaim_path = argv[3];
	}
	workload_pid = getpid(); /* before READY, not part of selected syscall truth */
	int thread_count = syscall_work || lock_work ? 4 : reclaim_work ? 1 : cpu_work || memory_work ? 2 : 3;
	raise(SIGSTOP);
	for (long i = 0; i < thread_count; i++)
		if (pthread_create(&threads[i], NULL, worker, (void *)i)) return 3;
	for (int i = 0; i < thread_count; i++)
		if (pthread_join(threads[i], NULL)) return 4;
	if (shared_fd >= 0) { close(shared_fd); if (unlink(argv[2])) return 6; }
	return 0;
}
