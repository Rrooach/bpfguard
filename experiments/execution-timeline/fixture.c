/* SPDX-License-Identifier: GPL-2.0-only */
/* A controlled, real CPU/runqueue + cold file + pipe + pthread + wait4 probe.
 * It is deliberately not a benchmark score or a storage saturation test. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DATA_BYTES (64UL * 1024 * 1024)
static const char *source_path;
static uint64_t read_total;
static int channel[2];
static unsigned int reader_delay_ms;

static uint64_t now_ns(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) abort();
	return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void busy(unsigned int ms)
{
	uint64_t stop = now_ns() + (uint64_t)ms * 1000000;
	volatile uint64_t value = 7;
	while (now_ns() < stop)
		for (int i = 0; i < 10000; i++) value = value * 6364136223846793005ULL + 1;
}
static void *reader(void *unused)
{
	(void)unused;
	pthread_setname_np(pthread_self(), "cold-file-read");
	if (reader_delay_ms) {
		struct timespec delay = {.tv_nsec = (long)reader_delay_ms * 1000000};
		nanosleep(&delay, NULL);
	}
	int fd = open(source_path, O_RDONLY);
	if (fd < 0) abort();
	char data[16384];
	ssize_t n;
	while ((n = read(fd, data, sizeof(data))) > 0) read_total += n;
	if (n < 0 || close(fd) || read_total != DATA_BYTES) abort();
	return NULL;
}
static void *short_thread(void *unused)
{
	(void)unused;
	pthread_setname_np(pthread_self(), "short-lived");
	struct timespec delay = {.tv_nsec = 1000000};
	nanosleep(&delay, NULL);
	return NULL;
}
static void *pipe_writer(void *unused)
{
	(void)unused;
	pthread_setname_np(pthread_self(), "pipe-producer");
	struct timespec delay = {.tv_nsec = 80000000};
	nanosleep(&delay, NULL);
	if (write(channel[1], "timeline", 8) != 8) abort();
	return NULL;
}
static int prepare(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) { perror("prepare file"); return 1; }
	char data[65536];
	memset(data, 'x', sizeof(data));
	for (size_t n = 0; n < DATA_BYTES; n += sizeof(data))
		if (write(fd, data, sizeof(data)) != sizeof(data)) abort();
	if (fsync(fd) || posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) || close(fd)) abort();
	return 0;
}
int main(int argc, char **argv)
{
	if (argc != 3) { fprintf(stderr, "usage: fixture prepare|evict|run|join FILE\n"); return 2; }
	if (!strcmp(argv[1], "prepare")) return prepare(argv[2]);
	if (!strcmp(argv[1], "evict")) {
		int fd = open(argv[2], O_RDONLY);
		if (fd < 0 || posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED) || close(fd)) abort();
		return 0;
	}
	int join_mode = !strcmp(argv[1], "join");
	if (strcmp(argv[1], "run") && !join_mode) return 2;
	source_path = argv[2];
	cpu_set_t allowed, one;
	if (sched_getaffinity(0, sizeof(allowed), &allowed)) abort();
	CPU_ZERO(&one);
	for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) if (CPU_ISSET(cpu, &allowed)) {
		CPU_SET(cpu, &one); break;
	}
	if (sched_setaffinity(0, sizeof(one), &one)) abort();
	if (join_mode) {
		pthread_t thread;
		reader_delay_ms = 20;
		if (pthread_create(&thread, NULL, reader, NULL) || pthread_join(thread, NULL)) abort();
		printf("JOIN_FIXTURE_OK bytes=%llu\n", (unsigned long long)read_total);
		return 0;
	}
	pid_t competitor = fork();
	if (competitor < 0) abort();
	if (!competitor) { pthread_setname_np(pthread_self(), "cpu-competitor"); busy(500); return 0; }
	pid_t search = fork();
	if (search < 0) abort();
	if (!search) {
		pthread_setname_np(pthread_self(), "search-worker");
		pthread_t a, b, c;
		if (pipe(channel) || pthread_create(&a, NULL, reader, NULL)
		    || pthread_create(&b, NULL, short_thread, NULL)
		    || pthread_create(&c, NULL, pipe_writer, NULL)) abort();
		char bytes[8];
		if (read(channel[0], bytes, sizeof(bytes)) != 8) abort();
		busy(200);
		if (pthread_join(a, NULL) || pthread_join(b, NULL) || pthread_join(c, NULL)) abort();
		printf("FIXTURE_OK bytes=%llu short_thread=1 pipe_bytes=8\n", (unsigned long long)read_total);
		return 0;
	}
	int status;
	if (waitpid(search, &status, 0) != search || !WIFEXITED(status) || WEXITSTATUS(status)) abort();
	if (waitpid(competitor, &status, 0) != competitor || !WIFEXITED(status) || WEXITSTATUS(status)) abort();
	return 0;
}
