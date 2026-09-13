// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

enum profile {
	PROFILE_QUIET,
	PROFILE_FILE,
};

static void fail(const char *operation)
{
	fprintf(stderr, "%s: %s\n", operation, strerror(errno));
	exit(EXIT_FAILURE);
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s --profile quiet|file --iterations COUNT "
		"--scratch-dir DIR [--batch-size COUNT --pause-us USEC] "
		"[--cpu CPU]\n",
		program);
}

static uint64_t parse_u64(const char *value, const char *name)
{
	char *end = NULL;
	unsigned long long result;

	errno = 0;
	result = strtoull(value, &end, 10);
	if (errno || !end || end == value || *end) {
		fprintf(stderr, "invalid %s: %s\n", name, value);
		exit(EXIT_FAILURE);
	}
	return (uint64_t)result;
}

static uint64_t timespec_ns(const struct timespec *value)
{
	return (uint64_t)value->tv_sec * UINT64_C(1000000000) +
		(uint64_t)value->tv_nsec;
}

static uint64_t timeval_ns(const struct timeval *value)
{
	return (uint64_t)value->tv_sec * UINT64_C(1000000000) +
		(uint64_t)value->tv_usec * UINT64_C(1000);
}

static void pin_to_cpu(uint64_t cpu)
{
	cpu_set_t set;

	if (cpu >= CPU_SETSIZE) {
		errno = EINVAL;
		fail("--cpu exceeds CPU_SETSIZE");
	}
	CPU_ZERO(&set);
	CPU_SET((int)cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) < 0)
		fail("sched_setaffinity");
}

static uint64_t pause_batch(uint64_t pause_us)
{
	struct timespec before;
	struct timespec after;
	struct timespec remaining = {
		.tv_sec = (time_t)(pause_us / UINT64_C(1000000)),
		.tv_nsec = (long)((pause_us % UINT64_C(1000000)) * 1000),
	};

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &before) < 0)
		fail("clock_gettime(pause start)");
	while (nanosleep(&remaining, &remaining) < 0) {
		if (errno != EINTR)
			fail("nanosleep");
	}
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &after) < 0)
		fail("clock_gettime(pause end)");
	if (timespec_ns(&after) < timespec_ns(&before)) {
		errno = ERANGE;
		fail("non-monotonic pause clock");
	}
	return timespec_ns(&after) - timespec_ns(&before);
}

static void quiet_iteration(volatile uint64_t *sink)
{
	for (unsigned int call = 0; call < 5; call++) {
		long result = syscall(__NR_getpid);

		if (result < 0)
			fail("getpid");
		*sink ^= (uint64_t)result;
	}
}

static void file_iteration(int directory_fd, uint64_t iteration,
			   volatile uint64_t *sink)
{
	const char *source = "effect-current";
	const char *renamed = "effect-renamed";
	uint64_t payload = iteration;
	ssize_t written;
	int descriptor;

	descriptor = openat(directory_fd, source,
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (descriptor < 0)
		fail("openat(effect-current)");
	written = write(descriptor, &payload, sizeof(payload));
	if (written != (ssize_t)sizeof(payload)) {
		if (written >= 0)
			errno = EIO;
		fail("write(effect-current)");
	}
	if (close(descriptor) < 0)
		fail("close(effect-current)");
	if (renameat(directory_fd, source, directory_fd, renamed) < 0)
		fail("renameat(effect-current)");
	if (unlinkat(directory_fd, renamed, 0) < 0)
		fail("unlinkat(effect-renamed)");
	*sink ^= payload;
}

int main(int argc, char **argv)
{
	enum profile profile = PROFILE_QUIET;
	const char *profile_name = NULL;
	const char *scratch_dir = NULL;
	uint64_t iterations = UINT64_MAX;
	uint64_t batch_size = 0;
	uint64_t pause_us = 0;
	uint64_t cpu = UINT64_MAX;
	uint64_t pacing_sleeps = 0;
	uint64_t pacing_sleep_ns = 0;
	volatile uint64_t sink = 0;
	struct timespec started;
	struct timespec finished;
	struct rusage usage_started;
	struct rusage usage_finished;
	uint64_t elapsed_ns;
	uint64_t user_ns;
	uint64_t system_ns;
	int directory_fd = -1;

	for (int index = 1; index < argc; index++) {
		if (!strcmp(argv[index], "--profile") && index + 1 < argc) {
			profile_name = argv[++index];
			if (!strcmp(profile_name, "quiet"))
				profile = PROFILE_QUIET;
			else if (!strcmp(profile_name, "file"))
				profile = PROFILE_FILE;
			else {
				usage(argv[0]);
				return EXIT_FAILURE;
			}
		} else if (!strcmp(argv[index], "--iterations") && index + 1 < argc) {
			iterations = parse_u64(argv[++index], "iterations");
		} else if (!strcmp(argv[index], "--scratch-dir") && index + 1 < argc) {
			scratch_dir = argv[++index];
		} else if (!strcmp(argv[index], "--batch-size") && index + 1 < argc) {
			batch_size = parse_u64(argv[++index], "batch size");
		} else if (!strcmp(argv[index], "--pause-us") && index + 1 < argc) {
			pause_us = parse_u64(argv[++index], "pause duration");
		} else if (!strcmp(argv[index], "--cpu") && index + 1 < argc) {
			cpu = parse_u64(argv[++index], "CPU");
		} else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (!profile_name || !scratch_dir || iterations == UINT64_MAX ||
	    iterations > UINT64_C(1000000) ||
	    (batch_size == 0) != (pause_us == 0) ||
	    batch_size > UINT64_C(1000000) || pause_us > UINT64_C(1000000)) {
		errno = EINVAL;
		fail("invalid workload configuration");
	}
	if (cpu != UINT64_MAX)
		pin_to_cpu(cpu);
	directory_fd = open(scratch_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (directory_fd < 0)
		fail("open(scratch directory)");
	if (unlinkat(directory_fd, "effect-current", 0) < 0 && errno != ENOENT)
		fail("remove stale effect-current");
	if (unlinkat(directory_fd, "effect-renamed", 0) < 0 && errno != ENOENT)
		fail("remove stale effect-renamed");

	if (getrusage(RUSAGE_SELF, &usage_started) < 0 ||
	    clock_gettime(CLOCK_MONOTONIC_RAW, &started) < 0)
		fail("start measurement");
	for (uint64_t iteration = 0; iteration < iterations; iteration++) {
		if (profile == PROFILE_QUIET)
			quiet_iteration(&sink);
		else
			file_iteration(directory_fd, iteration, &sink);
		if (batch_size && iteration + 1 < iterations &&
		    (iteration + 1) % batch_size == 0) {
			pacing_sleep_ns += pause_batch(pause_us);
			pacing_sleeps++;
		}
	}
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &finished) < 0 ||
	    getrusage(RUSAGE_SELF, &usage_finished) < 0)
		fail("finish measurement");
	if (close(directory_fd) < 0)
		fail("close(scratch directory)");

	if (timespec_ns(&finished) < timespec_ns(&started) ||
	    timeval_ns(&usage_finished.ru_utime) <
		timeval_ns(&usage_started.ru_utime) ||
	    timeval_ns(&usage_finished.ru_stime) <
		timeval_ns(&usage_started.ru_stime)) {
		errno = ERANGE;
		fail("non-monotonic workload counters");
	}
	elapsed_ns = timespec_ns(&finished) - timespec_ns(&started);
	user_ns = timeval_ns(&usage_finished.ru_utime) -
		timeval_ns(&usage_started.ru_utime);
	system_ns = timeval_ns(&usage_finished.ru_stime) -
		timeval_ns(&usage_started.ru_stime);
	if (pacing_sleep_ns > elapsed_ns) {
		errno = ERANGE;
		fail("pacing duration exceeds elapsed duration");
	}
	printf("{\"schema_version\":1,\"profile\":\"%s\","
	       "\"iterations\":%" PRIu64 ",\"syscalls_per_iteration\":5,"
	       "\"logical_effects_per_iteration\":%u,"
	       "\"batch_size\":%" PRIu64 ",\"pause_us\":%" PRIu64 ","
	       "\"pacing_sleeps\":%" PRIu64 ","
	       "\"pacing_sleep_ns\":%" PRIu64 ","
	       "\"elapsed_ns\":%" PRIu64 ",\"active_elapsed_ns\":%" PRIu64 ","
	       "\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 ","
	       "\"sink\":%" PRIu64 "}\n",
	       profile_name, iterations, profile == PROFILE_FILE ? 4U : 0U,
	       batch_size, pause_us, pacing_sleeps, pacing_sleep_ns, elapsed_ns,
	       elapsed_ns - pacing_sleep_ns, user_ns, system_ns, (uint64_t)sink);
	return EXIT_SUCCESS;
}
