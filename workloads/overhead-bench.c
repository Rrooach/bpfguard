// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

enum bench_mode {
	MODE_NOOP,
	MODE_GETPID,
	MODE_BPF_UPDATE,
};

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s --mode noop|getpid|bpf-update "
		"--iterations COUNT [--cpu CPU] "
		"[--batch-size COUNT --pause-us MICROSECONDS]\n",
		program);
}

static void fail(const char *operation)
{
	fprintf(stderr, "%s: %s\n", operation, strerror(errno));
	exit(EXIT_FAILURE);
}

static uint64_t parse_u64(const char *value, const char *name)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(value, &end, 10);
	if (errno || !end || *end || end == value) {
		fprintf(stderr, "invalid %s: %s\n", name, value);
		exit(EXIT_FAILURE);
	}
	return (uint64_t)parsed;
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

static int sys_bpf(enum bpf_cmd command, union bpf_attr *attr)
{
	return (int)syscall(__NR_bpf, command, attr, sizeof(*attr));
}

static int create_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = 1;
	memcpy(attr.map_name, "obs_overhead", sizeof("obs_overhead"));
	return sys_bpf(BPF_MAP_CREATE, &attr);
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

static uint64_t pause_between_batches(uint64_t pause_us)
{
	struct timespec started;
	struct timespec finished;
	struct timespec remaining = {
		.tv_sec = (time_t)(pause_us / UINT64_C(1000000)),
		.tv_nsec = (long)((pause_us % UINT64_C(1000000)) * UINT64_C(1000)),
	};

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &started) < 0)
		fail("clock_gettime(pause start)");
	while (nanosleep(&remaining, &remaining) < 0) {
		if (errno != EINTR)
			fail("nanosleep");
	}
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &finished) < 0)
		fail("clock_gettime(pause finish)");
	if (timespec_ns(&finished) < timespec_ns(&started)) {
		errno = ERANGE;
		fail("non-monotonic pacing clock");
	}
	return timespec_ns(&finished) - timespec_ns(&started);
}

int main(int argc, char **argv)
{
	enum bench_mode mode = MODE_NOOP;
	const char *mode_name = NULL;
	uint64_t iterations = UINT64_MAX;
	uint64_t cpu = UINT64_MAX;
	uint64_t batch_size = 0;
	uint64_t pause_us = 0;
	uint64_t pacing_sleeps = 0;
	uint64_t pacing_sleep_ns = 0;
	uint64_t start_ns;
	uint64_t end_ns;
	uint64_t user_start;
	uint64_t system_start;
	uint64_t user_end;
	uint64_t system_end;
	uint64_t bpf_syscalls = 0;
	uint64_t ordinary_syscalls = 0;
	volatile uint64_t sink = 0;
	struct timespec started;
	struct timespec finished;
	struct rusage usage_started;
	struct rusage usage_finished;
	union bpf_attr attr;
	uint32_t key = 0;
	uint64_t value = 0;
	int map_fd = -1;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
			mode_name = argv[++i];
			if (!strcmp(mode_name, "noop"))
				mode = MODE_NOOP;
			else if (!strcmp(mode_name, "getpid"))
				mode = MODE_GETPID;
			else if (!strcmp(mode_name, "bpf-update"))
				mode = MODE_BPF_UPDATE;
			else {
				usage(argv[0]);
				return EXIT_FAILURE;
			}
		} else if (!strcmp(argv[i], "--iterations") && i + 1 < argc) {
			iterations = parse_u64(argv[++i], "iteration count");
		} else if (!strcmp(argv[i], "--cpu") && i + 1 < argc) {
			cpu = parse_u64(argv[++i], "CPU");
		} else if (!strcmp(argv[i], "--batch-size") && i + 1 < argc) {
			batch_size = parse_u64(argv[++i], "batch size");
		} else if (!strcmp(argv[i], "--pause-us") && i + 1 < argc) {
			pause_us = parse_u64(argv[++i], "pause duration");
		} else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (!mode_name || iterations == UINT64_MAX) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	if ((mode == MODE_BPF_UPDATE && iterations > 100000) ||
	    (mode != MODE_BPF_UPDATE && iterations > 100000000)) {
		errno = E2BIG;
		fail("iteration count exceeds benchmark safety bound");
	}
	if ((batch_size == 0) != (pause_us == 0) ||
	    (mode != MODE_BPF_UPDATE && (batch_size != 0 || pause_us != 0)) ||
	    batch_size > 100000 || pause_us > 1000000) {
		errno = EINVAL;
		fail("invalid pacing configuration");
	}
	if (cpu != UINT64_MAX)
		pin_to_cpu(cpu);

	if (mode == MODE_BPF_UPDATE) {
		map_fd = create_map();
		if (map_fd < 0)
			fail("BPF_MAP_CREATE");
		bpf_syscalls = 1 + iterations;
		memset(&attr, 0, sizeof(attr));
		attr.map_fd = (uint32_t)map_fd;
		attr.key = (uint64_t)(uintptr_t)&key;
		attr.value = (uint64_t)(uintptr_t)&value;
		attr.flags = BPF_ANY;
	} else if (mode == MODE_GETPID) {
		ordinary_syscalls = iterations;
	}

	if (getrusage(RUSAGE_SELF, &usage_started) < 0)
		fail("getrusage(start)");
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &started) < 0)
		fail("clock_gettime(start)");
	for (uint64_t iteration = 0; iteration < iterations; iteration++) {
		if (mode == MODE_GETPID) {
			long result = syscall(__NR_getpid);

			if (result < 0)
				fail("getpid");
			sink ^= (uint64_t)result;
		} else if (mode == MODE_BPF_UPDATE) {
			value = iteration;
			if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr) < 0)
				fail("BPF_MAP_UPDATE_ELEM");
			sink ^= value;
			if (batch_size != 0 && iteration + 1 < iterations &&
			    (iteration + 1) % batch_size == 0) {
				pacing_sleep_ns += pause_between_batches(pause_us);
				pacing_sleeps++;
			}
		} else {
			__asm__ volatile("" : "+r"(sink) : : "memory");
		}
	}
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &finished) < 0)
		fail("clock_gettime(finish)");
	if (getrusage(RUSAGE_SELF, &usage_finished) < 0)
		fail("getrusage(finish)");
	if (map_fd >= 0 && close(map_fd) < 0)
		fail("close(map_fd)");

	start_ns = timespec_ns(&started);
	end_ns = timespec_ns(&finished);
	user_start = timeval_ns(&usage_started.ru_utime);
	system_start = timeval_ns(&usage_started.ru_stime);
	user_end = timeval_ns(&usage_finished.ru_utime);
	system_end = timeval_ns(&usage_finished.ru_stime);
	if (end_ns < start_ns || user_end < user_start ||
	    system_end < system_start || pacing_sleep_ns > end_ns - start_ns) {
		errno = ERANGE;
		fail("non-monotonic benchmark counters");
	}

	printf("{\"schema_version\":1,\"mode\":\"%s\","
	       "\"iterations\":%" PRIu64 ",\"cpu\":",
	       mode_name, iterations);
	if (cpu == UINT64_MAX)
		printf("null");
	else
		printf("%" PRIu64, cpu);
	printf(",\"batch_size\":%" PRIu64 ",\"pause_us\":%" PRIu64
	       ",\"pacing_sleeps\":%" PRIu64
	       ",\"pacing_sleep_ns\":%" PRIu64
	       ",\"elapsed_ns\":%" PRIu64 ",\"active_elapsed_ns\":%" PRIu64
	       ",\"user_cpu_ns\":%" PRIu64
	       ",\"system_cpu_ns\":%" PRIu64 ",\"ordinary_syscalls\":%" PRIu64
	       ",\"bpf_syscalls\":%" PRIu64 ",\"sink\":%" PRIu64 "}\n",
	       batch_size, pause_us, pacing_sleeps, pacing_sleep_ns,
	       end_ns - start_ns, end_ns - start_ns - pacing_sleep_ns,
	       user_end - user_start, system_end - system_start,
	       ordinary_syscalls, bpf_syscalls, (uint64_t)sink);
	return EXIT_SUCCESS;
}
