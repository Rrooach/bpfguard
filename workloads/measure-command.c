// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void usage(const char *program)
{
	fprintf(stderr, "usage: %s OUTPUT -- COMMAND [ARG ...]\n", program);
}

static void fail(const char *operation)
{
	fprintf(stderr, "%s: %s\n", operation, strerror(errno));
	exit(EXIT_FAILURE);
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

int main(int argc, char **argv)
{
	const char *output;
	struct timespec started;
	struct timespec finished;
	struct rusage usage_result;
	uint64_t start_ns;
	uint64_t end_ns;
	int output_fd;
	int status;
	int exit_code = -1;
	int signal_number = 0;
	pid_t child;

	if (argc < 4 || strcmp(argv[2], "--")) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	output = argv[1];
	output_fd = open(output, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (output_fd < 0)
		fail("open(output)");
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &started) < 0)
		fail("clock_gettime(start)");
	child = fork();
	if (child < 0)
		fail("fork");
	if (child == 0) {
		execv(argv[3], &argv[3]);
		fprintf(stderr, "execv(%s): %s\n", argv[3], strerror(errno));
		_exit(127);
	}
	if (wait4(child, &status, 0, &usage_result) < 0)
		fail("wait4");
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &finished) < 0)
		fail("clock_gettime(finish)");
	if (WIFEXITED(status))
		exit_code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		signal_number = WTERMSIG(status);
	else {
		errno = ECHILD;
		fail("unexpected child status");
	}
	start_ns = timespec_ns(&started);
	end_ns = timespec_ns(&finished);
	if (end_ns < start_ns) {
		errno = ERANGE;
		fail("non-monotonic benchmark clock");
	}
	if (dprintf(output_fd,
		    "{\"schema_version\":1,\"wall_ns\":%" PRIu64
		    ",\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64
		    ",\"max_rss_kb\":%ld,\"voluntary_context_switches\":%ld"
		    ",\"involuntary_context_switches\":%ld,\"exit_code\":%d"
		    ",\"signal\":%d}\n",
		    end_ns - start_ns, timeval_ns(&usage_result.ru_utime),
		    timeval_ns(&usage_result.ru_stime), usage_result.ru_maxrss,
		    usage_result.ru_nvcsw, usage_result.ru_nivcsw, exit_code,
		    signal_number) < 0)
		fail("write(output)");
	if (fsync(output_fd) < 0)
		fail("fsync(output)");
	if (close(output_fd) < 0)
		fail("close(output)");
	if (signal_number)
		return 128 + signal_number;
	return exit_code;
}
