// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAX_THREADS 256U
#define OBSERVER_STATX_INO 0x00000100U
#define OBSERVER_STATX_MNT_ID_UNIQUE 0x00004000U

#ifndef SYS_statx
#define SYS_statx 332
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

struct observer_statx_timestamp {
	int64_t seconds;
	uint32_t nanoseconds;
	int32_t reserved;
};

struct observer_statx {
	uint32_t mask;
	uint32_t block_size;
	uint64_t attributes;
	uint32_t link_count;
	uint32_t user_id;
	uint32_t group_id;
	uint16_t mode;
	uint16_t spare0;
	uint64_t inode;
	uint64_t size;
	uint64_t blocks;
	uint64_t attributes_mask;
	struct observer_statx_timestamp access_time;
	struct observer_statx_timestamp birth_time;
	struct observer_statx_timestamp change_time;
	struct observer_statx_timestamp modification_time;
	uint32_t rdev_major;
	uint32_t rdev_minor;
	uint32_t device_major;
	uint32_t device_minor;
	uint64_t mount_id_unique;
	uint8_t tail[128];
};

struct shared_state;

struct worker_state {
	struct shared_state *shared;
	unsigned int index;
	pid_t tid;
	char comm[16];
	char path[PATH_MAX];
	int file_fd;
	uint32_t device_major;
	uint32_t device_minor;
	uint64_t inode;
	uint64_t mount_id_unique;
};

struct shared_state {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	unsigned int ready;
	unsigned int blocking_ready;
	bool released;
	bool abort;
	unsigned int threads;
	unsigned int iterations;
	int (*pipes)[2];
	atomic_int worker_error;
};

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s --threads N --iterations N --scratch-dir ABSOLUTE_PATH\n",
		program);
	exit(2);
}

static unsigned int parse_count(const char *value, unsigned int maximum,
	const char *name)
{
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(value, &end, 10);
	if (errno != 0 || end == value || *end != '\0' || parsed == 0 ||
	    parsed > maximum) {
		fprintf(stderr, "invalid %s: %s\n", name, value);
		exit(2);
	}
	return (unsigned int)parsed;
}

static uint64_t monotonic_ns(void)
{
	struct timespec value;

	if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) {
		perror("clock_gettime");
		exit(1);
	}
	return (uint64_t)value.tv_sec * UINT64_C(1000000000) +
		(uint64_t)value.tv_nsec;
}

static int fill_pipe(int read_fd, int write_fd)
{
	char buffer[4096];
	int capacity;
	ssize_t written;

	memset(buffer, 0x5a, sizeof(buffer));
	if (fcntl(write_fd, F_SETPIPE_SZ, (int)sizeof(buffer)) < 0 &&
	    errno != EPERM) {
		return -1;
	}
	capacity = fcntl(write_fd, F_GETPIPE_SZ);
	if (capacity <= 0)
		return -1;
	for (;;) {
		written = write(write_fd, buffer, sizeof(buffer));
		if (written > 0)
			continue;
		if (written < 0 && errno == EINTR)
			continue;
		if (written < 0 && errno == EAGAIN)
			break;
		return -1;
	}
	if (fcntl(write_fd, F_SETFL, fcntl(write_fd, F_GETFL) & ~O_NONBLOCK) < 0)
		return -1;
	(void)read_fd;
	return capacity;
}

static int drain_pipe(int fd)
{
	char buffer[4096];

	for (;;) {
		ssize_t count = read(fd, buffer, sizeof(buffer));

		if (count > 0)
			continue;
		if (count < 0 && errno == EINTR)
			continue;
		if (count < 0 && errno == EAGAIN)
			return 0;
		if (count == 0)
			return 0;
		return -1;
	}
}

static int read_current_syscall(pid_t tid, long *syscall_number)
{
	char path[64];
	char buffer[256];
	char *end = NULL;
	ssize_t count;
	int fd;
	long value;

	snprintf(path, sizeof(path), "/proc/self/task/%ld/syscall", (long)tid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	do {
		count = read(fd, buffer, sizeof(buffer) - 1U);
	} while (count < 0 && errno == EINTR);
	close(fd);
	if (count <= 0)
		return -1;
	buffer[count] = '\0';
	errno = 0;
	value = strtol(buffer, &end, 10);
	if (errno != 0 || end == buffer)
		return -1;
	*syscall_number = value;
	return 0;
}

static unsigned int wait_for_blocked_workers(struct worker_state *workers,
	unsigned int threads)
{
	struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000};
	unsigned int attempt;
	unsigned int index;
	unsigned int confirmed = 0;

	for (attempt = 0; attempt < 1000U; attempt++) {
		confirmed = 0;
		for (index = 0; index < threads; index++) {
			long syscall_number;

			if (read_current_syscall(workers[index].tid,
						 &syscall_number) == 0 &&
			    syscall_number == SYS_write)
				confirmed++;
		}
		if (confirmed == threads)
			return confirmed;
		nanosleep(&delay, NULL);
	}
	return confirmed;
}

static int capture_file_identity(struct worker_state *worker)
{
	struct observer_statx value;

	memset(&value, 0, sizeof(value));
	if (syscall(SYS_statx, worker->file_fd, "", AT_EMPTY_PATH,
		    OBSERVER_STATX_INO | OBSERVER_STATX_MNT_ID_UNIQUE,
		    &value) != 0)
		return -1;
	if ((value.mask & (OBSERVER_STATX_INO |
			   OBSERVER_STATX_MNT_ID_UNIQUE)) !=
	    (OBSERVER_STATX_INO | OBSERVER_STATX_MNT_ID_UNIQUE)) {
		errno = ENOTSUP;
		return -1;
	}
	worker->device_major = value.device_major;
	worker->device_minor = value.device_minor;
	worker->inode = value.inode;
	worker->mount_id_unique = value.mount_id_unique;
	return 0;
}

static void set_worker_error(struct shared_state *shared)
{
	atomic_store_explicit(&shared->worker_error, 1, memory_order_relaxed);
}

static void *worker_main(void *opaque)
{
	struct worker_state *worker = opaque;
	struct shared_state *shared = worker->shared;
	unsigned int iteration;
	char byte;
	ssize_t count;

	worker->tid = (pid_t)syscall(SYS_gettid);
	snprintf(worker->comm, sizeof(worker->comm), "ce%03u",
		 worker->index);
	if (pthread_setname_np(pthread_self(), worker->comm) != 0)
		set_worker_error(shared);

	pthread_mutex_lock(&shared->mutex);
	shared->ready++;
	pthread_cond_broadcast(&shared->condition);
	while (!shared->released && !shared->abort)
		pthread_cond_wait(&shared->condition, &shared->mutex);
	if (shared->abort) {
		pthread_mutex_unlock(&shared->mutex);
		return NULL;
	}
	pthread_mutex_unlock(&shared->mutex);

	byte = (char)(worker->index & 0x7fU);
	for (iteration = 0; iteration < shared->iterations; iteration++) {
		off_t offset = (off_t)iteration;

		count = syscall(SYS_pwrite64, worker->file_fd, &byte, 1, offset);
		if (count != 1) {
			set_worker_error(shared);
			break;
		}
	}

	pthread_mutex_lock(&shared->mutex);
	shared->blocking_ready++;
	pthread_cond_broadcast(&shared->condition);
	pthread_mutex_unlock(&shared->mutex);

	count = syscall(SYS_write, shared->pipes[worker->index][1], &byte, 1);
	if (count != 1)
		set_worker_error(shared);
	return NULL;
}

int main(int argc, char **argv)
{
	struct shared_state shared = {
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.condition = PTHREAD_COND_INITIALIZER,
	};
	struct worker_state *workers = NULL;
	pthread_t *thread_ids = NULL;
	const char *scratch_dir = NULL;
	unsigned int created = 0;
	unsigned int index;
	uint64_t started_ns;
	uint64_t finished_ns;
	struct stat file_stat;
	unsigned int overlap_confirmed = 0;
	int exit_status = 1;
	int option;

	for (option = 1; option < argc; option++) {
		if (strcmp(argv[option], "--threads") == 0 && option + 1 < argc) {
			shared.threads = parse_count(argv[++option], MAX_THREADS,
				"thread count");
		} else if (strcmp(argv[option], "--iterations") == 0 &&
			   option + 1 < argc) {
			shared.iterations = parse_count(argv[++option], 1000000U,
				"iteration count");
		} else if (strcmp(argv[option], "--scratch-dir") == 0 &&
			   option + 1 < argc) {
			scratch_dir = argv[++option];
		} else {
			usage(argv[0]);
		}
	}
	if (shared.threads == 0 || shared.iterations == 0 || scratch_dir == NULL ||
	    scratch_dir[0] != '/')
		usage(argv[0]);

	workers = calloc(shared.threads, sizeof(*workers));
	thread_ids = calloc(shared.threads, sizeof(*thread_ids));
	shared.pipes = calloc(shared.threads, sizeof(*shared.pipes));
	if (workers == NULL || thread_ids == NULL || shared.pipes == NULL) {
		perror("calloc");
		goto out;
	}
	for (index = 0; index < shared.threads; index++) {
		shared.pipes[index][0] = -1;
		shared.pipes[index][1] = -1;
		workers[index].file_fd = -1;
	}

	for (index = 0; index < shared.threads; index++) {
		int flags;
		int length;

		length = snprintf(workers[index].path, sizeof(workers[index].path),
			"%s/thread-%03u.dat", scratch_dir, index);
		if (length < 0 || (size_t)length >= sizeof(workers[index].path)) {
			errno = ENAMETOOLONG;
			perror("worker path");
			goto out;
		}
		workers[index].file_fd = open(workers[index].path,
			O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
		if (workers[index].file_fd < 0 ||
		    capture_file_identity(&workers[index]) != 0) {
			perror("open/capture worker file");
			goto out;
		}

		if (pipe2(shared.pipes[index], O_CLOEXEC | O_NONBLOCK) != 0) {
			perror("pipe2");
			goto out;
		}
		if (fill_pipe(shared.pipes[index][0], shared.pipes[index][1]) < 0) {
			perror("fill pipe");
			goto out;
		}
		flags = fcntl(shared.pipes[index][0], F_GETFL);
		if (flags < 0 ||
		    fcntl(shared.pipes[index][0], F_SETFL, flags | O_NONBLOCK) < 0) {
			perror("configure pipe reader");
			goto out;
		}
	}

	started_ns = monotonic_ns();
	for (index = 0; index < shared.threads; index++) {
		workers[index].shared = &shared;
		workers[index].index = index;
		if (pthread_create(&thread_ids[index], NULL, worker_main,
				   &workers[index]) != 0) {
			fprintf(stderr, "pthread_create failed at worker %u\n", index);
			pthread_mutex_lock(&shared.mutex);
			shared.abort = true;
			pthread_cond_broadcast(&shared.condition);
			pthread_mutex_unlock(&shared.mutex);
			goto join;
		}
		created++;
	}

	pthread_mutex_lock(&shared.mutex);
	while (shared.ready != shared.threads)
		pthread_cond_wait(&shared.condition, &shared.mutex);
	shared.released = true;
	pthread_cond_broadcast(&shared.condition);
	while (shared.blocking_ready != shared.threads)
		pthread_cond_wait(&shared.condition, &shared.mutex);
	pthread_mutex_unlock(&shared.mutex);

	overlap_confirmed = wait_for_blocked_workers(workers, shared.threads);
	if (overlap_confirmed != shared.threads) {
		fprintf(stderr, "only %u/%u workers observed inside SYS_write\n",
			overlap_confirmed, shared.threads);
		set_worker_error(&shared);
	}
	for (index = 0; index < shared.threads; index++) {
		if (drain_pipe(shared.pipes[index][0]) != 0) {
			perror("drain pipe");
			set_worker_error(&shared);
		}
	}

join:
	for (index = 0; index < created; index++) {
		if (pthread_join(thread_ids[index], NULL) != 0) {
			fprintf(stderr, "pthread_join failed at worker %u\n", index);
			set_worker_error(&shared);
		}
	}
	finished_ns = monotonic_ns();
	if (created != shared.threads ||
	    atomic_load_explicit(&shared.worker_error, memory_order_relaxed) != 0)
		goto out;
	for (index = 0; index < shared.threads; index++) {
		if (fstat(workers[index].file_fd, &file_stat) != 0) {
			perror("fstat");
			goto out;
		}
		if ((uint64_t)file_stat.st_size != shared.iterations) {
			fprintf(stderr, "unexpected output size for worker %u: %jd\n",
				index, (intmax_t)file_stat.st_size);
			goto out;
		}
	}

	printf("{\"schema_version\":1,\"tgid\":%ld,\"threads\":%u,"
	       "\"iterations\":%u,\"expected_pwrite_pairs\":%" PRIu64 ","
	       "\"expected_blocking_write_pairs\":%u,"
	       "\"overlap_confirmed_by_proc\":%u,\"started_ns\":%" PRIu64 ","
	       "\"finished_ns\":%" PRIu64 ",\"workers\":[",
	       (long)getpid(), shared.threads, shared.iterations,
	       (uint64_t)shared.threads * shared.iterations, shared.threads,
	       overlap_confirmed, started_ns, finished_ns);
	for (index = 0; index < shared.threads; index++) {
		printf("%s{\"index\":%u,\"tid\":%ld,\"comm\":\"%s\","
		       "\"device_major\":%u,\"device_minor\":%u,"
		       "\"inode\":%" PRIu64 ",\"mount_id_unique\":%" PRIu64 "}",
		       index == 0 ? "" : ",", index, (long)workers[index].tid,
		       workers[index].comm, workers[index].device_major,
		       workers[index].device_minor, workers[index].inode,
		       workers[index].mount_id_unique);
	}
	printf("]}\n");
	if (fflush(stdout) != 0) {
		perror("fflush");
		goto out;
	}
	exit_status = 0;

out:
	if (shared.pipes != NULL) {
		for (index = 0; index < shared.threads; index++) {
			if (workers != NULL && workers[index].file_fd >= 0)
				close(workers[index].file_fd);
			if (shared.pipes[index][0] >= 0)
				close(shared.pipes[index][0]);
			if (shared.pipes[index][1] >= 0)
				close(shared.pipes[index][1]);
		}
	}
	free(shared.pipes);
	free(thread_ids);
	free(workers);
	return exit_status;
}
