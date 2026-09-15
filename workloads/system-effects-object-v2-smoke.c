// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#ifndef SYS_fchmodat2
#define SYS_fchmodat2 452
#endif

#ifndef SYS_statx
#define SYS_statx 332
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef AT_STATX_SYNC_AS_STAT
#define AT_STATX_SYNC_AS_STAT 0x0000
#endif

#define OBSERVER_STATX_INO 0x00000100U
#define OBSERVER_STATX_MNT_ID_UNIQUE 0x00004000U

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

struct socket_truth {
	uint64_t listener_cookie;
	uint64_t client_cookie;
	uint64_t accepted_cookie;
	uint16_t listener_port;
	uint16_t client_port;
	uint16_t accept_peer_port;
};

struct child_socket_truth {
	uint64_t cookie;
	uint16_t port;
};

/* Keep this private ABI definition independent of the Host libc headers.
 * The validation Guest runs the repository kernel, whose statx UAPI exposes
 * STATX_MNT_ID_UNIQUE, while an older build Host may still name offset 0x90 as
 * reserved padding. The kernel statx structure is fixed at 256 bytes.
 */
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
	uint32_t direct_io_memory_alignment;
	uint32_t direct_io_offset_alignment;
	uint64_t subvolume;
	uint32_t atomic_write_unit_min;
	uint32_t atomic_write_unit_max;
	uint32_t atomic_write_segments_max;
	uint32_t direct_io_read_offset_alignment;
	uint32_t atomic_write_unit_max_optimized;
	uint32_t spare2;
	uint64_t spare3[8];
};

_Static_assert(sizeof(struct observer_statx) == 256,
	       "statx ABI size must remain 256 bytes");
_Static_assert(offsetof(struct observer_statx, mount_id_unique) == 0x90,
	       "statx mount ID must remain at ABI offset 0x90");

struct file_truth {
	uint64_t inode;
	uint64_t mount_id_unique;
	uint32_t device_major;
	uint32_t device_minor;
};

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

static void wait_success(pid_t child, const char *operation)
{
	int status;

	if (waitpid(child, &status, 0) != child)
		fail(operation);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		errno = ECHILD;
		fail(operation);
	}
}

static uint64_t read_socket_cookie(int socket_fd, const char *operation)
{
	uint64_t cookie = 0;
	socklen_t length = sizeof(cookie);

	if (getsockopt(socket_fd, SOL_SOCKET, SO_COOKIE, &cookie, &length) != 0)
		fail(operation);
	if (length != sizeof(cookie) || cookie == 0) {
		errno = EPROTO;
		fail(operation);
	}
	return cookie;
}

static void read_file_truth(int file_fd, struct file_truth *truth)
{
	struct observer_statx extended;
	struct stat basic;

	if (fstat(file_fd, &basic) != 0)
		fail("fstat file truth");
	memset(&extended, 0, sizeof(extended));
	if (syscall(SYS_statx, file_fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT,
		    OBSERVER_STATX_INO | OBSERVER_STATX_MNT_ID_UNIQUE,
		    &extended) != 0)
		fail("statx file truth");
	if ((extended.mask & (OBSERVER_STATX_INO |
			      OBSERVER_STATX_MNT_ID_UNIQUE)) !=
	    (OBSERVER_STATX_INO | OBSERVER_STATX_MNT_ID_UNIQUE) ||
	    extended.mount_id_unique == 0 || extended.inode == 0 ||
	    extended.inode != (uint64_t)basic.st_ino ||
	    extended.device_major != (uint32_t)major(basic.st_dev) ||
	    extended.device_minor != (uint32_t)minor(basic.st_dev)) {
		errno = EOPNOTSUPP;
		fail("statx unique mount identity");
	}
	truth->inode = extended.inode;
	truth->mount_id_unique = extended.mount_id_unique;
	truth->device_major = extended.device_major;
	truth->device_minor = extended.device_minor;
}

static void exercise_socket_lifecycle(struct socket_truth *truth)
{
	struct sockaddr_in address = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	struct sockaddr_in accepted_peer;
	struct child_socket_truth child_truth;
	int truth_pipe[2];
	socklen_t address_length = sizeof(address);
	socklen_t peer_length = sizeof(accepted_peer);
	int accepted, client, listener;
	char received = 0;
	pid_t child;

	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		fail("socket listener");
	if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0)
		fail("bind listener");
	if (getsockname(listener, (struct sockaddr *)&address,
			&address_length) != 0)
		fail("getsockname listener");
	truth->listener_port = ntohs(address.sin_port);
	truth->listener_cookie = read_socket_cookie(listener,
						    "getsockopt listener cookie");
	if (truth->listener_port == 0) {
		errno = EPROTO;
		fail("listener assigned port");
	}
	if (listen(listener, 1) != 0)
		fail("listen");
	if (pipe2(truth_pipe, O_CLOEXEC) != 0)
		fail("socket truth pipe");

	child = fork();
	if (child < 0)
		fail("fork socket client");
	if (child == 0) {
		socklen_t client_length = sizeof(address);

		if (close(truth_pipe[0]) != 0)
			_exit(20);
		client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (client < 0)
			_exit(21);
		if (connect(client, (struct sockaddr *)&address,
			    sizeof(address)) != 0)
			_exit(22);
		if (getsockname(client, (struct sockaddr *)&address,
				&client_length) != 0)
			_exit(23);
		child_truth.port = ntohs(address.sin_port);
		client_length = sizeof(child_truth.cookie);
		if (getsockopt(client, SOL_SOCKET, SO_COOKIE,
			       &child_truth.cookie, &client_length) != 0 ||
		    client_length != sizeof(child_truth.cookie) ||
		    child_truth.cookie == 0 || child_truth.port == 0)
			_exit(24);
		if (write(truth_pipe[1], &child_truth,
			  sizeof(child_truth)) != (ssize_t)sizeof(child_truth))
			_exit(25);
		if (write(client, "x", 1) != 1)
			_exit(26);
		if (close(client) != 0)
			_exit(27);
		if (close(truth_pipe[1]) != 0)
			_exit(28);
		_exit(0);
	}
	if (close(truth_pipe[1]) != 0)
		fail("close socket truth writer");

	memset(&accepted_peer, 0, sizeof(accepted_peer));
	accepted = accept4(listener, (struct sockaddr *)&accepted_peer,
			   &peer_length, SOCK_CLOEXEC);
	if (accepted < 0)
		fail("accept4");
	if (peer_length != sizeof(accepted_peer) ||
	    accepted_peer.sin_family != AF_INET) {
		errno = EPROTO;
		fail("accept4 peer endpoint");
	}
	truth->accept_peer_port = ntohs(accepted_peer.sin_port);
	truth->accepted_cookie = read_socket_cookie(accepted,
						    "getsockopt accepted cookie");
	if (read(truth_pipe[0], &child_truth,
		 sizeof(child_truth)) != (ssize_t)sizeof(child_truth)) {
		errno = EPROTO;
		fail("read socket truth");
	}
	truth->client_port = child_truth.port;
	truth->client_cookie = child_truth.cookie;
	if (truth->client_port != truth->accept_peer_port ||
	    truth->listener_cookie == truth->client_cookie ||
	    truth->listener_cookie == truth->accepted_cookie ||
	    truth->client_cookie == truth->accepted_cookie) {
		errno = EPROTO;
		fail("socket truth consistency");
	}
	if (read(accepted, &received, 1) != 1 || received != 'x') {
		errno = EPROTO;
		fail("read accepted socket");
	}
	if (close(truth_pipe[0]) != 0 || close(accepted) != 0 ||
	    close(listener) != 0)
		fail("close sockets");
	wait_success(child, "wait socket client");
}

static void exercise_exec_lifecycle(void)
{
	pid_t child = fork();

	if (child < 0)
		fail("fork exec child");
	if (child == 0) {
		execl("/bin/true", "true", (char *)NULL);
		_exit(30);
	}
	wait_success(child, "wait exec child");
}

int main(int argc, char **argv)
{
	static const char initial[] = "initial-state-v2";
	static const char xattr_value[] = "observer-v2";
	char before[4096], after[4096], hardlink_one[4096], hardlink_two[4096];
	char symlink_path[4096], fifo_path[4096], unlinkat_directory[4096];
	void *mapping;
	void *private_mapping;
	struct file_truth file_truth;
	struct socket_truth socket_truth;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s NEW-DIRECTORY\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (mkdir(argv[1], 0700) != 0)
		fail("mkdir");
	make_path(before, sizeof(before), argv[1], "before.bin");
	make_path(after, sizeof(after), argv[1], "after.bin");
	make_path(hardlink_one, sizeof(hardlink_one), argv[1], "link.bin");
	make_path(hardlink_two, sizeof(hardlink_two), argv[1], "linkat.bin");
	make_path(symlink_path, sizeof(symlink_path), argv[1], "target.link");
	make_path(fifo_path, sizeof(fifo_path), argv[1], "effect.fifo");
	make_path(unlinkat_directory, sizeof(unlinkat_directory), argv[1],
		  "unlinkat-directory");

	/* Keep these deterministic operations in the real E2E workload.  The
	 * expanded observer has distinct path_symlink and path_mknod hooks; an
	 * assertion without an executing workload would only test stale evidence.
	 */
	if (symlink("before.bin", symlink_path) != 0)
		fail("symlink");
	if (mknod(fifo_path, S_IFIFO | 0600, 0) != 0)
		fail("mknod fifo");
	if (mkdir(unlinkat_directory, 0700) != 0)
		fail("mkdir unlinkat directory");

	fd = open(before, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
	if (fd < 0)
		fail("open");
	read_file_truth(fd, &file_truth);
	if (write(fd, initial, sizeof(initial)) != (ssize_t)sizeof(initial))
		fail("write initial");
	if (fchmod(fd, 0640) != 0)
		fail("fchmod");
	if (syscall(SYS_fchmodat2, AT_FDCWD, before, 0600, 0) != 0)
		fail("fchmodat2");
	if (fchown(fd, getuid(), getgid()) != 0)
		fail("fchown");
	if (fsetxattr(fd, "user.bpf_observer", xattr_value,
		      sizeof(xattr_value), 0) != 0)
		fail("fsetxattr");
	if (fremovexattr(fd, "user.bpf_observer") != 0)
		fail("fremovexattr");

	mapping = mmap(NULL, sizeof(initial), PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED)
		fail("mmap shared writable");
	memcpy(mapping, "mapped", 6);
	if (msync(mapping, sizeof(initial), MS_SYNC) != 0)
		fail("msync");
	if (munmap(mapping, sizeof(initial)) != 0)
		fail("munmap");

	/* Exercise the file_mprotect resolver itself: mmap is intentionally
	 * read-only at entry, then mprotect creates the shared file-write channel.
	 */
	mapping = mmap(NULL, sizeof(initial), PROT_READ, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED)
		fail("mmap shared read-only");
	if (mprotect(mapping, sizeof(initial), PROT_READ | PROT_WRITE) != 0)
		fail("mprotect shared writable");
	memcpy(mapping, "protected", 9);
	if (msync(mapping, sizeof(initial), MS_SYNC) != 0)
		fail("msync mprotect mapping");
	if (munmap(mapping, sizeof(initial)) != 0)
		fail("munmap mprotect mapping");

	/* This selected mprotect has no file-backed shared object. It must remain
	 * in operation history as explicit UNSUPPORTED/UNRESOLVED evidence without
	 * turning complete transport into a missing-object failure.
	 */
	private_mapping = mmap(NULL, 4096, PROT_READ,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (private_mapping == MAP_FAILED)
		fail("mmap anonymous private");
	if (mprotect(private_mapping, 4096, PROT_READ | PROT_WRITE) != 0)
		fail("mprotect anonymous private");
	memset(private_mapping, 0xa5, 4096);
	if (munmap(private_mapping, 4096) != 0)
		fail("munmap anonymous private");
	if (close(fd) != 0)
		fail("close file");
	if (link(before, hardlink_one) != 0)
		fail("link");
	if (linkat(AT_FDCWD, before, AT_FDCWD, hardlink_two, 0) != 0)
		fail("linkat");
	if (unlink(hardlink_one) != 0 ||
	    unlinkat(AT_FDCWD, hardlink_two, 0) != 0)
		fail("unlink hard links");
	if (unlinkat(AT_FDCWD, unlinkat_directory, AT_REMOVEDIR) != 0)
		fail("unlinkat directory");
	if (unlink(symlink_path) != 0 || unlink(fifo_path) != 0)
		fail("unlink created special entries");

	if (rename(before, after) != 0)
		fail("rename");
	exercise_socket_lifecycle(&socket_truth);
	exercise_exec_lifecycle();
	if (unlink(after) != 0)
		fail("unlink");
	if (rmdir(argv[1]) != 0)
		fail("rmdir");

	printf("{\"system_effects_object_v2_smoke\":\"ok\","
	       "\"file_device_major\":%u,\"file_device_minor\":%u,"
	       "\"file_inode\":%" PRIu64 ",\"file_mount_id_unique\":%" PRIu64 ","
	       "\"listener_port\":%u,\"client_port\":%u,"
	       "\"accept_peer_port\":%u,\"listener_cookie\":%" PRIu64 ","
	       "\"client_cookie\":%" PRIu64 ",\"accepted_cookie\":%" PRIu64 ","
	       "\"final_filesystem_state\":\"restored\"}\n",
	       file_truth.device_major, file_truth.device_minor, file_truth.inode,
	       file_truth.mount_id_unique, socket_truth.listener_port,
	       socket_truth.client_port,
	       socket_truth.accept_peer_port, socket_truth.listener_cookie,
	       socket_truth.client_cookie, socket_truth.accepted_cookie);
	return EXIT_SUCCESS;
}
