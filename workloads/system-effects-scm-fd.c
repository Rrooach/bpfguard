// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void fail(const char *operation)
{
	perror(operation);
	exit(EXIT_FAILURE);
}

static socklen_t make_address(struct sockaddr_un *address, const char *path)
{
	size_t length = strlen(path);

	if (length == 0 || length >= sizeof(address->sun_path)) {
		errno = ENAMETOOLONG;
		fail("Unix socket path");
	}
	memset(address, 0, sizeof(*address));
	address->sun_family = AF_UNIX;
	memcpy(address->sun_path, path, length + 1);
	return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + length + 1);
}

static int serve_fd(const char *socket_path, const char *file_path)
{
	struct sockaddr_un address;
	union {
		struct cmsghdr alignment;
		unsigned char bytes[CMSG_SPACE(sizeof(int))];
	} control;
	struct iovec iov;
	struct msghdr message;
	struct cmsghdr *header;
	char byte = 'F';
	int file_fd, listener, peer;

	file_fd = open(file_path, O_WRONLY | O_CLOEXEC);
	if (file_fd < 0)
		fail("open file for descriptor transfer");
	listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		fail("socket");
	if (unlink(socket_path) != 0 && errno != ENOENT)
		fail("unlink stale socket");
	if (bind(listener, (struct sockaddr *)&address,
		 make_address(&address, socket_path)) != 0)
		fail("bind");
	if (listen(listener, 1) != 0)
		fail("listen");
	puts("READY");
	if (fflush(stdout) != 0)
		fail("flush readiness");

	peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
	if (peer < 0)
		fail("accept4");
	memset(&control, 0, sizeof(control));
	memset(&message, 0, sizeof(message));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	header = CMSG_FIRSTHDR(&message);
	if (header == NULL) {
		errno = EPROTO;
		fail("construct SCM_RIGHTS message");
	}
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(file_fd));
	memcpy(CMSG_DATA(header), &file_fd, sizeof(file_fd));
	if (sendmsg(peer, &message, 0) != (ssize_t)sizeof(byte))
		fail("sendmsg SCM_RIGHTS");

	if (close(peer) != 0 || close(listener) != 0 || close(file_fd) != 0)
		fail("close server descriptor");
	if (unlink(socket_path) != 0)
		fail("unlink socket");
	return EXIT_SUCCESS;
}

static int receive_and_write(const char *socket_path)
{
	static const char payload[] = "x";
	struct sockaddr_un address;
	union {
		struct cmsghdr alignment;
		unsigned char bytes[CMSG_SPACE(sizeof(int))];
	} control;
	struct iovec iov;
	struct msghdr message;
	struct cmsghdr *header;
	char byte;
	int fd = -1;
	int connection;

	connection = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (connection < 0)
		fail("socket");
	if (connect(connection, (struct sockaddr *)&address,
		    make_address(&address, socket_path)) != 0)
		fail("connect");
	memset(&control, 0, sizeof(control));
	memset(&message, 0, sizeof(message));
	iov.iov_base = &byte;
	iov.iov_len = sizeof(byte);
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	if (recvmsg(connection, &message, MSG_CMSG_CLOEXEC) !=
	    (ssize_t)sizeof(byte))
		fail("recvmsg SCM_RIGHTS");
	header = CMSG_FIRSTHDR(&message);
	if (header == NULL || header->cmsg_level != SOL_SOCKET ||
	    header->cmsg_type != SCM_RIGHTS ||
	    header->cmsg_len != CMSG_LEN(sizeof(fd))) {
		errno = EPROTO;
		fail("validate SCM_RIGHTS message");
	}
	memcpy(&fd, CMSG_DATA(header), sizeof(fd));
	if (write(fd, payload, sizeof(payload) - 1) !=
	    (ssize_t)(sizeof(payload) - 1))
		fail("write transferred fd");
	if (close(fd) != 0 || close(connection) != 0)
		fail("close client descriptor");
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	if (argc == 4 && strcmp(argv[1], "serve") == 0)
		return serve_fd(argv[2], argv[3]);
	if (argc == 3 && strcmp(argv[1], "receive") == 0)
		return receive_and_write(argv[2]);
	fprintf(stderr, "usage: %s serve SOCKET FILE | receive SOCKET\n", argv[0]);
	return 2;
}
