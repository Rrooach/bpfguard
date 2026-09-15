// SPDX-License-Identifier: GPL-2.0-only

/*
 * A deliberately inert process used by the disposable-VM deployment tests.
 * The harness installs this exact binary under Docker-init, Kata-shim, and
 * QEMU basenames so live /proc identity and closure revalidation exercise the
 * production discovery path without pretending that a real runtime exists.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;

static void handle_stop(int signal_number)
{
	(void)signal_number;
	stopping = 1;
}

static int attach_tap(const char *specification, int multi_queue)
{
	char *separator;
	char *end;
	char buffer[64];
	struct ifreq request = { 0 };
	long requested_fd;
	int opened_fd;

	if (strlen(specification) >= sizeof(buffer)) {
		fprintf(stderr, "fixture TAP specification is too long\n");
		return -1;
	}
	strcpy(buffer, specification);
	separator = strchr(buffer, ':');
	if (!separator || separator == buffer || separator[1] == '\0') {
		fprintf(stderr, "fixture TAP specification must be FD:IFNAME\n");
		return -1;
	}
	*separator++ = '\0';
	errno = 0;
	requested_fd = strtol(buffer, &end, 10);
	if (errno || *end != '\0' || requested_fd < 3 || requested_fd > 65535 ||
	    strlen(separator) >= IFNAMSIZ || strchr(separator, ':')) {
		fprintf(stderr, "invalid fixture TAP descriptor or interface\n");
		return -1;
	}
	opened_fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
	if (opened_fd < 0) {
		fprintf(stderr, "open /dev/net/tun: %s\n", strerror(errno));
		return -1;
	}
	request.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (multi_queue)
		request.ifr_flags |= IFF_MULTI_QUEUE;
	strcpy(request.ifr_name, separator);
	if (ioctl(opened_fd, TUNSETIFF, &request) != 0) {
		fprintf(stderr, "attach TAP %s: %s\n", separator, strerror(errno));
		close(opened_fd);
		return -1;
	}
	if (opened_fd != requested_fd) {
		if (dup2(opened_fd, (int)requested_fd) < 0) {
			fprintf(stderr, "dup TAP descriptor: %s\n", strerror(errno));
			close(opened_fd);
			return -1;
		}
		close(opened_fd);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct sigaction action = {
		.sa_handler = handle_stop,
	};
	int index;
	static const char tap_prefix[] = "--fixture-tap-fd=";
	static const char tap_mq_prefix[] = "--fixture-tap-mq-fd=";

	for (index = 1; index < argc; index++) {
		if (strncmp(argv[index], tap_prefix, sizeof(tap_prefix) - 1) == 0) {
			if (attach_tap(argv[index] + sizeof(tap_prefix) - 1, 0) != 0)
				return 1;
		} else if (strncmp(argv[index], tap_mq_prefix,
				   sizeof(tap_mq_prefix) - 1) == 0) {
			if (attach_tap(argv[index] + sizeof(tap_mq_prefix) - 1, 1) != 0)
				return 1;
		}
	}

	if (sigemptyset(&action.sa_mask) != 0 ||
	    sigaction(SIGINT, &action, NULL) != 0 ||
	    sigaction(SIGTERM, &action, NULL) != 0) {
		fprintf(stderr, "install signal handlers: %s\n", strerror(errno));
		return 1;
	}
	while (!stopping)
		pause();
	return 0;
}
