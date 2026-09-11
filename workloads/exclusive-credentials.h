/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_OBSERVER_EXCLUSIVE_CREDENTIALS_H
#define BPF_OBSERVER_EXCLUSIVE_CREDENTIALS_H

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef CAP_PERFMON
#define CAP_PERFMON 38
#endif
#ifndef CAP_BPF
#define CAP_BPF 39
#endif

#define EXCLUSIVE_UID ((uid_t)65534)
#define EXCLUSIVE_GID ((gid_t)65534)
#define EXCLUSIVE_OBSERVER_BOUNDING                                      \
	((UINT64_C(1) << CAP_SYS_ADMIN) | (UINT64_C(1) << CAP_PERFMON) | \
	 (UINT64_C(1) << CAP_BPF))
#define EXCLUSIVE_LOCKED_SECUREBITS                                      \
	(SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP | \
	 SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED |        \
	 SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)

struct exclusive_bpf_fdinfo_fields {
	bool object_id;
	bool token_allowed_cmds;
	bool token_allowed_maps;
	bool token_allowed_progs;
	bool token_allowed_attachs;
};

static void exclusive_inspect_fdinfo_line(
	struct exclusive_bpf_fdinfo_fields *fields, const char *line)
{
	if (!strncmp(line, "prog_id:", 8) || !strncmp(line, "map_id:", 7) ||
	    !strncmp(line, "link_id:", 8) || !strncmp(line, "btf_id:", 7))
		fields->object_id = true;
	else if (!strncmp(line, "allowed_cmds:", 13))
		fields->token_allowed_cmds = true;
	else if (!strncmp(line, "allowed_maps:", 13))
		fields->token_allowed_maps = true;
	else if (!strncmp(line, "allowed_progs:", 14))
		fields->token_allowed_progs = true;
	else if (!strncmp(line, "allowed_attachs:", 16))
		fields->token_allowed_attachs = true;
}

static bool exclusive_fdinfo_describes_bpf(
	const struct exclusive_bpf_fdinfo_fields *fields)
{
	return fields->object_id ||
	       (fields->token_allowed_cmds && fields->token_allowed_maps &&
		fields->token_allowed_progs && fields->token_allowed_attachs);
}

static int exclusive_process_has_bpf_fd(void)
{
	DIR *directory = opendir("/proc/self/fdinfo");
	struct dirent *entry;
	int result = 0;

	if (!directory)
		return -1;
	while ((entry = readdir(directory)) != NULL) {
		struct exclusive_bpf_fdinfo_fields fields = { 0 };
		const char *cursor = entry->d_name;
		char path[128];
		char line[256];
		FILE *file;
		int file_failed;

		if (!*cursor)
			continue;
		while (*cursor && isdigit((unsigned char)*cursor))
			cursor++;
		if (*cursor)
			continue;
		if (snprintf(path, sizeof(path), "/proc/self/fdinfo/%s",
			     entry->d_name) >= (int)sizeof(path)) {
			result = -1;
			break;
		}
		file = fopen(path, "re");
		if (!file) {
			result = -1;
			break;
		}
		while (fgets(line, sizeof(line), file))
			exclusive_inspect_fdinfo_line(&fields, line);
		file_failed = ferror(file);
		if (fclose(file) < 0)
			file_failed = 1;
		if (file_failed) {
			result = -1;
			break;
		}
		if (exclusive_fdinfo_describes_bpf(&fields)) {
			result = 1;
			break;
		}
	}
	if (closedir(directory) < 0)
		result = -1;
	return result;
}

static uint64_t exclusive_bounding_mask(void)
{
	uint64_t mask = 0;
	int capability;

	for (capability = 0; capability < 64; capability++) {
		int present = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);

		if (present < 0) {
			if (errno == EINVAL)
				break;
			return UINT64_MAX;
		}
		if (present)
			mask |= UINT64_C(1) << capability;
	}
	return mask;
}

static uint64_t exclusive_ambient_mask(void)
{
	uint64_t mask = 0;
	int capability;

	for (capability = 0; capability < 64; capability++) {
		int present = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
				    capability, 0, 0);

		if (present < 0) {
			if (errno == EINVAL)
				break;
			return UINT64_MAX;
		}
		if (present)
			mask |= UINT64_C(1) << capability;
	}
	return mask;
}

/* Run before installing seccomp and before issuing the fixture's first bpf().
 * This proves the file-capability transition, rather than merely trusting the
 * provisioning command that was intended to create it. */
static int assert_exclusive_credentials(uint64_t expected_effective)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2] = { 0 };
	uid_t real_uid, effective_uid, saved_uid;
	gid_t real_gid, effective_gid, saved_gid;
	uint64_t effective;
	uint64_t permitted;
	uint64_t inheritable;
	int securebits;
	int no_new_privs;

	if (getresuid(&real_uid, &effective_uid, &saved_uid) < 0 ||
	    getresgid(&real_gid, &effective_gid, &saved_gid) < 0 ||
	    real_uid != EXCLUSIVE_UID || effective_uid != EXCLUSIVE_UID ||
	    saved_uid != EXCLUSIVE_UID || real_gid != EXCLUSIVE_GID ||
	    effective_gid != EXCLUSIVE_GID || saved_gid != EXCLUSIVE_GID ||
	    getgroups(0, NULL) != 0)
		goto rejected;
	if (syscall(SYS_capget, &header, data) < 0)
		goto rejected;
	effective = data[0].effective | ((uint64_t)data[1].effective << 32);
	permitted = data[0].permitted | ((uint64_t)data[1].permitted << 32);
	inheritable = data[0].inheritable |
		      ((uint64_t)data[1].inheritable << 32);
	securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
	no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (effective != expected_effective || permitted != expected_effective ||
	    inheritable != 0 ||
	    exclusive_bounding_mask() != EXCLUSIVE_OBSERVER_BOUNDING ||
	    exclusive_ambient_mask() != 0 ||
	    securebits != EXCLUSIVE_LOCKED_SECUREBITS || no_new_privs != 0 ||
	    exclusive_process_has_bpf_fd() != 0)
		goto rejected;
	return 0;

rejected:
	errno = EPERM;
	return -1;
}

#endif /* BPF_OBSERVER_EXCLUSIVE_CREDENTIALS_H */
