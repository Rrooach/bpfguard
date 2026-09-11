// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/securebits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC 0xcafe4a11
#endif
#ifndef DEVTMPFS_MAGIC
/* devtmpfs uses the tmpfs superblock magic. */
#define DEVTMPFS_MAGIC TMPFS_MAGIC
#endif
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC 0x1cd1
#endif
#ifndef TRACEFS_MAGIC
#define TRACEFS_MAGIC 0x74726163
#endif
#ifndef CAP_PERFMON
#define CAP_PERFMON 38
#endif
#ifndef CAP_BPF
#define CAP_BPF 39
#endif
/* BPF command 31 was added after the headers on some supported build hosts. */
#ifndef BPF_LINK_GET_NEXT_ID
#define BPF_LINK_GET_NEXT_ID ((enum bpf_cmd)31)
#endif
#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000UL
#endif
#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#define STRICT_STATX_MNT_ID(state) ((state).__spare2[0])
#else
#define STRICT_STATX_MNT_ID(state) ((state).stx_mnt_id)
#endif

#define ARRAY_SIZE(values) (sizeof(values) / sizeof((values)[0]))
#define STRICT_UID ((uid_t)65534)
#define STRICT_GID ((gid_t)65534)
#define INPUT_ROOT "/opt/bpf-state-observer-exclusive-e2e"
#define EVIDENCE_ROOT "/evidence"
#define OUTPUT_ROOT EVIDENCE_ROOT "/results"
#define SUPERVISOR_REPORT_ROOT EVIDENCE_ROOT "/supervisor"
#define EVIDENCE_DEVICE "/dev/vdb"
#define STRICT_INIT INPUT_ROOT "/strict-init"
#define STRICT_RUNNER INPUT_ROOT "/guest-strict-e2e.sh"
#define OBSERVER INPUT_ROOT "/bpf-state-observer"
#define ASSERT_BINARY INPUT_ROOT "/vm-e2e-assert"
#define OUTSIDER_GATE INPUT_ROOT "/vm-outsider-gate-assert"
#define MAP_WORKLOAD INPUT_ROOT "/map-lifecycle"
#define NOOP_WORKLOAD INPUT_ROOT "/exclusive-noop"
#define RECORDER_OBJECT INPUT_ROOT "/recorder.bpf.o"
#define EXCLUSIVE_SCOPE INPUT_ROOT "/exclusive-vm-scope.json"
#define HARNESS_PUBLIC_KEY INPUT_ROOT "/harness-public.key"
#define HARNESS_WRONG_PUBLIC_KEY INPUT_ROOT "/wrong-harness-public.key"
#define CGROUP_ROOT "/sys/fs/cgroup/bpf-state-observer"
#define EXCLUSIVE_BPF_ROOT "/sys/fs/bpf/bpf-state-observer-exclusive-e2e"
#define INIT_STATUS SUPERVISOR_REPORT_ROOT "/strict-init.status"
#define GUEST_STATUS OUTPUT_ROOT "/guest-e2e-status"
#define FINAL_INVENTORY_STATUS OUTPUT_ROOT "/final-global-inventory.status"
#define RUNNER_TIMEOUT_SECONDS 180
#define MAX_CMDLINE_BYTES 8192
#define MAX_KERNEL_IDENTITY_BYTES 2048
#define RECORDER_ENV_PREFIX "BPF_OBSERVER_RECORDER_SHA256="
#define POLICY_ID_ENV_PREFIX "BPF_OBSERVER_HARNESS_POLICY_ID="
#define POLICY_SHA_ENV_PREFIX "BPF_OBSERVER_HARNESS_POLICY_SHA256="
#define KERNEL_IDENTITY_ENV_PREFIX "BPF_OBSERVER_HARNESS_KERNEL_IDENTITY="

/* The experiment kernel intentionally still guards global BPF ID enumeration
 * and get-FD-by-ID with CAP_SYS_ADMIN. CAP_BPF and CAP_PERFMON cover recorder
 * load and tracepoint attachment. No other capability crosses into the runner
 * branch's bounding set. */
#define OBSERVER_CAP_MASK                                                   \
	((UINT64_C(1) << CAP_SYS_ADMIN) | (UINT64_C(1) << CAP_PERFMON) |     \
	 (UINT64_C(1) << CAP_BPF))
#define MAP_WORKLOAD_CAP_MASK (UINT64_C(1) << CAP_BPF)
#define PID1_CAP_MASK (UINT64_C(1) << CAP_SYS_BOOT)
#define LOCKED_NOROOT_SECUREBITS                                            \
	(SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |    \
	 SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_KEEP_CAPS_LOCKED |           \
	 SECBIT_NO_CAP_AMBIENT_RAISE | SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED)

struct boot_parameters {
	char recorder_sha256[65];
	char policy_id[256];
	char policy_sha256[65];
	char kernel_identity[MAX_KERNEL_IDENTITY_BYTES + 1];
};

struct capability_state {
	uint64_t effective;
	uint64_t permitted;
	uint64_t inheritable;
	uint64_t bounding;
	uint64_t ambient;
	int securebits;
	int no_new_privs;
};

struct harness_device {
	char path[64];
	unsigned int major;
	unsigned int minor;
};

struct bpf_fdinfo_fields {
	bool object_id;
	bool token_allowed_cmds;
	bool token_allowed_maps;
	bool token_allowed_progs;
	bool token_allowed_attachs;
};

__attribute__((noreturn)) static void power_off_forever(void)
{
	sync();
	if (reboot(RB_POWER_OFF) < 0)
		dprintf(STDERR_FILENO, "strict-init: poweroff failed: %s\n",
			strerror(errno));
	for (;;)
		pause();
}

__attribute__((format(printf, 1, 2), noreturn))
static void fatal(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	dprintf(STDERR_FILENO, "strict-init: FATAL: ");
	vdprintf(STDERR_FILENO, format, arguments);
	dprintf(STDERR_FILENO, "\n");
	va_end(arguments);
	/* Do not cache this before fork: a runner-child failure must exit so that
	 * PID1 can reap it, record FAIL, and perform the terminal poweroff. */
	if (getpid() == 1)
		power_off_forever();
	exit(EXIT_FAILURE);
}

static void require(bool condition, const char *message)
{
	if (!condition)
		fatal("%s", message);
}

__attribute__((format(printf, 2, 3)))
static bool append_report(int descriptor, const char *format, ...)
{
	va_list arguments;
	int result;

	va_start(arguments, format);
	result = vdprintf(descriptor, format, arguments);
	va_end(arguments);
	return result >= 0;
}

static bool is_directory_empty(const char *path)
{
	DIR *directory;
	struct dirent *entry;
	bool empty = true;

	directory = opendir(path);
	if (!directory)
		return false;
	while ((entry = readdir(directory)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		empty = false;
		break;
	}
	closedir(directory);
	return empty;
}

static void ensure_directory(const char *path, mode_t mode)
{
	struct stat state;

	if (lstat(path, &state) == 0) {
		if (!S_ISDIR(state.st_mode) || S_ISLNK(state.st_mode))
			fatal("%s is not a real directory", path);
		return;
	}
	if (errno != ENOENT || mkdir(path, mode) < 0)
		fatal("create directory %s: %s", path, strerror(errno));
}

static uint64_t path_mount_id(const char *path)
{
	struct statx state = { 0 };

	if (statx(AT_FDCWD, path, AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW,
		  STATX_MNT_ID, &state) < 0)
		fatal("statx mount ID for %s: %s", path, strerror(errno));
	if (!(state.stx_mask & STATX_MNT_ID))
		fatal("kernel omitted mount ID for %s", path);
	return STRICT_STATX_MNT_ID(state);
}

static bool is_exact_mountpoint(const char *path)
{
	char parent[256];
	char *separator;
	size_t length = strlen(path);

	if (length < 2 || length >= sizeof(parent) || path[0] != '/' ||
	    path[length - 1] == '/')
		fatal("invalid fixed mountpoint path %s", path);
	memcpy(parent, path, length + 1);
	separator = strrchr(parent, '/');
	if (separator == parent)
		parent[1] = '\0';
	else
		*separator = '\0';
	return path_mount_id(path) != path_mount_id(parent);
}

static void mount_or_verify(const char *source, const char *target,
			    const char *filesystem, unsigned long flags,
			    const char *data, long expected_magic)
{
	struct statfs state;
	struct statvfs mount_flags;
	bool already_mounted;

	already_mounted = is_exact_mountpoint(target);
	if (already_mounted) {
		if (statfs(target, &state) < 0 ||
		    (long)state.f_type != expected_magic)
			fatal("existing mount at %s is not %s", target,
			      filesystem);
		if (mount(NULL, target, NULL, MS_REMOUNT | flags, data) < 0)
			fatal("remount %s with strict flags: %s", target,
			      strerror(errno));
	} else if (mount(source, target, filesystem, flags, data) < 0)
		fatal("mount %s on %s: %s", filesystem, target,
		      strerror(errno));
	if (statfs(target, &state) < 0 || (long)state.f_type != expected_magic)
		fatal("%s is not a %s mount", target, filesystem);
	if (statvfs(target, &mount_flags) < 0)
		fatal("read mount flags for %s: %s", target, strerror(errno));
	if (!!(mount_flags.f_flag & ST_RDONLY) != !!(flags & MS_RDONLY) ||
	    ((flags & MS_NOSUID) && !(mount_flags.f_flag & ST_NOSUID)) ||
	    ((flags & MS_NODEV) && !(mount_flags.f_flag & ST_NODEV)) ||
	    ((flags & MS_NOEXEC) && !(mount_flags.f_flag & ST_NOEXEC)))
		fatal("%s does not expose the requested strict mount flags", target);
}

static void prepare_mounts(void)
{
	struct statvfs root;
	struct rlimit memlock = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	struct rlimit core = {
		.rlim_cur = 0,
		.rlim_max = 0,
	};

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
		fatal("make root mount propagation private: %s", strerror(errno));

	ensure_directory("/dev", 0755);
	mount_or_verify("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC,
			"mode=0755", DEVTMPFS_MAGIC);
	ensure_directory("/dev/pts", 0755);
	mount_or_verify("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
			"newinstance,ptmxmode=0666,mode=0620", DEVPTS_SUPER_MAGIC);
	ensure_directory("/dev/shm", 01777);
	mount_or_verify("tmpfs", "/dev/shm", "tmpfs",
			MS_NOSUID | MS_NODEV | MS_NOEXEC,
			"mode=1777,size=16m", TMPFS_MAGIC);

	ensure_directory("/proc", 0555);
	mount_or_verify("proc", "/proc", "proc",
			MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL, PROC_SUPER_MAGIC);
	ensure_directory("/sys", 0555);
	mount_or_verify("sysfs", "/sys", "sysfs",
			MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL,
			SYSFS_MAGIC);

	ensure_directory("/sys/fs/cgroup", 0755);
	mount_or_verify("none", "/sys/fs/cgroup", "cgroup2",
			MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL,
			CGROUP2_SUPER_MAGIC);
	if (chmod("/sys/fs/cgroup", 0755) < 0)
		fatal("set cgroup2 root cleanup permissions: %s", strerror(errno));
	{
		struct stat state;

		if (lstat("/sys/fs/cgroup", &state) < 0 ||
		    !S_ISDIR(state.st_mode) || S_ISLNK(state.st_mode) ||
		    state.st_uid != 0 || (state.st_mode & 0777) != 0755)
			fatal("cgroup2 root cleanup permissions were not retained");
	}
	ensure_directory("/sys/kernel/tracing", 0755);
	mount_or_verify("tracefs", "/sys/kernel/tracing", "tracefs",
			MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
			"gid=65534,mode=0550",
			TRACEFS_MAGIC);
	ensure_directory("/sys/fs/bpf", 0755);
	mount_or_verify("bpf", "/sys/fs/bpf", "bpf",
			MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL, BPF_FS_MAGIC);

	ensure_directory("/run", 0755);
	mount_or_verify("tmpfs", "/run", "tmpfs",
			MS_NOSUID | MS_NODEV | MS_NOEXEC,
			"mode=0755,size=16m", TMPFS_MAGIC);
	ensure_directory("/tmp", 01777);
	mount_or_verify("tmpfs", "/tmp", "tmpfs",
			MS_NOSUID | MS_NODEV | MS_NOEXEC,
			"mode=1777,size=64m", TMPFS_MAGIC);

	if (statvfs("/", &root) < 0)
		fatal("stat root filesystem: %s", strerror(errno));
	if (!(root.f_flag & ST_RDONLY))
		fatal("provisioned strict root must be mounted read-only");
	if (root.f_flag & ST_NOSUID)
		fatal("root filesystem is nosuid; exact file capabilities cannot work");
	if (setrlimit(RLIMIT_MEMLOCK, &memlock) < 0)
		fatal("raise inherited memlock limit: %s", strerror(errno));
	if (setrlimit(RLIMIT_CORE, &core) < 0)
		fatal("disable userspace core dumps: %s", strerror(errno));
}

static void prepare_evidence_filesystem(void)
{
	struct stat device;
	struct stat target;
	struct statvfs flags;
	struct timespec delay = {
		.tv_sec = 0,
		.tv_nsec = 25000000,
	};
	int attempts;
	DIR *directory;
	struct dirent *entry;

	for (attempts = 0; attempts < 400; attempts++) {
		if (lstat(EVIDENCE_DEVICE, &device) == 0 &&
		    S_ISBLK(device.st_mode) && !S_ISLNK(device.st_mode))
			break;
		nanosleep(&delay, NULL);
	}
	if (attempts == 400)
		fatal("evidence block device %s did not appear", EVIDENCE_DEVICE);
	if (lstat(EVIDENCE_ROOT, &target) < 0 || !S_ISDIR(target.st_mode) ||
	    S_ISLNK(target.st_mode))
		fatal("read-only provisioned root omits real mountpoint %s",
		      EVIDENCE_ROOT);
	if (mount(EVIDENCE_DEVICE, EVIDENCE_ROOT, "ext4",
		  MS_NOSUID | MS_NODEV | MS_NOEXEC, "errors=remount-ro") < 0)
		fatal("mount evidence disk %s: %s", EVIDENCE_DEVICE,
		      strerror(errno));
	{
		struct statfs filesystem;

		if (statfs(EVIDENCE_ROOT, &filesystem) < 0 ||
		    (long)filesystem.f_type != EXT4_SUPER_MAGIC)
			fatal("evidence device is not ext4");
	}
	if (statvfs(EVIDENCE_ROOT, &flags) < 0)
		fatal("read evidence mount flags: %s", strerror(errno));
	if (flags.f_flag & ST_RDONLY || !(flags.f_flag & ST_NOSUID) ||
	    !(flags.f_flag & ST_NODEV) || !(flags.f_flag & ST_NOEXEC))
		fatal("evidence filesystem lacks rw,nosuid,nodev,noexec contract");

	/* A freshly formatted ext4 filesystem contains at most lost+found. The
	 * results directory is then an atomic claim made by measured PID1. */
	directory = opendir(EVIDENCE_ROOT);
	if (!directory)
		fatal("open evidence root: %s", strerror(errno));
	while ((entry = readdir(directory)) != NULL) {
		char path[sizeof(EVIDENCE_ROOT) + 32];
		struct stat state;

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		if (strcmp(entry->d_name, "lost+found"))
			fatal("evidence filesystem is not fresh: unexpected %s",
			      entry->d_name);
		snprintf(path, sizeof(path), "%s/lost+found", EVIDENCE_ROOT);
		if (lstat(path, &state) < 0 || !S_ISDIR(state.st_mode) ||
		    S_ISLNK(state.st_mode) || !is_directory_empty(path))
			fatal("evidence lost+found is not an empty real directory");
	}
	closedir(directory);
	if (mkdir(SUPERVISOR_REPORT_ROOT, 0755) < 0 ||
	    chmod(SUPERVISOR_REPORT_ROOT, 0755) < 0)
		fatal("claim supervisor report directory: %s", strerror(errno));
	if (mkdir(OUTPUT_ROOT, 0711) < 0 ||
	    chown(OUTPUT_ROOT, STRICT_UID, STRICT_GID) < 0 ||
	    chmod(OUTPUT_ROOT, 0711) < 0)
		fatal("claim evidence results directory: %s", strerror(errno));
}

static int read_small_value(const char *path, char *value, size_t capacity)
{
	int descriptor;
	ssize_t length;
	char extra;

	if (capacity < 2)
		return -1;
	descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		return -1;
	length = read(descriptor, value, capacity - 1);
	if (length <= 0 || read(descriptor, &extra, 1) != 0) {
		close(descriptor);
		return -1;
	}
	close(descriptor);
	value[length] = '\0';
	while (length > 0 && (value[length - 1] == '\n' ||
			      value[length - 1] == '\r'))
		value[--length] = '\0';
	return length > 0 ? 0 : -1;
}

static void require_block_read_only_state(const char *path,
					  const char *expected)
{
	char value[16];

	if (read_small_value(path, value, sizeof(value)) < 0 ||
	    strcmp(value, expected))
		fatal("block-device read-only state at %s is not %s", path,
		      expected);
}

static void write_control_value(const char *path, const char *value)
{
	int descriptor;
	size_t length = strlen(value);
	ssize_t written;

	descriptor = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		fatal("open kernel control %s: %s", path, strerror(errno));
	written = write(descriptor, value, length);
	if (written != (ssize_t)length) {
		int saved = errno;

		close(descriptor);
		fatal("write kernel control %s: %s", path, strerror(saved));
	}
	if (close(descriptor) < 0)
		fatal("close kernel control %s: %s", path, strerror(errno));
}

static void permanently_disable_unprivileged_bpf(void)
{
	static const char path[] = "/proc/sys/kernel/unprivileged_bpf_disabled";
	char value[32];

	/* Value 1 is the kernel's irreversible-until-reboot state. Value 2 is
	 * merely an administrator-reversible default and is not sufficient for
	 * the strict actor boundary. */
	write_control_value(path, "1\n");
	if (read_small_value(path, value, sizeof(value)) < 0 || strcmp(value, "1"))
		fatal("kernel did not enter irreversible unprivileged-BPF disabled state");
}

static bool kernel_control_is_empty(const char *path)
{
	char value[32];
	char extra;
	ssize_t length;
	int descriptor;

	descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		fatal("open kernel control %s: %s", path, strerror(errno));
	length = read(descriptor, value, sizeof(value) - 1);
	if (length < 0 || read(descriptor, &extra, 1) != 0) {
		int saved = errno;

		close(descriptor);
		fatal("read kernel control %s: %s", path, strerror(saved));
	}
	if (close(descriptor) < 0)
		fatal("close kernel control %s: %s", path, strerror(errno));
	while (length > 0 && (value[length - 1] == '\n' ||
			      value[length - 1] == '\r'))
		length--;
	return length == 0;
}

static const char *permanently_disable_module_loading(void)
{
	static const char modules_path[] = "/proc/sys/kernel/modules_disabled";
	static const char modprobe_path[] = "/proc/sys/kernel/modprobe";
	struct stat state;
	char value[32];

	if (lstat(modules_path, &state) < 0) {
		if (errno == ENOENT)
			return "MODULES_NOT_SUPPORTED";
		fatal("inspect kernel module control: %s", strerror(errno));
	}
	if (!S_ISREG(state.st_mode) || S_ISLNK(state.st_mode))
		fatal("kernel module control is not a regular procfs node");
	write_control_value(modules_path, "1\n");
	if (read_small_value(modules_path, value, sizeof(value)) < 0 ||
	    strcmp(value, "1"))
		fatal("kernel did not irreversibly disable module loading");

	/* modules_disabled rejects insertion, while an empty modprobe path also
	 * prevents request_module() from spawning even a doomed userspace helper. */
	write_control_value(modprobe_path, "\n");
	if (!kernel_control_is_empty(modprobe_path))
		fatal("kernel modprobe helper path remains enabled");
	return "DISABLED_IRREVERSIBLY_AND_HELPER_CLEARED";
}

static struct harness_device prepare_harness_device(void)
{
	static const char expected_name[] = "org.allox.harness";
	struct harness_device result;
	struct timespec delay = {
		.tv_sec = 0,
		.tv_nsec = 25000000,
	};
	int attempts;

	memset(&result, 0, sizeof(result));
	for (attempts = 0; attempts < 400; attempts++) {
		DIR *ports = opendir("/sys/class/virtio-ports");
		struct dirent *entry;
		char match[64] = "";
		unsigned int matches = 0;

		if (ports) {
			while ((entry = readdir(ports)) != NULL) {
				char name_path[256];
				char name[128];
				const char *cursor;

				if (entry->d_name[0] == '.')
					continue;
				for (cursor = entry->d_name; *cursor; cursor++) {
					if (!isalnum((unsigned char)*cursor))
						fatal("unsafe virtio-port sysfs name");
				}
				if (snprintf(name_path, sizeof(name_path),
					     "/sys/class/virtio-ports/%s/name",
					     entry->d_name) >= (int)sizeof(name_path))
					fatal("virtio-port sysfs path overflow");
				if (read_small_value(name_path, name, sizeof(name)) < 0 ||
				    strcmp(name, expected_name))
					continue;
				matches++;
				if (strlen(entry->d_name) + 1 > sizeof(match))
					fatal("virtio-port device name exceeds bound");
				strcpy(match, entry->d_name);
			}
			closedir(ports);
		}
		if (matches > 1)
			fatal("multiple virtio ports claim %s", expected_name);
		if (matches == 1) {
			char dev_path[256];
			char dev_value[64];
			struct stat state;
			unsigned int sys_major;
			unsigned int sys_minor;
			char trailing;

			if (snprintf(result.path, sizeof(result.path), "/dev/%s",
				     match) >= (int)sizeof(result.path) ||
			    snprintf(dev_path, sizeof(dev_path),
				     "/sys/class/virtio-ports/%s/dev", match) >=
				    (int)sizeof(dev_path))
				fatal("virtio-port device path overflow");
			if (read_small_value(dev_path, dev_value,
					     sizeof(dev_value)) == 0 &&
			    sscanf(dev_value, "%u:%u%c", &sys_major, &sys_minor,
				   &trailing) == 2 &&
			    lstat(result.path, &state) == 0 && S_ISCHR(state.st_mode) &&
			    !S_ISLNK(state.st_mode) &&
			    major(state.st_rdev) == sys_major &&
			    minor(state.st_rdev) == sys_minor) {
				if (chown(result.path, STRICT_UID, STRICT_GID) < 0 ||
				    chmod(result.path, 0600) < 0)
					fatal("delegate exact harness device %s: %s",
					      result.path, strerror(errno));
				result.major = sys_major;
				result.minor = sys_minor;
				return result;
			}
		}
		nanosleep(&delay, NULL);
	}
	fatal("unique authenticated virtio-serial device did not appear");
}

static void inspect_bpf_fdinfo_line(struct bpf_fdinfo_fields *fields,
				    const char *line)
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

static bool fdinfo_describes_bpf(const struct bpf_fdinfo_fields *fields)
{
	return fields->object_id ||
	       (fields->token_allowed_cmds && fields->token_allowed_maps &&
		fields->token_allowed_progs && fields->token_allowed_attachs);
}

static bool process_has_bpf_descriptor(pid_t pid)
{
	char directory_path[64];
	DIR *directory;
	struct dirent *entry;
	bool found = false;

	if (snprintf(directory_path, sizeof(directory_path), "/proc/%ld/fdinfo",
		     (long)pid) >= (int)sizeof(directory_path))
		fatal("fdinfo directory path overflow");
	directory = opendir(directory_path);
	if (!directory)
		fatal("open %s: %s", directory_path, strerror(errno));
	while ((entry = readdir(directory)) != NULL && !found) {
		struct bpf_fdinfo_fields fields = { 0 };
		char path[128];
		char line[256];
		FILE *file;
		const char *cursor = entry->d_name;

		if (!*cursor)
			continue;
		while (*cursor && isdigit((unsigned char)*cursor))
			cursor++;
		if (*cursor)
			continue;
		if (snprintf(path, sizeof(path), "%s/%s", directory_path,
			     entry->d_name) >= (int)sizeof(path))
			fatal("fdinfo path overflow");
		file = fopen(path, "re");
		if (!file)
			fatal("open %s: %s", path, strerror(errno));
		while (fgets(line, sizeof(line), file))
			inspect_bpf_fdinfo_line(&fields, line);
		if (ferror(file))
			fatal("read %s: %s", path, strerror(errno));
		if (fclose(file) < 0)
			fatal("close %s: %s", path, strerror(errno));
		found = fdinfo_describes_bpf(&fields);
	}
	closedir(directory);
	return found;
}

static void reopen_console(void)
{
	int descriptor = open("/dev/console", O_RDWR | O_NOCTTY | O_CLOEXEC);

	if (descriptor < 0)
		return;
	if (dup2(descriptor, STDIN_FILENO) < 0 ||
	    dup2(descriptor, STDOUT_FILENO) < 0 ||
	    dup2(descriptor, STDERR_FILENO) < 0)
		fatal("connect standard streams to /dev/console: %s", strerror(errno));
	if (descriptor > STDERR_FILENO)
		close(descriptor);
}

static bool is_lower_hex(const char *value, size_t expected_length)
{
	size_t index;

	if (strlen(value) != expected_length)
		return false;
	for (index = 0; index < expected_length; index++) {
		if (!((value[index] >= '0' && value[index] <= '9') ||
		      (value[index] >= 'a' && value[index] <= 'f')))
			return false;
	}
	return true;
}

static bool safe_token_value(const char *value, size_t maximum)
{
	size_t length = strlen(value);
	size_t index;

	if (!length || length > maximum)
		return false;
	for (index = 0; index < length; index++) {
		unsigned char byte = (unsigned char)value[index];

		if (byte <= 0x20 || byte >= 0x7f || byte == '\\' || byte == '\'' ||
		    byte == '"')
			return false;
	}
	return true;
}

static int extract_parameter(const char *cmdline, const char *name,
			     char *destination, size_t destination_size)
{
	char copy[MAX_CMDLINE_BYTES + 1];
	char *save = NULL;
	char *token;
	size_t name_length = strlen(name);
	int matches = 0;

	if (strlen(cmdline) > MAX_CMDLINE_BYTES)
		return -1;
	strcpy(copy, cmdline);
	for (token = strtok_r(copy, " \t\r\n", &save); token;
	     token = strtok_r(NULL, " \t\r\n", &save)) {
		const char *value;

		if (strncmp(token, name, name_length) || token[name_length] != '=')
			continue;
		value = token + name_length + 1;
		if (++matches != 1 || strlen(value) + 1 > destination_size)
			return -1;
		strcpy(destination, value);
	}
	return matches == 1 ? 0 : -1;
}

static void read_boot_parameters(struct boot_parameters *parameters)
{
	char cmdline[MAX_CMDLINE_BYTES + 1];
	char strict_mode[8];
	ssize_t length;
	int descriptor;

	memset(parameters, 0, sizeof(*parameters));
	descriptor = open("/proc/cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		fatal("open /proc/cmdline: %s", strerror(errno));
	length = read(descriptor, cmdline, MAX_CMDLINE_BYTES);
	if (length < 0)
		fatal("read /proc/cmdline: %s", strerror(errno));
	if (read(descriptor, cmdline, 1) != 0)
		fatal("kernel command line exceeds %d bytes", MAX_CMDLINE_BYTES);
	close(descriptor);
	cmdline[length] = '\0';

	if (extract_parameter(cmdline, "bpfobs.strict", strict_mode,
			      sizeof(strict_mode)) < 0 || strcmp(strict_mode, "1"))
		fatal("kernel command line needs one exact bpfobs.strict=1 token");
	if (extract_parameter(cmdline, "bpfobs.recorder_sha256",
			      parameters->recorder_sha256,
			      sizeof(parameters->recorder_sha256)) < 0 ||
	    !is_lower_hex(parameters->recorder_sha256, 64))
		fatal("invalid bpfobs.recorder_sha256");
	if (extract_parameter(cmdline, "bpfobs.policy_id", parameters->policy_id,
			      sizeof(parameters->policy_id)) < 0 ||
	    !safe_token_value(parameters->policy_id,
			     sizeof(parameters->policy_id) - 1))
		fatal("invalid bpfobs.policy_id");
	if (extract_parameter(cmdline, "bpfobs.policy_sha256",
			      parameters->policy_sha256,
			      sizeof(parameters->policy_sha256)) < 0 ||
	    !is_lower_hex(parameters->policy_sha256, 64))
		fatal("invalid bpfobs.policy_sha256");
	if (extract_parameter(cmdline, "bpfobs.kernel_identity",
			      parameters->kernel_identity,
			      sizeof(parameters->kernel_identity)) < 0 ||
	    !safe_token_value(parameters->kernel_identity,
			     MAX_KERNEL_IDENTITY_BYTES))
		fatal("invalid bpfobs.kernel_identity");
}

static void check_file(const char *path, mode_t required_bits, bool executable)
{
	struct stat state;
	mode_t permissions;

	if (lstat(path, &state) < 0)
		fatal("stat provisioned input %s: %s", path, strerror(errno));
	permissions = state.st_mode & 07777;
	if (!S_ISREG(state.st_mode) || S_ISLNK(state.st_mode) || state.st_nlink != 1)
		fatal("%s is not a singly linked regular file", path);
	if (state.st_uid != 0 || state.st_gid != 0 || (permissions & 0022) ||
	    (permissions & 07000))
		fatal("%s is not immutable to the strict runner", path);
	if (executable && (permissions & 0005) != 0005)
		fatal("%s is not readable/executable by the unprivileged runner", path);
	if (!executable && !(permissions & 0004))
		fatal("%s is not readable by the unprivileged runner", path);
	if ((permissions & required_bits) != required_bits)
		fatal("%s mode omits required bits %04o", path, required_bits);
}

static bool validate_capability_blob(const unsigned char *blob, ssize_t length,
				     uint64_t expected)
{
	uint32_t magic;
	uint32_t word;
	uint64_t permitted;
	uint64_t inheritable;

	if (length != (ssize_t)XATTR_CAPS_SZ_2 &&
	    length != (ssize_t)XATTR_CAPS_SZ_3)
		return false;
	memcpy(&word, blob, sizeof(word));
	magic = le32toh(word);
	if (magic != VFS_CAP_REVISION_2 + VFS_CAP_FLAGS_EFFECTIVE &&
	    magic != VFS_CAP_REVISION_3 + VFS_CAP_FLAGS_EFFECTIVE)
		return false;
	if ((magic & VFS_CAP_REVISION_MASK) == VFS_CAP_REVISION_2 &&
	    length != (ssize_t)XATTR_CAPS_SZ_2)
		return false;
	if ((magic & VFS_CAP_REVISION_MASK) == VFS_CAP_REVISION_3 &&
	    length != (ssize_t)XATTR_CAPS_SZ_3)
		return false;
	memcpy(&word, blob + 4, sizeof(word));
	permitted = le32toh(word);
	memcpy(&word, blob + 12, sizeof(word));
	permitted |= (uint64_t)le32toh(word) << 32;
	memcpy(&word, blob + 8, sizeof(word));
	inheritable = le32toh(word);
	memcpy(&word, blob + 16, sizeof(word));
	inheritable |= (uint64_t)le32toh(word) << 32;
	if (length == (ssize_t)XATTR_CAPS_SZ_3) {
		memcpy(&word, blob + 20, sizeof(word));
		if (le32toh(word) != 0)
			return false;
	}
	return permitted == expected && inheritable == 0;
}

static void check_file_capabilities(const char *path, uint64_t expected)
{
	unsigned char blob[XATTR_CAPS_SZ];
	ssize_t length;

	errno = 0;
	length = getxattr(path, "security.capability", blob, sizeof(blob));
	if (!expected) {
		if (length >= 0 || errno != ENODATA)
			fatal("%s unexpectedly has file capabilities", path);
		return;
	}
	if (length < 0)
		fatal("read file capabilities for %s: %s", path,
		      strerror(errno));
	if (!validate_capability_blob(blob, length, expected))
		fatal("%s has capabilities outside its exact contract", path);
}

static void validate_provisioned_inputs(void)
{
	static const char *const expected_entries[] = {
		"strict-init",
		"guest-strict-e2e.sh",
		"bpf-state-observer",
		"vm-e2e-assert",
		"vm-outsider-gate-assert",
		"map-lifecycle",
		"exclusive-noop",
		"recorder.bpf.o",
		"exclusive-vm-scope.json",
		"harness-public.key",
		"wrong-harness-public.key",
	};
	char executable[sizeof(STRICT_INIT) + 32];
	ssize_t length;
	struct stat directory;
	DIR *input;
	struct dirent *entry;

	length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
	if (length < 0 || (size_t)length >= sizeof(executable) - 1)
		fatal("resolve /proc/self/exe: %s", strerror(errno));
	executable[length] = '\0';
	if (strcmp(executable, STRICT_INIT))
		fatal("PID1 executable is %s, expected %s", executable, STRICT_INIT);

	if (lstat(INPUT_ROOT, &directory) < 0 || !S_ISDIR(directory.st_mode) ||
	    directory.st_uid != 0 || directory.st_gid != 0 ||
	    (directory.st_mode & 0022) || (directory.st_mode & 0005) != 0005)
		fatal("strict input root is absent or runner-writable");
	check_file(STRICT_INIT, 0500, true);
	check_file(STRICT_RUNNER, 0500, true);
	check_file(OBSERVER, 0500, true);
	check_file(ASSERT_BINARY, 0500, true);
	check_file(OUTSIDER_GATE, 0500, true);
	check_file(MAP_WORKLOAD, 0500, true);
	check_file(NOOP_WORKLOAD, 0500, true);
	check_file(RECORDER_OBJECT, 0400, false);
	check_file(EXCLUSIVE_SCOPE, 0400, false);
	check_file(HARNESS_PUBLIC_KEY, 0400, false);
	check_file(HARNESS_WRONG_PUBLIC_KEY, 0400, false);
	check_file_capabilities(STRICT_INIT, 0);
	check_file_capabilities(STRICT_RUNNER, 0);
	check_file_capabilities(OBSERVER, OBSERVER_CAP_MASK);
	check_file_capabilities(ASSERT_BINARY, 0);
	check_file_capabilities(OUTSIDER_GATE, OBSERVER_CAP_MASK);
	check_file_capabilities(MAP_WORKLOAD, MAP_WORKLOAD_CAP_MASK);
	check_file_capabilities(NOOP_WORKLOAD, 0);

	input = opendir(INPUT_ROOT);
	if (!input)
		fatal("open strict input root: %s", strerror(errno));
	while ((entry = readdir(input)) != NULL) {
		size_t index;
		bool expected = false;

		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
			continue;
		for (index = 0; index < ARRAY_SIZE(expected_entries); index++) {
			if (!strcmp(entry->d_name, expected_entries[index])) {
				expected = true;
				break;
			}
		}
		if (!expected)
			fatal("strict input root contains unexpected entry %s",
			      entry->d_name);
	}
	if (closedir(input) < 0)
		fatal("close strict input root: %s", strerror(errno));

	if (lstat(OUTPUT_ROOT, &directory) < 0 || !S_ISDIR(directory.st_mode) ||
	    directory.st_uid != STRICT_UID || directory.st_gid != STRICT_GID ||
	    (directory.st_mode & 0777) != 0711 || !is_directory_empty(OUTPUT_ROOT))
		fatal("strict output root is not a clean 0711 runner-owned directory");
}

static void require_empty_bpf_inventory(void)
{
	static const enum bpf_cmd commands[] = {
		BPF_PROG_GET_NEXT_ID,
		BPF_MAP_GET_NEXT_ID,
		BPF_LINK_GET_NEXT_ID,
	};
	size_t index;

	for (index = 0; index < ARRAY_SIZE(commands); index++) {
		union bpf_attr attributes;
		long result;

		memset(&attributes, 0, sizeof(attributes));
		errno = 0;
		result = syscall(__NR_bpf, commands[index], &attributes,
				 sizeof(attributes));
		if (result == 0)
			fatal("strict boot began with a pre-existing BPF object");
		if (errno != ENOENT)
			fatal("global BPF empty-inventory probe failed: %s",
			      strerror(errno));
	}
}

static unsigned int userspace_process_count(void)
{
	DIR *proc;
	struct dirent *entry;
	unsigned int count = 0;

	proc = opendir("/proc");
	if (!proc)
		fatal("open /proc for process census: %s", strerror(errno));
	for (;;) {
		char path[128];
		char stat_line[4096];
		char *after_comm;
		char state;
		unsigned long flags;
		const char *cursor;
		int descriptor;
		ssize_t length;

		errno = 0;
		entry = readdir(proc);
		if (!entry) {
			if (errno)
				fatal("enumerate /proc for process census: %s",
				      strerror(errno));
			break;
		}
		cursor = entry->d_name;
		if (!*cursor)
			continue;
		while (*cursor && isdigit((unsigned char)*cursor))
			cursor++;
		if (*cursor)
			continue;
		if (snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name) >=
		    (int)sizeof(path))
			fatal("process census path overflow");
		descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (descriptor < 0) {
			if (errno == ENOENT)
				continue;
			fatal("open process census record %s: %s", path,
			      strerror(errno));
		}
		length = read(descriptor, stat_line, sizeof(stat_line) - 1);
		close(descriptor);
		if (length <= 0)
			fatal("read process census record %s", path);
		stat_line[length] = '\0';
		after_comm = strrchr(stat_line, ')');
		if (!after_comm ||
		    sscanf(after_comm + 1, " %c %*d %*d %*d %*d %*d %lu",
			   &state, &flags) != 2)
			fatal("parse process census record %s", path);
		(void)state;
		if (!(flags & PF_KTHREAD))
			count++;
	}
	if (closedir(proc) < 0)
		fatal("close /proc process census: %s", strerror(errno));
	return count;
}

static uint64_t capability_bounding_mask(void)
{
	uint64_t mask = 0;
	int capability;

	for (capability = 0; capability < 64; capability++) {
		int present = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);

		if (present < 0) {
			if (errno == EINVAL)
				break;
			fatal("read capability bounding set: %s", strerror(errno));
		}
		if (present)
			mask |= UINT64_C(1) << capability;
	}
	return mask;
}

static uint64_t capability_ambient_mask(void)
{
	uint64_t mask = 0;
	int capability;

	for (capability = 0; capability < 64; capability++) {
		int present = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
				    capability, 0, 0);

		if (present < 0) {
			if (errno == EINVAL)
				break;
			fatal("read ambient capability set: %s", strerror(errno));
		}
		if (present)
			mask |= UINT64_C(1) << capability;
	}
	return mask;
}

static struct capability_state read_capability_state(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2];
	struct capability_state state;

	memset(data, 0, sizeof(data));
	if (syscall(SYS_capget, &header, data) < 0)
		fatal("capget: %s", strerror(errno));
	state.effective = data[0].effective |
			  ((uint64_t)data[1].effective << 32);
	state.permitted = data[0].permitted |
			  ((uint64_t)data[1].permitted << 32);
	state.inheritable = data[0].inheritable |
			    ((uint64_t)data[1].inheritable << 32);
	state.bounding = capability_bounding_mask();
	state.ambient = capability_ambient_mask();
	state.securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
	state.no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	if (state.securebits < 0 || state.no_new_privs < 0)
		fatal("read secure execution state: %s", strerror(errno));
	return state;
}

static void set_capability_sets(uint64_t effective, uint64_t permitted)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2];

	memset(data, 0, sizeof(data));
	data[0].effective = (uint32_t)effective;
	data[1].effective = (uint32_t)(effective >> 32);
	data[0].permitted = (uint32_t)permitted;
	data[1].permitted = (uint32_t)(permitted >> 32);
	if (syscall(SYS_capset, &header, data) < 0)
		fatal("capset: %s", strerror(errno));
}

static void restrict_bounding_set(uint64_t allowed)
{
	int capability;

	for (capability = 0; capability < 64; capability++) {
		int present = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);

		if (present < 0) {
			if (errno == EINVAL)
				break;
			fatal("inspect capability %d: %s", capability,
			      strerror(errno));
		}
		if (present && !(allowed & (UINT64_C(1) << capability)) &&
		    prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) < 0)
			fatal("drop bounding capability %d: %s", capability,
			      strerror(errno));
	}
}

static void clear_ambient_capabilities(void)
{
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
		fatal("clear ambient capabilities: %s", strerror(errno));
}

static void install_locked_noroot(void)
{
	if (prctl(PR_SET_SECUREBITS, LOCKED_NOROOT_SECUREBITS, 0, 0, 0) < 0)
		fatal("lock NOROOT/NO_SETUID_FIXUP securebits: %s",
		      strerror(errno));
}

static void assert_capability_state(const struct capability_state *state,
				    uint64_t expected_effective,
				    uint64_t expected_permitted,
				    uint64_t expected_bounding,
				    int expected_no_new_privs)
{
	if (state->effective != expected_effective ||
	    state->permitted != expected_permitted || state->inheritable != 0 ||
	    state->bounding != expected_bounding || state->ambient != 0 ||
	    state->securebits != LOCKED_NOROOT_SECUREBITS ||
	    state->no_new_privs != expected_no_new_privs)
		fatal("credential state violates the strict capability contract");
}

static void delegate_directory(const char *path, mode_t mode)
{
	ensure_directory(path, mode);
	if (chown(path, STRICT_UID, STRICT_GID) < 0 || chmod(path, mode) < 0)
		fatal("delegate %s: %s", path, strerror(errno));
}

static void delegate_cgroup_root(void)
{
	static const char *const delegated_files[] = {
		CGROUP_ROOT "/cgroup.procs",
		CGROUP_ROOT "/cgroup.threads",
		CGROUP_ROOT "/cgroup.subtree_control",
	};
	size_t index;

	delegate_directory(CGROUP_ROOT, 0755);
	for (index = 0; index < ARRAY_SIZE(delegated_files); index++) {
		if (chown(delegated_files[index], STRICT_UID, STRICT_GID) < 0)
			fatal("delegate %s: %s", delegated_files[index],
			      strerror(errno));
	}
}

static void validate_unprivileged_cleanup_parent(const char *path)
{
	struct stat state;

	if (lstat(path, &state) < 0 || !S_ISDIR(state.st_mode) ||
	    S_ISLNK(state.st_mode) || state.st_uid != 0 ||
	    (state.st_mode & 0300) != 0300)
		fatal("cleanup parent %s is not UID-0 owner-writable/searchable", path);
}

static int open_status_report(unsigned int userspace_count,
			      const struct harness_device *harness,
			      const char *module_lockdown)
{
	int descriptor;

	descriptor = open(INIT_STATUS,
			  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
			  0644);
	if (descriptor < 0)
		fatal("create %s: %s", INIT_STATUS, strerror(errno));
	if (fchmod(descriptor, 0644) < 0)
		fatal("set strict-init report mode: %s", strerror(errno));
	dprintf(descriptor, "schema_version=1\n");
	dprintf(descriptor, "strict_init_path=%s\n", STRICT_INIT);
	dprintf(descriptor, "strict_runner_path=%s\n", STRICT_RUNNER);
	dprintf(descriptor, "pid1=%ld\n", (long)getpid());
	dprintf(descriptor, "userspace_processes_before_runner=%u\n",
		userspace_count);
	dprintf(descriptor, "initial_bpf_programs=0\n");
	dprintf(descriptor, "initial_bpf_maps=0\n");
	dprintf(descriptor, "initial_bpf_links=0\n");
	dprintf(descriptor, "initial_external_bpf_fds=0\n");
	dprintf(descriptor, "unprivileged_bpf_disabled=1\n");
	dprintf(descriptor, "module_loading=%s\n", module_lockdown);
	dprintf(descriptor, "modprobe_helper=%s\n",
		!strcmp(module_lockdown, "MODULES_NOT_SUPPORTED") ?
			"NOT_SUPPORTED" : "EMPTY");
	dprintf(descriptor, "rlimit_core=0\n");
	dprintf(descriptor, "strict_root_block_read_only=1\n");
	dprintf(descriptor, "evidence_block_read_only=0\n");
	dprintf(descriptor, "runner_uid=%u\n", (unsigned int)STRICT_UID);
	dprintf(descriptor, "runner_gid=%u\n", (unsigned int)STRICT_GID);
	dprintf(descriptor, "observer_file_caps=%016llx\n",
		(unsigned long long)OBSERVER_CAP_MASK);
	dprintf(descriptor, "map_workload_file_caps=%016llx\n",
		(unsigned long long)MAP_WORKLOAD_CAP_MASK);
	dprintf(descriptor, "harness_port_name=org.allox.harness\n");
	dprintf(descriptor, "harness_device_path=%s\n", harness->path);
	dprintf(descriptor, "harness_device_major=%u\n", harness->major);
	dprintf(descriptor, "harness_device_minor=%u\n", harness->minor);
	dprintf(descriptor, "cleanup_parent_access=DAC_OWNER_NO_OVERRIDE_CAP\n");
	if (fsync(descriptor) < 0)
		fatal("sync strict-init report: %s", strerror(errno));
	return descriptor;
}

static void write_parent_credentials(int descriptor)
{
	struct capability_state state = read_capability_state();

	assert_capability_state(&state, PID1_CAP_MASK, PID1_CAP_MASK,
				PID1_CAP_MASK, 1);
	dprintf(descriptor, "pid1_cap_effective=%016llx\n",
		(unsigned long long)state.effective);
	dprintf(descriptor, "pid1_cap_permitted=%016llx\n",
		(unsigned long long)state.permitted);
	dprintf(descriptor, "pid1_cap_bounding=%016llx\n",
		(unsigned long long)state.bounding);
	dprintf(descriptor, "pid1_cap_ambient=%016llx\n",
		(unsigned long long)state.ambient);
	dprintf(descriptor, "pid1_securebits=%x\n", state.securebits);
	dprintf(descriptor, "pid1_no_new_privs=%d\n", state.no_new_privs);
	if (fsync(descriptor) < 0)
		fatal("sync PID1 credential report: %s", strerror(errno));
}

static void prepare_runner_credentials(void)
{
	struct capability_state state;

	restrict_bounding_set(OBSERVER_CAP_MASK);
	clear_ambient_capabilities();
	install_locked_noroot();
	if (setgroups(0, NULL) < 0 || setresgid(STRICT_GID, STRICT_GID, STRICT_GID) < 0 ||
	    setresuid(STRICT_UID, STRICT_UID, STRICT_UID) < 0)
		fatal("drop runner UID/GID: %s", strerror(errno));
	set_capability_sets(0, 0);
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
		fatal("make strict runner nondumpable: %s", strerror(errno));
	state = read_capability_state();
	assert_capability_state(&state, 0, 0, OBSERVER_CAP_MASK, 0);
}

static void prepare_pid1_wait_credentials(void)
{
	struct capability_state state;

	restrict_bounding_set(PID1_CAP_MASK);
	clear_ambient_capabilities();
	install_locked_noroot();
	set_capability_sets(PID1_CAP_MASK, PID1_CAP_MASK);
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		fatal("set PID1 no_new_privs: %s", strerror(errno));
	state = read_capability_state();
	assert_capability_state(&state, PID1_CAP_MASK, PID1_CAP_MASK,
				PID1_CAP_MASK, 1);
}

static void close_child_descriptors_except(int handshake)
{
	int descriptor;

	for (descriptor = 3; descriptor < 1024; descriptor++) {
		if (descriptor != handshake)
			close(descriptor);
	}
}

static bool format_environment_value(char *destination, size_t capacity,
				     const char *prefix, const char *value)
{
	int length = snprintf(destination, capacity, "%s%s", prefix, value);

	return length >= 0 && (size_t)length < capacity;
}

static void enter_delegated_cgroup(void)
{
	char pid[32];
	char membership[128];
	int length;

	length = snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
	if (length <= 0 || (size_t)length >= sizeof(pid))
		fatal("format strict runner PID for cgroup migration");
	write_control_value(CGROUP_ROOT "/cgroup.procs", pid);
	if (read_small_value("/proc/self/cgroup", membership,
			     sizeof(membership)) < 0 ||
	    strcmp(membership, "0::/bpf-state-observer"))
		fatal("strict runner did not enter the exact delegated cgroup root");
}

static void execute_runner(const struct boot_parameters *parameters,
			   int handshake)
{
	char recorder_environment[sizeof(RECORDER_ENV_PREFIX) + 64];
	char policy_id_environment[sizeof(POLICY_ID_ENV_PREFIX) +
				   sizeof(parameters->policy_id) - 1];
	char policy_sha_environment[sizeof(POLICY_SHA_ENV_PREFIX) + 64];
	char kernel_identity_environment[sizeof(KERNEL_IDENTITY_ENV_PREFIX) +
					 MAX_KERNEL_IDENTITY_BYTES];
	char *const arguments[] = {
		"/bin/bash",
		STRICT_RUNNER,
		NULL,
	};
	char *environment[] = {
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG=C",
		"LC_ALL=C",
		"HOME=/nonexistent",
		recorder_environment,
		policy_id_environment,
		policy_sha_environment,
		kernel_identity_environment,
		NULL,
	};
	char release;

	if (setpgid(0, 0) < 0)
		fatal("create strict runner process group: %s", strerror(errno));
	/* cgroup v2 migration permission is checked at the common ancestor.
	 * Enter the delegated root while still privileged; Observer descendants
	 * can then move only into the exact per-run children below that root. */
	enter_delegated_cgroup();
	prepare_runner_credentials();
	if (read(handshake, &release, 1) != 1 || release != 'R')
		fatal("PID1 did not release strict runner after dropping capabilities");
	close_child_descriptors_except(handshake);
	close(handshake);

	if (!format_environment_value(recorder_environment,
				      sizeof(recorder_environment),
				      RECORDER_ENV_PREFIX,
				      parameters->recorder_sha256) ||
	    !format_environment_value(policy_id_environment,
				      sizeof(policy_id_environment),
				      POLICY_ID_ENV_PREFIX, parameters->policy_id) ||
	    !format_environment_value(policy_sha_environment,
				      sizeof(policy_sha_environment),
				      POLICY_SHA_ENV_PREFIX,
				      parameters->policy_sha256) ||
	    !format_environment_value(kernel_identity_environment,
				      sizeof(kernel_identity_environment),
				      KERNEL_IDENTITY_ENV_PREFIX,
				      parameters->kernel_identity))
		fatal("strict runner environment exceeds its fixed bound");
	execve("/bin/bash", arguments, environment);
	fatal("exec strict Guest runner: %s", strerror(errno));
}

static int wait_for_runner(pid_t child)
{
	struct timespec delay = {
		.tv_sec = 0,
		.tv_nsec = 100000000,
	};
	struct timespec start;
	struct timespec now;
	int status = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
		fatal("read monotonic clock: %s", strerror(errno));
	for (;;) {
		pid_t waited = waitpid(child, &status, WNOHANG);

		if (waited == child)
			return status;
		if (waited < 0)
			fatal("wait for strict runner: %s", strerror(errno));
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			fatal("read monotonic clock: %s", strerror(errno));
		if (now.tv_sec - start.tv_sec >= RUNNER_TIMEOUT_SECONDS)
			fatal("strict runner exceeded %d-second Host-fenced timeout",
			      RUNNER_TIMEOUT_SECONDS);
		nanosleep(&delay, NULL);
	}
}

static bool verify_runner_final_inventory_status(void)
{
	static const char expected[] =
		"schema_version=1\n"
		"programs=0\n"
		"maps=0\n"
		"links=0\n"
		"completeness=COMPLETE\n"
		"result=PASS\n";
	char contents[sizeof(expected) + 1];
	struct stat state;
	int descriptor;
	ssize_t length;
	char extra;

	if (lstat(FINAL_INVENTORY_STATUS, &state) < 0 ||
	    !S_ISREG(state.st_mode) || S_ISLNK(state.st_mode) ||
	    state.st_nlink != 1 || state.st_uid != STRICT_UID ||
	    state.st_gid != STRICT_GID || (state.st_mode & 0777) != 0444)
		return false;
	descriptor = open(FINAL_INVENTORY_STATUS,
			  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		return false;
	length = read(descriptor, contents, sizeof(contents) - 1);
	if (length < 0 || read(descriptor, &extra, 1) != 0) {
		close(descriptor);
		return false;
	}
	close(descriptor);
	contents[length] = '\0';
	return !strcmp(contents, expected);
}

static void reap_adopted_children(void)
{
	int status;

	while (waitpid(-1, &status, WNOHANG) > 0)
		;
}

static int assert_runner_credentials(void)
{
	struct capability_state state;

	if (getuid() != STRICT_UID || geteuid() != STRICT_UID ||
	    getgid() != STRICT_GID || getegid() != STRICT_GID)
		fatal("runner credential check executed under the wrong UID/GID");
	state = read_capability_state();
	assert_capability_state(&state, 0, 0, OBSERVER_CAP_MASK, 0);
	printf("runner_uid=%u\n", (unsigned int)getuid());
	printf("runner_gid=%u\n", (unsigned int)getgid());
	printf("runner_cap_effective=%016llx\n",
	       (unsigned long long)state.effective);
	printf("runner_cap_permitted=%016llx\n",
	       (unsigned long long)state.permitted);
	printf("runner_cap_inheritable=%016llx\n",
	       (unsigned long long)state.inheritable);
	printf("runner_cap_bounding=%016llx\n",
	       (unsigned long long)state.bounding);
	printf("runner_cap_ambient=%016llx\n",
	       (unsigned long long)state.ambient);
	printf("runner_securebits=%x\n", state.securebits);
	printf("runner_no_new_privs=%d\n", state.no_new_privs);
	return EXIT_SUCCESS;
}

static int self_test(void)
{
	uint32_t observer_words[XATTR_CAPS_SZ_2 / sizeof(uint32_t)];
	unsigned char *observer_blob = (unsigned char *)(void *)observer_words;
	char digest[65];
	char digest_environment[sizeof(POLICY_SHA_ENV_PREFIX) + 64];
	char value[32];

	memset(observer_words, 0, sizeof(observer_words));
	observer_words[0] = htole32(VFS_CAP_REVISION_2 |
				      VFS_CAP_FLAGS_EFFECTIVE);
	observer_words[1] = htole32((uint32_t)OBSERVER_CAP_MASK);
	observer_words[3] = htole32((uint32_t)(OBSERVER_CAP_MASK >> 32));
	require(validate_capability_blob(observer_blob, sizeof(observer_words),
					 OBSERVER_CAP_MASK),
		"self-test rejected the Observer capability blob");
	require(!validate_capability_blob(observer_blob, sizeof(observer_words),
					 MAP_WORKLOAD_CAP_MASK),
		"self-test accepted the wrong capability mask");
	observer_words[2] = htole32(1);
	require(!validate_capability_blob(observer_blob, sizeof(observer_words),
					 OBSERVER_CAP_MASK),
		"self-test accepted inheritable file capabilities");
	require(extract_parameter("a=1 wanted=exact z=3", "wanted", value,
				  sizeof(value)) == 0 && !strcmp(value, "exact"),
		"self-test could not extract a unique command-line field");
	require(extract_parameter("wanted=one wanted=two", "wanted", value,
				  sizeof(value)) < 0,
		"self-test accepted a duplicate command-line field");
	require(is_lower_hex(
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		64),
		"self-test rejected canonical SHA-256");
	require(!safe_token_value("contains space", 64),
		"self-test accepted whitespace in a boot parameter");
	memset(digest, 'a', sizeof(digest) - 1);
	digest[sizeof(digest) - 1] = '\0';
	require(format_environment_value(digest_environment,
					 sizeof(digest_environment),
					 POLICY_SHA_ENV_PREFIX, digest),
		"self-test rejected the maximum policy SHA environment");
	require(!format_environment_value(digest_environment,
					  sizeof(digest_environment) - 1,
					  POLICY_SHA_ENV_PREFIX, digest),
		"self-test accepted a truncated policy SHA environment");
	printf("STRICT_INIT_SELF_TEST_PASS\n");
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	struct boot_parameters parameters;
	struct harness_device harness;
	unsigned int userspace_count;
	int status_descriptor;
	int handshake[2];
	pid_t child;
	int child_status;
	bool success;
	bool final_pid1_fd_clean;
	bool final_bpffs_clean;
	bool final_inventory_verified;
	unsigned int final_userspace_count;
	const char *module_lockdown;
	char release = 'R';

	if (argc == 2 && !strcmp(argv[1], "--self-test"))
		return self_test();
	if (argc == 2 && !strcmp(argv[1], "--assert-runner-creds"))
		return assert_runner_credentials();
	if (argc != 1) {
		fprintf(stderr,
			"usage: %s [--self-test | --assert-runner-creds]\n",
			argv[0]);
		return EXIT_FAILURE;
	}
	require(getpid() == 1,
		"strict boot supervisor must be the kernel-selected PID1");
	umask(0077);
	prepare_mounts();
	reopen_console();
	dprintf(STDOUT_FILENO, "strict-init: minimal exclusive boot started\n");
	read_boot_parameters(&parameters);
	prepare_evidence_filesystem();
	require_block_read_only_state("/sys/block/vda/ro", "1");
	require_block_read_only_state("/sys/block/vdb/ro", "0");
	validate_provisioned_inputs();
	harness = prepare_harness_device();
	permanently_disable_unprivileged_bpf();
	module_lockdown = permanently_disable_module_loading();
	userspace_count = userspace_process_count();
	if (userspace_count != 1)
		fatal("expected exactly one userspace process before runner, found %u",
		      userspace_count);
	if (!is_directory_empty("/sys/fs/bpf"))
		fatal("bpffs is not empty at strict boot");
	require_empty_bpf_inventory();
	if (process_has_bpf_descriptor(1))
		fatal("PID1 unexpectedly holds a BPF-related descriptor");
	validate_unprivileged_cleanup_parent("/sys/fs/cgroup");
	validate_unprivileged_cleanup_parent("/sys/fs/bpf");
	delegate_cgroup_root();
	delegate_directory(EXCLUSIVE_BPF_ROOT, 0700);
	status_descriptor = open_status_report(userspace_count, &harness,
					       module_lockdown);
	if (pipe2(handshake, O_CLOEXEC) < 0)
		fatal("create capability-drop handshake: %s", strerror(errno));

	child = fork();
	if (child < 0)
		fatal("fork strict runner: %s", strerror(errno));
	if (child == 0) {
		close(handshake[1]);
		close(status_descriptor);
		execute_runner(&parameters, handshake[0]);
	}
	close(handshake[0]);
	if (setpgid(child, child) < 0 && errno != EACCES)
		fatal("fix strict runner process group: %s", strerror(errno));
	prepare_pid1_wait_credentials();
	write_parent_credentials(status_descriptor);
	if (write(handshake[1], &release, 1) != 1)
		fatal("release strict runner: %s", strerror(errno));
	close(handshake[1]);

	child_status = wait_for_runner(child);
	reap_adopted_children();
	/* The measured runner writes GUEST_STATUS as its final operation and only
	 * then exits zero. PID1 deliberately retains no DAC override capability,
	 * so the retrieval boot performs the independent file-level assertion. */
	success = WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
	final_userspace_count = userspace_process_count();
	if (final_userspace_count != 1) {
		dprintf(STDERR_FILENO,
			"strict-init: userspace descendants survived runner exit\n");
		success = false;
	}
	final_pid1_fd_clean = !process_has_bpf_descriptor(1);
	if (!final_pid1_fd_clean) {
		dprintf(STDERR_FILENO,
			"strict-init: PID1 gained a BPF-related descriptor\n");
		success = false;
	}
	final_inventory_verified = verify_runner_final_inventory_status();
	if (!final_inventory_verified) {
		dprintf(STDERR_FILENO,
			"strict-init: final global inventory proof is absent or invalid\n");
		success = false;
	}
	/* The delegated root is deliberately 0700 and owned by the runner UID.
	 * PID1 no longer has a DAC override capability, so it must not enumerate
	 * that directory. rmdir is the fail-closed emptiness test and needs only
	 * owner write/search permission on the root-owned bpffs parent. */
	if (rmdir(EXCLUSIVE_BPF_ROOT) < 0) {
		dprintf(STDERR_FILENO, "strict-init: remove exclusive bpffs root: %s\n",
			strerror(errno));
		success = false;
	}
	final_bpffs_clean = is_directory_empty("/sys/fs/bpf");
	if (!final_bpffs_clean) {
		dprintf(STDERR_FILENO,
			"strict-init: global bpffs contains an unexpected entry\n");
		success = false;
	}
	if (rmdir(CGROUP_ROOT) < 0) {
		dprintf(STDERR_FILENO, "strict-init: remove cgroup root: %s\n",
			strerror(errno));
		success = false;
	}
	if (!append_report(status_descriptor, "runner_wait_status=%d\n",
			   child_status) ||
	    !append_report(status_descriptor, "final_userspace_processes=%u\n",
			   final_userspace_count) ||
	    !append_report(status_descriptor, "final_pid1_bpf_fds=%u\n",
			   final_pid1_fd_clean ? 0 : 1) ||
	    !append_report(status_descriptor, "final_bpffs_entries=%s\n",
			   final_bpffs_clean ? "0" : "NONZERO") ||
	    !append_report(status_descriptor, "final_global_inventory=%s\n",
			   final_inventory_verified ?
				   "VERIFIED_RUNNER_FILECAP_SNAPSHOT_EMPTY" :
				   "INVALID")) {
		dprintf(STDERR_FILENO,
			"strict-init: append final observations to report failed\n");
		success = false;
	}
	if (!append_report(status_descriptor, "cleanup_complete=%s\n",
			   success ? "true" : "false")) {
		dprintf(STDERR_FILENO,
			"strict-init: append cleanup result to report failed\n");
		success = false;
	}
	if (fsync(status_descriptor) < 0) {
		dprintf(STDERR_FILENO, "strict-init: sync final report: %s\n",
			strerror(errno));
		success = false;
	}
	/* PASS is the final completion marker. An I/O error while persisting it can
	 * leave media ambiguous, so the Host must additionally require the console
	 * PASS marker emitted only after this fsync and close both succeed. */
	if (success) {
		if (!append_report(status_descriptor, "result=PASS\n") ||
		    fsync(status_descriptor) < 0) {
			dprintf(STDERR_FILENO,
				"strict-init: persist PASS completion marker failed: %s\n",
				strerror(errno));
			success = false;
		}
	} else if (!append_report(status_descriptor, "result=FAIL\n") ||
		   fsync(status_descriptor) < 0) {
		dprintf(STDERR_FILENO,
			"strict-init: could not persist FAIL completion marker\n");
	}
	if (close(status_descriptor) < 0) {
		dprintf(STDERR_FILENO, "strict-init: close final report failed: %s\n",
			strerror(errno));
		success = false;
	}
	dprintf(STDOUT_FILENO, "strict-init: strict suite %s\n",
		success ? "PASS" : "FAIL");
	power_off_forever();
}
