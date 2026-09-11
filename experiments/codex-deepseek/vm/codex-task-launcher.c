// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/magic.h>
#include <linux/securebits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../../workloads/exclusive-credentials.h"

#define CODEX_BINARY "/opt/codex-collection/codex/bin/codex"
#define CODEX_PATH "/opt/codex-collection/codex/codex-path:/usr/bin:/bin"
#define MODEL_CATALOG "/opt/codex-collection/models.json"
#define MAP_FIXTURE "/opt/bpf-state-observer/map-lifecycle"
#define PROMPT_ROOT "/opt/codex-collection/tasks/"
#define WORKSPACE_ROOT "/var/lib/bpf-observer/agent-collection/"
#define STATE_ROOT "/run/codex-collection/"
#ifndef COLLECTION_LAUNCHER
#define COLLECTION_LAUNCHER "/opt/codex-collection/codex-task-launcher"
#endif
#define MAX_API_KEY_BYTES 512
#define MAX_PROMPT_BYTES (64 * 1024)
#define MAX_WORKSPACE_BYTES (UINT64_C(16) * 1024 * 1024)
#define MAX_WORKSPACE_INODES UINT64_C(256)
#define CODEX_EFFECTIVE_GID ((gid_t)65533)
#define PROC_ISOLATION_CANARY "sk-codex-parent-environ-isolation-canary"

#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#define COLLECTION_STATX_MNT_ID(state) ((state).__spare2[0])
#else
#define COLLECTION_STATX_MNT_ID(state) ((state).stx_mnt_id)
#endif

static void fatal(const char *format, ...)
{
	va_list arguments;

	va_start(arguments, format);
	fputs("codex-task-launcher: ", stderr);
	vfprintf(stderr, format, arguments);
	fputc('\n', stderr);
	va_end(arguments);
	exit(EXIT_FAILURE);
}

static bool has_prefix(const char *value, const char *prefix)
{
	return !strncmp(value, prefix, strlen(prefix));
}

static void require_directory(const char *input, const char *prefix,
			      char resolved[PATH_MAX])
{
	struct stat before;
	struct stat after;

	if (!realpath(input, resolved))
		fatal("resolve directory %s: %s", input, strerror(errno));
	if (!has_prefix(resolved, prefix))
		fatal("directory %s is outside %s", resolved, prefix);
	if (lstat(input, &before) < 0 || stat(resolved, &after) < 0)
		fatal("inspect directory %s: %s", input, strerror(errno));
	if (!S_ISDIR(before.st_mode) || S_ISLNK(before.st_mode) ||
	    !S_ISDIR(after.st_mode) || before.st_dev != after.st_dev ||
	    before.st_ino != after.st_ino || after.st_uid != EXCLUSIVE_UID ||
	    after.st_gid != EXCLUSIVE_GID || (after.st_mode & 07777) != 0700)
		fatal("directory %s does not satisfy the exact nobody-owned 0700 contract",
		      input);
}

static uint64_t mount_id(const char *path)
{
	struct statx state;

	memset(&state, 0, sizeof(state));
	if (syscall(SYS_statx, AT_FDCWD, path,
		    AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW,
		    STATX_TYPE | STATX_MNT_ID, &state) < 0)
		fatal("read mount identity for %s: %s", path, strerror(errno));
	if (!(state.stx_mask & STATX_MNT_ID))
		fatal("kernel omitted mount identity for %s", path);
	return COLLECTION_STATX_MNT_ID(state);
}

static void require_dedicated_state_tmpfs(const char *state_path)
{
	const char *relative;
	const char *separator;
	char batch_mount[PATH_MAX];
	struct stat mount_state;
	struct statfs filesystem;
	struct statvfs mount_options;
	size_t mount_length;
	uint64_t base_mount_id;
	uint64_t batch_mount_id;
	uint64_t state_mount_id;

	if (!has_prefix(state_path, STATE_ROOT))
		fatal("state path %s is outside %s", state_path, STATE_ROOT);
	relative = state_path + strlen(STATE_ROOT);
	separator = strchr(relative, '/');
	if (!*relative || !separator || separator == relative)
		fatal("state path %s does not name a directory below a batch mount",
		      state_path);
	mount_length = (size_t)(separator - state_path);
	if (mount_length + 1 > sizeof(batch_mount))
		fatal("batch state mount path is too long");
	memcpy(batch_mount, state_path, mount_length);
	batch_mount[mount_length] = '\0';

	if (lstat(batch_mount, &mount_state) < 0 ||
	    !S_ISDIR(mount_state.st_mode) || S_ISLNK(mount_state.st_mode) ||
	    mount_state.st_uid != 0 || mount_state.st_gid != 0 ||
	    (mount_state.st_mode & 0777) != 0711)
		fatal("batch state mount %s violates its root-owned 0711 contract",
		      batch_mount);
	if (statfs(state_path, &filesystem) < 0 ||
	    (long)filesystem.f_type != TMPFS_MAGIC)
		fatal("Codex state path %s is not backed by tmpfs", state_path);
	if (statvfs(state_path, &mount_options) < 0)
		fatal("read mount flags for %s: %s", state_path, strerror(errno));
	if ((mount_options.f_flag & (ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
	    (ST_NOSUID | ST_NODEV | ST_NOEXEC))
		fatal("Codex state tmpfs %s lacks nosuid,nodev,noexec", state_path);
	base_mount_id = mount_id(STATE_ROOT);
	batch_mount_id = mount_id(batch_mount);
	state_mount_id = mount_id(state_path);
	if (batch_mount_id == base_mount_id || state_mount_id != batch_mount_id)
		fatal("Codex state path %s is not inside its dedicated batch mount",
		      state_path);
}

static void require_dedicated_workspace_tmpfs(const char *workspace_path)
{
	char parent[PATH_MAX];
	char *separator;
	struct statfs filesystem;
	struct statvfs limits;
	uint64_t total_bytes;

	if (!has_prefix(workspace_path, WORKSPACE_ROOT))
		fatal("workspace path %s is outside %s", workspace_path,
		      WORKSPACE_ROOT);
	if (strlen(workspace_path) + 1 > sizeof(parent))
		fatal("workspace path is too long");
	strcpy(parent, workspace_path);
	separator = strrchr(parent, '/');
	if (!separator || separator == parent)
		fatal("workspace path %s has no safe parent", workspace_path);
	*separator = '\0';

	if (statfs(workspace_path, &filesystem) < 0 ||
	    (long)filesystem.f_type != TMPFS_MAGIC)
		fatal("workspace %s is not backed by tmpfs", workspace_path);
	if (statvfs(workspace_path, &limits) < 0)
		fatal("read workspace mount limits for %s: %s", workspace_path,
		      strerror(errno));
	if ((limits.f_flag & (ST_NOSUID | ST_NODEV | ST_NOEXEC)) !=
	    (ST_NOSUID | ST_NODEV | ST_NOEXEC))
		fatal("workspace tmpfs %s lacks nosuid,nodev,noexec",
		      workspace_path);
	if (!limits.f_frsize || limits.f_blocks > UINT64_MAX / limits.f_frsize)
		fatal("workspace tmpfs %s has invalid capacity metadata",
		      workspace_path);
	total_bytes = (uint64_t)limits.f_blocks * limits.f_frsize;
	if (!total_bytes || total_bytes > MAX_WORKSPACE_BYTES ||
	    !limits.f_files || limits.f_files > MAX_WORKSPACE_INODES)
		fatal("workspace tmpfs %s exceeds the 16 MiB/256-inode contract",
		      workspace_path);
	if (mount_id(workspace_path) == mount_id(parent))
		fatal("workspace %s is not a dedicated mount", workspace_path);
}

static int open_prompt(const char *input, char resolved[PATH_MAX])
{
	struct stat state;
	int descriptor;

	if (!realpath(input, resolved))
		fatal("resolve prompt %s: %s", input, strerror(errno));
	if (!has_prefix(resolved, PROMPT_ROOT))
		fatal("prompt %s is outside %s", resolved, PROMPT_ROOT);
	descriptor = open(resolved, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		fatal("open prompt %s: %s", resolved, strerror(errno));
	if (fstat(descriptor, &state) < 0)
		fatal("inspect prompt %s: %s", resolved, strerror(errno));
	if (!S_ISREG(state.st_mode) || state.st_uid != 0 || state.st_gid != 0 ||
	    state.st_nlink != 1 || (state.st_mode & 0022) != 0 ||
	    state.st_size <= 0 || state.st_size > MAX_PROMPT_BYTES)
		fatal("prompt %s does not satisfy the immutable input contract", resolved);
	return descriptor;
}

static void validate_model(const char *model)
{
	const unsigned char *cursor = (const unsigned char *)model;

	if (strcmp(model, "deepseek-flash") && strcmp(model, "deepseek-v4-pro"))
		fatal("unsupported model %s", model);
	for (; *cursor; cursor++) {
		if (!isalnum(*cursor) && *cursor != '-' && *cursor != '_' &&
		    *cursor != '.')
			fatal("model contains an unsafe character");
	}
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

static void clear_capability_sets(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[2] = { 0 };

	if (syscall(SYS_capset, &header, data) < 0)
		fatal("clear capability sets: %s", strerror(errno));
}

static void require_suid_dumpable_zero(void)
{
	static const char path[] = "/proc/sys/fs/suid_dumpable";
	char value[16];
	char extra;
	ssize_t length;
	int descriptor;

	descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor < 0)
		fatal("open %s: %s", path, strerror(errno));
	length = read(descriptor, value, sizeof(value) - 1);
	if (length <= 0 || read(descriptor, &extra, 1) != 0)
		fatal("read exact %s value", path);
	if (close(descriptor) < 0)
		fatal("close %s: %s", path, strerror(errno));
	value[length] = '\0';
	while (length > 0 && (value[length - 1] == '\n' ||
			      value[length - 1] == '\r'))
		value[--length] = '\0';
	if (strcmp(value, "0"))
		fatal("%s must be 0 before the provider credential is exposed", path);
}

static void assert_codex_execution_credentials(void)
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
	struct rlimit core;

	if (getresuid(&real_uid, &effective_uid, &saved_uid) < 0 ||
	    getresgid(&real_gid, &effective_gid, &saved_gid) < 0 ||
	    real_uid != EXCLUSIVE_UID || effective_uid != EXCLUSIVE_UID ||
	    saved_uid != EXCLUSIVE_UID || real_gid != EXCLUSIVE_GID ||
	    effective_gid != CODEX_EFFECTIVE_GID ||
	    saved_gid != CODEX_EFFECTIVE_GID ||
	    getgroups(0, NULL) != 0)
		fatal("Codex split-GID execution contract is not exact");
	if (getrlimit(RLIMIT_CORE, &core) < 0 || core.rlim_cur != 0 ||
	    core.rlim_max != 0)
		fatal("Codex core-dump limit is not permanently zero");
	if (syscall(SYS_capget, &header, data) < 0)
		fatal("read Codex capability sets: %s", strerror(errno));
	effective = data[0].effective | ((uint64_t)data[1].effective << 32);
	permitted = data[0].permitted | ((uint64_t)data[1].permitted << 32);
	inheritable = data[0].inheritable |
		      ((uint64_t)data[1].inheritable << 32);
	if (effective != 0 || permitted != 0 || inheritable != 0 ||
	    exclusive_bounding_mask() != EXCLUSIVE_OBSERVER_BOUNDING ||
	    exclusive_ambient_mask() != 0 ||
	    prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) !=
		    EXCLUSIVE_LOCKED_SECUREBITS ||
	    prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0 ||
	    prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0 ||
	    exclusive_process_has_bpf_fd() != 0)
		fatal("Codex post-drop security state is not exact");
}

static void drop_to_collection_credentials(bool codex_process)
{
	struct rlimit core = { 0, 0 };

	if (geteuid() != 0)
		fatal("launcher must start as root");
	if (setrlimit(RLIMIT_CORE, &core) < 0)
		fatal("disable core dumps: %s", strerror(errno));
	restrict_bounding_set(EXCLUSIVE_OBSERVER_BOUNDING);
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
		fatal("clear ambient capabilities: %s", strerror(errno));
	if (prctl(PR_SET_SECUREBITS, EXCLUSIVE_LOCKED_SECUREBITS, 0, 0, 0) < 0)
		fatal("lock securebits: %s", strerror(errno));
	if (setgroups(0, NULL) < 0 ||
	    setresgid(EXCLUSIVE_GID,
		      codex_process ? CODEX_EFFECTIVE_GID : EXCLUSIVE_GID,
		      codex_process ? CODEX_EFFECTIVE_GID : EXCLUSIVE_GID) < 0 ||
	    setresuid(EXCLUSIVE_UID, EXCLUSIVE_UID, EXCLUSIVE_UID) < 0)
		fatal("drop UID/GID: %s", strerror(errno));
	clear_capability_sets();
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
		fatal("make Codex process nondumpable: %s", strerror(errno));
	if (codex_process)
		assert_codex_execution_credentials();
	else if (assert_exclusive_credentials(0) < 0)
		fatal("post-drop credential assertion failed: %s", strerror(errno));
}

static void set_clean_environment(const char *api_key, const char *state_root)
{
	if (clearenv() < 0)
		fatal("clear environment: %s", strerror(errno));
	if (setenv("PATH", CODEX_PATH, 1) < 0 ||
	    setenv("HOME", state_root, 1) < 0 ||
	    setenv("CODEX_HOME", state_root, 1) < 0 ||
	    setenv("USER", "nobody", 1) < 0 ||
	    setenv("LOGNAME", "nobody", 1) < 0 ||
	    setenv("SHELL", "/bin/bash", 1) < 0 ||
	    setenv("LANG", "C.UTF-8", 1) < 0 ||
	    setenv("LC_ALL", "C.UTF-8", 1) < 0)
		fatal("construct clean environment: %s", strerror(errno));
	if (access("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0 &&
	    setenv("SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt", 1) < 0)
		fatal("set CA bundle path: %s", strerror(errno));
	if (api_key && setenv("DEEPSEEK_API_KEY", api_key, 1) < 0)
		fatal("set provider credential: %s", strerror(errno));
}

static void run_fixture_self_test(void)
{
	char *const arguments[] = {
		(char *)MAP_FIXTURE,
		"--ephemeral",
		"--exclusive-contract",
		NULL,
	};

	set_clean_environment(NULL, "/nonexistent");
	if (chdir("/") < 0)
		fatal("change to /: %s", strerror(errno));
	drop_to_collection_credentials(false);
	execv(MAP_FIXTURE, arguments);
	fatal("exec fixture: %s", strerror(errno));
}

static pid_t parse_pid(const char *value)
{
	char *end = NULL;
	long parsed;

	errno = 0;
	parsed = strtol(value, &end, 10);
	if (errno || !end || *end || parsed <= 1 || parsed > INT_MAX)
		fatal("invalid proc-isolation parent PID");
	return (pid_t)parsed;
}

static void run_proc_environment_reader(const char *parent_input)
{
	char path[64];
	pid_t parent = parse_pid(parent_input);
	int descriptor;

	if (assert_exclusive_credentials(0) < 0)
		fatal("tool-side credential normalization did not occur");
	if (getenv("DEEPSEEK_API_KEY"))
		fatal("proc-isolation reader inherited the provider credential");
	if (getppid() != parent)
		fatal("proc-isolation reader parent changed before the access check");
	if (snprintf(path, sizeof(path), "/proc/%ld/environ", (long)parent) >=
	    (int)sizeof(path))
		fatal("proc-isolation path is too long");
	errno = 0;
	descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (descriptor >= 0) {
		close(descriptor);
		fatal("same-UID tool process could open Codex parent environment");
	}
	if (errno != EACCES && errno != EPERM)
		fatal("Codex parent environment failed with unexpected errno %d", errno);
}

static void run_post_exec_proc_isolation_self_test(void)
{
	char parent_pid[32];
	char *child_environment[] = {
		"PATH=/usr/bin:/bin",
		"LANG=C",
		"LC_ALL=C",
		NULL,
	};
	char *bash_arguments[] = {
		"bash",
		"--noprofile",
		"--norc",
		"-c",
		"exec " COLLECTION_LAUNCHER " "
		"--proc-environ-reader \"$1\"",
		"bash",
		parent_pid,
		NULL,
	};
	pid_t child;
	int status;

	assert_codex_execution_credentials();
	if (!getenv("DEEPSEEK_API_KEY") ||
	    strcmp(getenv("DEEPSEEK_API_KEY"), PROC_ISOLATION_CANARY))
		fatal("post-exec isolation parent lost its canary credential");
	if (snprintf(parent_pid, sizeof(parent_pid), "%ld", (long)getpid()) >=
	    (int)sizeof(parent_pid))
		fatal("proc-isolation parent PID is too long");
	if (fflush(NULL) != 0)
		fatal("flush streams before proc-isolation fork: %s", strerror(errno));
	child = fork();
	if (child < 0)
		fatal("fork proc-isolation reader: %s", strerror(errno));
	if (child == 0) {
		execve("/bin/bash", bash_arguments, child_environment);
		_exit(120);
	}
	do {
		if (waitpid(child, &status, 0) == child)
			break;
		if (errno != EINTR)
			fatal("wait for proc-isolation reader: %s", strerror(errno));
	} while (true);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fatal("same-UID proc-isolation reader did not prove access denial");
	assert_codex_execution_credentials();
	puts("CODEX_PARENT_ENVIRON_ISOLATION_PASS");
}

static void run_proc_isolation_self_test(void)
{
	char *arguments[] = {
		"codex-task-launcher",
		"--post-exec-proc-isolation-self-test",
		NULL,
	};

	require_suid_dumpable_zero();
	set_clean_environment(PROC_ISOLATION_CANARY, "/nonexistent");
	drop_to_collection_credentials(true);
	execv("/proc/self/exe", arguments);
	fatal("exec post-drop proc-isolation parent: %s", strerror(errno));
}

static void run_codex(const char *model, const char *prompt_input,
		      const char *workspace_input, const char *state_input)
{
	char prompt[PATH_MAX];
	char workspace[PATH_MAX];
	char state_root[PATH_MAX];
	char last_message[PATH_MAX];
	const char *source_key;
	char *api_key;
	size_t key_length;
	int prompt_fd;
	char *arguments[60];
	size_t index = 0;

	validate_model(model);
	prompt_fd = open_prompt(prompt_input, prompt);
	require_directory(workspace_input, WORKSPACE_ROOT, workspace);
	require_dedicated_workspace_tmpfs(workspace);
	require_directory(state_input, STATE_ROOT, state_root);
	require_dedicated_state_tmpfs(state_root);
	require_suid_dumpable_zero();
	if (snprintf(last_message, sizeof(last_message), "%s/last-message.txt",
		     state_root) >= (int)sizeof(last_message))
		fatal("last-message path is too long");
	if (access(last_message, F_OK) == 0 || errno != ENOENT)
		fatal("last-message destination already exists or cannot be checked");

	source_key = getenv("DEEPSEEK_API_KEY");
	if (!source_key)
		fatal("DEEPSEEK_API_KEY is absent");
	key_length = strlen(source_key);
	if (key_length < 4 || key_length > MAX_API_KEY_BYTES ||
	    strncmp(source_key, "sk-", 3) || strchr(source_key, '\n') ||
	    strchr(source_key, '\r'))
		fatal("DEEPSEEK_API_KEY has an invalid shape");
	api_key = strdup(source_key);
	if (!api_key)
		fatal("copy provider credential: %s", strerror(errno));

	if (prompt_fd != STDIN_FILENO) {
		if (dup2(prompt_fd, STDIN_FILENO) < 0 || close(prompt_fd) < 0)
			fatal("connect prompt to stdin: %s", strerror(errno));
	}
	if (chdir(workspace) < 0)
		fatal("change to workspace %s: %s", workspace, strerror(errno));
	umask(0077);
	set_clean_environment(api_key, state_root);
	drop_to_collection_credentials(true);

	arguments[index++] = (char *)CODEX_BINARY;
	arguments[index++] = "exec";
	arguments[index++] = "--strict-config";
	arguments[index++] = "--ephemeral";
	arguments[index++] = "--json";
	arguments[index++] = "--color";
	arguments[index++] = "never";
	arguments[index++] = "--ignore-user-config";
	arguments[index++] = "--ignore-rules";
	arguments[index++] = "--skip-git-repo-check";
	arguments[index++] = "--dangerously-bypass-approvals-and-sandbox";
	arguments[index++] = "--cd";
	arguments[index++] = workspace;
	arguments[index++] = "--output-last-message";
	arguments[index++] = last_message;
	arguments[index++] = "--model";
	arguments[index++] = (char *)model;
	arguments[index++] = "--config";
	arguments[index++] = "model_provider=\"deepseek\"";
	arguments[index++] = "--config";
	arguments[index++] = "forced_login_method=\"api\"";
	arguments[index++] = "--config";
	arguments[index++] = "model_reasoning_effort=\"low\"";
	arguments[index++] = "--config";
	arguments[index++] = "model_catalog_json=\"" MODEL_CATALOG "\"";
	arguments[index++] = "--config";
	arguments[index++] = "model_providers.deepseek.name=\"DeepSeek\"";
	arguments[index++] = "--config";
	arguments[index++] = "model_providers.deepseek.base_url=\"https://api.deepseek.com/\"";
	arguments[index++] = "--config";
	arguments[index++] = "model_providers.deepseek.env_key=\"DEEPSEEK_API_KEY\"";
	arguments[index++] = "--config";
	arguments[index++] = "model_providers.deepseek.wire_api=\"responses\"";
	arguments[index++] = "--config";
	arguments[index++] = "model_providers.deepseek.requires_openai_auth=false";
	arguments[index++] = "--config";
	arguments[index++] = "model_providers.deepseek.request_max_retries=0";
	arguments[index++] = "--config";
	arguments[index++] = "model_providers.deepseek.stream_max_retries=0";
	arguments[index++] = "--config";
	arguments[index++] = "model_providers.deepseek.stream_idle_timeout_ms=300000";
	arguments[index++] = "--config";
	arguments[index++] = "shell_environment_policy.inherit=\"core\"";
	arguments[index++] = "--config";
	arguments[index++] = "shell_environment_policy.ignore_default_excludes=false";
	arguments[index++] = "--config";
	arguments[index++] = "shell_environment_policy.filters.DEEPSEEK_API_KEY=\"exclude\"";
	arguments[index++] = "--config";
	arguments[index++] = "web_search=\"disabled\"";
	arguments[index++] = "--config";
	arguments[index++] = "otel.exporter=\"none\"";
	arguments[index++] = "-";
	arguments[index] = NULL;

	execv(CODEX_BINARY, arguments);
	memset(api_key, 0, key_length);
	fatal("exec Codex: %s", strerror(errno));
}

static void usage(const char *program)
{
	fprintf(stderr,
		"usage: %s --self-test\n"
		"       %s --fixture-self-test\n"
		"       %s --proc-isolation-self-test\n"
		"       %s MODEL PROMPT WORKSPACE STATE_ROOT\n",
		program, program, program, program);
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--self-test")) {
		puts("codex-task-launcher self-test PASS");
		return EXIT_SUCCESS;
	}
	if (argc == 2 && !strcmp(argv[1], "--fixture-self-test"))
		run_fixture_self_test();
	if (argc == 2 && !strcmp(argv[1], "--proc-isolation-self-test")) {
		run_proc_isolation_self_test();
		return EXIT_FAILURE;
	}
	if (argc == 2 &&
	    !strcmp(argv[1], "--post-exec-proc-isolation-self-test")) {
		run_post_exec_proc_isolation_self_test();
		return EXIT_SUCCESS;
	}
	if (argc == 3 && !strcmp(argv[1], "--proc-environ-reader")) {
		run_proc_environment_reader(argv[2]);
		return EXIT_SUCCESS;
	}
	if (argc == 5)
		run_codex(argv[1], argv[2], argv[3], argv[4]);
	usage(argv[0]);
	return EXIT_FAILURE;
}
