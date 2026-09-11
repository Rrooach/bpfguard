#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 0077

usage()
{
	echo "usage: $0 deploy-only|run BATCH_ID MODEL" >&2
	exit 2
}

[[ "$#" -eq 3 ]] || usage
readonly MODE="$1"
readonly BATCH_ID="$2"
readonly MODEL="$3"
[[ "$MODE" == deploy-only || "$MODE" == run ]] || usage
[[ "$BATCH_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || {
	echo "invalid batch ID" >&2
	exit 2
}
[[ "$MODEL" == deepseek-flash || "$MODEL" == deepseek-v4-pro ]] || {
	echo "unsupported model: $MODEL" >&2
	exit 2
}
[[ "$(id -u)" -eq 0 ]] || {
	echo "guest suite must run as root" >&2
	exit 1
}
for command in awk mount mountpoint sha256sum stat tar umount; do
	command -v "$command" >/dev/null || {
		echo "missing Guest runtime dependency: $command" >&2
		exit 1
	}
done

readonly OBSERVER_ROOT=/opt/bpf-state-observer
readonly COLLECTION_ROOT=/opt/codex-collection
readonly OBSERVER="$OBSERVER_ROOT/bpf-state-observer"
readonly RECORDER="$OBSERVER_ROOT/recorder.bpf.o"
readonly SCOPE="$COLLECTION_ROOT/collection-scope.json"
readonly TASKS_ROOT="$COLLECTION_ROOT/tasks"
readonly CODEX_ROOT="$COLLECTION_ROOT/codex"
readonly CODEX="$CODEX_ROOT/bin/codex"
readonly CODEX_PATH="$CODEX_ROOT/codex-path:/usr/bin:/bin"
readonly MODELS="$COLLECTION_ROOT/models.json"
readonly LAUNCHER="$COLLECTION_ROOT/codex-task-launcher"
readonly VALIDATOR="$COLLECTION_ROOT/agent-collection-assert"
readonly CGROUP_ROOT=/sys/fs/cgroup/bpf-state-observer
readonly RESULTS_PARENT=/var/lib/bpf-observer/agent-collection
readonly RESULTS_ROOT="$RESULTS_PARENT/$BATCH_ID"
readonly VOLATILE_ROOT="/run/codex-collection/$BATCH_ID"
readonly -a EXPECTED_TASK_FILES=(
	00-text-only.txt
	01-file-write.txt
	02-ephemeral-map.txt
	03-transient-restore.txt
)
readonly -a EXPECTED_TASK_SHA256=(
	7a951b3044580c63992559e94d0e963deb457a59392d2347e9f51da9bec7910a
	b639491ff8f7b0f812c0ba299ffd6d7a3aed35ba87f61154d4f3e0e718ff98b7
	3eaf3962eaca1ece215aaca53ad8aaa4473f222ee5bd51544eedc9d4cf1aa733
	24e00bc598e5bb52e4882cb6b717d6c04d86aa6ced10bb8e01cbceec6a3cdcb8
)

for input in "$OBSERVER" "$RECORDER" "$SCOPE" "$CODEX" "$MODELS" \
	"$LAUNCHER" "$VALIDATOR" "$OBSERVER_ROOT/map-lifecycle"; do
	[[ -f "$input" && ! -L "$input" ]] || {
		echo "missing or unsafe immutable input: $input" >&2
		exit 1
	}
done
[[ -d "$TASKS_ROOT" && ! -L "$TASKS_ROOT" ]] || {
	echo "missing task directory: $TASKS_ROOT" >&2
	exit 1
}
mapfile -d '' -t actual_task_entries < <(
	find "$TASKS_ROOT" -mindepth 1 -maxdepth 1 -printf '%f\0' | LC_ALL=C sort -z
)
[[ "${#actual_task_entries[@]}" -eq "${#EXPECTED_TASK_FILES[@]}" ]] || {
	echo "task directory does not contain exactly four contract entries" >&2
	exit 1
}
for task_index in "${!EXPECTED_TASK_FILES[@]}"; do
	expected_task="${EXPECTED_TASK_FILES[$task_index]}"
	task_path="$TASKS_ROOT/$expected_task"
	[[ "${actual_task_entries[$task_index]}" == "$expected_task" &&
	   -f "$task_path" && ! -L "$task_path" && -s "$task_path" &&
	   "$(stat -c %u:%g:%a:%h -- "$task_path")" == 0:0:444:1 ]] || {
		echo "task input violates the fixed contract: $expected_task" >&2
		exit 1
	}
	task_digest="$(sha256sum -- "$task_path" | awk '{print $1}')"
	[[ "$task_digest" == "${EXPECTED_TASK_SHA256[$task_index]}" ]] || {
		echo "task input digest violates the fixed contract: $expected_task" >&2
		exit 1
	}
done
[[ ! -e "$RESULTS_ROOT" && ! -L "$RESULTS_ROOT" ]] || {
	echo "refusing to reuse result path: $RESULTS_ROOT" >&2
	exit 1
}
[[ ! -e "$VOLATILE_ROOT" && ! -L "$VOLATILE_ROOT" ]] || {
	echo "refusing to reuse volatile state path: $VOLATILE_ROOT" >&2
	exit 1
}

DEEPSEEK_API_KEY=""
volatile_mounted=0
active_workspace=""
workspace_mounted=0
cleanup()
{
	local status=$?

	trap - EXIT HUP INT TERM
	DEEPSEEK_API_KEY=""
	unset DEEPSEEK_API_KEY || true
	if [[ "$workspace_mounted" -eq 1 && -n "$active_workspace" ]] &&
		mountpoint -q -- "$active_workspace"; then
		if ! umount -- "$active_workspace"; then
			echo "failed to unmount active task workspace" >&2
			status=1
		fi
	fi
	if [[ "$volatile_mounted" -eq 1 ]] && mountpoint -q -- "$VOLATILE_ROOT"; then
		if ! umount -- "$VOLATILE_ROOT"; then
			echo "failed to unmount volatile Codex state" >&2
			status=1
		fi
	fi
	if [[ -d "$VOLATILE_ROOT" && ! -L "$VOLATILE_ROOT" ]]; then
		rm -rf -- "$VOLATILE_ROOT"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ulimit -c 0
ulimit -l unlimited
if tail -n +2 /proc/swaps | grep -q '[^[:space:]]'; then
	echo "swap must be disabled before injecting the provider credential" >&2
	exit 1
fi
[[ -f /proc/sys/fs/suid_dumpable &&
   ! -L /proc/sys/fs/suid_dumpable ]] || {
	echo "fs.suid_dumpable control is unavailable" >&2
	exit 1
}
if [[ "$(< /proc/sys/fs/suid_dumpable)" != 0 ]]; then
	printf '0\n' > /proc/sys/fs/suid_dumpable
fi
[[ "$(< /proc/sys/fs/suid_dumpable)" == 0 ]] || {
	echo "fs.suid_dumpable must be zero" >&2
	exit 1
}
if [[ "$(stat -f -c %T /sys/kernel/tracing 2>/dev/null || true)" != tracefs ]]; then
	mount -t tracefs tracefs /sys/kernel/tracing
fi
if [[ "$(stat -f -c %T /sys/fs/bpf 2>/dev/null || true)" != bpf_fs ]]; then
	mount -t bpf bpf /sys/fs/bpf
fi
[[ "$(stat -f -c %T /sys/fs/cgroup)" == cgroup2fs ]]
[[ -r /sys/kernel/tracing/events/raw_syscalls/sys_enter/id ]]
[[ -r /sys/kernel/tracing/events/raw_syscalls/sys_exit/id ]]

install -d -o root -g root -m 0711 "$RESULTS_PARENT"
install -d -o root -g root -m 0711 "$RESULTS_ROOT"
install -d -o root -g root -m 0711 /run/codex-collection
install -d -o root -g root -m 0711 "$VOLATILE_ROOT"
mount -t tmpfs \
	-o mode=0711,uid=0,gid=0,nosuid,nodev,noexec,size=64m \
	"codex-collection-$BATCH_ID" "$VOLATILE_ROOT"
volatile_mounted=1
mountpoint -q -- "$VOLATILE_ROOT"
[[ "$(stat -f -c %T -- "$VOLATILE_ROOT")" == tmpfs ]]

workspace_mount_is_bounded()
{
	local workspace="$1"
	local block_size
	local blocks
	local inodes

	mountpoint -q -- "$workspace" || return 1
	[[ "$(stat -f -c %T -- "$workspace")" == tmpfs ]] || return 1
	[[ "$(stat -c %u:%g:%a -- "$workspace")" == 65534:65534:700 ]] ||
		return 1
	block_size="$(stat -f -c %S -- "$workspace")"
	blocks="$(stat -f -c %b -- "$workspace")"
	inodes="$(stat -f -c %c -- "$workspace")"
	[[ "$block_size" =~ ^[1-9][0-9]*$ && "$blocks" =~ ^[1-9][0-9]*$ &&
	   "$inodes" =~ ^[1-9][0-9]*$ ]] || return 1
	(( block_size * blocks <= 16 * 1024 * 1024 && inodes <= 256 )) ||
		return 1
	awk -v target="$workspace" '
		function has(options, wanted) {
			return index("," options ",", "," wanted ",") != 0
		}
		$5 == target {
			found = 1
			if (!has($6, "nosuid") || !has($6, "nodev") ||
			    !has($6, "noexec"))
				bad = 1
			separator = 0
			for (field = 7; field <= NF; field++)
				if ($field == "-") {
					separator = field
					break
				}
			if (!separator || $(separator + 1) != "tmpfs")
				bad = 1
		}
		END { exit !(found && !bad) }
	' /proc/self/mountinfo
}

mount_bounded_workspace()
{
	local workspace="$1"
	local label="$2"

	[[ "$workspace_mounted" -eq 0 && -z "$active_workspace" ]] || return 1
	[[ "$label" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || return 1
	install -d -o root -g root -m 0700 "$workspace"
	active_workspace="$workspace"
	if ! mount -t tmpfs \
		-o mode=0700,uid=65534,gid=65534,nosuid,nodev,noexec,size=16m,nr_inodes=256 \
		"codex-workspace-$label" "$workspace"; then
		active_workspace=""
		return 1
	fi
	workspace_mounted=1
	workspace_mount_is_bounded "$workspace"
}

unmount_bounded_workspace()
{
	local workspace="$1"

	[[ "$workspace_mounted" -eq 1 && "$active_workspace" == "$workspace" ]] ||
		return 1
	mountpoint -q -- "$workspace" || return 1
	umount -- "$workspace" || return 1
	! mountpoint -q -- "$workspace" || return 1
	workspace_mounted=0
	active_workspace=""
	return 0
}

"$LAUNCHER" --proc-isolation-self-test \
	> "$RESULTS_ROOT/security-isolation.txt"
{
	echo 'post_exec_parent_environ_denial=PASS'
	echo 'codex_dumpable=FORCED_ZERO_BY_SPLIT_GID'
	echo 'fs.suid_dumpable=0'
	echo 'volatile_state=DEDICATED_TMPFS_NOSUID_NODEV_NOEXEC'
	echo 'task_workspace=PER_TASK_TMPFS_16M_256_INODES_NOSUID_NODEV_NOEXEC'
} >> "$RESULTS_ROOT/security-isolation.txt"

{
	echo 'task_contract=codex-deepseek-four-task-v1'
	echo "task_count=${#EXPECTED_TASK_FILES[@]}"
	for task_index in "${!EXPECTED_TASK_FILES[@]}"; do
		echo "task=${EXPECTED_TASK_FILES[$task_index]} sha256=${EXPECTED_TASK_SHA256[$task_index]}"
	done
} > "$RESULTS_ROOT/task-contract.txt"

readonly RECORDER_SHA256="$(sha256sum "$RECORDER" | awk '{print $1}')"
[[ "$RECORDER_SHA256" =~ ^[a-f0-9]{64}$ ]]

{
	echo 'profile=agent-collection-v1'
	echo 'claim_mode=DIAGNOSTIC_OBSERVED_ONLY'
	echo 'strict_exclusive_vm_v1=false'
	echo 'unchanged_within_scope_authorized=false'
	echo 'network=QEMU_USER_MODE_OUTBOUND_ENABLED'
	echo 'credential_proc_isolation=POST_EXEC_NONDUMPABLE_SPLIT_GID'
	echo 'volatile_state=DEDICATED_TMPFS_NOSUID_NODEV_NOEXEC'
	echo 'task_workspace=PER_TASK_TMPFS_16M_256_INODES_NOSUID_NODEV_NOEXEC'
	echo "batch_id=$BATCH_ID"
	echo "model=$MODEL"
} > "$RESULTS_ROOT/collection-contract.txt"

{
	date -u '+utc=%Y-%m-%dT%H:%M:%SZ'
	uname -a
	echo "boot_id=$(</proc/sys/kernel/random/boot_id)"
	echo "unprivileged_bpf_disabled=$(</proc/sys/kernel/unprivileged_bpf_disabled)"
	"$CODEX" --version
	echo "codex_sha256=$(sha256sum "$CODEX" | awk '{print $1}')"
	echo "observer_sha256=$(sha256sum "$OBSERVER" | awk '{print $1}')"
	echo "recorder_sha256=$RECORDER_SHA256"
	echo "scope_sha256=$(sha256sum "$SCOPE" | awk '{print $1}')"
	echo "models_sha256=$(sha256sum "$MODELS" | awk '{print $1}')"
	if [[ -r /etc/os-release ]]; then
		grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' /etc/os-release
	fi
} > "$RESULTS_ROOT/environment.txt"

readonly MODEL_DEBUG_HOME="$VOLATILE_ROOT/model-debug-home"
install -d -o root -g root -m 0700 "$MODEL_DEBUG_HOME"
env -i PATH="$CODEX_PATH" HOME="$MODEL_DEBUG_HOME" \
	CODEX_HOME="$MODEL_DEBUG_HOME" LANG=C.UTF-8 LC_ALL=C.UTF-8 \
	"$CODEX" debug models \
	--config "model_catalog_json=\"$MODELS\"" \
	> "$RESULTS_ROOT/resolved-models.json"
grep -q "\"slug\":\"$MODEL\"" "$RESULTS_ROOT/resolved-models.json"

getent ahosts api.deepseek.com > "$RESULTS_ROOT/deepseek-dns.txt"
if ! timeout --foreground 15s bash -c \
	'exec 3<>/dev/tcp/api.deepseek.com/443; exec 3>&-; exec 3<&-'; then
	echo "cannot establish a TCP connection to api.deepseek.com:443" >&2
	exit 1
fi
echo 'tcp_443=PASS' > "$RESULTS_ROOT/deepseek-network.txt"

# Exercise the exact non-root Codex/provider path without using a real account
# or spending tokens. A syntactically shaped but invalid key must reach the
# DeepSeek Responses endpoint and be rejected. This catches CLI/config/TLS
# regressions that a raw TCP probe cannot detect.
readonly AUTH_PROBE_ROOT="$RESULTS_ROOT/provider-auth-probe"
readonly AUTH_PROBE_WORKSPACE="$AUTH_PROBE_ROOT/workspace"
readonly AUTH_PROBE_STATE="$VOLATILE_ROOT/provider-auth-probe"
install -d -o root -g root -m 0711 "$AUTH_PROBE_ROOT"
install -d -o 65534 -g 65534 -m 0700 "$AUTH_PROBE_STATE"
mount_bounded_workspace "$AUTH_PROBE_WORKSPACE" provider-auth-probe || {
	echo "failed to establish bounded provider-probe workspace" >&2
	exit 1
}
awk -v target="$AUTH_PROBE_WORKSPACE" '$5 == target { print }' \
	/proc/self/mountinfo > "$AUTH_PROBE_ROOT/workspace.mountinfo"
set +e
DEEPSEEK_API_KEY=sk-invalid-agent-collection-probe \
	timeout --foreground 90s "$LAUNCHER" "$MODEL" \
	"$TASKS_ROOT/00-text-only.txt" "$AUTH_PROBE_WORKSPACE" \
	"$AUTH_PROBE_STATE" > "$AUTH_PROBE_ROOT/codex.jsonl" \
	2> "$AUTH_PROBE_ROOT/codex.stderr"
auth_probe_rc=$?
set -e
unmount_bounded_workspace "$AUTH_PROBE_WORKSPACE" || {
	echo "failed to unmount provider-probe workspace" >&2
	exit 1
}
rm -rf -- "$AUTH_PROBE_STATE"
[[ "$auth_probe_rc" -eq 1 ]] || {
	echo "invalid-key provider probe returned unexpected status: $auth_probe_rc" >&2
	exit 1
}
if ! "$VALIDATOR" --provider-auth-probe \
	"$AUTH_PROBE_ROOT/codex.jsonl" "$AUTH_PROBE_ROOT/codex.stderr" \
	> "$AUTH_PROBE_ROOT/validation.json" \
	2> "$AUTH_PROBE_ROOT/validation.stderr"; then
	echo "provider authentication probe violates its strict event contract" >&2
	exit 1
fi
echo "provider_auth_rejection=PASS validator=PASS rc=$auth_probe_rc" \
	> "$AUTH_PROBE_ROOT/status.txt"

"$OBSERVER" doctor \
	--recorder-object "$RECORDER" \
	--cgroup-root "$CGROUP_ROOT" \
	--output "$RESULTS_ROOT/doctor.json"
grep -q '"ready_for_runtime": true' "$RESULTS_ROOT/doctor.json"
if grep -q '"status": "FAIL"' "$RESULTS_ROOT/doctor.json"; then
	echo "observer doctor contains a failed prerequisite" >&2
	exit 1
fi

readonly CALIBRATION_ROOT="$RESULTS_ROOT/calibration"
install -d -o root -g root -m 0700 "$CALIBRATION_ROOT"
"$OBSERVER" observe \
	--scope "$SCOPE" \
	--recorder-object "$RECORDER" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	--output-dir "$CALIBRATION_ROOT/observer-run" \
	--cgroup-root "$CGROUP_ROOT" \
	--run-id agent-calibration \
	--run-epoch 7000 \
	--timeout-ms 30000 \
	--drain-timeout-ms 5000 \
	-- "$LAUNCHER" --fixture-self-test \
	> "$CALIBRATION_ROOT/observe.json" \
	2> "$CALIBRATION_ROOT/observe.stderr"
"$OBSERVER" verify-run \
	--run-dir "$CALIBRATION_ROOT/observer-run" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	> "$CALIBRATION_ROOT/verify.json"
grep -q '"workload_exit_code": 0' "$CALIBRATION_ROOT/observe.json"
grep -q '"events_verified": 6' "$CALIBRATION_ROOT/verify.json"
grep -q '"evidence_complete": true' "$CALIBRATION_ROOT/verify.json"
echo 'calibration=PASS' > "$CALIBRATION_ROOT/status.txt"

if [[ "$MODE" == deploy-only ]]; then
	echo 'deployment=PASS' > "$RESULTS_ROOT/status.txt"
	echo "guest-run-suite: deployment, provider rejection, and calibration PASS"
	exit 0
fi

IFS= read -r DEEPSEEK_API_KEY || {
	echo "provider credential was not supplied on stdin" >&2
	exit 1
}
if IFS= read -r _unexpected_input; then
	echo "provider credential input contains more than one line" >&2
	exit 1
fi
[[ "$DEEPSEEK_API_KEY" == sk-* && ${#DEEPSEEK_API_KEY} -le 512 ]] || {
	echo "provider credential has an invalid shape" >&2
	exit 1
}
export DEEPSEEK_API_KEY

workspace_inventory()
{
	local workspace="$1"
	local output="$2"
	local relative
	local path
	local kind
	local digest

	(
		cd "$workspace"
		while IFS= read -r -d '' relative; do
			path="$workspace/$relative"
			kind="$(stat -c %F -- "$path")"
			digest=-
			if [[ -f "$path" && ! -L "$path" ]]; then
				digest="$(sha256sum -- "$path" | awk '{print $1}')"
			elif [[ -L "$path" ]]; then
				digest="link:$(readlink -- "$path")"
			fi
			printf 'path=%q\ttype=%q\tmode=%s\tuid=%s\tgid=%s\tsize=%s\tsha256=%q\n' \
				"$relative" "$kind" \
				"$(stat -c %a -- "$path")" \
				"$(stat -c %u -- "$path")" \
				"$(stat -c %g -- "$path")" \
				"$(stat -c %s -- "$path")" "$digest"
		done < <(find . -xdev -mindepth 1 -printf '%P\0' | LC_ALL=C sort -z)
	) > "$output"
}

postcondition()
{
	local task="$1"
	local workspace="$2"
	local before_inventory="$3"
	local after_inventory="$4"
	local last_message="$5"
	local expected_message

	case "$task" in
	00-text-only)
		expected_message=TEXT_ONLY_OK
		[[ ! -s "$after_inventory" ]] || return 1
		;;
	01-file-write)
		expected_message=FILE_WRITE_OK
		[[ -f "$workspace/artifact.txt" && ! -L "$workspace/artifact.txt" ]] ||
			return 1
		cmp -s "$workspace/artifact.txt" <(printf 'codex-collection-ok\n') ||
			return 1
		[[ "$(find "$workspace" -xdev -mindepth 1 -printf . | wc -c)" -eq 1 ]] ||
			return 1
		;;
	02-ephemeral-map)
		expected_message=EPHEMERAL_MAP_OK
		cmp -s "$before_inventory" "$after_inventory" || return 1
		;;
	03-transient-restore)
		expected_message=TRANSIENT_RESTORE_OK
		cmp -s "$before_inventory" "$after_inventory" || return 1
		;;
	*)
		return 1
		;;
	esac
	[[ -f "$last_message" && ! -L "$last_message" ]] || return 1
	[[ "$(< "$last_message")" == "$expected_message" ]] || return 1
	return 0
}

readonly SUMMARY="$RESULTS_ROOT/summary.tsv"
printf 'task\tobserver_rc\tverify_rc\tevents\tevidence_contract\tcodex_jsonl_contract\tpostcondition\tworkspace_capture\ttask_status\tstate_verdict\n' \
	> "$SUMMARY"
install -d -o root -g root -m 0711 "$RESULTS_ROOT/tasks"
overall_status=0
epoch=7100
for expected_task_file in "${EXPECTED_TASK_FILES[@]}"; do
	task_file="$TASKS_ROOT/$expected_task_file"
	task="$(basename -- "$task_file" .txt)"
	epoch=$((epoch + 1))
	task_root="$RESULTS_ROOT/tasks/$task"
	workspace="$task_root/workspace"
	state_root="$VOLATILE_ROOT/$task"
	install -d -o root -g root -m 0711 "$task_root"
	install -d -o 65534 -g 65534 -m 0700 "$state_root"
	mount_bounded_workspace "$workspace" "$task" || {
		echo "failed to establish bounded workspace for $task" >&2
		exit 1
	}
	awk -v target="$workspace" '$5 == target { print }' \
		/proc/self/mountinfo > "$task_root/workspace.mountinfo"
	install -o root -g root -m 0400 "$task_file" "$task_root/prompt.txt"
	workspace_inventory "$workspace" "$task_root/workspace.before"

	set +e
	"$OBSERVER" observe \
		--scope "$SCOPE" \
		--recorder-object "$RECORDER" \
		--expected-recorder-sha256 "$RECORDER_SHA256" \
		--output-dir "$task_root/observer-run" \
		--cgroup-root "$CGROUP_ROOT" \
		--run-id "agent-$task" \
		--run-epoch "$epoch" \
		--timeout-ms 600000 \
		--drain-timeout-ms 10000 \
		-- "$LAUNCHER" "$MODEL" "$task_file" "$workspace" "$state_root" \
		> "$task_root/observe.json" \
		2> "$task_root/observe.stderr"
	observer_rc=$?
	set -e

	workspace_inventory "$workspace" "$task_root/workspace.after"
	diff -u "$task_root/workspace.before" "$task_root/workspace.after" \
		> "$task_root/workspace.diff" || true
	if [[ -f "$state_root/last-message.txt" ]]; then
		install -o root -g root -m 0400 "$state_root/last-message.txt" \
			"$task_root/last-message.txt"
	fi
	rm -rf -- "$state_root"

	verify_rc=1
	actual_events=0
	verdict=UNAVAILABLE
	if [[ "$observer_rc" -eq 0 ]]; then
		set +e
		"$OBSERVER" verify-run \
			--run-dir "$task_root/observer-run" \
			--expected-recorder-sha256 "$RECORDER_SHA256" \
			> "$task_root/verify.json" \
			2> "$task_root/verify.stderr"
		verify_rc=$?
		set -e
		if [[ -f "$task_root/observer-run/raw-events.jsonl" ]]; then
			actual_events="$(wc -l < "$task_root/observer-run/raw-events.jsonl")"
		fi
	fi

	evidence_contract=FAIL
	codex_jsonl_contract=FAIL
	set +e
	"$VALIDATOR" "$task" "$MODEL" "$epoch" "$task_root" "$task_file" \
		"$workspace" "$state_root" "$LAUNCHER" \
		> "$task_root/task-validation.json" \
		2> "$task_root/task-validation.stderr"
	validation_rc=$?
	set -e
	case "$validation_rc" in
	0)
		evidence_contract=PASS
		codex_jsonl_contract=PASS
		verdict=INCONCLUSIVE
		;;
	20)
		codex_jsonl_contract=PASS
		;;
	21)
		evidence_contract=PASS
		verdict=INCONCLUSIVE
		;;
	esac

	post_status=FAIL
	if postcondition "$task" "$workspace" "$task_root/workspace.before" \
		"$task_root/workspace.after" "$task_root/last-message.txt"; then
		post_status=PASS
	fi
	workspace_capture=FAIL
	if tar --format=pax --numeric-owner -C "$workspace" \
		-cf "$task_root/workspace.tar" . &&
		[[ -f "$task_root/workspace.tar" &&
		   ! -L "$task_root/workspace.tar" ]]; then
		(
			cd "$task_root"
			sha256sum workspace.tar > workspace.tar.sha256
		)
		workspace_capture=PASS
	else
		echo "failed to capture workspace for $task" >&2
		overall_status=1
	fi
	if ! unmount_bounded_workspace "$workspace"; then
		echo "failed to unmount workspace for $task" >&2
		exit 1
	fi
	task_status=FAIL
	if [[ "$observer_rc" -eq 0 && "$verify_rc" -eq 0 && \
	      "$evidence_contract" == PASS && \
	      "$codex_jsonl_contract" == PASS && "$post_status" == PASS &&
	      "$workspace_capture" == PASS ]]; then
		task_status=PASS
	else
		overall_status=1
	fi
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
		"$task" "$observer_rc" "$verify_rc" "$actual_events" \
		"$evidence_contract" "$codex_jsonl_contract" \
		"$post_status" "$workspace_capture" "$task_status" "$verdict" \
		>> "$SUMMARY"
done

[[ "$(wc -l < "$SUMMARY")" -eq "$((1 + ${#EXPECTED_TASK_FILES[@]}))" ]] || {
	echo "summary does not contain exactly four task rows" >&2
	overall_status=1
}

DEEPSEEK_API_KEY=""
unset DEEPSEEK_API_KEY
if [[ "$overall_status" -eq 0 ]]; then
	echo 'collection=PASS' > "$RESULTS_ROOT/status.txt"
	echo "guest-run-suite: Codex collection PASS"
else
	echo 'collection=FAIL' > "$RESULTS_ROOT/status.txt"
	echo "guest-run-suite: one or more task contracts failed" >&2
fi
exit "$overall_status"
