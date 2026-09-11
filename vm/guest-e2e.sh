#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 OBSERVER_DIRECTORY RECORDER_SHA256" >&2
	exit 2
fi

BASE="$1"
RECORDER_SHA256="$2"
BIN="${BASE}/bpf-state-observer"
ASSERT_BIN="${BASE}/vm-e2e-assert"
OBJ="${BASE}/recorder.bpf.o"
WORKLOAD="${BASE}/map-lifecycle"
CGROUP_ROOT=/sys/fs/cgroup/bpf-state-observer
PIN_ROOT=/sys/fs/bpf/bpf-state-observer-e2e
PIN_PATH="${PIN_ROOT}/map"
TARGET_READY="${BASE}/target-ready"
TARGET_RELEASE="${BASE}/target-release"
OUTSIDER_READY="${BASE}/outsider-ready"
OUTSIDER_RELEASE="${BASE}/outsider-release"
PIN_ROOT_OWNED=0
OBSERVE_PID=""
OUTSIDER_PID=""

[[ "$RECORDER_SHA256" =~ ^[a-f0-9]{64}$ ]] || {
	echo "recorder SHA-256 is not canonical lowercase hexadecimal" >&2
	exit 2
}
for path in "$BIN" "$ASSERT_BIN" "$OBJ" "$WORKLOAD" \
	"${BASE}/default-scope.json" "${BASE}/vm-pinned-scope.json"; do
	[[ -f "$path" ]] || { echo "missing Guest input: $path" >&2; exit 2; }
done

stop_child()
{
	local pid="$1"
	local attempts

	[[ -n "$pid" ]] || return 0
	if kill -0 "$pid" 2>/dev/null; then
		kill -TERM "$pid" 2>/dev/null || true
		for ((attempts = 0; attempts < 50; attempts++)); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.02
		done
	fi
	if kill -0 "$pid" 2>/dev/null; then
		kill -KILL "$pid" 2>/dev/null || true
	fi
	wait "$pid" 2>/dev/null || true
}

cleanup_owned_resources()
{
	local cleanup_status=0

	# Let either cooperative child leave its rendezvous before terminating its
	# direct parent. The outer host timeout remains the final failure fence.
	touch -- "$TARGET_RELEASE" "$OUTSIDER_RELEASE" 2>/dev/null || true
	stop_child "$OUTSIDER_PID"
	stop_child "$OBSERVE_PID"
	OUTSIDER_PID=""
	OBSERVE_PID=""

	# Path existence alone never authorizes removal. Only a directory this
	# invocation atomically created may have its fixture pin unlinked.
	if [[ "$PIN_ROOT_OWNED" -eq 1 ]]; then
		if [[ -e "$PIN_PATH" || -L "$PIN_PATH" ]]; then
			unlink -- "$PIN_PATH" || cleanup_status=1
		fi
		if [[ -d "$PIN_ROOT" ]]; then
			rmdir -- "$PIN_ROOT" || cleanup_status=1
		fi
		if [[ "$cleanup_status" -eq 0 ]]; then
			PIN_ROOT_OWNED=0
		fi
	fi
	return "$cleanup_status"
}

exit_cleanup()
{
	local exit_status=$?

	trap - EXIT INT TERM
	set +e
	cleanup_owned_resources
	if [[ $? -ne 0 ]]; then
		exit_status=1
	fi
	exit "$exit_status"
}
trap exit_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_ready_file()
{
	local path="$1"
	local child_pid="$2"
	local attempts

	for ((attempts = 0; attempts < 200; attempts++)); do
		[[ -s "$path" ]] && return 0
		if ! kill -0 "$child_pid" 2>/dev/null; then
			echo "child $child_pid exited before publishing $path" >&2
			return 1
		fi
		sleep 0.05
	done
	echo "timed out waiting for rendezvous file $path" >&2
	return 1
}

cgroup_path_for_pid()
{
	local pid="$1"

	awk -F: '$1 == "0" && $2 == "" { print $3; found = 1 }
		END { if (!found) exit 1 }' "/proc/${pid}/cgroup"
}

[[ "$(stat -f -c %T /sys/fs/cgroup)" == "cgroup2fs" ]]
[[ "$(stat -f -c %T /sys/kernel/tracing)" == "tracefs" ]]
[[ "$(stat -f -c %T /sys/fs/bpf)" == "bpf_fs" ]]
[[ -r /sys/kernel/tracing/events/raw_syscalls/sys_enter/id ]]
[[ -r /sys/kernel/tracing/events/raw_syscalls/sys_exit/id ]]
[[ ! -e "$PIN_ROOT" && ! -L "$PIN_ROOT" ]] || {
	echo "refusing to reuse pre-existing fixture pin root: $PIN_ROOT" >&2
	exit 1
}
for path in "$TARGET_READY" "$TARGET_RELEASE" "$OUTSIDER_READY" \
	"$OUTSIDER_RELEASE"; do
	[[ ! -e "$path" && ! -L "$path" ]] || {
		echo "refusing to reuse rendezvous path: $path" >&2
		exit 1
	}
done

ulimit -l unlimited
mkdir -p "${BASE}/runs"

echo "E0 doctor"
"$BIN" doctor \
	--recorder-object "$OBJ" \
	--cgroup-root "$CGROUP_ROOT" \
	--output "${BASE}/doctor.json"
grep -q '"ready_for_runtime": true' "${BASE}/doctor.json"
if grep -q '"status": "FAIL"' "${BASE}/doctor.json"; then
	echo "doctor contains a failed prerequisite" >&2
	exit 1
fi

echo "E1 ephemeral Map and native transport"
"$BIN" observe \
	--scope "${BASE}/default-scope.json" \
	--recorder-object "$OBJ" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	--output-dir "${BASE}/runs/ephemeral" \
	--cgroup-root "$CGROUP_ROOT" \
	--run-id e2e-ephemeral \
	--run-epoch 1001 \
	--timeout-ms 10000 \
	--drain-timeout-ms 5000 \
	-- "$WORKLOAD" --ephemeral \
		--ready-file "$TARGET_READY" --release-file "$TARGET_RELEASE" \
	> "${BASE}/observe-ephemeral.json" \
	2> "${BASE}/observe-ephemeral.stderr" &
OBSERVE_PID=$!

# The target publishes readiness only after Observer has moved it into the
# exact run cgroup and exec'd it. Hold it there while a second copy performs
# real bpf() operations from the Guest script's parent cgroup.
wait_for_ready_file "$TARGET_READY" "$OBSERVE_PID"
TARGET_PID="$(< "$TARGET_READY")"
[[ "$TARGET_PID" =~ ^[1-9][0-9]*$ ]]
[[ "$TARGET_PID" != "$OBSERVE_PID" ]]
TARGET_CGROUP="$(cgroup_path_for_pid "$TARGET_PID")"
[[ "$TARGET_CGROUP" == "/bpf-state-observer/e2e-ephemeral" ]]

"$WORKLOAD" --ephemeral \
	--ready-file "$OUTSIDER_READY" --release-file "$OUTSIDER_RELEASE" \
	> "${BASE}/outsider.stdout" 2> "${BASE}/outsider.stderr" &
OUTSIDER_PID=$!
wait_for_ready_file "$OUTSIDER_READY" "$OUTSIDER_PID"
[[ "$(< "$OUTSIDER_READY")" == "$OUTSIDER_PID" ]]
OUTSIDER_CGROUP="$(cgroup_path_for_pid "$OUTSIDER_PID")"
PARENT_CGROUP="$(cgroup_path_for_pid "$$")"
[[ "$OUTSIDER_CGROUP" == "$PARENT_CGROUP" ]]
[[ "$OUTSIDER_CGROUP" != "$TARGET_CGROUP" ]]
touch -- "$OUTSIDER_RELEASE"
if ! wait "$OUTSIDER_PID"; then
	echo "out-of-cgroup negative-control workload failed" >&2
	exit 1
fi
# Keep the numeric PID for the structured no-leak assertion, but it is no
# longer a live child that cleanup is allowed to signal.
NEGATIVE_CONTROL_PID="$OUTSIDER_PID"
OUTSIDER_PID=""

touch -- "$TARGET_RELEASE"
if ! wait "$OBSERVE_PID"; then
	echo "managed ephemeral observation failed" >&2
	exit 1
fi
OBSERVE_PID=""
"$BIN" verify-run \
	--run-dir "${BASE}/runs/ephemeral" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	> "${BASE}/verify-ephemeral.json"
"$ASSERT_BIN" ephemeral "${BASE}/runs/ephemeral" "$NEGATIVE_CONTROL_PID"

grep -q '"workload_exit_code": 0' "${BASE}/observe-ephemeral.json"
grep -q '"events_verified": 6' "${BASE}/verify-ephemeral.json"
grep -q '"evidence_complete": true' "${BASE}/verify-ephemeral.json"
grep -q '"state_verdict": "INCONCLUSIVE"' "${BASE}/verify-ephemeral.json"
[[ ! -e "${CGROUP_ROOT}/e2e-ephemeral" ]]

echo "E2 pinned frozen HASH Map and state diff"
if ! mkdir -m 0700 -- "$PIN_ROOT"; then
	echo "could not atomically claim fixture pin root: $PIN_ROOT" >&2
	exit 1
fi
PIN_ROOT_OWNED=1
"$BIN" observe \
	--scope "${BASE}/vm-pinned-scope.json" \
	--recorder-object "$OBJ" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	--output-dir "${BASE}/runs/pinned" \
	--cgroup-root "$CGROUP_ROOT" \
	--run-id e2e-pinned \
	--run-epoch 1002 \
	--timeout-ms 10000 \
	--drain-timeout-ms 5000 \
	-- "$WORKLOAD" --freeze --pin "$PIN_PATH" \
	> "${BASE}/observe-pinned.json" \
	2> "${BASE}/observe-pinned.stderr"
"$BIN" verify-run \
	--run-dir "${BASE}/runs/pinned" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	> "${BASE}/verify-pinned.json"
"$ASSERT_BIN" pinned "${BASE}/runs/pinned"

grep -q '"workload_exit_code": 0' "${BASE}/observe-pinned.json"
grep -q '"events_verified": 10' "${BASE}/verify-pinned.json"
grep -q '"evidence_complete": true' "${BASE}/verify-pinned.json"
grep -q '"state_verdict": "CHANGED_WITHIN_SCOPE"' "${BASE}/verify-pinned.json"
[[ -e "$PIN_PATH" ]]
[[ ! -e "${CGROUP_ROOT}/e2e-pinned" ]]

echo "E3 trusted recorder policy rejection"
if "$BIN" verify-run \
	--run-dir "${BASE}/runs/pinned" \
	--expected-recorder-sha256 \
	0000000000000000000000000000000000000000000000000000000000000000 \
	> "${BASE}/wrong-digest.stdout" \
	2> "${BASE}/wrong-digest.stderr"; then
	echo "verify-run accepted an incorrect trusted recorder digest" >&2
	exit 1
fi

if ! cleanup_owned_resources; then
	echo "failed to remove owned fixture resources" >&2
	exit 1
fi
[[ ! -e "$PIN_ROOT" && ! -L "$PIN_ROOT" ]]

{
	echo "result=PASS"
	echo "kernel_release=$(uname -r)"
	echo "recorder_sha256=${RECORDER_SHA256}"
	echo "outsider_pid=${NEGATIVE_CONTROL_PID}"
	echo "ephemeral_events=6"
	echo "pinned_events=10"
} > "${BASE}/guest-e2e-status"

trap - EXIT INT TERM
echo "BPF_OBSERVER_GUEST_E2E_PASS"
