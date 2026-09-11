#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# This runner is entered only by vm/strict-init.c. It deliberately contains no
# systemd, SSH, network, provisioning, mount, chown, setcap, or poweroff path.
# PID1 establishes those invariants and releases this process only after both
# branches have irreversibly installed their capability contracts.
set -euo pipefail

readonly INPUT_ROOT=/opt/bpf-state-observer-exclusive-e2e
readonly EVIDENCE_ROOT=/evidence
readonly OUTPUT_ROOT="${EVIDENCE_ROOT}/results"
readonly STRICT_INIT="${INPUT_ROOT}/strict-init"
readonly BIN="${INPUT_ROOT}/bpf-state-observer"
readonly ASSERT_BIN="${INPUT_ROOT}/vm-e2e-assert"
readonly OUTSIDER_GATE_BIN="${INPUT_ROOT}/vm-outsider-gate-assert"
readonly OBJ="${INPUT_ROOT}/recorder.bpf.o"
readonly WORKLOAD="${INPUT_ROOT}/map-lifecycle"
readonly NOOP_WORKLOAD="${INPUT_ROOT}/exclusive-noop"
readonly EXCLUSIVE_SCOPE="${INPUT_ROOT}/exclusive-vm-scope.json"
readonly HARNESS_PUBLIC_KEY="${INPUT_ROOT}/harness-public.key"
readonly HARNESS_WRONG_PUBLIC_KEY="${INPUT_ROOT}/wrong-harness-public.key"
readonly HARNESS_CHANNEL_ALIAS=/dev/virtio-ports/org.allox.harness
readonly CGROUP_ROOT=/sys/fs/cgroup/bpf-state-observer
readonly EXCLUSIVE_PIN_ROOT=/sys/fs/bpf/bpf-state-observer-exclusive-e2e
readonly STRICT_INIT_STATUS="${EVIDENCE_ROOT}/supervisor/strict-init.status"
readonly CREDENTIAL_REPORT="${OUTPUT_ROOT}/runner-credentials.txt"
readonly PRECONDITION_REPORT="${OUTPUT_ROOT}/exclusive-clean-precondition.log"
readonly EXPECTED_RUNNER_BOUNDING=000000c000200000
readonly EXPECTED_PID1_CAPS=0000000000400000
readonly EXPECTED_LOCKED_SECUREBITS=ef
HARNESS_CHANNEL=""
OBSERVE_PID=""
MODULE_LOADING_STATE=""

require_sha256()
{
	local name="$1"
	local value="$2"

	[[ "$value" =~ ^[a-f0-9]{64}$ ]] || {
		echo "$name is not canonical lowercase SHA-256" >&2
		exit 2
	}
}

: "${BPF_OBSERVER_RECORDER_SHA256:?strict PID1 omitted recorder digest}"
: "${BPF_OBSERVER_HARNESS_POLICY_ID:?strict PID1 omitted policy ID}"
: "${BPF_OBSERVER_HARNESS_POLICY_SHA256:?strict PID1 omitted policy digest}"
: "${BPF_OBSERVER_HARNESS_KERNEL_IDENTITY:?strict PID1 omitted kernel identity}"
require_sha256 BPF_OBSERVER_RECORDER_SHA256 "$BPF_OBSERVER_RECORDER_SHA256"
require_sha256 BPF_OBSERVER_HARNESS_POLICY_SHA256 \
	"$BPF_OBSERVER_HARNESS_POLICY_SHA256"
[[ "$BPF_OBSERVER_HARNESS_POLICY_ID" != *[[:space:]]* ]]
[[ "$BPF_OBSERVER_HARNESS_KERNEL_IDENTITY" != *[[:space:]]* ]]

for path in "$STRICT_INIT" "$BIN" "$ASSERT_BIN" "$OUTSIDER_GATE_BIN" \
	"$OBJ" "$WORKLOAD" "$NOOP_WORKLOAD" "$EXCLUSIVE_SCOPE" \
	"$HARNESS_PUBLIC_KEY" "$HARNESS_WRONG_PUBLIC_KEY" \
	"$STRICT_INIT_STATUS"; do
	[[ -f "$path" && ! -L "$path" ]] || {
		echo "missing or unsafe strict Guest input: $path" >&2
		exit 2
	}
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

exit_cleanup()
{
	local exit_status=$?

	trap - EXIT INT TERM
	set +e
	stop_child "$OBSERVE_PID"
	exit "$exit_status"
}
trap exit_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

status_value()
{
	local field="$1"
	local status_path="$2"

	awk -v field="$field" '
		index($0, field "=") == 1 {
			if (found++) exit 2
			print substr($0, length(field) + 2)
		}
		END { if (found != 1) exit 1 }
	' "$status_path"
}

proc_status_value()
{
	local field="$1"
	local status_path="$2"

	awk -v field="$field" '$1 == field ":" {
		if (found++) exit 2
		print $2
	}
	END { if (found != 1) exit 1 }' "$status_path"
}

resolve_harness_channel()
{
	local attempts name_file port_name candidate resolved_alias sys_port
	local matching_device matches

	for ((attempts = 0; attempts < 200; attempts++)); do
		matching_device=""
		matches=0
		for name_file in /sys/class/virtio-ports/*/name; do
			[[ -f "$name_file" ]] || continue
			IFS= read -r port_name < "$name_file" || continue
			[[ "$port_name" == "org.allox.harness" ]] || continue
			matches=$((matches + 1))
			sys_port="${name_file%/name}"
			candidate="/dev/${sys_port##*/}"
			matching_device="$candidate"
		done
		if [[ "$matches" -gt 1 ]]; then
			echo "multiple virtio ports claim the harness name" >&2
			return 1
		fi
		if [[ "$matches" -eq 1 && -c "$matching_device" &&
			-r "$matching_device" && -w "$matching_device" ]]; then
			resolved_alias="$(readlink -f -- "$HARNESS_CHANNEL_ALIAS" 2>/dev/null || true)"
			if [[ -c "$HARNESS_CHANNEL_ALIAS" &&
				"$resolved_alias" == "$matching_device" ]]; then
				HARNESS_CHANNEL="$HARNESS_CHANNEL_ALIAS"
			else
				HARNESS_CHANNEL="$matching_device"
			fi
			return 0
		fi
		sleep 0.05
	done

	echo "authenticated virtio-serial harness channel is unavailable" >&2
	for name_file in /sys/class/virtio-ports/*/name; do
		[[ -f "$name_file" ]] || continue
		IFS= read -r port_name < "$name_file" || port_name="<unreadable>"
		echo "virtio port ${name_file}: ${port_name}" >&2
	done
	return 1
}

run_exclusive_fixture()
{
	local fixture="$1"
	local run_id="$2"
	local run_epoch="$3"
	local expected_events="$4"
	shift 4
	local run_dir="${OUTPUT_ROOT}/runs/${fixture}"

	[[ ! -e "$run_dir" && ! -L "$run_dir" ]] || {
		echo "refusing to reuse exclusive run directory: $run_dir" >&2
		return 1
	}
	"$BIN" observe \
		--scope "$EXCLUSIVE_SCOPE" \
		--recorder-object "$OBJ" \
		--expected-recorder-sha256 "$BPF_OBSERVER_RECORDER_SHA256" \
		--output-dir "$run_dir" \
		--cgroup-root "$CGROUP_ROOT" \
		--run-id "$run_id" \
		--run-epoch "$run_epoch" \
		--timeout-ms 10000 \
		--drain-timeout-ms 5000 \
		"${HARNESS_OBSERVE_OPTIONS[@]}" \
		-- "$@" \
		> "${OUTPUT_ROOT}/observe-${fixture}.json" \
		2> "${OUTPUT_ROOT}/observe-${fixture}.stderr"
	"$BIN" verify-run \
		--run-dir "$run_dir" \
		--expected-recorder-sha256 "$BPF_OBSERVER_RECORDER_SHA256" \
		"${HARNESS_VERIFY_OPTIONS[@]}" \
		> "${OUTPUT_ROOT}/verify-${fixture}.json"
	"$ASSERT_BIN" "$fixture" "$run_dir"

	grep -q '"workload_exit_code": 0' \
		"${OUTPUT_ROOT}/observe-${fixture}.json"
	grep -q "\"events_verified\": ${expected_events}" \
		"${OUTPUT_ROOT}/verify-${fixture}.json"
	grep -q '"evidence_complete": true' \
		"${OUTPUT_ROOT}/verify-${fixture}.json"
	grep -q '"harness_authenticated": true' \
		"${OUTPUT_ROOT}/verify-${fixture}.json"
	grep -q '"state_verdict": "UNCHANGED_WITHIN_SCOPE"' \
		"${OUTPUT_ROOT}/verify-${fixture}.json"
	[[ ! -e "${CGROUP_ROOT}/${run_id}" ]]
}

# This executable has no file capabilities. It checks securebits with prctl(2)
# as well as every capability set, which shell-visible /proc alone cannot do.
"$STRICT_INIT" --assert-runner-creds > "$CREDENTIAL_REPORT"
grep -qx 'runner_uid=65534' "$CREDENTIAL_REPORT"
grep -qx 'runner_gid=65534' "$CREDENTIAL_REPORT"
grep -qx 'runner_cap_effective=0000000000000000' "$CREDENTIAL_REPORT"
grep -qx 'runner_cap_permitted=0000000000000000' "$CREDENTIAL_REPORT"
grep -qx 'runner_cap_inheritable=0000000000000000' "$CREDENTIAL_REPORT"
grep -qx "runner_cap_bounding=${EXPECTED_RUNNER_BOUNDING}" "$CREDENTIAL_REPORT"
grep -qx 'runner_cap_ambient=0000000000000000' "$CREDENTIAL_REPORT"
grep -qx "runner_securebits=${EXPECTED_LOCKED_SECUREBITS}" "$CREDENTIAL_REPORT"
grep -qx 'runner_no_new_privs=0' "$CREDENTIAL_REPORT"

[[ "$(status_value strict_init_path "$STRICT_INIT_STATUS")" == "$STRICT_INIT" ]]
[[ "$(status_value pid1 "$STRICT_INIT_STATUS")" == 1 ]]
[[ "$(proc_status_value CapEff /proc/1/status)" == "$EXPECTED_PID1_CAPS" ]]
[[ "$(proc_status_value CapPrm /proc/1/status)" == "$EXPECTED_PID1_CAPS" ]]
[[ "$(proc_status_value CapBnd /proc/1/status)" == "$EXPECTED_PID1_CAPS" ]]
[[ "$(proc_status_value CapAmb /proc/1/status)" == 0000000000000000 ]]
[[ "$(proc_status_value NoNewPrivs /proc/1/status)" == 1 ]]
[[ "$(< /proc/self/cgroup)" == '0::/bpf-state-observer' ]]
[[ "$(status_value userspace_processes_before_runner "$STRICT_INIT_STATUS")" == 1 ]]
[[ "$(status_value initial_bpf_programs "$STRICT_INIT_STATUS")" == 0 ]]
[[ "$(status_value initial_bpf_maps "$STRICT_INIT_STATUS")" == 0 ]]
[[ "$(status_value initial_bpf_links "$STRICT_INIT_STATUS")" == 0 ]]
[[ "$(status_value initial_external_bpf_fds "$STRICT_INIT_STATUS")" == 0 ]]
[[ "$(status_value unprivileged_bpf_disabled "$STRICT_INIT_STATUS")" == 1 ]]
MODULE_LOADING_STATE="$(status_value module_loading "$STRICT_INIT_STATUS")"
case "$MODULE_LOADING_STATE" in
	DISABLED_IRREVERSIBLY_AND_HELPER_CLEARED)
		[[ "$(< /proc/sys/kernel/modules_disabled)" == 1 ]]
		[[ "$(< /proc/sys/kernel/modprobe)" == "" ]]
		[[ "$(status_value modprobe_helper "$STRICT_INIT_STATUS")" == EMPTY ]]
		;;
	MODULES_NOT_SUPPORTED)
		[[ ! -e /proc/sys/kernel/modules_disabled ]]
		[[ "$(status_value modprobe_helper "$STRICT_INIT_STATUS")" == NOT_SUPPORTED ]]
		;;
	*)
		echo "unknown strict module-loading state: $MODULE_LOADING_STATE" >&2
		exit 1
		;;
esac
[[ "$(status_value rlimit_core "$STRICT_INIT_STATUS")" == 0 ]]
[[ "$(ulimit -c)" == 0 ]]
[[ "$(status_value strict_root_block_read_only "$STRICT_INIT_STATUS")" == 1 ]]
[[ "$(status_value evidence_block_read_only "$STRICT_INIT_STATUS")" == 0 ]]
[[ "$(< /sys/block/vda/ro)" == 1 ]]
[[ "$(< /sys/block/vdb/ro)" == 0 ]]
[[ "$(status_value pid1_cap_effective "$STRICT_INIT_STATUS")" == "$EXPECTED_PID1_CAPS" ]]
[[ "$(status_value pid1_securebits "$STRICT_INIT_STATUS")" == "$EXPECTED_LOCKED_SECUREBITS" ]]
[[ "$(status_value harness_port_name "$STRICT_INIT_STATUS")" == org.allox.harness ]]
[[ "$(status_value harness_device_path "$STRICT_INIT_STATUS")" == /dev/vport* ]]
[[ "$(stat -c %u:%g:%a -- "$(status_value harness_device_path "$STRICT_INIT_STATUS")")" == 65534:65534:600 ]]
IFS=: read -r harness_major harness_minor < \
	"/sys/class/virtio-ports/$(basename -- "$(status_value harness_device_path "$STRICT_INIT_STATUS")")/dev"
[[ "$harness_major" == "$(status_value harness_device_major "$STRICT_INIT_STATUS")" ]]
[[ "$harness_minor" == "$(status_value harness_device_minor "$STRICT_INIT_STATUS")" ]]
[[ "$(< /proc/sys/kernel/unprivileged_bpf_disabled)" == 1 ]]

[[ "$(stat -f -c %T /sys/fs/cgroup)" == cgroup2fs ]]
[[ "$(stat -f -c %T /sys/kernel/tracing)" == tracefs ]]
[[ "$(stat -c %u:%g:%a -- /sys/kernel/tracing)" == 0:65534:550 ]]
[[ "$(stat -f -c %T /sys/fs/bpf)" == bpf_fs ]]
[[ "$(stat -f -c %T "$EVIDENCE_ROOT")" == ext2/ext3 ]]
[[ -r /sys/kernel/tracing/events/raw_syscalls/sys_enter/id ]]
[[ -r /sys/kernel/tracing/events/raw_syscalls/sys_exit/id ]]
[[ "$(stat -c %u:%g:%a -- "$CGROUP_ROOT")" == 65534:65534:755 ]]
[[ "$(stat -c %u:%g:%a -- "$EXCLUSIVE_PIN_ROOT")" == 65534:65534:700 ]]
[[ -z "$(ls -A -- "$EXCLUSIVE_PIN_ROOT")" ]]

# Strict QEMU supplies no NIC. The kernel-owned loopback interface is allowed;
# any additional interface means the Host did not launch the exclusive shape.
for network_path in /sys/class/net/*; do
	[[ -e "$network_path" ]] || continue
	[[ "${network_path##*/}" == lo ]] || {
		echo "strict boot unexpectedly exposes network interface $network_path" >&2
		exit 1
	}
done

resolve_harness_channel
HARNESS_OBSERVE_OPTIONS=(
	--harness-channel "$HARNESS_CHANNEL"
	--harness-public-key "$HARNESS_PUBLIC_KEY"
	--harness-policy-id "$BPF_OBSERVER_HARNESS_POLICY_ID"
	--expected-harness-policy-sha256 "$BPF_OBSERVER_HARNESS_POLICY_SHA256"
	--harness-kernel-identity "$BPF_OBSERVER_HARNESS_KERNEL_IDENTITY"
)
HARNESS_VERIFY_OPTIONS=(
	--harness-public-key "$HARNESS_PUBLIC_KEY"
	--harness-policy-id "$BPF_OBSERVER_HARNESS_POLICY_ID"
	--expected-harness-policy-sha256 "$BPF_OBSERVER_HARNESS_POLICY_SHA256"
	--harness-kernel-identity "$BPF_OBSERVER_HARNESS_KERNEL_IDENTITY"
)
HARNESS_WRONG_KEY_VERIFY_OPTIONS=(
	--harness-public-key "$HARNESS_WRONG_PUBLIC_KEY"
	--harness-policy-id "$BPF_OBSERVER_HARNESS_POLICY_ID"
	--expected-harness-policy-sha256 "$BPF_OBSERVER_HARNESS_POLICY_SHA256"
	--harness-kernel-identity "$BPF_OBSERVER_HARNESS_KERNEL_IDENTITY"
)

mkdir -- "${OUTPUT_ROOT}/runs"

echo "S0 strict credential and runtime doctor"
"$BIN" doctor \
	--recorder-object "$OBJ" \
	--cgroup-root "$CGROUP_ROOT" \
	--output "${OUTPUT_ROOT}/doctor.json"
grep -q '"ready_for_runtime": true' "${OUTPUT_ROOT}/doctor.json"
if grep -q '"status": "FAIL"' "${OUTPUT_ROOT}/doctor.json"; then
	echo "strict doctor contains a failed prerequisite" >&2
	exit 1
fi

{
	echo 'result=PASS'
	echo 'boot_shape=STATIC_MEASURED_PID1_NO_SYSTEMD_NO_SSH_NO_NIC'
	echo 'userspace_processes_before_runner=1'
	echo 'initial_bpf_programs=0'
	echo 'initial_bpf_maps=0'
	echo 'initial_bpf_links=0'
	echo 'initial_external_bpf_fds=0'
	echo 'unprivileged_bpf_disabled=1'
	echo "module_loading=${MODULE_LOADING_STATE}"
	echo 'rlimit_core=0'
	echo 'strict_root_block_read_only=1'
	echo 'evidence_block_read_only=0'
	echo 'runner_uid=65534'
	echo 'runner_effective_capabilities=0'
	echo 'runner_cgroup=/bpf-state-observer'
	echo "runner_bounding_capabilities=${EXPECTED_RUNNER_BOUNDING}"
	echo "pid1_effective_capabilities=${EXPECTED_PID1_CAPS}"
	echo "locked_securebits=${EXPECTED_LOCKED_SECUREBITS}"
	echo 'bpffs_initially_empty=true'
	echo 'non_loopback_network_interfaces=0'
} > "$PRECONDITION_REPORT"

echo "S1 outside-cgroup actor rejection gate"
"$OUTSIDER_GATE_BIN" "$OBJ" "$BPF_OBSERVER_RECORDER_SHA256" \
	"${OUTPUT_ROOT}/outside-actor-gate" \
	> "${OUTPUT_ROOT}/outside-actor-gate.log" 2>&1
grep -qx 'OUTSIDE_BPF_ACTOR_GATE_REJECTED_TRANSIENT_MAP' \
	"${OUTPUT_ROOT}/outside-actor-gate.log"
[[ -z "$(ls -A -- "$EXCLUSIVE_PIN_ROOT")" ]]

echo "S2 authenticated exclusive-vm-v1 no-op"
run_exclusive_fixture exclusive-noop e2e-exclusive-noop 1101 2 \
	"$NOOP_WORKLOAD" --exclusive-contract

echo "S3 authenticated exclusive-vm-v1 ephemeral Map"
run_exclusive_fixture exclusive-ephemeral e2e-exclusive-ephemeral 1102 6 \
	"$WORKLOAD" --ephemeral --exclusive-contract

echo "S4 authenticated exclusive-vm-v1 transient restore"
run_exclusive_fixture exclusive-restore e2e-exclusive-restore 1103 10 \
	"$WORKLOAD" --transient-restore --exclusive-contract

[[ -z "$(ls -A -- "$EXCLUSIVE_PIN_ROOT")" ]]

echo "S5 authenticated evidence fail-closed verification"
if "$BIN" verify-run \
	--run-dir "${OUTPUT_ROOT}/runs/exclusive-noop" \
	--expected-recorder-sha256 "$BPF_OBSERVER_RECORDER_SHA256" \
	> "${OUTPUT_ROOT}/exclusive-no-key.stdout" \
	2> "${OUTPUT_ROOT}/exclusive-no-key.stderr"; then
	echo "verify-run accepted authenticated evidence without a trusted key/policy" >&2
	exit 1
fi
if "$BIN" verify-run \
	--run-dir "${OUTPUT_ROOT}/runs/exclusive-noop" \
	--expected-recorder-sha256 "$BPF_OBSERVER_RECORDER_SHA256" \
	"${HARNESS_WRONG_KEY_VERIFY_OPTIONS[@]}" \
	> "${OUTPUT_ROOT}/exclusive-wrong-key.stdout" \
	2> "${OUTPUT_ROOT}/exclusive-wrong-key.stderr"; then
	echo "verify-run accepted authenticated evidence under the wrong public key" >&2
	exit 1
fi

readonly TAMPERED_RUN="${OUTPUT_ROOT}/tampered-exclusive-noop"
[[ ! -e "$TAMPERED_RUN" && ! -L "$TAMPERED_RUN" ]]
cp -a -- "${OUTPUT_ROOT}/runs/exclusive-noop" "$TAMPERED_RUN"
printf '\n' >> "${TAMPERED_RUN}/verdict.json"
if "$BIN" verify-run \
	--run-dir "$TAMPERED_RUN" \
	--expected-recorder-sha256 "$BPF_OBSERVER_RECORDER_SHA256" \
	"${HARNESS_VERIFY_OPTIONS[@]}" \
	> "${OUTPUT_ROOT}/exclusive-tampered.stdout" \
	2> "${OUTPUT_ROOT}/exclusive-tampered.stderr"; then
	echo "verify-run accepted a modified copy of authenticated evidence" >&2
	exit 1
fi

grep -Eq 'harness|authenticated|policy|key' \
	"${OUTPUT_ROOT}/exclusive-no-key.stderr"
grep -Eq 'signature|public key|fingerprint|harness' \
	"${OUTPUT_ROOT}/exclusive-wrong-key.stderr"
grep -Eq 'digest|size|artifact|manifest|changed' \
	"${OUTPUT_ROOT}/exclusive-tampered.stderr"

# This is the last privileged executable launched by the runner. Its exact
# file capability grants global enumeration, and the measured shell performs
# no further bpf() or privileged exec after proving all three inventories are
# empty. PID1 independently checks the process census and bpffs after exit.
echo "S6 final global Program/Map/Link inventory"
"$BIN" snapshot \
	--scope "$EXCLUSIVE_SCOPE" \
	--phase s1 \
	--output "${OUTPUT_ROOT}/final-global-inventory.json"
grep -qx '  "programs": \[\],' \
	"${OUTPUT_ROOT}/final-global-inventory.json"
grep -qx '  "maps": \[\],' \
	"${OUTPUT_ROOT}/final-global-inventory.json"
grep -qx '  "links": \[\],' \
	"${OUTPUT_ROOT}/final-global-inventory.json"
grep -q '"status": "COMPLETE"' \
	"${OUTPUT_ROOT}/final-global-inventory.json"
[[ -z "$(ls -A -- "$EXCLUSIVE_PIN_ROOT")" ]]
{
	echo 'schema_version=1'
	echo 'programs=0'
	echo 'maps=0'
	echo 'links=0'
	echo 'completeness=COMPLETE'
	echo 'result=PASS'
} > "${OUTPUT_ROOT}/final-global-inventory.status"
chmod 0444 "${OUTPUT_ROOT}/final-global-inventory.json" \
	"${OUTPUT_ROOT}/final-global-inventory.status"

{
	echo 'result=PASS'
	echo "kernel_release=$(uname -r)"
	echo "recorder_sha256=${BPF_OBSERVER_RECORDER_SHA256}"
	echo "harness_policy_id=${BPF_OBSERVER_HARNESS_POLICY_ID}"
	echo "harness_policy_sha256=${BPF_OBSERVER_HARNESS_POLICY_SHA256}"
	echo "harness_kernel_identity=${BPF_OBSERVER_HARNESS_KERNEL_IDENTITY}"
	echo "harness_channel=${HARNESS_CHANNEL}"
	echo 'strict_pid1=true'
	echo 'runner_uid=65534'
	echo 'runner_effective_capabilities=0'
	echo 'outside_actor_gate=REJECTED_TRANSIENT_MAP'
	echo 'final_global_programs=0'
	echo 'final_global_maps=0'
	echo 'final_global_links=0'
	echo 'exclusive_noop_events=2'
	echo 'exclusive_ephemeral_events=6'
	echo 'exclusive_restore_events=10'
} > "${OUTPUT_ROOT}/guest-e2e-status"
chmod 0444 "${OUTPUT_ROOT}/guest-e2e-status"

trap - EXIT INT TERM
echo "BPF_OBSERVER_STRICT_GUEST_E2E_PASS"
