#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# A/B/C recovery acceptance inside a disposable, privileged Linux Guest.
# Protocol v3 executes the measured recovery helper directly, outside the
# frozen target cgroup. Do not run this script on a durable host.

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
usage: guest-recovery-abc-e2e.sh DEPLOYMENT_OBSERVER RECOVERY_VERIFY EFFECT_OBJECT EFFECT_SHA256 LIFECYCLE_OBJECT LIFECYCLE_SHA256 STATE_WORKLOAD ENDPOINT_WORKLOAD BPF_WORKLOAD RECOVERY_HELPER TEST_MODULE NEW_EVIDENCE_ROOT
EOF
	exit 2
}

[[ $# -eq 12 && ${EUID} -eq 0 ]] || usage
observer=$1
verifier=$2
effect_object=$3
effect_sha256=$4
lifecycle_object=$5
lifecycle_sha256=$6
state_workload=$7
endpoint_workload=$8
bpf_workload=$9
recovery_helper=${10}
test_module=${11}
evidence_root=${12}
[[ $evidence_root == /* && ! -e $evidence_root && ! -L $evidence_root ]] || usage

for path in "$observer" "$verifier" "$state_workload" "$endpoint_workload" \
	"$bpf_workload" "$recovery_helper"; do
	[[ $path == /* && -f $path && -x $path && ! -L $path ]] || {
		echo "missing absolute fixture executable: $path" >&2
		exit 2
	}
done
for path in "$effect_object" "$lifecycle_object" "$test_module"; do
	[[ $path == /* && -f $path && ! -L $path ]] || {
		echo "missing absolute fixture input: $path" >&2
		exit 2
	}
done
for digest in "$effect_sha256" "$lifecycle_sha256"; do
	[[ $digest =~ ^[0-9a-f]{64}$ ]] || usage
done
[[ $(sha256sum "$effect_object" | awk '{print $1}') == "$effect_sha256" ]]
[[ $(sha256sum "$lifecycle_object" | awk '{print $1}') == "$lifecycle_sha256" ]]
for tool in /usr/sbin/ip /usr/sbin/tc /usr/sbin/nft /usr/sbin/insmod \
	/usr/sbin/rmmod /usr/bin/mount /usr/bin/umount /usr/bin/sleep; do
	[[ -x $tool ]] || { echo "missing Guest tool: $tool" >&2; exit 2; }
done
for command in awk findmnt grep mountpoint od readlink sha256sum stat tr; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing Guest command: $command" >&2
		exit 2
	}
done
[[ -s /sys/kernel/btf/vmlinux ]]
grep -qw bpf /sys/kernel/security/lsm
[[ $(stat -f -c %t /sys/fs/cgroup) == 63677270 ]]

trusted_tool()
{
	local resolved
	resolved=$(readlink -f -- "$1")
	[[ $resolved == /* && -f $resolved && -x $resolved && ! -L $resolved ]]
	[[ $(stat -Lc %u "$resolved") == 0 ]]
	[[ $(stat -Lc %h "$resolved") == 1 ]]
	(( ((8#$(stat -Lc %a "$resolved")) & 8#022) == 0 )) || return 1
	printf '%s\n' "$resolved"
}

ip_tool=$(trusted_tool /usr/sbin/ip)
tc_tool=$(trusted_tool /usr/sbin/tc)
nft_tool=$(trusted_tool /usr/sbin/nft)
ip_sha=$(sha256sum "$ip_tool" | awk '{print $1}')
tc_sha=$(sha256sum "$tc_tool" | awk '{print $1}')
nft_sha=$(sha256sum "$nft_tool" | awk '{print $1}')
helper_sha=$(sha256sum "$recovery_helper" | awk '{print $1}')
mount_ns=$(stat -Lc %i /proc/self/ns/mnt)
network_ns=$(stat -Lc %i /proc/self/ns/net)
limits='{"max_records":16384,"max_value_bytes":4194304,"max_total_value_bytes":16777216,"deadline_ms":15000}'
mkdir -m 0700 "$evidence_root"

hex_bytes()
{
	printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

require_fixed()
{
	local needle=$1
	local path=$2
	awk -v needle="$needle" '
		{ line=$0; gsub(/[[:space:]]/, "", line); if (index(line, needle)) found=1 }
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing expected evidence in $path: $needle" >&2
		exit 1
	}
}

json_string()
{
	local line=$1
	local key=$2
	local suffix
	suffix=${line#*\"$key\":\"}
	[[ $suffix != "$line" ]] || return 1
	printf '%s\n' "${suffix%%\"*}"
}

read_message()
{
	local expected=$1
	local destination=$2
	local line
	IFS= read -r -t 45 -u "$observer_out_fd" line || {
		echo "observer did not emit $expected" >&2
		exit 1
	}
	printf '%s\n' "$line" >"$destination"
	require_fixed "\"protocol_version\":3" "$destination"
	require_fixed "\"status\":\"$expected\"" "$destination"
	require_fixed "\"run_id\":\"$run_id\"" "$destination"
	require_fixed "\"checkpoint_id\":\"$checkpoint_id\"" "$destination"
	require_fixed "\"recovery_id\":\"$recovery_id\"" "$destination"
	if [[ $expected == READY || $expected == AGENT_STARTED || \
		$expected == SNAPSHOT_C ]]; then
		message_nonce=$(json_string "$line" nonce)
		[[ $message_nonce =~ ^[0-9a-f]{64}$ ]] || {
			echo "$expected contains an invalid nonce" >&2
			exit 1
		}
	fi
}

send_command()
{
	local name=$1
	local sequence=$2
	local nonce=$3
	printf '%s\n' "{\"protocol_version\":3,\"command\":\"$name\",\"run_id\":\"$run_id\",\"epoch\":1,\"checkpoint_id\":\"$checkpoint_id\",\"recovery_id\":\"$recovery_id\",\"command_seq\":$sequence,\"nonce\":\"$nonce\"}" >&"$observer_in_fd"
}

wait_frozen()
{
	local expected=$1
	local attempt
	for (( attempt=0; attempt<500; attempt++ )); do
		awk -v expected="$expected" '$1 == "frozen" && $2 == expected { found=1 }
			END { exit(found ? 0 : 1) }' "$cgroup_root/cgroup.events" && return 0
		sleep 0.01
	done
	echo "target cgroup did not reach frozen=$expected" >&2
	return 1
}

write_scopes()
{
	local bpf_scope=$case_dir/bpf-scope.json
	local filesystem_scope=$case_dir/filesystem-scope.json
	local linux_scope=$case_dir/linux-scope.json
	printf '%s\n' "{\"event_interfaces\":[\"BPF_USER_SYSCALL\"],\"allowed_bpf_commands\":[0,2,5,6,28],\"object_types\":[\"PROGRAM\",\"MAP\",\"LINK\"],\"map_content_types\":[\"HASH\"],\"map_ids\":[],\"bpffs_roots\":[\"$bpffs_root\"],\"attachment_targets\":[],\"budget\":{\"max_map_entries\":65536,\"max_map_bytes\":67108864,\"per_map_deadline_ms\":5000}}" >"$bpf_scope"
	printf '%s\n' "{\"protocol_version\":1,\"roots\":[{\"path_bytes_hex\":\"$(hex_bytes "$filesystem_root")\"}],\"capture\":{\"regular_file_content\":\"SHA256\",\"symlinks\":\"TARGET_BYTES\",\"xattrs\":\"NAMES_AND_VALUE_SHA256\",\"cross_filesystems\":\"SAME_DEVICE_ONLY\"},\"limits\":{\"max_entries\":16384,\"max_total_path_bytes\":16777216,\"max_file_content_bytes\":4194304,\"max_total_content_bytes\":67108864,\"max_xattr_list_bytes\":262144,\"max_xattrs_per_entry\":128,\"max_total_xattrs\":65536,\"max_xattr_value_bytes\":1048576,\"max_total_xattr_bytes\":16777216,\"max_symlink_target_bytes\":4096,\"max_depth\":64,\"deadline_ms\":30000}}" >"$filesystem_scope"
	printf '%s\n' "{\"protocol_version\":1,\"sysctl\":{\"proc_sys_root_bytes_hex\":\"$(hex_bytes /proc/sys)\",\"keys\":[\"net/ipv4/ip_forward\"],\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"mounts\":{\"namespace\":{\"pid\":0,\"expected_namespace_inode\":$mount_ns},\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"network\":{\"namespace\":{\"pid\":0,\"expected_namespace_inode\":$network_ns},\"collectors\":{\"addresses\":true,\"routes\":true,\"rules\":true,\"traffic_control\":true,\"nftables\":true},\"normalization\":\"NETWORK_CONFIGURATION_ONLY_V1\",\"ip_binary_bytes_hex\":\"$(hex_bytes "$ip_tool")\",\"expected_ip_sha256\":\"$ip_sha\",\"tc_binary_bytes_hex\":\"$(hex_bytes "$tc_tool")\",\"expected_tc_sha256\":\"$tc_sha\",\"nft_binary_bytes_hex\":\"$(hex_bytes "$nft_tool")\",\"expected_nft_sha256\":\"$nft_sha\",\"tc_interfaces\":[\"lo\"],\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"modules\":{\"proc_modules_path_bytes_hex\":\"$(hex_bytes /proc/modules)\",\"sys_module_root_bytes_hex\":\"$(hex_bytes /sys/module)\",\"selection\":{\"mode\":\"ALL_LOADED\"},\"capture_parameters\":false,\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"process_residual\":null}" >"$linux_scope"
}

cleanup_case()
{
	set +e
	if [[ -n ${observer_pid:-} ]]; then
		kill "$observer_pid" 2>/dev/null
		wait "$observer_pid" 2>/dev/null
		observer_pid=
	fi
	if [[ -d ${cgroup_root:-/nonexistent} ]]; then
		printf '1\n' >"$cgroup_root/cgroup.freeze" 2>/dev/null
		if [[ -d ${state_dir:-/nonexistent} ]]; then
			"$recovery_helper" "$checkpoint_id" full "$state_dir" \
				>"$case_dir/cleanup.stdout" 2>"$case_dir/cleanup.stderr"
		fi
		printf '0\n' >"$cgroup_root/cgroup.freeze" 2>/dev/null
	fi
	if [[ -n ${anchor_pid:-} ]]; then
		kill "$anchor_pid" 2>/dev/null
		wait "$anchor_pid" 2>/dev/null
		anchor_pid=
	fi
	if [[ -d ${residual_child:-/nonexistent} ]]; then
		printf '1\n' >"$residual_child/cgroup.kill" 2>/dev/null
		rmdir "$residual_child" 2>/dev/null
	fi
	if [[ -d ${cgroup_root:-/nonexistent} ]]; then
		printf '1\n' >"$cgroup_root/cgroup.kill" 2>/dev/null
		rmdir "$cgroup_root" 2>/dev/null
	fi
	if [[ -d ${filesystem_root:-/nonexistent} ]]; then
		rm -f -- "$filesystem_root/persistent-state" 2>/dev/null
		rmdir "$filesystem_root" 2>/dev/null
	fi
	set -e
}

run_case()
{
	local label=$1
	local mode=$2
	local expected_verdict=$3
	local ready_nonce pre_restore_nonce finish_nonce finished manifest_sha verdict_sha
	local filesystem_scope_json bpf_scope_json
	checkpoint_id=abc-$label
	recovery_id=recover-$label
	run_id=recovery-$label
	case_dir=$evidence_root/$label
	state_dir=$case_dir/state
	cgroup_root=/sys/fs/cgroup/bpf-observer-recovery-$checkpoint_id
	residual_child=$cgroup_root/residual-child
	filesystem_root=/tmp/bpf-observer-recovery-$checkpoint_id
	bpffs_root=/sys/fs/bpf/bpf-observer-recovery-$checkpoint_id
	output_dir=$case_dir/artifacts
	anchor_pid=
	observer_pid=
	mkdir -m 0700 "$case_dir" "$state_dir"
	[[ ! -e $cgroup_root && ! -e $filesystem_root && ! -e $bpffs_root ]]
	[[ ! -e /mnt/bpf-observer-expanded-e2e ]]
	! /usr/sbin/ip link show dev bpfobse2e0 >/dev/null 2>&1
	! /usr/sbin/nft list table inet bpf_observer_e2e >/dev/null 2>&1
	! grep -q '^bpf_observer_e2e_state ' /proc/modules
	mkdir -m 0700 "$filesystem_root" "$bpffs_root" "$cgroup_root"
	printf '%s\n' "$checkpoint_id" >"$state_dir/checkpoint-id"
	tr -d '\n' </proc/sys/net/ipv4/ip_forward >"$state_dir/ip-forward.before"
	printf '\n' >>"$state_dir/ip-forward.before"
	tr -d '\n' </proc/sys/kernel/random/boot_id >"$state_dir/boot-id"
	printf '\n' >>"$state_dir/boot-id"
	stat -Lc %i /proc/self/ns/mnt >"$state_dir/mount-ns-id"
	stat -Lc %i /proc/self/ns/net >"$state_dir/network-ns-id"
	write_scopes
	filesystem_scope_json=$(tr -d '\n' <"$case_dir/filesystem-scope.json")
	bpf_scope_json=$(tr -d '\n' <"$case_dir/bpf-scope.json")
	if [[ $mode == full ]]; then
		# Deleting a new file cannot restore its parent directory ctime.
		# This case makes no filesystem endpoint-consistency claim.
		filesystem_scope_json=null
	fi
	if [[ $label == full-linux || $label == leak-file || $label == protocol-abort ]]; then
		# Without an exclusive BPF actor contract, equal BPF endpoints do not
		# establish negative global BPF-state proof. These cases exercise the
		# Linux and filesystem verdicts without making that BPF claim.
		bpf_scope_json=null
	fi
	/usr/bin/sleep 300 &
	anchor_pid=$!
	printf '%s\n' "$anchor_pid" >"$cgroup_root/cgroup.procs"
	printf '1\n' >"$cgroup_root/cgroup.freeze"
	wait_frozen 1

	printf '%s\n' "{\"protocol_version\":3,\"deployment\":{\"deployment_kind\":\"DIRECT\",\"configuration\":{\"root_pid\":$anchor_pid,\"expected_cgroup_path\":\"/bpf-observer-recovery-$checkpoint_id\",\"require_dedicated_cgroup\":false,\"limits\":{\"max_proc_entries\":131072,\"max_cgroup_nodes\":4096,\"max_cgroup_depth\":64,\"max_open_fds_per_process\":8192}}},\"recorder_object_path\":\"$effect_object\",\"recorder_object_sha256\":\"$effect_sha256\",\"lifecycle_object_path\":\"$lifecycle_object\",\"lifecycle_object_sha256\":\"$lifecycle_sha256\",\"output_directory\":\"$output_dir\",\"run_id\":\"$run_id\",\"epoch\":1,\"profile\":\"full\",\"object_resolution_mode\":\"KERNEL_OBJECT_EXPANDED_PARTIAL\",\"bpf_state_scope\":$bpf_scope_json,\"filesystem_state_scope\":$filesystem_scope_json,\"linux_state_scope\":$(tr -d '\n' <"$case_dir/linux-scope.json"),\"poll_interval_ms\":20,\"drain_timeout_ms\":5000,\"recovery\":{\"checkpoint_id\":\"$checkpoint_id\",\"recovery_id\":\"$recovery_id\",\"executable_path\":\"$recovery_helper\",\"expected_sha256\":\"$helper_sha\",\"argv\":[\"$checkpoint_id\",\"$mode\",\"$state_dir\"],\"timeout_ms\":10000,\"max_output_bytes\":65536}}" >"$case_dir/config.json"
	coproc OBSERVER_PROCESS {
		"$observer" --config "$case_dir/config.json" 2>"$case_dir/observer.stderr"
	}
	observer_pid=$OBSERVER_PROCESS_PID
	observer_out_fd=${OBSERVER_PROCESS[0]}
	observer_in_fd=${OBSERVER_PROCESS[1]}
	read_message READY "$case_dir/ready.json"
	ready_nonce=$message_nonce
	[[ -s $output_dir/snapshot-a.json ]]
	if [[ $label == protocol-abort ]]; then
		# A wrong first command must not fabricate B/C or a finalized verdict.
		send_command PRE_RESTORE 2 "$ready_nonce"
		exec {observer_in_fd}>&-
		completed_observer_pid=$observer_pid
		observer_pid=
		if wait "$completed_observer_pid"; then
			echo "invalid recovery control command was accepted" >&2
			exit 1
		fi
		require_fixed '"status":"ABORTED_PARTIAL_EVIDENCE"' "$output_dir/recovery-abort.json"
		require_fixed '"verdict":"INCONCLUSIVE"' "$output_dir/recovery-abort.json"
		[[ ! -e $output_dir/snapshot-b.json && ! -e $output_dir/snapshot-c.json ]]
		[[ ! -e $output_dir/recovery-artifact-manifest.json ]]
		cleanup_case
		printf 'RECOVERY_ABC_CASE_PASS case=%s verdict=INCONCLUSIVE\n' "$label"
		return 0
	fi
	printf '0\n' >"$cgroup_root/cgroup.freeze"
	wait_frozen 0
	send_command AGENT_STARTED 1 "$ready_nonce"
	read_message AGENT_STARTED "$case_dir/agent-started.json"
	pre_restore_nonce=$message_nonce

	/bin/bash -e -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; exec "$2" "$3"' \
		_ "$cgroup_root" "$state_workload" "$test_module" \
		>"$case_dir/state-workload.stdout" 2>"$case_dir/state-workload.stderr"
	/bin/bash -e -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; exec "$2" "$3" "$4"' \
		_ "$cgroup_root" "$endpoint_workload" \
		"$filesystem_root/persistent-state" "$bpffs_root/persistent-map" \
		>"$case_dir/endpoint-workload.stdout" 2>"$case_dir/endpoint-workload.stderr"
	/bin/bash -e -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; exec "$2" "$3" "$4" "$5"' \
		_ "$cgroup_root" "$bpf_workload" "$cgroup_root" \
		"$bpffs_root/persistent-program" "$bpffs_root/persistent-link" \
		>"$case_dir/bpf-workload.stdout" 2>"$case_dir/bpf-workload.stderr"
	mkdir -m 0700 "$residual_child"
	/bin/bash -e -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; exec /usr/bin/sleep 300' \
		_ "$residual_child" </dev/null >/dev/null 2>&1 &
	residual_pid=$!
	for (( attempt=0; attempt<500; attempt++ )); do
		[[ -n $(<"$residual_child/cgroup.procs") ]] && break
		sleep 0.01
	done
	[[ -n $(<"$residual_child/cgroup.procs") ]]
	printf '1\n' >"$cgroup_root/cgroup.freeze"
	wait_frozen 1
	send_command PRE_RESTORE 2 "$pre_restore_nonce"
	read_message SNAPSHOT_B "$case_dir/snapshot-b-message.json"
	[[ -s $output_dir/snapshot-b.json ]]
	read_message RESTORE_COMPLETE "$case_dir/restore-complete.json"
	read_message SNAPSHOT_C "$case_dir/snapshot-c-message.json"
	finish_nonce=$message_nonce
	[[ -s $output_dir/snapshot-c.json ]]
	send_command FINISH 3 "$finish_nonce"
	exec {observer_in_fd}>&-
	read_message FINISHED "$case_dir/finished.json"
	finished=$(<"$case_dir/finished.json")
	manifest_sha=$(json_string "$finished" artifact_manifest_sha256)
	verdict_sha=$(json_string "$finished" verdict_sha256)
	[[ $manifest_sha =~ ^[0-9a-f]{64}$ ]]
	[[ $verdict_sha =~ ^[0-9a-f]{64}$ ]]
	completed_observer_pid=$observer_pid
	observer_pid=
	wait "$completed_observer_pid"
	require_fixed "\"verdict\":\"$expected_verdict\"" "$output_dir/recovery-verdict.json"
	if [[ $mode == fail-before ]]; then
		require_fixed '"success":false' "$output_dir/recovery.json"
		require_fixed '"exit_code":73' "$output_dir/recovery.json"
	else
		require_fixed '"success":true' "$output_dir/recovery.json"
	fi
	for phase in a b c; do
		[[ -s $output_dir/snapshot-$phase.json ]]
	done
	for phase in agent recovery residual; do
		[[ -s $output_dir/$phase-delta.json ]]
	done
	{
		printf '{"expected_config":'
		tr -d '\n' <"$case_dir/config.json"
		printf ',"expected_artifact_manifest_sha256":"%s"' "$manifest_sha"
		printf ',"expected_recovery_verdict_sha256":"%s"' "$verdict_sha"
		printf '}\n'
	} >"$case_dir/expectation.json"
	"$verifier" --artifacts "$output_dir" --expectation "$case_dir/expectation.json" \
		>"$case_dir/verify.json"
	require_fixed '"verified":true' "$case_dir/verify.json"
	cleanup_case
	printf 'RECOVERY_ABC_CASE_PASS case=%s verdict=%s\n' "$label" "$expected_verdict"
}

# The existing state workload uses fixed names. Cases are therefore strictly
# sequential; an unexpected preexisting object is an error, not cleanup input.
mkdir -p /sys/fs/bpf
[[ $(stat -f -c %t /sys/fs/bpf) == cafe4a11 ]] || {
	echo "Guest bpffs must already be mounted" >&2
	exit 2
}
trap cleanup_case EXIT
run_case full-linux full CONSISTENT_WITHIN_SCOPE
run_case full-bpf-limited full INCONCLUSIVE
run_case leak-file leave-file INCONSISTENT_WITHIN_SCOPE
run_case helper-fails fail-before INCONCLUSIVE
run_case protocol-abort full INCONCLUSIVE
trap - EXIT
printf 'RECOVERY_ABC_GUEST_E2E_PASS effect_sha256=%s lifecycle_sha256=%s helper_sha256=%s\n' \
	"$effect_sha256" "$lifecycle_sha256" "$helper_sha"
