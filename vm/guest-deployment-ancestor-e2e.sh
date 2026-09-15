#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Exercise the one-shot deployment adapter against a descendant cgroup which
# is created only after READY and removed before FINISH.  The target root stays
# frozen at both protocol barriers; the disposable-VM harness owns resume and
# cleanup between them.

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
usage: guest-deployment-ancestor-e2e.sh DEPLOYMENT_OBSERVER DEPLOYMENT_VERIFY EFFECT_OBJECT EFFECT_SHA256 LIFECYCLE_OBJECT LIFECYCLE_SHA256 OBJECT_WORKLOAD ENDPOINT_STATE_WORKLOAD LINUX_STATE_SCOPE EVIDENCE_ROOT
EOF
	exit 2
}

[[ $# -eq 10 ]] || usage
[[ ${EUID} -eq 0 ]] || { echo "deployment ancestor E2E requires Guest root" >&2; exit 2; }

deployment_observer=$1
deployment_verify=$2
effect_object=$3
effect_sha256=$4
lifecycle_object=$5
lifecycle_sha256=$6
object_workload=$7
endpoint_state_workload=$8
linux_state_scope_path=$9
evidence_root=${10}
scope_name=bpf-observer-deployment-dynamic
scope_path=/sys/fs/cgroup/$scope_name
scope_cgroup_path=/$scope_name
child_path=$scope_path/ephemeral-child
target_path=/tmp/bpf-observer-deployment-dynamic
filesystem_scope_root=/tmp/bpf-observer-deployment-state-scope
filesystem_marker=$filesystem_scope_root/persistent-state
bpffs_mount=/sys/fs/bpf
bpffs_scope_root=$bpffs_mount/bpf-observer-deployment-state
bpffs_pin=$bpffs_scope_root/persistent-map
output_dir=$evidence_root/deployment-ancestor
config=$evidence_root/deployment-ancestor.config.json
expectation=$evidence_root/deployment-ancestor.expectation.json
bpf_scope=$evidence_root/deployment-ancestor.bpf-scope.json
filesystem_scope=$evidence_root/deployment-ancestor.filesystem-scope.json
ready_file=$evidence_root/deployment-ancestor.ready.json
finished_file=$evidence_root/deployment-ancestor.finished.json
observer_stderr=$evidence_root/deployment-ancestor.stderr
workload_stdout=$evidence_root/deployment-ancestor.workload.stdout
workload_stderr=$evidence_root/deployment-ancestor.workload.stderr
verify_output=$evidence_root/deployment-ancestor.verify.json
anchor_pid=
deployment_pid=
completed_deployment_pid=
mounted_bpffs=0

for path in "$deployment_observer" "$deployment_verify" "$object_workload" \
	"$endpoint_state_workload"; do
	[[ $path == /* && -x $path && -f $path ]] || {
		echo "missing deployment E2E executable: $path" >&2
		exit 2
	}
done
[[ $linux_state_scope_path == /* && -f $linux_state_scope_path && \
	! -L $linux_state_scope_path ]] || {
	echo "missing deployment Linux-state scope: $linux_state_scope_path" >&2
	exit 2
}
for path in "$effect_object" "$lifecycle_object"; do
	[[ $path == /* && -f $path ]] || {
		echo "missing deployment E2E BPF object: $path" >&2
		exit 2
	}
done
for digest in "$effect_sha256" "$lifecycle_sha256"; do
	[[ $digest =~ ^[0-9a-f]{64}$ ]] || {
		echo "invalid deployment E2E object digest" >&2
		exit 2
	}
done
[[ $(sha256sum "$effect_object" | awk '{print $1}') == "$effect_sha256" ]]
[[ $(sha256sum "$lifecycle_object" | awk '{print $1}') == "$lifecycle_sha256" ]]
[[ $evidence_root == /* && -d $evidence_root && ! -L $evidence_root ]]
[[ ! -e $scope_path && ! -L $scope_path && ! -e $output_dir ]]
[[ ! -e $target_path && ! -L $target_path ]]
[[ ! -e $filesystem_scope_root && ! -L $filesystem_scope_root ]]
[[ ! -e $bpffs_scope_root && ! -L $bpffs_scope_root ]]

hex_bytes()
{
	printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

require_fixed()
{
	local needle=$1
	local path=$2
	grep -Fq -- "$needle" "$path" && return 0
	awk -v needle="$needle" '
		{
			line=$0
			gsub(/[[:space:]]/, "", line)
			if (index(line, needle)) {
				found=1
				exit
			}
		}
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing expected deployment evidence in $path: $needle" >&2
		exit 1
	}
}

require_async_producer_seal()
{
	local path=$1
	awk '
		{
			line=$0
			gsub(/[[:space:]]/, "", line)
			json=json line
		}
		END {
			marker="\"async_producer_seal\":{"
			start=index(json, marker)
			if (!start)
				exit 1
			object=substr(json, start + length(marker))
			end_pos=index(object, "}")
			if (!end_pos)
				exit 1
			object=substr(object, 1, end_pos - 1)
			exit(index(object, "\"complete\":true") &&
			     index(object, "\"links_expected\":2") &&
			     index(object, "\"links_detached\":2") ? 0 : 1)
		}
	' "$path" || {
		echo "invalid async_producer_seal object in $path" >&2
		exit 1
	}
}

require_linux_domain_complete()
{
	local key=$1
	local domain=$2
	local path=$3
	awk -v key="$key" -v domain="$domain" '
		{
			line=$0
			gsub(/[[:space:]]/, "", line)
			json=json line
		}
		END {
			marker="\"" key "\":{"
			start=index(json, marker)
			if (!start)
				exit 1
			object=substr(json, start + length(marker))
			completeness="\"state_completeness\":{"
			complete_pos=index(object, completeness)
			if (!complete_pos)
				exit 1
			prefix=substr(object, 1, complete_pos + length(completeness) - 1)
			state=substr(object, complete_pos + length(completeness))
			end_pos=index(state, "}")
			if (!end_pos)
				exit 1
			state=substr(state, 1, end_pos - 1)
			exit(index(prefix, "\"domain\":\"" domain "\"") &&
			     index(state, "\"status\":\"COMPLETE\"") &&
			     index(state, "\"reasons\":[]") ? 0 : 1)
		}
	' "$path" || {
		echo "Linux-state domain $key is not canonically COMPLETE in $path" >&2
		exit 1
	}
}

require_report_object_string()
{
	local object=$1
	local key=$2
	local value=$3
	local path=$4
	awk -v object="$object" -v key="$key" -v value="$value" '
		$0 == "  \"" object "\": {" { inside=1; next }
		inside && ($0 == "  }," || $0 == "  }") { exit }
		inside && ($0 == "    \"" key "\": \"" value "\"," ||
		           $0 == "    \"" key "\": \"" value "\"") {
			found=1
			exit
		}
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing $object.$key=$value in $path" >&2
		exit 1
	}
}

require_report_top_level_string()
{
	local key=$1
	local value=$2
	local path=$3
	awk -v key="$key" -v value="$value" '
		$0 == "  \"" key "\": \"" value "\"," ||
		$0 == "  \"" key "\": \"" value "\"" { found=1; exit }
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing top-level $key=$value in $path" >&2
		exit 1
	}
}

json_u64()
{
	local key=$1
	local path=$2
	awk -v marker="\"$key\"" '
		match($0, marker "[[:space:]]*:[[:space:]]*[0-9]+") {
			value=substr($0, RSTART, RLENGTH)
			sub(/^.*:/, "", value)
			gsub(/[[:space:]]/, "", value)
			print value
			found=1
			exit
		}
		END { if (!found) exit 1 }
	' "$path"
}

wait_frozen()
{
	local expected=$1
	local attempt
	for attempt in $(seq 1 500); do
		awk -v expected="$expected" '$1 == "frozen" && $2 == expected { found=1 }
			END { exit(found ? 0 : 1) }' "$scope_path/cgroup.events" && return 0
		sleep 0.01
	done
	echo "deployment root did not reach frozen=$expected" >&2
	return 1
}

cleanup()
{
	set +e
	if [[ -n $deployment_pid ]]; then
		kill "$deployment_pid" 2>/dev/null
		wait "$deployment_pid" 2>/dev/null
	fi
	if [[ -d $scope_path ]]; then
		printf '0\n' >"$scope_path/cgroup.freeze" 2>/dev/null
	fi
	if [[ -n $anchor_pid ]]; then
		kill "$anchor_pid" 2>/dev/null
		wait "$anchor_pid" 2>/dev/null
	fi
	if [[ -d $child_path ]]; then
		[[ -e $child_path/cgroup.kill ]] && printf '1\n' >"$child_path/cgroup.kill" 2>/dev/null
		rmdir "$child_path" 2>/dev/null
	fi
	if [[ -d $scope_path ]]; then
		[[ -e $scope_path/cgroup.kill ]] && printf '1\n' >"$scope_path/cgroup.kill" 2>/dev/null
		rmdir "$scope_path" 2>/dev/null
	fi
	rm -f -- "$bpffs_pin" "$filesystem_marker" 2>/dev/null
	rmdir "$bpffs_scope_root" "$filesystem_scope_root" 2>/dev/null
	if [[ $mounted_bpffs -eq 1 ]]; then
		umount "$bpffs_mount" 2>/dev/null
	fi
	rm -rf -- "$target_path" 2>/dev/null
}
trap cleanup EXIT

mkdir -p "$bpffs_mount"
if ! mountpoint -q "$bpffs_mount"; then
	mount -t bpf bpf "$bpffs_mount"
	mounted_bpffs=1
fi
[[ $(stat -f -c %t "$bpffs_mount") == cafe4a11 ]]
mkdir -m 0700 "$bpffs_scope_root" "$filesystem_scope_root"
printf '%s\n' "{\"event_interfaces\":[\"BPF_USER_SYSCALL\"],\"allowed_bpf_commands\":[0,2,6],\"object_types\":[\"MAP\"],\"map_content_types\":[\"HASH\"],\"map_ids\":[],\"bpffs_roots\":[\"$bpffs_scope_root\"],\"attachment_targets\":[],\"budget\":{\"max_map_entries\":65536,\"max_map_bytes\":67108864,\"per_map_deadline_ms\":5000}}" >"$bpf_scope"
printf '%s\n' "{\"protocol_version\":1,\"roots\":[{\"path_bytes_hex\":\"$(hex_bytes "$filesystem_scope_root")\"}],\"capture\":{\"regular_file_content\":\"SHA256\",\"symlinks\":\"TARGET_BYTES\",\"xattrs\":\"NAMES_AND_VALUE_SHA256\",\"cross_filesystems\":\"SAME_DEVICE_ONLY\"},\"limits\":{\"max_entries\":16384,\"max_total_path_bytes\":16777216,\"max_file_content_bytes\":4194304,\"max_total_content_bytes\":67108864,\"max_xattr_list_bytes\":262144,\"max_xattrs_per_entry\":128,\"max_total_xattrs\":65536,\"max_xattr_value_bytes\":1048576,\"max_total_xattr_bytes\":16777216,\"max_symlink_target_bytes\":4096,\"max_depth\":64,\"deadline_ms\":30000}}" >"$filesystem_scope"
bpf_scope_json=$(tr -d '\n' <"$bpf_scope")
filesystem_scope_json=$(tr -d '\n' <"$filesystem_scope")
linux_state_scope_json=$(tr -d '\n' <"$linux_state_scope_path")

mkdir -m 0755 "$scope_path"
/usr/bin/sleep 300 &
anchor_pid=$!
printf '%s\n' "$anchor_pid" >"$scope_path/cgroup.procs"
printf '1\n' >"$scope_path/cgroup.freeze"
wait_frozen 1

printf '%s\n' "{\"protocol_version\":2,\"deployment\":{\"deployment_kind\":\"DIRECT\",\"configuration\":{\"root_pid\":$anchor_pid,\"expected_cgroup_path\":\"$scope_cgroup_path\",\"require_dedicated_cgroup\":false,\"limits\":{\"max_proc_entries\":131072,\"max_cgroup_nodes\":4096,\"max_cgroup_depth\":64,\"max_open_fds_per_process\":8192}}},\"recorder_object_path\":\"$effect_object\",\"recorder_object_sha256\":\"$effect_sha256\",\"lifecycle_object_path\":\"$lifecycle_object\",\"lifecycle_object_sha256\":\"$lifecycle_sha256\",\"output_directory\":\"$output_dir\",\"run_id\":\"deployment-dynamic\",\"epoch\":1,\"profile\":\"full\",\"object_resolution_mode\":\"KERNEL_OBJECT_EXPANDED_PARTIAL\",\"bpf_state_scope\":$bpf_scope_json,\"filesystem_state_scope\":$filesystem_scope_json,\"linux_state_scope\":$linux_state_scope_json,\"poll_interval_ms\":20,\"drain_timeout_ms\":5000}" >"$config"

coproc DEPLOYMENT_PROCESS {
	"$deployment_observer" --config "$config" 2>"$observer_stderr"
}
deployment_pid=$DEPLOYMENT_PROCESS_PID
deployment_out_fd=${DEPLOYMENT_PROCESS[0]}
deployment_in_fd=${DEPLOYMENT_PROCESS[1]}
IFS= read -r -t 30 -u "$deployment_out_fd" ready || {
	echo "deployment observer did not emit READY" >&2
	exit 1
}
printf '%s\n' "$ready" >"$ready_file"
require_fixed '"status":"READY"' "$ready_file"
require_fixed '"mode":"CGROUP_V2_ANCESTOR_ROOT"' "$ready_file"
require_fixed '"dynamic_descendants_including_ephemeral":true' "$ready_file"
require_fixed '"leaf_cgroup_id_retained":false' "$ready_file"
require_fixed '"socket_state_enabled":true' "$ready_file"
for field in bpf_state_scope_sha256 bpf_state_s0_sha256 \
	filesystem_state_scope_sha256 filesystem_state_s0_sha256 \
	linux_state_scope_sha256 linux_state_s0_sha256; do
	require_fixed "\"$field\":\"" "$ready_file"
done
finish_nonce=${ready#*\"finish_nonce\":\"}
finish_nonce=${finish_nonce%%\"*}
[[ $finish_nonce =~ ^[0-9a-f]{64}$ ]] || {
	echo "deployment READY returned a noncanonical finish nonce" >&2
	exit 1
}

printf '0\n' >"$scope_path/cgroup.freeze"
wait_frozen 0
mkdir -m 0755 "$child_path"
/bin/bash -e -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; "$2" "$3"; "$4" "$5" "$6"' \
	_ "$child_path" "$object_workload" "$target_path" \
	"$endpoint_state_workload" "$filesystem_marker" "$bpffs_pin" \
	>"$workload_stdout" 2>"$workload_stderr"
[[ -z $(cat "$child_path/cgroup.procs") ]]
rmdir "$child_path"
[[ ! -e $child_path && ! -e $target_path ]]
[[ -f $filesystem_marker && -e $bpffs_pin ]]

printf '1\n' >"$scope_path/cgroup.freeze"
wait_frozen 1
printf '%s\n' "{\"protocol_version\":2,\"command\":\"FINISH\",\"run_id\":\"deployment-dynamic\",\"finish_nonce\":\"$finish_nonce\"}" \
	>&"$deployment_in_fd"
exec {deployment_in_fd}>&-
IFS= read -r -t 30 -u "$deployment_out_fd" finished || {
	echo "deployment observer did not emit FINISHED" >&2
	exit 1
}
printf '%s\n' "$finished" >"$finished_file"
completed_deployment_pid=$deployment_pid
deployment_pid=
wait "$completed_deployment_pid"
require_fixed '"status":"FINISHED"' "$finished_file"
require_fixed '"evidence_status":"INCOMPLETE"' "$finished_file"
report_sha=${finished#*\"report_sha256\":\"}
report_sha=${report_sha%%\"*}
manifest_sha=${finished#*\"artifact_manifest_sha256\":\"}
manifest_sha=${manifest_sha%%\"*}
[[ $report_sha =~ ^[0-9a-f]{64}$ && $manifest_sha =~ ^[0-9a-f]{64}$ ]]

report=$output_dir/deployment-observation-report.json
artifact_manifest=$output_dir/artifact-manifest.json
events=$output_dir/system-effects.jsonl
lifecycle=$output_dir/process-lifecycle.jsonl
require_fixed '"observation_boundary":"TARGET_LINUX_HOST_DIRECT_SYSCALLS_AND_DYNAMIC_CGROUP_ROOT_SUBTREES"' "$report"
require_fixed '"whole_tree_coverage_status":"DYNAMIC_ANCESTOR_COMPLETE"' "$report"
require_fixed '"transport_status":"COMPLETE"' "$report"
require_report_object_string aggregate_health evidence_status COMPLETE "$report"
require_report_top_level_string overall_evidence_status INCOMPLETE "$report"
require_report_object_string aggregate_lifecycle_health root_scope_status PARTIAL "$report"
require_fixed '"partial_cgroup_count":1' "$report"
require_fixed '"complete_cgroup_count":0' "$report"
require_fixed '"event_dropped":0' "$report"
for telemetry_file in "$report" "$artifact_manifest"; do
	require_fixed '"diagnostic_performance":{' "$telemetry_file"
	require_fixed '"purpose":"DIAGNOSTIC_ONLY_NOT_TRUSTED_EVIDENCE"' \
		"$telemetry_file"
	require_fixed '"clock":"RUST_STD_INSTANT_MONOTONIC_V1"' "$telemetry_file"
	require_fixed '"trusted_evidence":false' "$telemetry_file"
	require_fixed '"affects_verdict":false' "$telemetry_file"
	require_fixed '"s0_endpoint_capture":{' "$telemetry_file"
	require_fixed '"closing_drain":{' "$telemetry_file"
	require_fixed '"s1_endpoint_capture":{' "$telemetry_file"
	require_fixed '"system_effects_duration_ns":' "$telemetry_file"
	require_fixed '"process_lifecycle_duration_ns":' "$telemetry_file"
done
for path in "$output_dir/socket-state.raw.bin" \
	"$output_dir/socket-state.jsonl" \
	"$output_dir/socket-state.health.json"; do
	[[ -e $path && -f $path && ! -L $path ]] || {
		echo "missing deployment socket-state artifact: $path" >&2
		exit 1
	}
done
socket_health=$output_dir/socket-state.health.json
require_fixed '"status":"COMPLETE"' "$socket_health"
require_fixed '"event_dropped":0' "$socket_health"
require_fixed '"producer_barrier_complete":true' "$socket_health"
require_async_producer_seal "$socket_health"
require_fixed '"drain_completed":true' "$socket_health"
require_fixed '"wal_durable":true' "$socket_health"
require_fixed '"reasons":[]' "$socket_health"
require_fixed '"unsupported_sockets":0' "$socket_health"
socket_events=$(json_u64 events_persisted "$socket_health")
socket_published=$(json_u64 event_published "$socket_health")
[[ $socket_events -gt 0 && $socket_events -eq $socket_published ]]
[[ $(wc -l <"$output_dir/socket-state.jsonl") -eq $socket_events ]]
for kind in ACCEPT_SNAPSHOT TRANSITION DESTROY; do
	require_fixed "\"kind\":\"$kind\"" "$output_dir/socket-state.jsonl"
done
for operation in SOCKET_BIND SOCKET_CONNECT SOCKET_ACCEPT; do
	require_fixed "\"origin_operation\":\"$operation\"" \
		"$output_dir/socket-state.jsonl"
done
require_fixed '"cgroup_match_mode":"ANCESTOR_ROOT"' \
	"$output_dir/socket-state.jsonl"
require_fixed '"socket_state":{' "$report"
require_fixed '"socket_state_status":"COMPLETE"' \
	"$artifact_manifest"
require_fixed '"evidence_status":"INCOMPLETE"' \
	"$artifact_manifest"
committed_artifact_total_bytes=$(json_u64 committed_artifact_total_bytes \
	"$artifact_manifest")
[[ $committed_artifact_total_bytes -gt 0 ]]
for path in \
	"$output_dir/bpf-state-s0.json" \
	"$output_dir/bpf-state-s1.json" \
	"$output_dir/bpf-state-verdict.json" \
	"$output_dir/filesystem-state-s0.json" \
	"$output_dir/filesystem-state-s1.json" \
	"$output_dir/filesystem-state-comparison.json" \
	"$output_dir/linux-state-s0.json" \
	"$output_dir/linux-state-s1.json" \
	"$output_dir/linux-state-comparison.json"; do
	[[ -s $path ]] || { echo "missing deployment endpoint artifact: $path" >&2; exit 1; }
done
require_fixed '"state_verdict":"CHANGED_WITHIN_SCOPE"' \
	"$output_dir/bpf-state-verdict.json"
require_fixed '"verdict":"CHANGED_WITHIN_SCOPE"' \
	"$output_dir/filesystem-state-comparison.json"
require_fixed '"endpoint_difference":"OBSERVED_DIFFERENT"' \
	"$output_dir/filesystem-state-comparison.json"
for domain_spec in \
	'sysctl SYSCTL' \
	'mounts MOUNT' \
	'network NETWORK' \
	'modules KERNEL_MODULE' \
	'process_residual PROCESS_RESIDUAL'; do
	read -r domain_key domain_name <<<"$domain_spec"
	require_linux_domain_complete "$domain_key" "$domain_name" \
		"$output_dir/linux-state-comparison.json"
done
require_fixed '"terminal_state":"NON_EMPTY_WITHIN_SCOPE"' \
	"$output_dir/linux-state-comparison.json"
for domain in SYSCTL MOUNT NETWORK KERNEL_MODULE PROCESS_RESIDUAL; do
	require_fixed "\"domain\":\"$domain\"" \
		"$output_dir/linux-state-comparison.json"
done
require_report_top_level_string linux_state_evidence_status COMPLETE \
	"$artifact_manifest"
require_fixed '"causal_attribution_established":false' "$report"
require_fixed '"actor_contract_authenticated_by_observer":false' "$report"
require_fixed '"unchanged_verdict_authorized":false' "$report"
for operation in FILE_CREATE_OR_TRUNCATE FD_WRITE SOCKET_BIND SOCKET_CONNECT SOCKET_ACCEPT; do
	awk -v operation="\"operation\":\"$operation\"" '
		index($0, operation) &&
		index($0, "\"kind\":\"OPERATION_RESULT\"") &&
		index($0, "\"cgroup_match_mode\":\"ANCESTOR_ROOT\"") &&
		index($0, "\"leaf_cgroup_id_retained\":false") &&
		index($0, "\"cgroup_id_at_syscall_entry\":0") { found=1 }
		END { exit(found ? 0 : 1) }
	' "$events" || {
		echo "missing dynamic ancestor system-effect evidence for $operation" >&2
		exit 1
	}
done
for kind in FORK EXEC EXIT; do
	awk -v kind="\"kind\":\"$kind\"" '
		index($0, kind) &&
		index($0, "\"cgroup_match_mode\":\"ANCESTOR_ROOT\"") &&
		index($0, "\"cgroup_id_semantics\":\"MATCHED_SCOPE_ROOT_AT_LIFECYCLE_HOOK\"") &&
		index($0, "\"leaf_cgroup_id_retained\":false") { found=1 }
		END { exit(found ? 0 : 1) }
	' "$lifecycle" || {
		echo "missing dynamic ancestor lifecycle evidence for $kind" >&2
		exit 1
	}
done

{
	printf '{"expected_config":'
	tr -d '\n' <"$config"
	printf ',"expected_artifact_manifest_sha256":"%s","expected_report_sha256":"%s"}\n' \
		"$manifest_sha" "$report_sha"
} >"$expectation"
"$deployment_verify" --artifacts "$output_dir" --expectation "$expectation" \
	>"$verify_output"
require_fixed '"verified":true' "$verify_output"
require_fixed '"evidence_status":"INCOMPLETE"' "$verify_output"
require_fixed '"socket_state_status":"COMPLETE"' "$verify_output"
require_fixed "\"socket_state_event_count\":$socket_events" "$verify_output"
require_fixed '"bpf_state_verdict":"CHANGED_WITHIN_SCOPE"' "$verify_output"
require_fixed '"filesystem_state_verdict":"CHANGED_WITHIN_SCOPE"' "$verify_output"
require_report_top_level_string linux_state_evidence_status COMPLETE "$verify_output"
require_fixed "\"committed_artifact_total_bytes\":$committed_artifact_total_bytes" \
	"$verify_output"

rm -f -- "$bpffs_pin" "$filesystem_marker"
rmdir "$bpffs_scope_root" "$filesystem_scope_root"
if [[ $mounted_bpffs -eq 1 ]]; then
	umount "$bpffs_mount"
	mounted_bpffs=0
fi

printf '0\n' >"$scope_path/cgroup.freeze"
wait_frozen 0
kill "$anchor_pid"
wait "$anchor_pid" 2>/dev/null || true
anchor_pid=
rmdir "$scope_path"
trap - EXIT

printf 'DEPLOYMENT_ANCESTOR_VM_E2E_PASS effect_sha256=%s lifecycle_sha256=%s\n' \
	"$effect_sha256" "$lifecycle_sha256"
