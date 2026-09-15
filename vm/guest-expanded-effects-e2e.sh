#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Privileged disposable-Guest acceptance for expanded kernel objects, process
# lifecycle evidence, and Linux endpoint-state confirmation.  This mutates the
# Guest deliberately; the Host runner must use a throw-away disk snapshot.

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
	usage: guest-expanded-effects-e2e.sh OBSERVER EFFECT_OBJECT EFFECT_SHA256 LIFECYCLE_OBJECT LIFECYCLE_SHA256 OBJECT_WORKLOAD STATE_WORKLOAD RESIDUAL_WORKLOAD STATE_MODULE OVERHEAD_WORKLOAD MEASURE_COMMAND DEPLOYMENT_OBSERVER DEPLOYMENT_VERIFY DEPLOYMENT_DIRECT_RUNNER DEPLOYMENT_SYNTHETIC_RUNNER DEPLOYMENT_LIVE_FIXTURE DEPLOYMENT_ENDPOINT_WORKLOAD EVIDENCE_ROOT
EOF
	exit 2
}

[[ $# -eq 18 ]] || usage
[[ ${EUID} -eq 0 ]] || { echo "expanded E2E requires Guest root" >&2; exit 2; }

observer=$1
effect_object=$2
effect_sha256=$3
lifecycle_object=$4
lifecycle_sha256=$5
object_workload=$6
state_workload=$7
residual_workload=$8
state_module=$9
overhead_workload=${10}
measure_command=${11}
deployment_observer=${12}
deployment_verify=${13}
deployment_direct_runner=${14}
deployment_synthetic_runner=${15}
deployment_live_fixture=${16}
deployment_endpoint_workload=${17}
evidence_root=${18}
cgroup_root=/sys/fs/cgroup/bpf-observer-expanded-e2e
object_mode=kernel-object-expanded-partial

for path in "$observer" "$object_workload" "$overhead_workload" \
	"$measure_command" "$deployment_observer" "$deployment_verify" \
	"$deployment_direct_runner" "$deployment_synthetic_runner" \
	"$deployment_live_fixture" "$deployment_endpoint_workload"; do
	[[ $path == /* && -x $path && -f $path ]] || {
		echo "required executable is unavailable: $path" >&2
		exit 2
	}
done
for path in "$effect_object" "$lifecycle_object" "$state_workload" \
	"$residual_workload" "$state_module"; do
	[[ $path == /* && -f $path ]] || {
		echo "required input is unavailable: $path" >&2
		exit 2
	}
done
for digest in "$effect_sha256" "$lifecycle_sha256"; do
	[[ $digest =~ ^[0-9a-f]{64}$ ]] || {
		echo "noncanonical object digest: $digest" >&2
		exit 2
	}
done
[[ $(sha256sum "$effect_object" | awk '{print $1}') == "$effect_sha256" ]]
[[ $(sha256sum "$lifecycle_object" | awk '{print $1}') == "$lifecycle_sha256" ]]
[[ $evidence_root == /* && ! -e $evidence_root && ! -L $evidence_root ]] || {
	echo "EVIDENCE_ROOT must be a new absolute path" >&2
	exit 2
}
[[ ! -e $cgroup_root ]] || {
	echo "dedicated expanded-E2E cgroup root already exists" >&2
	exit 2
}

for command in awk grep mountpoint od readlink sha256sum stat tr wc; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing Guest command: $command" >&2
		exit 2
	}
done
for command in /usr/sbin/ip /usr/sbin/tc /usr/sbin/nft /usr/sbin/insmod \
	/usr/bin/mount /usr/bin/setsid /usr/bin/sleep; do
	[[ -x $command ]] || { echo "missing Guest command: $command" >&2; exit 2; }
done
[[ -s /sys/kernel/btf/vmlinux ]]
grep -qw bpf /sys/kernel/security/lsm
[[ $(stat -f -c %t /sys/fs/cgroup) == 63677270 ]]

trusted_tool()
{
	local requested=$1
	local resolved
	resolved=$(readlink -f "$requested")
	[[ $resolved == /* && -f $resolved && -x $resolved && ! -L $resolved ]]
	[[ $(stat -Lc %h "$resolved") == 1 ]]
	[[ $(stat -Lc %u "$resolved") == 0 ]]
	(( (8#$(stat -Lc %a "$resolved")) & 8#022 == 0 ))
	printf '%s\n' "$resolved"
}

ip_tool=$(trusted_tool /usr/sbin/ip)
tc_tool=$(trusted_tool /usr/sbin/tc)
nft_tool=$(trusted_tool /usr/sbin/nft)
ip_sha=$(sha256sum "$ip_tool" | awk '{print $1}')
tc_sha=$(sha256sum "$tc_tool" | awk '{print $1}')
nft_sha=$(sha256sum "$nft_tool" | awk '{print $1}')
mnt_ns=$(stat -Lc %i /proc/self/ns/mnt)
net_ns=$(stat -Lc %i /proc/self/ns/net)

hex_bytes()
{
	printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

limits='{"max_records":16384,"max_value_bytes":4194304,"max_total_value_bytes":16777216,"deadline_ms":15000}'
write_full_scope()
{
	local output=$1
	printf '%s\n' "{\"protocol_version\":1,\"sysctl\":{\"proc_sys_root_bytes_hex\":\"$(hex_bytes /proc/sys)\",\"keys\":[\"net/ipv4/ip_forward\"],\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"mounts\":{\"namespace\":{\"pid\":0,\"expected_namespace_inode\":$mnt_ns},\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"network\":{\"namespace\":{\"pid\":0,\"expected_namespace_inode\":$net_ns},\"collectors\":{\"addresses\":true,\"routes\":true,\"rules\":true,\"traffic_control\":true,\"nftables\":true},\"normalization\":\"NETWORK_CONFIGURATION_ONLY_V1\",\"ip_binary_bytes_hex\":\"$(hex_bytes "$ip_tool")\",\"expected_ip_sha256\":\"$ip_sha\",\"tc_binary_bytes_hex\":\"$(hex_bytes "$tc_tool")\",\"expected_tc_sha256\":\"$tc_sha\",\"nft_binary_bytes_hex\":\"$(hex_bytes "$nft_tool")\",\"expected_nft_sha256\":\"$nft_sha\",\"tc_interfaces\":[\"lo\"],\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"modules\":{\"proc_modules_path_bytes_hex\":\"$(hex_bytes /proc/modules)\",\"sys_module_root_bytes_hex\":\"$(hex_bytes /sys/module)\",\"selection\":{\"mode\":\"ALL_LOADED\"},\"capture_parameters\":false,\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"process_residual\":null}" >"$output"
}

write_incomplete_scope()
{
	local output=$1
	printf '%s\n' "{\"protocol_version\":1,\"sysctl\":{\"proc_sys_root_bytes_hex\":\"$(hex_bytes /proc/sys)\",\"keys\":[\"does/not/exist\",\"net/ipv4/ip_forward\"],\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$limits},\"mounts\":null,\"network\":null,\"modules\":null,\"process_residual\":null}" >"$output"
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
		echo "missing expected evidence in $path: $needle" >&2
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

count_fixed()
{
	local needle=$1
	local path=$2
	awk -v needle="$needle" '
		{
			line=$0
			gsub(/[[:space:]]/, "", line)
			if (index(line, needle))
				count++
		}
		END { print count + 0 }
	' "$path"
}

require_kernel_object()
{
	local operation=$1
	local identity_kind=$2
	local role=$3
	local path=$4
	awk -v operation="\"operation\":\"$operation\"" \
		-v identity="\"kind\":\"$identity_kind\"" \
		-v role="\"role\":\"$role\"" '
		index($0, operation) &&
		index($0, "\"kind\":\"OPERATION_RESULT\"") &&
		index($0, "\"quality\":\"KERNEL_RESOLVED\"") &&
		index($0, identity) && index($0, role) { found=1 }
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing resolved $operation/$identity_kind/$role evidence" >&2
		exit 1
	}
}

require_kernel_object_syscall()
{
	local syscall_name=$1
	local path=$2
	awk -v syscall="\"syscall_name\":\"$syscall_name\"" '
		index($0, syscall) &&
		index($0, "\"operation\":\"HARD_LINK_CREATE\"") &&
		index($0, "\"kind\":\"OPERATION_RESULT\"") &&
		index($0, "\"quality\":\"KERNEL_RESOLVED\"") &&
		index($0, "\"kind\":\"FILE_OBJECT\"") &&
		index($0, "\"role\":\"SOURCE\"") { found=1 }
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing resolved HARD_LINK_CREATE/FILE_OBJECT/SOURCE evidence for $syscall_name" >&2
		exit 1
	}
}

require_kernel_object_for_syscall()
{
	local syscall_name=$1
	local operation=$2
	local identity_kind=$3
	local role=$4
	local path=$5
	awk -v syscall="\"syscall_name\":\"$syscall_name\"" \
		-v operation="\"operation\":\"$operation\"" \
		-v identity="\"kind\":\"$identity_kind\"" \
		-v role="\"role\":\"$role\"" '
		index($0, syscall) && index($0, operation) &&
		index($0, "\"kind\":\"OPERATION_RESULT\"") &&
		index($0, "\"quality\":\"KERNEL_RESOLVED\"") &&
		index($0, identity) && index($0, role) { found=1 }
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing resolved $syscall_name/$operation/$identity_kind/$role evidence" >&2
		exit 1
	}
}

require_unlinkat_flag()
{
	local expected_flag=$1
	local path=$2
	awk -v expected="$expected_flag" '
		index($0, "\"syscall_name\":\"unlinkat\"") &&
		index($0, "\"operation\":\"PATH_ENTRY_REMOVE\"") &&
		index($0, "\"kind\":\"OPERATION_RESULT\"") {
			split($0, suffix, "\"raw_arguments\":\\[")
			split(suffix[2], argument, ",")
			if (argument[3] == expected)
				found=1
		}
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing generic PATH_ENTRY_REMOVE unlinkat result for flags=$expected_flag" >&2
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

require_same_file_identity()
{
	local syscall_name=$1
	local operation=$2
	local identity_kind=$3
	local role=$4
	local require_mount=$5
	local mount_id=$6
	local device_major=$7
	local device_minor=$8
	local inode=$9
	local path=${10}
	local resolved_path=${11:-}
	if [[ -n $resolved_path ]]; then
		resolved_path="\"display\":\"$resolved_path\""
	fi
	awk -v syscall="\"syscall_name\":\"$syscall_name\"" \
		-v operation="\"operation\":\"$operation\"" \
		-v identity="\"kind\":\"$identity_kind\"" \
		-v role="\"role\":\"$role\"" \
		-v mount_id="\"mount_id_unique\":$mount_id" \
		-v major="\"device_major\":$device_major" \
		-v minor="\"device_minor\":$device_minor" \
		-v inode="\"inode\":$inode" -v require_mount="$require_mount" \
		-v resolved_path="$resolved_path" '
		index($0, syscall) && index($0, operation) &&
		index($0, "\"kind\":\"OPERATION_RESULT\"") &&
		index($0, "\"quality\":\"KERNEL_RESOLVED\"") &&
		index($0, identity) && index($0, role) &&
		index($0, major) && index($0, minor) && index($0, inode) &&
		(!require_mount || index($0, mount_id)) &&
		(resolved_path == "" || index($0, resolved_path)) { found=1 }
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing ground-truth file identity for $syscall_name/$operation" >&2
		exit 1
	}
}

require_socket_result_truth()
{
	local operation=$1
	local role=$2
	local cookie=$3
	local port=$4
	local path=$5
	awk -v operation="\"operation\":\"$operation\"" \
		-v role="\"role\":\"$role\"" \
		-v cookie="\"socket_cookie\":$cookie" \
		-v port="\"port\":$port" '
		index($0, operation) && index($0, "\"kind\":\"OPERATION_RESULT\"") &&
		index($0, "\"quality\":\"KERNEL_RESOLVED\"") &&
		index($0, "\"kind\":\"SOCKET_OBJECT\"") && index($0, role) &&
		index($0, cookie) && index($0, port) { found=1 }
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing ground-truth socket result for $operation" >&2
		exit 1
	}
}

require_socket_state_truth()
{
	local operation=$1
	local cookie=$2
	local first_port=$3
	local second_port=$4
	local path=$5
	awk -v operation="\"origin_operation\":\"$operation\"" \
		-v cookie="\"socket_cookie\":$cookie" \
		-v first_port="\"port\":$first_port" \
		-v second_port="\"port\":$second_port" '
		index($0, operation) && index($0, cookie) && index($0, first_port) &&
		(second_port == "\"port\":0" || index($0, second_port)) { found=1 }
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing ground-truth socket-state evidence for $operation" >&2
		exit 1
	}
}

require_effect_health()
{
	local run_dir=$1
	local health=$run_dir/system-effects.health.json
	local dropped persisted published
	require_fixed '"transport_status":"COMPLETE"' "$health"
	require_fixed '"producer_barrier_complete":true' "$health"
	require_fixed '"drain_completed":true' "$health"
	require_fixed '"wal_durable":true' "$health"
	dropped=$(json_u64 event_dropped "$health")
	persisted=$(json_u64 events_persisted "$health")
	published=$(json_u64 event_published "$health")
	[[ $dropped -eq 0 && $persisted -eq $published ]] || {
		echo "lossy system-effect health in $run_dir" >&2
		exit 1
	}
	printf '%s\n' "$persisted"
}

require_lifecycle_health()
{
	local run_dir=$1
	local health=$run_dir/process-lifecycle.health.json
	local dropped persisted published
	require_fixed '"status":"PARTIAL"' "$health"
	require_fixed '"initial_task_ledger_present":false' "$health"
	require_fixed '"migration_hook_present":false' "$health"
	require_fixed '"clone_into_cgroup_covered":false' "$health"
	require_fixed '"complete":false' "$health"
	require_fixed '"producer_barrier_complete":true' "$health"
	require_fixed '"drain_completed":true' "$health"
	require_fixed '"wal_durable":true' "$health"
	dropped=$(json_u64 event_dropped "$health")
	persisted=$(json_u64 events_persisted "$health")
	published=$(json_u64 event_published "$health")
	[[ $dropped -eq 0 && $persisted -eq $published && $persisted -gt 0 ]] || {
		echo "lossy or empty process-lifecycle health in $run_dir" >&2
		exit 1
	}
	printf '%s\n' "$persisted"
}

require_socket_state_health()
{
	local run_dir=$1
	local minimum_events=${2:-0}
	local health=$run_dir/socket-state.health.json
	local dropped persisted published
	for path in "$run_dir/socket-state.raw.bin" \
		"$run_dir/socket-state.jsonl" "$health"; do
		[[ -e $path && -f $path && ! -L $path ]] || {
			echo "missing socket-state artifact: $path" >&2
			exit 1
		}
	done
	require_fixed '"status":"COMPLETE"' "$health"
	require_fixed '"producer_barrier_complete":true' "$health"
	require_async_producer_seal "$health"
	require_fixed '"drain_completed":true' "$health"
	require_fixed '"wal_durable":true' "$health"
	require_fixed '"reasons":[]' "$health"
	dropped=$(json_u64 event_dropped "$health")
	persisted=$(json_u64 events_persisted "$health")
	published=$(json_u64 event_published "$health")
	[[ $dropped -eq 0 && $persisted -eq $published && \
		$persisted -ge $minimum_events ]] || {
		echo "lossy or undersized socket-state evidence in $run_dir" >&2
		exit 1
	}
	printf '%s\n' "$persisted"
}

count_successful_netlink_socket_results()
{
	local events=$1
	awk '
		index($0, "\"kind\":\"OPERATION_RESULT\"") &&
		index($0, "\"result_status\":\"RETURNED_SUCCESS\"") &&
		(index($0, "\"operation\":\"SOCKET_BIND\"") ||
		 index($0, "\"operation\":\"SOCKET_CONNECT\"") ||
		 index($0, "\"operation\":\"SOCKET_ACCEPT\"")) &&
		index($0, "\"kind\":\"SOCKET_OBJECT\"") &&
		index($0, "\"address_family\":16") { count++ }
		END { print count + 0 }
	' "$events"
}

verify_run()
{
	local run_dir=$1
	local scope=$2
	"$observer" verify-effects \
		--run-dir "$run_dir" \
		--expected-recorder-sha256 "$effect_sha256" \
		--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
		--expected-profile full \
		--expected-object-resolution "$object_mode" \
		--expected-linux-state-scope "$scope" \
		--confirm-process-residual
}

mkdir -m 0700 "$evidence_root"
full_scope=$evidence_root/linux-state-scope.json
incomplete_scope=$evidence_root/linux-state-incomplete-scope.json
write_full_scope "$full_scope"
write_incomplete_scope "$incomplete_scope"

# This preflight is advisory; successful real load/attach in every run below
# remains the definitive BPF capability gate.
"$observer" doctor --recorder-object "$effect_object" \
	--process-lifecycle-object "$lifecycle_object" \
	--cgroup-root /sys/fs/cgroup --object-resolution "$object_mode" \
	--output "$evidence_root/doctor.json"
require_fixed '"ready_for_runtime":true' "$evidence_root/doctor.json"

object_run=$evidence_root/run-object-restored
"$observer" observe-effects \
	--recorder-object "$effect_object" \
	--expected-recorder-sha256 "$effect_sha256" \
	--process-lifecycle-object "$lifecycle_object" \
	--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
	--output-dir "$object_run" --cgroup-root "$cgroup_root" \
	--run-id expanded-object --run-epoch 1 --profile full \
	--timeout-ms 30000 --drain-timeout-ms 5000 \
	--object-resolution "$object_mode" \
	--linux-state-scope "$full_scope" --confirm-process-residual \
	-- "$object_workload" /tmp/bpf-observer-object-v2 \
	>"$evidence_root/run-object-restored.outcome.json"

events=$object_run/system-effects.jsonl
workload_truth=$object_run/workload.stdout
truth_file=/tmp/bpf-observer-object-v2/before.bin
file_device_major=$(json_u64 file_device_major "$workload_truth")
file_device_minor=$(json_u64 file_device_minor "$workload_truth")
file_inode=$(json_u64 file_inode "$workload_truth")
file_mount_id=$(json_u64 file_mount_id_unique "$workload_truth")
[[ $file_inode -gt 0 && $file_mount_id -gt 0 ]] || {
	echo "invalid independent fstat/statx file ground truth" >&2
	exit 1
}
require_same_file_identity openat FILE_CREATE_OR_TRUNCATE FILE_OBJECT PRIMARY \
	1 "$file_mount_id" "$file_device_major" "$file_device_minor" \
	"$file_inode" "$events" "$truth_file"
for tuple in \
	'write FD_WRITE FILE_OBJECT PRIMARY 1' \
	'fchmod PERMISSIONS_CHANGE FILE_OBJECT PRIMARY 1' \
	'fchmodat2 PERMISSIONS_CHANGE FILE_OBJECT PRIMARY 1' \
	'fchown OWNERSHIP_CHANGE FILE_OBJECT PRIMARY 1' \
	'fsetxattr EXTENDED_ATTRIBUTE_SET INODE_OBJECT PRIMARY 0' \
	'fremovexattr EXTENDED_ATTRIBUTE_REMOVE INODE_OBJECT PRIMARY 0' \
	'mmap MEMORY_WRITE_CHANNEL FILE_OBJECT PRIMARY 1' \
	'mprotect MEMORY_WRITE_CHANNEL FILE_OBJECT PRIMARY 1' \
	'link HARD_LINK_CREATE FILE_OBJECT SOURCE 1' \
	'linkat HARD_LINK_CREATE FILE_OBJECT SOURCE 1' \
	'rename FILE_RENAME FILE_OBJECT SOURCE 1' \
	'unlink FILE_UNLINK FILE_OBJECT PRIMARY 1' \
	'unlinkat PATH_ENTRY_REMOVE FILE_OBJECT PRIMARY 1'; do
	read -r syscall_name operation identity_kind role require_mount <<<"$tuple"
	require_same_file_identity "$syscall_name" "$operation" \
		"$identity_kind" "$role" "$require_mount" "$file_mount_id" \
		"$file_device_major" "$file_device_minor" "$file_inode" "$events"
done
for triple in \
	'DIRECTORY_CREATE FILE_OBJECT PARENT' \
	'SYMLINK_CREATE FILE_OBJECT PARENT' \
	'DEVICE_NODE_CREATE FILE_OBJECT PARENT' \
	'FILE_CREATE_OR_TRUNCATE FILE_OBJECT PRIMARY' \
	'FD_WRITE FILE_OBJECT PRIMARY' \
	'PERMISSIONS_CHANGE FILE_OBJECT PRIMARY' \
	'OWNERSHIP_CHANGE FILE_OBJECT PRIMARY' \
	'EXTENDED_ATTRIBUTE_SET INODE_OBJECT PRIMARY' \
	'EXTENDED_ATTRIBUTE_REMOVE INODE_OBJECT PRIMARY' \
	'MEMORY_WRITE_CHANNEL FILE_OBJECT PRIMARY' \
	'FILE_RENAME FILE_OBJECT SOURCE' \
	'PATH_ENTRY_REMOVE FILE_OBJECT PRIMARY' \
	'FILE_UNLINK FILE_OBJECT PRIMARY' \
	'DIRECTORY_REMOVE FILE_OBJECT PRIMARY' \
	'SOCKET_BIND SOCKET_OBJECT PRIMARY' \
	'SOCKET_CONNECT SOCKET_OBJECT PEER' \
	'SOCKET_ACCEPT SOCKET_OBJECT PEER'; do
	read -r operation identity role <<<"$triple"
	require_kernel_object "$operation" "$identity" "$role" "$events"
done
for kind in FORK EXEC EXIT; do
	require_fixed "\"kind\":\"$kind\"" "$object_run/process-lifecycle.jsonl"
done
for syscall_name in link linkat; do
	require_kernel_object_syscall "$syscall_name" "$events"
done
require_kernel_object_for_syscall mprotect MEMORY_WRITE_CHANNEL \
	FILE_OBJECT PRIMARY "$events"
require_kernel_object_for_syscall fchmodat2 PERMISSIONS_CHANGE \
	FILE_OBJECT PRIMARY "$events"
for syscall_name in fsetxattr fremovexattr; do
	awk -v syscall="\"syscall_name\":\"$syscall_name\"" '
		index($0, syscall) &&
		index($0, "\"kind\":\"OPERATION_ATTEMPT\"") &&
		index($0, "\"display\":\"user.bpf_observer\"") { found=1 }
		END { exit(found ? 0 : 1) }
	' "$events" || {
		echo "missing captured xattr name for $syscall_name" >&2
		exit 1
	}
done
require_unlinkat_flag 0 "$events"
require_unlinkat_flag 512 "$events"
awk '
	index($0, "\"syscall_name\":\"unlinkat\"") &&
	index($0, "\"kind\":\"OPERATION_RESULT\"") &&
	(index($0, "\"operation\":\"FILE_UNLINK\"") ||
	 index($0, "\"operation\":\"DIRECTORY_REMOVE\"")) { bad=1 }
	END { exit(bad ? 1 : 0) }
' "$events" || {
	echo "unlinkat was silently misclassified as a file or directory operation" >&2
	exit 1
}
awk '
	index($0, "\"syscall_name\":\"mprotect\"") &&
	index($0, "\"operation\":\"MEMORY_WRITE_CHANNEL\"") &&
	index($0, "\"kind\":\"OPERATION_RESULT\"") &&
	index($0, "\"flags\":524288") &&
	index($0, "\"quality\":\"UNRESOLVED\"") &&
	index($0, "\"authority\":\"NONE\"") &&
	index($0, "\"objects\":[]") { found=1 }
	END { exit(found ? 0 : 1) }
' "$events" || {
	echo "missing explicit unsupported anonymous/private mprotect evidence" >&2
	exit 1
}
object_unsupported=$(json_u64 object_unsupported \
	"$object_run/system-effects.health.json")
[[ $object_unsupported -ge 1 ]] || {
	echo "mprotect unsupported evidence was not reproduced in health accounting" >&2
	exit 1
}
awk '
	index($0, "\"operation\":\"SOCKET_ACCEPT\"") &&
	index($0, "\"kind\":\"OPERATION_RESULT\"") &&
	index($0, "\"role\":\"PEER\"") &&
	index($0, "\"authority\":\"KERNEL_SOCKET_STATE\"") { found=1 }
	END { exit(found ? 0 : 1) }
' "$events" || {
	echo "missing kernel-state-authoritative accepted socket endpoint" >&2
	exit 1
}
socket_events=$(require_socket_state_health "$object_run" 1)
require_fixed '"unsupported_sockets":0' "$object_run/socket-state.health.json"
listener_port=$(json_u64 listener_port "$workload_truth")
client_port=$(json_u64 client_port "$workload_truth")
accept_peer_port=$(json_u64 accept_peer_port "$workload_truth")
listener_cookie=$(json_u64 listener_cookie "$workload_truth")
client_cookie=$(json_u64 client_cookie "$workload_truth")
accepted_cookie=$(json_u64 accepted_cookie "$workload_truth")
[[ $listener_port -gt 0 && $listener_port -le 65535 &&
	$client_port -gt 0 && $client_port -le 65535 &&
	$client_port -eq $accept_peer_port &&
	$listener_cookie -gt 0 && $client_cookie -gt 0 && $accepted_cookie -gt 0 &&
	$listener_cookie -ne $client_cookie &&
	$listener_cookie -ne $accepted_cookie &&
	$client_cookie -ne $accepted_cookie ]] || {
	echo "invalid socket ground truth emitted by workload" >&2
	exit 1
}
require_socket_result_truth SOCKET_BIND PRIMARY "$listener_cookie" 0 "$events"
require_socket_result_truth SOCKET_CONNECT PEER "$client_cookie" \
	"$listener_port" "$events"
require_socket_result_truth SOCKET_ACCEPT PEER "$accepted_cookie" \
	"$accept_peer_port" "$events"
require_socket_state_truth SOCKET_BIND "$listener_cookie" "$listener_port" 0 \
	"$object_run/socket-state.jsonl"
require_socket_state_truth SOCKET_CONNECT "$client_cookie" "$listener_port" \
	"$client_port" "$object_run/socket-state.jsonl"
require_socket_state_truth SOCKET_ACCEPT "$accepted_cookie" "$listener_port" \
	"$accept_peer_port" "$object_run/socket-state.jsonl"
for operation in SOCKET_BIND SOCKET_CONNECT SOCKET_ACCEPT; do
	awk -v operation="\"operation\":\"$operation\"" '
		index($0, operation) &&
		index($0, "\"kind\":\"OPERATION_RESULT\"") &&
		index($0, "\"address_family\":2") &&
		index($0, "\"socket_type\":1") &&
		index($0, "\"protocol\":6") { found=1 }
		END { exit(found ? 0 : 1) }
	' "$events" || {
		echo "invalid AF_INET/SOCK_STREAM/TCP object identity for $operation" >&2
		exit 1
	}
done
for kind in ACCEPT_SNAPSHOT TRANSITION DESTROY; do
	require_fixed "\"kind\":\"$kind\"" "$object_run/socket-state.jsonl"
done
require_fixed '"authority":"SOCKET_COOKIE_OWNER_FROM_SYSCALL_ENTRY"' \
	"$object_run/socket-state.jsonl"
for operation in SOCKET_BIND SOCKET_CONNECT SOCKET_ACCEPT; do
	require_fixed "\"origin_operation\":\"$operation\"" \
		"$object_run/socket-state.jsonl"
done
[[ $(wc -l <"$object_run/socket-state.jsonl") -eq $socket_events ]]
require_fixed '"status":"PARTIAL"' "$object_run/process-lifecycle.health.json"
require_fixed '"producer_barrier_complete":true' "$object_run/process-lifecycle.health.json"
require_fixed '"drain_completed":true' "$object_run/process-lifecycle.health.json"
require_fixed '"terminal_state":"EMPTY_WITHIN_SCOPE"' "$object_run/linux-state-comparison.json"
for domain in network_config sysctl mounts modules process_residual; do
	require_fixed "\"$domain\":\"INCONCLUSIVE\"" \
		"$evidence_root/run-object-restored.outcome.json"
done
verify_run "$object_run" "$full_scope" >"$evidence_root/run-object-restored.verify.json"
require_fixed '"socket_state_status":"COMPLETE"' \
	"$evidence_root/run-object-restored.verify.json"
require_fixed '"socket_state_artifacts_verified":true' \
	"$evidence_root/run-object-restored.verify.json"
require_fixed "\"socket_state_events_verified\":$socket_events" \
	"$evidence_root/run-object-restored.verify.json"

# Deliberately missing sysctl input must remain honest INCOMPLETE/INCONCLUSIVE;
# the verifier should accept the faithfully reported negative evidence.
incomplete_run=$evidence_root/run-incomplete-state
"$observer" observe-effects \
	--recorder-object "$effect_object" \
	--expected-recorder-sha256 "$effect_sha256" \
	--process-lifecycle-object "$lifecycle_object" \
	--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
	--output-dir "$incomplete_run" --cgroup-root "$cgroup_root" \
	--run-id incomplete-state --run-epoch 1 --profile full \
	--timeout-ms 30000 --drain-timeout-ms 5000 \
	--object-resolution "$object_mode" \
	--linux-state-scope "$incomplete_scope" --confirm-process-residual \
	-- /bin/true >"$evidence_root/run-incomplete-state.outcome.json"
require_fixed '"endpoint_difference":"INDETERMINATE"' "$incomplete_run/linux-state-comparison.json"
require_fixed '"status":"INCOMPLETE"' "$incomplete_run/linux-state-comparison.json"
require_fixed '"verdict":"INCONCLUSIVE"' "$incomplete_run/linux-state-comparison.json"
require_socket_state_health "$incomplete_run" 0 >/dev/null
require_fixed '"unsupported_sockets":0' "$incomplete_run/socket-state.health.json"
verify_run "$incomplete_run" "$incomplete_scope" >"$evidence_root/run-incomplete-state.verify.json"
require_fixed '"socket_state_artifacts_verified":true' \
	"$evidence_root/run-incomplete-state.verify.json"

# The deployment adapter registers a frozen root, then observes an object
# workload in a child cgroup created only after READY and deleted before
# FINISH.  Offline verification must independently accept the closed evidence.
"$deployment_direct_runner" "$deployment_observer" "$deployment_verify" \
	"$effect_object" "$effect_sha256" "$lifecycle_object" \
	"$lifecycle_sha256" "$object_workload" \
	"$deployment_endpoint_workload" "$full_scope" "$evidence_root" \
	>"$evidence_root/deployment-ancestor.harness.stdout"
require_fixed 'DEPLOYMENT_ANCESTOR_VM_E2E_PASS ' \
	"$evidence_root/deployment-ancestor.harness.stdout"

# Docker/Kata-shaped targets exercise production live procfs/cgroup/namespace
# and host-resource revalidation.  Their runtime identities are explicitly
# synthetic and the artifacts never claim a real Docker/Kata runtime E2E.
"$deployment_synthetic_runner" "$deployment_observer" "$deployment_verify" \
	"$effect_object" "$effect_sha256" "$lifecycle_object" \
	"$lifecycle_sha256" "$object_workload" "$deployment_live_fixture" \
	"$evidence_root" >"$evidence_root/deployment-live-synthetic.harness.stdout"
require_fixed 'DEPLOYMENT_LIVE_SYNTHETIC_VM_E2E_PASS ' \
	"$evidence_root/deployment-live-synthetic.harness.stdout"
require_fixed '"real_docker_runtime_e2e":false' \
	"$evidence_root/deployment-live-synthetic-status.json"
require_fixed '"real_kata_runtime_e2e":false' \
	"$evidence_root/deployment-live-synthetic-status.json"

# Persist a deterministic difference in sysctl, mounts, local network state,
# and loaded modules. The VM is discarded after S1 and evidence recovery.
changed_run=$evidence_root/run-state-changed
"$observer" observe-effects \
	--recorder-object "$effect_object" \
	--expected-recorder-sha256 "$effect_sha256" \
	--process-lifecycle-object "$lifecycle_object" \
	--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
	--output-dir "$changed_run" --cgroup-root "$cgroup_root" \
	--run-id changed-state --run-epoch 1 --profile full \
	--timeout-ms 30000 --drain-timeout-ms 5000 \
	--object-resolution "$object_mode" \
	--linux-state-scope "$full_scope" --confirm-process-residual \
	-- /bin/bash "$state_workload" "$state_module" \
	>"$evidence_root/run-state-changed.outcome.json"
comparison=$changed_run/linux-state-comparison.json
for needle in \
	'"key":"net/ipv4/ip_forward"' \
	'"key":"mount/' \
	'"key":"ip/address"' \
	'"key":"ip/route/ipv4"' \
	'"key":"tc/qdisc"' \
	'"key":"nft/ruleset"' \
	'"key":"module/bpf_observer_e2e_state"'; do
	require_fixed "$needle" "$comparison"
done
changed_count=$(count_fixed '"verdict":"CHANGED_WITHIN_SCOPE"' "$comparison")
[[ $changed_count -eq 4 ]] || {
	echo "expected exactly four changed Linux endpoint domains, got $changed_count" >&2
	exit 1
}
require_fixed '"terminal_state":"EMPTY_WITHIN_SCOPE"' "$comparison"
require_socket_state_health "$changed_run" 0 >/dev/null
changed_unsupported_sockets=$(json_u64 unsupported_sockets \
	"$changed_run/socket-state.health.json")
embedded_changed_unsupported_sockets=$(json_u64 unsupported_sockets \
	"$changed_run/system-effects.health.json")
changed_netlink_socket_results=$(count_successful_netlink_socket_results \
	"$changed_run/system-effects.jsonl")
[[ $changed_unsupported_sockets -gt 0 &&
	$changed_unsupported_sockets -eq $embedded_changed_unsupported_sockets &&
	$changed_unsupported_sockets -eq $changed_netlink_socket_results ]] || {
	echo "changed-state unsupported socket accounting is not exactly explained by successful AF_NETLINK operation results: socket_health=$changed_unsupported_sockets embedded_health=$embedded_changed_unsupported_sockets netlink_results=$changed_netlink_socket_results" >&2
	exit 1
}
verify_run "$changed_run" "$full_scope" >"$evidence_root/run-state-changed.verify.json"
require_fixed '"socket_state_artifacts_verified":true' \
	"$evidence_root/run-state-changed.verify.json"

# A live descendant must prevent the empty/frozen close boundary. This run is
# expected to fail and the runner must clean the exact cgroup with cgroup.kill.
residual_run=$evidence_root/run-residual-negative
if "$observer" observe-effects \
	--recorder-object "$effect_object" \
	--expected-recorder-sha256 "$effect_sha256" \
	--process-lifecycle-object "$lifecycle_object" \
	--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
	--output-dir "$residual_run" --cgroup-root "$cgroup_root" \
	--run-id residual-negative --run-epoch 1 --profile full \
	--timeout-ms 1000 --drain-timeout-ms 1000 \
	--object-resolution "$object_mode" --confirm-process-residual \
	-- /bin/bash "$residual_workload" \
	>"$evidence_root/run-residual-negative.outcome.json" \
	2>"$evidence_root/run-residual-negative.stderr"; then
	echo "residual-process negative unexpectedly finalized" >&2
	exit 1
fi
require_fixed '"run_status":"FAILED"' "$residual_run/system-effects.manifest.json"
[[ ! -e $cgroup_root/residual-negative ]]

# Four excluded warm-up blocks and twelve measured blocks compare identical
# file-effect workloads under user-input and expanded+lifecycle collection.
# Every block contains both modes at both N=0 and N=1024.  A four-row order
# cycle balances load order, mode order, and their first-order carryover.
# Collection success is deliberately separate from statistical acceptance;
# the Host runs the pinned analyzer after recovering the immutable raw tree.
overhead_root=$evidence_root/overhead-paired
overhead_scratch_root=/dev/shm/bpf-observer-expanded-overhead
[[ ! -e $overhead_scratch_root ]]
mkdir -m 0700 "$overhead_root" "$overhead_root/warmup" \
	"$overhead_root/measured" "$overhead_scratch_root"
summary=$overhead_root/summary.jsonl
warmup_summary=$overhead_root/warmup-summary.jsonl
: >"$summary"
: >"$warmup_summary"
printf '%s\n' "{\"schema_version\":1,\"benchmark\":\"expanded-system-effects-overhead-v1\",\"recorder_object_sha256\":\"$effect_sha256\",\"process_lifecycle_object_sha256\":\"$lifecycle_sha256\",\"warmup_blocks\":4,\"measured_blocks\":12,\"loads\":[0,1024],\"modes\":[\"user-input\",\"expanded-lifecycle\"],\"primary_system_event_delta\":\"expanded-lifecycle@1024-expanded-lifecycle@0\",\"contrast\":\"[(expanded-lifecycle-user-input)@1024-(expanded-lifecycle-user-input)@0]\",\"order_cycle\":\"FOUR_ROW_LOAD_AND_MODE_COUNTERBALANCED\"}" \
	>"$overhead_root/design.json"

run_overhead_arm()
{
	local class=$1
	local block=$2
	local order_position=$3
	local load=$4
	local mode=$5
	local output_summary=$6
	local block_root=$overhead_root/$class/block-$(printf '%03d' "$block")
	local arm=$block_root/n-$load/$mode
	local run_dir=$arm/evidence
	local scratch=$overhead_scratch_root/$class-block-$block-n-$load-$mode
	local resolution lifecycle_events socket_state_events
	local socket_state_health
	local effect_events wall_ns user_cpu_ns system_cpu_ns max_rss_kb
	local voluntary_context_switches involuntary_context_switches
	local system_raw_bytes system_jsonl_bytes system_health_bytes
	local lifecycle_raw_bytes=0 lifecycle_jsonl_bytes=0 lifecycle_health_bytes=0
	local socket_raw_bytes=0 socket_jsonl_bytes=0 socket_health_bytes=0
	local -a observe verify

	mkdir -m 0700 "$arm" "$scratch"
	observe=(
		"$observer" observe-effects
		--recorder-object "$effect_object"
		--expected-recorder-sha256 "$effect_sha256"
		--output-dir "$run_dir" --cgroup-root "$cgroup_root"
		--run-id "overhead-$class-$block-$load-$mode" --run-epoch 1
		--profile full --timeout-ms 30000 --drain-timeout-ms 5000
	)
	if [[ $mode == expanded-lifecycle ]]; then
		observe+=(
			--object-resolution "$object_mode"
			--process-lifecycle-object "$lifecycle_object"
			--expected-process-lifecycle-sha256 "$lifecycle_sha256"
		)
		resolution=$object_mode
	else
		observe+=(--object-resolution user-input)
		resolution=user-input
	fi
	observe+=(-- "$overhead_workload" --profile file
		--iterations "$load" --scratch-dir "$scratch"
		--batch-size 128 --pause-us 1000)
	"$measure_command" "$arm/command.json" -- "${observe[@]}" \
		>"$arm/observer.stdout" 2>"$arm/observer.stderr"
	rmdir "$scratch"
	require_fixed '"exit_code":0' "$arm/command.json"
	require_fixed '"signal":0' "$arm/command.json"
	require_fixed '"run_status":"FINALIZED"' \
		"$run_dir/system-effects.manifest.json"
	effect_events=$(require_effect_health "$run_dir")
	system_raw_bytes=$(stat -c %s "$run_dir/system-effects.raw.bin")
	system_jsonl_bytes=$(stat -c %s "$run_dir/system-effects.jsonl")
	system_health_bytes=$(stat -c %s "$run_dir/system-effects.health.json")
	lifecycle_events=0
	socket_state_events=0
	socket_state_health=DISABLED
	verify=(
		"$observer" verify-effects --run-dir "$run_dir"
		--expected-recorder-sha256 "$effect_sha256"
		--expected-profile full --expected-object-resolution "$resolution"
	)
	if [[ $mode == expanded-lifecycle ]]; then
		lifecycle_events=$(require_lifecycle_health "$run_dir")
		socket_state_events=$(require_socket_state_health "$run_dir" 0)
		require_fixed '"unsupported_sockets":0' "$run_dir/socket-state.health.json"
		lifecycle_raw_bytes=$(stat -c %s "$run_dir/process-lifecycle.raw.bin")
		lifecycle_jsonl_bytes=$(stat -c %s "$run_dir/process-lifecycle.jsonl")
		lifecycle_health_bytes=$(stat -c %s "$run_dir/process-lifecycle.health.json")
		socket_raw_bytes=$(stat -c %s "$run_dir/socket-state.raw.bin")
		socket_jsonl_bytes=$(stat -c %s "$run_dir/socket-state.jsonl")
		socket_health_bytes=$(stat -c %s "$run_dir/socket-state.health.json")
		socket_state_health=COMPLETE
		verify+=(--expected-process-lifecycle-sha256 "$lifecycle_sha256")
	else
		[[ ! -e $run_dir/process-lifecycle.raw.bin &&
			! -e $run_dir/process-lifecycle.jsonl &&
			! -e $run_dir/process-lifecycle.health.json &&
			! -e $run_dir/socket-state.raw.bin &&
			! -e $run_dir/socket-state.jsonl &&
			! -e $run_dir/socket-state.health.json ]]
	fi
	"${verify[@]}" >"$arm/verify.json"
	if [[ $mode == expanded-lifecycle ]]; then
		require_fixed '"socket_state_status":"COMPLETE"' "$arm/verify.json"
		require_fixed '"socket_state_artifacts_verified":true' "$arm/verify.json"
		require_fixed "\"socket_state_events_verified\":$socket_state_events" \
			"$arm/verify.json"
	else
		require_fixed '"socket_state_artifacts_verified":false' "$arm/verify.json"
		require_fixed '"socket_state_events_verified":0' "$arm/verify.json"
	fi
	wall_ns=$(json_u64 wall_ns "$arm/command.json")
	user_cpu_ns=$(json_u64 user_cpu_ns "$arm/command.json")
	system_cpu_ns=$(json_u64 system_cpu_ns "$arm/command.json")
	max_rss_kb=$(json_u64 max_rss_kb "$arm/command.json")
	voluntary_context_switches=$(json_u64 voluntary_context_switches "$arm/command.json")
	involuntary_context_switches=$(json_u64 involuntary_context_switches "$arm/command.json")
	printf '%s\n' "{\"schema_version\":1,\"class\":\"$class\",\"block\":$block,\"order_position\":$order_position,\"iterations\":$load,\"mode\":\"$mode\",\"wall_ns\":$wall_ns,\"user_cpu_ns\":$user_cpu_ns,\"system_cpu_ns\":$system_cpu_ns,\"max_rss_kb\":$max_rss_kb,\"voluntary_context_switches\":$voluntary_context_switches,\"involuntary_context_switches\":$involuntary_context_switches,\"system_effect_events\":$effect_events,\"system_effect_raw_bytes\":$system_raw_bytes,\"system_effect_jsonl_bytes\":$system_jsonl_bytes,\"system_effect_health_bytes\":$system_health_bytes,\"process_lifecycle_events\":$lifecycle_events,\"process_lifecycle_raw_bytes\":$lifecycle_raw_bytes,\"process_lifecycle_jsonl_bytes\":$lifecycle_jsonl_bytes,\"process_lifecycle_health_bytes\":$lifecycle_health_bytes,\"socket_state_events\":$socket_state_events,\"socket_state_raw_bytes\":$socket_raw_bytes,\"socket_state_jsonl_bytes\":$socket_jsonl_bytes,\"socket_state_health_bytes\":$socket_health_bytes,\"socket_state_health\":\"$socket_state_health\",\"lossless\":true,\"offline_verified\":true}" >>"$output_summary"
}

run_overhead_block()
{
	local class=$1
	local block=$2
	local output_summary=$3
	local order_index=$(((block - 1) % 4))
	local block_root=$overhead_root/$class/block-$(printf '%03d' "$block")
	local order_position=0
	local entry load mode
	local -a order

	case $order_index in
	0) order=('0 user-input' '0 expanded-lifecycle' '1024 expanded-lifecycle' '1024 user-input') ;;
	1) order=('1024 user-input' '1024 expanded-lifecycle' '0 expanded-lifecycle' '0 user-input') ;;
	2) order=('0 expanded-lifecycle' '0 user-input' '1024 user-input' '1024 expanded-lifecycle') ;;
	3) order=('1024 expanded-lifecycle' '1024 user-input' '0 user-input' '0 expanded-lifecycle') ;;
	esac
	mkdir -m 0700 "$block_root" "$block_root/n-0" \
		"$block_root/n-1024"
	printf '%s\n' "${order[@]}" >"$block_root/treatment-order.txt"
	for entry in "${order[@]}"; do
		read -r load mode <<<"$entry"
		order_position=$((order_position + 1))
		echo "class=$class block=$block position=$order_position load=$load mode=$mode"
		run_overhead_arm "$class" "$block" "$order_position" "$load" \
			"$mode" "$output_summary"
	done
}

for block in $(seq 1 4); do
	run_overhead_block warmup "$block" "$warmup_summary"
done
for block in $(seq 1 12); do
	run_overhead_block measured "$block" "$summary"
done
rmdir "$overhead_scratch_root"
[[ $(wc -l <"$warmup_summary") -eq 16 ]]
[[ $(wc -l <"$summary") -eq 48 ]]
printf '%s\n' '{"schema_version":1,"collection_status":"PASS","inference_status":"PENDING_HOST_ANALYZER","interpretation":"EXPLORATORY_UNTIL_ANALYZED","warmup_blocks":4,"measured_blocks":12,"arms_per_block":4,"loads":[0,1024],"order":"FOUR_ROW_LOAD_AND_MODE_COUNTERBALANCED","batch_size":128,"pause_us":1000}' \
	>"$overhead_root/collection-status.json"

printf 'EXPANDED_EFFECTS_VM_E2E_PASS effect_sha256=%s lifecycle_sha256=%s\n' \
	"$effect_sha256" "$lifecycle_sha256"
