#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Exercise production live /proc, cgroup-v2, namespace, and sysfs discovery for
# Docker and Kata-shaped targets without claiming that the fixtures are real
# Docker/Kata runtimes.  The outer VM is disposable and owns all cleanup.

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
usage: guest-deployment-live-synthetic-e2e.sh DEPLOYMENT_OBSERVER DEPLOYMENT_VERIFY EFFECT_OBJECT EFFECT_SHA256 LIFECYCLE_OBJECT LIFECYCLE_SHA256 OBJECT_WORKLOAD LIVE_FIXTURE EVIDENCE_ROOT
EOF
	exit 2
}

[[ $# -eq 9 ]] || usage
[[ ${EUID} -eq 0 ]] || { echo "deployment live synthetic E2E requires Guest root" >&2; exit 2; }

deployment_observer=$1
deployment_verify=$2
effect_object=$3
effect_sha256=$4
lifecycle_object=$5
lifecycle_sha256=$6
object_workload=$7
live_fixture=$8
evidence_root=$9
fixture_root=/tmp/bpf-observer-deployment-live-fixtures
docker_id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
docker_name=docker-$docker_id.scope
docker_scope=/sys/fs/cgroup/$docker_name
docker_cgroup_path=/$docker_name
docker_child=$docker_scope/effect-child
docker_init=$fixture_root/docker-init
docker_filesystem_root=$fixture_root/docker-private-filesystem
docker_filesystem_marker=$docker_filesystem_root/root-marker
docker_launcher_pid=
docker_init_pid=
docker_mount_namespace_inode=
kata_id=kata-synthetic-e2e
kata_name=bpf-observer-$kata_id
kata_scope=/sys/fs/cgroup/$kata_name
kata_cgroup_path=/$kata_name
kata_child=$kata_scope/effect-child
kata_shim=$fixture_root/containerd-shim-kata-v2
kata_qemu=$fixture_root/qemu-system-x86_64
kata_disk=$fixture_root/kata-disk.raw
kata_tap=katae2etap0
kata_tap_multi=katae2etap1
kata_shim_pid=
kata_qemu_pid=
kata_shim_starttime=
kata_qemu_starttime=
active_observer_pid=
active_control_fifo=
active_output_fifo=
created_tun_node=0

for path in "$deployment_observer" "$deployment_verify" "$object_workload" \
	"$live_fixture"; do
	[[ $path == /* && -x $path && -f $path ]] || {
		echo "missing live synthetic executable: $path" >&2
		exit 2
	}
done
for path in "$effect_object" "$lifecycle_object"; do
	[[ $path == /* && -f $path ]] || {
		echo "missing live synthetic BPF object: $path" >&2
		exit 2
	}
done
for digest in "$effect_sha256" "$lifecycle_sha256"; do
	[[ $digest =~ ^[0-9a-f]{64}$ ]] || {
		echo "invalid live synthetic BPF digest" >&2
		exit 2
	}
done
[[ $(sha256sum "$effect_object" | awk '{print $1}') == "$effect_sha256" ]]
[[ $(sha256sum "$lifecycle_object" | awk '{print $1}') == "$lifecycle_sha256" ]]
[[ $evidence_root == /* && -d $evidence_root && ! -L $evidence_root ]]
[[ ! -e $fixture_root && ! -L $fixture_root ]]
[[ ! -e $docker_scope && ! -L $docker_scope ]]
[[ ! -e $kata_scope && ! -L $kata_scope ]]
for command in awk grep install ip mknod mount od readlink seq sha256sum stat tr \
	truncate unshare; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing live synthetic Guest command: $command" >&2
		exit 2
	}
done

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

hex_bytes()
{
	printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'
}

ip_tool=$(trusted_tool /usr/sbin/ip)
tc_tool=$(trusted_tool /usr/sbin/tc)
nft_tool=$(trusted_tool /usr/sbin/nft)
ip_sha=$(sha256sum "$ip_tool" | awk '{print $1}')
tc_sha=$(sha256sum "$tc_tool" | awk '{print $1}')
nft_sha=$(sha256sum "$nft_tool" | awk '{print $1}')
state_limits='{"max_records":16384,"max_value_bytes":4194304,"max_total_value_bytes":16777216,"deadline_ms":15000}'

write_namespace_state_scope()
{
	local pid=$1
	local output=$2
	local mnt_ns net_ns
	mnt_ns=$(stat -Lc %i "/proc/$pid/ns/mnt")
	net_ns=$(stat -Lc %i "/proc/$pid/ns/net")
	printf '%s\n' "{\"protocol_version\":1,\"sysctl\":null,\"mounts\":{\"namespace\":{\"pid\":$pid,\"expected_namespace_inode\":$mnt_ns},\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$state_limits},\"network\":{\"namespace\":{\"pid\":$pid,\"expected_namespace_inode\":$net_ns},\"collectors\":{\"addresses\":true,\"routes\":true,\"rules\":true,\"traffic_control\":true,\"nftables\":true},\"normalization\":\"NETWORK_CONFIGURATION_ONLY_V1\",\"ip_binary_bytes_hex\":\"$(hex_bytes "$ip_tool")\",\"expected_ip_sha256\":\"$ip_sha\",\"tc_binary_bytes_hex\":\"$(hex_bytes "$tc_tool")\",\"expected_tc_sha256\":\"$tc_sha\",\"nft_binary_bytes_hex\":\"$(hex_bytes "$nft_tool")\",\"expected_nft_sha256\":\"$nft_sha\",\"tc_interfaces\":[\"lo\"],\"evidence\":\"BYTES_AND_SHA256\",\"limits\":$state_limits},\"modules\":null,\"process_residual\":null}" >"$output"
}

write_filesystem_scope()
{
	local root=$1
	local output=$2
	printf '%s\n' "{\"protocol_version\":1,\"roots\":[{\"path_bytes_hex\":\"$(hex_bytes "$root")\"}],\"capture\":{\"regular_file_content\":\"SHA256\",\"symlinks\":\"TARGET_BYTES\",\"xattrs\":\"NAMES_AND_VALUE_SHA256\",\"cross_filesystems\":\"SAME_DEVICE_ONLY\"},\"limits\":{\"max_entries\":1024,\"max_total_path_bytes\":1048576,\"max_file_content_bytes\":1048576,\"max_total_content_bytes\":4194304,\"max_xattr_list_bytes\":65536,\"max_xattrs_per_entry\":64,\"max_total_xattrs\":4096,\"max_xattr_value_bytes\":262144,\"max_total_xattr_bytes\":1048576,\"max_symlink_target_bytes\":4096,\"max_depth\":16,\"deadline_ms\":15000}}" >"$output"
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
		echo "missing expected live synthetic evidence in $path: $needle" >&2
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

# Match a scalar inside one named top-level JSON object. The report is emitted
# with serde_json's pretty formatter; restricting both indentation levels
# prevents a nested domain's identically named field from satisfying an
# aggregate assertion.
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

require_manifest_process_u64()
{
	local role=$1
	local key=$2
	local value=$3
	local path=$4
	awk -v role="$role" -v key="$key" -v value="$value" '
		$0 == "    {" { inside=1; has_role=0; has_value=0; next }
		inside && $0 == "      \"role\": \"" role "\"," { has_role=1 }
		inside && ($0 == "      \"" key "\": " value "," ||
		           $0 == "      \"" key "\": " value) { has_value=1 }
		inside && ($0 == "    }," || $0 == "    }") {
			if (has_role && has_value) {
				found=1
				exit
			}
			inside=0
		}
		END { exit(found ? 0 : 1) }
	' "$path" || {
		echo "missing $role process $key=$value in $path" >&2
		exit 1
	}
}

require_filesystem_entry_content_status()
{
	local display=$1
	local status=$2
	local path=$3
	awk -v display="$display" -v status="$status" '
		{
			line=$0
			gsub(/[[:space:]]/, "", line)
			json=json line
		}
		END {
			marker="\"relative_path_display\":\"" display "\""
			start=index(json, marker)
			if (!start)
				exit 1
			rest=substr(json, start + length(marker))
			next_entry=index(rest, "\"relative_path_display\":")
			if (next_entry)
				rest=substr(rest, 1, next_entry - 1)
			expected="\"content\":{\"status\":\"" status "\""
			exit(index(rest, expected) ? 0 : 1)
		}
	' "$path" || {
		echo "missing filesystem entry $display with content status $status in $path" >&2
		exit 1
	}
}

require_filesystem_comparison_completeness()
{
	local status=$1
	local path=$2
	awk -v status="$status" '
		{
			line=$0
			gsub(/[[:space:]]/, "", line)
			json=json line
		}
		END {
			expected="\"state_completeness\":{\"status\":\"" status "\",\"reasons\":[]}"
			exit(index(json, expected) ? 0 : 1)
		}
	' "$path" || {
		echo "missing canonical filesystem completeness $status in $path" >&2
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

proc_starttime()
{
	local pid=$1
	# comm may contain spaces and parentheses.  Delete through the final `) `;
	# starttime is then field 20 in the remaining status tail (original field 22).
	awk '{ line=$0; sub(/^.*\) /, "", line); count=split(line, field, " ");
		if (count >= 20 && field[20] ~ /^[0-9]+$/) print field[20]; else exit 1 }' \
		"/proc/$pid/stat"
}

wait_final_fixture_process()
{
	local label=$1
	local pid=$2
	local expected_exe=$3
	shift 3
	local attempt actual_exe first_starttime second_starttime cmdline token
	local matched=0

	for attempt in $(seq 1 500); do
		[[ -r /proc/$pid/status && -r /proc/$pid/stat && -e /proc/$pid/exe && \
			-r /proc/$pid/cmdline ]] || { sleep 0.01; continue; }
		actual_exe=$(readlink -f "/proc/$pid/exe") || { sleep 0.01; continue; }
		[[ $actual_exe == "$expected_exe" ]] || { sleep 0.01; continue; }
		grep -Fxq -- "$pid" "$kata_scope/cgroup.procs" || { sleep 0.01; continue; }
		cmdline=$(tr '\0' '\n' <"/proc/$pid/cmdline") || { sleep 0.01; continue; }
		matched=1
		for token in "$@"; do
			grep -Fxq -- "$token" <<<"$cmdline" || { matched=0; break; }
		done
		[[ $matched -eq 1 ]] || { sleep 0.01; continue; }
		first_starttime=$(proc_starttime "$pid") || { sleep 0.01; continue; }
		sleep 0.01
		second_starttime=$(proc_starttime "$pid") || { sleep 0.01; continue; }
		[[ $first_starttime == "$second_starttime" ]] || { sleep 0.01; continue; }
		printf '%s\n' "$first_starttime"
		return 0
	done
	echo "$label fixture did not settle on final exe/cmdline/starttime/cgroup" >&2
	return 1
}

wait_frozen()
{
	local scope=$1
	local expected=$2
	local attempt
	for attempt in $(seq 1 500); do
		awk -v expected="$expected" '$1 == "frozen" && $2 == expected { found=1 }
			END { exit(found ? 0 : 1) }' "$scope/cgroup.events" && return 0
		sleep 0.01
	done
	echo "$scope did not reach frozen=$expected" >&2
	return 1
}

kill_scope()
{
	local scope=$1
	[[ -d $scope ]] || return 0
	printf '0\n' >"$scope/cgroup.freeze" 2>/dev/null || true
	[[ -e $scope/cgroup.kill ]] && printf '1\n' >"$scope/cgroup.kill" 2>/dev/null
	for child in "$scope/effect-child"; do
		[[ -d $child ]] && rmdir "$child" 2>/dev/null
	done
	rmdir "$scope" 2>/dev/null
}

cleanup()
{
	set +e
	if [[ -n $active_observer_pid ]]; then
		kill "$active_observer_pid" 2>/dev/null
		wait "$active_observer_pid" 2>/dev/null
	fi
	[[ -z $active_control_fifo ]] || rm -f -- "$active_control_fifo"
	[[ -z $active_output_fifo ]] || rm -f -- "$active_output_fifo"
	kill_scope "$docker_scope"
	kill_scope "$kata_scope"
	for pid in "$docker_launcher_pid" "$kata_shim_pid" "$kata_qemu_pid"; do
		[[ -n $pid ]] || continue
		kill "$pid" 2>/dev/null
		wait "$pid" 2>/dev/null
	done
	ip link del "$kata_tap" 2>/dev/null
	ip link del "$kata_tap_multi" 2>/dev/null
	rm -rf -- "$fixture_root" 2>/dev/null
	if [[ $created_tun_node -eq 1 ]]; then
		rm -f -- /dev/net/tun 2>/dev/null
	fi
}
trap cleanup EXIT

run_observer()
{
	local label=$1
	local run_id=$2
	local scope=$3
	local child=$4
	local config=$5
	local output_dir=$6
	local target_path=/tmp/bpf-observer-$label-effect
	local control_fifo=$evidence_root/$label.control.fifo
	local output_fifo=$evidence_root/$label.output.fifo
	local ready_file=$evidence_root/$label.ready.json
	local finished_file=$evidence_root/$label.finished.json
	local stderr_file=$evidence_root/$label.stderr
	local verify_file=$evidence_root/$label.verify.json
	local expectation=$evidence_root/$label.expectation.json
	local control_fd output_fd ready finished finish_nonce report_sha manifest_sha
	local completed_observer_pid

	[[ ! -e $target_path && ! -L $target_path && ! -e $output_dir ]]
	mkfifo -m 0600 "$control_fifo" "$output_fifo"
	active_control_fifo=$control_fifo
	active_output_fifo=$output_fifo
	exec {control_fd}<>"$control_fifo"
	exec {output_fd}<>"$output_fifo"
	"$deployment_observer" --config "$config" \
		<"$control_fifo" >"$output_fifo" 2>"$stderr_file" &
	active_observer_pid=$!
	IFS= read -r -t 30 -u "$output_fd" ready || {
		echo "$label observer did not emit READY" >&2
		return 1
	}
	printf '%s\n' "$ready" >"$ready_file"
	require_fixed '"protocol_version":2' "$ready_file"
	require_fixed '"status":"READY"' "$ready_file"
	require_fixed '"mode":"CGROUP_V2_ANCESTOR_ROOT"' "$ready_file"
	require_fixed '"dynamic_descendants_including_ephemeral":true' "$ready_file"
	require_fixed '"socket_state_enabled":true' "$ready_file"
	require_fixed '"linux_state_scope_sha256":"' "$ready_file"
	require_fixed '"linux_state_s0_sha256":"' "$ready_file"
	finish_nonce=${ready#*\"finish_nonce\":\"}
	finish_nonce=${finish_nonce%%\"*}
	[[ $finish_nonce =~ ^[0-9a-f]{64}$ ]]

	printf '0\n' >"$scope/cgroup.freeze"
	wait_frozen "$scope" 0
	mkdir -m 0755 "$child"
	/bin/bash -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; exec "$2" "$3"' \
		_ "$child" "$object_workload" "$target_path" \
		>"$evidence_root/$label.workload.stdout" \
		2>"$evidence_root/$label.workload.stderr"
	[[ -z $(cat "$child/cgroup.procs") ]]
	rmdir "$child"
	[[ ! -e $target_path ]]
	printf '1\n' >"$scope/cgroup.freeze"
	wait_frozen "$scope" 1
	printf '%s\n' "{\"protocol_version\":2,\"command\":\"FINISH\",\"run_id\":\"$run_id\",\"finish_nonce\":\"$finish_nonce\"}" \
		>&"$control_fd"
	IFS= read -r -t 30 -u "$output_fd" finished || {
		echo "$label observer did not emit FINISHED" >&2
		return 1
	}
	printf '%s\n' "$finished" >"$finished_file"
	exec {control_fd}>&-
	exec {output_fd}>&-
	completed_observer_pid=$active_observer_pid
	active_observer_pid=
	wait "$completed_observer_pid"
	rm -f -- "$control_fifo" "$output_fifo"
	active_control_fifo=
	active_output_fifo=
	require_fixed '"protocol_version":2' "$finished_file"
	require_fixed '"status":"FINISHED"' "$finished_file"
	# The effect and socket transports can close completely, but lifecycle
	# schema v2 deliberately remains PARTIAL (no authoritative S0 task ledger
	# or cgroup-migration enrollment stream). The conservative run aggregate
	# must therefore remain INCOMPLETE rather than overclaiming causality.
	require_fixed '"evidence_status":"INCOMPLETE"' "$finished_file"
	report_sha=${finished#*\"report_sha256\":\"}
	report_sha=${report_sha%%\"*}
	manifest_sha=${finished#*\"artifact_manifest_sha256\":\"}
	manifest_sha=${manifest_sha%%\"*}
	[[ $report_sha =~ ^[0-9a-f]{64}$ && $manifest_sha =~ ^[0-9a-f]{64}$ ]]
	require_fixed '"stable":true' "$output_dir/pre-finish-validation.json"
	require_fixed '"mismatches":[]' "$output_dir/pre-finish-validation.json"
	require_fixed '"stable":true' "$output_dir/closure-validation.json"
	require_fixed '"mismatches":[]' "$output_dir/closure-validation.json"
	require_report_object_string aggregate_health evidence_status COMPLETE \
		"$output_dir/deployment-observation-report.json"
	require_report_top_level_string overall_evidence_status INCOMPLETE \
		"$output_dir/deployment-observation-report.json"
	require_report_object_string aggregate_lifecycle_health root_scope_status PARTIAL \
		"$output_dir/deployment-observation-report.json"
	require_fixed '"whole_tree_coverage_status":"DYNAMIC_ANCESTOR_COMPLETE"' \
		"$output_dir/deployment-observation-report.json"
	local report=$output_dir/deployment-observation-report.json
	local artifact_manifest=$output_dir/artifact-manifest.json
	local committed_artifact_total_bytes
	for telemetry_file in "$report" "$artifact_manifest"; do
		require_fixed '"diagnostic_performance":{' "$telemetry_file"
		require_fixed '"purpose":"DIAGNOSTIC_ONLY_NOT_TRUSTED_EVIDENCE"' \
			"$telemetry_file"
		require_fixed '"clock":"RUST_STD_INSTANT_MONOTONIC_V1"' \
			"$telemetry_file"
		require_fixed '"trusted_evidence":false' "$telemetry_file"
		require_fixed '"affects_verdict":false' "$telemetry_file"
		require_fixed '"s0_endpoint_capture":{' "$telemetry_file"
		require_fixed '"closing_drain":{' "$telemetry_file"
		require_fixed '"s1_endpoint_capture":{' "$telemetry_file"
	done
	committed_artifact_total_bytes=$(json_u64 committed_artifact_total_bytes \
		"$artifact_manifest")
	[[ $committed_artifact_total_bytes -gt 0 ]]
	for path in "$output_dir/socket-state.raw.bin" \
		"$output_dir/socket-state.jsonl" \
		"$output_dir/socket-state.health.json"; do
		[[ -e $path && -f $path && ! -L $path ]] || {
			echo "missing $label socket-state artifact: $path" >&2
			exit 1
		}
	done
	local socket_events socket_published
	require_fixed '"status":"COMPLETE"' "$output_dir/socket-state.health.json"
	require_fixed '"event_dropped":0' "$output_dir/socket-state.health.json"
	require_fixed '"producer_barrier_complete":true' \
		"$output_dir/socket-state.health.json"
	require_async_producer_seal "$output_dir/socket-state.health.json"
	require_fixed '"drain_completed":true' "$output_dir/socket-state.health.json"
	require_fixed '"wal_durable":true' "$output_dir/socket-state.health.json"
	require_fixed '"reasons":[]' "$output_dir/socket-state.health.json"
	require_fixed '"unsupported_sockets":0' "$output_dir/socket-state.health.json"
	socket_events=$(json_u64 events_persisted "$output_dir/socket-state.health.json")
	socket_published=$(json_u64 event_published "$output_dir/socket-state.health.json")
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
	require_fixed '"socket_state_status":"COMPLETE"' \
		"$output_dir/artifact-manifest.json"
	for path in "$output_dir/linux-state-s0.json" \
		"$output_dir/linux-state-s1.json" \
		"$output_dir/linux-state-comparison.json"; do
		[[ -s $path ]] || { echo "missing $label Linux-state artifact: $path" >&2; exit 1; }
	done
	for domain_spec in \
		'mounts MOUNT' \
		'network NETWORK' \
		'process_residual PROCESS_RESIDUAL'; do
		read -r domain_key domain_name <<<"$domain_spec"
		require_linux_domain_complete "$domain_key" "$domain_name" \
			"$output_dir/linux-state-comparison.json"
	done
	require_fixed '"terminal_state":"NON_EMPTY_WITHIN_SCOPE"' \
		"$output_dir/linux-state-comparison.json"
	for domain in MOUNT NETWORK PROCESS_RESIDUAL; do
		require_fixed "\"domain\":\"$domain\"" \
			"$output_dir/linux-state-comparison.json"
	done
	require_report_top_level_string linux_state_evidence_status COMPLETE \
		"$artifact_manifest"
	{
		printf '{"expected_config":'
		tr -d '\n' <"$config"
		printf ',"expected_artifact_manifest_sha256":"%s","expected_report_sha256":"%s"}\n' \
			"$manifest_sha" "$report_sha"
	} >"$expectation"
	"$deployment_verify" --artifacts "$output_dir" --expectation "$expectation" \
		>"$verify_file"
	require_fixed '"verified":true' "$verify_file"
	require_fixed '"evidence_status":"INCOMPLETE"' "$verify_file"
	require_fixed '"socket_state_status":"COMPLETE"' "$verify_file"
	require_fixed "\"socket_state_event_count\":$socket_events" "$verify_file"
	require_report_top_level_string linux_state_evidence_status COMPLETE \
		"$verify_file"
	require_fixed "\"committed_artifact_total_bytes\":$committed_artifact_total_bytes" \
		"$verify_file"
}

mkdir -m 0700 "$fixture_root"
install -m 0755 "$live_fixture" "$docker_init"
install -m 0755 "$live_fixture" "$kata_shim"
install -m 0755 "$live_fixture" "$kata_qemu"

# Docker-shaped target: a real nested PID and mount namespace whose init has
# NSpid 1, rooted in a cgroup component bound to the full 64-hex container ID.
# The tmpfs and marker exist only in the private mount namespace; the host sees
# the empty underlying mountpoint throughout the run.
mkdir -m 0755 "$docker_scope"
mkdir -m 0700 "$docker_filesystem_root"
docker_mount_setup='mount --make-rprivate /
mount -t tmpfs -o mode=0700,nosuid,nodev,noexec bpf-observer-docker-private "$1"
printf "%s\n" docker-private-root >"$1/root-marker"
exec "$2" "$3"'
/bin/bash -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; exec "$2" --fork --pid --mount-proc /bin/bash -e -c "$3" _ "$4" "$5" "$6"' \
	_ "$docker_scope" /usr/bin/unshare "$docker_mount_setup" \
	"$docker_filesystem_root" "$docker_init" "$docker_id" &
docker_launcher_pid=$!
for attempt in $(seq 1 500); do
	for pid in $(cat "$docker_scope/cgroup.procs"); do
		[[ -r /proc/$pid/status && -e /proc/$pid/exe ]] || continue
		[[ $(awk '/^NSpid:/{print $NF}' "/proc/$pid/status") == 1 ]] || continue
		[[ $(readlink -f "/proc/$pid/exe") == "$docker_init" ]] || continue
		docker_init_pid=$pid
		break 2
	done
	sleep 0.01
done
[[ -n $docker_init_pid ]]
docker_mount_namespace_inode=$(stat -Lc %i "/proc/$docker_init_pid/ns/mnt")
[[ $docker_mount_namespace_inode =~ ^[1-9][0-9]*$ ]]
[[ $docker_mount_namespace_inode != $(stat -Lc %i /proc/self/ns/mnt) ]]
[[ -f /proc/$docker_init_pid/root$docker_filesystem_marker ]]
require_fixed docker-private-root "/proc/$docker_init_pid/root$docker_filesystem_marker"
[[ ! -e $docker_filesystem_marker ]]
awk '/^NSpid:/{print}' "/proc/$docker_init_pid/status" \
	>"$evidence_root/docker-live-synthetic.nspid.txt"
[[ $(awk '{print $NF}' "$evidence_root/docker-live-synthetic.nspid.txt") == 1 ]]
printf '1\n' >"$docker_scope/cgroup.freeze"
wait_frozen "$docker_scope" 1
docker_config=$evidence_root/docker-live-synthetic.config.json
docker_output=$evidence_root/docker-live-synthetic
docker_state_scope=$evidence_root/docker-live-synthetic.linux-state-scope.json
docker_filesystem_scope=$evidence_root/docker-live-synthetic.filesystem-scope.json
write_namespace_state_scope "$docker_init_pid" "$docker_state_scope"
write_filesystem_scope "$docker_filesystem_root" "$docker_filesystem_scope"
docker_state_scope_json=$(tr -d '\n' <"$docker_state_scope")
docker_filesystem_scope_json=$(tr -d '\n' <"$docker_filesystem_scope")
printf '%s\n' "{\"protocol_version\":2,\"deployment\":{\"deployment_kind\":\"DOCKER\",\"configuration\":{\"container_id\":\"$docker_id\",\"init_pid\":$docker_init_pid,\"expected_cgroup_path\":\"$docker_cgroup_path\",\"limits\":{\"max_proc_entries\":131072,\"max_cgroup_nodes\":4096,\"max_cgroup_depth\":64,\"max_open_fds_per_process\":8192}}},\"recorder_object_path\":\"$effect_object\",\"recorder_object_sha256\":\"$effect_sha256\",\"lifecycle_object_path\":\"$lifecycle_object\",\"lifecycle_object_sha256\":\"$lifecycle_sha256\",\"output_directory\":\"$docker_output\",\"run_id\":\"docker-live-synthetic\",\"epoch\":1,\"profile\":\"full\",\"object_resolution_mode\":\"KERNEL_OBJECT_EXPANDED_PARTIAL\",\"bpf_state_scope\":null,\"filesystem_state_scope\":$docker_filesystem_scope_json,\"linux_state_scope\":$docker_state_scope_json,\"poll_interval_ms\":20,\"drain_timeout_ms\":5000}" >"$docker_config"
run_observer docker-live-synthetic docker-live-synthetic "$docker_scope" \
	"$docker_child" "$docker_config" "$docker_output"
docker_manifest=$docker_output/deployment-manifest.json
require_fixed '"deployment_kind":"DOCKER"' "$docker_manifest"
require_fixed '"source_trust":"KERNEL_FILESYSTEMS_VERIFIED"' "$docker_manifest"
require_fixed '"identity_strength":"KERNEL_ANCHORED"' "$docker_manifest"
require_fixed '"role":"DOCKER_INIT"' "$docker_manifest"
require_manifest_process_u64 DOCKER_INIT mount_namespace_id \
	"$docker_mount_namespace_inode" "$docker_manifest"
docker_ready=$evidence_root/docker-live-synthetic.ready.json
docker_verify=$evidence_root/docker-live-synthetic.verify.json
for path in "$docker_output/filesystem-state-s0.json" \
	"$docker_output/filesystem-state-s1.json" \
	"$docker_output/filesystem-state-comparison.json"; do
	[[ -s $path ]] || { echo "missing Docker filesystem-state artifact: $path" >&2; exit 1; }
done
for snapshot in "$docker_output/filesystem-state-s0.json" \
	"$docker_output/filesystem-state-s1.json"; do
	require_fixed '"mount_namespace_capture_source":"RETAINED_FILE_DESCRIPTOR"' "$snapshot"
	require_fixed "\"mount_namespace_inode\":$docker_mount_namespace_inode" "$snapshot"
	require_filesystem_entry_content_status root-marker CAPTURED "$snapshot"
done
require_fixed '"endpoint_difference":"OBSERVED_IDENTICAL"' \
	"$docker_output/filesystem-state-comparison.json"
require_filesystem_comparison_completeness COMPLETE \
	"$docker_output/filesystem-state-comparison.json"
require_fixed '"filesystem_state_scope":{' "$docker_output/observation-contract.json"
require_fixed '"filesystem_state_scope_sha256":"' "$docker_ready"
require_fixed '"filesystem_state_scope_sha256":"' "$docker_output/artifact-manifest.json"
require_fixed '"filesystem_state_verdict":"INCONCLUSIVE"' \
	"$docker_output/artifact-manifest.json"
require_fixed '"filesystem_state":{' \
	"$docker_output/deployment-observation-report.json"
require_fixed '"filesystem_state_scope_sha256":"' "$docker_verify"
require_fixed '"filesystem_state_verdict":"INCONCLUSIVE"' "$docker_verify"
[[ ! -e $docker_filesystem_marker ]]
kill_scope "$docker_scope"
wait "$docker_launcher_pid" 2>/dev/null || true
docker_launcher_pid=
[[ ! -e $docker_filesystem_marker ]]
rmdir "$docker_filesystem_root"

# Kata-shaped target: real host PIDs/cgroup/sysfs identities, a real regular
# disk object, and real TAP queues resolved from the exact QEMU process's
# fdinfo. The named
# processes are inert fixtures; no Kata guest is created or entered.
truncate -s 1048576 "$kata_disk"
if [[ ! -e /dev/net/tun ]]; then
	mkdir -p /dev/net
	mknod -m 0600 /dev/net/tun c 10 200
	created_tun_node=1
fi
[[ -c /dev/net/tun ]]
ip tuntap add dev "$kata_tap" mode tap
ip tuntap add dev "$kata_tap_multi" mode tap multi_queue
ip link set dev "$kata_tap" up
ip link set dev "$kata_tap_multi" up
mkdir -m 0755 "$kata_scope"
/bin/bash -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; exec "$2" "$3"' \
	_ "$kata_scope" "$kata_shim" "$kata_id" &
kata_shim_pid=$!
/bin/bash -c 'printf "%s\n" "$BASHPID" >"$1/cgroup.procs"; exec "$2" "$3" -drive "file=$4,format=raw" -netdev "tap,id=net0,fd=9" -netdev "tap,id=net1,fds=10:11" "--fixture-tap-fd=9:$5" "--fixture-tap-mq-fd=10:$6" "--fixture-tap-mq-fd=11:$6"' \
	_ "$kata_scope" "$kata_qemu" "$kata_id" "$kata_disk" "$kata_tap" \
	"$kata_tap_multi" &
kata_qemu_pid=$!
kata_shim_starttime=$(wait_final_fixture_process kata-shim "$kata_shim_pid" \
	"$kata_shim" "$kata_shim" "$kata_id")
kata_qemu_starttime=$(wait_final_fixture_process kata-hypervisor "$kata_qemu_pid" \
	"$kata_qemu" "$kata_qemu" "$kata_id" \
	"file=$kata_disk,format=raw" \
	"tap,id=net0,fd=9" "tap,id=net1,fds=10:11" \
	"--fixture-tap-fd=9:$kata_tap" \
	"--fixture-tap-mq-fd=10:$kata_tap_multi" \
	"--fixture-tap-mq-fd=11:$kata_tap_multi")
[[ $kata_shim_starttime =~ ^[0-9]+$ && $kata_qemu_starttime =~ ^[0-9]+$ ]]
printf '1\n' >"$kata_scope/cgroup.freeze"
wait_frozen "$kata_scope" 1
[[ $(proc_starttime "$kata_shim_pid") == "$kata_shim_starttime" ]]
[[ $(proc_starttime "$kata_qemu_pid") == "$kata_qemu_starttime" ]]
[[ $(readlink -f "/proc/$kata_shim_pid/exe") == "$kata_shim" ]]
[[ $(readlink -f "/proc/$kata_qemu_pid/exe") == "$kata_qemu" ]]
grep -Fxq -- "$kata_shim_pid" "$kata_scope/cgroup.procs"
grep -Fxq -- "$kata_qemu_pid" "$kata_scope/cgroup.procs"
grep -Fxq -- $'iff:\t'$kata_tap "/proc/$kata_qemu_pid/fdinfo/9"
grep -Fxq -- $'iff:\t'$kata_tap_multi "/proc/$kata_qemu_pid/fdinfo/10"
grep -Fxq -- $'iff:\t'$kata_tap_multi "/proc/$kata_qemu_pid/fdinfo/11"
{
	printf 'shim_pid=%s shim_starttime=%s shim_exe=%s\n' \
		"$kata_shim_pid" "$kata_shim_starttime" \
		"$(readlink -f "/proc/$kata_shim_pid/exe")"
	printf 'hypervisor_pid=%s hypervisor_starttime=%s hypervisor_exe=%s\n' \
		"$kata_qemu_pid" "$kata_qemu_starttime" \
		"$(readlink -f "/proc/$kata_qemu_pid/exe")"
	printf 'cgroup=%s\n' "$kata_cgroup_path"
} >"$evidence_root/kata-live-synthetic.pre-freeze-identity.txt"
kata_config=$evidence_root/kata-live-synthetic.config.json
kata_output=$evidence_root/kata-live-synthetic
kata_state_scope=$evidence_root/kata-live-synthetic.linux-state-scope.json
write_namespace_state_scope "$kata_shim_pid" "$kata_state_scope"
kata_state_scope_json=$(tr -d '\n' <"$kata_state_scope")
printf '%s\n' "{\"protocol_version\":2,\"deployment\":{\"deployment_kind\":\"KATA_HOST\",\"configuration\":{\"sandbox_id\":\"$kata_id\",\"shim_pid\":$kata_shim_pid,\"expected_hypervisor_pid\":$kata_qemu_pid,\"additional_host_pids\":[],\"expected_cgroup_path\":\"$kata_cgroup_path\",\"limits\":{\"max_proc_entries\":131072,\"max_cgroup_nodes\":4096,\"max_cgroup_depth\":64,\"max_open_fds_per_process\":8192}}},\"recorder_object_path\":\"$effect_object\",\"recorder_object_sha256\":\"$effect_sha256\",\"lifecycle_object_path\":\"$lifecycle_object\",\"lifecycle_object_sha256\":\"$lifecycle_sha256\",\"output_directory\":\"$kata_output\",\"run_id\":\"kata-live-synthetic\",\"epoch\":1,\"profile\":\"full\",\"object_resolution_mode\":\"KERNEL_OBJECT_EXPANDED_PARTIAL\",\"bpf_state_scope\":null,\"filesystem_state_scope\":null,\"linux_state_scope\":$kata_state_scope_json,\"poll_interval_ms\":20,\"drain_timeout_ms\":5000}" >"$kata_config"
run_observer kata-live-synthetic kata-live-synthetic "$kata_scope" \
	"$kata_child" "$kata_config" "$kata_output"
kata_manifest=$kata_output/deployment-manifest.json
require_fixed '"deployment_kind":"KATA_HOST"' "$kata_manifest"
require_fixed '"source_trust":"KERNEL_FILESYSTEMS_VERIFIED"' "$kata_manifest"
require_fixed '"identity_strength":"KERNEL_ANCHORED"' "$kata_manifest"
require_fixed '"role":"KATA_SHIM"' "$kata_manifest"
require_fixed '"role":"KATA_HYPERVISOR"' "$kata_manifest"
require_fixed '"kind":"VIRTUAL_DISK_FILE"' "$kata_manifest"
require_fixed '"kind":"TAP_INTERFACE"' "$kata_manifest"
require_fixed '"resolution":"RESOLVED"' "$kata_manifest"
require_fixed '"network_binding":"QEMU_FD"' "$kata_manifest"
require_fixed '"network_binding":"QEMU_FDS"' "$kata_manifest"
require_fixed '"kata_guest_entered":false' "$kata_manifest"
require_fixed '"kata_host_backends_discovered_from_qemu_argv":true' "$kata_manifest"
require_fixed '"kata_tap_fdinfo_evidence_present":true' "$kata_manifest"

printf '%s\n' '{"schema_version":1,"status":"PASS","fixture_kind":"LIVE_KERNEL_INTERFACES_SYNTHETIC_RUNTIME_IDENTITIES","live_procfs":true,"live_cgroup_v2":true,"live_pid_namespace":true,"live_sysfs":true,"real_tap_device":true,"real_tap_fdinfo":true,"qemu_fd_and_fds_argv":true,"real_docker_runtime_e2e":false,"real_kata_runtime_e2e":false,"kata_guest_entered":false}' \
	>"$evidence_root/deployment-live-synthetic-status.json"

kill_scope "$kata_scope"
wait "$kata_shim_pid" 2>/dev/null || true
wait "$kata_qemu_pid" 2>/dev/null || true
kata_shim_pid=
kata_qemu_pid=
ip link del "$kata_tap"
ip link del "$kata_tap_multi"
rm -rf -- "$fixture_root"
[[ $created_tun_node -eq 0 ]] || rm -f -- /dev/net/tun
created_tun_node=0
trap - EXIT

printf 'DEPLOYMENT_LIVE_SYNTHETIC_VM_E2E_PASS effect_sha256=%s lifecycle_sha256=%s\n' \
	"$effect_sha256" "$lifecycle_sha256"
