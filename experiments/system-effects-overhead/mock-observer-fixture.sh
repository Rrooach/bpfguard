#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

# Non-privileged protocol fixture used only by check.sh. It emulates the small
# subset of `observe-effects` output consumed by observer-wrapper.sh.

set -euo pipefail
umask 0077

[[ "${1:-}" == observe-effects ]] || exit 2
shift
OUTPUT=
PROFILE=
OBJECT_RESOLUTION=
while [[ $# -gt 0 ]]; do
	case "$1" in
	--output-dir) OUTPUT="$2"; shift 2 ;;
	--profile) PROFILE="$2"; shift 2 ;;
	--object-resolution) OBJECT_RESOLUTION="$2"; shift 2 ;;
	--recorder-object|--expected-recorder-sha256|--cgroup-root|--timeout-ms|--drain-timeout-ms)
		shift 2
		;;
	--)
		shift
		break
		;;
	*) exit 2 ;;
	esac
done
[[ -n "$OUTPUT" && -n "$PROFILE" &&
	( "$OBJECT_RESOLUTION" == user-input ||
	  "$OBJECT_RESOLUTION" == kernel-file-open-partial ||
	  "$OBJECT_RESOLUTION" == kernel-file-open-write-partial ) &&
	$# -gt 0 && ! -e "$OUTPUT" ]] || exit 2
mkdir -m 0700 "$OUTPUT"
set +e
"$@" > "$OUTPUT/workload.stdout" 2> "$OUTPUT/workload.stderr"
workload_status=$?
set -e
readonly POLICY_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
readonly OBJECT_SHA256="$(sha256sum "${BPF_STATE_OBSERVER_EFFECTS_OBJECT:?}" | awk '{print $1}')"
case "$OBJECT_RESOLUTION" in
user-input) readonly OBJECT_RESOLUTION_WIRE=USER_INPUT ;;
kernel-file-open-partial) readonly OBJECT_RESOLUTION_WIRE=KERNEL_FILE_OPEN_PARTIAL ;;
kernel-file-open-write-partial) readonly OBJECT_RESOLUTION_WIRE=KERNEL_FILE_OPEN_WRITE_PARTIAL ;;
esac
readonly ATTRIBUTION='{"protocol_version":1,"direct_claim":"SELECTED_NATIVE_SYSCALL_CALLER_IN_EXACT_CGROUP_AT_ENTRY","mode":"DIRECT","authority":"KERNEL_CURRENT_CGROUP_ID_AT_SYSCALL_ENTRY","subject":"RUN_EXECUTION_DOMAIN","component":"UNCLASSIFIED_CGROUP_MEMBER","delegated_effects":"NOT_OBSERVED","causal_status":"CAUSAL_NOT_ESTABLISHED"}'
printf '%s\n' "{\"run_status\":\"FINALIZED\",\"run_id\":\"wrapper-fixture\",\"run_epoch\":1,\"policy_sha256\":\"$POLICY_SHA256\",\"policy_profile\":\"$PROFILE\",\"object_resolution_mode\":\"$OBJECT_RESOLUTION_WIRE\",\"expected_recorder_object_sha256\":\"$OBJECT_SHA256\",\"loaded_recorder_object_sha256\":\"$OBJECT_SHA256\",\"transport_status\":\"COMPLETE\",\"workload_exit_code\":$workload_status,\"workload_signal\":null,\"attribution_contract\":$ATTRIBUTION,\"coverage\":{\"operation_events_are_state_diff\":false}}" > "$OUTPUT/system-effects.manifest.json"
printf '%s\n' "{\"profile\":\"$PROFILE\",\"policy_sha256\":\"$POLICY_SHA256\"}" > "$OUTPUT/system-effects.policy.json"
printf '%s\n' "{\"run_id\":\"wrapper-fixture\",\"run_epoch\":1,\"profile\":\"$PROFILE\",\"object_resolution_mode\":\"$OBJECT_RESOLUTION_WIRE\",\"transport_status\":\"COMPLETE\",\"coverage_status\":\"PARTIAL\",\"object_resolution_status\":\"PARTIAL\",\"event_published\":2,\"event_dropped\":0,\"events_persisted\":2,\"pending_remaining\":0,\"userspace_failures\":0,\"fatal_kernel_flags\":0,\"producer_barrier_complete\":true,\"drain_completed\":true,\"wal_durable\":true}" > "$OUTPUT/system-effects.health.json"
printf 'fixture-wal\n' > "$OUTPUT/system-effects.raw.bin"
printf '%s\n' '{"kind":"OPERATION_ATTEMPT"}' '{"kind":"OPERATION_RESULT"}' > "$OUTPUT/system-effects.jsonl"
printf '%s\n' '{"transport_status":"COMPLETE"}'
