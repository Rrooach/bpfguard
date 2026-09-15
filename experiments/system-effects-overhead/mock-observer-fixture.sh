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
LIFECYCLE_OBJECT=
LIFECYCLE_SHA256=
while [[ $# -gt 0 ]]; do
	case "$1" in
	--output-dir) OUTPUT="$2"; shift 2 ;;
	--profile) PROFILE="$2"; shift 2 ;;
	--object-resolution) OBJECT_RESOLUTION="$2"; shift 2 ;;
	--process-lifecycle-object) LIFECYCLE_OBJECT="$2"; shift 2 ;;
	--expected-process-lifecycle-sha256) LIFECYCLE_SHA256="$2"; shift 2 ;;
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
	  "$OBJECT_RESOLUTION" == kernel-file-open-write-partial ||
	  "$OBJECT_RESOLUTION" == kernel-object-expanded-partial ) &&
	$# -gt 0 && ! -e "$OUTPUT" ]] || exit 2
if [[ "$OBJECT_RESOLUTION" == kernel-object-expanded-partial ]]; then
	[[ -f "$LIFECYCLE_OBJECT" && "$LIFECYCLE_SHA256" =~ ^[0-9a-f]{64}$ ]] || exit 2
else
	[[ -z "$LIFECYCLE_OBJECT" && -z "$LIFECYCLE_SHA256" ]] || exit 2
fi
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
kernel-object-expanded-partial) readonly OBJECT_RESOLUTION_WIRE=KERNEL_OBJECT_EXPANDED_PARTIAL ;;
esac
readonly ATTRIBUTION='{"protocol_version":1,"direct_claim":"SELECTED_NATIVE_SYSCALL_CALLER_IN_EXACT_CGROUP_AT_ENTRY","mode":"DIRECT","authority":"KERNEL_CURRENT_CGROUP_ID_AT_SYSCALL_ENTRY","subject":"RUN_EXECUTION_DOMAIN","component":"UNCLASSIFIED_CGROUP_MEMBER","delegated_effects":"NOT_OBSERVED","causal_status":"CAUSAL_NOT_ESTABLISHED"}'
LIFECYCLE_FRAGMENT=
SOCKET_MANIFEST_FRAGMENT=
SOCKET_HEALTH_FRAGMENT=
if [[ "$OBJECT_RESOLUTION" == kernel-object-expanded-partial ]]; then
	LIFECYCLE_FRAGMENT=",\"process_lifecycle\":{\"protocol_version\":2,\"expected_object_sha256\":\"$LIFECYCLE_SHA256\",\"loaded_object_sha256\":\"$LIFECYCLE_SHA256\",\"status\":\"PARTIAL\",\"event_published\":3,\"event_dropped\":0,\"task_read_failed\":0}"
	SOCKET_MANIFEST_FRAGMENT=',"socket_state":{"protocol_version":1,"wal_artifact":"socket-state.raw.bin","jsonl_artifact":"socket-state.jsonl","health_artifact":"socket-state.health.json","status":"COMPLETE","event_published":0,"event_dropped":0,"destroy_events_persisted":0,"owners_retired_at_barrier":0}'
	SOCKET_HEALTH_FRAGMENT=',"socket_state":{"schema_version":1,"run_id":"wrapper-fixture","boot_id":"00000000-0000-0000-0000-000000000001","run_epoch":1,"cgroup_id":1,"cgroup_match_mode":"EXACT_CURRENT","status":"COMPLETE","event_attempted":0,"event_published":0,"event_dropped":0,"events_persisted":0,"final_event_seq":0,"destroy_events_persisted":0,"owners_retired_at_barrier":0,"owner_insert_failed":0,"owner_conflict":0,"owner_delete_failed":0,"state_read_failed":0,"userspace_failures":0,"owner_remaining":0,"producer_barrier_complete":true,"drain_completed":true,"wal_durable":true,"reasons":[]}'
fi
printf '%s\n' "{\"run_status\":\"FINALIZED\",\"run_id\":\"wrapper-fixture\",\"boot_id\":\"00000000-0000-0000-0000-000000000001\",\"run_epoch\":1,\"cgroup_id\":1,\"policy_sha256\":\"$POLICY_SHA256\",\"policy_profile\":\"$PROFILE\",\"object_resolution_mode\":\"$OBJECT_RESOLUTION_WIRE\",\"expected_recorder_object_sha256\":\"$OBJECT_SHA256\",\"loaded_recorder_object_sha256\":\"$OBJECT_SHA256\"$LIFECYCLE_FRAGMENT$SOCKET_MANIFEST_FRAGMENT,\"transport_status\":\"COMPLETE\",\"workload_exit_code\":$workload_status,\"workload_signal\":null,\"attribution_contract\":$ATTRIBUTION,\"coverage\":{\"operation_events_are_state_diff\":false}}" > "$OUTPUT/system-effects.manifest.json"
printf '%s\n' "{\"profile\":\"$PROFILE\",\"policy_sha256\":\"$POLICY_SHA256\"}" > "$OUTPUT/system-effects.policy.json"
printf '%s\n' "{\"run_id\":\"wrapper-fixture\",\"run_epoch\":1,\"profile\":\"$PROFILE\",\"object_resolution_mode\":\"$OBJECT_RESOLUTION_WIRE\",\"transport_status\":\"COMPLETE\",\"coverage_status\":\"PARTIAL\",\"object_resolution_status\":\"PARTIAL\",\"event_published\":2,\"event_dropped\":0,\"events_persisted\":2,\"pending_remaining\":0,\"userspace_failures\":0,\"fatal_kernel_flags\":0,\"producer_barrier_complete\":true,\"drain_completed\":true,\"wal_durable\":true$SOCKET_HEALTH_FRAGMENT}" > "$OUTPUT/system-effects.health.json"
printf 'fixture-wal\n' > "$OUTPUT/system-effects.raw.bin"
printf '%s\n' '{"kind":"OPERATION_ATTEMPT"}' '{"kind":"OPERATION_RESULT"}' > "$OUTPUT/system-effects.jsonl"
if [[ "$OBJECT_RESOLUTION" == kernel-object-expanded-partial ]]; then
	printf '%s\n' '{"fixture":"fork"}' '{"fixture":"exec"}' '{"fixture":"exit"}' > "$OUTPUT/process-lifecycle.jsonl"
	printf 'fixture-lifecycle-wal\n' > "$OUTPUT/process-lifecycle.raw.bin"
	printf '%s\n' '{"schema_version":2,"run_id":"wrapper-fixture","run_epoch":1,"cgroup_id":1,"status":"PARTIAL","event_attempted":3,"event_published":3,"event_dropped":0,"events_persisted":3,"task_read_failed":0,"exec_path_read_failed":0,"exec_path_truncated":0,"userspace_failures":0,"producer_barrier_complete":true,"drain_completed":true,"wal_durable":true,"poll_calls":1,"maximum_events_per_poll":3,"callback_queue_high_water":3,"callback_queue_capacity":4096,"lineage":{"event_count":3,"task_identities":1,"exited_task_identities":1,"group_dead_exits":1,"enrollment":{"initial_task_ledger_present":false,"initial_tasks_enrolled":0,"migration_hook_present":false,"clone_into_cgroup_covered":false,"migration_enrolled_task_identities":0,"fork_enrolled_task_identities":1,"exec_introduced_task_identities":0,"exit_introduced_task_identities":0,"forks_with_unenrolled_parent":1,"complete":false},"correlation":"PARTIAL_FORK_EXEC_EXIT_BY_BOOT_ID_PID_START_BOOTTIME_AND_EXEC_OLD_PID"},"reasons":[],"limitations":["process-lifecycle schema v2 has no authoritative S0 task/thread enrollment ledger and no cgroup migration or CLONE_INTO_CGROUP enrollment hook; EXEC/EXIT may introduce identities during replay, so whole-tree lifecycle association is PARTIAL"]}' > "$OUTPUT/process-lifecycle.health.json"
	: > "$OUTPUT/socket-state.jsonl"
	: > "$OUTPUT/socket-state.raw.bin"
	printf '%s\n' '{"schema_version":1,"run_id":"wrapper-fixture","boot_id":"00000000-0000-0000-0000-000000000001","run_epoch":1,"cgroup_id":1,"cgroup_match_mode":"EXACT_CURRENT","status":"COMPLETE","event_attempted":0,"event_published":0,"event_dropped":0,"events_persisted":0,"final_event_seq":0,"destroy_events_persisted":0,"owners_retired_at_barrier":0,"owner_insert_failed":0,"owner_conflict":0,"owner_delete_failed":0,"state_read_failed":0,"userspace_failures":0,"owner_remaining":0,"producer_barrier_complete":true,"drain_completed":true,"wal_durable":true,"reasons":[]}' > "$OUTPUT/socket-state.health.json"
fi
printf '%s\n' '{"transport_status":"COMPLETE"}'
