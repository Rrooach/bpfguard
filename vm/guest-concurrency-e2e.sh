#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Run only inside a disposable privileged Guest.  The workload supplies
# independent TID, inode and simultaneous-blocking ground truth; the Host
# analyzer checks it against both evidence streams after offline verification.

set -euo pipefail

usage()
{
	cat >&2 <<'EOF'
usage: guest-concurrency-e2e.sh OBSERVER EFFECT_OBJECT EFFECT_SHA256 LIFECYCLE_OBJECT LIFECYCLE_SHA256 CONCURRENCY_WORKLOAD NEW_EVIDENCE_ROOT
EOF
	exit 2
}

[[ $# -eq 7 && ${EUID} -eq 0 ]] || usage
observer=$1
effect_object=$2
effect_sha256=$3
lifecycle_object=$4
lifecycle_sha256=$5
workload=$6
evidence_root=$7
cgroup_root=/sys/fs/cgroup/bpf-observer-concurrency-e2e
object_mode=kernel-object-expanded-partial
scratch=

for path in "$observer" "$workload"; do
	[[ $path == /* && -f $path && -x $path && ! -L $path ]] || {
		echo "missing absolute executable: $path" >&2
		exit 2
	}
done
for path in "$effect_object" "$lifecycle_object"; do
	[[ $path == /* && -f $path && ! -L $path ]] || {
		echo "missing absolute BPF object: $path" >&2
		exit 2
	}
done
for digest in "$effect_sha256" "$lifecycle_sha256"; do
	[[ $digest =~ ^[0-9a-f]{64}$ ]] || usage
done
[[ $(sha256sum "$effect_object" | awk '{print $1}') == "$effect_sha256" ]]
[[ $(sha256sum "$lifecycle_object" | awk '{print $1}') == "$lifecycle_sha256" ]]
[[ $evidence_root == /* && ! -e $evidence_root && ! -L $evidence_root ]] || {
	echo "EVIDENCE_ROOT must be a new absolute path" >&2
	exit 2
}
[[ ! -e $cgroup_root ]] || {
	echo "dedicated concurrency cgroup already exists" >&2
	exit 2
}
for command in awk find grep sha256sum stat; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing Guest command: $command" >&2
		exit 2
	}
done
[[ -s /sys/kernel/btf/vmlinux ]]
grep -qw bpf /sys/kernel/security/lsm
[[ $(stat -f -c %t /sys/fs/cgroup) == 63677270 ]]

require_fixed()
{
	local needle=$1
	local file=$2
	grep -Fq -- "$needle" "$file" || {
		echo "missing expected evidence in $file: $needle" >&2
		exit 1
	}
}

json_u64()
{
	local key=$1
	local file=$2
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
	' "$file"
}

cleanup()
{
	set +e
	if [[ -n $scratch && -d $scratch ]]; then
		find "$scratch" -maxdepth 1 -type f -delete
		rmdir "$scratch" 2>/dev/null
	fi
	if [[ -d $cgroup_root ]]; then
		printf '1\n' >"$cgroup_root/cgroup.kill" 2>/dev/null
		find "$cgroup_root" -depth -type d -exec rmdir -- {} \; 2>/dev/null
	fi
	set -e
}
trap cleanup EXIT

mkdir -m 0700 "$evidence_root"
"$observer" doctor --recorder-object "$effect_object" \
	--process-lifecycle-object "$lifecycle_object" \
	--cgroup-root /sys/fs/cgroup --object-resolution "$object_mode" \
	--output "$evidence_root/doctor.json"
require_fixed '"ready_for_runtime": true' "$evidence_root/doctor.json"

run_case()
{
	local label=$1
	local threads=$2
	local iterations=$3
	local case_dir=$evidence_root/$label
	local run_dir=$case_dir/artifacts

	scratch=/tmp/bpf-observer-concurrency-$label-$$
	[[ ! -e $scratch && ! -e $case_dir ]]
	mkdir -m 0700 "$case_dir" "$scratch"
	"$observer" observe-effects \
		--recorder-object "$effect_object" \
		--expected-recorder-sha256 "$effect_sha256" \
		--process-lifecycle-object "$lifecycle_object" \
		--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
		--output-dir "$run_dir" --cgroup-root "$cgroup_root" \
		--run-id "concurrency-$label" --run-epoch 1 --profile balanced \
		--timeout-ms 180000 --drain-timeout-ms 30000 \
		--object-resolution "$object_mode" \
		-- "$workload" --threads "$threads" --iterations "$iterations" \
			--scratch-dir "$scratch" \
		>"$case_dir/outcome.json" 2>"$case_dir/observer.stderr"

	require_fixed '"run_status": "FINALIZED"' \
		"$run_dir/system-effects.manifest.json"
	require_fixed '"transport_status": "COMPLETE"' \
		"$run_dir/system-effects.health.json"
	require_fixed '"event_dropped": 0' "$run_dir/system-effects.health.json"
	require_fixed '"pending_remaining": 0' "$run_dir/system-effects.health.json"
	require_fixed '"status": "PARTIAL"' \
		"$run_dir/process-lifecycle.health.json"
	require_fixed '"event_dropped": 0' \
		"$run_dir/process-lifecycle.health.json"

	"$observer" verify-effects --run-dir "$run_dir" \
		--expected-recorder-sha256 "$effect_sha256" \
		--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
		--expected-profile balanced \
		--expected-object-resolution "$object_mode" \
		>"$case_dir/verify.json"
	require_fixed '"transport_complete": true' "$case_dir/verify.json"
	require_fixed '"process_lifecycle_status": "PARTIAL"' \
		"$case_dir/verify.json"
	require_fixed '"process_lifecycle_artifacts_verified": true' \
		"$case_dir/verify.json"
	require_fixed '"syscall_lifecycle_identity_correlation_verified": true' \
		"$case_dir/verify.json"

	find "$scratch" -maxdepth 1 -type f -delete
	rmdir "$scratch"
	scratch=
	printf 'CONCURRENCY_CASE_GUEST_PASS case=%s threads=%s iterations=%s\n' \
		"$label" "$threads" "$iterations"
}

run_overload_case()
{
	local label=overload
	local threads=64
	local iterations=512
	local case_dir=$evidence_root/$label
	local run_dir=$case_dir/artifacts
	local dropped failures

	scratch=/tmp/bpf-observer-concurrency-$label-$$
	[[ ! -e $scratch && ! -e $case_dir ]]
	mkdir -m 0700 "$case_dir" "$scratch"
	"$observer" observe-effects \
		--recorder-object "$effect_object" \
		--expected-recorder-sha256 "$effect_sha256" \
		--process-lifecycle-object "$lifecycle_object" \
		--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
		--output-dir "$run_dir" --cgroup-root "$cgroup_root" \
		--run-id "concurrency-$label" --run-epoch 1 --profile balanced \
		--timeout-ms 180000 --drain-timeout-ms 30000 \
		--object-resolution "$object_mode" --allow-incomplete-transport \
		-- "$workload" --threads "$threads" --iterations "$iterations" \
			--scratch-dir "$scratch" \
		>"$case_dir/outcome.json" 2>"$case_dir/observer.stderr"

	if grep -Fq '"transport_status": "COMPLETE"' \
		"$run_dir/system-effects.health.json"; then
		"$observer" verify-effects --run-dir "$run_dir" \
			--expected-recorder-sha256 "$effect_sha256" \
			--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
			--expected-profile balanced \
			--expected-object-resolution "$object_mode" \
			>"$case_dir/verify.json" 2>"$case_dir/verify.stderr"
		printf '%s\n' '{"schema_version":1,"outcome":"COMPLETE"}' \
			>"$case_dir/overload-result.json"
	else
		require_fixed '"transport_status": "INCOMPLETE"' \
			"$run_dir/system-effects.health.json"
		dropped=$(json_u64 event_dropped "$run_dir/system-effects.health.json")
		failures=$(json_u64 userspace_failures \
			"$run_dir/system-effects.health.json")
		[[ $dropped -gt 0 || $failures -gt 0 ]] || {
			echo "incomplete overload has no loss/failure accounting" >&2
			exit 1
		}
		if "$observer" verify-effects --run-dir "$run_dir" \
			--expected-recorder-sha256 "$effect_sha256" \
			--expected-process-lifecycle-sha256 "$lifecycle_sha256" \
			--expected-profile balanced \
			--expected-object-resolution "$object_mode" \
			>"$case_dir/verify.json" 2>"$case_dir/verify.stderr"; then
			echo "offline verifier accepted incomplete overload evidence" >&2
			exit 1
		fi
		[[ -s $case_dir/verify.stderr ]]
		printf '%s\n' \
			"{\"schema_version\":1,\"outcome\":\"INCOMPLETE_FAIL_CLOSED\",\"event_dropped\":$dropped,\"userspace_failures\":$failures}" \
			>"$case_dir/overload-result.json"
	fi
	find "$scratch" -maxdepth 1 -type f -delete
	rmdir "$scratch"
	scratch=
	printf 'CONCURRENCY_OVERLOAD_GUEST_PASS threads=%s iterations=%s outcome=%s\n' \
		"$threads" "$iterations" \
		"$(grep -o 'INCOMPLETE_FAIL_CLOSED\|COMPLETE' "$case_dir/overload-result.json")"
}

run_case correctness 8 64
run_case parallel64 64 64
run_overload_case
cleanup
trap - EXIT
printf 'CONCURRENCY_GUEST_E2E_PASS effect_sha256=%s lifecycle_sha256=%s\n' \
	"$effect_sha256" "$lifecycle_sha256"
