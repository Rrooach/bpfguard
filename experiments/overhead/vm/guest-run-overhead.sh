#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 0077

if [[ $# -ne 3 ]]; then
	echo "usage: $0 INPUT_ROOT RESULTS_ROOT REPETITIONS" >&2
	exit 2
fi

readonly INPUT_ROOT="$1"
readonly RESULTS_ROOT="$2"
readonly REPETITIONS="$3"
readonly OBSERVER="$INPUT_ROOT/bpf-state-observer"
readonly RECORDER="$INPUT_ROOT/recorder.bpf.o"
readonly WORKLOAD="$INPUT_ROOT/overhead-bench"
readonly MEASURE="$INPUT_ROOT/measure-command"
readonly SCOPE="$INPUT_ROOT/scope.json"
readonly CGROUP_ROOT=/sys/fs/cgroup/bpf-overhead
readonly WARMUPS=3
readonly WORKLOAD_CPU=1
readonly CONTROLLER_CPU=0
readonly BPF_BATCH_SIZE=128
readonly BPF_PAUSE_US=1000

[[ "$INPUT_ROOT" == /opt/bpf-overhead ]] || {
	echo "unexpected input root: $INPUT_ROOT" >&2
	exit 2
}
[[ "$RESULTS_ROOT" =~ ^/var/lib/bpf-overhead/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || {
	echo "unexpected results root: $RESULTS_ROOT" >&2
	exit 2
}
if [[ ! "$REPETITIONS" =~ ^[1-9][0-9]*$ ]] ||
	(( REPETITIONS < 12 || REPETITIONS > 48 || REPETITIONS % 6 != 0 )); then
	echo "repetitions must be one of 12, 18, 24, 30, 36, 42, or 48" >&2
	exit 2
fi
for path in "$OBSERVER" "$RECORDER" "$WORKLOAD" "$MEASURE" "$SCOPE"; do
	[[ -f "$path" && ! -L "$path" ]] || {
		echo "missing or unsafe benchmark input: $path" >&2
		exit 1
	}
done
for command in awk date getconf grep install nproc sha256sum stat taskset uname wc; do
	command -v "$command" >/dev/null || {
		echo "missing Guest dependency: $command" >&2
		exit 1
	}
done
[[ "$(stat -f -c %T /sys/fs/cgroup)" == cgroup2fs ]]
[[ "$(stat -f -c %T /sys/kernel/tracing)" == tracefs ]]
[[ "$(stat -f -c %T /sys/fs/bpf)" == bpf_fs ]]
[[ "$(getconf _NPROCESSORS_ONLN)" -ge 2 ]]
[[ ! -e "$RESULTS_ROOT" && ! -L "$RESULTS_ROOT" ]] || {
	echo "refusing to reuse benchmark results: $RESULTS_ROOT" >&2
	exit 1
}
install -d -o root -g root -m 0700 "$RESULTS_ROOT"
ulimit -l unlimited

readonly RECORDER_SHA256="$(sha256sum "$RECORDER" | awk '{print $1}')"
[[ "$RECORDER_SHA256" =~ ^[a-f0-9]{64}$ ]]

{
	echo 'schema_version=1'
	echo "boot_id=$(< /proc/sys/kernel/random/boot_id)"
	echo "kernel=$(uname -r)"
	echo "online_cpus=$(< /sys/devices/system/cpu/online)"
	echo "reported_cpus=$(nproc)"
	echo "controller_cpu=$CONTROLLER_CPU"
	echo "workload_cpu=$WORKLOAD_CPU"
	echo "bpf_batch_size=$BPF_BATCH_SIZE"
	echo "bpf_pause_us=$BPF_PAUSE_US"
	echo 'case_order=cyclic-latin-square-v1'
	echo "warmups=$WARMUPS"
	echo "repetitions=$REPETITIONS"
	echo "recorder_sha256=$RECORDER_SHA256"
	if [[ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
		echo "cpu0_governor=$(< /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
	else
		echo 'cpu0_governor=not_exposed'
	fi
	if [[ -r /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor ]]; then
		echo "cpu1_governor=$(< /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor)"
	else
		echo 'cpu1_governor=not_exposed'
	fi
	echo "swap_rows=$(awk 'END { print NR - 1 }' /proc/swaps)"
	echo "loadavg_before=$(< /proc/loadavg)"
} > "$RESULTS_ROOT/environment.txt"

"$OBSERVER" doctor \
	--recorder-object "$RECORDER" \
	--cgroup-root "$CGROUP_ROOT" \
	--output "$RESULTS_ROOT/doctor.json"
grep -q '"ready_for_runtime": true' "$RESULTS_ROOT/doctor.json"
if grep -q '"status": "FAIL"' "$RESULTS_ROOT/doctor.json"; then
	echo "observer doctor contains a failed prerequisite" >&2
	exit 1
fi

validate_workload_json()
{
	local path="$1"
	local expected_mode="$2"
	local expected_iterations="$3"

	[[ "$(wc -l < "$path")" -eq 1 ]]
	grep -Fq '"schema_version":1' "$path"
	grep -Fq "\"mode\":\"$expected_mode\"" "$path"
	grep -Fq "\"iterations\":$expected_iterations" "$path"
	grep -Fq '"cpu":1' "$path"
	grep -Eq '"elapsed_ns":[0-9]+' "$path"
	grep -Eq '"active_elapsed_ns":[0-9]+' "$path"
	grep -Eq '"pacing_sleep_ns":[0-9]+' "$path"
	if [[ "$expected_mode" == bpf-update ]]; then
		local expected_sleeps=0
		if (( expected_iterations > 0 )); then
			expected_sleeps=$(((expected_iterations - 1) / BPF_BATCH_SIZE))
		fi
		grep -Fq "\"batch_size\":$BPF_BATCH_SIZE" "$path"
		grep -Fq "\"pause_us\":$BPF_PAUSE_US" "$path"
		grep -Fq "\"pacing_sleeps\":$expected_sleeps" "$path"
	else
		grep -Fq '"batch_size":0' "$path"
		grep -Fq '"pause_us":0' "$path"
		grep -Fq '"pacing_sleeps":0' "$path"
		grep -Fq '"pacing_sleep_ns":0' "$path"
	fi
}

workload_arguments()
{
	local mode="$1"
	local iterations="$2"

	WORKLOAD_ARGUMENTS=(
		"$WORKLOAD" --mode "$mode" --iterations "$iterations"
		--cpu "$WORKLOAD_CPU"
	)
	if [[ "$mode" == bpf-update ]]; then
		WORKLOAD_ARGUMENTS+=(
			--batch-size "$BPF_BATCH_SIZE"
			--pause-us "$BPF_PAUSE_US"
		)
	fi
}

validate_measurement()
{
	local path="$1"

	[[ "$(wc -l < "$path")" -eq 1 ]]
	grep -Fq '"schema_version":1' "$path"
	grep -Eq '"wall_ns":[1-9][0-9]*' "$path"
	grep -Fq '"exit_code":0' "$path"
	grep -Fq '"signal":0' "$path"
}

json_number()
{
	local path="$1"
	local field="$2"

	awk -v key="\"$field\":" '
		$1 == key {
			gsub(/,/, "", $2)
			print $2
			found = 1
		}
		END { if (!found) exit 1 }
	' "$path"
}

run_direct()
{
	local root="$1"
	local mode="$2"
	local iterations="$3"
	local -a WORKLOAD_ARGUMENTS

	install -d -o root -g root -m 0700 "$root"
	workload_arguments "$mode" "$iterations"
	taskset -c "$CONTROLLER_CPU" "$MEASURE" "$root/command.json" -- \
		"${WORKLOAD_ARGUMENTS[@]}" \
		> "$root/workload.json" 2> "$root/command.stderr"
	validate_measurement "$root/command.json"
	validate_workload_json "$root/workload.json" "$mode" "$iterations"
}

run_observed()
{
	local root="$1"
	local mode="$2"
	local iterations="$3"
	local run_id="$4"
	local run_epoch="$5"
	local expected_syscalls=0
	local -a WORKLOAD_ARGUMENTS

	install -d -o root -g root -m 0700 "$root"
	workload_arguments "$mode" "$iterations"
	taskset -c "$CONTROLLER_CPU" "$MEASURE" "$root/command.json" -- \
		"$OBSERVER" observe \
		--scope "$SCOPE" \
		--recorder-object "$RECORDER" \
		--expected-recorder-sha256 "$RECORDER_SHA256" \
		--output-dir "$root/observer-run" \
		--cgroup-root "$CGROUP_ROOT" \
		--run-id "$run_id" \
		--run-epoch "$run_epoch" \
		--timeout-ms 30000 \
		--drain-timeout-ms 5000 \
		-- "${WORKLOAD_ARGUMENTS[@]}" \
		> "$root/observe.json" 2> "$root/command.stderr"
	validate_measurement "$root/command.json"
	validate_workload_json "$root/observer-run/workload.stdout" \
		"$mode" "$iterations"
	"$OBSERVER" verify-run \
		--run-dir "$root/observer-run" \
		--expected-recorder-sha256 "$RECORDER_SHA256" \
		> "$root/verify.json" 2> "$root/verify.stderr"
	if [[ "$mode" == bpf-update ]]; then
		expected_syscalls=$((iterations + 1))
	fi
	local expected_events=$((2 * expected_syscalls))
	local health="$root/observer-run/health.json"
	[[ "$(json_number "$health" syscall_attempted)" -eq "$expected_syscalls" ]]
	[[ "$(json_number "$health" syscall_completed)" -eq "$expected_syscalls" ]]
	[[ "$(json_number "$health" event_attempted)" -eq "$expected_events" ]]
	[[ "$(json_number "$health" event_published)" -eq "$expected_events" ]]
	[[ "$(json_number "$health" event_dropped)" -eq 0 ]]
	[[ "$(json_number "$health" events_persisted)" -eq "$expected_events" ]]
	[[ "$(json_number "$health" pending_insert_failed)" -eq 0 ]]
	[[ "$(json_number "$health" pending_missing)" -eq 0 ]]
	[[ "$(json_number "$health" pending_remaining)" -eq 0 ]]
	[[ "$(json_number "$health" parse_failed)" -eq 0 ]]
	[[ "$(wc -l < "$root/observer-run/raw-events.jsonl")" -eq \
		$((expected_events + 2)) ]]
	grep -q '"evidence_complete": true' "$root/verify.json"
	[[ "$(json_number "$root/verify.json" events_verified)" -eq \
		$((expected_events + 2)) ]]
}

run_pair()
{
	local class="$1"
	local sample="$2"
	local mode="$3"
	local iterations="$4"
	local case_name="$5"
	local position="$6"
	local pair_root="$RESULTS_ROOT/$class/$case_name/sample-$(printf '%03d' "$sample")"
	local order=direct-first
	local epoch=$((100000 + sample + iterations))

	install -d -o root -g root -m 0700 "$pair_root"
	echo "$position" > "$pair_root/case-position.txt"
	if (( sample % 2 == 0 )); then
		order=observed-first
	fi
	echo "$order" > "$pair_root/order.txt"
	if [[ "$order" == direct-first ]]; then
		run_direct "$pair_root/direct" "$mode" "$iterations"
		run_observed "$pair_root/observed" "$mode" "$iterations" \
			"oh-$class-$case_name-$sample" "$epoch"
	else
		run_observed "$pair_root/observed" "$mode" "$iterations" \
			"oh-$class-$case_name-$sample" "$epoch"
		run_direct "$pair_root/direct" "$mode" "$iterations"
	fi
}

run_matrix()
{
	local class="$1"
	local count="$2"
	local sample
	local spec
	local mode
	local iterations
	local case_name
	local case_count
	local offset
	local position
	local index
	local -a cases=(
		'noop 0 noop-0'
		'getpid 100000 getpid-100000'
		'bpf-update 0 bpf-update-0'
		'bpf-update 4096 bpf-update-4096'
		'bpf-update 16384 bpf-update-16384'
		'bpf-update 32768 bpf-update-32768'
	)
	case_count="${#cases[@]}"

	for ((sample = 1; sample <= count; sample++)); do
		offset=$(((sample - 1) % case_count))
		for ((position = 0; position < case_count; position++)); do
			index=$(((offset + position) % case_count))
			spec="${cases[$index]}"
			read -r mode iterations case_name <<< "$spec"
			echo "benchmark class=$class sample=$sample position=$position case=$case_name"
			run_pair "$class" "$sample" "$mode" "$iterations" "$case_name" \
				"$position"
		done
	done
}

run_matrix warmup "$WARMUPS"
run_matrix samples "$REPETITIONS"
echo "loadavg_after=$(< /proc/loadavg)" >> "$RESULTS_ROOT/environment.txt"
echo 'collection=PASS' > "$RESULTS_ROOT/status.txt"
echo "guest overhead evidence collection PASS"
