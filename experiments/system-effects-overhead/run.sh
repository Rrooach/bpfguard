#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 0077

OUTPUT=
WORKLOAD=
MEASURE=
WRAPPER=
SCRATCH_PARENT=/dev/shm
REPETITIONS=12
WARMUP_BLOCKS=4
ITERATIONS_CSV=0,256,1024,4096
BATCH_SIZE=128
PAUSE_US=1000
CPU=

usage()
{
	echo "usage: $0 --output DIR --workload FILE --measure FILE --observer-wrapper FILE [--scratch-parent DIR] [--repetitions N] [--warmup-blocks N] [--iterations CSV] [--batch-size N] [--pause-us N] [--cpu N]" >&2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--output) OUTPUT="$2"; shift 2 ;;
	--workload) WORKLOAD="$2"; shift 2 ;;
	--measure) MEASURE="$2"; shift 2 ;;
	--observer-wrapper) WRAPPER="$2"; shift 2 ;;
	--scratch-parent) SCRATCH_PARENT="$2"; shift 2 ;;
	--repetitions) REPETITIONS="$2"; shift 2 ;;
	--warmup-blocks) WARMUP_BLOCKS="$2"; shift 2 ;;
	--iterations) ITERATIONS_CSV="$2"; shift 2 ;;
	--batch-size) BATCH_SIZE="$2"; shift 2 ;;
	--pause-us) PAUSE_US="$2"; shift 2 ;;
	--cpu) CPU="$2"; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) usage; exit 2 ;;
	esac
done

[[ -n "$OUTPUT" && -n "$WORKLOAD" && -n "$MEASURE" && -n "$WRAPPER" ]] || {
	usage
	exit 2
}
for path in "$WORKLOAD" "$MEASURE" "$WRAPPER"; do
	[[ "$path" == /* && -f "$path" && ! -L "$path" && -x "$path" ]] || {
		echo "benchmark helper must be an absolute, executable regular file: $path" >&2
		exit 2
	}
	if [[ "$path" == *\"* || "$path" == *\\* || "$path" == *$'\n'* ||
		"$path" == *$'\r'* ]]; then
		echo "helper path cannot be represented safely in config.json: $path" >&2
		exit 2
	fi
done
[[ "$OUTPUT" == /* && ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || {
	echo "output must be a new absolute path: $OUTPUT" >&2
	exit 2
}
[[ -d "$SCRATCH_PARENT" && -w "$SCRATCH_PARENT" ]] || {
	echo "scratch parent is not a writable directory: $SCRATCH_PARENT" >&2
	exit 2
}
[[ "$SCRATCH_PARENT" == /* && "$SCRATCH_PARENT" != *$'\n'* &&
	"$SCRATCH_PARENT" != *$'\r'* ]] || {
	echo "scratch parent must be an absolute single-line path" >&2
	exit 2
}
[[ "$REPETITIONS" =~ ^[0-9]+$ && "$WARMUP_BLOCKS" =~ ^[0-9]+$ &&
	"$BATCH_SIZE" =~ ^[1-9][0-9]*$ && "$PAUSE_US" =~ ^[1-9][0-9]*$ ]] || {
	echo "invalid numeric option" >&2
	exit 2
}
(( REPETITIONS >= 4 && REPETITIONS <= 48 && REPETITIONS % 4 == 0 &&
	WARMUP_BLOCKS <= 16 && WARMUP_BLOCKS % 4 == 0 &&
	BATCH_SIZE <= 1000000 && PAUSE_US <= 1000000 )) || {
	echo "invalid repetition, warmup, batch, or pacing bound" >&2
	exit 2
}
IFS=, read -r -a LOADS <<< "$ITERATIONS_CSV"
(( ${#LOADS[@]} >= 2 )) || { echo "at least two load points are required" >&2; exit 2; }
previous=-1
for load in "${LOADS[@]}"; do
	[[ "$load" =~ ^[0-9]+$ ]] || { echo "invalid load point: $load" >&2; exit 2; }
	(( load <= 1000000 )) || { echo "load point exceeds 1000000: $load" >&2; exit 2; }
	(( load > previous )) || { echo "load points must be strictly increasing" >&2; exit 2; }
	previous=$load
done
(( LOADS[0] == 0 )) || { echo "the first load point must be zero" >&2; exit 2; }
if [[ -n "$CPU" && ! "$CPU" =~ ^[0-9]+$ ]]; then
	echo "invalid CPU: $CPU" >&2
	exit 2
fi

mkdir -m 0700 -p "$(dirname "$OUTPUT")"
mkdir -m 0700 "$OUTPUT"
SCRATCH_ROOT="$(mktemp -d "$SCRATCH_PARENT/system-effects-overhead.XXXXXX")"
cleanup()
{
	rm -f "$SCRATCH_ROOT/run/effect-current" "$SCRATCH_ROOT/run/effect-renamed"
	rmdir "$SCRATCH_ROOT/run" 2>/dev/null || true
	rmdir "$SCRATCH_ROOT" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sha256_file()
{
	sha256sum "$1" | awk '{print $1}'
}

{
	echo "boot_id=$(< /proc/sys/kernel/random/boot_id)"
	echo "kernel=$(uname -r)"
	echo "online_cpus=$(< /sys/devices/system/cpu/online)"
	echo "scratch_parent=$SCRATCH_PARENT"
	echo "scratch_filesystem=$(stat -f -c %T "$SCRATCH_PARENT")"
	echo "loadavg_before=$(< /proc/loadavg)"
} > "$OUTPUT/environment.txt"

readonly -a ORDER_0=(quiet-direct quiet-observed effect-observed effect-direct)
readonly -a ORDER_1=(quiet-observed effect-direct quiet-direct effect-observed)
readonly -a ORDER_2=(effect-direct effect-observed quiet-observed quiet-direct)
readonly -a ORDER_3=(effect-observed quiet-direct effect-direct quiet-observed)

readonly WORKLOAD_SHA256="$(sha256_file "$WORKLOAD")"
readonly MEASURE_SHA256="$(sha256_file "$MEASURE")"
readonly WRAPPER_SHA256="$(sha256_file "$WRAPPER")"
CPU_JSON=null
[[ -n "$CPU" ]] && CPU_JSON="$CPU"

cat > "$OUTPUT/config.json" <<EOF
{"schema_version":1,"repetitions":$REPETITIONS,"warmup_blocks":$WARMUP_BLOCKS,"iterations":[${ITERATIONS_CSV}],"batch_size":$BATCH_SIZE,"pause_us":$PAUSE_US,"cpu":$CPU_JSON,"workload":"$WORKLOAD","workload_sha256":"$WORKLOAD_SHA256","measure_sha256":"$MEASURE_SHA256","observer_wrapper":"$WRAPPER","observer_wrapper_sha256":"$WRAPPER_SHA256"}
EOF

run_treatment()
{
	local root="$1"
	local treatment="$2"
	local iterations="$3"
	local profile=quiet
	local observed=0
	local scratch="$SCRATCH_ROOT/run"
	local -a command

	[[ "$treatment" == effect-* ]] && profile=file
	[[ "$treatment" == *-observed ]] && observed=1
	mkdir -m 0700 -p "$root"
	mkdir -m 0700 "$scratch"
	command=("$WORKLOAD" --profile "$profile" --iterations "$iterations"
		--scratch-dir "$scratch" --batch-size "$BATCH_SIZE" --pause-us "$PAUSE_US")
	[[ -n "$CPU" ]] && command+=(--cpu "$CPU")
	if (( observed )); then
		"$MEASURE" "$root/command.json" -- "$WRAPPER" \
			--result-dir "$root/observer" \
			--workload-stdout "$root/workload.json" \
			--workload-stderr "$root/workload.stderr" -- \
			"${command[@]}" > "$root/wrapper.stdout" 2> "$root/wrapper.stderr"
	else
		"$MEASURE" "$root/command.json" -- "${command[@]}" \
			> "$root/workload.json" 2> "$root/workload.stderr"
	fi
	rmdir "$scratch"
}

run_block()
{
	local class="$1"
	local block="$2"
	local block_root="$OUTPUT/$class/block-$(printf '%03d' "$block")"
	local load_count=${#LOADS[@]}
	local load_position
	local load_index
	local iterations
	local order_index=$(((block - 1) % 4))
	local order_name="ORDER_$order_index[@]"
	local -a order=("${!order_name}")

	mkdir -m 0700 -p "$block_root"
	printf '%s\n' "${order[*]}" > "$block_root/treatment-order.txt"
	for ((load_position = 0; load_position < load_count; load_position++)); do
		load_index=$(((load_position + block - 1) % load_count))
		iterations=${LOADS[$load_index]}
		for treatment in "${order[@]}"; do
			echo "class=$class block=$block load=$iterations treatment=$treatment"
			run_treatment "$block_root/n-$iterations/$treatment" "$treatment" "$iterations"
		done
	done
}

for ((block = 1; block <= WARMUP_BLOCKS; block++)); do
	run_block warmup "$block"
done
for ((block = 1; block <= REPETITIONS; block++)); do
	run_block samples "$block"
done
echo "loadavg_after=$(< /proc/loadavg)" >> "$OUTPUT/environment.txt"
[[ "$(sha256_file "$WORKLOAD")" == "$WORKLOAD_SHA256" &&
	"$(sha256_file "$MEASURE")" == "$MEASURE_SHA256" &&
	"$(sha256_file "$WRAPPER")" == "$WRAPPER_SHA256" ]] || {
	echo "a benchmark input changed during collection" >&2
	exit 1
}
echo "collection=PASS" > "$OUTPUT/status.txt"
echo "system-effects overhead collection PASS"
