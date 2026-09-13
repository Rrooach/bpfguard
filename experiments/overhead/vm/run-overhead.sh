#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail
umask 0077

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly EXPERIMENT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly PROJECT_DIR="$(cd -- "$EXPERIMENT_DIR/../.." && pwd)"
readonly QEMU_BINARY="${QEMU_BINARY:-qemu-system-x86_64}"

KERNEL_IMAGE=""
ROOTFS_IMAGE=""
SSH_KEY=""
SSH_PORT=10044
REPETITIONS=12
OUTPUT_PARENT="$PROJECT_DIR/.output/overhead"

usage()
{
	cat >&2 <<USAGE
Usage: $0 --kernel BZIMAGE --rootfs RAW_IMAGE --ssh-key PRIVATE_KEY [options]

Run the paired BPF State Observer overhead microbenchmark in a disposable KVM.

Required:
  --kernel PATH       x86-64 bzImage with Observer prerequisites
  --rootfs PATH       raw Guest image, used only as an immutable backing file
  --ssh-key PATH      root SSH private key for the Guest

Options:
  --ssh-port PORT     loopback SSH port (default: $SSH_PORT)
  --repetitions N     measured pairs per case, 12..48 in steps of 6 (default: $REPETITIONS)
  --output-dir DIR    batch parent (default: $OUTPUT_PARENT)
USAGE
	exit 2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--kernel)
		[[ $# -ge 2 ]] || usage
		KERNEL_IMAGE="$2"
		shift 2
		;;
	--rootfs)
		[[ $# -ge 2 ]] || usage
		ROOTFS_IMAGE="$2"
		shift 2
		;;
	--ssh-key)
		[[ $# -ge 2 ]] || usage
		SSH_KEY="$2"
		shift 2
		;;
	--ssh-port)
		[[ $# -ge 2 ]] || usage
		SSH_PORT="$2"
		shift 2
		;;
	--repetitions)
		[[ $# -ge 2 ]] || usage
		REPETITIONS="$2"
		shift 2
		;;
	--output-dir)
		[[ $# -ge 2 ]] || usage
		OUTPUT_PARENT="$2"
		shift 2
		;;
	-h|--help)
		usage
		;;
	*)
		echo "unknown argument: $1" >&2
		usage
		;;
	esac
done

[[ -n "$KERNEL_IMAGE" && -n "$ROOTFS_IMAGE" && -n "$SSH_KEY" ]] || usage
[[ "$SSH_PORT" =~ ^[0-9]+$ && "$SSH_PORT" -ge 1024 && "$SSH_PORT" -le 65535 ]] || {
	echo "invalid SSH port: $SSH_PORT" >&2
	exit 2
}
if [[ ! "$REPETITIONS" =~ ^[1-9][0-9]*$ ]] ||
	(( REPETITIONS < 12 || REPETITIONS > 48 || REPETITIONS % 6 != 0 )); then
	echo "repetitions must be one of 12, 18, 24, 30, 36, 42, or 48" >&2
	exit 2
fi
for command in "$QEMU_BINARY" qemu-img make node awk date env find grep install \
	mkdir python3 readlink realpath scp seq sha256sum sleep sort ssh ss stat \
	tail timeout xargs; do
	command -v "$command" >/dev/null || {
		echo "missing Host dependency: $command" >&2
		exit 1
	}
done
readonly QEMU="$(realpath -- "$(command -v "$QEMU_BINARY")")"
readonly QEMU_IMG="$(realpath -- "$(command -v qemu-img)")"
for path in "$KERNEL_IMAGE" "$ROOTFS_IMAGE" "$SSH_KEY" "$QEMU" "$QEMU_IMG"; do
	[[ -f "$path" && ! -L "$path" ]] || {
		echo "missing or unsafe input: $path" >&2
		exit 1
	}
done
KERNEL_IMAGE="$(realpath -- "$KERNEL_IMAGE")"
ROOTFS_IMAGE="$(realpath -- "$ROOTFS_IMAGE")"
SSH_KEY="$(realpath -- "$SSH_KEY")"
for path in "$KERNEL_IMAGE" "$ROOTFS_IMAGE" "$QEMU"; do
	[[ "$path" != *,* && "$path" != *$'\n'* && "$path" != *$'\r'* ]] || {
		echo "path is unsafe for QEMU argument construction: $path" >&2
		exit 2
	}
done
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || {
	echo "/dev/kvm is unavailable" >&2
	exit 1
}
[[ "$("$QEMU_IMG" info --output=json "$ROOTFS_IMAGE" | \
	python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')" == raw ]] || {
	echo "rootfs must be a raw image" >&2
	exit 1
}
if ss -H -ltn | awk '{print $4}' | grep -Eq "(^|[:.])$SSH_PORT$"; then
	echo "SSH port is already in use: $SSH_PORT" >&2
	exit 1
fi

readonly HOST_TMPDIR="$PROJECT_DIR/.output/tmp"
install -d -m 0700 "$HOST_TMPDIR" "$OUTPUT_PARENT"
export TMPDIR="$HOST_TMPDIR"
OUTPUT_PARENT="$(realpath -- "$OUTPUT_PARENT")"
readonly BATCH_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
readonly RUN_ROOT="$OUTPUT_PARENT/$BATCH_ID"
for path in "$OUTPUT_PARENT" "$RUN_ROOT"; do
	[[ "$path" != *,* && "$path" != *$'\n'* && "$path" != *$'\r'* ]] || {
		echo "output path is unsafe for QEMU argument construction: $path" >&2
		exit 2
	}
done
[[ ! -e "$RUN_ROOT" && ! -L "$RUN_ROOT" ]] || {
	echo "refusing to reuse output: $RUN_ROOT" >&2
	exit 1
}
install -d -m 0700 "$RUN_ROOT" "$RUN_ROOT/inputs" "$RUN_ROOT/qemu-tmp"

readonly KERNEL_SIZE="$(stat -c %s "$KERNEL_IMAGE")"
readonly KERNEL_SHA256="$(sha256sum "$KERNEL_IMAGE" | awk '{print $1}')"
readonly ROOTFS_SIZE="$(stat -c %s "$ROOTFS_IMAGE")"
readonly ROOTFS_SHA256="$(sha256sum "$ROOTFS_IMAGE" | awk '{print $1}')"
readonly SSH_KEY_SIZE="$(stat -c %s "$SSH_KEY")"
readonly SSH_KEY_SHA256="$(sha256sum "$SSH_KEY" | awk '{print $1}')"

echo "H0 building benchmark inputs"
make -C "$PROJECT_DIR" release bpf workloads
readonly OBSERVER="$PROJECT_DIR/.output/cargo-target/release/bpf-state-observer"
readonly RECORDER="$PROJECT_DIR/.output/recorder.bpf.o"
readonly WORKLOAD="$PROJECT_DIR/.output/workloads/overhead-bench"
readonly MEASURE="$PROJECT_DIR/.output/workloads/measure-command"
readonly SCOPE="$EXPERIMENT_DIR/config/scope.json"
readonly GUEST_RUNNER="$SCRIPT_DIR/guest-run-overhead.sh"
readonly ANALYZER="$EXPERIMENT_DIR/analyze.js"
for path in "$OBSERVER" "$RECORDER" "$WORKLOAD" "$MEASURE" "$SCOPE" \
	"$GUEST_RUNNER" "$ANALYZER"; do
	[[ -f "$path" && ! -L "$path" ]] || {
		echo "missing benchmark build input: $path" >&2
		exit 1
	}
done
install -m 0555 "$OBSERVER" "$RUN_ROOT/inputs/bpf-state-observer"
install -m 0444 "$RECORDER" "$RUN_ROOT/inputs/recorder.bpf.o"
install -m 0555 "$WORKLOAD" "$RUN_ROOT/inputs/overhead-bench"
install -m 0555 "$MEASURE" "$RUN_ROOT/inputs/measure-command"
install -m 0444 "$SCOPE" "$RUN_ROOT/inputs/scope.json"
install -m 0555 "$GUEST_RUNNER" "$RUN_ROOT/inputs/guest-run-overhead.sh"
install -m 0555 "$ANALYZER" "$RUN_ROOT/inputs/analyze.js"
(
	cd "$RUN_ROOT/inputs"
	sha256sum * > SHA256SUMS
)
{
	echo "kernel_path=$KERNEL_IMAGE"
	echo "kernel_size=$KERNEL_SIZE"
	echo "kernel_sha256=$KERNEL_SHA256"
	echo "rootfs_path=$ROOTFS_IMAGE"
	echo "rootfs_size=$ROOTFS_SIZE"
	echo "rootfs_sha256=$ROOTFS_SHA256"
	echo "ssh_key_path=$SSH_KEY"
	echo "ssh_key_size=$SSH_KEY_SIZE"
	echo "ssh_key_sha256=$SSH_KEY_SHA256"
	echo "qemu_path=$QEMU"
	echo "qemu_sha256=$(sha256sum "$QEMU" | awk '{print $1}')"
	"$QEMU" --version
} > "$RUN_ROOT/host-input-identities.txt"

readonly OVERLAY="$RUN_ROOT/overhead-root-overlay.qcow2"
readonly CONSOLE="$RUN_ROOT/console.log"
readonly QEMU_STDERR="$RUN_ROOT/qemu.stderr"
"$QEMU_IMG" create -q -f qcow2 -F raw -b "$ROOTFS_IMAGE" "$OVERLAY"
readonly -a QEMU_ARGS=(
	-m 2048
	-smp 2
	-display none
	-monitor none
	-serial "file:$CONSOLE"
	-no-reboot
	-enable-kvm
	-cpu host,migratable=off
	-device e1000,netdev=net0
	-netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22"
	-drive "file=$OVERLAY,format=qcow2,index=0,media=disk,snapshot=off"
	-kernel "$KERNEL_IMAGE"
	-append 'root=/dev/sda rw console=ttyS0,115200 earlyprintk=serial net.ifnames=0'
)
{
	printf 'qemu=%q\n' "$QEMU"
	printf 'argv='
	printf '%q ' "${QEMU_ARGS[@]}"
	printf '\n'
} > "$RUN_ROOT/qemu.argv"

QEMU_PID=""
QEMU_START=""
qemu_identity()
{
	local stat_line
	local remainder
	local -a fields
	[[ "$1" =~ ^[1-9][0-9]*$ && -r "/proc/$1/stat" ]] || return 1
	IFS= read -r stat_line < "/proc/$1/stat" || return 1
	remainder="${stat_line##*) }"
	read -r -a fields <<< "$remainder"
	[[ "${#fields[@]}" -ge 20 ]]
	printf '%s %s\n' "${fields[0]}" "${fields[19]}"
}

qemu_running()
{
	local current
	[[ -n "$QEMU_PID" && -n "$QEMU_START" ]] || return 1
	current="$(qemu_identity "$QEMU_PID")" || return 1
	[[ "${current#* }" == "$QEMU_START" && "${current%% *}" != Z ]]
}

stop_qemu()
{
	local attempt
	if qemu_running; then
		kill -TERM "$QEMU_PID" 2>/dev/null || true
		for ((attempt = 0; attempt < 100; attempt++)); do
			qemu_running || break
			sleep 0.1
		done
	fi
	if qemu_running; then
		kill -KILL "$QEMU_PID" 2>/dev/null || true
	fi
	if [[ -n "$QEMU_PID" ]]; then
		wait "$QEMU_PID" 2>/dev/null || true
	fi
	QEMU_PID=""
	QEMU_START=""
}

cleanup()
{
	local status=$?
	trap - EXIT HUP INT TERM
	set +e
	stop_qemu
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

readonly -a SSH_OPTIONS=(
	-p "$SSH_PORT"
	-i "$SSH_KEY"
	-o BatchMode=yes
	-o IdentitiesOnly=yes
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=5
)
readonly -a SCP_OPTIONS=(
	-P "$SSH_PORT"
	-i "$SSH_KEY"
	-o BatchMode=yes
	-o IdentitiesOnly=yes
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=5
)

echo "H1 starting 2-vCPU KVM"
TMPDIR="$RUN_ROOT/qemu-tmp" "$QEMU" "${QEMU_ARGS[@]}" \
	> /dev/null 2> "$QEMU_STDERR" &
QEMU_PID=$!
identity="$(qemu_identity "$QEMU_PID")" || {
	echo "could not bind QEMU process identity" >&2
	exit 1
}
QEMU_START="${identity#* }"

guest_ready=0
for _attempt in $(seq 1 120); do
	if timeout --foreground 6s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
		'test "$(id -u)" -eq 0 && test "$(getconf _NPROCESSORS_ONLN)" -eq 2' \
		> "$RUN_ROOT/guest-ready.txt" 2>/dev/null; then
		guest_ready=1
		break
	fi
	qemu_running || break
	sleep 1
done
[[ "$guest_ready" -eq 1 ]] || {
	echo "Guest SSH did not become ready" >&2
	tail -100 "$CONSOLE" >&2 || true
	exit 1
}

echo "H2 provisioning immutable benchmark payload"
ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
	'test ! -e /opt/bpf-overhead && install -d -o root -g root -m 0755 /opt/bpf-overhead'
scp "${SCP_OPTIONS[@]}" "$RUN_ROOT/inputs/bpf-state-observer" \
	"$RUN_ROOT/inputs/recorder.bpf.o" "$RUN_ROOT/inputs/overhead-bench" \
	"$RUN_ROOT/inputs/measure-command" "$RUN_ROOT/inputs/scope.json" \
	"$RUN_ROOT/inputs/guest-run-overhead.sh" \
	root@127.0.0.1:/opt/bpf-overhead/
ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 'bash -s' \
	> "$RUN_ROOT/provision.log" 2> "$RUN_ROOT/provision.stderr" <<'PROVISION'
set -euo pipefail
chown -R root:root /opt/bpf-overhead
find /opt/bpf-overhead -type d -exec chmod 0555 {} +
find /opt/bpf-overhead -type f -exec chmod 0444 {} +
chmod 0555 /opt/bpf-overhead/bpf-state-observer \
	/opt/bpf-overhead/overhead-bench \
	/opt/bpf-overhead/measure-command \
	/opt/bpf-overhead/guest-run-overhead.sh
test "$(find /opt/bpf-overhead -type f | wc -l)" -eq 6
sha256sum /opt/bpf-overhead/*
PROVISION

echo "H3 running paired benchmark"
set +e
timeout --foreground 1800s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
	"/opt/bpf-overhead/guest-run-overhead.sh /opt/bpf-overhead \
	/var/lib/bpf-overhead/$BATCH_ID $REPETITIONS" \
	> "$RUN_ROOT/guest.stdout" 2> "$RUN_ROOT/guest.stderr"
guest_status=$?
set -e

echo "H4 extracting and analyzing results"
set +e
scp -r "${SCP_OPTIONS[@]}" \
	"root@127.0.0.1:/var/lib/bpf-overhead/$BATCH_ID" \
	"$RUN_ROOT/guest-results"
extract_status=$?
set -e
if [[ "$extract_status" -ne 0 ]]; then
	echo "failed to extract Guest benchmark results" >&2
	guest_status=1
fi
if [[ "$guest_status" -eq 0 ]]; then
	node "$RUN_ROOT/inputs/analyze.js" "$RUN_ROOT/guest-results" \
		"$RUN_ROOT/report.json" "$RUN_ROOT/REPORT.md" \
		> "$RUN_ROOT/analyze.stdout" 2> "$RUN_ROOT/analyze.stderr" || \
		guest_status=1
fi

timeout --foreground 20s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
	'sync; systemctl poweroff' > "$RUN_ROOT/poweroff.log" 2>&1 || true
for _attempt in $(seq 1 300); do
	qemu_running || break
	sleep 0.1
done
if qemu_running; then
	echo "Guest did not power off; stopping owned QEMU" >&2
	guest_status=1
	stop_qemu
else
	set +e
	wait "$QEMU_PID"
	qemu_status=$?
	set -e
	QEMU_PID=""
	QEMU_START=""
	[[ "$qemu_status" -eq 0 ]] || guest_status=1
fi

echo "H5 validating retained evidence"
overlay_status=0
"$QEMU_IMG" check -f qcow2 "$OVERLAY" \
	> "$RUN_ROOT/overlay-check.log" 2>&1 || overlay_status=1
"$QEMU_IMG" info --backing-chain --output=json "$OVERLAY" \
	> "$RUN_ROOT/overlay-info.json"
python3 - "$RUN_ROOT/overlay-info.json" "$OVERLAY" "$ROOTFS_IMAGE" <<'PY' \
	> "$RUN_ROOT/overlay-validation.txt" 2> "$RUN_ROOT/overlay-validation.stderr" || \
	overlay_status=1
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    chain = json.load(stream)
valid = (
    isinstance(chain, list)
    and len(chain) == 2
    and chain[0].get("filename") == sys.argv[2]
    and chain[0].get("format") == "qcow2"
    and chain[0].get("full-backing-filename") == sys.argv[3]
    and chain[0].get("backing-filename-format") == "raw"
    and chain[1].get("filename") == sys.argv[3]
    and chain[1].get("format") == "raw"
)
if not valid:
    raise SystemExit("unexpected overlay backing chain")
print("overlay_chain=PASS")
PY

host_input_status=0
[[ "$(stat -c %s "$KERNEL_IMAGE")" == "$KERNEL_SIZE" && \
	"$(sha256sum "$KERNEL_IMAGE" | awk '{print $1}')" == "$KERNEL_SHA256" ]] || \
	host_input_status=1
[[ "$(stat -c %s "$ROOTFS_IMAGE")" == "$ROOTFS_SIZE" && \
	"$(sha256sum "$ROOTFS_IMAGE" | awk '{print $1}')" == "$ROOTFS_SHA256" ]] || \
	host_input_status=1
[[ "$(stat -c %s "$SSH_KEY")" == "$SSH_KEY_SIZE" && \
	"$(sha256sum "$SSH_KEY" | awk '{print $1}')" == "$SSH_KEY_SHA256" ]] || \
	host_input_status=1
(
	cd "$RUN_ROOT/inputs"
	sha256sum -c SHA256SUMS
) > "$RUN_ROOT/input-revalidation.txt" || host_input_status=1

{
	echo "batch_id=$BATCH_ID"
	echo "guest_status=$guest_status"
	echo "overlay_status=$overlay_status"
	echo "host_input_status=$host_input_status"
	echo "repetitions=$REPETITIONS"
	echo "result_path=$RUN_ROOT"
} > "$RUN_ROOT/host-summary.txt"
(
	cd "$RUN_ROOT"
	find . -type f ! -name BATCH_SHA256SUMS -print0 | \
		LC_ALL=C sort -z | xargs -0 sha256sum > BATCH_SHA256SUMS
)

if [[ "$guest_status" -eq 0 && "$overlay_status" -eq 0 && \
	"$host_input_status" -eq 0 ]]; then
	echo "overhead evidence collection PASS: $RUN_ROOT"
	exit 0
fi
echo "overhead evidence collection failed; diagnostics retained at $RUN_ROOT" >&2
exit 1
