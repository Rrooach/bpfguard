#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# exclusive-vm-v1 acceptance uses two separate boots. A normal systemd boot
# only provisions a frozen root; it never produces strict evidence. The
# second boot selects the measured static PID1, has no NIC, exposes that root
# read-only, and writes only to a fresh evidence disk recovered by the Host.
set -euo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -P -- "$SCRIPT_DIR/.." && pwd -P)"
KERNEL_ROOT="$(cd -P -- "$PROJECT_DIR/../../.." && pwd -P)"
OUTPUT_BASE="$PROJECT_DIR/.output/vm-e2e"
QEMU_BINARY="${QEMU_BINARY:-qemu-system-x86_64}"
SSH_PORT="${SSH_PORT:-10022}"
SSH_COMMAND_TIMEOUT="${SSH_COMMAND_TIMEOUT:-20s}"
SCP_COMMAND_TIMEOUT="${SCP_COMMAND_TIMEOUT:-120s}"
PROVISION_TIMEOUT_SECONDS="${VM_E2E_PROVISION_TIMEOUT_SECONDS:-180}"
STRICT_TIMEOUT_SECONDS="${VM_E2E_STRICT_TIMEOUT_SECONDS:-240}"
EVIDENCE_BYTES="${VM_E2E_EVIDENCE_BYTES:-268435456}"
MIN_FREE_BYTES="${VM_E2E_MIN_FREE_BYTES:-1073741824}"
KERNEL_BZIMAGE=""
ROOTFS_IMAGE=""
SSH_KEY=""
QEMU_PID=""
QEMU_START_TIME=""
QEMU_EXECUTABLE=""
HARNESS_PID=""
HARNESS_SECRET_DIR=""
HARNESS_SECRET_KEY=""
HARNESS_WRONG_SECRET_KEY=""
HARNESS_SOCKET=""

usage()
{
	cat <<EOF
Usage: $0 --kernel BZIMAGE --rootfs RAW_IMAGE --ssh-key PRIVATE_KEY [options]

Run the authenticated exclusive-vm-v1 acceptance gate. The first VM boot
only provisions a frozen root. The second uses the measured minimal PID1,
has no network device, keeps vda read-only, and writes evidence to vdb.

Options:
  --kernel PATH       x86-64 bzImage (required)
  --rootfs PATH       raw x86-64 Linux image with root SSH access (required)
  --ssh-key PATH      private key authorized for root in the image (required)
  --ssh-port PORT     provisioning-only loopback port (default: $SSH_PORT)
  --output-dir DIR    per-run output parent (default: $OUTPUT_BASE)
  -h, --help          show this help
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--kernel)
		KERNEL_BZIMAGE="${2:-}"
		shift 2
		;;
	--rootfs)
		ROOTFS_IMAGE="${2:-}"
		shift 2
		;;
	--ssh-key)
		SSH_KEY="${2:-}"
		shift 2
		;;
	--ssh-port)
		SSH_PORT="${2:-}"
		shift 2
		;;
	--output-dir)
		OUTPUT_BASE="${2:-}"
		shift 2
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

[[ -n "$KERNEL_BZIMAGE" && -n "$ROOTFS_IMAGE" && -n "$SSH_KEY" ]] || {
	usage >&2
	exit 2
}
[[ "$SSH_PORT" =~ ^[1-9][0-9]{0,4}$ && "$SSH_PORT" -le 65535 ]] || {
	echo "invalid SSH port: $SSH_PORT" >&2
	exit 2
}
for value_name in PROVISION_TIMEOUT_SECONDS STRICT_TIMEOUT_SECONDS \
	EVIDENCE_BYTES MIN_FREE_BYTES; do
	value="${!value_name}"
	[[ "$value" =~ ^[1-9][0-9]*$ ]] || {
		echo "$value_name must be a positive integer" >&2
		exit 2
	}
done
(( EVIDENCE_BYTES >= 67108864 )) || {
	echo "VM_E2E_EVIDENCE_BYTES must be at least 67108864" >&2
	exit 2
}

KERNEL_BZIMAGE="$(realpath -e -- "$KERNEL_BZIMAGE")"
ROOTFS_IMAGE="$(realpath -e -- "$ROOTFS_IMAGE")"
SSH_KEY="$(realpath -e -- "$SSH_KEY")"
OUTPUT_BASE="$(realpath -m -- "$OUTPUT_BASE")"
for path in "$KERNEL_BZIMAGE" "$ROOTFS_IMAGE" "$SSH_KEY"; do
	[[ -f "$path" && ! -L "$path" ]] || {
		echo "not a real regular input file: $path" >&2
		exit 2
	}
done
for path in "$KERNEL_BZIMAGE" "$ROOTFS_IMAGE" "$OUTPUT_BASE"; do
	[[ "$path" != *,* && "$path" != *$'\n'* ]] || {
		echo "QEMU paths may not contain comma or newline: $path" >&2
		exit 2
	}
done
for command in "$QEMU_BINARY" qemu-img cmp cp debugfs df e2fsck file \
	find grep install mkfs.ext4 mktemp ps readlink realpath scp sha256sum \
	ssh ss stat timeout truncate; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing host dependency: $command" >&2
		exit 2
	}
done
[[ -x "$KERNEL_ROOT/scripts/extract-ikconfig" ]] || {
	echo "kernel extract-ikconfig helper is unavailable" >&2
	exit 2
}
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || {
	echo "/dev/kvm is not usable by the current user" >&2
	exit 2
}
file "$KERNEL_BZIMAGE" | grep -q 'Linux kernel x86 boot executable bzImage' || {
	echo "--kernel is not an x86 bzImage" >&2
	exit 2
}
file "$ROOTFS_IMAGE" | grep -q 'ext4 filesystem data' || {
	echo "--rootfs must be a raw ext4 filesystem image" >&2
	exit 2
}
if ss -ltnH "sport = :$SSH_PORT" | grep -q .; then
	echo "loopback SSH port $SSH_PORT is already in use" >&2
	exit 2
fi

make -C "$PROJECT_DIR" release bpf workloads vm-strict

BIN="$PROJECT_DIR/.output/cargo-target/release/bpf-state-observer"
ASSERT_BIN="$PROJECT_DIR/.output/cargo-target/release/vm-e2e-assert"
OUTSIDER_GATE_BIN="$PROJECT_DIR/.output/cargo-target/release/vm-outsider-gate-assert"
HARNESSD_BIN="$PROJECT_DIR/.output/cargo-target/release/bpf-harnessd"
STRICT_INIT_BIN="$PROJECT_DIR/.output/vm/strict-init"
OBJ="$PROJECT_DIR/.output/recorder.bpf.o"
WORKLOAD="$PROJECT_DIR/.output/workloads/map-lifecycle"
NOOP_WORKLOAD="$PROJECT_DIR/.output/workloads/exclusive-noop"
EXCLUSIVE_SCOPE="$PROJECT_DIR/config/exclusive-vm-scope.json"
CONTRACT_SPEC="$PROJECT_DIR/config/exclusive-vm-v1.json"
ASSERT_SOURCE="$PROJECT_DIR/crates/observerd/src/bin/vm-e2e-assert.rs"
OUTSIDER_GATE_SOURCE="$PROJECT_DIR/crates/observerd/src/bin/vm-outsider-gate-assert.rs"
WORKLOAD_SOURCE="$PROJECT_DIR/workloads/map-lifecycle.c"
NOOP_SOURCE="$PROJECT_DIR/workloads/exclusive-noop.c"
STRICT_INIT_SOURCE="$SCRIPT_DIR/strict-init.c"
STRICT_GUEST_RUNNER="$SCRIPT_DIR/guest-strict-e2e.sh"
LEGACY_GUEST_RUNNER="$SCRIPT_DIR/guest-e2e.sh"
HOST_RUNNER="$SCRIPT_DIR/run-e2e.sh"
KERNEL_BUILDER="$SCRIPT_DIR/build-e2e-kernel.sh"
E2E_CONFIG="$SCRIPT_DIR/e2e-x86.config"
BASE_CONFIG="$SCRIPT_DIR/bpf-state-observer.config"
for path in "$BIN" "$ASSERT_BIN" "$OUTSIDER_GATE_BIN" "$HARNESSD_BIN" \
	"$STRICT_INIT_BIN" "$OBJ" "$WORKLOAD" "$NOOP_WORKLOAD" \
	"$EXCLUSIVE_SCOPE" "$CONTRACT_SPEC" "$ASSERT_SOURCE" \
	"$OUTSIDER_GATE_SOURCE" "$WORKLOAD_SOURCE" "$NOOP_SOURCE" \
	"$STRICT_INIT_SOURCE" "$STRICT_GUEST_RUNNER" "$LEGACY_GUEST_RUNNER" \
	"$HOST_RUNNER" "$KERNEL_BUILDER" "$E2E_CONFIG" "$BASE_CONFIG"; do
	[[ -f "$path" && ! -L "$path" ]] || {
		echo "missing or unsafe E2E input: $path" >&2
		exit 2
	}
done
"$STRICT_INIT_BIN" --self-test
bash -n "$STRICT_GUEST_RUNNER"
bash -n "$LEGACY_GUEST_RUNNER"
bash -n "$HOST_RUNNER"

RUN_TAG="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RUN_ROOT="$OUTPUT_BASE/$RUN_TAG"
AUDIT_INPUTS="$RUN_ROOT/inputs"
HOST_RESULTS="$RUN_ROOT/host-results"
PROVISION_EXTRACT="$RUN_ROOT/provision-inspection"
EVIDENCE_EXTRACT="$RUN_ROOT/strict-evidence"
PROVISION_QEMU_TMP="$RUN_ROOT/provision-qemu-tmp"
STRICT_QEMU_TMP="$RUN_ROOT/strict-qemu-tmp"
PROVISION_CONSOLE="$RUN_ROOT/provision-console.log"
PROVISION_QEMU_STDERR="$RUN_ROOT/provision-qemu.stderr"
STRICT_CONSOLE="$RUN_ROOT/strict-console.log"
STRICT_QEMU_STDERR="$RUN_ROOT/strict-qemu.stderr"
PROVISION_OVERLAY="$RUN_ROOT/provision-overlay.qcow2"
PROVISION_FLAT="$RUN_ROOT/provision-root.raw"
STRICT_OVERLAY="$RUN_ROOT/strict-root-overlay.qcow2"
EVIDENCE_IMAGE="$RUN_ROOT/strict-evidence-original.ext4"
EVIDENCE_RECOVERY_IMAGE="$RUN_ROOT/strict-evidence-recovery.ext4"
STRICT_INPUT_ROOT=/opt/bpf-state-observer-exclusive-e2e

mkdir -p "$OUTPUT_BASE"
if [[ -e "$RUN_ROOT" || -L "$RUN_ROOT" ]]; then
	echo "refusing to reuse VM result directory: $RUN_ROOT" >&2
	exit 2
fi
available_bytes="$(df -PB1 "$OUTPUT_BASE" | awk 'NR == 2 { print $4 }')"
rootfs_bytes="$(stat -c %s "$ROOTFS_IMAGE")"
input_bytes=0
for path in "$KERNEL_BZIMAGE" "$BIN" "$ASSERT_BIN" "$OUTSIDER_GATE_BIN" \
	"$HARNESSD_BIN" "$STRICT_INIT_BIN" "$OBJ" "$WORKLOAD" \
	"$NOOP_WORKLOAD" "$EXCLUSIVE_SCOPE" "$CONTRACT_SPEC" \
	"$ASSERT_SOURCE" "$OUTSIDER_GATE_SOURCE" "$WORKLOAD_SOURCE" \
	"$NOOP_SOURCE" "$STRICT_INIT_SOURCE" "$STRICT_GUEST_RUNNER" \
	"$LEGACY_GUEST_RUNNER" "$HOST_RUNNER" "$KERNEL_BUILDER" \
	"$E2E_CONFIG" "$BASE_CONFIG"; do
	input_bytes=$((input_bytes + $(stat -c %s "$path")))
done
required_bytes=$((3 * rootfs_bytes + 2 * EVIDENCE_BYTES + input_bytes + MIN_FREE_BYTES))
[[ "$available_bytes" =~ ^[0-9]+$ && "$required_bytes" -gt "$rootfs_bytes" ]] || {
	echo "cannot safely calculate E2E output-space requirements" >&2
	exit 2
}
if (( available_bytes < required_bytes )); then
	echo "insufficient E2E output space: $available_bytes available, $required_bytes required" >&2
	exit 2
fi
install -d -m 0700 "$RUN_ROOT" "$AUDIT_INPUTS" "$HOST_RESULTS" \
	"$PROVISION_EXTRACT" "$PROVISION_QEMU_TMP" "$STRICT_QEMU_TMP"

# Snapshot every executable/configuration input. The external base rootfs and
# Host QEMU binary are measured in place and checked after both boots.
install -m 0644 "$KERNEL_BZIMAGE" "$AUDIT_INPUTS/kernel.bzImage"
install -m 0755 "$BIN" "$AUDIT_INPUTS/bpf-state-observer"
install -m 0755 "$ASSERT_BIN" "$AUDIT_INPUTS/vm-e2e-assert"
install -m 0755 "$OUTSIDER_GATE_BIN" "$AUDIT_INPUTS/vm-outsider-gate-assert"
install -m 0755 "$HARNESSD_BIN" "$AUDIT_INPUTS/bpf-harnessd"
install -m 0755 "$STRICT_INIT_BIN" "$AUDIT_INPUTS/strict-init"
install -m 0644 "$OBJ" "$AUDIT_INPUTS/recorder.bpf.o"
install -m 0755 "$WORKLOAD" "$AUDIT_INPUTS/map-lifecycle"
install -m 0755 "$NOOP_WORKLOAD" "$AUDIT_INPUTS/exclusive-noop"
install -m 0644 "$EXCLUSIVE_SCOPE" "$AUDIT_INPUTS/exclusive-vm-scope.json"
install -m 0644 "$CONTRACT_SPEC" "$AUDIT_INPUTS/exclusive-vm-v1.json"
install -m 0644 "$ASSERT_SOURCE" "$AUDIT_INPUTS/vm-e2e-assert.rs"
install -m 0644 "$OUTSIDER_GATE_SOURCE" \
	"$AUDIT_INPUTS/vm-outsider-gate-assert.rs"
install -m 0644 "$WORKLOAD_SOURCE" "$AUDIT_INPUTS/map-lifecycle.c"
install -m 0644 "$NOOP_SOURCE" "$AUDIT_INPUTS/exclusive-noop.c"
install -m 0644 "$STRICT_INIT_SOURCE" "$AUDIT_INPUTS/strict-init.c"
install -m 0755 "$STRICT_GUEST_RUNNER" "$AUDIT_INPUTS/guest-strict-e2e.sh"
install -m 0755 "$LEGACY_GUEST_RUNNER" "$AUDIT_INPUTS/guest-e2e.sh"
install -m 0755 "$HOST_RUNNER" "$AUDIT_INPUTS/run-e2e.sh"
install -m 0755 "$KERNEL_BUILDER" "$AUDIT_INPUTS/build-e2e-kernel.sh"
install -m 0644 "$E2E_CONFIG" "$AUDIT_INPUTS/e2e-x86.config"
install -m 0644 "$BASE_CONFIG" "$AUDIT_INPUTS/bpf-state-observer.config"

AUDIT_KERNEL="$AUDIT_INPUTS/kernel.bzImage"
AUDIT_BIN="$AUDIT_INPUTS/bpf-state-observer"
AUDIT_ASSERT_BIN="$AUDIT_INPUTS/vm-e2e-assert"
AUDIT_OUTSIDER_GATE="$AUDIT_INPUTS/vm-outsider-gate-assert"
AUDIT_HARNESSD="$AUDIT_INPUTS/bpf-harnessd"
AUDIT_STRICT_INIT="$AUDIT_INPUTS/strict-init"
AUDIT_OBJ="$AUDIT_INPUTS/recorder.bpf.o"
AUDIT_WORKLOAD="$AUDIT_INPUTS/map-lifecycle"
AUDIT_NOOP_WORKLOAD="$AUDIT_INPUTS/exclusive-noop"

"$KERNEL_ROOT/scripts/extract-ikconfig" "$AUDIT_KERNEL" \
	> "$RUN_ROOT/kernel.config"
for setting in \
	CONFIG_BPF=y \
	CONFIG_BPF_SYSCALL=y \
	CONFIG_BPF_EVENTS=y \
	CONFIG_CGROUPS=y \
	CONFIG_CGROUP_BPF=y \
	CONFIG_CGROUP_FREEZER=y \
	CONFIG_SECCOMP=y \
	CONFIG_SECCOMP_FILTER=y \
	CONFIG_PERF_EVENTS=y \
	CONFIG_TRACEPOINTS=y \
	CONFIG_EVENT_TRACING=y \
	CONFIG_BLK_DEV_INITRD=y \
	CONFIG_RD_GZIP=y \
	CONFIG_DEVTMPFS=y \
	CONFIG_DEVTMPFS_MOUNT=y \
	CONFIG_PROC_FS=y \
	CONFIG_SYSFS=y \
	CONFIG_TMPFS=y \
	CONFIG_EXT4_FS=y \
	CONFIG_EXT4_FS_SECURITY=y \
	CONFIG_SECURITY=y \
	CONFIG_ATA=y \
	CONFIG_ATA_PIIX=y \
	CONFIG_NET=y \
	CONFIG_INET=y \
	CONFIG_E1000=y \
	CONFIG_VIRTIO=y \
	CONFIG_VIRTIO_PCI=y \
	CONFIG_VIRTIO_BLK=y \
	CONFIG_VIRTIO_CONSOLE=y \
	CONFIG_SERIAL_8250=y \
	CONFIG_SERIAL_8250_CONSOLE=y \
	CONFIG_CONFIGFS_FS=y \
	CONFIG_IKCONFIG=y \
	CONFIG_IKCONFIG_PROC=y; do
	grep -qx "$setting" "$RUN_ROOT/kernel.config" || {
		echo "acceptance kernel omits required setting: $setting" >&2
		exit 2
	}
done
grep -qx '# CONFIG_BPF_PRELOAD is not set' "$RUN_ROOT/kernel.config" || {
	echo "acceptance kernel must disable CONFIG_BPF_PRELOAD" >&2
	exit 2
}
grep -qx 'CONFIG_INITRAMFS_SOURCE=""' "$RUN_ROOT/kernel.config" || {
	echo "acceptance kernel must not embed an unmeasured initramfs userspace" >&2
	exit 2
}
[[ "$(grep -Ec '^(CONFIG_MODULES=y|# CONFIG_MODULES is not set)$' \
	"$RUN_ROOT/kernel.config")" -eq 1 ]] || {
	echo "acceptance kernel has an ambiguous module configuration" >&2
	exit 2
}

sha256_of()
{
	sha256sum "$1" | awk '{print $1}'
}

require_sha256()
{
	local name="$1"
	local value="$2"
	[[ "$value" =~ ^[a-f0-9]{64}$ ]] || {
		echo "$name is not canonical lowercase SHA-256" >&2
		exit 1
	}
}

KERNEL_SHA256="$(sha256_of "$AUDIT_KERNEL")"
KERNEL_CONFIG_SHA256="$(sha256_of "$RUN_ROOT/kernel.config")"
ROOTFS_SHA256="$(sha256_of "$ROOTFS_IMAGE")"
RECORDER_SHA256="$(sha256_of "$AUDIT_OBJ")"
OBSERVER_SHA256="$(sha256_of "$AUDIT_BIN")"
ASSERT_SHA256="$(sha256_of "$AUDIT_ASSERT_BIN")"
OUTSIDER_GATE_SHA256="$(sha256_of "$AUDIT_OUTSIDER_GATE")"
HARNESSD_SHA256="$(sha256_of "$AUDIT_HARNESSD")"
STRICT_INIT_SHA256="$(sha256_of "$AUDIT_STRICT_INIT")"
STRICT_RUNNER_SHA256="$(sha256_of "$AUDIT_INPUTS/guest-strict-e2e.sh")"
WORKLOAD_SHA256="$(sha256_of "$AUDIT_WORKLOAD")"
NOOP_WORKLOAD_SHA256="$(sha256_of "$AUDIT_NOOP_WORKLOAD")"
QEMU_EXECUTABLE="$(realpath -e -- "$(command -v -- "$QEMU_BINARY")")"
QEMU_SHA256="$(sha256_of "$QEMU_EXECUTABLE")"
for pair in \
	"KERNEL_SHA256:$KERNEL_SHA256" \
	"KERNEL_CONFIG_SHA256:$KERNEL_CONFIG_SHA256" \
	"ROOTFS_SHA256:$ROOTFS_SHA256" \
	"RECORDER_SHA256:$RECORDER_SHA256" \
	"OBSERVER_SHA256:$OBSERVER_SHA256" \
	"OUTSIDER_GATE_SHA256:$OUTSIDER_GATE_SHA256" \
	"STRICT_INIT_SHA256:$STRICT_INIT_SHA256" \
	"STRICT_RUNNER_SHA256:$STRICT_RUNNER_SHA256" \
	"QEMU_SHA256:$QEMU_SHA256"; do
	require_sha256 "${pair%%:*}" "${pair#*:}"
done
{
	echo "qemu_executable=$QEMU_EXECUTABLE"
	echo "qemu_sha256=$QEMU_SHA256"
	"$QEMU_EXECUTABLE" --version
} > "$RUN_ROOT/qemu-host-identity.txt"

SSH_OPTIONS=(
	-i "$SSH_KEY"
	-p "$SSH_PORT"
	-o BatchMode=yes
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=2
	-o ServerAliveInterval=2
	-o ServerAliveCountMax=3
)
SCP_OPTIONS=(
	-q
	-i "$SSH_KEY"
	-P "$SSH_PORT"
	-o BatchMode=yes
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=2
	-o ServerAliveInterval=2
	-o ServerAliveCountMax=3
)

ssh_bounded()
{
	local duration="$1"
	shift
	timeout --foreground "$duration" ssh "${SSH_OPTIONS[@]}" "$@"
}

scp_bounded()
{
	local duration="$1"
	shift
	timeout --foreground "$duration" scp "${SCP_OPTIONS[@]}" "$@"
}

qemu_start_time()
{
	local pid="$1"
	local stat_line stat_tail
	local -a stat_fields
	IFS= read -r stat_line < "/proc/$pid/stat" || return 1
	stat_tail="${stat_line##*) }"
	read -r -a stat_fields <<< "$stat_tail"
	[[ "${#stat_fields[@]}" -ge 20 ]] || return 1
	printf '%s\n' "${stat_fields[19]}"
}

qemu_is_running()
{
	local state
	[[ -n "$QEMU_PID" ]] || return 1
	kill -0 "$QEMU_PID" 2>/dev/null || return 1
	state="$(ps -o stat= -p "$QEMU_PID" 2>/dev/null || true)"
	[[ -n "$state" && "$state" != Z* ]]
}

qemu_identity_matches()
{
	local current_start current_executable
	[[ -n "$QEMU_PID" && -n "$QEMU_START_TIME" && \
		-n "$QEMU_EXECUTABLE" ]] || return 1
	current_start="$(qemu_start_time "$QEMU_PID")" || return 1
	current_executable="$(readlink -f -- "/proc/$QEMU_PID/exe")" || return 1
	[[ "$current_start" == "$QEMU_START_TIME" && \
		"$current_executable" == "$QEMU_EXECUTABLE" ]]
}

record_qemu_argv()
{
	local prefix="$1"
	shift
	{
		printf '%q ' "$QEMU_EXECUTABLE" "$@"
		printf '\n'
	} > "$prefix.shell"
	printf '%s\0' "$QEMU_EXECUTABLE" "$@" > "$prefix.nul"
}

adopt_qemu_pid()
{
	[[ "$QEMU_PID" =~ ^[1-9][0-9]*$ ]] && qemu_is_running || {
		echo "QEMU failed immediately after launch" >&2
		return 1
	}
	QEMU_START_TIME="$(qemu_start_time "$QEMU_PID")"
	qemu_identity_matches || {
		echo "could not establish the direct QEMU child identity" >&2
		return 1
	}
}

wait_qemu_success()
{
	local timeout_seconds="$1"
	local label="$2"
	local attempts=$((timeout_seconds * 10))
	local index wait_status=0
	for ((index = 0; index < attempts; index++)); do
		qemu_is_running || break
		sleep 0.1
	done
	if qemu_is_running; then
		echo "$label QEMU exceeded ${timeout_seconds}s" >&2
		return 1
	fi
	wait "$QEMU_PID" || wait_status=$?
	QEMU_PID=""
	QEMU_START_TIME=""
	if [[ "$wait_status" -ne 0 ]]; then
		echo "$label QEMU exited with status $wait_status" >&2
		return 1
	fi
}

stop_qemu()
{
	local pid="$QEMU_PID"
	local wait_status=0
	local attempts
	[[ -n "$pid" ]] || return 0
	if qemu_is_running; then
		qemu_identity_matches || {
			echo "refusing to signal QEMU PID $pid after identity changed" >&2
			return 1
		}
		kill -TERM "$pid" 2>/dev/null || true
		for ((attempts = 0; attempts < 50; attempts++)); do
			qemu_is_running || break
			sleep 0.1
		done
	fi
	if qemu_is_running; then
		qemu_identity_matches || return 1
		kill -KILL "$pid" 2>/dev/null || true
	fi
	wait "$pid" 2>/dev/null || wait_status=$?
	QEMU_PID=""
	QEMU_START_TIME=""
	[[ "$wait_status" -eq 0 || "$wait_status" -eq 137 || \
		"$wait_status" -eq 143 ]]
}

harness_is_running()
{
	local state
	[[ -n "$HARNESS_PID" ]] || return 1
	kill -0 "$HARNESS_PID" 2>/dev/null || return 1
	state="$(ps -o stat= -p "$HARNESS_PID" 2>/dev/null || true)"
	[[ -n "$state" && "$state" != Z* ]]
}

stop_harnessd()
{
	local pid="$HARNESS_PID"
	local wait_status=0
	local attempts
	[[ -n "$pid" ]] || return 0
	if harness_is_running; then
		kill -TERM "$pid" 2>/dev/null || true
		for ((attempts = 0; attempts < 50; attempts++)); do
			harness_is_running || break
			sleep 0.05
		done
	fi
	if harness_is_running; then
		kill -KILL "$pid" 2>/dev/null || true
	fi
	wait "$pid" 2>/dev/null || wait_status=$?
	HARNESS_PID=""
	[[ "$wait_status" -eq 0 || "$wait_status" -eq 124 || \
		"$wait_status" -eq 137 || "$wait_status" -eq 143 ]]
}

remove_private_key()
{
	local path="$1"
	[[ -n "$path" ]] || return 0
	if [[ -e "$path" || -L "$path" ]]; then
		[[ -f "$path" && ! -L "$path" ]] || {
			echo "refusing to unlink non-regular harness secret: $path" >&2
			return 1
		}
		[[ "$(stat -c %h -- "$path")" -eq 1 ]] || {
			echo "refusing to unlink multiply-linked harness secret: $path" >&2
			return 1
		}
		unlink -- "$path"
	fi
}

cleanup_harness_secrets()
{
	local cleanup_status=0
	remove_private_key "$HARNESS_SECRET_KEY" || cleanup_status=1
	remove_private_key "$HARNESS_WRONG_SECRET_KEY" || cleanup_status=1
	if [[ -n "$HARNESS_SOCKET" && \
		(-e "$HARNESS_SOCKET" || -L "$HARNESS_SOCKET") ]]; then
		if [[ -S "$HARNESS_SOCKET" && ! -L "$HARNESS_SOCKET" ]]; then
			unlink -- "$HARNESS_SOCKET" || cleanup_status=1
		else
			echo "refusing to unlink unexpected harness socket: $HARNESS_SOCKET" >&2
			cleanup_status=1
		fi
	fi
	if [[ -n "$HARNESS_SECRET_DIR" && -d "$HARNESS_SECRET_DIR" ]]; then
		rmdir -- "$HARNESS_SECRET_DIR" || cleanup_status=1
	fi
	return "$cleanup_status"
}

cleanup_on_exit()
{
	local status=$?
	trap - EXIT INT TERM
	stop_qemu || status=1
	stop_harnessd || status=1
	cleanup_harness_secrets || status=1
	exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

HARNESS_SECRET_DIR="$(mktemp -d \
	"$PROJECT_DIR/.output/.exclusive-harness-secret.XXXXXX")"
[[ -d "$HARNESS_SECRET_DIR" && ! -L "$HARNESS_SECRET_DIR" ]]
[[ "$(stat -c %a -- "$HARNESS_SECRET_DIR")" == 700 ]]
HARNESS_SECRET_KEY="$HARNESS_SECRET_DIR/ed25519-private.key"
HARNESS_WRONG_SECRET_KEY="$HARNESS_SECRET_DIR/wrong-ed25519-private.key"
HARNESS_SOCKET="/disk/bpfguard/linux/.bpfobs-harness-$$.sock"
[[ ! -e "$HARNESS_SOCKET" && ! -L "$HARNESS_SOCKET" ]]
HARNESS_PUBLIC_KEY="$AUDIT_INPUTS/harness-public.key"
HARNESS_WRONG_PUBLIC_KEY="$AUDIT_INPUTS/wrong-harness-public.key"
{
	printf 'trusted_fingerprint='
	"$AUDIT_HARNESSD" keygen --secret-key "$HARNESS_SECRET_KEY" \
		--public-key "$HARNESS_PUBLIC_KEY"
	printf 'wrong_fingerprint='
	"$AUDIT_HARNESSD" keygen --secret-key "$HARNESS_WRONG_SECRET_KEY" \
		--public-key "$HARNESS_WRONG_PUBLIC_KEY"
} > "$RUN_ROOT/harness-keygen.log"
for secret in "$HARNESS_SECRET_KEY" "$HARNESS_WRONG_SECRET_KEY"; do
	[[ -f "$secret" && ! -L "$secret" ]]
	[[ "$(stat -c %a -- "$secret")" == 600 ]]
	[[ "$(stat -c %h -- "$secret")" -eq 1 ]]
done
[[ "$(sha256_of "$HARNESS_PUBLIC_KEY")" != \
	"$(sha256_of "$HARNESS_WRONG_PUBLIC_KEY")" ]]

echo "P0 provisioning immutable strict inputs"
qemu-img create -q -f qcow2 -F raw -b "$ROOTFS_IMAGE" "$PROVISION_OVERLAY"
PROVISION_QEMU_ARGS=(
	-m 2048
	-smp 2
	-display none
	-monitor none
	-serial "file:$PROVISION_CONSOLE"
	-no-reboot
	-enable-kvm
	-cpu host,migratable=off
	-device e1000,netdev=net0
	-netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22"
	-drive "file=$PROVISION_OVERLAY,format=qcow2,index=0,media=disk,snapshot=off"
	-kernel "$AUDIT_KERNEL"
	-append 'root=/dev/sda rw console=ttyS0,115200 earlyprintk=serial net.ifnames=0'
)
record_qemu_argv "$RUN_ROOT/provision-qemu.argv" "${PROVISION_QEMU_ARGS[@]}"
TMPDIR="$PROVISION_QEMU_TMP" "$QEMU_EXECUTABLE" \
	"${PROVISION_QEMU_ARGS[@]}" > /dev/null 2> "$PROVISION_QEMU_STDERR" &
QEMU_PID=$!
adopt_qemu_pid

guest_ready=0
for _attempt in $(seq 1 90); do
	if ssh_bounded 5s root@127.0.0.1 \
		'test -d /sys/fs/cgroup && command -v setcap >/dev/null && command -v getcap >/dev/null && uname -r' \
		> "$RUN_ROOT/kernel-release.txt" 2>/dev/null; then
		guest_ready=1
		break
	fi
	qemu_is_running || break
	sleep 1
done
if [[ "$guest_ready" -ne 1 ]]; then
	echo "provisioning Guest SSH did not become ready" >&2
	tail -100 "$PROVISION_CONSOLE" >&2 || true
	exit 1
fi

ssh_bounded "$SSH_COMMAND_TIMEOUT" root@127.0.0.1 \
	"test ! -e '$STRICT_INPUT_ROOT' && install -d -o root -g root -m 0755 '$STRICT_INPUT_ROOT' && install -d -o root -g root -m 0755 /evidence"
scp_bounded "$SCP_COMMAND_TIMEOUT" \
	"$AUDIT_STRICT_INIT" \
	"$AUDIT_INPUTS/guest-strict-e2e.sh" \
	"$AUDIT_BIN" "$AUDIT_ASSERT_BIN" "$AUDIT_OUTSIDER_GATE" \
	"$AUDIT_OBJ" "$AUDIT_WORKLOAD" "$AUDIT_NOOP_WORKLOAD" \
	"$AUDIT_INPUTS/exclusive-vm-scope.json" \
	"$HARNESS_PUBLIC_KEY" "$HARNESS_WRONG_PUBLIC_KEY" \
	"root@127.0.0.1:$STRICT_INPUT_ROOT/"

if ! ssh_bounded "$SCP_COMMAND_TIMEOUT" root@127.0.0.1 \
	bash -s -- "$STRICT_INPUT_ROOT" \
	> "$RUN_ROOT/provision-guest.log" \
	2> "$RUN_ROOT/provision-guest.stderr" <<'PROVISION_SCRIPT'
set -euo pipefail
readonly input_root="$1"
readonly observer="$input_root/bpf-state-observer"
readonly outsider="$input_root/vm-outsider-gate-assert"
readonly map_workload="$input_root/map-lifecycle"
readonly expected_count=11

[[ "$input_root" == /opt/bpf-state-observer-exclusive-e2e ]]
[[ -d "$input_root" && ! -L "$input_root" ]]
mapfile -t entries < <(
	find "$input_root" -mindepth 1 -maxdepth 1 -printf '%f\n' |
		LC_ALL=C sort
)
[[ "${#entries[@]}" -eq "$expected_count" ]]
expected=(
	bpf-state-observer
	exclusive-noop
	exclusive-vm-scope.json
	guest-strict-e2e.sh
	harness-public.key
	map-lifecycle
	recorder.bpf.o
	strict-init
	vm-e2e-assert
	vm-outsider-gate-assert
	wrong-harness-public.key
)
for index in "${!expected[@]}"; do
	[[ "${entries[$index]}" == "${expected[$index]}" ]]
done
for path in "$input_root"/*; do
	[[ -f "$path" && ! -L "$path" && "$(stat -c %h -- "$path")" -eq 1 ]]
	chown root:root "$path"
done
chown root:root "$input_root" /evidence
chmod 0755 "$input_root" /evidence
chmod 0555 \
	"$input_root/strict-init" \
	"$input_root/guest-strict-e2e.sh" \
	"$input_root/bpf-state-observer" \
	"$input_root/vm-e2e-assert" \
	"$input_root/vm-outsider-gate-assert" \
	"$input_root/map-lifecycle" \
	"$input_root/exclusive-noop"
chmod 0444 \
	"$input_root/recorder.bpf.o" \
	"$input_root/exclusive-vm-scope.json" \
	"$input_root/harness-public.key" \
	"$input_root/wrong-harness-public.key"
setcap 'cap_sys_admin,cap_perfmon,cap_bpf=ep' "$observer"
setcap 'cap_sys_admin,cap_perfmon,cap_bpf=ep' "$outsider"
setcap 'cap_bpf=ep' "$map_workload"

echo 'result=PASS'
echo "bash_sha256=$(sha256sum /bin/bash | awk '{print $1}')"
echo "strict_input_count=${#entries[@]}"
for path in "$input_root"/*; do
	printf 'input='
	stat -c '%n uid=%u gid=%g mode=%a links=%h' "$path"
	digest="$(sha256sum "$path" | awk '{print $1}')"
	echo "input_sha256=$path:$digest"
done
echo 'file_capabilities_begin'
getcap -n "$input_root"/* || true
echo 'file_capabilities_end'
sync
PROVISION_SCRIPT
then
	cat "$RUN_ROOT/provision-guest.log" >&2 || true
	cat "$RUN_ROOT/provision-guest.stderr" >&2 || true
	echo "strict input provisioning failed" >&2
	exit 1
fi

# Record the entire rootfs file-capability inventory. Existing unrelated
# distro capabilities are allowed because the strict runner's bounding set
# masks them. Any SYS_ADMIN/PERFMON/BPF grant must be exactly one of the three
# measured files provisioned above.
if ! ssh_bounded 120s root@127.0.0.1 \
	"timeout --foreground 90s bash -c 'find / -xdev -type f -exec getcap -n {} +'" \
	> "$RUN_ROOT/provision-root-filecaps.txt" \
	2> "$RUN_ROOT/provision-root-filecaps.stderr"; then
	echo "full provisioned-root file-capability enumeration failed" >&2
	cat "$RUN_ROOT/provision-root-filecaps.stderr" >&2 || true
	exit 1
fi
if ! ssh_bounded "$SSH_COMMAND_TIMEOUT" root@127.0.0.1 \
	"getcap -n '$STRICT_INPUT_ROOT/bpf-state-observer' '$STRICT_INPUT_ROOT/vm-outsider-gate-assert' '$STRICT_INPUT_ROOT/map-lifecycle'" \
	> "$RUN_ROOT/provision-expected-sensitive-filecaps.txt" \
	2> "$RUN_ROOT/provision-expected-sensitive-filecaps.stderr"; then
	echo "exact intended file-capability query failed" >&2
	exit 1
fi
[[ ! -s "$RUN_ROOT/provision-root-filecaps.stderr" ]]
[[ ! -s "$RUN_ROOT/provision-expected-sensitive-filecaps.stderr" ]]
LC_ALL=C sort -o "$RUN_ROOT/provision-root-filecaps.txt" \
	"$RUN_ROOT/provision-root-filecaps.txt"
LC_ALL=C sort -o "$RUN_ROOT/provision-expected-sensitive-filecaps.txt" \
	"$RUN_ROOT/provision-expected-sensitive-filecaps.txt"
grep -E 'cap_(sys_admin|perfmon|bpf)' "$RUN_ROOT/provision-root-filecaps.txt" |
	LC_ALL=C sort > "$RUN_ROOT/provision-sensitive-filecaps.txt"
[[ "$(wc -l < "$RUN_ROOT/provision-expected-sensitive-filecaps.txt")" -eq 3 ]]
cmp -s "$RUN_ROOT/provision-sensitive-filecaps.txt" \
	"$RUN_ROOT/provision-expected-sensitive-filecaps.txt" || {
	echo "root contains a sensitive file capability outside the exact allowlist" >&2
	exit 1
}

# The systemd boot never runs Observer. Freeze it only after a clean Guest
# poweroff and successful QEMU exit.
ssh_bounded 15s root@127.0.0.1 'sync; systemctl poweroff' \
	> "$RUN_ROOT/provision-poweroff.log" 2>&1 || true
if ! wait_qemu_success "$PROVISION_TIMEOUT_SECONDS" provisioning; then
	tail -100 "$PROVISION_CONSOLE" >&2 || true
	cat "$PROVISION_QEMU_STDERR" >&2 || true
	exit 1
fi
qemu-img check -f qcow2 "$PROVISION_OVERLAY" \
	> "$RUN_ROOT/provision-overlay-check.log" 2>&1
chmod 0444 "$PROVISION_OVERLAY"
PROVISION_OVERLAY_SHA256="$(sha256_of "$PROVISION_OVERLAY")"
require_sha256 PROVISION_OVERLAY_SHA256 "$PROVISION_OVERLAY_SHA256"
printf '%s\n' "$PROVISION_OVERLAY_SHA256" \
	> "$RUN_ROOT/provision-overlay.sha256"
qemu-img info --backing-chain --output=json "$PROVISION_OVERLAY" \
	> "$RUN_ROOT/provision-overlay-info.json"

# Flatten only for Host byte inspection. The strict VM consumes a child of the
# frozen qcow2 chain; all three root representations are rehashed later.
TMPDIR="$PROVISION_QEMU_TMP" qemu-img convert -f qcow2 -O raw \
	"$PROVISION_OVERLAY" "$PROVISION_FLAT"
chmod 0444 "$PROVISION_FLAT"
PROVISION_FLAT_SHA256="$(sha256_of "$PROVISION_FLAT")"
require_sha256 PROVISION_FLAT_SHA256 "$PROVISION_FLAT_SHA256"
printf '%s\n' "$PROVISION_FLAT_SHA256" > "$RUN_ROOT/provision-flat.sha256"

PROVISIONED_NAMES=(
	strict-init
	guest-strict-e2e.sh
	bpf-state-observer
	vm-e2e-assert
	vm-outsider-gate-assert
	recorder.bpf.o
	map-lifecycle
	exclusive-noop
	exclusive-vm-scope.json
	harness-public.key
	wrong-harness-public.key
)
for name in "${PROVISIONED_NAMES[@]}"; do
	(
		cd "$PROVISION_EXTRACT"
		debugfs -R "dump $STRICT_INPUT_ROOT/$name $name" "$PROVISION_FLAT"
	) >> "$RUN_ROOT/provision-debugfs.log" 2>&1
	cmp -s "$AUDIT_INPUTS/$name" "$PROVISION_EXTRACT/$name" || {
		echo "frozen provisioned bytes differ for $name" >&2
		exit 1
	}
done
(
	cd "$PROVISION_EXTRACT"
	debugfs -R 'dump /bin/bash bash' "$PROVISION_FLAT"
) >> "$RUN_ROOT/provision-debugfs.log" 2>&1
for path in \
	"$STRICT_INPUT_ROOT/bpf-state-observer" \
	"$STRICT_INPUT_ROOT/vm-outsider-gate-assert" \
	"$STRICT_INPUT_ROOT/map-lifecycle" \
	"$STRICT_INPUT_ROOT" /evidence; do
	debugfs -R "stat $path" "$PROVISION_FLAT"
	debugfs -R "ea_list $path" "$PROVISION_FLAT"
done > "$RUN_ROOT/provision-debugfs-metadata.log" 2>&1

PROVISION_BASH_SHA256="$(sha256_of "$PROVISION_EXTRACT/bash")"
GUEST_REPORTED_BASH_SHA256="$(sed -n 's/^bash_sha256=//p' \
	"$RUN_ROOT/provision-guest.log")"
require_sha256 PROVISION_BASH_SHA256 "$PROVISION_BASH_SHA256"
[[ "$(grep -c '^bash_sha256=' "$RUN_ROOT/provision-guest.log")" -eq 1 ]]
[[ "$GUEST_REPORTED_BASH_SHA256" == "$PROVISION_BASH_SHA256" ]] || {
	echo "offline-extracted /bin/bash differs from provisioning report" >&2
	exit 1
}
printf '%s\n' "$PROVISION_BASH_SHA256" > "$RUN_ROOT/provision-bash.sha256"
[[ "$(sha256_of "$PROVISION_FLAT")" == "$PROVISION_FLAT_SHA256" ]]
[[ "$(sha256_of "$PROVISION_OVERLAY")" == "$PROVISION_OVERLAY_SHA256" ]]
[[ "$(sha256_of "$ROOTFS_IMAGE")" == "$ROOTFS_SHA256" ]]

qemu-img create -q -f qcow2 -F qcow2 -b "$PROVISION_OVERLAY" \
	"$STRICT_OVERLAY"
qemu-img check -f qcow2 "$STRICT_OVERLAY" \
	> "$RUN_ROOT/strict-overlay-check-before.log" 2>&1
chmod 0444 "$STRICT_OVERLAY"
STRICT_OVERLAY_SHA256="$(sha256_of "$STRICT_OVERLAY")"
require_sha256 STRICT_OVERLAY_SHA256 "$STRICT_OVERLAY_SHA256"
printf '%s\n' "$STRICT_OVERLAY_SHA256" \
	> "$RUN_ROOT/strict-overlay-before.sha256"
qemu-img info --backing-chain --output=json "$STRICT_OVERLAY" \
	> "$RUN_ROOT/strict-overlay-info.json"

truncate -s "$EVIDENCE_BYTES" "$EVIDENCE_IMAGE"
mkfs.ext4 -q -F -m 0 -L BPF_OBS_EVID \
	-E lazy_itable_init=0,lazy_journal_init=0 "$EVIDENCE_IMAGE"
chmod 0600 "$EVIDENCE_IMAGE"
EVIDENCE_INITIAL_SHA256="$(sha256_of "$EVIDENCE_IMAGE")"
require_sha256 EVIDENCE_INITIAL_SHA256 "$EVIDENCE_INITIAL_SHA256"
printf '%s\n' "$EVIDENCE_INITIAL_SHA256" > "$RUN_ROOT/evidence-initial.sha256"
debugfs -R stats "$EVIDENCE_IMAGE" \
	> "$RUN_ROOT/evidence-initial-debugfs.log" 2>&1

BOOT_UUID="$(< /proc/sys/kernel/random/uuid)"
BOOT_NONCE="${BOOT_UUID//-/}"
[[ "$BOOT_NONCE" =~ ^[a-f0-9]{32}$ ]] || {
	echo "Host boot nonce is not canonical lowercase hexadecimal" >&2
	exit 1
}
printf '%s\n' "$BOOT_NONCE" > "$RUN_ROOT/strict-boot-nonce.txt"

# Hash a non-circular semantic argv shape. The two dynamic cmdline values are
# exact placeholders because each carries the digest of this shape; the final
# literal argv is separately recorded byte-for-byte.
QEMU_SHAPE="$RUN_ROOT/strict-qemu-shape.txt"
cat > "$QEMU_SHAPE" <<EOF
schema_version=1
qemu_sha256=$QEMU_SHA256
machine=default-pc-kvm
memory_mib=2048
vcpus=2
nodefaults=true
user_config=false
display=none
monitor=none
network_devices=0
serial=ttyS0-file
root_bus=virtio-blk
root_device=vda
root_overlay_sha256=$STRICT_OVERLAY_SHA256
root_readonly=true
root_snapshot=false
evidence_bus=virtio-blk
evidence_device=vdb
evidence_initial_sha256=$EVIDENCE_INITIAL_SHA256
evidence_readonly=false
evidence_snapshot=false
harness_transport=virtio-serial:org.allox.harness
kernel_sha256=$KERNEL_SHA256
init=/opt/bpf-state-observer-exclusive-e2e/strict-init
cmdline_identity=EXACT_POLICY_BOUND_VALUE
cmdline_policy_sha256=EXACT_POLICY_BOUND_VALUE
boot_nonce=$BOOT_NONCE
EOF
QEMU_SHAPE_SHA256="$(sha256_of "$QEMU_SHAPE")"
require_sha256 QEMU_SHAPE_SHA256 "$QEMU_SHAPE_SHA256"

# Compact labels keep the full x86 kernel command line below 1900 bytes. The
# adjacent component map gives every label an unambiguous audit meaning.
HARNESS_KERNEL_IDENTITY="k:$KERNEL_SHA256;c:$KERNEL_CONFIG_SHA256;b:$ROOTFS_SHA256;p:$PROVISION_OVERLAY_SHA256;f:$PROVISION_FLAT_SHA256;o:$STRICT_OVERLAY_SHA256;e:$EVIDENCE_INITIAL_SHA256;i:$STRICT_INIT_SHA256;r:$STRICT_RUNNER_SHA256;s:$PROVISION_BASH_SHA256;g:$OUTSIDER_GATE_SHA256;q:$QEMU_SHA256;a:$QEMU_SHAPE_SHA256;n:$BOOT_NONCE"
[[ "$HARNESS_KERNEL_IDENTITY" != *[[:space:]]* ]]
cat > "$RUN_ROOT/harness-kernel-identity-components.txt" <<EOF
schema_version=1
compact_identity=$HARNESS_KERNEL_IDENTITY
k=kernel_bzimage_sha256:$KERNEL_SHA256
c=kernel_config_sha256:$KERNEL_CONFIG_SHA256
b=base_rootfs_sha256:$ROOTFS_SHA256
p=frozen_provision_overlay_sha256:$PROVISION_OVERLAY_SHA256
f=offline_flattened_provision_sha256:$PROVISION_FLAT_SHA256
o=readonly_strict_overlay_initial_sha256:$STRICT_OVERLAY_SHA256
e=fresh_evidence_initial_sha256:$EVIDENCE_INITIAL_SHA256
i=strict_init_sha256:$STRICT_INIT_SHA256
r=strict_runner_sha256:$STRICT_RUNNER_SHA256
s=provisioned_bash_sha256:$PROVISION_BASH_SHA256
g=outside_actor_gate_sha256:$OUTSIDER_GATE_SHA256
q=qemu_binary_sha256:$QEMU_SHA256
a=qemu_shape_sha256:$QEMU_SHAPE_SHA256
n=fresh_boot_nonce:$BOOT_NONCE
EOF
printf '%s\n' "$HARNESS_KERNEL_IDENTITY" \
	> "$RUN_ROOT/harness-kernel-identity.txt"

EXCLUSIVE_SCOPE_SHA256="$("$AUDIT_HARNESSD" canonical-json-digest \
	--input "$AUDIT_INPUTS/exclusive-vm-scope.json")"
require_sha256 EXCLUSIVE_SCOPE_SHA256 "$EXCLUSIVE_SCOPE_SHA256"
HARNESS_POLICY_ID="exclusive-vm-v1-$RUN_TAG"
HARNESS_POLICY="$AUDIT_INPUTS/exclusive-vm-v1-policy.json"
cat > "$HARNESS_POLICY" <<EOF
{
  "protocol_version": 1,
  "contract_id": "exclusive-vm-v1",
  "policy_id": "$HARNESS_POLICY_ID",
  "observer_exclusions_derivation": "MEASURED_OBSERVER_RECORDER_OWNED_V1",
  "allowed_kernel_identities": ["$HARNESS_KERNEL_IDENTITY"],
  "allowed_observer_sha256": ["$OBSERVER_SHA256"],
  "allowed_recorder_sha256": ["$RECORDER_SHA256"],
  "allowed_scope_sha256": ["$EXCLUSIVE_SCOPE_SHA256"],
  "allowed_workloads": [
    {
      "run_id": "e2e-exclusive-noop",
      "run_epoch": 1101,
      "cgroup_path": "/sys/fs/cgroup/bpf-state-observer/e2e-exclusive-noop",
      "argv": ["$STRICT_INPUT_ROOT/exclusive-noop", "--exclusive-contract"],
      "executable_sha256": "$NOOP_WORKLOAD_SHA256"
    },
    {
      "run_id": "e2e-exclusive-ephemeral",
      "run_epoch": 1102,
      "cgroup_path": "/sys/fs/cgroup/bpf-state-observer/e2e-exclusive-ephemeral",
      "argv": ["$STRICT_INPUT_ROOT/map-lifecycle", "--ephemeral", "--exclusive-contract"],
      "executable_sha256": "$WORKLOAD_SHA256"
    },
    {
      "run_id": "e2e-exclusive-restore",
      "run_epoch": 1103,
      "cgroup_path": "/sys/fs/cgroup/bpf-state-observer/e2e-exclusive-restore",
      "argv": ["$STRICT_INPUT_ROOT/map-lifecycle", "--transient-restore", "--exclusive-contract"],
      "executable_sha256": "$WORKLOAD_SHA256"
    }
  ],
  "checks": [
    {"name":"exclusive_vm","passed":true,"evidence":"Host launches the offline-inspected frozen root under the measured static PID1 with -nodefaults, no NIC, read-only vda, separate fresh vdb, exact virtio-serial channel and audited argv shape"},
    {"name":"no_other_bpf_actors","passed":true,"evidence":"exact strict-init requires one userspace PID and empty global Program/Map/Link and FD inventories before releasing the non-root runner; the production recorder gate rejects every outside-cgroup bpf() attempt and its transient-map negative probe is mandatory"},
    {"name":"no_external_bpf_fds","passed":true,"evidence":"strict-init requires PID1 has no BPF descriptor; measured Observer child pre-exec applies close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC); exact fixtures create no descendants"},
    {"name":"scm_rights_blocked","passed":true,"evidence":"fixture seccomp denies socket, socketpair, sendmsg, recvmsg, sendmmsg and recvmmsg"},
    {"name":"pidfd_getfd_blocked","passed":true,"evidence":"fixture seccomp denies pidfd_getfd"},
    {"name":"writable_map_mmap_blocked","passed":true,"evidence":"fixture seccomp denies mmap and mremap after installing its contract"},
    {"name":"cgroup_empty","passed":true,"evidence":"Observer requires populated=0 and frozen=1 before PRE_S1"},
    {"name":"attachment_dependency_closure_complete","passed":true,"evidence":"exact map-only fixtures cannot load programs or create attachment dependencies under seccomp"},
    {"name":"special_map_values_excluded","passed":true,"evidence":"exact fixtures create only no-BTF scalar-value maps from the contract whitelist"},
    {"name":"prog_test_run_blocked","passed":true,"evidence":"fixture seccomp allows only MAP_CREATE and MAP_UPDATE_ELEM bpf commands"},
    {"name":"new_bpf_loaders_blocked","passed":true,"evidence":"fixed workload digests and seccomp command allowlist exclude BPF_PROG_LOAD and BPF_BTF_LOAD"},
    {"name":"in_flight_bpf_barrier_complete","passed":true,"evidence":"empty frozen cgroup, paired syscall records, durable WAL drain, post-S1 reconciliation, FINAL_ACK, and tracepoint-detach synchronization are mandatory"}
  ]
}
EOF
HARNESS_POLICY_SHA256="$("$AUDIT_HARNESSD" policy-digest \
	--policy "$HARNESS_POLICY")"
require_sha256 HARNESS_POLICY_SHA256 "$HARNESS_POLICY_SHA256"
printf '%s\n' "$HARNESS_POLICY_SHA256" > "$RUN_ROOT/harness-policy.sha256"

STRICT_CMDLINE="root=/dev/vda ro rootfstype=ext4 console=ttyS0,115200 earlyprintk=serial init=$STRICT_INPUT_ROOT/strict-init bpfobs.strict=1 bpfobs.recorder_sha256=$RECORDER_SHA256 bpfobs.policy_id=$HARNESS_POLICY_ID bpfobs.policy_sha256=$HARNESS_POLICY_SHA256 bpfobs.kernel_identity=$HARNESS_KERNEL_IDENTITY"
if (( ${#STRICT_CMDLINE} >= 1900 )); then
	echo "strict kernel command line is ${#STRICT_CMDLINE} bytes; limit is 1899" >&2
	exit 1
fi
printf '%s\n' "$STRICT_CMDLINE" > "$RUN_ROOT/strict-kernel-cmdline.txt"
printf '%s\n' "${#STRICT_CMDLINE}" > "$RUN_ROOT/strict-kernel-cmdline-length.txt"

echo "S0 launching authenticated minimal strict VM"
timeout --foreground 330s "$AUDIT_HARNESSD" serve \
	--socket "$HARNESS_SOCKET" \
	--secret-key "$HARNESS_SECRET_KEY" \
	--policy "$HARNESS_POLICY" \
	--max-sessions 3 \
	--timeout-ms 300000 \
	> "$RUN_ROOT/harnessd.log" 2>&1 &
HARNESS_PID=$!
for _attempt in $(seq 1 200); do
	[[ -S "$HARNESS_SOCKET" ]] && break
	if ! harness_is_running; then
		echo "authenticated harness exited before binding its socket" >&2
		cat "$RUN_ROOT/harnessd.log" >&2
		exit 1
	fi
	sleep 0.025
done
[[ -S "$HARNESS_SOCKET" ]] || {
	echo "timed out waiting for authenticated harness socket" >&2
	exit 1
}

# The signer read its key before publishing the socket. No private key or
# private-key directory survives into the strict boot or final audit.
remove_private_key "$HARNESS_SECRET_KEY"
remove_private_key "$HARNESS_WRONG_SECRET_KEY"
rmdir -- "$HARNESS_SECRET_DIR"
[[ ! -e "$HARNESS_SECRET_DIR" && ! -L "$HARNESS_SECRET_DIR" ]]

STRICT_QEMU_ARGS=(
	-machine accel=kvm
	-m 2048
	-smp 2
	-nodefaults
	-no-user-config
	-display none
	-monitor none
	-serial "file:$STRICT_CONSOLE"
	-no-reboot
	-cpu host,migratable=off
	-drive "file=$STRICT_OVERLAY,format=qcow2,if=virtio,readonly=on,snapshot=off"
	-drive "file=$EVIDENCE_IMAGE,format=raw,if=virtio,readonly=off,snapshot=off"
	-chardev "socket,id=harness,path=$HARNESS_SOCKET"
	-device virtio-serial-pci
	-device virtserialport,chardev=harness,name=org.allox.harness
	-kernel "$AUDIT_KERNEL"
	-append "$STRICT_CMDLINE"
)
record_qemu_argv "$RUN_ROOT/strict-qemu.argv" "${STRICT_QEMU_ARGS[@]}"
grep -q -- '-nodefaults' "$RUN_ROOT/strict-qemu.argv.shell"
if grep -Eq -- '(^|[[:space:]])(-net|-nic|.*netdev=)' \
	"$RUN_ROOT/strict-qemu.argv.shell"; then
	echo "strict QEMU argv unexpectedly contains a network option" >&2
	exit 1
fi
grep -zFxq -- \
	"file=$STRICT_OVERLAY,format=qcow2,if=virtio,readonly=on,snapshot=off" \
	"$RUN_ROOT/strict-qemu.argv.nul"
grep -zFxq -- \
	"file=$EVIDENCE_IMAGE,format=raw,if=virtio,readonly=off,snapshot=off" \
	"$RUN_ROOT/strict-qemu.argv.nul"
grep -zFxq -- "$STRICT_CMDLINE" "$RUN_ROOT/strict-qemu.argv.nul"

TMPDIR="$STRICT_QEMU_TMP" "$QEMU_EXECUTABLE" "${STRICT_QEMU_ARGS[@]}" \
	> /dev/null 2> "$STRICT_QEMU_STDERR" &
QEMU_PID=$!
adopt_qemu_pid
if ! wait_qemu_success "$STRICT_TIMEOUT_SECONDS" strict; then
	tail -200 "$STRICT_CONSOLE" >&2 || true
	cat "$STRICT_QEMU_STDERR" >&2 || true
	cat "$RUN_ROOT/harnessd.log" >&2 || true
	exit 1
fi

if ! wait "$HARNESS_PID"; then
	HARNESS_PID=""
	echo "authenticated harness did not complete exactly three sessions" >&2
	cat "$RUN_ROOT/harnessd.log" >&2 || true
	exit 1
fi
HARNESS_PID=""
[[ ! -e "$HARNESS_SOCKET" && ! -L "$HARNESS_SOCKET" ]]

STRICT_OVERLAY_AFTER_SHA256="$(sha256_of "$STRICT_OVERLAY")"
printf '%s\n' "$STRICT_OVERLAY_AFTER_SHA256" \
	> "$RUN_ROOT/strict-overlay-after.sha256"
[[ "$STRICT_OVERLAY_AFTER_SHA256" == "$STRICT_OVERLAY_SHA256" ]] || {
	echo "read-only strict root overlay changed during strict boot" >&2
	exit 1
}
qemu-img check -f qcow2 "$STRICT_OVERLAY" \
	> "$RUN_ROOT/strict-overlay-check-after.log" 2>&1
[[ "$(sha256_of "$PROVISION_OVERLAY")" == "$PROVISION_OVERLAY_SHA256" ]]
[[ "$(sha256_of "$PROVISION_FLAT")" == "$PROVISION_FLAT_SHA256" ]]
[[ "$(sha256_of "$ROOTFS_IMAGE")" == "$ROOTFS_SHA256" ]]

# Freeze the original evidence and use a copy for ext4 journal recovery. The
# original is never opened writable again. Hashes prove copying, recovery, and
# extraction did not mutate either frozen source unexpectedly.
chmod 0444 "$EVIDENCE_IMAGE"
EVIDENCE_FINAL_SHA256="$(sha256_of "$EVIDENCE_IMAGE")"
require_sha256 EVIDENCE_FINAL_SHA256 "$EVIDENCE_FINAL_SHA256"
printf '%s\n' "$EVIDENCE_FINAL_SHA256" > "$RUN_ROOT/evidence-final.sha256"
cp --reflink=auto --sparse=always "$EVIDENCE_IMAGE" "$EVIDENCE_RECOVERY_IMAGE"
[[ "$(sha256_of "$EVIDENCE_IMAGE")" == "$EVIDENCE_FINAL_SHA256" ]]
[[ "$(sha256_of "$EVIDENCE_RECOVERY_IMAGE")" == "$EVIDENCE_FINAL_SHA256" ]]
chmod 0600 "$EVIDENCE_RECOVERY_IMAGE"
set +e
e2fsck -f -y "$EVIDENCE_RECOVERY_IMAGE" \
	> "$RUN_ROOT/evidence-recovery-e2fsck.log" 2>&1
E2FSCK_STATUS=$?
set -e
printf '%s\n' "$E2FSCK_STATUS" > "$RUN_ROOT/evidence-recovery-e2fsck.status"
[[ "$E2FSCK_STATUS" -eq 0 || "$E2FSCK_STATUS" -eq 1 ]] || {
	echo "evidence recovery e2fsck failed with status $E2FSCK_STATUS" >&2
	exit 1
}
chmod 0444 "$EVIDENCE_RECOVERY_IMAGE"
EVIDENCE_RECOVERY_SHA256="$(sha256_of "$EVIDENCE_RECOVERY_IMAGE")"
require_sha256 EVIDENCE_RECOVERY_SHA256 "$EVIDENCE_RECOVERY_SHA256"
printf '%s\n' "$EVIDENCE_RECOVERY_SHA256" \
	> "$RUN_ROOT/evidence-recovery.sha256"

install -d -m 0700 "$EVIDENCE_EXTRACT"
(
	cd "$EVIDENCE_EXTRACT"
	debugfs -R 'rdump / .' "$EVIDENCE_RECOVERY_IMAGE"
) > "$RUN_ROOT/evidence-debugfs.log" 2>&1
[[ "$(sha256_of "$EVIDENCE_RECOVERY_IMAGE")" == "$EVIDENCE_RECOVERY_SHA256" ]]
[[ "$(sha256_of "$EVIDENCE_IMAGE")" == "$EVIDENCE_FINAL_SHA256" ]]

if find "$EVIDENCE_EXTRACT" -type l -print -quit | grep -q .; then
	echo "recovered evidence contains a symbolic link" >&2
	exit 1
fi
if find "$EVIDENCE_EXTRACT" ! -type f ! -type d -print -quit | grep -q .; then
	echo "recovered evidence contains a non-file/non-directory node" >&2
	exit 1
fi
[[ -d "$EVIDENCE_EXTRACT/results" && -d "$EVIDENCE_EXTRACT/supervisor" ]]
[[ -d "$EVIDENCE_EXTRACT/lost+found" && \
	-z "$(find "$EVIDENCE_EXTRACT/lost+found" -mindepth 1 -print -quit)" ]]
STRICT_RESULTS="$EVIDENCE_EXTRACT/results"
STRICT_SUPERVISOR="$EVIDENCE_EXTRACT/supervisor"

echo "S1 independently verifying recovered strict evidence"
HOST_HARNESS_VERIFY_OPTIONS=(
	--harness-public-key "$HARNESS_PUBLIC_KEY"
	--harness-policy-id "$HARNESS_POLICY_ID"
	--expected-harness-policy-sha256 "$HARNESS_POLICY_SHA256"
	--harness-kernel-identity "$HARNESS_KERNEL_IDENTITY"
)
for fixture in exclusive-noop exclusive-ephemeral exclusive-restore; do
	"$AUDIT_BIN" verify-run \
		--run-dir "$STRICT_RESULTS/runs/$fixture" \
		--expected-recorder-sha256 "$RECORDER_SHA256" \
		"${HOST_HARNESS_VERIFY_OPTIONS[@]}" \
		> "$HOST_RESULTS/verify-$fixture.json"
	"$AUDIT_ASSERT_BIN" "$fixture" "$STRICT_RESULTS/runs/$fixture" \
		> "$HOST_RESULTS/assert-$fixture.log" 2>&1
	{
		echo result=PASS
		echo "fixture=$fixture"
	} >> "$HOST_RESULTS/assert-$fixture.log"
done

if "$AUDIT_BIN" verify-run \
	--run-dir "$STRICT_RESULTS/runs/exclusive-noop" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	> /dev/null 2> "$HOST_RESULTS/exclusive-no-key.stderr"; then
	echo "Host accepted authenticated evidence without a trusted key/policy" >&2
	exit 1
fi
HOST_WRONG_KEY_VERIFY_OPTIONS=(
	--harness-public-key "$HARNESS_WRONG_PUBLIC_KEY"
	--harness-policy-id "$HARNESS_POLICY_ID"
	--expected-harness-policy-sha256 "$HARNESS_POLICY_SHA256"
	--harness-kernel-identity "$HARNESS_KERNEL_IDENTITY"
)
if "$AUDIT_BIN" verify-run \
	--run-dir "$STRICT_RESULTS/runs/exclusive-noop" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	"${HOST_WRONG_KEY_VERIFY_OPTIONS[@]}" \
	> /dev/null 2> "$HOST_RESULTS/exclusive-wrong-key.stderr"; then
	echo "Host accepted authenticated evidence under the wrong key" >&2
	exit 1
fi
HOST_TAMPERED_RUN="$HOST_RESULTS/tampered-exclusive-noop"
[[ ! -e "$HOST_TAMPERED_RUN" && ! -L "$HOST_TAMPERED_RUN" ]]
cp -a -- "$STRICT_RESULTS/runs/exclusive-noop" "$HOST_TAMPERED_RUN"
printf '\n' >> "$HOST_TAMPERED_RUN/verdict.json"
if "$AUDIT_BIN" verify-run \
	--run-dir "$HOST_TAMPERED_RUN" \
	--expected-recorder-sha256 "$RECORDER_SHA256" \
	"${HOST_HARNESS_VERIFY_OPTIONS[@]}" \
	> /dev/null 2> "$HOST_RESULTS/exclusive-tampered.stderr"; then
	echo "Host accepted a modified authenticated evidence copy" >&2
	exit 1
fi

# A signed transcript alone is insufficient. Require the measured supervisor,
# strict runner, signer, console, root immutability, and offline recovery to
# independently reach their exact terminal states.
grep -qx 'strict_root_block_read_only=1' "$STRICT_SUPERVISOR/strict-init.status"
grep -qx 'result=PASS' "$STRICT_SUPERVISOR/strict-init.status"
grep -qx 'runner_wait_status=0' "$STRICT_SUPERVISOR/strict-init.status"
grep -qx 'final_userspace_processes=1' "$STRICT_SUPERVISOR/strict-init.status"
grep -qx 'final_pid1_bpf_fds=0' "$STRICT_SUPERVISOR/strict-init.status"
grep -qx 'final_bpffs_entries=0' "$STRICT_SUPERVISOR/strict-init.status"
grep -qx 'final_global_inventory=VERIFIED_RUNNER_FILECAP_SNAPSHOT_EMPTY' \
	"$STRICT_SUPERVISOR/strict-init.status"
grep -qx 'cleanup_complete=true' "$STRICT_SUPERVISOR/strict-init.status"
grep -qx 'result=PASS' "$STRICT_RESULTS/guest-e2e-status"
grep -qx 'outside_actor_gate=REJECTED_TRANSIENT_MAP' \
	"$STRICT_RESULTS/guest-e2e-status"
grep -qx 'final_global_programs=0' "$STRICT_RESULTS/guest-e2e-status"
grep -qx 'final_global_maps=0' "$STRICT_RESULTS/guest-e2e-status"
grep -qx 'final_global_links=0' "$STRICT_RESULTS/guest-e2e-status"
grep -qx 'OUTSIDE_BPF_ACTOR_GATE_REJECTED_TRANSIENT_MAP' \
	"$STRICT_RESULTS/outside-actor-gate.log"
grep -qx 'result=PASS' "$STRICT_RESULTS/exclusive-clean-precondition.log"
grep -qx 'runner_cgroup=/bpf-state-observer' \
	"$STRICT_RESULTS/exclusive-clean-precondition.log"
grep -q '"ready_for_runtime": true' "$STRICT_RESULTS/doctor.json"
if grep -q '"status": "FAIL"' "$STRICT_RESULTS/doctor.json"; then
	echo "strict doctor contains a failed prerequisite" >&2
	exit 1
fi
[[ "$(grep -c 'final_ack=VERIFIED' "$RUN_ROOT/harnessd.log")" -eq 3 ]]
grep -q 'session=1 final_ack=VERIFIED run_id="e2e-exclusive-noop" run_epoch=1101' \
	"$RUN_ROOT/harnessd.log"
grep -q 'session=2 final_ack=VERIFIED run_id="e2e-exclusive-ephemeral" run_epoch=1102' \
	"$RUN_ROOT/harnessd.log"
grep -q 'session=3 final_ack=VERIFIED run_id="e2e-exclusive-restore" run_epoch=1103' \
	"$RUN_ROOT/harnessd.log"
grep -qx 'result=COMPLETE sessions=3' "$RUN_ROOT/harnessd.log"
grep -q 'BPF_OBSERVER_STRICT_GUEST_E2E_PASS' "$STRICT_CONSOLE"
grep -q 'strict-init: strict suite PASS' "$STRICT_CONSOLE"

for fixture in exclusive-noop exclusive-ephemeral exclusive-restore; do
	grep -qx 'result=PASS' "$HOST_RESULTS/assert-$fixture.log"
	grep -q '"evidence_complete": true' "$HOST_RESULTS/verify-$fixture.json"
	grep -q '"harness_authenticated": true' "$HOST_RESULTS/verify-$fixture.json"
	grep -q '"state_verdict": "UNCHANGED_WITHIN_SCOPE"' \
		"$HOST_RESULTS/verify-$fixture.json"
done
grep -q '"events_verified": 2' "$HOST_RESULTS/verify-exclusive-noop.json"
grep -q '"events_verified": 6' "$HOST_RESULTS/verify-exclusive-ephemeral.json"
grep -q '"events_verified": 10' "$HOST_RESULTS/verify-exclusive-restore.json"
grep -Eq 'harness|authenticated|policy|key' \
	"$HOST_RESULTS/exclusive-no-key.stderr"
grep -Eq 'signature|public key|fingerprint|harness' \
	"$HOST_RESULTS/exclusive-wrong-key.stderr"
grep -Eq 'digest|size|artifact|manifest|changed' \
	"$HOST_RESULTS/exclusive-tampered.stderr"
grep -Eq 'harness|authenticated|policy|key' \
	"$STRICT_RESULTS/exclusive-no-key.stderr"
grep -Eq 'signature|public key|fingerprint|harness' \
	"$STRICT_RESULTS/exclusive-wrong-key.stderr"
grep -Eq 'digest|size|artifact|manifest|changed' \
	"$STRICT_RESULTS/exclusive-tampered.stderr"

cleanup_harness_secrets
[[ ! -e "$HARNESS_SECRET_KEY" && ! -L "$HARNESS_SECRET_KEY" ]]
[[ ! -e "$HARNESS_WRONG_SECRET_KEY" && ! -L "$HARNESS_WRONG_SECRET_KEY" ]]
[[ ! -e "$HARNESS_SOCKET" && ! -L "$HARNESS_SOCKET" ]]
[[ ! -e "$HARNESS_SECRET_DIR" && ! -L "$HARNESS_SECRET_DIR" ]]

# Re-measure every external/current security input before committing audit.
[[ "$(sha256_of "$KERNEL_BZIMAGE")" == "$KERNEL_SHA256" ]]
[[ "$(sha256_of "$ROOTFS_IMAGE")" == "$ROOTFS_SHA256" ]]
[[ "$(sha256_of "$QEMU_EXECUTABLE")" == "$QEMU_SHA256" ]]
[[ "$(sha256_of "$BIN")" == "$OBSERVER_SHA256" ]]
[[ "$(sha256_of "$ASSERT_BIN")" == "$ASSERT_SHA256" ]]
[[ "$(sha256_of "$OUTSIDER_GATE_BIN")" == "$OUTSIDER_GATE_SHA256" ]]
[[ "$(sha256_of "$HARNESSD_BIN")" == "$HARNESSD_SHA256" ]]
[[ "$(sha256_of "$STRICT_INIT_BIN")" == "$STRICT_INIT_SHA256" ]]
[[ "$(sha256_of "$STRICT_GUEST_RUNNER")" == "$STRICT_RUNNER_SHA256" ]]
[[ "$(sha256_of "$OBJ")" == "$RECORDER_SHA256" ]]
[[ "$(sha256_of "$WORKLOAD")" == "$WORKLOAD_SHA256" ]]
[[ "$(sha256_of "$NOOP_WORKLOAD")" == "$NOOP_WORKLOAD_SHA256" ]]
[[ "$(sha256_of "$PROVISION_OVERLAY")" == "$PROVISION_OVERLAY_SHA256" ]]
[[ "$(sha256_of "$PROVISION_FLAT")" == "$PROVISION_FLAT_SHA256" ]]
[[ "$(sha256_of "$STRICT_OVERLAY")" == "$STRICT_OVERLAY_SHA256" ]]
[[ "$(sha256_of "$EVIDENCE_IMAGE")" == "$EVIDENCE_FINAL_SHA256" ]]
[[ "$(sha256_of "$EVIDENCE_RECOVERY_IMAGE")" == "$EVIDENCE_RECOVERY_SHA256" ]]
[[ "$("$AUDIT_HARNESSD" canonical-json-digest \
	--input "$AUDIT_INPUTS/exclusive-vm-scope.json")" == \
	"$EXCLUSIVE_SCOPE_SHA256" ]]
[[ "$("$AUDIT_HARNESSD" policy-digest --policy "$HARNESS_POLICY")" == \
	"$HARNESS_POLICY_SHA256" ]]
cmp -s "$HOST_RUNNER" "$AUDIT_INPUTS/run-e2e.sh"
cmp -s "$STRICT_GUEST_RUNNER" "$AUDIT_INPUTS/guest-strict-e2e.sh"
cmp -s "$STRICT_INIT_SOURCE" "$AUDIT_INPUTS/strict-init.c"

cat > "$RUN_ROOT/ACCEPTANCE_SCOPE.txt" <<'EOF'
This gate proves exclusive-vm-v1 only for the exact measured cooperative
fixtures and VM shape in this audit. The strict boot has a static PID1, one
non-root measured runner, no systemd/SSH/NIC, a block-read-only frozen root,
a separate fresh evidence disk, an empty initial BPF inventory, an active
outside-cgroup bpf() negative gate, and a Host-authenticated ordered transcript.
It proves no endpoint delta within the declared scope; the restore fixture's
event history intentionally proves that transient operations can still occur.
It does not claim hostile-Guest containment, general workload support, crash
recovery, compat ABIs, or completeness outside declared interfaces/types.
EOF

# Create a closed inventory after all mutation and secret cleanup. The list is
# itself hashed; SHA256SUMS is the sole intentionally self-excluded artifact.
if find "$RUN_ROOT" \( -name '*private.key' -o -name '*.sock' \) \
	-print -quit | grep -q .; then
	echo "private/socket material leaked into the final audit directory" >&2
	exit 1
fi
(
	cd "$RUN_ROOT"
	find . -type f ! -name SHA256SUMS ! -name AUDIT_FILES.txt \
		-printf '%P\n' | LC_ALL=C sort
) > "$RUN_ROOT/AUDIT_FILES.txt"
for required in \
	harness-keygen.log harnessd.log harness-policy.sha256 \
	harness-kernel-identity.txt harness-kernel-identity-components.txt \
	strict-qemu.argv.shell strict-qemu.argv.nul strict-qemu-shape.txt \
	strict-kernel-cmdline.txt provision-root-filecaps.txt \
	provision-overlay.sha256 strict-overlay-before.sha256 \
	strict-overlay-after.sha256 evidence-initial.sha256 evidence-final.sha256 \
	evidence-recovery.sha256 inputs/exclusive-vm-v1-policy.json \
	inputs/harness-public.key inputs/wrong-harness-public.key \
	inputs/bpf-harnessd inputs/strict-init inputs/guest-strict-e2e.sh \
	inputs/exclusive-vm-scope.json inputs/map-lifecycle \
	inputs/exclusive-noop inputs/map-lifecycle.c inputs/exclusive-noop.c \
	inputs/vm-outsider-gate-assert inputs/vm-outsider-gate-assert.rs \
	strict-evidence/results/runs/exclusive-noop/manifest.json \
	strict-evidence/results/runs/exclusive-ephemeral/manifest.json \
	strict-evidence/results/runs/exclusive-restore/manifest.json \
	host-results/verify-exclusive-noop.json \
	host-results/verify-exclusive-ephemeral.json \
	host-results/verify-exclusive-restore.json \
	host-results/assert-exclusive-noop.log \
	host-results/assert-exclusive-ephemeral.log \
	host-results/assert-exclusive-restore.log \
	host-results/exclusive-no-key.stderr \
	host-results/exclusive-wrong-key.stderr \
	host-results/exclusive-tampered.stderr \
	strict-evidence/results/exclusive-no-key.stderr \
	strict-evidence/results/exclusive-wrong-key.stderr \
	strict-evidence/results/exclusive-tampered.stderr \
	strict-evidence/supervisor/strict-init.status \
	strict-evidence/results/guest-e2e-status \
	strict-evidence/results/outside-actor-gate.log \
	strict-console.log strict-qemu.stderr; do
	grep -Fxq "$required" "$RUN_ROOT/AUDIT_FILES.txt" || {
		echo "closed audit inventory omitted required artifact: $required" >&2
		exit 1
	}
done
{
	printf '%s  %s\n' "$ROOTFS_SHA256" "$ROOTFS_IMAGE"
	printf '%s  %s\n' "$QEMU_SHA256" "$QEMU_EXECUTABLE"
	(
		cd "$RUN_ROOT"
		sha256sum AUDIT_FILES.txt
		while IFS= read -r relative; do
			sha256sum -- "$relative"
		done < AUDIT_FILES.txt
	)
} > "$RUN_ROOT/SHA256SUMS"

trap - EXIT INT TERM
echo "BPF_OBSERVER_EXCLUSIVE_VM_E2E_PASS"
echo "Audit directory: $RUN_ROOT"
