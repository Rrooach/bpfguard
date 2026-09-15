#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Host orchestrator for the privileged expanded system-effects acceptance.
# The supplied raw image is never written: QEMU's temporary snapshot mode is
# mandatory and all mutations disappear with this uniquely tracked VM.

set -euo pipefail

SCRIPT_DIR=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PROJECT_DIR=$(cd -P -- "$SCRIPT_DIR/.." && pwd -P)
KERNEL_ROOT=$(cd -P -- "$PROJECT_DIR/../../.." && pwd -P)
QEMU_BINARY=${QEMU_BINARY:-qemu-system-x86_64}
SSH_PORT=${VM_EXPANDED_SSH_PORT:-10029}
OUTPUT_BASE=$PROJECT_DIR/.output/validation/expanded-effects-vm
KERNEL_BUILD_DIR=$PROJECT_DIR/.output/vm-kernel-effects
PAHOLE_BIN=${VM_EFFECTS_PAHOLE:-$PROJECT_DIR/.output/toolchain/install-static/bin/pahole}
ROOTFS_IMAGE=
SSH_KEY=
QEMU_PID=
QEMU_START_TIME=
QEMU_EXECUTABLE=

usage()
{
	cat <<EOF
Usage: $0 --rootfs RAW_IMAGE --ssh-key PRIVATE_KEY [options]

Options:
  --kernel-build-dir DIR  effects-object O= directory (default: $KERNEL_BUILD_DIR)
  --pahole PATH           pahole >= 1.22 used for module BTF (default: $PAHOLE_BIN)
  --ssh-port PORT         unique loopback SSH port (default: $SSH_PORT)
  --output-dir DIR        retained result parent (default: $OUTPUT_BASE)
  -h, --help              show this help
EOF
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--rootfs)
		ROOTFS_IMAGE=${2:-}
		shift 2
		;;
	--ssh-key)
		SSH_KEY=${2:-}
		shift 2
		;;
	--kernel-build-dir)
		KERNEL_BUILD_DIR=${2:-}
		shift 2
		;;
	--pahole)
		PAHOLE_BIN=${2:-}
		shift 2
		;;
	--ssh-port)
		SSH_PORT=${2:-}
		shift 2
		;;
	--output-dir)
		OUTPUT_BASE=${2:-}
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

[[ -n $ROOTFS_IMAGE && -n $SSH_KEY ]] || { usage >&2; exit 2; }
[[ $SSH_PORT =~ ^[1-9][0-9]{0,4}$ && $SSH_PORT -le 65535 ]] || {
	echo "invalid SSH port: $SSH_PORT" >&2
	exit 2
}
ROOTFS_IMAGE=$(realpath -e -- "$ROOTFS_IMAGE")
SSH_KEY=$(realpath -e -- "$SSH_KEY")
KERNEL_BUILD_DIR=$(realpath -e -- "$KERNEL_BUILD_DIR")
PAHOLE_BIN=$(realpath -e -- "$PAHOLE_BIN")
OUTPUT_BASE=$(realpath -m -- "$OUTPUT_BASE")
KERNEL_BZIMAGE=$KERNEL_BUILD_DIR/arch/x86/boot/bzImage
KERNEL_CONFIG=$KERNEL_BUILD_DIR/.config
KERNEL_VMLINUX=$KERNEL_BUILD_DIR/vmlinux
KERNEL_SYMVERS=$KERNEL_BUILD_DIR/Module.symvers

for path in "$ROOTFS_IMAGE" "$SSH_KEY" "$KERNEL_BZIMAGE" "$KERNEL_CONFIG" \
	"$KERNEL_VMLINUX" "$KERNEL_SYMVERS" "$PAHOLE_BIN"; do
	[[ -f $path && ! -L $path ]] || { echo "unsafe or missing input: $path" >&2; exit 2; }
done
for command in "$QEMU_BINARY" awk cc date file find grep install make node \
	qemu-system-x86_64 readelf readlink realpath scp seq sha256sum sleep sort \
	ssh ss stat sync timeout tr xargs; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing Host command: $command" >&2
		exit 2
	}
done
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || {
	echo "/dev/kvm is unavailable" >&2
	exit 2
}
file "$ROOTFS_IMAGE" | grep -q 'ext4 filesystem data' || {
	echo "--rootfs must be a raw ext4 image" >&2
	exit 2
}
file "$KERNEL_BZIMAGE" | grep -q 'Linux kernel x86 boot executable bzImage' || {
	echo "effects kernel is not an x86 bzImage" >&2
	exit 2
}
readelf -S "$KERNEL_VMLINUX" | grep -q '\.BTF' || {
	echo "effects vmlinux has no BTF" >&2
	exit 2
}
if ss -ltnH "sport = :$SSH_PORT" | grep -q .; then
	echo "loopback SSH port $SSH_PORT is already in use" >&2
	exit 2
fi

for setting in \
	CONFIG_BPF_LSM=y CONFIG_SECURITY_PATH=y CONFIG_NF_TABLES=y \
	CONFIG_NF_TABLES_INET=y CONFIG_NF_TABLES_NETDEV=y CONFIG_DUMMY=y \
	CONFIG_IPV6_MULTIPLE_TABLES=y \
	CONFIG_VETH=y CONFIG_TUN=y CONFIG_NET_SCHED=y CONFIG_NET_SCH_HTB=y \
	CONFIG_NET_SCH_TBF=y CONFIG_NET_SCH_FQ=y CONFIG_NET_SCH_FQ_CODEL=y \
	CONFIG_NET_CLS_ACT=y CONFIG_NET_SCH_INGRESS=y CONFIG_NET_CLS_U32=y \
	CONFIG_NET_CLS_BPF=y CONFIG_NET_CLS_FLOWER=y CONFIG_NET_CLS_MATCHALL=y \
	CONFIG_NET_ACT_GACT=y CONFIG_NET_ACT_MIRRED=y CONFIG_NET_ACT_BPF=y \
	CONFIG_DEBUG_INFO_BTF=y; do
	grep -qx "$setting" "$KERNEL_CONFIG" || {
		echo "effects kernel omits required setting: $setting" >&2
		exit 2
	}
done

make -C "$PROJECT_DIR" release system-effects-bpf process-lifecycle-bpf \
	"$PROJECT_DIR/.output/workloads/system-effects-object-v2-smoke" \
	"$PROJECT_DIR/.output/workloads/deployment-endpoint-state-change"

OBSERVER=$PROJECT_DIR/.output/cargo-target/release/bpf-state-observer
DEPLOYMENT_OBSERVER=$PROJECT_DIR/.output/cargo-target/release/deployment-observe
DEPLOYMENT_VERIFY=$PROJECT_DIR/.output/cargo-target/release/deployment-observe-verify
EFFECT_OBJECT=$PROJECT_DIR/.output/system_effects.bpf.o
LIFECYCLE_OBJECT=$PROJECT_DIR/.output/process_lifecycle.bpf.o
OBJECT_WORKLOAD=$PROJECT_DIR/.output/workloads/system-effects-object-v2-smoke
DEPLOYMENT_ENDPOINT_WORKLOAD=$PROJECT_DIR/.output/workloads/deployment-endpoint-state-change
STATE_WORKLOAD=$PROJECT_DIR/workloads/system-effects-state-change.sh
RESIDUAL_WORKLOAD=$PROJECT_DIR/workloads/system-effects-residual-process.sh
OVERHEAD_WORKLOAD_SOURCE=$PROJECT_DIR/experiments/system-effects-overhead/system-effects-workload.c
MEASURE_COMMAND_SOURCE=$PROJECT_DIR/experiments/system-effects-overhead/measure-command.c
EXPANDED_OVERHEAD_ANALYZER=$PROJECT_DIR/experiments/system-effects-overhead/analyze-expanded.js
GUEST_RUNNER=$SCRIPT_DIR/guest-expanded-effects-e2e.sh
DEPLOYMENT_GUEST_RUNNER=$SCRIPT_DIR/guest-deployment-ancestor-e2e.sh
DEPLOYMENT_SYNTHETIC_GUEST_RUNNER=$SCRIPT_DIR/guest-deployment-live-synthetic-e2e.sh
DEPLOYMENT_LIVE_FIXTURE_SOURCE=$PROJECT_DIR/workloads/deployment-live-fixture.c
MODULE_SOURCE=$SCRIPT_DIR/linux-state-e2e-module
for path in "$OBSERVER" "$DEPLOYMENT_OBSERVER" "$DEPLOYMENT_VERIFY" \
	"$EFFECT_OBJECT" "$LIFECYCLE_OBJECT" \
	"$OBJECT_WORKLOAD" "$DEPLOYMENT_ENDPOINT_WORKLOAD" \
	"$STATE_WORKLOAD" "$RESIDUAL_WORKLOAD" \
	"$OVERHEAD_WORKLOAD_SOURCE" "$MEASURE_COMMAND_SOURCE" \
	"$EXPANDED_OVERHEAD_ANALYZER" \
	"$GUEST_RUNNER" "$DEPLOYMENT_GUEST_RUNNER" \
	"$DEPLOYMENT_SYNTHETIC_GUEST_RUNNER" \
	"$DEPLOYMENT_LIVE_FIXTURE_SOURCE" "$MODULE_SOURCE/Makefile" \
	"$MODULE_SOURCE/bpf_observer_e2e_state.c"; do
	[[ -f $path && ! -L $path ]] || { echo "missing build input: $path" >&2; exit 2; }
done
bash -n "$STATE_WORKLOAD"
bash -n "$RESIDUAL_WORKLOAD"
bash -n "$GUEST_RUNNER"
bash -n "$DEPLOYMENT_GUEST_RUNNER"
bash -n "$DEPLOYMENT_SYNTHETIC_GUEST_RUNNER"
node --check "$EXPANDED_OVERHEAD_ANALYZER"
node "$EXPANDED_OVERHEAD_ANALYZER" --self-test
"$OBSERVER" observe-effects --help | grep -q -- '--process-lifecycle-object'
"$OBSERVER" observe-effects --help | grep -q -- 'kernel-object-expanded-partial'
"$OBSERVER" doctor --help | grep -q -- '--process-lifecycle-object'
"$OBSERVER" verify-effects --help | grep -q -- '--expected-process-lifecycle-sha256'
"$DEPLOYMENT_OBSERVER" --help | grep -q -- 'deployment-observe --config'
"$DEPLOYMENT_VERIFY" --help | grep -q -- '--expectation'

RUN_TAG=$(date -u +%Y%m%dT%H%M%SZ)-$$
RUN_ROOT=$OUTPUT_BASE/$RUN_TAG
INPUTS=$RUN_ROOT/inputs
MODULE_BUILD=$RUN_ROOT/module-build
HELPER_BUILD=$RUN_ROOT/helper-build
GUEST_RESULTS=$RUN_ROOT/guest-results
CONSOLE=$RUN_ROOT/console.log
QEMU_STDERR=$RUN_ROOT/qemu.stderr
QEMU_PIDFILE=$RUN_ROOT/qemu.pid
GUEST_STDOUT=$RUN_ROOT/guest.stdout
GUEST_STDERR=$RUN_ROOT/guest.stderr
mkdir -p "$OUTPUT_BASE"
[[ ! -e $RUN_ROOT && ! -L $RUN_ROOT ]] || { echo "result path exists" >&2; exit 2; }
install -d -m 0700 "$RUN_ROOT" "$INPUTS" "$MODULE_BUILD" "$HELPER_BUILD"

cc -O2 -std=c11 -Wall -Wextra -Werror "$OVERHEAD_WORKLOAD_SOURCE" \
	-o "$HELPER_BUILD/system-effects-overhead-workload"
cc -O2 -std=c11 -Wall -Wextra -Werror "$MEASURE_COMMAND_SOURCE" \
	-o "$HELPER_BUILD/measure-command"
cc -O2 -std=c11 -Wall -Wextra -Werror "$DEPLOYMENT_LIVE_FIXTURE_SOURCE" \
	-o "$HELPER_BUILD/deployment-live-fixture"

make -C "$KERNEL_ROOT" O="$KERNEL_BUILD_DIR" M="$MODULE_SOURCE" \
	MO="$MODULE_BUILD" PAHOLE="$PAHOLE_BIN" modules
STATE_MODULE=$MODULE_BUILD/bpf_observer_e2e_state.ko
[[ -f $STATE_MODULE && ! -L $STATE_MODULE ]] || {
	echo "test state module was not produced" >&2
	exit 1
}

install -m 0755 "$OBSERVER" "$INPUTS/bpf-state-observer"
install -m 0755 "$DEPLOYMENT_OBSERVER" "$INPUTS/deployment-observe"
install -m 0755 "$DEPLOYMENT_VERIFY" "$INPUTS/deployment-observe-verify"
install -m 0644 "$EFFECT_OBJECT" "$INPUTS/system_effects.bpf.o"
install -m 0644 "$LIFECYCLE_OBJECT" "$INPUTS/process_lifecycle.bpf.o"
install -m 0755 "$OBJECT_WORKLOAD" "$INPUTS/system-effects-object-v2-smoke"
install -m 0755 "$DEPLOYMENT_ENDPOINT_WORKLOAD" \
	"$INPUTS/deployment-endpoint-state-change"
install -m 0755 "$STATE_WORKLOAD" "$INPUTS/system-effects-state-change.sh"
install -m 0755 "$RESIDUAL_WORKLOAD" "$INPUTS/system-effects-residual-process.sh"
install -m 0755 "$HELPER_BUILD/system-effects-overhead-workload" \
	"$INPUTS/system-effects-overhead-workload"
install -m 0755 "$HELPER_BUILD/measure-command" "$INPUTS/measure-command"
install -m 0644 "$OVERHEAD_WORKLOAD_SOURCE" \
	"$INPUTS/system-effects-overhead-workload.c"
install -m 0644 "$MEASURE_COMMAND_SOURCE" "$INPUTS/measure-command.c"
install -m 0755 "$EXPANDED_OVERHEAD_ANALYZER" \
	"$INPUTS/analyze-expanded-overhead.js"
install -m 0755 "$GUEST_RUNNER" "$INPUTS/guest-expanded-effects-e2e.sh"
install -m 0755 "$DEPLOYMENT_GUEST_RUNNER" \
	"$INPUTS/guest-deployment-ancestor-e2e.sh"
install -m 0755 "$DEPLOYMENT_SYNTHETIC_GUEST_RUNNER" \
	"$INPUTS/guest-deployment-live-synthetic-e2e.sh"
install -m 0755 "$HELPER_BUILD/deployment-live-fixture" \
	"$INPUTS/deployment-live-fixture"
install -m 0644 "$STATE_MODULE" "$INPUTS/bpf_observer_e2e_state.ko"
install -m 0644 "$KERNEL_BZIMAGE" "$INPUTS/kernel.bzImage"
install -m 0644 "$KERNEL_CONFIG" "$INPUTS/kernel.config"
install -m 0644 "$KERNEL_SYMVERS" "$INPUTS/Module.symvers"

EFFECT_SHA=$(sha256sum "$INPUTS/system_effects.bpf.o" | awk '{print $1}')
LIFECYCLE_SHA=$(sha256sum "$INPUTS/process_lifecycle.bpf.o" | awk '{print $1}')
QEMU_EXECUTABLE=$(realpath -e -- "$(command -v -- "$QEMU_BINARY")")

qemu_start_time()
{
	local pid=$1
	local line tail
	local -a fields
	IFS= read -r line <"/proc/$pid/stat" || return 1
	tail=${line##*) }
	read -r -a fields <<<"$tail"
	[[ ${#fields[@]} -ge 20 ]] || return 1
	printf '%s\n' "${fields[19]}"
}

qemu_identity_matches()
{
	local current_executable current_start
	[[ -n $QEMU_PID && -n $QEMU_START_TIME && -n $QEMU_EXECUTABLE ]] || return 1
	kill -0 "$QEMU_PID" 2>/dev/null || return 1
	current_start=$(qemu_start_time "$QEMU_PID") || return 1
	current_executable=$(readlink -f -- "/proc/$QEMU_PID/exe") || return 1
	[[ $current_start == "$QEMU_START_TIME" && $current_executable == "$QEMU_EXECUTABLE" ]]
	tr '\0' ' ' <"/proc/$QEMU_PID/cmdline" | grep -q 'bpf-observer-expanded-e2e'
}

cleanup()
{
	local attempt
	[[ -n $QEMU_PID ]] || return 0
	if qemu_identity_matches; then
		kill -TERM "$QEMU_PID" 2>/dev/null || true
		for attempt in $(seq 1 50); do
			kill -0 "$QEMU_PID" 2>/dev/null || break
			sleep 0.1
		done
	fi
	if qemu_identity_matches; then
		kill -KILL "$QEMU_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT

QEMU_ARGS=(
	-daemonize -pidfile "$QEMU_PIDFILE" -name bpf-observer-expanded-e2e
	-m 2048 -smp 2 -enable-kvm -cpu host,migratable=off
	-display none -serial "file:$CONSOLE" -no-reboot
	-kernel "$INPUTS/kernel.bzImage"
	-append 'root=/dev/sda rw console=ttyS0,115200 net.ifnames=0 lsm=capability,selinux,bpf'
	-drive "file=$ROOTFS_IMAGE,format=raw,if=ide,snapshot=on"
	-netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22"
	-device e1000,netdev=net0
)
printf '%q ' "$QEMU_EXECUTABLE" "${QEMU_ARGS[@]}" >"$RUN_ROOT/qemu.argv.shell"
printf '\n' >>"$RUN_ROOT/qemu.argv.shell"
"$QEMU_EXECUTABLE" "${QEMU_ARGS[@]}" 2>"$QEMU_STDERR"
QEMU_PID=$(cat "$QEMU_PIDFILE")
[[ $QEMU_PID =~ ^[1-9][0-9]*$ ]] || { echo "invalid QEMU PID" >&2; exit 1; }
QEMU_START_TIME=$(qemu_start_time "$QEMU_PID")
qemu_identity_matches || { echo "could not establish QEMU identity" >&2; exit 1; }

SSH_OPTIONS=(
	-i "$SSH_KEY" -p "$SSH_PORT" -o BatchMode=yes
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ConnectTimeout=2 -o ServerAliveInterval=2 -o ServerAliveCountMax=3
)
SCP_OPTIONS=(
	-q -i "$SSH_KEY" -P "$SSH_PORT" -o BatchMode=yes
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ConnectTimeout=2 -o ServerAliveInterval=2 -o ServerAliveCountMax=3
)

ready=0
for attempt in $(seq 1 60); do
	qemu_identity_matches || { echo "QEMU exited before SSH readiness" >&2; exit 1; }
	if ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 true 2>/dev/null; then
		ready=1
		break
	fi
	sleep 1
done
[[ $ready -eq 1 ]] || { echo "Guest SSH did not become ready" >&2; exit 1; }

GUEST_INPUT_ROOT=/opt/bpf-observer-expanded-e2e-$RUN_TAG
ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 "mkdir -m 0700 '$GUEST_INPUT_ROOT'"
scp "${SCP_OPTIONS[@]}" "$INPUTS/bpf-state-observer" \
	"$INPUTS/system_effects.bpf.o" "$INPUTS/process_lifecycle.bpf.o" \
	"$INPUTS/system-effects-object-v2-smoke" \
	"$INPUTS/deployment-endpoint-state-change" \
	"$INPUTS/system-effects-state-change.sh" \
	"$INPUTS/system-effects-residual-process.sh" \
		"$INPUTS/system-effects-overhead-workload" \
		"$INPUTS/measure-command" \
		"$INPUTS/deployment-observe" \
		"$INPUTS/deployment-observe-verify" \
		"$INPUTS/guest-expanded-effects-e2e.sh" \
		"$INPUTS/guest-deployment-ancestor-e2e.sh" \
		"$INPUTS/guest-deployment-live-synthetic-e2e.sh" \
		"$INPUTS/deployment-live-fixture" \
	"$INPUTS/bpf_observer_e2e_state.ko" \
	"root@127.0.0.1:$GUEST_INPUT_ROOT/"

GUEST_EVIDENCE=/var/lib/bpf-observer-expanded-e2e-$RUN_TAG
if ! timeout --foreground 900s ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
	/bin/bash "$GUEST_INPUT_ROOT/guest-expanded-effects-e2e.sh" \
	"$GUEST_INPUT_ROOT/bpf-state-observer" \
	"$GUEST_INPUT_ROOT/system_effects.bpf.o" "$EFFECT_SHA" \
	"$GUEST_INPUT_ROOT/process_lifecycle.bpf.o" "$LIFECYCLE_SHA" \
	"$GUEST_INPUT_ROOT/system-effects-object-v2-smoke" \
	"$GUEST_INPUT_ROOT/system-effects-state-change.sh" \
	"$GUEST_INPUT_ROOT/system-effects-residual-process.sh" \
	"$GUEST_INPUT_ROOT/bpf_observer_e2e_state.ko" \
	"$GUEST_INPUT_ROOT/system-effects-overhead-workload" \
	"$GUEST_INPUT_ROOT/measure-command" \
	"$GUEST_INPUT_ROOT/deployment-observe" \
	"$GUEST_INPUT_ROOT/deployment-observe-verify" \
	"$GUEST_INPUT_ROOT/guest-deployment-ancestor-e2e.sh" \
	"$GUEST_INPUT_ROOT/guest-deployment-live-synthetic-e2e.sh" \
	"$GUEST_INPUT_ROOT/deployment-live-fixture" \
	"$GUEST_INPUT_ROOT/deployment-endpoint-state-change" \
	"$GUEST_EVIDENCE" \
	>"$GUEST_STDOUT" 2>"$GUEST_STDERR"; then
	# Preserve a partial diagnostic tree before the snapshot VM is stopped.
	# Failure evidence is never treated as a successful closed artifact set.
	scp "${SCP_OPTIONS[@]}" -r \
		"root@127.0.0.1:$GUEST_EVIDENCE" "$GUEST_RESULTS" \
		>/dev/null 2>&1 || true
	sed -n '1,200p' "$GUEST_STDERR" >&2
	exit 1
fi
grep -q '^EXPANDED_EFFECTS_VM_E2E_PASS ' "$GUEST_STDOUT"

scp "${SCP_OPTIONS[@]}" -r \
	"root@127.0.0.1:$GUEST_EVIDENCE" "$GUEST_RESULTS"
sync
node "$INPUTS/analyze-expanded-overhead.js" \
	"$GUEST_RESULTS/overhead-paired" \
	"$GUEST_RESULTS/overhead-paired/report.json" \
	"$GUEST_RESULTS/overhead-paired/REPORT.md"
ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 '/sbin/poweroff -f' >/dev/null 2>&1 || true
for attempt in $(seq 1 100); do
	kill -0 "$QEMU_PID" 2>/dev/null || break
	sleep 0.1
done
if kill -0 "$QEMU_PID" 2>/dev/null; then
	echo "Guest did not power off after evidence recovery" >&2
	exit 1
fi
QEMU_PID=
QEMU_START_TIME=

if grep -Eq 'BUG:|kernel panic|Oops:' "$CONSOLE"; then
	echo "Guest console contains a kernel failure" >&2
	exit 1
fi
{
	sha256sum "$ROOTFS_IMAGE"
	sha256sum "$QEMU_EXECUTABLE"
} >"$RUN_ROOT/external-inputs.sha256"
find "$INPUTS" "$GUEST_RESULTS" -type f -print0 \
	| sort -z \
	| xargs -0 sha256sum >"$RUN_ROOT/SHA256SUMS"

printf 'EXPANDED_EFFECTS_HOST_E2E_PASS result=%s effect_sha256=%s lifecycle_sha256=%s\n' \
	"$RUN_ROOT" "$EFFECT_SHA" "$LIFECYCLE_SHA"
