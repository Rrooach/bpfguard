#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Launch a NEW disposable Guest for the destructive A/B/C recovery acceptance.
# This runner never attaches a writable raw image to QEMU: snapshot=on is
# embedded in the only -drive argument and the base image is hashed both ways.

set -euo pipefail

script_dir=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -P -- "$script_dir/.." && pwd -P)
qemu_binary=${QEMU_BINARY:-qemu-system-x86_64}
kernel_build_dir=$project_dir/.output/vm-kernel-effects
output_base=$project_dir/.output/validation/recovery-abc-vm
ssh_port=10049
rootfs=
ssh_key=
module=
run_root=
qemu_pid=
qemu_start=
qemu_exe=

usage()
{
	cat >&2 <<'EOF'
usage: run-recovery-abc-e2e.sh --rootfs RAW_IMAGE --ssh-key PRIVATE_KEY --module TEST_MODULE.ko [--kernel-build-dir DIR] [--ssh-port PORT] [--output-base DIR]

The raw image must not be in use by any process. QEMU is started with
snapshot=on; do not reuse the old persistent Terminal-Bench Guest.
EOF
	exit 2
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--rootfs) rootfs=${2:-}; shift 2 ;;
	--ssh-key) ssh_key=${2:-}; shift 2 ;;
	--module) module=${2:-}; shift 2 ;;
	--kernel-build-dir) kernel_build_dir=${2:-}; shift 2 ;;
	--ssh-port) ssh_port=${2:-}; shift 2 ;;
	--output-base) output_base=${2:-}; shift 2 ;;
	-h|--help) usage ;;
	*) usage ;;
	esac
done
[[ -n $rootfs && -n $ssh_key && -n $module ]] || usage
[[ $ssh_port =~ ^[1-9][0-9]{0,4}$ && $ssh_port -le 65535 ]] || usage
rootfs=$(realpath -e -- "$rootfs")
ssh_key=$(realpath -e -- "$ssh_key")
module=$(realpath -e -- "$module")
kernel_build_dir=$(realpath -e -- "$kernel_build_dir")
output_base=$(realpath -m -- "$output_base")
kernel_image=$kernel_build_dir/arch/x86/boot/bzImage
kernel_release_file=$kernel_build_dir/include/config/kernel.release
for path in "$rootfs" "$ssh_key" "$module" "$kernel_image" "$kernel_release_file"; do
	[[ -f $path && ! -L $path ]] || {
		echo "missing or symlinked Host input: $path" >&2
		exit 2
	}
done
for command in "$qemu_binary" awk date file find fuser grep install mktemp modinfo \
	qemu-system-x86_64 readlink realpath scp seq sha256sum sleep sort ssh ss \
	stat sync timeout tr xargs; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing Host command: $command" >&2
		exit 2
	}
done
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || {
	echo "KVM unavailable" >&2
	exit 2
}
file "$rootfs" | grep -q 'ext4 filesystem data' || {
	echo "raw Guest image is not ext4" >&2
	exit 2
}
file "$kernel_image" | grep -q 'Linux kernel x86 boot executable bzImage' || {
	echo "effects kernel bzImage is unavailable" >&2
	exit 2
}
kernel_release=$(<"$kernel_release_file")
module_vermagic=$(modinfo -F vermagic "$module")
[[ $module_vermagic == "$kernel_release "* ]] || {
	echo "test module vermagic differs from effects kernel" >&2
	exit 2
}
if fuser -s "$rootfs" 2>/dev/null; then
	echo "raw image is already open; refuse to share it with another VM" >&2
	exit 2
fi
if ss -ltnH "sport = :$ssh_port" | grep -q .; then
	echo "selected loopback SSH port is already in use" >&2
	exit 2
fi
qemu_exe=$(realpath -e -- "$(command -v "$qemu_binary")")

make -C "$project_dir" release bpf workloads
inputs_source=$project_dir/.output
for path in \
	"$inputs_source/cargo-target/release/deployment-observe" \
	"$inputs_source/cargo-target/release/deployment-observe-recovery-verify" \
	"$inputs_source/system_effects.bpf.o" \
	"$inputs_source/process_lifecycle.bpf.o" \
	"$inputs_source/workloads/deployment-endpoint-state-change" \
	"$inputs_source/workloads/deployment-recovery-bpf-state" \
	"$project_dir/workloads/system-effects-state-change.sh" \
	"$project_dir/workloads/deployment-recovery-helper.sh" \
	"$script_dir/guest-recovery-abc-e2e.sh"; do
	[[ -f $path && ! -L $path ]] || {
		echo "missing current-source build artifact: $path" >&2
		exit 2
	}
done
bash -n "$project_dir/workloads/system-effects-state-change.sh" \
	"$project_dir/workloads/deployment-recovery-helper.sh" \
	"$script_dir/guest-recovery-abc-e2e.sh"

mkdir -p "$output_base"
run_root=$(mktemp -d "$output_base/run-XXXXXXXX")
mkdir -m 0700 "$run_root/inputs"
install -m 0755 "$inputs_source/cargo-target/release/deployment-observe" "$run_root/inputs/"
install -m 0755 "$inputs_source/cargo-target/release/deployment-observe-recovery-verify" "$run_root/inputs/"
install -m 0644 "$inputs_source/system_effects.bpf.o" "$run_root/inputs/"
install -m 0644 "$inputs_source/process_lifecycle.bpf.o" "$run_root/inputs/"
install -m 0755 "$inputs_source/workloads/deployment-endpoint-state-change" "$run_root/inputs/"
install -m 0755 "$inputs_source/workloads/deployment-recovery-bpf-state" "$run_root/inputs/"
install -m 0755 "$project_dir/workloads/system-effects-state-change.sh" "$run_root/inputs/"
install -m 0755 "$project_dir/workloads/deployment-recovery-helper.sh" "$run_root/inputs/"
install -m 0755 "$script_dir/guest-recovery-abc-e2e.sh" "$run_root/inputs/"
install -m 0644 "$module" "$run_root/inputs/bpf_observer_e2e_state.ko"
install -m 0644 "$kernel_image" "$run_root/inputs/kernel.bzImage"
effect_sha=$(sha256sum "$run_root/inputs/system_effects.bpf.o" | awk '{print $1}')
lifecycle_sha=$(sha256sum "$run_root/inputs/process_lifecycle.bpf.o" | awk '{print $1}')
base_sha_before=$(sha256sum "$rootfs" | awk '{print $1}')
name=recovery-abc-${run_root##*/}

qemu_start_time()
{
	local line tail
	local -a fields
	IFS= read -r line <"/proc/$1/stat" || return 1
	tail=${line##*) }
	read -r -a fields <<<"$tail"
	[[ ${#fields[@]} -ge 20 ]] || return 1
	printf '%s\n' "${fields[19]}"
}

qemu_identity_matches()
{
	local actual_start actual_exe
	[[ -n $qemu_pid && -n $qemu_start ]] || return 1
	kill -0 "$qemu_pid" 2>/dev/null || return 1
	actual_start=$(qemu_start_time "$qemu_pid") || return 1
	actual_exe=$(readlink -f -- "/proc/$qemu_pid/exe") || return 1
	[[ $actual_start == "$qemu_start" && $actual_exe == "$qemu_exe" ]] || return 1
	tr '\0' ' ' <"/proc/$qemu_pid/cmdline" | grep -Fq -- "$name"
	tr '\0' ' ' <"/proc/$qemu_pid/cmdline" | grep -Fq -- "file=$rootfs,format=raw,if=ide,snapshot=on"
}

cleanup()
{
	local attempt
	[[ -n $qemu_pid ]] || return 0
	if qemu_identity_matches; then
		kill -TERM "$qemu_pid" 2>/dev/null || true
		for attempt in $(seq 1 50); do
			kill -0 "$qemu_pid" 2>/dev/null || break
			sleep 0.1
		done
	fi
	if qemu_identity_matches; then
		kill -KILL "$qemu_pid" 2>/dev/null || true
	fi
}
trap cleanup EXIT

qemu_args=(
	-daemonize -pidfile "$run_root/qemu.pid" -name "$name"
	-m 2048 -smp 2 -enable-kvm -cpu host,migratable=off
	-display none -serial "file:$run_root/console.log" -no-reboot
	-kernel "$run_root/inputs/kernel.bzImage"
	-append 'root=/dev/sda rw console=ttyS0,115200 net.ifnames=0 lsm=capability,selinux,bpf'
	-drive "file=$rootfs,format=raw,if=ide,snapshot=on"
	-netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$ssh_port-:22"
	-device e1000,netdev=net0
)
printf '%q ' "$qemu_exe" "${qemu_args[@]}" >"$run_root/qemu.argv.shell"
printf '\n' >>"$run_root/qemu.argv.shell"
"$qemu_exe" "${qemu_args[@]}" 2>"$run_root/qemu.stderr"
qemu_pid=$(<"$run_root/qemu.pid")
[[ $qemu_pid =~ ^[1-9][0-9]*$ ]]
qemu_start=$(qemu_start_time "$qemu_pid")
qemu_identity_matches || {
	echo "new QEMU process identity or snapshot=on drive cannot be proved" >&2
	exit 1
}

ssh_options=(
	-i "$ssh_key" -p "$ssh_port" -o BatchMode=yes
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ConnectTimeout=2 -o ServerAliveInterval=2 -o ServerAliveCountMax=3
)
scp_options=(
	-q -i "$ssh_key" -P "$ssh_port" -o BatchMode=yes
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ConnectTimeout=2 -o ServerAliveInterval=2 -o ServerAliveCountMax=3
)
ready=0
for attempt in $(seq 1 60); do
	qemu_identity_matches || { echo "new QEMU exited before SSH readiness" >&2; exit 1; }
	if ssh "${ssh_options[@]}" root@127.0.0.1 true 2>/dev/null; then
		ready=1
		break
	fi
	sleep 1
done
[[ $ready -eq 1 ]] || { echo "Guest SSH did not become ready" >&2; exit 1; }
guest_inputs=/opt/bpf-observer-$name
guest_evidence=/var/lib/bpf-observer-$name
ssh "${ssh_options[@]}" root@127.0.0.1 \
	"mkdir -m 0700 '$guest_inputs'"
scp "${scp_options[@]}" "$run_root/inputs/"* \
	"root@127.0.0.1:$guest_inputs/"

if ! timeout --foreground 900s ssh "${ssh_options[@]}" root@127.0.0.1 \
	/bin/bash "$guest_inputs/guest-recovery-abc-e2e.sh" \
	"$guest_inputs/deployment-observe" \
	"$guest_inputs/deployment-observe-recovery-verify" \
	"$guest_inputs/system_effects.bpf.o" "$effect_sha" \
	"$guest_inputs/process_lifecycle.bpf.o" "$lifecycle_sha" \
	"$guest_inputs/system-effects-state-change.sh" \
	"$guest_inputs/deployment-endpoint-state-change" \
	"$guest_inputs/deployment-recovery-bpf-state" \
	"$guest_inputs/deployment-recovery-helper.sh" \
	"$guest_inputs/bpf_observer_e2e_state.ko" "$guest_evidence" \
	>"$run_root/guest.stdout" 2>"$run_root/guest.stderr"; then
	scp "${scp_options[@]}" -r "root@127.0.0.1:$guest_evidence" \
		"$run_root/partial-guest-evidence" >/dev/null 2>&1 || true
	sed -n '1,160p' "$run_root/guest.stderr" >&2
	exit 1
fi
grep -q '^RECOVERY_ABC_GUEST_E2E_PASS ' "$run_root/guest.stdout"
scp "${scp_options[@]}" -r "root@127.0.0.1:$guest_evidence" \
	"$run_root/guest-evidence"
sync
base_sha_after=$(sha256sum "$rootfs" | awk '{print $1}')
[[ $base_sha_before == "$base_sha_after" ]] || {
	echo "raw base image changed despite snapshot=on; reject result" >&2
	exit 1
}
if grep -Eq 'BUG:|kernel panic|Oops:' "$run_root/console.log"; then
	echo "Guest console contains a kernel failure" >&2
	exit 1
fi
find "$run_root/inputs" "$run_root/guest-evidence" -type f -print0 \
	| sort -z | xargs -0 sha256sum >"$run_root/SHA256SUMS"
printf 'RECOVERY_ABC_HOST_E2E_PASS result=%s base_sha256=%s\n' \
	"$run_root" "$base_sha_after"
