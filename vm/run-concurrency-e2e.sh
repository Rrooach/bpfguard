#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Launch a new disposable Guest for the pthread concurrency acceptance.  The
# only QEMU drive is snapshot=on and the base image is hashed before and after.

set -euo pipefail

script_dir=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -P -- "$script_dir/.." && pwd -P)
qemu_binary=${QEMU_BINARY:-qemu-system-x86_64}
kernel_build_dir=$project_dir/.output/vm-kernel-effects
output_base=$project_dir/.output/validation/concurrent-effects-vm
ssh_port=10059
rootfs=
ssh_key=
run_root=
qemu_pid=
qemu_pid_at_launch=
qemu_start=
qemu_exe=

usage()
{
	cat >&2 <<'EOF'
usage: run-concurrency-e2e.sh --rootfs RAW_IMAGE --ssh-key PRIVATE_KEY [--kernel-build-dir DIR] [--ssh-port PORT] [--output-base DIR]

The raw image must not be open by another process.  This runner always uses a
new QEMU process and snapshot=on; it never attaches to an existing Guest.
EOF
	exit 2
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--rootfs) rootfs=${2:-}; shift 2 ;;
	--ssh-key) ssh_key=${2:-}; shift 2 ;;
	--kernel-build-dir) kernel_build_dir=${2:-}; shift 2 ;;
	--ssh-port) ssh_port=${2:-}; shift 2 ;;
	--output-base) output_base=${2:-}; shift 2 ;;
	-h|--help) usage ;;
	*) usage ;;
	esac
done
[[ -n $rootfs && -n $ssh_key ]] || usage
[[ $ssh_port =~ ^[1-9][0-9]{0,4}$ && $ssh_port -le 65535 ]] || usage
rootfs=$(realpath -e -- "$rootfs")
ssh_key=$(realpath -e -- "$ssh_key")
kernel_build_dir=$(realpath -e -- "$kernel_build_dir")
output_base=$(realpath -m -- "$output_base")
kernel_image=$kernel_build_dir/arch/x86/boot/bzImage
for path in "$rootfs" "$ssh_key" "$kernel_image"; do
	[[ -f $path && ! -L $path ]] || {
		echo "missing or symlinked Host input: $path" >&2
		exit 2
	}
done
for command in "$qemu_binary" awk date file find fuser grep install mktemp node \
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
	"$inputs_source/cargo-target/release/bpf-state-observer" \
	"$inputs_source/system_effects.bpf.o" \
	"$inputs_source/process_lifecycle.bpf.o" \
	"$inputs_source/workloads/system-effects-concurrency" \
	"$script_dir/run-concurrency-e2e.sh" \
	"$script_dir/guest-concurrency-e2e.sh" \
	"$script_dir/analyze-concurrency-e2e.js"; do
	[[ -f $path && ! -L $path ]] || {
		echo "missing current-source build artifact: $path" >&2
		exit 2
	}
done
bash -n "$script_dir/guest-concurrency-e2e.sh"
node --check "$script_dir/analyze-concurrency-e2e.js"

mkdir -p "$output_base"
run_root=$(mktemp -d "$output_base/run-XXXXXXXX")
mkdir -m 0700 "$run_root/inputs"
install -m 0755 "$inputs_source/cargo-target/release/bpf-state-observer" \
	"$run_root/inputs/"
install -m 0644 "$inputs_source/system_effects.bpf.o" "$run_root/inputs/"
install -m 0644 "$inputs_source/process_lifecycle.bpf.o" "$run_root/inputs/"
install -m 0755 "$inputs_source/workloads/system-effects-concurrency" \
	"$run_root/inputs/"
install -m 0755 "$script_dir/run-concurrency-e2e.sh" "$run_root/inputs/"
install -m 0755 "$script_dir/guest-concurrency-e2e.sh" "$run_root/inputs/"
install -m 0644 "$script_dir/analyze-concurrency-e2e.js" "$run_root/inputs/"
install -m 0644 "$kernel_image" "$run_root/inputs/kernel.bzImage"
effect_sha=$(sha256sum "$run_root/inputs/system_effects.bpf.o" | awk '{print $1}')
lifecycle_sha=$(sha256sum "$run_root/inputs/process_lifecycle.bpf.o" | awk '{print $1}')
base_sha_before=$(sha256sum "$rootfs" | awk '{print $1}')
name=concurrent-effects-${run_root##*/}

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
	tr '\0' ' ' <"/proc/$qemu_pid/cmdline" | \
		grep -Fq -- "file=$rootfs,format=raw,if=ide,snapshot=on"
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
		for attempt in $(seq 1 50); do
			kill -0 "$qemu_pid" 2>/dev/null || break
			sleep 0.1
		done
	fi
	! qemu_identity_matches || {
		echo "exact QEMU process did not terminate" >&2
		return 1
	}
}
trap cleanup EXIT

qemu_args=(
	-daemonize -pidfile "$run_root/qemu.pid" -name "$name"
	-m 2048 -smp 4 -enable-kvm -cpu host,migratable=off
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
qemu_pid_at_launch=$qemu_pid
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
	qemu_identity_matches || {
		echo "new QEMU exited before SSH readiness" >&2
		exit 1
	}
	if ssh "${ssh_options[@]}" root@127.0.0.1 true 2>/dev/null; then
		ready=1
		break
	fi
	sleep 1
done
[[ $ready -eq 1 ]] || {
	echo "Guest SSH did not become ready" >&2
	exit 1
}
guest_inputs=/opt/bpf-observer-$name
guest_evidence=/var/lib/bpf-observer-$name
ssh "${ssh_options[@]}" root@127.0.0.1 "mkdir -m 0700 '$guest_inputs'"
scp "${scp_options[@]}" "$run_root/inputs/"* \
	"root@127.0.0.1:$guest_inputs/"

if ! timeout --foreground 900s ssh "${ssh_options[@]}" root@127.0.0.1 \
	/bin/bash "$guest_inputs/guest-concurrency-e2e.sh" \
	"$guest_inputs/bpf-state-observer" \
	"$guest_inputs/system_effects.bpf.o" "$effect_sha" \
	"$guest_inputs/process_lifecycle.bpf.o" "$lifecycle_sha" \
	"$guest_inputs/system-effects-concurrency" "$guest_evidence" \
	>"$run_root/guest.stdout" 2>"$run_root/guest.stderr"; then
	scp "${scp_options[@]}" -r "root@127.0.0.1:$guest_evidence" \
		"$run_root/partial-guest-evidence" >/dev/null 2>&1 || true
	sed -n '1,200p' "$run_root/guest.stderr" >&2
	exit 1
fi
grep -q '^CONCURRENCY_GUEST_E2E_PASS ' "$run_root/guest.stdout"
scp "${scp_options[@]}" -r "root@127.0.0.1:$guest_evidence" \
	"$run_root/guest-evidence"
node "$run_root/inputs/analyze-concurrency-e2e.js" "$run_root/guest-evidence" \
	>"$run_root/concurrency-analysis.json"
grep -q '"status": "PASS"' "$run_root/concurrency-analysis.json"

sync
cleanup
qemu_pid=
base_sha_after=$(sha256sum "$rootfs" | awk '{print $1}')
[[ $base_sha_before == "$base_sha_after" ]] || {
	echo "raw base image changed despite snapshot=on; reject result" >&2
	exit 1
}
if grep -Eq 'BUG:|kernel panic|Oops:' "$run_root/console.log"; then
	echo "Guest console contains a kernel failure" >&2
	exit 1
fi
kernel_sha=$(sha256sum "$run_root/inputs/kernel.bzImage" | awk '{print $1}')
runner_sha=$(sha256sum "$run_root/inputs/run-concurrency-e2e.sh" | awk '{print $1}')
analyzer_sha=$(sha256sum "$run_root/inputs/analyze-concurrency-e2e.js" | awk '{print $1}')
printf '%s\n' \
	"{\"schema_version\":1,\"base_image_sha256_before\":\"$base_sha_before\",\"base_image_sha256_after\":\"$base_sha_after\",\"kernel_sha256\":\"$kernel_sha\",\"effect_object_sha256\":\"$effect_sha\",\"lifecycle_object_sha256\":\"$lifecycle_sha\",\"host_runner_sha256\":\"$runner_sha\",\"host_analyzer_sha256\":\"$analyzer_sha\",\"qemu_pid\":$qemu_pid_at_launch,\"qemu_start_time_ticks\":$qemu_start,\"ssh_port\":$ssh_port,\"snapshot_on\":true}" \
	>"$run_root/run-metadata.json"
find "$run_root/inputs" "$run_root/guest-evidence" -type f -print0 \
	| sort -z | xargs -0 sha256sum >"$run_root/SHA256SUMS"
sha256sum "$run_root/concurrency-analysis.json" "$run_root/run-metadata.json" \
	"$run_root/qemu.argv.shell" "$run_root/qemu.stderr" \
	"$run_root/console.log" "$run_root/guest.stdout" \
	"$run_root/guest.stderr" >>"$run_root/SHA256SUMS"
printf 'CONCURRENCY_HOST_E2E_PASS result=%s base_sha256=%s\n' \
	"$run_root" "$base_sha_after"
