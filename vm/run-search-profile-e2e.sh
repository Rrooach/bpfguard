#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Search-profile smoke validation in a NEW, disposable QEMU guest. This never
# connects to an existing guest, drops the Host's caches, or changes its cgroups.
# Performance results from this smoke test are not a calibrated benchmark.
set -euo pipefail

script_dir=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -P -- "$script_dir/.." && pwd -P)
kernel_dir=$project_dir/.output/vm-kernel-profile-psi
output_base=$project_dir/.output/search-profile-e2e
corpus=$project_dir/../../../lib
sampler=$project_dir/.output/cargo-target/debug/allox-load-sampler
hist_object=$project_dir/.output/kernel_hist.bpf.o
python_binary=${PROFILE_PYTHON:-/usr/bin/python3.8}
qemu_binary=${QEMU_BINARY:-qemu-system-x86_64}
rootfs= ssh_key= queries_file= run_root= qemu_pid= qemu_start= qemu_exe=
guest_root= base_sha_before= name=
ssh_port=10079
modes=baseline,sampler
concurrency=1,2,4
jobs=8
passes=1
repetitions=3
warmups=1
cpus=0,1
timeout_seconds=1200
calibration_kind=search
calibration_seconds=0.4
require_psi=1
hist_groups=sched,syscall
interval_ms=100
workspace_layout=shared
intervention=none
cache_mode=warm

usage()
{
	cat <<'EOF'
Usage: run-search-profile-e2e.sh --rootfs UNUSED_RAW_IMAGE --ssh-key KEY --queries-file JSON [options]

Required inputs are local files; the key is used only by SSH, never copied.
Options:
  --corpus DIR              Source corpus (default: kernel lib/, about 13 MiB)
  --kernel-build-dir DIR    BTF+PSI kernel (default: vm-kernel-profile-psi)
  --sampler FILE            Built allox-load-sampler executable
  --kernel-hist-object FILE Built kernel_hist.bpf.o
  --kernel-hist-groups CSV  Optional probe groups (default: sched,syscall)
  --require-psi             Require system and cgroup PSI (default)
  --allow-missing-psi       Explicit legacy compatibility; missing PSI is unknown
  --modes CSV               baseline,sampler (add kernel-hist for optional BPF)
  --concurrency CSV         1,2,4
  --jobs N                  8 fixed jobs in every condition
  --passes N                1 search pass per job
  --repetitions N           3 repeated measurements
  --warmups N               1 warmup
  --cpus CSV                0,1 guest CPUs; guest has four vCPUs
  --interval-ms N           100/500/1000 etc.; process interval is max(500,N)
  --workspace-layout MODE   shared (default) or independent identical copies
  --intervention MODE       none or exact-reuse (first scan remains timed)
  --cache MODE              warm or guest-cold (ONLY this new disposable Guest)
  --calibration-kind KIND   Optional cpu, sleep, or read micro-calibration
  --calibration-seconds N   0.4 seconds of calibration work
  --python FILE             Host Python 3.8+ interpreter for offline staging
  --ssh-port PORT           10079; must be free
  --output-base DIR         New per-run directory under .output/search-profile-e2e
  --timeout-seconds N       1200 for the guest campaign

Build current binaries first: make all kernel-hist-bpf
No API/model requests or apt installs. Real Observer three-arm experiments use
experiments/profile-validation/campaign.py with separately pinned Observer assets.
The source raw image must be unused, and is hash-checked before/after snapshot=on.
Build the default PSI kernel first with vm/build-profile-kernel.sh.
Old kernels require --kernel-build-dir OLD_DIR --allow-missing-psi.
EOF
}

while [[ $# -gt 0 ]]; do
	case $1 in
	--rootfs) rootfs=${2:?}; shift 2 ;;
	--ssh-key) ssh_key=${2:?}; shift 2 ;;
	--queries-file) queries_file=${2:?}; shift 2 ;;
	--corpus) corpus=${2:?}; shift 2 ;;
	--kernel-build-dir) kernel_dir=${2:?}; shift 2 ;;
	--sampler) sampler=${2:?}; shift 2 ;;
	--kernel-hist-object) hist_object=${2:?}; shift 2 ;;
	--kernel-hist-groups) hist_groups=${2:?}; shift 2 ;;
	--require-psi) require_psi=1; shift ;;
	--allow-missing-psi) require_psi=0; shift ;;
	--modes) modes=${2:?}; shift 2 ;;
	--concurrency) concurrency=${2:?}; shift 2 ;;
	--jobs) jobs=${2:?}; shift 2 ;;
	--passes) passes=${2:?}; shift 2 ;;
	--repetitions) repetitions=${2:?}; shift 2 ;;
	--warmups) warmups=${2:?}; shift 2 ;;
	--cpus) cpus=${2:?}; shift 2 ;;
	--interval-ms) interval_ms=${2:?}; shift 2 ;;
	--workspace-layout) workspace_layout=${2:?}; shift 2 ;;
	--intervention) intervention=${2:?}; shift 2 ;;
	--cache) cache_mode=${2:?}; shift 2 ;;
	--calibration-kind) calibration_kind=${2:?}; shift 2 ;;
	--calibration-seconds) calibration_seconds=${2:?}; shift 2 ;;
	--python) python_binary=${2:?}; shift 2 ;;
	--ssh-port) ssh_port=${2:?}; shift 2 ;;
	--output-base) output_base=${2:?}; shift 2 ;;
	--timeout-seconds) timeout_seconds=${2:?}; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; exit 2 ;;
	esac
done
[[ -n $rootfs && -n $ssh_key && -n $queries_file ]] || { usage >&2; exit 2; }
[[ $ssh_port =~ ^[1-9][0-9]{0,4}$ && $ssh_port -le 65535 ]] || exit 2
[[ $modes =~ ^(baseline|sampler|kernel-hist)(,(baseline|sampler|kernel-hist))*$ ]] || exit 2
[[ $concurrency =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]] || exit 2
[[ $cpus =~ ^[0-3](,[0-3])*$ ]] || exit 2
[[ $interval_ms =~ ^[0-9]+$ && $interval_ms -ge 10 && $interval_ms -le 60000 ]] || exit 2
[[ $workspace_layout == shared || $workspace_layout == independent ]] || exit 2
[[ $intervention == none || $intervention == exact-reuse ]] || exit 2
[[ $cache_mode == warm || $cache_mode == guest-cold ]] || exit 2
[[ $calibration_kind =~ ^(search|cpu|sleep|read)$ ]] || exit 2
[[ $hist_groups =~ ^(sched|syscall|mem|lock|irq|blk)(,(sched|syscall|mem|lock|irq|blk))*$ ]] || exit 2
[[ $calibration_seconds =~ ^([0-9]+([.][0-9]*)?|\.[0-9]+)$ ]] || exit 2
for value in "$jobs" "$passes" "$repetitions" "$timeout_seconds"; do
	[[ $value =~ ^[1-9][0-9]*$ ]] || exit 2
done
[[ $warmups =~ ^[0-9]+$ ]] || exit 2
for command in "$qemu_binary" "$python_binary" awk file find fuser grep install \
	ldd mkdir mktemp readlink realpath scp sed seq sha256sum sleep sort ssh ss stat \
	tar timeout tr; do
	command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done
rootfs=$(realpath -e -- "$rootfs")
ssh_key=$(realpath -e -- "$ssh_key")
queries_file=$(realpath -e -- "$queries_file")
corpus=$(realpath -e -- "$corpus")
kernel_dir=$(realpath -e -- "$kernel_dir")
sampler=$(realpath -e -- "$sampler")
python_binary=$(realpath -e -- "$python_binary")
output_base=$(realpath -m -- "$output_base")
kernel_image=$kernel_dir/arch/x86/boot/bzImage
[[ -d $corpus && $corpus != / && -x $sampler ]] || exit 2
for path in "$rootfs" "$ssh_key" "$queries_file" "$kernel_image" \
	"$project_dir/experiments/search-profile/run.py"; do
	[[ -f $path && ! -L $path ]] || { echo "missing regular input: $path" >&2; exit 2; }
done
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || { echo 'KVM unavailable' >&2; exit 2; }
file "$rootfs" | grep -q 'ext4 filesystem data' || { echo 'rootfs must be raw ext4' >&2; exit 2; }
file "$kernel_image" | grep -q 'Linux kernel x86 boot executable bzImage' || exit 2
if fuser -s "$rootfs" 2>/dev/null; then
	echo 'rootfs is already open; refuse to share an existing VM image' >&2
	exit 2
fi
if ss -ltnH "sport = :$ssh_port" | grep -q .; then
	echo 'SSH port is already in use' >&2
	exit 2
fi
if [[ ,$modes, == *,kernel-hist,* ]]; then
	hist_object=$(realpath -e -- "$hist_object")
	[[ -f $hist_object && ! -L $hist_object ]] || exit 2
	grep -qx 'CONFIG_DEBUG_INFO_BTF=y' "$kernel_dir/.config" || {
		echo 'kernel-hist requires a BTF-enabled guest kernel' >&2; exit 2;
	}
fi
if [[ $require_psi -eq 1 ]]; then
	grep -qx 'CONFIG_PSI=y' "$kernel_dir/.config" || {
		echo '--require-psi requires CONFIG_PSI=y in the selected kernel' >&2; exit 2;
	}
fi

# Bundle only the specified interpreter's stdlib and non-glibc dependencies.
# The guest's newer glibc supplies its own loader/libc. Never copy credentials,
# user site-packages, environment secrets, or the Host's entire /usr tree.
python_version=$("$python_binary" -I -c 'import sys; assert sys.version_info >= (3, 8); print("%d.%d" % sys.version_info[:2])')
python_stdlib=$("$python_binary" -I -c 'import sysconfig; print(sysconfig.get_path("stdlib"))')
[[ -d $python_stdlib && $python_stdlib != / ]] || exit 2
mkdir -p "$output_base"
run_root=$(mktemp -d "$output_base/run-XXXXXXXX")
mkdir -m 0700 "$run_root/inputs" "$run_root/staging"
mkdir -p "$run_root/staging/python/bin" "$run_root/staging/python/lib" \
	"$run_root/staging/search-profile"
install -m 0755 "$python_binary" "$run_root/staging/python/bin/python3"
tar -C "$(dirname -- "$python_stdlib")" \
	--exclude=site-packages --exclude=dist-packages --exclude=__pycache__ \
	--exclude='*.pyc' -cf - "$(basename -- "$python_stdlib")" \
	| tar -C "$run_root/staging/python/lib" -xf -
[[ -d $run_root/staging/python/lib/python$python_version ]] || exit 2
dependency_paths()
{
	ldd "$1" 2>/dev/null | awk '/=> \/[^ ]+/ {print $3}'
}
{
	dependency_paths "$python_binary"
	while IFS= read -r -d '' extension; do
		dependency_paths "$extension"
	done < <(find "$python_stdlib/lib-dynload" -maxdepth 1 -type f -name '*.so' -print0)
} | sort -u | while IFS= read -r dependency; do
	case ${dependency##*/} in
	libc.so.*|libpthread.so.*|libdl.so.*|libm.so.*|libutil.so.*|librt.so.*|ld-linux*) continue ;;
	esac
	install -m 0644 "$dependency" "$run_root/staging/python/lib/${dependency##*/}"
done
while IFS= read -r -d '' source; do
	install -m 0644 "$source" "$run_root/staging/search-profile/"
done < <(find "$project_dir/experiments/search-profile" -maxdepth 1 -type f -name '*.py' -print0)
install -m 0644 "$queries_file" "$run_root/staging/queries.json"
install -m 0755 "$sampler" "$run_root/staging/allox-load-sampler"
install -m 0644 "$kernel_image" "$run_root/inputs/kernel.bzImage"
install -m 0644 "$kernel_dir/.config" "$run_root/inputs/kernel.config"
install -m 0755 "$script_dir/run-search-profile-e2e.sh" "$run_root/inputs/"
if [[ ,$modes, == *,kernel-hist,* ]]; then
	install -m 0644 "$hist_object" "$run_root/staging/kernel_hist.bpf.o"
fi
tar -C "$run_root/staging" -czf "$run_root/inputs/runtime.tar.gz" .
tar -C "$corpus" --exclude=.git --exclude=.output --exclude=__pycache__ \
	-czf "$run_root/inputs/corpus.tar.gz" .
base_sha_before=$(sha256sum "$rootfs" | awk '{print $1}')
printf '%s\n' "$base_sha_before" >"$run_root/base-image.sha256.before"
name=search-profile-${run_root##*/}
qemu_exe=$(realpath -e -- "$(command -v "$qemu_binary")")

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
	tr '\0' ' ' <"/proc/$qemu_pid/cmdline" | grep -Fq -- "$name" || return 1
	tr '\0' ' ' <"/proc/$qemu_pid/cmdline" | \
		grep -Fq -- "file=$rootfs,format=raw,if=ide,snapshot=on"
}

cleanup()
{
	local attempt
	if qemu_identity_matches; then
		kill -TERM "$qemu_pid" 2>/dev/null || true
		for attempt in $(seq 1 50); do
			qemu_identity_matches || break
			sleep 0.1
		done
	fi
	if qemu_identity_matches; then
		kill -KILL "$qemu_pid" 2>/dev/null || true
		for attempt in $(seq 1 50); do
			qemu_identity_matches || break
			sleep 0.1
		done
	fi
	if qemu_identity_matches; then
		echo 'exact test QEMU did not terminate' >&2
		return 1
	fi
}
trap cleanup EXIT
qemu_args=(
	-daemonize -pidfile "$run_root/qemu.pid" -name "$name"
	-m 2048 -smp 4 -enable-kvm -cpu host,migratable=off
	-display none -serial "file:$run_root/console.log" -no-reboot
	-kernel "$run_root/inputs/kernel.bzImage"
	-append 'root=/dev/sda rw console=ttyS0,115200 net.ifnames=0 lsm=capability,selinux,bpf psi=1'
	-drive "file=$rootfs,format=raw,if=ide,snapshot=on"
	-netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:$ssh_port-:22"
	-device e1000,netdev=net0
)
# Recheck just before launch: packaging may have taken time.
! fuser -s "$rootfs" 2>/dev/null || { echo 'rootfs became busy' >&2; exit 2; }
! ss -ltnH "sport = :$ssh_port" | grep -q . || { echo 'SSH port became busy' >&2; exit 2; }
printf '%q ' "$qemu_exe" "${qemu_args[@]}" >"$run_root/qemu.argv.shell"
printf '\n' >>"$run_root/qemu.argv.shell"
"$qemu_exe" "${qemu_args[@]}" 2>"$run_root/qemu.stderr"
qemu_pid=$(<"$run_root/qemu.pid")
[[ $qemu_pid =~ ^[1-9][0-9]*$ ]] || exit 1
qemu_start=$(qemu_start_time "$qemu_pid")
qemu_identity_matches || { echo 'new QEMU identity cannot be proved' >&2; exit 1; }
ssh_options=(
	-i "$ssh_key" -p "$ssh_port" -o BatchMode=yes
	-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$run_root/known_hosts"
	-o LogLevel=ERROR -o ConnectTimeout=2 -o ServerAliveInterval=2
	-o ServerAliveCountMax=3
)
scp_options=(
	-q -i "$ssh_key" -P "$ssh_port" -o BatchMode=yes
	-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$run_root/known_hosts"
	-o LogLevel=ERROR -o ConnectTimeout=2 -o ServerAliveInterval=2
	-o ServerAliveCountMax=3
)
ready=0
for attempt in $(seq 1 60); do
	qemu_identity_matches || { echo 'new QEMU exited before SSH' >&2; exit 1; }
	if ssh "${ssh_options[@]}" root@127.0.0.1 true 2>/dev/null; then
		ready=1
		break
	fi
	sleep 1
done
[[ $ready -eq 1 ]] || { echo 'Guest SSH did not become ready' >&2; exit 1; }
guest_root=/opt/$name
ssh "${ssh_options[@]}" root@127.0.0.1 "mkdir -m 0700 '$guest_root'"
scp "${scp_options[@]}" "$run_root/inputs/runtime.tar.gz" \
	"$run_root/inputs/corpus.tar.gz" "root@127.0.0.1:$guest_root/"

# Everything below runs inside this new VM. The campaign must handle missing
# PSI and other optional files as unavailable, not as a measured zero.
guest_status=0
timeout --foreground "${timeout_seconds}s" ssh "${ssh_options[@]}" \
	root@127.0.0.1 /bin/bash -s -- "$guest_root" "$modes" "$concurrency" \
	"$jobs" "$passes" "$repetitions" "$warmups" "$cpus" "$calibration_kind" \
	"$calibration_seconds" "$require_psi" "$hist_groups" "$interval_ms" "$workspace_layout" "$intervention" "$cache_mode" \
	>"$run_root/guest.stdout" 2>"$run_root/guest.stderr" <<'GUEST' || guest_status=$?
set -euo pipefail
guest_root=$1
modes=$2
concurrency=$3
jobs=$4
passes=$5
repetitions=$6
warmups=$7
cpus=$8
calibration_kind=$9
calibration_seconds=${10}
require_psi=${11}
hist_groups=${12}
interval_ms=${13}
workspace_layout=${14}
intervention=${15}
cache_mode=${16}
mkdir "$guest_root/runtime" "$guest_root/corpus" "$guest_root/results"
tar -C "$guest_root/runtime" -xzf "$guest_root/runtime.tar.gz"
tar -C "$guest_root/corpus" -xzf "$guest_root/corpus.tar.gz"
export PYTHONHOME=$guest_root/runtime/python
export LD_LIBRARY_PATH=$PYTHONHOME/lib
export PYTHONNOUSERSITE=1
export PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH
python=$PYTHONHOME/bin/python3
"$python" -c 'import ctypes, hashlib, json, multiprocessing, pathlib, subprocess, sys; print(sys.version)'
"$python" - "$guest_root/results/guest-environment.json" "$require_psi" <<'PY'
import json, os, pathlib, platform, sys, time
root = pathlib.Path('/sys/fs/cgroup')
state = {
    'schema_version': 1, 'purpose': 'FUNCTIONAL_SMOKE_NOT_CALIBRATED_PERFORMANCE',
    'kernel_release': platform.release(), 'python_version': sys.version,
    'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
    'clock_monotonic_ns': time.monotonic_ns(),
    'cpu_affinity': sorted(os.sched_getaffinity(0)),
    'cgroup_v2': (root / 'cgroup.controllers').is_file(),
    'psi_available': all(pathlib.Path('/proc/pressure/' + r).is_file() for r in ('cpu', 'memory', 'io')),
    'psi_system_sources': {r: pathlib.Path('/proc/pressure/' + r).read_text() if pathlib.Path('/proc/pressure/' + r).is_file() else None for r in ('cpu', 'memory', 'io')},
    'psi_cgroup_sources': {r: (root / (r + '.pressure')).read_text() if (root / (r + '.pressure')).is_file() else None for r in ('cpu', 'memory', 'io')},
    'kernel_command_line': pathlib.Path('/proc/cmdline').read_text().strip(),
    'psi_required': sys.argv[2] == '1',
    'btf_available': pathlib.Path('/sys/kernel/btf/vmlinux').is_file(),
    'cache_policy': 'WARM_NO_GLOBAL_DROP_CACHES',
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(state, indent=2) + '\n')
if not state['cgroup_v2']:
    raise SystemExit('cgroup v2 is required')
if state['psi_required'] and (not state['psi_available'] or any(v is None for v in state['psi_cgroup_sources'].values())):
    raise SystemExit('required system/cgroup PSI is unavailable')
PY
[[ ! -e /sys/fs/cgroup/search-profile ]] || { echo 'test cgroup already exists' >&2; exit 1; }
for controller in cpu memory io; do
	grep -qw "$controller" /sys/fs/cgroup/cgroup.controllers || {
		echo "Guest cgroup controller unavailable: $controller" >&2; exit 1;
	}
done
# This is the disposable guest's cgroup root, never the physical Host's.
printf '+cpu +memory +io\n' >/sys/fs/cgroup/cgroup.subtree_control
mkdir /sys/fs/cgroup/search-profile
hist_args=()
if [[ ,$modes, == *,kernel-hist,* ]]; then
	hist_object=$guest_root/runtime/kernel_hist.bpf.o
	hist_sha=$(sha256sum "$hist_object" | awk '{print $1}')
	hist_args=(--kernel-hist-object "$hist_object" --kernel-hist-sha256 "$hist_sha" \
		--kernel-hist-groups "$hist_groups")
fi
calibration_args=()
if [[ $calibration_kind != search ]]; then
	calibration_args=(--calibration-kind "$calibration_kind" \
		--calibration-seconds "$calibration_seconds")
fi
"$python" "$guest_root/runtime/search-profile/run.py" \
	--corpus "$guest_root/corpus" \
	--queries-file "$guest_root/runtime/queries.json" \
	--output-dir "$guest_root/results/campaign" \
	--sampler "$guest_root/runtime/allox-load-sampler" \
	--concurrency "$concurrency" --jobs "$jobs" --passes "$passes" \
	--repetitions "$repetitions" --warmups "$warmups" --cache "$cache_mode" --allow-guest-drop-caches \
	--interval-ms "$interval_ms" --process-interval-ms "$((interval_ms > 500 ? interval_ms : 500))" \
	--workspace-layout "$workspace_layout" --intervention "$intervention" \
	--cgroup-parent /sys/fs/cgroup/search-profile --modes "$modes" \
	--cpus "$cpus" "${hist_args[@]}" "${calibration_args[@]}"
rmdir /sys/fs/cgroup/search-profile
printf 'SEARCH_PROFILE_GUEST_E2E_PASS\n'
GUEST
copy_status=0
scp "${scp_options[@]}" -r "root@127.0.0.1:$guest_root/results" \
	"$run_root/guest-evidence" || copy_status=$?
cleanup
qemu_pid=
base_sha_after=$(sha256sum "$rootfs" | awk '{print $1}')
printf '%s\n' "$base_sha_after" >"$run_root/base-image.sha256.after"
[[ $base_sha_before == "$base_sha_after" ]] || {
	echo 'base image changed despite snapshot=on; reject result' >&2; exit 1;
}
[[ $copy_status -eq 0 ]] || { echo 'could not retrieve guest artifacts' >&2; exit 1; }
if [[ $guest_status -ne 0 ]]; then
	echo "Guest campaign failed ($guest_status); artifacts: $run_root" >&2
	sed -n '1,120p' "$run_root/guest.stderr" >&2
	exit "$guest_status"
fi
grep -q '^SEARCH_PROFILE_GUEST_E2E_PASS$' "$run_root/guest.stdout"
if grep -Eq 'BUG:|kernel panic|Oops:' "$run_root/console.log"; then
	echo 'Guest console contains a kernel failure' >&2; exit 1
fi
"$python_binary" -I - "$run_root" "$base_sha_before" "$base_sha_after" "$modes" <<'PY'
import hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])
campaign_root = root / 'guest-evidence/campaign'
campaign = json.loads((campaign_root / 'campaign.json').read_text())
environment = json.loads((root / 'guest-evidence/guest-environment.json').read_text())
assert campaign['status'] == 'COMPLETE', 'campaign did not complete'
assert campaign['trials'], 'campaign has no trials'
outputs = {}
task_count = 0
probe_recursion_misses = []
psi_trials = []
for trial in campaign['trials']:
    directory = campaign_root / trial['path']
    directory.resolve().relative_to(campaign_root.resolve())
    assert len(trial['results']) == campaign['jobs'], 'wrong fixed-work job count'
    report = json.loads((directory / 'report.json').read_text())
    assert len(report['tasks']) == campaign['jobs'], 'missing task correlations'
    for task in report['tasks']:
        assert task['identity_valid'], 'invalid task/process/cgroup identity'
        assert task['status'] == 'COMPLETE' and task['duration_ns'] >= 0
    for result in trial['results']:
        assert result['exit_code'] == 0, 'task failed'
        actual = (result['output_sha256'], result['output_bytes'])
        previous = outputs.setdefault(result['query_index'], actual)
        assert actual == previous, 'search output differs between conditions'
        task_count += 1
    if trial['mode'] != 'baseline' and environment.get('psi_required'):
        load = directory / 'load'
        meta = json.loads((load / 'load-meta.json').read_text())
        samples = [json.loads(line) for line in (load / 'load-samples.jsonl').read_text().splitlines()]
        assert len(samples) >= 2, 'PSI validation needs endpoint samples'
        assert all(group['available']['pressure'] for group in meta['cgroups']), 'cgroup PSI source missing'
        previous = {}
        for sample in samples:
            for index, group in enumerate([sample] + sample['cgroups']):
                assert group.get('present', True), 'PSI target disappeared during sampling'
                for resource in ('cpu', 'memory', 'io'):
                    value = group.get('psi', {}).get(resource, {}).get('some_total_us')
                    assert isinstance(value, int) and not isinstance(value, bool) and value >= 0, 'missing/invalid PSI counter'
                    key = (index, resource)
                    assert value >= previous.get(key, 0), 'PSI counter reset'
                    previous[key] = value
        psi_trials.append({'trial': trial['path'], 'concurrency': trial['concurrency'],
                           'mode': trial['mode'], 'warmup': trial['warmup'],
                           'sample_count': len(samples),
                           'root_some_stall_delta_us': {resource:
                               samples[-1]['cgroups'][0]['psi'][resource]['some_total_us'] -
                               samples[0]['cgroups'][0]['psi'][resource]['some_total_us']
                               for resource in ('cpu', 'memory', 'io')}})
    if trial['mode'] == 'kernel-hist':
        load = directory / 'load'
        stats = json.loads((load / 'load-sampler-stats.json').read_text())
        hist = stats['kernel_hist']
        assert not hist['runtime_stats_enabled_by_sampler'], 'unexpected global BPF stats enable'
        last = json.loads((load / 'load-samples.jsonl').read_text().splitlines()[-1])
        assert any(row[0] > 0 for row in last['khist']['m']), 'no kernel histogram observations'
        for program in hist['programs']:
            if program.get('recursion_misses', 0):
                probe_recursion_misses.append({'trial': trial['path'],
                                               'program': program['name'],
                                               'count': program['recursion_misses']})
def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()
state = {
    'schema_version': 1, 'status': 'PASS',
    'purpose': 'FUNCTIONAL_SMOKE_NOT_CALIBRATED_PERFORMANCE',
    'snapshot_on': True, 'existing_guests_touched': False,
    'base_image_sha256_before': sys.argv[2],
    'base_image_sha256_after': sys.argv[3], 'modes': sys.argv[4].split(','),
    'kernel_sha256': digest(root / 'inputs/kernel.bzImage'),
    'kernel_config_sha256': digest(root / 'inputs/kernel.config'),
    'runtime_archive_sha256': digest(root / 'inputs/runtime.tar.gz'),
    'corpus_archive_sha256': digest(root / 'inputs/corpus.tar.gz'),
    'validated_trial_count': len(campaign['trials']),
    'validated_task_count': task_count,
    'output_equivalence': True, 'task_identities_valid': True,
    'probe_recursion_misses': probe_recursion_misses,
    'histogram_completeness_claimed': False,
    'psi_required': environment.get('psi_required', False),
    'psi_sources_available': environment.get('psi_available', False),
    'psi_sample_validation': psi_trials,
}
(root / 'run-metadata.json').write_text(json.dumps(state, indent=2) + '\n')
paths = sorted(p for folder in ('inputs', 'guest-evidence')
               for p in (root / folder).rglob('*') if p.is_file())
(root / 'SHA256SUMS').write_text(''.join('%s  %s\n' % (digest(p), p.relative_to(root)) for p in paths))
PY
printf 'SEARCH_PROFILE_HOST_E2E_PASS result=%s base_sha256=%s\n' \
	"$run_root" "$base_sha_after"
