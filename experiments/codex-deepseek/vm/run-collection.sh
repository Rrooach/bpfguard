#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set +x
set -euo pipefail
umask 0077

# Capture and de-export the caller's credential before any external command or
# command substitution can inherit it. Keep the mutable copy so it can be
# overwritten as soon as the Guest workflow finishes.
COLLECTION_PROVIDER_SECRET="${DEEPSEEK_API_KEY:-}"
export -n COLLECTION_PROVIDER_SECRET 2>/dev/null || true
unset DEEPSEEK_API_KEY || true
ulimit -c 0

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly EXPERIMENT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly PROJECT_DIR="$(cd -- "$EXPERIMENT_DIR/../.." && pwd)"
readonly CODEX_VERSION=0.154.0
readonly EXPECTED_CODEX_SHA256=3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022
readonly EXPECTED_CODE_MODE_HOST_SHA256=0c57be435e73b70d9106c850d751cd259a7f04da958a453d7ef59090d82b70f1
readonly EXPECTED_BWRAP_SHA256=01fb705f067bd5365b63d8ad2323a61c8d007733ca5e649437e086f3fb9935d8
readonly EXPECTED_RG_SHA256=e62198eb19b136b88c330af83647b5a962cb99b6b1f066758568f12de1974849
readonly EXPECTED_ZSH_SHA256=67faaaa89242c4a332e16e508a1977cffc24bf7fca31d4411cdfd101f3831ef3
readonly EXPECTED_PACKAGE_SHA256=b039964d28d57b2a7e929ee9986303582501c7cc9787f6c018b6d3c7b35c87d7
readonly QEMU_BINARY="${QEMU_BINARY:-qemu-system-x86_64}"
readonly -a CODEX_VENDOR_FILES=(
	bin/codex
	bin/codex-code-mode-host
	codex-resources/bwrap
	codex-resources/zsh/bin/zsh
	codex-path/rg
	codex-package.json
)
readonly -a EXPECTED_CODEX_VENDOR_SHA256=(
	"$EXPECTED_CODEX_SHA256"
	"$EXPECTED_CODE_MODE_HOST_SHA256"
	"$EXPECTED_BWRAP_SHA256"
	"$EXPECTED_ZSH_SHA256"
	"$EXPECTED_RG_SHA256"
	"$EXPECTED_PACKAGE_SHA256"
)
readonly -a EXPECTED_TASK_NAMES=(
	00-text-only
	01-file-write
	02-ephemeral-map
	03-transient-restore
)

readonly HOST_TMPDIR="$PROJECT_DIR/.output/tmp"
install -d -m 0700 -- "$HOST_TMPDIR"
[[ -d "$HOST_TMPDIR" && ! -L "$HOST_TMPDIR" &&
	"$(stat -c %a -- "$HOST_TMPDIR")" == 700 ]] || {
	echo "unsafe Host temporary directory: $HOST_TMPDIR" >&2
	exit 1
}
export TMPDIR="$HOST_TMPDIR"

KERNEL_IMAGE=""
ROOTFS_IMAGE=""
SSH_KEY=""
SSH_PORT=10042
OUTPUT_PARENT="$PROJECT_DIR/.output/agent-collection"
MODEL=deepseek-flash
GUEST_MODE=run

require_qemu_safe_path()
{
	local path="$1"
	local label="$2"

	if [[ "$path" == *,* || "$path" == *$'\n'* ||
	      "$path" == *$'\r'* || "$path" == *\\* ]]; then
		echo "$label contains a character unsafe for a QEMU option: $path" >&2
		exit 2
	fi
}

usage()
{
	cat >&2 <<USAGE
Usage: $0 --kernel BZIMAGE --rootfs RAW_IMAGE --ssh-key PRIVATE_KEY [options]

Deploy Codex in a disposable, networked collection VM and either run the
DeepSeek task suite or stop after keyless deployment/calibration.

Required:
  --kernel PATH       x86-64 bzImage with the Observer prerequisites
  --rootfs PATH       raw ext4 Guest image used only as a backing file
  --ssh-key PATH      private key authorized for root in the Guest

Options:
  --ssh-port PORT     loopback SSH forwarding port (default: $SSH_PORT)
  --output-dir DIR    parent for timestamped batches (default: $OUTPUT_PARENT)
  --model MODEL       deepseek-flash or deepseek-v4-pro (default: $MODEL)
  --deploy-only       use only an invalid-key endpoint probe; no real key/inference

Normal mode requires DEEPSEEK_API_KEY in the caller environment. The key is
removed from the environment before QEMU or helper processes start and is sent
to the Guest only over the SSH stdin channel.
USAGE
	exit 2
}

while [[ "$#" -gt 0 ]]; do
	case "$1" in
	--kernel)
		[[ "$#" -ge 2 ]] || usage
		KERNEL_IMAGE="$2"
		shift 2
		;;
	--rootfs)
		[[ "$#" -ge 2 ]] || usage
		ROOTFS_IMAGE="$2"
		shift 2
		;;
	--ssh-key)
		[[ "$#" -ge 2 ]] || usage
		SSH_KEY="$2"
		shift 2
		;;
	--ssh-port)
		[[ "$#" -ge 2 ]] || usage
		SSH_PORT="$2"
		shift 2
		;;
	--output-dir)
		[[ "$#" -ge 2 ]] || usage
		OUTPUT_PARENT="$2"
		shift 2
		;;
	--model)
		[[ "$#" -ge 2 ]] || usage
		MODEL="$2"
		shift 2
		;;
	--deploy-only)
		GUEST_MODE=deploy-only
		shift
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
[[ "$MODEL" == deepseek-flash || "$MODEL" == deepseek-v4-pro ]] || {
	echo "unsupported model: $MODEL" >&2
	exit 2
}
if [[ "$GUEST_MODE" == run ]]; then
	[[ "$COLLECTION_PROVIDER_SECRET" == sk-* &&
		${#COLLECTION_PROVIDER_SECRET} -le 512 &&
		"$COLLECTION_PROVIDER_SECRET" != *$'\n'* &&
		"$COLLECTION_PROVIDER_SECRET" != *$'\r'* ]] || {
		echo "DEEPSEEK_API_KEY is missing or has an invalid shape" >&2
		exit 2
	}
fi

require_qemu_safe_path "$QEMU_BINARY" "QEMU executable"
for command in "$QEMU_BINARY" qemu-img npm make cc curl python3 awk basename \
	chmod date dirname env find grep install mkdir mktemp readlink realpath seq \
	sha256sum sleep sort ssh scp ss stat tail tar timeout wc xargs; do
	command -v "$command" >/dev/null || {
		echo "missing Host dependency: $command" >&2
		exit 1
	}
done
readonly QEMU_EXECUTABLE="$(realpath -- "$(command -v "$QEMU_BINARY")")"
readonly QEMU_IMG_EXECUTABLE="$(realpath -- "$(command -v qemu-img)")"
[[ -f "$QEMU_EXECUTABLE" && ! -L "$QEMU_EXECUTABLE" &&
	-x "$QEMU_EXECUTABLE" ]] || {
	echo "QEMU executable is not a safe regular file: $QEMU_EXECUTABLE" >&2
	exit 1
}
[[ -f "$QEMU_IMG_EXECUTABLE" && ! -L "$QEMU_IMG_EXECUTABLE" &&
	-x "$QEMU_IMG_EXECUTABLE" ]] || {
	echo "qemu-img executable is not a safe regular file: $QEMU_IMG_EXECUTABLE" >&2
	exit 1
}
[[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || {
	echo "/dev/kvm is unavailable" >&2
	exit 1
}
for input in "$KERNEL_IMAGE" "$ROOTFS_IMAGE" "$SSH_KEY"; do
	[[ -f "$input" && ! -L "$input" ]] || {
		echo "missing or unsafe Host input: $input" >&2
		exit 1
	}
done
KERNEL_IMAGE="$(realpath -- "$KERNEL_IMAGE")"
ROOTFS_IMAGE="$(realpath -- "$ROOTFS_IMAGE")"
SSH_KEY="$(realpath -- "$SSH_KEY")"
require_qemu_safe_path "$QEMU_EXECUTABLE" "QEMU executable"
require_qemu_safe_path "$QEMU_IMG_EXECUTABLE" "qemu-img executable"
require_qemu_safe_path "$KERNEL_IMAGE" "kernel image"
require_qemu_safe_path "$ROOTFS_IMAGE" "rootfs image"
[[ "$("$QEMU_IMG_EXECUTABLE" info --output=json "$ROOTFS_IMAGE" | \
	python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')" == raw ]] || {
	echo "rootfs must be a raw image" >&2
	exit 1
}
if ss -H -ltn | awk '{print $4}' | grep -Eq "(^|[:.])$SSH_PORT$"; then
	echo "SSH port is already in use: $SSH_PORT" >&2
	exit 1
fi

readonly BATCH_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
require_qemu_safe_path "$OUTPUT_PARENT" "output directory"
mkdir -p -- "$OUTPUT_PARENT"
OUTPUT_PARENT="$(realpath -- "$OUTPUT_PARENT")"
require_qemu_safe_path "$OUTPUT_PARENT" "output directory"
readonly RUN_ROOT="$OUTPUT_PARENT/$BATCH_ID"
[[ ! -e "$RUN_ROOT" && ! -L "$RUN_ROOT" ]] || {
	echo "refusing to reuse batch output: $RUN_ROOT" >&2
	exit 1
}
install -d -m 0700 "$RUN_ROOT" "$RUN_ROOT/inputs" "$RUN_ROOT/qemu-tmp"

readonly KERNEL_IMAGE_SIZE="$(stat -c %s -- "$KERNEL_IMAGE")"
readonly KERNEL_IMAGE_SHA256="$(sha256sum -- "$KERNEL_IMAGE" | awk '{print $1}')"
readonly ROOTFS_IMAGE_SIZE="$(stat -c %s -- "$ROOTFS_IMAGE")"
readonly ROOTFS_IMAGE_SHA256="$(sha256sum -- "$ROOTFS_IMAGE" | awk '{print $1}')"
readonly SSH_KEY_SIZE="$(stat -c %s -- "$SSH_KEY")"
readonly SSH_KEY_SHA256="$(sha256sum -- "$SSH_KEY" | awk '{print $1}')"
readonly QEMU_EXECUTABLE_SIZE="$(stat -c %s -- "$QEMU_EXECUTABLE")"
readonly QEMU_EXECUTABLE_SHA256="$(sha256sum -- "$QEMU_EXECUTABLE" | awk '{print $1}')"
readonly QEMU_VERSION="$("$QEMU_EXECUTABLE" --version)"
readonly QEMU_IMG_EXECUTABLE_SIZE="$(stat -c %s -- "$QEMU_IMG_EXECUTABLE")"
readonly QEMU_IMG_EXECUTABLE_SHA256="$(sha256sum -- "$QEMU_IMG_EXECUTABLE" | awk '{print $1}')"
readonly QEMU_IMG_VERSION="$("$QEMU_IMG_EXECUTABLE" --version)"
{
	printf 'kernel_path=%q\n' "$KERNEL_IMAGE"
	echo "kernel_size=$KERNEL_IMAGE_SIZE"
	echo "kernel_sha256=$KERNEL_IMAGE_SHA256"
	printf 'rootfs_path=%q\n' "$ROOTFS_IMAGE"
	echo "rootfs_size=$ROOTFS_IMAGE_SIZE"
	echo "rootfs_sha256=$ROOTFS_IMAGE_SHA256"
	printf 'ssh_key_path=%q\n' "$SSH_KEY"
	echo "ssh_key_size=$SSH_KEY_SIZE"
	echo "ssh_key_sha256=$SSH_KEY_SHA256"
	printf 'qemu_path=%q\n' "$QEMU_EXECUTABLE"
	echo "qemu_size=$QEMU_EXECUTABLE_SIZE"
	echo "qemu_sha256=$QEMU_EXECUTABLE_SHA256"
	printf 'qemu_version=%q\n' "$QEMU_VERSION"
	printf 'qemu_img_path=%q\n' "$QEMU_IMG_EXECUTABLE"
	echo "qemu_img_size=$QEMU_IMG_EXECUTABLE_SIZE"
	echo "qemu_img_sha256=$QEMU_IMG_EXECUTABLE_SHA256"
	printf 'qemu_img_version=%q\n' "$QEMU_IMG_VERSION"
} > "$RUN_ROOT/host-input-identities.txt"

echo "B0 building Observer and credential launcher"
make -C "$PROJECT_DIR" release bpf workloads agent-collection-check

readonly OBSERVER="$PROJECT_DIR/.output/cargo-target/release/bpf-state-observer"
readonly RECORDER="$PROJECT_DIR/.output/recorder.bpf.o"
readonly MAP_FIXTURE="$PROJECT_DIR/.output/workloads/map-lifecycle"
readonly LAUNCHER="$PROJECT_DIR/.output/agent-collection/codex-task-launcher"
readonly SCOPE="$EXPERIMENT_DIR/config/collection-scope.json"
readonly TASKS="$EXPERIMENT_DIR/tasks"
readonly GUEST_RUNNER="$SCRIPT_DIR/guest-run-suite.sh"
readonly TASK_VALIDATOR="$PROJECT_DIR/.output/cargo-target/release/agent-collection-assert"
readonly FETCH_CATALOG="$SCRIPT_DIR/fetch-model-catalog.sh"
for input in "$OBSERVER" "$RECORDER" "$MAP_FIXTURE" "$LAUNCHER" \
	"$SCOPE" "$GUEST_RUNNER" "$TASK_VALIDATOR" "$FETCH_CATALOG"; do
	[[ -f "$input" && ! -L "$input" ]] || {
		echo "missing build/input artifact: $input" >&2
		exit 1
	}
done

echo "B1 resolving pinned Codex $CODEX_VERSION"
readonly CODEX_PREFIX="$PROJECT_DIR/.output/codex-$CODEX_VERSION"
readonly CODEX_VENDOR="$CODEX_PREFIX/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl"
if [[ ! -x "$CODEX_VENDOR/bin/codex" ]]; then
	[[ ! -e "$CODEX_PREFIX" ]] || {
		echo "partial Codex cache exists: $CODEX_PREFIX" >&2
		exit 1
	}
	env -u NODE_TLS_REJECT_UNAUTHORIZED npm install \
		--prefix "$CODEX_PREFIX" --no-audit --no-fund \
		"@openai/codex@$CODEX_VERSION"
fi
[[ -x "$CODEX_VENDOR/bin/codex" && -x "$CODEX_VENDOR/bin/codex-code-mode-host" &&
	-x "$CODEX_VENDOR/codex-resources/bwrap" &&
	-x "$CODEX_VENDOR/codex-path/rg" ]] || {
	echo "Codex vendor tree is incomplete" >&2
	exit 1
}
[[ "$($CODEX_VENDOR/bin/codex --version)" == "codex-cli $CODEX_VERSION" ]]
readonly CODEX_SHA256="$(sha256sum "$CODEX_VENDOR/bin/codex" | awk '{print $1}')"
[[ "$CODEX_SHA256" == "$EXPECTED_CODEX_SHA256" ]] || {
	echo "Codex binary digest does not match the audited $CODEX_VERSION build" >&2
	exit 1
}
[[ "$(find "$CODEX_VENDOR" -type f | wc -l)" -eq 6 ]]
for digest_and_path in \
	"$EXPECTED_CODE_MODE_HOST_SHA256:$CODEX_VENDOR/bin/codex-code-mode-host" \
	"$EXPECTED_BWRAP_SHA256:$CODEX_VENDOR/codex-resources/bwrap" \
	"$EXPECTED_RG_SHA256:$CODEX_VENDOR/codex-path/rg" \
	"$EXPECTED_ZSH_SHA256:$CODEX_VENDOR/codex-resources/zsh/bin/zsh" \
	"$EXPECTED_PACKAGE_SHA256:$CODEX_VENDOR/codex-package.json"; do
	expected_digest="${digest_and_path%%:*}"
	digest_path="${digest_and_path#*:}"
	[[ "$(sha256sum "$digest_path" | awk '{print $1}')" == "$expected_digest" ]] || {
		echo "Codex vendor digest mismatch: $digest_path" >&2
		exit 1
	}
done

echo "B2 freezing experiment inputs"
"$FETCH_CATALOG" "$RUN_ROOT/inputs/models.json" \
	> "$RUN_ROOT/model-catalog-source.txt"
install -m 0555 "$OBSERVER" "$RUN_ROOT/inputs/bpf-state-observer"
install -m 0444 "$RECORDER" "$RUN_ROOT/inputs/recorder.bpf.o"
install -m 0555 "$MAP_FIXTURE" "$RUN_ROOT/inputs/map-lifecycle"
install -m 0555 "$LAUNCHER" "$RUN_ROOT/inputs/codex-task-launcher"
install -m 0444 "$SCOPE" "$RUN_ROOT/inputs/collection-scope.json"
install -m 0555 "$GUEST_RUNNER" "$RUN_ROOT/inputs/guest-run-suite.sh"
install -m 0555 "$TASK_VALIDATOR" "$RUN_ROOT/inputs/agent-collection-assert"
install -d -m 0555 "$RUN_ROOT/inputs/tasks"
for task in "$TASKS"/*.txt; do
	install -m 0444 "$task" "$RUN_ROOT/inputs/tasks/$(basename -- "$task")"
done
readonly FROZEN_CODEX_VENDOR="$RUN_ROOT/inputs/codex"
install -d -m 0755 \
	"$FROZEN_CODEX_VENDOR/bin" \
	"$FROZEN_CODEX_VENDOR/codex-resources/zsh/bin" \
	"$FROZEN_CODEX_VENDOR/codex-path"
for relative in "${CODEX_VENDOR_FILES[@]}"; do
	mode=0555
	[[ "$relative" != codex-package.json ]] || mode=0444
	install -m "$mode" "$CODEX_VENDOR/$relative" \
		"$FROZEN_CODEX_VENDOR/$relative"
done
find "$FROZEN_CODEX_VENDOR" -type d -exec chmod 0555 {} +
[[ "$(find "$FROZEN_CODEX_VENDOR" -type f | wc -l)" -eq 6 ]]
for index in "${!CODEX_VENDOR_FILES[@]}"; do
	relative="${CODEX_VENDOR_FILES[$index]}"
	expected_digest="${EXPECTED_CODEX_VENDOR_SHA256[$index]}"
	[[ "$(sha256sum -- "$FROZEN_CODEX_VENDOR/$relative" | awk '{print $1}')" == \
		"$expected_digest" ]] || {
		echo "frozen Codex vendor digest mismatch: $relative" >&2
		exit 1
	}
done
{
	echo "codex_version=$CODEX_VERSION"
	echo "codex_sha256=$CODEX_SHA256"
	echo 'codex_vendor=inputs/codex'
	(
		cd "$FROZEN_CODEX_VENDOR"
		find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
	)
} > "$RUN_ROOT/codex-vendor-identity.txt"

guest_manifest_entry()
{
	local source="$1"
	local destination="$2"

	printf '%s  %s\n' "$(sha256sum -- "$source" | awk '{print $1}')" \
		"$destination"
}
readonly GUEST_PAYLOAD_MANIFEST="$RUN_ROOT/inputs/guest-payload.SHA256SUMS"
{
	guest_manifest_entry "$RUN_ROOT/inputs/bpf-state-observer" \
		/opt/bpf-state-observer/bpf-state-observer
	guest_manifest_entry "$RUN_ROOT/inputs/recorder.bpf.o" \
		/opt/bpf-state-observer/recorder.bpf.o
	guest_manifest_entry "$RUN_ROOT/inputs/map-lifecycle" \
		/opt/bpf-state-observer/map-lifecycle
	for name in models.json collection-scope.json codex-task-launcher \
		guest-run-suite.sh agent-collection-assert; do
		guest_manifest_entry "$RUN_ROOT/inputs/$name" \
			"/opt/codex-collection/$name"
	done
	for task in "$RUN_ROOT/inputs/tasks/"*.txt; do
		guest_manifest_entry "$task" \
			"/opt/codex-collection/tasks/$(basename -- "$task")"
	done
	for relative in "${CODEX_VENDOR_FILES[@]}"; do
		guest_manifest_entry "$FROZEN_CODEX_VENDOR/$relative" \
			"/opt/codex-collection/codex/$relative"
	done
} > "$GUEST_PAYLOAD_MANIFEST"
chmod 0444 "$GUEST_PAYLOAD_MANIFEST"
(
	cd "$RUN_ROOT/inputs"
	find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | \
		xargs -0 sha256sum > SHA256SUMS
)

readonly OVERLAY="$RUN_ROOT/collection-root-overlay.qcow2"
readonly CONSOLE="$RUN_ROOT/console.log"
readonly QEMU_STDERR="$RUN_ROOT/qemu.stderr"
"$QEMU_IMG_EXECUTABLE" create -q -f qcow2 -F raw \
	-b "$ROOTFS_IMAGE" "$OVERLAY"

SSH_OPTIONS=(
	-p "$SSH_PORT"
	-i "$SSH_KEY"
	-o BatchMode=yes
	-o IdentitiesOnly=yes
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=5
	-o ServerAliveInterval=15
	-o ServerAliveCountMax=4
)
SCP_OPTIONS=(
	-P "$SSH_PORT"
	-i "$SSH_KEY"
	-o BatchMode=yes
	-o IdentitiesOnly=yes
	-o StrictHostKeyChecking=no
	-o UserKnownHostsFile=/dev/null
	-o LogLevel=ERROR
	-o ConnectTimeout=5
)
QEMU_ARGS=(
	-m 4096
	-smp 4
	-display none
	-monitor none
	-serial "file:$CONSOLE"
	-no-reboot
	-enable-kvm
	-cpu host,migratable=off
	-device virtio-rng-pci
	-device e1000,netdev=net0
	-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22"
	-drive "file=$OVERLAY,format=qcow2,index=0,media=disk,snapshot=off"
	-kernel "$KERNEL_IMAGE"
	-append 'root=/dev/sda rw console=ttyS0,115200 earlyprintk=serial net.ifnames=0'
)
{
	printf 'qemu=%q\n' "$QEMU_EXECUTABLE"
	printf 'argv='
	printf '%q ' "${QEMU_ARGS[@]}"
	printf '\n'
} > "$RUN_ROOT/qemu.argv"

QEMU_PID=""
QEMU_START_TIME=""
process_state_and_start_time()
{
	local pid="$1"
	local stat_line
	local stat_fields
	local -a fields

	[[ "$pid" =~ ^[1-9][0-9]*$ && -r "/proc/$pid/stat" ]] || return 1
	IFS= read -r stat_line < "/proc/$pid/stat" || return 1
	[[ "$stat_line" == *") "* ]] || return 1
	stat_fields="${stat_line##*) }"
	read -r -a fields <<< "$stat_fields"
	[[ "${#fields[@]}" -ge 20 && "${#fields[0]}" -eq 1 &&
		"${fields[19]}" =~ ^[0-9]+$ ]] || return 1
	printf '%s %s\n' "${fields[0]}" "${fields[19]}"
}

qemu_is_owned()
{
	local identity

	[[ -n "$QEMU_START_TIME" ]] || return 1
	identity="$(process_state_and_start_time "$QEMU_PID")" || return 1
	[[ "${identity#* }" == "$QEMU_START_TIME" ]]
}

qemu_is_running()
{
	local identity
	local state
	local start_time

	[[ -n "$QEMU_START_TIME" ]] || return 1
	identity="$(process_state_and_start_time "$QEMU_PID")" || return 1
	state="${identity%% *}"
	start_time="${identity#* }"
	[[ "$start_time" == "$QEMU_START_TIME" &&
		"$state" != Z && "$state" != X && "$state" != x ]]
}

stop_owned_qemu()
{
	local attempt

	if qemu_is_owned; then
		if qemu_is_running; then
			kill -TERM "$QEMU_PID" 2>/dev/null || true
			for ((attempt = 0; attempt < 100; attempt++)); do
				qemu_is_running || break
				sleep 0.1
			done
			if qemu_is_running; then
				kill -KILL "$QEMU_PID" 2>/dev/null || true
			fi
		fi
		wait "$QEMU_PID" 2>/dev/null || true
	fi
	QEMU_PID=""
	QEMU_START_TIME=""
}

cleanup()
{
	local status=$?

	trap - EXIT HUP INT TERM
	set +e
	stop_owned_qemu
	COLLECTION_PROVIDER_SECRET=""
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

echo "B3 starting networked collection VM"
env -u DEEPSEEK_API_KEY TMPDIR="$RUN_ROOT/qemu-tmp" \
	"$QEMU_EXECUTABLE" "${QEMU_ARGS[@]}" \
	> /dev/null 2> "$QEMU_STDERR" &
QEMU_PID=$!
if ! qemu_identity="$(process_state_and_start_time "$QEMU_PID")"; then
	echo "could not bind the QEMU child process identity" >&2
	wait "$QEMU_PID" 2>/dev/null || true
	QEMU_PID=""
	exit 1
fi
QEMU_START_TIME="${qemu_identity#* }"

guest_ready=0
for _attempt in $(seq 1 120); do
	if timeout --foreground 6s env -u DEEPSEEK_API_KEY \
		ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
		'test "$(id -u)" -eq 0 && uname -r' \
		> "$RUN_ROOT/guest-kernel-release.txt" 2>/dev/null; then
		guest_ready=1
		break
	fi
	qemu_is_running || break
	sleep 1
done
if [[ "$guest_ready" -ne 1 ]]; then
	echo "collection Guest SSH did not become ready" >&2
	tail -100 "$CONSOLE" >&2 || true
	exit 1
fi
qemu_runtime_executable="$(readlink -f "/proc/$QEMU_PID/exe" 2>/dev/null || true)"
printf 'expected=%q\nactual=%q\n' "$QEMU_EXECUTABLE" \
	"$qemu_runtime_executable" > "$RUN_ROOT/qemu-runtime-identity.txt"
if ! qemu_is_running || [[ "$qemu_runtime_executable" != "$QEMU_EXECUTABLE" ]]; then
	echo "bound child is not the expected QEMU executable" >&2
	exit 1
fi

echo "B4 provisioning immutable collection payload"
env -u DEEPSEEK_API_KEY ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
	'test ! -e /opt/codex-collection && test ! -e /opt/bpf-state-observer &&
	 install -d -o root -g root -m 0755 /opt/codex-collection/codex \
	 /opt/codex-collection/tasks /opt/bpf-state-observer'
env -u DEEPSEEK_API_KEY scp "${SCP_OPTIONS[@]}" \
	"$RUN_ROOT/inputs/bpf-state-observer" \
	"$RUN_ROOT/inputs/recorder.bpf.o" \
	"$RUN_ROOT/inputs/map-lifecycle" \
	root@127.0.0.1:/opt/bpf-state-observer/
env -u DEEPSEEK_API_KEY scp "${SCP_OPTIONS[@]}" \
	"$RUN_ROOT/inputs/models.json" \
	"$RUN_ROOT/inputs/collection-scope.json" \
	"$RUN_ROOT/inputs/codex-task-launcher" \
	"$RUN_ROOT/inputs/guest-run-suite.sh" \
	"$RUN_ROOT/inputs/agent-collection-assert" \
	"$RUN_ROOT/inputs/guest-payload.SHA256SUMS" \
	root@127.0.0.1:/opt/codex-collection/
env -u DEEPSEEK_API_KEY scp "${SCP_OPTIONS[@]}" \
	"$RUN_ROOT/inputs/tasks/"*.txt \
	root@127.0.0.1:/opt/codex-collection/tasks/
tar -C "$FROZEN_CODEX_VENDOR" -cf - . | \
	env -u DEEPSEEK_API_KEY ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
	'tar -C /opt/codex-collection/codex -xf -'

env -u DEEPSEEK_API_KEY ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
	'bash -s' > "$RUN_ROOT/provision.log" 2> "$RUN_ROOT/provision.stderr" <<'PROVISION'
set -euo pipefail
for command in awk basename bash cmp cut date diff env find getcap getent grep \
	id install mount mountpoint readlink rm setcap sha256sum sort stat tail tar \
	timeout umount uname wc xargs; do
	command -v "$command" >/dev/null || {
		echo "missing Guest dependency: $command" >&2
		exit 1
	}
done
test -r /etc/ssl/certs/ca-certificates.crt
test "$(getent passwd 65534 | cut -d: -f3)" = 65534
test "$(getent group 65534 | cut -d: -f3)" = 65534
chown -R root:root /opt/codex-collection /opt/bpf-state-observer
expected_payload_files="$(wc -l < /opt/codex-collection/guest-payload.SHA256SUMS)"
actual_payload_files="$(find /opt/codex-collection /opt/bpf-state-observer \
	-type f ! -name guest-payload.SHA256SUMS | wc -l)"
test "$actual_payload_files" -eq "$expected_payload_files"
sha256sum --check --strict /opt/codex-collection/guest-payload.SHA256SUMS
find /opt/codex-collection /opt/bpf-state-observer -type d -exec chmod 0555 {} +
find /opt/codex-collection /opt/bpf-state-observer -type f -exec chmod 0444 {} +
chmod 0555 \
	/opt/codex-collection/codex/bin/codex \
	/opt/codex-collection/codex/bin/codex-code-mode-host \
	/opt/codex-collection/codex/codex-resources/bwrap \
	/opt/codex-collection/codex/codex-resources/zsh/bin/zsh \
	/opt/codex-collection/codex/codex-path/rg \
	/opt/codex-collection/codex-task-launcher \
	/opt/codex-collection/guest-run-suite.sh \
	/opt/codex-collection/agent-collection-assert \
	/opt/bpf-state-observer/bpf-state-observer \
	/opt/bpf-state-observer/map-lifecycle
setcap cap_bpf=ep /opt/bpf-state-observer/map-lifecycle
test "$(getcap -n /opt/bpf-state-observer/map-lifecycle)" = \
	'/opt/bpf-state-observer/map-lifecycle cap_bpf=ep'
capability_inventory="$(find / -xdev -type f -exec getcap -n -- {} + | LC_ALL=C sort)"
echo 'file_capability_inventory_begin'
printf '%s\n' "$capability_inventory"
echo 'file_capability_inventory_end'
retained_capability_inventory="$(printf '%s\n' "$capability_inventory" | \
	grep -E '([[:space:],])cap_(sys_admin|perfmon|bpf)([=,+-]|$)' || true)"
test "$retained_capability_inventory" = \
	'/opt/bpf-state-observer/map-lifecycle cap_bpf=ep'
/opt/codex-collection/codex/bin/codex --version
/opt/codex-collection/codex-task-launcher --self-test
/opt/codex-collection/agent-collection-assert --self-test
echo 'payload_sha256_begin'
find /opt/codex-collection /opt/bpf-state-observer -type f -print0 |
	sort -z | xargs -0 sha256sum
echo 'payload_sha256_end'
PROVISION

echo "B5 running Guest $GUEST_MODE workflow"
set +e
if [[ "$GUEST_MODE" == run ]]; then
	printf '%s\n' "$COLLECTION_PROVIDER_SECRET" | timeout --foreground 3000s \
		env -u DEEPSEEK_API_KEY ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
		"/opt/codex-collection/guest-run-suite.sh run '$BATCH_ID' '$MODEL'" \
		> "$RUN_ROOT/guest-suite.stdout" \
		2> "$RUN_ROOT/guest-suite.stderr"
	pipeline_status=("${PIPESTATUS[@]}")
	guest_status="${pipeline_status[1]}"
	if [[ "${pipeline_status[0]}" -ne 0 && "$guest_status" -eq 0 ]]; then
		guest_status="${pipeline_status[0]}"
	fi
else
	timeout --foreground 600s env -u DEEPSEEK_API_KEY \
		ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 \
		"/opt/codex-collection/guest-run-suite.sh deploy-only '$BATCH_ID' '$MODEL'" \
		> "$RUN_ROOT/guest-suite.stdout" \
		2> "$RUN_ROOT/guest-suite.stderr"
	guest_status=$?
fi
set -e
COLLECTION_PROVIDER_SECRET=""

echo "B6 extracting Guest results"
set +e
env -u DEEPSEEK_API_KEY scp -r "${SCP_OPTIONS[@]}" \
	"root@127.0.0.1:/var/lib/bpf-observer/agent-collection/$BATCH_ID" \
	"$RUN_ROOT/guest-results"
extract_status=$?
set -e
if [[ "$extract_status" -ne 0 ]]; then
	echo "failed to extract Guest result directory" >&2
	guest_status=1
fi

timeout --foreground 20s env -u DEEPSEEK_API_KEY \
	ssh "${SSH_OPTIONS[@]}" root@127.0.0.1 'sync; systemctl poweroff' \
	> "$RUN_ROOT/poweroff.log" 2>&1 || true
for _attempt in $(seq 1 300); do
	qemu_is_running || break
	sleep 0.1
done
if qemu_is_running; then
	echo "Guest did not power off cleanly; terminating owned QEMU" >&2
	stop_owned_qemu
	guest_status=1
elif ! qemu_is_owned && [[ -e "/proc/$QEMU_PID/stat" ]]; then
	echo "lost the bound QEMU child identity; refusing an unbounded wait" >&2
	guest_status=1
	QEMU_PID=""
	QEMU_START_TIME=""
else
	set +e
	wait "$QEMU_PID" 2>/dev/null
	qemu_exit=$?
	set -e
	QEMU_PID=""
	QEMU_START_TIME=""
	[[ "$qemu_exit" -eq 0 ]] || guest_status=1
fi

revalidate_host_input()
{
	local label="$1"
	local path="$2"
	local expected_size="$3"
	local expected_sha256="$4"
	local actual_size
	local actual_sha256

	if [[ ! -f "$path" || -L "$path" ]]; then
		echo "$label status=FAIL reason=missing_or_unsafe"
		return 1
	fi
	actual_size="$(stat -c %s -- "$path")" || return 1
	actual_sha256="$(sha256sum -- "$path" | awk '{print $1}')" || return 1
	echo "$label expected_size=$expected_size actual_size=$actual_size"
	echo "$label expected_sha256=$expected_sha256 actual_sha256=$actual_sha256"
	if [[ "$actual_size" != "$expected_size" ||
	      "$actual_sha256" != "$expected_sha256" ]]; then
		echo "$label status=FAIL reason=identity_changed"
		return 1
	fi
	echo "$label status=PASS"
}

overlay_status=0
if ! "$QEMU_IMG_EXECUTABLE" check -f qcow2 "$OVERLAY" \
	> "$RUN_ROOT/overlay-check.log" 2>&1; then
	echo "qemu-img check rejected the collection overlay" >&2
	overlay_status=1
fi
if "$QEMU_IMG_EXECUTABLE" info --backing-chain --output=json "$OVERLAY" \
	> "$RUN_ROOT/overlay-info.json" 2> "$RUN_ROOT/overlay-info.stderr"; then
	if ! python3 - "$RUN_ROOT/overlay-info.json" "$OVERLAY" \
		"$ROOTFS_IMAGE" > "$RUN_ROOT/overlay-validation.txt" \
		2> "$RUN_ROOT/overlay-validation.stderr" <<'PY'
import json
import sys

info_path, expected_overlay, expected_rootfs = sys.argv[1:]
with open(info_path, encoding="utf-8") as stream:
    chain = json.load(stream)
if not isinstance(chain, list) or len(chain) != 2:
    raise SystemExit("overlay chain must contain exactly the overlay and its raw backing image")
overlay, rootfs = chain
if not isinstance(overlay, dict) or not isinstance(rootfs, dict):
    raise SystemExit("overlay chain entries must be JSON objects")
expected_overlay_fields = {
    "filename": expected_overlay,
    "format": "qcow2",
    "backing-filename": expected_rootfs,
    "full-backing-filename": expected_rootfs,
    "backing-filename-format": "raw",
}
for field, expected in expected_overlay_fields.items():
    if overlay.get(field) != expected:
        raise SystemExit(f"unexpected overlay {field}: {overlay.get(field)!r}")
if rootfs.get("filename") != expected_rootfs or rootfs.get("format") != "raw":
    raise SystemExit("overlay does not terminate at the expected raw rootfs")
if "backing-filename" in rootfs or "full-backing-filename" in rootfs:
    raise SystemExit("raw rootfs unexpectedly has another backing image")
overlay_size = overlay.get("virtual-size")
rootfs_size = rootfs.get("virtual-size")
if type(overlay_size) is not int or overlay_size <= 0 or overlay_size != rootfs_size:
    raise SystemExit("overlay and raw rootfs virtual sizes do not match")
print("overlay_chain_status=PASS")
print(f"overlay={expected_overlay}")
print(f"raw_backing={expected_rootfs}")
print(f"virtual_size={overlay_size}")
PY
	then
		echo "collection overlay does not have the exact expected backing chain" >&2
		overlay_status=1
	fi
else
	echo "qemu-img could not inspect the collection overlay" \
		> "$RUN_ROOT/overlay-validation.stderr"
	: > "$RUN_ROOT/overlay-validation.txt"
	overlay_status=1
fi

echo "B7 independently verifying copied Observer runs"
host_verify_status=0
readonly FROZEN_OBSERVER="$RUN_ROOT/inputs/bpf-state-observer"
readonly FROZEN_RECORDER_SHA256="$(sha256sum \
	"$RUN_ROOT/inputs/recorder.bpf.o" | awk '{print $1}')"
expected_run_directories=("$RUN_ROOT/guest-results/calibration/observer-run")
expected_run_ids=(agent-calibration)
expected_run_epochs=(7000)
if [[ "$GUEST_MODE" == run ]]; then
	for task_index in "${!EXPECTED_TASK_NAMES[@]}"; do
		task="${EXPECTED_TASK_NAMES[$task_index]}"
		expected_run_directories+=("$RUN_ROOT/guest-results/tasks/$task/observer-run")
		expected_run_ids+=("agent-$task")
		expected_run_epochs+=("$((7101 + task_index))")
	done
fi

actual_run_directories=()
if [[ -d "$RUN_ROOT/guest-results" && ! -L "$RUN_ROOT/guest-results" ]]; then
	mapfile -d '' -t actual_run_directories < <(
		find "$RUN_ROOT/guest-results" -name observer-run -print0 |
			LC_ALL=C sort -z
	)
fi
if [[ "${#actual_run_directories[@]}" -ne "${#expected_run_directories[@]}" ]]; then
	echo "Host found ${#actual_run_directories[@]} Observer runs; expected ${#expected_run_directories[@]}" >&2
	host_verify_status=1
else
	for run_index in "${!expected_run_directories[@]}"; do
		if [[ "${actual_run_directories[$run_index]}" != \
		      "${expected_run_directories[$run_index]}" ]]; then
			echo "unexpected Observer run: ${actual_run_directories[$run_index]}" >&2
			host_verify_status=1
		fi
	done
fi

for run_index in "${!expected_run_directories[@]}"; do
	run_directory="${expected_run_directories[$run_index]}"
	verify_output="$(dirname -- "$run_directory")/host-verify.json"
	verify_stderr="$(dirname -- "$run_directory")/host-verify.stderr"
	if [[ ! -d "$run_directory" || -L "$run_directory" ]]; then
		echo "missing expected Observer run: $run_directory" >&2
		host_verify_status=1
		continue
	fi
	set +e
	"$FROZEN_OBSERVER" verify-run \
		--run-dir "$run_directory" \
		--expected-recorder-sha256 "$FROZEN_RECORDER_SHA256" \
		> "$verify_output" 2> "$verify_stderr"
	verify_status=$?
	set -e
	if [[ "$verify_status" -ne 0 ]] || ! python3 - \
		"$verify_output" "${expected_run_ids[$run_index]}" \
		"${expected_run_epochs[$run_index]}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    result = json.load(stream)
expected_epoch = int(sys.argv[3], 10)
valid = (
    result.get("run_id") == sys.argv[2]
    and result.get("run_epoch") == expected_epoch
    and result.get("evidence_complete") is True
    and result.get("state_verdict") == "INCONCLUSIVE"
)
raise SystemExit(0 if valid else 1)
PY
	then
		echo "Host verification contract failed: $run_directory" >&2
		host_verify_status=1
	fi
done

echo "B8 revalidating immutable Host inputs"
host_input_status=0
{
	revalidate_host_input kernel "$KERNEL_IMAGE" "$KERNEL_IMAGE_SIZE" \
		"$KERNEL_IMAGE_SHA256" || host_input_status=1
	revalidate_host_input rootfs "$ROOTFS_IMAGE" "$ROOTFS_IMAGE_SIZE" \
		"$ROOTFS_IMAGE_SHA256" || host_input_status=1
	revalidate_host_input ssh_key "$SSH_KEY" "$SSH_KEY_SIZE" \
		"$SSH_KEY_SHA256" || host_input_status=1
	revalidate_host_input qemu "$QEMU_EXECUTABLE" "$QEMU_EXECUTABLE_SIZE" \
		"$QEMU_EXECUTABLE_SHA256" || host_input_status=1
	revalidate_host_input qemu_img "$QEMU_IMG_EXECUTABLE" \
		"$QEMU_IMG_EXECUTABLE_SIZE" "$QEMU_IMG_EXECUTABLE_SHA256" || \
		host_input_status=1
	echo "overall_status=$host_input_status"
} > "$RUN_ROOT/host-input-revalidation.txt"

echo "B9 sealing the retained overlay and batch"
overlay_size=UNAVAILABLE
overlay_sha256=UNAVAILABLE
overlay_identity_status=FAIL
if [[ -f "$OVERLAY" && ! -L "$OVERLAY" ]] &&
	overlay_size="$(stat -c %s -- "$OVERLAY")" &&
	overlay_sha256="$(sha256sum -- "$OVERLAY" | awk '{print $1}')" &&
	[[ "$overlay_size" =~ ^[1-9][0-9]*$ &&
	   "$overlay_sha256" =~ ^[a-f0-9]{64}$ ]]; then
	overlay_identity_status=PASS
else
	echo "could not bind the final collection overlay identity" >&2
	overlay_status=1
fi
{
	printf 'path=%q\n' "$OVERLAY"
	echo "size=$overlay_size"
	echo "sha256=$overlay_sha256"
	echo "status=$overlay_identity_status"
} > "$RUN_ROOT/overlay-identity.txt"

{
	echo "batch_id=$BATCH_ID"
	echo "guest_mode=$GUEST_MODE"
	echo "guest_status=$guest_status"
	echo "host_verify_status=$host_verify_status"
	echo "overlay_status=$overlay_status"
	echo "host_input_status=$host_input_status"
	echo "strict_exclusive_vm_v1=false"
	echo "result_path=$RUN_ROOT"
} > "$RUN_ROOT/host-summary.txt"
find "$RUN_ROOT" -type f ! -name BATCH_SHA256SUMS ! -path "$OVERLAY" \
	-print0 | LC_ALL=C sort -z | xargs -0 sha256sum \
	> "$RUN_ROOT/BATCH_SHA256SUMS"

if [[ "$guest_status" -ne 0 || "$host_verify_status" -ne 0 ||
	  "$overlay_status" -ne 0 ||
	  "$host_input_status" -ne 0 ]]; then
	echo "agent collection failed; retained diagnostics at $RUN_ROOT" >&2
	exit 1
fi
echo "agent collection $GUEST_MODE PASS: $RUN_ROOT"
