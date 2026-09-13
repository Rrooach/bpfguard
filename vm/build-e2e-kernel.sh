#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -P -- "${SCRIPT_DIR}/.." && pwd -P)"
KERNEL_ROOT="$(cd -P -- "${PROJECT_DIR}/../../.." && pwd -P)"
BUILD_TMPDIR="${PROJECT_DIR}/.output/tmp"
mkdir -p "$BUILD_TMPDIR"
export TMPDIR="$BUILD_TMPDIR"
OUTPUT_DIR=""
VM_KERNEL_JOBS="${VM_KERNEL_JOBS:-$(nproc)}"
VM_KERNEL_PROFILE="baseline"
PAHOLE_BIN="${PAHOLE:-pahole}"
OUTPUT_MARKER_NAME=.bpf-state-observer-vm-kernel-output
OUTPUT_MARKER_MAGIC=bpf-state-observer-vm-kernel-output-v1

usage()
{
	cat <<EOF
Usage: $0 [--profile baseline|effects-object] [--output-dir DIR] [--jobs N]

Build an x86-64 acceptance-test bzImage from this Linux source tree. The
default baseline starts with x86_64_defconfig, merges the Observer requirements
and disposable-VM overlay, disables BTF/BPF_PRELOAD, and builds out of tree.

The effects-object profile adds a final, explicit BTF+BPF-LSM overlay for the
sleepable file_open object-resolution E2E. It requires pahole >= 1.22; select a
non-system binary with PAHOLE=/absolute/path/to/pahole.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--profile)
		VM_KERNEL_PROFILE="${2:-}"
		shift 2
		;;
	--output-dir)
		OUTPUT_DIR="${2:-}"
		shift 2
		;;
	--jobs)
		VM_KERNEL_JOBS="${2:-}"
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

case "$VM_KERNEL_PROFILE" in
baseline|effects-object) ;;
*)
	echo "--profile must be baseline or effects-object" >&2
	exit 2
	;;
esac
[[ "$VM_KERNEL_JOBS" =~ ^[1-9][0-9]*$ ]] || {
	echo "--jobs must be a positive integer" >&2
	exit 2
}
if [[ -z "$OUTPUT_DIR" ]]; then
	if [[ "$VM_KERNEL_PROFILE" == effects-object ]]; then
		OUTPUT_DIR="${PROJECT_DIR}/.output/vm-kernel-effects"
	else
		OUTPUT_DIR="${PROJECT_DIR}/.output/vm-kernel"
	fi
fi
OUTPUT_DIR="$(realpath -m -- "$OUTPUT_DIR")"

path_is_within()
{
	local path="$1"
	local parent="$2"

	[[ "$path" == "$parent" || "$path" == "$parent/"* ]]
}

# O= writes configuration and build products into its target. Keep it away
# from the source tree and its ancestors, except for this project's dedicated
# ignored output subtree used by the Makefile default.
if [[ "$OUTPUT_DIR" == / ]] || path_is_within "$KERNEL_ROOT" "$OUTPUT_DIR"; then
	echo "refusing dangerous kernel output directory: $OUTPUT_DIR" >&2
	exit 2
fi
if path_is_within "$OUTPUT_DIR" "$KERNEL_ROOT" && \
	! path_is_within "$OUTPUT_DIR" "${PROJECT_DIR}/.output"; then
	echo "refusing kernel output directory inside the source tree: $OUTPUT_DIR" >&2
	exit 2
fi
if [[ "$OUTPUT_DIR" == "${PROJECT_DIR}/.output" ]] || \
	path_is_within "$OUTPUT_DIR" "$BUILD_TMPDIR"; then
	echo "refusing reserved project output directory: $OUTPUT_DIR" >&2
	exit 2
fi
if [[ -e "$OUTPUT_DIR" && ! -d "$OUTPUT_DIR" ]]; then
	echo "kernel output path is not a directory: $OUTPUT_DIR" >&2
	exit 2
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_MARKER="${OUTPUT_DIR}/${OUTPUT_MARKER_NAME}"
EXPECTED_MARKER="${OUTPUT_MARKER_MAGIC}"$'\n'"kernel_root=${KERNEL_ROOT}"
if [[ -e "$OUTPUT_MARKER" || -L "$OUTPUT_MARKER" ]]; then
	if [[ ! -f "$OUTPUT_MARKER" || -L "$OUTPUT_MARKER" ]] || \
		[[ "$(cat -- "$OUTPUT_MARKER")" != "$EXPECTED_MARKER" ]]; then
		echo "refusing output directory with an invalid management marker: $OUTPUT_DIR" >&2
		exit 2
	fi
elif [[ -n "$(find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
	echo "refusing non-empty unowned kernel output directory: $OUTPUT_DIR" >&2
	exit 2
else
	( set -o noclobber
	  printf '%s\n' "$EXPECTED_MARKER" > "$OUTPUT_MARKER"
	) 2>/dev/null || {
		echo "could not claim kernel output directory safely: $OUTPUT_DIR" >&2
		exit 2
	}
fi

if [[ "$VM_KERNEL_PROFILE" == effects-object ]]; then
	PAHOLE_BIN="$(command -v -- "$PAHOLE_BIN")" || {
		echo "effects-object profile requires an executable pahole" >&2
		exit 1
	}
	PAHOLE_VERSION="$("${KERNEL_ROOT}/scripts/pahole-version.sh" "$PAHOLE_BIN")"
	[[ "$PAHOLE_VERSION" =~ ^[0-9]+$ ]] && (( 10#$PAHOLE_VERSION >= 122 )) || {
		echo "effects-object profile requires pahole >= 1.22" >&2
		exit 1
	}
fi

TMPDIR="$BUILD_TMPDIR" make -C "$KERNEL_ROOT" O="$OUTPUT_DIR" \
	PAHOLE="$PAHOLE_BIN" x86_64_defconfig
cp "$OUTPUT_DIR/.config" "$OUTPUT_DIR/e2e-defconfig.base"
CONFIG_FRAGMENTS=(
	"$OUTPUT_DIR/e2e-defconfig.base"
	"${SCRIPT_DIR}/bpf-state-observer.config"
	"${SCRIPT_DIR}/e2e-x86.config"
)
if [[ "$VM_KERNEL_PROFILE" == effects-object ]]; then
	CONFIG_FRAGMENTS+=("${SCRIPT_DIR}/effects-object-x86.config")
fi
"${KERNEL_ROOT}/scripts/kconfig/merge_config.sh" -m -O "$OUTPUT_DIR" \
	"${CONFIG_FRAGMENTS[@]}"
TMPDIR="$BUILD_TMPDIR" make -C "$KERNEL_ROOT" O="$OUTPUT_DIR" \
	PAHOLE="$PAHOLE_BIN" olddefconfig

for setting in \
	CONFIG_BPF_SYSCALL=y \
	CONFIG_BPF_EVENTS=y \
	CONFIG_CGROUPS=y \
	CONFIG_CGROUP_BPF=y \
	CONFIG_CGROUP_FREEZER=y \
	CONFIG_PERF_EVENTS=y \
	CONFIG_TRACEPOINTS=y \
	CONFIG_EVENT_TRACING=y \
	CONFIG_EXT4_FS=y \
	CONFIG_ATA_PIIX=y \
	CONFIG_E1000=y \
	CONFIG_CONFIGFS_FS=y; do
	grep -qx "$setting" "$OUTPUT_DIR/.config" || {
		echo "effective kernel config omitted required setting: $setting" >&2
		exit 1
	}
done
grep -qx '# CONFIG_BPF_PRELOAD is not set' "$OUTPUT_DIR/.config"
if [[ "$VM_KERNEL_PROFILE" == effects-object ]]; then
	for setting in \
		CONFIG_BPF_LSM=y \
		CONFIG_SECURITY=y \
		CONFIG_SECURITYFS=y \
		CONFIG_OVERLAY_FS=y \
		CONFIG_DEBUG_INFO=y \
		CONFIG_DEBUG_INFO_BTF=y; do
		grep -qx "$setting" "$OUTPUT_DIR/.config" || {
			echo "effects-object config omitted required setting: $setting" >&2
			exit 1
		}
	done
	LSM_LIST="$(sed -n 's/^CONFIG_LSM="\(.*\)"$/\1/p' "$OUTPUT_DIR/.config")"
	[[ ",$LSM_LIST," == *,bpf,* ]] || {
		echo "effects-object config does not activate bpf in CONFIG_LSM" >&2
		exit 1
	}
elif grep -qx 'CONFIG_DEBUG_INFO_BTF=y' "$OUTPUT_DIR/.config"; then
	echo "baseline acceptance kernel unexpectedly retained CONFIG_DEBUG_INFO_BTF=y" >&2
	exit 1
fi

TMPDIR="$BUILD_TMPDIR" make -C "$KERNEL_ROOT" \
	O="$OUTPUT_DIR" PAHOLE="$PAHOLE_BIN" -j "$VM_KERNEL_JOBS" bzImage

if [[ "$VM_KERNEL_PROFILE" == effects-object ]]; then
	readelf -S "$OUTPUT_DIR/vmlinux" | grep -q '\.BTF' || {
		echo "effects-object vmlinux has no .BTF section" >&2
		exit 1
	}
	sha256sum "$OUTPUT_DIR/arch/x86/boot/bzImage" \
		"$OUTPUT_DIR/vmlinux" "$OUTPUT_DIR/.config"
else
	sha256sum "$OUTPUT_DIR/arch/x86/boot/bzImage" "$OUTPUT_DIR/.config"
fi
