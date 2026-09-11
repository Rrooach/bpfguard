#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

SCRIPT_DIR="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -P -- "${SCRIPT_DIR}/.." && pwd -P)"
KERNEL_ROOT="$(cd -P -- "${PROJECT_DIR}/../../.." && pwd -P)"
OUTPUT_DIR="${PROJECT_DIR}/.output/vm-kernel"
VM_KERNEL_JOBS="${VM_KERNEL_JOBS:-$(nproc)}"
OUTPUT_MARKER_NAME=.bpf-state-observer-vm-kernel-output
OUTPUT_MARKER_MAGIC=bpf-state-observer-vm-kernel-output-v1

usage()
{
	cat <<EOF
Usage: $0 [--output-dir DIR] [--jobs N]

Build an x86-64 acceptance-test bzImage from this Linux source tree. The
result starts with x86_64_defconfig, merges the Observer requirements and the
disposable-VM overlay, disables BTF and BPF_PRELOAD, and builds out of tree.
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
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

[[ "$VM_KERNEL_JOBS" =~ ^[1-9][0-9]*$ ]] || {
	echo "--jobs must be a positive integer" >&2
	exit 2
}
[[ -n "$OUTPUT_DIR" ]] || {
	echo "--output-dir must not be empty" >&2
	exit 2
}
OUTPUT_DIR="$(realpath -m -- "$OUTPUT_DIR")"
BUILD_TMPDIR="${PROJECT_DIR}/.output/tmp"

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

mkdir -p "$BUILD_TMPDIR"

TMPDIR="$BUILD_TMPDIR" make -C "$KERNEL_ROOT" O="$OUTPUT_DIR" x86_64_defconfig
cp "$OUTPUT_DIR/.config" "$OUTPUT_DIR/e2e-defconfig.base"
"${KERNEL_ROOT}/scripts/kconfig/merge_config.sh" -m -O "$OUTPUT_DIR" \
	"$OUTPUT_DIR/e2e-defconfig.base" \
	"${SCRIPT_DIR}/bpf-state-observer.config" \
	"${SCRIPT_DIR}/e2e-x86.config"
TMPDIR="$BUILD_TMPDIR" make -C "$KERNEL_ROOT" O="$OUTPUT_DIR" olddefconfig

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
if grep -qx 'CONFIG_DEBUG_INFO_BTF=y' "$OUTPUT_DIR/.config"; then
	echo "acceptance kernel unexpectedly retained CONFIG_DEBUG_INFO_BTF=y" >&2
	exit 1
fi

TMPDIR="$BUILD_TMPDIR" make -C "$KERNEL_ROOT" \
	O="$OUTPUT_DIR" -j "$VM_KERNEL_JOBS" bzImage

sha256sum "$OUTPUT_DIR/arch/x86/boot/bzImage" "$OUTPUT_DIR/.config"
