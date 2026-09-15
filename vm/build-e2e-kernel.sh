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
expanded VFS/socket/lifecycle object-resolution E2E, plus built-in nftables,
virtual-link, representative traffic-control, and Docker/Harbor cgroup,
bridge, conntrack and NAT support. It requires pahole >= 1.22; select a
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
		CONFIG_SECURITY_PATH=y \
		CONFIG_OVERLAY_FS=y \
		CONFIG_MEMCG=y \
		CONFIG_CGROUP_PIDS=y \
		CONFIG_CPUSETS=y \
		CONFIG_CFS_BANDWIDTH=y \
		CONFIG_BLK_CGROUP=y \
		CONFIG_BLK_DEV_THROTTLING=y \
		CONFIG_BRIDGE=y \
		CONFIG_BRIDGE_NETFILTER=y \
		CONFIG_NETFILTER=y \
		CONFIG_NETFILTER_ADVANCED=y \
		CONFIG_NETFILTER_NETLINK=y \
		CONFIG_NF_CONNTRACK=y \
		CONFIG_NF_CT_NETLINK=y \
		CONFIG_NF_NAT=y \
		CONFIG_NF_TABLES=y \
		CONFIG_NF_TABLES_INET=y \
		CONFIG_NF_TABLES_NETDEV=y \
		CONFIG_NFT_CT=y \
		CONFIG_NFT_FIB=y \
		CONFIG_NFT_FIB_IPV4=y \
		CONFIG_NFT_FIB_IPV6=y \
		CONFIG_NFT_FIB_INET=y \
		CONFIG_NFT_NAT=y \
		CONFIG_NFT_MASQ=y \
		CONFIG_NFT_REDIR=y \
		CONFIG_NFT_COMPAT=y \
		CONFIG_NFT_REJECT=y \
		CONFIG_NFT_REJECT_INET=y \
		CONFIG_NFT_REJECT_IPV4=y \
		CONFIG_NFT_REJECT_IPV6=y \
		CONFIG_NETFILTER_XTABLES=y \
		CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y \
		CONFIG_NETFILTER_XT_MATCH_COMMENT=y \
		CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y \
		CONFIG_NETFILTER_XT_MATCH_MULTIPORT=y \
		CONFIG_NETFILTER_XT_MARK=y \
		CONFIG_NETFILTER_XT_TARGET_CHECKSUM=y \
		CONFIG_NETFILTER_XT_TARGET_MASQUERADE=y \
		CONFIG_NETFILTER_XT_TARGET_REDIRECT=y \
		CONFIG_IPV6_MULTIPLE_TABLES=y \
		CONFIG_DUMMY=y \
		CONFIG_VETH=y \
		CONFIG_TUN=y \
		CONFIG_NET_SCHED=y \
		CONFIG_NET_SCH_HTB=y \
		CONFIG_NET_SCH_TBF=y \
		CONFIG_NET_SCH_FQ=y \
		CONFIG_NET_SCH_FQ_CODEL=y \
		CONFIG_NET_CLS_ACT=y \
		CONFIG_NET_SCH_INGRESS=y \
		CONFIG_NET_CLS_U32=y \
		CONFIG_NET_CLS_BPF=y \
		CONFIG_NET_CLS_FLOWER=y \
		CONFIG_NET_CLS_MATCHALL=y \
		CONFIG_NET_ACT_GACT=y \
		CONFIG_NET_ACT_MIRRED=y \
		CONFIG_NET_ACT_BPF=y \
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

BUILD_TARGETS=(bzImage)
if [[ "$VM_KERNEL_PROFILE" == effects-object ]]; then
	# The expanded endpoint-state E2E builds one empty, test-only module
	# against this exact output.  Building modules here produces the matching
	# Module.symvers; modules_prepare alone deliberately cannot do that.
	BUILD_TARGETS+=(modules)
fi
TMPDIR="$BUILD_TMPDIR" make -C "$KERNEL_ROOT" \
	O="$OUTPUT_DIR" PAHOLE="$PAHOLE_BIN" -j "$VM_KERNEL_JOBS" \
	"${BUILD_TARGETS[@]}"

if [[ "$VM_KERNEL_PROFILE" == effects-object ]]; then
	readelf -S "$OUTPUT_DIR/vmlinux" | grep -q '\.BTF' || {
		echo "effects-object vmlinux has no .BTF section" >&2
		exit 1
	}
	[[ -s "$OUTPUT_DIR/Module.symvers" ]] || {
		echo "effects-object build did not produce Module.symvers" >&2
		exit 1
	}
	sha256sum "$OUTPUT_DIR/arch/x86/boot/bzImage" \
		"$OUTPUT_DIR/vmlinux" "$OUTPUT_DIR/.config" \
		"$OUTPUT_DIR/Module.symvers"
else
	sha256sum "$OUTPUT_DIR/arch/x86/boot/bzImage" "$OUTPUT_DIR/.config"
fi
