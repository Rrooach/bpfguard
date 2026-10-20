#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

script_dir=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
project_dir=$(cd -P -- "$script_dir/.." && pwd -P)
kernel_root=$(cd -P -- "$project_dir/../../.." && pwd -P)
base_config=$project_dir/.output/vm-kernel-allox-plugin-btf/.config
output_dir=$project_dir/.output/vm-kernel-profile-psi
pahole_binary=${PAHOLE:-$project_dir/.output/toolchain/install-static/bin/pahole}
build_jobs=${VM_KERNEL_JOBS:-16}

usage()
{
	cat <<'EOF'
Usage: bash vm/build-profile-kernel.sh [options]
  --base-config FILE   Existing measured BTF/cgroup experiment configuration
  --output-dir DIR    New or empty output (default: .output/vm-kernel-profile-psi)
  --pahole FILE       pahole >= 1.22 (default: project's static toolchain)
  --jobs N            Build parallelism (default: 16)

Builds a separate PSI-enabled kernel without changing the base configuration,
existing kernels, running guests, or Host settings. The output must be empty.
EOF
}
while [[ $# -gt 0 ]]; do
	case $1 in
	--base-config) base_config=${2:?}; shift 2 ;;
	--output-dir) output_dir=${2:?}; shift 2 ;;
	--pahole) pahole_binary=${2:?}; shift 2 ;;
	--jobs) build_jobs=${2:?}; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) usage >&2; exit 2 ;;
	esac
done
[[ $build_jobs =~ ^[1-9][0-9]*$ ]] || exit 2
base_config=$(realpath -e -- "$base_config")
pahole_binary=$(realpath -e -- "$pahole_binary")
output_dir=$(realpath -m -- "$output_dir")
[[ -f $base_config && ! -L $base_config && -x $pahole_binary ]] || exit 2
# Restrict all writes to a dedicated project output child, never its root.
[[ $output_dir == "$project_dir/.output/"* &&
   $output_dir != "$project_dir/.output/tmp" &&
   $output_dir != "$project_dir/.output/tmp/"* ]] || {
	echo 'profile kernel output must be a dedicated project .output child' >&2; exit 2;
}
if [[ -e $output_dir ]]; then
	[[ -d $output_dir && ! -L $output_dir ]] || exit 2
	[[ -z $(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
		echo 'refusing nonempty output; select a fresh directory' >&2; exit 2;
	}
fi
pahole_version=$("$kernel_root/scripts/pahole-version.sh" "$pahole_binary")
[[ $pahole_version =~ ^[0-9]+$ ]] && ((10#$pahole_version >= 122)) || {
	echo 'BTF performance kernel requires pahole >= 1.22' >&2; exit 2;
}
mkdir -p "$output_dir" "$project_dir/.output/tmp"
export TMPDIR=$project_dir/.output/tmp
install -m 0644 "$base_config" "$output_dir/profile-base.config"
install -m 0644 "$script_dir/profile-x86.config" "$output_dir/profile-overlay.config"
sha256sum "$base_config" "$script_dir/profile-x86.config" "$pahole_binary" \
	>"$output_dir/profile-inputs.sha256"
git -C "$kernel_root" rev-parse HEAD >"$output_dir/profile-kernel-git-head.txt"
${CC:-gcc} --version >"$output_dir/profile-compiler-version.txt"
"$kernel_root/scripts/kconfig/merge_config.sh" -m -O "$output_dir" \
	"$output_dir/profile-base.config" "$output_dir/profile-overlay.config"
make -C "$kernel_root" O="$output_dir" PAHOLE="$pahole_binary" olddefconfig
for setting in CONFIG_PSI=y CONFIG_SCHEDSTATS=y CONFIG_CGROUPS=y \
	CONFIG_CGROUP_SCHED=y CONFIG_MEMCG=y CONFIG_BLK_CGROUP=y \
	CONFIG_DEBUG_INFO_BTF=y CONFIG_BPF_SYSCALL=y; do
	grep -qx "$setting" "$output_dir/.config" || {
		echo "profile kernel omitted $setting" >&2; exit 1;
	}
done
grep -qx '# CONFIG_PSI_DEFAULT_DISABLED is not set' "$output_dir/.config"
make -C "$kernel_root" O="$output_dir" PAHOLE="$pahole_binary" \
	-j "$build_jobs" bzImage
readelf -S "$output_dir/vmlinux" | grep -q '\.BTF'
sha256sum "$output_dir/.config" "$output_dir/arch/x86/boot/bzImage" \
	"$output_dir/vmlinux" >"$output_dir/profile-built.sha256"
printf 'PROFILE_PSI_KERNEL_BUILD_PASS output=%s\n' "$output_dir"
