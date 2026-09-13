#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

readonly HERE="$(cd "$(dirname "$0")" && pwd)"
readonly OBJECT="${1:-$HERE/../../.output/system_effects.bpf.o}"
readonly OBJDUMP="${LLVM_OBJDUMP:-llvm-objdump-14}"

[[ -f "$OBJECT" && ! -L "$OBJECT" ]] || {
	echo "compiled system-effects BPF object is missing: $OBJECT" >&2
	exit 2
}
command -v "$OBJDUMP" >/dev/null || {
	echo "BPF disassembler is unavailable: $OBJDUMP" >&2
	exit 2
}

permission="$($OBJDUMP -d --no-show-raw-insn \
	--section=lsm/file_permission "$OBJECT")"
permission_count="$(awk '/^[[:space:]]+[0-9]+:/ { count++ } END { print count + 0 }' \
	<<< "$permission")"
[[ "$permission_count" == 12 ]] || {
	echo "file_permission wrapper changed from the attested 12-instruction shape" >&2
	exit 1
}
permission_off_path="$(awk '/^[[:space:]]+[0-7]:/ { print }' <<< "$permission")"
if grep -Fq 'r10' <<< "$permission_off_path"; then
	echo "file_permission off-path performs unexpected stack work" >&2
	exit 1
fi
grep -Eq '^[[:space:]]+3:.*&= 2$' <<< "$permission"
grep -Eq '^[[:space:]]+4:.*if .* == 0 goto' <<< "$permission"

enter="$($OBJDUMP -d --no-show-raw-insn \
	--section=tracepoint/raw_syscalls/sys_enter "$OBJECT")"
first_enter_call="$(awk '/^[[:space:]]+[0-9]+:.*call / { print; exit }' <<< "$enter")"
grep -Eq 'call 1$' <<< "$first_enter_call" || {
	echo "sys_enter no longer performs policy-Map lookup before other helpers" >&2
	exit 1
}
enter_before_lookup="$(awk '{ print } /^[[:space:]]+[0-9]+:.*call / { exit }' <<< "$enter")"
if grep -Fq '*(u64 *)(r10' <<< "$enter_before_lookup"; then
	echo "sys_enter performs eager wide stack initialization before policy lookup" >&2
	exit 1
fi

echo "system-effects BPF fast-path check PASS object_sha256=$(sha256sum "$OBJECT" | awk '{print $1}')"
