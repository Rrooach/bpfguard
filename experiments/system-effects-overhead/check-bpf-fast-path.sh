#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

set -euo pipefail

readonly HERE="$(cd "$(dirname "$0")" && pwd)"
readonly OBJECT="${1:-$HERE/../../.output/system_effects.bpf.o}"
readonly LIFECYCLE_OBJECT="${2:-$HERE/../../.output/process_lifecycle.bpf.o}"
readonly OBJDUMP="${LLVM_OBJDUMP:-llvm-objdump-14}"
readonly NM="${LLVM_NM:-llvm-nm-14}"

[[ -f "$OBJECT" && ! -L "$OBJECT" ]] || {
	echo "compiled system-effects BPF object is missing: $OBJECT" >&2
	exit 2
}
[[ -f "$LIFECYCLE_OBJECT" && ! -L "$LIFECYCLE_OBJECT" ]] || {
	echo "compiled process-lifecycle BPF object is missing: $LIFECYCLE_OBJECT" >&2
	exit 2
}
command -v "$OBJDUMP" >/dev/null || {
	echo "BPF disassembler is unavailable: $OBJDUMP" >&2
	exit 2
}
command -v "$NM" >/dev/null || {
	echo "BPF symbol inspector is unavailable: $NM" >&2
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

section_instruction_count()
{
	local object=$1
	local section=$2
	"$OBJDUMP" -d --no-show-raw-insn --section="$section" "$object" \
		| awk '/^[[:space:]]+[0-9]+:/ { count++ } END { print count + 0 }'
}

require_instruction_cap()
{
	local object=$1
	local section=$2
	local cap=$3
	local count
	count=$(section_instruction_count "$object" "$section")
	if (( count == 0 || count > cap )); then
		echo "$section instruction count $count exceeds the attested cap $cap" >&2
		exit 1
	fi
}

require_symbol_instruction_cap()
{
	local object=$1
	local symbol=$2
	local cap=$3
	local size_hex size_bytes count
	size_hex=$($NM --print-size --size-sort "$object" \
		| awk -v wanted="$symbol" '$4 == wanted { print $2 }')
	[[ $size_hex =~ ^[0-9a-fA-F]+$ ]] || {
		echo "$symbol has no unique compiled size" >&2
		exit 1
	}
	size_bytes=$((16#$size_hex))
	(( size_bytes % 8 == 0 )) || {
		echo "$symbol has a non-instruction-aligned BPF size" >&2
		exit 1
	}
	count=$((size_bytes / 8))
	if (( count == 0 || count > cap )); then
		echo "$symbol instruction count $count exceeds the attested cap $cap" >&2
		exit 1
	fi
}

# These LSM programs are global hooks. Keep their entire thin wrappers bounded;
# expensive object reads remain behind the shared pending-call/run gates.
for section in \
	lsm/path_mkdir lsm/path_symlink lsm/path_mknod \
	lsm/path_unlink lsm/path_rmdir lsm/path_rename lsm/path_link \
	lsm/path_chmod lsm/path_chown; do
	require_instruction_cap "$OBJECT" "$section" 8
done
for section in lsm/inode_setxattr lsm/inode_removexattr; do
	require_instruction_cap "$OBJECT" "$section" 6
done
for section in lsm/socket_connect lsm/socket_bind; do
	require_instruction_cap "$OBJECT" "$section" 13
done
require_instruction_cap "$OBJECT" lsm/mmap_file 160
require_instruction_cap "$OBJECT" lsm/file_mprotect 160

# file_post_open can call bpf_d_path only after the pending-call gate. Keep
# the complete global hook bounded and pin its first two helpers to PID
# identity and pending-map lookup. Using the post-open hook avoids duplicate
# overlayfs backing-file callbacks without adding a version-private f_mode
# test. file_permission delegates the same gate to its out-of-line resolver.
# The expanded exit budget catches accidental growth in the largest selected
# syscall path.
require_instruction_cap "$OBJECT" lsm.s/file_post_open 260
file_post_open=$($OBJDUMP -d --no-show-raw-insn --section=lsm.s/file_post_open "$OBJECT")
file_post_open_first_two=$(awk '/^[[:space:]]+[0-9]+:.*call / { print $NF; seen++ } seen == 2 { exit }' \
	<<< "$file_post_open")
[[ "$file_post_open_first_two" == $'14\n1' ]] || {
	echo "file_post_open no longer gates on PID and pending-map before object/path reads" >&2
	exit 1
}
require_symbol_instruction_cap "$OBJECT" record_file_permission 230
permission_resolver=$($OBJDUMP -d --no-show-raw-insn \
	--disassemble-symbols=record_file_permission "$OBJECT")
permission_resolver_first_two=$(awk '/^[[:space:]]+[0-9]+:.*call / { print $NF; seen++ } seen == 2 { exit }' \
	<<< "$permission_resolver")
[[ "$permission_resolver_first_two" == $'14\n1' ]] || {
	echo "record_file_permission no longer gates on PID and pending-map before file reads" >&2
	exit 1
}
require_symbol_instruction_cap "$OBJECT" trace_effect_expanded_exit 1300

# The out-of-line resolvers must reject a task by PID/pending-map membership
# before looking at a VFS or socket object. Helper 14 is get_current_pid_tgid;
# helper 1 is map_lookup_elem.
for symbol in record_path_object record_inode_xattr_object record_socket_object; do
	resolver=$($OBJDUMP -d --no-show-raw-insn \
		--disassemble-symbols="$symbol" "$OBJECT")
	first_two_calls=$(awk '/^[[:space:]]+[0-9]+:.*call / { print $NF; seen++ } seen == 2 { exit }' \
		<<< "$resolver")
	[[ "$first_two_calls" == $'14\n1' ]] || {
		echo "$symbol no longer gates on PID and pending-map before object reads" >&2
		exit 1
	}
done

# accept/accept4 resolution occurs at fexit/do_accept because the accepted
# struct file does not exist at syscall entry. The wrapper must remain thin,
# and the resolver must still reject by selected pending syscall before reading
# the returned file/socket.
require_instruction_cap "$OBJECT" fexit/do_accept 8
accept_resolver=$($OBJDUMP -d --no-show-raw-insn \
	--disassemble-symbols=record_accepted_socket "$OBJECT")
accept_first_two_calls=$(awk '/^[[:space:]]+[0-9]+:.*call / { print $NF; seen++ } seen == 2 { exit }' \
	<<< "$accept_resolver")
[[ "$accept_first_two_calls" == $'14\n1' ]] || {
	echo "record_accepted_socket no longer gates on PID and pending-map before object reads" >&2
	exit 1
}

# These hooks execute for host-wide TCP state activity. Cookie extraction plus
# a single owner-map miss must precede run lookup, socket field reads, ring
# allocation, and publication.
for entry in 'tp_btf/inet_sock_set_state:50' 'tp_btf/tcp_destroy_sock:90'; do
	section=${entry%%:*}
	cap=${entry##*:}
	require_instruction_cap "$OBJECT" "$section" "$cap"
	state_hook=$($OBJDUMP -d --no-show-raw-insn --section="$section" "$OBJECT")
	first_two_calls=$(awk '/^[[:space:]]+[0-9]+:.*call / { print $NF; seen++ } seen == 2 { exit }' \
		<<< "$state_hook")
	[[ "$first_two_calls" == $'46\n1' ]] || {
		echo "$section no longer gates on socket cookie and owner map before state reads" >&2
		exit 1
	}
done

# Lifecycle hooks run for every host fork/exec/exit. Cap the compiled programs
# and require their first call to enter the shared exact/ancestor run matcher.
# The matcher itself must perform get_current_cgroup_id (80) and a run-map
# lookup (1) before ancestry traversal, task/BPRM reads, or ring allocation.
lifecycle_gate=$($OBJDUMP -d --no-show-raw-insn \
	--disassemble-symbols=lifecycle_current_run "$LIFECYCLE_OBJECT")
lifecycle_gate_first_two=$(awk '/^[[:space:]]+[0-9]+:.*call / { print $NF; seen++ } seen == 2 { exit }' \
	<<< "$lifecycle_gate")
[[ "$lifecycle_gate_first_two" == $'80\n1' ]] || {
	echo "lifecycle_current_run no longer performs current-cgroup/run-map gating first" >&2
	exit 1
}
for entry in \
	'tp_btf/sched_process_fork:190' \
	'tp_btf/sched_process_exec:240' \
	'tp_btf/sched_process_exit:220'; do
	section=${entry%%:*}
	cap=${entry##*:}
	require_instruction_cap "$LIFECYCLE_OBJECT" "$section" "$cap"
	lifecycle=$($OBJDUMP -d --no-show-raw-insn \
		--section="$section" "$LIFECYCLE_OBJECT")
	first_call=$(awk '/^[[:space:]]+[0-9]+:.*call / { print $NF; exit }' <<< "$lifecycle")
	[[ "$first_call" == -1 ]] || {
		echo "$section no longer enters the shared cgroup/run gate before event work" >&2
		exit 1
	}
	done

# Guard the semantic tail as well as the instruction budget. A past source
# regression placed an unconditional return after reserve, which would leave
# a loadable hook that never published EXIT. Helper 131 is ringbuf_reserve and
# helper 132 is ringbuf_submit; the EXIT kind is the fixed ABI value 3.
lifecycle_exit=$($OBJDUMP -d --no-show-raw-insn \
	--section=tp_btf/sched_process_exit "$LIFECYCLE_OBJECT")
grep -Eq 'call 131$' <<< "$lifecycle_exit" || {
	echo "sched_process_exit no longer reserves a lifecycle event" >&2
	exit 1
}
grep -Eq 'r[0-9]+ = 3$' <<< "$lifecycle_exit" || {
	echo "sched_process_exit no longer materializes the fixed EXIT kind" >&2
	exit 1
}
grep -Eq 'call 132$' <<< "$lifecycle_exit" || {
	echo "sched_process_exit no longer submits a lifecycle event" >&2
	exit 1
}

echo "system-effects BPF fast-path check PASS object_sha256=$(sha256sum "$OBJECT" | awk '{print $1}') lifecycle_sha256=$(sha256sum "$LIFECYCLE_OBJECT" | awk '{print $1}')"
