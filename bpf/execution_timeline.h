/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ALLOX_EXECUTION_TIMELINE_H
#define ALLOX_EXECUTION_TIMELINE_H
#include <linux/types.h>
#define ET_MAGIC 0x45544c31U
#define ET_VERSION 1
#define ET_STACK_DEPTH 16
#define ET_PATH_BYTES 256
#define ET_MAX_THREADS 16384
enum et_kind { ET_SWITCH_OUT=1, ET_SWITCH_IN, ET_WAKEUP, ET_FORK, ET_EXEC,
    ET_EXIT, ET_SYSCALL_ENTER, ET_SYSCALL_EXIT, ET_FILE_READ, ET_FILE_OBJECT,
    ET_WAKING, ET_SECCOMP_SKIP };
enum et_state { ET_STATE_UNKNOWN=0, ET_RUNNABLE, ET_SLEEP_D, ET_SLEEP_S, ET_STOPPED };
enum et_flags { ET_IDENTITY_FAILED=1, ET_PEER_FAILED=2, ET_OBJECT_VALID=4,
    ET_OBJECT_FAILED=8, ET_REQUESTED_VALID=16, ET_STACK_VALID=32,
    ET_STACK_FAILED=64, ET_PATH_VALID=128, ET_PATH_FAILED=256,
    ET_UNPAIRED=512, ET_COMPAT_UNSUPPORTED=1024, ET_BOUNDARY_RETURN=2048,
    ET_FORK_CHILD_RETURN=4096, ET_PEER_IDLE=8192,
    /* x86-64 rt_sigreturn restores orig_ax, so the exit tracepoint can report
     * nr=-1. result then contains a restored register, not an ordinary errno. */
    ET_SIGRETURN_RESTORED=16384, ET_CLEAR_CHILD_TID_VALID=32768,
    ET_CLEAR_CHILD_TID_FAILED=65536,
    /* FORK start_ns is a parent syscall reference, not a child interval. */
    ET_FORK_PARENT_CALL_VALID=131072, ET_WAKE_ATTEMPT_VALID=262144,
    ET_WAKEUP_NEW=524288, ET_WAKE_ATTEMPT_MISSING=1048576,
    ET_PATH_AT_LSM_PERMISSION=2097152,
    /* FORK syscall_nr was read from current parent's saved syscall frame.
     * No sys_enter, parent call ID, entry timestamp, or duration is implied. */
    ET_FORK_PARENT_REGS_VALID=4194304,
    /* Exit references a separately emitted, same-lifetime seccomp skip proof.
     * No sys_enter, syscall wall duration, filter action, or policy is implied. */
    ET_SECCOMP_SKIPPED_EXIT=8388608,
    /* bprm filename: kernel-copied execution name, NOT a canonical d_path. */
    ET_PATH_AT_EXEC_FILENAME=16777216 };
enum et_health { ET_ATTEMPTED, ET_EMITTED, ET_RING_DROPS, ET_ID_READ_ERRORS,
    ET_CONTEXT_FULL, ET_CONTEXT_COLLISION, ET_UNPAIRED_RESULTS, ET_OBJECT_ERRORS,
    ET_STACK_ERRORS, ET_PATH_ERRORS, ET_UNSUPPORTED_ABI, ET_NESTED_VFS,
    ET_CENSORED_EXEC, ET_CENSORED_EXIT, ET_CONTEXT_DELETE_ERRORS,
    ET_BOUNDARY_RETURNS, ET_FORK_CHILD_RETURNS, ET_SIGRETURN_RESTORED_EXITS,
    ET_CLEAR_CHILD_TID_READ_ERRORS,
    ET_WAKE_CONTEXT_FULL, ET_WAKE_CONTEXT_COLLISION, ET_WAKE_REFERENCE_MISSING,
    ET_WAKE_CONTEXT_DELETE_ERRORS, ET_WAKE_EXIT_UNRESOLVED,
    ET_KPROBE_REGISTER_READ_ERRORS,
    ET_FORK_REGS_READ_ERRORS,
    ET_SECCOMP_SKIPS, ET_SECCOMP_READ_ERRORS, ET_SECCOMP_CONTEXT_ERRORS,
    ET_HEALTH_COUNT };
struct et_identity {
    __u64 thread_birth_ns, process_birth_ns, cgroup_id;
    __u32 tid, tgid;
    char comm[16];
};
struct et_file {
    __u64 mount_id, inode;
    __s64 size;
    __u32 device, generation;
};
/* Fixed little-endian native x86-64 schema. All bytes (including padding) are
 * zero initialized; event.size is sizeof(et_event). No userspace buffers. */
struct et_event {
    __u32 magic; __u16 version, kind; __u32 size, flags;
    __u8 boot_id[16];
    __u64 timestamp_ns, cpu_seq, root_cgroup_id;
    struct et_identity task, peer;
    __u64 syscall_call_id, start_ns, end_ns, requested_bytes;
    __s64 result;
    __u64 args[6];
    struct et_file file;
    __u32 cpu, state, prev_state, preempt;
    __s32 syscall_nr, stack_bytes, path_bytes;
    __u32 old_tid;
    __u64 kernel_stack[ET_STACK_DEPTH];
    char path[ET_PATH_BYTES];
};
struct et_config { __u64 root_cgroup_id; __u32 root_level, enabled, kernel_stacks, reserved; __u8 boot_id[16]; };
struct et_pending {
    struct et_identity task;
    __u64 call_id, args[6], vfs_start_ns;
    struct et_file file;
    __u64 requested;
    __s32 nr;
    __u32 flags, depth, vector;
};
struct et_enrollment { __u64 thread_birth_ns; __u32 syscall_seen; __s32 fork_nr; };
struct et_wake_pending { struct et_identity task; __u64 attempt_ns; };
struct et_seccomp_pending { struct et_identity task; __u64 proof_ns; __s64 result; __s32 nr; __u32 reserved; };
#endif
