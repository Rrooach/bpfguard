/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_STATE_OBSERVER_PROCESS_LIFECYCLE_H
#define BPF_STATE_OBSERVER_PROCESS_LIFECYCLE_H

#include <linux/types.h>

#define EFFECT_LIFECYCLE_SCHEMA_VERSION 2
#define EFFECT_LIFECYCLE_MAX_RUNS 1024
#define EFFECT_LIFECYCLE_MAX_ANCESTOR_ROOTS 8
#define EFFECT_LIFECYCLE_RING_BYTES (1U << 20)
#define EFFECT_LIFECYCLE_EXEC_PATH_BYTES 128

enum effect_lifecycle_kind {
	EFFECT_LIFECYCLE_FORK = 1,
	EFFECT_LIFECYCLE_EXEC = 2,
	EFFECT_LIFECYCLE_EXIT = 3,
};

enum effect_lifecycle_flags {
	EFFECT_LIFECYCLE_F_EXEC_PATH_READ_FAILED = 1U << 0,
	EFFECT_LIFECYCLE_F_EXEC_PATH_TRUNCATED = 1U << 1,
	EFFECT_LIFECYCLE_F_TASK_READ_FAILED = 1U << 2,
};

struct effect_lifecycle_run_state {
	__u64 epoch;
	__u64 next_event_seq;
	__u64 event_attempted;
	__u64 event_published;
	__u64 event_dropped;
	__u64 task_read_failed;
	__u64 exec_path_read_failed;
	__u64 exec_path_truncated;
};

struct effect_lifecycle_ancestor_config {
	__u32 root_count;
	__u32 reserved;
};

/* Keep this fixed layout synchronized with lifecycle.rs. start_boottime_ns is
 * the boot-scoped task identity component used to disambiguate PID reuse.
 * For FORK, pid/tgid/start identify the child and parent_* identify its
 * creating task. For EXEC/EXIT, pid/tgid/start identify current; parent_* is a
 * point-in-time relationship snapshot. exec_path exists only on EXEC.
 */
struct effect_lifecycle_event {
	__u32 schema_version;
	__u16 kind;
	__u16 exec_path_len;
	__u32 flags;
	__s32 exit_code;
	__u64 run_epoch;
	__u64 event_seq;
	__u64 ktime_ns;
	__u64 cgroup_id;
	__u64 start_boottime_ns;
	__u64 parent_start_boottime_ns;
	__u32 pid;
	__u32 tgid;
	__u32 parent_pid;
	__u32 parent_tgid;
	__u32 old_pid;
	__u8 group_dead;
	__u8 reserved[3];
	__u8 comm[16];
	__u8 parent_comm[16];
	__u8 exec_path[EFFECT_LIFECYCLE_EXEC_PATH_BYTES];
};

#endif /* BPF_STATE_OBSERVER_PROCESS_LIFECYCLE_H */
