/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_STATE_OBSERVER_RECORDER_H
#define BPF_STATE_OBSERVER_RECORDER_H

#include <linux/types.h>

#define RECORDER_SCHEMA_VERSION 1
#define RECORDER_RING_BYTES (1U << 20)
#define RECORDER_MAX_RUNS 1024
#define RECORDER_MAX_PENDING 16384
#define RECORDER_BPF_COMMON_ATTRS (1U << 16)

enum recorder_event_kind {
	RECORDER_EVENT_SYSCALL_ATTEMPTED = 1,
	RECORDER_EVENT_COMMAND_COMPLETED = 2,
};

enum recorder_event_flags {
	RECORDER_F_COMMON_ATTRS = 1U << 0,
	RECORDER_F_PENDING_INSERT_FAILED = 1U << 1,
	RECORDER_F_PENDING_MISSING = 1U << 2,
	RECORDER_F_PENDING_POISONED = 1U << 3,
	RECORDER_F_PENDING_DELETE_FAILED = 1U << 4,
};

/* Keep this layout synchronized with crates/recorder/src/protocol.rs. */
struct recorder_event {
	__u32 schema_version;
	__u16 kind;
	__u16 flags;
	__u32 command;
	__u32 attr_size;
	__u64 run_epoch;
	__u64 event_seq;
	__u64 related_attempt_seq;
	__u64 ktime_ns;
	__u64 cgroup_id;
	__u64 pid_tgid;
	__s64 return_value;
};

struct recorder_config {
	/* Native plus supported compat ABI syscall numbers; -1 disables a slot. */
	__s64 bpf_syscall_nrs[3];
	/* During an authenticated exclusive window, every bpf() attempt outside
	 * a registered workload cgroup is evidence of another actor.  The exact
	 * Observer TGID is excluded because snapshot enumeration itself uses
	 * bpf(); no other TGID is trusted by this kernel-side gate.
	 */
	__u32 observer_tgid;
	__u32 exclusive_window;
	__u64 outside_cgroup_syscall_attempted;
};

/* Atomic counters are intentionally per run, not global or LRU-evictable. */
struct recorder_run_state {
	__u64 epoch;
	__u64 next_event_seq;
	__u64 syscall_attempted;
	__u64 syscall_completed;
	__u64 event_attempted;
	__u64 event_published;
	__u64 event_dropped;
	__u64 pending_insert_failed;
	__u64 pending_missing;
	__u64 pending_remaining;
};

struct recorder_pending {
	__u64 epoch;
	__u64 cgroup_id;
	__u64 attempt_seq;
	__u32 command;
	__u32 attr_size;
	__u16 flags;
	__u16 reserved16;
	__u32 reserved32;
};

#endif /* BPF_STATE_OBSERVER_RECORDER_H */
