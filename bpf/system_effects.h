/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_STATE_OBSERVER_SYSTEM_EFFECTS_H
#define BPF_STATE_OBSERVER_SYSTEM_EFFECTS_H

#include <linux/types.h>

#define EFFECT_SCHEMA_VERSION 1
#define EFFECT_POLICY_ENTRIES 1024
#define EFFECT_MAX_RUNS 1024
#define EFFECT_MAX_PENDING 16384
#define EFFECT_RING_BYTES (1U << 22)
#define EFFECT_CAPTURE_BYTES 96
#define EFFECT_FILE_PATH_BYTES 128

enum effect_event_kind {
	EFFECT_EVENT_OPERATION_ATTEMPT = 1,
	EFFECT_EVENT_OPERATION_RESULT = 2,
};

enum effect_capture_kind {
	EFFECT_CAPTURE_NONE = 0,
	EFFECT_CAPTURE_USER_STRING = 1,
	EFFECT_CAPTURE_SOCKADDR = 2,
};

enum effect_event_flags {
	EFFECT_F_PENDING_INSERT_FAILED = 1U << 0,
	EFFECT_F_PENDING_MISSING = 1U << 1,
	EFFECT_F_PENDING_POISONED = 1U << 2,
	EFFECT_F_PENDING_DELETE_FAILED = 1U << 3,
	EFFECT_F_PAYLOAD1_READ_FAILED = 1U << 4,
	EFFECT_F_PAYLOAD1_TRUNCATED = 1U << 5,
	EFFECT_F_PAYLOAD2_READ_FAILED = 1U << 6,
	EFFECT_F_PAYLOAD2_TRUNCATED = 1U << 7,
	EFFECT_F_POLICY_INVALID = 1U << 8,
	EFFECT_F_USER_MEMORY_SNAPSHOT = 1U << 9,
	EFFECT_F_SYSCALL_MISMATCH = 1U << 10,
	EFFECT_F_PAYLOAD1_INVALID_LENGTH = 1U << 11,
	EFFECT_F_PAYLOAD2_INVALID_LENGTH = 1U << 12,
	EFFECT_F_OBJECT_JOIN_MISSING = 1U << 13,
	EFFECT_F_OBJECT_JOIN_AMBIGUOUS = 1U << 14,
	EFFECT_F_OBJECT_READ_FAILED = 1U << 15,
	EFFECT_F_OBJECT_DELETE_FAILED = 1U << 16,
	EFFECT_F_OBJECT_PATH_UNAVAILABLE = 1U << 17,
};

enum effect_file_path_quality {
	EFFECT_FILE_PATH_NOT_REQUESTED = 0,
	EFFECT_FILE_PATH_RESOLVED_AT_HOOK = 1,
	EFFECT_FILE_PATH_TRUNCATED_AT_HOOK = 2,
	EFFECT_FILE_PATH_UNAVAILABLE = 3,
};

enum effect_object_resolver {
	EFFECT_OBJECT_RESOLVER_NONE = 0,
	EFFECT_OBJECT_RESOLVER_FILE_OPEN = 1,
	EFFECT_OBJECT_RESOLVER_FILE_PERMISSION_WRITE = 2,
};

enum effect_object_resolver_mask {
	EFFECT_OBJECT_RESOLVE_FILE_OPEN = 1U << 0,
	EFFECT_OBJECT_RESOLVE_FILE_PERMISSION_WRITE = 1U << 1,
};

struct effect_capture_policy {
	__u8 kind;
	__u8 arg_index;
	__u8 length_arg_index;
	__u8 reserved;
};

/* One ARRAY lookup rejects unselected syscalls before cgroup/pending work.
 * filter_mask == 0 disables the filter; otherwise at least one masked bit in
 * args[filter_arg_index] is required.
 */
struct effect_syscall_policy {
	__u32 enabled;
	__u16 domain;
	__u16 operation;
	struct effect_capture_policy capture[2];
	__u64 filter_mask;
	__u8 filter_arg_index;
	__u8 object_resolver;
	__u8 reserved[6];
};

struct effect_object_config {
	__u32 resolver_mask;
	__u32 capture_path;
};

/* Keep this layout synchronized with
 * crates/system-effects-recorder/src/protocol.rs.
 */
struct effect_event_header {
	__u32 schema_version;
	__u16 kind;
	__u16 domain;
	__u32 operation;
	__u32 flags;
	__s32 syscall_nr;
	__u32 reserved32;
	__u64 run_epoch;
	__u64 event_seq;
	__u64 related_attempt_seq;
	__u64 ktime_ns;
	__u64 cgroup_id;
	__u64 pid_tgid;
	__s64 return_value;
	__u64 args[6];
	__u8 comm[16];
	__u16 payload1_len;
	__u16 payload2_len;
	__u8 payload1_kind;
	__u8 payload2_kind;
	__u8 payload1_arg_index;
	__u8 payload2_arg_index;
};

struct effect_event {
	struct effect_event_header header;
	__u8 payload1[EFFECT_CAPTURE_BYTES];
	__u8 payload2[EFFECT_CAPTURE_BYTES];
};

/* Kernel-resolved FILE_OBJECT data is emitted only by the opt-in BPF
 * LSM/alternate exit pair. file_open may add a point-in-time path snapshot;
 * the non-sleepable file_permission hook deliberately does not. The
 * boot-scoped mount/device/inode fields are the object identity.
 */
struct effect_file_identity {
	__u64 mount_id_unique;
	__u64 inode;
	__u64 filesystem_magic;
	__u32 device_major;
	__u32 device_minor;
	__u32 inode_generation;
	__u16 path_len;
	__u8 generation_valid;
	__u8 path_quality;
	__u32 reserved32;
	__u8 path[EFFECT_FILE_PATH_BYTES];
	__u32 reserved_tail;
};

struct effect_file_event {
	struct effect_event_header header;
	struct effect_file_identity object;
};

struct effect_file_pending {
	__u64 epoch;
	__u64 cgroup_id;
	__u64 attempt_seq;
	struct effect_file_identity object;
};

struct effect_run_state {
	__u64 epoch;
	__u64 next_event_seq;
	__u64 operation_attempted;
	__u64 operation_completed;
	__u64 event_attempted;
	__u64 event_published;
	__u64 event_dropped;
	__u64 pending_insert_failed;
	__u64 pending_missing;
	__u64 pending_remaining;
	__u64 object_resolution_attempted;
	__u64 object_resolution_resolved;
	__u64 object_resolution_unresolved;
	__u64 object_resolution_failed_syscalls;
	__u64 object_join_missing;
	__u64 object_join_ambiguous;
	__u64 object_read_failed;
	__u64 object_delete_failed;
	__u64 object_path_unavailable;
	__u64 object_pending_remaining;
};

/* Payload bytes are published only with the entry event. Keeping them out of
 * this map bounds non-evictable in-flight state to 96 bytes per thread.
 */
struct effect_pending_call {
	__u64 epoch;
	__u64 cgroup_id;
	__u64 attempt_seq;
	__u64 args[6];
	__u32 flags;
	__s32 syscall_nr;
	__u16 domain;
	__u16 operation;
	__u32 object_resolver;
	__u64 reserved64;
};

#endif /* BPF_STATE_OBSERVER_SYSTEM_EFFECTS_H */
