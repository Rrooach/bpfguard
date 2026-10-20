/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef OBSERVER_NATIVE_EXEC_ARGS_H
#define OBSERVER_NATIVE_EXEC_ARGS_H
#include <linux/types.h>
#define NEA_MAGIC 0x4e454131U
#define NEA_HEALTH_MAGIC 0x4e454148U
#define NEA_VERSION 1
#define NEA_MAX_ARGS 8
#define NEA_ARG_BYTES 4096
#define NEA_FILENAME_BYTES 256
#define NEA_HEADER_BYTES 432
#define NEA_ENTRY_BYTES (NEA_HEADER_BYTES + NEA_MAX_ARGS * NEA_ARG_BYTES)
enum nea_kind { NEA_ENTRY=1, NEA_SUCCESS, NEA_FAILED, NEA_ABORTED, NEA_UNCONFIRMED };
enum nea_flags { NEA_FILENAME_TRUNCATED=1, NEA_FILENAME_FAILED=2,
    NEA_ARGC_TRUNCATED=4, NEA_ARGV_POINTER_FAILED=8, NEA_ARGV_STRING_FAILED=16,
    NEA_ENTRY_MISSING=32, NEA_ARGV_STRING_TRUNCATED=64 };
enum nea_arg_flags { NEA_ARG_UNREAD=0, NEA_ARG_COMPLETE=1, NEA_ARG_TRUNCATED=2, NEA_ARG_FAILED=3 };
enum nea_health_index { NEA_ATTEMPTED_ENTRIES, NEA_ENTRIES, NEA_SUCCESSES,
    NEA_FAILURES, NEA_ABORTS, NEA_UNCONFIRMED_RESULTS, NEA_RING_DROPS,
    NEA_READ_FAILURES, NEA_IDENTITY_FAILURES, NEA_PENDING_FULL,
    NEA_PENDING_COLLISIONS, NEA_UNMATCHED_SUCCESS, NEA_DELETE_ERRORS,
    NEA_SEQUENCE, NEA_HEALTH_COUNT };
/* Native little-endian x86-64 v1. Markers use only the first HEADER_BYTES;
 * ENTRY adds 8 fixed zero-padded argument slots. No existing Observer ABI. */
struct nea_event {
    __u32 magic; __u16 version, kind; __u32 size, flags;
    __u8 boot_id[16];
    __u64 timestamp_ns, cpu_seq, root_cgroup_id, entry_ns;
    __u64 thread_birth_ns, process_birth_ns, cgroup_id;
    __s64 result;
    __u32 tid, tgid, cpu, old_tid;
    __s32 syscall_nr; __u32 argc, filename_bytes, reserved;
    __u16 argv_bytes[NEA_MAX_ARGS], argv_flags[NEA_MAX_ARGS];
    char comm[16], filename[NEA_FILENAME_BYTES];
    char argv[NEA_MAX_ARGS][NEA_ARG_BYTES];
};
struct nea_config { __u64 cgroup_id; __u32 enabled, reserved; __u8 boot_id[16]; };
struct nea_pending { __u64 entry_ns, thread_birth_ns, process_birth_ns, cgroup_id;
    __u32 tid, tgid; __s32 nr; __u32 reserved; };
struct nea_health_receipt {
    __u32 magic; __u16 version, size;
    __u8 boot_id[16];
    __u64 cgroup_id, begin_ns, end_ns, records, bytes, max_bytes;
    __u64 parse_errors, write_errors, cap_discarded, pending_at_end;
    __u64 counters[NEA_HEALTH_COUNT];
};
#endif
