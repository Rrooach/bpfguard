/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ALLOX_FILE_ACCESS_H
#define ALLOX_FILE_ACCESS_H

#define FA_MAGIC 0x46414343
#define FA_VERSION 1
#define FA_EVENT_BYTES 192
#define FA_DOMAINS 16
#define FA_THREADS 8192
#define FA_RING_BYTES (64 * 1024 * 1024)

enum fa_kind { FA_READ = 1, FA_READV, FA_DIRECTORY, FA_OPEN, FA_FILEMAP_FAULT,
	FA_MM_FAULT };
enum fa_flags {
	FA_OBJECT_VALID = 1, FA_REQUESTED_VALID = 2, FA_OFFSET_VALID = 4,
	FA_SYSCALL_VALID = 8, FA_FAULT_FLAGS_VALID = 32,
	FA_FAULT_RETURN_VALID = 64, FA_REGULAR_FILE = 128, FA_DIRECTORY_FILE = 256,
	FA_NO_FILE_VMA = 512
};
enum fa_health_index {
	FA_CONTEXT_FULL, FA_PENDING_FULL, FA_OBJECT_READ_FAILED, FA_NESTED_HOOKS,
	FA_UNPAIRED_EXIT, FA_SYSCALL_EXIT_PENDING, FA_UNSUPPORTED_ABI,
	FA_RING_DROPS, FA_FAULT_PENDING_FULL, FA_FAULT_UNPAIRED,
	FA_FAULT_EXIT_PENDING, FA_SYSCALL_MISMATCH, FA_MULTIPLE_VFS,
	FA_OFFSET_READ_FAILED, FA_MM_PENDING_FULL, FA_MM_UNPAIRED,
	FA_MM_EXIT_PENDING, FA_HEALTH_COUNT
};
struct fa_config { __u32 count, enabled, emit_events, reserved; };
struct fa_domain { __u64 cgroup_id; __u32 level, reserved; };
/* Little-endian native x86-64 fixed records. cpu_seq starts at one and
 * advances BEFORE ring reservation, including failed reservations.
 * Object metadata is an identity/version hint, NOT an immutable version.
 */
struct fa_event {
	__u32 magic; __u16 version, kind; __u32 size, flags;
	__u64 cpu_seq, domain_id, caller_cgroup_id;
	__u64 process_start_boottime_ns, thread_start_boottime_ns;
	__u64 start_ns, end_ns, syscall_start_ns, syscall_end_ns;
	__u64 mount_id, inode;
	__s64 file_size, offset;
	__u64 requested;
	__s64 result, syscall_result;
	__u64 fault_address, pgoff;
	__u32 device, generation, tgid, tid, cpu, syscall_nr;
	__u32 fault_flags, vm_fault_result;
};
struct fa_pending { struct fa_event event; __u32 depth, completed; };
struct fa_totals { __u64 attempted, emitted, ring_drops; };
#endif
