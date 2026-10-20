/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ALLOX_FILE_PROFILE_H
#define ALLOX_FILE_PROFILE_H

#define FP_DOMAINS 16
#define FP_FILES 8192
#define FP_THREADS 8192

enum fp_operation { FP_READ = 0, FP_READV = 1, FP_DIRECTORY = 2,
	FP_MMAP = 3, FP_OPERATIONS = 4 };
enum fp_counter { FP_C_CONTEXT_FULL, FP_C_PENDING_FULL, FP_C_OBJECT_READ,
	FP_C_AGGREGATE_FULL, FP_C_NESTED, FP_C_UNPAIRED, FP_C_EXIT_PENDING,
	FP_C_UNRESOLVED_MMAP, FP_C_UNSUPPORTED_ABI, FP_COUNTERS };

struct fp_domain { __u64 cgroup_id; __u32 level; __u32 reserved; };
struct fp_config { __u32 count; __u32 enabled; };
/* Boot-scoped object identity and metadata sampled at operation entry.
 * mtime/ctime/size are a VERSION_HINT, not a content hash or atomic version.
 */
struct fp_key {
	__u64 domain_id;
	__u64 caller_cgroup_id;
	__u64 process_start_boottime_ns;
	__u64 thread_start_boottime_ns;
	__u64 mount_id;
	__u64 inode;
	__s64 size;
	__s64 mtime_sec;
	__s64 ctime_sec;
	__u32 device;
	__u32 generation;
	__u32 mtime_nsec;
	__u32 ctime_nsec;
	__u32 tgid;
	__u32 tid;
	__u32 operation;
	__u32 reserved;
};
struct fp_value {
	__u64 calls;
	__u64 success_calls;
	__u64 errors;
	__u64 returned_bytes;
	__u64 duration_ns;
	__u64 max_duration_ns;
	__u64 first_start_ns;
	__u64 last_end_ns;
};
#endif
