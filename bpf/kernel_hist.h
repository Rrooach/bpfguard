/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef ALLOX_KERNEL_HIST_H
#define ALLOX_KERNEL_HIST_H

/*
 * Per-subsystem latency histograms for the load sampler. This layout is a
 * fixed ABI shared with crates/load-sampler/src/khist.rs; keep both in sync.
 *
 * Every metric is a log2 histogram of nanoseconds: bucket b counts events
 * lasting [2^b, 2^(b+1)) ns, with bucket 0 also holding 0-1 ns and the last
 * bucket holding everything >= 2^31 ns. Counts and sums are cumulative.
 */

#define KH_BUCKETS 32
#define KH_MAX_DOMAINS 16
#define KH_ABI_VERSION 2

/* Optional extension: the original ABI2 histogram/counter layout is unchanged. */
#define KH_BLOCK_DIAG_VERSION 1
#define KH_BLOCK_DIAG_SAMPLES 8
#define KH_BLOCK_DIAG_COUNTERS 10

enum kh_block_diag_counter {
	KH_BD_READ_FAILED,
	KH_BD_FLUSH_ISSUED,
	KH_BD_FLUSH_COMPLETED,
	KH_BD_FLUSH_ERROR,
	KH_BD_QUEUE_UNKNOWN,
	KH_BD_UNTRACKED_COMPLETE,
	KH_BD_UNTRACKED_REQUEUE,
	KH_BD_ZERO_NONFLUSH,
	KH_BD_ZERO_FLUSH_BAD_BYTES,
	KH_BD_SAMPLE_ATTEMPTS,
};

enum kh_block_diag_reason {
	KH_BD_NO_INSERT = 1,
	KH_BD_ZERO_FLUSH_COMPLETE,
	KH_BD_ZERO_OTHER,
	KH_BD_UNTRACKED_END,
	KH_BD_UNTRACKED_REQUEUE_EVENT,
	KH_BD_OBJECT_READ_ERROR,
	KH_BD_INVALID_FLUSH_BYTES,
	KH_BD_FLUSH_COMPLETE_ERROR,
};

struct kh_block_sample {
	__u64 timestamp_ns;
	__u64 request_key; /* address only; userspace emits a hash, not a lifetime ID */
	__u64 remaining_bytes;
	__u32 nr_bytes;
	__u32 cmd_flags;
	__u32 rq_flags;
	__s32 error;
	__u32 reason;
	__u32 reserved;
};

struct kh_block_diag {
	__u64 flush_count[KH_BUCKETS];
	__u64 flush_sum_ns;
	__u64 counter[KH_BLOCK_DIAG_COUNTERS];
	struct kh_block_sample samples[KH_BLOCK_DIAG_SAMPLES];
};

enum kh_metric {
	/* Scheduler, target cgroup tasks. */
	KH_SCHED_RUNQ,		/* wakeup or preemption -> back on CPU */
	KH_SCHED_OFFCPU_D,	/* switched out uninterruptible -> woken */
	KH_SCHED_OFFCPU_S,	/* switched out interruptible -> woken */
	KH_SCHED_ONCPU,		/* switched in -> switched out */
	/* Memory, target cgroup tasks in task context. */
	KH_MEM_FAULT_MINOR,	/* handle_mm_fault without VM_FAULT_MAJOR */
	KH_MEM_FAULT_MAJOR,	/* handle_mm_fault with VM_FAULT_MAJOR */
	KH_MEM_PAGE_ALLOC,	/* __alloc_frozen_pages_noprof */
	KH_MEM_MEMCG_CHARGE,	/* try_charge_memcg */
	KH_MEM_DIRECT_RECLAIM,	/* mm_vmscan_direct_reclaim_begin/end */
	KH_MEM_MEMCG_RECLAIM,	/* mm_vmscan_memcg_reclaim_begin/end */
	KH_MEM_COMPACTION,	/* mm_compaction_begin/end */
	/* Lock contention, target cgroup tasks in task context. */
	KH_LOCK_SPIN,
	KH_LOCK_MUTEX,
	KH_LOCK_RWSEM,
	KH_LOCK_OTHER,
	/* Block layer, whole system (requests are not attributed). */
	KH_BLK_QUEUE,		/* block_rq_insert -> block_rq_issue */
	KH_BLK_SERVICE,		/* block_rq_issue -> block_rq_complete */
	/* Softirq handler duration, whole system. */
	KH_SOFTIRQ_NET,
	KH_SOFTIRQ_BLOCK,
	KH_SOFTIRQ_OTHER,
	/* Syscall enter -> exit, target cgroup tasks, by class. */
	KH_SYSCALL_FILE_IO,
	KH_SYSCALL_FILE_META,
	KH_SYSCALL_MEMORY,
	KH_SYSCALL_PROCESS,
	KH_SYSCALL_NETWORK,
	KH_SYSCALL_WAIT,
	KH_SYSCALL_OTHER,
	KH_METRICS,
};

#define KH_SYSCALL_CLASSES (KH_SYSCALL_OTHER - KH_SYSCALL_FILE_IO + 1)
#define KH_SYSCALL_SLOTS 512

enum kh_counter {
	KH_C_SWITCH_VOLUNTARY,	/* target task switched out not runnable */
	KH_C_SWITCH_PREEMPTED,	/* target task switched out still runnable */
	KH_C_MIGRATIONS,	/* target task moved to another CPU */
	KH_C_WAKEUPS,		/* target task woken from a sleep */
	KH_C_STORAGE_MISS,	/* task storage unavailable; event dropped */
	KH_C_BLK_UNTRACKED,	/* block request without a tracked start */
	KH_C_UNPAIRED,		/* end event without a matching start */
	KH_C_INITIAL_CHILD_RETURN_CENSORED, /* observed birth, child clone return has no child enter */
	KH_C_DOMAIN_CHANGE,
	KH_C_TASK_ENROLLED,
	KH_C_TASK_EXIT,
	KH_C_TASK_EXIT_UNFINISHED,
	KH_C_EXIT_SYSCALL_CENSORED,
	KH_C_BLK_PARTIAL,
	KH_C_BLK_REQUEUE,
	KH_C_BLK_INSERT_COLLISION,
	KH_C_BLK_ISSUE_WITHOUT_INSERT,
	KH_C_BLK_COMPLETE_ERROR,
	KH_C_BLK_BYTE_MISMATCH,
	KH_C_BLK_UPDATE_FAILED,
	KH_C_BLK_DELETE_FAILED,
	KH_C_BLK_ZERO_LENGTH,
	KH_COUNTERS,
};

/* One mmapable ARRAY element per possible CPU; user space sums them. */
struct kh_slot {
	__u64 count[KH_METRICS][KH_BUCKETS];
	__u64 sum_ns[KH_METRICS];
	__u64 counter[KH_COUNTERS];
};

struct kh_config {
	__u32 cpu_count;
	__u32 domain_count;
	__u32 enabled;
	__u32 abi_version;
};

struct kh_domain {
	__u64 cgroup_id;
	__u32 cgroup_level;
	__u32 reserved;
};

enum kh_completion_kind {
	KH_COMPLETION_INVALID,
	KH_COMPLETION_PARTIAL,
	KH_COMPLETION_FINAL,
	KH_COMPLETION_ZERO_LENGTH,
};

/* Shared by the BPF program and its native regression fixture. */
static __inline __attribute__((always_inline)) unsigned int
kh_completion_kind(__u64 remaining, __u32 nr_bytes)
{
	if (!remaining)
		return KH_COMPLETION_ZERO_LENGTH;
	if (!nr_bytes || nr_bytes > remaining)
		return KH_COMPLETION_INVALID;
	return nr_bytes == remaining ? KH_COMPLETION_FINAL : KH_COMPLETION_PARTIAL;
}

static __inline __attribute__((always_inline)) int
kh_service_eligible(unsigned int requeued, unsigned int had_error,
		    unsigned int completion)
{
	return !requeued && !had_error && completion == KH_COMPLETION_FINAL;
}

#endif
