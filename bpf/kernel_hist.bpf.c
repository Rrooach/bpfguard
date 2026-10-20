// SPDX-License-Identifier: GPL-2.0-only
/*
 * Latency histograms for the load sampler: where target-cgroup tasks spend
 * time inside the kernel (scheduler, memory, locks, syscalls) plus the
 * system-wide block layer and softirq handlers. Programs only count; no
 * events leave the kernel. User space mmaps kh_hist and reads cumulative
 * per-CPU slots at each sample.
 */

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "kernel_hist.h"

#define KH_TASK_RUNNING 0x0
#define KH_TASK_INTERRUPTIBLE 0x1
#define KH_TASK_UNINTERRUPTIBLE 0x2
#define KH_TASK_NOLOAD 0x400
#define KH_VM_FAULT_MAJOR 0x4
#define KH_LCB_F_SPIN (1U << 0)
#define KH_LCB_F_READ (1U << 1)
#define KH_LCB_F_WRITE (1U << 2)
#define KH_LCB_F_MUTEX (1U << 5)
#define KH_NET_TX_SOFTIRQ 2
#define KH_NET_RX_SOFTIRQ 3
#define KH_BLOCK_SOFTIRQ 4
#define KH_MAX_LEVEL 31

struct kernfs_node {
	__u64 id;
} __attribute__((preserve_access_index));

struct cgroup {
	int level;
	struct kernfs_node *kn;
	struct cgroup *ancestors[];
} __attribute__((preserve_access_index));

struct css_set {
	struct cgroup *dfl_cgrp;
} __attribute__((preserve_access_index));

struct task_struct {
	struct css_set *cgroups;
} __attribute__((preserve_access_index));

struct pt_regs {
	unsigned long di;
	unsigned long si;
	unsigned long orig_ax;
	unsigned long ax;
} __attribute__((preserve_access_index));

/* Per-task in-flight state. Depth counters make nested or interrupted
 * start/end pairs record only the outermost interval. */
struct kh_task {
	__u64 cgroup_id;
	__u32 domain_mask;
	__u32 exited;
	__u32 newborn;
	__u64 runq_ts;
	__u64 block_ts;
	__u64 oncpu_ts;
	__u64 syscall_ts;
	__u64 fault_ts;
	__u64 alloc_ts;
	__u64 charge_ts;
	__u64 lock_ts;
	__u64 reclaim_ts;
	__u64 memcg_reclaim_ts;
	__u64 compact_ts;
	__u32 block_state;
	__u32 syscall_metric;
	__u32 syscall_nr;
	__u32 lock_metric;
	__u16 fault_depth;
	__u16 alloc_depth;
	__u16 charge_depth;
	__u16 lock_depth;
};

struct kh_blk {
	__u64 insert_ts;
	__u64 issue_ts;
	__u64 remaining_bytes;
	__u32 requeued;
	__u32 had_error;
	__u32 cmd_flags;
	__u32 rq_flags;
	__u32 object_valid;
	__u32 reserved;
};

struct request {
	unsigned int __data_len;
	unsigned int cmd_flags;
	unsigned int rq_flags;
} __attribute__((preserve_access_index));

enum req_op { REQ_OP_FLUSH = 2 };

struct kh_softirq {
	__u64 ts;
	__u32 vec;
	__u32 active;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1); /* resized to CPUs * (domains + one system slot) */
	__type(key, __u32);
	__type(value, struct kh_slot);
} kh_hist SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct kh_config);
} kh_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, KH_MAX_DOMAINS);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct kh_domain);
} kh_domains SEC(".maps");

/* Registration is immutable for this object's lifetime; kernfs IDs include
 * a generation. Cache both positive and negative membership by leaf identity.
 * LRU eviction only causes a recomputation, never silent event dropping. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} kh_membership SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, KH_SYSCALL_SLOTS);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} kh_syscall_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct kh_task);
} kh_tasks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct kh_blk);
} kh_blk_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kh_block_diag);
} kh_block_diagnostics SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kh_softirq);
} kh_softirq_inflight SEC(".maps");

/* Task context means "not inside a softirq handler on this CPU", tracked by
 * the softirq_entry/exit hooks below (this kernel's BTF has no per-CPU
 * __preempt_count). Hard-IRQ allocations and locks are rare and not
 * excluded. */
static __always_inline int kh_in_task(void)
{
	__u32 zero = 0;
	struct kh_softirq *slot = bpf_map_lookup_elem(&kh_softirq_inflight, &zero);

	return !slot || !slot->active;
}

static __always_inline struct kh_slot *kh_slot(__u32 slot_id)
{
	__u32 cpu = bpf_get_smp_processor_id();
	__u32 zero = 0, key;
	struct kh_config *cfg = bpf_map_lookup_elem(&kh_config, &zero);

	if (!cfg || cpu >= cfg->cpu_count || slot_id > cfg->domain_count)
		return 0;
	key = slot_id * cfg->cpu_count + cpu;
	return bpf_map_lookup_elem(&kh_hist, &key);
}

static __always_inline __u32 kh_log2(__u64 v)
{
	__u32 r = 0;

	if (v >> 32) {
		v >>= 32;
		r += 32;
	}
	if (v >> 16) {
		v >>= 16;
		r += 16;
	}
	if (v >> 8) {
		v >>= 8;
		r += 8;
	}
	if (v >> 4) {
		v >>= 4;
		r += 4;
	}
	if (v >> 2) {
		v >>= 2;
		r += 2;
	}
	if (v >> 1)
		r += 1;
	return r;
}

static __always_inline void kh_record_slot(__u32 slot_id, __u64 metric,
					 __u64 start, __u64 now)
{
	struct kh_slot *slot;
	__u64 delta;
	__u32 bucket;

	if (!start || now < start || metric >= KH_METRICS)
		return;
	slot = kh_slot(slot_id);
	if (!slot)
		return;
	delta = now - start;
	bucket = kh_log2(delta);
	if (bucket >= KH_BUCKETS)
		bucket = KH_BUCKETS - 1;
	__sync_fetch_and_add(&slot->count[metric][bucket], 1);
	__sync_fetch_and_add(&slot->sum_ns[metric], delta);
}

/* Scalar-only global subprograms are independently verified. Inlining the
 * membership mask through every aggregation loop creates exponential
 * verifier states as the number of selected domains grows. */
__noinline void kh_record(__u32 mask, __u64 metric, __u64 start, __u64 now)
{
	if (metric >= KH_BLK_QUEUE && metric <= KH_SOFTIRQ_OTHER) {
		kh_record_slot(0, metric, start, now);
		return;
	}
	for (__u32 i = 0; i < KH_MAX_DOMAINS; i++) {
		if (mask & (1U << i))
			kh_record_slot(i + 1, metric, start, now);
	}
}

__noinline void kh_count(__u32 mask, __u64 counter)
{
	for (__u32 i = 0; i <= KH_MAX_DOMAINS; i++) {
		struct kh_slot *slot;
		if ((i == 0 && mask) || (i && !(mask & (1U << (i - 1)))))
			continue;
		slot = kh_slot(i);
		if (slot && counter < KH_COUNTERS)
			__sync_fetch_and_add(&slot->counter[counter], 1);
	}
}

static __always_inline struct kh_config *kh_cfg(void)
{
	__u32 zero = 0;
	struct kh_config *cfg = bpf_map_lookup_elem(&kh_config, &zero);

	return cfg && cfg->enabled && cfg->abi_version == KH_ABI_VERSION &&
	       cfg->domain_count <= KH_MAX_DOMAINS ? cfg : 0;
}

struct kh_match_context {
	struct cgroup *cgroup;
	__u32 domain_count;
	__u32 mask;
	int depth;
};

/* bpf_loop (Linux >= 5.17) bounds and independently verifies each callback;
 * plain loops carrying a 16-bit membership mask multiply verifier paths. */
static long (*kh_bpf_loop)(__u32 count, void *callback, void *context, __u64 flags) =
	(void *)181;

static long kh_match_domain(__u32 index, void *raw)
{
	struct kh_match_context *context = raw;
	struct cgroup *cgrp = context->cgroup, *ancestor = 0;
	struct kh_domain *domain;
	__u32 level;

	if (index >= KH_MAX_DOMAINS || index >= context->domain_count)
		return 1;
	domain = bpf_map_lookup_elem(&kh_domains, &index);
	if (!domain)
		return 0;
	level = domain->cgroup_level & KH_MAX_LEVEL;
	if (context->depth < (int)level)
		return 0;
	if (!bpf_core_read(&ancestor, sizeof(ancestor), &cgrp->ancestors[level]) &&
	    ancestor && BPF_CORE_READ(ancestor, kn, id) == domain->cgroup_id)
		context->mask |= 1U << index;
	return 0;
}

/* Compare each selected ancestor identity: nested domains are inclusive. */
static __always_inline __u32 kh_task_matches(struct task_struct *task)
{
	struct kh_config *cfg = kh_cfg();
	struct kh_match_context context = {};
	struct cgroup *cgrp;
	__u64 cgroup_id;
	__u32 *cached;

	if (!cfg || !task)
		return 0;
	cgrp = BPF_CORE_READ(task, cgroups, dfl_cgrp);
	if (!cgrp)
		return 0;
	cgroup_id = BPF_CORE_READ(cgrp, kn, id);
	cached = bpf_map_lookup_elem(&kh_membership, &cgroup_id);
	if (cached)
		return *cached;
	context.cgroup = cgrp;
	context.depth = BPF_CORE_READ(cgrp, level);
	context.domain_count = cfg->domain_count;
	kh_bpf_loop(KH_MAX_DOMAINS, kh_match_domain, &context, 0);
	/* Failure to cache is not failure to observe: use the freshly calculated
	 * membership and retry on the next event. */
	bpf_map_update_elem(&kh_membership, &cgroup_id, &context.mask, BPF_ANY);
	return context.mask;
}

/* Storage is created only from scheduler and syscall-entry hooks. Fault,
 * allocation, charge, reclaim and lock hooks never allocate: they may run
 * inside the allocator or while a lock is contended, and every target task
 * already has storage from its first context switch. */
static __always_inline struct kh_task *kh_task(struct task_struct *task)
{
	struct kh_task *state;
	__u32 mask;
	__u64 cgroup_id = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id);
	struct kh_task empty = {};

	if (!kh_cfg())
		return 0;
	state = bpf_task_storage_get(&kh_tasks, task, 0, 0);
	if (state && state->cgroup_id == cgroup_id && state->domain_mask)
		return state->exited ? 0 : state;
	mask = kh_task_matches(task);
	if (!mask) {
		if (state && state->domain_mask) {
			kh_count(state->domain_mask, KH_C_DOMAIN_CHANGE);
			__builtin_memcpy(state, &empty, sizeof(empty));
		}
		return 0;
	}

	state = bpf_task_storage_get(&kh_tasks, task, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!state) {
		kh_count(mask, KH_C_STORAGE_MISS);
		return 0;
	}
	if (!state->cgroup_id)
		kh_count(mask, KH_C_TASK_ENROLLED);
	else if (state->cgroup_id != cgroup_id) {
		__u32 added = mask & ~state->domain_mask;
		kh_count(state->domain_mask | mask, KH_C_DOMAIN_CHANGE);
		__builtin_memcpy(state, &empty, sizeof(empty));
		if (added)
			kh_count(added, KH_C_TASK_ENROLLED);
	}
	state->cgroup_id = cgroup_id;
	state->domain_mask = mask;
	if (state->exited)
		return 0;
	return state;
}

static __always_inline struct kh_task *kh_current_task(void)
{
	struct kh_task *state = bpf_task_storage_get(&kh_tasks, bpf_get_current_task_btf(), 0, 0);
	if (!kh_cfg() || !state || state->exited)
		return 0;
	if (state->cgroup_id != bpf_get_current_cgroup_id()) {
		return kh_task(bpf_get_current_task_btf());
	}
	return state;
}

/* ---- Scheduler ---- */

static __always_inline void kh_wakeup(struct task_struct *task)
{
	struct kh_task *state;
	__u64 now;

	state = kh_task(task);
	if (!state)
		return;
	now = bpf_ktime_get_ns();
	if (state->block_ts) {
		kh_record(state->domain_mask, state->block_state & KH_TASK_UNINTERRUPTIBLE ?
				  KH_SCHED_OFFCPU_D : KH_SCHED_OFFCPU_S,
			  state->block_ts, now);
		state->block_ts = 0;
		/* This counter counts matched sleeps, not every wakeup hook. */
		kh_count(state->domain_mask, KH_C_WAKEUPS);
	}
	/* Existing tasks can already be stopped when probes attach. Their first
	 * ordinary wakeup has no observed block_ts but still begins runqueue wait.
	 * A repeated wakeup must not erase an earlier queue-entry timestamp. */
	if (!state->runq_ts)
		state->runq_ts = now;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(kh_sched_wakeup, struct task_struct *task)
{
	(void)ctx;
	kh_wakeup(task);
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(kh_sched_wakeup_new, struct task_struct *task)
{
	struct kh_task *state;
	(void)ctx;
	state = kh_task(task);
	if (state)
		state->newborn = 1;
	kh_wakeup(task);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(kh_sched_switch, unsigned long preempt, struct task_struct *prev,
	     struct task_struct *next, unsigned int prev_state)
{
	struct kh_task *state;
	__u64 now = bpf_ktime_get_ns();

	(void)ctx;
	if ((state = kh_task(prev))) {
		kh_record(state->domain_mask, KH_SCHED_ONCPU, state->oncpu_ts, now);
		state->oncpu_ts = 0;
		/* TASK_IDLE (uninterruptible + noload) is not a real D wait. */
		if (preempt || prev_state == KH_TASK_RUNNING) {
			state->runq_ts = now;
			kh_count(state->domain_mask, KH_C_SWITCH_PREEMPTED);
		} else {
			state->runq_ts = 0;
			state->block_ts = now;
			state->block_state = prev_state & KH_TASK_NOLOAD ?
						     KH_TASK_INTERRUPTIBLE :
						     prev_state;
			kh_count(state->domain_mask, KH_C_SWITCH_VOLUNTARY);
		}
	}
	if ((state = kh_task(next))) {
		kh_record(state->domain_mask, KH_SCHED_RUNQ, state->runq_ts, now);
		state->runq_ts = 0;
		state->oncpu_ts = now;
	}
	return 0;
}

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(kh_sched_migrate, struct task_struct *task, int dest_cpu)
{
	__u32 mask = kh_task_matches(task);
	(void)ctx;
	(void)dest_cpu;
	if (mask)
		kh_count(mask, KH_C_MIGRATIONS);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(kh_sched_exit, struct task_struct *task)
{
	struct kh_task *state;
	(void)ctx;
	state = bpf_task_storage_get(&kh_tasks, task, 0, 0);
	if (!kh_cfg() || !state || state->exited || !state->domain_mask)
		return 0;
	if (state->cgroup_id != BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, id)) {
		state = kh_task(task);
		if (!state)
			return 0;
	}
	/* Close only the observed CPU interval. Non-returning exit syscalls are
	 * censored, not fabricated ordinary syscall completions. */
	kh_record(state->domain_mask, KH_SCHED_ONCPU, state->oncpu_ts,
		  bpf_ktime_get_ns());
	if (state->syscall_ts &&
	    (state->syscall_nr == 60 || state->syscall_nr == 231))
		kh_count(state->domain_mask, KH_C_EXIT_SYSCALL_CENSORED);
	if ((state->syscall_ts && state->syscall_nr != 60 && state->syscall_nr != 231) ||
	    state->fault_ts || state->alloc_ts || state->charge_ts ||
	    state->lock_ts || state->reclaim_ts || state->memcg_reclaim_ts ||
	    state->compact_ts || state->runq_ts)
		kh_count(state->domain_mask, KH_C_TASK_EXIT_UNFINISHED);
	kh_count(state->domain_mask, KH_C_TASK_EXIT);
	state->oncpu_ts = 0;
	state->exited = 1;
	return 0;
}

/* ---- Memory ---- */

static __always_inline int kh_fault_begin(void)
{
	struct kh_task *state;

	if (!(state = kh_current_task()))
		return 0;
	if (state->fault_depth++ == 0)
		state->fault_ts = bpf_ktime_get_ns();
	return 0;
}

static __always_inline int kh_fault_finish(__u32 ret)
{
	struct kh_task *state;

	if (!(state = kh_current_task()))
		return 0;
	if (!state->fault_depth) {
		kh_count(state->domain_mask, KH_C_UNPAIRED);
		return 0;
	}
	if (--state->fault_depth == 0) {
		kh_record(state->domain_mask, ret & KH_VM_FAULT_MAJOR ? KH_MEM_FAULT_MAJOR :
						    KH_MEM_FAULT_MINOR,
			  state->fault_ts, bpf_ktime_get_ns());
		state->fault_ts = 0;
	}
	return 0;
}

static __always_inline int kh_alloc_begin(void)
{
	struct kh_task *state;

	if (!kh_in_task() ||
	    !(state = kh_current_task()))
		return 0;
	if (state->alloc_depth++ == 0)
		state->alloc_ts = bpf_ktime_get_ns();
	return 0;
}

static __always_inline int kh_alloc_finish(void)
{
	struct kh_task *state;

	if (!kh_in_task() ||
	    !(state = kh_current_task()))
		return 0;
	if (!state->alloc_depth) {
		kh_count(state->domain_mask, KH_C_UNPAIRED);
		return 0;
	}
	if (--state->alloc_depth == 0) {
		kh_record(state->domain_mask, KH_MEM_PAGE_ALLOC, state->alloc_ts, bpf_ktime_get_ns());
		state->alloc_ts = 0;
	}
	return 0;
}

static __always_inline int kh_charge_begin(void)
{
	struct kh_task *state;

	if (!kh_in_task() ||
	    !(state = kh_current_task()))
		return 0;
	if (state->charge_depth++ == 0)
		state->charge_ts = bpf_ktime_get_ns();
	return 0;
}

static __always_inline int kh_charge_finish(void)
{
	struct kh_task *state;

	if (!kh_in_task() ||
	    !(state = kh_current_task()))
		return 0;
	if (!state->charge_depth) {
		kh_count(state->domain_mask, KH_C_UNPAIRED);
		return 0;
	}
	if (--state->charge_depth == 0) {
		kh_record(state->domain_mask, KH_MEM_MEMCG_CHARGE, state->charge_ts,
			  bpf_ktime_get_ns());
		state->charge_ts = 0;
	}
	return 0;
}

#define KH_MEMORY_PAIR(prefix, function) \
SEC("fentry/" #function) int BPF_PROG(kh_##prefix##_enter) \
{ (void)ctx; return kh_##prefix##_begin(); } \
SEC("fexit/" #function) int BPF_PROG(kh_##prefix##_exit) \
{ (void)ctx; return kh_##prefix##_finish(); } \
SEC("kprobe/" #function) int kh_##prefix##_enter_kprobe(struct pt_regs *ctx) \
{ (void)ctx; return kh_##prefix##_begin(); } \
SEC("kretprobe/" #function) int kh_##prefix##_exit_kprobe(struct pt_regs *ctx) \
{ (void)ctx; return kh_##prefix##_finish(); }

KH_MEMORY_PAIR(alloc, __alloc_frozen_pages_noprof)
KH_MEMORY_PAIR(charge, try_charge_memcg)

SEC("fentry/handle_mm_fault")
int BPF_PROG(kh_fault_enter)
{ (void)ctx; return kh_fault_begin(); }
SEC("fexit/handle_mm_fault")
int BPF_PROG(kh_fault_exit, void *vma, unsigned long address,
	     unsigned int flags, void *regs, unsigned int ret)
{ (void)ctx; (void)vma; (void)address; (void)flags; (void)regs; return kh_fault_finish(ret); }
SEC("kprobe/handle_mm_fault")
int kh_fault_enter_kprobe(struct pt_regs *ctx)
{ (void)ctx; return kh_fault_begin(); }
SEC("kretprobe/handle_mm_fault")
int kh_fault_exit_kprobe(struct pt_regs *ctx)
{ return kh_fault_finish((__u32)BPF_CORE_READ(ctx, ax)); }

/* Reclaim and compaction begin/end tracepoints run in the stalled task. */
#define KH_SPAN_BEGIN(name, field)                                         \
	SEC("tp_btf/" #name "_begin")                                      \
	int kh_##name##_begin(void *ctx)                                   \
	{                                                                  \
		struct kh_task *state;                                     \
		(void)ctx;                                                 \
		if ((state = kh_current_task()))                          \
			state->field = bpf_ktime_get_ns();                 \
		return 0;                                                  \
	}
#define KH_SPAN_END(name, field, metric)                                   \
	SEC("tp_btf/" #name "_end")                                        \
	int kh_##name##_end(void *ctx)                                     \
	{                                                                  \
		struct kh_task *state;                                     \
		(void)ctx;                                                 \
		if (!(state = kh_current_task()))                         \
			return 0;                                          \
		if (!state->field) {                                       \
			kh_count(state->domain_mask, KH_C_UNPAIRED);        \
			return 0;                                          \
		}                                                          \
		kh_record(state->domain_mask, metric, state->field, bpf_ktime_get_ns()); \
		state->field = 0;                                          \
		return 0;                                                  \
	}

KH_SPAN_BEGIN(mm_vmscan_direct_reclaim, reclaim_ts)
KH_SPAN_END(mm_vmscan_direct_reclaim, reclaim_ts, KH_MEM_DIRECT_RECLAIM)
KH_SPAN_BEGIN(mm_vmscan_memcg_reclaim, memcg_reclaim_ts)
KH_SPAN_END(mm_vmscan_memcg_reclaim, memcg_reclaim_ts, KH_MEM_MEMCG_RECLAIM)
KH_SPAN_BEGIN(mm_compaction, compact_ts)
KH_SPAN_END(mm_compaction, compact_ts, KH_MEM_COMPACTION)

/* ---- Lock contention ---- */

SEC("tp_btf/contention_begin")
int BPF_PROG(kh_lock_begin, void *lock, unsigned int flags)
{
	struct kh_task *state;

	(void)ctx;
	(void)lock;
	if (!kh_in_task() ||
	    !(state = kh_current_task()))
		return 0;
	if (state->lock_depth++ != 0)
		return 0;
	state->lock_ts = bpf_ktime_get_ns();
	if (flags & KH_LCB_F_MUTEX)
		state->lock_metric = KH_LOCK_MUTEX;
	else if (flags & KH_LCB_F_SPIN)
		state->lock_metric = KH_LOCK_SPIN;
	else if (flags & (KH_LCB_F_READ | KH_LCB_F_WRITE))
		state->lock_metric = KH_LOCK_RWSEM;
	else
		state->lock_metric = KH_LOCK_OTHER;
	return 0;
}

SEC("tp_btf/contention_end")
int BPF_PROG(kh_lock_end, void *lock, int ret)
{
	struct kh_task *state;

	(void)ctx;
	(void)lock;
	(void)ret;
	if (!kh_in_task() ||
	    !(state = kh_current_task()))
		return 0;
	if (!state->lock_depth) {
		kh_count(state->domain_mask, KH_C_UNPAIRED);
		return 0;
	}
	if (--state->lock_depth == 0) {
		kh_record(state->domain_mask, state->lock_metric, state->lock_ts, bpf_ktime_get_ns());
		state->lock_ts = 0;
	}
	return 0;
}

/* ---- Block layer (system-wide) ---- */

static __always_inline struct kh_block_diag *kh_block_diag(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&kh_block_diagnostics, &zero);
}

static __always_inline void kh_block_count(__u32 counter)
{
	struct kh_block_diag *diag = kh_block_diag();
	if (diag && counter < KH_BLOCK_DIAG_COUNTERS)
		__sync_fetch_and_add(&diag->counter[counter], 1);
}

static __always_inline void kh_block_sample(void *rq, const struct kh_blk *value,
					  __u32 reason, int error, __u32 nr_bytes)
{
	struct kh_block_diag *diag = kh_block_diag();
	__u64 index;
	if (!diag)
		return;
	index = __sync_fetch_and_add(&diag->counter[KH_BD_SAMPLE_ATTEMPTS], 1);
	if (index >= KH_BLOCK_DIAG_SAMPLES)
		return; /* bounded diagnostic sampling, not an event history */
	diag->samples[index].timestamp_ns = bpf_ktime_get_ns();
	diag->samples[index].request_key = (__u64)rq;
	diag->samples[index].remaining_bytes = value->remaining_bytes;
	diag->samples[index].nr_bytes = nr_bytes;
	diag->samples[index].cmd_flags = value->cmd_flags;
	diag->samples[index].rq_flags = value->rq_flags;
	diag->samples[index].error = error;
	diag->samples[index].reason = reason;
	diag->samples[index].reserved = value->object_valid;
}

static __always_inline int kh_block_identity(void *rq, struct kh_blk *value)
{
	__u32 bytes = 0;
	if (bpf_core_read(&bytes, sizeof(bytes),
			 &((struct request *)rq)->__data_len) ||
	    bpf_core_read(&value->cmd_flags, sizeof(value->cmd_flags),
			 &((struct request *)rq)->cmd_flags) ||
	    bpf_core_read(&value->rq_flags, sizeof(value->rq_flags),
			 &((struct request *)rq)->rq_flags)) {
		kh_block_count(KH_BD_READ_FAILED);
		kh_block_sample(rq, value, KH_BD_OBJECT_READ_ERROR, 0, 0);
		return 0;
	}
	value->remaining_bytes = bytes;
	value->object_valid = 1;
	return 1;
}

static __always_inline int kh_block_is_flush(const struct kh_blk *value)
{
	return value->object_valid && (value->cmd_flags & 0xff) ==
		bpf_core_enum_value(enum req_op, REQ_OP_FLUSH);
}

static __always_inline void kh_block_flush_record(__u64 start, __u64 end)
{
	struct kh_block_diag *diag = kh_block_diag();
	__u64 elapsed;
	__u32 bucket;
	if (!diag || !start || end < start)
		return;
	elapsed = end - start;
	bucket = kh_log2(elapsed);
	if (bucket >= KH_BUCKETS)
		bucket = KH_BUCKETS - 1;
	__sync_fetch_and_add(&diag->flush_count[bucket], 1);
	__sync_fetch_and_add(&diag->flush_sum_ns, elapsed);
}

SEC("tp_btf/block_rq_insert")
int BPF_PROG(kh_blk_insert, void *rq)
{
	struct kh_blk value = { .insert_ts = bpf_ktime_get_ns() };
	struct kh_blk *tracked;
	__u64 key = (__u64)rq;

	(void)ctx;
	if (!kh_cfg())
		return 0;
	tracked = bpf_map_lookup_elem(&kh_blk_inflight, &key);
	if (tracked) {
		if (tracked->requeued) {
			tracked->insert_ts = value.insert_ts;
			return 0;
		}
		/* Do not silently overwrite an in-flight pointer on reuse/merge. */
		kh_count(0, KH_C_BLK_INSERT_COLLISION);
		if (bpf_map_delete_elem(&kh_blk_inflight, &key))
			kh_count(0, KH_C_BLK_DELETE_FAILED);
	}
	if (bpf_map_update_elem(&kh_blk_inflight, &key, &value, BPF_NOEXIST))
		kh_count(0, KH_C_BLK_UPDATE_FAILED);
	return 0;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(kh_blk_issue, void *rq)
{
	__u64 key = (__u64)rq, now = bpf_ktime_get_ns();
	struct kh_blk *tracked, value = { .issue_ts = now };

	(void)ctx;
	if (!kh_cfg())
		return 0;
	kh_block_identity(rq, &value);
	if (kh_block_is_flush(&value))
		kh_block_count(KH_BD_FLUSH_ISSUED);
	tracked = bpf_map_lookup_elem(&kh_blk_inflight, &key);
	if (tracked) {
		if (tracked->issue_ts) {
			kh_count(0, KH_C_BLK_INSERT_COLLISION);
			tracked->requeued = 1;
		}
		kh_record(0, KH_BLK_QUEUE, tracked->insert_ts, now);
		tracked->insert_ts = 0;
		tracked->issue_ts = now;
		tracked->remaining_bytes = value.remaining_bytes;
		tracked->cmd_flags = value.cmd_flags;
		tracked->rq_flags = value.rq_flags;
		tracked->object_valid = value.object_valid;
	} else {
		kh_count(0, KH_C_BLK_ISSUE_WITHOUT_INSERT);
		/* Direct dispatch and FLUSH bypass insert by design. No queue
		 * interval is invented; the subsequent service remains measurable. */
		kh_block_count(KH_BD_QUEUE_UNKNOWN);
		kh_block_sample(rq, &value, KH_BD_NO_INSERT, 0, 0);
		if (bpf_map_update_elem(&kh_blk_inflight, &key, &value, BPF_NOEXIST))
			kh_count(0, KH_C_BLK_UPDATE_FAILED);
	}
	return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(kh_blk_complete, void *rq, int error, unsigned int nr_bytes)
{
	__u64 key = (__u64)rq;
	struct kh_blk *tracked;
	__u32 completion;

	(void)ctx;
	if (!kh_cfg())
		return 0;
	tracked = bpf_map_lookup_elem(&kh_blk_inflight, &key);
	if (!tracked || !tracked->issue_ts) {
		struct kh_blk observed = {};
		kh_count(0, KH_C_BLK_UNTRACKED);
		kh_block_count(KH_BD_UNTRACKED_COMPLETE);
		kh_block_identity(rq, &observed);
		kh_block_sample(rq, &observed, KH_BD_UNTRACKED_END, error, nr_bytes);
		if (tracked && bpf_map_delete_elem(&kh_blk_inflight, &key))
			kh_count(0, KH_C_BLK_DELETE_FAILED);
		return 0;
	}
	completion = kh_completion_kind(tracked->remaining_bytes, nr_bytes);
	if (error) {
		kh_count(0, KH_C_BLK_COMPLETE_ERROR);
		tracked->had_error = 1;
	}
	if (completion == KH_COMPLETION_PARTIAL) {
		tracked->remaining_bytes -= nr_bytes;
		kh_count(0, KH_C_BLK_PARTIAL);
		return 0;
	} else if (completion == KH_COMPLETION_INVALID)
		kh_count(0, KH_C_BLK_BYTE_MISMATCH);
	else if (completion == KH_COMPLETION_ZERO_LENGTH) {
		if (kh_block_is_flush(tracked) && !nr_bytes) {
			if (error || tracked->had_error) {
				kh_block_count(KH_BD_FLUSH_ERROR);
				kh_block_sample(rq, tracked, KH_BD_FLUSH_COMPLETE_ERROR, error, nr_bytes);
			} else {
				kh_block_count(KH_BD_FLUSH_COMPLETED);
				if (!tracked->requeued)
					kh_block_flush_record(tracked->issue_ts, bpf_ktime_get_ns());
				kh_block_sample(rq, tracked, KH_BD_ZERO_FLUSH_COMPLETE, error, nr_bytes);
			}
		} else {
			kh_count(0, KH_C_BLK_ZERO_LENGTH);
			kh_block_count(kh_block_is_flush(tracked) ?
				KH_BD_ZERO_FLUSH_BAD_BYTES : KH_BD_ZERO_NONFLUSH);
			kh_block_sample(rq, tracked, kh_block_is_flush(tracked) ?
				KH_BD_INVALID_FLUSH_BYTES : KH_BD_ZERO_OTHER, error, nr_bytes);
		}
	}
	else if (kh_service_eligible(tracked->requeued, tracked->had_error, completion))
		kh_record(0, KH_BLK_SERVICE, tracked->issue_ts, bpf_ktime_get_ns());
	if (bpf_map_delete_elem(&kh_blk_inflight, &key))
		kh_count(0, KH_C_BLK_DELETE_FAILED);
	return 0;
}

SEC("tp_btf/block_rq_requeue")
int BPF_PROG(kh_blk_requeue, void *rq)
{
	__u64 key = (__u64)rq;
	struct kh_blk *tracked;
	(void)ctx;
	if (!kh_cfg())
		return 0;
	kh_count(0, KH_C_BLK_REQUEUE);
	tracked = bpf_map_lookup_elem(&kh_blk_inflight, &key);
	if (!tracked) {
		struct kh_blk observed = {};
		kh_count(0, KH_C_BLK_UNTRACKED);
		kh_block_count(KH_BD_UNTRACKED_REQUEUE);
		kh_block_identity(rq, &observed);
		kh_block_sample(rq, &observed, KH_BD_UNTRACKED_REQUEUE_EVENT, 0, 0);
		return 0;
	}
	/* Requeued requests remain bounded and tracked to terminal completion,
	 * but no precise service histogram is asserted across requeue/merges. */
	tracked->requeued = 1;
	tracked->issue_ts = 0;
	tracked->insert_ts = 0;
	return 0;
}

/* ---- Softirq (system-wide) ---- */

SEC("tp_btf/softirq_entry")
int BPF_PROG(kh_softirq_entry, unsigned int vec)
{
	__u32 zero = 0;
	struct kh_softirq *slot = bpf_map_lookup_elem(&kh_softirq_inflight, &zero);

	(void)ctx;
	if (slot && kh_cfg()) {
		slot->ts = bpf_ktime_get_ns();
		slot->vec = vec;
		slot->active = 1;
	}
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(kh_softirq_exit, unsigned int vec)
{
	__u32 zero = 0, metric;
	struct kh_softirq *slot = bpf_map_lookup_elem(&kh_softirq_inflight, &zero);

	(void)ctx;
	if (!slot || !slot->active || slot->vec != vec)
		return 0;
	slot->active = 0;
	if (vec == KH_NET_RX_SOFTIRQ || vec == KH_NET_TX_SOFTIRQ)
		metric = KH_SOFTIRQ_NET;
	else if (vec == KH_BLOCK_SOFTIRQ)
		metric = KH_SOFTIRQ_BLOCK;
	else
		metric = KH_SOFTIRQ_OTHER;
	kh_record(0, metric, slot->ts, bpf_ktime_get_ns());
	return 0;
}

/* ---- Syscalls by class ---- */

static __always_inline void kh_sys_enter_value(__u32 nr)
{
	struct kh_task *state;
	__u32 *klass;
	struct kh_config *cfg = kh_cfg();

	if (!cfg)
		return;
	klass = nr < KH_SYSCALL_SLOTS ?
			bpf_map_lookup_elem(&kh_syscall_class, &nr) : 0;
	if ((klass && *klass == 0xffffffffU) || (!klass && (cfg->enabled & 2)))
		return;
	state = kh_current_task();
	if (!state)
		state = kh_task(bpf_get_current_task_btf());
	if (!state)
		return;
	if (state->syscall_ts)
		kh_count(state->domain_mask, KH_C_UNPAIRED);
	state->newborn = 0;
	state->syscall_metric = KH_SYSCALL_FILE_IO +
				(klass && *klass < KH_SYSCALL_CLASSES ?
					 *klass :
					 KH_SYSCALL_OTHER - KH_SYSCALL_FILE_IO);
	state->syscall_ts = bpf_ktime_get_ns();
	state->syscall_nr = nr;
}

static __always_inline void kh_sys_exit_value(__u32 nr, long ret)
{
	struct kh_task *state;
	struct kh_config *cfg = kh_cfg();
	__u32 *klass;

	if (!cfg)
		return;
	klass = nr < KH_SYSCALL_SLOTS ?
			bpf_map_lookup_elem(&kh_syscall_class, &nr) : 0;
	if ((klass && *klass == 0xffffffffU) || (!klass && (cfg->enabled & 2)))
		return;
	if (!(state = kh_current_task()))
		return;
	if (!state->syscall_ts) {
		/* The first child return from clone/fork has no syscall entry in
		 * that child. Censor only when sched_wakeup_new proved this birth;
		 * an ordinary missing entry still remains a coverage failure. */
		if (state->newborn && ret == 0 && (nr == 56 || nr == 57 || nr == 58 || nr == 435)) {
			kh_count(state->domain_mask, KH_C_INITIAL_CHILD_RETURN_CENSORED);
		} else
			kh_count(state->domain_mask, KH_C_UNPAIRED);
		state->newborn = 0;
		return;
	}
	kh_record(state->domain_mask, state->syscall_metric, state->syscall_ts, bpf_ktime_get_ns());
	state->syscall_ts = 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(kh_sys_enter, void *regs, long id)
{
	(void)ctx;
	(void)regs;
	kh_sys_enter_value((__u32)id);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(kh_sys_exit, void *regs, long ret)
{
	(void)ctx;
	(void)regs;
	kh_sys_exit_value((__u32)BPF_CORE_READ((struct pt_regs *)regs, orig_ax), ret);
	return 0;
}

/* Registration-only callbacks enable the kernel SYSCALL_WORK tracepoint
 * flag. They do not measure or produce spans. A skipped noop callback does
 * not skip trace_syscall_enter/exit or the separately attached kprobe. */
SEC("tp_btf/sys_enter")
int BPF_PROG(kh_sys_enter_dispatch, void *regs, long id)
{
	(void)ctx; (void)regs; (void)id;
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(kh_sys_exit_dispatch, void *regs, long ret)
{
	(void)ctx; (void)regs; (void)ret;
	return 0;
}

/* kprobe handlers execute with preemption disabled, unlike this kernel's
 * faultable raw syscall dispatcher with its per-CPU recursion guard. */
SEC("kprobe/trace_syscall_enter")
int kh_sys_enter_kprobe(struct pt_regs *ctx)
{
	struct pt_regs *regs = (void *)BPF_CORE_READ(ctx, di);
	kh_sys_enter_value((__u32)BPF_CORE_READ(regs, orig_ax));
	return 0;
}

SEC("kprobe/trace_syscall_exit")
int kh_sys_exit_kprobe(struct pt_regs *ctx)
{
	struct pt_regs *regs = (void *)BPF_CORE_READ(ctx, di);
	kh_sys_exit_value((__u32)BPF_CORE_READ(regs, orig_ax), (long)BPF_CORE_READ(ctx, si));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
