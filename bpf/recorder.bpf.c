// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>

#include "recorder.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name
#define __always_inline inline __attribute__((always_inline))

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(const void *map, const void *key,
				   const void *value, __u64 flags) =
	(void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(const void *map, const void *key) =
	(void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) =
	(void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_cgroup_id)(void) =
	(void *)BPF_FUNC_get_current_cgroup_id;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_submit;

/* Fixed raw_syscalls tracepoint layouts. This recorder is built and tested
 * against the pinned experiment kernel; it deliberately avoids guessing at
 * per-command internal kernel function names.
 */
struct recorder_trace_entry {
	__u16 type;
	__u8 flags;
	__u8 preempt_count;
	__s32 pid;
};

struct recorder_sys_enter {
	struct recorder_trace_entry common;
	long id;
	unsigned long args[6];
};

struct recorder_sys_exit {
	struct recorder_trace_entry common;
	long id;
	long ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct recorder_config);
} recorder_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, RECORDER_MAX_RUNS);
	__type(key, __u64);
	__type(value, struct recorder_run_state);
} run_states SEC(".maps");

/* A regular preallocated HASH is required: an LRU map could silently evict an
 * in-flight syscall and manufacture a false complete trace.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, RECORDER_MAX_PENDING);
	__type(key, __u64);
	__type(value, struct recorder_pending);
} pending_calls SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RECORDER_RING_BYTES);
} events SEC(".maps");

static __always_inline struct recorder_config *get_config(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&recorder_config, &zero);
}

static __always_inline int is_configured_syscall(
	const struct recorder_config *config, long syscall_nr)
{
	return (config->bpf_syscall_nrs[0] >= 0 &&
		syscall_nr == config->bpf_syscall_nrs[0]) ||
	       (config->bpf_syscall_nrs[1] >= 0 &&
		syscall_nr == config->bpf_syscall_nrs[1]) ||
	       (config->bpf_syscall_nrs[2] >= 0 &&
		syscall_nr == config->bpf_syscall_nrs[2]);
}

static __always_inline __u64 next_sequence(struct recorder_run_state *run)
{
	return __sync_fetch_and_add(&run->next_event_seq, 1) + 1;
}

static __always_inline void publish(struct recorder_run_state *run,
				    const struct recorder_event *source)
{
	struct recorder_event *event;

	__sync_fetch_and_add(&run->event_attempted, 1);
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&run->event_dropped, 1);
		return;
	}
	__builtin_memcpy(event, source, sizeof(*event));
	/* Once reserved, submit cannot fail. Count before submit so a userspace
	 * drain can safely wait for a record that has not become visible yet.
	 */
	__sync_fetch_and_add(&run->event_published, 1);
	bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_bpf_enter(struct recorder_sys_enter *ctx)
{
	struct recorder_config *config;
	struct recorder_run_state *run;
	struct recorder_pending *existing;
	struct recorder_pending pending = {};
	struct recorder_event event = {};
	__u64 cgroup_id, pid_tgid;
	__u32 raw_command;
	long syscall_nr;
	int err;

	syscall_nr = ctx->id;
	config = get_config();
	if (!config || !is_configured_syscall(config, syscall_nr))
		return 0;

	cgroup_id = bpf_get_current_cgroup_id();
	run = bpf_map_lookup_elem(&run_states, &cgroup_id);
	if (!run || !run->epoch) {
		pid_tgid = bpf_get_current_pid_tgid();
		if (config->exclusive_window &&
		    (__u32)(pid_tgid >> 32) != config->observer_tgid)
			__sync_fetch_and_add(
				&config->outside_cgroup_syscall_attempted, 1);
		return 0;
	}

	pid_tgid = bpf_get_current_pid_tgid();
	raw_command = (__u32)ctx->args[0];
	pending.epoch = run->epoch;
	pending.cgroup_id = cgroup_id;
	pending.attempt_seq = next_sequence(run);
	pending.command = raw_command & ~RECORDER_BPF_COMMON_ATTRS;
	pending.attr_size = (__u32)ctx->args[2];
	if (raw_command & RECORDER_BPF_COMMON_ATTRS)
		pending.flags |= RECORDER_F_COMMON_ATTRS;

	__sync_fetch_and_add(&run->syscall_attempted, 1);
	err = bpf_map_update_elem(&pending_calls, &pid_tgid, &pending, BPF_NOEXIST);
	if (err) {
		pending.flags |= RECORDER_F_PENDING_INSERT_FAILED;
		__sync_fetch_and_add(&run->pending_insert_failed, 1);
		/* Never let the next exit masquerade as the completion of a stale
		 * attempt. A tid cannot execute two syscalls concurrently, so this
		 * value is necessarily stale when BPF_NOEXIST fails.
		 */
		existing = bpf_map_lookup_elem(&pending_calls, &pid_tgid);
		if (existing)
			existing->flags |= RECORDER_F_PENDING_POISONED;
	} else {
		__sync_fetch_and_add(&run->pending_remaining, 1);
	}

	event.schema_version = RECORDER_SCHEMA_VERSION;
	event.kind = RECORDER_EVENT_SYSCALL_ATTEMPTED;
	event.flags = pending.flags;
	event.command = pending.command;
	event.attr_size = pending.attr_size;
	event.run_epoch = pending.epoch;
	event.event_seq = pending.attempt_seq;
	event.ktime_ns = bpf_ktime_get_ns();
	event.cgroup_id = cgroup_id;
	event.pid_tgid = pid_tgid;
	publish(run, &event);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_bpf_exit(struct recorder_sys_exit *ctx)
{
	struct recorder_config *config;
	struct recorder_pending *stored;
	struct recorder_pending pending = {};
	struct recorder_run_state *run;
	struct recorder_event event = {};
	__u64 pid_tgid, cgroup_id;
	long syscall_nr;

	syscall_nr = ctx->id;
	config = get_config();
	if (!config || !is_configured_syscall(config, syscall_nr))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	stored = bpf_map_lookup_elem(&pending_calls, &pid_tgid);
	if (stored) {
		pending = *stored;
		run = bpf_map_lookup_elem(&run_states, &pending.cgroup_id);
		if (!run || run->epoch != pending.epoch) {
			bpf_map_delete_elem(&pending_calls, &pid_tgid);
			return 0;
		}
		__sync_fetch_and_add(&run->syscall_completed, 1);
		/* Only a successful delete proves that this pending record was
		 * consumed. Decrementing first could falsely declare the run drained.
		 */
		if (bpf_map_delete_elem(&pending_calls, &pid_tgid) == 0) {
			__sync_fetch_and_sub(&run->pending_remaining, 1);
		} else {
			pending.flags |= RECORDER_F_PENDING_DELETE_FAILED;
		}
		if (pending.flags & RECORDER_F_PENDING_POISONED) {
			pending.flags |= RECORDER_F_PENDING_MISSING;
			pending.command = ~0U;
			pending.attr_size = 0;
			pending.attempt_seq = 0;
			__sync_fetch_and_add(&run->pending_missing, 1);
		}
	} else {
		/* Attribute an unpaired exit to its current exact cgroup when
		 * possible. This is a health failure, never a fabricated pair.
		 */
		cgroup_id = bpf_get_current_cgroup_id();
		run = bpf_map_lookup_elem(&run_states, &cgroup_id);
		if (!run || !run->epoch)
			return 0;
		pending.epoch = run->epoch;
		pending.cgroup_id = cgroup_id;
		pending.flags = RECORDER_F_PENDING_MISSING;
		pending.command = ~0U;
		__sync_fetch_and_add(&run->syscall_completed, 1);
		__sync_fetch_and_add(&run->pending_missing, 1);
	}

	event.schema_version = RECORDER_SCHEMA_VERSION;
	event.kind = RECORDER_EVENT_COMMAND_COMPLETED;
	event.flags = pending.flags;
	event.command = pending.command;
	event.attr_size = pending.attr_size;
	event.run_epoch = pending.epoch;
	event.event_seq = next_sequence(run);
	event.related_attempt_seq = pending.attempt_seq;
	event.ktime_ns = bpf_ktime_get_ns();
	event.cgroup_id = pending.cgroup_id;
	event.pid_tgid = pid_tgid;
	event.return_value = ctx->ret;
	publish(run, &event);
	return 0;
}

_Static_assert(sizeof(struct recorder_event) == 72, "recorder event ABI changed");
_Static_assert(sizeof(struct recorder_config) == 40, "recorder config ABI changed");
_Static_assert(sizeof(struct recorder_run_state) == 80, "run state ABI changed");
_Static_assert(sizeof(struct recorder_pending) == 40, "pending state ABI changed");

char LICENSE[] SEC("license") = "GPL";
