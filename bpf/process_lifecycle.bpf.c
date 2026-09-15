// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "process_lifecycle.h"

struct task_struct {
	int pid;
	int tgid;
	int exit_code;
	__u64 start_boottime;
	char comm[16];
	struct task_struct *real_parent;
} __attribute__((preserve_access_index));

struct linux_binprm {
	const char *filename;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EFFECT_LIFECYCLE_MAX_RUNS);
	__type(key, __u64);
	__type(value, struct effect_lifecycle_run_state);
} effect_lifecycle_runs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, EFFECT_LIFECYCLE_MAX_ANCESTOR_ROOTS);
	__type(key, __u32);
	__type(value, __u32);
} life_roots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EFFECT_LIFECYCLE_MAX_ANCESTOR_ROOTS);
	__type(key, __u32);
	__type(value, __u64);
} life_root_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct effect_lifecycle_ancestor_config);
} life_root_cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EFFECT_LIFECYCLE_RING_BYTES);
} effect_lifecycle_events SEC(".maps");

static __always_inline __u64
lifecycle_next_sequence(struct effect_lifecycle_run_state *run)
{
	return __sync_fetch_and_add(&run->next_event_seq, 1) + 1;
}

/* This gate is deliberately the first work in every global lifecycle hook.
 * Exact standalone mode pays one current-cgroup helper plus one HASH lookup.
 * Only an exact miss with a nonzero sealed root count performs the bounded
 * ancestor checks; no task/BPRM reads or ring work precedes membership.
 */
static __always_inline struct effect_lifecycle_run_state *
lifecycle_ancestor_run(__u32 index, __u64 *cgroup_id)
{
	struct effect_lifecycle_run_state *run;
	__u64 *root_id;

	root_id = bpf_map_lookup_elem(&life_root_ids, &index);
	if (!root_id || !*root_id)
		return 0;
	if (bpf_current_task_under_cgroup(&life_roots, index) != 1)
		return 0;
	run = bpf_map_lookup_elem(&effect_lifecycle_runs, root_id);
	if (!run || !run->epoch)
		return 0;
	*cgroup_id = *root_id;
	return run;
}

static __attribute__((noinline)) struct effect_lifecycle_run_state *
lifecycle_current_run(__u64 *cgroup_id)
{
	struct effect_lifecycle_ancestor_config *config;
	struct effect_lifecycle_run_state *run;
	__u64 current;
	__u32 zero = 0;

	current = bpf_get_current_cgroup_id();
	run = bpf_map_lookup_elem(&effect_lifecycle_runs, &current);
	if (run && run->epoch) {
		*cgroup_id = current;
		return run;
	}
	config = bpf_map_lookup_elem(&life_root_cfg, &zero);
	if (!config || !config->root_count ||
	    config->root_count > EFFECT_LIFECYCLE_MAX_ANCESTOR_ROOTS)
		return 0;
	if (config->root_count > 0 &&
	    (run = lifecycle_ancestor_run(0, cgroup_id)))
		return run;
	if (config->root_count > 1 &&
	    (run = lifecycle_ancestor_run(1, cgroup_id)))
		return run;
	if (config->root_count > 2 &&
	    (run = lifecycle_ancestor_run(2, cgroup_id)))
		return run;
	if (config->root_count > 3 &&
	    (run = lifecycle_ancestor_run(3, cgroup_id)))
		return run;
	if (config->root_count > 4 &&
	    (run = lifecycle_ancestor_run(4, cgroup_id)))
		return run;
	if (config->root_count > 5 &&
	    (run = lifecycle_ancestor_run(5, cgroup_id)))
		return run;
	if (config->root_count > 6 &&
	    (run = lifecycle_ancestor_run(6, cgroup_id)))
		return run;
	if (config->root_count > 7 &&
	    (run = lifecycle_ancestor_run(7, cgroup_id)))
		return run;
	return 0;
}

static __always_inline void
lifecycle_copy_task(struct effect_lifecycle_event *event,
		    const struct task_struct *task, int parent)
{
	long error = 0;

	if (!task) {
		event->flags |= EFFECT_LIFECYCLE_F_TASK_READ_FAILED;
		return;
	}
	if (parent) {
		error |= bpf_core_read(&event->parent_pid,
				       sizeof(event->parent_pid), &task->pid);
		error |= bpf_core_read(&event->parent_tgid,
				       sizeof(event->parent_tgid), &task->tgid);
		error |= bpf_core_read(&event->parent_start_boottime_ns,
				       sizeof(event->parent_start_boottime_ns),
				       &task->start_boottime);
		error |= bpf_core_read(&event->parent_comm,
				       sizeof(event->parent_comm), &task->comm);
	} else {
		error |= bpf_core_read(&event->pid, sizeof(event->pid),
				       &task->pid);
		error |= bpf_core_read(&event->tgid, sizeof(event->tgid),
				       &task->tgid);
		error |= bpf_core_read(&event->start_boottime_ns,
				       sizeof(event->start_boottime_ns),
				       &task->start_boottime);
		error |= bpf_core_read(&event->comm, sizeof(event->comm),
				       &task->comm);
	}
	if (error)
		event->flags |= EFFECT_LIFECYCLE_F_TASK_READ_FAILED;
}

static __always_inline struct effect_lifecycle_event *
lifecycle_reserve(struct effect_lifecycle_run_state *run, __u64 cgroup_id,
		  __u16 kind)
{
	struct effect_lifecycle_event *event;

	__sync_fetch_and_add(&run->event_attempted, 1);
	event = bpf_ringbuf_reserve(&effect_lifecycle_events,
				    sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&run->event_dropped, 1);
		return 0;
	}
	__builtin_memset(event, 0, sizeof(*event));
	event->schema_version = EFFECT_LIFECYCLE_SCHEMA_VERSION;
	event->kind = kind;
	event->run_epoch = run->epoch;
	event->event_seq = lifecycle_next_sequence(run);
	event->ktime_ns = bpf_ktime_get_ns();
	event->cgroup_id = cgroup_id;
	return event;
}

static __always_inline void
lifecycle_submit(struct effect_lifecycle_run_state *run,
		 struct effect_lifecycle_event *event)
{
	if (event->flags & EFFECT_LIFECYCLE_F_TASK_READ_FAILED)
		__sync_fetch_and_add(&run->task_read_failed, 1);
	if (event->flags & EFFECT_LIFECYCLE_F_EXEC_PATH_READ_FAILED)
		__sync_fetch_and_add(&run->exec_path_read_failed, 1);
	if (event->flags & EFFECT_LIFECYCLE_F_EXEC_PATH_TRUNCATED)
		__sync_fetch_and_add(&run->exec_path_truncated, 1);
	__sync_fetch_and_add(&run->event_published, 1);
	bpf_ringbuf_submit(event, 0);
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(trace_effect_process_fork, struct task_struct *parent,
	     struct task_struct *child)
{
	struct effect_lifecycle_run_state *run;
	struct effect_lifecycle_event *event;
	__u64 cgroup_id;

	(void)ctx;
	run = lifecycle_current_run(&cgroup_id);
	if (!run)
		return 0;
	event = lifecycle_reserve(run, cgroup_id, EFFECT_LIFECYCLE_FORK);
	if (!event)
		return 0;
	lifecycle_copy_task(event, child, 0);
	lifecycle_copy_task(event, parent, 1);
	lifecycle_submit(run, event);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(trace_effect_process_exec, struct task_struct *task, int old_pid,
	     struct linux_binprm *bprm)
{
	struct effect_lifecycle_run_state *run;
	struct effect_lifecycle_event *event;
	struct task_struct *parent = 0;
	const char *filename = 0;
	__u64 cgroup_id;
	long length;

	(void)ctx;
	run = lifecycle_current_run(&cgroup_id);
	if (!run)
		return 0;
	event = lifecycle_reserve(run, cgroup_id, EFFECT_LIFECYCLE_EXEC);
	if (!event)
		return 0;
	lifecycle_copy_task(event, task, 0);
	event->old_pid = (__u32)old_pid;
	if (bpf_core_read(&parent, sizeof(parent), &task->real_parent))
		event->flags |= EFFECT_LIFECYCLE_F_TASK_READ_FAILED;
	lifecycle_copy_task(event, parent, 1);
	if (bpf_core_read(&filename, sizeof(filename), &bprm->filename) ||
	    !filename) {
		event->flags |= EFFECT_LIFECYCLE_F_EXEC_PATH_READ_FAILED;
	} else {
		length = bpf_probe_read_kernel_str(event->exec_path,
					   sizeof(event->exec_path), filename);
		if (length <= 0) {
			event->flags |= EFFECT_LIFECYCLE_F_EXEC_PATH_READ_FAILED;
		} else {
			/* The ABI stores logical bytes, not the helper's trailing NUL. */
			event->exec_path_len = (__u16)(length - 1);
			if (length == EFFECT_LIFECYCLE_EXEC_PATH_BYTES)
				event->flags |=
					EFFECT_LIFECYCLE_F_EXEC_PATH_TRUNCATED;
		}
	}
	lifecycle_submit(run, event);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(trace_effect_process_exit, struct task_struct *task,
	     _Bool group_dead)
{
	struct effect_lifecycle_run_state *run;
	struct effect_lifecycle_event *event;
	struct task_struct *parent = 0;
	__u64 cgroup_id;

	(void)ctx;
	run = lifecycle_current_run(&cgroup_id);
	if (!run)
		return 0;
	event = lifecycle_reserve(run, cgroup_id, EFFECT_LIFECYCLE_EXIT);
	if (!event)
		return 0;
	lifecycle_copy_task(event, task, 0);
	event->group_dead = group_dead ? 1 : 0;
	if (bpf_core_read(&parent, sizeof(parent), &task->real_parent) ||
	    bpf_core_read(&event->exit_code, sizeof(event->exit_code),
			  &task->exit_code))
		event->flags |= EFFECT_LIFECYCLE_F_TASK_READ_FAILED;
	lifecycle_copy_task(event, parent, 1);
	lifecycle_submit(run, event);
	return 0;
}

_Static_assert(sizeof(struct effect_lifecycle_run_state) == 64,
	       "lifecycle run-state ABI changed");
_Static_assert(sizeof(struct effect_lifecycle_event) == 248,
	       "lifecycle event ABI changed");

char LICENSE[] SEC("license") = "GPL";
