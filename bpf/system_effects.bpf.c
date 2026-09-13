// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "system_effects.h"

#define EFFECT_MAY_WRITE 0x2

/* A deliberately minimal local BTF model. Every access below is relocated by
 * CO-RE; no target-kernel byte offset is compiled into the program.
 */
struct dentry;

struct super_block {
	__u32 s_dev;
	unsigned long s_magic;
} __attribute__((preserve_access_index));

struct inode {
	struct super_block *i_sb;
	unsigned long i_ino;
	__u32 i_generation;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct mount {
	struct vfsmount mnt;
	__u64 mnt_id_unique;
} __attribute__((preserve_access_index));

struct effect_trace_entry {
	__u16 type;
	__u8 flags;
	__u8 preempt_count;
	__s32 pid;
};

struct effect_sys_enter {
	struct effect_trace_entry common;
	long id;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;
	unsigned long arg3;
	unsigned long arg4;
	unsigned long arg5;
};

struct effect_sys_exit {
	struct effect_trace_entry common;
	long id;
	long ret;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EFFECT_POLICY_ENTRIES);
	__type(key, __u32);
	__type(value, struct effect_syscall_policy);
} effect_policy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EFFECT_MAX_RUNS);
	__type(key, __u64);
	__type(value, struct effect_run_state);
} effect_runs SEC(".maps");

/* This must not be LRU: eviction would turn evidence loss into an apparently
 * ordinary filtered syscall exit.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EFFECT_MAX_PENDING);
	__type(key, __u64);
	__type(value, struct effect_pending_call);
} effect_pending SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct effect_object_config);
} effect_object_config SEC(".maps");

/* This map is created only while the opt-in LSM/exit pair is autoloaded, so
 * user-input mode pays no idle-memory cost. Keep it non-evicting and use the
 * HASH default preallocation in object modes: bounded upfront memory avoids
 * allocator failure and latency variance in the evidence-critical hook path.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EFFECT_MAX_PENDING);
	__type(key, __u64);
	__type(value, struct effect_file_pending);
} effect_file_objects SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EFFECT_RING_BYTES);
} effect_events SEC(".maps");

static __always_inline __u64 next_sequence(struct effect_run_state *run)
{
	return __sync_fetch_and_add(&run->next_event_seq, 1) + 1;
}

/* The verifier does not permit a variable offset from a tracepoint context or
 * the BPF stack on all supported experiment kernels. Keep every load at a
 * statically provable offset.
 */
static __always_inline __u64
enter_argument(const struct effect_sys_enter *ctx, __u8 index)
{
	__u64 value;

	switch (index) {
	case 0:
		asm volatile("%0 = *(u64 *)(%1 + 16)"
			     : "=r"(value) : "r"(ctx));
		return value;
	case 1:
		asm volatile("%0 = *(u64 *)(%1 + 24)"
			     : "=r"(value) : "r"(ctx));
		return value;
	case 2:
		asm volatile("%0 = *(u64 *)(%1 + 32)"
			     : "=r"(value) : "r"(ctx));
		return value;
	case 3:
		asm volatile("%0 = *(u64 *)(%1 + 40)"
			     : "=r"(value) : "r"(ctx));
		return value;
	case 4:
		asm volatile("%0 = *(u64 *)(%1 + 48)"
			     : "=r"(value) : "r"(ctx));
		return value;
	case 5:
		asm volatile("%0 = *(u64 *)(%1 + 56)"
			     : "=r"(value) : "r"(ctx));
		return value;
	default:
		return 0;
	}
}

static __always_inline __u64 saved_argument(const __u64 *args, __u8 index)
{
	switch (index) {
	case 0:
		return args[0];
	case 1:
		return args[1];
	case 2:
		return args[2];
	case 3:
		return args[3];
	case 4:
		return args[4];
	case 5:
		return args[5];
	default:
		return 0;
	}
}

static __always_inline struct effect_syscall_policy *
select_policy(struct effect_sys_enter *ctx)
{
	struct effect_syscall_policy *policy;
	__u32 key;

	if (ctx->id < 0 || ctx->id >= EFFECT_POLICY_ENTRIES)
		return 0;
	key = (__u32)ctx->id;
	policy = bpf_map_lookup_elem(&effect_policy, &key);
	if (!policy || policy->enabled != 1 || !policy->domain ||
	    !policy->operation)
		return 0;
	if (policy->filter_mask) {
		if (policy->filter_arg_index >= 6)
			return 0;
		if (!(enter_argument(ctx, policy->filter_arg_index) &
		      policy->filter_mask))
			return 0;
	}
	return policy;
}

static __always_inline int selected_exit(long syscall_nr)
{
	struct effect_syscall_policy *policy;
	__u32 key;

	if (syscall_nr < 0 || syscall_nr >= EFFECT_POLICY_ENTRIES)
		return 0;
	key = (__u32)syscall_nr;
	policy = bpf_map_lookup_elem(&effect_policy, &key);
	return policy && policy->enabled == 1;
}

static __always_inline void
fill_header(struct effect_event_header *event,
	    const struct effect_pending_call *pending, __u16 kind,
	    __u64 event_seq, __u64 pid_tgid, __s64 return_value)
{
	event->schema_version = EFFECT_SCHEMA_VERSION;
	event->kind = kind;
	event->domain = pending->domain;
	event->operation = pending->operation;
	event->flags = pending->flags;
	event->syscall_nr = pending->syscall_nr;
	event->run_epoch = pending->epoch;
	event->event_seq = event_seq;
	if (kind == EFFECT_EVENT_OPERATION_RESULT)
		event->related_attempt_seq = pending->attempt_seq;
	event->ktime_ns = bpf_ktime_get_ns();
	event->cgroup_id = pending->cgroup_id;
	event->pid_tgid = pid_tgid;
	event->return_value = return_value;
	__builtin_memcpy(event->args, pending->args, sizeof(event->args));
	bpf_get_current_comm(event->comm, sizeof(event->comm));
}

static __always_inline void capture_argument(
	const struct effect_capture_policy *capture, const __u64 *args,
	__u8 *payload, __u16 *payload_len, __u8 *payload_kind,
	__u8 *payload_arg_index, __u32 *flags, __u32 read_failed_flag,
	__u32 truncated_flag, __u32 invalid_length_flag)
{
	__u64 requested;
	long result;

	*payload_kind = capture->kind;
	*payload_arg_index = capture->arg_index;
	if (capture->kind == EFFECT_CAPTURE_NONE)
		return;
	*flags |= EFFECT_F_USER_MEMORY_SNAPSHOT;
	if (capture->arg_index >= 6) {
		*flags |= EFFECT_F_POLICY_INVALID;
		*payload_kind = EFFECT_CAPTURE_NONE;
		return;
	}

	if (capture->kind == EFFECT_CAPTURE_USER_STRING) {
		result = bpf_probe_read_user_str(
			payload, EFFECT_CAPTURE_BYTES,
			(const void *)(unsigned long)saved_argument(
				args, capture->arg_index));
		if (result < 0) {
			*flags |= read_failed_flag;
			return;
		}
		*payload_len = (__u16)result;
		if (result == EFFECT_CAPTURE_BYTES)
			*flags |= truncated_flag;
		return;
	}

	if (capture->kind != EFFECT_CAPTURE_SOCKADDR) {
		*flags |= EFFECT_F_POLICY_INVALID;
		*payload_kind = EFFECT_CAPTURE_NONE;
		return;
	}
	if (capture->length_arg_index >= 6) {
		*flags |= EFFECT_F_POLICY_INVALID;
		*payload_kind = EFFECT_CAPTURE_NONE;
		return;
	}
	requested = saved_argument(args, capture->length_arg_index);
	if (!requested) {
		*flags |= invalid_length_flag;
		return;
	}
	if (requested > EFFECT_CAPTURE_BYTES) {
		requested = EFFECT_CAPTURE_BYTES;
		*flags |= truncated_flag;
	}
	result = bpf_probe_read_user(
		payload, (__u32)requested,
		(const void *)(unsigned long)saved_argument(
			args, capture->arg_index));
	if (result < 0) {
		*flags |= read_failed_flag;
		return;
	}
	*payload_len = (__u16)requested;
}

static __always_inline void publish_compact_attempt(
	struct effect_run_state *run,
	const struct effect_pending_call *pending, __u64 pid_tgid)
{
	struct effect_event_header *event;

	__sync_fetch_and_add(&run->event_attempted, 1);
	event = bpf_ringbuf_reserve(&effect_events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&run->event_dropped, 1);
		return;
	}
	__builtin_memset(event, 0, sizeof(*event));
	fill_header(event, pending, EFFECT_EVENT_OPERATION_ATTEMPT,
		    pending->attempt_seq, pid_tgid, 0);
	__sync_fetch_and_add(&run->event_published, 1);
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void publish_full_attempt(
	struct effect_run_state *run,
	const struct effect_pending_call *pending,
	const struct effect_syscall_policy *policy, __u64 pid_tgid)
{
	struct effect_event *event;

	__sync_fetch_and_add(&run->event_attempted, 1);
	event = bpf_ringbuf_reserve(&effect_events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&run->event_dropped, 1);
		return;
	}
	__builtin_memset(event, 0, sizeof(*event));
	fill_header(&event->header, pending, EFFECT_EVENT_OPERATION_ATTEMPT,
		    pending->attempt_seq, pid_tgid, 0);
	capture_argument(&policy->capture[0], pending->args,
			 event->payload1, &event->header.payload1_len,
			 &event->header.payload1_kind,
			 &event->header.payload1_arg_index,
			 &event->header.flags,
			 EFFECT_F_PAYLOAD1_READ_FAILED,
			 EFFECT_F_PAYLOAD1_TRUNCATED,
			 EFFECT_F_PAYLOAD1_INVALID_LENGTH);
	capture_argument(&policy->capture[1], pending->args,
			 event->payload2, &event->header.payload2_len,
			 &event->header.payload2_kind,
			 &event->header.payload2_arg_index,
			 &event->header.flags,
			 EFFECT_F_PAYLOAD2_READ_FAILED,
			 EFFECT_F_PAYLOAD2_TRUNCATED,
			 EFFECT_F_PAYLOAD2_INVALID_LENGTH);
	__sync_fetch_and_add(&run->event_published, 1);
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void publish_result(
	struct effect_run_state *run,
	const struct effect_pending_call *pending, __u64 event_seq,
	__u64 pid_tgid, __s64 return_value)
{
	struct effect_event_header *event;

	__sync_fetch_and_add(&run->event_attempted, 1);
	event = bpf_ringbuf_reserve(&effect_events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&run->event_dropped, 1);
		return;
	}
	__builtin_memset(event, 0, sizeof(*event));
	fill_header(event, pending, EFFECT_EVENT_OPERATION_RESULT, event_seq,
		    pid_tgid, return_value);
	__sync_fetch_and_add(&run->event_published, 1);
	bpf_ringbuf_submit(event, 0);
}

static __always_inline void publish_file_result(
	struct effect_run_state *run,
	const struct effect_pending_call *pending,
	const struct effect_file_identity *object, __u64 event_seq,
	__u64 pid_tgid, __s64 return_value)
{
	struct effect_file_event *event;

	__sync_fetch_and_add(&run->event_attempted, 1);
	event = bpf_ringbuf_reserve(&effect_events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&run->event_dropped, 1);
		return;
	}
	__builtin_memset(event, 0, sizeof(*event));
	fill_header(&event->header, pending, EFFECT_EVENT_OPERATION_RESULT,
		    event_seq, pid_tgid, return_value);
	event->object = *object;
	__sync_fetch_and_add(&run->event_published, 1);
	bpf_ringbuf_submit(event, 0);
}

static __always_inline int is_file_open_resolver(
	const struct effect_pending_call *pending)
{
	return pending->object_resolver == EFFECT_OBJECT_RESOLVER_FILE_OPEN &&
	       pending->domain == 1 &&
	       (pending->operation == 1 || pending->operation == 2);
}

static __always_inline int is_file_permission_write_resolver(
	const struct effect_pending_call *pending)
{
	return pending->object_resolver ==
		       EFFECT_OBJECT_RESOLVER_FILE_PERMISSION_WRITE &&
	       pending->domain == 7 && pending->operation == 3;
}

static __always_inline int object_resolver_enabled(
	const struct effect_pending_call *pending,
	const struct effect_object_config *config)
{
	if (is_file_open_resolver(pending))
		return config->resolver_mask & EFFECT_OBJECT_RESOLVE_FILE_OPEN;
	if (is_file_permission_write_resolver(pending))
		return config->resolver_mask &
		       EFFECT_OBJECT_RESOLVE_FILE_PERMISSION_WRITE;
	return 0;
}

static __always_inline void mark_object_flag(
	struct effect_run_state *run, struct effect_pending_call *pending,
	__u32 flag)
{
	if (pending->flags & flag)
		return;
	pending->flags |= flag;
	if (flag == EFFECT_F_OBJECT_JOIN_MISSING)
		__sync_fetch_and_add(&run->object_join_missing, 1);
	else if (flag == EFFECT_F_OBJECT_JOIN_AMBIGUOUS)
		__sync_fetch_and_add(&run->object_join_ambiguous, 1);
	else if (flag == EFFECT_F_OBJECT_READ_FAILED)
		__sync_fetch_and_add(&run->object_read_failed, 1);
	else if (flag == EFFECT_F_OBJECT_DELETE_FAILED)
		__sync_fetch_and_add(&run->object_delete_failed, 1);
}

static __attribute__((noinline)) int record_selected_enter(
	struct effect_sys_enter *ctx, struct effect_syscall_policy *policy,
	struct effect_run_state *run, __u64 cgroup_id)
{
	struct effect_pending_call *existing;
	struct effect_pending_call pending = {};
	__u64 pid_tgid;
	long error;

	pid_tgid = bpf_get_current_pid_tgid();
	pending.epoch = run->epoch;
	pending.cgroup_id = cgroup_id;
	pending.attempt_seq = next_sequence(run);
	pending.syscall_nr = (__s32)ctx->id;
	pending.domain = policy->domain;
	pending.operation = policy->operation;
	pending.object_resolver = policy->object_resolver;
	if (pending.object_resolver >
	    EFFECT_OBJECT_RESOLVER_FILE_PERMISSION_WRITE)
		pending.flags |= EFFECT_F_POLICY_INVALID;
	pending.args[0] = ctx->arg0;
	pending.args[1] = ctx->arg1;
	pending.args[2] = ctx->arg2;
	pending.args[3] = ctx->arg3;
	pending.args[4] = ctx->arg4;
	pending.args[5] = ctx->arg5;

	__sync_fetch_and_add(&run->operation_attempted, 1);
	error = bpf_map_update_elem(&effect_pending, &pid_tgid, &pending,
				    BPF_NOEXIST);
	if (error) {
		pending.flags |= EFFECT_F_PENDING_INSERT_FAILED;
		__sync_fetch_and_add(&run->pending_insert_failed, 1);
		existing = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
		if (existing)
			existing->flags |= EFFECT_F_PENDING_POISONED;
	} else {
		__sync_fetch_and_add(&run->pending_remaining, 1);
	}

	if (policy->capture[0].kind != EFFECT_CAPTURE_NONE ||
	    policy->capture[1].kind != EFFECT_CAPTURE_NONE)
		publish_full_attempt(run, &pending, policy, pid_tgid);
	else
		publish_compact_attempt(run, &pending, pid_tgid);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_effect_enter(struct effect_sys_enter *ctx)
{
	struct effect_syscall_policy *policy;
	struct effect_run_state *run;
	__u64 cgroup_id;

	/* This lookup is deliberately first: unselected syscalls do no cgroup
	 * lookup, pending initialization, capture, allocation, or publication.
	 */
	policy = select_policy(ctx);
	if (!policy)
		return 0;
	cgroup_id = bpf_get_current_cgroup_id();
	run = bpf_map_lookup_elem(&effect_runs, &cgroup_id);
	if (!run || !run->epoch)
		return 0;
	return record_selected_enter(ctx, policy, run, cgroup_id);
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_effect_exit(struct effect_sys_exit *ctx)
{
	struct effect_pending_call *stored;
	struct effect_pending_call pending;
	struct effect_run_state *run;
	__u64 pid_tgid, event_seq;

	/* Keep the ARRAY rejection on the global exit path too. A selected open
	 * that failed the entry bit-filter has no pending item and returns below.
	 */
	if (!selected_exit(ctx->id))
		return 0;
	pid_tgid = bpf_get_current_pid_tgid();
	stored = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!stored)
		return 0;
	pending = *stored;
	run = bpf_map_lookup_elem(&effect_runs, &pending.cgroup_id);
	if (!run || run->epoch != pending.epoch) {
		bpf_map_delete_elem(&effect_pending, &pid_tgid);
		return 0;
	}

	__sync_fetch_and_add(&run->operation_completed, 1);
	if (bpf_map_delete_elem(&effect_pending, &pid_tgid) == 0) {
		__sync_fetch_and_sub(&run->pending_remaining, 1);
	} else {
		pending.flags |= EFFECT_F_PENDING_DELETE_FAILED;
	}
	if (pending.syscall_nr != (__s32)ctx->id)
		pending.flags |= EFFECT_F_SYSCALL_MISMATCH;
	if (pending.flags &
	    (EFFECT_F_PENDING_POISONED | EFFECT_F_SYSCALL_MISMATCH)) {
		pending.flags |= EFFECT_F_PENDING_MISSING;
		pending.attempt_seq = 0;
		__sync_fetch_and_add(&run->pending_missing, 1);
	}
	event_seq = next_sequence(run);
	publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
	return 0;
}

/* This program is never autoloaded in user-input mode. The exact cgroup run
 * lookup precedes every file/path field read and the comparatively expensive
 * path rendering helper.
 */
SEC("lsm.s/file_open")
int BPF_PROG(trace_effect_file_object, struct file *file, int ret)
{
	struct effect_object_config *config;
	struct effect_pending_call *pending;
	struct effect_file_pending *existing;
	struct effect_file_pending resolved;
	struct effect_run_state *run;
	struct super_block *super_block = 0;
	struct vfsmount *vfsmount = 0;
	struct mount *mount = 0;
	struct inode *inode = 0;
	__u64 cgroup_id, pid_tgid;
	__u32 config_key = 0;
	__u32 device = 0;
	long path_length;
	long error = 0;

	(void)ctx;
	if (ret)
		return ret;
	pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!pending || !is_file_open_resolver(pending))
		return ret;
	cgroup_id = bpf_get_current_cgroup_id();
	if (pending->cgroup_id != cgroup_id)
		return ret;
	run = bpf_map_lookup_elem(&effect_runs, &cgroup_id);
	if (!run || !run->epoch || pending->epoch != run->epoch)
		return ret;
	config = bpf_map_lookup_elem(&effect_object_config, &config_key);
	if (!config || !(config->resolver_mask & EFFECT_OBJECT_RESOLVE_FILE_OPEN))
		return ret;
	existing = bpf_map_lookup_elem(&effect_file_objects, &pid_tgid);
	if (existing) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return ret;
	}

	__builtin_memset(&resolved, 0, sizeof(resolved));
	/* All accesses from here down are BTF-described CO-RE reads. */
	error |= bpf_core_read(&inode, sizeof(inode), &file->f_inode);
	error |= bpf_core_read(&vfsmount, sizeof(vfsmount), &file->f_path.mnt);
	if (!inode || !vfsmount)
		error = -1;
	if (!error)
		error |= bpf_core_read(&super_block, sizeof(super_block),
				       &inode->i_sb);
	if (!super_block)
		error = -1;
	if (!error) {
		mount = (struct mount *)((char *)vfsmount -
			bpf_core_field_offset(struct mount, mnt));
		error |= bpf_core_read(&resolved.object.mount_id_unique,
				       sizeof(resolved.object.mount_id_unique),
				       &mount->mnt_id_unique);
		error |= bpf_core_read(&resolved.object.inode,
				       sizeof(resolved.object.inode), &inode->i_ino);
		error |= bpf_core_read(&resolved.object.inode_generation,
				       sizeof(resolved.object.inode_generation),
				       &inode->i_generation);
		error |= bpf_core_read(&resolved.object.filesystem_magic,
				       sizeof(resolved.object.filesystem_magic),
				       &super_block->s_magic);
		error |= bpf_core_read(&device, sizeof(device),
				       &super_block->s_dev);
	}
	if (error || !resolved.object.mount_id_unique ||
	    !resolved.object.inode || !resolved.object.filesystem_magic) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return ret;
	}
	resolved.object.device_major = device >> 20;
	resolved.object.device_minor = device & ((1U << 20) - 1);
	resolved.object.generation_valid =
		resolved.object.inode_generation != 0;
	resolved.object.path_quality = EFFECT_FILE_PATH_NOT_REQUESTED;
	if (config->capture_path == 1) {
		path_length = bpf_d_path(&file->f_path,
					 (char *)resolved.object.path,
					 sizeof(resolved.object.path));
		if (path_length > 1 && path_length <= EFFECT_FILE_PATH_BYTES) {
			resolved.object.path_len = (__u16)(path_length - 1);
			resolved.object.path_quality =
				EFFECT_FILE_PATH_RESOLVED_AT_HOOK;
		} else {
			resolved.object.path_quality =
				EFFECT_FILE_PATH_UNAVAILABLE;
			__sync_fetch_and_add(&run->object_path_unavailable, 1);
		}
	}
	resolved.epoch = pending->epoch;
	resolved.cgroup_id = pending->cgroup_id;
	resolved.attempt_seq = pending->attempt_seq;
	if (bpf_map_update_elem(&effect_file_objects, &pid_tgid, &resolved,
				BPF_NOEXIST) != 0) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return ret;
	}
	__sync_fetch_and_add(&run->object_pending_remaining, 1);
	return ret;
}

/* This hook resolves the struct file actually checked by the VFS write path.
 * It is loaded only for the explicit open+write mode. file_permission is not
 * a sleepable LSM hook, so this program deliberately records the stable
 * mount/device/inode identity without calling bpf_d_path. Operation and exact
 * cgroup selection precede every object field read.
 */
static __attribute__((noinline)) int record_file_permission(
	struct file *file, int ret)
{
	struct effect_object_config *config;
	struct effect_pending_call *pending;
	struct effect_file_pending *existing;
	struct effect_file_pending resolved;
	struct effect_run_state *run;
	struct super_block *super_block = 0;
	struct vfsmount *vfsmount = 0;
	struct mount *mount = 0;
	struct inode *inode = 0;
	__u64 cgroup_id, pid_tgid;
	__u32 config_key = 0;
	__u32 device = 0;
	long error = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!pending || !is_file_permission_write_resolver(pending))
		return ret;
	cgroup_id = bpf_get_current_cgroup_id();
	if (pending->cgroup_id != cgroup_id)
		return ret;
	run = bpf_map_lookup_elem(&effect_runs, &cgroup_id);
	if (!run || !run->epoch || pending->epoch != run->epoch)
		return ret;
	config = bpf_map_lookup_elem(&effect_object_config, &config_key);
	if (!config ||
	    !(config->resolver_mask &
	      EFFECT_OBJECT_RESOLVE_FILE_PERMISSION_WRITE))
		return ret;
	existing = bpf_map_lookup_elem(&effect_file_objects, &pid_tgid);
	if (existing) {
		/* rw_verify_area checks the syscall-visible file before a stacked
		 * filesystem reaches backing files. Keep that first exact object.
		 */
		if (existing->epoch == pending->epoch &&
		    existing->cgroup_id == pending->cgroup_id &&
		    existing->attempt_seq == pending->attempt_seq)
			return ret;
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return ret;
	}

	__builtin_memset(&resolved, 0, sizeof(resolved));
	error |= bpf_core_read(&inode, sizeof(inode), &file->f_inode);
	error |= bpf_core_read(&vfsmount, sizeof(vfsmount), &file->f_path.mnt);
	if (!inode || !vfsmount)
		error = -1;
	if (!error)
		error |= bpf_core_read(&super_block, sizeof(super_block),
				       &inode->i_sb);
	if (!super_block)
		error = -1;
	if (!error) {
		mount = (struct mount *)((char *)vfsmount -
			bpf_core_field_offset(struct mount, mnt));
		error |= bpf_core_read(&resolved.object.mount_id_unique,
				       sizeof(resolved.object.mount_id_unique),
				       &mount->mnt_id_unique);
		error |= bpf_core_read(&resolved.object.inode,
				       sizeof(resolved.object.inode), &inode->i_ino);
		error |= bpf_core_read(&resolved.object.inode_generation,
				       sizeof(resolved.object.inode_generation),
				       &inode->i_generation);
		error |= bpf_core_read(&resolved.object.filesystem_magic,
				       sizeof(resolved.object.filesystem_magic),
				       &super_block->s_magic);
		error |= bpf_core_read(&device, sizeof(device),
				       &super_block->s_dev);
	}
	if (error || !resolved.object.mount_id_unique ||
	    !resolved.object.inode || !resolved.object.filesystem_magic) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return ret;
	}
	resolved.object.device_major = device >> 20;
	resolved.object.device_minor = device & ((1U << 20) - 1);
	resolved.object.generation_valid =
		resolved.object.inode_generation != 0;
	resolved.object.path_quality = EFFECT_FILE_PATH_NOT_REQUESTED;
	resolved.epoch = pending->epoch;
	resolved.cgroup_id = pending->cgroup_id;
	resolved.attempt_seq = pending->attempt_seq;
	if (bpf_map_update_elem(&effect_file_objects, &pid_tgid, &resolved,
				BPF_NOEXIST) != 0) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return ret;
	}
	__sync_fetch_and_add(&run->object_pending_remaining, 1);
	return ret;
}

SEC("lsm/file_permission")
int BPF_PROG(trace_effect_file_permission, struct file *file, int mask, int ret)
{
	(void)ctx;
	if (ret || !(mask & EFFECT_MAY_WRITE))
		return ret;
	return record_file_permission(file, ret);
}

/* Kernel-object mode substitutes this program for trace_effect_exit. Keeping
 * a distinct program ensures that user-input mode retains its original exit
 * hot path byte-for-byte and never touches the object map.
 */
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_effect_file_exit(struct effect_sys_exit *ctx)
{
	struct effect_object_config *config;
	struct effect_file_pending *stored_object;
	struct effect_file_pending file_object;
	struct effect_pending_call *stored;
	struct effect_pending_call pending;
	struct effect_run_state *run;
	struct effect_run_state *object_run;
	__u64 pid_tgid, event_seq, object_attempt_seq;
	__u32 config_key = 0;
	int object_enabled = 0;
	int object_exact = 0;
	int object_deleted = 0;
	int object_present = 0;

	if (!selected_exit(ctx->id))
		return 0;
	pid_tgid = bpf_get_current_pid_tgid();
	stored = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!stored)
		return 0;
	pending = *stored;
	/* Preserve the correlation key before a poisoned syscall pair deliberately
	 * clears the externally published related_attempt_seq below.
	 */
	object_attempt_seq = pending.attempt_seq;
	run = bpf_map_lookup_elem(&effect_runs, &pending.cgroup_id);
	if (!run || run->epoch != pending.epoch) {
		bpf_map_delete_elem(&effect_pending, &pid_tgid);
		return 0;
	}

	__sync_fetch_and_add(&run->operation_completed, 1);
	if (bpf_map_delete_elem(&effect_pending, &pid_tgid) == 0) {
		__sync_fetch_and_sub(&run->pending_remaining, 1);
	} else {
		pending.flags |= EFFECT_F_PENDING_DELETE_FAILED;
	}
	if (pending.syscall_nr != (__s32)ctx->id)
		pending.flags |= EFFECT_F_SYSCALL_MISMATCH;
	if (pending.flags &
	    (EFFECT_F_PENDING_POISONED | EFFECT_F_SYSCALL_MISMATCH)) {
		pending.flags |= EFFECT_F_PENDING_MISSING;
		pending.attempt_seq = 0;
		__sync_fetch_and_add(&run->pending_missing, 1);
	}
	config = bpf_map_lookup_elem(&effect_object_config, &config_key);
	if (config)
		object_enabled = object_resolver_enabled(&pending, config);
	else if (pending.object_resolver != EFFECT_OBJECT_RESOLVER_NONE)
		mark_object_flag(run, &pending, EFFECT_F_OBJECT_READ_FAILED);
	if (!object_enabled) {
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
	}

	stored_object = bpf_map_lookup_elem(&effect_file_objects, &pid_tgid);
	if (stored_object) {
		object_present = 1;
		file_object = *stored_object;
		if (file_object.object.path_quality ==
		    EFFECT_FILE_PATH_UNAVAILABLE)
			pending.flags |= EFFECT_F_OBJECT_PATH_UNAVAILABLE;
		object_exact = file_object.epoch == pending.epoch &&
			       file_object.cgroup_id == pending.cgroup_id &&
			       file_object.attempt_seq == object_attempt_seq;
		if (!object_exact)
			mark_object_flag(run, &pending,
					 EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		if (bpf_map_delete_elem(&effect_file_objects, &pid_tgid) == 0) {
			object_deleted = 1;
			object_run = bpf_map_lookup_elem(&effect_runs,
						 &file_object.cgroup_id);
			if (object_run && object_run->epoch == file_object.epoch &&
			    object_run->object_pending_remaining)
				__sync_fetch_and_sub(
					&object_run->object_pending_remaining, 1);
			else
				mark_object_flag(run, &pending,
						 EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		} else {
			mark_object_flag(run, &pending,
					 EFFECT_F_OBJECT_DELETE_FAILED);
		}
	}

	/* A zero-byte or failed FD write is outside the positive-byte object-
	 * resolution contract. The hook may have run for scalar zero-length writes,
	 * so its temporary join is still removed above, but no FILE_OBJECT identity
	 * is claimed and no statement about other side effects is made.
	 */
	if (is_file_permission_write_resolver(&pending) && ctx->ret <= 0) {
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
	}

	__sync_fetch_and_add(&run->object_resolution_attempted, 1);
	if (is_file_open_resolver(&pending) && ctx->ret < 0) {
		__sync_fetch_and_add(&run->object_resolution_failed_syscalls, 1);
		__sync_fetch_and_add(&run->object_resolution_unresolved, 1);
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
	}
	/* A successful selected open or positive-byte selected write is required to
	 * have traversed its declared object hook. In particular, O_PATH currently
	 * lies outside this closed resolver contract: until its disposition is
	 * captured and independently replayed, a missing file_open join is fatal
	 * rather than guessed to be a legitimate partial result.
	 */
	if (!object_present &&
	    !(pending.flags & (EFFECT_F_OBJECT_JOIN_AMBIGUOUS |
			       EFFECT_F_OBJECT_READ_FAILED)))
		mark_object_flag(run, &pending, EFFECT_F_OBJECT_JOIN_MISSING);
	if (!object_exact || !object_deleted ||
	    pending.flags & (EFFECT_F_PENDING_MISSING |
			     EFFECT_F_PENDING_POISONED |
			     EFFECT_F_SYSCALL_MISMATCH) ||
	    pending.flags & (EFFECT_F_OBJECT_JOIN_MISSING |
			     EFFECT_F_OBJECT_JOIN_AMBIGUOUS |
			     EFFECT_F_OBJECT_READ_FAILED |
			     EFFECT_F_OBJECT_DELETE_FAILED)) {
		__sync_fetch_and_add(&run->object_resolution_unresolved, 1);
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
	}

	__sync_fetch_and_add(&run->object_resolution_resolved, 1);
	event_seq = next_sequence(run);
	publish_file_result(run, &pending, &file_object.object, event_seq,
			    pid_tgid, ctx->ret);
	return 0;
}

_Static_assert(sizeof(struct effect_capture_policy) == 4,
	       "capture policy ABI changed");
_Static_assert(sizeof(struct effect_syscall_policy) == 32,
	       "syscall policy ABI changed");
_Static_assert(sizeof(struct effect_event_header) == 152,
	       "compact event ABI changed");
_Static_assert(sizeof(struct effect_event) == 344,
	       "full event ABI changed");
_Static_assert(sizeof(struct effect_file_identity) == 176,
	       "file object identity ABI changed");
_Static_assert(sizeof(struct effect_file_event) == 328,
	       "file object event ABI changed");
_Static_assert(sizeof(struct effect_file_pending) == 200,
	       "file object pending ABI changed");
_Static_assert(sizeof(struct effect_run_state) == 160,
	       "run state ABI changed");
_Static_assert(sizeof(struct effect_pending_call) == 96,
	       "pending state ABI changed");

char LICENSE[] SEC("license") = "GPL";
