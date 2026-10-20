// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "system_effects.h"

#define EFFECT_MAY_READ 0x4
#define EFFECT_MAY_WRITE 0x2

/* Userspace rejects pre-access recorder objects for the file-access profile. */
const volatile __u32 effect_file_access_abi_v1 = 1;
#define EFFECT_PROT_WRITE 0x2
#define EFFECT_MAP_SHARED 0x1
#define EFFECT_MAP_ANONYMOUS 0x20
#define EFFECT_VM_SHARED (1UL << 3)
#define EFFECT_AF_INET 2
#define EFFECT_AF_INET6 10
#define EFFECT_SOCK_STREAM 1
#define EFFECT_IPPROTO_TCP 6
#define EFFECT_EINPROGRESS 115
#define EFFECT_EALREADY 114
#define EFFECT_EISCONN 106
#define EFFECT_ENOENT 2

/* A deliberately minimal local BTF model. Every access below is relocated by
 * CO-RE; no target-kernel byte offset is compiled into the program.
 */
struct dentry {
	struct inode *d_inode;
} __attribute__((preserve_access_index));

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

struct vm_area_struct {
	unsigned long vm_flags;
	struct file *vm_file;
} __attribute__((preserve_access_index));

struct net {
	__u64 net_cookie;
} __attribute__((preserve_access_index));

typedef struct {
	struct net *net;
} possible_net_t;

struct in6_addr {
	union {
		__u8 u6_addr8[16];
	} in6_u;
} __attribute__((preserve_access_index));

struct sock_common {
	__u32 skc_daddr;
	__u32 skc_rcv_saddr;
	__u16 skc_dport;
	__u16 skc_num;
	unsigned short skc_family;
	volatile unsigned char skc_state;
	int skc_bound_dev_if;
	possible_net_t skc_net;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

struct sock {
	struct sock_common __sk_common;
	__u16 sk_protocol;
	__u16 sk_type;
} __attribute__((preserve_access_index));

struct socket {
	short type;
	struct sock *sk;
} __attribute__((preserve_access_index));

struct proto_accept_arg;

struct effect_sockaddr_in {
	__u16 family;
	__u16 port;
	__u32 address;
	__u8 zero[8];
};

struct effect_sockaddr_in6 {
	__u16 family;
	__u16 port;
	__u32 flowinfo;
	__u8 address[16];
	__u32 scope_id;
};

struct task_struct {
	__u64 start_boottime;
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

/* Deployment mode registers only stable cgroup-v2 roots here.  The helper
 * follows kernel ancestry for the current task, so a child created and removed
 * entirely between userspace barriers remains observable.  Exact standalone
 * mode leaves root_count zero and retains its single HASH lookup fast path.
 */
struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__uint(max_entries, EFFECT_MAX_ANCESTOR_ROOTS);
	__type(key, __u32);
	__type(value, __u32);
} effect_roots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, EFFECT_MAX_ANCESTOR_ROOTS);
	__type(key, __u32);
	__type(value, __u64);
} effect_root_ids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct effect_ancestor_config);
} effect_root_cfg SEC(".maps");

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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EFFECT_MAX_PENDING);
	__type(key, __u64);
	__type(value, struct effect_socket_pending);
} effect_socket_objects SEC(".maps");

/* Expanded mode only.  Cookie ownership is introduced synchronously by a
 * directly attributed syscall object hook and consumed before any expensive
 * field reads on global TCP state tracepoints.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EFFECT_MAX_RUNS);
	__type(key, __u64);
	__type(value, struct effect_socket_state_run);
} effect_socket_state_runs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, EFFECT_MAX_SOCKET_OWNERS);
	__type(key, __u64);
	__type(value, struct effect_socket_owner);
} effect_socket_owners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EFFECT_SOCKET_STATE_RING_BYTES);
} effect_socket_state_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, EFFECT_RING_BYTES);
} effect_events SEC(".maps");

static __always_inline __u64 next_sequence(struct effect_run_state *run)
{
	return __sync_fetch_and_add(&run->next_event_seq, 1) + 1;
}

/* Returns the run state and writes the identity of the matched scope.  In
 * exact mode that identity is the caller's current cgroup ID.  In ancestor
 * mode it is the registered root ID; the current leaf ID is deliberately not
 * claimed by the v1 event ABI.
 */
static __always_inline struct effect_run_state *
effect_ancestor_run(__u32 index, __u64 *scope_cgroup_id)
{
	struct effect_run_state *run;
	__u64 *root_id;

	root_id = bpf_map_lookup_elem(&effect_root_ids, &index);
	if (!root_id || !*root_id)
		return 0;
	if (bpf_current_task_under_cgroup(&effect_roots, index) != 1)
		return 0;
	run = bpf_map_lookup_elem(&effect_runs, root_id);
	if (!run || !run->epoch)
		return 0;
	*scope_cgroup_id = *root_id;
	return run;
}

static __attribute__((noinline)) struct effect_run_state *
effect_current_run(__u64 *scope_cgroup_id)
{
	struct effect_ancestor_config *config;
	struct effect_run_state *run;
	__u64 current;
	__u32 zero = 0;

	current = bpf_get_current_cgroup_id();
	run = bpf_map_lookup_elem(&effect_runs, &current);
	if (run && run->epoch) {
		*scope_cgroup_id = current;
		return run;
	}
	config = bpf_map_lookup_elem(&effect_root_cfg, &zero);
	if (!config || !config->root_count ||
	    config->root_count > EFFECT_MAX_ANCESTOR_ROOTS)
		return 0;
	if (config->root_count > 0 &&
	    (run = effect_ancestor_run(0, scope_cgroup_id)))
		return run;
	if (config->root_count > 1 &&
	    (run = effect_ancestor_run(1, scope_cgroup_id)))
		return run;
	if (config->root_count > 2 &&
	    (run = effect_ancestor_run(2, scope_cgroup_id)))
		return run;
	if (config->root_count > 3 &&
	    (run = effect_ancestor_run(3, scope_cgroup_id)))
		return run;
	if (config->root_count > 4 &&
	    (run = effect_ancestor_run(4, scope_cgroup_id)))
		return run;
	if (config->root_count > 5 &&
	    (run = effect_ancestor_run(5, scope_cgroup_id)))
		return run;
	if (config->root_count > 6 &&
	    (run = effect_ancestor_run(6, scope_cgroup_id)))
		return run;
	if (config->root_count > 7 &&
	    (run = effect_ancestor_run(7, scope_cgroup_id)))
		return run;
	return 0;
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
	event->task_start_boottime_ns = pending->task_start_boottime_ns;
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

static __always_inline void publish_socket_result(
	struct effect_run_state *run,
	const struct effect_pending_call *pending,
	const struct effect_socket_identity *object, __u64 event_seq,
	__u64 pid_tgid, __s64 return_value)
{
	struct effect_socket_event *event;

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

static __always_inline void mark_object_flag(
	struct effect_run_state *run, struct effect_pending_call *pending,
	__u32 flag);

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

static __always_inline int is_file_permission_read_resolver(
	const struct effect_pending_call *pending)
{
	return pending->object_resolver ==
		       EFFECT_OBJECT_RESOLVER_FILE_PERMISSION_READ &&
	       pending->domain == 7 && pending->operation == 21;
}

static __always_inline int is_file_permission_resolver(
	const struct effect_pending_call *pending)
{
	return is_file_permission_write_resolver(pending) ||
	       is_file_permission_read_resolver(pending);
}

static __always_inline int is_file_resolver(
	const struct effect_pending_call *pending, __u32 resolver)
{
	return pending->object_resolver == resolver && pending->domain == 1;
}

static __always_inline int is_socket_resolver(
	const struct effect_pending_call *pending, __u32 resolver)
{
	return pending->object_resolver == resolver && pending->domain == 2;
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
	if (is_file_permission_read_resolver(pending))
		return config->resolver_mask &
		       EFFECT_OBJECT_RESOLVE_FILE_PERMISSION_READ;
	if (is_file_resolver(pending,
			     EFFECT_OBJECT_RESOLVER_PATH_CREATE_PARENT))
		return config->resolver_mask &
		       EFFECT_OBJECT_RESOLVE_PATH_CREATE_PARENT;
	if (is_file_resolver(pending, EFFECT_OBJECT_RESOLVER_PATH_UNLINK))
		return config->resolver_mask & EFFECT_OBJECT_RESOLVE_PATH_UNLINK;
	if (is_file_resolver(pending,
			     EFFECT_OBJECT_RESOLVER_PATH_RENAME_SOURCE))
		return config->resolver_mask &
		       EFFECT_OBJECT_RESOLVE_PATH_RENAME_SOURCE;
	if (is_file_resolver(pending,
			     EFFECT_OBJECT_RESOLVER_PATH_LINK_SOURCE))
		return config->resolver_mask &
		       EFFECT_OBJECT_RESOLVE_PATH_LINK_SOURCE;
	if (is_file_resolver(pending, EFFECT_OBJECT_RESOLVER_PATH_SETATTR))
		return config->resolver_mask & EFFECT_OBJECT_RESOLVE_PATH_SETATTR;
	if (is_file_resolver(pending, EFFECT_OBJECT_RESOLVER_INODE_XATTR))
		return config->resolver_mask & EFFECT_OBJECT_RESOLVE_INODE_XATTR;
	if (is_file_resolver(pending, EFFECT_OBJECT_RESOLVER_MMAP_FILE_WRITE))
		return config->resolver_mask &
		       EFFECT_OBJECT_RESOLVE_MMAP_FILE_WRITE;
	if (is_file_resolver(pending,
			     EFFECT_OBJECT_RESOLVER_MPROTECT_FILE_WRITE))
		return config->resolver_mask &
		       EFFECT_OBJECT_RESOLVE_MPROTECT_FILE_WRITE;
	if (is_socket_resolver(pending, EFFECT_OBJECT_RESOLVER_SOCKET_CONNECT))
		return config->resolver_mask & EFFECT_OBJECT_RESOLVE_SOCKET_CONNECT;
	if (is_socket_resolver(pending, EFFECT_OBJECT_RESOLVER_SOCKET_BIND))
		return config->resolver_mask & EFFECT_OBJECT_RESOLVE_SOCKET_BIND;
	if (is_socket_resolver(pending, EFFECT_OBJECT_RESOLVER_SOCKET_ACCEPT))
		return config->resolver_mask & EFFECT_OBJECT_RESOLVE_SOCKET_ACCEPT;
	return 0;
}

static __always_inline int mmap_file_write_eligible(
	const struct effect_pending_call *pending)
{
	return pending->object_resolver ==
		       EFFECT_OBJECT_RESOLVER_MMAP_FILE_WRITE &&
	       (pending->args[2] & EFFECT_PROT_WRITE) &&
	       (pending->args[3] & EFFECT_MAP_SHARED) &&
	       !(pending->args[3] & EFFECT_MAP_ANONYMOUS);
}

static __always_inline int mprotect_file_write_eligible(
	const struct effect_pending_call *pending)
{
	return pending->object_resolver ==
		       EFFECT_OBJECT_RESOLVER_MPROTECT_FILE_WRITE &&
	       (pending->args[2] & EFFECT_PROT_WRITE);
}

static __attribute__((noinline)) int record_file_identity(
	struct effect_pending_call *pending, struct effect_run_state *run,
	struct inode *inode, struct vfsmount *vfsmount)
{
	struct effect_file_pending *existing;
	struct effect_file_pending resolved;
	struct super_block *super_block = 0;
	struct mount *mount = 0;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 device = 0;
	long error = 0;

	existing = bpf_map_lookup_elem(&effect_file_objects, &pid_tgid);
	if (existing) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return 0;
	}
	__builtin_memset(&resolved, 0, sizeof(resolved));
	if (!inode) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return 0;
	}
	error |= bpf_core_read(&super_block, sizeof(super_block), &inode->i_sb);
	if (!super_block)
		error = -1;
	if (!error && vfsmount) {
		mount = (struct mount *)((char *)vfsmount -
			bpf_core_field_offset(struct mount, mnt));
		error |= bpf_core_read(&resolved.object.mount_id_unique,
				       sizeof(resolved.object.mount_id_unique),
				       &mount->mnt_id_unique);
	}
	if (!error) {
		error |= bpf_core_read(&resolved.object.inode,
				       sizeof(resolved.object.inode), &inode->i_ino);
		error |= bpf_core_read(&resolved.object.inode_generation,
				       sizeof(resolved.object.inode_generation),
				       &inode->i_generation);
		error |= bpf_core_read(&resolved.object.filesystem_magic,
				       sizeof(resolved.object.filesystem_magic),
				       &super_block->s_magic);
		error |= bpf_core_read(&device, sizeof(device), &super_block->s_dev);
	}
	if (error || !resolved.object.inode ||
	    !resolved.object.filesystem_magic ||
	    (pending->object_resolver != EFFECT_OBJECT_RESOLVER_INODE_XATTR &&
	     !resolved.object.mount_id_unique)) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return 0;
	}
	resolved.object.device_major = device >> 20;
	resolved.object.device_minor = device & ((1U << 20) - 1);
	resolved.object.generation_valid = resolved.object.inode_generation != 0;
	resolved.object.path_quality = EFFECT_FILE_PATH_NOT_REQUESTED;
	resolved.epoch = pending->epoch;
	resolved.cgroup_id = pending->cgroup_id;
	resolved.attempt_seq = pending->attempt_seq;
	if (bpf_map_update_elem(&effect_file_objects, &pid_tgid, &resolved,
				BPF_NOEXIST) != 0) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return 0;
	}
	__sync_fetch_and_add(&run->object_pending_remaining, 1);
	return 0;
}

static __always_inline struct effect_pending_call *
gated_object_pending(__u32 resolver, struct effect_run_state **run_out)
{
	struct effect_object_config *config;
	struct effect_pending_call *pending;
	struct effect_run_state *run;
	__u64 pid_tgid;
	__u32 config_key = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!pending || pending->object_resolver != resolver)
		return 0;
	/* Scope membership authority is the sys_enter gate which created this
	 * same-pid_tgid pending record.  Object hooks join to that immutable
	 * matched root and epoch; they must not re-run an ancestor predicate (and
	 * sleepable BPF LSM programs cannot reference CGROUP_ARRAY maps).
	 */
	run = bpf_map_lookup_elem(&effect_runs, &pending->cgroup_id);
	if (!run || !run->epoch || run->epoch != pending->epoch)
		return 0;
	config = bpf_map_lookup_elem(&effect_object_config, &config_key);
	if (!config || !object_resolver_enabled(pending, config))
		return 0;
	*run_out = run;
	return pending;
}

/* Fixed-resolver hooks must not pay for object_resolver_enabled()'s complete
 * resolver switch on every invocation. The pending resolver equality remains
 * authenticated, while the caller supplies its compile-time mask bit.
 */
static __always_inline struct effect_pending_call *
gated_object_pending_mask(__u32 resolver, __u32 resolver_mask,
			   struct effect_run_state **run_out)
{
	struct effect_object_config *config;
	struct effect_pending_call *pending;
	struct effect_run_state *run;
	__u64 pid_tgid;
	__u32 config_key = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!pending || pending->object_resolver != resolver)
		return 0;
	run = bpf_map_lookup_elem(&effect_runs, &pending->cgroup_id);
	if (!run || !run->epoch || run->epoch != pending->epoch)
		return 0;
	config = bpf_map_lookup_elem(&effect_object_config, &config_key);
	if (!config || !(config->resolver_mask & resolver_mask))
		return 0;
	*run_out = run;
	return pending;
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
	else if (flag == EFFECT_F_OBJECT_UNSUPPORTED)
		__sync_fetch_and_add(&run->object_unsupported, 1);
}

static __attribute__((noinline)) int record_selected_enter(
	struct effect_sys_enter *ctx, struct effect_syscall_policy *policy,
	struct effect_run_state *run, __u64 cgroup_id)
{
	struct effect_pending_call *existing;
	struct effect_pending_call pending = {};
	struct task_struct *task;
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
	if (pending.object_resolver > EFFECT_OBJECT_RESOLVER_FILE_PERMISSION_READ)
		pending.flags |= EFFECT_F_POLICY_INVALID;
	pending.args[0] = ctx->arg0;
	pending.args[1] = ctx->arg1;
	pending.args[2] = ctx->arg2;
	pending.args[3] = ctx->arg3;
	pending.args[4] = ctx->arg4;
	pending.args[5] = ctx->arg5;
	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task ||
	    bpf_core_read(&pending.task_start_boottime_ns,
			  sizeof(pending.task_start_boottime_ns),
			  &task->start_boottime) ||
	    !pending.task_start_boottime_ns) {
		pending.task_start_boottime_ns = 0;
		pending.flags |= EFFECT_F_TASK_READ_FAILED;
		__sync_fetch_and_add(&run->task_read_failed, 1);
	}

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
	run = effect_current_run(&cgroup_id);
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
/* file_post_open runs after the filesystem ->open callback.  Unlike
 * file_open, it is not re-entered by overlayfs backing_file_open(), whose
 * internal vfs_open() deliberately bypasses this path-level post hook.  The
 * object captured here is therefore the struct file returned to the caller,
 * without relying on the version-private numeric value of FMODE_BACKING.
 */
SEC("lsm.s/file_post_open")
int BPF_PROG(trace_effect_file_post_open_object, struct file *file, int mask,
	     int ret)
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
	__u64 pid_tgid;
	__u32 config_key = 0;
	__u32 device = 0;
	long path_length;
	long error = 0;

	(void)ctx;
	(void)mask;
	if (ret)
		return ret;
	pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!pending || !is_file_open_resolver(pending))
		return ret;
	/* `pending` was created only after sys_enter proved exact/root scope
	 * membership.  Same-thread PID/TGID plus root/epoch/attempt is the strict
	 * join authority here and keeps this sleepable program's call graph free
	 * of CGROUP_ARRAY.
	 */
	run = bpf_map_lookup_elem(&effect_runs, &pending->cgroup_id);
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

/* Resolve the struct file actually checked by the selected VFS read/write path.
 * The read hook is separately enabled only for the opt-in file-access profile.
 * file_permission is not
 * a sleepable LSM hook, so this program deliberately records the stable
 * mount/device/inode identity without calling bpf_d_path. Operation and exact
 * cgroup selection precede every object field read.
 */
static __always_inline int record_file_permission_object(
	struct file *file, int ret, int read_side)
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
	__u64 pid_tgid;
	__u32 config_key = 0;
	__u32 device = 0;
	long error = 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!pending || !(read_side ? is_file_permission_read_resolver(pending) :
			 is_file_permission_write_resolver(pending)))
		return ret;
	run = bpf_map_lookup_elem(&effect_runs, &pending->cgroup_id);
	if (!run || !run->epoch || pending->epoch != run->epoch)
		return ret;
	config = bpf_map_lookup_elem(&effect_object_config, &config_key);
	if (!config || !(config->resolver_mask &
			 (read_side ? EFFECT_OBJECT_RESOLVE_FILE_PERMISSION_READ :
			  EFFECT_OBJECT_RESOLVE_FILE_PERMISSION_WRITE)))
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

static __attribute__((noinline)) int record_file_permission(
	struct file *file, int ret)
{
	return record_file_permission_object(file, ret, 0);
}

static __attribute__((noinline)) int record_file_permission_read(
	struct file *file, int ret)
{
	return record_file_permission_object(file, ret, 1);
}

SEC("lsm/file_permission")
int BPF_PROG(trace_effect_file_permission, struct file *file, int mask, int ret)
{
	(void)ctx;
	if (ret || !(mask & EFFECT_MAY_WRITE))
		return ret;
	return record_file_permission(file, ret);
}

/* Keep read-side object work out of legacy profiles, including their global
 * LSM fast path. Userspace disables autoload and attachment unless both the
 * file-access profile and a read-capable object-resolution mode are selected.
 */
SEC("lsm/file_permission")
int BPF_PROG(trace_effect_file_permission_read, struct file *file, int mask, int ret)
{
	(void)ctx;
	if (ret || !(mask & EFFECT_MAY_READ))
		return ret;
	return record_file_permission_read(file, ret);
}

static __attribute__((noinline)) int record_path_object(
	__u32 resolver, const struct path *path, struct dentry *target, int ret)
{
	struct effect_pending_call *pending;
	struct effect_run_state *run = 0;
	struct vfsmount *vfsmount = 0;
	struct dentry *dentry = target;
	struct inode *inode = 0;
	long error = 0;

	if (ret)
		return ret;
	pending = gated_object_pending(resolver, &run);
	if (!pending)
		return ret;
	/* No path, dentry, or inode field is read before the exact run gate. */
	error |= bpf_core_read(&vfsmount, sizeof(vfsmount), &path->mnt);
	if (!dentry)
		error |= bpf_core_read(&dentry, sizeof(dentry), &path->dentry);
	if (dentry)
		error |= bpf_core_read(&inode, sizeof(inode), &dentry->d_inode);
	if (error || !vfsmount || !inode) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return ret;
	}
	record_file_identity(pending, run, inode, vfsmount);
	return ret;
}

SEC("lsm/path_mkdir")
int BPF_PROG(trace_effect_path_mkdir, const struct path *dir,
	     struct dentry *dentry, unsigned short mode, int ret)
{
	(void)ctx;
	(void)dentry;
	(void)mode;
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_CREATE_PARENT,
				  dir, 0, ret);
}

SEC("lsm/path_symlink")
int BPF_PROG(trace_effect_path_symlink, const struct path *dir,
	     struct dentry *dentry, const char *old_name, int ret)
{
	(void)ctx;
	(void)dentry;
	(void)old_name;
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_CREATE_PARENT,
				  dir, 0, ret);
}

SEC("lsm/path_mknod")
int BPF_PROG(trace_effect_path_mknod, const struct path *dir,
	     struct dentry *dentry, unsigned short mode, unsigned int dev,
	     int ret)
{
	(void)ctx;
	(void)dentry;
	(void)mode;
	(void)dev;
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_CREATE_PARENT,
				  dir, 0, ret);
}

SEC("lsm/path_unlink")
int BPF_PROG(trace_effect_path_unlink, const struct path *dir,
	     struct dentry *dentry, int ret)
{
	(void)ctx;
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_UNLINK, dir,
				  dentry, ret);
}

SEC("lsm/path_rmdir")
int BPF_PROG(trace_effect_path_rmdir, const struct path *dir,
	     struct dentry *dentry, int ret)
{
	(void)ctx;
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_UNLINK, dir,
				  dentry, ret);
}

SEC("lsm/path_rename")
int BPF_PROG(trace_effect_path_rename, const struct path *old_dir,
	     struct dentry *old_dentry, const struct path *new_dir,
	     struct dentry *new_dentry, unsigned int flags, int ret)
{
	(void)ctx;
	(void)new_dir;
	(void)new_dentry;
	(void)flags;
	/* The source object is authoritative. Destination pathname remains the
	 * independently captured syscall argument and is not promoted to object.
	 */
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_RENAME_SOURCE,
				  old_dir, old_dentry, ret);
}

SEC("lsm/path_link")
int BPF_PROG(trace_effect_path_link, struct dentry *old_dentry,
	     const struct path *new_dir, struct dentry *new_dentry, int ret)
{
	(void)ctx;
	(void)new_dentry;
	/* Hard links cannot cross mounts. Pairing the source inode with the
	 * destination directory's mount yields the source object identity in the
	 * mount where the new directory entry was requested. The new child itself
	 * is intentionally not claimed by this pre-operation hook.
	 */
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_LINK_SOURCE,
				  new_dir, old_dentry, ret);
}

SEC("lsm/path_chmod")
int BPF_PROG(trace_effect_path_chmod, const struct path *path,
	     unsigned short mode, int ret)
{
	(void)ctx;
	(void)mode;
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_SETATTR, path, 0,
				  ret);
}

SEC("lsm/path_chown")
int BPF_PROG(trace_effect_path_chown, const struct path *path,
	     unsigned int uid, unsigned int gid, int ret)
{
	(void)ctx;
	(void)uid;
	(void)gid;
	return record_path_object(EFFECT_OBJECT_RESOLVER_PATH_SETATTR, path, 0,
				  ret);
}

static __attribute__((noinline)) int record_inode_xattr_object(
	struct dentry *dentry, int ret)
{
	struct effect_pending_call *pending;
	struct effect_run_state *run = 0;
	struct inode *inode = 0;

	if (ret)
		return ret;
	pending = gated_object_pending(EFFECT_OBJECT_RESOLVER_INODE_XATTR, &run);
	if (!pending)
		return ret;
	if (bpf_core_read(&inode, sizeof(inode), &dentry->d_inode) || !inode) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return ret;
	}
	/* inode xattr hooks have no vfsmount argument. The emitted identity is
	 * explicitly device+inode+generation scoped and never invents a mount ID.
	 */
	record_file_identity(pending, run, inode, 0);
	return ret;
}

SEC("lsm/inode_setxattr")
int BPF_PROG(trace_effect_inode_setxattr, void *idmap, struct dentry *dentry,
	     const char *name, const void *value, unsigned long size, int flags,
	     int ret)
{
	(void)ctx;
	(void)idmap;
	(void)name;
	(void)value;
	(void)size;
	(void)flags;
	return record_inode_xattr_object(dentry, ret);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(trace_effect_inode_removexattr, void *idmap,
	     struct dentry *dentry, const char *name, int ret)
{
	(void)ctx;
	(void)idmap;
	(void)name;
	return record_inode_xattr_object(dentry, ret);
}

SEC("lsm/mmap_file")
int BPF_PROG(trace_effect_mmap_file, struct file *file,
	     unsigned long reqprot, unsigned long prot, unsigned long flags,
	     int ret)
{
	struct effect_pending_call *pending;
	struct effect_run_state *run = 0;
	struct vfsmount *vfsmount = 0;
	struct inode *inode = 0;

	(void)ctx;
	(void)reqprot;
	(void)prot;
	(void)flags;
	if (ret || !file)
		return ret;
	pending = gated_object_pending_mask(
		EFFECT_OBJECT_RESOLVER_MMAP_FILE_WRITE,
		EFFECT_OBJECT_RESOLVE_MMAP_FILE_WRITE, &run);
	if (!pending || !mmap_file_write_eligible(pending))
		return ret;
	if (bpf_core_read(&inode, sizeof(inode), &file->f_inode) ||
	    bpf_core_read(&vfsmount, sizeof(vfsmount), &file->f_path.mnt) ||
	    !inode || !vfsmount) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return ret;
	}
	record_file_identity(pending, run, inode, vfsmount);
	return ret;
}

/* mprotect may span several VMAs and file_mprotect runs once per VMA.  The
 * fixed object frame can make a complete claim only for one shared VMA backed
 * by one struct file. Anonymous/private or mixed ranges are explicitly
 * UNSUPPORTED; two eligible file VMAs become AMBIGUOUS through the existing
 * BPF_NOEXIST join. This is permission-channel evidence, never proof that a
 * page was subsequently dirtied.
 */
SEC("lsm/file_mprotect")
int BPF_PROG(trace_effect_file_mprotect, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot, int ret)
{
	struct effect_pending_call *pending;
	struct effect_run_state *run = 0;
	struct vfsmount *vfsmount = 0;
	struct file *file = 0;
	struct inode *inode = 0;
	unsigned long vm_flags = 0;
	long error = 0;

	(void)ctx;
	(void)reqprot;
	if (ret)
		return ret;
	pending = gated_object_pending_mask(
		EFFECT_OBJECT_RESOLVER_MPROTECT_FILE_WRITE,
		EFFECT_OBJECT_RESOLVE_MPROTECT_FILE_WRITE, &run);
	if (!pending || !mprotect_file_write_eligible(pending))
		return ret;
	/* The syscall-entry filter and LSM hook must agree that write permission
	 * was requested. A disagreement is evidence failure, not unsupported input.
	 */
	if (!(prot & EFFECT_PROT_WRITE)) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return ret;
	}
	error |= bpf_core_read(&file, sizeof(file), &vma->vm_file);
	error |= bpf_core_read(&vm_flags, sizeof(vm_flags), &vma->vm_flags);
	if (error) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return ret;
	}
	if (!file || !(vm_flags & EFFECT_VM_SHARED)) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_UNSUPPORTED);
		return ret;
	}
	error |= bpf_core_read(&inode, sizeof(inode), &file->f_inode);
	error |= bpf_core_read(&vfsmount, sizeof(vfsmount), &file->f_path.mnt);
	if (error || !inode || !vfsmount) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return ret;
	}
	record_file_identity(pending, run, inode, vfsmount);
	return ret;
}

static __always_inline int socket_state_supported(
	const struct effect_socket_identity *object)
{
	return (object->address_family == EFFECT_AF_INET ||
		object->address_family == EFFECT_AF_INET6) &&
	       object->socket_type == EFFECT_SOCK_STREAM &&
	       object->protocol == EFFECT_IPPROTO_TCP;
}

static __always_inline struct effect_socket_state_run *
socket_state_run(const struct effect_pending_call *pending)
{
	struct effect_socket_state_run *state;

	state = bpf_map_lookup_elem(&effect_socket_state_runs,
				    &pending->cgroup_id);
	if (!state || !state->epoch || state->epoch != pending->epoch)
		return 0;
	return state;
}

static __attribute__((noinline)) int register_socket_owner(
	const struct effect_pending_call *pending,
	const struct effect_socket_identity *object, __u32 provisional)
{
	struct effect_socket_state_run *state;
	struct effect_socket_owner *existing;
	struct effect_socket_owner owner = {};
	__u64 cookie = object->socket_cookie;

	state = socket_state_run(pending);
	if (!state)
		return 0;
	if (!socket_state_supported(object)) {
		__sync_fetch_and_add(&state->unsupported_sockets, 1);
		return 0;
	}
	existing = bpf_map_lookup_elem(&effect_socket_owners, &cookie);
	if (existing) {
		/* Preserve the first directly attributed operation in this run. A
		 * later connect on an explicitly bound socket does not weaken that
		 * boot/cgroup/epoch/process ownership proof.
		 */
		if (existing->epoch == pending->epoch &&
		    existing->cgroup_id == pending->cgroup_id)
			return 0;
		__sync_fetch_and_add(&state->owner_conflict, 1);
		return 0;
	}
	owner.epoch = pending->epoch;
	owner.cgroup_id = pending->cgroup_id;
	owner.origin_attempt_seq = pending->attempt_seq;
	owner.origin_pid_tgid = bpf_get_current_pid_tgid();
	owner.origin_task_start_boottime_ns =
		pending->task_start_boottime_ns;
	owner.origin_operation = pending->operation;
	if (provisional)
		owner.flags = EFFECT_SOCKET_STATE_F_OWNER_PROVISIONAL;
	if (bpf_map_update_elem(&effect_socket_owners, &cookie, &owner,
				BPF_NOEXIST) != 0) {
		__sync_fetch_and_add(&state->owner_insert_failed, 1);
		return 0;
	}
	__sync_fetch_and_add(&state->owner_remaining, 1);
	return 0;
}

static __always_inline void complete_socket_owner(
	const struct effect_pending_call *pending,
	const struct effect_socket_identity *object, long result)
{
	struct effect_socket_state_run *state;
	struct effect_socket_owner *owner;
	__u64 cookie = object->socket_cookie;
	int retain;

	if (!socket_state_supported(object))
		return;
	state = socket_state_run(pending);
	if (!state)
		return;
	owner = bpf_map_lookup_elem(&effect_socket_owners, &cookie);
	/* An earlier bind owner is intentionally retained and is not finalized by
	 * a later connect result.
	 */
	if (!owner || owner->epoch != pending->epoch ||
	    owner->cgroup_id != pending->cgroup_id ||
	    owner->origin_attempt_seq != pending->attempt_seq)
		return;
	retain = result >= 0;
	if (pending->object_resolver == EFFECT_OBJECT_RESOLVER_SOCKET_CONNECT &&
	    (result == -EFFECT_EINPROGRESS || result == -EFFECT_EALREADY ||
	     result == -EFFECT_EISCONN))
		retain = 1;
	if (retain) {
		owner->flags &= ~EFFECT_SOCKET_STATE_F_OWNER_PROVISIONAL;
		return;
	}
	if (bpf_map_delete_elem(&effect_socket_owners, &cookie) != 0) {
		__sync_fetch_and_add(&state->owner_delete_failed, 1);
		return;
	}
	if (state->owner_remaining)
		__sync_fetch_and_sub(&state->owner_remaining, 1);
	else
		__sync_fetch_and_add(&state->owner_conflict, 1);
}

struct effect_socket_state_spec {
	__u32 old_state;
	__u32 new_state;
	__u16 kind;
	__u16 reserved;
};

static __attribute__((noinline)) long fill_socket_state(
	struct effect_socket_state_event *event, struct sock *sk,
	const struct effect_socket_owner *owner, __u64 socket_cookie,
	const struct effect_socket_state_spec *spec)
{
	struct net *net = 0;
	__u32 ipv4 = 0;
	__u16 family = 0, socket_type = 0, protocol = 0;
	__u16 peer_port_network = 0;
	__u8 current_state = 0;
	long error = 0;

	__builtin_memset(event, 0, sizeof(*event));
	error |= bpf_core_read(&family, sizeof(family),
			       &sk->__sk_common.skc_family);
	error |= bpf_core_read(&socket_type, sizeof(socket_type), &sk->sk_type);
	error |= bpf_core_read(&protocol, sizeof(protocol), &sk->sk_protocol);
	error |= bpf_core_read(&current_state, sizeof(current_state),
			       &sk->__sk_common.skc_state);
	error |= bpf_core_read(&net, sizeof(net), &sk->__sk_common.skc_net.net);
	if (net)
		error |= bpf_core_read(&event->network_namespace_cookie,
				       sizeof(event->network_namespace_cookie),
				       &net->net_cookie);
	else
		error = -1;
	error |= bpf_core_read(&event->local_port, sizeof(event->local_port),
			       &sk->__sk_common.skc_num);
	error |= bpf_core_read(&peer_port_network, sizeof(peer_port_network),
			       &sk->__sk_common.skc_dport);
	if (family == EFFECT_AF_INET) {
		error |= bpf_core_read(&ipv4, sizeof(ipv4),
				       &sk->__sk_common.skc_rcv_saddr);
		__builtin_memcpy(event->local_address, &ipv4, sizeof(ipv4));
		error |= bpf_core_read(&ipv4, sizeof(ipv4),
				       &sk->__sk_common.skc_daddr);
		__builtin_memcpy(event->peer_address, &ipv4, sizeof(ipv4));
	} else if (family == EFFECT_AF_INET6) {
		error |= bpf_core_read(
			event->local_address, sizeof(event->local_address),
			&sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		error |= bpf_core_read(
			event->peer_address, sizeof(event->peer_address),
			&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} else {
		error = -1;
	}
	if (error || !socket_cookie || !event->network_namespace_cookie ||
	    socket_type != EFFECT_SOCK_STREAM || protocol != EFFECT_IPPROTO_TCP ||
	    current_state < 1 || current_state > 12)
		return -1;
	if (spec->kind == EFFECT_SOCKET_STATE_TRANSITION &&
	    (spec->old_state < 1 || spec->old_state > 12 ||
	     spec->new_state < 1 || spec->new_state > 12))
		return -1;

	event->schema_version = EFFECT_SOCKET_STATE_SCHEMA_VERSION;
	event->kind = spec->kind;
	event->flags = (__u16)owner->flags;
	if (spec->kind != EFFECT_SOCKET_STATE_TRANSITION)
		event->flags = 0;
	event->run_epoch = owner->epoch;
	event->ktime_ns = bpf_ktime_get_ns();
	event->cgroup_id = owner->cgroup_id;
	event->origin_attempt_seq = owner->origin_attempt_seq;
	event->origin_pid_tgid = owner->origin_pid_tgid;
	event->origin_task_start_boottime_ns =
		owner->origin_task_start_boottime_ns;
	event->socket_cookie = socket_cookie;
	event->address_family = family;
	event->socket_type = socket_type;
	event->protocol = protocol;
	event->origin_operation = owner->origin_operation;
	event->peer_port = bpf_ntohs(peer_port_network);
	if (spec->kind == EFFECT_SOCKET_STATE_ACCEPT_SNAPSHOT) {
		event->old_state = 0;
		event->new_state = current_state;
	} else if (spec->kind == EFFECT_SOCKET_STATE_DESTROY) {
		event->old_state = current_state;
		event->new_state = 0;
	} else {
		event->old_state = spec->old_state;
		event->new_state = spec->new_state;
	}
	return 0;
}

static __attribute__((noinline)) int publish_socket_state(
	struct sock *sk, const struct effect_socket_owner *owner,
	__u64 socket_cookie, const struct effect_socket_state_spec *spec)
{
	struct effect_socket_state_run *state;
	struct effect_socket_state_event prepared;
	struct effect_socket_state_event *event;
	__u64 sequence;

	state = bpf_map_lookup_elem(&effect_socket_state_runs,
				    &owner->cgroup_id);
	if (!state || !state->epoch || state->epoch != owner->epoch)
		return 0;
	if (fill_socket_state(&prepared, sk, owner, socket_cookie, spec) != 0) {
		__sync_fetch_and_add(&state->state_read_failed, 1);
		return 0;
	}
	sequence = __sync_fetch_and_add(&state->next_event_seq, 1) + 1;
	prepared.event_seq = sequence;
	__sync_fetch_and_add(&state->event_attempted, 1);
	event = bpf_ringbuf_reserve(&effect_socket_state_events,
				    sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&state->event_dropped, 1);
		return 0;
	}
	*event = prepared;
	__sync_fetch_and_add(&state->event_published, 1);
	bpf_ringbuf_submit(event, 0);
	return 0;
}

static __attribute__((noinline)) int record_socket_object(
	__u32 resolver, struct socket *socket, const void *address, int addrlen,
	__u8 endpoint_role)
{
	struct effect_pending_call *pending;
	struct effect_socket_pending *existing;
	struct effect_socket_pending resolved;
	struct effect_run_state *run = 0;
	struct sock *sk = 0;
	struct net *net = 0;
	__u64 pid_tgid;
	__u32 retained;
	__u16 endpoint_family = 0, family = 0, socket_type = 0, protocol = 0;
	long error = 0;

	pending = gated_object_pending(resolver, &run);
	if (!pending)
		return 0;
	pid_tgid = bpf_get_current_pid_tgid();
	existing = bpf_map_lookup_elem(&effect_socket_objects, &pid_tgid);
	if (existing) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return 0;
	}
	if (!address || addrlen < 2) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return 0;
	}
	__builtin_memset(&resolved, 0, sizeof(resolved));
	/* socket is a trusted BTF argument of the LSM hook. A probe-read into a
	 * scalar erases that provenance and the verifier then rejects sk as the
	 * argument to bpf_get_socket_cookie(). Preserve the direct CO-RE pointer
	 * load; it remains strictly after the pending/cgroup/run/policy gate.
	 */
	sk = __builtin_preserve_access_index(socket->sk);
	if (!sk)
		error = -1;
	if (!error) {
		resolved.object.socket_cookie = bpf_get_socket_cookie(sk);
		error |= bpf_core_read(&family, sizeof(family),
				       &sk->__sk_common.skc_family);
		error |= bpf_core_read(&socket_type, sizeof(socket_type), &sk->sk_type);
		error |= bpf_core_read(&protocol, sizeof(protocol), &sk->sk_protocol);
		error |= bpf_core_read(&net, sizeof(net),
				       &sk->__sk_common.skc_net.net);
		if (net)
			error |= bpf_core_read(
				&resolved.object.network_namespace_cookie,
				sizeof(resolved.object.network_namespace_cookie),
				&net->net_cookie);
		else
			error = -1;
		resolved.object.address_family = family;
		resolved.object.socket_type = socket_type;
		resolved.object.protocol = protocol;
	}
	/* The signed LSM argument is rejected before conversion. Keep both arms
	 * verifier-provable: one exact 128-byte constant, or a value masked to
	 * 0..127 (and known >=2 from the early return). This retains the full
	 * endpoint buffer without passing a sign-extended scalar to the helper.
	 */
	if ((__u32)addrlen >= EFFECT_SOCKET_ENDPOINT_BYTES)
		retained = EFFECT_SOCKET_ENDPOINT_BYTES;
	else
		retained = ((__u32)addrlen) & (EFFECT_SOCKET_ENDPOINT_BYTES - 1);
	if ((__u32)addrlen > EFFECT_SOCKET_ENDPOINT_BYTES) {
		resolved.object.endpoint_quality =
			EFFECT_SOCKET_ENDPOINT_KERNEL_RESOLVED_TRUNCATED;
	} else {
		resolved.object.endpoint_quality =
			EFFECT_SOCKET_ENDPOINT_KERNEL_RESOLVED;
	}
	if (!error)
		error |= bpf_probe_read_kernel(resolved.object.endpoint, retained,
				       address);
	if (!error)
		error |= bpf_probe_read_kernel(&endpoint_family,
				       sizeof(endpoint_family), address);
	if (error || !resolved.object.socket_cookie ||
	    !resolved.object.network_namespace_cookie ||
	    !resolved.object.address_family || !resolved.object.socket_type) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return 0;
	}
	resolved.object.endpoint_len = (__u16)retained;
	resolved.object.endpoint_address_family = endpoint_family;
	resolved.object.endpoint_role = endpoint_role;
	resolved.object.endpoint_authority =
		EFFECT_SOCKET_ENDPOINT_LSM_ARGUMENT;
	resolved.epoch = pending->epoch;
	resolved.cgroup_id = pending->cgroup_id;
	resolved.attempt_seq = pending->attempt_seq;
	if (bpf_map_update_elem(&effect_socket_objects, &pid_tgid, &resolved,
				BPF_NOEXIST) != 0) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return 0;
	}
	__sync_fetch_and_add(&run->object_pending_remaining, 1);
	register_socket_owner(pending, &resolved.object, 1);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(trace_effect_socket_connect, struct socket *socket,
	     void *address, int addrlen, int ret)
{
	(void)ctx;
	if (!ret)
		record_socket_object(EFFECT_OBJECT_RESOLVER_SOCKET_CONNECT, socket,
				     address, addrlen,
				     EFFECT_SOCKET_ENDPOINT_PEER);
	return ret;
}

SEC("lsm/socket_bind")
int BPF_PROG(trace_effect_socket_bind, struct socket *socket, void *address,
	     int addrlen, int ret)
{
	(void)ctx;
	if (!ret)
		record_socket_object(EFFECT_OBJECT_RESOLVER_SOCKET_BIND, socket,
				     address, addrlen,
				     EFFECT_SOCKET_ENDPOINT_LOCAL);
	return ret;
}

static __attribute__((noinline)) struct sock *record_accepted_socket(
	struct file *accepted_file)
{
	struct effect_pending_call *pending;
	struct effect_socket_pending *existing;
	struct effect_socket_pending resolved;
	struct effect_socket_state_run *state;
	struct effect_run_state *run = 0;
	struct effect_sockaddr_in endpoint4 = {};
	struct effect_sockaddr_in6 endpoint6 = {};
	struct socket *socket;
	struct sock *sk;
	struct net *net = 0;
	__u64 pid_tgid;
	__u32 bound_device = 0;
	__u16 family = 0, socket_type = 0, protocol = 0;
	long error = 0;

	/* pending/run/config lookup is deliberately first. do_accept is also used
	 * by io_uring and kernel callers which are outside this native-syscall
	 * correlation contract.
	 */
	pending = gated_object_pending(EFFECT_OBJECT_RESOLVER_SOCKET_ACCEPT,
				       &run);
	if (!pending)
		return 0;
	/* Linux ERR_PTR values occupy the final 4095 unsigned pointer values;
	 * ordinary kernel pointers must not be classified using signed < 0.
	 */
	if (!accepted_file ||
	    (unsigned long)accepted_file >= (unsigned long)-4095)
		return 0;
	pid_tgid = bpf_get_current_pid_tgid();
	existing = bpf_map_lookup_elem(&effect_socket_objects, &pid_tgid);
	if (existing) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return 0;
	}
	socket = bpf_sock_from_file(accepted_file);
	if (!socket) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return 0;
	}
	sk = __builtin_preserve_access_index(socket->sk);
	if (!sk) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return 0;
	}
	__builtin_memset(&resolved, 0, sizeof(resolved));
	resolved.object.socket_cookie = bpf_get_socket_cookie(sk);
	error |= bpf_core_read(&family, sizeof(family),
			       &sk->__sk_common.skc_family);
	error |= bpf_core_read(&socket_type, sizeof(socket_type), &sk->sk_type);
	error |= bpf_core_read(&protocol, sizeof(protocol), &sk->sk_protocol);
	error |= bpf_core_read(&net, sizeof(net), &sk->__sk_common.skc_net.net);
	if (net)
		error |= bpf_core_read(
			&resolved.object.network_namespace_cookie,
			sizeof(resolved.object.network_namespace_cookie),
			&net->net_cookie);
	else
		error = -1;
	if (error || !resolved.object.socket_cookie ||
	    !resolved.object.network_namespace_cookie) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return 0;
	}
	resolved.object.address_family = family;
	resolved.object.socket_type = socket_type;
	resolved.object.protocol = protocol;
	if ((family != EFFECT_AF_INET && family != EFFECT_AF_INET6) ||
	    socket_type != EFFECT_SOCK_STREAM || protocol != EFFECT_IPPROTO_TCP) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_UNSUPPORTED);
		state = socket_state_run(pending);
		if (state)
			__sync_fetch_and_add(&state->unsupported_sockets, 1);
		return 0;
	}
	if (family == EFFECT_AF_INET) {
		endpoint4.family = EFFECT_AF_INET;
		error |= bpf_core_read(&endpoint4.port, sizeof(endpoint4.port),
				       &sk->__sk_common.skc_dport);
		error |= bpf_core_read(&endpoint4.address,
				       sizeof(endpoint4.address),
				       &sk->__sk_common.skc_daddr);
		__builtin_memcpy(resolved.object.endpoint, &endpoint4,
				 sizeof(endpoint4));
		resolved.object.endpoint_len = sizeof(endpoint4);
	} else {
		endpoint6.family = EFFECT_AF_INET6;
		error |= bpf_core_read(&endpoint6.port, sizeof(endpoint6.port),
				       &sk->__sk_common.skc_dport);
		error |= bpf_core_read(
			endpoint6.address, sizeof(endpoint6.address),
			&sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
		error |= bpf_core_read(&bound_device, sizeof(bound_device),
				       &sk->__sk_common.skc_bound_dev_if);
		endpoint6.scope_id = bound_device;
		__builtin_memcpy(resolved.object.endpoint, &endpoint6,
				 sizeof(endpoint6));
		resolved.object.endpoint_len = sizeof(endpoint6);
	}
	if (error) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_READ_FAILED);
		return 0;
	}
	resolved.object.endpoint_address_family = family;
	resolved.object.endpoint_role = EFFECT_SOCKET_ENDPOINT_PEER;
	resolved.object.endpoint_quality = EFFECT_SOCKET_ENDPOINT_KERNEL_RESOLVED;
	resolved.object.endpoint_authority = EFFECT_SOCKET_ENDPOINT_KERNEL_STATE;
	resolved.epoch = pending->epoch;
	resolved.cgroup_id = pending->cgroup_id;
	resolved.attempt_seq = pending->attempt_seq;
	if (bpf_map_update_elem(&effect_socket_objects, &pid_tgid, &resolved,
				BPF_NOEXIST) != 0) {
		mark_object_flag(run, pending, EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
		return 0;
	}
	__sync_fetch_and_add(&run->object_pending_remaining, 1);
	register_socket_owner(pending, &resolved.object, 0);
	return sk;
}

SEC("fexit/do_accept")
int BPF_PROG(trace_effect_do_accept_exit, struct file *listener,
	     struct proto_accept_arg *arg, void *peer_address,
	     int *peer_address_length, int flags, struct file *accepted_file)
{
	struct effect_socket_state_spec snapshot = {
		.kind = EFFECT_SOCKET_STATE_ACCEPT_SNAPSHOT,
	};
	struct effect_pending_call *pending;
	struct effect_socket_owner *owner;
	struct sock *sk;
	__u64 pid_tgid, cookie;

	(void)ctx;
	(void)listener;
	(void)arg;
	(void)peer_address;
	(void)peer_address_length;
	(void)flags;
	/* Publish after the large object-resolution stack frame has returned.
	 * Nesting publication and its reader under that frame exceeds the BPF
	 * cumulative 512-byte stack limit with the supported clang toolchain.
	 */
	sk = record_accepted_socket(accepted_file);
	if (!sk)
		return 0;
	pid_tgid = bpf_get_current_pid_tgid();
	pending = bpf_map_lookup_elem(&effect_pending, &pid_tgid);
	if (!pending)
		return 0;
	cookie = bpf_get_socket_cookie(sk);
	owner = bpf_map_lookup_elem(&effect_socket_owners, &cookie);
	if (owner && owner->epoch == pending->epoch &&
	    owner->cgroup_id == pending->cgroup_id &&
	    owner->origin_attempt_seq == pending->attempt_seq)
		publish_socket_state(sk, owner, cookie, &snapshot);
	return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(trace_effect_inet_sock_set_state, const struct sock *sk,
	     int old_state, int new_state)
{
	struct effect_socket_owner *stored;
	struct effect_socket_owner owner;
	struct effect_socket_state_spec transition = {
		.old_state = (__u32)old_state,
		.new_state = (__u32)new_state,
		.kind = EFFECT_SOCKET_STATE_TRANSITION,
	};
	__u64 socket_cookie;

	(void)ctx;
	/* Global TCP hook fast path: cookie plus one HASH miss precedes every
	 * socket field read, run lookup, allocation, and publication.
	 */
	socket_cookie = bpf_get_socket_cookie((struct sock *)sk);
	if (!socket_cookie)
		return 0;
	stored = bpf_map_lookup_elem(&effect_socket_owners, &socket_cookie);
	if (!stored)
		return 0;
	owner = *stored;
	return publish_socket_state((struct sock *)sk, &owner, socket_cookie,
				    &transition);
}

SEC("tp_btf/tcp_destroy_sock")
int BPF_PROG(trace_effect_tcp_destroy_sock, struct sock *sk)
{
	struct effect_socket_state_run *state;
	struct effect_socket_owner *stored;
	struct effect_socket_owner owner;
	struct effect_socket_state_spec destroy = {
		.kind = EFFECT_SOCKET_STATE_DESTROY,
	};
	__u64 socket_cookie;
	long delete_result;

	(void)ctx;
	/* Same global fast-path gate as inet_sock_set_state. */
	socket_cookie = bpf_get_socket_cookie(sk);
	if (!socket_cookie)
		return 0;
	stored = bpf_map_lookup_elem(&effect_socket_owners, &socket_cookie);
	if (!stored)
		return 0;
	owner = *stored;
	publish_socket_state(sk, &owner, socket_cookie, &destroy);
	state = bpf_map_lookup_elem(&effect_socket_state_runs,
				    &owner.cgroup_id);
	delete_result = bpf_map_delete_elem(&effect_socket_owners,
					    &socket_cookie);
	/* A failed provisional bind/connect can be removed by its syscall-exit
	 * path after this hook copied the owner. ENOENT then means that path
	 * already closed the ownership and decremented owner_remaining. Closing-
	 * barrier userspace retirement cannot race this hook: userspace first
	 * synchronously detaches this producer and its state-transition peer.
	 */
	if (delete_result == -EFFECT_ENOENT)
		return 0;
	if (delete_result != 0) {
		if (state && state->epoch == owner.epoch)
			__sync_fetch_and_add(&state->owner_delete_failed, 1);
		return 0;
	}
	if (state && state->epoch == owner.epoch) {
		if (state->owner_remaining)
			__sync_fetch_and_sub(&state->owner_remaining, 1);
		else
			__sync_fetch_and_add(&state->owner_conflict, 1);
	}
	return 0;
}

/* The legacy file-object modes deliberately use a separate exit program.  It
 * has no relocation against effect_socket_objects, so disabling that map is a
 * real load-time property rather than a promise that a runtime branch is cold.
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
	/* Most selected operations have no kernel-object resolver. Keep their
	 * expanded-mode exit path identical to the compact result path and avoid
	 * the object-config Map lookup and resolver chain entirely.
	 */
	if (pending.object_resolver == EFFECT_OBJECT_RESOLVER_NONE) {
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
	}
	/* Anonymous/private or otherwise ineligible mappings retain syscall
	 * history but need no object-config lookup or pending-object join.
	 */
	if (pending.object_resolver ==
		    EFFECT_OBJECT_RESOLVER_MMAP_FILE_WRITE &&
	    !mmap_file_write_eligible(&pending)) {
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
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

	if (is_file_permission_resolver(&pending) && ctx->ret <= 0) {
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

/* Expanded-object mode substitutes this handler for both legacy exit paths.
 * It is the only sys_exit program which references the socket pending map.
 */
SEC("tracepoint/raw_syscalls/sys_exit")
int trace_effect_expanded_exit(struct effect_sys_exit *ctx)
{
	struct effect_object_config *config;
	struct effect_file_pending *stored_object;
	struct effect_file_pending file_object;
	struct effect_socket_pending *stored_socket;
	struct effect_socket_pending socket_object;
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
	int socket_resolver = 0;

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
	/* Full profile selects all PROT_WRITE mmap calls for operation history,
	 * but object resolution is intentionally restricted to file-backed
	 * MAP_SHARED mappings. Reject ineligible calls before the object-config and
	 * pending-object lookups so ordinary anonymous/private mappings stay cheap
	 * and do not fabricate a missing-join failure.
	 */
	if (pending.object_resolver ==
		    EFFECT_OBJECT_RESOLVER_MMAP_FILE_WRITE &&
	    !mmap_file_write_eligible(&pending)) {
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
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
	socket_resolver =
		is_socket_resolver(&pending,
				   EFFECT_OBJECT_RESOLVER_SOCKET_CONNECT) ||
		is_socket_resolver(&pending, EFFECT_OBJECT_RESOLVER_SOCKET_BIND) ||
		is_socket_resolver(&pending, EFFECT_OBJECT_RESOLVER_SOCKET_ACCEPT);
	if (socket_resolver) {
		stored_socket = bpf_map_lookup_elem(&effect_socket_objects,
					    &pid_tgid);
		if (stored_socket) {
			object_present = 1;
			socket_object = *stored_socket;
			object_exact = socket_object.epoch == pending.epoch &&
				       socket_object.cgroup_id == pending.cgroup_id &&
				       socket_object.attempt_seq == object_attempt_seq;
			if (!object_exact)
				mark_object_flag(run, &pending,
						 EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
			if (bpf_map_delete_elem(&effect_socket_objects,
						&pid_tgid) == 0) {
				object_deleted = 1;
				object_run = bpf_map_lookup_elem(
					&effect_runs, &socket_object.cgroup_id);
				if (object_run &&
				    object_run->epoch == socket_object.epoch &&
				    object_run->object_pending_remaining)
					__sync_fetch_and_sub(
						&object_run->object_pending_remaining,
						1);
				else
					mark_object_flag(
						run, &pending,
						EFFECT_F_OBJECT_JOIN_AMBIGUOUS);
			} else {
				mark_object_flag(run, &pending,
						 EFFECT_F_OBJECT_DELETE_FAILED);
			}
		}
		__sync_fetch_and_add(&run->object_resolution_attempted, 1);
		if (pending.flags & EFFECT_F_OBJECT_UNSUPPORTED) {
			__sync_fetch_and_add(&run->object_resolution_unresolved, 1);
			event_seq = next_sequence(run);
			publish_result(run, &pending, event_seq, pid_tgid,
				       ctx->ret);
			return 0;
		}
		/* A pre-hook failure (bad FD/address, or an earlier LSM denial) has
		 * no object join to require.  Preserve it as an unresolved failed
		 * syscall.  EINPROGRESS and other negative results which did traverse
		 * the hook retain their resolved socket/request endpoint identity.
		 */
		if (ctx->ret < 0 && !object_present &&
		    !(pending.flags & (EFFECT_F_OBJECT_JOIN_AMBIGUOUS |
				       EFFECT_F_OBJECT_READ_FAILED |
				       EFFECT_F_OBJECT_DELETE_FAILED))) {
			__sync_fetch_and_add(
				&run->object_resolution_failed_syscalls, 1);
			__sync_fetch_and_add(&run->object_resolution_unresolved, 1);
			event_seq = next_sequence(run);
			publish_result(run, &pending, event_seq, pid_tgid,
				       ctx->ret);
			return 0;
		}
		if (!object_present &&
		    !(pending.flags & (EFFECT_F_OBJECT_JOIN_AMBIGUOUS |
				       EFFECT_F_OBJECT_READ_FAILED)))
			mark_object_flag(run, &pending,
					 EFFECT_F_OBJECT_JOIN_MISSING);
		if (!object_exact || !object_deleted ||
		    pending.flags &
			    (EFFECT_F_PENDING_MISSING |
			     EFFECT_F_PENDING_POISONED |
			     EFFECT_F_SYSCALL_MISMATCH |
			     EFFECT_F_OBJECT_JOIN_MISSING |
			     EFFECT_F_OBJECT_JOIN_AMBIGUOUS |
			     EFFECT_F_OBJECT_READ_FAILED |
			     EFFECT_F_OBJECT_DELETE_FAILED)) {
			__sync_fetch_and_add(&run->object_resolution_unresolved, 1);
			event_seq = next_sequence(run);
			publish_result(run, &pending, event_seq, pid_tgid,
				       ctx->ret);
			return 0;
		}
		complete_socket_owner(&pending, &socket_object.object, ctx->ret);
		__sync_fetch_and_add(&run->object_resolution_resolved, 1);
		event_seq = next_sequence(run);
		publish_socket_result(run, &pending, &socket_object.object,
				      event_seq, pid_tgid, ctx->ret);
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

	/* A zero-byte or failed FD read/write is outside the positive-byte object-
	 * resolution contract. The hook may have run for scalar zero-length writes,
	 * so its temporary join is still removed above, but no FILE_OBJECT identity
	 * is claimed and no statement about other side effects is made.
	 */
	if (is_file_permission_resolver(&pending) && ctx->ret <= 0) {
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
	}

	__sync_fetch_and_add(&run->object_resolution_attempted, 1);
	/* file_mprotect can cover anonymous/private or mixed VMA ranges.  Its LSM
	 * hook marks those ranges unsupported and any provisional single-file join
	 * has already been removed above. Preserve the syscall result without
	 * promoting an incomplete subset to a resolved object claim.
	 */
	/* Socket resolvers returned above; among the remaining file resolvers only
	 * file_mprotect can deliberately report UNSUPPORTED.
	 */
	/* File-permission reads/writes with nonpositive returns and ineligible mmap calls
	 * already returned before object accounting. Every remaining file resolver
	 * treats a negative syscall result as an unresolved failed operation. Share
	 * the unresolved publication tail with deliberate mprotect UNSUPPORTED.
	 */
	if ((pending.flags & EFFECT_F_OBJECT_UNSUPPORTED) || ctx->ret < 0) {
		if (!(pending.flags & EFFECT_F_OBJECT_UNSUPPORTED))
			__sync_fetch_and_add(
				&run->object_resolution_failed_syscalls, 1);
		__sync_fetch_and_add(&run->object_resolution_unresolved, 1);
		event_seq = next_sequence(run);
		publish_result(run, &pending, event_seq, pid_tgid, ctx->ret);
		return 0;
	}
	/* A successful selected open or positive-byte selected write is required to
	 * have traversed its declared object hook. In particular, O_PATH and
	 * O_TMPFILE currently lie outside this closed resolver contract because
	 * their namei branches bypass file_post_open. Until their disposition is
	 * captured and independently replayed, a missing join is fatal rather than
	 * guessed to be a legitimate partial result.
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
_Static_assert(sizeof(struct effect_event_header) == 160,
	       "compact event ABI changed");
_Static_assert(sizeof(struct effect_event) == 352,
	       "full event ABI changed");
_Static_assert(sizeof(struct effect_file_identity) == 176,
	       "file object identity ABI changed");
_Static_assert(sizeof(struct effect_file_event) == 336,
	       "file object event ABI changed");
	_Static_assert(sizeof(struct effect_file_pending) == 200,
	       "file object pending ABI changed");
	_Static_assert(sizeof(struct effect_socket_identity) == 176,
	       "socket object identity ABI changed");
	_Static_assert(sizeof(struct effect_socket_event) == 336,
	       "socket object event ABI changed");
	_Static_assert(sizeof(struct effect_socket_pending) == 200,
	       "socket object pending ABI changed");
_Static_assert(sizeof(struct effect_socket_owner) == 48,
	       "socket owner ABI changed");
_Static_assert(sizeof(struct effect_socket_state_event) == 152,
	       "socket state event ABI changed");
_Static_assert(sizeof(struct effect_socket_state_run) == 88,
	       "socket state run ABI changed");
_Static_assert(sizeof(struct effect_run_state) == 176,
	       "run state ABI changed");
_Static_assert(sizeof(struct effect_pending_call) == 96,
	       "pending state ABI changed");

char LICENSE[] SEC("license") = "GPL";
