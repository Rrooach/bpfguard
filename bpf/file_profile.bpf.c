// SPDX-License-Identifier: GPL-2.0-only
/* Explicit, bounded diagnostic mode. No buffers, paths or ring events.
 * Successful VFS bytes are not disk bytes; mmap maps, not actual accesses.
 */
#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "file_profile.h"

struct super_block { __u32 s_dev; } __attribute__((preserve_access_index));
struct inode {
	struct super_block *i_sb;
	unsigned long i_ino;
	__s64 i_size, i_mtime_sec, i_ctime_sec;
	__u32 i_mtime_nsec, i_ctime_nsec, i_generation;
} __attribute__((preserve_access_index));
struct vfsmount { int unused; } __attribute__((preserve_access_index));
struct mount { struct vfsmount mnt; __u64 mnt_id_unique;
} __attribute__((preserve_access_index));
struct path { struct vfsmount *mnt; void *dentry;
} __attribute__((preserve_access_index));
struct file { struct path f_path; struct inode *f_inode;
} __attribute__((preserve_access_index));
struct thread_info { __u32 status; } __attribute__((preserve_access_index));
struct task_struct {
	struct thread_info thread_info;
	struct task_struct *group_leader;
	__u64 start_boottime;
} __attribute__((preserve_access_index));
struct fp_enter { __u64 pad; __s64 nr; __u64 args[6]; };
struct fp_exit { __u64 pad; __s64 nr, ret; };
struct fp_call {
	struct fp_key object;
	__u64 start_ns;
	__s64 return_value;
	__u64 end_ns;
	__u32 object_valid;
	__u32 depth;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, __u32); __type(value, struct fp_config);
} fp_config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, FP_DOMAINS);
	__type(key, __u32); __type(value, struct fp_domain);
} fp_domains SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, FP_THREADS);
	__type(key, __u64); __type(value, struct fp_call);
} fp_calls SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, FP_THREADS);
	__type(key, __u64); __type(value, struct fp_call);
} fp_pending SEC(".maps");
/* Last observed unmatched interval for debugging, not an unbounded log. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, __u32); __type(value, struct fp_call);
} fp_pending_sample SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, FP_FILES);
	__type(key, struct fp_key); __type(value, struct fp_value);
} fp_files SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, FP_COUNTERS);
	__type(key, __u32); __type(value, __u64);
} fp_health SEC(".maps");

static __always_inline void health(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&fp_health, &index);
	if (value) ++*value;
}

static __always_inline __u64 domain(void)
{
	__u32 zero = 0;
	struct fp_config *config = bpf_map_lookup_elem(&fp_config, &zero);
	if (!config || !config->enabled) return 0;
	for (__u32 i = 0; i < FP_DOMAINS; ++i) {
		if (i >= config->count) break;
		struct fp_domain *root = bpf_map_lookup_elem(&fp_domains, &i);
		if (root && bpf_get_current_ancestor_cgroup_id(root->level) == root->cgroup_id)
			return root->cgroup_id;
	}
	return 0;
}

static __always_inline int operation(__s64 nr)
{
	if (nr == 0 || nr == 17) return FP_READ;
	if (nr == 19 || nr == 295 || nr == 327) return FP_READV;
	if (nr == 78 || nr == 217) return FP_DIRECTORY;
	if (nr == 9) return FP_MMAP;
	return -1;
}

static __always_inline int file_identity(struct fp_key *key, struct file *file)
{
	struct inode *inode = 0;
	struct super_block *sb = 0;
	struct vfsmount *mnt = 0;
	int error = bpf_core_read(&inode, sizeof(inode), &file->f_inode);
	if (error || !inode) return -1;
	error |= bpf_core_read(&sb, sizeof(sb), &inode->i_sb);
	error |= bpf_core_read(&mnt, sizeof(mnt), &file->f_path.mnt);
	if (error || !sb || !mnt) return -1;
	struct mount *mount = (void *)mnt - bpf_core_field_offset(struct mount, mnt);
	error |= bpf_core_read(&key->mount_id, sizeof(key->mount_id), &mount->mnt_id_unique);
	error |= bpf_core_read(&key->device, sizeof(key->device), &sb->s_dev);
	error |= bpf_core_read(&key->inode, sizeof(key->inode), &inode->i_ino);
	error |= bpf_core_read(&key->generation, sizeof(key->generation), &inode->i_generation);
	error |= bpf_core_read(&key->size, sizeof(key->size), &inode->i_size);
	error |= bpf_core_read(&key->mtime_sec, sizeof(key->mtime_sec), &inode->i_mtime_sec);
	error |= bpf_core_read(&key->ctime_sec, sizeof(key->ctime_sec), &inode->i_ctime_sec);
	error |= bpf_core_read(&key->mtime_nsec, sizeof(key->mtime_nsec), &inode->i_mtime_nsec);
	error |= bpf_core_read(&key->ctime_nsec, sizeof(key->ctime_nsec), &inode->i_ctime_nsec);
	return error || !key->inode || !key->mount_id ? -1 : 0;
}

static __always_inline void record(struct fp_call *call, __s64 ret, __u64 end)
{
	struct fp_value zero = {};
	struct fp_value *value = bpf_map_lookup_elem(&fp_files, &call->object);
	if (!value) {
		bpf_map_update_elem(&fp_files, &call->object, &zero, BPF_NOEXIST);
		value = bpf_map_lookup_elem(&fp_files, &call->object);
	}
	if (!value) { health(FP_C_AGGREGATE_FULL); return; }
	/* Key includes a TID instance: only that thread updates this entry. */
	++value->calls;
	if (ret >= 0) ++value->success_calls; else ++value->errors;
	if (ret > 0 && (call->object.operation == FP_READ || call->object.operation == FP_READV))
		value->returned_bytes += ret;
	__u64 duration = end - call->start_ns;
	value->duration_ns += duration;
	if (duration > value->max_duration_ns) value->max_duration_ns = duration;
	if (!value->first_start_ns) value->first_start_ns = call->start_ns;
	value->last_end_ns = end;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int fp_sys_enter(struct fp_enter *ctx)
{
	/* Native table only. Recognize selected x32 aliases solely to report
	 * unsupported ABI, never decode them with the native syscall schema. */
	int op = operation(ctx->nr & ~0x40000000LL);
	if (op < 0) return 0;
	__u64 root = domain();
	if (!root) return 0;
	__u64 id = bpf_get_current_pid_tgid();
	struct task_struct *task = (void *)bpf_get_current_task_btf(), *leader = 0;
	__u32 status = 0;
	if (bpf_core_read(&status, sizeof(status), &task->thread_info.status)) {
		health(FP_C_OBJECT_READ); return 0;
	}
	/* x86 TS_COMPAT=0x0002: actual syscall ABI, not ELF/address size. */
	if ((status & 0x0002) || (ctx->nr & 0x40000000LL)) {
		health(FP_C_UNSUPPORTED_ABI); return 0;
	}
	/* Anonymous mmap has no file; it is deliberately not counted. */
	if (op == FP_MMAP && ((ctx->args[3] & 0x20) || (__s64)ctx->args[4] < 0)) return 0;
	struct fp_call call = {};
	call.object.domain_id = root;
	call.object.caller_cgroup_id = bpf_get_current_cgroup_id();
	call.object.tgid = id >> 32;
	call.object.tid = (__u32)id;
	call.object.operation = op;
	int error = bpf_core_read(&leader, sizeof(leader), &task->group_leader);
	if (error || !leader) { health(FP_C_OBJECT_READ); return 0; }
	error |= bpf_core_read(&call.object.process_start_boottime_ns,
		sizeof(call.object.process_start_boottime_ns), &leader->start_boottime);
	error |= bpf_core_read(&call.object.thread_start_boottime_ns,
		sizeof(call.object.thread_start_boottime_ns), &task->start_boottime);
	if (error) { health(FP_C_OBJECT_READ); return 0; }
	call.start_ns = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&fp_calls, &id, &call, BPF_ANY)) health(FP_C_CONTEXT_FULL);
	return 0;
}

static __always_inline int begin(struct file *file, __u32 expected)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fp_call *context = bpf_map_lookup_elem(&fp_calls, &id);
	if (!context || context->object.operation != expected) return 0;
	struct fp_call *nested = bpf_map_lookup_elem(&fp_pending, &id);
	if (nested) { ++nested->depth; health(FP_C_NESTED); return 0; }
	struct fp_call call = *context;
	call.start_ns = bpf_ktime_get_ns();
	call.depth = 1;
	call.object_valid = !file_identity(&call.object, file);
	if (!call.object_valid) { health(FP_C_OBJECT_READ); return 0; }
	if (bpf_map_update_elem(&fp_pending, &id, &call, BPF_ANY)) health(FP_C_PENDING_FULL);
	return 0;
}

static __always_inline int end(__s64 ret, __u32 expected)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fp_call *context = bpf_map_lookup_elem(&fp_calls, &id);
	if (!context || context->object.operation != expected) return 0;
	struct fp_call *call = bpf_map_lookup_elem(&fp_pending, &id);
	if (!call) { health(FP_C_UNPAIRED); return 0; }
	if (call->depth > 1) { --call->depth; return 0; }
	/* Keep fexit very small: allocating/updating aggregate maps here can
	 * lengthen the trampoline recursion-guard window under preemption.
	 * syscall exit performs aggregation only after this exact VFS interval
	 * has finished. No syscall duration is mislabeled as VFS duration. */
	call->return_value = ret;
	call->end_ns = bpf_ktime_get_ns();
	return 0;
}

SEC("fentry/vfs_read")
int BPF_PROG(fp_read_enter, struct file *file) { (void)ctx; return begin(file, FP_READ); }
SEC("fexit/vfs_read")
int BPF_PROG(fp_read_exit, struct file *file, void *buffer, unsigned long count,
	void *pos, __s64 ret)
{ (void)ctx; (void)file; (void)buffer; (void)count; (void)pos; return end(ret, FP_READ); }
SEC("fentry/vfs_readv")
int BPF_PROG(fp_readv_enter, struct file *file) { (void)ctx; return begin(file, FP_READV); }
SEC("fexit/vfs_readv")
int BPF_PROG(fp_readv_exit, struct file *file, void *vec, unsigned long vlen,
	void *pos, unsigned int flags, __s64 ret)
{ (void)ctx; (void)file; (void)vec; (void)vlen; (void)pos; (void)flags; return end(ret, FP_READV); }
SEC("fentry/iterate_dir")
int BPF_PROG(fp_dir_enter, struct file *file) { (void)ctx; return begin(file, FP_DIRECTORY); }
SEC("fexit/iterate_dir")
int BPF_PROG(fp_dir_exit, struct file *file, void *dir_context, int ret)
{ (void)ctx; (void)file; (void)dir_context; return end(ret, FP_DIRECTORY); }
/* The hook identifies an actual file, but only sys_exit establishes that
 * mmap itself succeeded. Its cost is the syscall interval, not VFS time. */
SEC("fentry/security_mmap_file")
int BPF_PROG(fp_mmap_file, struct file *file)
{
	(void)ctx;
	__u64 id = bpf_get_current_pid_tgid();
	struct fp_call *call = bpf_map_lookup_elem(&fp_calls, &id);
	if (!call || call->object.operation != FP_MMAP || !file) return 0;
	if (call->object_valid) { health(FP_C_NESTED); call->object_valid = 2; return 0; }
	call->object_valid = !file_identity(&call->object, file);
	if (!call->object_valid) health(FP_C_OBJECT_READ);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int fp_sys_exit(struct fp_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fp_call *call = bpf_map_lookup_elem(&fp_calls, &id);
	if (!call) return 0;
	if (call->object.operation == FP_MMAP) {
		if (call->object_valid == 1) record(call, ctx->ret, bpf_ktime_get_ns());
		else health(FP_C_UNRESOLVED_MMAP);
	}
	struct fp_call *pending = bpf_map_lookup_elem(&fp_pending, &id);
	if (pending) {
		if (pending->end_ns && pending->depth == 1) {
			record(pending, pending->return_value, pending->end_ns);
		} else {
			__u32 zero = 0;
			bpf_map_update_elem(&fp_pending_sample, &zero, pending, BPF_ANY);
			health(FP_C_EXIT_PENDING);
		}
		bpf_map_delete_elem(&fp_pending, &id);
	}
	bpf_map_delete_elem(&fp_calls, &id);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
