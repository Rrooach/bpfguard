// SPDX-License-Identifier: GPL-2.0-only
/* Opt-in per-call diagnostic stream, never enabled in the default profile.
 * No path/read buffer capture; bounded per-thread state, not per-file maps.
 */
#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "file_access.h"

struct super_block { __u32 s_dev; } __attribute__((preserve_access_index));
struct inode {
	struct super_block *i_sb; unsigned long i_ino; __s64 i_size;
	__u32 i_generation; unsigned short i_mode;
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
	struct thread_info thread_info; struct task_struct *group_leader;
	__u64 start_boottime;
} __attribute__((preserve_access_index));
struct pt_regs {
	unsigned long di, si, dx, cx, ax;
} __attribute__((preserve_access_index));
struct vm_area_struct { struct file *vm_file; unsigned long vm_start, vm_pgoff;
} __attribute__((preserve_access_index));
enum fault_flag { FA_FAULT_FLAG_PLACEHOLDER = 0 };
struct vm_fault {
	struct vm_area_struct *vma; enum fault_flag flags;
	unsigned long address, pgoff;
} __attribute__((preserve_access_index));
struct fa_enter { __u64 pad; __s64 nr; __u64 args[6]; };
struct fa_exit { __u64 pad; __s64 nr, ret; };

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
	__type(key, __u32); __type(value, struct fa_config);
} fa_config SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, FA_DOMAINS);
	__type(key, __u32); __type(value, struct fa_domain);
} fa_domains SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, FA_THREADS);
	__type(key, __u64); __type(value, struct fa_event);
} fa_calls SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, FA_THREADS);
	__type(key, __u64); __type(value, struct fa_pending);
} fa_pending SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, FA_THREADS);
	__type(key, __u64); __type(value, struct fa_pending);
} fa_faults SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, FA_THREADS);
	__type(key, __u64); __type(value, struct fa_pending);
} fa_mm_faults SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, FA_HEALTH_COUNT);
	__type(key, __u32); __type(value, __u64);
} fa_health SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
	__type(key, __u32); __type(value, struct fa_totals);
} fa_totals SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, FA_RING_BYTES);
} fa_events SEC(".maps");

static __always_inline void health(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&fa_health, &index);
	if (value) __sync_fetch_and_add(value, 1);
}
static __always_inline __u64 domain(void)
{
	__u32 zero = 0;
	struct fa_config *config = bpf_map_lookup_elem(&fa_config, &zero);
	if (!config || !config->enabled) return 0;
	for (__u32 i = 0; i < FA_DOMAINS; ++i) {
		if (i >= config->count) break;
		struct fa_domain *root = bpf_map_lookup_elem(&fa_domains, &i);
		if (root && bpf_get_current_ancestor_cgroup_id(root->level) == root->cgroup_id)
			return root->cgroup_id;
	}
	return 0;
}
static __always_inline int base(struct fa_event *event, __u64 root)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct task_struct *task = (void *)bpf_get_current_task_btf(), *leader = 0;
	event->magic = FA_MAGIC; event->version = FA_VERSION; event->size = FA_EVENT_BYTES;
	event->domain_id = root; event->caller_cgroup_id = bpf_get_current_cgroup_id();
	event->tgid = id >> 32; event->tid = (__u32)id;
	if (bpf_core_read(&leader, sizeof(leader), &task->group_leader) || !leader)
		return -1;
	return bpf_core_read(&event->process_start_boottime_ns,
		sizeof(event->process_start_boottime_ns), &leader->start_boottime) |
		bpf_core_read(&event->thread_start_boottime_ns,
		sizeof(event->thread_start_boottime_ns), &task->start_boottime);
}
static __always_inline int object(struct fa_event *event, struct file *file)
{
	struct inode *inode = 0; struct super_block *sb = 0;
	struct vfsmount *mnt = 0; unsigned short mode = 0;
	if (!file || bpf_core_read(&inode, sizeof(inode), &file->f_inode) || !inode)
		return -1;
	int error = bpf_core_read(&sb, sizeof(sb), &inode->i_sb);
	error |= bpf_core_read(&mnt, sizeof(mnt), &file->f_path.mnt);
	if (error || !sb || !mnt) return -1;
	struct mount *mount = (void *)mnt - bpf_core_field_offset(struct mount, mnt);
	error |= bpf_core_read(&event->mount_id, sizeof(event->mount_id), &mount->mnt_id_unique);
	error |= bpf_core_read(&event->device, sizeof(event->device), &sb->s_dev);
	error |= bpf_core_read(&event->inode, sizeof(event->inode), &inode->i_ino);
	error |= bpf_core_read(&event->generation, sizeof(event->generation), &inode->i_generation);
	error |= bpf_core_read(&event->file_size, sizeof(event->file_size), &inode->i_size);
	error |= bpf_core_read(&mode, sizeof(mode), &inode->i_mode);
	if (error || !event->inode || !event->mount_id) return -1;
	event->flags |= FA_OBJECT_VALID;
	if ((mode & 0170000) == 0100000) event->flags |= FA_REGULAR_FILE;
	if ((mode & 0170000) == 0040000) event->flags |= FA_DIRECTORY_FILE;
	return 0;
}
static __always_inline void emit(struct fa_event *event)
{
	__u32 zero = 0;
	struct fa_totals *totals = bpf_map_lookup_elem(&fa_totals, &zero);
	struct fa_config *config = bpf_map_lookup_elem(&fa_config, &zero);
	if (!totals || !config) return;
	event->cpu = bpf_get_smp_processor_id();
	event->cpu_seq = __sync_fetch_and_add(&totals->attempted, 1) + 1;
	if (!config->emit_events) return;
	struct fa_event *out = bpf_ringbuf_reserve(&fa_events, sizeof(*out), 0);
	if (!out) { __sync_fetch_and_add(&totals->ring_drops, 1); health(FA_RING_DROPS); return; }
	*out = *event;
	bpf_ringbuf_submit(out, 0);
	__sync_fetch_and_add(&totals->emitted, 1);
}
static __always_inline int kind(__s64 nr)
{
	if (nr == 0 || nr == 17) return FA_READ;
	if (nr == 19 || nr == 295 || nr == 327) return FA_READV;
	if (nr == 78 || nr == 217) return FA_DIRECTORY;
	if (nr == 2 || nr == 85 || nr == 257 || nr == 437) return FA_OPEN;
	return 0;
}
SEC("tracepoint/raw_syscalls/sys_enter")
int fa_sys_enter(struct fa_enter *ctx)
{
	__u64 root = domain();
	if (!root) return 0;
	struct task_struct *task = (void *)bpf_get_current_task_btf();
	__u32 status = 0;
	if (bpf_core_read(&status, sizeof(status), &task->thread_info.status)) {
		health(FA_OBJECT_READ_FAILED); return 0;
	}
	if ((status & 2) || (ctx->nr & 0x40000000LL)) {
		health(FA_UNSUPPORTED_ABI); return 0;
	}
	int op = kind(ctx->nr);
	if (!op) return 0;
	__u64 id = bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&fa_calls, &id)) {
		health(FA_SYSCALL_MISMATCH); bpf_map_delete_elem(&fa_calls, &id);
	}
	struct fa_event event = {};
	if (base(&event, root)) { health(FA_OBJECT_READ_FAILED); return 0; }
	event.kind = op; event.syscall_nr = ctx->nr;
	event.syscall_start_ns = bpf_ktime_get_ns();
	event.flags |= FA_SYSCALL_VALID;
	if (op == FA_READ) { event.requested = ctx->args[2]; event.flags |= FA_REQUESTED_VALID; }
	if (bpf_map_update_elem(&fa_calls, &id, &event, BPF_NOEXIST)) health(FA_CONTEXT_FULL);
	return 0;
}
static __always_inline int begin(struct file *file, __u32 expected, const __s64 *pos)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fa_event *context = bpf_map_lookup_elem(&fa_calls, &id);
	if (!context || context->kind != expected) return 0;
	struct fa_pending *nested = bpf_map_lookup_elem(&fa_pending, &id);
	if (nested) {
		if (nested->completed) { health(FA_MULTIPLE_VFS); return 0; }
		++nested->depth; health(FA_NESTED_HOOKS); return 0;
	}
	struct fa_pending call = { .event = *context, .depth = 1 };
	call.event.start_ns = bpf_ktime_get_ns();
	if (object(&call.event, file)) health(FA_OBJECT_READ_FAILED);
	if (pos) {
		if (!bpf_probe_read_kernel(&call.event.offset, sizeof(call.event.offset), pos))
			call.event.flags |= FA_OFFSET_VALID;
		else health(FA_OFFSET_READ_FAILED);
	}
	if (bpf_map_update_elem(&fa_pending, &id, &call, BPF_NOEXIST)) health(FA_PENDING_FULL);
	return 0;
}
static __always_inline int end(__s64 ret, __u32 expected)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fa_event *context = bpf_map_lookup_elem(&fa_calls, &id);
	if (!context || context->kind != expected) return 0;
	struct fa_pending *call = bpf_map_lookup_elem(&fa_pending, &id);
	if (!call) { health(FA_UNPAIRED_EXIT); return 0; }
	if (call->depth > 1) { --call->depth; return 0; }
	if (call->completed) { health(FA_MULTIPLE_VFS); return 0; }
	/* Avoid ring/map allocation inside read return trampoline: sys_exit emits. */
	call->event.result = ret; call->event.end_ns = bpf_ktime_get_ns();
	call->completed = 1;
	return 0;
}
#ifndef FA_USE_KPROBE
SEC("fentry/vfs_read")
int BPF_PROG(fa_read_enter, struct file *file, void *buffer, unsigned long count, __s64 *pos)
{ (void)ctx; (void)buffer; (void)count; return begin(file, FA_READ, pos); }
SEC("fexit/vfs_read")
int BPF_PROG(fa_read_exit, struct file *file, void *buffer, unsigned long count, void *pos, __s64 ret)
{ (void)ctx; (void)file; (void)buffer; (void)count; (void)pos; return end(ret, FA_READ); }
SEC("fentry/vfs_readv")
int BPF_PROG(fa_readv_enter, struct file *file, void *vec, unsigned long vlen, __s64 *pos)
{ (void)ctx; (void)vec; (void)vlen; return begin(file, FA_READV, pos); }
SEC("fexit/vfs_readv")
int BPF_PROG(fa_readv_exit, struct file *file, void *vec, unsigned long vlen, void *pos,
	unsigned int flags, __s64 ret)
{ (void)ctx; (void)file; (void)vec; (void)vlen; (void)pos; (void)flags; return end(ret, FA_READV); }
SEC("fentry/iterate_dir")
int BPF_PROG(fa_dir_enter, struct file *file)
{ (void)ctx; return begin(file, FA_DIRECTORY, 0); }
SEC("fexit/iterate_dir")
int BPF_PROG(fa_dir_exit, struct file *file, void *dir_context, int ret)
{ (void)ctx; (void)file; (void)dir_context; return end(ret, FA_DIRECTORY); }
#else
SEC("kprobe/vfs_read")
int fa_read_enter(struct pt_regs *ctx)
{ return begin((void *)BPF_CORE_READ(ctx, di), FA_READ, (void *)BPF_CORE_READ(ctx, cx)); }
SEC("kretprobe/vfs_read")
int fa_read_exit(struct pt_regs *ctx)
{ return end((__s64)BPF_CORE_READ(ctx, ax), FA_READ); }
SEC("kprobe/vfs_readv")
int fa_readv_enter(struct pt_regs *ctx)
{ return begin((void *)BPF_CORE_READ(ctx, di), FA_READV, (void *)BPF_CORE_READ(ctx, cx)); }
SEC("kretprobe/vfs_readv")
int fa_readv_exit(struct pt_regs *ctx)
{ return end((__s64)BPF_CORE_READ(ctx, ax), FA_READV); }
SEC("kprobe/iterate_dir")
int fa_dir_enter(struct pt_regs *ctx)
{ return begin((void *)BPF_CORE_READ(ctx, di), FA_DIRECTORY, 0); }
SEC("kretprobe/iterate_dir")
int fa_dir_exit(struct pt_regs *ctx)
{ return end((__s32)BPF_CORE_READ(ctx, ax), FA_DIRECTORY); }
#endif
static __always_inline int open_file(struct file *file)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fa_event *call = bpf_map_lookup_elem(&fa_calls, &id);
	if (!call || call->kind != FA_OPEN) return 0;
	if (call->flags & FA_OBJECT_VALID) { health(FA_MULTIPLE_VFS); return 0; }
	if (object(call, file)) health(FA_OBJECT_READ_FAILED);
	return 0;
}
#ifndef FA_USE_KPROBE
SEC("fentry/security_file_open")
int BPF_PROG(fa_open_file, struct file *file)
{ (void)ctx; return open_file(file); }
#else
SEC("kprobe/security_file_open")
int fa_open_file(struct pt_regs *ctx)
{ return open_file((void *)BPF_CORE_READ(ctx, di)); }
#endif
SEC("tracepoint/raw_syscalls/sys_exit")
int fa_sys_exit(struct fa_exit *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fa_event *call = bpf_map_lookup_elem(&fa_calls, &id);
	if (!call) return 0;
	__u64 end_ns = bpf_ktime_get_ns();
	if (call->syscall_nr != ctx->nr) health(FA_SYSCALL_MISMATCH);
	struct fa_pending *pending = bpf_map_lookup_elem(&fa_pending, &id);
	if (pending) {
		if (pending->completed && pending->depth == 1) {
			pending->event.syscall_end_ns = end_ns;
			pending->event.syscall_result = ctx->ret; emit(&pending->event);
		} else health(FA_SYSCALL_EXIT_PENDING);
		bpf_map_delete_elem(&fa_pending, &id);
	} else {
		call->start_ns = call->syscall_start_ns; call->end_ns = end_ns;
		call->syscall_end_ns = end_ns; call->syscall_result = ctx->ret;
		call->result = ctx->ret;
		/* Invalid-fd and pre-VFS denial are visible, not invented file objects. */
		if (ctx->ret >= 0 && !(call->flags & FA_OBJECT_VALID))
			health(FA_SYSCALL_EXIT_PENDING);
		emit(call);
	}
	bpf_map_delete_elem(&fa_calls, &id);
	return 0;
}
static __always_inline int fault_begin(struct vm_fault *vmf)
{
	__u64 root = domain();
	if (!root) return 0;
	__u64 id = bpf_get_current_pid_tgid();
	struct fa_pending *nested = bpf_map_lookup_elem(&fa_faults, &id);
	if (nested) { ++nested->depth; health(FA_NESTED_HOOKS); return 0; }
	struct fa_pending call = { .depth = 1 };
	struct vm_area_struct *vma = 0; struct file *file = 0;
	if (base(&call.event, root)) { health(FA_OBJECT_READ_FAILED); return 0; }
	call.event.kind = FA_FILEMAP_FAULT; call.event.syscall_nr = 0xffffffff;
	call.event.start_ns = bpf_ktime_get_ns();
	int error = bpf_core_read(&vma, sizeof(vma), &vmf->vma);
	if (!error && vma) error |= bpf_core_read(&file, sizeof(file), &vma->vm_file);
	error |= bpf_core_read(&call.event.fault_address, sizeof(call.event.fault_address), &vmf->address);
	error |= bpf_core_read(&call.event.pgoff, sizeof(call.event.pgoff), &vmf->pgoff);
	error |= bpf_core_read(&call.event.fault_flags, sizeof(call.event.fault_flags), &vmf->flags);
	if (error || !file || object(&call.event, file)) health(FA_OBJECT_READ_FAILED);
	else call.event.flags |= FA_FAULT_FLAGS_VALID;
	if (bpf_map_update_elem(&fa_faults, &id, &call, BPF_NOEXIST)) health(FA_FAULT_PENDING_FULL);
	return 0;
}
static __always_inline int fault_end(unsigned int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fa_pending *call = bpf_map_lookup_elem(&fa_faults, &id);
	if (!call) {
		if (domain()) health(FA_FAULT_UNPAIRED);
		return 0;
	}
	if (call->depth > 1) { --call->depth; return 0; }
	call->event.end_ns = bpf_ktime_get_ns(); call->event.vm_fault_result = ret;
	call->event.flags |= FA_FAULT_RETURN_VALID;
	emit(&call->event); bpf_map_delete_elem(&fa_faults, &id);
	return 0;
}
#ifndef FA_USE_KPROBE
SEC("fentry/filemap_fault")
int BPF_PROG(fa_fault_enter, struct vm_fault *vmf)
{ (void)ctx; return fault_begin(vmf); }
SEC("fexit/filemap_fault")
int BPF_PROG(fa_fault_exit, struct vm_fault *vmf, unsigned int ret)
{ (void)ctx; (void)vmf; return fault_end(ret); }
#else
SEC("kprobe/filemap_fault")
int fa_fault_enter(struct pt_regs *ctx)
{ return fault_begin((void *)BPF_CORE_READ(ctx, di)); }
SEC("kretprobe/filemap_fault")
int fa_fault_exit(struct pt_regs *ctx)
{ return fault_end((__u32)BPF_CORE_READ(ctx, ax)); }
#endif
/* handle_mm_fault includes filemap_map_pages/fault-around fast paths and
 * anonymous VMAs. filemap_fault is a nested refill path, not another
 * independent process fault to be added to this outer attempt count.
 */
static __always_inline int mm_fault_begin(struct vm_area_struct *vma,
	unsigned long address, unsigned int flags)
{
	__u64 root = domain();
	if (!root) return 0;
	__u64 id = bpf_get_current_pid_tgid();
	struct fa_pending *nested = bpf_map_lookup_elem(&fa_mm_faults, &id);
	if (nested) {
		++nested->depth; health(FA_NESTED_HOOKS);
		/* An inner MM attempt is not emitted: this cannot be called complete. */
		health(FA_MM_UNPAIRED); return 0;
	}
	struct fa_pending call = { .depth = 1 };
	if (base(&call.event, root)) { health(FA_OBJECT_READ_FAILED); return 0; }
	call.event.kind = FA_MM_FAULT; call.event.syscall_nr = 0xffffffff;
	call.event.start_ns = bpf_ktime_get_ns();
	call.event.fault_address = address; call.event.fault_flags = flags;
	call.event.flags |= FA_FAULT_FLAGS_VALID;
	struct file *file = 0; unsigned long vm_start = 0, vm_pgoff = 0;
	int error = bpf_core_read(&file, sizeof(file), &vma->vm_file);
	error |= bpf_core_read(&vm_start, sizeof(vm_start), &vma->vm_start);
	error |= bpf_core_read(&vm_pgoff, sizeof(vm_pgoff), &vma->vm_pgoff);
	if (error || address < vm_start) health(FA_OBJECT_READ_FAILED);
	else {
		/* Native x86-64 base page is 4096, also gated by the collector. */
		call.event.pgoff = vm_pgoff + ((address - vm_start) >> 12);
		if (!file) call.event.flags |= FA_NO_FILE_VMA;
		else if (object(&call.event, file)) health(FA_OBJECT_READ_FAILED);
	}
	if (bpf_map_update_elem(&fa_mm_faults, &id, &call, BPF_NOEXIST)) health(FA_MM_PENDING_FULL);
	return 0;
}
static __always_inline int mm_fault_end(unsigned int ret)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct fa_pending *call = bpf_map_lookup_elem(&fa_mm_faults, &id);
	if (!call) { if (domain()) health(FA_MM_UNPAIRED); return 0; }
	if (call->depth > 1) { --call->depth; return 0; }
	/* VMA may have been freed: never dereference it from the return hook. */
	call->event.end_ns = bpf_ktime_get_ns(); call->event.vm_fault_result = ret;
	call->event.flags |= FA_FAULT_RETURN_VALID;
	emit(&call->event); bpf_map_delete_elem(&fa_mm_faults, &id);
	return 0;
}
#ifndef FA_USE_KPROBE
SEC("fentry/handle_mm_fault")
int BPF_PROG(fa_mm_fault_enter, struct vm_area_struct *vma,
	unsigned long address, unsigned int flags)
{ (void)ctx; return mm_fault_begin(vma, address, flags); }
SEC("fexit/handle_mm_fault")
int BPF_PROG(fa_mm_fault_exit, struct vm_area_struct *vma,
	unsigned long address, unsigned int flags, void *regs, unsigned int ret)
{ (void)ctx; (void)vma; (void)address; (void)flags; (void)regs; return mm_fault_end(ret); }
#else
SEC("kprobe/handle_mm_fault")
int fa_mm_fault_enter(struct pt_regs *ctx)
{ return mm_fault_begin((void *)BPF_CORE_READ(ctx, di), BPF_CORE_READ(ctx, si),
	(__u32)BPF_CORE_READ(ctx, dx)); }
SEC("kretprobe/handle_mm_fault")
int fa_mm_fault_exit(struct pt_regs *ctx)
{ return mm_fault_end((__u32)BPF_CORE_READ(ctx, ax)); }
#endif
SEC("tracepoint/sched/sched_process_exit")
int fa_task_exit(void *ctx)
{
	(void)ctx;
	__u64 id = bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&fa_calls, &id)) {
		health(FA_SYSCALL_EXIT_PENDING); bpf_map_delete_elem(&fa_calls, &id);
	}
	if (bpf_map_lookup_elem(&fa_pending, &id)) {
		health(FA_SYSCALL_EXIT_PENDING); bpf_map_delete_elem(&fa_pending, &id);
	}
	if (bpf_map_lookup_elem(&fa_faults, &id)) {
		health(FA_FAULT_EXIT_PENDING); bpf_map_delete_elem(&fa_faults, &id);
	}
	if (bpf_map_lookup_elem(&fa_mm_faults, &id)) {
		health(FA_MM_EXIT_PENDING); bpf_map_delete_elem(&fa_mm_faults, &id);
	}
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
