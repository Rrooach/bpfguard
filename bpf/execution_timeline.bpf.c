// SPDX-License-Identifier: GPL-2.0-only
/* Opt-in same-run scheduler/syscall/file timeline. Not enabled by Observer's
 * default profiles. Stacks are candidate context, not a certified wait cause. */
#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "execution_timeline.h"

struct kernfs_node { __u64 id; } __attribute__((preserve_access_index));
struct cgroup { int level; struct kernfs_node *kn; struct cgroup *ancestors[]; } __attribute__((preserve_access_index));
struct css_set { struct cgroup *dfl_cgrp; } __attribute__((preserve_access_index));
struct thread_info { __u32 status; } __attribute__((preserve_access_index));
struct task_struct {
    struct thread_info thread_info; int pid, tgid; __u64 start_boottime;
    struct task_struct *group_leader, *real_parent; struct css_set *cgroups;
    int *clear_child_tid;
    char comm[16];
} __attribute__((preserve_access_index));
struct super_block { __u32 s_dev; } __attribute__((preserve_access_index));
struct inode { struct super_block *i_sb; unsigned long i_ino; __s64 i_size; __u32 i_generation; } __attribute__((preserve_access_index));
struct vfsmount { int unused; } __attribute__((preserve_access_index));
struct mount { struct vfsmount mnt; __u64 mnt_id_unique; } __attribute__((preserve_access_index));
struct path { struct vfsmount *mnt; void *dentry; } __attribute__((preserve_access_index));
struct file { struct path f_path; struct inode *f_inode; } __attribute__((preserve_access_index));
struct linux_binprm { struct file *file; const char *filename; } __attribute__((preserve_access_index));
/* CO-RE relocates each named register to the running x86-64 pt_regs layout.
 * The userspace loader also validates register widths and VFS prototypes. */
struct pt_regs { unsigned long di, si, dx, cx, ax, orig_ax; } __attribute__((preserve_access_index));
struct et_enter { __u64 pad; __s64 nr; __u64 args[6]; };
struct et_leave { __u64 pad; __s64 nr, ret; };
extern int bpf_path_d_path(const struct path *path,char *buf,unsigned long buf__sz) __ksym;

struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct et_config); } et_config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,ET_MAX_THREADS); __type(key,__u64); __type(value,struct et_pending); } et_pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,ET_MAX_THREADS); __type(key,__u64); __type(value,struct et_enrollment); } et_enrolled SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,ET_MAX_THREADS); __type(key,__u64); __type(value,struct et_wake_pending); } et_wake_pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,ET_MAX_THREADS); __type(key,__u64); __type(value,struct et_seccomp_pending); } et_seccomp_pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,ET_HEALTH_COUNT); __type(key,__u32); __type(value,__u64); } et_health SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,16*1024*1024); } et_events SEC(".maps");

static __always_inline __u64 count(__u32 index)
{
    __u64 *value=bpf_map_lookup_elem(&et_health,&index);
    return value ? __sync_fetch_and_add(value,1)+1 : 0;
}
static __always_inline struct et_config *config(void)
{
    __u32 zero=0; struct et_config *cfg=bpf_map_lookup_elem(&et_config,&zero);
    return cfg && cfg->enabled && cfg->root_cgroup_id && cfg->root_level<32 ? cfg:0;
}
/* Target task membership, never the current waker's cgroup. */
static __always_inline __u64 membership(struct task_struct *task, struct et_config *cfg)
{
    struct css_set *css=0; struct cgroup *cg=0,*ancestor=0;
    struct kernfs_node *kn=0; __u64 id=0; int level=0;
    if (!task || bpf_core_read(&css,sizeof(css),&task->cgroups) || !css ||
        bpf_core_read(&cg,sizeof(cg),&css->dfl_cgrp) || !cg ||
        bpf_core_read(&level,sizeof(level),&cg->level) || level<(int)cfg->root_level)
        return 0;
    __u32 depth=cfg->root_level;
    if (depth>=32) return 0;
    if (bpf_core_read(&ancestor,sizeof(ancestor),&cg->ancestors[depth]) || !ancestor ||
        bpf_core_read(&kn,sizeof(kn),&ancestor->kn) || !kn ||
        bpf_core_read(&id,sizeof(id),&kn->id) || id!=cfg->root_cgroup_id)
        return 0;
    if (bpf_core_read(&kn,sizeof(kn),&cg->kn) || !kn || bpf_core_read(&id,sizeof(id),&kn->id)) return 0;
    return id;
}
static __always_inline int identity(struct et_identity *out, struct task_struct *task)
{
    struct task_struct *leader=0; struct css_set *css=0; struct cgroup *cg=0; struct kernfs_node *kn=0;
    int error=0;
    if (!task) return -1;
    error|=bpf_core_read(&out->tid,sizeof(out->tid),&task->pid);
    error|=bpf_core_read(&out->tgid,sizeof(out->tgid),&task->tgid);
    error|=bpf_core_read(&out->thread_birth_ns,sizeof(out->thread_birth_ns),&task->start_boottime);
    error|=bpf_core_read(&out->comm,sizeof(out->comm),&task->comm);
    error|=bpf_core_read(&leader,sizeof(leader),&task->group_leader);
    if (!leader) return -1;
    error|=bpf_core_read(&out->process_birth_ns,sizeof(out->process_birth_ns),&leader->start_boottime);
    if (bpf_core_read(&css,sizeof(css),&task->cgroups) || !css ||
        bpf_core_read(&cg,sizeof(cg),&css->dfl_cgrp) || !cg ||
        bpf_core_read(&kn,sizeof(kn),&cg->kn) || !kn) return -1;
    error|=bpf_core_read(&out->cgroup_id,sizeof(out->cgroup_id),&kn->id);
    return error || !out->tid || !out->tgid || !out->thread_birth_ns || !out->process_birth_ns ? -1:0;
}
static __always_inline __u64 task_key(const struct et_identity *id)
{ return ((__u64)id->tgid<<32)|id->tid; }
static __always_inline struct et_pending *pending(const struct et_identity *id)
{
    __u64 key=task_key(id); struct et_pending *p=bpf_map_lookup_elem(&et_pending,&key);
    return p && p->task.thread_birth_ns==id->thread_birth_ns && p->task.process_birth_ns==id->process_birth_ns ? p:0;
}
static __always_inline struct et_enrollment *enrollment(const struct et_identity *id)
{
    __u64 key=task_key(id);struct et_enrollment *s=bpf_map_lookup_elem(&et_enrolled,&key);
    if(s&&s->thread_birth_ns==id->thread_birth_ns)return s;
    struct et_enrollment value={.thread_birth_ns=id->thread_birth_ns,.fork_nr=-1};
    if(bpf_map_update_elem(&et_enrolled,&key,&value,BPF_ANY)){count(ET_CONTEXT_FULL);return 0;}
    return bpf_map_lookup_elem(&et_enrolled,&key);
}
static __always_inline struct et_event *reserve(struct task_struct *task, struct et_config *cfg,__u16 kind,__u64 now)
{
    __u64 seq=count(ET_ATTEMPTED);
    struct et_event *e=bpf_ringbuf_reserve(&et_events,sizeof(*e),0);
    if (!e) { count(ET_RING_DROPS); return 0; }
    __builtin_memset(e,0,sizeof(*e)); e->magic=ET_MAGIC;e->version=ET_VERSION;e->kind=kind;e->size=sizeof(*e);
    __builtin_memcpy(e->boot_id,cfg->boot_id,sizeof(e->boot_id));
    e->cpu=bpf_get_smp_processor_id();e->cpu_seq=seq;e->timestamp_ns=now;e->root_cgroup_id=cfg->root_cgroup_id;
    e->syscall_nr=-1;
    if (identity(&e->task,task)) { e->flags|=ET_IDENTITY_FAILED;count(ET_ID_READ_ERRORS); }
    struct et_pending *p=pending(&e->task);
    if (p) { e->syscall_call_id=p->call_id;e->syscall_nr=p->nr; }
    return e;
}
static __always_inline void submit(struct et_event *e)
{ bpf_ringbuf_submit(e,0);count(ET_EMITTED); }
static __always_inline void peer(struct et_event *e,struct task_struct *task)
{
    int pid=-1;
    if(task&&!bpf_core_read(&pid,sizeof(pid),&task->pid)&&pid==0){
        e->flags|=ET_PEER_IDLE;
        if(bpf_core_read(&e->peer.comm,sizeof(e->peer.comm),&task->comm)){
            e->flags|=ET_PEER_FAILED;count(ET_ID_READ_ERRORS);
        }
        return;
    }
    if(identity(&e->peer,task)){e->flags|=ET_PEER_FAILED;count(ET_ID_READ_ERRORS);}
}
static __always_inline int file_object(struct et_file *out,struct file *file)
{
    struct inode *ino=0;struct super_block *sb=0;struct vfsmount *mnt=0;
    if (!file || bpf_core_read(&ino,sizeof(ino),&file->f_inode)||!ino ||
        bpf_core_read(&sb,sizeof(sb),&ino->i_sb)||!sb ||
        bpf_core_read(&mnt,sizeof(mnt),&file->f_path.mnt)||!mnt) return -1;
    struct mount *mount=(void *)mnt-bpf_core_field_offset(struct mount,mnt);
    int err=bpf_core_read(&out->mount_id,sizeof(out->mount_id),&mount->mnt_id_unique);
    err|=bpf_core_read(&out->inode,sizeof(out->inode),&ino->i_ino);
    err|=bpf_core_read(&out->size,sizeof(out->size),&ino->i_size);
    err|=bpf_core_read(&out->device,sizeof(out->device),&sb->s_dev);
    err|=bpf_core_read(&out->generation,sizeof(out->generation),&ino->i_generation);
    return err || !out->mount_id || !out->inode ? -1:0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(et_switch,unsigned long preempt,struct task_struct *prev,struct task_struct *next,unsigned int prev_state)
{
    struct et_config *cfg=config();if(!cfg)return 0;__u64 now=bpf_ktime_get_ns();
    if(membership(prev,cfg)) {
        struct et_event *e=reserve(prev,cfg,ET_SWITCH_OUT,now);
        if(e){e->prev_state=prev_state;e->preempt=preempt;
            e->state=preempt||!prev_state?ET_RUNNABLE:(prev_state&4||prev_state&8)?ET_STOPPED:
                (prev_state&2)&&!(prev_state&0x400)?ET_SLEEP_D:ET_SLEEP_S;
            peer(e,next);
            if(cfg->kernel_stacks){e->stack_bytes=bpf_get_stack(ctx,e->kernel_stack,sizeof(e->kernel_stack),0);
                if(e->stack_bytes>0)e->flags|=ET_STACK_VALID;else{e->flags|=ET_STACK_FAILED;count(ET_STACK_ERRORS);}}
            submit(e);}
    }
    if(membership(next,cfg)){struct et_event *e=reserve(next,cfg,ET_SWITCH_IN,now);if(e){peer(e,prev);submit(e);}}
    return 0;
}
static __always_inline int wake(struct task_struct *task,int is_new)
{
    struct et_config *cfg=config();if(!cfg||!membership(task,cfg))return 0;
    struct et_identity id={};if(identity(&id,task)){count(ET_ID_READ_ERRORS);return 0;}
    __u64 key=task_key(&id),attempt=0;
    struct et_wake_pending *w=bpf_map_lookup_elem(&et_wake_pending,&key);
    if(!is_new&&w&&w->task.thread_birth_ns==id.thread_birth_ns&&w->task.process_birth_ns==id.process_birth_ns)attempt=w->attempt_ns;
    if(!is_new&&!attempt)count(ET_WAKE_REFERENCE_MISSING);
    if(is_new&&w)count(ET_WAKE_CONTEXT_COLLISION);
    struct et_event *e=reserve(task,cfg,ET_WAKEUP,bpf_ktime_get_ns());
    if(e){
        if(is_new)e->flags|=ET_WAKEUP_NEW;
        else if(attempt){e->start_ns=attempt;e->flags|=ET_WAKE_ATTEMPT_VALID;}
        else e->flags|=ET_WAKE_ATTEMPT_MISSING;
        peer(e,(void *)bpf_get_current_task_btf());submit(e);}
    /* WAKEUP loss must not strand a map entry; transport loss stays fatal. */
    if(w&&bpf_map_delete_elem(&et_wake_pending,&key))count(ET_WAKE_CONTEXT_DELETE_ERRORS);
    return 0;
}
SEC("tp_btf/sched_waking")
int BPF_PROG(et_waking,struct task_struct *task)
{
    (void)ctx;struct et_config *cfg=config();if(!cfg||!membership(task,cfg))return 0;
    struct et_wake_pending w={};if(identity(&w.task,task)){count(ET_ID_READ_ERRORS);return 0;}
    w.attempt_ns=bpf_ktime_get_ns();__u64 key=task_key(&w.task);
    if(bpf_map_lookup_elem(&et_wake_pending,&key))count(ET_WAKE_CONTEXT_COLLISION);
    if(bpf_map_update_elem(&et_wake_pending,&key,&w,BPF_ANY))count(ET_WAKE_CONTEXT_FULL);
    struct et_event *e=reserve(task,cfg,ET_WAKING,w.attempt_ns);
    if(e){peer(e,(void *)bpf_get_current_task_btf());submit(e);}return 0;
}
SEC("tp_btf/sched_wakeup") int BPF_PROG(et_wakeup,struct task_struct *task){(void)ctx;return wake(task,0);}
SEC("tp_btf/sched_wakeup_new") int BPF_PROG(et_wakeup_new,struct task_struct *task){(void)ctx;return wake(task,1);}
static __always_inline void exit_wake_context(__u64 key)
{
    if(bpf_map_lookup_elem(&et_wake_pending,&key)){
        count(ET_WAKE_EXIT_UNRESOLVED);
        if(bpf_map_delete_elem(&et_wake_pending,&key))count(ET_WAKE_CONTEXT_DELETE_ERRORS);
    }
}
static __always_inline void discard_seccomp_context(__u64 key)
{
    if(bpf_map_lookup_elem(&et_seccomp_pending,&key)){
        count(ET_SECCOMP_CONTEXT_ERRORS);
        if(bpf_map_delete_elem(&et_seccomp_pending,&key))count(ET_CONTEXT_DELETE_ERRORS);
    }
}
/* This kernel's BTF-validated bool __seccomp_filter(int,bool) returns false
 * when it skips dispatch BEFORE raw_syscalls/sys_enter. Observe that actual
 * result, then record saved syscall number/result, never infer from errno.
 * Fast allow/cgroup rejects do not emit events or allocate per-thread state. */
SEC("fexit/__seccomp_filter")
int BPF_PROG(et_seccomp_skip,int this_syscall,_Bool recheck_after_trace,_Bool allowed)
{
    (void)ctx;if(allowed)return 0;
    struct et_config *cfg=config();if(!cfg||bpf_get_current_ancestor_cgroup_id(cfg->root_level)!=cfg->root_cgroup_id)return 0;
    struct task_struct *task=(void *)bpf_get_current_task_btf();
    struct et_seccomp_pending proof={};unsigned long nr=0,result=0;__u32 status=0;
    if(identity(&proof.task,task)){count(ET_ID_READ_ERRORS);return 0;}
    struct pt_regs *regs=(void *)bpf_task_pt_regs(task);
    if(!regs||bpf_core_read(&status,sizeof(status),&task->thread_info.status)||
        bpf_core_read(&nr,sizeof(nr),&regs->orig_ax)||bpf_core_read(&result,sizeof(result),&regs->ax)){
        count(ET_SECCOMP_READ_ERRORS);return 0;}
    if((status&2)||(nr&0x40000000ULL)){count(ET_UNSUPPORTED_ABI);return 0;}
    if((__s64)nr!=this_syscall||this_syscall<0){count(ET_SECCOMP_CONTEXT_ERRORS);return 0;}
    __u64 key=task_key(&proof.task);
    if(pending(&proof.task)||bpf_map_lookup_elem(&et_seccomp_pending,&key)){
        count(ET_SECCOMP_CONTEXT_ERRORS);return 0;}
    proof.proof_ns=bpf_ktime_get_ns();proof.nr=this_syscall;proof.result=(__s64)result;
    if(bpf_map_update_elem(&et_seccomp_pending,&key,&proof,BPF_NOEXIST)){count(ET_SECCOMP_CONTEXT_ERRORS);return 0;}
    struct et_event *e=reserve(task,cfg,ET_SECCOMP_SKIP,proof.proof_ns);
    if(e){e->syscall_nr=proof.nr;e->result=proof.result;e->args[0]=recheck_after_trace;submit(e);}
    count(ET_SECCOMP_SKIPS);return 0;
}
SEC("tp_btf/sched_process_fork")
int BPF_PROG(et_fork,struct task_struct *parent,struct task_struct *child)
{
    (void)ctx;struct et_config *cfg=config();if(!cfg)return 0;
    __u64 parent_selected=membership(parent,cfg);
    if(!parent_selected&&!membership(child,cfg))return 0;
    struct et_identity child_id={},parent_id={};
    __u64 parent_call_id=0;__s32 parent_nr=-1;int parent_regs_valid=0;
    if(identity(&child_id,child)){count(ET_ID_READ_ERRORS);}
    else if(identity(&parent_id,parent)){count(ET_ID_READ_ERRORS);}
    else{
        struct et_pending *call=parent_selected?pending(&parent_id):0;
        if(call&&(call->nr==56||call->nr==57||call->nr==58||call->nr==435)){
            parent_call_id=call->call_id;parent_nr=call->nr;
        }else if(!call&&parent==(struct task_struct *)bpf_get_current_task_btf()){
            /* cgroup migration/CLONE_INTO_CGROUP can expose a fork after the
             * parent's syscall entry happened outside the selected scope.
             * Read exact native orig_ax; never invent the missing sys_enter. */
            __u32 status=0;__u64 original_nr=0;
            struct pt_regs *regs=(void *)bpf_task_pt_regs(parent);
            if(!regs||bpf_core_read(&status,sizeof(status),&parent->thread_info.status)||
                bpf_core_read(&original_nr,sizeof(original_nr),&regs->orig_ax))count(ET_FORK_REGS_READ_ERRORS);
            else if((status&2)||(original_nr&0x40000000ULL))count(ET_UNSUPPORTED_ABI);
            else if(original_nr==56||original_nr==57||original_nr==58||original_nr==435){
                parent_nr=original_nr;parent_regs_valid=1;
            }
        }
        struct et_enrollment *s=enrollment(&child_id);
        if(s){s->fork_nr=-2; /* birth observed: not an enrollment boundary */
            if(parent_call_id||parent_regs_valid)s->fork_nr=parent_nr;}
    }
    struct et_event *e=reserve(child,cfg,ET_FORK,bpf_ktime_get_ns());
    if(e){peer(e,parent);
        if(parent_call_id&&!(e->flags&ET_PEER_FAILED)){
            e->flags|=ET_FORK_PARENT_CALL_VALID;e->start_ns=parent_call_id;e->syscall_nr=parent_nr;
        }else if(parent_regs_valid&&!(e->flags&ET_PEER_FAILED)){
            e->flags|=ET_FORK_PARENT_REGS_VALID;e->syscall_nr=parent_nr;
        }
        submit(e);}return 0;
}
SEC("tp_btf/sched_process_exec")
int BPF_PROG(et_exec,struct task_struct *task,int old_pid,struct linux_binprm *bprm)
{
    (void)ctx;struct et_config *cfg=config();if(!cfg||!membership(task,cfg))return 0;
    struct et_event *e=reserve(task,cfg,ET_EXEC,bpf_ktime_get_ns());
    if(e){
        struct file *executable=0;const char *filename=0;
        e->flags|=ET_PATH_AT_EXEC_FILENAME;
        if(!bprm||bpf_core_read(&executable,sizeof(executable),&bprm->file)||file_object(&e->file,executable)){
            e->flags|=ET_OBJECT_FAILED;count(ET_OBJECT_ERRORS);
        }else e->flags|=ET_OBJECT_VALID;
        if(!bprm||bpf_core_read(&filename,sizeof(filename),&bprm->filename)||!filename){
            e->path_bytes=-1;e->flags|=ET_PATH_FAILED;count(ET_PATH_ERRORS);
        }else{
            e->path_bytes=bpf_probe_read_kernel_str(e->path,sizeof(e->path),filename);
            if(e->path_bytes>0&&e->path_bytes<(int)sizeof(e->path))e->flags|=ET_PATH_VALID;
            else{e->flags|=ET_PATH_FAILED;count(ET_PATH_ERRORS);}
        }
    }
    /* This lifecycle hook runs in current: cleanup is mandatory even if its
     * ring reservation failed. The ring drop remains a completeness failure. */
    __u64 oldkey=(bpf_get_current_pid_tgid()&0xffffffff00000000ULL)|(__u32)old_pid;
    struct et_pending *call=bpf_map_lookup_elem(&et_pending,&oldkey);
    if(call){if(e){e->syscall_call_id=call->call_id;e->syscall_nr=call->nr;}
        count(ET_CENSORED_EXEC);
        if(bpf_map_delete_elem(&et_pending,&oldkey))count(ET_CONTEXT_DELETE_ERRORS);}
    exit_wake_context(oldkey);
    discard_seccomp_context(oldkey);
    if(e){e->old_tid=old_pid;struct task_struct *p=0;bpf_core_read(&p,sizeof(p),&task->real_parent);peer(e,p);submit(e);}
    return 0;
}
SEC("tp_btf/sched_process_exit")
int BPF_PROG(et_exit,struct task_struct *task)
{
    (void)ctx;struct et_config *cfg=config();if(!cfg||!membership(task,cfg))return 0;
    struct et_event *e=reserve(task,cfg,ET_EXIT,bpf_ktime_get_ns());
    if(e){
        /* sched_process_exit precedes exit_mm/mm_release in this kernel.
         * This is only the user virtual address registered for exit clearing;
         * no user buffer is read and no successful futex wake is fabricated. */
        if(bpf_core_read(&e->args[0],sizeof(e->args[0]),&task->clear_child_tid)){
            e->flags|=ET_CLEAR_CHILD_TID_FAILED;count(ET_CLEAR_CHILD_TID_READ_ERRORS);
        }else e->flags|=ET_CLEAR_CHILD_TID_VALID;
        submit(e);}
    /* Never let lost lifecycle output strand per-thread state. The task is
     * current in sched_process_exit, so its host pid/tgid key is exact. */
    __u64 key=bpf_get_current_pid_tgid();
    if(bpf_map_lookup_elem(&et_pending,&key)){count(ET_CENSORED_EXIT);
        if(bpf_map_delete_elem(&et_pending,&key))count(ET_CONTEXT_DELETE_ERRORS);}
    if(bpf_map_lookup_elem(&et_enrolled,&key)&&bpf_map_delete_elem(&et_enrolled,&key))count(ET_CONTEXT_DELETE_ERRORS);
    exit_wake_context(key);
    discard_seccomp_context(key);
    return 0;
}
SEC("tracepoint/raw_syscalls/sys_enter")
int et_sys_enter(struct et_enter *ctx)
{
    struct et_config *cfg=config();struct task_struct *task=(void *)bpf_get_current_task_btf();
    if(!cfg||!membership(task,cfg))return 0;
    struct et_pending p={};if(identity(&p.task,task)){count(ET_ID_READ_ERRORS);return 0;}
    __u32 status=0;if(bpf_core_read(&status,sizeof(status),&task->thread_info.status)||(status&2)||(ctx->nr&0x40000000LL)){count(ET_UNSUPPORTED_ABI);return 0;}
    p.call_id=bpf_ktime_get_ns();p.nr=ctx->nr;__builtin_memcpy(p.args,ctx->args,sizeof(p.args));
    struct et_enrollment *seen=enrollment(&p.task);if(seen)seen->syscall_seen=1;
    __u64 key=task_key(&p.task);
    discard_seccomp_context(key);
    if(bpf_map_lookup_elem(&et_pending,&key)){count(ET_CONTEXT_COLLISION);if(bpf_map_delete_elem(&et_pending,&key))count(ET_CONTEXT_DELETE_ERRORS);}
    if(bpf_map_update_elem(&et_pending,&key,&p,BPF_NOEXIST)){count(ET_CONTEXT_FULL);return 0;}
    struct et_event *e=reserve(task,cfg,ET_SYSCALL_ENTER,p.call_id);
    if(e){__builtin_memcpy(e->args,p.args,sizeof(p.args));submit(e);}return 0;
}
SEC("tracepoint/raw_syscalls/sys_exit")
int et_sys_exit(struct et_leave *ctx)
{
    struct et_config *cfg=config();struct task_struct *task=(void *)bpf_get_current_task_btf();if(!cfg||!membership(task,cfg))return 0;
    struct et_identity id={};if(identity(&id,task)){count(ET_ID_READ_ERRORS);return 0;}
    struct et_pending *p=pending(&id);
    __u64 key=task_key(&id);struct et_seccomp_pending *skip=bpf_map_lookup_elem(&et_seccomp_pending,&key);
    int skip_valid=!p&&skip&&skip->task.thread_birth_ns==id.thread_birth_ns&&
        skip->task.process_birth_ns==id.process_birth_ns&&skip->task.cgroup_id==id.cgroup_id&&
        skip->nr==ctx->nr&&skip->result==ctx->ret;
    if(skip&&!skip_valid)count(ET_SECCOMP_CONTEXT_ERRORS);
    struct et_enrollment *seen=enrollment(&id);
    /* Successful exec is closed by its lifecycle event, not a fabricated
     * ordinary syscall result after the process identity transition. */
    if(!p&&!skip&&ctx->ret==0&&(ctx->nr==59||ctx->nr==322))return 0;
    struct et_event *e=reserve(task,cfg,ET_SYSCALL_EXIT,bpf_ktime_get_ns());
    if(e){e->syscall_nr=ctx->nr;e->result=ctx->ret;
        if(p&&(p->nr==ctx->nr||(p->nr==15&&ctx->nr==-1))){
            e->start_ns=p->call_id;e->end_ns=e->timestamp_ns;__builtin_memcpy(e->args,p->args,sizeof(e->args));
            /* Keep the actual exit id (-1) and restored register in raw data.
             * Only the exact observed pending rt_sigreturn may close this way. */
            if(p->nr==15&&ctx->nr==-1){e->flags|=ET_SIGRETURN_RESTORED;count(ET_SIGRETURN_RESTORED_EXITS);}
        }
        else if(skip_valid&&skip->proof_ns<e->timestamp_ns){
            e->flags|=ET_SECCOMP_SKIPPED_EXIT;e->args[0]=skip->proof_ns;
        }else if(!p&&seen&&!seen->syscall_seen){
            if(seen->fork_nr==ctx->nr&&ctx->ret==0){e->flags|=ET_FORK_CHILD_RETURN;count(ET_FORK_CHILD_RETURNS);}
            else if(seen->fork_nr==-1){e->flags|=ET_BOUNDARY_RETURN;count(ET_BOUNDARY_RETURNS);}
            else{e->flags|=ET_UNPAIRED;count(ET_UNPAIRED_RESULTS);}
        }else{e->flags|=ET_UNPAIRED;count(ET_UNPAIRED_RESULTS);}
        submit(e);}
    if(seen)seen->syscall_seen=1;
    if(skip&&bpf_map_delete_elem(&et_seccomp_pending,&key))count(ET_CONTEXT_DELETE_ERRORS);
    if(p&&bpf_map_delete_elem(&et_pending,&key))count(ET_CONTEXT_DELETE_ERRORS);return 0;
}
static __always_inline int is_read(struct et_pending *p)
{ return p&&(p->nr==0||p->nr==17||p->nr==19||p->nr==295||p->nr==327); }
static __always_inline int read_begin(struct file *file,__u64 count_bytes,int vector)
{
    struct et_config *cfg=config();if(!cfg||bpf_get_current_ancestor_cgroup_id(cfg->root_level)!=cfg->root_cgroup_id)return 0;struct et_identity id={};
    if(identity(&id,(void *)bpf_get_current_task_btf())){count(ET_ID_READ_ERRORS);return 0;}
    struct et_pending *p=pending(&id);if(!is_read(p))return 0;
    if(p->depth){p->depth++;count(ET_NESTED_VFS);return 0;}
    p->vfs_start_ns=bpf_ktime_get_ns();p->depth=1;p->vector=vector;p->requested=count_bytes;p->flags=0;
    if(file_object(&p->file,file)){p->flags|=ET_OBJECT_FAILED;count(ET_OBJECT_ERRORS);}else p->flags|=ET_OBJECT_VALID;
    return 0;
}
static __always_inline int read_end(__s64 ret)
{
    struct et_config *cfg=config();if(!cfg||bpf_get_current_ancestor_cgroup_id(cfg->root_level)!=cfg->root_cgroup_id)return 0;struct et_identity id={};
    if(identity(&id,(void *)bpf_get_current_task_btf())){count(ET_ID_READ_ERRORS);return 0;}
    struct et_pending *p=pending(&id);if(!is_read(p)||!p->depth)return 0;
    if(p->depth>1){p->depth--;return 0;}
    p->depth=0;struct et_event *e=reserve((void *)bpf_get_current_task_btf(),cfg,ET_FILE_READ,bpf_ktime_get_ns());
    if(e){e->start_ns=p->vfs_start_ns;e->end_ns=e->timestamp_ns;e->file=p->file;e->flags|=p->flags;e->result=ret;
        if(!p->vector){e->requested_bytes=p->requested;e->flags|=ET_REQUESTED_VALID;}submit(e);}return 0;
}
static __always_inline int kprobe_read_begin(struct pt_regs *ctx,int vector)
{
    struct et_config *cfg=config();
    if(!cfg||bpf_get_current_ancestor_cgroup_id(cfg->root_level)!=cfg->root_cgroup_id)return 0;
    unsigned long file=0,buffer=0,count_bytes=0;
    int error=bpf_core_read(&file,sizeof(file),&ctx->di);
    error|=bpf_core_read(&buffer,sizeof(buffer),&ctx->si);
    error|=bpf_core_read(&count_bytes,sizeof(count_bytes),&ctx->dx);
    if(error){count(ET_KPROBE_REGISTER_READ_ERRORS);return 0;}
    /* Never dereference or retain the user buffer/iovec. vlen is not bytes. */
    (void)buffer;return read_begin((void *)file,vector?0:count_bytes,vector);
}
static __always_inline int kprobe_read_end(struct pt_regs *ctx)
{
    struct et_config *cfg=config();
    if(!cfg||bpf_get_current_ancestor_cgroup_id(cfg->root_level)!=cfg->root_cgroup_id)return 0;
    unsigned long result=0;
    if(bpf_core_read(&result,sizeof(result),&ctx->ax)){count(ET_KPROBE_REGISTER_READ_ERRORS);return 0;}
    return read_end((__s64)result);
}
SEC("kprobe/vfs_read") int et_read_begin(struct pt_regs *ctx){return kprobe_read_begin(ctx,0);}
SEC("kretprobe/vfs_read") int et_read_end(struct pt_regs *ctx){return kprobe_read_end(ctx);}
SEC("kprobe/vfs_readv") int et_readv_begin(struct pt_regs *ctx){return kprobe_read_begin(ctx,1);}
SEC("kretprobe/vfs_readv") int et_readv_end(struct pt_regs *ctx){return kprobe_read_end(ctx);}
/* Observe, never enforce: preserve the input BPF LSM chain return on every
 * path. This non-sleepable LSM hook uses the trusted-path kfunc rather than
 * tracing's per-CPU recursion guard or any change to scheduler preemption. */
SEC("lsm/file_permission")
int BPF_PROG(et_file_permission,struct file *file,int mask,int ret)
{
    (void)ctx;struct et_config *cfg=config();if(!cfg||!(mask&4)||bpf_get_current_ancestor_cgroup_id(cfg->root_level)!=cfg->root_cgroup_id)return ret;
    struct task_struct *task=(void *)bpf_get_current_task_btf();struct et_identity id={};
    if(identity(&id,task)){count(ET_ID_READ_ERRORS);return ret;}struct et_pending *p=pending(&id);if(!is_read(p))return ret;
    struct et_event *e=reserve(task,cfg,ET_FILE_OBJECT,bpf_ktime_get_ns());if(!e)return ret;
    e->flags|=ET_PATH_AT_LSM_PERMISSION;e->result=ret;
    if(file_object(&e->file,file)){e->flags|=ET_OBJECT_FAILED;count(ET_OBJECT_ERRORS);}else e->flags|=ET_OBJECT_VALID;
    e->path_bytes=bpf_path_d_path(&file->f_path,e->path,sizeof(e->path));
    if(e->path_bytes>0&&e->path_bytes<=ET_PATH_BYTES)e->flags|=ET_PATH_VALID;
    else{e->flags|=ET_PATH_FAILED;count(ET_PATH_ERRORS);}submit(e);return ret;
}
char LICENSE[] SEC("license")="GPL";
