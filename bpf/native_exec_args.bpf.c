// SPDX-License-Identifier: GPL-2.0-only
/* Opt-in exact-cgroup x86-64 argv evidence. User memory at sys_enter is NOT
 * the kernel's final copied argv; concurrent userspace mutation remains possible. */
#include <linux/bpf.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "native_exec_args.h"
struct task_struct { int pid, tgid; __u64 start_boottime; struct task_struct *group_leader;
    char comm[16]; } __attribute__((preserve_access_index));
struct pt_regs { unsigned long di, si, dx; } __attribute__((preserve_access_index));
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct nea_config); } nea_config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,4096); __type(key,__u64); __type(value,struct nea_pending); } nea_pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,NEA_HEALTH_COUNT); __type(key,__u32); __type(value,__u64); } nea_health SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,16*1024*1024); } nea_events SEC(".maps");

static __always_inline __u64 count(__u32 index)
{ __u64 *value=bpf_map_lookup_elem(&nea_health,&index); return value?__sync_fetch_and_add(value,1)+1:0; }
static __always_inline struct nea_config *config(void)
{ __u32 zero=0;struct nea_config *cfg=bpf_map_lookup_elem(&nea_config,&zero);
  return cfg&&cfg->enabled&&cfg->cgroup_id&&bpf_get_current_cgroup_id()==cfg->cgroup_id?cfg:0; }
static __always_inline int current_identity(struct nea_pending *id)
{ struct task_struct *task=(void *)bpf_get_current_task_btf(),*leader=0;
  __u64 pid=bpf_get_current_pid_tgid();id->tid=(__u32)pid;id->tgid=pid>>32;
  id->cgroup_id=bpf_get_current_cgroup_id();
  if(!task||bpf_core_read(&id->thread_birth_ns,sizeof(id->thread_birth_ns),&task->start_boottime)||
     bpf_core_read(&leader,sizeof(leader),&task->group_leader)||!leader||
     bpf_core_read(&id->process_birth_ns,sizeof(id->process_birth_ns),&leader->start_boottime)||
     !id->thread_birth_ns||!id->process_birth_ns){count(NEA_IDENTITY_FAILURES);return -1;}return 0; }
static __always_inline void header(struct nea_event *e,struct nea_config *cfg,struct nea_pending *id,__u16 kind,__u32 size,__u64 seq)
{ e->magic=NEA_MAGIC;e->version=NEA_VERSION;e->kind=kind;e->size=size;
  __builtin_memcpy(e->boot_id,cfg->boot_id,16);e->timestamp_ns=bpf_ktime_get_ns();e->cpu_seq=seq;
  e->root_cgroup_id=cfg->cgroup_id;e->entry_ns=id->entry_ns;e->thread_birth_ns=id->thread_birth_ns;
  e->process_birth_ns=id->process_birth_ns;e->cgroup_id=id->cgroup_id;e->tid=id->tid;e->tgid=id->tgid;
  e->cpu=bpf_get_smp_processor_id();e->syscall_nr=id->nr;bpf_get_current_comm(e->comm,sizeof(e->comm)); }
static __always_inline void marker(struct nea_config *cfg,struct nea_pending *id,__u16 kind,__s64 result,__u32 old_tid,__u32 flags)
{ __u64 seq=count(NEA_SEQUENCE);struct nea_event *e=bpf_ringbuf_reserve(&nea_events,NEA_HEADER_BYTES,0);
  if(!e){count(NEA_RING_DROPS);return;}__builtin_memset(e,0,NEA_HEADER_BYTES);
  header(e,cfg,id,kind,NEA_HEADER_BYTES,seq);e->result=result;e->old_tid=old_tid;e->flags=flags;
  bpf_ringbuf_submit(e,0);
  if(kind==NEA_SUCCESS)count(NEA_SUCCESSES);else if(kind==NEA_FAILED)count(NEA_FAILURES);
  else if(kind==NEA_ABORTED)count(NEA_ABORTS);else count(NEA_UNCONFIRMED_RESULTS); }
static __always_inline void remove_pending(__u64 key)
{ if(bpf_map_delete_elem(&nea_pending,&key))count(NEA_DELETE_ERRORS); }

SEC("raw_tracepoint/sys_enter")
int nea_enter(struct bpf_raw_tracepoint_args *ctx)
{ __s64 nr=ctx->args[1];if(nr!=59&&nr!=322)return 0;
  struct nea_config *cfg=config();if(!cfg)return 0;count(NEA_ATTEMPTED_ENTRIES);
  struct nea_pending id={};if(current_identity(&id))return 0;
  id.entry_ns=bpf_ktime_get_ns();id.nr=nr;__u64 key=bpf_get_current_pid_tgid();
  if(bpf_map_lookup_elem(&nea_pending,&key))count(NEA_PENDING_COLLISIONS);
  if(bpf_map_update_elem(&nea_pending,&key,&id,BPF_ANY)){count(NEA_PENDING_FULL);return 0;}
  __u64 seq=count(NEA_SEQUENCE);struct nea_event *e=bpf_ringbuf_reserve(&nea_events,NEA_ENTRY_BYTES,0);
  if(!e){count(NEA_RING_DROPS);return 0;}
  /* LLVM's BPF backend does not lower a 33-KiB builtin memset. A bounded
   * aligned loop initializes every exported byte without a large BPF stack. */
#pragma clang loop unroll(disable)
  for(int zero=0;zero<NEA_ENTRY_BYTES/8;zero++)((volatile __u64 *)e)[zero]=0;
  header(e,cfg,&id,NEA_ENTRY,NEA_ENTRY_BYTES,seq);
  struct pt_regs *regs=(void *)ctx->args[0];__u64 filename=0,argv=0;
  int error=nr==59?(bpf_core_read(&filename,sizeof(filename),&regs->di)|bpf_core_read(&argv,sizeof(argv),&regs->si)):
      (bpf_core_read(&filename,sizeof(filename),&regs->si)|bpf_core_read(&argv,sizeof(argv),&regs->dx));
  if(error){e->flags|=NEA_FILENAME_FAILED|NEA_ARGV_POINTER_FAILED;count(NEA_READ_FAILURES);goto submit;}
  long bytes=bpf_probe_read_user_str(e->filename,NEA_FILENAME_BYTES,(void *)filename);
  if(bytes<=0){e->flags|=NEA_FILENAME_FAILED;count(NEA_READ_FAILURES);}else{
      e->filename_bytes=bytes;if(bytes==NEA_FILENAME_BYTES)e->flags|=NEA_FILENAME_TRUNCATED;}
  if(!argv)goto submit;
#pragma unroll
  for(int i=0;i<NEA_MAX_ARGS;i++){
      __u64 arg=0;if(bpf_probe_read_user(&arg,sizeof(arg),(void *)(argv+i*8))){
          e->flags|=NEA_ARGV_POINTER_FAILED;count(NEA_READ_FAILURES);goto submit;}
      if(!arg)goto submit;e->argc=i+1;
      bytes=bpf_probe_read_user_str(e->argv[i],NEA_ARG_BYTES,(void *)arg);
      if(bytes<=0){e->argv_flags[i]=NEA_ARG_FAILED;e->flags|=NEA_ARGV_STRING_FAILED;count(NEA_READ_FAILURES);goto submit;}
      e->argv_bytes[i]=bytes;e->argv_flags[i]=bytes==NEA_ARG_BYTES?NEA_ARG_TRUNCATED:NEA_ARG_COMPLETE;
      if(bytes==NEA_ARG_BYTES)e->flags|=NEA_ARGV_STRING_TRUNCATED;
  }
  e->flags|=NEA_ARGC_TRUNCATED;
submit:
  bpf_ringbuf_submit(e,0);count(NEA_ENTRIES);return 0; }

SEC("raw_tracepoint/sys_exit")
int nea_leave(struct bpf_raw_tracepoint_args *ctx)
{ struct nea_config *cfg=config();if(!cfg)return 0;__u64 key=bpf_get_current_pid_tgid();
  struct nea_pending *pending=bpf_map_lookup_elem(&nea_pending,&key);if(!pending)return 0;
  struct nea_pending id={};if(current_identity(&id))return 0;
  if(id.thread_birth_ns!=pending->thread_birth_ns){count(NEA_PENDING_COLLISIONS);remove_pending(key);return 0;}
  __s64 result=ctx->args[1];marker(cfg,pending,result<0?NEA_FAILED:NEA_UNCONFIRMED,result,0,0);
  remove_pending(key);return 0; }

SEC("raw_tracepoint/sched_process_exec")
int nea_exec(struct bpf_raw_tracepoint_args *ctx)
{ struct nea_config *cfg=config();if(!cfg)return 0;__u32 old_tid=ctx->args[1];
  struct nea_pending id={};if(current_identity(&id))return 0;
  __u64 key=((__u64)id.tgid<<32)|old_tid;
  struct nea_pending *pending=bpf_map_lookup_elem(&nea_pending,&key);
  if(!pending||pending->thread_birth_ns!=id.thread_birth_ns){count(NEA_UNMATCHED_SUCCESS);
      id.nr=-1;marker(cfg,&id,NEA_SUCCESS,0,old_tid,NEA_ENTRY_MISSING);return 0;}
  /* Keep the exact pre-exec identity for the reference. old_tid records
   * de-thread; this is not a claim that post-exec process birth is unchanged. */
  marker(cfg,pending,NEA_SUCCESS,0,old_tid,0);remove_pending(key);return 0; }

SEC("raw_tracepoint/sched_process_exit")
int nea_exit(struct bpf_raw_tracepoint_args *ctx)
{ (void)ctx;struct nea_config *cfg=config();if(!cfg)return 0;__u64 key=bpf_get_current_pid_tgid();
  struct nea_pending *pending=bpf_map_lookup_elem(&nea_pending,&key);if(!pending)return 0;
  marker(cfg,pending,NEA_ABORTED,0,0,0);remove_pending(key);return 0; }
char LICENSE[] SEC("license")="GPL";
