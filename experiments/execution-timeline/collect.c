// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>
#include "execution_timeline.h"
_Static_assert(sizeof(struct et_event)==688,"execution timeline v1 ABI changed");

static volatile sig_atomic_t stopping;
static volatile sig_atomic_t stop_signal;
/* Explicit buffers: setvbuf(NULL, ..., size) need not honor the requested size.
 * Capture raw is closed before its buffer is reused by deferred/offline reads. */
static char raw_stdio_buffer[1048576],json_stdio_buffer[262144];
static const char *kinds[]={"INVALID","SWITCH_OUT","SWITCH_IN","WAKEUP","FORK","EXEC","EXIT","SYSCALL_ENTER","SYSCALL_EXIT","FILE_READ","FILE_OBJECT","WAKING","SECCOMP_SKIP"};
static const char *states[]={"UNKNOWN","RUNNABLE","SLEEP_D","SLEEP_S","STOPPED"};
static const char *health_names[]={"attempted","emitted","ring_drops","identity_read_errors","context_full","context_collision","unpaired_results","object_errors","stack_errors","path_errors","unsupported_abi","nested_vfs","censored_exec","censored_exit","context_delete_errors","boundary_returns","fork_child_returns","sigreturn_restored_exits","clear_child_tid_read_errors","wake_context_full","wake_context_collision","wake_reference_missing","wake_context_delete_errors","wake_exit_unresolved","kprobe_register_read_errors","fork_regs_read_errors","seccomp_skips","seccomp_read_errors","seccomp_context_errors"};
_Static_assert(sizeof(health_names)/sizeof(health_names[0])==ET_HEALTH_COUNT,"health counter labels differ from kernel map");
struct seq { uint64_t value; uint32_t cpu; };
struct program_diagnostic {const char *program,*section;uint64_t recursion_misses;uint32_t id;int info_error;};
struct output {
    FILE *raw,*json;struct seq *seq;size_t records,capacity;
    uint64_t max_bytes,bytes,parse_errors,write_errors,cap_discarded;
    uint64_t sequence_errors,sequence_gaps,duplicate_sequences;int truncated_tail;
};
static void on_signal(int sig){stop_signal=sig;stopping=1;}
static uint64_t mono(void){struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts))return 0;return (uint64_t)ts.tv_sec*1000000000ULL+ts.tv_nsec;}
static void string(FILE *out,const char *str,size_t n)
{
    fputc('"',out);for(size_t i=0;i<n&&str[i];i++){unsigned char c=str[i];
        if(c=='"'||c=='\\'){fputc('\\',out);fputc(c,out);}else if(c<32||c>=127)fprintf(out,"\\u%04x",c);else fputc(c,out);}
    fputc('"',out);
}
static void uuid(FILE *out,const unsigned char *bytes)
{
    fputc('"',out);for(int i=0;i<16;i++){if(i==4||i==6||i==8||i==10)fputc('-',out);fprintf(out,"%02x",bytes[i]);}fputc('"',out);
}
static void identity(FILE *out,const struct et_identity *id)
{
    fprintf(out,"{\"tid\":%u,\"tgid\":%u,\"thread_birth_ns\":%llu,\"process_birth_ns\":%llu,\"cgroup_id\":%llu,\"comm\":",
        id->tid,id->tgid,(unsigned long long)id->thread_birth_ns,(unsigned long long)id->process_birth_ns,(unsigned long long)id->cgroup_id);
    string(out,id->comm,sizeof(id->comm));fputc('}',out);
}
static int valid(const struct et_event *e)
{
    if(e->magic!=ET_MAGIC||e->version!=ET_VERSION||e->size!=sizeof(*e)||e->kind<ET_SWITCH_OUT||e->kind>ET_SECCOMP_SKIP||
        !e->timestamp_ns||!e->cpu_seq||!e->root_cgroup_id||e->state>ET_STOPPED||e->cpu>1048576U||(e->flags&~33554431U))return -1;
    if((e->flags&ET_PATH_AT_EXEC_FILENAME)&&(e->kind!=ET_EXEC||(e->flags&ET_PATH_AT_LSM_PERMISSION)))return -1;
    if(e->flags&ET_PATH_AT_EXEC_FILENAME){
        unsigned object=e->flags&(ET_OBJECT_VALID|ET_OBJECT_FAILED),path=e->flags&(ET_PATH_VALID|ET_PATH_FAILED);
        if(!object||(object&(object-1))||!path||(path&(path-1))||((e->flags&ET_PATH_VALID)&&e->path_bytes>=ET_PATH_BYTES))return -1;
    }
    if(e->kind==ET_SECCOMP_SKIP&&(e->flags||e->syscall_call_id||e->start_ns||e->end_ns||e->syscall_nr<0||
        e->args[0]>1||e->args[1]||e->args[2]||e->args[3]||e->args[4]||e->args[5]))return -1;
    if((e->flags&ET_SECCOMP_SKIPPED_EXIT)&&(e->kind!=ET_SYSCALL_EXIT||e->flags!=ET_SECCOMP_SKIPPED_EXIT||
        e->syscall_call_id||e->start_ns||e->end_ns||e->syscall_nr<0||!e->args[0]||e->args[0]>=e->timestamp_ns||
        e->args[1]||e->args[2]||e->args[3]||e->args[4]||e->args[5]))return -1;
    if((e->flags&ET_SIGRETURN_RESTORED)&&(e->kind!=ET_SYSCALL_EXIT||e->syscall_nr!=-1||!e->syscall_call_id||e->start_ns!=e->syscall_call_id||e->end_ns!=e->timestamp_ns))return -1;
    if((e->flags&(ET_CLEAR_CHILD_TID_VALID|ET_CLEAR_CHILD_TID_FAILED))&&(e->kind!=ET_EXIT||(e->flags&(ET_CLEAR_CHILD_TID_VALID|ET_CLEAR_CHILD_TID_FAILED))==(ET_CLEAR_CHILD_TID_VALID|ET_CLEAR_CHILD_TID_FAILED)))return -1;
    if((e->flags&ET_FORK_PARENT_CALL_VALID)&&(e->kind!=ET_FORK||!e->start_ns||e->start_ns>e->timestamp_ns||e->end_ns||
        (e->syscall_nr!=56&&e->syscall_nr!=57&&e->syscall_nr!=58&&e->syscall_nr!=435)))return -1;
    if((e->flags&ET_FORK_PARENT_REGS_VALID)&&(e->kind!=ET_FORK||e->start_ns||e->end_ns||e->syscall_call_id||
        (e->flags&(ET_FORK_PARENT_CALL_VALID|ET_PEER_FAILED))||
        (e->syscall_nr!=56&&e->syscall_nr!=57&&e->syscall_nr!=58&&e->syscall_nr!=435)))return -1;
    unsigned wake_flags=e->flags&(ET_WAKE_ATTEMPT_VALID|ET_WAKEUP_NEW|ET_WAKE_ATTEMPT_MISSING);
    if(wake_flags&&(e->kind!=ET_WAKEUP||(wake_flags&(wake_flags-1))))return -1;
    if((e->flags&ET_WAKE_ATTEMPT_VALID)&&(!e->start_ns||e->start_ns>e->timestamp_ns||e->end_ns))return -1;
    if(e->kind==ET_WAKING&&(e->start_ns||e->end_ns))return -1;
    if((e->flags&ET_PATH_AT_LSM_PERMISSION)&&e->kind!=ET_FILE_OBJECT)return -1;
    if(!(e->flags&ET_IDENTITY_FAILED)&&(!e->task.tid||!e->task.tgid||!e->task.thread_birth_ns||!e->task.process_birth_ns||!e->task.cgroup_id))return -1;
    if((e->flags&ET_STACK_VALID)&&(e->stack_bytes<=0||e->stack_bytes>(int)sizeof(e->kernel_stack)||e->stack_bytes%8))return -1;
    if((e->flags&ET_PATH_VALID)&&(e->path_bytes<=0||e->path_bytes>ET_PATH_BYTES||e->path[e->path_bytes-1]))return -1;
    if((e->flags&ET_OBJECT_VALID)&&(!e->file.inode||!e->file.mount_id))return -1;
    if(e->kind==ET_FILE_READ&&(!e->syscall_call_id||!e->start_ns||e->start_ns>e->end_ns||e->end_ns!=e->timestamp_ns))return -1;
    if(e->kind==ET_FILE_READ&&(e->flags&ET_REQUESTED_VALID)&&e->result>0&&(uint64_t)e->result>e->requested_bytes)return -1;
    if(e->kind==ET_SYSCALL_ENTER&&e->syscall_call_id!=e->timestamp_ns)return -1;
    return 0;
}
static void project(FILE *out,const struct et_event *e)
{
    fprintf(out,"{\"schema_version\":1,\"event\":\"%s\",\"boot_id\":",kinds[e->kind]);uuid(out,e->boot_id);
    fprintf(out,",\"timestamp_ns\":%llu,\"cpu\":%u,\"cpu_seq\":%llu,\"root_cgroup_id\":%llu,\"caller_cgroup_id\":%llu,\"flags\":%u,\"task\":",
        (unsigned long long)e->timestamp_ns,e->cpu,(unsigned long long)e->cpu_seq,(unsigned long long)e->root_cgroup_id,(unsigned long long)e->task.cgroup_id,e->flags);
    identity(out,&e->task);fputs(",\"peer\":",out);identity(out,&e->peer);
    bool has_peer=e->kind==ET_SWITCH_OUT||e->kind==ET_SWITCH_IN||e->kind==ET_WAKEUP||e->kind==ET_FORK||e->kind==ET_EXEC||e->kind==ET_WAKING;
    fprintf(out,",\"peer_quality\":\"%s\",\"boundary_return\":%s,\"fork_child_return\":%s",
        !has_peer?"NOT_APPLICABLE":e->flags&ET_PEER_IDLE?"KNOWN_IDLE_NO_USER_THREAD_ID":e->flags&ET_PEER_FAILED?"UNRESOLVED":"STABLE_TASK_IDENTITY",
        e->flags&ET_BOUNDARY_RETURN?"true":"false",e->flags&ET_FORK_CHILD_RETURN?"true":"false");
    fprintf(out,",\"tid\":%u,\"tgid\":%u,\"thread_birth_ns\":%llu,\"process_birth_ns\":%llu,\"state\":\"%s\",\"prev_state\":%u,\"preempt\":%s,\"old_tid\":%u,\"syscall_call_id\":%llu,\"syscall_nr\":%d,\"start_ns\":",
        e->task.tid,e->task.tgid,(unsigned long long)e->task.thread_birth_ns,(unsigned long long)e->task.process_birth_ns,
        states[e->state],e->prev_state,e->preempt?"true":"false",e->old_tid,(unsigned long long)e->syscall_call_id,e->syscall_nr);
    if(e->start_ns&&!(e->flags&(ET_FORK_PARENT_CALL_VALID|ET_WAKE_ATTEMPT_VALID)))fprintf(out,"%llu",(unsigned long long)e->start_ns);else fputs("null",out);
    fputs(",\"end_ns\":",out);if(e->end_ns)fprintf(out,"%llu",(unsigned long long)e->end_ns);else fputs("null",out);
    fputs(",\"duration_ns\":",out);if(e->start_ns&&e->end_ns>=e->start_ns&&!(e->flags&(ET_FORK_PARENT_CALL_VALID|ET_WAKE_ATTEMPT_VALID)))fprintf(out,"%llu",(unsigned long long)(e->end_ns-e->start_ns));else fputs("null",out);
    fputs(",\"requested_bytes\":",out);if(e->flags&ET_REQUESTED_VALID)fprintf(out,"%llu",(unsigned long long)e->requested_bytes);else fputs("null",out);
    fputs(",\"returned_bytes\":",out);if(e->kind==ET_FILE_READ&&e->result>=0)fprintf(out,"%lld",(long long)e->result);else fputs("null",out);
    fputs(",\"return_value\":",out);if((e->kind==ET_FILE_READ||e->kind==ET_SYSCALL_EXIT||e->kind==ET_SECCOMP_SKIP)&&!(e->flags&ET_SIGRETURN_RESTORED))fprintf(out,"%lld",(long long)e->result);else fputs("null",out);
    fprintf(out,",\"seccomp_skipped_exit\":%s,\"seccomp_skip_reference_ns\":",e->flags&ET_SECCOMP_SKIPPED_EXIT?"true":"false");
    if(e->flags&ET_SECCOMP_SKIPPED_EXIT)fprintf(out,"%llu",(unsigned long long)e->args[0]);else fputs("null",out);
    fprintf(out,",\"seccomp_skip_proof\":\"%s\",\"seccomp_action\":\"%s\",\"seccomp_recheck_after_trace\":",
        e->kind==ET_SECCOMP_SKIP?"KERNEL_FEXIT_FILTER_FALSE_AND_SAVED_REGISTERS":"NOT_APPLICABLE",
        e->kind==ET_SECCOMP_SKIP||e->flags&ET_SECCOMP_SKIPPED_EXIT?"UNKNOWN_NOT_OBSERVED":"NOT_APPLICABLE");
    if(e->kind==ET_SECCOMP_SKIP)fputs(e->args[0]?"true":"false",out);else fputs("null",out);
    fprintf(out,",\"sigreturn_restored\":%s,\"syscall_entry_nr\":",e->flags&ET_SIGRETURN_RESTORED?"true":"false");
    if(e->kind==ET_SYSCALL_EXIT)fprintf(out,"%d",e->flags&ET_SIGRETURN_RESTORED?15:e->syscall_nr);else fputs("null",out);
    fputs(",\"observed_exit_syscall_nr\":",out);if(e->kind==ET_SYSCALL_EXIT)fprintf(out,"%d",e->syscall_nr);else fputs("null",out);
    fputs(",\"restored_register_value\":",out);if(e->flags&ET_SIGRETURN_RESTORED)fprintf(out,"%lld",(long long)e->result);else fputs("null",out);
    fprintf(out,",\"closure_kind\":\"%s\"",e->flags&ET_SECCOMP_SKIPPED_EXIT?"SECCOMP_SKIPPED_WITHOUT_RAW_ENTRY":e->flags&ET_SIGRETURN_RESTORED?"SIGNAL_FRAME_RESTORED_NOT_ORDINARY_RETURN":e->kind==ET_SYSCALL_EXIT?"ORDINARY_SYSCALL_RETURN":"NOT_APPLICABLE");
    fputs(",\"clear_child_tid\":",out);if(e->kind==ET_EXIT&&(e->flags&ET_CLEAR_CHILD_TID_VALID))fprintf(out,"%llu",(unsigned long long)e->args[0]);else fputs("null",out);
    fprintf(out,",\"clear_child_tid_quality\":\"%s\"",e->flags&ET_CLEAR_CHILD_TID_VALID?"KERNEL_REGISTERED_USER_ADDRESS_ONLY_NOT_WAKE_PROOF":e->flags&ET_CLEAR_CHILD_TID_FAILED?"READ_FAILED":"NOT_CAPTURED");
    fputs(",\"fork_parent_call_id\":",out);if(e->flags&ET_FORK_PARENT_CALL_VALID)fprintf(out,"%llu",(unsigned long long)e->start_ns);else fputs("null",out);
    fputs(",\"fork_parent_syscall_nr\":",out);if(e->flags&(ET_FORK_PARENT_CALL_VALID|ET_FORK_PARENT_REGS_VALID))fprintf(out,"%d",e->syscall_nr);else fputs("null",out);
    fprintf(out,",\"fork_parent_syscall_source\":\"%s\"",e->flags&ET_FORK_PARENT_CALL_VALID?"KERNEL_PARENT_PENDING_SYSCALL_ENTRY":e->flags&ET_FORK_PARENT_REGS_VALID?"KERNEL_PT_REGS_AT_FORK_NO_ENTRY_EVENT":"NOT_CAPTURED");
    fprintf(out,",\"fork_parent_call_quality\":\"%s\"",e->flags&ET_FORK_PARENT_CALL_VALID?"KERNEL_FORK_PARENT_PENDING_CALL_REFERENCE_NOT_CHILD_INTERVAL":"NOT_CAPTURED");
    fputs(",\"wake_attempt_ns\":",out);
    if(e->kind==ET_WAKING)fprintf(out,"%llu",(unsigned long long)e->timestamp_ns);
    else if(e->flags&ET_WAKE_ATTEMPT_VALID)fprintf(out,"%llu",(unsigned long long)e->start_ns);
    else fputs("null",out);
    fprintf(out,",\"wake_kind\":\"%s\",\"wake_attempt_quality\":\"%s\"",
        e->kind==ET_WAKING?"SOURCE_CPU_ATTEMPT":e->kind!=ET_WAKEUP?"NOT_APPLICABLE":e->flags&ET_WAKEUP_NEW?"NEW_TASK_NO_WAKING_REQUIRED":"EXISTING_TASK",
        e->kind==ET_WAKING?"SOURCE_CPU_CURRENT_WAKER":e->flags&ET_WAKE_ATTEMPT_VALID?"KERNEL_WAKING_REFERENCE_NOT_LOCK_OWNER_PROOF":e->flags&ET_WAKEUP_NEW?"NOT_APPLICABLE_NEW_TASK":e->flags&ET_WAKE_ATTEMPT_MISSING?"SOURCE_WAKING_NOT_CAPTURED_OR_IDENTITY_MISMATCH":"NOT_CAPTURED");
    fputs(",\"lsm_chain_return_value_at_observer\":",out);if(e->flags&ET_PATH_AT_LSM_PERMISSION)fprintf(out,"%lld",(long long)e->result);else fputs("null",out);
    fprintf(out,",\"lsm_policy_effect\":\"%s\"",e->flags&ET_PATH_AT_LSM_PERMISSION?"RETURN_INPUT_UNCHANGED":"NOT_APPLICABLE");
    fputs(",\"exec_filename\":",out);
    if((e->flags&(ET_PATH_AT_EXEC_FILENAME|ET_PATH_VALID))==(ET_PATH_AT_EXEC_FILENAME|ET_PATH_VALID))string(out,e->path,(size_t)e->path_bytes);
    else fputs("null",out);
    fprintf(out,",\"exec_filename_quality\":\"%s\",\"exec_object_quality\":\"%s\"",
        !(e->flags&ET_PATH_AT_EXEC_FILENAME)?"NOT_CAPTURED":e->flags&ET_PATH_VALID?"KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH":"READ_FAILED_OR_TRUNCATED",
        e->kind!=ET_EXEC?"NOT_APPLICABLE":e->flags&ET_OBJECT_VALID?"KERNEL_BPRM_FILE_IDENTITY":e->flags&ET_OBJECT_FAILED?"READ_FAILED":"NOT_CAPTURED");
    fputs(",\"args\":[",out);for(int i=0;i<6;i++)fprintf(out,"%s%llu",i?",":"",(unsigned long long)e->args[i]);
    fputs("],\"file\":",out);
    if(e->flags&ET_OBJECT_VALID){fprintf(out,"{\"mount_id\":%llu,\"mount_id_unique\":%llu,\"device\":%u,\"device_major\":%u,\"device_minor\":%u,\"inode\":%llu,\"generation\":%u,\"generation_valid\":%s,\"size\":%lld,\"path_quality\":\"%s\",\"path\":",
        (unsigned long long)e->file.mount_id,(unsigned long long)e->file.mount_id,e->file.device,e->file.device>>20,e->file.device&((1U<<20)-1),
        (unsigned long long)e->file.inode,e->file.generation,e->file.generation?"true":"false",(long long)e->file.size,
        e->flags&ET_PATH_VALID?(e->flags&ET_PATH_AT_EXEC_FILENAME?"KERNEL_EXEC_FILENAME_NOT_CANONICAL_PATH":e->flags&ET_PATH_AT_LSM_PERMISSION?"KERNEL_PATH_AT_LSM_PERMISSION_CANDIDATE":"KERNEL_PATH_AT_PERMISSION_CANDIDATE"):e->flags&ET_PATH_FAILED?"FAILED_OR_TRUNCATED":"NOT_CAPTURED");
        if(e->flags&ET_PATH_VALID)string(out,e->path,(size_t)e->path_bytes);else fputs("null",out);
        fputs(",\"path_raw_hex\":",out);if(e->flags&ET_PATH_VALID){fputc('"',out);for(int i=0;i<e->path_bytes-1;i++)fprintf(out,"%02x",(unsigned char)e->path[i]);fputc('"',out);}else fputs("null",out);fputc('}',out);
    }else fputs("null",out);
    fprintf(out,",\"path_errno_or_bytes\":%d,\"stack_quality\":\"%s\",\"kernel_stack\":[",e->path_bytes,
        e->flags&ET_STACK_VALID?"SWITCH_OUT_KERNEL_CONTEXT_NOT_PROVEN_CAUSE":e->flags&ET_STACK_FAILED?"FAILED":"NOT_REQUESTED");
    if(e->flags&ET_STACK_VALID)for(int i=0;i<e->stack_bytes/8;i++)fprintf(out,"%s\"0x%016llx\"",i?",":"",(unsigned long long)e->kernel_stack[i]);
    fprintf(out,"],\"kernel_stack_truncated_possible\":%s}\n",e->stack_bytes==(int)sizeof(e->kernel_stack)?"true":"false");
}
static int consume(void *context,void *data,size_t bytes)
{
    struct output *out=context;struct et_event *e=data;
    if(bytes!=sizeof(*e)||valid(e)){out->parse_errors++;stopping=1;return 0;}
    if(out->records>=out->capacity||out->bytes+bytes>out->max_bytes){out->cap_discarded++;stopping=1;return 0;}
    if(out->raw&&fwrite(data,bytes,1,out->raw)!=1){out->write_errors++;stopping=1;return 0;}
    if(out->json){project(out->json,e);if(ferror(out->json)){out->write_errors++;stopping=1;return 0;}}
    out->seq[out->records++]=(struct seq){e->cpu_seq,e->cpu};out->bytes+=bytes;
    return 0;
}
static int seq_cmp(const void *a,const void *b)
{const struct seq *x=a,*y=b;return x->cpu!=y->cpu?(x->cpu>y->cpu?1:-1):x->value==y->value?0:x->value>y->value?1:-1;}
static void sequences(struct output *out)
{
    qsort(out->seq,out->records,sizeof(*out->seq),seq_cmp);
    uint32_t cpu=UINT32_MAX;uint64_t last=0;
    for(size_t i=0;i<out->records;i++){struct seq *s=&out->seq[i];if(s->cpu!=cpu){cpu=s->cpu;last=0;}
        if(s->value!=last+1){out->sequence_errors++;if(s->value==last)out->duplicate_sequences++;else out->sequence_gaps++;}
        last=s->value;}
}
static int flush(FILE *file)
{return file&&(fflush(file)||fsync(fileno(file)))?-1:0;}
static FILE *fresh(const char *path)
{int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);return fd<0?NULL:fdopen(fd,"wb");}
/* The same fixed-ABI reader is used for offline --decode and post-detach
 * projection. Do not consult the live stop flag: a signal already stopped the
 * capture, but must not truncate the remaining evidence projection. */
static void read_raw(FILE *input,struct output *out)
{
    struct et_event event;size_t n=0;
    while((n=fread(&event,1,sizeof(event),input))==sizeof(event)){
        consume(out,&event,n);
        if(out->parse_errors||out->write_errors||out->cap_discarded)break;
    }
    if(n&&n!=sizeof(event))out->truncated_tail=1;
    if(ferror(input))out->parse_errors++;
}
static int same_raw_identity(const struct stat *a,const struct stat *b)
{
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_size==b->st_size&&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static int deferred_projection(const char *raw,FILE *json,struct output *capture,const struct stat *expected)
{
    int fd=open(raw,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat before,after;
    if(fd<0)return -1;
    if(fstat(fd,&before)||!same_raw_identity(&before,expected)){close(fd);return -1;}
    FILE *input=fdopen(fd,"rb");if(!input){close(fd);return -1;}
    if(setvbuf(input,raw_stdio_buffer,_IOFBF,sizeof(raw_stdio_buffer))){fclose(input);return -1;}
    struct output projected={.json=json,.seq=capture->seq,.capacity=capture->capacity,.max_bytes=capture->max_bytes};
    read_raw(input,&projected);sequences(&projected);
    int failed=projected.parse_errors||projected.write_errors||projected.cap_discarded||projected.truncated_tail||
        projected.records!=capture->records||projected.bytes!=capture->bytes||
        projected.sequence_errors!=capture->sequence_errors||
        projected.sequence_gaps!=capture->sequence_gaps||projected.duplicate_sequences!=capture->duplicate_sequences;
    if(fstat(fileno(input),&after)||!same_raw_identity(&before,&after))failed=1;
    if(fclose(input))failed=1;
    return failed?-1:0;
}
static int decode(const char *raw,const char *json,size_t capacity,uint64_t max_bytes)
{
    FILE *input=fopen(raw,"rb");FILE *output=fresh(json);if(!input||!output){perror("decode input/fresh output");if(input)fclose(input);if(output)fclose(output);return 1;}
    struct output out={.json=output,.capacity=capacity,.max_bytes=max_bytes};out.seq=calloc(capacity,sizeof(*out.seq));
    if(!out.seq){fclose(input);fclose(output);return 1;}
    if(setvbuf(input,raw_stdio_buffer,_IOFBF,sizeof(raw_stdio_buffer))||setvbuf(output,json_stdio_buffer,_IOFBF,sizeof(json_stdio_buffer)))out.write_errors++;
    if(!out.write_errors)read_raw(input,&out);
    sequences(&out);if(flush(output))out.write_errors++;
    int bad=out.parse_errors||out.write_errors||out.cap_discarded||out.duplicate_sequences||out.truncated_tail;
    fprintf(stderr,"{\"schema_version\":1,\"mode\":\"OFFLINE_DECODE_NO_BPF\",\"status\":\"%s\",\"event_bytes\":%zu,\"records\":%zu,\"parse_errors\":%llu,\"sequence_errors\":%llu,\"sequence_gaps\":%llu,\"duplicate_sequences\":%llu,\"truncated_tail\":%s,\"cap_discarded\":%llu,\"write_errors\":%llu}\n",
        bad?"INCOMPLETE":out.sequence_gaps?"DECODED_WITH_SEQUENCE_GAPS_NOT_RUN_VERIFICATION":"DECODED_RAW_RECORDS_ONLY_NOT_RUN_VERIFICATION",sizeof(struct et_event),out.records,
        (unsigned long long)out.parse_errors,(unsigned long long)out.sequence_errors,(unsigned long long)out.sequence_gaps,(unsigned long long)out.duplicate_sequences,out.truncated_tail?"true":"false",(unsigned long long)out.cap_discarded,(unsigned long long)out.write_errors);
    free(out.seq);fclose(input);if(fclose(output))bad=1;return bad?1:0;
}
static int root_identity(const char *path,__u64 *id,__u32 *level)
{
    char resolved[PATH_MAX];struct stat st;
    if(!realpath(path,resolved)||strcmp(path,resolved)||strncmp(path,"/sys/fs/cgroup",14)||
        (path[14]&&path[14]!='/')||stat(path,&st)||!S_ISDIR(st.st_mode))return -1;
    *id=st.st_ino;*level=0;for(const char *p=path+14;*p;p++)if(*p=='/')(*level)++;
    return *level>=32?-1:0;
}
static int boot_id(unsigned char bytes[16],char text[40])
{
    FILE *f=fopen("/proc/sys/kernel/random/boot_id","r");if(!f)return -1;
    if(!fgets(text,40,f)){fclose(f);return -1;}fclose(f);text[strcspn(text,"\n")]=0;
    if(strlen(text)!=36)return -1;
    int p=0;
    for(int i=0;i<16;i++){if(p==8||p==13||p==18||p==23)p++;unsigned v;if(sscanf(text+p,"%2x",&v)!=1)return -1;bytes[i]=v;p+=2;}return 0;
}
static int active_bpf_lsm(void)
{
    char text[4096];FILE *source=fopen("/sys/kernel/security/lsm","r");if(!source)return 0;
    if(!fgets(text,sizeof(text),source)||ferror(source)){fclose(source);return 0;}
    int complete=strchr(text,'\n')||feof(source);fclose(source);if(!complete)return 0;
    char *save=NULL;for(char *name=strtok_r(text,",\n",&save);name;name=strtok_r(NULL,",\n",&save))if(!strcmp(name,"bpf"))return 1;
    return 0;
}
#define ET_TRACE_GROUP "allox_execution_timeline"
#define ET_KRET_MAXACTIVE 4096
#define ET_TRACE_TEXT_LIMIT (4U*1024*1024)
struct owned_hook {
    char name[128],program[32],anchor[32],definition[512];
    dev_t device;ino_t inode;uint64_t event_id;
    uint64_t initial_hits,initial_misses,hits,misses,initial_begin_ns,initial_end_ns,final_begin_ns,final_end_ns;
    int is_return,created,anchored,initial_valid,final_valid,removed,cleanup_error;
};
struct owned_traces {
    char root[PATH_MAX];struct stat root_identity;struct owned_hook hooks[4];
    int count;unsigned required_mask;uint64_t errors,misses,cleanup_errors;uint32_t function_ids[2],registers_id,orig_ax_offset,ax_offset,seccomp_function_id;
    char boot_id[40];uint64_t root_cgroup_id,capture_start_ns,capture_end_ns;
};
static int path_join(char *out,size_t cap,const char *root,const char *suffix)
{
    size_t a=strlen(root),b=strlen(suffix);if(a+b+2>cap)return -1;
    memcpy(out,root,a);out[a]='/';memcpy(out+a+1,suffix,b+1);return 0;
}
static int trace_text(const char *path,char **result)
{
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    char *text=malloc(ET_TRACE_TEXT_LIMIT+1);if(!text){close(fd);return -1;}
    size_t used=0;int error=0;
    /* proc sysctl handlers can reject multi-megabyte reads with ENOMEM.
     * Bound each syscall, independently of the bounded total text size. */
    while(used<ET_TRACE_TEXT_LIMIT){size_t request=ET_TRACE_TEXT_LIMIT-used;if(request>4096)request=4096;
        ssize_t got=read(fd,text+used,request);
        if(got<0&&errno==EINTR)continue;
        if(got<0){error=1;break;}if(!got)break;used+=(size_t)got;}
    if(used==ET_TRACE_TEXT_LIMIT){char c;if(read(fd,&c,1)!=0)error=1;}
    if(memchr(text,0,used))error=1;
    if(close(fd))error=1;
    if(error){free(text);return -1;}text[used]=0;*result=text;return 0;
}
static int trace_command(const struct owned_traces *traces,const char *command)
{
    char path[PATH_MAX];if(path_join(path,sizeof(path),traces->root,"kprobe_events"))return -1;
    int fd=open(path,O_WRONLY|O_APPEND|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    size_t size=strlen(command);ssize_t wrote;
    do{wrote=write(fd,command,size);}while(wrote<0&&errno==EINTR);
    int error=wrote!=(ssize_t)size;if(close(fd))error=1;return error?-1:0;
}
static int decimal(const char *text,uint64_t *result)
{
    if(!*text)return -1;
    for(const char *p=text;*p;p++)if(!isdigit((unsigned char)*p))return -1;
    char *end;errno=0;unsigned long long value=strtoull(text,&end,10);
    if(errno||*end)return -1;
    *result=value;return 0;
}
static int profile_text(char *text,const char *name,uint64_t *hits,uint64_t *misses)
{
    int found=0;char *save=NULL;
    for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
        char key[128],a[64],b[64],extra;
        int n=sscanf(line,"%127s %63s %63s %c",key,a,b,&extra);
        if(n<1||strcmp(key,name))continue;
        if(++found!=1||n!=3||decimal(a,hits)||decimal(b,misses))return -1;
    }
    return found==1?0:-1;
}
static int hook_profile(const struct owned_traces *traces,const struct owned_hook *hook,uint64_t *hits,uint64_t *misses)
{
    char path[PATH_MAX],*text=NULL;
    if(path_join(path,sizeof(path),traces->root,"kprobe_profile")||trace_text(path,&text))return -1;
    int result=profile_text(text,hook->name,hits,misses);free(text);return result;
}
static int definition_text(char *text,const struct owned_hook *hook,char output[512])
{
    char token[256],prefix[32];snprintf(token,sizeof(token),ET_TRACE_GROUP "/%s",hook->name);
    if(hook->is_return)snprintf(prefix,sizeof(prefix),"r%d",ET_KRET_MAXACTIVE);else strcpy(prefix,"p");
    int found=0;char *save=NULL;
    for(char *line=strtok_r(text,"\n",&save);line;line=strtok_r(NULL,"\n",&save)){
        char head[320],anchor[64],extra;int n=sscanf(line,"%319s %63s %c",head,anchor,&extra);
        char *colon=n>=1?strchr(head,':'):NULL;if(!colon||strcmp(colon+1,token))continue;
        *colon=0;
        char alternative[64];snprintf(alternative,sizeof(alternative),"%s+0",hook->anchor);
        if(++found!=1||n!=2||strcmp(head,prefix)||(strcmp(anchor,hook->anchor)&&strcmp(anchor,alternative)))return -1;
        if(strlen(line)>=512)return -1;
        strcpy(output,line);
    }
    return found==1?0:-1;
}
static int hook_identity(const struct owned_traces *traces,const struct owned_hook *hook,struct stat *identity,uint64_t *id,char definition[512])
{
    struct stat root;char path[PATH_MAX],suffix[320],*text=NULL;
    if(lstat(traces->root,&root)||root.st_dev!=traces->root_identity.st_dev||root.st_ino!=traces->root_identity.st_ino)return -1;
    snprintf(suffix,sizeof(suffix),"events/" ET_TRACE_GROUP "/%s",hook->name);
    if(path_join(path,sizeof(path),traces->root,suffix)||lstat(path,identity)||!S_ISDIR(identity->st_mode))return -1;
    strcat(suffix,"/id");if(path_join(path,sizeof(path),traces->root,suffix)||trace_text(path,&text))return -1;
    size_t used=strlen(text);while(used&&isspace((unsigned char)text[used-1]))text[--used]=0;
    int error=decimal(text,id)||!*id||*id>UINT32_MAX;free(text);text=NULL;if(error)return -1;
    if(path_join(path,sizeof(path),traces->root,"kprobe_events")||trace_text(path,&text))return -1;
    error=definition_text(text,hook,definition);free(text);return error;
}
static int verify_hook(const struct owned_traces *traces,const struct owned_hook *hook)
{
    struct stat st;uint64_t id;char definition[512];
    return !hook->anchored||hook_identity(traces,hook,&st,&id,definition)||st.st_dev!=hook->device||st.st_ino!=hook->inode||
        id!=hook->event_id||strcmp(definition,hook->definition)?-1:0;
}
static const struct btf_type *btf_base(const struct btf *btf,uint32_t id)
{
    for(int i=0;i<16;i++){const struct btf_type *type=btf__type_by_id(btf,id);if(!type)return NULL;
        unsigned kind=btf_kind(type);
        if(kind==BTF_KIND_TYPEDEF||kind==BTF_KIND_CONST||kind==BTF_KIND_VOLATILE||kind==BTF_KIND_RESTRICT||kind==BTF_KIND_TYPE_TAG)id=type->type;
        else return type;}
    return NULL;
}
static int btf_integer(const struct btf *btf,uint32_t id,uint32_t bytes,int is_signed)
{
    const struct btf_type *type=btf_base(btf,id);
    return !type||!btf_is_int(type)||type->size!=bytes||!!(btf_int_encoding(type)&BTF_INT_SIGNED)!=is_signed?-1:0;
}
static int btf_pointer(const struct btf *btf,uint32_t id,const char *structure)
{
    const struct btf_type *type=btf_base(btf,id);if(!type||!btf_is_ptr(type))return -1;
    if(!structure)return 0;
    type=btf_base(btf,type->type);const char *name=type?btf__name_by_offset(btf,type->name_off):NULL;
    return !type||!btf_is_struct(type)||!name||strcmp(name,structure)?-1:0;
}
static int btf_boolean(const struct btf *btf,uint32_t id)
{
    const struct btf_type *type=btf_base(btf,id);
    return !type||!btf_is_int(type)||type->size!=1||btf_int_encoding(type)!=BTF_INT_BOOL?-1:0;
}
static int validate_btf_types(struct btf *btf,struct owned_traces *traces)
{
    int result=-1;
    const char *names[]={"vfs_read","vfs_readv"};
    for(int i=0;i<2;i++){
        int id=btf__find_by_name_kind(btf,names[i],BTF_KIND_FUNC);if(id<=0)goto done;
        const struct btf_type *fn=btf_base(btf,id),*proto=fn?btf_base(btf,fn->type):NULL;
        if(!proto||!btf_is_func_proto(proto)||btf_vlen(proto)!=(unsigned)(i?5:4)||btf_integer(btf,proto->type,8,1))goto done;
        const struct btf_param *params=btf_params(proto);
        if(btf_pointer(btf,params[0].type,"file")||btf_pointer(btf,params[1].type,i?"iovec":NULL)||btf_integer(btf,params[2].type,8,0))goto done;
        const struct btf_type *pos=btf_base(btf,params[3].type);
        if(!pos||!btf_is_ptr(pos)||btf_integer(btf,pos->type,8,1)||(i&&btf_integer(btf,params[4].type,4,1)))goto done;
        traces->function_ids[i]=id;
    }
    int id=btf__find_by_name_kind(btf,"pt_regs",BTF_KIND_STRUCT);if(id<=0)goto done;
    const struct btf_type *regs=btf_base(btf,id);if(!regs||!btf_is_struct(regs)||btf_vlen(regs)>256)goto done;
    const char *registers[]={"di","si","dx","cx","ax","orig_ax"};const struct btf_member *members=btf_members(regs);
    for(int r=0;r<6;r++){int found=0;
        for(int j=0;j<btf_vlen(regs);j++){
            const char *name=btf__name_by_offset(btf,members[j].name_off);
            if(!name||strcmp(name,registers[r]))continue;
            if(++found!=1||btf_integer(btf,members[j].type,8,0)||btf_member_bitfield_size(regs,j)||
                btf_member_bit_offset(regs,j)%64||btf_member_bit_offset(regs,j)+64>regs->size*8)goto done;
            if(r==5)traces->orig_ax_offset=btf_member_bit_offset(regs,j)/8;
            if(r==4)traces->ax_offset=btf_member_bit_offset(regs,j)/8;
        }
        if(found!=1)goto done;
    }
    traces->registers_id=id;
    id=btf__find_by_name_kind(btf,"__seccomp_filter",BTF_KIND_FUNC);if(id<=0)goto done;
    const struct btf_type *fn=btf_base(btf,id),*proto=fn?btf_base(btf,fn->type):NULL;
    if(!proto||!btf_is_func_proto(proto)||btf_vlen(proto)!=2||btf_boolean(btf,proto->type))goto done;
    const struct btf_param *params=btf_params(proto);
    if(btf_integer(btf,params[0].type,4,1)||btf_boolean(btf,params[1].type))goto done;
    traces->seccomp_function_id=id;result=0;
done:return result;
}
static int validate_btf(struct owned_traces *traces)
{
#if !defined(__x86_64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    (void)traces;return -1;
#else
    struct btf *btf=btf__load_vmlinux_btf();if(libbpf_get_error(btf))return -1;
    int result=validate_btf_types(btf,traces);btf__free(btf);return result;
#endif
}
static int prepare_tracefs(struct owned_traces *traces)
{
    const char *roots[]={"/sys/kernel/tracing","/sys/kernel/debug/tracing"};
    for(int i=0;i<2;i++){char resolved[PATH_MAX],path[PATH_MAX];struct statfs fs;
        if(!realpath(roots[i],resolved)||statfs(resolved,&fs)||fs.f_type!=TRACEFS_MAGIC||lstat(resolved,&traces->root_identity))continue;
        strcpy(traces->root,resolved);
        if(!path_join(path,sizeof(path),resolved,"kprobe_events")&&!access(path,W_OK)&&
            !path_join(path,sizeof(path),resolved,"kprobe_profile")&&!access(path,R_OK))return 0;
    }
    return -1;
}
static struct bpf_link *owned_attach_error(struct owned_traces *traces,const char *program,const char *stage)
{
    int error=errno;traces->errors++;
    fprintf(stderr,"owned VFS hook attach failed: program=%s stage=%s errno=%d (%s); no READY or fallback\n",
        program?program:"(unknown)",stage,error,strerror(error));
    return NULL;
}
static struct bpf_link *attach_owned_trace(struct owned_traces *traces,struct bpf_program *program)
{
    const char *section=bpf_program__section_name(program),*name=bpf_program__name(program);int is_return=!strncmp(section,"kretprobe/",10);
    if(traces->count>=4){errno=EOVERFLOW;return owned_attach_error(traces,name,"more than four hooks");}
    const char *anchor=section+(is_return?10:7);
    if((strcmp(anchor,"vfs_read")&&strcmp(anchor,"vfs_readv"))||strlen(name)>=32){errno=EINVAL;return owned_attach_error(traces,name,"unexpected anchor or program name");}
    const char *required_names[]={"et_read_begin","et_read_end","et_readv_begin","et_readv_end"};
    const char *required_sections[]={"kprobe/vfs_read","kretprobe/vfs_read","kprobe/vfs_readv","kretprobe/vfs_readv"};
    int index=-1;for(int i=0;i<4;i++)if(!strcmp(name,required_names[i])&&!strcmp(section,required_sections[i]))index=i;
    if(index<0||(traces->required_mask&(1U<<index))){errno=EINVAL;return owned_attach_error(traces,name,"unexpected or repeated program/section pair");}
    char *uuid_text=NULL;if(trace_text("/proc/sys/kernel/random/uuid",&uuid_text))return owned_attach_error(traces,name,"read unique event UUID");
    char uuid[33];int n=0;for(char *p=uuid_text;*p&&*p!='\n';p++){
        if(*p=='-')continue;
        if(!isxdigit((unsigned char)*p)||n>=32){free(uuid_text);errno=EINVAL;return owned_attach_error(traces,name,"malformed event UUID");}uuid[n++]=*p;}
    free(uuid_text);if(n!=32){errno=EINVAL;return owned_attach_error(traces,name,"short event UUID");}uuid[32]=0;
    struct owned_hook *hook=&traces->hooks[traces->count++];hook->is_return=is_return;
    snprintf(hook->name,sizeof(hook->name),"alloxet_%s_%s",uuid,name);strcpy(hook->program,name);strcpy(hook->anchor,anchor);
    char path[PATH_MAX],suffix[320],command[512];snprintf(suffix,sizeof(suffix),"events/" ET_TRACE_GROUP "/%s",hook->name);
    struct stat check;if(path_join(path,sizeof(path),traces->root,suffix)){errno=ENAMETOOLONG;return owned_attach_error(traces,name,"event path length");}
    if(!lstat(path,&check)){errno=EEXIST;return owned_attach_error(traces,name,"event already exists");}
    if(errno!=ENOENT)return owned_attach_error(traces,name,"check fresh event path");
    if(is_return)snprintf(command,sizeof(command),"r%d:" ET_TRACE_GROUP "/%s %s\n",ET_KRET_MAXACTIVE,hook->name,anchor);
    else snprintf(command,sizeof(command),"p:" ET_TRACE_GROUP "/%s %s\n",hook->name,anchor);
    hook->created=1;if(trace_command(traces,command))return owned_attach_error(traces,name,"register exact owned tracefs event");
    struct stat identity;if(hook_identity(traces,hook,&identity,&hook->event_id,hook->definition))return owned_attach_error(traces,name,"anchor event definition and identity");
    hook->device=identity.st_dev;hook->inode=identity.st_ino;hook->anchored=1;hook->initial_begin_ns=mono();
    if(hook_profile(traces,hook,&hook->initial_hits,&hook->initial_misses))return owned_attach_error(traces,name,"initial kprobe profile");
    hook->initial_end_ns=mono();hook->initial_valid=1;
    int cpu=0;char *online=NULL;if(trace_text("/sys/devices/system/cpu/online",&online))return owned_attach_error(traces,name,"read online CPU");
    if(sscanf(online,"%d",&cpu)!=1||cpu<0){free(online);errno=EINVAL;return owned_attach_error(traces,name,"malformed online CPU");}free(online);
    struct perf_event_attr attr={.type=PERF_TYPE_TRACEPOINT,.size=sizeof(attr),.config=hook->event_id};
    int fd=syscall(SYS_perf_event_open,&attr,-1,cpu,-1,PERF_FLAG_FD_CLOEXEC);if(fd<0)return owned_attach_error(traces,name,"perf_event_open owned tracepoint");
    /* Trace-kprobe's prog_array is global: one perf attachment, all CPUs. */
    struct bpf_link *link=bpf_program__attach_perf_event(program,fd);
    if(!link||libbpf_get_error(link)){int error=errno;close(fd);errno=error;return owned_attach_error(traces,name,"attach perf event BPF program");}traces->required_mask|=1U<<index;return link;
}
static void finish_traces(struct owned_traces *traces,const char *directory)
{
    for(int i=0;i<traces->count;i++){
        struct owned_hook *hook=&traces->hooks[i];hook->final_begin_ns=mono();
        if(!hook->created||verify_hook(traces,hook)||!hook->initial_valid||hook_profile(traces,hook,&hook->hits,&hook->misses)||
            hook->hits<hook->initial_hits||hook->misses<hook->initial_misses)traces->errors++;
        else{hook->final_valid=1;uint64_t delta=hook->misses-hook->initial_misses;
            if(UINT64_MAX-traces->misses<delta)traces->errors++;else traces->misses+=delta;}
        hook->final_end_ns=mono();
    }
    for(int i=traces->count-1;i>=0;i--){struct owned_hook *hook=&traces->hooks[i];char command[256];
        if(!hook->created)continue;
        snprintf(command,sizeof(command),"-:" ET_TRACE_GROUP "/%s\n",hook->name);
        if(verify_hook(traces,hook)||trace_command(traces,command)){hook->cleanup_error=1;traces->cleanup_errors++;}
        else hook->removed=1;
    }
    char path[PATH_MAX];if(path_join(path,sizeof(path),directory,"kprobe-hooks.json")){traces->errors++;return;}
    FILE *out=fresh(path);if(!out){traces->errors++;return;}
    fprintf(out,"{\"schema_version\":1,\"backend\":\"OWNED_TRACEFS_KPROBE_KRETPROBE\",\"boot_id\":\"%s\",\"root_cgroup_id\":%llu,\"capture_start_ns\":%llu,\"capture_end_ns\":%llu,\"run_binding\":\"MANIFEST_RUN_ID_BINDS_THIS_BOOT_ROOT_WINDOW; NATIVE_HAS_NO_AGENT_RUN_ID\",\"kretprobe_maxactive\":%d,\"btf_abi\":{\"status\":\"VALIDATED_NATIVE_X86_64\",\"vfs_read_function_id\":%u,\"vfs_readv_function_id\":%u,\"pt_regs_struct_id\":%u,\"registers\":[\"di\",\"si\",\"dx\",\"cx\",\"ax\"],\"fork_syscall_register\":\"orig_ax\",\"fork_syscall_register_offset\":%u},\"scope\":\"GLOBAL_HOOK_NOT_AGENT_ATTRIBUTED; ANY_MISS_OR_UNKNOWN_INVALIDATES_SELECTED_HISTORY\",\"errors\":%llu,\"cleanup_errors\":%llu,\"misses_delta\":%llu,\"hooks\":[",traces->boot_id,(unsigned long long)traces->root_cgroup_id,(unsigned long long)traces->capture_start_ns,(unsigned long long)traces->capture_end_ns,ET_KRET_MAXACTIVE,traces->function_ids[0],traces->function_ids[1],traces->registers_id,traces->orig_ax_offset,(unsigned long long)traces->errors,(unsigned long long)traces->cleanup_errors,(unsigned long long)traces->misses);
    for(int i=0;i<traces->count;i++){struct owned_hook *h=&traces->hooks[i];
        fprintf(out,"%s{\"program\":",i?",":"");string(out,h->program,strlen(h->program));fputs(",\"name\":",out);string(out,h->name,strlen(h->name));
        fputs(",\"tracefs_root\":",out);string(out,traces->root,strlen(traces->root));fputs(",\"definition\":",out);string(out,h->definition,strlen(h->definition));
        fprintf(out,",\"device\":%llu,\"directory_inode\":%llu,\"event_id\":%llu,\"maxactive\":%d,\"initial_valid\":%s,\"final_valid\":%s,\"initial_hits\":%llu,\"initial_misses\":%llu,\"hits\":%llu,\"misses\":%llu,\"initial_begin_ns\":%llu,\"initial_end_ns\":%llu,\"final_begin_ns\":%llu,\"final_end_ns\":%llu,\"removed\":%s,\"cleanup_error\":%s}",
            (unsigned long long)h->device,(unsigned long long)h->inode,(unsigned long long)h->event_id,h->is_return?ET_KRET_MAXACTIVE:0,
            h->initial_valid?"true":"false",h->final_valid?"true":"false",(unsigned long long)h->initial_hits,(unsigned long long)h->initial_misses,
            (unsigned long long)h->hits,(unsigned long long)h->misses,(unsigned long long)h->initial_begin_ns,(unsigned long long)h->initial_end_ns,
            (unsigned long long)h->final_begin_ns,(unsigned long long)h->final_end_ns,h->removed?"true":"false",h->cleanup_error?"true":"false");
    }
    fprintf(out,"],\"seccomp_abi\":{\"status\":\"VALIDATED_NATIVE_X86_64\",\"section\":\"fexit/__seccomp_filter\",\"program\":\"et_seccomp_skip\",\"function_id\":%u,\"prototype\":\"bool(int,bool)\",\"skip_return\":false,\"syscall_register\":\"orig_ax\",\"syscall_register_offset\":%u,\"result_register\":\"ax\",\"result_register_offset\":%u,\"action\":\"UNKNOWN_NOT_OBSERVED\"}}\n",traces->seccomp_function_id,traces->orig_ax_offset,traces->ax_offset);
    if(flush(out))traces->errors++;
    if(fclose(out))traces->errors++;
}
static int pending_seccomp_count(int fd)
{
    uint64_t key,next;int count=0;void *previous=NULL;
    while(!bpf_map_get_next_key(fd,previous,&next)){
        key=next;previous=&key;if(++count>ET_MAX_THREADS)return -1;
    }
    return errno==ENOENT?count:-1;
}
static int export_pending(int fd,const char *directory,uint64_t end_ns)
{
    char path[PATH_MAX];snprintf(path,sizeof(path),"%s/censored-contexts.json",directory);
    FILE *out=fresh(path);if(!out)return -1;
    fputs("{\"schema_version\":1,\"scope\":\"ACTUAL_PENDING_MAP_AFTER_DISABLE_DETACH_DRAIN; NOT_SYNTHETIC_COMPLETIONS\",\"contexts\":[",out);
    uint64_t key,next;int count=0,error=0;void *previous=NULL;
    while(!bpf_map_get_next_key(fd,previous,&next)){
        struct et_pending p={};key=next;previous=&key;
        if(++count>ET_MAX_THREADS||bpf_map_lookup_elem(fd,&key,&p)){error=1;break;}
        fprintf(out,"%s{\"kind\":\"SYSCALL_INFLIGHT_AT_DETACH\",\"task\":",count>1?",":"");identity(out,&p.task);
        fprintf(out,",\"syscall_call_id\":%llu,\"syscall_nr\":%d,\"start_ns\":%llu,\"capture_ended_ns\":%llu,\"vfs_start_ns\":%llu,\"vfs_depth\":%u,\"args\":[",
            (unsigned long long)p.call_id,p.nr,(unsigned long long)p.call_id,(unsigned long long)end_ns,(unsigned long long)p.vfs_start_ns,p.depth);
        for(int i=0;i<6;i++)fprintf(out,"%s%llu",i?",":"",(unsigned long long)p.args[i]);
        fputs("]}",out);
    }
    if(errno!=ENOENT)error=1;
    fprintf(out,"],\"pending_syscalls\":%d,\"status\":\"%s\",\"interpretation\":\"RIGHT_CENSORED_SOURCE_BOUNDARY; DOES_NOT_EXCLUDE_CGROUP_MIGRATION_OR_MISSED_EXIT; OFFLINE_OWNERSHIP_AND_RAW_LIFECYCLE_CHECK_REQUIRED\"}\n",count,error?"SNAPSHOT_FAILED":"CAPTURED_NOT_CLEARED");
    if(flush(out))error=1;
    if(fclose(out))error=1;
    return error?-1:count;
}
static int export_pending_wakes(int fd,const char *directory,uint64_t end_ns)
{
    char path[PATH_MAX];snprintf(path,sizeof(path),"%s/censored-wakes.json",directory);
    FILE *out=fresh(path);if(!out)return -1;
    fputs("{\"schema_version\":1,\"scope\":\"ACTUAL_PENDING_WAKE_MAP_AFTER_DISABLE_DETACH_DRAIN; NOT_SYNTHETIC_WAKEUPS\",\"contexts\":[",out);
    uint64_t key,next;int count=0,error=0;void *previous=NULL;
    while(!bpf_map_get_next_key(fd,previous,&next)){
        struct et_wake_pending w={};key=next;previous=&key;
        if(++count>ET_MAX_THREADS||bpf_map_lookup_elem(fd,&key,&w)){error=1;break;}
        fprintf(out,"%s{\"kind\":\"WAKING_AWAITING_WAKEUP_AT_DETACH\",\"task\":",count>1?",":"");identity(out,&w.task);
        fprintf(out,",\"wake_attempt_ns\":%llu,\"capture_ended_ns\":%llu}",(unsigned long long)w.attempt_ns,(unsigned long long)end_ns);
    }
    if(errno!=ENOENT)error=1;
    fprintf(out,"],\"pending_wakes\":%d,\"status\":\"%s\",\"interpretation\":\"RIGHT_CENSORED_SOURCE_BOUNDARY; DOES_NOT_EXCLUDE_CGROUP_MIGRATION_OR_MISSED_WAKEUP; OFFLINE_STABLE_IDENTITY_AND_RAW_WAKING_CHECK_REQUIRED\"}\n",count,error?"SNAPSHOT_FAILED":"CAPTURED_NOT_CLEARED");
    if(flush(out))error=1;
    if(fclose(out))error=1;
    return error?-1:count;
}
static int self_test_deferred(const struct et_event *seed)
{
    char directory[]="/tmp/allox-timeline-selftest-XXXXXX",path[PATH_MAX];
    if(!mkdtemp(directory))return 1;
    snprintf(path,sizeof(path),"%s/raw.bin",directory);
    FILE *raw=fresh(path),*json=tmpfile(),*reference=tmpfile();int bad=1;
    struct seq seq[5]={};struct output capture={.raw=raw,.seq=seq,.capacity=5,.max_bytes=5*sizeof(struct et_event)};
    if(!raw||!json||!reference)goto cleanup;
    struct et_event events[5]={*seed,*seed,*seed,*seed,*seed};
    events[1].kind=ET_SYSCALL_EXIT;events[1].flags=ET_SIGRETURN_RESTORED;events[1].syscall_nr=-1;
    events[1].start_ns=events[1].syscall_call_id;events[1].end_ns=events[1].timestamp_ns;events[1].cpu_seq=2;events[1].result=-13;
    events[2].kind=ET_FORK;events[2].flags=ET_FORK_PARENT_CALL_VALID;events[2].start_ns=50;
    events[2].end_ns=0;events[2].syscall_nr=56;events[2].cpu_seq=3;events[2].peer=seed->task;
    events[3].kind=ET_WAKING;events[3].flags=0;events[3].start_ns=0;events[3].end_ns=0;events[3].cpu_seq=4;events[3].peer=seed->task;
    events[4].kind=ET_WAKEUP;events[4].flags=ET_WAKE_ATTEMPT_VALID;events[4].start_ns=events[3].timestamp_ns;
    events[4].timestamp_ns=110;events[4].end_ns=0;events[4].cpu_seq=5;events[4].peer=seed->task;
    for(int i=0;i<5;i++){consume(&capture,&events[i],sizeof(events[i]));project(reference,&events[i]);}
    if(capture.parse_errors||capture.write_errors||capture.cap_discarded||flush(raw))goto cleanup;
    struct stat expected;if(fstat(fileno(raw),&expected))goto cleanup;
    if(fclose(raw)){raw=NULL;goto cleanup;}raw=NULL;sequences(&capture);
    /* A signal STOP is deliberately already set: post-detach projection must
     * still consume the entire fixed raw file, not just its first record. */
    sig_atomic_t previous=stopping;stopping=1;
    int failed=deferred_projection(path,json,&capture,&expected);stopping=previous;
    if(failed||flush(json)||flush(reference))goto cleanup;
    rewind(json);rewind(reference);
    for(;;){int actual=fgetc(json),wanted=fgetc(reference);if(actual!=wanted)goto cleanup;if(actual==EOF)break;}
    if(ferror(json)||ferror(reference))goto cleanup;
    expected.st_ino++;
    if(!deferred_projection(path,json,&capture,&expected))goto cleanup;
    bad=0;
cleanup:
    if(raw)fclose(raw);
    if(json)fclose(json);
    if(reference)fclose(reference);
    if(unlink(path)||rmdir(directory))bad=1;
    return bad;
}
static int self_test(void)
{
    struct et_event e={.magic=ET_MAGIC,.version=ET_VERSION,.kind=ET_SWITCH_OUT,.size=sizeof(e),
        .timestamp_ns=100,.cpu_seq=1,.root_cgroup_id=2,.task={.tid=3,.tgid=3,.thread_birth_ns=4,.process_birth_ns=4,.cgroup_id=2}};
    if(valid(&e))return 1;
    e.size--;if(!valid(&e))return 1;e.size++;
    e.kind=ET_FILE_READ;e.syscall_call_id=50;e.start_ns=60;e.end_ns=100;e.flags=ET_REQUESTED_VALID;e.requested_bytes=3;e.result=4;
    if(!valid(&e))return 1;
    e.result=3;if(valid(&e))return 1;
    if(self_test_deferred(&e))return 1;
    printf("{\"status\":\"SELF_TEST_PASSED_SYNTHETIC_ONLY\",\"schema_version\":1,\"event_bytes\":%zu,\"deferred_projection\":\"BYTE_IDENTICAL_TO_LIVE_PROJECTOR_SYNTHETIC_ONLY\",\"stopped_boundary_projection\":\"ALL_RECORDS_PRESERVED\",\"changed_raw_identity\":\"REJECTED\"}\n",sizeof(e));return 0;
}
static uint64_t integer(const char *text)
{char *end;errno=0;unsigned long long v=strtoull(text,&end,10);if(errno||!*text||*end||text[0]=='-'){fprintf(stderr,"invalid integer\n");exit(2);}return v;}
int main(int argc,char **argv)
{
    const char *object=NULL,*group=NULL,*directory=NULL,*raw=NULL,*json=NULL;
    size_t capacity=1000000;uint64_t max_bytes=1073741824ULL;uint32_t ring_bytes=16777216;int stacks=0,live_json=0;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--self-test"))return self_test();
        if(!strcmp(argv[i],"--kernel-stacks")){stacks=1;continue;}
        if(!strcmp(argv[i],"--live-json")){live_json=1;continue;}
        if(!strcmp(argv[i],"--help")){puts("collect --object BPF --cgroup ROOT --output-dir FRESH [--kernel-stacks] [--live-json] [--ring-bytes N] [--max-records N] [--max-bytes N]\ncollect --decode RAW --output FRESH_JSON [--max-records N] [--max-bytes N]\nDefault: raw-only capture; JSON projection after disable/detach/drain. --live-json projects during capture for A/B calibration.\nControl: STOP newline on stdin; SIGINT/SIGTERM also stop/detach/drain. READY JSON on stdout.");return 0;}
        if(i+1>=argc){fprintf(stderr,"missing argument\n");return 2;}
        const char *option=argv[i++],*value=argv[i];
        if(!strcmp(option,"--object"))object=value;else if(!strcmp(option,"--cgroup"))group=value;else if(!strcmp(option,"--output-dir"))directory=value;
        else if(!strcmp(option,"--decode"))raw=value;else if(!strcmp(option,"--output"))json=value;
        else if(!strcmp(option,"--max-records"))capacity=integer(value);else if(!strcmp(option,"--max-bytes"))max_bytes=integer(value);
        else if(!strcmp(option,"--ring-bytes")){uint64_t n=integer(value);if(n>268435456)return 2;ring_bytes=n;}
        else{fprintf(stderr,"unknown option %s\n",option);return 2;}
    }
    if(!capacity||capacity>10000000||!max_bytes||max_bytes>16ULL*1024*1024*1024)return 2;
    if(raw){if(!json||object||group||directory||live_json)return 2;return decode(raw,json,capacity,max_bytes);}
    if(!object||!group||!directory||json||ring_bytes<4096||(ring_bytes&(ring_bytes-1)))return 2;
    struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};(void)setrlimit(RLIMIT_MEMLOCK,&limit);
    signal(SIGINT,on_signal);signal(SIGTERM,on_signal);signal(SIGPIPE,SIG_IGN);
    struct et_config cfg={.kernel_stacks=stacks};char boot[40];
    if(root_identity(group,&cfg.root_cgroup_id,&cfg.root_level)||boot_id(cfg.boot_id,boot)){fprintf(stderr,"canonical cgroup/boot identity failed\n");return 1;}
    if(!active_bpf_lsm()){fprintf(stderr,"required active BPF LSM could not be verified via /sys/kernel/security/lsm; mount securityfs and enable bpf in the LSM list; no fallback or READY\n");return 1;}
    struct owned_traces traces={};
    strcpy(traces.boot_id,boot);traces.root_cgroup_id=cfg.root_cgroup_id;
    if(validate_btf(&traces)||prepare_tracefs(&traces)){fprintf(stderr,"required x86-64 VFS/pt_regs BTF ABI or writable tracefs with kprobe_profile unavailable; no fallback or READY\n");return 1;}
    if(mkdir(directory,0700)){perror("fresh output directory");return 1;}
    char path[PATH_MAX];snprintf(path,sizeof(path),"%s/events.bin",directory);FILE *binary=fresh(path);
    snprintf(path,sizeof(path),"%s/events.jsonl",directory);FILE *events=fresh(path);
    if(!binary||!events){perror("fresh events outputs");if(binary)fclose(binary);if(events)fclose(events);return 1;}
    struct output out={.raw=binary,.json=live_json?events:NULL,.capacity=capacity,.max_bytes=max_bytes};out.seq=calloc(capacity,sizeof(*out.seq));
    struct bpf_object *obj=NULL;struct ring_buffer *ring=NULL;struct bpf_link *links[32]={};int link_count=0,rc=1,fd=-1,cpus=0,program_count=0;uint64_t totals[ET_HEALTH_COUNT]={},program_errors=0,recursion_misses=0;uint64_t *values=NULL;struct program_diagnostic programs[32]={};
    uint64_t start=mono(),end=0,projection_start=0,projection_end=0,projection_errors=0;const char *reason="LOAD_OR_ATTACH_FAILED";
    traces.capture_start_ns=start;
    if(!out.seq)goto finish;
    if(setvbuf(binary,raw_stdio_buffer,_IOFBF,sizeof(raw_stdio_buffer))||setvbuf(events,json_stdio_buffer,_IOFBF,sizeof(json_stdio_buffer))){out.write_errors++;goto finish;}
    obj=bpf_object__open_file(object,NULL);if(libbpf_get_error(obj)){obj=NULL;goto finish;}
    struct bpf_map *map=bpf_object__find_map_by_name(obj,"et_events");if(!map||bpf_map__set_max_entries(map,ring_bytes))goto finish;
    if(bpf_object__load(obj))goto finish;
    fd=bpf_object__find_map_fd_by_name(obj,"et_config");uint32_t zero=0;
    if(fd<0||bpf_map_update_elem(fd,&zero,&cfg,BPF_ANY))goto finish;
    struct bpf_program *program;
    int seccomp_attached=0;
    bpf_object__for_each_program(program,obj){if(link_count==32)goto finish;
        const char *section=bpf_program__section_name(program);struct bpf_link *link;
        if(!strncmp(section,"kprobe/",7)||!strncmp(section,"kretprobe/",10))link=attach_owned_trace(&traces,program);
        else{if(!strncmp(section,"fentry/",7)||!strncmp(section,"fexit/",6)){
                if(strcmp(section,"fexit/__seccomp_filter")||strcmp(bpf_program__name(program),"et_seccomp_skip")||seccomp_attached++){
                    fprintf(stderr,"unexpected disallowed tracing section: %s\n",section);goto finish;}}
            link=bpf_program__attach(program);}
        if(!link||libbpf_get_error(link)){fprintf(stderr,"BPF program attachment failed: program=%s section=%s errno=%d (%s); no READY\n",bpf_program__name(program),section,errno,strerror(errno));goto finish;}
        links[link_count++]=link;}
    if(traces.count!=4||traces.required_mask!=15||seccomp_attached!=1)goto finish;
    ring=ring_buffer__new(bpf_object__find_map_fd_by_name(obj,"et_events"),consume,&out,NULL);if(!ring)goto finish;
    cfg.enabled=1;if(bpf_map_update_elem(fd,&zero,&cfg,BPF_ANY))goto finish;
    snprintf(path,sizeof(path),"%s/meta.json",directory);FILE *meta=fresh(path);if(!meta)goto finish;
    fprintf(meta,"{\"schema_version\":1,\"boot_id\":\"%s\",\"event_bytes\":%zu,\"root_cgroup_id\":%llu,\"root_level\":%u,\"kernel_stacks\":%s,\"ring_bytes\":%u,\"max_records\":%zu,\"max_bytes\":%llu,\"enabled_monotonic_ns\":%llu,\"json_projection\":\"%s\",\"raw_stdio_buffer_bytes\":1048576,\"json_stdio_buffer_bytes\":262144,\"read_hook_backend\":\"OWNED_TRACEFS_KPROBE_KRETPROBE\",\"kretprobe_maxactive\":4096,\"kprobe_evidence\":\"kprobe-hooks.json\",\"read_timing_scope\":\"ACTUAL_VFS_ENTRY_TO_RETURN_NOT_SYSCALL_WALL\",\"object_hook\":\"LSM_FILE_PERMISSION_BPF_PATH_D_PATH_NON_SLEEPABLE\",\"object_hook_prerequisites\":\"ACTIVE_BPF_LSM_AND_TRUSTED_PATH_KFUNC_REQUIRED_NO_FALLBACK\",\"lsm_policy_effect\":\"RETURN_INPUT_UNCHANGED\",\"scope\":\"SELECTED_CGROUP_DESCENDANTS_NATIVE_SCHED_SYSCALL_VFS_READ_ONLY; NO_HOST_OR_BLOCK_REQUEST_CAUSAL_ATTRIBUTION\",\"path_semantics\":\"BOUNDED_PATH_AT_LSM_PERMISSION_CANDIDATE_NOT_READ_SUCCESS; PRECEDING_LSM_DENIALS_OR_PRIVATE_INODES_CAN_SKIP_THIS_HOOK\",\"seccomp_hook\":\"FEXIT_FILTER_FALSE_SAVED_REGS_V1\"}\n",
        boot,sizeof(struct et_event),(unsigned long long)cfg.root_cgroup_id,cfg.root_level,stacks?"true":"false",ring_bytes,capacity,(unsigned long long)max_bytes,(unsigned long long)mono(),live_json?"DURING_CAPTURE":"AFTER_DETACH");
    int meta_error=flush(meta);if(fclose(meta))meta_error=1;if(meta_error)goto finish;
    printf("{\"type\":\"READY\",\"status\":\"READY\",\"event\":\"READY\",\"schema_version\":1,\"boot_id\":\"%s\",\"event_bytes\":%zu,\"root_cgroup_id\":%llu,\"root_level\":%u,\"timestamp_ns\":%llu,\"clock\":\"CLOCK_MONOTONIC\",\"seccomp_hook\":\"FEXIT_FILTER_FALSE_SAVED_REGS_V1\"}\n",boot,sizeof(struct et_event),(unsigned long long)cfg.root_cgroup_id,cfg.root_level,(unsigned long long)mono());fflush(stdout);
    reason="CONTROL_STOP";
    while(!stopping){int n=ring_buffer__poll(ring,25);if(n<0&&n!=-EINTR){reason="RING_POLL_FAILED";out.parse_errors++;break;}
        struct pollfd control={.fd=STDIN_FILENO,.events=POLLIN};int available=poll(&control,1,0);
        if(available<0&&errno!=EINTR){reason="CONTROL_POLL_FAILED";out.parse_errors++;break;}
        if(available>0&&(control.revents&(POLLIN|POLLHUP))){char text[32];ssize_t got=read(STDIN_FILENO,text,sizeof(text));
            if(got==5&&!memcmp(text,"STOP\n",5))break;
            if(!got){reason="CONTROL_EOF";break;}
            reason="INVALID_CONTROL";out.parse_errors++;break;}}
    if(out.cap_discarded)reason="CAP_REACHED";
    else if(stop_signal)reason="SIGNAL_STOP";
    rc=0;
finish:
    end=mono();if(fd>=0){uint32_t k=0;cfg.enabled=0;if(bpf_map_update_elem(fd,&k,&cfg,BPF_ANY)){out.parse_errors++;rc=1;}}
    for(int i=link_count-1;i>=0;i--)if(bpf_link__destroy(links[i]))out.parse_errors++;
    if(ring){for(int i=0;i<1000;i++){int n=ring_buffer__consume(ring);if(n<=0){if(n<0)out.parse_errors++;break;}}}
    end=mono();
    traces.capture_end_ns=end;
    finish_traces(&traces,directory);
    if(obj){cpus=libbpf_num_possible_cpus();if(cpus>0)values=calloc((size_t)cpus*ET_HEALTH_COUNT,sizeof(*values));
        int hfd=bpf_object__find_map_fd_by_name(obj,"et_health");
        for(uint32_t i=0;i<ET_HEALTH_COUNT;i++){if(!values||hfd<0||bpf_map_lookup_elem(hfd,&i,values+(size_t)i*cpus)){out.parse_errors++;break;}for(int c=0;c<cpus;c++)totals[i]+=values[(size_t)i*cpus+c];}
        bpf_object__for_each_program(program,obj){struct bpf_prog_info info={};uint32_t size=sizeof(info);
            if(program_count==32){program_errors++;continue;}
            struct program_diagnostic *diagnostic=&programs[program_count++];
            diagnostic->program=bpf_program__name(program);diagnostic->section=bpf_program__section_name(program);
            if(bpf_obj_get_info_by_fd(bpf_program__fd(program),&info,&size)){diagnostic->info_error=1;program_errors++;}
            else{diagnostic->id=info.id;diagnostic->recursion_misses=info.recursion_misses;recursion_misses+=info.recursion_misses;}}}
    sequences(&out);if(flush(binary))out.write_errors++;
    struct stat raw_stat;int raw_identity_valid=0;
    if(fstat(fileno(binary),&raw_stat)){out.write_errors++;}else{
        raw_identity_valid=1;
        if((uint64_t)raw_stat.st_size!=out.bytes)out.write_errors++;
        out.truncated_tail=raw_stat.st_size%(off_t)sizeof(struct et_event)!=0;}
    int pending=obj?export_pending(bpf_object__find_map_fd_by_name(obj,"et_pending"),directory,end):-1;
    int pending_wakes=obj?export_pending_wakes(bpf_object__find_map_fd_by_name(obj,"et_wake_pending"),directory,end):-1;
    int pending_seccomp=obj?pending_seccomp_count(bpf_object__find_map_fd_by_name(obj,"et_seccomp_pending")):-1;
    if(fclose(binary))out.write_errors++;
    if(!live_json&&out.seq){projection_start=mono();snprintf(path,sizeof(path),"%s/events.bin",directory);
        if(!raw_identity_valid||deferred_projection(path,events,&out,&raw_stat))projection_errors++;}
    if(flush(events))out.write_errors++;
    if(fclose(events))out.write_errors++;
    if(projection_start)projection_end=mono();
    uint64_t failures=out.parse_errors+out.write_errors+out.sequence_errors+out.cap_discarded+program_errors+recursion_misses+out.truncated_tail+projection_errors+traces.errors+traces.misses+traces.cleanup_errors;
    if(traces.count!=4||traces.required_mask!=15)failures++;
    for(int i=ET_RING_DROPS;i<ET_HEALTH_COUNT;i++)if(i!=ET_NESTED_VFS&&i!=ET_CENSORED_EXEC&&i!=ET_CENSORED_EXIT&&i!=ET_BOUNDARY_RETURNS&&i!=ET_FORK_CHILD_RETURNS&&i!=ET_SIGRETURN_RESTORED_EXITS&&i!=ET_SECCOMP_SKIPS)failures+=totals[i];
    if(totals[ET_ATTEMPTED]!=totals[ET_EMITTED]+totals[ET_RING_DROPS]||totals[ET_EMITTED]!=out.records)failures++;
    if(pending<0||pending_wakes<0)failures++;
    if(pending_seccomp)failures++;
    snprintf(path,sizeof(path),"%s/health.json",directory);FILE *health=fresh(path);
    if(health){fprintf(health,"{\"schema_version\":1,\"status\":\"%s\",\"stop_reason\":\"%s\",\"start_ns\":%llu,\"end_ns\":%llu,\"records\":%zu,\"raw_bytes\":%llu,\"event_bytes\":%zu,\"parse_errors\":%llu,\"write_errors\":%llu,\"sequence_errors\":%llu,\"truncated_tail\":%s,\"cap_discarded\":%llu,\"pending_syscalls\":%d,\"pending_wakes\":%d,\"program_info_errors\":%llu,\"recursion_misses\":%llu,\"counters\":{",
        !rc&&!failures?((pending||pending_wakes)?"COMPLETE_TRANSPORT_CENSORED_AT_BOUNDARY":"COMPLETE_FOR_SELECTED_HOOKS"):"INCOMPLETE",reason,(unsigned long long)start,(unsigned long long)end,out.records,(unsigned long long)out.bytes,sizeof(struct et_event),
        (unsigned long long)out.parse_errors,(unsigned long long)out.write_errors,(unsigned long long)out.sequence_errors,out.truncated_tail?"true":"false",(unsigned long long)out.cap_discarded,pending,pending_wakes,(unsigned long long)program_errors,(unsigned long long)recursion_misses);
        for(int i=0;i<ET_HEALTH_COUNT;i++)fprintf(health,"%s\"%s\":%llu",i?",":"",health_names[i],(unsigned long long)totals[i]);
        fprintf(health,"},\"seccomp_hook\":\"FEXIT_FILTER_FALSE_SAVED_REGS_V1\",\"pending_seccomp_skips\":%d,\"read_hook_backend\":\"OWNED_TRACEFS_KPROBE_KRETPROBE\",\"kprobe_misses\":%llu,\"kprobe_profile_errors\":%llu,\"kprobe_cleanup_errors\":%llu,\"json_projection\":\"%s\",\"json_projection_errors\":%llu,\"json_projection_timing_scope\":\"AFTER_DETACH_REOPEN_PROJECT_FLUSH_CLOSE; LIVE_MODE_NOT_SEPARATELY_MEASURED\",\"json_projection_started_ns\":",pending_seccomp,(unsigned long long)traces.misses,(unsigned long long)traces.errors,(unsigned long long)traces.cleanup_errors,live_json?"DURING_CAPTURE":"AFTER_DETACH",(unsigned long long)projection_errors);
        if(projection_start)fprintf(health,"%llu,\"json_projection_ended_ns\":%llu,\"json_projection_duration_ns\":%llu",(unsigned long long)projection_start,(unsigned long long)projection_end,(unsigned long long)(projection_end-projection_start));
        else fputs("null,\"json_projection_ended_ns\":null,\"json_projection_duration_ns\":null",health);
        fputs(",\"programs\":[",health);
        for(int i=0;i<program_count;i++){
            struct program_diagnostic *diagnostic=&programs[i];fputs(i?",{\"program\":":"{\"program\":",health);
            string(health,diagnostic->program,strlen(diagnostic->program));fputs(",\"section\":",health);string(health,diagnostic->section,strlen(diagnostic->section));
            fprintf(health,",\"info_error\":%s,\"program_id\":",diagnostic->info_error?"true":"false");
            if(diagnostic->info_error)fputs("null,\"recursion_misses\":null}",health);
            else fprintf(health,"%u,\"recursion_misses\":%llu}",diagnostic->id,(unsigned long long)diagnostic->recursion_misses);
        }
        fputs("],\"cpus\":[",health);
        if(values)for(int c=0;c<cpus;c++)fprintf(health,"%s{\"cpu\":%d,\"attempted\":%llu,\"emitted\":%llu,\"ring_drops\":%llu}",c?",":"",c,
            (unsigned long long)values[(size_t)ET_ATTEMPTED*cpus+c],(unsigned long long)values[(size_t)ET_EMITTED*cpus+c],(unsigned long long)values[(size_t)ET_RING_DROPS*cpus+c]);
        fputs("],\"scope\":\"SELECTED_HOOK_TRANSPORT_HEALTH_NOT_COMPLETE_AGENT_COVERAGE\",\"stack_semantics\":\"SWITCH_OUT_CONTEXT_CANDIDATE_NOT_PROVEN_CAUSE\",\"object_hook\":\"LSM_FILE_PERMISSION_BPF_PATH_D_PATH_NON_SLEEPABLE\",\"lsm_policy_effect\":\"RETURN_INPUT_UNCHANGED\",\"path_semantics\":\"PATH_AT_LSM_PERMISSION_CANDIDATE_NOT_READ_SUCCESS; PRECEDING_LSM_DENIALS_OR_PRIVATE_INODES_CAN_SKIP_THIS_HOOK; BOUNDED_PATH_FAILS_EXPLICITLY\"}\n",health);
        int health_error=flush(health);if(fclose(health))health_error=1;if(health_error)failures++;}else failures++;
    if(ring)ring_buffer__free(ring);
    if(obj)bpf_object__close(obj);
    free(values);free(out.seq);
    return rc||failures?1:0;
}
