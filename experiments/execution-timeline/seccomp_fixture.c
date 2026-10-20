// SPDX-License-Identifier: GPL-2.0-only
/* Zero-paid native fixture: deliberately skipped syscalls have no raw entry.
 * Successful zero emulation is included: errno-only inference cannot pass. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static void *worker(void *unused)
{
    (void)unused;
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone3,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getppid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EACCES),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getuid,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program={.len=sizeof(instructions)/sizeof(instructions[0]),.filter=instructions};
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)||prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program))return (void *)1;
    for(int i=0;i<17;i++){
        errno=0;if(syscall(SYS_clone3,NULL,0)!=-1||errno!=ENOSYS)return (void *)2;
        errno=0;if(syscall(SYS_getppid)!=-1||errno!=EACCES)return (void *)3;
        if(syscall(SYS_getuid)!=0||syscall(SYS_getpid)<=0)return (void *)4;
    }
    return NULL;
}
int main(void)
{
    pthread_t threads[4];
    for(int i=0;i<4;i++)if(pthread_create(&threads[i],NULL,worker,NULL))return 5;
    for(int i=0;i<4;i++){void *result;if(pthread_join(threads[i],&result)||result)return 6;}
    puts("{\"status\":\"EXPECTED_SECCOMP_SKIPS_COMPLETED\",\"threads\":4,\"iterations\":17,\"skips\":204,\"errno_values\":[38,13,0],\"api_calls\":0}");
    return 0;
}
