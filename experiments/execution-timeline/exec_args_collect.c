// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include "native_exec_args.h"
_Static_assert(sizeof(struct nea_event)==NEA_ENTRY_BYTES,"entry ABI");
_Static_assert(offsetof(struct nea_event,argv)==NEA_HEADER_BYTES,"header ABI");
_Static_assert(sizeof(struct nea_health_receipt)==216,"health ABI");
static volatile sig_atomic_t stopping;
static void stop(int signal){(void)signal;stopping=1;}
static uint64_t mono(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
struct output {FILE *raw;struct nea_health_receipt health;};
static int exclusive(const char *path){return open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0600);}
static int boot(unsigned char *bytes)
{ FILE *f=fopen("/proc/sys/kernel/random/boot_id","r");char text[80];if(!f)return -1;
  if(!fgets(text,sizeof(text),f)){fclose(f);return -1;}fclose(f);size_t at=0;
  for(size_t i=0;text[i]&&text[i]!='\n';){if(text[i]=='-'){i++;continue;}unsigned value=0;
      if(at>=16||sscanf(text+i,"%2x",&value)!=1)return -1;
      bytes[at++]=value;i+=2;}return at==16?0:-1; }
static int event(void *context,void *data,size_t size)
{ struct output *out=context;struct nea_event *e=data;
  if(size<16||e->magic!=NEA_MAGIC||e->version!=NEA_VERSION||e->size!=size||
     e->kind<NEA_ENTRY||e->kind>NEA_UNCONFIRMED||
     (e->kind==NEA_ENTRY?size!=NEA_ENTRY_BYTES:size!=NEA_HEADER_BYTES)||
     (e->flags&~127U)||!e->timestamp_ns||!e->cpu_seq||!e->tid||!e->tgid||
     !e->thread_birth_ns||!e->process_birth_ns||e->cgroup_id!=out->health.cgroup_id||
     e->root_cgroup_id!=out->health.cgroup_id||memcmp(e->boot_id,out->health.boot_id,16)){
      out->health.parse_errors++;return 0;}
  if(out->health.bytes+size>out->health.max_bytes){out->health.cap_discarded++;return 0;}
  if(fwrite(data,1,size,out->raw)!=size){out->health.write_errors++;return -EIO;}
  out->health.bytes+=size;out->health.records++;return 0; }
static int health_counters(struct bpf_object *object,struct nea_health_receipt *receipt)
{ int fd=bpf_object__find_map_fd_by_name(object,"nea_health"),n=libbpf_num_possible_cpus();
  if(fd<0||n<=0)return -1;
  uint64_t *values=calloc((size_t)n,sizeof(*values));if(!values)return -1;
  for(uint32_t key=0;key<NEA_HEALTH_COUNT;key++){
      if(bpf_map_lookup_elem(fd,&key,values)){free(values);return -1;}
      for(int cpu=0;cpu<n;cpu++)receipt->counters[key]+=values[cpu];}
  free(values);fd=bpf_object__find_map_fd_by_name(object,"nea_pending");uint64_t key=0,next;
  if(fd<0)return -1;
  int error=bpf_map_get_next_key(fd,NULL,&next);
  while(!error){receipt->pending_at_end++;key=next;error=bpf_map_get_next_key(fd,&key,&next);}
  return errno==ENOENT?0:-1; }
static void usage(void)
{fputs("exec-args-collect --object FILE --cgroup-id ID --output NEW_DIR [--max-bytes N]\n"
       "Signal SIGTERM after target is quiescent. Exact cgroup only; native x86-64 execve/execveat.\n",stderr);}
int main(int argc,char **argv)
{ const char *object_path=NULL,*directory=NULL;uint64_t cgroup_id=0,max_bytes=256ULL*1024*1024;
  if(argc==2&&!strcmp(argv[1],"--self-test")){printf("{\"version\":1,\"entry_bytes\":%zu,\"header_bytes\":%zu,\"health_bytes\":%zu,\"args\":8,\"arg_bytes\":4096}\n",sizeof(struct nea_event),offsetof(struct nea_event,argv),sizeof(struct nea_health_receipt));return 0;}
  for(int i=1;i<argc;i++){
      if(i+1>=argc){usage();return 2;}const char *value=argv[++i],*option=argv[i-1];
      if(!strcmp(option,"--object"))object_path=value;
      else if(!strcmp(option,"--output"))directory=value;
      else if(!strcmp(option,"--cgroup-id")||!strcmp(option,"--max-bytes")){
          char *end=NULL;errno=0;unsigned long long parsed=strtoull(value,&end,10);
          if(errno||!value[0]||!end||*end||value[0]=='-'){usage();return 2;}
          if(!strcmp(option,"--cgroup-id"))cgroup_id=parsed;else max_bytes=parsed;
      }else{usage();return 2;}}
  if(!object_path||!directory||!cgroup_id||max_bytes<NEA_ENTRY_BYTES||max_bytes>4ULL*1024*1024*1024){usage();return 2;}
  struct utsname machine;if(uname(&machine)||strcmp(machine.machine,"x86_64")){fputs("native x86-64 required\n",stderr);return 2;}
  if(mkdir(directory,0700)){perror("fresh output directory");return 1;}
  char path[4096];if(snprintf(path,sizeof(path),"%s/events.bin",directory)>=(int)sizeof(path))return 1;
  int raw_fd=exclusive(path);if(raw_fd<0){perror("raw WAL");return 1;}
  struct output out={0};out.raw=fdopen(raw_fd,"wb");if(!out.raw){close(raw_fd);return 1;}
  static char buffer[1048576];setvbuf(out.raw,buffer,_IOFBF,sizeof(buffer));
  out.health.magic=NEA_HEALTH_MAGIC;out.health.version=NEA_VERSION;out.health.size=sizeof(out.health);
  out.health.cgroup_id=cgroup_id;out.health.max_bytes=max_bytes;out.health.begin_ns=mono();
  int status=1;struct bpf_object *object=NULL;struct ring_buffer *ring=NULL;
  struct bpf_link *links[8]={0};size_t link_count=0;
  if(boot(out.health.boot_id)){fputs("boot identity unavailable\n",stderr);goto finish;}
  object=bpf_object__open_file(object_path,NULL);if(libbpf_get_error(object)){object=NULL;goto finish;}
  if(bpf_object__load(object))goto finish;
  struct nea_config cfg={.cgroup_id=cgroup_id};memcpy(cfg.boot_id,out.health.boot_id,16);
  int config_fd=bpf_object__find_map_fd_by_name(object,"nea_config");uint32_t zero=0;
  if(config_fd<0||bpf_map_update_elem(config_fd,&zero,&cfg,BPF_ANY))goto finish;
  struct bpf_program *program;bpf_object__for_each_program(program,object){
      if(link_count>=8)goto finish;
      struct bpf_link *link=bpf_program__attach(program);
      if(libbpf_get_error(link))goto finish;
      links[link_count++]=link;}
  if(link_count!=4){fputs("all four selected hooks must attach\n",stderr);goto finish;}
  ring=ring_buffer__new(bpf_object__find_map_fd_by_name(object,"nea_events"),event,&out,NULL);
  if(!ring)goto finish;
  signal(SIGTERM,stop);signal(SIGINT,stop);
  cfg.enabled=1;if(bpf_map_update_elem(config_fd,&zero,&cfg,BPF_ANY))goto finish;
  if(snprintf(path,sizeof(path),"%s/ready.pending",directory)>=(int)sizeof(path))goto disable;
  int ready_fd=exclusive(path);if(ready_fd<0)goto disable;FILE *ready=fdopen(ready_fd,"w");
  if(!ready){close(ready_fd);goto disable;}
  fprintf(ready,"{\"status\":\"READY\",\"schema_version\":1,\"cgroup_id\":%"PRIu64",\"scope\":\"EXACT_CGROUP_ID_NOT_DESCENDANTS\",\"argv_source\":\"USER_ARGV_AT_SYSCALL_ENTRY\",\"max_args\":8,\"arg_bytes\":4096}\n",cgroup_id);
  if(fflush(ready)||fsync(fileno(ready))){fclose(ready);goto disable;}fclose(ready);
  char ready_path[4096];
  if(snprintf(ready_path,sizeof(ready_path),"%s/ready.json",directory)>=(int)sizeof(ready_path)||
     link(path,ready_path)||unlink(path))goto disable;
  status=0;while(!stopping){int result=ring_buffer__poll(ring,100);if(result<0&&result!=-EINTR){status=1;break;}}
disable:
  cfg.enabled=0;if(bpf_map_update_elem(config_fd,&zero,&cfg,BPF_ANY))status=1;
  for(int drain=0;drain<4096;drain++){int result=ring_buffer__consume(ring);if(result<=0){if(result<0)status=1;break;}}
  if(health_counters(object,&out.health)){out.health.parse_errors++;status=1;}
finish:
  out.health.end_ns=mono();if(fflush(out.raw)||fsync(fileno(out.raw)))out.health.write_errors++;
  fclose(out.raw);
  if(snprintf(path,sizeof(path),"%s/health.bin",directory)<(int)sizeof(path)){
      int fd=exclusive(path);if(fd<0||write(fd,&out.health,sizeof(out.health))!=(ssize_t)sizeof(out.health)||fsync(fd)){status=1;}if(fd>=0)close(fd);
  }else status=1;
  if(ring)ring_buffer__free(ring);
  for(size_t i=0;i<link_count;i++)bpf_link__destroy(links[i]);
  if(object)bpf_object__close(object);
  return status; }
