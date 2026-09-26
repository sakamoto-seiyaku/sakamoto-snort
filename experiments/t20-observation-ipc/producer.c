#define _GNU_SOURCE
#include "ipc.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void put32(uint8_t *p,uint32_t v) {memcpy(p,&v,4);}
static void put64(uint8_t *p,uint64_t v) {memcpy(p,&v,8);}
static void sleep_us(unsigned us)
{struct timespec t={us/1000000,(us%1000000)*1000}; while(nanosleep(&t,&t)&&errno==EINTR) {}}
static int cmp64(const void *a,const void *b)
{uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b; return (x>y)-(x<y);}

int main(int argc,char **argv)
{
  if(argc!=8) {fprintf(stderr,"producer path consumer generation count batch interval_us scenario\n"); return 2;}
  uint64_t gen=strtoull(argv[3],NULL,10), count=strtoull(argv[4],NULL,10);
  unsigned batch=atoi(argv[5]),interval=atoi(argv[6]); const char *scenario=argv[7];
  if(!gen || !count || count>1000000 || !batch || batch>1024) return 2;
  int event=eventfd(0,EFD_NONBLOCK); if(event<0) return 3;
  ipc *h=ipc_open(argv[1],event,gen,1); if(!h) {perror("create");return 3;}
  char fdtext[32]; snprintf(fdtext,sizeof(fdtext),"%d",event);
  pid_t child=-1;
  if(strcmp(scenario,"absent")) {
    child=fork();
    if(child==0) {
      execl(argv[2],argv[2],argv[1],fdtext,argv[3],argv[5],scenario,NULL);
      perror("exec");_exit(3);
    }
    if(child<0) return 3;
  }
  /* Setup is excluded from offered-record timing; consumer starts before load. */
  sleep_us(200000);
  uint64_t idle_cpu=ipc_cpu(),idle_wall=ipc_now();
  if(!strcmp(scenario,"idle")) sleep_us(3000000);
  idle_cpu=ipc_cpu()-idle_cpu;idle_wall=ipc_now()-idle_wall;
  uint64_t *times=calloc(count,sizeof(*times)); if(!times)return 3;
  uint64_t *export_times=calloc(count,sizeof(*export_times)); if(!export_times)return 3;
  uint64_t wall=ipc_now(),cpu=ipc_cpu();
  unsigned batch_accepted=0;
  for(uint64_t seq=1;seq<=count;seq++) {
    unsigned c=!strcmp(scenario,"isolation")?1:0;
    if(!strcmp(scenario,"isolation") && seq%100==0) c=0;
    uint32_t shape=(seq%10<7)?0:(seq%10<9)?1:2;
    uint32_t n=shape==0?128:shape==1?512:2048;
    uint8_t record[2048];
    for(unsigned i=0;i<n;i++)record[i]=(uint8_t)(seq*17+i*13+gen);
    put32(record,1);put32(record+4,n);put64(record+8,gen);put64(record+16,seq);
    put64(record+24,ipc_now());put64(record+32,seq/10+1);
    put64(record+40,seq*1500);put64(record+48,seq*2);put32(record+56,shape);
    put32(record+60,c);
    if(!strcmp(scenario,"corrupt") && seq==1)record[100]^=1;
    uint64_t before=ipc_now(); int admitted=ipc_write(h,c,record,n);times[seq-1]=ipc_now()-before;
    if(!admitted)batch_accepted++;
    if(seq%batch==0 || seq==count) {
#ifndef T20_VPP
      if(batch_accepted)ipc_notify(h);
#else
      (void)batch_accepted;
#endif
      batch_accepted=0;
      export_times[seq-1]=ipc_now()-before;
      if(interval)sleep_us(interval);
    } else export_times[seq-1]=ipc_now()-before;
  }
  uint8_t bad[1]={0}; (void)ipc_write(h,0,bad,1);
  uint64_t elapsed=ipc_now()-wall,used=ipc_cpu()-cpu;
  ipc_finish(h);
  qsort(times,count,sizeof(*times),cmp64);
  qsort(export_times,count,sizeof(*export_times),cmp64);
  printf("{\"role\":\"producer_timing\",\"count\":%llu,\"wall_ns\":%llu,\"cpu_ns\":%llu,\"idle_wall_ns\":%llu,\"idle_cpu_ns\":%llu,\"attempt_p50_ns\":%llu,\"attempt_p99_ns\":%llu,\"attempt_max_ns\":%llu,\"export_p50_ns\":%llu,\"export_p99_ns\":%llu,\"export_max_ns\":%llu}\n",
    (unsigned long long)count,(unsigned long long)elapsed,(unsigned long long)used,
    (unsigned long long)idle_wall,(unsigned long long)idle_cpu,
    (unsigned long long)times[count/2],(unsigned long long)times[(count-1)*99/100],(unsigned long long)times[count-1],
    (unsigned long long)export_times[count/2],(unsigned long long)export_times[(count-1)*99/100],(unsigned long long)export_times[count-1]);
  free(times);free(export_times);
  ipc_report(h,"producer");
  int status=0;
  if(child>0) {
    uint64_t until=ipc_now()+8000000000ULL;
    while(waitpid(child,&status,WNOHANG)==0 && ipc_now()<until)sleep_us(10000);
    if(ipc_now()>=until) {kill(child,SIGKILL);waitpid(child,&status,0);status=9;}
  }
  ipc_close(h);close(event);
  return child<0?0:WIFEXITED(status)?WEXITSTATUS(status):5;
}
