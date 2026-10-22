/* External, bounded, read-only queue observer. Never writes Product memory. */
#define _GNU_SOURCE
#include <vlib/vlib.h>
#include <vlib/threads.h>
#include "product_packet.h"
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t expired;
static void expire(int signal_number) { (void)signal_number; expired=1; }
static uint64_t now_ns(void) {
  struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))_exit(90);
  return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;
}
static int memory_fd=-1;
static int read_memory(uint64_t address,void *value,size_t bytes) {
  return pread(memory_fd,value,bytes,(off_t)address)==(ssize_t)bytes ? 0:-1;
}
static uint64_t number(const char *value) {
  char *end;errno=0;uint64_t result=strtoull(value,&end,0);
  if(errno || !*value || *end){fprintf(stderr,"invalid number\n");exit(2);}return result;
}
static void task_status(pid_t pid,pid_t tid,const char *phase) {
  char path[96],line[256];snprintf(path,sizeof(path),"/proc/%d/task/%d/status",pid,tid);
  FILE *file=fopen(path,"r");if(!file)return;
  while(fgets(line,sizeof(line),file))
    if(!strncmp(line,"State:",6)||!strncmp(line,"TracerPid:",10)||!strncmp(line,"Pid:",4)||!strncmp(line,"Tgid:",5)) {
      line[strcspn(line,"\n")]=0;printf("event=task_status phase=%s %s\n",phase,line);
    }
  fclose(file);
}
static void layout(void) {
#define FIELD(type,field) printf("layout.%s.%s=%zu\n",#type,#field,offsetof(type,field))
  FIELD(vlib_thread_main_t,frame_queue_mains);
  FIELD(vlib_frame_queue_main_t,vlib_frame_queues);
  FIELD(vlib_frame_queue_t,elts);FIELD(vlib_frame_queue_t,head);
  FIELD(vlib_frame_queue_t,tail);FIELD(vlib_frame_queue_t,nelts);
  FIELD(vlib_frame_queue_elt_t,valid);FIELD(vlib_frame_queue_elt_t,n_vectors);
  printf("layout.fqm_size=%zu\nlayout.elt_size=%zu\n",sizeof(vlib_frame_queue_main_t),sizeof(vlib_frame_queue_elt_t));
}
static int client(int argc,char **argv) {
  if(argc!=8)return 2;
  uid_t uid=(uid_t)number(argv[2]);unsigned port=(unsigned)number(argv[3]),peer_port=(unsigned)number(argv[5]);
  if(!uid||port<1024||port>65535||!peer_port||peer_port>65535||number(argv[7])!=65||strlen(argv[6])>100)return 2;
  if(getuid()!=uid && (setgid(uid)||setuid(uid))){perror("client uid");return 3;}
  int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0){perror("client socket");return 3;}
  struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(port)},peer={.sin_family=AF_INET,.sin_port=htons(peer_port)};
  inet_pton(AF_INET,"10.111.0.2",&local.sin_addr);
  if(inet_pton(AF_INET,argv[4],&peer.sin_addr)!=1 || bind(fd,(void*)&local,sizeof(local)) || connect(fd,(void*)&peer,sizeof(peer))){perror("client bind/connect");close(fd);return 3;}
  struct timeval timeout={5,0};
  if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
     setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))){perror("client timeout");close(fd);return 3;}
  char request[128];int length=snprintf(request,sizeof(request),"%s:0",argv[6]);
  if(length<1 || send(fd,request,(size_t)length,0)!=length){perror("client send");close(fd);return 3;}
  printf("event=client_sent uid=%u port=%u nonce=%s\n",uid,port,argv[6]);
  unsigned char seen[65]={0};
  for(unsigned n=0;n<65;n++){
    char response[256];ssize_t bytes=recv(fd,response,sizeof(response)-1,0);
    if(bytes<0){perror("client recv");close(fd);return 3;}response[bytes]=0;
    unsigned index=0;
    if(bytes!=length || memcmp(response,request,(size_t)length)){
      if(bytes<=length+6 || memcmp(response,request,(size_t)length) || memcmp(response+length,"|ring-",6)){fprintf(stderr,"wrong client response\n");close(fd);return 3;}
      index=(unsigned)number(response+length+6);
    }
    if(index>=65 || seen[index]){fprintf(stderr,"duplicate client response\n");close(fd);return 3;}
    seen[index]=1;printf("event=client_received index=%u\n",index);
  }
  close(fd);printf("event=client_complete unique=65\n");return 0;
}
int main(int argc,char **argv) {
  setvbuf(stdout,0,_IOLBF,0);
  if(argc>=2 && !strcmp(argv[1],"client"))return client(argc,argv);
  if(argc==2 && !strcmp(argv[1],"layout")){layout();return 0;}
  /* pid tid generation owners graph tm generation_offset owners_offset kind_offset
   * queue_offset deferred_offset pending_offset */
  if(argc!=17 && argc!=18)return 2;
  const char *mode=argc==18?argv[17]:"pressure";
  if(strcmp(mode,"pressure") && strcmp(mode,"probe") && strcmp(mode,"snapshot"))return 2;
  pid_t pid=(pid_t)number(argv[1]),tid=(pid_t)number(argv[2]);
  uint64_t generation=number(argv[3]),owners=number(argv[4]),graph=number(argv[5]),tm=number(argv[6]);
  uint64_t go=number(argv[7]),oo=number(argv[8]),ko=number(argv[9]);
  uint64_t qo=number(argv[10]),dfo=number(argv[11]),po=number(argv[12]);
  uint64_t debt_offsets[4]={number(argv[13]),number(argv[14]),number(argv[15]),number(argv[16])};
  if(pid<2 || tid<2 || pid==tid || !generation || (owners!=1 && owners!=3))return 2;
  char path[128],text[1024];
  snprintf(path,sizeof(path),"/proc/%d/task/%d/comm",pid,tid);
  FILE *f=fopen(path,"r");if(!f || !fgets(text,sizeof(text),f)){perror("thread comm");return 3;}fclose(f);
  char expected[32];snprintf(expected,sizeof(expected),"vpp_wk_%llu",(unsigned long long)owners);
  text[strcspn(text,"\n")]=0;
  if(strcmp(text,expected)){fprintf(stderr,"wrong I/O role: %s != %s\n",text,expected);return 3;}
  snprintf(path,sizeof(path),"/proc/%d/mem",pid);memory_fd=open(path,O_RDONLY|O_CLOEXEC);
  if(memory_fd<0){perror("memory");return 3;}
  uint64_t found_gen=0,mains=0,queues=0,fq=0,elts=0,initial_deferred=0;
  uint32_t found_owners=0,kind=0,index=0;
  if(read_memory(graph+go,&found_gen,8)||read_memory(graph+oo,&found_owners,4)||
     read_memory(graph+ko,&kind,4)||read_memory(graph+qo,&index,4)||
     read_memory(graph+dfo,&initial_deferred,8)||found_gen!=generation||found_owners!=owners||
     kind!=PRODUCT_ADAPTER_OBLIGATION_VPN_TUN||index>64){fprintf(stderr,"generation/topology mismatch\n");close(memory_fd);return 3;}
  if(read_memory(tm+offsetof(vlib_thread_main_t,frame_queue_mains),&mains,8)||!mains||
     read_memory(mains+index*sizeof(vlib_frame_queue_main_t)+offsetof(vlib_frame_queue_main_t,vlib_frame_queues),&queues,8)||!queues||
     read_memory(queues+(owners+1)*sizeof(void*),&fq,8)||!fq||
     read_memory(fq+offsetof(vlib_frame_queue_t,elts),&elts,8)||!elts){perror("queue address");close(memory_fd);return 3;}
  task_status(pid,tid,"before");
  uint32_t original_debts[4]={0};
  uint64_t settle_deadline=now_ns()+250000000ULL;
  int settled=0;
  do {
    settled=1;
    for(unsigned i=0;i<4;i++) {
      if(read_memory(graph+debt_offsets[i],&original_debts[i],4)||original_debts[i])settled=0;
    }
    if(settled)break;
    struct timespec pause={0,1000000};nanosleep(&pause,0);
  }while(now_ns()<settle_deadline);
  if(!settled){fprintf(stderr,"original graph debt not zero before pause\n");close(memory_fd);return 3;}
  printf("event=original_debts obligations=%u buffers=%u handoffs=%u frames=%u\n",original_debts[0],original_debts[1],original_debts[2],original_debts[3]);
  uint64_t initial_head=0,initial_tail=0;
  uint32_t slots=0;
  if(read_memory(fq+offsetof(vlib_frame_queue_t,head),&initial_head,8)||
     read_memory(fq+offsetof(vlib_frame_queue_t,tail),&initial_tail,8)||
     read_memory(fq+offsetof(vlib_frame_queue_t,nelts),&slots,4)||slots!=2||initial_head!=initial_tail){
    fprintf(stderr,"completion ring must be empty slots2\n");close(memory_fd);return 3;}
  printf("event=before originals_debt=0 pid=%d tid=%d generation=%llu owners=%llu queue=%u fq=0x%llx head=%llu tail=%llu slots=%u deferred=%llu\n",
    pid,tid,(unsigned long long)generation,(unsigned long long)owners,index,(unsigned long long)fq,
    (unsigned long long)initial_head,(unsigned long long)initial_tail,slots,(unsigned long long)initial_deferred);
  if(!strcmp(mode,"snapshot")){close(memory_fd);return 0;}
  int seized=0,stopped=0,status=0,result=1,full=0;
  struct sigaction sa={.sa_handler=expire};sigemptyset(&sa.sa_mask);
  sigaction(SIGALRM,&sa,0);sigaction(SIGTERM,&sa,0);sigaction(SIGINT,&sa,0);
  uint64_t begin=now_ns(),deadline=begin+1900000000ULL;alarm(2);
  if(ptrace(PTRACE_SEIZE,tid,0,0)){perror("PTRACE_SEIZE");goto finish;}seized=1;
  if(ptrace(PTRACE_INTERRUPT,tid,0,0)){perror("PTRACE_INTERRUPT");goto finish;}
  while(!expired && now_ns()<deadline) {
    pid_t waited=waitpid(tid,&status,__WALL|WNOHANG);
    if(waited==tid){stopped=WIFSTOPPED(status);break;}
    if(waited<0 && errno!=EINTR){perror("waitpid");goto finish;}
    struct timespec pause={0,1000000};nanosleep(&pause,0);
  }
  if(!stopped || (unsigned)status>>16!=PTRACE_EVENT_STOP){fprintf(stderr,"missing PTRACE_EVENT_STOP\n");goto finish;}
  printf("event=paused pid=%d tid=%d generation=%llu owners=%llu elapsed_ns=%llu\n",pid,tid,
    (unsigned long long)generation,(unsigned long long)owners,(unsigned long long)(now_ns()-begin));
  task_status(pid,tid,"paused");
  if(!strcmp(mode,"probe")){result=0;goto finish;}
  while(!expired && now_ns()<deadline) {
    uint64_t head=0,tail=0,deferred=0,gen=0;uint32_t valid=0,vectors=0,pending=0;
    if(read_memory(fq+offsetof(vlib_frame_queue_t,head),&head,8)||
       read_memory(fq+offsetof(vlib_frame_queue_t,tail),&tail,8)||read_memory(graph+dfo,&deferred,8)||
       read_memory(graph+go,&gen,8)||read_memory(graph+po,&pending,4)||gen!=generation){fprintf(stderr,"snapshot/generation failed\n");goto finish;}
    uint64_t elt=elts+((head+1)&(slots-1))*sizeof(vlib_frame_queue_elt_t);
    if(read_memory(elt+offsetof(vlib_frame_queue_elt_t,valid),&valid,4)||
       read_memory(elt+offsetof(vlib_frame_queue_elt_t,n_vectors),&vectors,4)){perror("elt snapshot");goto finish;}
    if(head!=initial_head){fprintf(stderr,"consumer head advanced while stopped\n");goto finish;}
    if((tail-head==slots-1 && valid) || deferred>initial_deferred) {
      printf("event=snapshot head=%llu tail=%llu slots=%u valid=%u vectors=%u deferred=%llu pending=%u elapsed_ns=%llu\n",
        (unsigned long long)head,(unsigned long long)tail,slots,valid,vectors,(unsigned long long)deferred,pending,
        (unsigned long long)(now_ns()-begin));
      full|=(tail-head==slots-1 && valid && vectors>0);
      if(full && deferred>initial_deferred && pending){result=0;break;}
    }
    struct timespec pause={0,2000000};nanosleep(&pause,0);
  }
finish:
  if(seized && !stopped){
    ptrace(PTRACE_INTERRUPT,tid,0,0);
    for(int i=0;i<50;i++){
      if(waitpid(tid,&status,__WALL|WNOHANG)==tid){stopped=WIFSTOPPED(status);break;}
      struct timespec pause={0,1000000};nanosleep(&pause,0);
    }
  }
  int detach_success=0;
  if(seized && stopped){
    if(ptrace(PTRACE_DETACH,tid,0,0)){perror("PTRACE_DETACH");result=1;}
    else detach_success=1;
  }
  if(seized && !stopped){fprintf(stderr,"unable to confirm detach; tracer exit auto-detaches\n");result=1;}
  alarm(0);
  task_status(pid,tid,"after");
  printf("event=resumed result=%s full=%d elapsed_ns=%llu seized=%d stopped=%d detach_success=%d\n",result?"HOLD":"PASS",full,(unsigned long long)(now_ns()-begin),seized,stopped,detach_success);
  close(memory_fd);return result;
}
