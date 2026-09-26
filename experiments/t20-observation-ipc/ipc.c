#define _GNU_SOURCE
#include "ipc.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef T20_VPP
#include <svm/message_queue.h>
#include <vppinfra/mem.h>
#elif defined(T20_MINIMAL)
#include "minimal_ring.h"
#else
#include "concurrent/aeron_spsc_rb.h"
/* The subset needs only the initialization error hook, no Aeron runtime. */
void aeron_err_set(int e, const char *f, const char *p, int l, const char *fmt, ...)
{ (void)e; (void)f; (void)p; (void)l; (void)fmt; }
#endif

#define DATA_BYTES 262144u
#define HEADER_BYTES 4096u
typedef struct {
  uint64_t magic, generation, channel_bytes, mapped_bytes;
  _Atomic uint64_t attempted[2], accepted[2], dropped[2], invalid[2];
  _Atomic uint64_t accepted_sum[2], accepted_xor[2], accepted_bytes[2];
  _Atomic uint64_t prewait_publications[2];
  _Atomic uint64_t wait_epoch;
  _Atomic unsigned done;
} shared;
struct ipc {
  void *base;
  shared *s;
  int fd, event;
  uint64_t waits, signals, timeouts;
#ifdef T20_VPP
  svm_msg_q_t q[2];
#elif defined(T20_MINIMAL)
  minimal_ring *q[2];
#else
  aeron_spsc_rb_t q[2];
#endif
};

uint64_t ipc_now(void)
{ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint64_t)t.tv_sec*1000000000+t.tv_nsec; }
uint64_t ipc_cpu(void)
{ struct timespec t; clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t); return (uint64_t)t.tv_sec*1000000000+t.tv_nsec; }

ipc *ipc_open(const char *path, int event, uint64_t generation, int create)
{
  ipc *h = calloc(1, sizeof(*h));
  if (!h) return NULL;
  h->fd = -1; h->event = event;
  size_t total = 0;
#ifdef T20_VPP
  /* The library's private handles use its allocator, never shared pointers. */
  static int heap_ready;
  if (!heap_ready) {if (!clib_mem_init(NULL, 16u<<20)) goto fail; heap_ready=1;}
  svm_msg_q_ring_cfg_t rings[] = {{512,128,NULL},{128,512,NULL},{64,2048,NULL}};
  svm_msg_q_cfg_t cfg = {.q_nitems=704,.n_rings=3,.ring_cfgs=rings};
  size_t bytes = svm_msg_q_size_to_alloc(&cfg);
#elif defined(T20_MINIMAL)
  _Static_assert(DATA_BYTES==T20_RING_CAPACITY,"common capacity");
  size_t bytes = sizeof(minimal_ring);
#else
  size_t bytes = DATA_BYTES+AERON_RB_TRAILER_LENGTH;
#endif
  bytes = (bytes+63)&~(size_t)63;
  total = HEADER_BYTES+2*bytes;
  h->fd = open(path, create ? O_RDWR|O_CREAT|O_EXCL : O_RDWR, 0600);
  if (h->fd<0) goto fail;
  if (create && ftruncate(h->fd,total)) goto fail;
  struct stat st;
  if (fstat(h->fd,&st) || (size_t)st.st_size!=total) goto fail;
  h->base = mmap(NULL,total,PROT_READ|PROT_WRITE,MAP_SHARED,h->fd,0);
  if (h->base==MAP_FAILED) {h->base=NULL; goto fail;}
  h->s=h->base;
  if (create) {
    memset(h->base,0,total);
    h->s->magic=0x5432304950430002ULL; h->s->generation=generation;
    h->s->channel_bytes=bytes; h->s->mapped_bytes=total;
  } else if (h->s->magic!=0x5432304950430002ULL || h->s->generation!=generation ||
             h->s->channel_bytes!=bytes || h->s->mapped_bytes!=total) goto fail;
  for (unsigned c=0;c<2;c++) {
    void *base=(uint8_t*)h->base+HEADER_BYTES+c*bytes;
#ifdef T20_VPP
    if (create) svm_msg_q_init(base,&cfg);
    svm_msg_q_attach(&h->q[c],base);
    /* Both queues share the consumer notification source, not capacity. */
    svm_msg_q_set_eventfd(&h->q[c],event);
#elif defined(T20_MINIMAL)
    h->q[c]=base;
    if (create && minimal_ring_init(h->q[c])) goto fail;
#else
    if (aeron_spsc_rb_init(&h->q[c],base,DATA_BYTES+AERON_RB_TRAILER_LENGTH)) goto fail;
#endif
  }
  return h;
fail:
  if (h->base) munmap(h->base,total);
  if (h->fd>=0) close(h->fd);
  free(h); return NULL;
}

int ipc_write(ipc *h, unsigned c, const void *record, size_t n)
{
  if (c>1) return -3;
  atomic_fetch_add_explicit(&h->s->attempted[c],1,memory_order_relaxed);
  if (n<128 || n>2048) {
    atomic_fetch_add_explicit(&h->s->invalid[c],1,memory_order_relaxed); return -3;
  }
  /* The same odd epoch must bracket publication; a later wait cannot count it. */
  uint64_t wait_before=atomic_load_explicit(&h->s->wait_epoch,memory_order_seq_cst);
  int rc;
#ifdef T20_VPP
  unsigned ring=n<=128?0:n<=512?1:2;
  svm_msg_q_msg_t msg;
  rc=svm_msg_q_lock_and_alloc_msg_w_ring(&h->q[c],ring,1,&msg);
  if (!rc) {
    memcpy(svm_msg_q_msg_data(&h->q[c],&msg),record,n);
    svm_msg_q_add_and_unlock(&h->q[c],&msg);
  }
#elif defined(T20_MINIMAL)
  rc=minimal_ring_write(h->q[c],record,n)==0?0:-2;
#else
  rc=aeron_spsc_rb_write(&h->q[c],1,record,n)==AERON_RB_SUCCESS?0:-2;
#endif
  uint64_t wait_after=atomic_load_explicit(&h->s->wait_epoch,memory_order_seq_cst);
  if (rc) atomic_fetch_add_explicit(&h->s->dropped[c],1,memory_order_relaxed);
  else {
    uint64_t seq; memcpy(&seq,(const uint8_t*)record+16,8);
    atomic_fetch_add_explicit(&h->s->accepted[c],1,memory_order_relaxed);
    atomic_fetch_add_explicit(&h->s->accepted_sum[c],seq,memory_order_relaxed);
    atomic_fetch_xor_explicit(&h->s->accepted_xor[c],seq,memory_order_relaxed);
    atomic_fetch_add_explicit(&h->s->accepted_bytes[c],n,memory_order_relaxed);
    if (ipc_same_prewait_epoch(wait_before,wait_after))
      atomic_fetch_add_explicit(&h->s->prewait_publications[c],1,memory_order_relaxed);
  }
  return rc;
}

#if !defined(T20_VPP) && !defined(T20_MINIMAL)
typedef struct {record_fn fn; void *arg;} callback;
static void bridge(int32_t type, const void *data, size_t length, void *arg)
{ callback *c=arg; (void)type; c->fn(data,length,c->arg); }
#endif
size_t ipc_read(ipc *h, unsigned c, size_t limit, record_fn fn, void *arg)
{
#ifdef T20_VPP
  size_t n=0;
  while(n<limit && !svm_msg_q_is_empty(&h->q[c])) {
    svm_msg_q_msg_t msg; svm_msg_q_sub_raw(&h->q[c],&msg);
    const uint8_t *data=svm_msg_q_msg_data(&h->q[c],&msg);
    uint32_t len; memcpy(&len,data+4,4);
    /* Never trust a variable length before bounding it by its actual slot. */
    size_t slot=h->q[c].rings[msg.ring_index].elsize;
    fn(data,len<=slot?len:0,arg);
    svm_msg_q_free_msg(&h->q[c],&msg); n++;
  }
  return n;
#elif defined(T20_MINIMAL)
  size_t n;
  if (minimal_ring_read(h->q[c],limit,fn,arg,&n)) {
    fputs("minimal ring corrupt state\n",stderr);exit(4);
  }
  return n;
#else
  callback cb={fn,arg};
  return aeron_spsc_rb_read(&h->q[c],bridge,&cb,limit);
#endif
}
void ipc_notify(ipc *h)
{
  uint64_t one=1;
  ssize_t rc;do {rc=write(h->event,&one,8);} while(rc<0 && errno==EINTR);
  if (rc!=8 && !(rc<0 && errno==EAGAIN)) {perror("notify"); exit(4);}
}
int ipc_wait(ipc *h)
{
  struct pollfd p={h->event,POLLIN,0}; h->waits++;
  int rc; do {rc=poll(&p,1,5000);} while(rc<0 && errno==EINTR);
  if (rc==0) {h->timeouts++; return -1;}
  if (rc<0 || !(p.revents&POLLIN)) return -2;
  uint64_t value;
  ssize_t got;do {got=read(h->event,&value,8);} while(got<0 && errno==EINTR);
  if (got==8) h->signals+=value;
  else if (!(got<0 && errno==EAGAIN)) return -3;
  return 0;
}
int ipc_wait_race(ipc *h)
{
  /* Odd = after empty check/before poll. Never reset: reject a later window. */
  atomic_fetch_add_explicit(&h->s->wait_epoch,1,memory_order_seq_cst);
  struct timespec delay={0,200000};
  while(nanosleep(&delay,&delay)<0 && errno==EINTR) {}
  atomic_fetch_add_explicit(&h->s->wait_epoch,1,memory_order_seq_cst);
  return ipc_wait(h);
}
int ipc_same_prewait_epoch(uint64_t before,uint64_t after)
{ return (before&1) && before==after; }
int ipc_done(ipc *h) {return atomic_load_explicit(&h->s->done,memory_order_acquire);}
void ipc_finish(ipc *h)
{atomic_store_explicit(&h->s->done,1,memory_order_release); ipc_notify(h);}
void ipc_report(ipc *h,const char *role)
{
  struct rusage r; getrusage(RUSAGE_SELF,&r);
  unsigned long vm=0,rss=0,threads=0; char line[256];
  FILE *status=fopen("/proc/self/status","r");
  if(status) {
    while(fgets(line,sizeof(line),status)) {
      if(sscanf(line,"VmSize: %lu",&vm)==1)continue;
      if(sscanf(line,"VmRSS: %lu",&rss)==1)continue;
      (void)sscanf(line,"Threads: %lu",&threads);
    }
    fclose(status);
  }
  printf("{\"role\":\"%s\",\"generation\":%llu,\"mapping\":\"%p\",\"shared_bytes\":%llu,\"rss_kib\":%ld,\"current_rss_kib\":%lu,\"virtual_kib\":%lu,\"threads\":%lu,\"voluntary_switches\":%ld,\"involuntary_switches\":%ld,\"waits\":%llu,\"signals_read\":%llu,\"timeouts\":%llu,\"channels\":[",role,
    (unsigned long long)h->s->generation,h->base,(unsigned long long)h->s->mapped_bytes,
    r.ru_maxrss,rss,vm,threads,r.ru_nvcsw,r.ru_nivcsw,(unsigned long long)h->waits,
    (unsigned long long)h->signals,(unsigned long long)h->timeouts);
  for(unsigned c=0;c<2;c++) printf("%s{\"attempted\":%llu,\"accepted\":%llu,\"dropped\":%llu,\"invalid\":%llu,\"sum\":%llu,\"xor\":%llu,\"bytes\":%llu,\"prewait\":%llu}",c?",":"",
    (unsigned long long)atomic_load(&h->s->attempted[c]),(unsigned long long)atomic_load(&h->s->accepted[c]),
    (unsigned long long)atomic_load(&h->s->dropped[c]),(unsigned long long)atomic_load(&h->s->invalid[c]),
    (unsigned long long)atomic_load(&h->s->accepted_sum[c]),(unsigned long long)atomic_load(&h->s->accepted_xor[c]),
    (unsigned long long)atomic_load(&h->s->accepted_bytes[c]),
    (unsigned long long)atomic_load(&h->s->prewait_publications[c]));
  puts("]}"); fflush(stdout);
}
void ipc_close(ipc *h)
{
#ifdef T20_VPP
  for(unsigned c=0;c<2;c++) {h->q[c].q.evtfd=-1; svm_msg_q_cleanup(&h->q[c]);}
#endif
  munmap(h->base,h->s->mapped_bytes); close(h->fd); free(h);
}
