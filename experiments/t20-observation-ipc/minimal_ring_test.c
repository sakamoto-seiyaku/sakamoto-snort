#include "minimal_ring.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint64_t sequence; size_t length; } expected_record;
typedef struct {
  expected_record records[4096];
  size_t first, last;
  uint64_t checked;
} reference_fifo;
static minimal_ring queue;
static reference_fifo reference;

static void fill(uint8_t *data,size_t n,uint64_t sequence)
{ for(size_t i=0;i<n;i++)data[i]=(uint8_t)(sequence*17+i*13); }
static void expect(uint64_t sequence,size_t length)
{
  assert(reference.last-reference.first<4096);
  reference.records[reference.last++%4096]=(expected_record){sequence,length};
}
static void check(const uint8_t *data,size_t n,void *unused)
{
  (void)unused;
  assert(reference.first<reference.last);
  expected_record e=reference.records[reference.first++%4096];
  assert(n==e.length);
  for(size_t i=0;i<n;i++)assert(data[i]==(uint8_t)(e.sequence*17+i*13));
  reference.checked++;
}
static size_t drain(size_t limit)
{
  size_t n;
  assert(minimal_ring_read(&queue,limit,check,NULL,&n)==0);
  return n;
}
static void reset(void)
{
  memset(&queue,0,sizeof(queue));
  memset(&reference,0,sizeof(reference));
  assert(minimal_ring_init(&queue)==0);
}
static void boundaries(void)
{
  const size_t sizes[]={1,7,8,9,127,128,129,511,512,513,2047,2048};
  reset();uint8_t data[2049]={0};
  assert(minimal_ring_write(&queue,data,0)==-1);
  assert(minimal_ring_write(&queue,data,2049)==-1);
  assert(minimal_ring_write(&queue,NULL,128)==-1);
  assert(atomic_load(&queue.tail)==0);
  for(size_t i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++) {
    fill(data,sizes[i],i+1);expect(i+1,sizes[i]);
    assert(minimal_ring_write(&queue,data,sizes[i])==0);
    assert(drain(0)==0);assert(drain(1)==1);assert(drain(1)==0);
  }
}
static void full_immutable(void)
{
  reset();uint8_t data[128];fill(data,sizeof(data),1);
  for(size_t i=0;i<1927;i++) {
    assert(minimal_ring_write(&queue,data,sizeof(data))==0);expect(1,128);
  }
  unsigned char *before=malloc(sizeof(queue));assert(before);
  memcpy(before,&queue,sizeof(queue));
  for(unsigned i=0;i<100;i++)assert(minimal_ring_write(&queue,data,sizeof(data))==1);
  assert(memcmp(before,&queue,sizeof(queue))==0);free(before);
  assert(drain(4096)==1927);
}
static void held(const uint8_t *data,size_t n,void *arg)
{
  unsigned *calls=arg;uint8_t replacement[128];fill(replacement,sizeof(replacement),2);
  assert(atomic_load(&queue.head)==0);
  assert(minimal_ring_write(&queue,replacement,sizeof(replacement))==1);
  check(data,n,NULL);(*calls)++;
}
static void borrowed_reclamation(void)
{
  reset();uint8_t data[128];fill(data,sizeof(data),1);
  for(size_t i=0;i<1927;i++) {
    assert(minimal_ring_write(&queue,data,sizeof(data))==0);expect(1,128);
  }
  unsigned calls=0;size_t n;
  assert(minimal_ring_read(&queue,1,held,&calls,&n)==0 && n==1 && calls==1);
  fill(data,sizeof(data),2);
  assert(minimal_ring_write(&queue,data,sizeof(data))==0);expect(2,128);
  assert(drain(4096)==1927);
}
static void wraps(void)
{
  uint8_t data[128];fill(data,sizeof(data),42);
  const uint64_t seeds[]={T20_RING_CAPACITY-64,UINT64_MAX-63};
  for(size_t i=0;i<2;i++) {
    reset();atomic_store(&queue.head,seeds[i]);atomic_store(&queue.tail,seeds[i]);
    assert(minimal_ring_write(&queue,data,sizeof(data))==0);expect(42,128);
    uint64_t end=seeds[i]+64+136;
    assert(atomic_load(&queue.tail)==end);
    assert(drain(1)==1 && atomic_load(&queue.head)==end);
  }
  reset();atomic_store(&queue.head,T20_RING_CAPACITY-64);
  atomic_store(&queue.tail,T20_RING_CAPACITY-64);
  assert(minimal_ring_write(&queue,data,56)==0);expect(42,56);
  assert(atomic_load(&queue.tail)==T20_RING_CAPACITY && drain(1)==1);
}
static void corrupt_headers(void)
{
  const uint32_t headers[][2]={{2049,0},{8,1},{16,0},{0,0}};
  for(size_t i=0;i<4;i++) {
    reset();memcpy(queue.data,headers[i],8);
    atomic_store(&queue.tail,i==3?T20_RING_CAPACITY:8);
    size_t n=99;
    assert(minimal_ring_read(&queue,1,check,NULL,&n)==-1);
    assert(n==0 && atomic_load(&queue.head)==0);
  }
  reset();atomic_store(&queue.tail,T20_RING_CAPACITY+8);
  uint8_t data[128]={0};size_t n;
  assert(minimal_ring_write(&queue,data,sizeof(data))==-1);
  assert(minimal_ring_read(&queue,1,check,NULL,&n)==-1);
}
static void fifo_model(void)
{
  reset();uint8_t data[2048];uint32_t rng=0x12345678;
  uint64_t accepted=0,full=0;
  for(uint64_t seq=1;seq<=200000;seq++) {
    rng=rng*1664525u+1013904223u;
    size_t length=128+(rng%1921);
    fill(data,length,seq);
    int rc=minimal_ring_write(&queue,data,length);
    assert(rc==0 || rc==1);
    if(rc==0){expect(seq,length);accepted++;}else full++;
    if((rng&7)==0)(void)drain(1+((rng>>8)%8));
  }
  while(drain(32)) {}
  assert(accepted==reference.checked && full>0 && reference.first==reference.last);
  assert(atomic_load(&queue.head)==atomic_load(&queue.tail));
  assert(atomic_load(&queue.head)>100*T20_RING_CAPACITY);
}
int main(void)
{
  boundaries();full_immutable();borrowed_reclamation();wraps();corrupt_headers();fifo_model();
  puts("{\"status\":\"PASS\",\"cases\":[\"boundaries\",\"invalid_lengths\",\"full_immutable\",\"borrowed_reclamation\",\"physical_wrap\",\"counter_wrap\",\"corrupt_headers\",\"fifo_model\"],\"model_operations\":200000}");
  return 0;
}
