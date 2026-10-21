#!/usr/bin/env python3
"""Real reserve/prepare/finish with out-of-order loans and the actual receive pool."""
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[2]
PRODUCT=ROOT/'src/product/vpp'
source=(PRODUCT/'product_root_nfqueue_adapter.c').read_text()
def function(name):
    match=re.search(r'(?m)^'+re.escape(name)+r'\s*\(',source)
    assert match, name
    start=source.rfind('\n',0,match.start()-1)+1
    opening=source.index('{',match.end())
    depth,end=1,opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}')
        end+=1
    return source[start:end]+'\n'
def declaration(name,kind='struct'):
    end=source.index('} '+name+';')+len('} '+name+';')
    return source[source.rfind('typedef '+kind,0,end):end]+'\n'
prefix=r'''
#include <assert.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "product_packet_completion.h"
#include "product_root_receive_pool.h"
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
typedef uint64_t u64;typedef unsigned long uword;
typedef struct {u32 thread_index;} vlib_main_t;
#define PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY PRODUCT_ROOT_COMPLETION_CAPACITY
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES PRODUCT_ROOT_COMPLETION_MAX_LANES
#define SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS 1
#define clib_memset memset
#define ASSERT assert
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add(p,n,__ATOMIC_RELAXED)
#define clib_atomic_fetch_sub_relax(p,n) __atomic_fetch_sub(p,n,__ATOMIC_RELAXED)
#define PRODUCT_EXECUTION_OWNER_UNKNOWN UINT32_MAX
static u32 vlib_get_worker_thread_index(u32 w){return w+1;}
static u32 vlib_get_worker_index(u32 t){return t-1;}
static u32 product_packet_graph_worker_count(void){return 2;}
static u32 product_packet_graph_trace_limit(void){return 0;}
'''
names=(('product_root_nfqueue_fault_mode_t','enum'),('product_root_nfqueue_pending_t','struct'),
       ('product_root_nfqueue_lane_t','struct'),('product_root_nfqueue_main_t','struct'),
       ('product_root_verdict_work_t','struct'))
types=''.join(declaration(name,kind) for name,kind in names)
outcome_start=source.index('enum\n{\n  PRODUCT_VERDICT_SUCCEEDED')
outcomes=source[outcome_start:source.index('};',outcome_start)+2]+'\n'
dependencies=r'''
static product_root_nfqueue_main_t product_root_nfqueue_main;
static void product_root_nfqueue_return_receive(product_root_nfqueue_lane_t *lane,u32 slot,u32 buffer){
 assert(product_root_receive_pool_return(&lane->receive_pool,lane->generation,(u16)slot,buffer));
}
'''
helpers=''
for name in ('product_root_nfqueue_pending_find','product_root_nfqueue_pending_deactivate'):
    if re.search(r'(?m)^'+name+r'\s*\(',source):helpers+=function(name)
helpers+=''.join(function(name) for name in ('product_root_nfqueue_reserve',
              'product_root_nfqueue_record_verdict_attempt','product_root_nfqueue_prepare_completion',
              'product_root_nfqueue_finish_completion'))
suffix=r'''
static vlib_main_t vm={1};
static void reset(void){
 memset(&product_root_nfqueue_main,0,sizeof(product_root_nfqueue_main));
 product_root_nfqueue_main.generation=42;product_root_nfqueue_main.lane_count=1;
 product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
 lane->generation=42;lane->socket_ready=1;lane->fd=27;lane->queue_id=176;
 u32 buffers[PRODUCT_ROOT_RECEIVE_TOTAL];
 for(u32 i=0;i<PRODUCT_ROOT_RECEIVE_TOTAL;i++)buffers[i]=1000+i;
 /* Retain the explicit 64-slot collision regression alongside the new
  * 128-slot startup default exercised by the pool/capacity tests. */
 assert(product_root_receive_pool_init_capacity(&lane->receive_pool,42,buffers,64));
}
static product_root_nfqueue_pending_t *borrow(u32 id){
 product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
 u16 slot=product_root_receive_pool_take(&lane->receive_pool,42,0);
 assert(slot!=PRODUCT_ROOT_RECEIVE_NONE);
 product_root_nfqueue_pending_t *p=product_root_nfqueue_reserve(&product_root_nfqueue_main,lane,id,lane->receive_pool.buffers[slot],slot);
 assert(p && "free completion slots must admit a new ID despite an older colliding ID");
 return p;
}
static product_packet_completion_frame_t completion(product_root_nfqueue_pending_t *p){
 product_packet_completion_frame_t value=p->completion;
 value.producer_thread=1;value.terminal_intent=PRODUCT_PACKET_INTENT_PASS_ADAPTER;
 value.flags=PRODUCT_COMPLETION_POLICY_QUALIFIED|PRODUCT_COMPLETION_POLICY_QUALIFIED_MATCHED;
 return value;
}
static void finish(product_root_nfqueue_pending_t *p,u32 outcome){
 product_root_verdict_work_t work;
 product_packet_completion_frame_t value=completion(p);
 assert(product_root_nfqueue_prepare_completion(&vm,p->buffer_index,&value,&work));
 assert(work.pending==p);
 product_root_nfqueue_finish_completion(&work,outcome,outcome==PRODUCT_VERDICT_SUCCEEDED?32:-1,
                                       outcome==PRODUCT_VERDICT_SUCCEEDED?0:EIO);
}
static void retained_old_loan(void){
 reset();product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
 product_root_nfqueue_pending_t *old=borrow(1);
 product_adapter_obligation_t identity=old->completion.obligation;
 for(u32 id=2;id<=64;id++)finish(borrow(id),PRODUCT_VERDICT_SUCCEEDED);
 assert(lane->pending_count==1 && lane->receive_pool.normal_free==63 && old->active);
 product_root_nfqueue_pending_t *next=borrow(65);
 assert(next!=old && old->active && !memcmp(&old->completion.obligation,&identity,sizeof(identity)));
 assert(lane->pending_count==2);
 /* Duplicate an active displaced identity: it must not get a second loan. */
 assert(!product_root_nfqueue_reserve(&product_root_nfqueue_main,lane,65,2000,0));
 product_packet_completion_frame_t saved=completion(next);
 u32 buffer=next->buffer_index;finish(next,PRODUCT_VERDICT_SUCCEEDED);
 product_root_verdict_work_t work;
 assert(!product_root_nfqueue_prepare_completion(&vm,buffer,&saved,&work));
 assert(lane->duplicate_completion_drops==1 && old->active && lane->pending_count==1);
 product_root_nfqueue_pending_t *newer=borrow(129);
 assert(!product_root_nfqueue_prepare_completion(&vm,buffer,&saved,&work));
 assert(product_root_nfqueue_main.stale_completion_drops==1 && newer->active);
 finish(newer,PRODUCT_VERDICT_FAILED_DEFINITE);finish(old,PRODUCT_VERDICT_SUCCEEDED);
 assert(!lane->pending_count && !product_root_nfqueue_main.pending_count);
 assert(!lane->receive_pool.outstanding && lane->receive_pool.normal_free==64);
 assert(lane->verdict_attempts==66 && lane->verdict_succeeded==65 && lane->verdict_failed==1);
 puts("PASS old loan survives ID 65/129 collisions, real pool returns, duplicate/stale exclusion and exact settlement");
}
static void full_capacity_and_reverse_drain(void){
 reset();product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
 product_root_nfqueue_pending_t *items[64];
 for(u32 i=0;i<64;i++)items[i]=borrow(1+64*i);
 assert(lane->pending_count==64 && lane->receive_pool.normal_free==0);
 assert(!product_root_nfqueue_reserve(&product_root_nfqueue_main,lane,4097,2000,0));
 assert(!product_root_nfqueue_reserve(&product_root_nfqueue_main,lane,65,2000,0));
 for(u32 i=64;i>0;i--)finish(items[i-1],i%5?PRODUCT_VERDICT_SUCCEEDED:PRODUCT_VERDICT_OUTCOME_UNKNOWN);
 assert(!lane->pending_count && !product_root_nfqueue_main.pending_count);
 assert(!lane->receive_pool.outstanding && lane->receive_pool.normal_free==64 && lane->receive_pool.reserve_free==8);
 assert(lane->verdict_attempts==64 && lane->verdict_failed==12 && lane->verdict_succeeded==52);
 puts("PASS 64 colliding IDs use exactly 64 loans, genuine full remains bounded, reverse drain includes UNKNOWN");
}
static void packet_id_wrap_and_wrong_identity(void){
 reset();product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
 product_root_nfqueue_pending_t *a=borrow(UINT32_MAX),*b=borrow(0),*c=borrow(64);
 product_packet_completion_frame_t value=completion(c);
 product_root_verdict_work_t work;
 value.obligation.token++;assert(!product_root_nfqueue_prepare_completion(&vm,c->buffer_index,&value,&work));
 value=completion(c);value.obligation.queue_generation--;assert(!product_root_nfqueue_prepare_completion(&vm,c->buffer_index,&value,&work));
 value=completion(c);assert(!product_root_nfqueue_prepare_completion(&vm,c->buffer_index+1,&value,&work));
 assert(c->active && lane->pending_count==3);
 finish(c,PRODUCT_VERDICT_SUCCEEDED);finish(b,PRODUCT_VERDICT_SUCCEEDED);finish(a,PRODUCT_VERDICT_SUCCEEDED);
 assert(!lane->pending_count && !lane->receive_pool.outstanding && lane->receive_pool.normal_free==64);
 puts("PASS UINT32 packet-ID wrap, exact token/generation/carrier verification and final pool conservation");
}
int main(void){retained_old_loan();full_capacity_and_reverse_drain();packet_id_wrap_and_wrong_identity();}
'''
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
with tempfile.TemporaryDirectory(prefix='sakamoto-root-pending-') as folder:
    path=Path(folder);fixture=path/'fixture.c';exe=path/'fixture'
    fixture.write_text(prefix+types+outcomes+dependencies+helpers+suffix)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-Wall','-Wextra','-Werror','-O1','-g',
                    '-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie','-I',str(PRODUCT),str(fixture),'-o',str(exe)],check=True)
    # The runner uses ptrace; this fixture allocates no heap. Keep ASan/UBSan
    # bounds checks while avoiding LeakSanitizer's unsupported process walk.
    subprocess.run([str(exe)],check=True,timeout=5,
                   env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0:handle_segv=0'})
print('adapter_source_sha256='+hashlib.sha256(source.encode()).hexdigest())
