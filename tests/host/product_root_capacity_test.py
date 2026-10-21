#!/usr/bin/env python3
"""Actual resize, 128 colliding loans and non-destructive configuration ACK.

Allocation/transport are seams; this proves conservation and failure behavior,
not kernel pressure or performance. Reuse the existing actual-code fixture.
"""
import os
from pathlib import Path
import resource
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
base = runpy.run_path(str(ROOT / 'tests/host/product_root_pending_test.py'))
function = base['function']
seams = r'''
#include <arpa/inet.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#define clib_memcpy_fast memcpy
#define clib_panic(x) assert(!(x))
static unsigned allocation_fail,allocations,freed,next_buffer=2000;
static u32 vlib_buffer_alloc(vlib_main_t *vm,u32 *indices,u32 count){
 assert(vm);allocations++;u32 n=allocation_fail?20:count;
 for(u32 i=0;i<n;i++)indices[i]=next_buffer++;
 return n;
}
static void vlib_buffer_free(vlib_main_t *vm,const u32 *indices,u32 count){assert(vm && indices);freed+=count;}
static int product_root_nfqueue_last_errno;
static unsigned ack_kind,submitted,consumed,queue_has_packet;
static u32 ack_sequence,requested_maxlen;
static int product_nfnl_send(int fd,const struct nlmsghdr *nlh,int flags){
 assert(fd==27 && !flags && nlh->nlmsg_type==((NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_CONFIG));
 assert(nlh->nlmsg_flags==(NLM_F_REQUEST|NLM_F_ACK));
 const struct nfgenmsg *nfgen=NLMSG_DATA(nlh);assert(ntohs(nfgen->res_id)==176);
 const struct nfattr *attr=(const struct nfattr*)((const u8*)nlh+NLMSG_LENGTH(sizeof(*nfgen)));
 assert(attr->nfa_type==NFQA_CFG_QUEUE_MAXLEN && attr->nfa_len==NFA_LENGTH(sizeof(u32)));
 memcpy(&requested_maxlen,NFA_DATA(attr),sizeof(u32));requested_maxlen=ntohl(requested_maxlen);
 ack_sequence=nlh->nlmsg_seq;submitted++;
 if(ack_kind==5){product_root_nfqueue_last_errno=EPERM;return 0;}
 return 1;
}
static ssize_t fake_recv(int fd,void *data,size_t size,int flags){
 assert(fd==27 && size==512);
 if(!submitted && !queue_has_packet){errno=EAGAIN;return -1;}
 if(ack_kind==4 && submitted){errno=EAGAIN;return -1;}
 struct nlmsghdr *nlh=data;memset(data,0,size);
 nlh->nlmsg_len=NLMSG_LENGTH(sizeof(struct nlmsgerr));
 nlh->nlmsg_type=(queue_has_packet || ack_kind==2)?((NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET):NLMSG_ERROR;
 nlh->nlmsg_seq=ack_sequence+(ack_kind==3);
 ((struct nlmsgerr*)NLMSG_DATA(nlh))->error=ack_kind==1?-EPERM:0;
 if(flags==MSG_DONTWAIT){consumed++;return nlh->nlmsg_len;}
 assert(flags==(MSG_PEEK|MSG_DONTWAIT));return nlh->nlmsg_len;
}
#define recv fake_recv
#define usleep(value) ((void)(value))
'''
production = ''.join(function(name) for name in (
    'product_nfnl_type', 'product_nfnl_addattr', 'product_nfnl_fill_header',
    'product_root_nfqueue_resize_empty_pool', 'product_root_nfqueue_apply_maxlen'))
suffix = base['suffix'].replace(
    'int main(void){retained_old_loan();full_capacity_and_reverse_drain();packet_id_wrap_and_wrong_identity();}', '')
extended = r'''
static void resize_and_128(void){
 reset();product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
 lane->receive_allocated=72;allocations=freed=0;
 assert(product_root_nfqueue_resize_empty_pool(&vm,lane,64) && !allocations);
 product_root_nfqueue_pending_t *old=borrow(1);
 assert(!product_root_nfqueue_resize_empty_pool(&vm,lane,128) && !allocations);
 finish(old,PRODUCT_VERDICT_SUCCEEDED);
 product_root_receive_pool_t snapshot=lane->receive_pool;allocation_fail=1;
 assert(!product_root_nfqueue_resize_empty_pool(&vm,lane,128) && errno==ENOMEM);
 assert(!memcmp(&snapshot,&lane->receive_pool,sizeof(snapshot)) && lane->receive_allocated==72 && freed==20);
 allocation_fail=0;assert(product_root_nfqueue_resize_empty_pool(&vm,lane,128));
 assert(lane->receive_allocated==136 && lane->receive_pool.normal_capacity==128 && freed==92);
 product_root_nfqueue_pending_t *items[128];
 for(u32 i=0;i<128;i++)items[i]=borrow(1+128*i);
 assert(lane->pending_count==128 && !lane->receive_pool.normal_free);
 assert(lane->pending_active_slots==UINT64_MAX && lane->pending_active_slots_high==UINT64_MAX);
 assert(lane->pending_high_water==128 && lane->loan_high_water==128);
 assert(!product_root_nfqueue_reserve(&product_root_nfqueue_main,lane,1+128*90,9,0));
 assert(!product_root_nfqueue_reserve(&product_root_nfqueue_main,lane,1+128*128,9,0));
 product_packet_completion_frame_t replay=completion(items[90]);u32 carrier=items[90]->buffer_index;
 for(u32 i=128;i>0;i--)finish(items[i-1],i%5?PRODUCT_VERDICT_SUCCEEDED:PRODUCT_VERDICT_OUTCOME_UNKNOWN);
 assert(!lane->pending_count && !lane->receive_pool.outstanding && lane->receive_pool.normal_free==128);
 assert(!lane->pending_active_slots && !lane->pending_active_slots_high);
 product_root_verdict_work_t work;assert(!product_root_nfqueue_prepare_completion(&vm,carrier,&replay,&work));
 assert(lane->duplicate_completion_drops==1);
 product_root_nfqueue_pending_t *held=borrow(1),*next=borrow(129);
 assert(held!=next && product_root_nfqueue_pending_find(lane,1,held->completion.obligation.token,42)==held);
 finish(next,PRODUCT_VERDICT_SUCCEEDED);finish(held,PRODUCT_VERDICT_SUCCEEDED);
 assert(product_root_nfqueue_resize_empty_pool(&vm,lane,64));
 assert(lane->receive_allocated==72 && lane->receive_pool.normal_free==64 && lane->receive_pool.reserve_free==8);
 assert(!lane->pending_displaced_slots && !lane->pending_displaced_slots_high);
 puts("PASS transactional resize, actual 128 colliding loans, high-bank history/replay and reverse UNKNOWN drain");
}
static void maxlen_ack(void){
 for(unsigned kind=0;kind<=5;kind++){
  reset();product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
  lane->queue_maxlen=1024;ack_kind=kind;submitted=consumed=queue_has_packet=0;
  int ok=product_root_nfqueue_apply_maxlen(lane,4096);
  assert(submitted==1 && requested_maxlen==4096 && ok==(kind==0));
  assert(lane->queue_maxlen==(kind==0?4096:kind==5?1024:0));assert(consumed==(kind<=1));
 }
 reset();product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
 lane->queue_maxlen=1024;submitted=consumed=0;queue_has_packet=1;ack_kind=0;
 assert(!product_root_nfqueue_apply_maxlen(lane,4096) && !submitted && !consumed && lane->queue_maxlen==1024);
 queue_has_packet=0;assert(!product_root_nfqueue_apply_maxlen(lane,0));
 assert(!product_root_nfqueue_apply_maxlen(lane,65537) && !submitted);
 product_root_nfqueue_pending_t *p=borrow(1);
 assert(!product_root_nfqueue_apply_maxlen(lane,4096) && !submitted);finish(p,PRODUCT_VERDICT_SUCCEEDED);
 puts("PASS ACK-confirmed maxlen, negative/timeout/foreign-envelope failures, zero unexpected packet consumption");
}
int main(void){resize_and_128();maxlen_ack();}
'''
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='root-capacity-') as folder:
    path = Path(folder)
    fixture, exe = path / 'test.c', path / 'test'
    fixture.write_text('#include <arpa/inet.h>\n' + base['prefix'] + base['types'] + base['outcomes'] + seams +
                       base['dependencies'] + base['helpers'] + production + suffix + extended)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O1', '-g',
                    '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
                    '-I', str(ROOT / 'src/product/vpp'), str(fixture), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True, timeout=15,
                   env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0:handle_segv=0'})
