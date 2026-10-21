#!/usr/bin/env python3
"""Run the actual bounded receive callback and socket tuning with native seams.

The real lane declarations, receive pool and reserve/deactivate functions are
used. Netlink input, VPP buffers, graph publication and socket options are fake;
this proves bounded callback/loan behavior, not kernel pressure or delivery.
"""
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / 'src/product/vpp'
source = (PRODUCT / 'product_root_nfqueue_adapter.c').read_text()


def function(name):
    match = re.search(r'(?m)^' + re.escape(name) + r'\s*\(', source)
    assert match, name
    start = source.rfind('\n', 0, match.start() - 1) + 1
    opening = source.index('{', match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'


def declaration(name, kind='struct'):
    end = source.index('} ' + name + ';') + len('} ' + name + ';')
    return source[source.rfind('typedef ' + kind, 0, end):end] + '\n'


prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include "product_packet.h"
#include "product_packet_completion.h"
#include "product_root_receive_pool.h"
#include "product_packet_batch.h"
typedef uint8_t u8; typedef uint16_t u16; typedef int16_t i16;
typedef uint32_t u32; typedef uint64_t u64; typedef unsigned long uword;
typedef struct {u32 thread_index;} vlib_main_t;
typedef struct {u32 file_descriptor, polling_thread_index; uword private_data;} clib_file_t;
typedef int clib_error_t;
typedef struct {u8 data[2048], opaque2[56]; u32 ref_count,flags,template,trace_handle,total_length_not_including_first_buffer,buffer_pool_index; i16 current_data; u16 current_length;} vlib_buffer_t;
static vlib_buffer_t buffers[PRODUCT_ROOT_RECEIVE_TOTAL];
static struct {u32 buffer_template;} buffer_pool;
typedef struct {u32 buffer_index; product_platform_packet_facts_t platform; product_adapter_obligation_t obligation;} product_packet_graph_external_item_t;
typedef struct {u32 count; struct {u32 linux_ifindex,context;} entries[1]; u64 revision,event_elapsed_ns;} sakamoto_product_network_snapshot_t;
static sakamoto_product_network_snapshot_t network;
#define PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY PRODUCT_ROOT_COMPLETION_CAPACITY
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES PRODUCT_ROOT_COMPLETION_MAX_LANES
#define PRODUCT_ROOT_NFQUEUE_READ_BUDGET 64U
#define PRODUCT_ROOT_NFQUEUE_RCVBUF_REQUEST_LIMIT (1024U*1024U)
#define SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT 1
#define SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS 1
#define VLIB_BUFFER_NEXT_PRESENT 1
#define PREDICT_FALSE(x) (x)
#define clib_memset memset
#define clib_max(a,b) ((a)>(b)?(a):(b))
#define clib_min(a,b) ((a)<(b)?(a):(b))
#define clib_panic(x) assert(!(x))
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add(p,n,__ATOMIC_RELAXED)
#define clib_atomic_fetch_sub_relax(p,n) __atomic_fetch_sub(p,n,__ATOMIC_RELAXED)
#define clib_atomic_store_rel_n(p,n) __atomic_store_n(p,n,__ATOMIC_RELEASE)
#define uword_to_pointer(x,t) ((t)(x))
#define ASSERT assert
static clib_error_t error_value=1;
#define clib_error_return(...) (&error_value)
#define clib_error_return_unix(...) (&error_value)
static vlib_main_t vm={1};
static vlib_main_t *vlib_get_main(void){return &vm;}
static u32 vlib_get_thread_index(void){return vm.thread_index;}
static u32 vlib_get_worker_thread_index(u32 w){return w+1;}
static u32 product_packet_graph_trace_limit(void){return 0;}
static const sakamoto_product_network_snapshot_t *product_network_snapshot_current(void){return &network;}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *v,u32 i){assert(v==&vm && i<PRODUCT_ROOT_RECEIVE_TOTAL); return &buffers[i];}
#define vlib_get_buffer_pool(v,i) (&buffer_pool)
#define vlib_buffer_get_current(b) ((b)->data+(b)->current_data)
static u32 vlib_buffer_get_default_data_size(vlib_main_t *v){assert(v==&vm);return 2048;}
'''
types = ''.join(declaration(name, kind) for name, kind in (
    ('product_root_nfqueue_fault_mode_t', 'enum'),
    ('product_root_nfqueue_packet_t', 'struct'),
    ('product_root_nfqueue_pending_t', 'struct'),
    ('product_root_nfqueue_lane_t', 'struct'),
    ('product_root_nfqueue_main_t', 'struct'),
    ('product_root_input_batch_t', 'struct')))
deps = r'''
static product_root_nfqueue_main_t product_root_nfqueue_main;
static unsigned remaining, physical_reads, publications, queued, next_id;
static int receive_error=EAGAIN, controls, fail_get, fail_set, malformed_get;
static int socket_capacity=212992, socket_cap=262144;
static unsigned gets,sets;
static int fake_get(int fd,int level,int option,void *value,socklen_t *length){
 assert(fd==27 && level==SOL_SOCKET && option==SO_RCVBUF); gets++;
 if(fail_get && gets==(unsigned)fail_get){errno=EBADF;return -1;}
 *(int*)value=socket_capacity; *length=malformed_get?1:sizeof(int); return 0;
}
static int fake_set(int fd,int level,int option,const void *value,socklen_t length){
 assert(fd==27 && level==SOL_SOCKET && option==SO_RCVBUF && length==sizeof(int));sets++;
 if(fail_set){errno=EPERM;return -1;}
 int request=*(const int*)value;socket_capacity=2*clib_min(request,socket_cap);return 0;
}
#define getsockopt fake_get
#define setsockopt fake_set
static ssize_t fake_recv(int fd,void *data,size_t length,int flags){
 assert(fd==27 && flags==(MSG_DONTWAIT|MSG_TRUNC)); physical_reads++;
 if(!remaining){errno=receive_error;return -1;}remaining--;
 if(!data){assert(!length);return 64;}
 assert(length==2048);memset(data,0,64);
 struct nlmsghdr *nlh=data;nlh->nlmsg_len=64;
 nlh->nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET;nlh->nlmsg_seq=++next_id;
 struct nfgenmsg *nfgen=NLMSG_DATA(nlh);nfgen->res_id=htons(176);return 64;
}
#define recv fake_recv
static int product_root_nfqueue_transient_errno(int e){return e==EAGAIN||e==EWOULDBLOCK||e==EINTR||e==ENOBUFS;}
static void product_root_nfqueue_mark_lane_fault(product_root_nfqueue_main_t *nm,product_root_nfqueue_lane_t *lane,const char *cause,int e){assert(nm && cause && e);nm->fault_latched=1;(void)lane;}
static int product_root_nfqueue_consume_control(product_root_nfqueue_lane_t *lane,const u8 *data,u32 length){assert(lane && data && length==64);return controls;}
static int product_root_nfqueue_parse_packet(u8 *data,u32 length,product_root_nfqueue_packet_t *p){
 assert(length==64);memset(p,0,sizeof(*p));p->packet_id=((struct nlmsghdr*)data)->nlmsg_seq;
 p->identity_present=p->uid_present=1;p->uid=12632;p->hook=NF_INET_LOCAL_OUT;p->ip_family=4;p->protocol=IPPROTO_UDP;
 p->payload=data+32;p->payload_length=32;return 1;
}
static void product_root_nfqueue_accept_unadmitted(product_root_nfqueue_main_t *nm,product_root_nfqueue_lane_t *lane,u8 *data,u32 length,const char *cause){assert(nm && lane && data && length && cause);lane->ingress_accepts++;}
static void product_diagnostic_write_hex(FILE *stream,const u8 *data,u32 length){(void)stream;(void)data;(void)length;}
'''
helpers = ''.join(function(name) for name in (
    'product_root_nfqueue_pending_find', 'product_root_nfqueue_pending_deactivate',
    'product_root_nfqueue_reserve', 'product_root_nfqueue_return_receive'))
graph = r'''
static u32 product_packet_graph_submit_external_batch(vlib_main_t *v,const product_packet_graph_external_item_t *items,u32 count,u8 *accepted){
 assert(v==&vm && count && count<=PRODUCT_ROOT_INPUT_BATCH_SIZE);publications++;queued+=count;
 for(u32 i=0;i<count;i++){assert(items[i].obligation.kind==PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE);accepted[i]=1;}return count;
}
'''
production = ''.join(function(name) for name in (
    'product_root_input_batch_flush', 'product_root_nfqueue_read_dispatch',
    'product_root_nfqueue_read_ready', 'product_root_nfqueue_read_rcvbuf',
    'product_root_nfqueue_apply_io_tuning'))
suffix = r'''
static clib_file_t file;
static product_root_nfqueue_lane_t *lane;
static void reset(void){
 memset(&product_root_nfqueue_main,0,sizeof(product_root_nfqueue_main));
 product_root_nfqueue_main.generation=42;product_root_nfqueue_main.lane_count=1;
 lane=&product_root_nfqueue_main.lanes[0];lane->generation=42;lane->fd=27;lane->socket_ready=1;
 lane->queue_id=176;lane->read_budget=64;lane->rcvbuf_effective=212992;
 u32 indices[PRODUCT_ROOT_RECEIVE_TOTAL];for(u32 i=0;i<PRODUCT_ROOT_RECEIVE_TOTAL;i++){indices[i]=i;memset(&buffers[i],0,sizeof(buffers[i]));buffers[i].ref_count=1;}
 assert(product_root_receive_pool_init_capacity(&lane->receive_pool,42,indices,64));
 file=(clib_file_t){27,1,(uword)lane};vm.thread_index=1;
 remaining=physical_reads=publications=queued=next_id=gets=sets=0;
 controls=fail_get=fail_set=malformed_get=0;receive_error=EAGAIN;socket_capacity=212992;
}
static void drain(void){
 for(u32 i=0;i<PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY;i++)if(lane->pending[i].active){
  product_root_nfqueue_pending_t *p=&lane->pending[i];product_root_nfqueue_pending_deactivate(&product_root_nfqueue_main,lane,p);
  product_root_nfqueue_return_receive(lane,p->receive_slot,p->buffer_index);
 }
 assert(!lane->pending_count && !product_root_nfqueue_main.pending_count && !lane->receive_pool.outstanding);
 assert(lane->receive_pool.normal_free==64 && lane->receive_pool.reserve_free==8);
}
int main(void){
 reset();remaining=70;assert(!product_root_nfqueue_read_ready(&file));
 assert(physical_reads==64 && remaining==6 && lane->pending_count==64 && queued==64 && publications==2);
 assert(lane->read_budget_exits==1 && lane->read_callback_max==64 && lane->read_callback_datagrams==64);
 drain();assert(!product_root_nfqueue_read_ready(&file));assert(queued==70 && remaining==0 && physical_reads==71);
 assert(lane->recv_eagain==1 && lane->read_callbacks==2 && lane->read_budget_exits==1);drain();
 reset();assert(product_root_nfqueue_apply_io_tuning(lane,32,0));remaining=70;
 assert(!product_root_nfqueue_read_ready(&file));assert(remaining==38 && queued==32 && publications==1);drain();
 assert(!product_root_nfqueue_read_ready(&file));assert(remaining==6 && queued==64);drain();
 assert(!product_root_nfqueue_read_ready(&file));assert(!remaining && queued==70 && lane->read_budget_exits==2);drain();
 reset();assert(product_root_nfqueue_apply_io_tuning(lane,1,0));remaining=1;
 assert(!product_root_nfqueue_read_ready(&file));assert(queued==1 && publications==1 && physical_reads==1);drain();
 assert(!product_root_nfqueue_read_ready(&file));assert(lane->read_empty_callbacks==1 && lane->recv_eagain==1);drain();
 reset();controls=1;remaining=65;assert(!product_root_nfqueue_read_ready(&file));
 assert(remaining==1 && !queued && !lane->receive_pool.outstanding && lane->read_budget_exits==1);drain();
 reset();for(int i=0;i<3;i++){receive_error=i==0?EAGAIN:i==1?EINTR:ENOBUFS;assert(!product_root_nfqueue_read_ready(&file));drain();}
 assert(lane->recv_calls==3 && lane->recv_eagain==1 && lane->recv_eintr==1 && lane->recv_enobufs==1 && lane->receive_overruns==1);
 lane->receive_paused=1;assert(!product_root_nfqueue_read_ready(&file));assert(lane->read_callbacks==3 && physical_reads==3);
 reset();lane->listener_fault_after_submit=1;remaining=4;assert(product_root_nfqueue_read_ready(&file));
 assert(remaining==3 && queued==1 && lane->read_callback_datagrams==1 && !lane->read_budget_exits);drain();
 reset();assert(product_root_nfqueue_apply_io_tuning(lane,32,1048576));assert(socket_capacity==524288 && lane->rcvbuf_effective==524288 && lane->rcvbuf_requested==1048576 && lane->read_budget==32);
 assert(product_root_nfqueue_apply_io_tuning(lane,64,0));assert(sets==1 && lane->rcvbuf_requested==1048576 && lane->read_budget==64);
 unsigned prior_gets=gets;assert(!product_root_nfqueue_apply_io_tuning(lane,0,0));assert(!product_root_nfqueue_apply_io_tuning(lane,65,0));assert(!product_root_nfqueue_apply_io_tuning(lane,32,1048577));assert(gets==prior_gets && sets==1);
 reset();fail_set=1;assert(!product_root_nfqueue_apply_io_tuning(lane,32,65536));assert(lane->read_budget==64 && lane->rcvbuf_effective==212992 && !lane->rcvbuf_requested);
 reset();fail_get=1;assert(!product_root_nfqueue_apply_io_tuning(lane,32,65536));assert(!sets && lane->read_budget==64);
 reset();fail_get=2;assert(!product_root_nfqueue_apply_io_tuning(lane,32,65536));assert(sets==1 && !lane->rcvbuf_effective && lane->rcvbuf_requested==65536 && lane->read_budget==64);
 reset();malformed_get=1;assert(!product_root_nfqueue_apply_io_tuning(lane,32,0));assert(errno==EIO && lane->read_budget==64);
 reset();lane->draining=1;assert(!product_root_nfqueue_apply_io_tuning(lane,32,65536));assert(!gets && !sets);
 puts("Root IO: bounded 64/32/1 callbacks, partial flush, transient/paused/fault paths, pool conservation, capped socket tuning and failed-state visibility PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='product-root-io-') as temp:
    path = Path(temp)
    (path / 'test.c').write_text(prefix + types + deps + helpers + graph + production + suffix)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-g',
                    '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie',
                    '-I', str(PRODUCT), str(path / 'test.c'), '-o', str(path / 'test')], check=True)
    # The sandbox uses a ptrace runner. Bound failures and let a genuine SIGSEGV
    # terminate directly instead of recursing through ASan's signal handler.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:handle_segv=0')
    subprocess.run([str(path / 'test')], check=True, env=environment, timeout=15)
print('Product Root source SHA256:', hashlib.sha256(source.encode()).hexdigest())
