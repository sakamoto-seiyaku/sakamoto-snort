#!/usr/bin/env python3
"""Actual default Root socket/receive startup; no diagnostic tuning commands."""
import os
from pathlib import Path
import resource
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
base = runpy.run_path(str(ROOT / 'tests/host/product_root_io_test.py'))
prefix = base['prefix'].replace('typedef int clib_error_t;\n', '').replace(
    'typedef struct {u32 file_descriptor, polling_thread_index; uword private_data;} clib_file_t;',
    'typedef struct clib_file_s clib_file_t; typedef int clib_error_t;\n'
    'struct clib_file_s {u32 file_descriptor,polling_thread_index;uword private_data;'
    'clib_error_t *(*read_function)(clib_file_t*);clib_error_t *(*error_function)(clib_file_t*);char *description;};')
seams = r'''
static int product_root_nfqueue_last_errno, closed, configured, file_added, file_main;
static int fake_socket(int domain,int type,int protocol){
 assert(domain==AF_NETLINK && type==(SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK) && protocol==NETLINK_NETFILTER);return 27;
}
static int fake_bind(int fd,const struct sockaddr *address,socklen_t size){
 assert(fd==27 && size==sizeof(struct sockaddr_nl) && address->sa_family==AF_NETLINK);return 0;
}
static int fake_close(int fd){assert(fd==27);closed++;return 0;}
#define socket fake_socket
#define bind fake_bind
#define close fake_close
static void product_root_nfqueue_warn_errno(const char *s){assert(s);}
static int product_nfqueue_configure(int fd,u32 queue,u32 family,u32 maxlen){
 assert(fd==27 && queue==176 && family==4 && maxlen==4096);configured++;return 1;
}
static clib_error_t *product_root_nfqueue_error_ready(clib_file_t *file){(void)file;return 0;}
#define format(...) ((char *)"default-root-lane")
#define pointer_to_uword(p) ((uword)(p))
#define PRODUCT_ROOT_NFQUEUE_FLAGS (NFQA_CFG_F_UID_GID|NFQA_CFG_F_FAIL_OPEN)
static u32 clib_file_add(int *main,clib_file_t *file){
 assert(main==&file_main && file->file_descriptor==27 && file->polling_thread_index==1);
 assert(file->read_function==product_root_nfqueue_read_ready && file->error_function==product_root_nfqueue_error_ready);
 assert(file->description);file_added++;return 17;
}
'''
production = ''.join(base['function'](name) for name in (
    'product_root_nfqueue_reset_lane', 'product_root_nfqueue_open_lane'))
main = r'''
static void startup(void){
 memset(&product_root_nfqueue_main,0,sizeof(product_root_nfqueue_main));
 product_root_nfqueue_main.generation=42;product_root_nfqueue_main.lane_count=1;
 product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
 product_root_nfqueue_reset_lane(lane,0,176);
 lane->generation=42;lane->queue_maxlen=PRODUCT_ROOT_DEFAULT_QUEUE_MAXLEN;
 u32 indices[PRODUCT_ROOT_RECEIVE_TOTAL];
 for(u32 i=0;i<PRODUCT_ROOT_RECEIVE_TOTAL;i++){indices[i]=i;memset(&buffers[i],0,sizeof(buffers[i]));buffers[i].ref_count=1;}
 assert(product_root_receive_pool_init(&lane->receive_pool,42,indices));
 assert(lane->receive_pool.normal_capacity==128 && lane->receive_pool.normal_free==128 && lane->receive_pool.reserve_free==8);
 assert(lane->read_budget==16);
 gets=sets=closed=configured=file_added=physical_reads=publications=queued=next_id=0;
 controls=fail_get=fail_set=malformed_get=0;receive_error=EAGAIN;socket_capacity=212992;socket_cap=8*1024*1024;
}
int main(void){
 for(unsigned lifetime=0;lifetime<2;lifetime++){
  startup();product_root_nfqueue_main_t *nm=&product_root_nfqueue_main;
  product_root_nfqueue_lane_t *lane=&nm->lanes[0];
  assert(product_root_nfqueue_open_lane(nm,lane));
  assert(lane->read_budget==16 && lane->rcvbuf_requested==1048576 && lane->rcvbuf_effective==2097152);
  assert(lane->listener_ready && lane->socket_ready && nm->ready_lane_mask==1 && file_added==1 && configured==1);
  clib_file_t file={.file_descriptor=27,.polling_thread_index=1,.private_data=(uword)lane};
  remaining=20;assert(!product_root_nfqueue_read_ready(&file));
  assert(physical_reads==16 && remaining==4 && queued==16 && lane->pending_count==16);
  for(u32 i=0;i<2*PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY;i++)if(lane->pending[i].active){
   product_root_nfqueue_pending_t *p=&lane->pending[i];
   product_root_nfqueue_pending_deactivate(nm,lane,p);product_root_nfqueue_return_receive(lane,p->receive_slot,p->buffer_index);
  }
  assert(!lane->pending_count && !lane->receive_pool.outstanding && lane->receive_pool.normal_free==128);
 }
 startup();fail_set=1;
 assert(!product_root_nfqueue_open_lane(&product_root_nfqueue_main,&product_root_nfqueue_main.lanes[0]));
 assert(closed==1 && !configured && !file_added && !product_root_nfqueue_main.ready_lane_mask);
 assert(!product_root_nfqueue_main.lanes[0].socket_ready && product_root_nfqueue_main.lanes[0].fd==-1);
 startup();fail_get=2;
 assert(!product_root_nfqueue_open_lane(&product_root_nfqueue_main,&product_root_nfqueue_main.lanes[0]));
 assert(sets==1 && closed==1 && !configured && !file_added && !product_root_nfqueue_main.ready_lane_mask);
 assert(!product_root_nfqueue_main.lanes[0].rcvbuf_effective);
 startup();socket_cap=262144;
 assert(product_root_nfqueue_open_lane(&product_root_nfqueue_main,&product_root_nfqueue_main.lanes[0]));
 assert(product_root_nfqueue_main.lanes[0].rcvbuf_requested==1048576 && product_root_nfqueue_main.lanes[0].rcvbuf_effective==524288);
 puts("PASS actual default startup/restart:128+8 loans,16-read callbacks,1MiB request/actual readback,pre-listener failures and capped capacity visibility");
}
'''
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='root-defaults-') as folder:
    path = Path(folder)
    fixture = path / 'test.c'
    fixture.write_text(prefix + base['types'] + base['deps'] + base['helpers'] +
                       base['graph'] + base['production'] + seams + production + main)
    subprocess.run([os.environ.get('CC','cc'),'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-Wno-unused-parameter','-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie',
                    '-I',str(ROOT/'src/product/vpp'),str(fixture),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True,timeout=15,
                   env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0:handle_segv=0'})

# Exercise the real shared startup method, not only its selector, so Root
# defaults cannot leak into VPN or survive a diagnostic change on restart.
import re
graph_source = (ROOT/'src/product/vpp/product_packet_graph.c').read_text()
def graph_function(name):
    match=re.search(r'(?m)^'+re.escape(name)+r'\s*\(',graph_source)
    begin=graph_source.rfind('\n',0,match.start()-1)+1
    opening=graph_source.index('{',match.end());depth=1;end=opening+1
    while depth:
        depth+=(graph_source[end]=='{')-(graph_source[end]=='}');end+=1
    return graph_source[begin:end]+'\n'
graph_prefix=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "product_packet.h"
#include "product_root_defaults.h"
typedef uint32_t u32;typedef uint64_t u64;
typedef struct {u32 thread_index;} vlib_main_t;
#define PRODUCT_GRAPH_HANDOFF_CREDITS 32
#define SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT 1
#define clib_memset memset
#define ASSERT assert
#define clib_atomic_load_acq_n(p) (*(p))
#define clib_atomic_store_rel_n(p,v) (*(p)=(v))
typedef struct {
 vlib_main_t *vlib_main;product_adapter_obligation_kind_t adapter_kind;
 u64 generation,lifecycle_obligations,lifecycle_buffers,lifecycle_handoffs,lifecycle_completion_frames;
 u32 enabled,accepting,trace_packets,trace_limit,policy_hold_next_us[2],misroute_next;
 u64 primary_published,primary_received,primary_rejected,owner_delivery_checks,owner_delivery_failures;
 u64 completion_returns,completion_deferred,completion_retry_attempts,completion_pending_returns;
 u32 l4_policy_bank_readers[2],l4_policy_active_bank,policy_publish_sequence;
 u64 l4_policy_banks[2],l4_policy_view_active,lifecycle_terminal_intents,lifecycle_settlements,lifecycle_returns;
 u32 configured_credits;
} product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main;
static u64 product_packet_batch_stats[3];
static unsigned calls,flow_end_debt,vpn_mode,policy_ready=1;
static unsigned product_flow_end_buffer_debt(void){return flow_end_debt;}
static void product_fragment_start(vlib_main_t *vm){assert(vm);calls++;}
static unsigned product_vpn_tun_product_mode(void){return vpn_mode;}
static void product_capacity_configure_empty(product_packet_graph_main_t *g,u32 credits,u32 primary,u32 completion){
 assert(g && primary==64 && completion==128);g->configured_credits=credits;calls++;
}
static int product_packet_graph_flow_pools_reset(product_packet_graph_main_t *g){assert(g);calls++;return 1;}
static void product_policy_domains_clear(product_packet_graph_main_t *g){assert(g);calls++;}
static int product_core_policy_start(u64 gen){assert(gen);calls++;return policy_ready;}
'''
graph_code=graph_prefix+graph_function('product_packet_graph_default_handoff_credits')+graph_function('product_packet_graph_start_external')+r'''
int main(void){
 vlib_main_t vm={0};product_packet_graph_main_t *g=&product_packet_graph_main;
 assert(product_packet_graph_start_external(&vm,42,PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE));
 assert(g->configured_credits==48 && g->enabled && g->accepting && g->adapter_kind==PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE);
 unsigned before=calls;
 assert(!product_packet_graph_start_external(&vm,43,PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE) && calls==before);
 g->enabled=g->accepting=0;g->configured_credits=1;
 assert(product_packet_graph_start_external(&vm,43,PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE));
 assert(g->configured_credits==48 && g->generation==43);
 g->enabled=g->accepting=0;vpn_mode=1;
 assert(product_packet_graph_start_external(&vm,44,PRODUCT_ADAPTER_OBLIGATION_VPN_TUN));
 assert(g->configured_credits==32 && !g->trace_limit && g->adapter_kind==PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
 g->enabled=g->accepting=0;before=calls;
 assert(!product_packet_graph_start_external(&vm,45,PRODUCT_ADAPTER_OBLIGATION_NONE) && calls==before);
 g->lifecycle_buffers=1;
 assert(!product_packet_graph_start_external(&vm,45,PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE) && calls==before);
 g->lifecycle_buffers=0;policy_ready=0;
 assert(!product_packet_graph_start_external(&vm,45,PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE) && !g->enabled && !g->accepting);
 puts("PASS actual startup:Root48/VPN32 credits,restart resets diagnostics,live debt/invalid adapter/publication failure never report ready");
}
'''
with tempfile.TemporaryDirectory(prefix='graph-defaults-') as folder:
    path=Path(folder);(path/'test.c').write_text(graph_code)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-I',str(ROOT/'src/product/vpp'),str(path/'test.c'),'-o',str(path/'test')],check=True)
    subprocess.run([str(path/'test')],check=True,timeout=15)
