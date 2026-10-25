#!/usr/bin/env python3
"""Actual TUN return acceptance/completion with native scheduling dependencies.

Credit/stamp and write helpers are production headers. Graph scheduling is a
controlled seam here; product_external_batch_test separately executes the actual
Product graph helpers and pinned VPP native enqueue inline when supplied.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "src/product/vpp"
source = (PRODUCT / "product_vpn_tun_adapter.c").read_text()
adapter_header = (PRODUCT / "product_root_dns_adapter.h").read_text()


def adapter_declaration(name):
    match = re.search(r"(?m)^(?:int|void)\s+" + re.escape(name) + r"\([^;]+;", adapter_header, re.S)
    assert match, name
    return match.group()


def function(name):
    match = re.search(r"(?m)^.*\b" + re.escape(name) + r"\s*\(", source)
    assert match, name
    opening = source.index("{", match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[match.start():end] + "\n"


owner_begin = source.rfind("typedef struct", 0, source.index("product_vpn_return_credit_t credit;"))
owner_end = source.index("static u32 active_owner_count", owner_begin)
tun_begin = source.index("static struct {", owner_end)
tun_end = source.index("extern vlib_node_registration_t", tun_begin)
prefix = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>
#include "product_packet.h"
#include "product_packet_completion.h"
#include "product_vpn_flow_stack.h"
#include "product_vpn_return_credit.h"
#include "product_vpn_return_stamp.h"
#include "product_vpn_tun_write.h"
#include "sakamoto_product_observation.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef double f64;
typedef struct {u32 thread_index;} vlib_main_t;
typedef struct {u32 node_index;} vlib_node_runtime_t;
typedef struct {u8 opaque[40],opaque2[56],data[10240];u16 current_length;} vlib_buffer_t;
#define TUN_PENDING 128
#define TUN_CONTROL_SLOTS 4
#define PRODUCT_VPN_RETURN_WORKERS 3
#define PRODUCT_VPN_RETURN_CAPACITY 128
#define CLIB_CACHE_LINE_BYTES 64
#define clib_memset memset
#define clib_memcpy_fast memcpy
#if TEST_TCP_BATCH
#define SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT 1
#endif
typedef struct {u64 token;u32 buffer;u8 active;} tun_pending_t;
typedef struct {u32 file;int fd;} tun_control_t;
"""
prefix += "\n".join(adapter_declaration(name) for name in (
    "product_root_dns_vpn_return_admit", "product_root_dns_vpn_reply_complete",
    "product_root_dns_vpn_reply_freed")) + "\n"
deps = r"""
static u32 owners=2;
static u32 active_owner_count(void){return owners;}
static u32 vlib_get_worker_index(u32 thread){assert(thread);return thread-1;}
static u32 vlib_get_worker_thread_index(u32 worker){return worker+1;}
static u32 vlib_get_thread_index(void){return 1;}
static u64 trace_monotonic_ns(void){return 0;}
static u64 product_packet_graph_trace_limit(void){return 0;}
static vlib_buffer_t buffers[64];
static u8 live[64],freed[64];
static unsigned allocated,alloc_fail,next_calls,fallback_calls,scheduled,callback_active,graph_runs;
static unsigned graph_reject;
static product_adapter_obligation_t obligations[64];
static product_platform_packet_facts_t saved_platform[64];
static u32 publication_order[64];
static int vlib_buffer_alloc(vlib_main_t *vm,u32 *index,u32 count){
 assert(vm && vm->thread_index<=owners && count==1);
 if(alloc_fail)return 0;
 assert(allocated<64);*index=allocated++;live[*index]=1;return 1;
}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm,u32 index){assert(vm && index<allocated && live[index]);return buffers+index;}
static void vlib_buffer_reset(vlib_buffer_t *buffer){buffer->current_length=0;}
static u8 *vlib_buffer_get_current(vlib_buffer_t *buffer){return buffer->data;}
static u32 vlib_buffer_get_default_data_size(vlib_main_t *vm){assert(vm);return sizeof(buffers[0].data);}
static void vlib_buffer_free(vlib_main_t *vm,u32 *index,u32 count){
 assert(vm && count==1 && *index<allocated && live[*index] && !freed[*index]);live[*index]=0;freed[*index]++;
}
static void tun_resume_reads(vlib_main_t *vm){assert(vm->thread_index==owners+1);}
static int schedule_return(vlib_main_t *vm,u32 index,const product_platform_packet_facts_t *platform,
 const product_adapter_obligation_t *obligation){
 assert(callback_active && !graph_runs && vm->thread_index<=owners && live[index]);
 assert(obligation->origin_worker==owners && obligation->packet_id==vm->thread_index);
 assert(obligation->queue_generation==tun.generation);
 u64 incarnation=0;
 assert(product_vpn_return_stamp_lookup(&returns[vm->thread_index-1].stamps,tun.generation,obligation->token,&incarnation));
 assert(incarnation==700+scheduled);
 assert(product_vpn_return_credit_used(&returns[vm->thread_index-1].credit));
 if(graph_reject)return 0;
 obligations[index]=*obligation;saved_platform[index]=*platform;publication_order[scheduled++]=index;
 return 1;
}
int product_packet_graph_submit_vpn_return_next(vlib_main_t *vm,vlib_node_runtime_t *node,u32 next,
 u32 index,const product_platform_packet_facts_t *platform,const product_adapter_obligation_t *obligation){
 assert(node && node->node_index==19 && next==2);next_calls++;return schedule_return(vm,index,platform,obligation);
}
static int product_packet_graph_submit_external(vlib_main_t *vm,u32 index,
 const product_platform_packet_facts_t *platform,const product_adapter_obligation_t *obligation){
 fallback_calls++;return schedule_return(vm,index,platform,obligation);
}
void product_root_dns_vpn_return_admit(vlib_main_t *vm,u32 index,
 const product_adapter_obligation_t *obligation,const product_platform_packet_facts_t *platform){
 assert(vm && index<allocated && obligation && platform);
}
void product_root_dns_vpn_reply_complete(vlib_main_t *vm,u32 index,
 const product_packet_completion_frame_t *frame,u8 delivery){
 assert(vm && index<allocated && frame && delivery<=PRODUCT_DNS_DELIVERY_OUTCOME_UNKNOWN);
}
void product_root_dns_vpn_reply_freed(vlib_main_t *vm,u32 index,
 const product_packet_completion_frame_t *frame){
 assert(vm && index<allocated && frame);
}
"""
production = "\n".join(function(name) for name in (
    "return_sequence_limit", "return_token_owner", "return_token_make",
    "product_vpn_tun_submit_return", "product_vpn_tun_complete_from_graph",
    "product_vpn_tun_return_freed"))
suffix = r"""
static vlib_main_t owner_vm={1};
static vlib_node_runtime_t node={19};
static void reset(void){
 memset(&tun,0,sizeof(tun));memset(returns,0,sizeof(returns));memset(buffers,0,sizeof(buffers));
 memset(live,0,sizeof(live));memset(freed,0,sizeof(freed));
 allocated=alloc_fail=next_calls=fallback_calls=scheduled=callback_active=graph_runs=graph_reject=0;
 tun.generation=7041;tun.origin_worker=owners;tun.tun_fd=19;
 for(unsigned i=0;i<owners;i++){
  assert(!product_vpn_return_credit_init(&returns[i].credit,tun.generation,128));
  returns[i].stamps.generation=tun.generation;
 }
}
static product_vpn_flow_stack_output_result_t output(vlib_node_runtime_t *source_node){
 const u8 a[]={0x45,1,2},b[]={3,4,5,6,7};
 product_vpn_flow_stack_span_t spans[]={{a,sizeof(a)},{b,sizeof(b)}};
 product_platform_packet_facts_t platform={.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN,
   .direction=PRODUCT_PACKET_DIRECTION_INPUT,.uid=10456,.network_context_id=4};
 callback_active=1;
 product_vpn_flow_stack_output_result_t result=product_vpn_tun_submit_return(&owner_vm,source_node,2,
   spans,2,sizeof(a)+sizeof(b),&platform,tun.generation,10,11,700+scheduled,701);
 callback_active=0;assert(!graph_runs);
 if(result==PRODUCT_VPN_FLOW_STACK_OUTPUT_ACCEPTED){
  u32 index=publication_order[scheduled-1];
  const u8 expected[]={0x45,1,2,3,4,5,6,7};
  assert(buffers[index].current_length==8 && !memcmp(buffers[index].data,expected,8));
  assert(saved_platform[index].uid==10456 && saved_platform[index].network_context_id==4);
 }
 return result;
}
static void rejection_paths(void){
 reset();graph_reject=1;
 assert(output(&node)==PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED);
 assert(next_calls==1 && !fallback_calls && !scheduled && allocated==1 && freed[0]==1);
 assert(!product_vpn_return_credit_used(&returns[0].credit) && product_vpn_return_stamp_empty(&returns[0].stamps));
 reset();returns[0].fault_reject_at=1;
 assert(output(&node)==PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED);
 assert(!next_calls && !fallback_calls && allocated==1 && freed[0]==1);
 assert(!product_vpn_return_credit_used(&returns[0].credit) && product_vpn_return_stamp_empty(&returns[0].stamps));
 reset();alloc_fail=1;
 assert(output(&node)==PRODUCT_VPN_FLOW_STACK_OUTPUT_NO_MEMORY);
 assert(!allocated && !next_calls && !fallback_calls && !product_vpn_return_credit_used(&returns[0].credit));
 assert(product_vpn_return_stamp_empty(&returns[0].stamps));
 reset();returns[0].credit.capacity=1;
 assert(output(&node)==PRODUCT_VPN_FLOW_STACK_OUTPUT_ACCEPTED);
 assert(output(&node)==PRODUCT_VPN_FLOW_STACK_OUTPUT_NO_MEMORY);
 assert(allocated==1 && next_calls==1 && scheduled==1 && returns[0].no_credit==1);
 vlib_main_t io_vm={owners+1};u32 index=publication_order[0];
 product_packet_completion_frame_t completion={.obligation=obligations[index],.producer_thread=1,
  .flags=PRODUCT_COMPLETION_FLOW_STACK_RETURN,.terminal_intent=PRODUCT_PACKET_INTENT_DROP_RUNTIME,
  .runtime_drop_reason=PRODUCT_PACKET_DROP_POLICY_L4};
 assert(product_vpn_tun_complete_from_graph(&io_vm,index,&completion));
 vlib_buffer_free(&io_vm,&index,1);product_vpn_tun_return_freed(&io_vm,index,&completion);
 assert(!product_vpn_return_credit_used(&returns[0].credit) && product_vpn_return_stamp_empty(&returns[0].stamps));
 reset();tun.graph_quiesced=1;
 assert(output(&node)==PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED && !allocated);
 reset();owner_vm.thread_index=owners+1;
 assert(output(&node)==PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED && !allocated);owner_vm.thread_index=1;
}
static void mixed_completion(u32 producing_owner){
 owner_vm.thread_index=producing_owner+1;reset();int fd[2];assert(!pipe2(fd,O_NONBLOCK|O_CLOEXEC));tun.tun_fd=fd[1];
 for(unsigned i=0;i<6;i++)assert(output(i==5?0:&node)==PRODUCT_VPN_FLOW_STACK_OUTPUT_ACCEPTED);
 assert(next_calls==5 && fallback_calls==1 && scheduled==6 && !graph_runs);
 assert(product_vpn_return_credit_used(&returns[producing_owner].credit)==6);
 assert(returns[producing_owner].copy_calls==6 && returns[producing_owner].copy_bytes==48);
 tun.fault_write_short_at=2;tun.fault_write_eagain_at=3;
 vlib_main_t io_vm={owners+1};
 for(unsigned i=0;i<6;i++){
  u32 index=publication_order[i];assert(index==i && !callback_active);graph_runs++;
  product_packet_completion_frame_t completion={.obligation=obligations[index],.producer_thread=producing_owner+1,
    .flags=PRODUCT_COMPLETION_FLOW_STACK_RETURN,.terminal_intent=PRODUCT_PACKET_INTENT_PASS_ADAPTER};
  if(i==0){completion.terminal_intent=PRODUCT_PACKET_INTENT_DROP_RUNTIME;completion.runtime_drop_reason=PRODUCT_PACKET_DROP_POLICY_L4;}
  if(i==1){completion.terminal_intent=PRODUCT_PACKET_INTENT_DROP_RUNTIME;completion.runtime_drop_reason=PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION;}
  assert(product_vpn_tun_complete_from_graph(&io_vm,index,&completion));
  assert(live[index] && !freed[index]);
  assert(product_vpn_return_credit_used(&returns[producing_owner].credit)==6-i);
  vlib_buffer_free(&io_vm,&index,1);
  product_vpn_tun_return_freed(&io_vm,index,&completion);
  assert(!live[index] && freed[index]==1 && product_vpn_return_credit_used(&returns[producing_owner].credit)==5-i);
 }
 assert(tun.completed==6 && tun.policy_drops==1 && tun.runtime_drops==1);
 assert(tun.tun_write_attempts==4 && tun.tun_writes==2 && tun.tun_write_failed==2);
 assert(tun.tun_write_short==1 && tun.tun_write_eagain==1 && !tun.tun_write_error);
 assert(product_vpn_return_stamp_empty(&returns[producing_owner].stamps));
 u8 bytes[32];assert(read(fd[0],bytes,sizeof(bytes))==16);close(fd[0]);close(fd[1]);
}
int main(void){
 for(owners=1;owners<=3;owners+=2){
  owner_vm.thread_index=1;rejection_paths();
  for(u32 owner=0;owner<owners;owner++)mixed_completion(owner);
 }
 printf("PASS actual TUN return TCP=%u: N1/N3 all owners, native-next selection and NULL fallback, callback-before-graph, single multi-span packet copy, reject/free/stamp/credit conservation, mixed policy/runtime/write/short/EAGAIN completion\n",TEST_TCP_BATCH);
 return 0;
}
"""
with tempfile.TemporaryDirectory(prefix="sakamoto-vpn-return-") as temporary:
    directory = Path(temporary)
    c_source, executable = directory / "return.c", directory / "return"
    c_source.write_text(prefix + source[owner_begin:owner_end] + source[tun_begin:tun_end]
                        + deps + production + suffix)
    for mode in (0, 1):
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        f"-DTEST_TCP_BATCH={mode}", "-I", str(PRODUCT),
                        "-I", str(ROOT / "src/product/include"), str(c_source),
                        "-o", str(executable)], check=True, timeout=30)
        subprocess.run([str(executable)], check=True, timeout=5)
print("tun_source_sha256=" + hashlib.sha256(source.encode()).hexdigest())
