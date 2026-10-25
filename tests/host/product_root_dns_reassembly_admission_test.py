#!/usr/bin/env python3
"""Join actual reassembly resource completion to Root NFQUEUE disposition.

The fixture drives the production fragment resource emitter and production
Root completion preparation. VPP scheduling and the native netlink syscall are
controlled seams; their framing/outcome matrix is covered separately by
product_nfqueue_verdict_batch_test.py.
"""

from pathlib import Path
from product_root_dns_mark_fixture import mark_fixture
import os
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "src/product/vpp"
FRAG = (PRODUCT / "product_packet_reassembly_graph.inc").read_text()
ADAPTER = (PRODUCT / "product_root_nfqueue_adapter.c").read_text()


def function(source, name):
    match = re.search(r"(?m)^" + re.escape(name) + r"\s*\(", source)
    assert match, name
    start = source.rfind("\n", 0, match.start() - 1) + 1
    opening = source.index("{", match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


def declaration(source, name, kind="struct"):
    end = source.index("} " + name + ";") + len("} " + name + ";")
    return source[source.rfind("typedef " + kind, 0, end):end] + "\n"


prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/netfilter.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "product_fragment.h"
#include "product_packet_completion.h"
#include "product_dns.h"
#include "sakamoto_product_observation.h"
#include "product_root_dns_admission.h"
#include "product_root_receive_pool.h"
typedef uint8_t u8; typedef uint16_t u16; typedef int16_t i16;
typedef uint32_t u32; typedef uint64_t u64; typedef unsigned long uword;
typedef struct {u32 thread_index;} vlib_main_t;
typedef struct {u32 node_index;} vlib_node_runtime_t;
typedef struct {
  u32 flow_id_prefix[2],flow_id;
  u8 data[2048], opaque[40], opaque2[56];
  u32 ref_count, flags, next_buffer; i16 current_data; u16 current_length;
} vlib_buffer_t;
#define PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY PRODUCT_ROOT_COMPLETION_CAPACITY
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES PRODUCT_ROOT_COMPLETION_MAX_LANES
#define SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS 1
#define VLIB_BUFFER_NEXT_PRESENT 1
#define VLIB_BUFFER_TOTAL_LENGTH_VALID 2
#define PRODUCT_FRAGMENT_NONE ((u32)~0)
#define PRODUCT_FRAGMENT_TRACE (1<<0)
#define PRODUCT_FRAGMENT_PINNED (1<<1)
#define PRODUCT_FRAGMENT_PREPARED (1<<3)
#define PRODUCT_FRAGMENT_IPV6 (1<<4)
#define PRODUCT_FRAGMENT_VALID (1<<7)
#define PREDICT_FALSE(x) (x)
#define clib_memcpy_fast memcpy
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add((p),(n),__ATOMIC_RELAXED)
#define clib_atomic_fetch_sub_relax(p,n) __atomic_fetch_sub((p),(n),__ATOMIC_RELAXED)
#define ASSERT assert
#define clib_panic(message) do {fputs((message),stderr);assert(0);} while(0)
#define vlib_buffer_get_current(b) ((b)->data+(b)->current_data)
#define PRODUCT_EXECUTION_OWNER_UNKNOWN UINT32_MAX
typedef struct {
  product_adapter_obligation_t obligation;
  product_platform_packet_facts_t platform;
} product_buffer_platform_metadata_t;
typedef product_buffer_platform_metadata_t product_root_buffer_platform_metadata_t;
typedef struct {
  u64 generation; product_adapter_obligation_kind_t adapter_kind;
  u64 lifecycle_completion_frames, lifecycle_terminal_intents;
} product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main;
static vlib_buffer_t buffers[2];
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm,u32 index) {
  assert(vm && index<2);return &buffers[index];
}
static u32 vlib_get_worker_thread_index(u32 worker){return worker+1;}
static u32 vlib_get_worker_index(u32 thread){return thread-1;}
static u32 product_packet_graph_worker_count(void){return 1;}
static u32 product_packet_graph_trace_limit(void){return 0;}
typedef struct {u32 tun_io_worker;} product_runtime_topology_t;
#define PRODUCT_TOPOLOGY_VPN 1
static product_runtime_topology_t product_runtime_topology_current(int profile) {
  assert(profile==PRODUCT_TOPOLOGY_VPN);return (product_runtime_topology_t){.tun_io_worker=1};
}
static struct {u32 index;} product_packet_origin_completion_node={17};
static u32 emitted[2], emitted_count;
static void product_fragment_to_node(vlib_main_t *vm,u32 node,u32 index) {
  assert(vm && node==product_packet_origin_completion_node.index && emitted_count<2);
  emitted[emitted_count++]=index;
}
static void product_completion_return(vlib_main_t *vm,vlib_node_runtime_t *node,u32 index,
 const product_packet_completion_frame_t *completion) {
  (void)vm;(void)node;(void)index;(void)completion;assert(0);
}
enum {
  PRODUCT_REASSEMBLY_ERROR_NONE,
  PRODUCT_REASSEMBLY_ERROR_TIMEOUT,
  PRODUCT_REASSEMBLY_ERROR_DUPLICATE_FRAGMENT,
  PRODUCT_REASSEMBLY_ERROR_FRAGMENT_CONFLICT,
  PRODUCT_REASSEMBLY_ERROR_INTERNAL,
  PRODUCT_REASSEMBLY_ERROR_CAPACITY,
  PRODUCT_REASSEMBLY_ERROR_BUNDLE_CAPACITY,
  PRODUCT_REASSEMBLY_ERROR_RESOURCE,
  PRODUCT_REASSEMBLY_ERROR_HANDOFF,
  PRODUCT_REASSEMBLY_ERROR_STOP,
  PRODUCT_REASSEMBLY_ERROR_MALFORMED,
};
'''

fragment_types = declaration(FRAG, "product_fragment_envelope_t")
adapter_types = "".join(declaration(ADAPTER, name, kind) for name, kind in (
    ("product_root_nfqueue_fault_mode_t", "enum"),
    ("product_root_nfqueue_pending_t", "struct"),
    ("product_root_nfqueue_lane_t", "struct"),
    ("product_root_nfqueue_main_t", "struct"),
    ("product_root_verdict_work_t", "struct"),
))
outcomes_start = ADAPTER.index("enum\n{\n  PRODUCT_VERDICT_SUCCEEDED")
outcomes = ADAPTER[outcomes_start:ADAPTER.index("};", outcomes_start) + 2]

dependencies = r'''
static product_root_nfqueue_main_t product_root_nfqueue_main;
typedef struct {u64 resource_bypasses,error_groups;} product_fragment_counters_t;
static product_fragment_counters_t fragment_counters;
static product_fragment_counters_t *product_fragment_counters(vlib_main_t *vm) {
  assert(vm);return &fragment_counters;
}
static __thread int product_root_nfqueue_last_errno;
static __thread ssize_t product_root_nfqueue_last_send_result;
static u32 verdicts[2], verdict_count, returns[2];
static u32 admission_observations,basic_failures;
static void product_root_dns_adapter_admission_observe(vlib_main_t *v,u64 token,
 const product_platform_packet_facts_t *platform,
 const product_root_dns_admission_facts_t *facts,u8 coverage,u8 delivery) {
 assert(v && token && platform && facts && coverage==PRODUCT_DNS_CAPACITY);
 assert(delivery==PRODUCT_DNS_DELIVERY_RESOURCE_DROP);admission_observations++;
}
static void product_observation_basic(vlib_main_t *v,unsigned outcome,u32 bytes) {
 assert(v && outcome==2 && bytes);basic_failures++;
}
static int product_nfqueue_send_verdict(int fd,u32 queue,u32 packet,u32 verdict,int flags,int set_mark,u32 mark) {
  assert(!set_mark && !mark);
  assert(fd==27 && queue==176 && packet<2 && !flags && !verdicts[packet]);
  verdicts[packet]=verdict+1;verdict_count++;product_root_nfqueue_last_send_result=32;
  product_root_nfqueue_last_errno=0;return 1;
}
static void product_root_nfqueue_return_receive(product_root_nfqueue_lane_t *lane,
 u16 slot,u32 index) {assert(lane && slot==index && !returns[index]++);}
'''

fragment_production = "\n".join(function(FRAG, name) for name in (
    "product_fragment_load",
    "product_fragment_resource_error",
    "product_fragment_emit",
    "product_fragment_error_emit",
    "product_fragment_fail_bundle",
))
adapter_production = "\n".join(function(ADAPTER, name) for name in (
    "product_root_nfqueue_dns_query_candidate",
    "product_root_nfqueue_pending_find",
    "product_root_nfqueue_pending_deactivate",
    "product_root_nfqueue_record_verdict_attempt",
    "product_root_nfqueue_prepare_completion",
    "product_root_nfqueue_finish_completion",
    "product_root_nfqueue_complete_from_graph",
))

suffix = r'''
static vlib_main_t vm={.thread_index=1};
static vlib_node_runtime_t node;
static void packet(u32 index,int first,int response,int active,int family) {
  vlib_buffer_t *buffer=&buffers[index];memset(buffer,0,sizeof(*buffer));
  buffer->ref_count=1;
  if(family==4) {
    buffer->data[0]=0x45;buffer->data[2]=0;buffer->data[3]=48;
    buffer->data[6]=first?0x20:0;buffer->data[7]=first?0:1;buffer->data[8]=64;
    buffer->data[9]=IPPROTO_UDP;buffer->data[20]=0x9c;buffer->data[21]=0x40;
    buffer->data[22]=0;buffer->data[23]=53;buffer->data[24]=0;buffer->data[25]=28;
    buffer->data[28]=0x12;buffer->data[29]=0x34;buffer->data[30]=response?0x81:0x01;
    buffer->current_length=48;
  } else {
    buffer->data[0]=0x60;buffer->data[5]=28;buffer->data[6]=44;buffer->data[7]=64;
    buffer->data[40]=IPPROTO_UDP;buffer->data[43]=first?1:8;
    buffer->data[48]=0x9c;buffer->data[49]=0x40;buffer->data[50]=0;buffer->data[51]=53;
    buffer->data[52]=0;buffer->data[53]=20;buffer->data[56]=0x12;buffer->data[57]=0x34;
    buffer->data[58]=response?0x81:0x01;buffer->current_length=68;
  }
  product_fragment_envelope_t envelope={
    .obligation={.token=100+index,.queue_generation=42,.packet_id=index,
      .origin_lane=0,.origin_worker=0,.kind=PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE},
    .platform={.direction=PRODUCT_PACKET_DIRECTION_OUTPUT,
      .provenance=PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE,
      .reserved=active?PRODUCT_PLATFORM_ADMISSION_DNS_REPLACEMENT_ACTIVE:0},
    .flags=PRODUCT_FRAGMENT_VALID,
  };
  memcpy(buffer->opaque2,&envelope,sizeof(envelope));
}
static void reset(int response,int active,int family) {
  memset(&product_root_nfqueue_main,0,sizeof(product_root_nfqueue_main));
  memset(&fragment_counters,0,sizeof(fragment_counters));
  memset(verdicts,0,sizeof(verdicts));memset(returns,0,sizeof(returns));
  emitted_count=verdict_count=0;
  admission_observations=basic_failures=0;
  product_packet_graph_main=(product_packet_graph_main_t){
    .generation=42,.adapter_kind=PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE};
  product_root_nfqueue_main.generation=42;product_root_nfqueue_main.lane_count=1;
  product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
  lane->generation=42;lane->worker_index=0;lane->fd=27;lane->queue_id=176;lane->socket_ready=1;
  for(u32 i=0;i<2;i++) {
    packet(i,i==0,response,active,family);
    product_root_nfqueue_pending_t *pending=&lane->pending[i];
    product_fragment_envelope_t envelope;memcpy(&envelope,buffers[i].opaque2,sizeof(envelope));
    pending->completion.obligation=envelope.obligation;pending->buffer_index=i;
    pending->receive_slot=i;pending->active=1;lane->pending_active_slots|=UINT64_C(1)<<i;
    lane->pending_count++;product_root_nfqueue_main.pending_count++;
  }
}
static void run(int response,int active,int family,u32 first_verdict) {
  reset(response,active,family);
  product_fragment_piece_t pieces[2]={{.buffer_index=0},{.buffer_index=1}};
  product_fragment_bundle_t bundle={.pieces=pieces,.count=2,.first=0};
  product_fragment_fail_bundle(&vm,&node,&bundle,PRODUCT_REASSEMBLY_ERROR_RESOURCE);
  assert(emitted_count==2 && fragment_counters.resource_bypasses==2);
  for(u32 i=0;i<2;i++) {
    product_packet_completion_frame_t completion;
    memcpy(&completion,buffers[emitted[i]].opaque2,sizeof(completion));
    assert(completion.terminal_intent==PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS);
    assert(completion.processing_bypass_reason==PRODUCT_PACKET_BYPASS_REASSEMBLY_RESOURCE);
    assert(product_root_nfqueue_complete_from_graph(&vm,emitted[i],&completion));
  }
  assert(verdict_count==2 && verdicts[0]==first_verdict+1 && verdicts[1]==NF_ACCEPT+1);
  assert(returns[0]==1 && returns[1]==1 && !product_root_nfqueue_main.pending_count);
  assert(product_root_nfqueue_main.lanes[0].ingress_dns_drop_attempts==(first_verdict==NF_DROP));
  assert(admission_observations==(first_verdict==NF_DROP));
  assert(basic_failures==(first_verdict==NF_DROP));
}
int main(void) {
  run(0,0,4,NF_ACCEPT);
  run(0,1,4,NF_DROP);
  run(1,1,4,NF_ACCEPT);
  run(0,1,6,NF_DROP);
  puts("Root DNS reassembly admission: actual resource completion drops active query first fragment, preserves off/QR response and settles every original PASS");
}
'''

with tempfile.TemporaryDirectory(prefix="product-root-dns-reassembly-") as temp:
    path = Path(temp)
    source = path / "test.c"
    binary = path / "test"
    source.write_text(prefix + mark_fixture() + fragment_types + adapter_types + outcomes + dependencies
                      + fragment_production + adapter_production + suffix)
    subprocess.run([
        os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=undefined", "-fno-sanitize-recover=all",
        "-I", str(PRODUCT), "-I", str(ROOT / "src/product/include"),
        str(source), "-o", str(binary),
    ], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
