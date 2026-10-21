#!/usr/bin/env python3
"""Exercise the actual NFQUEUE verdict preparation, sender and settlement.

Compile the same origin-window helpers for scalar, sendmmsg and packed sendto.
The socket dependency decodes the intended wire messages, independently of the
injected native result. It proves datagram framing and exactly one identity
settlement/loan return; a full send result does not prove kernel callbacks ran.
sendmmsg failures preserve its successful prefix and uncertain boundary. Packed
failures apply to the whole datagram and must never trigger a verdict retry.
"""
from pathlib import Path
import hashlib
import os
import re
import resource
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "src/product/vpp"
source = (PRODUCT / "product_root_nfqueue_adapter.c").read_text()
mode_config = re.search(
    r"(?m)^#ifndef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE\n.*?^#endif",
    source, re.DOTALL).group(0) + "\n"


def function(name):
    match = re.search(r"(?m)^" + re.escape(name) + r"\s*\(", source)
    if not match:
        raise RuntimeError("Missing production function: " + name)
    start = source.rfind("\n", 0, match.start() - 1) + 1
    opening = source.index("{", match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


def declaration(name, kind="struct"):
    end = source.index("} " + name + ";") + len("} " + name + ";")
    start = source.rfind("typedef " + kind, 0, end)
    return source[start:end] + "\n"


prefix = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "product_packet_completion.h"
#include "product_packet_batch.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
typedef uint64_t u64; typedef unsigned long uword;
typedef struct { u32 thread_index; } vlib_main_t;
#include "product_root_receive_pool.h"
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES PRODUCT_ROOT_COMPLETION_MAX_LANES
#define PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY PRODUCT_ROOT_COMPLETION_CAPACITY
#define SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS 1
#define clib_memset memset
#define clib_memcpy_fast memcpy
#define clib_max(a,b) ((a) > (b) ? (a) : (b))
#define clib_min(a,b) ((a) < (b) ? (a) : (b))
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add(p,n,__ATOMIC_RELAXED)
#define clib_atomic_fetch_sub_relax(p,n) __atomic_fetch_sub(p,n,__ATOMIC_RELAXED)
#define ASSERT assert
#define PRODUCT_EXECUTION_OWNER_UNKNOWN UINT32_MAX
static u32 vlib_get_worker_thread_index(u32 w) { return w+1; }
static u32 vlib_get_worker_index(u32 t) { return t-1; }
static u32 product_packet_graph_worker_count(void) { return 2; }
static u32 product_packet_graph_trace_limit(void) { return 0; }
'''

types = "".join(declaration(name, kind) for name, kind in (
    ("product_root_nfqueue_fault_mode_t", "enum"),
    ("product_root_nfqueue_pending_t", "struct"),
    ("product_root_nfqueue_lane_t", "struct"),
    ("product_root_nfqueue_main_t", "struct"),
    ("product_nfqueue_verdict_request_t", "union"),
    ("product_root_verdict_work_t", "struct")))

outcomes = source[source.index("enum\n{\n  PRODUCT_VERDICT_SUCCEEDED"):source.index("};", source.index("enum\n{\n  PRODUCT_VERDICT_SUCCEEDED")) + 2]

dependencies = r'''
static product_root_nfqueue_main_t product_root_nfqueue_main;
static __thread int product_root_nfqueue_last_errno;
static __thread ssize_t product_root_nfqueue_last_send_result;
static int attempts[256], returns[256], verdicts[256], calls, partial_id=-1;
static int sendto_calls, sendmmsg_calls, write_fault_errno=EFAULT;
static int fail_id=-1, unknown_write_id=-1, wrong_length_id=-1;
static u32 sent_order[256], sent_count;
static u32 call_messages[64], datagram_messages[64], datagram_count;
static product_packet_completion_frame_t completions[32];
static u32 indices[32];
_Static_assert(sizeof(product_nfqueue_verdict_request_t)==32,"verdict request wire size");
_Static_assert(_Alignof(product_nfqueue_verdict_request_t)>=NLMSG_ALIGNTO,"aligned requests");
static void product_root_nfqueue_return_receive(product_root_nfqueue_lane_t *lane,
  u32 slot, u32 index) {
  assert(slot == index && !returns[index]++);
  assert(!lane->pending[index % PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY].active);
}
static u32 decode(int fd, const void *bytes, size_t length) {
  const struct nlmsghdr *nlh=bytes;
  assert((uintptr_t)bytes % NLMSG_ALIGNTO == 0);
  assert(length == 32 && length == nlh->nlmsg_len);
  assert(nlh->nlmsg_flags == NLM_F_REQUEST && !nlh->nlmsg_pid);
  assert(nlh->nlmsg_type == ((NFNL_SUBSYS_QUEUE<<8) | NFQNL_MSG_VERDICT));
  const struct nfgenmsg *gen=NLMSG_DATA(nlh);
  assert(gen->nfgen_family == AF_UNSPEC && gen->version == NFNETLINK_V0);
  assert(ntohs(gen->res_id) == (u32)fd);
  const struct nfattr *attr=(const void*)((const char*)gen+NLMSG_ALIGN(sizeof(*gen)));
  assert(NFA_TYPE(attr) == NFQA_VERDICT_HDR && attr->nfa_len == 12);
  const struct nfqnl_msg_verdict_hdr *hdr=NFA_DATA(attr);
  u32 id=ntohl(hdr->id);
  assert(nlh->nlmsg_seq == id);
  assert(id < 256 && !returns[id] && !attempts[id]++);
  verdicts[id]=ntohl(hdr->verdict);
  sent_order[sent_count++]=id;
  return id;
}
static void destination(const struct sockaddr *address,socklen_t length) {
  assert(length == sizeof(struct sockaddr_nl));
  const struct sockaddr_nl *kernel=(const struct sockaddr_nl*)address;
  assert(kernel->nl_family == AF_NETLINK && !kernel->nl_pid && !kernel->nl_groups);
}
static ssize_t fixture_sendto(int fd,const void *bytes,size_t length,int flags,
  const struct sockaddr *address,socklen_t address_length) {
  destination(address,address_length);
  assert(length && length <= PRODUCT_PACKET_BATCH_SIZE*32 && length%32==0);
  int remaining=(int)length, failed=0, bad_write=0, short_write=0;
  u32 count=0;
  for (const struct nlmsghdr *nlh=bytes; NLMSG_OK(nlh,remaining);
       nlh=NLMSG_NEXT(nlh,remaining)) {
    u32 id=decode(fd,nlh,nlh->nlmsg_len); count++;
    failed |= (int)id==fail_id;
    bad_write |= (int)id==unknown_write_id;
    short_write |= (int)id==wrong_length_id;
  }
  assert(remaining==0 && count==length/32 && calls<64 && datagram_count<64);
  call_messages[calls++]=count; sendto_calls++;
  datagram_messages[datagram_count++]=count;
  if (failed || flags) { errno=EOPNOTSUPP; return -1; }
  if (bad_write) { errno=write_fault_errno; return -1; }
  if (short_write) return length-1;
  return length;
}
#if SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 2
static int fixture_sendmmsg(int fd,struct mmsghdr *messages,unsigned int count,int flags) {
  assert(count > 0 && count <= PRODUCT_PACKET_BATCH_SIZE && calls<64);
  call_messages[calls++]=count; sendmmsg_calls++;
  for (u32 i=0;i<count;i++) {
    struct msghdr *m=&messages[i].msg_hdr;
    assert(m->msg_iovlen==1 && m->msg_namelen==sizeof(struct sockaddr_nl));
    destination(m->msg_name,m->msg_namelen);
    assert(datagram_count<64); datagram_messages[datagram_count++]=1;
    u32 id=decode(fd,m->msg_iov[0].iov_base,m->msg_iov[0].iov_len);
    if ((int)id==unknown_write_id) { errno=write_fault_errno; return i ? (int)i : -1; }
    if ((int)id==partial_id || (int)id==fail_id || flags) {
      errno=i ? 0x5555 : EOPNOTSUPP; return i ? (int)i : -1;
    }
    messages[i].msg_len=m->msg_iov[0].iov_len-((int)id==wrong_length_id);
  }
  return count;
}
#endif
#define sendto fixture_sendto
#define sendmmsg fixture_sendmmsg
'''

helpers = "\n".join(function(name) for name in (
    "product_root_nfqueue_pending_find", "product_root_nfqueue_pending_deactivate",
    "product_nfnl_type", "product_nfnl_addattr", "product_nfnl_send",
    "product_nfnl_fill_header", "product_nfqueue_fill_verdict",
    "product_nfqueue_send_verdict", "product_root_nfqueue_record_verdict_attempt",
    "product_root_nfqueue_prepare_completion", "product_root_nfqueue_finish_completion",
    "product_root_nfqueue_complete_from_graph", "product_root_nfqueue_send_verdict_window",
    "product_root_nfqueue_complete_batch_from_graph", "product_root_nfqueue_consume_control"))

suffix = r'''
static vlib_main_t vm={1};
static void reset(u32 n) {
  memset(&product_root_nfqueue_main,0,sizeof(product_root_nfqueue_main));
  memset(attempts,0,sizeof(attempts)); memset(returns,0,sizeof(returns));
  memset(verdicts,0,sizeof(verdicts)); calls=sent_count=0;
  memset(call_messages,0,sizeof(call_messages));
  memset(datagram_messages,0,sizeof(datagram_messages));
  sendto_calls=sendmmsg_calls=datagram_count=0; write_fault_errno=EFAULT;
  partial_id=fail_id=unknown_write_id=wrong_length_id=-1;
  product_root_nfqueue_main.generation=42; product_root_nfqueue_main.lane_count=4;
  for (u32 l=0;l<4;l++) {
    product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[l];
    lane->generation=42; lane->lane_index=l; lane->worker_index=l%2;
    lane->fd=lane->queue_id=176+l; lane->socket_ready=1;
  }
  for (u32 i=0;i<n;i++) {
    indices[i]=i;
    completions[i]=(product_packet_completion_frame_t){
      .obligation={.token=100+i,.queue_generation=42,.packet_id=i,
        .origin_lane=0,.origin_worker=0,.kind=PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE},
      .producer_thread=1,.terminal_intent=i%2 ? PRODUCT_PACKET_INTENT_DROP_RUNTIME : PRODUCT_PACKET_INTENT_PASS_ADAPTER,
      .flags=PRODUCT_COMPLETION_POLICY_QUALIFIED|PRODUCT_COMPLETION_POLICY_QUALIFIED_MATCHED};
    product_root_nfqueue_pending_t *p=&product_root_nfqueue_main.lanes[0].pending[i];
    p->completion=completions[i]; p->buffer_index=i; p->receive_slot=i; p->active=1;
    product_root_nfqueue_main.lanes[0].pending_active_slots |= UINT64_C(1)<<i;
    product_root_nfqueue_main.lanes[0].pending_count++;
    product_root_nfqueue_main.pending_count++;
  }
}
static void run(u32 n) {
  u8 returned[32]; memset(returned,0xff,sizeof(returned));
  product_root_nfqueue_complete_batch_from_graph(&vm,indices,completions,n,returned);
  for (u32 i=0;i<n;i++) {
    u32 id=indices[i];
    assert(returned[i]==1 && attempts[id]==1 && returns[id]==1);
  }
  for (u32 i=n;i<32;i++) assert(returned[i]==0xff);
  assert(product_root_nfqueue_main.pending_count==0);
  assert(product_root_nfqueue_main.verdict_attempts==n);
  assert(product_root_nfqueue_main.internal_settlements==n);
  assert(product_root_nfqueue_main.buffer_returns==n);
}
static void successful_windows(void) {
  const u32 lengths[]={0,1,2,7,15,16};
  for (u32 at=0;at<sizeof(lengths)/sizeof(lengths[0]);at++) {
    u32 n=lengths[at]; reset(n); run(n);
    assert(sent_count==n && product_root_nfqueue_main.verdict_succeeded==n);
    assert(calls==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==1 ? (int)n : (n!=0)));
    assert(sendmmsg_calls==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==2 ? calls : 0));
    assert(sendto_calls==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==2 ? 0 : calls));
    assert(datagram_count==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==3 ? (n!=0) : n));
    for (u32 i=0;i<datagram_count;i++)
      assert(datagram_messages[i]==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==3 ? n : 1));
    if (n) assert(call_messages[0]==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==1 ? 1 : n));
  }
  reset(16); run(16);
  assert(product_root_nfqueue_main.verdict_succeeded==16);
  assert(product_root_nfqueue_main.lanes[0].policy_qualified_matched_allow_succeeded==8);
  assert(product_root_nfqueue_main.lanes[0].policy_qualified_matched_drop_succeeded==8);
  for (u32 i=0;i<16;i++) assert(verdicts[i]==(i%2 ? NF_DROP : NF_ACCEPT));
  product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
  assert(lane->graph_verdict_windows==1 && lane->graph_verdict_window_messages==16);
#if SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 1
  assert(lane->graph_sendto_calls==16 && !lane->graph_sendmmsg_calls && !lane->graph_packed_calls);
#elif SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 2
  assert(lane->graph_sendmmsg_calls==1 && lane->graph_sendmmsg_requested==16);
  assert(lane->graph_sendmmsg_sent==16 && !lane->graph_sendto_calls && !lane->graph_packed_calls);
#else
  assert(lane->graph_packed_calls==1 && lane->graph_packed_requested==16);
  assert(lane->graph_packed_sent==16 && lane->graph_packed_bytes==512);
  assert(lane->graph_packed_mixed_calls==1 && lane->graph_packed_max_messages==16);
  assert(!lane->graph_sendto_calls && !lane->graph_sendmmsg_calls);
#endif
  reset(8);
  const u32 order[]={6,1,5,0,7,2,4,3};
  product_packet_completion_frame_t original[8]; memcpy(original,completions,sizeof(original));
  for (u32 i=0;i<8;i++) { indices[i]=order[i]; completions[i]=original[order[i]]; }
  run(8);
  for (u32 i=0;i<8;i++) {
    assert(sent_order[i]==order[i]);
    assert(verdicts[i]==(i%2 ? NF_DROP : NF_ACCEPT));
  }
}
static void sendmmsg_boundaries(void) {
#if SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 2
  reset(8); partial_id=2; run(8); assert(calls==2);
  assert(product_root_nfqueue_main.verdict_succeeded==7);
  assert(product_root_nfqueue_main.verdict_outcome_unknown==1);
  assert(product_root_nfqueue_main.verdict_failed_definite==0);
  assert(product_root_nfqueue_main.lanes[0].graph_sendmmsg_requested==13);
  assert(product_root_nfqueue_main.lanes[0].graph_sendmmsg_sent==7);
  assert(product_root_nfqueue_main.lanes[0].graph_sendmmsg_partial_calls==1);
  for (u32 i=0;i<8;i++) assert(sent_order[i]==i);
  reset(4); fail_id=0; run(4); assert(calls==2);
  assert(product_root_nfqueue_main.verdict_succeeded==3);
  assert(product_root_nfqueue_main.verdict_failed_definite==1);
  reset(4); partial_id=3; run(4); assert(calls==1);
  assert(product_root_nfqueue_main.verdict_succeeded==3 && product_root_nfqueue_main.verdict_outcome_unknown==1);
  reset(4); unknown_write_id=0; run(4);
  assert(product_root_nfqueue_main.verdict_succeeded==3 && product_root_nfqueue_main.verdict_outcome_unknown==1);
  reset(4); unknown_write_id=0; write_fault_errno=EINTR; run(4);
  assert(product_root_nfqueue_main.verdict_succeeded==3 && product_root_nfqueue_main.verdict_outcome_unknown==1);
  reset(4); wrong_length_id=1; run(4);
  assert(product_root_nfqueue_main.verdict_succeeded==3 && product_root_nfqueue_main.verdict_outcome_unknown==1);
#endif
}
static void sendto_results(void) {
#if SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE != 2
  reset(4); fail_id=2; run(4);
  u32 failed=SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==3 ? 4 : 1;
  assert(product_root_nfqueue_main.verdict_succeeded==4-failed);
  assert(product_root_nfqueue_main.verdict_failed_definite==failed);
  assert(!product_root_nfqueue_main.verdict_outcome_unknown);
  reset(4); unknown_write_id=0; run(4);
  assert(product_root_nfqueue_main.verdict_succeeded==4-failed);
  assert(product_root_nfqueue_main.verdict_failed_definite==failed);
  assert(!product_root_nfqueue_main.verdict_outcome_unknown);
  reset(4); unknown_write_id=0; write_fault_errno=EINTR; run(4);
  assert(product_root_nfqueue_main.verdict_succeeded==4-failed);
  assert(product_root_nfqueue_main.verdict_failed_definite==failed);
  reset(4); wrong_length_id=1; run(4);
  assert(product_root_nfqueue_main.verdict_succeeded==4-failed);
  assert(product_root_nfqueue_main.verdict_outcome_unknown==failed);
  assert(!product_root_nfqueue_main.verdict_failed_definite);
  assert(product_root_nfqueue_main.lanes[0].policy_qualified_succeeded==4-failed);
  assert(calls==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==3 ? 1 : 4));
#endif
}
static void partitions_and_settlement(void) {
  reset(4); product_root_nfqueue_main.lanes[0].verdict_fault_next=1; run(4);
  assert(calls==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==1 ? 4 : 2));
  assert(product_root_nfqueue_main.verdict_succeeded==3 && product_root_nfqueue_main.verdict_failed_definite==1);
  reset(4); product_root_nfqueue_main.fault_mode=PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_FAILED_DEFINITE; run(4);
  assert(calls==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==3 ? 1 : 4));
  assert(product_root_nfqueue_main.verdict_failed_definite==4 && !product_root_nfqueue_main.verdict_succeeded);
  reset(6);
  for (u32 i=2;i<4;i++) {
    completions[i].obligation.origin_lane=2;
    product_root_nfqueue_main.lanes[2].pending[i]=product_root_nfqueue_main.lanes[0].pending[i];
    product_root_nfqueue_main.lanes[2].pending[i].completion=completions[i];
    product_root_nfqueue_main.lanes[0].pending[i].active=0;
    product_root_nfqueue_main.lanes[0].pending_active_slots &= ~(UINT64_C(1)<<i);
    product_root_nfqueue_main.lanes[2].pending_active_slots |= UINT64_C(1)<<i;
    product_root_nfqueue_main.lanes[0].pending_count--;
    product_root_nfqueue_main.lanes[2].pending_count++;
  }
  run(6); assert(calls==(SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE==1 ? 6 : 3));
  for (u32 i=0;i<6;i++) assert(sent_order[i]==i);
  assert(product_root_nfqueue_main.lanes[0].graph_verdict_windows==2);
  assert(product_root_nfqueue_main.lanes[2].graph_verdict_windows==1);
  reset(4); product_root_nfqueue_main.lanes[0].draining=1; run(4);
  assert(product_root_nfqueue_main.verdict_succeeded==4);
  reset(4); for (u32 i=1;i<4;i+=2) completions[i].producer_thread=2;
  run(4);
  assert(product_root_nfqueue_main.origin_local_completions==2);
  assert(product_root_nfqueue_main.origin_remote_completions==2);
  reset(4); completions[1].obligation.queue_generation=41;
  completions[2].flags|=PRODUCT_COMPLETION_REPLAY_PROBE;
  completions[3].obligation.kind=PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
  u8 returned[4]; product_root_nfqueue_complete_batch_from_graph(&vm,indices,completions,4,returned);
  assert(returned[0] && !returned[1] && !returned[2] && !returned[3]);
  assert(attempts[0]==1 && !attempts[1] && !attempts[2] && !attempts[3]);
  assert(product_root_nfqueue_main.stale_completion_drops==2);
  product_root_nfqueue_complete_batch_from_graph(&vm,indices,completions,1,returned);
  assert(!returned[0] && attempts[0]==1 && returns[0]==1);
  assert(product_root_nfqueue_main.lanes[0].duplicate_completion_drops==1);
  reset(4); run(4); int previous_calls=calls;
  product_root_nfqueue_complete_batch_from_graph(&vm,indices,completions,4,returned);
  assert(calls==previous_calls && product_root_nfqueue_main.duplicate_completion_drops==4);
  for (u32 i=0;i<4;i++) assert(!returned[i] && attempts[i]==1 && returns[i]==1);
  reset(4); completions[1].terminal_intent=PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS;
  completions[1].processing_bypass_reason=PRODUCT_PACKET_BYPASS_FLOW_CAPACITY;
  run(4); assert(verdicts[1]==NF_ACCEPT);
  assert(product_root_nfqueue_main.lanes[0].policy_qualified_succeeded==3);
  assert(product_root_nfqueue_main.lanes[0].policy_qualified_matched_allow_succeeded==2);
  assert(product_root_nfqueue_main.lanes[0].policy_qualified_matched_drop_succeeded==1);
  reset(1); completions[0].terminal_intent=PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS;
  product_root_nfqueue_complete_batch_from_graph(&vm,indices,completions,1,returned);
  assert(!returned[0] && !calls && !attempts[0] && !returns[0]);
  assert(product_root_nfqueue_main.pending_count==1 && product_root_nfqueue_main.stale_completion_drops==1);
  reset(1); product_root_nfqueue_main.lanes[0].socket_ready=0;
  product_root_nfqueue_complete_batch_from_graph(&vm,indices,completions,1,returned);
  assert(!returned[0] && !calls && product_root_nfqueue_main.pending_count==1);
  assert(product_root_nfqueue_main.stale_completion_drops==1);
  for (u32 invalid=0;invalid<4;invalid++) {
    reset(1);
    switch (invalid) {
      case 0: completions[0].obligation.origin_worker=1; break;
      case 1: indices[0]=1; break;
      case 2: completions[0].obligation.packet_id=10; break;
      case 3: completions[0].obligation.origin_lane=4; break;
    }
    product_root_nfqueue_complete_batch_from_graph(&vm,indices,completions,1,returned);
    assert(!returned[0] && !calls && !sent_count && !returns[0]);
    assert(product_root_nfqueue_main.pending_count==1 && product_root_nfqueue_main.stale_completion_drops==1);
  }
  reset(1); assert(product_root_nfqueue_complete_from_graph(&vm,0,completions));
  assert(calls==1 && returns[0]==1 && attempts[0]==1);
}
static u32 control_reply(u8 *bytes,int error,u32 sequence,u32 extra) {
  u32 length=NLMSG_LENGTH(sizeof(struct nlmsgerr))+extra;
  memset(bytes,0,length);
  struct nlmsghdr *nlh=(struct nlmsghdr*)bytes;
  nlh->nlmsg_len=length; nlh->nlmsg_type=NLMSG_ERROR; nlh->nlmsg_seq=sequence;
  struct nlmsgerr *reply=NLMSG_DATA(nlh);
  reply->error=error; reply->msg.nlmsg_len=32;
  reply->msg.nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_VERDICT;
  reply->msg.nlmsg_seq=sequence;
  return length;
}
static void control_envelopes(void) {
  reset(1);
  product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
  union { u8 bytes[128]; struct nlmsghdr alignment; } buffer;
  u32 one=control_reply(buffer.bytes,0,10,0);
  assert(product_root_nfqueue_consume_control(lane,buffer.bytes,one)==1);
  assert(lane->control_replies==1 && !lane->control_errors && !lane->control_malformed);
  one=control_reply(buffer.bytes,-ENOENT,21,0);
  u32 two=control_reply(buffer.bytes+one,-EPERM,22,0);
  assert(product_root_nfqueue_consume_control(lane,buffer.bytes,one+two)==1);
  assert(lane->control_replies==3 && lane->control_errors==2);
  assert(lane->control_first_error==ENOENT && lane->control_first_sequence==21);
  assert(lane->control_last_error==EPERM && lane->control_last_sequence==22);
  one=control_reply(buffer.bytes,0,23,1); /* Last message need not include trailing alignment. */
  assert(product_root_nfqueue_consume_control(lane,buffer.bytes,one)==1);
  assert(lane->control_replies==4 && lane->control_errors==2);
  assert(lane->control_first_sequence==21 && lane->control_last_sequence==22);

  one=control_reply(buffer.bytes,-EINVAL,30,0);
  ((struct nlmsghdr*)buffer.bytes)->nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET;
  assert(!product_root_nfqueue_consume_control(lane,buffer.bytes,one));
  assert(!product_root_nfqueue_consume_control(lane,buffer.bytes,15));
  assert(!lane->control_malformed && lane->control_replies==4 && lane->control_errors==2);
  for (u32 invalid=0;invalid<7;invalid++) {
    one=control_reply(buffer.bytes,-EINVAL,31,0);
    struct nlmsghdr *nlh=(struct nlmsghdr*)buffer.bytes;
    struct nlmsgerr *reply=NLMSG_DATA(nlh);
    switch (invalid) {
      case 0: nlh->nlmsg_len=one+4; break;
      case 1: nlh->nlmsg_len=NLMSG_HDRLEN; break;
      case 2: reply->error=EINVAL; break;
      case 3: reply->error=INT32_MIN; break;
      case 4: reply->msg.nlmsg_len=NLMSG_HDRLEN-1; break;
      case 5:
        two=control_reply(buffer.bytes+one,-ENOENT,32,0);
        ((struct nlmsghdr*)(buffer.bytes+one))->nlmsg_type=(NFNL_SUBSYS_QUEUE<<8)|NFQNL_MSG_PACKET;
        one+=two; break;
      case 6: buffer.bytes[one++]=0; break;
    }
    assert(!product_root_nfqueue_consume_control(lane,buffer.bytes,one));
    assert(lane->control_malformed==invalid+1);
    assert(lane->control_replies==4 && lane->control_errors==2); /* No partial-envelope counting. */
    assert(lane->control_first_sequence==21 && lane->control_last_sequence==22);
  }
  assert(!calls && !sent_count && !attempts[0] && !returns[0]);
  assert(product_root_nfqueue_main.pending_count==1 && lane->pending[0].active);
  assert(!product_root_nfqueue_main.internal_settlements && !product_root_nfqueue_main.verdict_attempts);
}
static void diagnostic_guard_expiry(void) {
  reset(0);
  product_root_nfqueue_lane_t *lane=&product_root_nfqueue_main.lanes[0];
  lane->verdict_id_fault_next=1;
  product_root_nfqueue_record_verdict_attempt(&product_root_nfqueue_main,lane,4095);
  assert(lane->verdict_id_fault_next && !lane->verdict_id_probe_expired);
  assert(lane->last_verdict_packet_id==4095 && lane->verdict_packet_id_known);

  reset(0); lane->verdict_id_fault_next=1;
  product_root_nfqueue_record_verdict_attempt(&product_root_nfqueue_main,lane,4096);
  assert(lane->verdict_id_probe_expired && !lane->verdict_id_fault_next);
  assert(lane->last_verdict_packet_id==4096 && lane->verdict_attempts==1);
  product_root_nfqueue_record_verdict_attempt(&product_root_nfqueue_main,lane,0);
  assert(lane->verdict_id_probe_expired && !lane->verdict_id_fault_next);
  assert(lane->last_verdict_packet_id==0 && lane->verdict_attempts==2);
  assert(product_root_nfqueue_main.verdict_attempts==2);

  reset(0); lane->verdict_id_fault_next=1;
  lane->verdict_attempts=product_root_nfqueue_main.verdict_attempts=4094;
  product_root_nfqueue_record_verdict_attempt(&product_root_nfqueue_main,lane,10);
  assert(lane->verdict_attempts==4095 && !lane->verdict_id_probe_expired && lane->verdict_id_fault_next);
  product_root_nfqueue_record_verdict_attempt(&product_root_nfqueue_main,lane,11);
  assert(lane->verdict_attempts==4096 && lane->verdict_id_probe_expired && !lane->verdict_id_fault_next);
  assert(product_root_nfqueue_main.verdict_attempts==4096);

  for (u32 loss=0;loss<3;loss++) {
    reset(0); lane->verdict_id_fault_next=1;
    if (loss==0) lane->identity_losses=1;
    else if (loss==1) lane->reserve_losses=1;
    else lane->receive_overruns=1;
    product_root_nfqueue_record_verdict_attempt(&product_root_nfqueue_main,lane,7);
    assert(lane->verdict_id_probe_expired && !lane->verdict_id_fault_next);
    lane->identity_losses=lane->reserve_losses=lane->receive_overruns=0;
    product_root_nfqueue_record_verdict_attempt(&product_root_nfqueue_main,lane,8);
    assert(lane->verdict_id_probe_expired && !lane->verdict_id_fault_next);
    assert(lane->verdict_attempts==2 && product_root_nfqueue_main.verdict_attempts==2);
    assert(!calls && !sent_count && !product_root_nfqueue_main.pending_count);
    assert(!product_root_nfqueue_main.internal_settlements && !product_root_nfqueue_main.buffer_returns);
  }
}
int main(void) {
  successful_windows(); sendmmsg_boundaries(); sendto_results(); partitions_and_settlement();
  control_envelopes();
  diagnostic_guard_expiry();
  printf("NFQUEUE independent verdict window mode=%u: PASS\n",SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE);
}
'''

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix="sakamoto-verdict-batch-") as folder:
    path = Path(folder)
    fixture = path / "fixture.c"
    fixture.write_text(prefix + mode_config + types + outcomes + dependencies + helpers + suffix)
    for mode in (None, 1, 2, 3):
        mode_flags = ([] if mode is None else [f"-DSAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE={mode}"])
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O1", "-g",
                        "-Wall", "-Wextra", "-Werror",
                        "-DSAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT=1",
                        *mode_flags,
                        "-I", str(PRODUCT), "-I", str(ROOT / "src/product/include"),
                        str(fixture), "-o", str(path / "fixture")], check=True, timeout=30)
        subprocess.run([str(path / "fixture")], check=True, timeout=5)
print("adapter_source_sha256=" + hashlib.sha256(source.encode()).hexdigest())
