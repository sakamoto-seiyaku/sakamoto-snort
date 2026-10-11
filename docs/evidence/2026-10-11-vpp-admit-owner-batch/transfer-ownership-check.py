#!/usr/bin/env python3
"""Exercise the actual experimental transfer helpers at the native queue seam."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).with_name('product_packet_graph_admit_experiment.inc')


def function(text, name):
    start = text.index(name + ' (')
    opening = text.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


source = SOURCE.read_text()
helpers = 'static void\n' + function(source, 'product_admit_batch_flush') + '\n\n'
helpers += 'static int\n' + function(source, 'product_admit_batch_stage_primary') + '\n'
harness = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "product_packet.h"
typedef uint32_t u32; typedef uint16_t u16; typedef uint8_t u8;
#define VLIB_FRAME_SIZE 256
#define ASSERT assert
#define PRODUCT_META_TRACE 64
#define PRODUCT_META_HANDOFF_CREDIT 128
#define PRODUCT_HANDOFF_PRIMARY 0
#define PRODUCT_ADMIT_NEXT_TERMINAL 2
#define clib_atomic_fetch_add_relax(p,n) (*(p) += (n))
typedef struct { u32 thread_index; } vlib_main_t;
typedef struct { int unused; } vlib_node_runtime_t;
typedef struct {
  u16 expected_owner; u8 state_bits, primary_handoff_count, corrective_handoff_count;
  uint64_t origin_obligation_id, generation;
  u8 runtime_drop_reason, processing_bypass_reason, terminal;
} product_buffer_metadata_t;
typedef struct { product_buffer_metadata_t metadata; int published, terminal; } vlib_buffer_t;
typedef struct {
  u32 primary_frame_queue, credits[2], reserved[2], primary_published, primary_rejected;
  int misroute_next;
} product_packet_graph_main_t;
typedef struct {
  product_buffer_metadata_t metadata[256]; product_packet_lease_t leases[256];
  u32 indices[272], failed[272]; u16 targets[272], slots[272]; u32 count;
} product_admit_batch_scratch_t;
static product_packet_graph_main_t product_packet_graph_main;
static vlib_buffer_t buffers[256];
static u32 calls, packet_attempts, transferred_total, rejected_total, force_fail[256];
static u32 published_order[256], published_count;
static u16 target_for[256];
static u16 vlib_get_worker_thread_index(u16 owner) { return owner + 1; }
static int product_handoff_credit_reserve(product_packet_graph_main_t *g, u16 owner,
                                          int stage, uint64_t token) {
  (void)stage; (void)token; if (!g->credits[owner]) return 0;
  g->credits[owner]--; g->reserved[owner]++; return 1;
}
static void product_handoff_credit_release(product_packet_graph_main_t *g,u16 owner) {
  assert(g->reserved[owner]); g->reserved[owner]--; g->credits[owner]++;
}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm,u32 bi) {
  (void)vm; assert(bi < 256 && !buffers[bi].published); return &buffers[bi];
}
static void product_metadata_store(vlib_buffer_t *b,const product_buffer_metadata_t *m) {
  assert(!b->published); b->metadata=*m;
}
static void product_metadata_set_terminal_intent(product_buffer_metadata_t *m,u8 intent) {
  m->terminal=intent;
}
static void product_admit_experiment_primary_attempt(vlib_main_t *vm,u32 n) {
  (void)vm; calls++; packet_attempts+=n;
}
static void product_admit_experiment_primary_result(vlib_main_t *vm,u32 n,u32 failed) {
  (void)vm; transferred_total+=n; rejected_total+=failed;
}
static u32 vlib_buffer_enqueue_to_thread_retained(vlib_main_t *vm,vlib_node_runtime_t *node,
  u32 queue,u32 *indices,u16 *targets,u32 n,u32 *failed) {
  (void)vm; (void)node; (void)queue;
  /* Verify padding exists, then model immediate ownership transfer/free. */
  volatile u32 padding=indices[n+7]+targets[n+7]; (void)padding;
  u32 accepted=0, rejected=0;
  for(u32 i=0;i<n;i++) {
    u32 bi=indices[i]; assert(!buffers[bi].published && !buffers[bi].terminal);
    if(force_fail[bi]) failed[rejected++]=bi;
    else { buffers[bi].published=1; target_for[bi]=targets[i];
           published_order[published_count++]=bi; accepted++; }
  }
  /* Failed indices are intentionally returned out of input order. */
  for(u32 i=0;i<rejected/2;i++) {u32 t=failed[i];failed[i]=failed[rejected-1-i];failed[rejected-1-i]=t;}
  return accepted;
}
static void vlib_buffer_enqueue_to_single_next(vlib_main_t *vm,vlib_node_runtime_t *node,
  u32 *bi,u32 next,u32 count) {
  (void)vm; (void)node; assert(next==PRODUCT_ADMIT_NEXT_TERMINAL && count==1);
  assert(!buffers[*bi].published && !buffers[*bi].terminal); buffers[*bi].terminal=1;
}
HELPERS
static void reset(void) {
  memset(&product_packet_graph_main,0,sizeof(product_packet_graph_main));
  product_packet_graph_main.credits[0]=product_packet_graph_main.credits[1]=256;
  memset(buffers,0,sizeof(buffers)); memset(force_fail,0,sizeof(force_fail));
  calls=packet_attempts=transferred_total=rejected_total=published_count=0;
}
static void prepare(product_admit_batch_scratch_t *s,u32 i,int vpn) {
  product_packet_lease_t *l=&s->leases[i];
  l->platform.provenance=vpn?PRODUCT_PACKET_PROVENANCE_VPN_TUN:PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE;
  l->assignment.valid=1; l->assignment.execution_owner=i%2;
  l->facts.l3_status=PRODUCT_PACKET_L3_COMPLETE;
  l->distribution=PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE;
  s->metadata[i]=(product_buffer_metadata_t){.expected_owner=i%2,.primary_handoff_count=1,
    .origin_obligation_id=1000+i,.generation=7};
}
static void case_run(u32 count,int vpn,int all_fail) {
  reset(); product_admit_batch_scratch_t s={0};vlib_main_t vm={.thread_index=1};
  vlib_node_runtime_t node={0};
  for(u32 i=0;i<count;i++) {
    prepare(&s,i,vpn);force_fail[i]=all_fail || i%3==1;
    product_packet_processing_bypass_reason_t reason=PRODUCT_PACKET_BYPASS_NONE;
    assert(product_admit_batch_stage_primary(&vm,&node,&s,i,i,&s.metadata[i],&reason));
    assert(reason==PRODUCT_PACKET_BYPASS_NONE);
  }
  product_admit_batch_flush(&vm,&node,&s);
  assert(!s.count && packet_attempts==count && transferred_total+rejected_total==count);
  assert(calls==(count!=0));
  u32 previous=0;
  for(u32 i=0;i<published_count;i++) {assert(i==0 || published_order[i]>previous);previous=published_order[i];}
  for(u32 i=0;i<count;i++) {
    if(force_fail[i]) {
      assert(buffers[i].terminal && !buffers[i].published);
      assert(!(buffers[i].metadata.state_bits & PRODUCT_META_HANDOFF_CREDIT));
      assert(s.leases[i].terminal_count==1);
      assert(s.leases[i].terminal_intent==(vpn?PRODUCT_PACKET_INTENT_DROP_RUNTIME:PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS));
      assert(product_packet_settle(&s.leases[i])==PRODUCT_PACKET_OK);
      assert(product_packet_settle(&s.leases[i])==PRODUCT_PACKET_ALREADY_SETTLED);
    } else {
      assert(buffers[i].published && !buffers[i].terminal);
      assert(target_for[i]==i%2+1);
      product_handoff_credit_release(&product_packet_graph_main,i%2);
    }
  }
  assert(product_packet_graph_main.primary_published==transferred_total);
  assert(product_packet_graph_main.primary_rejected==rejected_total);
  assert(!product_packet_graph_main.reserved[0] && !product_packet_graph_main.reserved[1]);
  assert(product_packet_graph_main.credits[0]==256 && product_packet_graph_main.credits[1]==256);
}
int main(void) {
  const u32 sizes[]={0,1,4,64,256};
  for(u32 i=0;i<sizeof(sizes)/sizeof(sizes[0]);i++)
    for(int vpn=0;vpn<2;vpn++)for(int fail=0;fail<2;fail++)case_run(sizes[i],vpn,fail);
  reset();product_admit_batch_scratch_t s={0};vlib_main_t vm={.thread_index=1};vlib_node_runtime_t node={0};
  prepare(&s,0,0);product_packet_graph_main.credits[0]=0;
  product_packet_processing_bypass_reason_t reason=PRODUCT_PACKET_BYPASS_NONE;
  assert(!product_admit_batch_stage_primary(&vm,&node,&s,0,0,&s.metadata[0],&reason));
  assert(reason==PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED && !s.count && !calls);
  assert(!buffers[0].published && !buffers[0].terminal && !product_packet_graph_main.reserved[0]);
  puts("admit bulk ownership/credit/partial rejection: PASS");
}
'''.replace('HELPERS', helpers)
with tempfile.TemporaryDirectory(prefix='sakamoto-admit-transfer-') as directory:
    path = Path(directory)
    (path / 'test.c').write_text(harness)
    subprocess.run(['cc', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I', str(ROOT / 'src/product/vpp'), str(path / 'test.c'),
                    str(ROOT / 'src/product/vpp/product_packet.c'), '-o', str(path / 'test')], check=True)
    # This sandbox uses ptrace, which LeakSanitizer cannot inspect. The tested
    # helpers allocate no heap; retain AddressSanitizer and UBSan checks.
    environment = os.environ.copy()
    environment['ASAN_OPTIONS'] = environment.get('ASAN_OPTIONS', '') + ':detect_leaks=0'
    subprocess.run([str(path / 'test')], check=True, env=environment, timeout=10)
