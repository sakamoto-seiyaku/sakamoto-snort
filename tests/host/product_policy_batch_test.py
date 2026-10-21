#!/usr/bin/env python3
"""Execute current policy windows, bank protection and qualified completion.

The C functions, private types, atomics and flag statements are extracted from
the product source at test time. VPP buffer operations, Flow observation,
diagnostic recording, domain destruction and send_verdict use controlled seams.
This checks the actual policy/settlement code, not a second host policy model;
it does not claim native queue, real socket or FlowRuntime qualification.
"""
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GRAPH = (ROOT / "src/product/vpp/product_packet_graph.c").read_text()
ADAPTER = (ROOT / "src/product/vpp/product_root_nfqueue_adapter.c").read_text()


def closing_brace(source, opening):
    """Ignore braces in comments and quoted diagnostic strings."""
    token = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    depth = 0
    for match in token.finditer(source, opening):
        if match.group() == "{":
            depth += 1
        elif match.group() == "}":
            depth -= 1
            if depth == 0:
                return match.end()
    raise AssertionError("unclosed source block")


def function(source, name, result):
    match = re.search(r'\n' + re.escape(name) + r'\s*\([^;]*?\n\{', source, re.S)
    assert match, name
    return result + "\n" + source[match.start() + 1:closing_brace(source, match.end() - 1)] + "\n"


def typedef(source, name):
    end = re.search(r'\}\s*' + re.escape(name) + r'\s*;', source)
    assert end, name
    start = list(re.finditer(r'\btypedef\s+(?:struct|union|enum)\b', source[:end.start()]))[-1].start()
    return source[start:end.end()] + "\n"


def statement(source, marker):
    start = source.index(marker)
    return source[start:source.index(";", start) + 1]


def anonymous_enum(source, member):
    member_at = source.index(member)
    start = source.rfind("enum", 0, member_at)
    end = closing_brace(source, source.index("{", start))
    return source[start:source.index(";", end) + 1] + "\n"


snapshot_functions = "".join(function(GRAPH, name, "static void") for name in (
    "product_policy_snapshot_acquire", "product_policy_snapshot_release"))
publisher = "".join(function(GRAPH, name, result) for name, result in (
    ("product_packet_graph_policy_writer_lock", "static void"),
    ("product_packet_graph_policy_writer_unlock", "static void"),
    ("product_packet_graph_publish_policy_bundle", "product_packet_result_t")))
projection = "".join(function(GRAPH, name, result) for name, result in (
    ("product_packet_graph_l4_direction_from_platform", "static void"),
    ("product_packet_graph_l4_packet_projection", "static void"),
    ("product_packet_graph_l4_view_evaluate", "static product_l4_policy_status_t")))
stage = function(GRAPH, "product_packet_graph_policy_stage_snapshot", "static product_packet_result_t")
owner = function(GRAPH, "product_packet_graph_policy_on_owner", "static product_packet_result_t")
flow_commit = function(GRAPH, "product_packet_graph_flow_record_decision", "static product_flow_entry_status_t")
node_start = GRAPH.index("VLIB_NODE_FN (product_packet_policy_node)")
node = GRAPH[node_start:closing_brace(GRAPH, GRAPH.index("{", node_start))] + "\n"
terminal_start = GRAPH.index("VLIB_NODE_FN (product_packet_terminal_node)")
terminal = GRAPH[terminal_start:closing_brace(GRAPH, GRAPH.index("{", terminal_start))]
fragment_at = terminal.index("if (metadata.fragment_bundle_count)")
fragment_guard = terminal[fragment_at:closing_brace(terminal, terminal.index("{", fragment_at))]
qualified_flag = statement(terminal, "if ((metadata.reserved_bits & 1U)")
matched_flag = statement(terminal, "if ((completion.flags & PRODUCT_COMPLETION_POLICY_QUALIFIED)")
completion_flag = qualified_flag + "\n" + matched_flag
assert fragment_at < terminal.index(qualified_flag), "fragment fanout must precede ordinary qualification"
metadata_flag = statement(node, "metadata.reserved_bits =")
completion = "".join(function(ADAPTER, name, result) for name, result in (
    ("product_root_nfqueue_record_verdict_attempt", "static void"),
    ("product_root_nfqueue_return_receive", "static void"),
    ("product_root_nfqueue_pending_find", "static product_root_nfqueue_pending_t *"),
    ("product_root_nfqueue_pending_deactivate", "static void"),
    ("product_root_nfqueue_prepare_completion", "static int"),
    ("product_root_nfqueue_finish_completion", "static void"),
    ("product_root_nfqueue_complete_from_graph", "int")))

# Keep the exact private member declarations used by extracted functions. Other
# graph storage is irrelevant to these seams and is not synthesized as a model.
main_type = typedef(GRAPH, "product_packet_graph_main_t")
plain_main = re.sub(r'/\*.*?\*/', '', main_type, flags=re.S)
required = sorted(set(re.findall(r'graph->(\w+)', snapshot_functions + publisher + projection + stage + owner + node)))
members = []
for member in required:
    match = re.search(r'(?m)^\s*([^\n;]*\b' + re.escape(member) + r'\b[^\n;]*;)', plain_main)
    assert match, member
    declaration = match.group(1).strip()
    if declaration not in members:
        members.append(declaration)
graph_type = "typedef struct {\n" + "\n".join(members) + "\n} product_packet_graph_main_t;\n"

prefix = r'''
#define SAKAMOTO_PRODUCT_HOST_EVIDENCE 1
#define SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS 1
#include <assert.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "product_packet_graph.h"
#include "product_flow_entry.h"
#include "product_observation.h"
#include "product_root_receive_pool.h"
#include "product_packet_batch.h"
#define PRODUCT_GRAPH_WORKERS 2
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES PRODUCT_ROOT_COMPLETION_MAX_LANES
#define PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY PRODUCT_ROOT_COMPLETION_CAPACITY
#define CLIB_CACHE_LINE_ALIGN_MARK(x)
#define ASSERT assert
#define PREDICT_FALSE(x) (x)
#define clib_panic(x) assert(!(x))
#define clib_memset memset
#define clib_memcpy_fast memcpy
#define clib_max(a,b) ((a) > (b) ? (a) : (b))
#define clib_atomic_load_acq_n(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define clib_atomic_store_rel_n(p,v) __atomic_store_n((p),(v),__ATOMIC_RELEASE)
#define clib_atomic_fetch_add_relax(p,v) __atomic_fetch_add((p),(v),__ATOMIC_RELAXED)
#define clib_atomic_fetch_sub_relax(p,v) __atomic_fetch_sub((p),(v),__ATOMIC_RELAXED)
#define clib_atomic_cmp_and_swap_acq_relax_n(p,e,v,w) __atomic_compare_exchange_n((p),(e),(v),(w),__ATOMIC_ACQUIRE,__ATOMIC_RELAXED)
#define VLIB_NODE_FN(name) uword name
#define PRODUCT_EVIDENCE_ADD(name,value) ((void)(value))
#define PRODUCT_POLICY_NEXT_CONSUMER 0
#define PRODUCT_TRACE_POLICY 1
#define PRODUCT_FLOW_PREFETCH_BUCKET 0
#define PRODUCT_FLOW_PREFETCH_INDEX 1
#define PRODUCT_FLOW_PREFETCH_STATE 2
static u32 vlib_get_thread_index(void) { return 0; }
static u32 vlib_get_worker_index(u32 thread) { assert(thread); return thread - 1; }
static u32 vlib_get_worker_thread_index(u32 worker) { return worker + 1; }
uint32_t product_packet_graph_worker_count(void) { return PRODUCT_GRAPH_WORKERS; }
uint32_t product_packet_graph_trace_limit(void) { return 0; }
'''

private_types = "".join(typedef(GRAPH, name) for name in (
    "product_packet_graph_l4_policy_bank_t", "product_policy_snapshot_t",
    "product_policy_worker_t", "product_compact_owner_assignment_t",
    "product_transport_metadata_t", "product_buffer_metadata_t",
    "product_packet_batch_stats_t"))
private_types += anonymous_enum(GRAPH, "PRODUCT_META_ADMITTED") + graph_type
private_types += "".join(typedef(ADAPTER, name) for name in (
    "product_root_nfqueue_fault_mode_t", "product_root_nfqueue_pending_t",
    "product_root_nfqueue_lane_t", "product_root_nfqueue_main_t",
    "product_root_verdict_work_t"))
private_types += anonymous_enum(ADAPTER, "PRODUCT_VERDICT_SUCCEEDED")

hooks = r'''
static product_packet_graph_main_t product_packet_graph_main;
static product_root_nfqueue_main_t product_root_nfqueue_main;
static product_packet_batch_stats_t product_packet_batch_stats[PRODUCT_GRAPH_WORKERS + 1];
static char retired_domain_marker;
static atomic_uint retired_destroyed, wait_seen, writer_done, wait_enabled;
static atomic_uint delayed_claim, claim_seen, claim_resume;
static u32 retired_bank;
void product_domains_destroy(product_domains_t *domains) {
  if (domains == (product_domains_t *)&retired_domain_marker)
    atomic_fetch_add(&retired_destroyed, 1);
}
uint64_t product_domains_match(const product_domains_t *domains, const uint8_t *name, size_t length) {
  (void)domains; (void)name; (void)length; return 0;
}
static u32 tracked_load(const u32 *p, int order) {
  u32 value = __atomic_load_n(p, order);
  if (atomic_load(&wait_enabled) && p == &product_packet_graph_main.l4_policy_bank_readers[retired_bank])
    atomic_store(&wait_seen, 1);
  return value;
}
static u32 tracked_claim(u32 *p, u32 value, int order) {
  if (atomic_exchange(&delayed_claim, 0)) {
    atomic_store(&claim_seen, 1);
    while (!atomic_load(&claim_resume)) sched_yield();
  }
  return __atomic_fetch_add(p, value, order);
}
#define __atomic_load_n(p,o) tracked_load((p),(o))
#define __atomic_fetch_add(p,v,o) tracked_claim((p),(v),(o))
'''

# Only snapshot claim uses the claim interception; all other atomic widths and
# orders remain the original compiler builtins. Both hooks return real atomics.
snapshot_code = snapshot_functions + "\n#undef __atomic_fetch_add\n"

stubs = r'''
static vlib_buffer_t buffers[VLIB_FRAME_SIZE];
static product_buffer_metadata_t metadata_storage[VLIB_FRAME_SIZE];
static u64 revisions[VLIB_FRAME_SIZE];
static u32 policy_calls, enqueued, freed, fragment_calls, publish_inside_node, injected_bypass;
static unsigned flow_interface_mode, flow_observe_calls, decision_submissions, regression_failures;
static product_flow_entry_t controlled_entry;
static char controlled_pool;
static product_flow_policy_identity_t submitted_identity;
static u64 submitted_winner;
static u32 submitted_reason;
static u8 submitted_decision;
static int native_send_success = 1;
static u32 native_send_calls, native_verdict;
static __thread int product_root_nfqueue_last_errno;
static __thread ssize_t product_root_nfqueue_last_send_result;
static product_l4_policy_rule_t source_rule(u8 action) {
  return (product_l4_policy_rule_t){.uid=17,.rule_id=91,.reason_id=191,.action=action,
    .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=65535,.destination_port_last=65535};
}
static void publish_revision(u64 revision) {
  product_l4_policy_rule_t rule=source_rule(PRODUCT_L4_POLICY_ACTION_ALLOW);
  product_packet_graph_policy_bundle_t bundle={.generation=7,.revision=revision,
    .snapshot_hash=revision+100,.l4_rule_count=1,.l4_rules=&rule};
  assert(product_packet_graph_publish_policy_bundle(&bundle)==PRODUCT_PACKET_OK);
}
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
static product_packet_batch_stats_t *product_packet_batch_counters(vlib_main_t *vm) {
  return &product_packet_batch_stats[vm->thread_index];
}
static u64 product_packet_event_clock_ns(void) { static u64 clock; return ++clock; }
static void product_batch_prefetch_buffer(vlib_buffer_t **b,u32 index,u32 count,int data) {
  (void)b; (void)index; (void)count; (void)data;
}
static void product_batch_flow_prefetch(vlib_main_t *vm,vlib_buffer_t **b,u32 index,u32 count,int phase) {
  (void)vm; (void)b; (void)index; (void)count; (void)phase;
}
#endif
static void product_packet_graph_record_policy_stage(product_packet_graph_main_t *g,
  const product_packet_graph_policy_evaluation_t *e) { (void)g; (void)e; }
static void product_packet_graph_record_l4_view_match(product_packet_graph_main_t *g,
  const product_packet_lease_t *l,u64 generation,u64 revision,u64 hash,
  const product_l4_policy_match_result_t *r) { (void)g; (void)l; (void)generation; (void)revision; (void)hash; (void)r; }
static void product_packet_graph_record_l4_view_no_match(product_packet_graph_main_t *g,
  u64 generation,u64 revision,u64 hash,u32 count,const product_l4_policy_match_result_t *r,
  const product_packet_lease_t *l) { (void)g; (void)l; (void)generation; (void)revision; (void)hash; (void)r; (void)count; }
static void product_packet_graph_flow_observe(vlib_main_t *vm,u32 index,product_packet_lease_t *lease,
  const product_packet_graph_policy_evaluation_t *e,int trace,product_flow_entry_observation_t *out) {
  (void)vm; (void)trace; memset(out,0,sizeof(*out));
  if(publish_inside_node) assert(e->generation==7);
  revisions[index]=e->revision; ++policy_calls;
  ++flow_observe_calls;
  if(flow_interface_mode==1) {
    controlled_entry=(product_flow_entry_t){.in_use=1,.linked=1,.incarnation=77,
      .policy_generation=e->generation,.policy_revision=e->revision,.policy_snapshot_hash=e->snapshot_hash};
    out->entry=&controlled_entry;out->slot=3;
    out->tracker.facts.state=PRODUCT_CT_ESTABLISHED;
    out->tracker.facts.direction=PRODUCT_FLOW_DIRECTION_ORIG;
  }
  if(flow_interface_mode==2) {
    assert(product_packet_set_terminal(lease,PRODUCT_PACKET_INTENT_DROP_RUNTIME)==PRODUCT_PACKET_OK);
    lease->runtime_drop_reason=PRODUCT_PACKET_DROP_INVALID_ENVELOPE;
  }
  if (injected_bypass) lease->processing_bypass_reason=PRODUCT_PACKET_BYPASS_FLOW_CAPACITY;
  if (publish_inside_node && (index==0 || index==PRODUCT_POLICY_BATCH_SIZE)) publish_revision(index?3:2);
}
product_flow_entry_status_t product_flow_entry_set_decision(product_flow_runtime_t *pool,
  const product_flow_entry_t *entry,const product_flow_policy_identity_t *policy,
  uint8_t decision,uint64_t winner,uint32_t reason) {
  assert(flow_interface_mode==1 && entry==&controlled_entry);
  assert(pool==product_packet_graph_main.flow_pools[0]);
  assert(policy->generation==entry->policy_generation && policy->revision==entry->policy_revision
         && policy->snapshot_hash==entry->policy_snapshot_hash);
  ++decision_submissions;submitted_identity=*policy;submitted_winner=winner;
  submitted_reason=reason;submitted_decision=decision;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}
static const char *product_packet_graph_flow_failure(product_packet_lease_t *lease,u16 worker,
  product_flow_entry_status_t status) {
  (void)lease;(void)worker;(void)status;assert(0);return "runtime_drop";
}
void product_observation_observed(vlib_main_t *vm,const product_flow_entry_t *entry,u32 slot,
  const product_observation_attribution_t *context) {
  (void)vm;assert(flow_interface_mode==1 && entry==&controlled_entry && slot==3 && context->valid);
  assert(context->policy_generation==entry->policy_generation && context->policy_revision==entry->policy_revision);
}
void product_observation_blocked(vlib_main_t *vm,const product_owner_assignment_t *assignment,u32 uid,
  u32 network,u8 direction,u32 bytes,const product_observation_attribution_t *context) {
  (void)vm; (void)assignment; (void)uid; (void)network; (void)direction; (void)bytes; assert(context->valid);
}
static u32 *vlib_frame_vector_args(vlib_frame_t *f) { return f->vectors; }
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm,u32 index) { (void)vm; return &buffers[index]; }
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
static void vlib_get_buffers(vlib_main_t *vm,u32 *indices,vlib_buffer_t **out,u32 count) {
  for(u32 i=0;i<count;++i) out[i]=vlib_get_buffer(vm,indices[i]);
}
#endif
static void vlib_buffer_free(vlib_main_t *vm,u32 *indices,u32 count) { (void)vm; (void)indices; freed+=count; }
static void product_metadata_load(vlib_buffer_t *b,product_buffer_metadata_t *out) { *out=metadata_storage[b->index]; }
static void product_metadata_store(vlib_buffer_t *b,const product_buffer_metadata_t *value) { metadata_storage[b->index]=*value; }
static product_packet_lease_t packet_fixture(void) {
  return (product_packet_lease_t){.policy_owner_ready=1,
    .platform={.uid=17,.availability=PRODUCT_PLATFORM_UID_KNOWN,.direction=PRODUCT_PACKET_DIRECTION_OUTPUT,
      .provenance=PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE},
    .facts={.ip_family=4,.protocol=17,.l3_status=PRODUCT_PACKET_L3_COMPLETE,.l4_status=PRODUCT_PACKET_L4_COMPLETE,
      .source_port=40000,.destination_port=443,.packet_length=48}};
}
static void product_lease_from_metadata(const product_buffer_metadata_t *m,const vlib_buffer_t *b,product_packet_lease_t *out) {
  (void)m; (void)b; *out=packet_fixture();
}
int product_packet_graph_get_platform_facts(const vlib_buffer_t *b,uint64_t generation,product_platform_packet_facts_t *out) {
  (void)b; (void)generation; *out=packet_fixture().platform; return 1;
}
static void product_packet_graph_platform_facts_unknown(product_platform_packet_facts_t *p) { memset(p,0,sizeof(*p)); }
static void product_add_trace(vlib_main_t *vm,vlib_node_runtime_t *node,vlib_buffer_t *b,int stage,u64 token) {
  (void)vm; (void)node; (void)b; (void)stage; (void)token;
}
static void vlib_buffer_enqueue_to_single_next(vlib_main_t *vm,vlib_node_runtime_t *node,u32 *indices,u32 next,u32 count) {
  (void)vm; (void)node; (void)indices; (void)next; enqueued+=count;
}
static void product_fragment_terminal(vlib_main_t *vm,vlib_node_runtime_t *node,u32 index,
  const product_buffer_metadata_t *m,const product_packet_lease_t *lease) {
  (void)vm; (void)node; (void)index; (void)m; (void)lease; ++fragment_calls;
}
static int product_nfqueue_send_verdict(int fd,u32 queue,u32 id,u32 verdict,int flags) {
  (void)queue; (void)id; assert(fd==123 && !flags); ++native_send_calls; native_verdict=verdict;
  product_root_nfqueue_last_send_result=native_send_success?32:-1;
  product_root_nfqueue_last_errno=native_send_success?0:EIO; return native_send_success;
}
'''

flag_wrappers = r'''
static void project_metadata(product_buffer_metadata_t *out,product_packet_result_t policy_result,
  product_packet_graph_policy_evaluation_t evaluation) {
  product_buffer_metadata_t metadata=*out;
''' + metadata_flag + r'''
  *out=metadata;
}
static void project_completion(vlib_main_t *vm,product_buffer_metadata_t metadata,
  const product_packet_lease_t *input,product_packet_completion_frame_t *out) {
  vlib_node_runtime_t storage={0}, *node=&storage;
  u32 buffer_index=0;
  product_packet_lease_t lease=*input;
  product_packet_completion_frame_t completion=*out;
  for(unsigned once=0;once<1;++once) {
''' + fragment_guard + "\n" + completion_flag + r'''
  }
  *out=completion;
}
'''

suffix = r'''
static void reset_graph(void) {
  product_packet_graph_main_t *g=&product_packet_graph_main;
  memset(g,0,sizeof(*g)); memset(product_packet_batch_stats,0,sizeof(product_packet_batch_stats));
  g->generation=7; g->flow_pools_initialized=1;
  product_l4_policy_rule_t rule=source_rule(PRODUCT_L4_POLICY_ACTION_ALLOW);
  assert(product_l4_policy_compile(&g->l4_policy_banks[0].view,&rule,1)==0);
  g->l4_policy_banks[0].generation=7;g->l4_policy_banks[0].revision=1;g->l4_policy_banks[0].snapshot_hash=101;
  atomic_store(&wait_enabled,0); atomic_store(&wait_seen,0); atomic_store(&writer_done,0);
  atomic_store(&delayed_claim,0); atomic_store(&claim_seen,0); atomic_store(&claim_resume,0);
  atomic_store(&retired_destroyed,0); policy_calls=enqueued=freed=fragment_calls=publish_inside_node=injected_bypass=0;
  flow_interface_mode=flow_observe_calls=decision_submissions=0;
  memset(&controlled_entry,0,sizeof(controlled_entry));memset(&submitted_identity,0,sizeof(submitted_identity));
  submitted_winner=submitted_reason=submitted_decision=0;
}
static void *writer(void *unused) { (void)unused; publish_revision(3); atomic_store(&writer_done,1); return NULL; }
static void *reader(void *argument) { product_policy_snapshot_acquire(&product_packet_graph_main,argument); return NULL; }
static void reader_protection(void) {
  reset_graph(); product_packet_graph_main_t *g=&product_packet_graph_main;
  product_policy_snapshot_t held, current;
  g->l4_policy_banks[0].domains=(product_domains_t *)&retired_domain_marker;
  product_policy_snapshot_acquire(g,&held); retired_bank=held.bank_index;
  publish_revision(2); atomic_store(&wait_enabled,1);
  pthread_t thread; assert(!pthread_create(&thread,NULL,writer,NULL));
  while(!atomic_load(&wait_seen)) { assert(!atomic_load(&writer_done)); sched_yield(); }
  assert(!atomic_load(&writer_done) && !atomic_load(&retired_destroyed));
  assert(held.bank->revision==1 && held.identity.revision==1 && g->l4_policy_bank_readers[retired_bank]==1);
  product_policy_snapshot_acquire(g,&current);
  assert(current.identity.revision==2); product_policy_snapshot_release(g,&current);
  product_policy_snapshot_release(g,&held); assert(!pthread_join(thread,NULL));
  assert(atomic_load(&writer_done) && atomic_load(&retired_destroyed)==1);
  product_policy_snapshot_acquire(g,&current);
  assert(current.identity.revision==3 && current.bank->revision==3);
  product_policy_snapshot_release(g,&current);
  assert(!g->l4_policy_bank_readers[0] && !g->l4_policy_bank_readers[1] && !g->policy_writer_lock);

  /* The actual SC validation must reject a claim delayed across two switches,
   * even when the bank index returns to the same value. */
  reset_graph(); atomic_store(&delayed_claim,1);
  assert(!pthread_create(&thread,NULL,reader,&current));
  while(!atomic_load(&claim_seen)) sched_yield();
  publish_revision(2); publish_revision(3); atomic_store(&claim_resume,1);
  assert(!pthread_join(thread,NULL));
  assert(current.identity.revision==3 && current.sequence==4 && current.bank_index==0);
  product_policy_snapshot_release(g,&current);
  assert(!g->l4_policy_bank_readers[0] && !g->l4_policy_bank_readers[1]);
}
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
static void bounded_node(void) {
  reset_graph(); assert(PRODUCT_POLICY_BATCH_SIZE==16);
  vlib_main_t vm={.thread_index=1};vlib_node_runtime_t node_runtime={0};vlib_frame_t frame={.n_vectors=33};
  for(u32 i=0;i<frame.n_vectors;++i) {
    frame.vectors[i]=i; buffers[i].index=i;
    metadata_storage[i]=(product_buffer_metadata_t){.generation=7};
  }
  publish_inside_node=1;
  assert(product_packet_policy_node(&vm,&node_runtime,&frame)==33);
  assert(policy_calls==33 && enqueued==33 && !freed);
  for(u32 i=0;i<33;++i) {
    assert(revisions[i]==1+i/16 && (metadata_storage[i].reserved_bits & 1U));
  }
  assert(product_packet_batch_stats[1].policy_claims==3);
  assert(product_packet_graph_main.policy_workers[0].acquired==33);
  assert(product_packet_graph_main.policy_workers[0].released==33);
  assert(!product_packet_graph_main.l4_policy_bank_readers[0] && !product_packet_graph_main.l4_policy_bank_readers[1]);
  frame.n_vectors=0; assert(product_packet_policy_node(&vm,&node_runtime,&frame)==0);
  assert(product_packet_batch_stats[1].policy_claims==3);
  /* Every item may take the early stale-generation continue; the final claim
   * still has to be released. The 17th item also exercises a partial window. */
  reset_graph(); frame.n_vectors=17;
  for(u32 i=0;i<17;++i) metadata_storage[i].generation=6;
  product_packet_graph_main.lifecycle_buffers=product_packet_graph_main.lifecycle_obligations=17;
  assert(product_packet_policy_node(&vm,&node_runtime,&frame)==17);
  assert(freed==17 && !policy_calls && !enqueued && product_packet_batch_stats[1].policy_claims==2);
  assert(!product_packet_graph_main.l4_policy_bank_readers[0] && !product_packet_graph_main.l4_policy_bank_readers[1]);
}
#endif
static void complete_fixture(product_packet_graph_policy_evaluation_t evaluation,product_packet_result_t result,
  product_packet_lease_t lease,u32 fragment_count,int send_ok,int force_member) {
  product_root_nfqueue_main_t *nm=&product_root_nfqueue_main;
  memset(nm,0,sizeof(*nm)); nm->generation=7;nm->lane_count=1;
  product_root_nfqueue_lane_t *lane=&nm->lanes[0];
  lane->generation=7;lane->worker_index=0;lane->fd=123;lane->socket_ready=1;
  u32 pool_buffers[PRODUCT_ROOT_RECEIVE_TOTAL];
  for(u32 i=0;i<PRODUCT_ROOT_RECEIVE_TOTAL;++i) pool_buffers[i]=100+i;
  assert(product_root_receive_pool_init(&lane->receive_pool,7,pool_buffers));
  u16 slot=product_root_receive_pool_take(&lane->receive_pool,7,0);u32 buffer_index=pool_buffers[slot];
  product_packet_completion_frame_t completion={.obligation={.token=17,.queue_generation=7,.packet_id=3,
    .kind=PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE,.origin_worker=0},.producer_thread=1,
    .terminal_intent=lease.terminal_intent==PRODUCT_PACKET_INTENT_NONE?PRODUCT_PACKET_INTENT_PASS_ADAPTER:lease.terminal_intent,
    .runtime_drop_reason=lease.runtime_drop_reason,.processing_bypass_reason=lease.processing_bypass_reason};
  product_buffer_metadata_t metadata={.fragment_bundle_count=fragment_count,.reserved_bits=14};
  project_metadata(&metadata,result,evaluation);
  assert((metadata.reserved_bits & ~3U)==12);
  unsigned expected_qualified=result==PRODUCT_PACKET_OK && evaluation.policy_qualified;
  assert(!!(metadata.reserved_bits & 1U)==expected_qualified);
  assert(!!(metadata.reserved_bits & 2U)==(expected_qualified && evaluation.matched));
  vlib_main_t vm={.thread_index=1};
  project_completion(&vm,metadata,&lease,&completion);
  unsigned qualified=!!(completion.flags & PRODUCT_COMPLETION_POLICY_QUALIFIED);
  unsigned matched=!!(completion.flags & PRODUCT_COMPLETION_POLICY_QUALIFIED_MATCHED);
  assert(!matched || qualified);
  if(fragment_count) assert(!qualified && !matched && fragment_calls);
  else assert(qualified==expected_qualified && matched==(expected_qualified && evaluation.matched));
  if(force_member) completion.flags|=PRODUCT_COMPLETION_POLICY_QUALIFIED|
    PRODUCT_COMPLETION_POLICY_QUALIFIED_MATCHED|PRODUCT_COMPLETION_FRAGMENT_MEMBER;
  product_root_nfqueue_pending_t *pending=&lane->pending[3];
  pending->completion=completion;pending->active=1;pending->buffer_index=buffer_index;pending->receive_slot=slot;
  lane->pending_count=nm->pending_count=1;native_send_success=send_ok;native_send_calls=0;
  assert(product_root_nfqueue_complete_from_graph(&vm,buffer_index,&completion)==1);
  assert(native_send_calls==1 && !lane->receive_pool.outstanding && lane->receive_returns==1);
  assert(lane->policy_qualified_succeeded==(u64)(qualified && send_ok && !force_member));
  u64 expected_allow=qualified && matched && send_ok && !force_member && native_verdict==NF_ACCEPT;
  u64 expected_drop=qualified && matched && send_ok && !force_member && native_verdict==NF_DROP;
  assert(lane->policy_qualified_matched_allow_succeeded==expected_allow);
  assert(lane->policy_qualified_matched_drop_succeeded==expected_drop);
  assert(expected_allow+expected_drop<=lane->policy_qualified_succeeded);
  assert(lane->verdict_succeeded==(u64)send_ok && lane->verdict_failed==(u64)!send_ok);
  assert(nm->verdict_failed_definite==(u64)!send_ok);
  assert(!lane->pending_count && !nm->pending_count && !pending->active);
  assert(native_verdict==(completion.terminal_intent==PRODUCT_PACKET_INTENT_PASS_ADAPTER?NF_ACCEPT:NF_DROP));
  assert(product_root_nfqueue_complete_from_graph(&vm,buffer_index,&completion)==0);
  assert(native_send_calls==1 && lane->duplicate_completion_drops==1);
  assert(lane->policy_qualified_matched_allow_succeeded==expected_allow);
  assert(lane->policy_qualified_matched_drop_succeeded==expected_drop);
}
static void qualification(void) {
  vlib_main_t vm={.thread_index=1};
  for(unsigned scenario=0;scenario<13;++scenario) {
    reset_graph(); product_packet_graph_main_t *g=&product_packet_graph_main;
    product_packet_lease_t lease=packet_fixture(); product_packet_graph_policy_evaluation_t evaluation;
    product_l4_policy_rule_t rule=source_rule(scenario==1?PRODUCT_L4_POLICY_ACTION_DROP:PRODUCT_L4_POLICY_ACTION_ALLOW);
    if(scenario==2) rule.protocol=6; /* Subject exists, but this packet has NoRule. */
    assert(product_l4_policy_compile(&g->l4_policy_banks[0].view,&rule,1)==0);
    if(scenario==3) lease.platform.uid=18;
    if(scenario==4) lease.platform.availability=0;
    if(scenario==5) assert(product_l4_policy_compile(&g->l4_policy_banks[0].view,NULL,0)==0);
    if(scenario==6) lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
    if(scenario==7) lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
    if(scenario==8) lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED;
    if(scenario==9) injected_bypass=1;
    if(scenario==10) {lease.terminal_intent=PRODUCT_PACKET_INTENT_DROP_RUNTIME;lease.runtime_drop_reason=PRODUCT_PACKET_DROP_INVALID_ENVELOPE;}
    if(scenario==11) g->l4_policy_banks[0].generation=8;
    if(scenario==12) g->l4_policy_banks[0].revision=0;
    product_policy_snapshot_t snapshot;product_policy_snapshot_acquire(g,&snapshot);
    product_packet_result_t result=product_packet_graph_policy_on_owner(&vm,0,&lease,&evaluation,0
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
      ,&snapshot
#endif
      );
    assert(result==PRODUCT_PACKET_OK);
    assert(evaluation.policy_qualified==(scenario<3));
    if(scenario==1) assert(lease.terminal_intent==PRODUCT_PACKET_INTENT_DROP_RUNTIME && lease.runtime_drop_reason==PRODUCT_PACKET_DROP_POLICY_L4);
    if(scenario==2) assert(!evaluation.matched && !lease.terminal_intent);
    if(scenario>=3 && scenario<=5) assert(policy_calls==1); /* Early NoMatch still maintains Flow. */
    product_policy_snapshot_release(g,&snapshot);
    complete_fixture(evaluation,result,lease,0,1,0);
    if(scenario==0 || scenario==1) complete_fixture(evaluation,result,lease,0,0,0);
    if(scenario==0) {
      complete_fixture(evaluation,result,lease,2,1,0);
      complete_fixture(evaluation,result,lease,0,1,1);
    }
  }
}
static product_packet_result_t invoke_owner(u32 buffer_index,product_packet_lease_t *lease,
  product_packet_graph_policy_evaluation_t *evaluation) {
  vlib_main_t vm={.thread_index=1};product_policy_snapshot_t snapshot;
  product_policy_snapshot_acquire(&product_packet_graph_main,&snapshot);
  product_packet_result_t result=product_packet_graph_policy_on_owner(&vm,buffer_index,lease,evaluation,0
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
    ,&snapshot
#endif
    );
  product_policy_snapshot_release(&product_packet_graph_main,&snapshot);return result;
}
static void expect_flow_commit(unsigned count,u64 winner,const char *scenario) {
  if(decision_submissions!=count) {
    fprintf(stderr,"REGRESSION: %s expected %u Flow decision submissions, observed %u\n",
      scenario,count,decision_submissions);++regression_failures;return;
  }
  if(count) {
    assert(submitted_winner==winner && submitted_reason==191 && submitted_decision==PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT);
    assert(submitted_identity.generation==7 && submitted_identity.revision==1 && submitted_identity.snapshot_hash==101);
  }
}
static void flow_winner_commit(void) {
  reset_graph();flow_interface_mode=1;
  product_packet_graph_main.flow_pools[0]=(product_flow_runtime_t *)&controlled_pool;
  product_packet_lease_t lease=packet_fixture();product_packet_graph_policy_evaluation_t evaluation;
  assert(invoke_owner(0,&lease,&evaluation)==PRODUCT_PACKET_OK);
  assert(evaluation.matched && evaluation.rule_id==91 && evaluation.revision==1 && !lease.terminal_intent);
  assert(flow_observe_calls==1);expect_flow_commit(1,91,"PRE complete ALLOW on new observation");
  uint64_t hits=product_packet_graph_main.policy_workers[0].cache.hits;
  lease=packet_fixture();
  assert(invoke_owner(1,&lease,&evaluation)==PRODUCT_PACKET_OK);
  assert(product_packet_graph_main.policy_workers[0].cache.hits==hits+1);
  assert(evaluation.matched && evaluation.rule_id==91 && !lease.terminal_intent && flow_observe_calls==2);
  expect_flow_commit(2,91,"PRE complete ALLOW cache hit on a new packet");

  reset_graph();flow_interface_mode=1;
  product_packet_graph_main.flow_pools[0]=(product_flow_runtime_t *)&controlled_pool;
  product_l4_policy_rule_t dynamic=source_rule(PRODUCT_L4_POLICY_ACTION_ALLOW);
  dynamic.expression_length=2;dynamic.expression[0]=PRODUCT_EXPRESSION_CT_STATE;
  dynamic.expression[1]=PRODUCT_CT_ESTABLISHED;
  assert(product_l4_policy_compile(&product_packet_graph_main.l4_policy_banks[0].view,&dynamic,1)==0);
  lease=packet_fixture();assert(invoke_owner(0,&lease,&evaluation)==PRODUCT_PACKET_OK);
  assert(evaluation.matched && evaluation.rule_id==91 && flow_observe_calls==1);
  expect_flow_commit(1,91,"POST winner commits once after Flow facts");

  reset_graph();flow_interface_mode=2;
  product_packet_graph_main.flow_pools[0]=(product_flow_runtime_t *)&controlled_pool;
  lease=packet_fixture();assert(invoke_owner(0,&lease,&evaluation)==PRODUCT_PACKET_OK);
  assert(flow_observe_calls==1 && lease.terminal_intent==PRODUCT_PACKET_INTENT_DROP_RUNTIME);
  expect_flow_commit(0,0,"failed Flow observation has no borrowed entry");

  reset_graph();flow_interface_mode=1;
  product_l4_policy_rule_t drop=source_rule(PRODUCT_L4_POLICY_ACTION_DROP);
  assert(product_l4_policy_compile(&product_packet_graph_main.l4_policy_banks[0].view,&drop,1)==0);
  lease=packet_fixture();assert(invoke_owner(0,&lease,&evaluation)==PRODUCT_PACKET_OK);
  assert(evaluation.matched && evaluation.rule_id==91 && lease.runtime_drop_reason==PRODUCT_PACKET_DROP_POLICY_L4);
  assert(!flow_observe_calls);expect_flow_commit(0,0,"complete PRE DROP does not create a Flow");
  assert(!regression_failures);
}
int main(void) {
  reader_protection();
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
  bounded_node();
#endif
  qualification();
  flow_winner_commit();
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
  puts("PASS actual policy/Root code: 16-packet revision windows, bank readers, PRE/cache-hit and POST winner commits, qualified/matched ALLOW/DROP verdicts, fragments, replay and failed-send pool return");
#else
  puts("PASS actual baseline policy/Root code: bank readers, PRE/cache-hit and POST winner commits, qualified/matched ALLOW/DROP verdicts, fragments, replay and failed-send pool return");
#endif
}
'''

vlib_stub = r'''
#ifndef POLICY_TEST_VLIB_STUB_H
#define POLICY_TEST_VLIB_STUB_H
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef int16_t i16;
typedef uint32_t u32; typedef uint64_t u64; typedef unsigned long uword;
#define VLIB_FRAME_SIZE 256
typedef struct { u32 thread_index; } vlib_main_t;
typedef struct { u32 node_index; } vlib_node_runtime_t;
typedef struct { u32 n_vectors, vectors[VLIB_FRAME_SIZE]; } vlib_frame_t;
typedef struct { u32 index; } vlib_buffer_t;
#endif
'''

with tempfile.TemporaryDirectory(prefix="sakamoto-policy-batch-") as temporary:
    directory = Path(temporary)
    (directory / "vlib").mkdir()
    (directory / "vlib/vlib.h").write_text(vlib_stub)
    test = directory / "test.c"
    code = prefix + private_types + hooks + snapshot_code + publisher + stubs + projection + flow_commit + stage + owner
    code += function(GRAPH, "product_metadata_set_terminal_intent", "static void")
    test.write_text(code + node + flag_wrappers + completion + suffix)
    failures = []
    for experiment in (False, True):
        binary = directory / ("test-batch" if experiment else "test-baseline")
        definitions = ["-DSAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT=1"] if experiment else []
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread", *definitions,
                        "-I" + str(directory), "-I" + str(ROOT / "src/product/include"),
                        "-I" + str(ROOT / "src/product/vpp"), str(test),
                        str(ROOT / "src/product/vpp/product_l4_policy.c"),
                        str(ROOT / "src/product/vpp/product_packet.c"), "-o", str(binary)], check=True)
        result = subprocess.run([str(binary)], timeout=10)
        if result.returncode:
            failures.append(binary.name)
    if failures:
        raise SystemExit("policy batch semantic regression failed: " + ", ".join(failures))
