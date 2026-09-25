#!/usr/bin/env python3
"""Audit the S209 mutation/snapshot boundary; real concurrency is verified on wire."""
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[2]
graph=(ROOT/'src/product/vpp/product_packet_graph.c').read_text()
entry=(ROOT/'src/product/vpp/product_flow_entry.c').read_text()
header=(ROOT/'src/product/vpp/product_flow_entry.h').read_text()
plugin=(ROOT/'src/product/vpp/product_core_plugin.c').read_text()
def body(name):
 m=re.search(r'\n'+name+r' \([^;]*?\n\{',graph,re.S);assert m,name
 start=m.end();level=1
 for i in range(start,len(graph)):
  level+=(graph[i]=='{')-(graph[i]=='}')
  if level==0:return graph[start:i]
 raise AssertionError('unclosed function '+name)
for name in ['product_packet_graph_policy_stage_snapshot','product_packet_graph_flow_observe','product_packet_graph_l4_view_evaluate']:
 f=body(name);assert 'policy_writer_lock' not in f,name
f=body('product_packet_graph_flow_observe')
assert 'vlib_get_worker_index (vm->thread_index)' in f and 'flow_pools[worker]' in f
assert 'clib_atomic' not in f and '__atomic' not in f
assert 'product_owner_assign' not in f and 'flow_pools[owner]' not in f
assert 'evaluation->generation' in f and 'evaluation->revision' in f and 'evaluation->snapshot_hash' in f
for forbidden in ['pthread','mutex','spinlock','__atomic','clib_atomic','publish_revision','active_policy_revision']:
 assert forbidden not in entry and forbidden not in header,forbidden
for field in ['policy_generation == policy->generation','policy_revision == policy->revision','policy_snapshot_hash == policy->snapshot_hash']:
 assert field in entry,field
publish=body('product_packet_graph_publish_policy_bundle')
assert 'flow_pools[' not in publish and 'flow_pools_flush' not in publish and 'product_flow_entry_' not in publish
assert publish.index('l4_policy_bank_readers[inactive_bank]')<publish.index('bank->view = compiled_view')<publish.index('sequence + 1U')<publish.index('l4_policy_active_bank, inactive_bank')
assert '__ATOMIC_SEQ_CST' in publish
claim=body('product_policy_snapshot_acquire');release=body('product_policy_snapshot_release')
assert 'snapshot->position = PRODUCT_L4_POLICY_POSITION_ALL' in claim, 'public complete-view callers require an initialized selector'
assert claim.index('__atomic_fetch_add')<claim.index('snapshot->bank =') and '__ATOMIC_SEQ_CST' in claim and '__ATOMIC_SEQ_CST' in release
owner=body('product_packet_graph_policy_on_owner')
assert owner.index('product_policy_snapshot_acquire') < owner.index('product_packet_graph_flow_observe') < owner.index('product_packet_graph_policy_stage_snapshot') < owner.rindex('product_packet_graph_flow_observe') < owner.index('product_policy_snapshot_release')
assert 'if (post_flow)' in owner
assert 'early.evaluation == PRODUCT_L4_POLICY_EVALUATION_NO_MATCH' in owner
assert 'result == PRODUCT_PACKET_OK && !post_flow' in owner
assert 'PRODUCT_L4_POLICY_POSITION_PRE' in owner and 'PRODUCT_L4_POLICY_POSITION_POST' in owner
assert 'lease->terminal_intent == PRODUCT_PACKET_INTENT_NONE' in owner
assert 'early_winner) matched_view = *early_winner' in body('product_packet_graph_policy_stage_snapshot')
stage=body('product_packet_graph_policy_stage_snapshot')
assert 'product_packet_graph_policy_gate_drop' not in graph
assert 'product_policy_snapshot_acquire' not in stage and 'policy_publish_sequence' not in stage
assert 'gate_table;' not in graph
assert re.search(r'VL_API_PRODUCT_CORE_POLICY_BUNDLE_APPLY, 1',plugin)
assert 'policy_packet_lock_acquisitions' in body('product_packet_graph_policy_writer_lock')
print('S209 current-worker counters, no Flow locks, immutable reader lifetime and writer-only publication audit: PASS')
