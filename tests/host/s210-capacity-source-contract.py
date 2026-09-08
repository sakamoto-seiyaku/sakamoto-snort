#!/usr/bin/env python3
"""Audit retained ownership and the real diagnostic-capacity branch boundary."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
graph = (ROOT/'src/product/vpp/product_packet_graph.c').read_text()
packet = (ROOT/'src/product/vpp/product_packet.c').read_text()
adapter = (ROOT/'src/product/vpp/product_root_nfqueue_adapter.c').read_text()


def body(source, name):
    match = re.search(r'\n'+name+r' \([^;]*?\n\{',source,re.S)
    assert match, name
    start, depth = match.end(), 1
    for i in range(start,len(source)):
        depth += (source[i]=='{')-(source[i]=='}')
        if not depth: return source[start:i]
    raise AssertionError(name)


primary = body(graph,'product_primary_handoff')
assert primary.count('vlib_buffer_enqueue_to_thread_retained (') == 1
assert 'graph->primary_frame_queue' in primary and 'ASSERT (failed == bi)' in primary
assert primary.index('product_handoff_credit_reserve') < primary.index('vlib_buffer_enqueue_to_thread_retained') < primary.index('product_handoff_credit_release')
for forbidden in ('vlib_buffer_free', 'product_owner_assign', 'product_packet_graph_policy', 'sleep', 'spill'):
    assert forbidden not in primary, forbidden
assert 'PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED' in primary
assert 'PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED' in primary
bypass = body(packet,'product_packet_bypass_primary_capacity')
assert 'PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE' in bypass
assert 'PRODUCT_PACKET_L4_FRAGMENT' in bypass and 'lease->terminal_count' in bypass
assert 'PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS' in bypass
assert 'PRODUCT_PACKET_INTENT_PASS_ADAPTER' not in bypass and 'policy_owner_ready = 1' not in bypass
returned = body(graph,'product_completion_return_try')
assert 'vlib_buffer_enqueue_to_thread_retained' in returned and 'vlib_buffer_free' not in returned
retained = body(graph,'product_completion_return')
assert 'queue->buffers[' in retained and 'queue->count < PRODUCT_COMPLETION_RETURN_CAPACITY' in retained
assert 'PRODUCT_COMPLETION_RETURN_CAPACITY >' in graph and 'PRODUCT_GRAPH_INJECTION_CAPACITY' in graph
origin = body(adapter,'product_root_nfqueue_complete_from_graph')
assert 'capacity_bypass' in origin and 'PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS' in origin
assert 'completion->runtime_drop_reason == PRODUCT_PACKET_DROP_NONE' in origin
assert origin.index('pending->active = 0') < origin.index('product_nfqueue_send_verdict')
assert origin.count('product_nfqueue_send_verdict (') == 1
fixture = body(graph,'product_capacity_cli')
assert 'lifecycle_obligations' in fixture and 'completion_pending_returns' in fixture and 'product_capacity_ring_empty' in fixture
reset = body(graph,'product_packet_graph_start_external')
assert 'product_capacity_configure_empty (graph, PRODUCT_GRAPH_HANDOFF_CREDITS, 64, 128)' in reset
ring = body(graph,'product_capacity_set_empty_ring')
assert 'fq->head == fq->tail' in ring and 'fq->nelts = slots' in ring
assert 'vlib_buffer_enqueue_to_thread_retained_fn' in (ROOT/'src/product/vpp/patches/core/0001-vlib-nonblocking-retained-enqueue.patch').read_text()
print('S210 real credit/ring rejection, caller-retained buffer, guarded Root bypass, reserved DROP return, default reset: PASS')
