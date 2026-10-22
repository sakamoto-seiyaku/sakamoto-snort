#!/usr/bin/env python3
"""Execute Product external batch submission and both single-item implementations.

The production functions and inline metadata types are compiled verbatim. Only
native buffers, frame publication, thread mapping, graph storage and startup
policy/pool initialization are supplied by this harness. Actual startup and stop
functions run with the Host evidence configuration. The actual origin helper uses a validated generation snapshot while tracked
startup getenv calls are forbidden during packet admission. This checks
scheduling ownership, not policy or device delivery.
"""

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/product/vpp/product_packet_graph.c"
HEADER = ROOT / "src/product/vpp/product_packet_graph.h"


def function(source: str, name: str) -> str:
    """Keep the complete actual function, including its preprocessor branches."""
    match = re.search(r"\n(?:static )?(?:void|int|u32)\s+" + re.escape(name)
                      + r"\s*\(", source)
    if match is None:
        raise RuntimeError(f"Missing production function: {name}")
    begin = match.start() + 1
    opening = source.index("{", match.end())
    depth = 1
    end = opening + 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[begin:end] + "\n"


source = SOURCE.read_text()
header = HEADER.read_text()
metadata_begin = source.index("enum\n{\n  PRODUCT_META_ADMITTED")
metadata_end = source.index("_Static_assert (sizeof (product_packet_completion_frame_t)", metadata_begin)
item_end = header.index("} product_packet_graph_external_item_t;")
item_begin = header.rfind("typedef struct", 0, item_end)
types = source[metadata_begin:metadata_end] + header[item_begin:item_end + len("} product_packet_graph_external_item_t;")]

prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "product_packet.h"
#include "product_runtime_topology.h"
typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef uint64_t u64;
#if TEST_BATCH
#define SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT 1
#endif
#if TEST_TCP_BATCH
#define SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT 1
#endif
#define PRODUCT_GRAPH_WORKERS 3
#define PRODUCT_VPN_RETURN_WORKERS 3
#define SAKAMOTO_PRODUCT_HOST_EVIDENCE 1
#define VLIB_FRAME_SIZE 256
#define ASSERT assert
#define clib_atomic_store_rel_n(p,n) __atomic_store_n((p),(n),__ATOMIC_RELEASE)
#define clib_warning(...) ((void)0)
#define PRODUCT_FLOW_END_DISCRIMINANT 0x80
#define PREDICT_FALSE(x) (x)
#define clib_memset memset
#define clib_memcpy_fast memcpy
#define clib_atomic_load_acq_n(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add((p),(n),__ATOMIC_RELAXED)
#define clib_panic(message) do { fputs((message), stderr); abort(); } while (0)
typedef struct { u32 thread_index; } vlib_main_t;
typedef struct { u32 node_index; } vlib_node_runtime_t;
typedef struct { u32 n_vectors, vectors[VLIB_FRAME_SIZE]; } vlib_frame_t;
typedef struct { u8 opaque[40], opaque2[56]; } vlib_buffer_t;
typedef struct { unsigned active; } product_dns_owner_t;
typedef struct { u64 codec_live_bytes, active_operations; } product_dns_resources_t;
typedef struct {
  vlib_main_t *vlib_main;
  u64 generation, trace_packets, trace_limit;
  u32 enabled, accepting, lifecycle_buffers, lifecycle_obligations, owner_count;
  product_adapter_obligation_kind_t adapter_kind;
  u32 lifecycle_handoffs, lifecycle_completion_frames, flow_capacity;
  u32 policy_hold_next_us[4], l4_policy_bank_readers[2], l4_policy_banks[2];
  u32 l4_policy_active_bank, policy_publish_sequence, l4_policy_view_active;
  u32 lifecycle_terminal_intents, lifecycle_settlements, lifecycle_returns;
  product_dns_owner_t dns_requests[PRODUCT_GRAPH_WORKERS];
} product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main;
static unsigned dns_stops;
static u32 product_packet_graph_worker_count(void) { return product_packet_graph_main.owner_count; }
static void product_dns_owner_stop(product_dns_owner_t *owner) { owner->active=0; ++dns_stops; }
static product_dns_resources_t product_dns_resources(void) { return (product_dns_resources_t){0}; }
#if TEST_BATCH
static u32 product_packet_batch_stats[4];
#endif
static struct { u32 index; } product_packet_admit_node = { 19 };
static vlib_buffer_t storage[VLIB_FRAME_SIZE + 16];
static vlib_frame_t published_frame;
static unsigned gets, frame_allocations, publications, forbidden_calls;
static unsigned topology_reads, packet_phase;
char *topology_getenv(const char *name) {
  ++topology_reads;
  assert(!packet_phase && "packet admission reparsed startup environment");
  return getenv(name);
}
static u32 configured_owners = 2, actual_workers;
static u32 vlib_num_workers(void) { return actual_workers; }
static u64 product_flow_end_buffer_debt(void) { return 0; }
static int product_vpn_tun_product_mode(void) { return 0; }
static int product_packet_graph_flow_pools_reset(product_packet_graph_main_t *g) { (void)g; return 1; }
static void product_policy_domains_clear(product_packet_graph_main_t *g) { (void)g; }
static void product_packet_graph_flow_pools_abort(product_packet_graph_main_t *g) { (void)g; }
static int product_core_policy_start(u64 generation) { assert(generation); return 1; }
static void product_flow_end_quiesce(vlib_main_t *vm) { assert(vm); }
static void product_observation_quiesce(void) {}
static u64 product_packet_graph_buffer_debt(void) { return product_packet_graph_main.lifecycle_buffers; }
static void product_packet_graph_policy_writer_lock(product_packet_graph_main_t *g) { (void)g; }
static void product_packet_graph_policy_writer_unlock(product_packet_graph_main_t *g) { (void)g; }
static void product_packet_graph_flow_pools_flush(product_packet_graph_main_t *g) { (void)g; }
#define EXPECTED_GETS (TEST_BATCH ? 1U : 3U)
#if !TEST_BATCH
static u32 vlib_get_thread_index(void) { return 0; }
#endif
static u32 vlib_get_worker_thread_index(u32 worker) {
  assert(worker <= PRODUCT_GRAPH_WORKERS);
  return 3 + 2 * worker;
}
static u32 vlib_get_worker_index(u32 thread) {
  assert(thread == 3 || thread == 5 || thread == 7 || thread == 9);
  return (thread - 3) / 2;
}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm, u32 index) {
  assert(vm && index < VLIB_FRAME_SIZE + 16);
  ++gets;
  return &storage[index];
}
static vlib_frame_t *vlib_get_frame_to_node(vlib_main_t *vm, u32 node) {
  assert(vm && node == product_packet_admit_node.index);
  assert(++frame_allocations == 1);
  return &published_frame;
}
static u32 *vlib_frame_vector_args(vlib_frame_t *frame) {
  assert(frame == &published_frame);
  return frame->vectors;
}
static void vlib_put_frame_to_node(vlib_main_t *, u32, vlib_frame_t *);
static void forbidden_call(const char *operation) {
  ++forbidden_calls;
  fprintf(stderr, "unexpected synchronous %s\n", operation);
  abort();
}
#define vlib_buffer_free(...) forbidden_call("free")
#define vlib_buffer_free_no_next(...) forbidden_call("free")
#define product_packet_graph_policy_stage(...) forbidden_call("policy")
#define product_packet_graph_policy_stage_snapshot(...) forbidden_call("policy")
#define product_packet_graph_policy_evaluate(...) forbidden_call("policy")
#define product_root_nfqueue_complete_from_graph(...) forbidden_call("Root completion")
#define product_vpn_tun_complete_from_graph(...) forbidden_call("VPN completion")
static vlib_frame_t native_frames[4];
static u32 native_frame_index, native_get_position, native_gets, native_puts, native_seen, native_ordinal, native_incremental, native_callback_active;
static void verify_native_publish(const u32 *, u32);
static void test_native_get(vlib_main_t *vm, vlib_node_runtime_t *node,
  u32 next, u32 **to, u32 *left) {
  assert(vm && node && node->node_index == 19 && next == 2 && native_callback_active);
  ++native_gets;
  if (native_frames[native_frame_index].n_vectors == VLIB_FRAME_SIZE)
    assert(++native_frame_index < 4);
  vlib_frame_t *frame = &native_frames[native_frame_index];
  native_get_position = frame->n_vectors;
  *to = frame->vectors + frame->n_vectors;
  *left = VLIB_FRAME_SIZE - frame->n_vectors;
}
static void test_native_put(vlib_main_t *vm, vlib_node_runtime_t *node,
  u32 next, u32 left) {
  assert(vm && node && next == 2 && left <= VLIB_FRAME_SIZE);
  vlib_frame_t *frame = &native_frames[native_frame_index];
  frame->n_vectors = VLIB_FRAME_SIZE - left;
  assert(frame->n_vectors >= native_get_position);
  verify_native_publish(frame->vectors + native_get_position,
                        frame->n_vectors - native_get_position);
  ++native_puts;
}
#define static_always_inline static inline
#define PREDICT_TRUE(x) (x)
#define clib_min(a,b) ((a)<(b)?(a):(b))
#define vlib_buffer_copy_indices(to,from,n) memcpy((to),(from),(n)*sizeof(u32))
#define vlib_get_next_frame(vm,node,next,to,left) test_native_get((vm),(node),(next),&(to),&(left))
#define vlib_get_next_frame_with_aux(vm,node,next,to,aux,left) do { \
  vlib_get_next_frame(vm,node,next,to,left); (aux)=(to); } while(0)
#define vlib_put_next_frame(vm,node,next,left) test_native_put((vm),(node),(next),(left))
static void vlib_buffer_enqueue_to_single_next(vlib_main_t *,
  vlib_node_runtime_t *, u32 *, u16, u32);
'''

dependencies = "\n".join(function(source, name) for name in (
    "product_metadata_load", "product_metadata_store",
    "product_packet_graph_set_platform_facts",
    "product_packet_graph_origin_valid", "product_packet_graph_start_external",
    "product_packet_graph_stop_external"))
production = "\n".join(function(source, name) for name in (
    "product_packet_graph_submit_external_batch_internal",
    "product_packet_graph_submit_external_batch", "product_packet_graph_submit_external",
    "product_packet_graph_submit_vpn_return_next"))

native_path = os.environ.get("SAKAMOTO_TEST_VPP_BUFFER_FUNCS")
native_source = ""
if native_path:
    native_source = Path(native_path).read_text()
    name = "vlib_buffer_enqueue_to_single_next_fn_inline"
    begin = native_source.rfind("static_always_inline", 0, native_source.index(name))
    opening = native_source.index("{", native_source.index(name))
    depth, end = 1, opening + 1
    while depth:
        depth += (native_source[end] == "{") - (native_source[end] == "}")
        end += 1
    native_enqueue = native_source[begin:end] + r"""
static void vlib_buffer_enqueue_to_single_next(vlib_main_t *vm,
  vlib_node_runtime_t *node, u32 *buffers, u16 next, u32 count) {
  vlib_buffer_enqueue_to_single_next_fn_inline(vm,node,buffers,0,next,count,0);
}
"""
else:
    native_enqueue = r"""
static void vlib_buffer_enqueue_to_single_next(vlib_main_t *vm,
  vlib_node_runtime_t *node, u32 *buffers, u16 next, u32 count) {
  (void)vm;(void)node;(void)buffers;(void)next;(void)count;
  forbidden_call("native enqueue requires SAKAMOTO_TEST_VPP_BUFFER_FUNCS");
}
"""

suffix = r'''
static const product_packet_graph_external_item_t *expected_items;
static const u8 *expected_mask;
static const u8 *returned_mask;
static u32 expected_length, expected_count, initial_buffers, initial_obligations;

static void verify_buffer(const product_packet_graph_external_item_t *item, u32 ordinal) {
  product_buffer_platform_metadata_t saved;
  product_buffer_metadata_t metadata = {0};
  memcpy(&saved, storage[item->buffer_index].opaque, sizeof(saved));
  product_metadata_load(&storage[item->buffer_index], &metadata);
  assert(memcmp(&saved.obligation, &item->obligation, sizeof(saved.obligation)) == 0);
  assert(memcmp(&saved.platform, &item->platform, sizeof(saved.platform)) == 0);
  assert(metadata.origin_obligation_id == item->obligation.token);
  assert(metadata.generation == item->obligation.queue_generation);
  assert(metadata.state_bits == (ordinal < 2 ? PRODUCT_META_TRACE : 0));
  metadata.state_bits = 0;
  metadata.origin_obligation_id = 0;
  metadata.generation = 0;
  const product_buffer_metadata_t empty = {0};
  assert(memcmp(&metadata, &empty, sizeof(metadata)) == 0);
}

static void vlib_put_frame_to_node(vlib_main_t *vm, u32 node, vlib_frame_t *frame) {
  assert(vm && node == product_packet_admit_node.index && frame == &published_frame);
  assert(++publications == 1 && frame->n_vectors == expected_count);
  /* Publication can hand ownership to the scheduler immediately. Both debts,
   * every acceptance result and all per-item metadata must already exist. */
  assert(product_packet_graph_main.lifecycle_buffers == initial_buffers + expected_count);
  assert(product_packet_graph_main.lifecycle_obligations == initial_obligations + expected_count);
  u32 ordinal = 0;
  for (u32 i = 0; i < expected_length; ++i) {
    if (returned_mask) assert(returned_mask[i] == expected_mask[i]);
    if (expected_mask[i]) {
      assert(frame->vectors[ordinal] == expected_items[i].buffer_index);
      verify_buffer(&expected_items[i], ordinal++);
    }
  }
  assert(ordinal == expected_count);
}

static void verify_native_publish(const u32 *indices, u32 count) {
  u32 transferred=native_incremental ? native_ordinal+count : expected_count;
  assert(product_packet_graph_main.lifecycle_buffers == initial_buffers + transferred);
  assert(product_packet_graph_main.lifecycle_obligations == initial_obligations + transferred);
  for(u32 i=0;i<count;i++) {
    while(native_seen<expected_length && !expected_mask[native_seen]) ++native_seen;
    assert(native_seen<expected_length && indices[i]==expected_items[native_seen].buffer_index);
    verify_buffer(&expected_items[native_seen], native_ordinal++);
    ++native_seen;
  }
}

static void reset_kind(product_adapter_obligation_kind_t kind) {
  packet_phase = 0;
  char owners[16];
  snprintf(owners, sizeof(owners), "%u", configured_owners);
  assert(setenv("SAKAMOTO_PRODUCT_OWNER_COUNT", owners, 1) == 0);
  assert(setenv("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID", "3", 1) == 0);
  actual_workers = configured_owners + (kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
  unsigned initial_topology_reads = topology_reads;
  product_packet_graph_main = (product_packet_graph_main_t){0};
  static vlib_main_t startup_vm = {0};
  assert(product_packet_graph_start_external(&startup_vm, 7041, kind));
  assert(topology_reads > initial_topology_reads);
  assert(product_packet_graph_main.owner_count == configured_owners);
  assert(product_packet_graph_main.adapter_kind == kind);
  product_packet_graph_main.trace_limit = 2;
  product_packet_graph_main.lifecycle_buffers = 17;
  product_packet_graph_main.lifecycle_obligations = 29;
  memset(storage, 0xa5, sizeof(storage));
  memset(&published_frame, 0, sizeof(published_frame));
  gets = frame_allocations = publications = forbidden_calls = 0;
  memset(native_frames,0,sizeof(native_frames));
  native_frame_index=native_get_position=native_gets=native_puts=native_seen=native_ordinal=native_incremental=native_callback_active=0;
  expected_items = 0;
  expected_mask = returned_mask = 0;
  expected_length = expected_count = 0;
  /* A generation keeps the topology validated before publication. Mutating
   * startup configuration must neither reparse nor change packet admission. */
  assert(setenv("SAKAMOTO_PRODUCT_OWNER_COUNT", "invalid", 1) == 0);
  assert(unsetenv("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID") == 0);
  packet_phase = 1;
}

static void reset(void) { reset_kind(PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE); }

static product_packet_graph_external_item_t root_item(u32 index, u32 worker) {
  return (product_packet_graph_external_item_t) {
    .buffer_index = index,
    .platform = { .uid = 10000 + index, .linux_ifindex = 70 + index,
      .network_context_id = index % 2 ? 1 : 4, .availability = index % 8,
      .direction = index % 2 ? PRODUCT_PACKET_DIRECTION_INPUT : PRODUCT_PACKET_DIRECTION_OUTPUT,
      .provenance = PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE },
    .obligation = { .token = 90000 + index,
      .queue_generation = product_packet_graph_main.generation,
      .packet_id = 2000 + index, .origin_lane = index % 4,
      .kind = PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE, .origin_worker = worker },
  };
}

static void expect(const product_packet_graph_external_item_t *items, u32 count,
                   const u8 *mask, const u8 *accepted) {
  expected_items = items;
  expected_mask = mask;
  returned_mask = accepted;
  expected_length = count;
  expected_count = 0;
  for (u32 i = 0; i < count; ++i) expected_count += mask[i];
  initial_buffers = product_packet_graph_main.lifecycle_buffers;
  initial_obligations = product_packet_graph_main.lifecycle_obligations;
}

static void batch(vlib_main_t *vm, product_packet_graph_external_item_t *items,
                  u32 count, const u8 *mask) {
  u8 accepted[VLIB_FRAME_SIZE + 2];
  product_packet_graph_external_item_t before[VLIB_FRAME_SIZE];
  vlib_buffer_t untouched[VLIB_FRAME_SIZE + 16];
  assert(count <= VLIB_FRAME_SIZE);
  memset(accepted, 0xa5, sizeof(accepted));
  memcpy(before, items, count * sizeof(*items));
  memcpy(untouched, storage, sizeof(storage));
  expect(items, count, mask, accepted + 1);
  u32 submitted = product_packet_graph_submit_external_batch(vm, items, count, accepted + 1);
  assert(submitted == expected_count);
  assert(accepted[0] == 0xa5 && accepted[count + 1] == 0xa5);
  assert(memcmp(accepted + 1, mask, count) == 0);
  assert(memcmp(before, items, count * sizeof(*items)) == 0);
  assert(frame_allocations == !!expected_count && publications == !!expected_count);
  assert(gets == expected_count && product_packet_graph_main.trace_packets == expected_count);
  assert(product_packet_graph_main.lifecycle_buffers == initial_buffers + expected_count);
  assert(product_packet_graph_main.lifecycle_obligations == initial_obligations + expected_count);
  for (u32 index = 0; index < VLIB_FRAME_SIZE + 16; ++index) {
    int transferred = 0;
    for (u32 i = 0; i < count; ++i) transferred |= mask[i] && items[i].buffer_index == index;
    if (!transferred) assert(memcmp(&storage[index], &untouched[index], sizeof(storage[index])) == 0);
  }
  assert(forbidden_calls == 0);
}

static void mixed_root(void) {
  reset();
  vlib_main_t vm = {.thread_index = 5};
  product_packet_graph_external_item_t items[8];
  for (u32 i = 0; i < 8; ++i) items[i] = root_item(15 - i, 1);
  items[0].obligation.origin_worker = PRODUCT_GRAPH_WORKERS;
  items[2].obligation.kind = PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED;
  items[4].obligation.queue_generation--;
  items[5].obligation.token = 0;
  items[6].obligation.origin_worker = 0;
  const u8 mask[] = {0,1,0,1,0,0,0,1};
  for (u32 i = 0; i < 8; ++i) if (!mask[i]) items[i].buffer_index = UINT32_MAX;
  batch(&vm, items, 8, mask);
}

static void rejected_and_empty(void) {
  vlib_main_t vm = {.thread_index = 3};
  const u8 none[3] = {0};
  for (u32 mode = 0; mode < 5; ++mode) {
    reset();
    product_packet_graph_external_item_t items[3];
    for (u32 i = 0; i < 3; ++i) items[i] = root_item(i, 0);
    if (mode == 0) for (u32 i = 0; i < 3; ++i) items[i].obligation.token = 0;
    if (mode == 1) product_packet_graph_main.enabled = 0;
    if (mode == 2) product_packet_graph_main.accepting = 0;
    if (mode == 4) vm.thread_index = 0;
    batch(mode == 3 ? 0 : &vm, items, 3, none);
  }
  reset();
  product_packet_graph_external_item_t item = root_item(0, 0);
  vm.thread_index = 3;
  batch(&vm, &item, 0, none);
  u8 accepted[3] = {0xa5,0xa5,0xa5};
  assert(product_packet_graph_submit_external_batch(&vm, 0, 3, accepted) == 0);
  assert(product_packet_graph_submit_external_batch(&vm, &item, 1, 0) == 0);
  assert(accepted[0] == 0xa5 && accepted[1] == 0xa5 && accepted[2] == 0xa5);
  assert(gets == 0 && frame_allocations == 0 && publications == 0);
}

static void frame_bound(void) {
  reset();
  vlib_main_t vm = {.thread_index = 3};
  product_packet_graph_external_item_t items[VLIB_FRAME_SIZE + 1];
  u8 mask[VLIB_FRAME_SIZE], accepted[VLIB_FRAME_SIZE + 1];
  for (u32 i = 0; i <= VLIB_FRAME_SIZE; ++i) items[i] = root_item(i, 0);
  memset(accepted, 0xa5, sizeof(accepted));
  assert(product_packet_graph_submit_external_batch(&vm, items, VLIB_FRAME_SIZE + 1, accepted) == 0);
  for (u32 i = 0; i <= VLIB_FRAME_SIZE; ++i) assert(accepted[i] == 0xa5);
  assert(gets == 0 && frame_allocations == 0 && publications == 0);
  assert(product_packet_graph_main.lifecycle_buffers == 17);
  assert(product_packet_graph_main.lifecycle_obligations == 29);
  assert(product_packet_graph_main.trace_packets == 0);
  memset(mask, 1, sizeof(mask));
  batch(&vm, items, VLIB_FRAME_SIZE, mask);
}

static void vpn_return(void) {
  reset_kind(PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
  vlib_main_t vm = {.thread_index = 5};
  product_packet_graph_external_item_t items[8];
  for (u32 i = 0; i < 8; ++i) {
    items[i] = root_item(20 + i, 0);
    items[i].obligation.kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
    items[i].obligation.origin_worker = 2;
    items[i].obligation.packet_id = 2;
    items[i].obligation.origin_lane = 0;
    items[i].platform.provenance = PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
    items[i].platform.direction = PRODUCT_PACKET_DIRECTION_INPUT;
  }
  items[0] = root_item(20, 1);
  items[1].obligation.packet_id = 1;
  items[3].obligation.origin_lane = 1;
  items[4].obligation.kind = PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE;
  items[6].platform.direction = PRODUCT_PACKET_DIRECTION_OUTPUT;
  items[7].obligation.origin_worker = 1;
  /* A Root obligation cannot enter a VPN generation. */
  const u8 mask[] = {0,0,1,0,0,1,0,0};
  batch(&vm, items, 8, mask);
  reset_kind(PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
  items[0] = root_item(30, 0);
  items[0].obligation.kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
  items[0].obligation.origin_worker = 2;
  items[0].platform.provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  vm.thread_index = 7;
  const u8 one[] = {1};
  batch(&vm, items, 1, one);
}

static void topology_matrix(void) {
  for (configured_owners = 1; configured_owners <= 3; configured_owners += 2) {
    for (u32 vpn = 0; vpn <= 1; ++vpn) {
      for (u32 worker = 0; worker <= configured_owners + 1; ++worker) {
        reset_kind(vpn ? PRODUCT_ADAPTER_OBLIGATION_VPN_TUN
                       : PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE);
        product_packet_graph_external_item_t item = root_item(7, worker);
        item.obligation.kind = product_packet_graph_main.adapter_kind;
        if (vpn) item.platform.provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN;
        int valid = vpn ? worker == configured_owners : worker < configured_owners;
        assert(product_packet_graph_origin_valid(&product_packet_graph_main, &item.obligation) == valid);
        if (worker <= PRODUCT_GRAPH_WORKERS) {
          vlib_main_t vm = {.thread_index = vlib_get_worker_thread_index(worker)};
          u8 mask[] = {(u8)valid};
          expect(&item, 1, mask, 0);
          assert(product_packet_graph_submit_external(&vm, item.buffer_index,
                   &item.platform, &item.obligation) == valid);
          assert(publications == (u32)valid);
          assert(product_packet_graph_main.lifecycle_buffers == 17U + valid);
          assert(product_packet_graph_main.lifecycle_obligations == 29U + valid);
        }
      }
    }
    /* Every owner can produce return packets; the I/O worker cannot. */
    for (u32 worker = 0; worker <= configured_owners; ++worker) {
      reset_kind(PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
      product_packet_graph_external_item_t item = root_item(9, configured_owners);
      item.obligation.kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
      item.obligation.origin_lane = 0;
      item.obligation.packet_id = worker + 1;
      item.platform.provenance = PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
      item.platform.direction = PRODUCT_PACKET_DIRECTION_INPUT;
      vlib_main_t vm = {.thread_index = vlib_get_worker_thread_index(worker)};
      u8 mask[] = {worker < configured_owners};
      expect(&item, 1, mask, 0);
      assert(product_packet_graph_submit_external(&vm, item.buffer_index,
               &item.platform, &item.obligation) == mask[0]);
      assert(publications == mask[0] && forbidden_calls == 0);
    }
  }
  configured_owners = 2;
}

static void invalid_snapshot_and_inactive(void) {
  for (u32 mode = 0; mode < 8; ++mode) {
    reset();
    product_packet_graph_external_item_t item = root_item(7, 0);
    vlib_main_t vm = {.thread_index = 3};
    if (mode == 0) product_packet_graph_main.owner_count = 0;
    if (mode == 1) product_packet_graph_main.owner_count = PRODUCT_GRAPH_WORKERS + 1;
    if (mode == 2) {
      product_packet_graph_main.adapter_kind = PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED;
      item.obligation.kind = PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED;
    }
    if (mode == 3) product_packet_graph_main.enabled = 0;
    if (mode == 4) product_packet_graph_main.accepting = 0;
    if (mode == 5) item.obligation.queue_generation--;
    if (mode == 6) item.obligation.token = 0;
    if (mode == 7) item.obligation.kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
    if (mode <= 2 || mode == 7)
      assert(!product_packet_graph_origin_valid(&product_packet_graph_main, &item.obligation));
    assert(!product_packet_graph_origin_valid(0, &item.obligation));
    assert(!product_packet_graph_origin_valid(&product_packet_graph_main, 0));
    const u8 none[] = {0};
    batch(&vm, &item, 1, none);
    assert(product_packet_graph_submit_external(&vm, UINT32_MAX,
             &item.platform, &item.obligation) == 0);
    assert(!gets && !publications && !forbidden_calls);
    assert(product_packet_graph_main.lifecycle_buffers == 17);
    assert(product_packet_graph_main.lifecycle_obligations == 29);
  }
}

static void startup_and_restart(void) {
  vlib_main_t vm = {0}, origin = {.thread_index = 3};
  packet_phase = 0;
  /* Invalid configuration, worker mismatch and invalid API arguments fail
   * before changing even the old snapshot. */
  for (u32 mode = 0; mode < 7; ++mode) {
    product_packet_graph_main = (product_packet_graph_main_t){0};
    assert(setenv("SAKAMOTO_PRODUCT_OWNER_COUNT", mode == 0 ? "bad" : "1", 1) == 0);
    assert(setenv("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID", "3", 1) == 0);
    if (mode == 1) assert(unsetenv("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID") == 0);
    actual_workers = mode == 2 ? 1 : 2;
    if (mode == 6) product_packet_graph_main.lifecycle_buffers = 1;
    const product_packet_graph_main_t before = product_packet_graph_main;
    assert(!product_packet_graph_start_external(mode == 3 ? 0 : &vm,
      mode == 4 ? 0 : 8000, mode == 5 ? PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED
                                    : PRODUCT_ADAPTER_OBLIGATION_VPN_TUN));
    assert(memcmp(&before, &product_packet_graph_main, sizeof(before)) == 0);
  }
  configured_owners = 1;
  reset();
  product_packet_graph_external_item_t old = root_item(7, 0);
  product_packet_graph_main.lifecycle_buffers = 0;
  product_packet_graph_main.lifecycle_obligations = 0;
  packet_phase = 0;
  assert(setenv("SAKAMOTO_PRODUCT_OWNER_COUNT", "3", 1) == 0);
  assert(setenv("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID", "3", 1) == 0);
  actual_workers = 4;
  const product_packet_graph_main_t live = product_packet_graph_main;
  assert(!product_packet_graph_start_external(&vm, 8001, PRODUCT_ADAPTER_OBLIGATION_VPN_TUN));
  assert(memcmp(&live, &product_packet_graph_main, sizeof(live)) == 0);
  const u32 stopping_owners = product_packet_graph_main.owner_count;
  dns_stops=0;
  product_packet_graph_stop_external(&vm);
  assert(!product_packet_graph_main.enabled && !product_packet_graph_main.accepting);
  assert(dns_stops == stopping_owners);
  assert(product_packet_graph_start_external(&vm, 8001, PRODUCT_ADAPTER_OBLIGATION_VPN_TUN));
  assert(product_packet_graph_main.owner_count == 3);
  assert(product_packet_graph_main.generation == 8001);
  assert(product_packet_graph_main.adapter_kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
  assert(setenv("SAKAMOTO_PRODUCT_OWNER_COUNT", "bad", 1) == 0);
  assert(unsetenv("SAKAMOTO_PRODUCT_TUN_IO_CPU_ID") == 0);
  packet_phase = 1;
  assert(!product_packet_graph_submit_external(&origin, UINT32_MAX, &old.platform, &old.obligation));
  old.obligation.kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
  old.obligation.origin_worker = 3;
  origin.thread_index = 9;
  assert(!product_packet_graph_submit_external(&origin, UINT32_MAX, &old.platform, &old.obligation));
  assert(!product_packet_graph_main.lifecycle_buffers && !product_packet_graph_main.lifecycle_obligations);
  old.obligation.queue_generation = 8001;
  old.platform.provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  const u8 one[] = {1};
  expect(&old, 1, one, 0);
  assert(product_packet_graph_submit_external(&origin, old.buffer_index,
           &old.platform, &old.obligation));
  assert(publications == 1 && product_packet_graph_main.lifecycle_buffers == 1);
  assert(product_packet_graph_main.lifecycle_obligations == 1);
  configured_owners = 2;
}

#if TEST_NATIVE_ENQUEUE
static void native_return_frames(void) {
  reset_kind(PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
  vlib_main_t vm={.thread_index=3};
  vlib_node_runtime_t node={.node_index=19};
  product_packet_graph_external_item_t items[8];
  for(u32 i=0;i<8;i++) {
    items[i]=root_item(20+i,2);
    items[i].obligation.kind=PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
    items[i].obligation.origin_lane=0;items[i].obligation.packet_id=1;
    items[i].platform.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
    items[i].platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;
  }
  items[0].obligation.kind=PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE;
  items[2].obligation.queue_generation--;
  items[4].obligation.origin_worker=1;
  items[6].obligation.packet_id=2;
  const u8 mask[]={0,1,0,1,0,1,0,1};
  u8 accepted[8];expect(items,8,mask,accepted);
  native_frames[0].n_vectors=VLIB_FRAME_SIZE-2;
  native_callback_active=1;
  assert(product_packet_graph_submit_external_batch_internal(&vm,items,8,accepted,&node,2)==4);
  native_callback_active=0;
  assert(!memcmp(mask,accepted,8) && native_frames[0].n_vectors==VLIB_FRAME_SIZE);
  assert(native_frames[1].n_vectors==2 && native_gets==2 && native_puts==2);
  assert(!publications && !frame_allocations && gets==4);
  /* A producing callback appends successive single returns to the same native
   * next frame. A NULL source never falls through from return-next. */
  reset_kind(PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
  items[0]=items[1];items[0].buffer_index=7;
  const u8 one[]={1};expect(items,1,one,0);
  assert(!product_packet_graph_submit_vpn_return_next(&vm,0,2,7,&items[0].platform,&items[0].obligation));
  assert(!product_packet_graph_submit_vpn_return_next(&vm,&node,2,7,0,&items[0].obligation));
  assert(!product_packet_graph_submit_vpn_return_next(&vm,&node,2,7,&items[0].platform,0));
  assert(!native_puts && !publications && !gets);
  native_callback_active=1;
  assert(product_packet_graph_submit_vpn_return_next(&vm,&node,2,7,&items[0].platform,&items[0].obligation));
  native_callback_active=0;
  assert(native_frames[0].n_vectors==1 && native_puts==1 && !publications);
  /* The I/O worker cannot impersonate a generating FlowOwner. */
  vm.thread_index=7;
  assert(!product_packet_graph_submit_vpn_return_next(&vm,&node,2,UINT32_MAX,&items[0].platform,&items[0].obligation));
  assert(native_puts==1 && gets==1);
  for(u32 count=VLIB_FRAME_SIZE-1;count<=VLIB_FRAME_SIZE+1;count++) {
    reset_kind(PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);vm.thread_index=3;
    product_packet_graph_external_item_t returns[VLIB_FRAME_SIZE+1];
    u8 ready[VLIB_FRAME_SIZE+1];memset(ready,1,sizeof(ready));
    for(u32 i=0;i<count;i++) {
      returns[i]=items[1];returns[i].buffer_index=i;
    }
    expect(returns,count,ready,0);native_incremental=1;
    for(u32 i=0;i<count;i++) {
      native_callback_active=1;
      assert(product_packet_graph_submit_vpn_return_next(&vm,&node,2,i,&returns[i].platform,&returns[i].obligation));
      native_callback_active=0;
      assert(native_ordinal==i+1 && !publications && !frame_allocations);
    }
    assert(native_frames[0].n_vectors==(count<VLIB_FRAME_SIZE?count:VLIB_FRAME_SIZE));
    assert(native_frame_index==(count>VLIB_FRAME_SIZE));
    if(count>VLIB_FRAME_SIZE)assert(native_frames[1].n_vectors==1);
    for(u32 i=0;i<count;i++)assert(native_frames[i/VLIB_FRAME_SIZE].vectors[i%VLIB_FRAME_SIZE]==i);
    assert(gets==count && native_puts==count);
    assert(product_packet_graph_main.lifecycle_buffers==initial_buffers+count);
    assert(product_packet_graph_main.lifecycle_obligations==initial_obligations+count);
  }
  puts("PASS actual pinned VPP native enqueue: partial/full/multiple frames at255/256/257, nonprefix rejection, original index order, debt-before-put, callback scheduling without graph execution");
}
#endif

static void single_wrapper(void) {
  vlib_main_t vm = {.thread_index = 3};
  const u8 one[] = {1};
  reset();
  product_packet_graph_external_item_t item = root_item(7, 0);
  expect(&item, 1, one, 0);
  assert(product_packet_graph_submit_external(&vm, item.buffer_index, &item.platform, &item.obligation) == 1);
  assert(publications == 1 && frame_allocations == 1 && gets == EXPECTED_GETS);
  reset();
  item = root_item(8, 0);
  memset(&item.platform, 0, sizeof(item.platform));
  expect(&item, 1, one, 0);
  assert(product_packet_graph_submit_external(&vm, item.buffer_index, 0, &item.obligation) == 1);
  assert(publications == 1 && frame_allocations == 1 && gets == EXPECTED_GETS);
  reset();
  item = root_item(9, 0);
  assert(product_packet_graph_submit_external(&vm, UINT32_MAX, &item.platform, 0) == 0);
  item.obligation.queue_generation--;
  assert(product_packet_graph_submit_external(&vm, UINT32_MAX, &item.platform, &item.obligation) == 0);
  assert(product_packet_graph_submit_external(0, UINT32_MAX, &item.platform, &item.obligation) == 0);
  assert(publications == 0 && frame_allocations == 0 && gets == 0);
  assert(product_packet_graph_main.lifecycle_buffers == 17);
  assert(product_packet_graph_main.lifecycle_obligations == 29 && forbidden_calls == 0);
}

int main(void) {
  /* Keep the unexpected-operation guard linked even when no forbidden seam
   * occurs in the extracted functions. */
  if (forbidden_calls) forbidden_call("preexisting operation");
#if TEST_NATIVE_ENQUEUE
  native_return_frames();
#else
  /* Explicit skip: Product acceptance still executes, but native get/put
   * behavior needs the configured, independently hashed pinned VPP source. */
  (void)test_native_get;(void)test_native_put;
  puts("SKIP actual pinned native enqueue: set SAKAMOTO_TEST_VPP_BUFFER_FUNCS");
#endif
  startup_and_restart();
  invalid_snapshot_and_inactive();
  topology_matrix();
  mixed_root();
  rejected_and_empty();
  frame_bound();
  vpn_return();
  single_wrapper();
  printf("PASS actual origin + external batch + %s single: N=1/3 Root/VPN snapshot, owner return/I/O rejection, no packet getenv, invalid/inactive/stale rejection, nonprefix indexes/metadata, debt-before-put; no synchronous free/policy/completion\n", TEST_BATCH ? "ON" : "OFF");
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="sakamoto-external-batch-") as temporary:
    directory = Path(temporary)
    c_source = directory / "external-batch.c"
    executable = directory / "external-batch"
    c_source.write_text(prefix + types + dependencies + native_enqueue + production + suffix)
    topology_object = directory / "topology.o"
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                    "-Werror", "-Dgetenv=topology_getenv", "-c",
                    str(ROOT / "src/product/vpp/product_runtime_topology.c"),
                    "-o", str(topology_object)], check=True, timeout=30)
    for mode, tcp_mode in ((0,0),(0,1),(1,0),(1,1)):

        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                        "-Werror", f"-DTEST_BATCH={mode}", f"-DTEST_TCP_BATCH={tcp_mode}", f"-DTEST_NATIVE_ENQUEUE={int(bool(native_path))}", "-I", str(ROOT / "src/product/vpp"),
                        str(c_source), str(topology_object),
                        "-o", str(executable)], check=True, timeout=30)
        subprocess.run([str(executable)], check=True, timeout=5,
                       env=dict(os.environ, SAKAMOTO_PRODUCT_TUN_IO_CPU_ID="3"))
if native_path:
    print("actual_native_enqueue_source=" + str(Path(native_path).resolve()))
    print("actual_native_enqueue_sha256=" + hashlib.sha256(native_source.encode()).hexdigest())
print("production_source_sha256=" + hashlib.sha256(source.encode()).hexdigest())
