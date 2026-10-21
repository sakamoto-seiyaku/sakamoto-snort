#!/usr/bin/env python3
"""Execute the Product external batch submission and enabled single-item wrapper.

The production functions and inline metadata types are compiled verbatim. Only
native buffers, frame publication, thread mapping and graph counters are supplied
by this harness. This checks scheduling ownership, not policy or device delivery.
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
    match = re.search(r"\n(?:static )?(?:void|int|u32)\n" + re.escape(name)
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
typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef uint64_t u64;
#define SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT 1
#define PRODUCT_GRAPH_WORKERS 2
#define PRODUCT_VPN_RETURN_WORKERS 2
#define VLIB_FRAME_SIZE 256
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
typedef struct {
  u64 generation, trace_packets, trace_limit;
  u32 enabled, accepting, lifecycle_buffers, lifecycle_obligations;
} product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main;
static struct { u32 index; } product_packet_admit_node = { 19 };
static vlib_buffer_t storage[VLIB_FRAME_SIZE + 16];
static vlib_frame_t published_frame;
static unsigned gets, frame_allocations, publications, forbidden_calls;
static u32 vlib_get_worker_thread_index(u32 worker) {
  assert(worker < PRODUCT_GRAPH_WORKERS);
  return 3 + 2 * worker;
}
static u32 vlib_get_worker_index(u32 thread) {
  assert(thread == 3 || thread == 5);
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
static void vlib_buffer_enqueue_to_single_next(vlib_main_t *vm,
  vlib_node_runtime_t *node, u32 *indices, u32 next, u32 count) {
  (void)vm; (void)node; (void)indices; (void)next; (void)count;
  forbidden_call("native next publication");
}
'''

dependencies = "\n".join(function(source, name) for name in (
    "product_metadata_load", "product_metadata_store",
    "product_packet_graph_set_platform_facts"))
production = "\n".join(function(source, name) for name in (
    "product_packet_graph_submit_external_batch_internal",
    "product_packet_graph_submit_external_batch", "product_packet_graph_submit_external"))

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

static void reset(void) {
  product_packet_graph_main = (product_packet_graph_main_t) {
    .generation = 7041, .trace_limit = 2, .enabled = 1, .accepting = 1,
    .lifecycle_buffers = 17, .lifecycle_obligations = 29,
  };
  memset(storage, 0xa5, sizeof(storage));
  memset(&published_frame, 0, sizeof(published_frame));
  gets = frame_allocations = publications = forbidden_calls = 0;
  expected_items = 0;
  expected_mask = returned_mask = 0;
  expected_length = expected_count = 0;
}

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
  reset();
  vlib_main_t vm = {.thread_index = 5};
  product_packet_graph_external_item_t items[8];
  for (u32 i = 0; i < 8; ++i) {
    items[i] = root_item(20 + i, 0);
    items[i].obligation.kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
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
  const u8 mask[] = {1,0,1,0,0,1,0,0};
  batch(&vm, items, 8, mask);
  reset();
  items[0] = root_item(30, 0);
  items[0].obligation.kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN;
  items[0].platform.provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  vm.thread_index = 3;
  const u8 one[] = {1};
  batch(&vm, items, 1, one);
}

static void single_wrapper(void) {
  vlib_main_t vm = {.thread_index = 3};
  const u8 one[] = {1};
  reset();
  product_packet_graph_external_item_t item = root_item(7, 0);
  expect(&item, 1, one, 0);
  assert(product_packet_graph_submit_external(&vm, item.buffer_index, &item.platform, &item.obligation) == 1);
  assert(publications == 1 && frame_allocations == 1 && gets == 1);
  reset();
  item = root_item(8, 0);
  memset(&item.platform, 0, sizeof(item.platform));
  expect(&item, 1, one, 0);
  assert(product_packet_graph_submit_external(&vm, item.buffer_index, 0, &item.obligation) == 1);
  assert(publications == 1 && frame_allocations == 1 && gets == 1);
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
  mixed_root();
  rejected_and_empty();
  frame_bound();
  vpn_return();
  single_wrapper();
  puts("PASS actual external batch + ON single wrapper: nonprefix acceptance, per-item metadata, debt-before-put, empty/rejected/frame bound, VPN return; no synchronous free/policy/completion");
  return 0;
}
'''

with tempfile.TemporaryDirectory(prefix="sakamoto-external-batch-") as temporary:
    directory = Path(temporary)
    c_source = directory / "external-batch.c"
    executable = directory / "external-batch"
    c_source.write_text(prefix + types + dependencies + production + suffix)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                    "-Werror", "-I", str(ROOT / "src/product/vpp"),
                    str(c_source), "-o", str(executable)], check=True, timeout=30)
    subprocess.run([str(executable)], check=True, timeout=5)
print("production_source_sha256=" + hashlib.sha256(source.encode()).hexdigest())
