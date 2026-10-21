#!/usr/bin/env python3
"""Run actual primary/completion/origin batching against native dependencies.

The production helpers, credit operations, metadata projections, capacity bypass
and retry/origin nodes are compiled verbatim. Retained enqueue returns deliberately
unordered failed buffer indices and makes transferred storage inaccessible before
returning. Adapter callbacks are controlled dependencies; no packet policy or
separate model of the batching helpers is used.
"""

import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "src/product/vpp"
graph = (PRODUCT / "product_packet_graph.c").read_text()
admit = (PRODUCT / "product_packet_batch_admit.inc").read_text()
completion = (PRODUCT / "product_packet_batch_completion.inc").read_text()
packet = (PRODUCT / "product_packet.c").read_text()


def function(source: str, name: str) -> str:
    match = re.search(r"(?m)^" + re.escape(name) + r"\s*\(", source)
    if match is None:
        raise RuntimeError(f"Missing production function: {name}")
    begin = source.rfind("\n", 0, match.start() - 1) + 1
    opening = source.index("{", match.end())
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[begin:end] + "\n"


def struct(source: str, name: str) -> str:
    end = source.index("} " + name + ";") + len("} " + name + ";")
    begin = source.rfind("typedef struct", 0, end)
    return source[begin:end] + "\n"


metadata_begin = graph.index("enum\n{\n  PRODUCT_META_ADMITTED")
metadata_end = graph.index("_Static_assert (sizeof (product_packet_completion_frame_t)", metadata_begin)
queue_end = graph.index("static product_completion_return_queue_t product_completion_returns")
queue_begin = graph.rfind("typedef struct", 0, queue_end)
types = (graph[metadata_begin:metadata_end]
         + struct(graph, "product_packet_batch_stats_t")
         + graph[queue_begin:queue_end]
         + struct(admit, "product_primary_batch_t")
         + struct(graph, "product_origin_reclaim_t"))
retry_begin = graph.index("VLIB_NODE_FN (product_packet_completion_retry_node)")
retry_end = graph.index("VLIB_REGISTER_NODE (product_packet_completion_retry_node)", retry_begin)
retry = graph[retry_begin:retry_end]
origin_begin = graph.index("VLIB_NODE_FN (product_packet_origin_completion_node)")
origin_end = graph.index("VLIB_REGISTER_NODE (product_packet_origin_completion_node)", origin_begin)
origin = function(graph, "product_origin_reclaim_flush") + graph[origin_begin:origin_end]

prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "product_packet.h"
#include "product_packet_completion.h"
#include "product_packet_batch.h"
typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned long uword;
#define SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT 1
#define PRODUCT_GRAPH_WORKERS 2
#define VLIB_FRAME_SIZE 256
#define PRODUCT_COMPLETION_RETURN_CAPACITY 512
#define PRODUCT_FLOW_END_DISCRIMINANT 0x80
#define CLIB_CACHE_LINE_BYTES 64
#define CLIB_CACHE_LINE_ALIGN_MARK(name)
#define static_always_inline static inline
#define VLIB_NODE_FN(name) uword name##_fn
#define ASSERT assert
#define PREDICT_FALSE(x) (x)
#define LOAD 0
#define clib_min(a,b) ((a) < (b) ? (a) : (b))
#define round_pow2(value,align) (((value) + (align) - 1) & ~((align) - 1))
#define clib_memset memset
#define clib_atomic_load_acq_n(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add((p),(n),__ATOMIC_RELAXED)
#define clib_atomic_fetch_sub_relax(p,n) __atomic_fetch_sub((p),(n),__ATOMIC_RELAXED)
#define clib_atomic_cmp_and_swap_acq_relax_n(p,e,v,w) \
  __atomic_compare_exchange_n((p),(e),(v),(w),__ATOMIC_ACQ_REL,__ATOMIC_RELAXED)
#define PRODUCT_EVIDENCE_ADD(name,value) do { (void)(value); } while (0)
#define PRODUCT_EVIDENCE_SUB(name,value) do { (void)(value); } while (0)
#define clib_panic(message) do { fputs((message), stderr); abort(); } while (0)
typedef struct { u32 thread_index; } vlib_main_t;
typedef struct { u32 node_index; } vlib_node_runtime_t;
typedef struct { u32 n_vectors, vectors[VLIB_FRAME_SIZE]; } vlib_frame_t;
typedef struct { u32 nelts; u64 head, tail; } vlib_frame_queue_t;
typedef struct { vlib_frame_queue_t **vlib_frame_queues; } vlib_frame_queue_main_t;
typedef struct { vlib_frame_queue_main_t *frame_queue_mains; } vlib_thread_main_t;
#define vec_elt_at_index(vector,index) (&(vector)[index])
static_always_inline vlib_thread_main_t *vlib_get_thread_main(void) {
  static vlib_frame_queue_t queues[PRODUCT_GRAPH_WORKERS + 1];
  static vlib_frame_queue_t *pointers[PRODUCT_GRAPH_WORKERS + 1];
  static vlib_frame_queue_main_t mains[32];
  static vlib_thread_main_t threads = {.frame_queue_mains = mains};
  for (u32 i = 0; i <= PRODUCT_GRAPH_WORKERS; ++i) {
    pointers[i] = &queues[i];
    queues[i].nelts = 2;
  }
  for (u32 i = 0; i < 32; ++i) mains[i].vlib_frame_queues = pointers;
  return &threads;
}
typedef struct {
  u8 opaque[40], opaque2[56];
  i16 current_data;
  u16 current_length;
  u8 data[128];
} vlib_buffer_t;
typedef struct {
  u64 generation, primary_published, primary_rejected;
  u64 primary_rejected_credit, primary_rejected_enqueue;
  u64 completion_returns, completion_deferred, completion_retry_attempts;
  u32 primary_frame_queue, completion_return_frame_queue, primary_credit_limit;
  u32 handoff_credits[PRODUCT_GRAPH_WORKERS], lifecycle_handoffs;
  u32 completion_pending_returns, lifecycle_buffers, lifecycle_obligations;
  u32 lifecycle_completion_frames, lifecycle_settlements, lifecycle_returns;
  u32 misroute_next;
} product_packet_graph_main_t;
typedef enum { PRODUCT_HANDOFF_PRIMARY, PRODUCT_HANDOFF_CORRECTIVE } product_handoff_stage_t;
enum { PRODUCT_ADMIT_NEXT_TERMINAL = 3 };
static product_packet_graph_main_t product_packet_graph_main;
static struct { u32 index; } product_packet_completion_retry_node = { 21 };
#define TEST_BUFFERS 768
static u8 *arena;
static size_t page_bytes;
static u8 live[TEST_BUFFERS], rejected[TEST_BUFFERS], held[TEST_BUFFERS];
static u32 gets[TEST_BUFFERS], attempted[TEST_BUFFERS], transfers[TEST_BUFFERS], terminals[TEST_BUFFERS];
static unsigned bulk_reads, prefetches, native_calls, physical_publications;
static unsigned interrupts, scheduled, schedules, release_primary_on_transfer;
static unsigned native_sizes[64], native_queues[64];
static product_packet_completion_frame_t transferred_completion[TEST_BUFFERS];
static product_packet_completion_frame_t origin_expected[TEST_BUFFERS];
static u32 root_callbacks[TEST_BUFFERS], root_pool_returns[TEST_BUFFERS], root_window_calls;
static u32 vpn_callbacks[TEST_BUFFERS], vpn_return_reclaims[TEST_BUFFERS], native_frees[TEST_BUFFERS];
static unsigned native_free_calls, native_free_sizes[64], origin_case;

static void check_live_pointer(const void *pointer) {
  uintptr_t address = (uintptr_t)pointer, start = (uintptr_t)arena;
  if (address >= start && address < start + page_bytes * TEST_BUFFERS) {
    unsigned index = (unsigned)((address - start) / page_bytes);
    if (!live[index]) {
      fprintf(stderr, "access after publication: buffer=%u\n", index);
      abort();
    }
  }
}
static void *checked_copy(void *destination, const void *source, size_t length) {
  if (length) { check_live_pointer(destination); check_live_pointer(source); }
  return memcpy(destination, source, length);
}
#define clib_memcpy_fast checked_copy
static void checked_prefetch(const void *pointer, size_t bytes, unsigned mode) {
  (void)bytes; (void)mode;
  check_live_pointer(pointer);
  ++prefetches;
}
#define CLIB_PREFETCH(pointer,bytes,mode) checked_prefetch((pointer),(bytes),(mode))
#define vlib_prefetch_buffer_header(buffer,mode) checked_prefetch((buffer),sizeof(*(buffer)),(mode))
#define vlib_prefetch_buffer_data(buffer,mode) checked_prefetch((buffer)->data,sizeof((buffer)->data),(mode))
static u32 vlib_get_worker_thread_index(u32 worker) {
  assert(worker < PRODUCT_GRAPH_WORKERS);
  return worker + 1;
}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *vm, u32 index) {
  assert(vm && index < TEST_BUFFERS);
  check_live_pointer(arena + page_bytes * index);
  assert(live[index]);
  ++gets[index];
  return (vlib_buffer_t *)(arena + page_bytes * index);
}
static void vlib_get_buffers(vlib_main_t *vm, const u32 *indices,
                             vlib_buffer_t **buffers, u32 count) {
  assert(count <= PRODUCT_COMPLETION_BATCH_SIZE);
  bulk_reads += count;
  for (u32 i = 0; i < count; ++i) buffers[i] = vlib_get_buffer(vm, indices[i]);
}
static u32 *vlib_frame_vector_args(vlib_frame_t *frame) {
  assert(frame && frame->n_vectors <= VLIB_FRAME_SIZE);
  return frame->vectors;
}
static u8 *vlib_buffer_get_current(vlib_buffer_t *buffer) {
  check_live_pointer(buffer);
  return buffer->data + buffer->current_data;
}
static int product_buffer_is_flow_end(const vlib_buffer_t *buffer) {
  check_live_pointer(buffer);
  return !!(buffer->opaque2[55] & PRODUCT_FLOW_END_DISCRIMINANT);
}
static int product_vpn_tun_return_held(vlib_main_t *vm,
  const product_packet_completion_frame_t *completion) {
  assert(vm && completion->obligation.token >= 10000);
  u64 index = completion->obligation.token - 10000;
  assert(index < TEST_BUFFERS);
  return held[index];
}
static void vlib_node_set_interrupt_pending(vlib_main_t *vm, u32 node) {
  assert(vm && node == product_packet_completion_retry_node.index);
  ++interrupts;
}
static int vlib_node_is_scheduled(vlib_main_t *vm, u32 node) {
  assert(vm && node == product_packet_completion_retry_node.index);
  return scheduled;
}
static void vlib_node_schedule(vlib_main_t *vm, u32 node, double seconds) {
  assert(vm && node == product_packet_completion_retry_node.index);
  assert(seconds == .001 && !scheduled);
  scheduled = 1;
  ++schedules;
}
static u32 vlib_buffer_enqueue_to_thread_retained(vlib_main_t *, vlib_node_runtime_t *,
  u32, u32 *, u16 *, u32, u32 *);
static void vlib_buffer_enqueue_to_single_next(vlib_main_t *, vlib_node_runtime_t *,
  u32 *, u32, u32);
static void vlib_buffer_free(vlib_main_t *, u32 *, u32);
static int product_root_nfqueue_complete_from_graph(vlib_main_t *, u32,
  const product_packet_completion_frame_t *);
#ifdef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT
static void product_root_nfqueue_complete_batch_from_graph(vlib_main_t *,
  const u32 *, const product_packet_completion_frame_t *, u32, u8 *);
#endif
static int product_vpn_tun_complete_from_graph(vlib_main_t *, u32,
  const product_packet_completion_frame_t *);
static void product_vpn_tun_return_freed(vlib_main_t *, u32,
  const product_packet_completion_frame_t *);
static void product_root_nfqueue_prefetch_completion(vlib_main_t *main,
  const product_packet_completion_frame_t *item) {
  assert(main && item);
  check_live_pointer(item);
}
static void product_fragment_origin_check(vlib_main_t *main, u32 index,
  const product_packet_completion_frame_t *item) {
  assert(main && index < TEST_BUFFERS && live[index]);
  check_live_pointer(item);
}
static u64 product_packet_event_clock_ns(void) { return 70000; }
'''

dependencies = "\n".join(function(graph, name) for name in (
    "product_metadata_load", "product_metadata_store",
    "product_packet_graph_platform_facts_unknown", "product_packet_graph_set_platform_facts",
    "product_packet_graph_get_platform_facts", "product_metadata_terminal_intent",
    "product_metadata_set_terminal_intent", "product_metadata_from_lease",
    "product_lease_from_metadata", "product_handoff_credit_reserve", "product_handoff_credit_release"))
dependencies += function(packet, "product_packet_bypass_primary_capacity")
dependencies += function(admit, "product_batch_prefetch_buffer")
stats = r'''
static product_packet_batch_stats_t packet_stats[PRODUCT_GRAPH_WORKERS + 1];
static product_packet_batch_stats_t *product_packet_batch_counters(vlib_main_t *vm) {
  assert(vm && vm->thread_index <= PRODUCT_GRAPH_WORKERS);
  return &packet_stats[vm->thread_index];
}
static product_completion_return_queue_t product_completion_returns[PRODUCT_GRAPH_WORKERS + 1];
'''
primary_helpers = "\n".join(function(admit, name) for name in (
    "product_primary_batch_flush", "product_primary_batch_append"))

suffix = r'''
static vlib_main_t vm = {.thread_index = 1};
static vlib_node_runtime_t node = {.node_index = 21};
static product_buffer_metadata_t transferred_metadata[TEST_BUFFERS], terminal_metadata[TEST_BUFFERS];

static void poison(u32 index) {
  assert(live[index] && ++transfers[index] == 1);
  memset(arena + page_bytes * index, 0xdd, page_bytes);
  assert(mprotect(arena + page_bytes * index, page_bytes, PROT_NONE) == 0);
  live[index] = 0;
}

static void assert_local_completion(u32 index, const product_packet_completion_frame_t *item) {
  check_live_pointer(item);
  assert((uintptr_t)item < (uintptr_t)arena ||
         (uintptr_t)item >= (uintptr_t)arena + page_bytes * TEST_BUFFERS);
  assert(memcmp(item, &origin_expected[index], sizeof(*item)) == 0);
}

static int product_root_nfqueue_complete_from_graph(vlib_main_t *main, u32 index,
  const product_packet_completion_frame_t *item) {
  assert(main == &vm && live[index] && ++root_callbacks[index] == 1);
  assert_local_completion(index, item);
  assert(item->obligation.kind == PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE);
  if ((item->flags & PRODUCT_COMPLETION_REPLAY_PROBE) || rejected[index]) return 0;
  assert(++root_pool_returns[index] == 1 && !native_frees[index]);
  poison(index); /* Root returns the original receive-pool loan here. */
  return 1;
}

#ifdef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT
static void product_root_nfqueue_complete_batch_from_graph(vlib_main_t *main,
  const u32 *indices, const product_packet_completion_frame_t *items, u32 count, u8 *returned) {
  assert(count && count <= PRODUCT_PACKET_BATCH_SIZE);
  root_window_calls++;
  for (u32 i=0; i<count; ++i) {
    returned[i]=0;
    if (items[i].obligation.kind == PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE)
      returned[i]=product_root_nfqueue_complete_from_graph(main,indices[i],items+i);
  }
}
#endif

static int product_vpn_tun_complete_from_graph(vlib_main_t *main, u32 index,
  const product_packet_completion_frame_t *item) {
  assert(main == &vm && live[index] && ++vpn_callbacks[index] == 1);
  assert_local_completion(index, item);
  assert(item->obligation.kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN);
  return !(item->flags & PRODUCT_COMPLETION_REPLAY_PROBE);
}

static void vlib_buffer_free(vlib_main_t *main, u32 *indices, u32 count) {
  assert(main == &vm && count && count <= PRODUCT_PACKET_BATCH_SIZE && native_free_calls < 64);
  if (origin_case == 1) {
    const u32 buffers[] = {33,17,1}, obligations[] = {23,12,1};
    assert(native_free_calls < 3);
    assert(product_packet_graph_main.lifecycle_buffers == buffers[native_free_calls]);
    assert(product_packet_graph_main.lifecycle_completion_frames == buffers[native_free_calls]);
    assert(product_packet_graph_main.lifecycle_obligations == obligations[native_free_calls]);
    assert(product_packet_graph_main.lifecycle_settlements == 23 - obligations[native_free_calls]);
    assert(product_packet_graph_main.lifecycle_returns == 23 - obligations[native_free_calls]);
  }
  native_free_sizes[native_free_calls++] = count;
  for (u32 i = 0; i < count; ++i) {
    u32 index = indices[i];
    assert(index < TEST_BUFFERS && live[index] && !root_pool_returns[index]);
    assert(++native_frees[index] == 1);
    poison(index);
  }
}

static void product_vpn_tun_return_freed(vlib_main_t *main, u32 index,
  const product_packet_completion_frame_t *item) {
  assert(main == &vm && !live[index] && native_frees[index] == 1 && vpn_callbacks[index] == 1);
  assert_local_completion(index, item);
  assert(!(item->flags & PRODUCT_COMPLETION_REPLAY_PROBE));
  assert(++vpn_return_reclaims[index] == 1);
}

static u32 vlib_buffer_enqueue_to_thread_retained(vlib_main_t *main,
  vlib_node_runtime_t *runtime, u32 queue, u32 *indices, u16 *targets,
  u32 count, u32 *failed) {
  assert(main == &vm && runtime == &node && count && count <= PRODUCT_COMPLETION_BATCH_SIZE);
  assert(native_calls < 64);
  native_sizes[native_calls] = count;
  native_queues[native_calls++] = queue;
  u32 accepted = 0, n_failed = 0;
  u8 published[PRODUCT_GRAPH_WORKERS + 1] = {0};
  for (u32 i = count; i; --i)
    if (rejected[indices[i - 1]]) failed[n_failed++] = indices[i - 1];
  for (u32 i = 0; i < count; ++i) {
    u32 index = indices[i];
    assert(index < TEST_BUFFERS && live[index] && !transfers[index]);
    assert(targets[i] == 1 || targets[i] == 2);
    ++attempted[index];
    if (queue == product_packet_graph_main.primary_frame_queue) {
      assert(count <= PRODUCT_PACKET_BATCH_SIZE);
      product_metadata_load((vlib_buffer_t *)(arena + page_bytes * index), &transferred_metadata[index]);
      assert(transferred_metadata[index].state_bits & PRODUCT_META_HANDOFF_CREDIT);
      assert(product_packet_graph_main.lifecycle_handoffs >= count);
    } else {
      assert(queue == product_packet_graph_main.completion_return_frame_queue && !held[index]);
      memcpy(&transferred_completion[index], arena + page_bytes * index + offsetof(vlib_buffer_t, opaque2),
             sizeof(transferred_completion[index]));
      assert(transferred_completion[index].obligation.token == 10000 + index);
      assert(targets[i] == vlib_get_worker_thread_index(transferred_completion[index].obligation.origin_worker));
    }
    if (rejected[index]) continue;
    if (!published[targets[i]]) { published[targets[i]] = 1; ++physical_publications; }
    if (queue == product_packet_graph_main.primary_frame_queue && release_primary_on_transfer)
      product_handoff_credit_release(&product_packet_graph_main, transferred_metadata[index].expected_owner);
    ++accepted;
    poison(index); /* A native consumer may reclaim before retained enqueue returns. */
  }
  assert(accepted + n_failed == count);
  return accepted;
}

static void vlib_buffer_enqueue_to_single_next(vlib_main_t *main,
  vlib_node_runtime_t *runtime, u32 *indices, u32 next, u32 count) {
  assert(main == &vm && runtime == &node && next == PRODUCT_ADMIT_NEXT_TERMINAL && count == 1);
  assert(live[indices[0]] && ++terminals[indices[0]] == 1);
  product_metadata_load(vlib_get_buffer(main, indices[0]), &terminal_metadata[indices[0]]);
}

static void reset(void) {
  assert(mprotect(arena, page_bytes * TEST_BUFFERS, PROT_READ | PROT_WRITE) == 0);
  memset(arena, 0, page_bytes * TEST_BUFFERS);
  memset(live, 0, sizeof(live));
  memset(rejected, 0, sizeof(rejected));
  memset(held, 0, sizeof(held));
  memset(gets, 0, sizeof(gets));
  memset(attempted, 0, sizeof(attempted));
  memset(transfers, 0, sizeof(transfers));
  memset(terminals, 0, sizeof(terminals));
  memset(packet_stats, 0, sizeof(packet_stats));
  memset(product_completion_returns, 0, sizeof(product_completion_returns));
  memset(product_completion_dispatch, 0, sizeof(product_completion_dispatch));
  memset(root_callbacks, 0, sizeof(root_callbacks));
  memset(root_pool_returns, 0, sizeof(root_pool_returns));
  root_window_calls = 0;
  memset(vpn_callbacks, 0, sizeof(vpn_callbacks));
  memset(vpn_return_reclaims, 0, sizeof(vpn_return_reclaims));
  memset(native_frees, 0, sizeof(native_frees));
  product_packet_graph_main = (product_packet_graph_main_t) {
    .generation = 741, .primary_frame_queue = 17, .completion_return_frame_queue = 18,
    .primary_credit_limit = 32, .handoff_credits = {32,32},
  };
  bulk_reads = prefetches = native_calls = physical_publications = 0;
  interrupts = scheduled = schedules = release_primary_on_transfer = 0;
  native_free_calls = origin_case = 0;
}

static vlib_buffer_t *new_buffer(u32 index) {
  assert(index < TEST_BUFFERS && !live[index] && !transfers[index]);
  live[index] = 1;
  product_packet_graph_main.lifecycle_buffers++;
  product_packet_graph_main.lifecycle_obligations++;
  return vlib_get_buffer(&vm, index);
}

static product_buffer_metadata_t primary(u32 index, u16 owner, u8 provenance) {
  vlib_buffer_t *buffer = new_buffer(index);
  buffer->current_length = 28;
  buffer->data[12] = 10; buffer->data[15] = index + 1;
  buffer->data[16] = 10; buffer->data[19] = 240;
  product_packet_lease_t lease = {
    .origin_obligation_id = 10000 + index,
    .facts = { .l3_status = PRODUCT_PACKET_L3_COMPLETE, .l4_status = PRODUCT_PACKET_L4_COMPLETE,
      .ip_family = 4, .protocol = 17, .packet_length = 28, .l3_header_length = 20, .l4_header_length = 8,
      .source_port = 24000 + index, .destination_port = 25000 },
    .assignment = { .execution_owner = owner, .valid = 1, .source_is_a = 1,
      .key = { .kind = PRODUCT_OWNER_KEY_L4_PORTS }, .canonical_hash = 40000 + index },
    .primary_handoff_count = 1,
  };
  product_buffer_metadata_t metadata;
  product_metadata_from_lease(&metadata, &lease, product_packet_graph_main.generation, buffer);
  product_adapter_obligation_t obligation = {
    .token = lease.origin_obligation_id, .queue_generation = metadata.generation,
    .packet_id = index + 1, .kind = PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE,
  };
  product_platform_packet_facts_t platform = {
    .uid = 1000 + index, .availability = PRODUCT_PLATFORM_UID_KNOWN, .provenance = provenance,
    .direction = PRODUCT_PACKET_DIRECTION_OUTPUT,
  };
  memcpy(buffer->opaque, &obligation, sizeof(obligation));
  product_metadata_store(buffer, &metadata);
  product_packet_graph_set_platform_facts(buffer, &platform, metadata.generation);
  return metadata;
}

static product_packet_completion_frame_t completion_item(u32 index, u16 origin) {
  vlib_buffer_t *buffer = new_buffer(index);
  product_packet_completion_frame_t item = {
    .obligation = { .token = 10000 + index, .queue_generation = product_packet_graph_main.generation,
      .packet_id = index + 1, .origin_worker = origin, .origin_lane = index % 4,
      .kind = PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE },
    .producer_thread = 2, .terminal_intent = PRODUCT_PACKET_INTENT_PASS_ADAPTER,
  };
  memcpy(buffer->opaque2, &item, sizeof(item));
  return item;
}

static void assert_queue(const u32 *expected, u32 count) {
  const product_completion_return_queue_t *queue = &product_completion_returns[vm.thread_index];
  assert(queue->count == count && product_packet_graph_main.completion_pending_returns == count);
  for (u32 i = 0; i < count; ++i) {
    u32 index = queue->buffers[(queue->head + i) % PRODUCT_COMPLETION_RETURN_CAPACITY];
    assert(index == expected[i] && live[index] && !transfers[index]);
  }
}

static void seed_queue(u32 count, u16 head, int hold_all) {
  product_completion_returns[vm.thread_index].head = head;
  for (u32 i = 0; i < count; ++i) {
    product_packet_completion_frame_t item = completion_item(i, i % 2);
    held[i] = hold_all;
    product_completion_defer(&vm, i, &item);
  }
  assert(product_packet_graph_main.completion_pending_returns == count);
}

static void primary_partial(void) {
  reset();
  product_primary_batch_t batch = {0};
  product_packet_processing_bypass_reason_t reason = PRODUCT_PACKET_BYPASS_NONE;
  for (u32 i = 0; i < 8; ++i) {
    product_buffer_metadata_t metadata = primary(i, i % 2,
      i == 3 ? PRODUCT_PACKET_PROVENANCE_VPN_TUN : PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE);
    assert(product_primary_batch_append(&vm, &node, &batch, i, &metadata, &reason));
  }
  rejected[1] = rejected[3] = rejected[6] = 1;
  product_primary_batch_flush(&vm, &node, &batch);
  assert(batch.count == 0 && native_calls == 1 && native_sizes[0] == 8);
  assert(product_packet_graph_main.primary_published == 5 && product_packet_graph_main.primary_rejected == 3);
  assert(product_packet_graph_main.primary_rejected_enqueue == 3 && product_packet_graph_main.primary_rejected_credit == 0);
  assert(product_packet_graph_main.handoff_credits[0] == 29 && product_packet_graph_main.handoff_credits[1] == 30);
  assert(product_packet_graph_main.lifecycle_handoffs == 5);
  const product_packet_batch_stats_t *stats = &packet_stats[vm.thread_index];
  assert(stats->primary_calls == 1 && stats->primary_vectors == 5 && stats->primary_failed == 3);
  assert(stats->primary_publications == 2 && physical_publications == 2);
  for (u32 i = 0; i < 8; ++i) {
    assert(attempted[i] == 1 && transfers[i] == !rejected[i]);
    if (!rejected[i]) continue;
    const product_buffer_metadata_t *metadata = &terminal_metadata[i];
    assert(terminals[i] == 1 && !(metadata->state_bits & PRODUCT_META_HANDOFF_CREDIT));
    assert(metadata->origin_obligation_id == 10000 + i && metadata->expected_owner == i % 2);
    if (i == 3) {
      assert(product_metadata_terminal_intent(metadata) == PRODUCT_PACKET_INTENT_DROP_RUNTIME);
      assert(metadata->runtime_drop_reason == PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION);
      assert(metadata->processing_bypass_reason == PRODUCT_PACKET_BYPASS_NONE);
    } else {
      assert(product_metadata_terminal_intent(metadata) == PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS);
      assert(metadata->runtime_drop_reason == PRODUCT_PACKET_DROP_NONE);
      assert(metadata->processing_bypass_reason == PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED);
    }
  }
  product_primary_batch_flush(&vm, &node, &batch);
  assert(native_calls == 1 && product_packet_graph_main.lifecycle_buffers == 8);
  puts("PASS primary unordered failed indices: credits, Root bypass, VPN failure, packet/publication counters, immediate transfer invalidation");
}

static void primary_boundaries(void) {
  reset();
  product_primary_batch_t batch = {0};
  product_packet_processing_bypass_reason_t reason = PRODUCT_PACKET_BYPASS_NONE;
  for (u32 i = 0; i < 32; ++i) {
    product_buffer_metadata_t metadata = primary(i, 1, PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE);
    assert(product_primary_batch_append(&vm, &node, &batch, i, &metadata, &reason));
    assert(batch.count == (i + 1) % 16 && native_calls == (i + 1) / 16);
  }
  product_buffer_metadata_t metadata = primary(32, 1, PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE);
  assert(!product_primary_batch_append(&vm, &node, &batch, 32, &metadata, &reason));
  assert(reason == PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED && native_calls == 2);
  assert(native_sizes[0] == 16 && native_sizes[1] == 16);
  assert(product_packet_graph_main.handoff_credits[1] == 0 && product_packet_graph_main.lifecycle_handoffs == 32);
  assert(product_packet_graph_main.primary_rejected == 1 && live[32] && !transfers[32]);
  assert(product_packet_graph_main.primary_rejected_credit == 1 && product_packet_graph_main.primary_rejected_enqueue == 0);
  reset();
  batch = (product_primary_batch_t){0};
  product_packet_graph_main.handoff_credits[0] = 0;
  product_packet_graph_main.lifecycle_handoffs = 32;
  metadata = primary(0, 1, PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE);
  assert(product_primary_batch_append(&vm, &node, &batch, 0, &metadata, &reason));
  assert(batch.count == 1 && native_calls == 0);
  metadata = primary(1, 0, PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE);
  assert(!product_primary_batch_append(&vm, &node, &batch, 1, &metadata, &reason));
  assert(batch.count == 0 && native_calls == 1 && native_sizes[0] == 1 && transfers[0] == 1);
  assert(reason == PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED);
  reset();
  batch = (product_primary_batch_t){0};
  product_packet_graph_main.handoff_credits[0] = 1;
  product_packet_graph_main.lifecycle_handoffs = 31;
  metadata = primary(0, 0, PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE);
  assert(product_primary_batch_append(&vm, &node, &batch, 0, &metadata, &reason));
  rejected[0] = 1;
  metadata = primary(1, 0, PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE);
  assert(product_primary_batch_append(&vm, &node, &batch, 1, &metadata, &reason));
  assert(native_calls == 1 && terminals[0] == 1 && batch.count == 1);
  product_primary_batch_flush(&vm, &node, &batch);
  assert(native_calls == 2 && transfers[1] == 1 && product_packet_graph_main.handoff_credits[0] == 0);
  reset();
  batch = (product_primary_batch_t){0};
  product_packet_graph_main.misroute_next = 1;
  metadata = primary(0, 1, PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE);
  rejected[0] = 1;
  assert(product_primary_batch_append(&vm, &node, &batch, 0, &metadata, &reason));
  assert(batch.targets[0] == vm.thread_index && batch.metadata[0].expected_owner == 1);
  product_primary_batch_flush(&vm, &node, &batch);
  assert(product_packet_graph_main.handoff_credits[0] == 32 && product_packet_graph_main.handoff_credits[1] == 32);
  assert(product_packet_graph_main.lifecycle_handoffs == 0);
  puts("PASS primary 16-window/32-credit bounds: flush-before-exhaustion, retained release retry, canonical owner credit, nonblocking rejection");
}

static product_completion_batch_t mixed_completion(void) {
  product_completion_batch_t batch = {0};
  for (u32 i = 0; i < 8; ++i) {
    batch.indices[batch.count] = i;
    batch.completion[batch.count++] = completion_item(i, i % 2);
  }
  rejected[1] = rejected[5] = held[2] = 1;
  return batch;
}

static void completion_partial(void) {
  reset();
  product_completion_batch_t batch = mixed_completion();
  u8 failed[PRODUCT_COMPLETION_BATCH_SIZE];
  const u8 expected[] = {0,1,1,0,0,1,0,0};
  assert(product_completion_batch_publish(&vm, &node, &batch, failed, 0) == 5);
  assert(memcmp(failed, expected, sizeof(expected)) == 0);
  assert(native_calls == 1 && native_sizes[0] == 7 && attempted[2] == 0);
  assert(product_packet_graph_main.completion_returns == 5 && product_packet_graph_main.completion_pending_returns == 0);
  assert(packet_stats[vm.thread_index].completion_calls == 1);
  assert(packet_stats[vm.thread_index].completion_vectors == 5 && packet_stats[vm.thread_index].completion_publications == 2);
  reset();
  batch = mixed_completion();
  product_completion_batch_flush(&vm, &node, &batch);
  const u32 queued[] = {1,2,5};
  assert_queue(queued, 3);
  assert(product_packet_graph_main.completion_deferred == 3 && interrupts == 3 && batch.count == 0);
  product_completion_batch_flush(&vm, &node, &batch);
  assert(native_calls == 1 && product_packet_graph_main.completion_pending_returns == 3);
  assert(product_packet_graph_main.lifecycle_buffers == 8 && product_packet_graph_main.lifecycle_obligations == 8);
  puts("PASS completion partial publish: per-position failure mask, held exclusion, original ring only, no duplicate debt, packet/publication counters");
}

static void completion_dispatch_and_direct(void) {
  reset();
  product_completion_batch_t batch = {0};
  product_completion_dispatch[vm.thread_index].active = &batch;
  for (u32 i = 0; i < PRODUCT_PACKET_BATCH_SIZE; ++i) {
    product_packet_completion_frame_t item = completion_item(i, i % 2);
    product_completion_return(&vm, &node, i, &item);
    assert(native_calls == (i + 1) / PRODUCT_PACKET_BATCH_SIZE);
  }
  assert(batch.count == 0 && native_sizes[0] == PRODUCT_PACKET_BATCH_SIZE);
  product_completion_dispatch[vm.thread_index].active = 0;
  product_packet_completion_frame_t item = completion_item(30, 0);
  product_completion_return(&vm, &node, 30, &item);
  assert(native_calls == 2 && native_sizes[1] == 1 && transfers[30] == 1);
  reset();
  seed_queue(PRODUCT_COMPLETION_RETURN_CAPACITY, 480, 0);
  rejected[0] = 1;
  item = completion_item(600, 1);
  product_completion_return(&vm, &node, 600, &item);
  assert(transfers[600] == 1 && attempted[0] == 0 && native_calls == 1);
  assert(product_completion_returns[vm.thread_index].count == 512);
  assert(product_packet_graph_main.completion_pending_returns == 512 && product_packet_graph_main.completion_deferred == 512);
  puts("PASS completion active dispatch and immediate fallback: fresh work tries directly with full old backlog, no added FIFO");
}

static void retry_wrap_and_drain(void) {
  reset();
  seed_queue(PRODUCT_COMPLETION_RETURN_CAPACITY, 480, 0);
  held[0] = held[3] = held[5] = 1;
  rejected[1] = rejected[7] = rejected[10] = 1;
  assert(product_packet_completion_retry_node_fn(&vm, &node, 0) == 58);
  assert(bulk_reads == 64 && native_calls == 1 && native_sizes[0] == 61);
  assert(product_packet_graph_main.completion_retry_attempts == 61);
  assert(schedules == 1 && scheduled && packet_stats[vm.thread_index].retry_windows == 1);
  u32 expected[512], count = 0;
  expected[count++] = 1; expected[count++] = 7; expected[count++] = 10;
  for (u32 i = 64; i < 512; ++i) expected[count++] = i;
  expected[count++] = 0; expected[count++] = 3; expected[count++] = 5;
  assert(count == 454);
  assert_queue(expected, count);
  assert(product_packet_graph_main.completion_deferred == 512);
  memset(held, 0, sizeof(held));
  memset(rejected, 0, sizeof(rejected));
  unsigned rounds = 1;
  while (product_completion_returns[vm.thread_index].count) {
    u32 before = product_completion_returns[vm.thread_index].count;
    scheduled = 0;
    assert(product_packet_completion_retry_node_fn(&vm, &node, 0) == clib_min(before, 64));
    assert(scheduled == (before > 64));
    ++rounds;
  }
  assert(rounds == 9 && native_calls == 9 && schedules == 8);
  assert(product_packet_graph_main.completion_returns == 512 && product_packet_graph_main.completion_pending_returns == 0);
  assert(product_packet_graph_main.completion_retry_attempts == 515 && product_packet_graph_main.completion_deferred == 512);
  assert(packet_stats[vm.thread_index].completion_vectors == 512);
  assert(packet_stats[vm.thread_index].completion_publications == physical_publications);
  for (u32 i = 0; i < 512; ++i) assert(transfers[i] == 1 && !live[i]);
  puts("PASS retry full-512 wrap: 64-scan bound, failed front order, held tail rotation, exact debt and 1ms progress, complete drain");
}

static void held_and_blocked_target(void) {
  reset();
  seed_queue(PRODUCT_COMPLETION_RETURN_CAPACITY, 480, 1);
  assert(product_packet_completion_retry_node_fn(&vm, &node, 0) == 0);
  assert(bulk_reads == 64 && native_calls == 0 && schedules == 1);
  assert(product_packet_graph_main.completion_retry_attempts == 0);
  u32 rotated[512];
  for (u32 i = 0; i < 448; ++i) rotated[i] = i + 64;
  for (u32 i = 0; i < 64; ++i) rotated[448 + i] = i;
  assert_queue(rotated, 512);
  reset();
  seed_queue(64, 500, 0);
  for (u32 i = 0; i < 64; i += 2) rejected[i] = 1;
  assert(product_packet_completion_retry_node_fn(&vm, &node, 0) == 32);
  u32 pending[32];
  for (u32 i = 0; i < 32; ++i) pending[i] = i * 2;
  assert_queue(pending, 32);
  assert(physical_publications == 1 && native_calls == 1 && native_sizes[0] == 64);
  assert(schedules == 1 && product_packet_graph_main.completion_retry_attempts == 64);
  u16 head = product_completion_returns[vm.thread_index].head;
  assert(product_packet_completion_retry_node_fn(&vm, &node, 0) == 0);
  assert_queue(pending, 32);
  assert(product_completion_returns[vm.thread_index].head == head && schedules == 1);
  assert(product_packet_graph_main.completion_deferred == 64 && product_packet_graph_main.completion_retry_attempts == 96);
  assert(packet_stats[vm.thread_index].completion_calls == 2 && packet_stats[vm.thread_index].completion_publications == 1);
  puts("PASS held-only rotation and blocked first target: other target progresses, complete failure stays at front, existing deadline not duplicated");
}

static void prepare_origin(u32 index, u8 kind, u8 flags) {
  product_packet_completion_frame_t item = completion_item(index, 0);
  item.obligation.kind = kind;
  item.flags = flags;
  if (kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN && !(flags & PRODUCT_COMPLETION_REPLAY_PROBE)) {
    item.flags |= PRODUCT_COMPLETION_FLOW_STACK_RETURN;
    item.obligation.packet_id = 1;
  }
  origin_expected[index] = item;
  memcpy(vlib_get_buffer(&vm, index)->opaque2, &item, sizeof(item));
  product_packet_graph_main.lifecycle_completion_frames++;
  if (flags & PRODUCT_COMPLETION_REPLAY_PROBE)
    product_packet_graph_main.lifecycle_obligations--; /* Replay has only carrier debt. */
}

static void origin_reclaim(void) {
  reset();
  origin_case = 1;
  vlib_frame_t frame = {.n_vectors = 33};
  for (u32 i = 0; i < frame.n_vectors; ++i) {
    u8 kind = i % 6 == 1 || i % 6 == 4 ? PRODUCT_ADAPTER_OBLIGATION_VPN_TUN :
      i % 6 == 2 ? PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED : PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE;
    u8 flags = i % 6 == 3 || i % 6 == 4 ? PRODUCT_COMPLETION_REPLAY_PROBE : 0;
    if (i == 0 || i == 3 || i == 7 || i == 16 || i == 32) flags |= PRODUCT_COMPLETION_TRACE;
    prepare_origin(i, kind, flags);
    if (i % 6 == 5) rejected[i] = 1;
    frame.vectors[i] = i;
  }
  assert(product_packet_graph_main.lifecycle_buffers == 33);
  assert(product_packet_graph_main.lifecycle_completion_frames == 33 && product_packet_graph_main.lifecycle_obligations == 23);
  assert(product_packet_origin_completion_node_fn(&vm, &node, &frame) == 33);
#ifdef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT
  assert(root_window_calls == 3);
#else
  assert(root_window_calls == 0);
#endif
  assert(native_free_calls == 3 && native_free_sizes[0] == 13 && native_free_sizes[1] == 13 && native_free_sizes[2] == 1);
  assert(product_packet_graph_main.lifecycle_buffers == 0 && product_packet_graph_main.lifecycle_completion_frames == 0);
  assert(product_packet_graph_main.lifecycle_obligations == 0);
  assert(product_packet_graph_main.lifecycle_settlements == 23 && product_packet_graph_main.lifecycle_returns == 23);
  assert(packet_stats[vm.thread_index].origin_frames == 1 && packet_stats[vm.thread_index].origin_vectors == 33);
  for (u32 i = 0; i < 33; ++i) {
    assert(transfers[i] == 1 && !live[i]);
    assert(root_pool_returns[i] == (i % 6 == 0));
    assert(native_frees[i] == (i % 6 != 0));
    assert(vpn_return_reclaims[i] == (i % 6 == 1));
    assert(root_callbacks[i] == (i % 6 == 0 || i % 6 == 3 || i % 6 == 5));
    assert(vpn_callbacks[i] == (i % 6 == 1 || i % 6 == 4));
  }
  product_origin_reclaim_t empty = {0};
  product_origin_reclaim_flush(&vm, &empty);
  assert(native_free_calls == 3 && product_packet_graph_main.lifecycle_settlements == 23);
  reset();
  frame.n_vectors = 2;
  prepare_origin(0, PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE, PRODUCT_COMPLETION_TRACE);
  prepare_origin(1, PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE, 0);
  frame.vectors[0] = 0; frame.vectors[1] = 1;
  assert(product_packet_origin_completion_node_fn(&vm, &node, &frame) == 2);
#ifdef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT
  assert(root_window_calls == 1);
#endif
  assert(native_free_calls == 0 && root_pool_returns[0] == 1 && root_pool_returns[1] == 1);
  assert(product_packet_graph_main.lifecycle_buffers == 0 && product_packet_graph_main.lifecycle_completion_frames == 0);
  assert(product_packet_graph_main.lifecycle_obligations == 0 && product_packet_graph_main.lifecycle_settlements == 2);
  reset();
  prepare_origin(0, PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE,
    PRODUCT_COMPLETION_REPLAY_PROBE | PRODUCT_COMPLETION_TRACE);
  frame.n_vectors = 1; frame.vectors[0] = 0;
  assert(product_packet_origin_completion_node_fn(&vm, &node, &frame) == 1);
  assert(native_free_calls == 1 && native_frees[0] == 1 && !root_pool_returns[0]);
  assert(product_packet_graph_main.lifecycle_buffers == 0 && product_packet_graph_main.lifecycle_completion_frames == 0);
  assert(product_packet_graph_main.lifecycle_obligations == 0 && product_packet_graph_main.lifecycle_settlements == 0);
  assert(product_packet_graph_main.lifecycle_returns == 0);
  puts("PASS actual origin node/reclaim: mixed Root/VPN/graph/replay, 16-window native free, free-before-VPN credit, local trace, exact pool/native returns and final debt");
}

int main(void) {
  page_bytes = (size_t)sysconf(_SC_PAGESIZE);
  assert(page_bytes >= sizeof(vlib_buffer_t));
  arena = mmap(0, page_bytes * TEST_BUFFERS, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(arena != MAP_FAILED);
  setvbuf(stdout, 0, _IONBF, 0);
  primary_partial();
  primary_boundaries();
  completion_partial();
  completion_dispatch_and_direct();
  retry_wrap_and_drain();
  held_and_blocked_target();
  origin_reclaim();
  assert(munmap(arena, page_bytes * TEST_BUFFERS) == 0);
  puts("PASS actual Product primary/completion/origin batch helpers and ON retry/origin nodes");
  return 0;
}
'''

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix="sakamoto-packet-batch-") as temporary:
    directory = Path(temporary)
    c_source = directory / "packet-batch.c"
    executable = directory / "packet-batch"
    c_source.write_text(prefix + types + dependencies + stats + primary_helpers + completion + retry + origin + suffix)
    for verdict_mode in (None, 1, 2, 3):
        flags = ([] if verdict_mode is None else [
            "-DSAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT=1",
            f"-DSAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE={verdict_mode}"])
        subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        *flags, "-I", str(PRODUCT), str(c_source), "-o", str(executable)],
                       check=True, timeout=30)
        subprocess.run([str(executable)], check=True, timeout=5)
        print("origin_verdict_mode=" + ("OFF" if verdict_mode is None else str(verdict_mode)))
for name, contents in (("graph", graph), ("admit", admit), ("completion", completion)):
    print(name + "_source_sha256=" + hashlib.sha256(contents.encode()).hexdigest())
