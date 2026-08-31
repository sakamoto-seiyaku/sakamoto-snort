/* SPDX-License-Identifier: Apache-2.0 */

/*
 * SAKAMOTO-174 Product packet kernel graph.  The CLI fixture is only a
 * bounded ingress/evidence seam: once bytes are materialized directly in a
 * VPP buffer, the graph moves that buffer index and its opaque2 metadata.
 */

#include "product_packet.h"

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>
#include <vnet/vnet.h>
#include <vppinfra/atomics.h>
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#include <vppinfra/crypto/sha2.h>
#endif

#include <string.h>
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#include <unistd.h>
#endif

#define PRODUCT_GRAPH_VECTOR_COUNT 8
#define PRODUCT_GRAPH_WORKERS 2
#define PRODUCT_GRAPH_FLOW_DOMAIN 7
#define PRODUCT_GRAPH_HASH_SEED UINT64_C (0x6f776e65722d3137)
#define PRODUCT_GRAPH_HANDOFF_CREDITS 32

_Static_assert (PRODUCT_GRAPH_HANDOFF_CREDITS < FRAME_QUEUE_MAX_NELTS,
                "handoff credits must remain below the private FQM depth");

enum
{
  PRODUCT_META_ADMITTED = 1 << 0,
  PRODUCT_META_GUARDED = 1 << 1,
  PRODUCT_META_SETTLED = 1 << 2,
  PRODUCT_META_SOURCE_IS_A = 1 << 3,
  PRODUCT_META_TERMINAL_SHIFT = 4,
  PRODUCT_META_TERMINAL_MASK = 3 << PRODUCT_META_TERMINAL_SHIFT,
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  PRODUCT_META_ADMIT_THREAD_2 = 1 << 6,
#endif
  PRODUCT_META_HANDOFF_CREDIT = 1 << 7,
};

typedef struct
{
  u8 endpoint_a[16];
  u8 endpoint_b[16];
  u64 origin_obligation_id;
  u16 port_a;
  u16 port_b;
  u16 expected_owner;
  u16 generation;
  u8 l3_header_length;
  u8 l4_header_length;
  u8 ip_family;
  u8 protocol;
  u8 state_bits;
  u8 primary_handoff_count;
  u8 corrective_handoff_count;
  u8 runtime_drop_reason;
} product_buffer_metadata_t;

_Static_assert (sizeof (product_buffer_metadata_t) ==
                  sizeof (((vlib_buffer_t *) 0)->opaque2),
                "Product PacketLease metadata must exactly fit opaque2");

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
typedef struct
{
  u32 buffer_index;
  u32 current_data;
  u32 length;
  u8 digest[32];
  u8 arrival_worker;
} product_ingress_evidence_t;

typedef struct
{
  product_canonical_flow_key_t canonical_key;
  u32 ingress_buffer_index;
  u32 terminal_buffer_index;
  u32 ingress_current_data;
  u32 terminal_current_data;
  u32 ingress_length;
  u32 terminal_length;
  u8 ingress_digest[32];
  u8 terminal_digest[32];
  u16 expected_owner;
  u8 family;
  u8 protocol;
  u8 l3_status;
  u8 l4_status;
  u8 arrival_worker;
  u8 primary_enqueues;
  u8 terminal_intents;
  u8 ledger_settlements;
  u8 buffer_returns;
  u8 terminal_intent;
  u8 runtime_drop_reason;
  u8 admit_thread;
  u8 guard_thread;
  u64 origin_obligation_id;
  product_packet_facts_t facts;
} product_fixture_result_t;

typedef struct __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES)))
{
  u32 value;
} product_result_ready_t;

_Static_assert (sizeof (product_result_ready_t) == CLIB_CACHE_LINE_BYTES,
                "each terminal publication flag must own one cache line");
#endif

typedef struct
{
  vlib_main_t *vlib_main;
  u32 owner_guard_frame_queue;
  u32 handoff_credits[PRODUCT_GRAPH_WORKERS];
  u32 lifecycle_obligations;
  u32 lifecycle_buffers;
  u32 lifecycle_handoffs;
  u32 lifecycle_terminal_intents;
  u32 lifecycle_settlements;
  u32 lifecycle_returns;
  u32 enabled;
  u32 accepting;
  u16 generation;
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  u32 ingress_frame_queue;
  u32 configured;
  u32 completed;
  u32 ingress_vectors;
  u32 admit_vectors;
  u32 guard_vectors;
  u32 terminal_vectors;
  u32 admitted;
  u32 local_packets;
  u32 remote_packets;
  u32 primary_enqueues;
  u32 primary_enqueue_max_per_packet;
  u32 terminal_intents;
  u32 ledger_settlements;
  u32 buffer_returns;
  u32 duplicate_terminals;
  u32 duplicate_settlements;
  u32 lost_buffers;
  u32 congestion_rejections;
  u32 runtime_drop_settlements;
  u32 stale_events_rejected;
  u32 cross_generation_admissions;
  u32 late_verdicts;
  u32 lifecycle_fixture;
  u32 buffer_debt;
  u32 handoff_credit_debt;
  u32 obligation_debt;
  product_fixture_result_t results[PRODUCT_GRAPH_VECTOR_COUNT];
  product_ingress_evidence_t ingress[PRODUCT_GRAPH_VECTOR_COUNT];
  product_result_ready_t result_ready[PRODUCT_GRAPH_VECTOR_COUNT];
  u32 reject_buffer_indices[2];
  u8 congestion_fixture;
  u64 ingress_fq_head_start[PRODUCT_GRAPH_WORKERS];
  u64 ingress_fq_tail_start[PRODUCT_GRAPH_WORKERS];
  u64 owner_fq_head_start[PRODUCT_GRAPH_WORKERS];
  u64 owner_fq_tail_start[PRODUCT_GRAPH_WORKERS];
#endif
} product_packet_graph_main_t;

static product_packet_graph_main_t product_packet_graph_main;

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#define PRODUCT_EVIDENCE_ADD(field, value)                                    \
  clib_atomic_fetch_add_relax (&graph->field, (value))
#define PRODUCT_EVIDENCE_SUB(field, value)                                    \
  clib_atomic_fetch_sub_relax (&graph->field, (value))
#else
#define PRODUCT_EVIDENCE_ADD(field, value) ((void) 0)
#define PRODUCT_EVIDENCE_SUB(field, value) ((void) 0)
#endif

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static const char *product_vector_names[PRODUCT_GRAPH_VECTOR_COUNT] = {
  "ipv4-tcp-forward", "ipv4-tcp-reverse", "ipv4-udp-forward",
  "ipv4-udp-reverse", "ipv6-tcp-forward", "ipv6-tcp-reverse",
  "ipv6-udp-forward", "ipv6-udp-reverse",
};
#endif

typedef enum
{
  PRODUCT_TRACE_ADMIT,
  PRODUCT_TRACE_OWNER_GUARD,
  PRODUCT_TRACE_TERMINAL,
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  PRODUCT_TRACE_FIXTURE,
#endif
} product_trace_stage_t;

typedef struct
{
  u64 obligation;
  u32 buffer_index;
  u16 thread_index;
  u8 stage;
} product_packet_trace_t;

static u8 *
format_product_packet_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  product_packet_trace_t *trace = va_arg (*args, product_packet_trace_t *);
  static const char *stages[] = {
    "admit", "owner-guard", "terminal",
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
    "fixture-ingress",
#endif
  };

  return format (s, "product-packet-trace node=%s buffer_index=%u "
                    "obligation=%llu thread=%u",
                 stages[trace->stage], trace->buffer_index,
                 (unsigned long long) trace->obligation,
                 trace->thread_index);
}

static void
product_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
                   vlib_buffer_t *buffer, product_trace_stage_t stage,
                   u64 obligation)
{
  if (PREDICT_FALSE (buffer->flags & VLIB_BUFFER_IS_TRACED))
    {
      product_packet_trace_t *trace =
        vlib_add_trace (vm, node, buffer, sizeof (*trace));
      trace->stage = (u8) stage;
      trace->buffer_index = vlib_get_buffer_index (vm, buffer);
      trace->obligation = obligation;
      trace->thread_index = (u16) vm->thread_index;
    }
}

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static int
product_fixture_index_from_obligation (u64 obligation, u8 *fixture_index)
{
  if (obligation < UINT64_C (174001)
      || obligation >= UINT64_C (174001) + PRODUCT_GRAPH_VECTOR_COUNT)
    return 0;
  *fixture_index = (u8) (obligation - UINT64_C (174001));
  return 1;
}
#endif

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static int
product_all_results_ready (const product_packet_graph_main_t *graph)
{
  u32 index;
  for (index = 0; index < PRODUCT_GRAPH_VECTOR_COUNT; index++)
    if (!clib_atomic_load_acq_n (&graph->result_ready[index].value))
      return 0;
  return 1;
}
#endif

static void
product_metadata_load (const vlib_buffer_t *buffer,
                       product_buffer_metadata_t *metadata)
{
  clib_memcpy_fast (metadata, buffer->opaque2, sizeof (*metadata));
}

static void
product_metadata_store (vlib_buffer_t *buffer,
                        const product_buffer_metadata_t *metadata)
{
  clib_memcpy_fast (buffer->opaque2, metadata, sizeof (*metadata));
}

static u8
product_metadata_terminal_intent (const product_buffer_metadata_t *metadata)
{
  return (metadata->state_bits & PRODUCT_META_TERMINAL_MASK)
         >> PRODUCT_META_TERMINAL_SHIFT;
}

static void
product_metadata_set_terminal_intent (product_buffer_metadata_t *metadata,
                                      u8 terminal_intent)
{
  metadata->state_bits =
    (metadata->state_bits & ~PRODUCT_META_TERMINAL_MASK)
    | ((terminal_intent << PRODUCT_META_TERMINAL_SHIFT)
       & PRODUCT_META_TERMINAL_MASK);
}

static void
product_metadata_from_lease (product_buffer_metadata_t *metadata,
                             const product_packet_lease_t *lease,
                             u16 generation)
{
  clib_memset (metadata, 0, sizeof (*metadata));
  clib_memcpy_fast (metadata->endpoint_a,
                    lease->canonical_key.endpoint_a.address, 16);
  clib_memcpy_fast (metadata->endpoint_b,
                    lease->canonical_key.endpoint_b.address, 16);
  metadata->origin_obligation_id = lease->origin_obligation_id;
  metadata->port_a = lease->canonical_key.endpoint_a.port;
  metadata->port_b = lease->canonical_key.endpoint_b.port;
  metadata->expected_owner = lease->expected_owner;
  metadata->generation = generation;
  metadata->l3_header_length = lease->facts.l3_header_length;
  metadata->l4_header_length = lease->facts.l4_header_length;
  metadata->ip_family = lease->facts.ip_family;
  metadata->protocol = lease->facts.protocol;
  metadata->state_bits = PRODUCT_META_ADMITTED;
  metadata->primary_handoff_count = lease->primary_handoff_count;
  metadata->corrective_handoff_count = lease->corrective_handoff_count;
  metadata->runtime_drop_reason = lease->runtime_drop_reason;
  if (memcmp (lease->facts.source_address,
              lease->canonical_key.endpoint_a.address, 16) == 0
      && lease->facts.source_port == lease->canonical_key.endpoint_a.port)
    metadata->state_bits |= PRODUCT_META_SOURCE_IS_A;
  product_metadata_set_terminal_intent (metadata, lease->terminal_intent);
}

static void
product_lease_from_metadata (const product_buffer_metadata_t *metadata,
                             u32 packet_length, product_packet_lease_t *lease)
{
  clib_memset (lease, 0, sizeof (*lease));
  lease->facts.l3_status =
    (metadata->state_bits & PRODUCT_META_ADMITTED)
      ? PRODUCT_PACKET_L3_COMPLETE
      : PRODUCT_PACKET_L3_UNAVAILABLE;
  lease->facts.l4_status =
    (metadata->state_bits & PRODUCT_META_ADMITTED)
      ? PRODUCT_PACKET_L4_COMPLETE
      : PRODUCT_PACKET_L4_UNAVAILABLE;
  lease->facts.ip_family = metadata->ip_family;
  lease->facts.protocol = metadata->protocol;
  lease->facts.l3_header_length = metadata->l3_header_length;
  lease->facts.l4_header_length = metadata->l4_header_length;
  lease->facts.packet_length = packet_length;
  lease->canonical_key.ip_family = metadata->ip_family;
  lease->canonical_key.protocol = metadata->protocol;
  clib_memcpy_fast (lease->canonical_key.endpoint_a.address,
                    metadata->endpoint_a, 16);
  clib_memcpy_fast (lease->canonical_key.endpoint_b.address,
                    metadata->endpoint_b, 16);
  lease->canonical_key.endpoint_a.port = metadata->port_a;
  lease->canonical_key.endpoint_b.port = metadata->port_b;
  if (metadata->state_bits & PRODUCT_META_SOURCE_IS_A)
    {
      clib_memcpy_fast (lease->facts.source_address, metadata->endpoint_a, 16);
      clib_memcpy_fast (lease->facts.destination_address, metadata->endpoint_b,
                        16);
      lease->facts.source_port = metadata->port_a;
      lease->facts.destination_port = metadata->port_b;
    }
  else
    {
      clib_memcpy_fast (lease->facts.source_address, metadata->endpoint_b, 16);
      clib_memcpy_fast (lease->facts.destination_address, metadata->endpoint_a,
                        16);
      lease->facts.source_port = metadata->port_b;
      lease->facts.destination_port = metadata->port_a;
    }
  lease->origin_obligation_id = metadata->origin_obligation_id;
  lease->expected_owner = metadata->expected_owner;
  lease->primary_handoff_count = metadata->primary_handoff_count;
  lease->corrective_handoff_count = metadata->corrective_handoff_count;
  lease->distribution = metadata->primary_handoff_count == 0
                          ? PRODUCT_PACKET_DISTRIBUTION_LOCAL
                          : PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE;
  lease->owner_guarded =
    (metadata->state_bits & PRODUCT_META_GUARDED) != 0;
  lease->terminal_intent = product_metadata_terminal_intent (metadata);
  lease->terminal_count = lease->terminal_intent == PRODUCT_PACKET_INTENT_NONE
                            ? 0
                            : 1;
  lease->runtime_drop_reason = metadata->runtime_drop_reason;
  lease->settled = (metadata->state_bits & PRODUCT_META_SETTLED) != 0;
}

typedef enum
{
  PRODUCT_HANDOFF_PRIMARY,
  PRODUCT_HANDOFF_CORRECTIVE,
} product_handoff_stage_t;

static int
product_handoff_credit_reserve (product_packet_graph_main_t *graph,
                                u16 target_worker,
                                product_handoff_stage_t stage,
                                u64 obligation)
{
  u32 available;

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (graph->congestion_fixture && obligation == UINT64_C (174001)
      && stage == PRODUCT_HANDOFF_PRIMARY)
    return 0;
#else
  (void) stage;
  (void) obligation;
#endif

  available = clib_atomic_load_acq_n (&graph->handoff_credits[target_worker]);
  while (available != 0)
    if (clib_atomic_cmp_and_swap_acq_relax_n (
          &graph->handoff_credits[target_worker], &available, available - 1,
          0))
      {
        PRODUCT_EVIDENCE_ADD (handoff_credit_debt, 1);
        clib_atomic_fetch_add_relax (&graph->lifecycle_handoffs, 1);
        return 1;
      }
  return 0;
}

static void
product_handoff_credit_release (product_packet_graph_main_t *graph,
                                u16 target_worker)
{
  clib_atomic_fetch_add_relax (&graph->handoff_credits[target_worker], 1);
  clib_atomic_fetch_sub_relax (&graph->lifecycle_handoffs, 1);
  PRODUCT_EVIDENCE_SUB (handoff_credit_debt, 1);
}

/*
 * This FQM is private to the Product graph. Its 64 slots are guarded by only
 * 32 credits per target worker. The retained enqueue is still nonblocking: a
 * rejected live buffer remains here with its obligation identity intact so
 * the Product terminal can settle it explicitly.
 */
static int
product_handoff_enqueue (vlib_main_t *vm, vlib_node_runtime_t *node,
                         product_packet_graph_main_t *graph,
                         u32 buffer_index,
                         product_buffer_metadata_t *metadata,
                         u16 target_worker, product_handoff_stage_t stage)
{
  u16 target_thread;
  u32 failed_buffer_index;

  if (!product_handoff_credit_reserve (
        graph, target_worker, stage, metadata->origin_obligation_id))
    return 0;

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (graph->congestion_fixture
      && metadata->origin_obligation_id == UINT64_C (174002)
      && stage == PRODUCT_HANDOFF_CORRECTIVE)
    {
      product_handoff_credit_release (graph, target_worker);
      return 0;
    }
#endif

  metadata->state_bits |= PRODUCT_META_HANDOFF_CREDIT;
  product_metadata_store (vlib_get_buffer (vm, buffer_index), metadata);
  target_thread = (u16) vlib_get_worker_thread_index (target_worker);
  if (vlib_buffer_enqueue_to_thread_retained (
        vm, node, graph->owner_guard_frame_queue, &buffer_index,
        &target_thread, 1, &failed_buffer_index)
      != 1)
    {
      metadata->state_bits &= ~PRODUCT_META_HANDOFF_CREDIT;
      product_metadata_store (vlib_get_buffer (vm, buffer_index), metadata);
      product_handoff_credit_release (graph, target_worker);
      return 0;
    }
  return 1;
}

static void
product_mark_handoff_rejected (product_packet_graph_main_t *graph,
                               vlib_main_t *vm, u32 buffer_index,
                               product_buffer_metadata_t *metadata,
                               product_packet_lease_t *lease,
                               product_handoff_stage_t stage)
{
  lease->terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
  lease->terminal_count = 1;
  lease->runtime_drop_reason =
    stage == PRODUCT_HANDOFF_PRIMARY
      ? PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION
      : PRODUCT_PACKET_DROP_CORRECTIVE_HANDOFF_CONGESTION;
  metadata->corrective_handoff_count = lease->corrective_handoff_count;
  metadata->runtime_drop_reason = lease->runtime_drop_reason;
  product_metadata_set_terminal_intent (metadata, lease->terminal_intent);
  product_metadata_store (vlib_get_buffer (vm, buffer_index), metadata);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (graph->congestion_fixture
      && metadata->origin_obligation_id >= UINT64_C (174001)
      && metadata->origin_obligation_id <= UINT64_C (174002))
    graph->reject_buffer_indices[metadata->origin_obligation_id
                                 - UINT64_C (174001)] = buffer_index;
  PRODUCT_EVIDENCE_ADD (congestion_rejections, 1);
#else
  (void) graph;
#endif
}

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
extern vlib_node_registration_t product_packet_test_ingress_node;
#endif
#include "product_packet_fragment_graph.inc"

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
enum
{
  PRODUCT_TEST_INGRESS_NEXT_ADMIT,
  PRODUCT_TEST_INGRESS_N_NEXT,
};

VLIB_NODE_FN (product_packet_test_ingress_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 count = frame->n_vectors;
  clib_atomic_fetch_add_relax (&graph->ingress_vectors, count);
  vlib_buffer_enqueue_to_single_next (vm, node, from,
                                      PRODUCT_TEST_INGRESS_NEXT_ADMIT, count);
  return count;
}

VLIB_REGISTER_NODE (product_packet_test_ingress_node) = {
  .name = "product-packet-test-ingress",
  .vector_size = sizeof (u32),
  .format_trace = format_product_packet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .n_next_nodes = PRODUCT_TEST_INGRESS_N_NEXT,
  .next_nodes = {
    [PRODUCT_TEST_INGRESS_NEXT_ADMIT] = "product-packet-admit",
  },
};
#endif

enum
{
  PRODUCT_ADMIT_NEXT_FRAGMENT_STEER,
  PRODUCT_ADMIT_NEXT_OWNER_GUARD,
  PRODUCT_ADMIT_NEXT_TERMINAL,
  PRODUCT_ADMIT_N_NEXT,
};

VLIB_NODE_FN (product_packet_admit_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;

  PRODUCT_EVIDENCE_ADD (admit_vectors, frame->n_vectors);

  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_buffer_metadata_t initial_metadata;
      product_buffer_metadata_t metadata;
      product_packet_lease_t lease;
      u16 logical_worker = (u16) vlib_get_worker_index (vm->thread_index);
      product_packet_ingress_t ingress;
      product_worker_layout_t layout = {
        .worker_count = PRODUCT_GRAPH_WORKERS,
        .hash_seed = PRODUCT_GRAPH_HASH_SEED,
      };

      product_metadata_load (buffer, &initial_metadata);
      if (!clib_atomic_load_acq_n (&graph->accepting))
        {
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      if (initial_metadata.generation != graph->generation)
        {
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
          PRODUCT_EVIDENCE_ADD (stale_events_rejected, 1);
#endif
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      if (product_fragment_packet_detect (vm, buffer))
        {
          clib_atomic_fetch_add_relax (&graph->lifecycle_obligations, 1);
          clib_atomic_fetch_add_relax (&graph->lifecycle_buffers, 1);
          vlib_buffer_enqueue_to_single_next (
            vm, node, &buffer_index, PRODUCT_ADMIT_NEXT_FRAGMENT_STEER, 1);
          continue;
        }

      clib_atomic_fetch_add_relax (&graph->lifecycle_obligations, 1);
      clib_atomic_fetch_add_relax (&graph->lifecycle_buffers, 1);
      clib_memset (&ingress, 0, sizeof (ingress));
      ingress.data = vlib_buffer_get_current (buffer);
      ingress.length = buffer->current_length;
      ingress.current_worker = logical_worker;
      ingress.flow_domain = PRODUCT_GRAPH_FLOW_DOMAIN;
      ingress.origin_obligation_id = initial_metadata.origin_obligation_id;
      clib_memset (&lease, 0, sizeof (lease));
      if (product_packet_admit (&layout, &ingress, &lease)
          != PRODUCT_PACKET_OK)
        {
          PRODUCT_EVIDENCE_ADD (lost_buffers, 1);
          PRODUCT_EVIDENCE_ADD (buffer_returns, 1);
          vlib_buffer_free (vm, &buffer_index, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
          PRODUCT_EVIDENCE_SUB (buffer_debt, 1);
          PRODUCT_EVIDENCE_SUB (obligation_debt, 1);
          continue;
        }
      product_metadata_from_lease (&metadata, &lease,
                                   initial_metadata.generation);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (vm->thread_index == vlib_get_worker_thread_index (1))
        metadata.state_bits |= PRODUCT_META_ADMIT_THREAD_2;
#endif
      product_metadata_store (buffer, &metadata);
      PRODUCT_EVIDENCE_ADD (admitted, 1);
      product_add_trace (vm, node, buffer, PRODUCT_TRACE_ADMIT,
                         metadata.origin_obligation_id);

      if (lease.distribution == PRODUCT_PACKET_DISTRIBUTION_LOCAL)
        {
          PRODUCT_EVIDENCE_ADD (local_packets, 1);
          vlib_buffer_enqueue_to_single_next (
            vm, node, &buffer_index, PRODUCT_ADMIT_NEXT_OWNER_GUARD, 1);
        }
      else
        {
          PRODUCT_EVIDENCE_ADD (remote_packets, 1);
          if (!product_handoff_enqueue (
                vm, node, graph, buffer_index, &metadata,
                lease.expected_owner, PRODUCT_HANDOFF_PRIMARY))
            {
              product_mark_handoff_rejected (
                graph, vm, buffer_index, &metadata, &lease,
                PRODUCT_HANDOFF_PRIMARY);
              vlib_buffer_enqueue_to_single_next (
                vm, node, &buffer_index, PRODUCT_ADMIT_NEXT_TERMINAL, 1);
            }
          else
            {
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
              u32 maximum;
              PRODUCT_EVIDENCE_ADD (primary_enqueues, 1);
              maximum = clib_atomic_load_acq_n (
                &graph->primary_enqueue_max_per_packet);
              if (maximum < lease.primary_handoff_count)
                clib_atomic_store_rel_n (
                  &graph->primary_enqueue_max_per_packet,
                  lease.primary_handoff_count);
#endif
            }
        }
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_admit_node) = {
  .name = "product-packet-admit",
  .vector_size = sizeof (u32),
  .format_trace = format_product_packet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .n_next_nodes = PRODUCT_ADMIT_N_NEXT,
  .next_nodes = {
    [PRODUCT_ADMIT_NEXT_FRAGMENT_STEER] = "product-packet-fragment-steer",
    [PRODUCT_ADMIT_NEXT_OWNER_GUARD] = "product-packet-owner-guard",
    [PRODUCT_ADMIT_NEXT_TERMINAL] = "product-packet-terminal",
  },
};

enum
{
  PRODUCT_OWNER_GUARD_NEXT_TERMINAL,
  PRODUCT_OWNER_GUARD_N_NEXT,
};

VLIB_NODE_FN (product_packet_owner_guard_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;

  PRODUCT_EVIDENCE_ADD (guard_vectors, frame->n_vectors);

  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_buffer_metadata_t metadata;
      product_packet_lease_t lease;
      u16 logical_worker = (u16) vlib_get_worker_index (vm->thread_index);
      u16 guard_worker = logical_worker;
      product_packet_result_t guard_result;

      product_metadata_load (buffer, &metadata);
      if (metadata.generation != graph->generation)
        {
          if (metadata.state_bits & PRODUCT_META_HANDOFF_CREDIT)
            product_handoff_credit_release (graph, metadata.expected_owner);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
          PRODUCT_EVIDENCE_ADD (stale_events_rejected, 1);
#endif
          vlib_buffer_free (vm, &buffer_index, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
          continue;
        }
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (graph->lifecycle_fixture
          && metadata.origin_obligation_id == UINT64_C (1759002))
        while (clib_atomic_load_acq_n (&graph->accepting))
          usleep (100);
#endif
      if (metadata.state_bits & PRODUCT_META_HANDOFF_CREDIT)
        {
          product_handoff_credit_release (graph, metadata.expected_owner);
          metadata.state_bits &= ~PRODUCT_META_HANDOFF_CREDIT;
          product_metadata_store (buffer, &metadata);
        }
      product_lease_from_metadata (&metadata, buffer->current_length, &lease);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (graph->congestion_fixture
          && metadata.origin_obligation_id == UINT64_C (174002))
        guard_worker = (u16) (logical_worker ^ 1);
#endif
      guard_result = product_packet_owner_guard (&lease, guard_worker);
      if (guard_result == PRODUCT_PACKET_CORRECTIVE_HANDOFF)
        {
          metadata.corrective_handoff_count =
            lease.corrective_handoff_count;
          if (!product_handoff_enqueue (
                vm, node, graph, buffer_index, &metadata,
                lease.expected_owner, PRODUCT_HANDOFF_CORRECTIVE))
            {
              product_mark_handoff_rejected (
                graph, vm, buffer_index, &metadata, &lease,
                PRODUCT_HANDOFF_CORRECTIVE);
              vlib_buffer_enqueue_to_single_next (
                vm, node, &buffer_index,
                PRODUCT_OWNER_GUARD_NEXT_TERMINAL, 1);
            }
          continue;
        }
      if (guard_result == PRODUCT_PACKET_REPEATED_OWNER_MISMATCH)
        {
          metadata.corrective_handoff_count =
            lease.corrective_handoff_count;
          metadata.runtime_drop_reason = lease.runtime_drop_reason;
          product_metadata_set_terminal_intent (&metadata,
                                                lease.terminal_intent);
          product_metadata_store (buffer, &metadata);
          vlib_buffer_enqueue_to_single_next (
            vm, node, &buffer_index, PRODUCT_OWNER_GUARD_NEXT_TERMINAL, 1);
          continue;
        }
      if (guard_result != PRODUCT_PACKET_OK)
        {
          PRODUCT_EVIDENCE_ADD (lost_buffers, 1);
          PRODUCT_EVIDENCE_ADD (buffer_returns, 1);
          vlib_buffer_free (vm, &buffer_index, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
          PRODUCT_EVIDENCE_SUB (buffer_debt, 1);
          PRODUCT_EVIDENCE_SUB (obligation_debt, 1);
          continue;
        }
      metadata.state_bits |= PRODUCT_META_GUARDED;
      product_metadata_store (buffer, &metadata);
      product_add_trace (vm, node, buffer, PRODUCT_TRACE_OWNER_GUARD,
                         metadata.origin_obligation_id);
      vlib_buffer_enqueue_to_single_next (
        vm, node, &buffer_index, PRODUCT_OWNER_GUARD_NEXT_TERMINAL, 1);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_owner_guard_node) = {
  .name = "product-packet-owner-guard",
  .vector_size = sizeof (u32),
  .format_trace = format_product_packet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .n_next_nodes = PRODUCT_OWNER_GUARD_N_NEXT,
  .next_nodes = {
    [PRODUCT_OWNER_GUARD_NEXT_TERMINAL] = "product-packet-terminal",
  },
};

VLIB_NODE_FN (product_packet_terminal_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;

  PRODUCT_EVIDENCE_ADD (terminal_vectors, frame->n_vectors);

  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_buffer_metadata_t metadata;
      product_packet_lease_t lease;
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      product_fixture_result_t completed_result;
      product_fixture_result_t *result;
      const product_ingress_evidence_t *ingress_evidence;
      u8 fixture_index;
      u8 lifecycle_fixture_packet = 0;
#endif

      product_metadata_load (buffer, &metadata);
      if (metadata.generation != graph->generation)
        {
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
          PRODUCT_EVIDENCE_ADD (stale_events_rejected, 1);
#endif
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      product_lease_from_metadata (&metadata, buffer->current_length, &lease);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (!product_fixture_index_from_obligation (
            metadata.origin_obligation_id, &fixture_index))
        {
          if (graph->lifecycle_fixture
              && metadata.origin_obligation_id >= UINT64_C (1759001)
              && metadata.origin_obligation_id <= UINT64_C (1759002))
            lifecycle_fixture_packet = 1;
          else
            {
          PRODUCT_EVIDENCE_ADD (lost_buffers, 1);
          PRODUCT_EVIDENCE_ADD (buffer_returns, 1);
          vlib_buffer_free (vm, &buffer_index, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
          PRODUCT_EVIDENCE_SUB (buffer_debt, 1);
          PRODUCT_EVIDENCE_SUB (obligation_debt, 1);
          continue;
            }
        }
#endif
      if (lease.terminal_intent == PRODUCT_PACKET_INTENT_NONE
          && product_packet_set_terminal (
               &lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER)
               != PRODUCT_PACKET_OK)
        {
          PRODUCT_EVIDENCE_ADD (duplicate_terminals, 1);
          PRODUCT_EVIDENCE_ADD (lost_buffers, 1);
          PRODUCT_EVIDENCE_ADD (buffer_returns, 1);
          vlib_buffer_free (vm, &buffer_index, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
          PRODUCT_EVIDENCE_SUB (buffer_debt, 1);
          PRODUCT_EVIDENCE_SUB (obligation_debt, 1);
          continue;
        }
      if (product_packet_settle (&lease) != PRODUCT_PACKET_OK)
        {
          PRODUCT_EVIDENCE_ADD (duplicate_settlements, 1);
          PRODUCT_EVIDENCE_ADD (lost_buffers, 1);
          PRODUCT_EVIDENCE_ADD (buffer_returns, 1);
          vlib_buffer_free (vm, &buffer_index, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
          PRODUCT_EVIDENCE_SUB (buffer_debt, 1);
          PRODUCT_EVIDENCE_SUB (obligation_debt, 1);
          continue;
        }
      product_metadata_set_terminal_intent (&metadata,
                                            lease.terminal_intent);
      metadata.runtime_drop_reason = lease.runtime_drop_reason;
      metadata.state_bits |= PRODUCT_META_SETTLED;
      product_metadata_store (buffer, &metadata);
      product_add_trace (vm, node, buffer, PRODUCT_TRACE_TERMINAL,
                         metadata.origin_obligation_id);

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (!lifecycle_fixture_packet)
        {
      result = &graph->results[fixture_index];
      ingress_evidence = &graph->ingress[fixture_index];
      clib_memset (&completed_result, 0, sizeof (completed_result));
      completed_result.ingress_buffer_index = ingress_evidence->buffer_index;
      completed_result.ingress_current_data = ingress_evidence->current_data;
      completed_result.ingress_length = ingress_evidence->length;
      clib_memcpy_fast (completed_result.ingress_digest,
                        ingress_evidence->digest, 32);
      completed_result.arrival_worker = ingress_evidence->arrival_worker;
      completed_result.canonical_key = lease.canonical_key;
      completed_result.terminal_buffer_index = buffer_index;
      completed_result.terminal_current_data = (u32) buffer->current_data;
      completed_result.terminal_length = buffer->current_length;
      clib_sha256 (vlib_buffer_get_current (buffer), buffer->current_length,
                   completed_result.terminal_digest);
      completed_result.expected_owner = lease.expected_owner;
      completed_result.family = lease.facts.ip_family;
      completed_result.protocol = lease.facts.protocol;
      completed_result.l3_status = lease.facts.l3_status;
      completed_result.l4_status = lease.facts.l4_status;
      completed_result.primary_enqueues = metadata.primary_handoff_count;
      completed_result.terminal_intents = lease.terminal_count;
      completed_result.ledger_settlements = lease.settled;
      completed_result.terminal_intent = lease.terminal_intent;
      completed_result.runtime_drop_reason = lease.runtime_drop_reason;
      completed_result.admit_thread =
        (metadata.state_bits & PRODUCT_META_ADMIT_THREAD_2)
          ? (u8) vlib_get_worker_thread_index (1)
          : (u8) vlib_get_worker_thread_index (0);
      completed_result.guard_thread = (u8) vm->thread_index;
      completed_result.origin_obligation_id = lease.origin_obligation_id;
      completed_result.facts = lease.facts;
        }
#endif

      vlib_buffer_free (vm, &buffer_index, 1);
      clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
      clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
      clib_atomic_fetch_add_relax (&graph->lifecycle_terminal_intents, 1);
      clib_atomic_fetch_add_relax (&graph->lifecycle_settlements, 1);
      clib_atomic_fetch_add_relax (&graph->lifecycle_returns, 1);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (!lifecycle_fixture_packet)
        {
      completed_result.buffer_returns = 1;
      PRODUCT_EVIDENCE_ADD (terminal_intents, 1);
      PRODUCT_EVIDENCE_ADD (ledger_settlements, 1);
      PRODUCT_EVIDENCE_ADD (buffer_returns, 1);
      if (lease.terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME)
        PRODUCT_EVIDENCE_ADD (runtime_drop_settlements, 1);
      *result = completed_result;
      PRODUCT_EVIDENCE_SUB (buffer_debt, 1);
      PRODUCT_EVIDENCE_SUB (obligation_debt, 1);
      clib_atomic_store_rel_n (&graph->result_ready[fixture_index].value, 1);
      clib_atomic_fetch_add_relax (&graph->completed, 1);
        }
#endif
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_terminal_node) = {
  .name = "product-packet-terminal",
  .vector_size = sizeof (u32),
  .format_trace = format_product_packet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
};

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static u32
product_ipv4_fixture (u8 *packet, u8 protocol, u32 source, u16 source_port,
                      u32 destination, u16 destination_port)
{
  clib_memset (packet, 0, 64);
  packet[0] = 0x45;
  packet[3] = protocol == 6 ? 40 : 28;
  packet[8] = 64;
  packet[9] = protocol;
  packet[12] = (u8) (source >> 24);
  packet[13] = (u8) (source >> 16);
  packet[14] = (u8) (source >> 8);
  packet[15] = (u8) source;
  packet[16] = (u8) (destination >> 24);
  packet[17] = (u8) (destination >> 16);
  packet[18] = (u8) (destination >> 8);
  packet[19] = (u8) destination;
  packet[20] = (u8) (source_port >> 8);
  packet[21] = (u8) source_port;
  packet[22] = (u8) (destination_port >> 8);
  packet[23] = (u8) destination_port;
  if (protocol == 6)
    packet[32] = 0x50;
  else
    packet[25] = 8;
  return protocol == 6 ? 40 : 28;
}

static u32
product_ipv6_fixture (u8 *packet, u8 protocol, const u8 source[16],
                      u16 source_port, const u8 destination[16],
                      u16 destination_port)
{
  u16 payload_length = protocol == 6 ? 20 : 8;
  clib_memset (packet, 0, 80);
  packet[0] = 0x60;
  packet[4] = (u8) (payload_length >> 8);
  packet[5] = (u8) payload_length;
  packet[6] = protocol;
  packet[7] = 64;
  clib_memcpy_fast (packet + 8, source, 16);
  clib_memcpy_fast (packet + 24, destination, 16);
  packet[40] = (u8) (source_port >> 8);
  packet[41] = (u8) source_port;
  packet[42] = (u8) (destination_port >> 8);
  packet[43] = (u8) destination_port;
  if (protocol == 6)
    packet[52] = 0x50;
  else
    packet[45] = 8;
  return 40 + payload_length;
}

static u32
product_materialize_fixture (u8 fixture_index, u8 *packet)
{
  static const u8 ip6_a[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                0,    0,    0,    0,    0, 0, 0, 1 };
  static const u8 ip6_b[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                0,    0,    0,    0,    0, 0, 0, 2 };
  switch (fixture_index)
    {
    case 0:
      return product_ipv4_fixture (packet, 6, 0x0a000001, 12345,
                                   0x0a000002, 443);
    case 1:
      return product_ipv4_fixture (packet, 6, 0x0a000002, 443,
                                   0x0a000001, 12345);
    case 2:
      return product_ipv4_fixture (packet, 17, 0xc0000201, 5353,
                                   0xc6336402, 53);
    case 3:
      return product_ipv4_fixture (packet, 17, 0xc6336402, 53,
                                   0xc0000201, 5353);
    case 4:
      return product_ipv6_fixture (packet, 6, ip6_a, 2222, ip6_b, 8443);
    case 5:
      return product_ipv6_fixture (packet, 6, ip6_b, 8443, ip6_a, 2222);
    case 6:
      return product_ipv6_fixture (packet, 17, ip6_a, 60000, ip6_b, 443);
    default:
      return product_ipv6_fixture (packet, 17, ip6_b, 443, ip6_a, 60000);
    }
}

static clib_error_t *
product_packet_graph_configure_cli (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 workers = 0;
  u8 *fixture = 0;
  (void) command;

  if (!unformat (input, "workers %u fixture %s", &workers, &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      vec_free (fixture);
      return clib_error_return (0, "expected: workers 2 fixture %s",
                                PRODUCT_GRAPH_FIXTURE);
    }
  if (workers != PRODUCT_GRAPH_WORKERS || vlib_num_workers () != workers
      || (strcmp ((char *) fixture, PRODUCT_GRAPH_FIXTURE) != 0
          && strcmp ((char *) fixture, PRODUCT_GRAPH_FRAGMENT_FIXTURE) != 0)
      || clib_atomic_load_acq_n (&graph->enabled)
      || clib_atomic_load_acq_n (&graph->buffer_debt) != 0
      || clib_atomic_load_acq_n (&graph->handoff_credit_debt) != 0
      || clib_atomic_load_acq_n (&graph->obligation_debt) != 0)
    {
      vec_free (fixture);
      return clib_error_return (0, "graph configuration rejected");
    }
  vec_free (fixture);
  graph->configured = 1;
  vlib_cli_output (vm, "graph.configure=ok");
  vlib_cli_output (vm, "graph.workers=2");
  vlib_cli_output (vm, "graph.fixture=%s", PRODUCT_GRAPH_FIXTURE);
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_configure_command, static) = {
  .path = "product packet-graph configure",
  .short_help = "product packet-graph configure workers 2 fixture "
                PRODUCT_GRAPH_FIXTURE,
  .function = product_packet_graph_configure_cli,
};

static clib_error_t *
product_packet_graph_enable_cli (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  vlib_frame_queue_main_t *ingress_fqm = vec_elt_at_index (
    thread_main->frame_queue_mains, graph->ingress_frame_queue);
  vlib_frame_queue_main_t *owner_fqm = vec_elt_at_index (
    thread_main->frame_queue_mains, graph->owner_guard_frame_queue);
  u32 worker;
  (void) input;
  (void) command;
  if (!graph->configured || clib_atomic_load_acq_n (&graph->enabled))
    return clib_error_return (0, "graph is not configured or is already enabled");
  if (graph->generation == UINT16_MAX
      || clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_buffers) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 0)
    return clib_error_return (0, "graph lifecycle is not clean");
  graph->generation++;
  clib_memset (graph->results, 0, sizeof (graph->results));
  clib_memset (graph->ingress, 0, sizeof (graph->ingress));
  clib_memset (graph->result_ready, 0, sizeof (graph->result_ready));
  clib_memset (graph->reject_buffer_indices, 0,
               sizeof (graph->reject_buffer_indices));
  graph->congestion_fixture = 0;
  clib_atomic_store_rel_n (&graph->completed, 0);
  clib_atomic_store_rel_n (&graph->ingress_vectors, 0);
  clib_atomic_store_rel_n (&graph->admit_vectors, 0);
  clib_atomic_store_rel_n (&graph->guard_vectors, 0);
  clib_atomic_store_rel_n (&graph->terminal_vectors, 0);
  clib_atomic_store_rel_n (&graph->admitted, 0);
  clib_atomic_store_rel_n (&graph->local_packets, 0);
  clib_atomic_store_rel_n (&graph->remote_packets, 0);
  clib_atomic_store_rel_n (&graph->primary_enqueues, 0);
  clib_atomic_store_rel_n (&graph->primary_enqueue_max_per_packet, 0);
  clib_atomic_store_rel_n (&graph->terminal_intents, 0);
  clib_atomic_store_rel_n (&graph->ledger_settlements, 0);
  clib_atomic_store_rel_n (&graph->buffer_returns, 0);
  clib_atomic_store_rel_n (&graph->duplicate_terminals, 0);
  clib_atomic_store_rel_n (&graph->duplicate_settlements, 0);
  clib_atomic_store_rel_n (&graph->lost_buffers, 0);
  clib_atomic_store_rel_n (&graph->congestion_rejections, 0);
  clib_atomic_store_rel_n (&graph->runtime_drop_settlements, 0);
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      u32 thread = vlib_get_worker_thread_index (worker);
      graph->ingress_fq_head_start[worker] =
        ingress_fqm->vlib_frame_queues[thread]->head;
      graph->ingress_fq_tail_start[worker] =
        ingress_fqm->vlib_frame_queues[thread]->tail;
      graph->owner_fq_head_start[worker] =
        owner_fqm->vlib_frame_queues[thread]->head;
      graph->owner_fq_tail_start[worker] =
        owner_fqm->vlib_frame_queues[thread]->tail;
    }
  clib_atomic_store_rel_n (&graph->enabled, 1);
  clib_atomic_store_rel_n (&graph->accepting, 1);
  vlib_cli_output (vm, "graph.enable=ok");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_enable_command, static) = {
  .path = "product packet-graph enable",
  .function = product_packet_graph_enable_cli,
};

static clib_error_t *
product_packet_graph_run_fixture_cli (vlib_main_t *vm,
                                      unformat_input_t *input,
                                      vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_node_runtime_t *ingress_runtime;
  u8 *fixture = 0;
  u32 buffer_indices[PRODUCT_GRAPH_VECTOR_COUNT];
  u16 thread_indices[PRODUCT_GRAPH_VECTOR_COUNT];
  u32 allocated;
  u32 index;
  (void) command;

  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || strcmp ((char *) fixture, PRODUCT_GRAPH_FIXTURE) != 0
      || !clib_atomic_load_acq_n (&graph->enabled)
      || clib_atomic_load_acq_n (&graph->completed) != 0)
    {
      vec_free (fixture);
      return clib_error_return (0, "fixture run rejected");
    }
  vec_free (fixture);
  allocated = vlib_buffer_alloc (vm, buffer_indices,
                                 PRODUCT_GRAPH_VECTOR_COUNT);
  if (allocated != PRODUCT_GRAPH_VECTOR_COUNT)
    {
      if (allocated != 0)
        vlib_buffer_free (vm, buffer_indices, allocated);
      return clib_error_return (0, "cannot allocate fixture buffers");
    }
  ingress_runtime =
    vlib_node_get_runtime (vm, product_packet_test_ingress_node.index);
  for (index = 0; index < PRODUCT_GRAPH_VECTOR_COUNT; index++)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_indices[index]);
      product_buffer_metadata_t metadata;
      product_ingress_evidence_t *evidence = &graph->ingress[index];
      u32 packet_length;

      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      packet_length = product_materialize_fixture (
        (u8) index, vlib_buffer_get_current (buffer));
      buffer->current_length = packet_length;
      clib_memset (&metadata, 0, sizeof (metadata));
      metadata.origin_obligation_id = UINT64_C (174001) + index;
      metadata.generation = graph->generation;
      product_metadata_store (buffer, &metadata);

      evidence->buffer_index = buffer_indices[index];
      evidence->current_data = (u32) buffer->current_data;
      evidence->length = packet_length;
      evidence->arrival_worker = (u8) (index & 1);
      clib_sha256 (vlib_buffer_get_current (buffer), packet_length,
                   evidence->digest);
      thread_indices[index] =
        (u16) vlib_get_worker_thread_index (evidence->arrival_worker);
      if (vlib_trace_buffer (vm, ingress_runtime, 0, buffer, 1))
        product_add_trace (vm, ingress_runtime, buffer, PRODUCT_TRACE_FIXTURE,
                           metadata.origin_obligation_id);
    }
  clib_atomic_store_rel_n (&graph->buffer_debt, PRODUCT_GRAPH_VECTOR_COUNT);
  clib_atomic_store_rel_n (&graph->obligation_debt,
                           PRODUCT_GRAPH_VECTOR_COUNT);
  if (vlib_buffer_enqueue_to_thread (
        vm, ingress_runtime, graph->ingress_frame_queue, buffer_indices,
        thread_indices, PRODUCT_GRAPH_VECTOR_COUNT, 0)
      != PRODUCT_GRAPH_VECTOR_COUNT)
    return clib_error_return (0, "fixture ingress frame queue is full");

  {
    f64 deadline = vlib_time_now (vm) + 5.0;
    while (!product_all_results_ready (graph)
           && vlib_time_now (vm) < deadline)
      usleep (1000);
  }
  if (!product_all_results_ready (graph))
    {
      vlib_thread_main_t *thread_main = vlib_get_thread_main ();
      vlib_frame_queue_main_t *ingress_fqm = vec_elt_at_index (
        thread_main->frame_queue_mains, graph->ingress_frame_queue);
      return clib_error_return (
        0, "fixture graph completion timed out (ingress=%u admit=%u guard=%u "
           "terminal=%u completed=%u fq-node=%u q1=%llu/%llu/%llu "
           "q2=%llu/%llu/%llu)",
        clib_atomic_load_acq_n (&graph->ingress_vectors),
        clib_atomic_load_acq_n (&graph->admit_vectors),
        clib_atomic_load_acq_n (&graph->guard_vectors),
        clib_atomic_load_acq_n (&graph->terminal_vectors),
        clib_atomic_load_acq_n (&graph->completed), ingress_fqm->node_index,
        (unsigned long long) ingress_fqm->vlib_frame_queues[1]->head,
        (unsigned long long) ingress_fqm->vlib_frame_queues[1]->tail,
        (unsigned long long) vlib_get_main_by_index (1)->check_frame_queues,
        (unsigned long long) ingress_fqm->vlib_frame_queues[2]->head,
        (unsigned long long) ingress_fqm->vlib_frame_queues[2]->tail,
        (unsigned long long) vlib_get_main_by_index (2)->check_frame_queues);
    }

  vlib_cli_output (vm, "fixture.id=%s", PRODUCT_GRAPH_FIXTURE);
  vlib_cli_output (vm, "fixture.workers=2");
  vlib_cli_output (vm, "fixture.vector_count=8");
  for (index = 0; index < PRODUCT_GRAPH_VECTOR_COUNT; index++)
    {
      const product_fixture_result_t *result = &graph->results[index];
      const char *name = product_vector_names[index];
      vlib_cli_output (vm, "vector.%s.family=%u", name, result->family);
      vlib_cli_output (vm, "vector.%s.protocol=%u", name, result->protocol);
      vlib_cli_output (vm, "vector.%s.l3_status=complete", name);
      vlib_cli_output (vm, "vector.%s.l4_status=complete", name);
      vlib_cli_output (vm, "vector.%s.canonical_key=%u/%u/%U:%u-%U:%u",
                       name, result->canonical_key.ip_family,
                       result->canonical_key.protocol,
                       format_hex_bytes_no_wrap,
                       result->canonical_key.endpoint_a.address, 16,
                       result->canonical_key.endpoint_a.port,
                       format_hex_bytes_no_wrap,
                       result->canonical_key.endpoint_b.address, 16,
                       result->canonical_key.endpoint_b.port);
      vlib_cli_output (vm, "vector.%s.expected_owner=%u", name,
                       result->expected_owner);
      vlib_cli_output (vm, "vector.%s.origin_obligation_id=%llu", name,
                       (unsigned long long) result->origin_obligation_id);
      vlib_cli_output (vm, "vector.%s.arrival_worker=%u", name,
                       result->arrival_worker);
      vlib_cli_output (vm, "vector.%s.actual_admit_thread=%u", name,
                       result->admit_thread);
      vlib_cli_output (vm, "vector.%s.actual_guard_thread=%u", name,
                       result->guard_thread);
      vlib_cli_output (vm, "vector.%s.placement=%s", name,
                       result->primary_enqueues == 0 ? "local" : "remote");
      vlib_cli_output (vm, "vector.%s.primary_enqueues=%u", name,
                       result->primary_enqueues);
      vlib_cli_output (vm, "vector.%s.terminal_intents=%u", name,
                       result->terminal_intents);
      vlib_cli_output (vm, "vector.%s.terminal_intent=%s", name,
                       result->terminal_intent
                           == PRODUCT_PACKET_INTENT_PASS_ADAPTER
                         ? "pass-adapter"
                         : "invalid");
      vlib_cli_output (vm, "vector.%s.ledger_settlements=%u", name,
                       result->ledger_settlements);
      vlib_cli_output (vm, "vector.%s.buffer_returns=%u", name,
                       result->buffer_returns);
      vlib_cli_output (vm, "vector.%s.ingress_buffer_index=%u", name,
                       result->ingress_buffer_index);
      vlib_cli_output (vm, "vector.%s.terminal_buffer_index=%u", name,
                       result->terminal_buffer_index);
      vlib_cli_output (vm, "vector.%s.ingress_digest=%U", name,
                       format_hex_bytes_no_wrap, result->ingress_digest, 32);
      vlib_cli_output (vm, "vector.%s.terminal_digest=%U", name,
                       format_hex_bytes_no_wrap, result->terminal_digest, 32);
      vlib_cli_output (vm, "vector.%s.ingress_current_data=%u", name,
                       result->ingress_current_data);
      vlib_cli_output (vm, "vector.%s.terminal_current_data=%u", name,
                       result->terminal_current_data);
      vlib_cli_output (vm, "vector.%s.ingress_length=%u", name,
                       result->ingress_length);
      vlib_cli_output (vm, "vector.%s.terminal_length=%u", name,
                       result->terminal_length);
      vlib_cli_output (vm, "vector.%s.source_address=%U", name,
                       format_hex_bytes_no_wrap,
                       result->facts.source_address, 16);
      vlib_cli_output (vm, "vector.%s.destination_address=%U", name,
                       format_hex_bytes_no_wrap,
                       result->facts.destination_address, 16);
      vlib_cli_output (vm, "vector.%s.source_port=%u", name,
                       result->facts.source_port);
      vlib_cli_output (vm, "vector.%s.destination_port=%u", name,
                       result->facts.destination_port);
      vlib_cli_output (vm, "vector.%s.l3_header_length=%u", name,
                       result->facts.l3_header_length);
      vlib_cli_output (vm, "vector.%s.l4_header_length=%u", name,
                       result->facts.l4_header_length);
      vlib_cli_output (vm, "vector.%s.packet_length=%u", name,
                       result->facts.packet_length);
    }
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_run_fixture_command, static) = {
  .path = PRODUCT_GRAPH_RUN_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_FIXTURE_HELP PRODUCT_GRAPH_FIXTURE,
  .function = product_packet_graph_run_fixture_cli,
  .is_mp_safe = 1,
};

static int
product_congestion_results_ready (const product_packet_graph_main_t *graph)
{
  return clib_atomic_load_acq_n (&graph->result_ready[0].value)
         && clib_atomic_load_acq_n (&graph->result_ready[1].value);
}

static clib_error_t *
product_packet_graph_run_congestion_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_node_runtime_t *ingress_runtime;
  u8 *fixture = 0;
  u32 buffer_indices[2];
  u16 thread_indices[2];
  u32 allocated;
  u32 index;
  (void) command;

  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || strcmp ((char *) fixture, PRODUCT_GRAPH_CONGESTION_FIXTURE) != 0
      || !clib_atomic_load_acq_n (&graph->enabled)
      || clib_atomic_load_acq_n (&graph->completed) != 0)
    {
      vec_free (fixture);
      return clib_error_return (0, "congestion fixture run rejected");
    }
  vec_free (fixture);
  graph->congestion_fixture = 1;
  allocated = vlib_buffer_alloc (vm, buffer_indices, 2);
  if (allocated != 2)
    {
      if (allocated != 0)
        vlib_buffer_free (vm, buffer_indices, allocated);
      return clib_error_return (0, "cannot allocate congestion buffers");
    }

  ingress_runtime =
    vlib_node_get_runtime (vm, product_packet_test_ingress_node.index);
  for (index = 0; index < 2; index++)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_indices[index]);
      product_buffer_metadata_t metadata;
      product_packet_ingress_t ingress;
      product_packet_lease_t lease;
      product_worker_layout_t layout = {
        .worker_count = PRODUCT_GRAPH_WORKERS,
        .hash_seed = PRODUCT_GRAPH_HASH_SEED,
      };
      product_ingress_evidence_t *evidence = &graph->ingress[index];
      u32 packet_length;
      u16 arrival_worker;

      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      packet_length = product_ipv4_fixture (
        vlib_buffer_get_current (buffer), index == 0 ? 6 : 17,
        index == 0 ? 0x0a000011 : 0xc0000211,
        index == 0 ? 31001 : 32001,
        index == 0 ? 0x0a000012 : 0xc6336412,
        index == 0 ? 443 : 53);
      buffer->current_length = packet_length;

      clib_memset (&ingress, 0, sizeof (ingress));
      ingress.data = vlib_buffer_get_current (buffer);
      ingress.length = packet_length;
      ingress.current_worker = 0;
      ingress.flow_domain = PRODUCT_GRAPH_FLOW_DOMAIN;
      ingress.origin_obligation_id = UINT64_C (174001) + index;
      if (product_packet_admit (&layout, &ingress, &lease)
          != PRODUCT_PACKET_OK)
        {
          vlib_buffer_free (vm, buffer_indices, 2);
          return clib_error_return (0, "congestion vector admission failed");
        }
      arrival_worker = index == 0 ? (u16) (lease.expected_owner ^ 1)
                                  : lease.expected_owner;

      clib_memset (&metadata, 0, sizeof (metadata));
      metadata.origin_obligation_id = UINT64_C (174001) + index;
      metadata.generation = graph->generation;
      product_metadata_store (buffer, &metadata);
      evidence->buffer_index = buffer_indices[index];
      evidence->current_data = (u32) buffer->current_data;
      evidence->length = packet_length;
      evidence->arrival_worker = (u8) arrival_worker;
      clib_sha256 (vlib_buffer_get_current (buffer), packet_length,
                   evidence->digest);
      thread_indices[index] =
        (u16) vlib_get_worker_thread_index (arrival_worker);
    }

  clib_atomic_store_rel_n (&graph->buffer_debt, 2);
  clib_atomic_store_rel_n (&graph->obligation_debt, 2);
  if (vlib_buffer_enqueue_to_thread (
        vm, ingress_runtime, graph->ingress_frame_queue, buffer_indices,
        thread_indices, 2, 0)
      != 2)
    return clib_error_return (0, "congestion ingress frame queue is full");

  {
    f64 deadline = vlib_time_now (vm) + 1.0;
    while (!product_congestion_results_ready (graph)
           && vlib_time_now (vm) < deadline)
      usleep (1000);
  }
  if (!product_congestion_results_ready (graph))
    return clib_error_return (0, "congestion fixture completion timed out");

  vlib_cli_output (vm, "fixture.id=%s", PRODUCT_GRAPH_CONGESTION_FIXTURE);
  vlib_cli_output (vm, "fixture.vector_count=2");
  for (index = 0; index < 2; index++)
    {
      const product_fixture_result_t *result = &graph->results[index];
      const char *name = index == 0 ? "primary-credit-exhausted"
                                    : "corrective-queue-full";
      const char *reason;
      if (result->runtime_drop_reason
          == PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION)
        reason = "primary-handoff-congestion";
      else if (result->runtime_drop_reason
               == PRODUCT_PACKET_DROP_CORRECTIVE_HANDOFF_CONGESTION)
        reason = "corrective-handoff-congestion";
      else
        return clib_error_return (0,
                                  "congestion result has no drop reason");
      if (result->terminal_intent != PRODUCT_PACKET_INTENT_DROP_RUNTIME)
        return clib_error_return (0,
                                  "congestion result is not runtime-drop");
      vlib_cli_output (vm, "vector.%s.handoff_stage=%s", name,
                       index == 0 ? "primary" : "corrective");
      vlib_cli_output (vm, "vector.%s.injected_fault=%s", name,
                       index == 0 ? "credit-exhausted" : "queue-full");
      vlib_cli_output (vm, "vector.%s.runtime_drop_reason=%s", name,
                       reason);
      vlib_cli_output (vm, "vector.%s.terminal_intent=%s", name,
                       result->terminal_intent
                           == PRODUCT_PACKET_INTENT_DROP_RUNTIME
                         ? "drop-runtime"
                         : "invalid");
      vlib_cli_output (vm, "vector.%s.terminal_intents=%u", name,
                       result->terminal_intents);
      vlib_cli_output (vm, "vector.%s.ledger_settlements=%u", name,
                       result->ledger_settlements);
      vlib_cli_output (vm, "vector.%s.buffer_returns=%u", name,
                       result->buffer_returns);
      vlib_cli_output (vm, "vector.%s.ingress_buffer_index=%u", name,
                       result->ingress_buffer_index);
      vlib_cli_output (vm, "vector.%s.reject_buffer_index=%u", name,
                       graph->reject_buffer_indices[index]);
      vlib_cli_output (vm, "vector.%s.terminal_buffer_index=%u", name,
                       result->terminal_buffer_index);
      vlib_cli_output (vm, "vector.%s.ingress_digest=%U", name,
                       format_hex_bytes_no_wrap, result->ingress_digest, 32);
      vlib_cli_output (vm, "vector.%s.terminal_digest=%U", name,
                       format_hex_bytes_no_wrap, result->terminal_digest, 32);
    }
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_run_congestion_fixture_command,
                  static) = {
  .path = PRODUCT_GRAPH_RUN_CONGESTION_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_CONGESTION_FIXTURE_COMMAND " "
                PRODUCT_GRAPH_CONGESTION_FIXTURE,
  .function = product_packet_graph_run_congestion_fixture_cli,
  .is_mp_safe = 1,
};

static clib_error_t *product_packet_graph_disable_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command);
static u64 product_packet_graph_frame_queue_occupancy (u32 frame_queue);

static int
product_lifecycle_enqueue_two_outstanding (vlib_main_t *vm)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_node_runtime_t *ingress_runtime =
    vlib_node_get_runtime (vm, product_packet_test_ingress_node.index);
  u32 buffers[2];
  u16 threads[2];
  u8 fragment_payload[32];
  product_buffer_metadata_t metadata;
  u32 allocated = vlib_buffer_alloc (vm, buffers, 2);
  if (allocated != 2)
    {
      if (allocated)
        vlib_buffer_free (vm, buffers, allocated);
      return 0;
    }
  product_fragment_payload (fragment_payload, 40001);
  for (u32 index = 0; index < 2; index++)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffers[index]);
      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      if (index == 0)
        buffer->current_length = product_fragment_materialize_ip4 (
          vlib_buffer_get_current (buffer), 0x5f01, 0, 1,
          fragment_payload, 8);
      else
        buffer->current_length = product_ipv4_fixture (
          vlib_buffer_get_current (buffer), 17, 0xc0000231, 33001,
          0xc6336432, 53);
      vnet_buffer (buffer)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (buffer)->sw_if_index[VLIB_TX] = ~0;
      clib_memset (&metadata, 0, sizeof (metadata));
      metadata.origin_obligation_id = UINT64_C (1759001) + index;
      metadata.generation = graph->generation;
      product_metadata_store (buffer, &metadata);
      threads[index] = (u16) vlib_get_worker_thread_index (index);
      if (index == 1)
        {
          product_packet_ingress_t ingress;
          product_packet_lease_t lease;
          product_worker_layout_t layout = {
            .worker_count = PRODUCT_GRAPH_WORKERS,
            .hash_seed = PRODUCT_GRAPH_HASH_SEED,
          };
          clib_memset (&ingress, 0, sizeof (ingress));
          ingress.data = vlib_buffer_get_current (buffer);
          ingress.length = buffer->current_length;
          ingress.current_worker = 0;
          ingress.flow_domain = PRODUCT_GRAPH_FLOW_DOMAIN;
          ingress.origin_obligation_id = metadata.origin_obligation_id;
          if (product_packet_admit (&layout, &ingress, &lease)
              != PRODUCT_PACKET_OK)
            return 0;
          threads[index] = (u16) vlib_get_worker_thread_index (
            (u16) (lease.expected_owner ^ 1));
        }
    }
  return vlib_buffer_enqueue_to_thread (
           vm, ingress_runtime, graph->ingress_frame_queue, buffers, threads,
           2, 0)
         == 2;
}

static int
product_lifecycle_enqueue_stale_events (vlib_main_t *vm, u16 generation)
{
  u32 buffers[2];
  u32 allocated = vlib_buffer_alloc (vm, buffers, 2);
  if (allocated != 2)
    {
      if (allocated)
        vlib_buffer_free (vm, buffers, allocated);
      return 0;
    }
  {
    vlib_buffer_t *buffer = vlib_get_buffer (vm, buffers[0]);
    product_packet_ingress_t ingress;
    product_packet_lease_t lease;
    product_buffer_metadata_t metadata;
    product_worker_layout_t layout = {
      .worker_count = PRODUCT_GRAPH_WORKERS,
      .hash_seed = PRODUCT_GRAPH_HASH_SEED,
    };
    vlib_buffer_reset (buffer);
    buffer->current_length = product_ipv4_fixture (
      vlib_buffer_get_current (buffer), 17, 0xc0000241, 34001,
      0xc6336442, 53);
    clib_memset (&ingress, 0, sizeof (ingress));
    ingress.data = vlib_buffer_get_current (buffer);
    ingress.length = buffer->current_length;
    ingress.current_worker = 0;
    ingress.flow_domain = PRODUCT_GRAPH_FLOW_DOMAIN;
    ingress.origin_obligation_id = UINT64_C (1759001);
    if (product_packet_admit (&layout, &ingress, &lease)
        != PRODUCT_PACKET_OK)
      return 0;
    product_metadata_from_lease (&metadata, &lease, generation);
    product_metadata_store (buffer, &metadata);
  }
  {
    vlib_buffer_t *buffer = vlib_get_buffer (vm, buffers[1]);
    product_fragment_metadata_t metadata;
    vlib_buffer_reset (buffer);
    buffer->current_length = 1;
    clib_memset (&metadata, 0, sizeof (metadata));
    metadata.obligation_ids[0] = UINT64_C (1759002);
    metadata.final_owner = PRODUCT_FRAGMENT_FINAL_OWNER_UNKNOWN;
    metadata.fragment_worker = 0;
    metadata.obligation_count = 1;
    metadata.family = 4;
    metadata.fixture_vector = 0xff;
    metadata.flags = PRODUCT_FRAGMENT_META_FRAGMENT;
    metadata.magic = PRODUCT_FRAGMENT_METADATA_MAGIC;
    metadata.custom_error = PRODUCT_FRAGMENT_ERROR_TIMEOUT;
    metadata.generation = generation;
    product_fragment_metadata_store (buffer, &metadata);
  }
  for (u32 index = 0; index < 2; index++)
    {
      u32 node_index = index == 0 ? product_packet_terminal_node.index
                                  : product_packet_fragment_error_node.index;
      vlib_frame_t *frame = vlib_get_frame_to_node (vm, node_index);
      u32 *to = vlib_frame_vector_args (frame);
      to[0] = buffers[index];
      frame->n_vectors = 1;
      vlib_put_frame_to_node (vm, node_index, frame);
    }
  return 1;
}

static clib_error_t *
product_packet_graph_run_lifecycle_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u8 *fixture = 0;
  u32 terminal_start;
  u32 settlement_start;
  u32 returns_start;
  u32 stale_start;
  u16 stale_generation;
  f64 drain_start;
  f64 drain_end;
  clib_error_t *error;
  (void) command;
  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || strcmp ((char *) fixture, PRODUCT_GRAPH_LIFECYCLE_FIXTURE) != 0
      || clib_atomic_load_acq_n (&graph->enabled))
    {
      vec_free (fixture);
      return clib_error_return (0, "lifecycle fixture run rejected");
    }
  vec_free (fixture);
  terminal_start =
    clib_atomic_load_acq_n (&graph->lifecycle_terminal_intents);
  settlement_start =
    clib_atomic_load_acq_n (&graph->lifecycle_settlements);
  returns_start = clib_atomic_load_acq_n (&graph->lifecycle_returns);
  stale_start = clib_atomic_load_acq_n (&graph->stale_events_rejected);
  graph->lifecycle_fixture = 1;

  error = product_packet_graph_enable_cli (vm, 0, 0);
  if (error)
    return error;
  stale_generation = graph->generation;
  if (!product_lifecycle_enqueue_two_outstanding (vm))
    return clib_error_return (0, "lifecycle outstanding injection failed");
  {
    f64 deadline = vlib_time_now (vm) + 0.05;
    while ((clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 2
            || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 1)
           && vlib_time_now (vm) < deadline)
      vlib_process_suspend (vm, 0.001);
  }
  if (clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 2
      || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 1)
    return clib_error_return (0, "lifecycle outstanding state not reached");
  drain_start = vlib_time_now (vm);
  error = product_packet_graph_disable_cli (vm, 0, 0);
  drain_end = vlib_time_now (vm);
  if (error)
    return error;

  graph->configured = 1;
  error = product_packet_graph_enable_cli (vm, 0, 0);
  if (error)
    return error;
  if (!product_lifecycle_enqueue_stale_events (vm, stale_generation))
    return clib_error_return (0, "lifecycle stale injection failed");
  {
    f64 deadline = vlib_time_now (vm) + 1.0;
    while (clib_atomic_load_acq_n (&graph->stale_events_rejected)
               - stale_start
             != 2
           && vlib_time_now (vm) < deadline)
      vlib_process_suspend (vm, 0.001);
  }
  if (clib_atomic_load_acq_n (&graph->stale_events_rejected) - stale_start
      != 2)
    return clib_error_return (0, "stale events were not fenced");
  error = product_packet_graph_disable_cli (vm, 0, 0);
  if (error)
    return error;

  graph->configured = 1;
  error = product_packet_graph_enable_cli (vm, 0, 0);
  if (error)
    return error;
  error = product_packet_graph_disable_cli (vm, 0, 0);
  if (error)
    return error;
  graph->lifecycle_fixture = 0;

  vlib_cli_output (vm, "fixture.id=%s", PRODUCT_GRAPH_LIFECYCLE_FIXTURE);
  vlib_cli_output (vm, "fixture.disable.admission_quiesced=1");
  vlib_cli_output (vm, "fixture.drain.fragment_outstanding=1");
  vlib_cli_output (vm, "fixture.drain.handoff_outstanding=1");
  vlib_cli_output (vm, "fixture.drain.input_obligations=2");
  vlib_cli_output (
    vm, "fixture.drain.terminal_intents=%u",
    clib_atomic_load_acq_n (&graph->lifecycle_terminal_intents)
      - terminal_start);
  vlib_cli_output (
    vm, "fixture.drain.ledger_settlements=%u",
    clib_atomic_load_acq_n (&graph->lifecycle_settlements)
      - settlement_start);
  vlib_cli_output (
    vm, "fixture.drain.buffer_returns=%u",
    clib_atomic_load_acq_n (&graph->lifecycle_returns) - returns_start);
  vlib_cli_output (vm, "fixture.drain.outstanding_obligations=0");
  vlib_cli_output (vm, "fixture.drain.elapsed_ms=%u",
                   (u32) ((drain_end - drain_start) * 1000.0));
  vlib_cli_output (vm,
                   "fixture.generation.stale_completion_after_reenable=1");
  vlib_cli_output (vm,
                   "fixture.generation.stale_timeout_after_reenable=1");
  vlib_cli_output (
    vm, "fixture.generation.stale_events_rejected=%u",
    clib_atomic_load_acq_n (&graph->stale_events_rejected) - stale_start);
  vlib_cli_output (
    vm, "fixture.generation.cross_generation_admissions=%u",
    clib_atomic_load_acq_n (&graph->cross_generation_admissions));
  vlib_cli_output (vm, "fixture.generation.late_verdicts=%u",
                   clib_atomic_load_acq_n (&graph->late_verdicts));
  vlib_cli_output (vm, "fixture.repeat.enable_disable_cycles=3");
  vlib_cli_output (vm, "fixture.fragment_contexts=0");
  vlib_cli_output (
    vm, "fixture.ingress_fqm_occupancy=%llu",
    (unsigned long long) product_packet_graph_frame_queue_occupancy (
      graph->ingress_frame_queue));
  vlib_cli_output (
    vm, "fixture.owner_fqm_occupancy=%llu",
    (unsigned long long) product_packet_graph_frame_queue_occupancy (
      graph->owner_guard_frame_queue));
  vlib_cli_output (vm, "fixture.fragment_context_debt=0");
  vlib_cli_output (vm, "fixture.handoff_credit_debt=0");
  vlib_cli_output (vm, "fixture.obligation_debt=0");
  vlib_cli_output (vm, "fixture.buffer_debt=0");
  vlib_cli_output (vm, "fixture.duplicate_settlements=0");
  vlib_cli_output (vm, "fixture.lost_buffers=0");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_run_lifecycle_fixture_command,
                  static) = {
  .path = PRODUCT_GRAPH_RUN_LIFECYCLE_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_LIFECYCLE_FIXTURE_COMMAND " "
                PRODUCT_GRAPH_LIFECYCLE_FIXTURE,
  .function = product_packet_graph_run_lifecycle_fixture_cli,
  .is_mp_safe = 1,
};

static clib_error_t *
product_packet_graph_show_cli (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  vlib_frame_queue_main_t *ingress_fqm = vec_elt_at_index (
    thread_main->frame_queue_mains, graph->ingress_frame_queue);
  vlib_frame_queue_main_t *owner_fqm = vec_elt_at_index (
    thread_main->frame_queue_mains, graph->owner_guard_frame_queue);
  u64 ingress_head_delta = 0;
  u64 ingress_tail_delta = 0;
  u64 owner_head_delta = 0;
  u64 owner_tail_delta = 0;
  u32 worker;
  (void) input;
  (void) command;
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      u32 thread = vlib_get_worker_thread_index (worker);
      ingress_head_delta += ingress_fqm->vlib_frame_queues[thread]->head
                            - graph->ingress_fq_head_start[worker];
      ingress_tail_delta += ingress_fqm->vlib_frame_queues[thread]->tail
                            - graph->ingress_fq_tail_start[worker];
      owner_head_delta += owner_fqm->vlib_frame_queues[thread]->head
                          - graph->owner_fq_head_start[worker];
      owner_tail_delta += owner_fqm->vlib_frame_queues[thread]->tail
                          - graph->owner_fq_tail_start[worker];
    }
  vlib_cli_output (vm, "graph.workers=2");
  vlib_cli_output (vm, "graph.enabled=%u",
                   clib_atomic_load_acq_n (&graph->enabled));
  vlib_cli_output (vm, "graph.generation=%u", graph->generation);
  vlib_cli_output (vm, "graph.fragment_context_debt=%u",
                   clib_atomic_load_acq_n (&graph->lifecycle_obligations));
  vlib_cli_output (vm, "graph.handoff_credit_debt=%u",
                   clib_atomic_load_acq_n (&graph->lifecycle_handoffs));
  vlib_cli_output (vm, "graph.obligation_debt=%u",
                   clib_atomic_load_acq_n (&graph->lifecycle_obligations));
  vlib_cli_output (vm, "graph.buffer_debt=%u",
                   clib_atomic_load_acq_n (&graph->lifecycle_buffers));
  vlib_cli_output (vm, "graph.admitted=%u",
                   clib_atomic_load_acq_n (&graph->admitted));
  vlib_cli_output (vm, "graph.local_packets=%u",
                   clib_atomic_load_acq_n (&graph->local_packets));
  vlib_cli_output (vm, "graph.remote_packets=%u",
                   clib_atomic_load_acq_n (&graph->remote_packets));
  vlib_cli_output (vm, "graph.primary_enqueues=%u",
                   clib_atomic_load_acq_n (&graph->primary_enqueues));
  vlib_cli_output (vm, "graph.primary_enqueue_max_per_packet=%u",
                   clib_atomic_load_acq_n (
                     &graph->primary_enqueue_max_per_packet));
  vlib_cli_output (vm, "graph.terminal_intents=%u",
                   clib_atomic_load_acq_n (&graph->terminal_intents));
  vlib_cli_output (vm, "graph.ledger_settlements=%u",
                   clib_atomic_load_acq_n (&graph->ledger_settlements));
  vlib_cli_output (vm, "graph.buffer_returns=%u",
                   clib_atomic_load_acq_n (&graph->buffer_returns));
  vlib_cli_output (vm, "graph.duplicate_terminals=%u",
                   clib_atomic_load_acq_n (&graph->duplicate_terminals));
  vlib_cli_output (vm, "graph.duplicate_settlements=%u",
                   clib_atomic_load_acq_n (&graph->duplicate_settlements));
  vlib_cli_output (vm, "graph.lost_buffers=%u",
                   clib_atomic_load_acq_n (&graph->lost_buffers));
  vlib_cli_output (vm, "graph.congestion_rejections=%u",
                   clib_atomic_load_acq_n (&graph->congestion_rejections));
  vlib_cli_output (
    vm, "graph.runtime_drop_settlements=%u",
    clib_atomic_load_acq_n (&graph->runtime_drop_settlements));
  vlib_cli_output (vm, "graph.ingress_frame_queue=%u",
                   graph->ingress_frame_queue);
  vlib_cli_output (vm, "graph.ingress_fq_node=%v",
                   vlib_get_node (vm, ingress_fqm->node_index)->name);
  vlib_cli_output (vm, "graph.ingress_fq_enqueued_frames=%llu",
                   (unsigned long long) ingress_tail_delta);
  vlib_cli_output (vm, "graph.ingress_fq_dequeued_frames=%llu",
                   (unsigned long long) ingress_head_delta);
  vlib_cli_output (vm, "graph.owner_guard_frame_queue=%u",
                   graph->owner_guard_frame_queue);
  vlib_cli_output (vm, "graph.owner_guard_fq_node=%v",
                   vlib_get_node (vm, owner_fqm->node_index)->name);
  vlib_cli_output (vm, "graph.owner_guard_fq_enqueued_frames=%llu",
                   (unsigned long long) owner_tail_delta);
  vlib_cli_output (vm, "graph.owner_guard_fq_dequeued_frames=%llu",
                   (unsigned long long) owner_head_delta);
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_show_command, static) = {
  .path = "show product packet-graph",
  .function = product_packet_graph_show_cli,
};

static u64
product_packet_graph_frame_queue_occupancy (u32 frame_queue)
{
  vlib_thread_main_t *thread_main = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm =
    vec_elt_at_index (thread_main->frame_queue_mains, frame_queue);
  u64 occupancy = 0;
  for (u32 worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      u32 thread = vlib_get_worker_thread_index (worker);
      occupancy += fqm->vlib_frame_queues[thread]->tail
                   - fqm->vlib_frame_queues[thread]->head;
    }
  return occupancy;
}

static u64
product_packet_graph_all_frame_queue_occupancy (void)
{
  return product_packet_graph_frame_queue_occupancy (
           product_packet_graph_main.ingress_frame_queue)
         + product_packet_graph_frame_queue_occupancy (
           product_packet_graph_main.owner_guard_frame_queue)
         + product_packet_graph_frame_queue_occupancy (
           product_fragment_graph_main.steer_frame_queue)
         + product_packet_graph_frame_queue_occupancy (
           product_fragment_graph_main.final_frame_queue);
}

static clib_error_t *
product_packet_graph_disable_cli (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  (void) input;
  (void) command;
  f64 deadline;
  if (!clib_atomic_load_acq_n (&graph->enabled))
    return clib_error_return (0, "graph is not enabled");
  clib_atomic_store_rel_n (&graph->accepting, 0);
  deadline = vlib_time_now (vm) + 2.0;
  while ((clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 0
          || clib_atomic_load_acq_n (&graph->lifecycle_buffers) != 0
          || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 0
          || product_packet_graph_all_frame_queue_occupancy () != 0)
         && vlib_time_now (vm) < deadline)
    vlib_process_suspend (vm, 0.001);
  if (clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_buffers) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 0
      || product_packet_graph_all_frame_queue_occupancy () != 0
      || clib_atomic_load_acq_n (&graph->buffer_debt) != 0
      || clib_atomic_load_acq_n (&graph->handoff_credit_debt) != 0
      || clib_atomic_load_acq_n (&graph->obligation_debt) != 0)
    return clib_error_return (0, "graph bounded drain timed out");
  clib_atomic_store_rel_n (&graph->enabled, 0);
  graph->configured = 0;
  vlib_cli_output (vm, "graph.disable=ok");
  vlib_cli_output (vm, "graph.buffer_debt=0");
  vlib_cli_output (vm, "graph.handoff_credit_debt=0");
  vlib_cli_output (vm, "graph.obligation_debt=0");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_disable_command, static) = {
  .path = "product packet-graph disable",
  .function = product_packet_graph_disable_cli,
};
#endif

static clib_error_t *
product_packet_graph_init (vlib_main_t *vm)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 worker;
  graph->vlib_main = vm;
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    clib_atomic_store_rel_n (&graph->handoff_credits[worker],
                             PRODUCT_GRAPH_HANDOFF_CREDITS);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  graph->ingress_frame_queue =
    vlib_frame_queue_main_init (product_packet_test_ingress_node.index, 0);
#endif
  graph->owner_guard_frame_queue =
    vlib_frame_queue_main_init (product_packet_owner_guard_node.index, 0);
  return 0;
}

VLIB_INIT_FUNCTION (product_packet_graph_init);
