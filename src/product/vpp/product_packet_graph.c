/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Product VPP packet graph. Ordinary packet bytes stay in one native buffer
 * through admit, owner-local policy, terminal and origin completion. A remote
 * assignment uses one Primary Handoff; historical Host-only fixture routes
 * are compiled separately from the product path.
 */

#include "product_packet.h"
#include "product_packet_graph.h"
#include "product_core_policy.h"
#include "product_flow_entry.h"
#include "product_protocol_catalog.h"
#include "product_flow_end.h"
#include "product_flow_expiry.h"
#include "product_root_nfqueue_adapter.h"
#include "product_vpn_tun_adapter.h"
#include "product_vpn_flow_stack_driver.h"
#include "product_network_snapshot.h"
#include "product_diagnostic_hex.h"

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/ip/ip.h>
#include <vnet/buffer.h>
#include <vnet/vnet.h>
#include <vppinfra/atomics.h>
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#include <vppinfra/crypto/sha2.h>
#endif

#include <string.h>
#include <stdio.h>
#include <time.h>
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#include <unistd.h>
#endif

#define PRODUCT_GRAPH_VECTOR_COUNT 8
#define PRODUCT_GRAPH_WORKERS 2
_Static_assert (PRODUCT_GRAPH_WORKERS == 2, "update rule-config query storage budget with worker layout");
#define PRODUCT_GRAPH_HASH_SEED UINT64_C (0x6f776e65722d3137)
#define PRODUCT_GRAPH_HANDOFF_CREDITS 32

_Static_assert (PRODUCT_GRAPH_HANDOFF_CREDITS < FRAME_QUEUE_MAX_NELTS,
                "handoff credits must remain below the private FQM depth");

enum
{
  PRODUCT_META_ADMITTED = 1 << 0,
  PRODUCT_META_POLICY_READY = 1 << 1,
  PRODUCT_META_SETTLED = 1 << 2,
  PRODUCT_META_SOURCE_IS_A = 1 << 3,
  PRODUCT_META_TERMINAL_SHIFT = 4,
  PRODUCT_META_TERMINAL_MASK = 3 << PRODUCT_META_TERMINAL_SHIFT,
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  PRODUCT_META_ADMIT_THREAD_2 = 1 << 6,
#endif
  PRODUCT_META_TRACE = 1 << 6,
  PRODUCT_META_HANDOFF_CREDIT = 1 << 7,
};

/* Owner assignment is independent of parser and adapter identity. */
typedef struct
{
  u16 expected_owner;
  u8 primary_handoff_count;
  u8 corrective_handoff_count;
  u8 key_kind, query_class;
  u8 assignment_valid : 1, flow_stack_result : 3, reserved_bits : 4;
  u8 reserved;
} product_compact_owner_assignment_t;

typedef union
{
  struct { u32 sequence, acknowledgment; u16 window; u8 flags, scale; } tcp;
  struct { u16 identifier, sequence; u8 type, code, identity_known; } icmp;
} product_transport_metadata_t;

typedef struct
{
  /* Aliases keep bounded transition code explicit while naming its owner. */
  union
  {
    product_compact_owner_assignment_t owner;
    struct
    {
      u16 expected_owner;
      u8 primary_handoff_count, corrective_handoff_count;
      u8 key_kind, query_class;
      /* The result belongs to lifecycle metadata, never to TCP PacketFacts.
       * Compact the existing boolean byte; no extra opaque storage or map. */
      u8 assignment_valid : 1, flow_stack_result : 3, reserved_bits : 4;
      u8 processing_bypass_reason;
    };
  };
  u32 fragment_bundle_head;
  u32 fragment_bundle_count;
  u64 canonical_hash;
  product_transport_metadata_t transport;
  u32 packet_length;
  u16 source_port, destination_port;
  u16 span_length;
  i16 span_current_data;
  u16 l3_header_length;
  u8 l4_header_length;
  u8 ip_family : 4, l3_status : 4;
  u8 protocol, l4_status;
  u8 state_bits, runtime_drop_reason;
  /* Stack projection of the one token in opaque; not serialized into opaque2. */
  u64 origin_obligation_id;
  /* The active graph and Adapter obligation share one generation. Keep its
   * one authoritative inline value in opaque and project it on the stack. */
  u64 generation;
} product_buffer_metadata_t;

#define PRODUCT_PACKET_METADATA_BYTES offsetof (product_buffer_metadata_t, origin_obligation_id)

typedef struct
{
  product_adapter_obligation_t obligation;
  product_platform_packet_facts_t platform;
} product_buffer_platform_metadata_t;

_Static_assert (sizeof (product_packet_completion_frame_t) <= sizeof (((vlib_buffer_t *) 0)->opaque2),
                "completion carrier fits existing opaque2");
_Static_assert (sizeof (product_packet_completion_frame_t) <=
                  PRODUCT_FLOW_END_DISCRIMINANT_OFFSET,
                "completion does not overwrite the END discriminant");
_Static_assert (PRODUCT_PACKET_DROP_REASSEMBLY_NO_RETURN <
                  PRODUCT_FLOW_END_DISCRIMINANT, "packet drop reasons are disjoint");
_Static_assert (sizeof (product_compact_owner_assignment_t) == 8, "owner layout");
_Static_assert (sizeof (product_transport_metadata_t) == 12, "transport layout");
_Static_assert (PRODUCT_VPN_FLOW_STACK_FAILED + 1 < 8, "flow stack result bits");
_Static_assert (PRODUCT_PACKET_METADATA_BYTES == 56, "packet layout");
_Static_assert (PRODUCT_PACKET_METADATA_BYTES ==
                  sizeof (((vlib_buffer_t *) 0)->opaque2), "opaque2 capacity");
_Static_assert (sizeof (product_buffer_platform_metadata_t) ==
                  sizeof (((vlib_buffer_t *) 0)->opaque), "opaque capacity");
_Static_assert (offsetof (product_buffer_metadata_t, canonical_hash) == 16,
                "canonical hash offset");
_Static_assert (offsetof (product_buffer_metadata_t, transport) == 24,
                "transport offset");
_Static_assert (offsetof (product_buffer_metadata_t, packet_length) == 36,
                "packet length offset");
_Static_assert (offsetof (product_buffer_metadata_t, span_current_data) == 46,
                "span offset");
_Static_assert (offsetof (product_buffer_platform_metadata_t, platform) == 24,
                "platform offset");
_Static_assert (offsetof (product_buffer_metadata_t, state_bits) == 54,
                "packet lifecycle offset");
_Static_assert (offsetof (product_buffer_metadata_t, runtime_drop_reason) ==
                  PRODUCT_FLOW_END_DISCRIMINANT_OFFSET,
                "ordinary packet shares the discriminant byte");
_Static_assert (_Alignof (product_buffer_metadata_t) == 8, "metadata alignment");
_Static_assert (_Alignof (product_buffer_platform_metadata_t) == 8, "platform overlay alignment");
_Static_assert (offsetof (product_platform_packet_facts_t, availability) == 12,
                "platform availability offset");
_Static_assert (offsetof (product_adapter_obligation_t, queue_generation) == 8,
                "completion generation offset");
_Static_assert (offsetof (product_adapter_obligation_t, packet_id) == 16,
                "completion packet identity offset");
/* Access is by memcpy: opaque itself need not provide typed pointer alignment. */

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
  product_canonical_owner_key_t canonical_key;
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
  /* Published banks are immutable.  Reader counts prevent reuse while a
   * worker is still evaluating the previous active bank. */
  product_l4_policy_view_t view;
  u64 generation;
  u64 revision;
  u64 snapshot_hash;
} product_packet_graph_l4_policy_bank_t;

/* One reader claim protects the complete Gate/L4 bank through owner mutation. */
typedef struct
{
  const product_packet_graph_l4_policy_bank_t *bank;
  product_flow_policy_identity_t identity;
  u32 bank_index;
  u32 sequence;
  u32 trace;
  u32 hold_us;
  product_ct_facts_t ct; /* Packet-local result; not stored in the immutable bank. */
  product_l4_policy_position_t position;
  product_policy_cache_t *cache; /* Current owner only; packet lifetime. */
  u64 flow_incarnation;
  u64 protocols;
  u8 protocols_available;
  u8 sni_result;
} product_policy_snapshot_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 acquired, released, retired, mismatches;
  u64 generation, revision, snapshot_hash;
  product_policy_cache_t cache;
} product_policy_worker_t;


typedef struct
{
  vlib_main_t *vlib_main;
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  u32 owner_guard_frame_queue;
#else
  u32 primary_frame_queue;
  u32 completion_return_frame_queue;
  u32 misroute_next;
  u32 primary_credit_limit, primary_ring_slots, completion_ring_slots;
  u32 completion_pending_returns;
  u64 primary_published, primary_received, primary_rejected;
  u64 owner_delivery_checks, owner_delivery_failures;
  u64 completion_returns, completion_deferred, completion_retry_attempts;
#endif
  u32 handoff_credits[PRODUCT_GRAPH_WORKERS];
  u32 lifecycle_obligations;
  u32 lifecycle_buffers;
  u32 lifecycle_handoffs;
  u32 trace_packets;
  u32 trace_limit;
  u32 policy_hold_next_us[PRODUCT_GRAPH_WORKERS];
  u32 lifecycle_terminal_intents;
  u32 lifecycle_settlements;
  u32 lifecycle_returns;
  u32 lifecycle_completion_frames;
  u32 enabled;
  u32 accepting;
  u32 policy_publish_sequence;
  u32 policy_writer_lock;
  u64 policy_packet_lock_acquisitions;
  u64 policy_publications;
  product_policy_worker_t policy_workers[PRODUCT_GRAPH_WORKERS];
  u32 l4_policy_active_bank;
  u32 l4_policy_bank_readers[2];
  u32 l4_policy_view_active;
  product_packet_graph_l4_policy_bank_t l4_policy_banks[2];
  u32 flow_pools_initialized;
  u64 flow_active_policy_revision;
  u64 flow_active_snapshot_hash;
  u64 flow_flush_count;
  product_flow_runtime_t *flow_pools[PRODUCT_GRAPH_WORKERS];
  u32 flow_capacity;
  u64 flow_unavailable[PRODUCT_GRAPH_WORKERS];
  u64 flow_mutation_errors[PRODUCT_GRAPH_WORKERS];
  u64 gate_policy_revision;
  u64 gate_policy_snapshot_hash;
  u64 gate_policy_rule_id;
  u32 gate_policy_subject_uid;
  u32 gate_policy_network_context_id;
  u32 gate_policy_blocked;
  u32 gate_policy_reason_id;
  u64 gate_table_last_match_revision;
  u64 gate_table_last_match_rule_id;
  u32 gate_table_last_winner_rank;
  u32 gate_table_last_probes;
  u32 gate_table_last_candidate_count;
  u32 gate_table_last_no_match_reason;
  u32 gate_table_last_match_action;
  u32 gate_table_last_match_reason_id;
  u64 l4_policy_revision;
  u64 l4_policy_snapshot_hash;
  u64 l4_policy_rule_id;
  u32 l4_policy_subject_uid;
  u32 l4_policy_network_context_id;
  u32 l4_policy_reason_id;
  u32 l4_policy_priority;
  u32 l4_policy_order;
  u32 l4_policy_source_address;
  u32 l4_policy_destination_address;
  u16 l4_policy_source_port_first;
  u16 l4_policy_source_port_last;
  u16 l4_policy_destination_port_first;
  u16 l4_policy_destination_port_last;
  u8 l4_policy_source_prefix_length;
  u8 l4_policy_destination_prefix_length;
  u8 l4_policy_direction;
  u8 l4_policy_protocol;
  u8 l4_policy_action;
  u64 l4_policy_view_match_records;
  u64 l4_policy_view_no_match_records;
  u64 l4_policy_view_last_revision;
  u64 l4_policy_view_last_rule_id;
  u32 l4_policy_view_last_winner_rank;
  u32 l4_policy_view_last_probes;
  u32 l4_policy_view_last_candidate_count;
  u32 l4_policy_view_last_no_match_reason;
  u64 policy_stage_evaluations;
  u64 policy_gate_evaluations;
  u64 policy_l4_evaluations;
  u64 policy_stage_pass_next;
  u64 policy_stage_drops;
  u8 policy_last_stage;
  u8 policy_last_verdict;
  u8 policy_last_matched;
  u8 policy_last_terminal_preserved;
  u32 policy_last_winner;
  u64 policy_last_revision;
  u64 policy_last_rule_id;
  u32 policy_last_reason_id;
  u64 l4_match_records;
  u64 l4_no_match_records;
  u64 l4_last_match_revision;
  u64 l4_last_match_rule_id;
  u64 l4_last_evaluation_revision;
  u32 l4_last_match_uid;
  u32 l4_last_match_network_context;
  u32 l4_last_match_reason_id;
  u32 l4_last_match_verdict;
  u32 l4_last_match_winner;
  u32 l4_last_match_uid_known;
  u32 l4_last_match_device_direction;
  u32 l4_last_match_action;
  u32 l4_last_evaluation_result;
  u32 l4_last_evaluation_verdict;
  u32 l4_last_evaluation_device_direction;
  /* Commit marker plus probe identity for the latest typed L4 match.  These
   * fields are internal evidence state; the public status keeps the sticky
   * last-match fields and current effective evaluation unchanged. */
  u64 l4_typed_match_policy_key;
  u64 l4_typed_match_probe_key;
  u64 l4_typed_match_subject_key;
  u64 l4_last_evaluation_probe_key;
  u64 policy_drop_records;
  u64 policy_last_drop_revision;
  u64 policy_last_drop_rule_id;
  u64 policy_last_drop_completion_attempts;
  u32 policy_last_drop_uid;
  u32 policy_last_drop_network_context;
  u32 policy_last_drop_reason_id;
  u32 policy_last_drop_verdict;
  u32 policy_last_drop_winner;
  u32 policy_last_drop_uid_known;
  u32 policy_last_drop_device_direction;
  u64 generation;
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  u32 ingress_frame_queue;
  u32 configured;
  u32 completed;
  u32 ingress_vectors;
  u32 admit_vectors;
  u32 guard_vectors;
  u32 policy_vectors;
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

static void
product_policy_snapshot_acquire (product_packet_graph_main_t *graph,
                                  product_policy_snapshot_t *snapshot)
{
  for (;;)
    {
      u32 sequence = __atomic_load_n (&graph->policy_publish_sequence,
                                      __ATOMIC_SEQ_CST);
      if (sequence & 1U)
        continue;
      u32 index = __atomic_load_n (&graph->l4_policy_active_bank,
                                   __ATOMIC_SEQ_CST);
      ASSERT (index < 2);
      /* SC claim/validation pairs with the publisher's SC reuse check. A
       * delayed claim must fail validation before reading a reused bank. */
      __atomic_fetch_add (&graph->l4_policy_bank_readers[index], 1,
                           __ATOMIC_SEQ_CST);
      if (sequence != __atomic_load_n (&graph->policy_publish_sequence,
                                       __ATOMIC_SEQ_CST)
          || index != __atomic_load_n (&graph->l4_policy_active_bank,
                                        __ATOMIC_SEQ_CST))
        {
          __atomic_fetch_sub (&graph->l4_policy_bank_readers[index], 1,
                               __ATOMIC_SEQ_CST);
          continue;
        }
      snapshot->ct = (product_ct_facts_t) {0};
      snapshot->cache = 0;
      snapshot->flow_incarnation = 0;
      snapshot->protocols = 0;
      snapshot->protocols_available = 0;
      snapshot->sni_result = 0;
      snapshot->position = PRODUCT_L4_POLICY_POSITION_ALL;
      snapshot->bank = &graph->l4_policy_banks[index];
      snapshot->bank_index = index;
      snapshot->sequence = sequence;
      snapshot->trace = 0;
      snapshot->hold_us = 0;
      snapshot->identity = (product_flow_policy_identity_t) {
        snapshot->bank->generation ? snapshot->bank->generation : graph->generation,
        snapshot->bank->revision, snapshot->bank->snapshot_hash
      };
      return;
    }
}

static void
product_policy_snapshot_release (product_packet_graph_main_t *graph,
                                  const product_policy_snapshot_t *snapshot)
{
  u32 previous = __atomic_fetch_sub (
    &graph->l4_policy_bank_readers[snapshot->bank_index], 1, __ATOMIC_SEQ_CST);
  ASSERT (previous != 0);
  (void) previous;
}

static product_packet_result_t product_packet_graph_policy_on_owner (
  vlib_main_t *vm, u32 buffer_index, product_packet_lease_t *lease,
  product_packet_graph_policy_evaluation_t *evaluation, int trace);


static void product_packet_graph_deactivate_policy_view (
  product_packet_graph_main_t *graph);
static void product_packet_graph_policy_writer_lock (
  product_packet_graph_main_t *graph);
static void product_packet_graph_policy_writer_unlock (
  product_packet_graph_main_t *graph);
static int product_packet_graph_flow_pools_reset (
  product_packet_graph_main_t *graph);
static void product_packet_graph_flow_pools_flush (
  product_packet_graph_main_t *graph);
static void product_packet_graph_flow_observe (
  vlib_main_t *vm, u32 buffer_index, product_packet_lease_t *lease,
  const product_packet_graph_policy_evaluation_t *evaluation, int trace,
  product_flow_entry_observation_t *observed);
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static int product_fragment_dispatch (vlib_main_t *, vlib_node_runtime_t *,
                                      u32, const product_buffer_metadata_t *);
static void product_fragment_start (vlib_main_t *);
static void product_fragment_terminal (vlib_main_t *, vlib_node_runtime_t *,
                                       u32, const product_buffer_metadata_t *,
                                       const product_packet_lease_t *);
static void product_fragment_origin_check (vlib_main_t *, u32,
                                           const product_packet_completion_frame_t *);
#endif

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
  PRODUCT_TRACE_POLICY,
  PRODUCT_TRACE_TERMINAL,
  PRODUCT_TRACE_FRAGMENT_INGRESS,
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  PRODUCT_TRACE_FIXTURE,
#endif
} product_trace_stage_t;

enum
{
  PRODUCT_NETWORK_GATE_WINNER_NONE = 0,
  PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE = 1,
  PRODUCT_POLICY_VERDICT_PASS_NEXT = 1,
  PRODUCT_POLICY_VERDICT_DROP = 2,
};

#define PRODUCT_POLICY_VERDICT_ALLOW PRODUCT_POLICY_VERDICT_PASS_NEXT
#define PRODUCT_PACKET_GRAPH_L4_MAX_PRIORITY UINT32_MAX

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
    "admit", "owner-guard", "policy", "terminal", "fragment-ingress",
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
  clib_memcpy_fast (metadata, buffer->opaque2, PRODUCT_PACKET_METADATA_BYTES);
  clib_memcpy_fast (&metadata->origin_obligation_id, buffer->opaque, sizeof (u64));
  product_buffer_platform_metadata_t platform;
  clib_memcpy_fast (&platform, buffer->opaque, sizeof (platform));
  metadata->generation = platform.obligation.queue_generation;
}

static void
product_metadata_store (vlib_buffer_t *buffer,
                        const product_buffer_metadata_t *metadata)
{
  if (PREDICT_FALSE (metadata->runtime_drop_reason & PRODUCT_FLOW_END_DISCRIMINANT))
    clib_panic ("packet drop reason overlaps FlowEnd discriminant");
  clib_memcpy_fast (buffer->opaque2, metadata, PRODUCT_PACKET_METADATA_BYTES);
  clib_memcpy_fast (buffer->opaque, &metadata->origin_obligation_id, sizeof (u64));
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  /* Historical fixtures do not all construct an Adapter obligation. */
  product_buffer_platform_metadata_t platform;
  clib_memcpy_fast (&platform, buffer->opaque, sizeof (platform));
  platform.obligation.queue_generation = metadata->generation;
  clib_memcpy_fast (buffer->opaque, &platform, sizeof (platform));
#endif
}

/* Own all opaque only along product admit -> policy -> terminal. */
static void
product_packet_graph_platform_facts_unknown (product_platform_packet_facts_t *platform)
{
  if (platform)
    clib_memset (platform, 0, sizeof (*platform));
}

void
product_packet_graph_set_platform_facts (vlib_buffer_t *buffer,
                                         const product_platform_packet_facts_t *platform,
                                         u64 generation)
{
  product_buffer_platform_metadata_t metadata;
  if (!buffer)
    return;
  clib_memcpy_fast (&metadata, buffer->opaque, sizeof (metadata));
  clib_memset (&metadata.platform, 0, sizeof (metadata.platform));
  if (platform && generation)
    metadata.platform = *platform;
  metadata.obligation.queue_generation = generation;
  clib_memcpy_fast (buffer->opaque, &metadata, sizeof (metadata));
}

int
product_packet_graph_get_platform_facts (const vlib_buffer_t *buffer,
                                         u64 generation,
                                         product_platform_packet_facts_t *platform)
{
  product_buffer_platform_metadata_t metadata;
  if (!platform)
    return 0;
  product_packet_graph_platform_facts_unknown (platform);
  if (!buffer || !generation)
    return 0;
  clib_memcpy_fast (&metadata, buffer->opaque, sizeof (metadata));
  if (metadata.obligation.queue_generation != generation)
    return 0;
  *platform = metadata.platform;
  return 1;
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
                             u64 generation, const vlib_buffer_t *buffer)
{
  const product_packet_facts_t *facts = &lease->facts;
  clib_memset (metadata, 0, sizeof (*metadata));
  metadata->origin_obligation_id = lease->origin_obligation_id;
  metadata->expected_owner = lease->assignment.execution_owner;
  metadata->generation = generation;
  metadata->canonical_hash = lease->assignment.canonical_hash;
  metadata->key_kind = lease->assignment.key.kind;
  metadata->query_class = lease->assignment.key.query_class;
  metadata->assignment_valid = lease->assignment.valid;
  metadata->l3_header_length = facts->l3_header_length;
  metadata->l4_header_length = facts->l4_header_length;
  metadata->ip_family = facts->ip_family;
  metadata->protocol = facts->protocol;
  metadata->l3_status = facts->l3_status;
  metadata->l4_status = facts->l4_status;
  metadata->packet_length = facts->packet_length;
  metadata->source_port = facts->source_port;
  metadata->destination_port = facts->destination_port;
  metadata->span_current_data = buffer->current_data;
  metadata->span_length = buffer->current_length;
  if (facts->protocol == 6)
    {
      metadata->transport.tcp.sequence = facts->tcp_sequence;
      metadata->transport.tcp.acknowledgment = facts->tcp_acknowledgment;
      metadata->transport.tcp.window = facts->tcp_window;
      metadata->transport.tcp.flags = facts->tcp_flags;
      metadata->transport.tcp.scale = facts->tcp_window_scale_known
                                       ? facts->tcp_window_scale : 255;
    }
  else if (facts->protocol == 1 || facts->protocol == 58)
    {
      metadata->transport.icmp.identifier = facts->icmp_identifier;
      metadata->transport.icmp.sequence = facts->icmp_sequence;
      metadata->transport.icmp.type = facts->icmp_type;
      metadata->transport.icmp.code = facts->icmp_code;
      metadata->transport.icmp.identity_known = facts->icmp_identity_known;
    }
  metadata->state_bits = PRODUCT_META_ADMITTED;
  metadata->primary_handoff_count = lease->primary_handoff_count;
  metadata->corrective_handoff_count = lease->corrective_handoff_count;
  metadata->runtime_drop_reason = lease->runtime_drop_reason;
  metadata->processing_bypass_reason = lease->processing_bypass_reason;
  if (lease->assignment.source_is_a)
    metadata->state_bits |= PRODUCT_META_SOURCE_IS_A;
  product_metadata_set_terminal_intent (metadata, lease->terminal_intent);
}

static int
product_lease_from_metadata (const product_buffer_metadata_t *metadata,
                             const vlib_buffer_t *buffer, product_packet_lease_t *lease)
{
  product_packet_facts_t *facts;
  clib_memset (lease, 0, sizeof (*lease));
  facts = &lease->facts;
  lease->origin_obligation_id = metadata->origin_obligation_id;
  lease->assignment.execution_owner = metadata->expected_owner;
  lease->primary_handoff_count = metadata->primary_handoff_count;
  lease->corrective_handoff_count = metadata->corrective_handoff_count;
  lease->distribution = metadata->primary_handoff_count == 0
                          ? PRODUCT_PACKET_DISTRIBUTION_LOCAL
                          : PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE;
  lease->policy_owner_ready = (metadata->state_bits & PRODUCT_META_POLICY_READY) != 0;
  lease->terminal_intent = product_metadata_terminal_intent (metadata);
  lease->terminal_count = lease->terminal_intent != PRODUCT_PACKET_INTENT_NONE;
  lease->runtime_drop_reason = metadata->runtime_drop_reason;
  lease->processing_bypass_reason = metadata->processing_bypass_reason;
  lease->settled = (metadata->state_bits & PRODUCT_META_SETTLED) != 0;
  /* The retained native span is immutable in this subgraph. No header decode,
   * pointer escape, or access after completion/free is permitted. */
  if (buffer->current_data != metadata->span_current_data
      || buffer->current_length != metadata->span_length
      || metadata->packet_length > buffer->current_length)
    goto invalid_span;
  facts->l3_status = metadata->l3_status;
  facts->l4_status = metadata->l4_status;
  facts->ip_family = metadata->ip_family;
  facts->protocol = metadata->protocol;
  facts->l3_header_length = metadata->l3_header_length;
  facts->l4_header_length = metadata->l4_header_length;
  facts->packet_length = metadata->packet_length;
  facts->source_port = metadata->source_port;
  facts->destination_port = metadata->destination_port;
  if (facts->l3_status == PRODUCT_PACKET_L3_COMPLETE)
    {
      const u8 *packet = vlib_buffer_get_current ((vlib_buffer_t *) buffer);
      u32 offset = facts->ip_family == 4 ? 12 : 8;
      u32 width = facts->ip_family == 4 ? 4 : 16;
      if ((facts->ip_family != 4 && facts->ip_family != 6)
          || offset + 2 * width > facts->packet_length
          || facts->l3_header_length > facts->packet_length
          || facts->l3_header_length + facts->l4_header_length > facts->packet_length)
        goto invalid_span;
      clib_memcpy_fast (facts->source_address + 16 - width, packet + offset, width);
      clib_memcpy_fast (facts->destination_address + 16 - width,
                        packet + offset + width, width);
      facts->transport_offset = facts->l3_header_length;
      facts->transport_length = facts->packet_length - facts->l3_header_length;
    }
  if (facts->protocol == 6)
    {
      facts->tcp_sequence = metadata->transport.tcp.sequence;
      facts->tcp_acknowledgment = metadata->transport.tcp.acknowledgment;
      facts->tcp_window = metadata->transport.tcp.window;
      facts->tcp_flags = metadata->transport.tcp.flags;
      facts->tcp_window_scale_known = metadata->transport.tcp.scale != 255;
      facts->tcp_window_scale = facts->tcp_window_scale_known
                                 ? metadata->transport.tcp.scale : 0;
    }
  else if (facts->protocol == 1 || facts->protocol == 58)
    {
      facts->icmp_identifier = metadata->transport.icmp.identifier;
      facts->icmp_sequence = metadata->transport.icmp.sequence;
      facts->icmp_type = metadata->transport.icmp.type;
      facts->icmp_code = metadata->transport.icmp.code;
      facts->icmp_identity_known = metadata->transport.icmp.identity_known;
    }
  /* Restore a typed key by the saved projection. No compare, canonicalization,
   * hash or owner selection occurs after admission. */
  product_owner_assignment_t *assignment = &lease->assignment;
  assignment->canonical_hash = metadata->canonical_hash;
  assignment->valid = metadata->assignment_valid;
  assignment->source_is_a = !!(metadata->state_bits & PRODUCT_META_SOURCE_IS_A);
  assignment->key.kind = metadata->key_kind;
  assignment->key.ip_family = facts->ip_family;
  assignment->key.protocol = facts->protocol;
  assignment->key.query_class = metadata->query_class;
  u8 *source = assignment->source_is_a ? assignment->key.address_a : assignment->key.address_b;
  u8 *destination = assignment->source_is_a ? assignment->key.address_b : assignment->key.address_a;
  clib_memcpy_fast (source, facts->source_address, 16);
  clib_memcpy_fast (destination, facts->destination_address, 16);
  if (assignment->key.kind == PRODUCT_OWNER_KEY_L4_PORTS)
    {
      assignment->key.transport.ports.a = assignment->source_is_a ? facts->source_port : facts->destination_port;
      assignment->key.transport.ports.b = assignment->source_is_a ? facts->destination_port : facts->source_port;
    }
  else if (assignment->key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY)
    assignment->key.transport.query.identifier = facts->icmp_identifier;
  product_packet_graph_get_platform_facts (buffer, metadata->generation, &lease->platform);
  return 1;

invalid_span:
  clib_memset (facts, 0, sizeof (*facts));
  lease->policy_owner_ready = 0;
  lease->terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
  lease->terminal_count = 1;
  lease->runtime_drop_reason = PRODUCT_PACKET_DROP_INVALID_ENVELOPE;
  return 0;
}

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static u64
product_packet_event_clock_ns (void)
{
  struct timespec value;
  if (clock_gettime (CLOCK_MONOTONIC, &value) != 0)
    return 0;
  return (u64) value.tv_sec * UINT64_C (1000000000) + value.tv_nsec;
}

static const char *
product_packet_evidence_source (const product_packet_lease_t *lease)
{
  switch (lease->platform.provenance)
    {
    case PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED: return "GRAPH_INJECTED";
    case PRODUCT_PACKET_PROVENANCE_VPN_TUN: return "TUN_CAPTURED";
    case PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN: return "FLOW_STACK_RETURN";
    case PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE: return "NFQ_CAPTURED";
    default: return "UNKNOWN";
    }
}

static void
product_metadata_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
                        vlib_buffer_t *buffer, u32 buffer_index,
                        const product_buffer_metadata_t *metadata,
                        const product_packet_lease_t *lease, const char *stage)
{
  if (!(metadata->state_bits & PRODUCT_META_TRACE))
    return;
  u64 entered_ns = product_packet_event_clock_ns ();
  const product_packet_facts_t *f = &lease->facts;
  const product_platform_packet_facts_t *p = &lease->platform;
  product_buffer_platform_metadata_t extra;
  clib_memcpy_fast (&extra, buffer->opaque, sizeof (extra));
  flockfile (stderr);
  fprintf (stderr, "s216 stage=%s source=%s node=%u thread=%u worker=%u buffer=%u generation=%llu token=%llu owner=%u l3=%u l4=%u family=%u protocol=%u packet_length=%u l3_length=%u l4_length=%u transport_offset=%u transport_length=%u src_port=%u dst_port=%u tcp_seq=%u tcp_ack=%u tcp_window=%u tcp_flags=%u wscale=%u wscale_known=%u icmp_type=%u icmp_code=%u icmp_id=%u icmp_seq=%u icmp_known=%u uid=%u ifindex=%u context=%u availability=%u direction=%u provenance=%u completion_kind=%u queue_generation=%llu packet_id=%u origin_lane=%u intent=%u src=",
    stage, product_packet_evidence_source (lease), node->node_index,
    vm->thread_index, vlib_get_worker_index (vm->thread_index), buffer_index,
    (unsigned long long) metadata->generation,
    (unsigned long long) metadata->origin_obligation_id, lease->assignment.execution_owner,
    f->l3_status, f->l4_status, f->ip_family, f->protocol, f->packet_length,
    f->l3_header_length, f->l4_header_length, f->transport_offset,
    f->transport_length, f->source_port, f->destination_port,
    f->tcp_sequence, f->tcp_acknowledgment, f->tcp_window, f->tcp_flags,
    f->tcp_window_scale, f->tcp_window_scale_known, f->icmp_type, f->icmp_code,
    f->icmp_identifier, f->icmp_sequence, f->icmp_identity_known,
    p->uid, p->linux_ifindex, p->network_context_id, p->availability,
    p->direction, p->provenance, extra.obligation.kind,
    (unsigned long long) extra.obligation.queue_generation,
    extra.obligation.packet_id, extra.obligation.origin_lane, lease->terminal_intent);
  product_diagnostic_write_hex (stderr, f->source_address, 16);
  fprintf (stderr, " dst=");
  product_diagnostic_write_hex (stderr, f->destination_address, 16);
  if (strcmp (stage, "admit") == 0)
    {
      const u8 *packet = vlib_buffer_get_current (buffer);
      fprintf (stderr, " raw=");
      product_diagnostic_write_hex (stderr, packet, buffer->current_length);
    }
  fprintf (stderr, " mono_ns=%llu\n", (unsigned long long) entered_ns);
  const product_owner_assignment_t *a = &lease->assignment;
  fprintf (stderr, "s207 stage=%s token=%llu generation=%llu thread=%u valid=%u owner=%u hash=%llu source_is_a=%u key_kind=%u key_family=%u key_protocol=%u query_class=%u query_id=%u port_a=%u port_b=%u key_a=",
    stage, (unsigned long long) metadata->origin_obligation_id,
    (unsigned long long) metadata->generation, vm->thread_index,
    a->valid, a->execution_owner, (unsigned long long) a->canonical_hash,
    a->source_is_a, a->key.kind, a->key.ip_family, a->key.protocol,
    a->key.query_class,
    a->key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY ? a->key.transport.query.identifier : 0,
    a->key.kind == PRODUCT_OWNER_KEY_L4_PORTS ? a->key.transport.ports.a : 0,
    a->key.kind == PRODUCT_OWNER_KEY_L4_PORTS ? a->key.transport.ports.b : 0);
  product_diagnostic_write_hex (stderr, a->key.address_a, 16);
  fprintf (stderr, " key_b=");
  product_diagnostic_write_hex (stderr, a->key.address_b, 16);
  fprintf (stderr, "\n");
  funlockfile (stderr);
}
#endif

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

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
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

#endif

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
extern vlib_node_registration_t product_packet_test_ingress_node;
#endif
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#include "product_packet_fragment_graph.inc"
#endif

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
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  PRODUCT_ADMIT_NEXT_FRAGMENT_STEER,
  PRODUCT_ADMIT_NEXT_OWNER_GUARD,
#endif
  PRODUCT_ADMIT_NEXT_POLICY,
  PRODUCT_ADMIT_NEXT_TERMINAL,
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  PRODUCT_ADMIT_NEXT_REASSEMBLY,
#endif
  PRODUCT_ADMIT_N_NEXT,
};

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static int
product_capacity_ring_empty (u32 queue_index)
{
  vlib_frame_queue_main_t *fqm = vec_elt_at_index (
    vlib_get_thread_main ()->frame_queue_mains, queue_index);
  for (u32 i = 0; i < vec_len (fqm->vlib_frame_queues); i++)
    {
      vlib_frame_queue_t *fq = fqm->vlib_frame_queues[i];
      if (fq && fq->head != fq->tail) return 0;
    }
  return 1;
}

/* Called only while workers are quiesced and every carrier is settled.
 * Storage remains the original full-size native allocation. Reduced test
 * capacities exercise the actual retained backend's ring-full branch. */
static void
product_capacity_set_empty_ring (u32 queue_index, u32 slots)
{
  vlib_frame_queue_main_t *fqm = vec_elt_at_index (
    vlib_get_thread_main ()->frame_queue_mains, queue_index);
  for (u32 i = 0; i < vec_len (fqm->vlib_frame_queues); i++)
    {
      vlib_frame_queue_t *fq = fqm->vlib_frame_queues[i];
      if (!fq) continue;
      ASSERT (fq->head == fq->tail);
      fq->head = fq->tail = 0;
      fq->nelts = slots;
    }
}

static void
product_capacity_configure_empty (product_packet_graph_main_t *graph,
                                   u32 credits, u32 primary, u32 completion)
{
  product_capacity_set_empty_ring (graph->primary_frame_queue, primary);
  product_capacity_set_empty_ring (graph->completion_return_frame_queue, completion);
  graph->primary_credit_limit = credits;
  graph->primary_ring_slots = primary;
  graph->completion_ring_slots = completion;
  for (u32 i = 0; i < PRODUCT_GRAPH_WORKERS; i++)
    clib_atomic_store_rel_n (&graph->handoff_credits[i], credits);
}

static int
product_primary_handoff (vlib_main_t *vm, vlib_node_runtime_t *node,
                          u32 bi, product_buffer_metadata_t *metadata,
                          product_packet_processing_bypass_reason_t *reason)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u16 owner = metadata->expected_owner;
  u16 target = vlib_get_worker_thread_index (owner);
  u32 failed;
  if (!product_handoff_credit_reserve (graph, owner, PRODUCT_HANDOFF_PRIMARY,
                                       metadata->origin_obligation_id))
    {
      *reason = PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED;
      clib_atomic_fetch_add_relax (&graph->primary_rejected, 1);
      return 0;
    }
  if (graph->misroute_next)
    {
      graph->misroute_next = 0;
      target = vm->thread_index; /* Explicit fault: do not rewrite owner. */
      metadata->state_bits |= PRODUCT_META_TRACE;
    }
  metadata->state_bits |= PRODUCT_META_HANDOFF_CREDIT;
  product_metadata_store (vlib_get_buffer (vm, bi), metadata);
  if (metadata->state_bits & PRODUCT_META_TRACE)
    fprintf (stderr, "s205 event=primary_publish thread=%u buffer=%u token=%llu generation=%llu owner=%u target_thread=%u primary=%u corrective=%u\n",
      vm->thread_index, bi, (unsigned long long) metadata->origin_obligation_id,
      (unsigned long long) metadata->generation, owner, target,
      metadata->primary_handoff_count, metadata->corrective_handoff_count);
  if (vlib_buffer_enqueue_to_thread_retained (vm, node, graph->primary_frame_queue,
        &bi, &target, 1, &failed) != 1)
    {
      ASSERT (failed == bi);
      *reason = PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED;
      if (metadata->fragment_bundle_count && (metadata->state_bits & PRODUCT_META_TRACE))
        {
          vlib_frame_queue_main_t *fqm = vec_elt_at_index (
            vlib_get_thread_main ()->frame_queue_mains, graph->primary_frame_queue);
          vlib_frame_queue_t *fq = fqm->vlib_frame_queues[target];
          fprintf (stderr, "s229 event=product_handoff_rejected thread=%u buffer=%u token=%llu generation=%llu family=%u reason=8 prepared=1 refs=1 queue=%u target_thread=%u slots=%u occupancy=%llu originals=%u\n",
            vm->thread_index, bi, (unsigned long long)metadata->origin_obligation_id,
            (unsigned long long)metadata->generation, metadata->ip_family,
            graph->primary_frame_queue, target, fq->nelts,
            (unsigned long long)(fq->tail-fq->head), metadata->fragment_bundle_count);
        }
      metadata->state_bits &= ~PRODUCT_META_HANDOFF_CREDIT;
      product_metadata_store (vlib_get_buffer (vm, bi), metadata);
      product_handoff_credit_release (graph, owner);
      clib_atomic_fetch_add_relax (&graph->primary_rejected, 1);
      return 0;
    }
  clib_atomic_fetch_add_relax (&graph->primary_published, 1);
  /* The receiver may already own/free bi. Read only this local metadata copy. */
  if (metadata->state_bits & PRODUCT_META_TRACE)
    fprintf (stderr, "s205 event=primary_accepted thread=%u buffer=%u token=%llu generation=%llu owner=%u target_thread=%u\n",
      vm->thread_index, bi, (unsigned long long) metadata->origin_obligation_id,
      (unsigned long long) metadata->generation, owner, target);
  return 1;
}
#endif

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
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (product_fragment_dispatch (vm, node, buffer_index, &initial_metadata))
        continue;
#endif
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
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
#endif
      clib_memset (&ingress, 0, sizeof (ingress));
      ingress.data = vlib_buffer_get_current (buffer);
      ingress.length = buffer->current_length;
      ingress.current_worker = logical_worker;
      ingress.origin_obligation_id = initial_metadata.origin_obligation_id;
      if (!product_packet_graph_get_platform_facts (
            buffer, initial_metadata.generation, &ingress.platform))
        product_packet_graph_platform_facts_unknown (&ingress.platform);
      clib_memset (&lease, 0, sizeof (lease));
      product_packet_result_t admit_result;
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (initial_metadata.fragment_bundle_count)
        {
          if (!product_lease_from_metadata (&initial_metadata, buffer, &lease))
            clib_panic ("prepared fragment packet metadata changed before admission");
          admit_result = PRODUCT_PACKET_OK;
        }
      else
#endif
        admit_result = product_packet_admit (&layout, &ingress, &lease);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (admit_result != PRODUCT_PACKET_OK)
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
#endif
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      /* Every successfully parsed L3 packet uses the same assignment. Missing
       * typed transport facts remain unavailable to policy predicates. */
      if (admit_result == PRODUCT_PACKET_OK)
        lease.policy_owner_ready = lease.distribution == PRODUCT_PACKET_DISTRIBUTION_LOCAL;
#endif
      product_metadata_from_lease (&metadata, &lease,
                                   initial_metadata.generation, buffer);
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      metadata.fragment_bundle_head = initial_metadata.fragment_bundle_head;
      metadata.fragment_bundle_count = initial_metadata.fragment_bundle_count;
#endif
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (vm->thread_index == vlib_get_worker_thread_index (1))
        metadata.state_bits |= PRODUCT_META_ADMIT_THREAD_2;
#endif
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      metadata.state_bits |= initial_metadata.state_bits & PRODUCT_META_TRACE;
      if (lease.policy_owner_ready)
        metadata.state_bits |= PRODUCT_META_POLICY_READY;
      if (admit_result != PRODUCT_PACKET_OK)
        metadata.state_bits &= ~PRODUCT_META_ADMITTED;
      product_metadata_trace (vm, node, buffer, buffer_index, &metadata, &lease, "admit");
      if (metadata.state_bits & PRODUCT_META_TRACE)
      fprintf(stderr, "s203 event=admit source=%s node=%u thread=%u worker=%u buffer=%u obligation=%llu generation=%llu parse=1 assignment=%u owner=%u family=%u protocol=%u src_port=%u dst_port=%u intent=%u\n",
        product_packet_evidence_source (&lease), node->node_index, vm->thread_index, logical_worker, buffer_index,
        (unsigned long long)metadata.origin_obligation_id, (unsigned long long)metadata.generation,
        lease.assignment.valid, lease.assignment.execution_owner, lease.facts.ip_family, lease.facts.protocol,
        lease.facts.source_port, lease.facts.destination_port, lease.terminal_intent);
#endif
      product_metadata_store (buffer, &metadata);
      PRODUCT_EVIDENCE_ADD (admitted, 1);
      product_add_trace (vm, node, buffer, PRODUCT_TRACE_ADMIT,
                         metadata.origin_obligation_id);

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (lease.terminal_intent == PRODUCT_PACKET_INTENT_NONE
          && lease.distribution == PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE)
        {
          product_packet_processing_bypass_reason_t reason = PRODUCT_PACKET_BYPASS_NONE;
          if (product_primary_handoff (vm, node, buffer_index, &metadata, &reason))
            continue;
          /* Retained rejection still owns this buffer on arrival worker. */
          if (product_packet_bypass_primary_capacity (&lease, reason) != PRODUCT_PACKET_OK)
            {
              lease.terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
              lease.terminal_count = 1;
              lease.runtime_drop_reason = PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION;
            }
          product_metadata_set_terminal_intent (&metadata, lease.terminal_intent);
          metadata.runtime_drop_reason = lease.runtime_drop_reason;
          metadata.processing_bypass_reason = lease.processing_bypass_reason;
          product_metadata_store (buffer, &metadata);
          if (metadata.state_bits & PRODUCT_META_TRACE)
            fprintf (stderr, "s210 event=primary_rejected thread=%u buffer=%u token=%llu generation=%llu owner=%u intent=%u reason=%u retained=1 policy_evaluated=0\n",
              vm->thread_index, buffer_index,
              (unsigned long long) metadata.origin_obligation_id,
              (unsigned long long) metadata.generation, metadata.expected_owner,
              lease.terminal_intent, reason);
        }
      vlib_buffer_enqueue_to_single_next (vm, node, &buffer_index,
        lease.terminal_intent == PRODUCT_PACKET_INTENT_NONE
          ? PRODUCT_ADMIT_NEXT_POLICY : PRODUCT_ADMIT_NEXT_TERMINAL, 1);
#else
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
                lease.assignment.execution_owner, PRODUCT_HANDOFF_PRIMARY))
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
#endif
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
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
    [PRODUCT_ADMIT_NEXT_FRAGMENT_STEER] = "product-packet-fragment-steer",
    [PRODUCT_ADMIT_NEXT_OWNER_GUARD] = "product-packet-owner-guard",
#endif
    [PRODUCT_ADMIT_NEXT_POLICY] = "product-packet-policy",
    [PRODUCT_ADMIT_NEXT_TERMINAL] = "product-packet-terminal",
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
    [PRODUCT_ADMIT_NEXT_REASSEMBLY] = "product-reassembly",
#endif
  },
};

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
enum
{
  PRODUCT_OWNER_GUARD_NEXT_POLICY,
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
      product_lease_from_metadata (&metadata, buffer, &lease);
      if (!product_packet_graph_get_platform_facts (buffer, metadata.generation,
                                                  &lease.platform))
        product_packet_graph_platform_facts_unknown (&lease.platform);
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
                lease.assignment.execution_owner, PRODUCT_HANDOFF_CORRECTIVE))
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
      metadata.state_bits |= PRODUCT_META_POLICY_READY;
      product_metadata_store (buffer, &metadata);
      product_add_trace (vm, node, buffer, PRODUCT_TRACE_OWNER_GUARD,
                         metadata.origin_obligation_id);
      vlib_buffer_enqueue_to_single_next (
        vm, node, &buffer_index, PRODUCT_OWNER_GUARD_NEXT_POLICY, 1);
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
    [PRODUCT_OWNER_GUARD_NEXT_POLICY] = "product-packet-policy",
    [PRODUCT_OWNER_GUARD_NEXT_TERMINAL] = "product-packet-terminal",
  },
};

#endif

enum
{
  PRODUCT_POLICY_NEXT_CONSUMER,
  PRODUCT_POLICY_N_NEXT,
};

VLIB_NODE_FN (product_packet_policy_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;

  PRODUCT_EVIDENCE_ADD (policy_vectors, frame->n_vectors);

  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_buffer_metadata_t metadata;
      product_packet_lease_t lease;
      product_packet_graph_policy_evaluation_t evaluation;
      product_packet_result_t policy_result;

      product_metadata_load (buffer, &metadata);
      if (metadata.generation != graph->generation)
        {
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
          PRODUCT_EVIDENCE_ADD (stale_events_rejected, 1);
#endif
          vlib_buffer_free (vm, &buffer_index, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
          clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
          continue;
        }
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (metadata.state_bits & PRODUCT_META_HANDOFF_CREDIT)
        {
          product_handoff_credit_release (graph, metadata.expected_owner);
          metadata.state_bits &= ~PRODUCT_META_HANDOFF_CREDIT;
          product_metadata_store (buffer, &metadata);
          clib_atomic_fetch_add_relax (&graph->primary_received, 1);
          if (metadata.state_bits & PRODUCT_META_TRACE)
            fprintf (stderr, "s205 event=primary_dequeue node=%u thread=%u buffer=%u token=%llu generation=%llu owner=%u primary=%u corrective=%u\n",
              node->node_index, vm->thread_index, buffer_index,
              (unsigned long long) metadata.origin_obligation_id,
              (unsigned long long) metadata.generation, metadata.expected_owner,
              metadata.primary_handoff_count, metadata.corrective_handoff_count);
        }
#endif
      product_lease_from_metadata (&metadata, buffer, &lease);
      if (!product_packet_graph_get_platform_facts (buffer, metadata.generation,
                                                  &lease.platform))
        product_packet_graph_platform_facts_unknown (&lease.platform);
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      /* Evidence check at the actual policy receiver. An implementation
       * error drops here; it never runs another selector or corrective hop. */
      int delivery_error = 0;
      if (metadata.state_bits & PRODUCT_META_TRACE)
        {
          clib_atomic_fetch_add_relax (&graph->owner_delivery_checks, 1);
          delivery_error = metadata.expected_owner != vlib_get_worker_index (vm->thread_index);
          if (delivery_error)
            clib_atomic_fetch_add_relax (&graph->owner_delivery_failures, 1);
          fprintf (stderr, "s205 event=owner_delivery node=%u thread=%u buffer=%u token=%llu owner=%u actual_worker=%u match=%u\n",
            node->node_index, vm->thread_index, buffer_index,
            (unsigned long long) metadata.origin_obligation_id, metadata.expected_owner,
            vlib_get_worker_index (vm->thread_index), !delivery_error);
        }
      if (delivery_error)
        {
          clib_memset (&evaluation, 0, sizeof (evaluation));
          lease.terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
          lease.terminal_count = 1;
          lease.runtime_drop_reason = PRODUCT_PACKET_DROP_OWNER_DELIVERY_MISMATCH;
          policy_result = PRODUCT_PACKET_OK;
        }
      else
        {
          if (lease.terminal_intent == PRODUCT_PACKET_INTENT_NONE)
            {
              lease.policy_owner_ready = 1;
              metadata.state_bits |= PRODUCT_META_POLICY_READY;
            }
          policy_result = product_packet_graph_policy_on_owner (
            vm, buffer_index, &lease, &evaluation,
            metadata.state_bits & PRODUCT_META_TRACE);
        }
#else
      policy_result = product_packet_graph_policy_on_owner (
            vm, buffer_index, &lease, &evaluation,
            metadata.state_bits & PRODUCT_META_TRACE);
#endif
      if (policy_result != PRODUCT_PACKET_OK
          && lease.terminal_intent == PRODUCT_PACKET_INTENT_NONE)
        {
          /* An unexpected stage order must fail closed before terminal. */
          if (product_packet_set_terminal (
                &lease, PRODUCT_PACKET_INTENT_DROP_RUNTIME)
              == PRODUCT_PACKET_OK)
            lease.runtime_drop_reason = PRODUCT_PACKET_DROP_INVALID_ENVELOPE;
        }
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      product_metadata_trace (vm, node, buffer, buffer_index, &metadata, &lease, "policy");
      if (metadata.state_bits & PRODUCT_META_TRACE)
      fprintf(stderr, "s203 event=policy source=%s node=%u thread=%u worker=%u buffer=%u obligation=%llu generation=%llu owner=%u stage=%u verdict=%u rule=%llu\n",
        product_packet_evidence_source (&lease), node->node_index, vm->thread_index, vlib_get_worker_index(vm->thread_index),
        buffer_index, (unsigned long long)metadata.origin_obligation_id, (unsigned long long)metadata.generation,
        lease.assignment.execution_owner, evaluation.stage, evaluation.verdict,
        (unsigned long long)evaluation.rule_id);
#endif
      product_metadata_set_terminal_intent (&metadata, lease.terminal_intent);
      metadata.runtime_drop_reason = lease.runtime_drop_reason;
      metadata.processing_bypass_reason = lease.processing_bypass_reason;
      product_metadata_store (buffer, &metadata);
      product_add_trace (vm, node, buffer, PRODUCT_TRACE_POLICY,
                         metadata.origin_obligation_id);
      vlib_buffer_enqueue_to_single_next (
        vm, node, &buffer_index, PRODUCT_POLICY_NEXT_CONSUMER, 1);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_policy_node) = {
  .name = "product-packet-policy",
  .vector_size = sizeof (u32),
  .format_trace = format_product_packet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .n_next_nodes = PRODUCT_POLICY_N_NEXT,
  .next_nodes = {
    [PRODUCT_POLICY_NEXT_CONSUMER] = "product-flow-consumer",
  },
};

enum
{
  PRODUCT_CONSUMER_NEXT_TERMINAL,
  PRODUCT_CONSUMER_NEXT_VPN_EGRESS,
  PRODUCT_CONSUMER_N_NEXT,
};

/* Both packets after conntrack and owner-created ENDs enter here. Packet-only
 * consumers are bypassed explicitly, not fed an empty pseudo IP packet. */
VLIB_NODE_FN (product_flow_consumer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      u32 bi = from[i], next = PRODUCT_CONSUMER_NEXT_TERMINAL;
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      if (product_buffer_is_flow_end (b))
        {
          if (product_flow_end_consume (vm, node, bi))
            continue;
        }
      else
        {
          product_buffer_metadata_t metadata;
          product_packet_lease_t lease;
          product_metadata_load (b, &metadata);
          product_lease_from_metadata (&metadata, b, &lease);
          if (product_packet_graph_get_platform_facts (b, metadata.generation,
                                                       &lease.platform) &&
              lease.platform.provenance == PRODUCT_PACKET_PROVENANCE_VPN_TUN &&
              lease.terminal_intent != PRODUCT_PACKET_INTENT_DROP_RUNTIME)
            next = PRODUCT_CONSUMER_NEXT_VPN_EGRESS;
          if (metadata.state_bits & PRODUCT_META_TRACE)
            fprintf (stderr, "s225 event=consumer_packet node=%u thread=%u owner=%u generation=%llu buffer=%u token=%llu next=%u is_flow_end=0\n",
              node->node_index, vm->thread_index, metadata.expected_owner,
              (unsigned long long) metadata.generation, bi,
              (unsigned long long) metadata.origin_obligation_id, next);
        }
      vlib_buffer_enqueue_to_single_next (vm, node, &bi, next, 1);
    }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (product_flow_consumer_node) = {
  .name = "product-flow-consumer", .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL, .n_next_nodes = PRODUCT_CONSUMER_N_NEXT,
  .next_nodes = {
    [PRODUCT_CONSUMER_NEXT_TERMINAL] = "product-packet-terminal",
    [PRODUCT_CONSUMER_NEXT_VPN_EGRESS] = "product-vpn-egress",
  },
};

VLIB_NODE_FN(product_vpn_egress_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args(frame);
  for (u32 i = 0; i < frame->n_vectors; ++i) {
    vlib_buffer_t *buffer = vlib_get_buffer(vm, from[i]);
    product_buffer_metadata_t metadata;
    product_packet_lease_t lease;
    product_metadata_load(buffer, &metadata);
    if (product_lease_from_metadata(&metadata, buffer, &lease) &&
        lease.platform.provenance == PRODUCT_PACKET_PROVENANCE_VPN_TUN &&
        lease.terminal_intent != PRODUCT_PACKET_INTENT_DROP_RUNTIME &&
        (lease.facts.ip_family == 4 || lease.facts.ip_family == 6) &&
        (lease.facts.protocol == 6 || lease.facts.protocol == 17) &&
        lease.facts.l4_status == PRODUCT_PACKET_L4_COMPLETE &&
        product_vpn_flow_stack_driver_enabled()) {
      product_vpn_flow_stack_input_result_t result = product_vpn_flow_stack_driver_input(
        vm, vlib_buffer_get_current(buffer), buffer->current_length,
        &lease.platform, metadata.generation);
      metadata.flow_stack_result = 1 + result;
      product_metadata_store(buffer, &metadata);
      if (metadata.state_bits & PRODUCT_META_TRACE)
        fprintf(stderr, "s237 event=input_copy node=%u thread=%u tls=%u owner=%u generation=%llu buffer=%u token=%llu bytes=%u result=%u\n",
          node->node_index, vm->thread_index, vlib_get_thread_index(), metadata.expected_owner,
          (unsigned long long)metadata.generation, from[i],
          (unsigned long long)metadata.origin_obligation_id, buffer->current_length, result);
    }
    vlib_buffer_enqueue_to_single_next(vm, node, &from[i], 0, 1);
  }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE(product_vpn_egress_node) = {
  .name = "product-vpn-egress", .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL, .n_next_nodes = 1,
  .next_nodes = {[0] = "product-packet-terminal"},
};

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#define PRODUCT_COMPLETION_RETURN_CAPACITY 512
_Static_assert (PRODUCT_COMPLETION_RETURN_CAPACITY >
                  PRODUCT_ROOT_COMPLETION_MAX_LANES * PRODUCT_ROOT_COMPLETION_CAPACITY
                  + 3 * PRODUCT_GRAPH_INJECTION_CAPACITY,
                "return backlog covers every current admitted carrier");
_Static_assert (PRODUCT_COMPLETION_RETURN_CAPACITY >
                  PRODUCT_VPN_TUN_CAPTURE_CAPACITY +
                  PRODUCT_VPN_RETURN_WORKERS * PRODUCT_VPN_RETURN_CAPACITY +
                  3 * PRODUCT_GRAPH_INJECTION_CAPACITY,
                "return backlog covers VPN capture and all owner return allowances");
extern vlib_node_registration_t product_packet_completion_retry_node;
typedef struct
{
  u32 buffers[PRODUCT_COMPLETION_RETURN_CAPACITY];
  u16 head, count;
} __attribute__((aligned(CLIB_CACHE_LINE_BYTES))) product_completion_return_queue_t;
static product_completion_return_queue_t product_completion_returns[PRODUCT_GRAPH_WORKERS + 1];

static int
product_completion_return_try (vlib_main_t *vm, vlib_node_runtime_t *node,
                                u32 bi, const product_packet_completion_frame_t *completion,
                                int retry)
{
  if (product_vpn_tun_return_held(vm, completion)) return 0;
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u16 target = vlib_get_worker_thread_index (completion->obligation.origin_worker);
  u32 failed;
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s205 event=%s thread=%u buffer=%u token=%llu generation=%llu target_thread=%u producer_thread=%u\n",
      retry ? "completion_return_retry" : "completion_return_publish",
      vm->thread_index, bi, (unsigned long long) completion->obligation.token,
      (unsigned long long) completion->obligation.queue_generation, target,
      completion->producer_thread);
  if (vlib_buffer_enqueue_to_thread_retained (vm, node,
        graph->completion_return_frame_queue, &bi, &target, 1, &failed) != 1)
    return 0;
  clib_atomic_fetch_add_relax (&graph->completion_returns, 1);
  /* No access to the transferred native buffer after successful enqueue. */
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s205 event=completion_return_accepted thread=%u buffer=%u token=%llu generation=%llu target_thread=%u\n",
      vm->thread_index, bi, (unsigned long long) completion->obligation.token,
      (unsigned long long) completion->obligation.queue_generation, target);
  return 1;
}

static void
product_completion_return (vlib_main_t *vm, vlib_node_runtime_t *node,
                            u32 bi, const product_packet_completion_frame_t *completion)
{
  if (product_completion_return_try (vm, node, bi, completion, 0))
    return;
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 thread = vm->thread_index;
  ASSERT (thread <= PRODUCT_GRAPH_WORKERS);
  product_completion_return_queue_t *queue = &product_completion_returns[thread];
  /* Root has four 64-credit lanes plus bounded replay, metadata-injection and
   * fragment-injection populations (32 carriers/generation each).
   * This queue owns indices only, within that existing admitted population. */
  ASSERT (queue->count < PRODUCT_COMPLETION_RETURN_CAPACITY);
  queue->buffers[(queue->head + queue->count) % PRODUCT_COMPLETION_RETURN_CAPACITY] = bi;
  queue->count++;
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s210 event=completion_deferred thread=%u buffer=%u token=%llu generation=%llu intent=%u drop_reason=%u pending=%u capacity=%u\n",
      vm->thread_index, bi, (unsigned long long) completion->obligation.token,
      (unsigned long long) completion->obligation.queue_generation,
      completion->terminal_intent, completion->runtime_drop_reason,
      queue->count, PRODUCT_COMPLETION_RETURN_CAPACITY);
  clib_atomic_fetch_add_relax (&graph->completion_pending_returns, 1);
  clib_atomic_fetch_add_relax (&graph->completion_deferred, 1);
  vlib_node_set_interrupt_pending (vm, product_packet_completion_retry_node.index);
}

VLIB_NODE_FN (product_packet_completion_retry_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 thread = vm->thread_index;
  u32 completed = 0;
  (void) frame;
  ASSERT (thread <= PRODUCT_GRAPH_WORKERS);
  product_completion_return_queue_t *queue = &product_completion_returns[thread];
  u32 budget = clib_min(queue->count, 64);
  while (queue->count && budget--)
    {
      u32 bi = queue->buffers[queue->head];
      product_packet_completion_frame_t completion;
      clib_memcpy_fast (&completion, vlib_get_buffer (vm, bi)->opaque2, sizeof (completion));
      /* Fault injection holds returns, not original-capture completions. Scan
       * this existing bounded storage so the test does not accidentally fill
       * the shared capture ledger behind a deliberately held return. */
      if (product_vpn_tun_return_held(vm, &completion))
        {
          queue->head = (queue->head + 1) % PRODUCT_COMPLETION_RETURN_CAPACITY;
          queue->buffers[(queue->head + queue->count - 1) % PRODUCT_COMPLETION_RETURN_CAPACITY] = bi;
          continue;
        }
      clib_atomic_fetch_add_relax (&graph->completion_retry_attempts, 1);
      if (!product_completion_return_try (vm, node, bi, &completion, 1))
        break;
      queue->head = (queue->head + 1) % PRODUCT_COMPLETION_RETURN_CAPACITY;
      queue->count--;
      clib_atomic_fetch_sub_relax (&graph->completion_pending_returns, 1);
      completed++;
    }
  /* A full destination is dependency-blocked, not immediately runnable work.
   * Retry on a bounded native deadline without occupying an idle CPU. */
  if (queue->count && !vlib_node_is_scheduled(vm, node->node_index))
    vlib_node_schedule(vm, node->node_index, 0.001);
  return completed;
}
VLIB_REGISTER_NODE (product_packet_completion_retry_node) = {
  .name = "product-completion-return",
  .type = VLIB_NODE_TYPE_SCHED,
  .state = VLIB_NODE_STATE_INTERRUPT,
};
#endif

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
extern vlib_node_registration_t product_packet_origin_completion_node;
static u32 product_completion_probe_frame_queue;
#include "product_packet_reassembly_graph.inc"
#endif

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
      if (product_buffer_is_flow_end (buffer))
        {
          product_flow_end_terminal (vm, node, buffer_index);
          continue;
        }
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
      product_lease_from_metadata (&metadata, buffer, &lease);
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
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
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
#endif
      product_metadata_set_terminal_intent (&metadata,
                                            lease.terminal_intent);
      metadata.runtime_drop_reason = lease.runtime_drop_reason;
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      metadata.state_bits |= PRODUCT_META_SETTLED;
#endif
      product_metadata_store (buffer, &metadata);
      product_add_trace (vm, node, buffer, PRODUCT_TRACE_TERMINAL,
                         metadata.origin_obligation_id);
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (metadata.fragment_bundle_count)
        {
          product_fragment_terminal (vm, node, buffer_index, &metadata, &lease);
          continue;
        }
#endif

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
      completed_result.canonical_key = lease.assignment.key;
      completed_result.terminal_buffer_index = buffer_index;
      completed_result.terminal_current_data = (u32) buffer->current_data;
      completed_result.terminal_length = buffer->current_length;
      clib_sha256 (vlib_buffer_get_current (buffer), buffer->current_length,
                   completed_result.terminal_digest);
      completed_result.expected_owner = lease.assignment.execution_owner;
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

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      product_metadata_trace (vm, node, buffer, buffer_index, &metadata, &lease, "terminal");
      if (metadata.state_bits & PRODUCT_META_TRACE)
      fprintf(stderr, "s203 event=terminal source=%s node=%u thread=%u worker=%u buffer=%u obligation=%llu generation=%llu intent=%u owner=%u\n",
        product_packet_evidence_source (&lease), node->node_index, vm->thread_index, vlib_get_worker_index(vm->thread_index),
        buffer_index, (unsigned long long)metadata.origin_obligation_id,
        (unsigned long long)metadata.generation, lease.terminal_intent, lease.assignment.execution_owner);
      product_buffer_platform_metadata_t completion_metadata;
      clib_memcpy_fast (&completion_metadata, buffer->opaque, sizeof (completion_metadata));
      product_packet_completion_frame_t completion = {
        .obligation = completion_metadata.obligation,
        .producer_thread = vm->thread_index,
        .terminal_intent = lease.terminal_intent,
        .runtime_drop_reason = lease.runtime_drop_reason,
        .processing_bypass_reason = lease.processing_bypass_reason,
        .flags = (metadata.state_bits & PRODUCT_META_TRACE) ? PRODUCT_COMPLETION_TRACE : 0,
      };
      if (lease.platform.provenance == PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN)
        completion.flags |= PRODUCT_COMPLETION_FLOW_STACK_RETURN;
      if (lease.platform.provenance == PRODUCT_PACKET_PROVENANCE_VPN_TUN &&
          (lease.facts.ip_family == 4 || lease.facts.ip_family == 6) &&
          (lease.facts.protocol == 6 || lease.facts.protocol == 17))
        completion.flow_stack_result = metadata.flow_stack_result;
      if (lease.platform.provenance == PRODUCT_PACKET_PROVENANCE_VPN_TUN
          && lease.terminal_intent == PRODUCT_PACKET_INTENT_PASS_ADAPTER
          && lease.facts.l3_status == PRODUCT_PACKET_L3_COMPLETE
          && lease.facts.l4_status == PRODUCT_PACKET_L4_OTHER_TERMINAL
          && lease.facts.protocol != 6 && lease.facts.protocol != 17)
        completion.flags |= PRODUCT_COMPLETION_TRANSPORT_UNSUPPORTED;
      /* End the packet metadata lifetime. Only this 32-byte value survives
       * into origin completion; packet bytes remain unchanged and owned. */
      clib_memcpy_fast (buffer->opaque2, &completion, sizeof (completion));
      clib_atomic_fetch_add_relax (&graph->lifecycle_completion_frames, 1);
      clib_atomic_fetch_add_relax (&graph->lifecycle_terminal_intents, 1);
      if (completion.flags & PRODUCT_COMPLETION_TRACE)
        fprintf (stderr, "s204 event=completion_publish source=%s node=%u thread=%u buffer=%u token=%llu generation=%llu packet=%u lane=%u intent=%u frame_bytes=%u frames=%u\n",
          product_packet_evidence_source (&lease), node->node_index, vm->thread_index,
          buffer_index, (unsigned long long) completion.obligation.token,
          (unsigned long long) completion.obligation.queue_generation,
          completion.obligation.packet_id, completion.obligation.origin_lane,
          completion.terminal_intent, (u32)sizeof (completion),
          clib_atomic_load_acq_n (&graph->lifecycle_completion_frames));
      if (vm->thread_index == vlib_get_worker_thread_index (completion.obligation.origin_worker)
          && !product_vpn_tun_return_held(vm, &completion))
        vlib_buffer_enqueue_to_single_next (vm, node, &buffer_index, 0, 1);
      else
        product_completion_return (vm, node, buffer_index, &completion);
      continue;
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
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  .n_next_nodes = 1,
  .next_nodes = { [0] = "product-packet-origin-completion" },
#endif
};

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
VLIB_NODE_FN (product_packet_origin_completion_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      u32 bi = from[i];
      product_packet_completion_frame_t completion;
      clib_memcpy_fast (&completion, vlib_get_buffer (vm, bi)->opaque2, sizeof (completion));
      const char *source = (completion.flags & PRODUCT_COMPLETION_REPLAY_PROBE)
        ? "COMPLETION_REPLAY" : completion.obligation.kind == PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED
        ? "GRAPH_INJECTED" : completion.obligation.kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN
        ? "TUN_CAPTURED" : "NFQ_CAPTURED";
      if (completion.flags & PRODUCT_COMPLETION_TRACE)
        fprintf (stderr, "s204 event=completion_consume source=%s node=%u thread=%u buffer=%u token=%llu generation=%llu packet=%u lane=%u producer_thread=%u intent=%u mono_ns=%llu\n",
          source, node->node_index, vm->thread_index, bi,
          (unsigned long long) completion.obligation.token,
          (unsigned long long) completion.obligation.queue_generation,
          completion.obligation.packet_id, completion.obligation.origin_lane,
          completion.producer_thread, completion.terminal_intent,
          (unsigned long long) product_packet_event_clock_ns ());
      /* Immutable AdapterObligation selects its native endpoint. No mutable
       * process-wide callback can redirect another adapter's completion. */
      int valid_tun_completion = 0;
      int root_buffer_returned = 0;
      product_fragment_origin_check (vm, bi, &completion);
      switch (completion.obligation.kind)
        {
        case PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE:
          root_buffer_returned = product_root_nfqueue_complete_from_graph (vm, bi, &completion);
          break;
        case PRODUCT_ADAPTER_OBLIGATION_VPN_TUN:
          valid_tun_completion = product_vpn_tun_complete_from_graph (vm, bi, &completion);
          break;
        default:
          break; /* GRAPH_INJECTED owns no native adapter operation. */
        }
      if (!root_buffer_returned)
        vlib_buffer_free (vm, &bi, 1);
      if (valid_tun_completion)
        product_vpn_tun_return_freed(vm, bi, &completion);
      clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
      clib_atomic_fetch_sub_relax (&graph->lifecycle_completion_frames, 1);
      if (!(completion.flags & PRODUCT_COMPLETION_REPLAY_PROBE))
        {
          clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
          clib_atomic_fetch_add_relax (&graph->lifecycle_settlements, 1);
          clib_atomic_fetch_add_relax (&graph->lifecycle_returns, 1);
        }
      if (completion.flags & PRODUCT_COMPLETION_TRACE)
        fprintf (stderr, "s203 event=buffer_free source=%s thread=%u buffer=%u obligation=%llu buffer_debt=%u obligation_debt=%u completion_frames=%u\n",
          source, vm->thread_index, bi, (unsigned long long) completion.obligation.token,
          clib_atomic_load_acq_n (&graph->lifecycle_buffers),
          clib_atomic_load_acq_n (&graph->lifecycle_obligations),
          clib_atomic_load_acq_n (&graph->lifecycle_completion_frames));
    }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (product_packet_origin_completion_node) = {
  .name = "product-packet-origin-completion",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};
#endif

uint64_t
product_packet_graph_completion_frame_debt (void)
{
  return clib_atomic_load_acq_n (&product_packet_graph_main.lifecycle_completion_frames);
}

int
product_packet_graph_replay_completion (vlib_main_t *vm,
                                        const product_packet_completion_frame_t *completion)
{
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 bi, failed;
  u16 thread;
  if (!vm || !completion || !graph->accepting || !graph->enabled
      || !(completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE)
      || completion->obligation.origin_worker >= PRODUCT_GRAPH_WORKERS
      || vlib_buffer_alloc (vm, &bi, 1) != 1)
    return 0;
  thread = vlib_get_worker_thread_index (completion->obligation.origin_worker);
  vlib_buffer_t *buffer = vlib_get_buffer (vm, bi);
  buffer->current_data = 0; buffer->current_length = 0;
  clib_memcpy_fast (buffer->opaque2, completion, sizeof (*completion));
  clib_atomic_fetch_add_relax (&graph->lifecycle_buffers, 1);
  clib_atomic_fetch_add_relax (&graph->lifecycle_completion_frames, 1);
  if (vlib_buffer_enqueue_to_thread_retained (vm,
        vlib_node_get_runtime (vm, product_packet_origin_completion_node.index),
        product_completion_probe_frame_queue, &bi, &thread, 1, &failed) != 1)
    {
      vlib_buffer_free (vm, &bi, 1);
      clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
      clib_atomic_fetch_sub_relax (&graph->lifecycle_completion_frames, 1);
      return 0;
    }
  return 1;
#else
  (void) vm; (void) completion;
  return 0;
#endif
}

int
product_packet_graph_start_external (vlib_main_t *vm, u64 generation)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;

  if (vm == 0 || generation == 0)
    return 0;
  if (clib_atomic_load_acq_n (&graph->enabled)
      || clib_atomic_load_acq_n (&graph->lifecycle_obligations) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_buffers) != 0
      || product_flow_end_buffer_debt () != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_completion_frames) != 0)
    return 0;

  graph->vlib_main = vm;

  graph->generation = generation;
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  product_fragment_start (vm);
#endif
  graph->trace_packets = 0;
  graph->trace_limit = 256;
  clib_memset (graph->policy_hold_next_us, 0, sizeof (graph->policy_hold_next_us));
  graph->lifecycle_completion_frames = 0;
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  graph->misroute_next = 0;
  product_capacity_configure_empty (graph, PRODUCT_GRAPH_HANDOFF_CREDITS, 64, 128);
  graph->primary_published = graph->primary_received = graph->primary_rejected = 0;
  graph->owner_delivery_checks = graph->owner_delivery_failures = 0;
  graph->completion_returns = graph->completion_deferred = graph->completion_retry_attempts = 0;
  graph->completion_pending_returns = 0;
#endif
  if (!product_packet_graph_flow_pools_reset (graph))
    return 0;
  ASSERT (__atomic_load_n (&graph->l4_policy_bank_readers[0], __ATOMIC_SEQ_CST) == 0);
  ASSERT (__atomic_load_n (&graph->l4_policy_bank_readers[1], __ATOMIC_SEQ_CST) == 0);
  clib_memset (graph->l4_policy_banks, 0, sizeof (graph->l4_policy_banks));
  __atomic_store_n (&graph->l4_policy_active_bank, 0, __ATOMIC_SEQ_CST);
  __atomic_store_n (&graph->policy_publish_sequence, 0, __ATOMIC_SEQ_CST);
  clib_atomic_store_rel_n (&graph->l4_policy_view_active, 0);
  clib_atomic_store_rel_n (&graph->lifecycle_terminal_intents, 0);
  clib_atomic_store_rel_n (&graph->lifecycle_settlements, 0);
  clib_atomic_store_rel_n (&graph->lifecycle_returns, 0);
  if (!product_core_policy_start (generation))
    return 0;
  clib_atomic_store_rel_n (&graph->enabled, 1);
  clib_atomic_store_rel_n (&graph->accepting, 1);
  return 1;
}

void
product_packet_graph_stop_external (vlib_main_t *vm)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_flow_end_quiesce (vm);
  if (PREDICT_FALSE (product_packet_graph_buffer_debt ()))
    clib_panic ("cannot stop graph with live packet/FlowEnd buffers");
  clib_atomic_store_rel_n (&graph->accepting, 0);
  clib_atomic_store_rel_n (&graph->enabled, 0);
  product_packet_graph_policy_writer_lock (graph);
  product_packet_graph_flow_pools_flush (graph);
  product_packet_graph_policy_writer_unlock (graph);
}

uint32_t
product_packet_graph_trace_limit (void)
{
  return product_packet_graph_main.trace_limit ? product_packet_graph_main.trace_limit : 256;
}

uint32_t
product_packet_graph_worker_count (void)
{
  return PRODUCT_GRAPH_WORKERS;
}

uint64_t
product_packet_graph_hash_seed (void)
{
  return PRODUCT_GRAPH_HASH_SEED;
}

uint32_t
product_packet_graph_handoff_credits (void)
{
  return PRODUCT_GRAPH_HANDOFF_CREDITS;
}

uint32_t
product_packet_graph_enabled (void)
{
  return clib_atomic_load_acq_n (&product_packet_graph_main.enabled);
}

uint32_t
product_packet_graph_accepting (void)
{
  return clib_atomic_load_acq_n (&product_packet_graph_main.accepting);
}

uint64_t
product_packet_graph_obligation_debt (void)
{
  return clib_atomic_load_acq_n (&product_packet_graph_main.lifecycle_obligations);
}

uint64_t
product_packet_graph_buffer_debt (void)
{
  return clib_atomic_load_acq_n (&product_packet_graph_main.lifecycle_buffers)
    + product_flow_end_buffer_debt ();
}

uint64_t
product_packet_graph_handoff_debt (void)
{
  return clib_atomic_load_acq_n (&product_packet_graph_main.lifecycle_handoffs);
}

static void
product_packet_graph_policy_writer_lock (product_packet_graph_main_t *graph)
{
  if (vlib_get_thread_index () != 0)
    clib_atomic_fetch_add_relax (&graph->policy_packet_lock_acquisitions, 1);
  u32 expected;

  do
    {
      expected = 0;
    }
  while (!clib_atomic_cmp_and_swap_acq_relax_n (
    &graph->policy_writer_lock, &expected, 1, 0));
}

static void
product_packet_graph_policy_writer_unlock (product_packet_graph_main_t *graph)
{
  clib_atomic_store_rel_n (&graph->policy_writer_lock, 0);
}

static int
product_packet_graph_flow_pools_reset (product_packet_graph_main_t *graph)
{
  u32 worker;

  if (graph == 0)
    return 0;
  if (product_flow_end_buffer_debt ())
    return 0;
  product_flow_end_unbind ();
  clib_atomic_store_rel_n (&graph->flow_pools_initialized, 0);
  clib_memset (graph->policy_workers, 0, sizeof (graph->policy_workers));
  graph->policy_packet_lock_acquisitions = 0;
  graph->policy_publications = 0;
  clib_memset (graph->flow_unavailable, 0, sizeof (graph->flow_unavailable));
  clib_memset (graph->flow_mutation_errors, 0, sizeof (graph->flow_mutation_errors));
  /* Provisional development setting, not a release sizing decision. */
  if (!graph->flow_capacity)
    graph->flow_capacity = 1024;
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      product_flow_runtime_destroy (graph->flow_pools[worker]);
      graph->flow_pools[worker] = 0;
    }
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    if (product_flow_runtime_create (
          &graph->flow_pools[worker], (u16) worker, PRODUCT_GRAPH_WORKERS,
          graph->generation, graph->flow_capacity) != PRODUCT_FLOW_ENTRY_STATUS_OK)
      {
        for (u32 cleanup = 0; cleanup < PRODUCT_GRAPH_WORKERS; cleanup++)
          {
            product_flow_runtime_destroy (graph->flow_pools[cleanup]);
            graph->flow_pools[cleanup] = 0;
          }
        return 0;
      }
  if (!product_flow_end_start (graph->generation, graph->flow_pools,
                               PRODUCT_GRAPH_WORKERS))
    return 0;
  clib_atomic_store_rel_n (&graph->flow_active_policy_revision, 0);
  clib_atomic_store_rel_n (&graph->flow_active_snapshot_hash, 0);
  clib_atomic_store_rel_n (&graph->flow_flush_count, 0);
  clib_atomic_store_rel_n (&graph->flow_pools_initialized, 1);
  return 1;
}

static void
product_packet_graph_flow_pools_flush (product_packet_graph_main_t *graph)
{
  u32 worker;

  if (graph == 0
      || clib_atomic_load_acq_n (&graph->flow_pools_initialized) == 0)
    return;
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      if (PREDICT_FALSE (product_flow_runtime_flush (graph->flow_pools[worker]) !=
                        PRODUCT_FLOW_ENTRY_STATUS_OK))
        clib_panic ("FlowRuntime flush attempted before END graph drain");

    }
  clib_atomic_store_rel_n (&graph->flow_active_policy_revision, 0);
  clib_atomic_store_rel_n (&graph->flow_active_snapshot_hash, 0);
  clib_atomic_fetch_add_relax (&graph->flow_flush_count, 1);
}


void
product_packet_graph_flow_status (product_packet_graph_flow_status_t *status)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 worker;

  if (status == 0)
    return;
  clib_memset (status, 0, sizeof (*status));
  product_packet_graph_policy_writer_lock (graph);
  status->worker_count = PRODUCT_GRAPH_WORKERS;
  status->max_entries_per_worker = graph->flow_capacity;
  status->active_generation =
    clib_atomic_load_acq_n (&graph->flow_pools_initialized) != 0
      ? graph->generation
      : 0;
  status->active_revision =
    clib_atomic_load_acq_n (&graph->flow_active_policy_revision);
  status->active_snapshot_hash =
    clib_atomic_load_acq_n (&graph->flow_active_snapshot_hash);
  /* Callers hold the control/CLI worker barrier. Only this bounded snapshot
   * aggregates pools; packets update their current worker's counters alone. */
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      product_flow_runtime_snapshot_t snapshot = product_flow_runtime_snapshot (graph->flow_pools[worker]);
      const product_flow_runtime_snapshot_t *pool = &snapshot;
      status->active_entries += pool->active_entries;
      status->allocation_count += pool->allocation_count;
      status->reuse_count += pool->reuse_count;
      status->early_drop_count += pool->early_drop_count;
      status->wrong_owner_count += pool->wrong_owner_count;
      status->capacity_rejection_count += pool->capacity_rejection_count;
      status->revision_invalidation_count += pool->revision_invalidation_count;
      status->revision_mismatch_count += pool->revision_mismatch_count + graph->flow_mutation_errors[worker];
      status->unavailable_count += graph->flow_unavailable[worker];
      status->pass_next_count += pool->allocation_count + pool->reuse_count;
      status->drop_count += pool->early_drop_count;
    }
  status->flush_count = clib_atomic_load_acq_n (&graph->flow_flush_count);
  product_packet_graph_policy_writer_unlock (graph);
}

static void
product_packet_graph_l4_direction_from_platform (
  const product_platform_packet_facts_t *platform, u8 *direction, u8 *direction_known)
{
  if (direction == 0 || direction_known == 0)
    return;

  *direction = PRODUCT_L4_POLICY_DIRECTION_ANY;
  *direction_known = 0;
  if (platform == 0)
    return;

  /* Direction and provenance are distinct typed platform facts. */
  if (platform->direction == PRODUCT_L4_POLICY_DIRECTION_INPUT
      || platform->direction == PRODUCT_L4_POLICY_DIRECTION_OUTPUT)
    {
      *direction = (u8) platform->direction;
      *direction_known = 1;
    }
}

static void
product_packet_graph_l4_packet_projection (
  const product_packet_lease_t *lease, product_l4_policy_packet_t *packet)
{
  const product_packet_facts_t *facts = &lease->facts;
  u64 network_context = lease->platform.network_context_id;

  clib_memset (packet, 0, sizeof (*packet));
  packet->uid = lease->platform.uid;
  packet->uid_known = !!(lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN);
  packet->network_context_known = !!(lease->platform.availability & PRODUCT_PLATFORM_CONTEXT_KNOWN);
  packet->network_context_id = (u32) network_context;
  /* Linux ifindex is independent of direction and provenance. */
  packet->ifindex = lease->platform.linux_ifindex;
  packet->ifindex_known = !!(lease->platform.availability & PRODUCT_PLATFORM_IFINDEX_KNOWN);
  packet->family = facts->ip_family;
  packet->protocol = facts->protocol;
  product_packet_graph_l4_direction_from_platform (
    &lease->platform, &packet->direction, &packet->direction_known);
  packet->source_port = facts->source_port;
  packet->destination_port = facts->destination_port;
  /* L4 availability controls only port predicates in the matcher. */
  packet->ports_available = facts->l4_status == PRODUCT_PACKET_L4_COMPLETE
    && (facts->protocol == PRODUCT_L4_POLICY_PROTOCOL_TCP
        || facts->protocol == PRODUCT_L4_POLICY_PROTOCOL_UDP);

  if (facts->ip_family == PRODUCT_L4_POLICY_FAMILY_IPV4)
    {
      /* PacketFacts stores IPv4 at [12..15]; the matcher is [0..3]. */
      clib_memcpy_fast (packet->source_address, facts->source_address + 12, 4);
      clib_memcpy_fast (packet->destination_address,
                        facts->destination_address + 12, 4);
    }
  else if (facts->ip_family == PRODUCT_L4_POLICY_FAMILY_IPV6)
    {
      clib_memcpy_fast (packet->source_address, facts->source_address, 16);
      clib_memcpy_fast (packet->destination_address,
                        facts->destination_address, 16);
    }
}

static const char *
product_packet_graph_flow_failure (product_packet_lease_t *lease, u16 worker,
                                   product_flow_entry_status_t status)
{
  if (status != PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED
      && status != PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER
      && status != PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION)
    product_packet_graph_main.flow_mutation_errors[worker]++;
  if (status == PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED
      && product_packet_bypass_flow_capacity (lease) == PRODUCT_PACKET_OK)
    return "capacity_bypass";
  if (lease->terminal_intent == PRODUCT_PACKET_INTENT_NONE)
    {
      lease->terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
      lease->terminal_count = 1;
      lease->runtime_drop_reason = PRODUCT_PACKET_DROP_FLOW_MUTATION;
    }
  return "runtime_drop";
}

/* Both placements record the complete decision under the packet's identity;
 * unexpected recording failure keeps the existing runtime-failure contract. */
static product_flow_entry_status_t
product_packet_graph_flow_record_decision (
  product_flow_runtime_t *pool, const product_flow_entry_t *entry,
  const product_packet_graph_policy_evaluation_t *evaluation,
  product_packet_lease_t *lease, u16 worker)
{
  product_flow_policy_identity_t identity = {
    evaluation->generation, evaluation->revision, evaluation->snapshot_hash
  };
  product_flow_entry_status_t status = product_flow_entry_set_decision (
    pool, entry, &identity,
    evaluation->verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP
      ? PRODUCT_FLOW_ENTRY_DECISION_DROP : PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT,
    evaluation->rule_id, evaluation->reason_id);
  if (status != PRODUCT_FLOW_ENTRY_STATUS_OK)
    (void) product_packet_graph_flow_failure (lease, worker, status);
  return status;
}

static void
product_packet_graph_flow_observe (
  vlib_main_t *vm, u32 buffer_index, product_packet_lease_t *lease,
  const product_packet_graph_policy_evaluation_t *evaluation, int trace,
  product_flow_entry_observation_t *observed)
{
  if (!vm || !lease || !evaluation || vm->thread_index == 0
      || vm->thread_index > PRODUCT_GRAPH_WORKERS || evaluation->terminal_preserved
      || evaluation->verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_NONE)
    return;
  u16 worker = (u16) vlib_get_worker_index (vm->thread_index);
  /* The only packet-side pool lookup uses the actual executing worker. */
  product_flow_runtime_t *pool = product_packet_graph_main.flow_pools[worker];
  if (!lease->assignment.valid
      || (lease->assignment.key.kind != PRODUCT_OWNER_KEY_L4_PORTS
          && lease->assignment.key.kind != PRODUCT_OWNER_KEY_ICMP_QUERY))
    {
      product_packet_graph_main.flow_unavailable[worker]++;
      return;
    }
  product_flow_entry_packet_t packet = {
    .facts = &lease->facts,
    .policy = { evaluation->generation, evaluation->revision, evaluation->snapshot_hash },
    .uid = (lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN)
      ? lease->platform.uid : PRODUCT_FLOW_ENTRY_UID_UNKNOWN,
    .network_context = (lease->platform.availability & PRODUCT_PLATFORM_CONTEXT_KNOWN)
      ? lease->platform.network_context_id : PRODUCT_FLOW_ENTRY_NETWORK_CONTEXT_UNKNOWN,
    .packet_bytes = lease->facts.packet_length,
    .device_direction = lease->platform.direction,
    .timestamp = (u64) (vlib_time_now (vm) * 1000000.0),
  };
  product_flow_entry_observation_t observation = { 0 };
  u8 stage_verdict = evaluation->verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP
    ? PRODUCT_FLOW_ENTRY_VERDICT_DROP : PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT;
  if (stage_verdict == PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT)
    product_flow_end_before_observe (vm);
  product_flow_entry_status_t status = product_flow_entry_observe (
    pool, &lease->assignment, &packet, stage_verdict, &observation);
  if (status == PRODUCT_FLOW_ENTRY_STATUS_OK || status == PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED)
    product_flow_expiry_observed (vm, &observation, packet.timestamp);
  const product_flow_entry_t *entry = observation.entry;
  if (status == PRODUCT_FLOW_ENTRY_STATUS_OK && entry
      && observation.tracker.facts.state != PRODUCT_CT_INVALID)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      u32 offset = lease->facts.transport_offset + lease->facts.l4_header_length;
      u32 length = lease->facts.transport_length >= lease->facts.l4_header_length
        ? lease->facts.transport_length - lease->facts.l4_header_length : 0;
      if (offset <= buffer->current_length && length <= buffer->current_length - offset)
        status = product_flow_entry_identify (pool, observation.slot,
          packet.policy.generation, entry->incarnation, &lease->facts,
          (const u8 *) vlib_buffer_get_current (buffer) + offset, length);
      product_flow_expiry_changed (vm);
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      if (trace)
        fprintf (stderr, "t13 event=sni token=%llu generation=%llu worker=%u slot=%u incarnation=%llu result=%u stop=%u attempts=%u bytes=%u work=%u cache_bytes=%u name=%s\n",
          (unsigned long long)lease->origin_obligation_id,
          (unsigned long long)packet.policy.generation, worker, observation.slot,
          (unsigned long long)entry->incarnation, entry->sni.result, entry->sni.stop,
          entry->sni.attempts, entry->sni.bytes, entry->sni.work,
          entry->tcp_bytes.length[0]+entry->tcp_bytes.length[1],
          entry->sni.result==PRODUCT_SNI_NAME?entry->sni.name:"-");
      if (trace)
        fprintf (stderr, "t14 event=tcp_cache token=%llu generation=%llu worker=%u slot=%u incarnation=%llu bytes0=%u bytes1=%u contiguous0=%u contiguous1=%u ranges0=%u ranges1=%u span0=%u span1=%u\n",
          (unsigned long long)lease->origin_obligation_id,
          (unsigned long long)packet.policy.generation, worker, observation.slot,
          (unsigned long long)entry->incarnation,
          entry->tcp_bytes.length[0],entry->tcp_bytes.length[1],
          entry->tcp_bytes.contiguous[0],entry->tcp_bytes.contiguous[1],
          entry->tcp_bytes.range_count[0],entry->tcp_bytes.range_count[1],
          entry->tcp_bytes.range_count[0]?entry->tcp_bytes.ranges[0][entry->tcp_bytes.range_count[0]-1].last:0,
          entry->tcp_bytes.range_count[1]?entry->tcp_bytes.ranges[1][entry->tcp_bytes.range_count[1]-1].last:0);
      if (trace)
        fprintf (stderr, "t12 event=lpi token=%llu generation=%llu worker=%u slot=%u incarnation=%llu available=%u protocols=%llu attempts=%u bytes=%u stop=%u outcome=%u status=%u\n",
          (unsigned long long) lease->origin_obligation_id,
          (unsigned long long) packet.policy.generation, worker, observation.slot,
          (unsigned long long) entry->incarnation, entry->lpi.available,
          (unsigned long long) entry->lpi.protocols, entry->lpi.attempts,
          entry->lpi.bytes, entry->lpi.stop_reason, entry->lpi.last_outcome, status);
#endif
    }
  const char *event = "observe";
  if (status == PRODUCT_FLOW_ENTRY_STATUS_OK)
    {
      /* Revision zero is the existing bootstrap default-pass view. It creates
       * flow facts but no cached policy decision before the first snapshot. */
      if (observed) *observed = observation;
      if (!observed && entry && packet.policy.revision != 0)
        {
          status = product_packet_graph_flow_record_decision (
            pool, entry, evaluation, lease, worker);
          if (status != PRODUCT_FLOW_ENTRY_STATUS_OK) event = "runtime_drop";
        }
    }
  else if (status == PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP)
    event = "early_drop";
  else
    event = product_packet_graph_flow_failure (lease, worker, status);
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (trace)
    {
    product_flow_runtime_snapshot_t counters = product_flow_runtime_snapshot (pool);
    fprintf (stderr, "s208 event=%s source=%s generation=%llu token=%llu buffer=%u thread=%u worker=%u owner=%u pool_worker=%u pool=%p slot=%u status=%u created=%u reused=%u invalidated=%u key_kind=%u hash=%llu stored_hash=%llu stored_kind=%u source_is_a=%u origin_is_a=%u flow_origin_dir=%u device_dir=%u flow_dir=%u packets=%llu bytes=%llu first_seen=%llu last_seen=%llu revision=%llu snapshot_hash=%llu policy_generation=%llu decision=%u active=%u allocations=%llu reuse_count=%llu early_drops=%llu\n",
      event, product_packet_evidence_source (lease), (unsigned long long) packet.policy.generation,
      (unsigned long long) lease->origin_obligation_id, buffer_index,
      vm->thread_index, worker, lease->assignment.execution_owner, counters.worker_index,
      (void *) pool, observation.slot, status,
      observation.created, observation.reused, observation.revision_invalidated,
      lease->assignment.key.kind, (unsigned long long) lease->assignment.canonical_hash,
      (unsigned long long) (entry ? entry->canonical_hash : 0), entry ? entry->key.kind : 0,
      lease->assignment.source_is_a, entry ? entry->origin_is_endpoint_a : 0,
      entry ? entry->flow_origin_device_direction : 0, packet.device_direction,
      observation.flow_direction, (unsigned long long) (entry ? entry->packets : 0),
      (unsigned long long) (entry ? entry->bytes : 0),
      (unsigned long long) (entry ? entry->first_seen : 0),
      (unsigned long long) (entry ? entry->last_seen : 0),
      (unsigned long long) (entry ? entry->policy_revision : packet.policy.revision),
      (unsigned long long) (entry ? entry->policy_snapshot_hash : packet.policy.snapshot_hash),
      (unsigned long long) (entry ? entry->policy_generation : packet.policy.generation),
      entry ? entry->decision : 0, counters.active_entries,
      (unsigned long long) counters.allocation_count, (unsigned long long) counters.reuse_count,
      (unsigned long long) counters.early_drop_count);
    if (entry && entry->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_UDP)
      fprintf (stderr, "s223 event=udp_update source=%s generation=%llu token=%llu buffer=%u thread=%u worker=%u owner=%u slot=%u incarnation=%llu created=%u invalidated=%u phase=%u ct_state=%u flow_dir=%u update=%u timeout=%u refresh=%u close=%u replacement=%u orig_packets=%llu reply_packets=%llu\n",
        product_packet_evidence_source (lease),
        (unsigned long long) packet.policy.generation,
        (unsigned long long) lease->origin_obligation_id, buffer_index,
        vm->thread_index, worker, lease->assignment.execution_owner,
        observation.slot, (unsigned long long) entry->incarnation,
        observation.created, observation.revision_invalidated,
        entry->protocol_state.udp.phase, observation.tracker.facts.state,
        observation.tracker.facts.direction, observation.tracker.update,
        observation.tracker.timeout, observation.tracker.refresh_deadline,
        observation.tracker.close_old_instance, observation.tracker.create_replacement,
        (unsigned long long) entry->side_packets[0],
        (unsigned long long) entry->side_packets[1]);
    if (lease->assignment.key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY &&
        observation.tracker.update != PRODUCT_CT_UPDATE_NONE)
      {
        const product_icmp_state_t empty = {0};
        const product_icmp_state_t *icmp = entry ? &entry->protocol_state.icmp : &empty;
        fprintf (stderr, "s224 event=icmp_update source=%s generation=%llu token=%llu buffer=%u thread=%u worker=%u owner=%u slot=%u incarnation=%llu created=%u invalidated=%u family=%u protocol=%u type=%u code=%u identifier=%u sequence=%u phase=%u seen_request=%u seen_reply=%u ct_state=%u flow_dir=%u update=%u timeout=%u refresh=%u close=%u replacement=%u orig_packets=%llu reply_packets=%llu\n",
          product_packet_evidence_source (lease), (unsigned long long) packet.policy.generation,
          (unsigned long long) lease->origin_obligation_id, buffer_index, vm->thread_index,
          worker, lease->assignment.execution_owner, observation.slot,
          (unsigned long long) (entry ? entry->incarnation : 0), observation.created,
          observation.revision_invalidated, lease->facts.ip_family, lease->facts.protocol,
          lease->facts.icmp_type, lease->facts.icmp_code, lease->facts.icmp_identifier,
          lease->facts.icmp_sequence, icmp->phase, icmp->seen_request, icmp->seen_reply,
          observation.tracker.facts.state, observation.tracker.facts.direction,
          observation.tracker.update, observation.tracker.timeout, observation.tracker.refresh_deadline,
          observation.tracker.close_old_instance, observation.tracker.create_replacement,
          (unsigned long long) (entry ? entry->side_packets[0] : 0),
          (unsigned long long) (entry ? entry->side_packets[1] : 0));
      }
    if (lease->facts.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_TCP &&
        observation.tracker.update != PRODUCT_CT_UPDATE_NONE)
      {
        const product_tcp_state_t empty = {0};
        const product_tcp_state_t *tcp = entry ? &entry->protocol_state.tcp : &empty;
        fprintf(stderr, "s222 event=tcp_update source=%s generation=%llu token=%llu buffer=%u thread=%u worker=%u owner=%u slot=%u incarnation=%llu previous_incarnation=%llu created=%u invalidated=%u ct_state=%u flow_dir=%u update=%u timeout=%u refresh=%u close=%u replacement=%u orig_state=%u reply_state=%u orig_seqlo=%u orig_seqhi=%u reply_seqlo=%u reply_seqhi=%u orig_maxwin=%u reply_maxwin=%u orig_scale=%u reply_scale=%u orig_flags=%u reply_flags=%u orig_packets=%llu reply_packets=%llu\n",
          product_packet_evidence_source(lease), (unsigned long long)packet.policy.generation,
          (unsigned long long)lease->origin_obligation_id, buffer_index, vm->thread_index,
          worker, lease->assignment.execution_owner, observation.slot,
          (unsigned long long)(entry ? entry->incarnation : 0),
          (unsigned long long)observation.previous_incarnation, observation.created,
          observation.revision_invalidated, observation.tracker.facts.state,
          observation.tracker.facts.direction, observation.tracker.update, observation.tracker.timeout,
          observation.tracker.refresh_deadline, observation.tracker.close_old_instance,
          observation.tracker.create_replacement, tcp->peer[0].phase, tcp->peer[1].phase,
          tcp->peer[0].seqlo, tcp->peer[0].seqhi, tcp->peer[1].seqlo, tcp->peer[1].seqhi,
          tcp->peer[0].max_window, tcp->peer[1].max_window,
          tcp->peer[0].window_scale, tcp->peer[1].window_scale,
          tcp->peer[0].flags_history, tcp->peer[1].flags_history,
          (unsigned long long)(entry ? entry->side_packets[0] : 0),
          (unsigned long long)(entry ? entry->side_packets[1] : 0));
      }
    }
#else
  (void) buffer_index; (void) trace; (void) event;
#endif
}

enum
{
  PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_NONE = 0,
  PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_PROBE,
  PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_SUBJECT,
  PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_UNRELATED,
};

#define PRODUCT_PACKET_GRAPH_L4_EVIDENCE_FNV_OFFSET \
  UINT64_C (14695981039346656037)
#define PRODUCT_PACKET_GRAPH_L4_EVIDENCE_FNV_PRIME UINT64_C (1099511628211)

static u64
product_packet_graph_l4_evidence_hash_byte (u64 hash, u8 value)
{
  return (hash ^ value) * PRODUCT_PACKET_GRAPH_L4_EVIDENCE_FNV_PRIME;
}

static u64
product_packet_graph_l4_evidence_hash_u16 (u64 hash, u16 value)
{
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 8);
  return product_packet_graph_l4_evidence_hash_byte (hash, (u8) value);
}

static u64
product_packet_graph_l4_evidence_hash_u32 (u64 hash, u32 value)
{
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 24);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 16);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 8);
  return product_packet_graph_l4_evidence_hash_byte (hash, (u8) value);
}

static u64
product_packet_graph_l4_evidence_hash_u64 (u64 hash, u64 value)
{
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 56);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 48);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 40);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 32);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 24);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 16);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, value >> 8);
  return product_packet_graph_l4_evidence_hash_byte (hash, (u8) value);
}

static u64
product_packet_graph_l4_evidence_hash_bytes (u64 hash, const u8 *value,
                                             u32 length)
{
  u32 index;

  for (index = 0; index < length; index++)
    hash = product_packet_graph_l4_evidence_hash_byte (hash, value[index]);
  return hash;
}

static u64
product_packet_graph_l4_match_policy_key (u64 generation, u64 revision,
                                          u64 snapshot_hash)
{
  u64 hash = PRODUCT_PACKET_GRAPH_L4_EVIDENCE_FNV_OFFSET;

  hash = product_packet_graph_l4_evidence_hash_u64 (hash, generation);
  hash = product_packet_graph_l4_evidence_hash_u64 (hash, revision);
  hash = product_packet_graph_l4_evidence_hash_u64 (hash, snapshot_hash);
  /* Zero is the invalid/empty commit marker. */
  return hash == 0 ? 1 : hash;
}

static u64
product_packet_graph_l4_match_evidence_key (
  const product_packet_lease_t *lease, u64 generation, u64 revision,
  u64 snapshot_hash, int include_destination_port)
{
  product_l4_policy_packet_t packet;
  u64 hash = PRODUCT_PACKET_GRAPH_L4_EVIDENCE_FNV_OFFSET;

  product_packet_graph_l4_packet_projection (lease, &packet);
  hash = product_packet_graph_l4_evidence_hash_u64 (
    hash, product_packet_graph_l4_match_policy_key (generation, revision,
                                                     snapshot_hash));
  hash = product_packet_graph_l4_evidence_hash_byte (hash, packet.family);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, packet.protocol);
  hash = product_packet_graph_l4_evidence_hash_bytes (
    hash, packet.source_address, sizeof (packet.source_address));
  hash = product_packet_graph_l4_evidence_hash_bytes (
    hash, packet.destination_address, sizeof (packet.destination_address));
  if (include_destination_port)
    hash = product_packet_graph_l4_evidence_hash_u16 (
      hash, packet.destination_port);
  hash = product_packet_graph_l4_evidence_hash_u32 (hash, packet.uid);
  hash = product_packet_graph_l4_evidence_hash_u32 (
    hash, packet.network_context_id);
  hash = product_packet_graph_l4_evidence_hash_u32 (hash, packet.ifindex);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, packet.direction);
  hash = product_packet_graph_l4_evidence_hash_byte (hash,
                                                     packet.uid_known);
  hash = product_packet_graph_l4_evidence_hash_byte (
    hash, packet.network_context_known);
  hash = product_packet_graph_l4_evidence_hash_byte (hash, packet.ifindex_known);
  hash = product_packet_graph_l4_evidence_hash_byte (hash,
                                                     packet.direction_known);
  return hash == 0 ? 1 : hash;
}

static void
product_packet_graph_l4_match_association_remember (
  product_packet_graph_main_t *graph, const product_packet_lease_t *lease,
  u64 generation, u64 revision, u64 snapshot_hash)
{
  u64 policy_key;
  u64 probe_key;
  u64 subject_key;

  policy_key = product_packet_graph_l4_match_policy_key (generation, revision,
                                                          snapshot_hash);
  probe_key = product_packet_graph_l4_match_evidence_key (
    lease, generation, revision, snapshot_hash, 1);
  subject_key = product_packet_graph_l4_match_evidence_key (
    lease, generation, revision, snapshot_hash, 0);
  clib_atomic_store_rel_n (&graph->l4_typed_match_probe_key, probe_key);
  clib_atomic_store_rel_n (&graph->l4_typed_match_subject_key, subject_key);
  /* Publish the complete keys last so readers never trust an old policy key
   * with partially updated evidence. */
  clib_atomic_store_rel_n (&graph->l4_typed_match_policy_key, policy_key);
}

static int
product_packet_graph_l4_match_association (
  const product_packet_graph_main_t *graph,
  const product_packet_lease_t *lease, u64 generation, u64 revision,
  u64 snapshot_hash)
{
  u64 policy_key;
  u64 probe_key;
  u64 subject_key;

  policy_key = product_packet_graph_l4_match_policy_key (generation, revision,
                                                          snapshot_hash);
  if (clib_atomic_load_acq_n (&graph->l4_typed_match_policy_key)
      != policy_key)
    return PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_NONE;
  probe_key = product_packet_graph_l4_match_evidence_key (
    lease, generation, revision, snapshot_hash, 1);
  subject_key = product_packet_graph_l4_match_evidence_key (
    lease, generation, revision, snapshot_hash, 0);
  if (probe_key == clib_atomic_load_acq_n (&graph->l4_typed_match_probe_key))
    return PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_PROBE;
  if (subject_key
      == clib_atomic_load_acq_n (&graph->l4_typed_match_subject_key))
    return PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_SUBJECT;
  return PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_UNRELATED;
}

static product_l4_policy_status_t
product_packet_graph_l4_view_evaluate (
  product_packet_graph_main_t *graph, const product_packet_lease_t *lease,
  const product_policy_snapshot_t *snapshot, product_l4_policy_match_result_t *match)
{
  product_l4_policy_packet_t packet;
  product_l4_policy_view_t empty_view;
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  u64 query_started = snapshot->trace ? product_packet_event_clock_ns () : 0;
  u64 previous_hits = snapshot->cache ? snapshot->cache->hits : 0;
#endif
  product_packet_graph_l4_packet_projection (lease, &packet);
  packet.protocol_set = snapshot->protocols;
  packet.protocol_set_known = snapshot->protocols_available;
  packet.sni_result = snapshot->sni_result;
  packet.ct_state = snapshot->ct.state;
  packet.ct_state_known = snapshot->ct.state != PRODUCT_CT_UNKNOWN;
  packet.flow_direction = snapshot->ct.direction;
  packet.flow_direction_known = snapshot->ct.direction != PRODUCT_FLOW_DIRECTION_UNKNOWN;
  if (snapshot->bank->generation != graph->generation)
    {
      product_l4_policy_init (&empty_view);
      return product_l4_policy_evaluate (&empty_view, &packet, match);
    }
  product_policy_cache_identity_t identity = {
    snapshot->identity.generation, snapshot->identity.revision,
    snapshot->identity.snapshot_hash, snapshot->flow_incarnation
  };
  product_l4_policy_status_t status = product_l4_policy_match_cached (
    snapshot->cache, &snapshot->bank->view, &packet, &identity, snapshot->position, match);
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (snapshot->trace)
    fprintf (stderr, "t11 event=cache token=%llu generation=%llu revision=%llu snapshot_hash=%llu incarnation=%llu position=%u hit=%u status=%u evaluation=%u rule=%llu rank=%u mode=%u declared=%u actual=%u reason=%u priority=%u order=%u hits=%llu misses=%llu\n",
      (unsigned long long) lease->origin_obligation_id,
      (unsigned long long) identity.generation, (unsigned long long) identity.revision,
      (unsigned long long) identity.snapshot_hash, (unsigned long long) identity.flow_incarnation,
      snapshot->position, snapshot->cache && snapshot->cache->hits != previous_hits,
      status, match->evaluation, (unsigned long long) match->rule_id,
      match->winner_rank, match->mode, match->action, match->actual_action,
      match->reason_id, match->priority, match->order,
      (unsigned long long) (snapshot->cache ? snapshot->cache->hits : 0),
      (unsigned long long) (snapshot->cache ? snapshot->cache->misses : 0));
  if (snapshot->trace)
    fprintf (stderr, "t09 event=query token=%llu generation=%llu revision=%llu snapshot_hash=%llu position=%u status=%u rule=%llu rank=%u masks=%u keys=%u residuals=%u subject_probes=%u query_ns=%llu\n",
      (unsigned long long) lease->origin_obligation_id,
      (unsigned long long) snapshot->identity.generation,
      (unsigned long long) snapshot->identity.revision,
      (unsigned long long) snapshot->bank->snapshot_hash, snapshot->position, status,
      (unsigned long long) match->rule_id, match->winner_rank,
      match->subtable_probes, match->key_probes, match->probes, match->subject_probes,
      (unsigned long long) (product_packet_event_clock_ns () - query_started));
#endif
  return status;
}

static void
product_packet_graph_record_l4_view_match (
  product_packet_graph_main_t *graph, const product_packet_lease_t *lease,
  u64 generation, u64 revision, u64 snapshot_hash,
  const product_l4_policy_match_result_t *match)
{
  u32 verdict;

  if (graph == 0 || lease == 0 || match == 0)
    return;
  verdict = match->actual_action == PRODUCT_L4_POLICY_ACTION_DROP
              ? PRODUCT_POLICY_VERDICT_DROP
              : PRODUCT_POLICY_VERDICT_ALLOW;
  clib_atomic_fetch_add_relax (&graph->l4_policy_view_match_records, 1);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_revision, revision);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_rule_id,
                           match->rule_id);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_winner_rank,
                           match->winner_rank);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_probes, match->probes);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_candidate_count,
                           match->candidate_count);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_no_match_reason,
                           PRODUCT_L4_POLICY_NO_MATCH_NONE);

  clib_atomic_fetch_add_relax (&graph->l4_match_records, 1);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_revision, revision);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_result,
                           PRODUCT_PACKET_GRAPH_L4_EVALUATION_MATCH);
  clib_atomic_store_rel_n (
    &graph->l4_last_evaluation_probe_key,
    product_packet_graph_l4_match_evidence_key (lease, generation, revision,
                                                 snapshot_hash, 1));
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_verdict, verdict);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_device_direction,
                           lease->platform.direction);
  clib_atomic_store_rel_n (&graph->l4_last_match_revision, revision);
  clib_atomic_store_rel_n (&graph->l4_last_match_rule_id, match->rule_id);
  clib_atomic_store_rel_n (&graph->l4_last_match_uid, lease->platform.uid);
  clib_atomic_store_rel_n (&graph->l4_last_match_network_context,
                           (u32) lease->platform.network_context_id);
  clib_atomic_store_rel_n (&graph->l4_last_match_reason_id, match->reason_id);
  clib_atomic_store_rel_n (&graph->l4_last_match_verdict, verdict);
  /* The public last-match winner identifies the winning stage, while the
   * matcher rank remains in l4_policy_view_last_winner_rank. */
  clib_atomic_store_rel_n (&graph->l4_last_match_winner,
                           PRODUCT_PACKET_GRAPH_L4_WINNER_RULE);
  clib_atomic_store_rel_n (&graph->l4_last_match_uid_known,
                           !!(lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN));
  clib_atomic_store_rel_n (&graph->l4_last_match_device_direction,
                           lease->platform.direction);
  clib_atomic_store_rel_n (&graph->l4_last_match_action, match->action);
  if (match->actual_action == PRODUCT_L4_POLICY_ACTION_DROP)
    {
      clib_atomic_fetch_add_relax (&graph->policy_drop_records, 1);
      clib_atomic_store_rel_n (&graph->policy_last_drop_revision, revision);
      clib_atomic_store_rel_n (&graph->policy_last_drop_rule_id,
                               match->rule_id);
      clib_atomic_store_rel_n (&graph->policy_last_drop_completion_attempts,
                               lease->terminal_count);
      clib_atomic_store_rel_n (&graph->policy_last_drop_uid, lease->platform.uid);
      clib_atomic_store_rel_n (&graph->policy_last_drop_network_context,
                               (u32) lease->platform.network_context_id);
      clib_atomic_store_rel_n (&graph->policy_last_drop_reason_id,
                               match->reason_id);
      clib_atomic_store_rel_n (&graph->policy_last_drop_verdict,
                               PRODUCT_POLICY_VERDICT_DROP);
      clib_atomic_store_rel_n (&graph->policy_last_drop_winner,
                               PRODUCT_PACKET_GRAPH_L4_WINNER_RULE);
      clib_atomic_store_rel_n (&graph->policy_last_drop_uid_known,
                               !!(lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN));
      clib_atomic_store_rel_n (&graph->policy_last_drop_device_direction,
                               lease->platform.direction);
    }
  product_packet_graph_l4_match_association_remember (
    graph, lease, generation, revision, snapshot_hash);
}

static void
product_packet_graph_record_l4_view_no_match (
  product_packet_graph_main_t *graph, u64 generation, u64 revision,
  u64 snapshot_hash, u32 view_rule_count,
  const product_l4_policy_match_result_t *match,
  const product_packet_lease_t *lease)
{
  int unrelated_no_match;
  int drop_association;
  u64 evaluation_probe_key;

  if (graph == 0 || match == 0 || lease == 0)
    return;
  /* Publish the observation identity before any evidence-preserving early
   * return.  The effective match fields may remain sticky, but consumers
   * must be able to prove that the latest observed probe was different. */
  evaluation_probe_key = product_packet_graph_l4_match_evidence_key (
    lease, generation, revision, snapshot_hash, 1);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_probe_key,
                           evaluation_probe_key);
  clib_atomic_fetch_add_relax (&graph->l4_policy_view_no_match_records, 1);
  clib_atomic_fetch_add_relax (&graph->l4_no_match_records, 1);
  unrelated_no_match = view_rule_count != 0
                       && (!(lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN)
                           || match->candidate_count == 0);
  if (unrelated_no_match)
    {
      /* Unknown/provenance-only returns must not erase known-subject evidence.
       * A non-empty view with no candidates is likewise not evidence for the
       * active subject.  Keep the counters above for complete observability.
       */
      return;
    }

  drop_association = product_packet_graph_l4_match_association (
    graph, lease, generation, revision, snapshot_hash);
  if (drop_association == PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_PROBE)
    {
      /* A retransmit/no-rule observation for the same completed probe cannot
       * undo the typed match that was already recorded for that flow. */
      return;
    }
  if (drop_association == PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_UNRELATED)
    {
      /* Background traffic may carry a known UID, but it is not evidence for
       * the latest typed probe.  Keep aggregate no-match counters while the
       * sticky match remains the effective S192 result. */
      return;
    }

  /* No-match is a new evaluation, not a replacement for last-match identity.
   * Keep the winner/rule fields from the most recent successful match while
   * exposing the current no-match probe and reason evidence below. */
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_revision, revision);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_probes, match->probes);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_candidate_count,
                           match->candidate_count);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_no_match_reason,
                           match->no_match_reason);

  clib_atomic_store_rel_n (&graph->l4_last_evaluation_revision, revision);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_result,
                           PRODUCT_PACKET_GRAPH_L4_EVALUATION_NO_MATCH);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_verdict,
                           PRODUCT_POLICY_VERDICT_PASS_NEXT);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_device_direction,
                           lease->platform.direction);
}

void
product_packet_graph_publish_gate_policy (
  const product_packet_graph_gate_policy_t *policy)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_gate_entry_t entry;
  product_packet_graph_policy_bundle_t bundle;

  if (policy == 0 || policy->revision == 0 || policy->snapshot_hash == 0
      || policy->subject_uid == UINT32_MAX || policy->network_context_id == 0
      || !policy->blocked || policy->rule_id == 0 || policy->reason_id == 0)
    return;

  clib_memset (&entry, 0, sizeof (entry));
  entry.rule_id = policy->rule_id;
  entry.uid = policy->subject_uid;
  entry.network_context_id = policy->network_context_id;
  entry.ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY;
  entry.source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  entry.source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  entry.destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  entry.destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  entry.direction = PRODUCT_L4_POLICY_DIRECTION_ANY;
  entry.action = PRODUCT_L4_POLICY_ACTION_DROP;
  entry.reason_id = policy->reason_id;
  bundle.generation = graph->generation;
  bundle.revision = policy->revision;
  bundle.snapshot_hash = policy->snapshot_hash;
  bundle.gate_entries = &entry;
  bundle.gate_entry_count = 1;
  bundle.l4_rules = 0;
  bundle.l4_rule_count = 0;
  (void) product_packet_graph_publish_policy_bundle (&bundle);
  product_packet_graph_deactivate_policy_view (graph);
}

void
product_packet_graph_clear_gate_policy (uint64_t revision,
                                        uint64_t snapshot_hash)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_policy_bundle_t bundle = {
    .generation = graph->generation,
    .revision = revision,
    .snapshot_hash = snapshot_hash,
    .gate_entries = 0,
    .gate_entry_count = 0,
    .l4_rules = 0,
    .l4_rule_count = 0,
  };

  (void) product_packet_graph_publish_policy_bundle (&bundle);
  product_packet_graph_deactivate_policy_view (graph);
}

void
product_packet_graph_gate_status (product_packet_graph_gate_status_t *status)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_policy_snapshot_t snapshot;
  const product_packet_graph_l4_policy_bank_t *bank;

  if (status == 0)
    return;
  clib_memset (status, 0, sizeof (*status));
  product_policy_snapshot_acquire (graph, &snapshot);
  bank = snapshot.bank;
  status->active_generation = bank->generation;
  status->active_revision = bank->revision;
  status->snapshot_hash = bank->snapshot_hash;
  status->active_entry_count = 0;
  status->max_probes = 0;
  status->rule_id = 0;
  status->subject_uid = UINT32_MAX;
  status->network_context_id = 0;
  status->blocked = 0;
  status->reason_id = 0;
  product_policy_snapshot_release (graph, &snapshot);

  status->last_match_revision = clib_atomic_load_acq_n (
    &graph->gate_table_last_match_revision);
  status->last_match_rule_id = clib_atomic_load_acq_n (
    &graph->gate_table_last_match_rule_id);
  status->last_match_winner_rank = clib_atomic_load_acq_n (
    &graph->gate_table_last_winner_rank);
  status->last_match_probes =
    clib_atomic_load_acq_n (&graph->gate_table_last_probes);
  status->last_match_candidate_count = clib_atomic_load_acq_n (
    &graph->gate_table_last_candidate_count);
  status->last_no_match_reason = clib_atomic_load_acq_n (
    &graph->gate_table_last_no_match_reason);
  status->last_match_action = clib_atomic_load_acq_n (
    &graph->gate_table_last_match_action);
  status->last_match_reason_id = clib_atomic_load_acq_n (
    &graph->gate_table_last_match_reason_id);
  if (status->last_match_revision != 0
      && status->last_match_revision != status->active_revision)
    {
      /* A probe that raced a publication is not evidence for the new bank. */
      status->last_match_revision = 0;
      status->last_match_rule_id = 0;
      status->last_match_winner_rank = 0;
      status->last_match_probes = 0;
      status->last_match_candidate_count = 0;
      status->last_no_match_reason =
        PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE;
      status->last_match_action = 0;
      status->last_match_reason_id = 0;
    }
  status->drop_records = clib_atomic_load_acq_n (&graph->policy_drop_records);
  status->last_drop_revision =
    clib_atomic_load_acq_n (&graph->policy_last_drop_revision);
  status->last_drop_rule_id =
    clib_atomic_load_acq_n (&graph->policy_last_drop_rule_id);
  status->last_drop_completion_attempts =
    clib_atomic_load_acq_n (&graph->policy_last_drop_completion_attempts);
  status->last_drop_uid =
    clib_atomic_load_acq_n (&graph->policy_last_drop_uid);
  status->last_drop_network_context =
    clib_atomic_load_acq_n (&graph->policy_last_drop_network_context);
  status->last_drop_reason_id =
    clib_atomic_load_acq_n (&graph->policy_last_drop_reason_id);
  status->last_drop_verdict =
    clib_atomic_load_acq_n (&graph->policy_last_drop_verdict);
  status->last_drop_winner =
    clib_atomic_load_acq_n (&graph->policy_last_drop_winner);
  status->last_drop_uid_known =
    clib_atomic_load_acq_n (&graph->policy_last_drop_uid_known);
  status->last_drop_device_direction =
    clib_atomic_load_acq_n (&graph->policy_last_drop_device_direction);
}

void
product_packet_graph_publish_l4_policy (
  const product_packet_graph_l4_policy_t *policy)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_l4_policy_rule_t rule;
  product_packet_graph_policy_bundle_t bundle;

  if (policy == 0 || policy->revision == 0 || policy->snapshot_hash == 0
      || policy->rule_id == 0 || policy->subject_uid == UINT32_MAX
      || policy->network_context_id == 0 || policy->reason_id == 0
      || policy->source_prefix_length > 32
      || policy->destination_prefix_length > 32
      || policy->source_port_first > policy->source_port_last
      || policy->destination_port_first > policy->destination_port_last
      || (policy->direction != PRODUCT_PACKET_GRAPH_L4_DIRECTION_INPUT
          && policy->direction != PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT)
      || policy->protocol != PRODUCT_PACKET_GRAPH_L4_PROTOCOL_TCP
      || (policy->action != PRODUCT_PACKET_GRAPH_L4_ACTION_ALLOW
          && policy->action != PRODUCT_PACKET_GRAPH_L4_ACTION_DROP))
    return;

  clib_memset (&rule, 0, sizeof (rule));
  rule.rule_id = policy->rule_id;
  rule.uid = policy->subject_uid;
  rule.network_context_id = policy->network_context_id;
  rule.ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY;
  rule.priority = policy->priority;
  rule.order = policy->order;
  rule.reason_id = policy->reason_id;
  rule.source_port_first = policy->source_port_first;
  rule.source_port_last = policy->source_port_last;
  rule.destination_port_first = policy->destination_port_first;
  rule.destination_port_last = policy->destination_port_last;
  rule.family = PRODUCT_L4_POLICY_FAMILY_IPV4;
  rule.protocol = policy->protocol;
  rule.direction = policy->direction;
  rule.source_prefix_length = policy->source_prefix_length;
  rule.destination_prefix_length = policy->destination_prefix_length;
  rule.action = policy->action == PRODUCT_PACKET_GRAPH_L4_ACTION_DROP
                  ? PRODUCT_L4_POLICY_ACTION_DROP
                  : PRODUCT_L4_POLICY_ACTION_ALLOW;
  rule.source_address[0] = policy->source_address >> 24;
  rule.source_address[1] = policy->source_address >> 16;
  rule.source_address[2] = policy->source_address >> 8;
  rule.source_address[3] = policy->source_address;
  rule.destination_address[0] = policy->destination_address >> 24;
  rule.destination_address[1] = policy->destination_address >> 16;
  rule.destination_address[2] = policy->destination_address >> 8;
  rule.destination_address[3] = policy->destination_address;
  bundle.generation = graph->generation;
  bundle.revision = policy->revision;
  bundle.snapshot_hash = policy->snapshot_hash;
  bundle.gate_entries = 0;
  bundle.gate_entry_count = 0;
  bundle.l4_rules = &rule;
  bundle.l4_rule_count = 1;
  (void) product_packet_graph_publish_policy_bundle (&bundle);
  product_packet_graph_deactivate_policy_view (graph);
}

void
product_packet_graph_clear_l4_policy (uint64_t revision,
                                      uint64_t snapshot_hash)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_policy_bundle_t bundle = {
    .generation = graph->generation,
    .revision = revision,
    .snapshot_hash = snapshot_hash,
    .gate_entries = 0,
    .gate_entry_count = 0,
    .l4_rules = 0,
    .l4_rule_count = 0,
  };

  (void) product_packet_graph_publish_policy_bundle (&bundle);
  product_packet_graph_deactivate_policy_view (graph);
}

product_packet_result_t
product_packet_graph_publish_policy_bundle (
  const product_packet_graph_policy_bundle_t *bundle)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_l4_policy_bank_t *bank;
  product_l4_policy_view_t compiled_view;
  product_l4_policy_status_t compile_status;
  u32 sequence;
  u32 active_bank;
  u32 inactive_bank;
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  u64 reuse_begin_ns, publish_begin_ns;
#endif

  if (bundle == 0 || bundle->generation == 0
      || bundle->generation > UINT16_MAX || bundle->revision == 0
      || bundle->snapshot_hash == 0
      || (bundle->gate_entry_count != 0 && bundle->gate_entries == 0)
      || bundle->gate_entry_count > PRODUCT_PACKET_GRAPH_GATE_TABLE_MAX_ENTRIES
      || (bundle->l4_rule_count != 0 && bundle->l4_rules == 0)
      || bundle->l4_rule_count > PRODUCT_L4_POLICY_MAX_RULES)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  if (bundle->generation != graph->generation)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  if (clib_atomic_load_acq_n (&graph->flow_pools_initialized) == 0)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  /* Retired Gate input cannot create a second runtime policy family. */
  if (bundle->gate_entry_count != 0)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  for (u32 index = 0; index < bundle->l4_rule_count; ++index)
    if (bundle->l4_rules[index].network_context_id == 0)
      return PRODUCT_PACKET_INVALID_ARGUMENT;
  product_l4_policy_init (&compiled_view);
  compile_status = product_l4_policy_compile (
    &compiled_view, bundle->l4_rules, bundle->l4_rule_count);
  if (compile_status != PRODUCT_L4_POLICY_STATUS_OK)
    return PRODUCT_PACKET_INVALID_ARGUMENT;

  product_packet_graph_policy_writer_lock (graph);
  sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
  if ((sequence & 1U) != 0)
    sequence++;
  active_bank = __atomic_load_n (&graph->l4_policy_active_bank, __ATOMIC_SEQ_CST);
  if (bundle->revision < graph->l4_policy_banks[active_bank].revision)
    {
      product_packet_graph_policy_writer_unlock (graph);
      return PRODUCT_PACKET_INVALID_ARGUMENT;
    }
  inactive_bank = active_bank ^ 1U;
  /* Active-bank readers continue while the writer waits for the retired bank.
   * SC ordering closes the delayed-reader claim versus reuse race on ARM. */
  while (__atomic_load_n (&graph->l4_policy_bank_readers[inactive_bank],
                          __ATOMIC_SEQ_CST) != 0)
    ;
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  reuse_begin_ns = product_packet_event_clock_ns ();
#endif
  bank = &graph->l4_policy_banks[inactive_bank];
  bank->view = compiled_view;
  bank->generation = bundle->generation;
  bank->revision = bundle->revision;
  bank->snapshot_hash = bundle->snapshot_hash;

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  publish_begin_ns = product_packet_event_clock_ns ();
#endif
  __atomic_store_n (&graph->policy_publish_sequence, sequence + 1U,
                     __ATOMIC_SEQ_CST);
  /* Publish the one ordinary rule view under the protected bank sequence. */
  clib_atomic_store_rel_n (&graph->gate_policy_revision, bundle->revision);
  clib_atomic_store_rel_n (&graph->gate_policy_snapshot_hash,
                           bundle->snapshot_hash);
  clib_atomic_store_rel_n (&graph->gate_policy_rule_id, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_subject_uid, UINT32_MAX);
  clib_atomic_store_rel_n (&graph->gate_policy_network_context_id, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_blocked, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_reason_id, 0);

  clib_atomic_store_rel_n (&graph->l4_policy_revision, bundle->revision);
  clib_atomic_store_rel_n (&graph->l4_policy_snapshot_hash,
                           bundle->snapshot_hash);
  clib_atomic_store_rel_n (&graph->l4_policy_rule_id, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_subject_uid, UINT32_MAX);
  clib_atomic_store_rel_n (&graph->l4_policy_network_context_id, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_reason_id, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_priority, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_order, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_source_address, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_destination_address, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_source_port_first, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_source_port_last, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_destination_port_first, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_destination_port_last, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_source_prefix_length, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_destination_prefix_length, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_direction, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_protocol, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_action, 0);
  if (bundle->l4_rule_count == 1)
    {
      /* A one-rule typed bundle has a stable scalar identity for the S191
       * evidence view; multi-rule bundles deliberately remain identity-free. */
      const product_l4_policy_rule_t *rule = &bundle->l4_rules[0];
      clib_atomic_store_rel_n (&graph->l4_policy_rule_id, rule->rule_id);
      clib_atomic_store_rel_n (&graph->l4_policy_subject_uid, rule->uid);
      clib_atomic_store_rel_n (&graph->l4_policy_network_context_id,
                               rule->network_context_id);
      clib_atomic_store_rel_n (&graph->l4_policy_reason_id, rule->reason_id);
      clib_atomic_store_rel_n (&graph->l4_policy_priority, rule->priority);
      clib_atomic_store_rel_n (&graph->l4_policy_order, rule->order);
      clib_atomic_store_rel_n (&graph->l4_policy_source_port_first,
                               rule->source_port_first);
      clib_atomic_store_rel_n (&graph->l4_policy_source_port_last,
                               rule->source_port_last);
      clib_atomic_store_rel_n (&graph->l4_policy_destination_port_first,
                               rule->destination_port_first);
      clib_atomic_store_rel_n (&graph->l4_policy_destination_port_last,
                               rule->destination_port_last);
      clib_atomic_store_rel_n (&graph->l4_policy_source_prefix_length,
                               rule->source_prefix_length);
      clib_atomic_store_rel_n (&graph->l4_policy_destination_prefix_length,
                               rule->destination_prefix_length);
      clib_atomic_store_rel_n (&graph->l4_policy_direction, rule->direction);
      clib_atomic_store_rel_n (&graph->l4_policy_protocol, rule->protocol);
      clib_atomic_store_rel_n (&graph->l4_policy_action, rule->action);
    }
  /* Last-match identity belongs to the just-published snapshot.  Clear it
   * before the bank index is released so it cannot be mistaken for evidence
   * from a prior revision. */
  clib_atomic_store_rel_n (&graph->gate_table_last_match_revision, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_rule_id, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_winner_rank, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_probes, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_candidate_count, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_no_match_reason,
                           PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_action, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_reason_id, 0);
  __atomic_store_n (&graph->l4_policy_active_bank, inactive_bank, __ATOMIC_SEQ_CST);
  clib_atomic_store_rel_n (&graph->l4_policy_view_active, 1);
  clib_atomic_store_rel_n (&graph->flow_active_policy_revision, bundle->revision);
  clib_atomic_store_rel_n (&graph->flow_active_snapshot_hash, bundle->snapshot_hash);
  __atomic_store_n (&graph->policy_publish_sequence, sequence + 2U, __ATOMIC_SEQ_CST);
  graph->policy_publications++;
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (graph->policy_publications <= 256)
    fprintf (stderr, "s209 event=publish thread=%u generation=%llu revision=%llu snapshot_hash=%llu bank=%u sequence=%u reuse_begin_ns=%llu publish_begin_ns=%llu mono_ns=%llu\n",
      vlib_get_thread_index (), (unsigned long long) bundle->generation,
      (unsigned long long) bundle->revision, (unsigned long long) bundle->snapshot_hash,
      inactive_bank, sequence + 2U, (unsigned long long) reuse_begin_ns,
      (unsigned long long) publish_begin_ns, (unsigned long long) product_packet_event_clock_ns ());
#endif
  product_packet_graph_policy_writer_unlock (graph);
  return PRODUCT_PACKET_OK;
}

product_packet_result_t
product_packet_graph_apply_policy_bundle (
  const product_packet_graph_policy_bundle_t *bundle)
{
  return product_packet_graph_publish_policy_bundle (bundle);
}

static void
product_packet_graph_deactivate_policy_view (product_packet_graph_main_t *graph)
{
  u32 sequence;

  if (graph == 0)
    return;
  product_packet_graph_policy_writer_lock (graph);
  sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
  if ((sequence & 1U) != 0)
    sequence++;
  __atomic_store_n (&graph->policy_publish_sequence, sequence + 1U, __ATOMIC_SEQ_CST);
  clib_atomic_store_rel_n (&graph->l4_policy_view_active, 0);
  /* Clearing/switching a policy view preserves flow identity and counters.
   * The published epoch invalidates only each entry's next-packet cache. */
  __atomic_store_n (&graph->policy_publish_sequence, sequence + 2U, __ATOMIC_SEQ_CST);
  product_packet_graph_policy_writer_unlock (graph);
}

void
product_packet_graph_l4_status (product_packet_graph_l4_status_t *status)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_policy_snapshot_t snapshot;

  if (status == 0)
    return;
  clib_memset (status, 0, sizeof (*status));
  status->active_revision =
    clib_atomic_load_acq_n (&graph->l4_policy_revision);
  status->snapshot_hash =
    clib_atomic_load_acq_n (&graph->l4_policy_snapshot_hash);
  status->rule_id = clib_atomic_load_acq_n (&graph->l4_policy_rule_id);
  status->match_records = clib_atomic_load_acq_n (&graph->l4_match_records);
  status->no_match_records =
    clib_atomic_load_acq_n (&graph->l4_no_match_records);
  status->last_match_revision =
    clib_atomic_load_acq_n (&graph->l4_last_match_revision);
  status->last_match_rule_id =
    clib_atomic_load_acq_n (&graph->l4_last_match_rule_id);
  status->last_evaluation_revision =
    clib_atomic_load_acq_n (&graph->l4_last_evaluation_revision);
  status->subject_uid =
    clib_atomic_load_acq_n (&graph->l4_policy_subject_uid);
  status->network_context_id =
    clib_atomic_load_acq_n (&graph->l4_policy_network_context_id);
  status->reason_id = clib_atomic_load_acq_n (&graph->l4_policy_reason_id);
  status->priority = clib_atomic_load_acq_n (&graph->l4_policy_priority);
  status->order = clib_atomic_load_acq_n (&graph->l4_policy_order);
  status->direction = clib_atomic_load_acq_n (&graph->l4_policy_direction);
  status->protocol = clib_atomic_load_acq_n (&graph->l4_policy_protocol);
  status->action = clib_atomic_load_acq_n (&graph->l4_policy_action);
  status->last_match_uid =
    clib_atomic_load_acq_n (&graph->l4_last_match_uid);
  status->last_match_network_context =
    clib_atomic_load_acq_n (&graph->l4_last_match_network_context);
  status->last_match_reason_id =
    clib_atomic_load_acq_n (&graph->l4_last_match_reason_id);
  status->last_match_verdict =
    clib_atomic_load_acq_n (&graph->l4_last_match_verdict);
  status->last_match_winner =
    clib_atomic_load_acq_n (&graph->l4_last_match_winner);
  status->last_match_uid_known =
    clib_atomic_load_acq_n (&graph->l4_last_match_uid_known);
  status->last_match_device_direction =
    clib_atomic_load_acq_n (&graph->l4_last_match_device_direction);
  status->last_match_action =
    clib_atomic_load_acq_n (&graph->l4_last_match_action);
  status->last_evaluation_result =
    clib_atomic_load_acq_n (&graph->l4_last_evaluation_result);
  status->last_evaluation_verdict =
    clib_atomic_load_acq_n (&graph->l4_last_evaluation_verdict);
  status->last_evaluation_device_direction =
    clib_atomic_load_acq_n (&graph->l4_last_evaluation_device_direction);

  status->view_active =
    clib_atomic_load_acq_n (&graph->l4_policy_view_active);
  status->last_match_winner_rank = clib_atomic_load_acq_n (
    &graph->l4_policy_view_last_winner_rank);
  status->last_match_probes =
    clib_atomic_load_acq_n (&graph->l4_policy_view_last_probes);
  status->last_match_candidate_count = clib_atomic_load_acq_n (
    &graph->l4_policy_view_last_candidate_count);
  status->last_no_match_reason = clib_atomic_load_acq_n (
    &graph->l4_policy_view_last_no_match_reason);
  status->typed_match_policy_key = clib_atomic_load_acq_n (
    &graph->l4_typed_match_policy_key);
  status->typed_match_probe_key = clib_atomic_load_acq_n (
    &graph->l4_typed_match_probe_key);
  status->last_evaluation_probe_key = clib_atomic_load_acq_n (
    &graph->l4_last_evaluation_probe_key);
  if (status->view_active)
    {
      product_policy_snapshot_acquire (graph, &snapshot);
      status->active_generation = snapshot.bank->generation;
      status->active_revision = snapshot.bank->revision;
      status->snapshot_hash = snapshot.bank->snapshot_hash;
      status->view_rule_count = snapshot.bank->view.rule_count;
      status->view_max_probes = snapshot.bank->view.max_probes;
      product_l4_policy_index_resources_t resources;
      product_l4_policy_index_resources (&snapshot.bank->view, &resources);
      status->index_subtables = resources.subtables;
      status->index_entries = resources.entries;
      status->index_storage_bytes = resources.storage_bytes;
      status->index_max_query_work = resources.max_query_work;
      product_l4_policy_plan_resources (&snapshot.bank->view, &status->plan_resources);
      product_policy_snapshot_release (graph, &snapshot);
      /* A multi-rule view has no single active rule identity. */
      if (status->view_rule_count != 1)
        {
          status->rule_id = 0;
          status->subject_uid = UINT32_MAX;
          status->network_context_id = 0;
          status->reason_id = 0;
          status->priority = 0;
          status->order = 0;
          status->direction = 0;
          status->protocol = 0;
          status->action = 0;
        }
    }
  else
    {
      status->active_generation = 0;
      status->view_rule_count = 0;
      status->view_max_probes = 0;
      status->last_match_winner_rank = 0;
      status->last_match_probes = 0;
      status->last_match_candidate_count = 0;
      status->last_no_match_reason = 0;
    }
}

static int
product_packet_graph_l4_policy_view_active (product_packet_graph_main_t *graph)
{
  return graph != 0 && clib_atomic_load_acq_n (&graph->l4_policy_view_active) != 0;
}

static void
product_packet_graph_record_policy_stage (
  product_packet_graph_main_t *graph,
  const product_packet_graph_policy_evaluation_t *evaluation)
{
  if (graph == 0 || evaluation == 0)
    return;
  clib_atomic_store_rel_n (&graph->policy_last_stage, evaluation->stage);
  clib_atomic_store_rel_n (&graph->policy_last_verdict, evaluation->verdict);
  clib_atomic_store_rel_n (&graph->policy_last_matched, evaluation->matched);
  clib_atomic_store_rel_n (&graph->policy_last_terminal_preserved,
                           evaluation->terminal_preserved);
  clib_atomic_store_rel_n (&graph->policy_last_winner, evaluation->winner);
  clib_atomic_store_rel_n (&graph->policy_last_revision,
                           evaluation->revision);
  clib_atomic_store_rel_n (&graph->policy_last_rule_id,
                           evaluation->rule_id);
  clib_atomic_store_rel_n (&graph->policy_last_reason_id,
                           evaluation->reason_id);
}

static product_packet_result_t
product_packet_graph_policy_stage_snapshot (
  product_packet_lease_t *lease, product_packet_graph_policy_evaluation_t *evaluation,
  const product_policy_snapshot_t *snapshot,
  const product_l4_policy_match_result_t *early_winner)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_l4_policy_match_result_t matched_view;
  product_packet_result_t result;
  clib_memset (evaluation, 0, sizeof (*evaluation));
  evaluation->generation = snapshot->identity.generation;
  evaluation->revision = snapshot->identity.revision;
  evaluation->snapshot_hash = snapshot->identity.snapshot_hash;
  evaluation->verdict = PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT;
  clib_atomic_fetch_add_relax (&graph->policy_stage_evaluations, 1);
  if (lease->terminal_intent != PRODUCT_PACKET_INTENT_NONE)
    {
      evaluation->verdict = lease->terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME
        ? PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP : PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT;
      evaluation->terminal_preserved = 1;
      product_packet_graph_record_policy_stage (graph, evaluation);
      return PRODUCT_PACKET_OK;
    }
  if (!lease->policy_owner_ready)
    return PRODUCT_PACKET_ORDER_VIOLATION;

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (snapshot->hold_us)
    {
      u64 begin = product_packet_event_clock_ns ();
      fprintf (stderr, "s209 event=hold_begin token=%llu thread=%u us=%u mono_ns=%llu\n",
        (unsigned long long) lease->origin_obligation_id, vlib_get_thread_index (),
        snapshot->hold_us, (unsigned long long) begin);
      while (product_packet_event_clock_ns () - begin < (u64) snapshot->hold_us * 1000)
        ;
      fprintf (stderr, "s209 event=hold_end token=%llu thread=%u mono_ns=%llu\n",
        (unsigned long long) lease->origin_obligation_id, vlib_get_thread_index (),
        (unsigned long long) product_packet_event_clock_ns ());
    }
#endif
  product_l4_policy_status_t matcher_status = PRODUCT_L4_POLICY_STATUS_OK;
  if (early_winner) matched_view = *early_winner;
  else matcher_status = product_packet_graph_l4_view_evaluate (
    graph, lease, snapshot, &matched_view);
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (snapshot->trace)
    fprintf (stderr, "s209 event=l4 token=%llu thread=%u generation=%llu revision=%llu snapshot_hash=%llu rule=%llu action=%u mode=%u actual_action=%u candidates=%u rank=%u status=%u ct_state=%u flow_dir=%u position=%u mono_ns=%llu\n",
      (unsigned long long) lease->origin_obligation_id, vlib_get_thread_index (),
      (unsigned long long) snapshot->identity.generation, (unsigned long long) snapshot->identity.revision,
      (unsigned long long) snapshot->bank->snapshot_hash, (unsigned long long) matched_view.rule_id,
      matched_view.action, matched_view.mode, matched_view.actual_action, matched_view.candidate_count,
      matched_view.winner_rank, matcher_status, snapshot->ct.state, snapshot->ct.direction, snapshot->position, (unsigned long long) product_packet_event_clock_ns ());
#endif
  clib_atomic_fetch_add_relax (&graph->policy_l4_evaluations, 1);
  evaluation->stage = PRODUCT_PACKET_GRAPH_POLICY_STAGE_L4;
  if (matcher_status != PRODUCT_L4_POLICY_STATUS_OK)
    {
      result = product_packet_set_terminal (lease, PRODUCT_PACKET_INTENT_DROP_RUNTIME);
      if (result == PRODUCT_PACKET_OK)
        {
          lease->runtime_drop_reason = PRODUCT_PACKET_DROP_INVALID_ENVELOPE;
          evaluation->verdict = PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP;
          clib_atomic_fetch_add_relax (&graph->policy_stage_drops, 1);
        }
      product_packet_graph_record_policy_stage (graph, evaluation);
      return result;
    }
  if (matched_view.evaluation == PRODUCT_L4_POLICY_EVALUATION_MATCH)
    {
      evaluation->matched = 1;
      evaluation->winner = PRODUCT_PACKET_GRAPH_L4_WINNER_RULE;
      evaluation->rule_id = matched_view.rule_id;
      evaluation->reason_id = matched_view.reason_id;
      evaluation->verdict = matched_view.stage_verdict == PRODUCT_L4_POLICY_VERDICT_DROP
        ? PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP : PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT;
      if (matched_view.actual_action == PRODUCT_L4_POLICY_ACTION_DROP)
        {
          result = product_packet_set_terminal (lease, PRODUCT_PACKET_INTENT_DROP_RUNTIME);
          if (result == PRODUCT_PACKET_OK)
            {
              lease->runtime_drop_reason = PRODUCT_PACKET_DROP_POLICY_L4;
              product_packet_graph_record_l4_view_match (
                graph, lease, evaluation->generation, evaluation->revision,
                evaluation->snapshot_hash, &matched_view);
              clib_atomic_fetch_add_relax (&graph->policy_stage_drops, 1);
            }
          product_packet_graph_record_policy_stage (graph, evaluation);
          return result;
        }
      product_packet_graph_record_l4_view_match (
        graph, lease, evaluation->generation, evaluation->revision,
        evaluation->snapshot_hash, &matched_view);
    }
  else
    {
      evaluation->reason_id = matched_view.no_match_reason;
      product_packet_graph_record_l4_view_no_match (
        graph, evaluation->generation, evaluation->revision,
        evaluation->snapshot_hash, snapshot->bank->view.rule_count, &matched_view, lease);
    }
  clib_atomic_fetch_add_relax (&graph->policy_stage_pass_next, 1);
  product_packet_graph_record_policy_stage (graph, evaluation);
  return PRODUCT_PACKET_OK;
}

product_packet_result_t
product_packet_graph_policy_stage (
  product_packet_lease_t *lease, product_packet_graph_policy_evaluation_t *evaluation)
{
  if (!lease || !evaluation)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  product_policy_snapshot_t snapshot;
  product_policy_snapshot_acquire (&product_packet_graph_main, &snapshot);
  product_packet_result_t result = product_packet_graph_policy_stage_snapshot (
    lease, evaluation, &snapshot, 0);
  product_policy_snapshot_release (&product_packet_graph_main, &snapshot);
  return result;
}

static product_packet_result_t
product_packet_graph_policy_on_owner (
  vlib_main_t *vm, u32 buffer_index, product_packet_lease_t *lease,
  product_packet_graph_policy_evaluation_t *evaluation, int trace)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_policy_snapshot_t snapshot;
  product_policy_snapshot_acquire (graph, &snapshot);
  product_policy_worker_t *worker = vm->thread_index > 0 && vm->thread_index <= PRODUCT_GRAPH_WORKERS
    ? &graph->policy_workers[vlib_get_worker_index (vm->thread_index)] : 0;
  snapshot.trace = trace;
  snapshot.cache = worker ? &worker->cache : 0;
  if (worker)
    {
      snapshot.hold_us = __atomic_exchange_n (
        &graph->policy_hold_next_us[vlib_get_worker_index (vm->thread_index)], 0,
        __ATOMIC_SEQ_CST);
      worker->acquired++;
      worker->generation = snapshot.identity.generation;
      worker->revision = snapshot.identity.revision;
      worker->snapshot_hash = snapshot.identity.snapshot_hash;
    }
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (trace)
    fprintf (stderr, "s209 event=acquire source=%s token=%llu buffer=%u thread=%u worker=%u owner=%u generation=%llu revision=%llu snapshot_hash=%llu bank=%u sequence=%u mono_ns=%llu\n",
      product_packet_evidence_source (lease), (unsigned long long) lease->origin_obligation_id,
      buffer_index, vm->thread_index, vlib_get_worker_index (vm->thread_index), lease->assignment.execution_owner,
      (unsigned long long) snapshot.identity.generation, (unsigned long long) snapshot.identity.revision,
      (unsigned long long) snapshot.identity.snapshot_hash, snapshot.bank_index, snapshot.sequence,
      (unsigned long long) product_packet_event_clock_ns ());
#endif
  /* PRE only produces complete logical winners. A complete early ALLOW is
   * retained while Flow runs; lower Rank post rules cannot replace it. */
  snapshot.position = PRODUCT_L4_POLICY_POSITION_PRE;
  product_l4_policy_match_result_t early = {0};
  product_l4_policy_status_t early_status = PRODUCT_L4_POLICY_STATUS_OK;
  int eligible = lease->policy_owner_ready
    && lease->terminal_intent == PRODUCT_PACKET_INTENT_NONE;
  if (eligible)
    early_status = product_packet_graph_l4_view_evaluate (graph, lease, &snapshot, &early);
  int post_flow = eligible && early_status == PRODUCT_L4_POLICY_STATUS_OK
    && early.evaluation == PRODUCT_L4_POLICY_EVALUATION_NO_MATCH;
  product_flow_entry_observation_t observation = {0};
  if (post_flow)
    {
      product_packet_graph_policy_evaluation_t pending = {
        .generation = snapshot.identity.generation,
        .revision = snapshot.identity.revision,
        .snapshot_hash = snapshot.identity.snapshot_hash,
        .verdict = PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT,
      };
      product_packet_graph_flow_observe (vm, buffer_index, lease, &pending, trace, &observation);
      snapshot.ct = observation.tracker.facts;
      snapshot.flow_incarnation = observation.entry ? observation.entry->incarnation : 0;
      snapshot.protocols = observation.entry ? observation.entry->lpi.protocols : 0;
      snapshot.protocols_available = observation.entry ? observation.entry->lpi.available : 0;
      snapshot.sni_result = observation.entry ? observation.entry->sni.result : 0;
      snapshot.position = PRODUCT_L4_POLICY_POSITION_POST;
    }
  product_packet_result_t result = product_packet_graph_policy_stage_snapshot (
    lease, evaluation, &snapshot,
    eligible && early_status == PRODUCT_L4_POLICY_STATUS_OK && !post_flow ? &early : 0);
  if (result == PRODUCT_PACKET_OK && !post_flow
      && lease->terminal_intent == PRODUCT_PACKET_INTENT_NONE)
    product_packet_graph_flow_observe (vm, buffer_index, lease, evaluation, trace, 0);
  else if (result == PRODUCT_PACKET_OK && observation.entry
           && !evaluation->terminal_preserved && snapshot.identity.revision)
    {
      u16 owner_worker = (u16) vlib_get_worker_index (vm->thread_index);
      product_flow_runtime_t *pool = graph->flow_pools[owner_worker];
      (void) product_packet_graph_flow_record_decision (
        pool, observation.entry, evaluation, lease, owner_worker);
    }
  u32 published_sequence = __atomic_load_n (&graph->policy_publish_sequence, __ATOMIC_SEQ_CST);
  if (worker)
    {
      worker->released++;
      worker->retired += published_sequence != snapshot.sequence;
      worker->mismatches += snapshot.bank->revision != snapshot.identity.revision
        || snapshot.bank->snapshot_hash != snapshot.identity.snapshot_hash
        || (snapshot.bank->generation != 0 && snapshot.bank->generation != snapshot.identity.generation);
    }
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  if (trace)
    fprintf (stderr, "s209 event=release source=%s token=%llu buffer=%u thread=%u worker=%u owner=%u generation=%llu revision=%llu snapshot_hash=%llu bank=%u sequence=%u published_sequence=%u content_generation=%llu content_revision=%llu content_hash=%llu mono_ns=%llu\n",
      product_packet_evidence_source (lease), (unsigned long long) lease->origin_obligation_id,
      buffer_index, vm->thread_index, vlib_get_worker_index (vm->thread_index), lease->assignment.execution_owner,
      (unsigned long long) snapshot.identity.generation, (unsigned long long) snapshot.identity.revision,
      (unsigned long long) snapshot.identity.snapshot_hash, snapshot.bank_index, snapshot.sequence, published_sequence,
      (unsigned long long) snapshot.bank->generation, (unsigned long long) snapshot.bank->revision,
      (unsigned long long) snapshot.bank->snapshot_hash, (unsigned long long) product_packet_event_clock_ns ());
#endif
  product_policy_snapshot_release (graph, &snapshot);
  return result;
}

int
product_packet_graph_submit_external (vlib_main_t *vm, u32 buffer_index,
                                      const product_platform_packet_facts_t *platform,
                                      const product_adapter_obligation_t *obligation)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_buffer_metadata_t metadata = { 0 };
  u64 origin_obligation_id = obligation ? obligation->token : 0;
  vlib_frame_t *frame;
  u32 *to;
  /* TUN return storage is created on its Flow Stack worker but completed by
   * the single TUN lane. Its VPN-private packet_id names only the producing
   * credit ledger; it never enters canonical assignment or policy facts. */
  int vpn_return = vm && vm->thread_index && platform && obligation &&
    obligation->kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN &&
    platform->provenance == PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN &&
    platform->direction == PRODUCT_PACKET_DIRECTION_INPUT &&
    obligation->origin_worker == 0 && obligation->origin_lane == 0 &&
    obligation->packet_id == vlib_get_worker_index(vm->thread_index) + 1 &&
    obligation->packet_id <= PRODUCT_VPN_RETURN_WORKERS;
  if (!vm || !obligation || obligation->origin_worker >= PRODUCT_GRAPH_WORKERS
      || (platform && platform->provenance == PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN && !vpn_return)
      || (!vpn_return &&
          vm->thread_index != vlib_get_worker_thread_index (obligation->origin_worker))
      || !origin_obligation_id || obligation->queue_generation != graph->generation
      || (obligation->kind != PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE
          && obligation->kind != PRODUCT_ADAPTER_OBLIGATION_VPN_TUN)
      || !clib_atomic_load_acq_n (&graph->enabled)
      || !clib_atomic_load_acq_n (&graph->accepting)) {
    fprintf(stderr, "s203 event=submit_reject thread=%u tls=%u obligation=%llu enabled=%u accepting=%u kind=%u\n",
      vm ? vm->thread_index : ~0U, vlib_get_thread_index(),
      (unsigned long long)origin_obligation_id, graph->enabled, graph->accepting,
      obligation ? obligation->kind : PRODUCT_ADAPTER_OBLIGATION_NONE);
    return 0;
  }
  if (clib_atomic_fetch_add_relax (&graph->trace_packets, 1) < graph->trace_limit)
    metadata.state_bits |= PRODUCT_META_TRACE;
  metadata.origin_obligation_id = origin_obligation_id;
  metadata.generation = graph->generation;
  product_buffer_platform_metadata_t platform_metadata = { .obligation = *obligation };
  clib_memcpy_fast (vlib_get_buffer (vm, buffer_index)->opaque,
                    &platform_metadata, sizeof (platform_metadata));
  product_metadata_store (vlib_get_buffer (vm, buffer_index), &metadata);
  product_packet_graph_set_platform_facts (vlib_get_buffer (vm, buffer_index),
                                         platform, metadata.generation);
  clib_atomic_fetch_add_relax (&graph->lifecycle_obligations, 1);
  clib_atomic_fetch_add_relax (&graph->lifecycle_buffers, 1);
  frame = vlib_get_frame_to_node (vm, product_packet_admit_node.index);
  to = vlib_frame_vector_args (frame);
  to[0] = buffer_index;
  frame->n_vectors = 1;
  vlib_put_frame_to_node (vm, product_packet_admit_node.index, frame);
  return 1;
}

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#include "product_packet_graph_host_fixtures.inc"
#endif

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static clib_error_t *
product_capacity_cli (vlib_main_t *vm, unformat_input_t *input,
                       vlib_cli_command_t *command)
{
  product_packet_graph_main_t *g = &product_packet_graph_main;
  u32 credits, primary, completion;
  (void) command;
  if (unformat (input, "off"))
    { credits = PRODUCT_GRAPH_HANDOFF_CREDITS; primary = 64; completion = 128; }
  else if (!unformat (input, "credits %u primary-slots %u completion-slots %u",
                      &credits, &primary, &completion))
    return clib_error_return (0, "expected off or credits N primary-slots N completion-slots N");
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || credits > PRODUCT_GRAPH_HANDOFF_CREDITS
      || (primary != 2 && primary != 64)
      || (completion != 2 && completion != 128))
    return clib_error_return (0, "unsupported diagnostic capacity");
  if (!g->accepting || g->lifecycle_obligations || g->lifecycle_buffers
      || g->lifecycle_handoffs || g->lifecycle_completion_frames
      || g->completion_pending_returns
      || !product_capacity_ring_empty (g->primary_frame_queue)
      || !product_capacity_ring_empty (g->completion_return_frame_queue))
    return clib_error_return (0, "capacity change requires an active empty graph");
  product_capacity_configure_empty (g, credits, primary, completion);
  vlib_cli_output (vm, "capacity.configured generation=%llu credits=%u primary_slots=%u completion_slots=%u",
    (unsigned long long) g->generation, credits, primary, completion);
  return 0;
}
VLIB_CLI_COMMAND (product_capacity_command, static) = {
  .path = "product capacity", .function = product_capacity_cli,
  /* Default CLI barrier protects empty native ring reconfiguration. */
};

static clib_error_t *
product_primary_misroute_cli (vlib_main_t *vm, unformat_input_t *input,
                              vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  (void) input; (void) command;
  if (!graph->accepting || graph->misroute_next)
    return clib_error_return (0, "misroute probe rejected");
  graph->misroute_next = 1;
  vlib_cli_output (vm, "primary.misroute_next=armed generation=%llu",
    (unsigned long long) graph->generation);
  return 0;
}
VLIB_CLI_COMMAND (product_primary_misroute_command, static) = {
  .path = "product primary misroute-next", .function = product_primary_misroute_cli,
};

static clib_error_t *
product_primary_status_cli (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *command)
{
  product_packet_graph_main_t *g = &product_packet_graph_main;
  (void) input; (void) command;
  vlib_cli_output (vm, "capacity.status credits=%u primary_slots=%u completion_slots=%u",
    g->primary_credit_limit, g->primary_ring_slots, g->completion_ring_slots);
  vlib_cli_output (vm, "primary.status generation=%llu published=%llu received=%llu rejected=%llu owner_checks=%llu owner_failures=%llu returns=%llu deferred=%llu retries=%llu pending_returns=%u handoff_debt=%u credit0=%u credit1=%u flows=%u",
    (unsigned long long) g->generation,
    (unsigned long long) clib_atomic_load_acq_n (&g->primary_published),
    (unsigned long long) clib_atomic_load_acq_n (&g->primary_received),
    (unsigned long long) clib_atomic_load_acq_n (&g->primary_rejected),
    (unsigned long long) clib_atomic_load_acq_n (&g->owner_delivery_checks),
    (unsigned long long) clib_atomic_load_acq_n (&g->owner_delivery_failures),
    (unsigned long long) clib_atomic_load_acq_n (&g->completion_returns),
    (unsigned long long) clib_atomic_load_acq_n (&g->completion_deferred),
    (unsigned long long) clib_atomic_load_acq_n (&g->completion_retry_attempts),
    clib_atomic_load_acq_n (&g->completion_pending_returns),
    clib_atomic_load_acq_n (&g->lifecycle_handoffs),
    clib_atomic_load_acq_n (&g->handoff_credits[0]),
    clib_atomic_load_acq_n (&g->handoff_credits[1]),
    product_flow_entry_pool_active_count (g->flow_pools[0])
      + product_flow_entry_pool_active_count (g->flow_pools[1]));
  return 0;
}
VLIB_CLI_COMMAND (product_primary_status_command, static) = {
  .path = "show product primary", .function = product_primary_status_cli,
};

/* Default CLI barrier makes these bounded pool snapshots safe. Packet-side
 * mutation never traverses or indexes another worker's pool. */
static clib_error_t *
product_flow_status_cli (vlib_main_t *vm, unformat_input_t *input,
                         vlib_cli_command_t *command)
{
  product_packet_graph_main_t *g = &product_packet_graph_main;
  (void) input; (void) command;
  product_policy_snapshot_t snapshot;
  product_policy_snapshot_acquire (g, &snapshot);
  vlib_cli_output (vm, "policy.snapshot generation=%llu revision=%llu snapshot_hash=%llu bank=%u sequence=%u publications=%llu packet_lock_acquisitions=%llu readers0=%u readers1=%u",
    (unsigned long long) snapshot.identity.generation, (unsigned long long) snapshot.identity.revision,
    (unsigned long long) snapshot.identity.snapshot_hash, snapshot.bank_index, snapshot.sequence,
    (unsigned long long) g->policy_publications, (unsigned long long) g->policy_packet_lock_acquisitions,
    __atomic_load_n (&g->l4_policy_bank_readers[0], __ATOMIC_SEQ_CST) - (snapshot.bank_index == 0),
    __atomic_load_n (&g->l4_policy_bank_readers[1], __ATOMIC_SEQ_CST) - (snapshot.bank_index == 1));
  product_policy_snapshot_release (g, &snapshot);
  for (u32 worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      product_flow_runtime_snapshot_t snapshot = product_flow_runtime_snapshot (g->flow_pools[worker]);
      const product_flow_runtime_snapshot_t *pool = &snapshot;
      const product_policy_worker_t *policy = &g->policy_workers[worker];
      vlib_cli_output (vm, "policy.cache worker=%u capacity=%u occupied=%u storage_bytes=%u hits=%llu misses=%llu replacements=%llu",
        worker, policy->cache.capacity ? policy->cache.capacity : PRODUCT_POLICY_CACHE_CAPACITY,
        policy->cache.occupied, (unsigned) sizeof (policy->cache),
        (unsigned long long) policy->cache.hits, (unsigned long long) policy->cache.misses,
        (unsigned long long) policy->cache.replacements);
      vlib_cli_output (vm, "policy.worker worker=%u acquired=%llu released=%llu retired=%llu mismatches=%llu generation=%llu revision=%llu snapshot_hash=%llu",
        worker, (unsigned long long) policy->acquired, (unsigned long long) policy->released,
        (unsigned long long) policy->retired, (unsigned long long) policy->mismatches,
        (unsigned long long) policy->generation, (unsigned long long) policy->revision,
        (unsigned long long) policy->snapshot_hash);
      vlib_cli_output (vm, "flow.pool worker=%u pool=%p entries=%u allocations=%llu reused=%llu early_drops=%llu wrong_owner=%llu capacity_drops=%llu invalidations=%llu flushes=%llu revision=%llu snapshot_hash=%llu epoch_source=last_packet unavailable=%llu revision_mismatches=%llu",
        worker, (void *)g->flow_pools[worker], pool->active_entries,
        (unsigned long long)pool->allocation_count, (unsigned long long)pool->reuse_count,
        (unsigned long long)pool->early_drop_count, (unsigned long long)pool->wrong_owner_count,
        (unsigned long long)pool->capacity_rejection_count,
        (unsigned long long)pool->revision_invalidation_count, (unsigned long long)pool->flush_count,
        (unsigned long long)policy->revision, (unsigned long long)policy->snapshot_hash,
        (unsigned long long) g->flow_unavailable[worker],
        (unsigned long long) (pool->revision_mismatch_count + g->flow_mutation_errors[worker]));
      vlib_cli_output (vm, "flow.runtime worker=%u generation=%llu capacity=%u high_watermark=%u allocated_bytes=%llu entry_bytes=%u capacity_misses=%llu",
        worker, (unsigned long long) pool->generation, pool->capacity, pool->high_watermark,
        (unsigned long long) pool->allocated_bytes, (u32) sizeof (product_flow_entry_t),
        (unsigned long long) pool->capacity_rejection_count);
      vlib_cli_output (vm, "flow.health worker=%u generation=%llu state=%s reason=%s capacity_misses=%llu retained_for_generation=1",
        worker, (unsigned long long) pool->generation,
        pool->capacity_rejection_count ? "error" : "ok",
        pool->capacity_rejection_count ? "FLOW_CAPACITY" : "NONE",
        (unsigned long long) pool->capacity_rejection_count);
      for (u32 protocol = 0; protocol < 3; protocol++)
        vlib_cli_output (vm, "flow.protocol worker=%u protocol=%s active=%u creates=%llu hits=%llu capacity_misses=%llu invalid_packets=%llu closed=%llu",
          worker, protocol == 0 ? "tcp" : protocol == 1 ? "udp" : "icmp_query",
          pool->protocol[protocol].active,
          (unsigned long long) pool->protocol[protocol].creates,
          (unsigned long long) pool->protocol[protocol].hits,
          (unsigned long long) pool->protocol[protocol].capacity_misses,
          (unsigned long long) pool->protocol[protocol].invalid_packets,
          (unsigned long long) pool->protocol[protocol].closed);
      for (u32 slot = 0; slot < pool->capacity; slot++)
        {
          const product_flow_entry_t *e = product_flow_runtime_entry (g->flow_pools[worker], slot);
          if (!e) continue;
          vlib_cli_output (vm, "flow.entry worker=%u slot=%u kind=%u family=%u protocol=%u hash=%llu key_a=%U key_b=%U port_a=%u port_b=%u origin_is_a=%u flow_origin_dir=%u device_dir=%u flow_dir=%u uid=%u context=%u packets=%llu bytes=%llu first_seen=%llu last_seen=%llu policy_generation=%llu revision=%llu snapshot_hash=%llu decision=%u rule=%llu query_class=%u identifier=%u incarnation=%llu orig_packets=%llu reply_packets=%llu orig_bytes=%llu reply_bytes=%llu",
            worker, slot, e->key.kind, e->key.ip_family, e->key.protocol,
            (unsigned long long)e->canonical_hash,
            format_hex_bytes, e->key.address_a, 16, format_hex_bytes, e->key.address_b, 16,
            e->key.kind == PRODUCT_OWNER_KEY_L4_PORTS ? e->key.transport.ports.a : 0,
            e->key.kind == PRODUCT_OWNER_KEY_L4_PORTS ? e->key.transport.ports.b : 0, e->origin_is_endpoint_a,
            e->flow_origin_device_direction, e->last_device_direction, e->last_flow_direction,
            e->uid, e->network_context, (unsigned long long)e->packets, (unsigned long long)e->bytes,
            (unsigned long long)e->first_seen, (unsigned long long)e->last_seen,
            (unsigned long long)e->policy_generation, (unsigned long long)e->policy_revision, (unsigned long long)e->policy_snapshot_hash,
            e->decision, (unsigned long long)e->winner_rule_id,
            e->key.query_class, e->key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY ? e->key.transport.query.identifier : 0,
            (unsigned long long)e->incarnation,
            (unsigned long long)e->side_packets[0], (unsigned long long)e->side_packets[1],
            (unsigned long long)e->side_bytes[0], (unsigned long long)e->side_bytes[1]);
          vlib_cli_output (vm, "flow.sni worker=%u slot=%u incarnation=%llu result=%u stop=%u attempts=%u bytes=%u work=%u cache_bytes=%u name=%s",
            worker, slot, (unsigned long long)e->incarnation, e->sni.result,
            e->sni.stop, e->sni.attempts, e->sni.bytes, e->sni.work,
            e->tcp_bytes.length[0]+e->tcp_bytes.length[1],
            e->sni.result==PRODUCT_SNI_NAME?e->sni.name:"-");
          vlib_cli_output (vm, "flow.tcp_cache worker=%u slot=%u incarnation=%llu bytes0=%u bytes1=%u contiguous0=%u contiguous1=%u ranges0=%u ranges1=%u span0=%u span1=%u reserved=%u range_limit=%u span_limit=%u",
            worker, slot, (unsigned long long)e->incarnation,
            e->tcp_bytes.length[0],e->tcp_bytes.length[1],
            e->tcp_bytes.contiguous[0],e->tcp_bytes.contiguous[1],
            e->tcp_bytes.range_count[0],e->tcp_bytes.range_count[1],
            e->tcp_bytes.range_count[0]?e->tcp_bytes.ranges[0][e->tcp_bytes.range_count[0]-1].last:0,
            e->tcp_bytes.range_count[1]?e->tcp_bytes.ranges[1][e->tcp_bytes.range_count[1]-1].last:0,
            (unsigned)sizeof e->tcp_bytes,PRODUCT_TCP_CACHE_RANGES,PRODUCT_TCP_CACHE_SIDE_BYTES);
          vlib_cli_output (vm, "flow.lpi worker=%u slot=%u incarnation=%llu available=%u protocols=%llu attempts=%u bytes=%u stop=%u outcome=%u stop_reason=%s",
            worker, slot, (unsigned long long)e->incarnation, e->lpi.available,
            (unsigned long long)e->lpi.protocols, e->lpi.attempts, e->lpi.bytes,
            e->lpi.stop_reason, e->lpi.last_outcome, product_lpi_stop_name(e->lpi.stop_reason));
          for (unsigned bit = 0; bit < PRODUCT_PROTOCOL_CATALOG_COUNT; ++bit)
            {
              u32 id = product_protocol_id_at (bit);
              if (e->lpi.protocols & product_protocol_bit (id))
                vlib_cli_output (vm, "flow.protocol_fact worker=%u slot=%u incarnation=%llu id=%u key=%s",
                  worker, slot, (unsigned long long)e->incarnation, id, product_protocol_key (id));
            }
          if (e->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_UDP)
            vlib_cli_output (vm, "flow.udp worker=%u slot=%u incarnation=%llu phase=%u",
              worker, slot, (unsigned long long) e->incarnation,
              e->protocol_state.udp.phase);
          if (e->deadline_us)
            vlib_cli_output (vm, "flow.timer worker=%u slot=%u incarnation=%llu deadline_us=%llu timeout=%u heap_position=%u",
              worker, slot, (unsigned long long) e->incarnation,
              (unsigned long long) e->deadline_us, e->timeout_class, e->heap_position);
          if (e->key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY)
            vlib_cli_output (vm, "flow.icmp worker=%u slot=%u incarnation=%llu phase=%u seen_request=%u seen_reply=%u",
              worker, slot, (unsigned long long) e->incarnation,
              e->protocol_state.icmp.phase, e->protocol_state.icmp.seen_request,
              e->protocol_state.icmp.seen_reply);
          if (e->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_TCP)
            {
              const product_tcp_state_t *s = &e->protocol_state.tcp;
              vlib_cli_output(vm, "flow.tcp worker=%u slot=%u incarnation=%llu initialized=%u orig_state=%u reply_state=%u orig_seqlo=%u orig_seqhi=%u reply_seqlo=%u reply_seqhi=%u orig_maxwin=%u reply_maxwin=%u orig_scale=%u reply_scale=%u orig_flags=%u reply_flags=%u timeout=%u",
                worker, slot, (unsigned long long)e->incarnation, s->initialized,
                s->peer[0].phase, s->peer[1].phase, s->peer[0].seqlo, s->peer[0].seqhi,
                s->peer[1].seqlo, s->peer[1].seqhi, s->peer[0].max_window, s->peer[1].max_window,
                s->peer[0].window_scale, s->peer[1].window_scale,
                s->peer[0].flags_history, s->peer[1].flags_history, s->timeout);
            }
        }
    }
  return 0;
}
VLIB_CLI_COMMAND (product_flow_status_command, static) = {
  .path = "show product flows", .function = product_flow_status_cli,
};

static clib_error_t *
product_policy_index_cli (vlib_main_t *vm, unformat_input_t *input,
                           vlib_cli_command_t *command)
{
  (void) input; (void) command;
  product_packet_graph_l4_status_t status;
  product_packet_graph_l4_status (&status);
  vlib_cli_output (vm, "policy.index generation=%llu revision=%llu hash=%llu masks=%u entries=%u view_bytes=%u max_query_work=%u",
    (unsigned long long) status.active_generation,
    (unsigned long long) status.active_revision,
    (unsigned long long) status.snapshot_hash,
    status.index_subtables, status.index_entries, status.index_storage_bytes,
    status.index_max_query_work);
  vlib_cli_output (vm, "policy.plan generation=%llu revision=%llu hash=%llu direct=%u factorized=%u residual=%u conditions=%u query_state_bytes=%u compile_scratch_bytes=%u publication_peak_bytes=%u direct_limit=%u entries_limit=%u conditions_limit=%u publication_limit_bytes=%u",
    (unsigned long long) status.active_generation,
    (unsigned long long) status.active_revision,
    (unsigned long long) status.snapshot_hash,
    status.plan_resources.direct_rules, status.plan_resources.factorized_rules,
    status.plan_resources.residual_rules, status.plan_resources.condition_items,
    status.plan_resources.query_state_bytes, status.plan_resources.compile_scratch_bytes,
    status.plan_resources.publication_peak_bytes, PRODUCT_L4_DIRECT_ENTRIES,
    PRODUCT_L4_INDEX_ENTRIES, PRODUCT_L4_CONDITION_ITEMS, PRODUCT_L4_COMPILE_PEAK_LIMIT);
  return 0;
}
VLIB_CLI_COMMAND (product_policy_index_command, static) = {
  .path = "show product policy-index", .function = product_policy_index_cli,
};

static clib_error_t *
product_flow_capacity_cli (vlib_main_t *vm, unformat_input_t *input,
                           vlib_cli_command_t *command)
{
  product_packet_graph_main_t *g = &product_packet_graph_main;
  u64 capacity;
  (void) command;
  if (!unformat (input, "%llu", &capacity) || !capacity
      || capacity > UINT32_MAX / 4
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected a positive startup entry capacity");
  if (g->enabled || g->lifecycle_obligations || g->lifecycle_buffers
      || g->lifecycle_handoffs || g->lifecycle_completion_frames)
    return clib_error_return (0, "capacity changes require stopped, drained runtime");
  g->flow_capacity = (u32) capacity;
  vlib_cli_output (vm, "flow.capacity next_start=%u live_resize=0", (u32) capacity);
  return 0;
}
VLIB_CLI_COMMAND (product_flow_capacity_command, static) = {
  .path = "product flow capacity", .short_help = "product flow capacity <entries-per-worker> (stopped only)",
  .function = product_flow_capacity_cli,
};

static clib_error_t *
product_policy_publish_cli (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *command)
{
  (void) vm; (void) input; (void) command;
  return clib_error_return (0, "retired: use the online Product rule configuration API");
}
VLIB_CLI_COMMAND (product_policy_publish_command, static) = {
  .path = "product policy publish", .short_help = "product policy publish <revision> <hash> <uid> <rule-id>",
  .function = product_policy_publish_cli, .is_mp_safe = 1,
};

static clib_error_t *
product_policy_hold_cli (vlib_main_t *vm, unformat_input_t *input,
                         vlib_cli_command_t *command)
{
  u32 worker, us;
  (void) command;
  if (!unformat (input, "%u %u", &worker, &us) || worker >= PRODUCT_GRAPH_WORKERS
      || us > 500000 || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected worker 0..1 and hold 0..500000 us");
  __atomic_store_n (&product_packet_graph_main.policy_hold_next_us[worker], us, __ATOMIC_SEQ_CST);
  vlib_cli_output (vm, "policy.hold=armed worker=%u us=%u", worker, us);
  return 0;
}
VLIB_CLI_COMMAND (product_policy_hold_command, static) = {
  .path = "product policy hold-next", .function = product_policy_hold_cli, .is_mp_safe = 1,
};

static clib_error_t *
product_packet_trace_limit_cli (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *command)
{
  product_packet_graph_main_t *g = &product_packet_graph_main;
  u32 limit;
  (void) command;
  if (!unformat (input, "%u", &limit) || limit < 256 || limit > 4096
      || (g->trace_packets && limit < g->trace_limit)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "trace limit 256..4096 may only increase after first packet");
  /* VPN attachment can generate kernel control packets before CLI is ready.
   * Increasing the cap under this CLI barrier does not reset the ordinal or
   * retroactively trace packets omitted before the increase. */
  g->trace_limit = limit;
  vlib_cli_output (vm, "packet.trace_limit=%u", limit);
  return 0;
}
VLIB_CLI_COMMAND (product_packet_trace_limit_command, static) = {
  .path = "product packet-trace limit", .function = product_packet_trace_limit_cli,
};

/* Test-only ingress accepts bounded caller-supplied bytes. It never makes an
 * NFQUEUE obligation or publishes transport readiness. */
static u32 product_metadata_injection_frame_queue;
static u64 product_metadata_injection_generation;
static u32 product_metadata_injection_count;

static clib_error_t *
product_metadata_inject_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u8 *hex = 0;
  u32 case_id = 0, bi, failed, arrival_worker = 0, uid = 21200;
  u32 fact_ifindex = 0, fact_context = 0, fact_available = 0;
  u32 fact_direction = 0, fact_provenance = 0;
  int explicit_facts = 0;
  int fragment_probe = strcmp (command->path, "product reassembly inject") == 0;
  int owner_probe = 0;
  (void) command;
  if (vm->thread_index != 0 || !unformat (input, "%u %s", &case_id, &hex) || !case_id || case_id > PRODUCT_GRAPH_INJECTION_CAPACITY
      || !graph->accepting || !graph->enabled)
    { vec_free (hex); return clib_error_return (0, "injection rejected"); }
  owner_probe = unformat (input, "worker %u", &arrival_worker);
  if (fragment_probe)
    {
      (void) unformat (input, "uid %u", &uid);
      explicit_facts = unformat (input, "facts %u %u %u %u %u %u",
        &uid, &fact_ifindex, &fact_context, &fact_available,
        &fact_direction, &fact_provenance);
      if (explicit_facts && (fact_ifindex > INT32_MAX || fact_available > 7
          || (fact_context && fact_context != 1 && fact_context != 2
              && fact_context != 4 && fact_context != 8)
          || (fact_direction != 0 && fact_direction != 1 && fact_direction != 3)
          || fact_provenance > PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED))
        { vec_free (hex); return clib_error_return (0, "invalid controlled platform facts"); }
    }
  if (arrival_worker >= PRODUCT_GRAPH_WORKERS
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    { vec_free (hex); return clib_error_return (0, "invalid injection worker"); }
  u16 thread = vlib_get_worker_thread_index (arrival_worker);
  u32 length = strlen ((char *) hex);
  u32 max_bytes = fragment_probe ? clib_min (2048, vlib_buffer_get_default_data_size (vm)) : 256;
  if (!length || (length & 1) || length / 2 > max_bytes)
    { vec_free (hex); return clib_error_return (0, "invalid bounded hex span"); }
  if (product_metadata_injection_generation != graph->generation)
    { product_metadata_injection_generation = graph->generation; product_metadata_injection_count = 0; }
  u32 *used = fragment_probe ? &product_fragment_main.injected
                            : &product_metadata_injection_count;
  if (*used & (1U << (case_id - 1)))
    { vec_free (hex); return clib_error_return (0, "duplicate case in generation"); }
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    { vec_free (hex); return clib_error_return (0, "buffer unavailable"); }
  vlib_buffer_t *buffer = vlib_get_buffer (vm, bi);
  buffer->current_data = 0;
  buffer->current_length = length / 2;
  u8 *bytes = vlib_buffer_get_current (buffer);
  for (u32 i = 0; i < length; i += 2)
    {
      u32 value = 0;
      for (u32 j = 0; j < 2; j++)
        {
          u8 c = hex[i+j];
          if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            { vec_free (hex); vlib_buffer_free (vm, &bi, 1); return clib_error_return (0, "invalid hex"); }
          value = value * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
        }
      bytes[i/2] = value;
    }
  vec_free (hex);
  product_buffer_metadata_t metadata = {
    .generation = graph->generation,
    .origin_obligation_id = (fragment_probe ? UINT64_C (212000000) : UINT64_C (216000000)) + case_id,
    .state_bits = PRODUCT_META_TRACE,
  };
  product_buffer_platform_metadata_t extra = {
    .obligation = { .token = metadata.origin_obligation_id,
      .queue_generation = graph->generation, .packet_id = case_id,
      .kind = PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED,
      .origin_worker = arrival_worker, .origin_lane = arrival_worker },
    .platform = { .availability = (case_id & 1) ? 7 : 0,
      .direction = PRODUCT_PACKET_DIRECTION_OUTPUT,
      .provenance = PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED },
  };
  if (owner_probe)
    {
      extra.platform.uid = case_id * 10000;
      extra.platform.linux_ifindex = case_id + 10;
      extra.platform.network_context_id = case_id + 100;
      extra.platform.direction = (case_id & 1)
        ? PRODUCT_PACKET_DIRECTION_OUTPUT : PRODUCT_PACKET_DIRECTION_INPUT;
    }
  if (fragment_probe)
    {
      extra.platform.uid = uid;
      extra.platform.availability = PRODUCT_PLATFORM_UID_KNOWN;
      extra.platform.direction = PRODUCT_PACKET_DIRECTION_OUTPUT;
    }
  if (explicit_facts)
    extra.platform = (product_platform_packet_facts_t) {
      .uid = uid, .linux_ifindex = fact_ifindex, .network_context_id = fact_context,
      .availability = fact_available, .direction = fact_direction, .provenance = fact_provenance,
    };
  if (fragment_probe)
    fprintf (stderr, "s219 event=controlled_fragment case=%u token=%llu generation=%llu arrival_worker=%u snapshot_revision=%llu uid=%u ifindex=%u context=%u availability=%u direction=%u provenance=%u\n",
      case_id, (unsigned long long) metadata.origin_obligation_id,
      (unsigned long long) graph->generation, arrival_worker,
      (unsigned long long) product_network_snapshot_current ()->revision,
      extra.platform.uid, extra.platform.linux_ifindex, extra.platform.network_context_id,
      extra.platform.availability, extra.platform.direction, extra.platform.provenance);
  product_metadata_store (buffer, &metadata);
  clib_memcpy_fast (buffer->opaque, &extra, sizeof (extra));
  clib_atomic_fetch_add_relax (&graph->lifecycle_buffers, 1);
  clib_atomic_fetch_add_relax (&graph->lifecycle_obligations, 1);
  if (vlib_buffer_enqueue_to_thread_retained (vm,
        vlib_node_get_runtime (vm, product_packet_admit_node.index),
        product_metadata_injection_frame_queue, &bi, &thread, 1, &failed) != 1)
    {
      vlib_buffer_free (vm, &bi, 1);
      clib_atomic_fetch_sub_relax (&graph->lifecycle_buffers, 1);
      clib_atomic_fetch_sub_relax (&graph->lifecycle_obligations, 1);
      return clib_error_return (0, "injection enqueue rejected and settled");
    }
  *used |= 1U << (case_id - 1);
  vlib_cli_output (vm, "%s.inject=accepted source=GRAPH_INJECTED case=%u generation=%llu buffer=%u target_thread=%u",
    fragment_probe ? "reassembly" : "metadata", case_id,
    (unsigned long long) graph->generation, bi, thread);
  return 0;
}

VLIB_CLI_COMMAND (product_metadata_inject_command, static) = {
  .path = "product metadata inject", .is_mp_safe = 1,
  .short_help = "product metadata inject <case 1..32> <hex, max 256 bytes> [worker <0|1>]",
  .function = product_metadata_inject_cli,
};

VLIB_CLI_COMMAND (product_reassembly_inject_command, static) = {
  .path = "product reassembly inject",
  /* Main-thread-only bounded inputs; admission counters are atomic and the
   * immutable buffer is transferred asynchronously. Do not wait for workers. */
  .is_mp_safe = 1,
  .short_help = "product reassembly inject <case 1..32> <hex, max 256 bytes> [worker <0|1>] [uid <uid>] [facts <uid> <ifindex> <context> <availability> <direction> <provenance>]",
  .function = product_metadata_inject_cli,
};

static clib_error_t *
product_metadata_check_cli (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *command)
{
  u32 bi;
  (void) input; (void) command;
  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return clib_error_return (0, "buffer unavailable");
  vlib_buffer_t *buffer = vlib_get_buffer (vm, bi);
  buffer->current_data = 0; buffer->current_length = 44;
  u8 *bytes = vlib_buffer_get_current (buffer);
  clib_memset (bytes, 0, 44);
  bytes[0] = 0x45; bytes[3] = 44; bytes[9] = 6;
  bytes[12] = 127; bytes[16] = 127; bytes[15] = 1; bytes[19] = 1;
  bytes[20] = 0x75; bytes[21] = 0x31; bytes[22] = 0x9d; bytes[23] = 0xd3;
  bytes[24] = 0x12; bytes[28] = 0x34; bytes[32] = 0x60; bytes[33] = 0x12;
  bytes[34] = 0xff; bytes[35] = 0xfe;
  bytes[40] = 3; bytes[41] = 3; bytes[42] = 7;
  product_worker_layout_t layout = { .worker_count = 2, .hash_seed = PRODUCT_GRAPH_HASH_SEED };
  product_packet_ingress_t ingress = { .data = bytes, .length = 44, .origin_obligation_id = 216,
    .platform = { .availability = 7, .direction = PRODUCT_PACKET_DIRECTION_OUTPUT,
      .provenance = PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED } };
  product_packet_lease_t before, after;
  product_buffer_metadata_t metadata;
  u64 generation = UINT64_C (0x123456780001);
  int ok = product_packet_admit (&layout, &ingress, &before) == PRODUCT_PACKET_OK;
  clib_memset (buffer->opaque, 0, sizeof (buffer->opaque));
  product_packet_graph_set_platform_facts (buffer, &ingress.platform, generation);
  product_metadata_from_lease (&metadata, &before, generation, buffer);
  product_metadata_store (buffer, &metadata);
  product_metadata_load (buffer, &metadata);
  ok &= product_lease_from_metadata (&metadata, buffer, &after)
    && memcmp (&before.facts, &after.facts, sizeof (before.facts)) == 0
    && memcmp (&before.platform, &after.platform, sizeof (before.platform)) == 0
    && memcmp (&before.assignment, &after.assignment, sizeof (before.assignment)) == 0;
  buffer->current_data++;
  int data_guard = !product_lease_from_metadata (&metadata, buffer, &after);
  buffer->current_data--; buffer->current_length--;
  int length_guard = !product_lease_from_metadata (&metadata, buffer, &after);
  buffer->current_length++;
  product_platform_packet_facts_t platform;
  int generation_guard = !product_packet_graph_get_platform_facts (buffer,
    generation + UINT64_C (0x100000000), &platform) && platform.availability == 0;
  vlib_buffer_free (vm, &bi, 1);
  vlib_cli_output (vm, "metadata.layout opaque=%u opaque2=%u owner=%u transport=%u platform=%u obligation=%u alignment=%u platform_offset=%u transport_offset=%u span_offset=%u",
    (u32)sizeof (buffer->opaque), (u32)sizeof (buffer->opaque2),
    (u32)sizeof (product_compact_owner_assignment_t), (u32)sizeof (product_transport_metadata_t),
    (u32)sizeof (product_platform_packet_facts_t), (u32)sizeof (product_adapter_obligation_t),
    (u32)_Alignof (product_buffer_metadata_t),
    (u32)offsetof (product_buffer_platform_metadata_t, platform),
    (u32)offsetof (product_buffer_metadata_t, transport),
    (u32)offsetof (product_buffer_metadata_t, span_current_data));
  vlib_cli_output (vm, "metadata.check roundtrip=%u data_guard=%u length_guard=%u generation_guard=%u buffer_return=1",
    ok, data_guard, length_guard, generation_guard);
  return ok && data_guard && length_guard && generation_guard ? 0
    : clib_error_return (0, "metadata check failed");
}
VLIB_CLI_COMMAND (product_metadata_check_command, static) = {
  .path = "product metadata check", .function = product_metadata_check_cli,
};
#endif

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#include "product_flow_collision_check.inc"
#endif

static clib_error_t *
product_flow_startup_config (vlib_main_t *vm, unformat_input_t *input)
{
  (void) vm;
  u64 capacity = 1024; /* Check before narrowing: unformat %u truncates u64. */
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    if (!unformat (input, "entries %llu", &capacity) || !capacity
        || capacity > UINT32_MAX / 4)
      return clib_error_return (0, "product-flow-runtime: expected entries <positive capacity>");
  product_packet_graph_main.flow_capacity = (u32) capacity;
  return 0;
}
VLIB_CONFIG_FUNCTION (product_flow_startup_config, "product-flow-runtime");

static clib_error_t *
product_packet_graph_init (vlib_main_t *vm)
{
  if (product_lpi_init ())
    return clib_error_return (0, "application protocol registry initialization failed");
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 worker;
  graph->vlib_main = vm;
  clib_error_t *flow_end_error = product_flow_end_init (vm);
  if (flow_end_error)
    return flow_end_error;
  /* Storage belongs to an Adapter generation and is allocated at start. */
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    clib_atomic_store_rel_n (&graph->handoff_credits[worker],
                             PRODUCT_GRAPH_HANDOFF_CREDITS);
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  graph->ingress_frame_queue =
    vlib_frame_queue_main_init (product_packet_test_ingress_node.index, 0);
#endif
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  product_metadata_injection_frame_queue =
    vlib_frame_queue_main_init (product_packet_admit_node.index, 64);
  product_completion_probe_frame_queue =
    vlib_frame_queue_main_init (product_packet_origin_completion_node.index, 64);
#endif
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  graph->owner_guard_frame_queue =
    vlib_frame_queue_main_init (product_packet_owner_guard_node.index, 0);
#else
  graph->primary_frame_queue =
    vlib_frame_queue_main_init (product_packet_policy_node.index, 64);
  graph->completion_return_frame_queue =
    vlib_frame_queue_main_init (product_packet_origin_completion_node.index, 128);
#endif
  return 0;
}

VLIB_INIT_FUNCTION (product_packet_graph_init);

/* Called on the API main thread. One bounded copy under the worker barrier. */
int product_packet_graph_sni_query (uint64_t generation, uint32_t worker,
  uint32_t slot, uint64_t incarnation, sakamoto_product_sni_status_t *out)
{
  memset(out,0,sizeof *out);
  product_packet_graph_main_t *graph=&product_packet_graph_main;
  if(!generation || generation!=graph->generation || worker>=PRODUCT_GRAPH_WORKERS)
    return -5;
  vlib_main_t *vm=vlib_get_main();
  vlib_worker_thread_barrier_sync(vm);
  const product_flow_entry_t *entry=product_flow_runtime_entry(graph->flow_pools[worker],slot);
  int rv=-5;
  if(entry && entry->linked && entry->incarnation==incarnation) {
    out->generation=generation;out->incarnation=incarnation;out->worker=worker;out->slot=slot;
    out->protocols=entry->lpi.protocols;out->protocols_available=entry->lpi.available;
    out->result=entry->sni.result;out->stop=entry->sni.stop;out->attempts=entry->sni.attempts;
    out->bytes=entry->sni.bytes;out->work=entry->sni.work;
    out->cache_bytes=entry->tcp_bytes.length[0]+entry->tcp_bytes.length[1];
    out->name_length=entry->sni.name_length;memcpy(out->name,entry->sni.name,sizeof out->name);
    rv=0;
  }
  vlib_worker_thread_barrier_release(vm);
  return rv;
}
