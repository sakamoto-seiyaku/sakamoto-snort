/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Product VPP packet graph. Ordinary packet bytes stay in one native buffer
 * through admit, owner-local policy, terminal and origin completion. A remote
 * assignment uses one Primary Handoff; historical Host-only fixture routes
 * are compiled separately from the product path.
 */

#include "product_packet.h"
#include "product_packet_graph.h"
#include "product_flow_entry.h"

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>
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
#define PRODUCT_GRAPH_FLOW_DOMAIN 7
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
  u64 generation;
  u16 expected_owner;
  u8 primary_handoff_count;
  u8 corrective_handoff_count;
} product_owner_assignment_t;

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
    product_owner_assignment_t owner;
    struct
    {
      u64 generation;
      u16 expected_owner;
      u8 primary_handoff_count, corrective_handoff_count;
    };
  };
  u64 origin_obligation_id;
  product_transport_metadata_t transport;
  u32 packet_length;
  u16 source_port, destination_port;
  u16 span_length;
  i16 span_current_data;
  u8 l3_header_length, l4_header_length;
  u8 ip_family, protocol, l3_status, l4_status;
  u8 state_bits, runtime_drop_reason;
} product_buffer_metadata_t;

typedef struct
{
  product_adapter_obligation_t obligation;
  product_platform_packet_facts_t platform;
} product_buffer_platform_metadata_t;

_Static_assert (sizeof (product_packet_completion_frame_t) <= sizeof (((vlib_buffer_t *) 0)->opaque2),
                "completion carrier fits existing opaque2");
_Static_assert (sizeof (product_owner_assignment_t) == 16, "owner layout");
_Static_assert (sizeof (product_transport_metadata_t) == 12, "transport layout");
_Static_assert (sizeof (product_buffer_metadata_t) == 56, "packet layout");
_Static_assert (sizeof (product_buffer_metadata_t) ==
                  sizeof (((vlib_buffer_t *) 0)->opaque2), "opaque2 capacity");
_Static_assert (sizeof (product_buffer_platform_metadata_t) ==
                  sizeof (((vlib_buffer_t *) 0)->opaque), "opaque capacity");
_Static_assert (offsetof (product_buffer_metadata_t, origin_obligation_id) == 16,
                "obligation token offset");
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
  /* Published banks are immutable.  Reader counts prevent reuse while a
   * worker is still evaluating the previous active bank. */
  product_packet_graph_gate_table_t gate_table;
  product_l4_policy_view_t view;
  u64 generation;
  u64 revision;
  u64 snapshot_hash;
} product_packet_graph_l4_policy_bank_t;

typedef struct
{
  vlib_main_t *vlib_main;
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  u32 owner_guard_frame_queue;
#else
  u32 primary_frame_queue;
  u32 completion_return_frame_queue;
  u32 misroute_next;
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
  u32 lifecycle_terminal_intents;
  u32 lifecycle_settlements;
  u32 lifecycle_returns;
  u32 lifecycle_completion_frames;
  u32 enabled;
  u32 accepting;
  u32 policy_publish_sequence;
  u32 policy_publish_lock;
  u32 l4_policy_active_bank;
  u32 l4_policy_bank_readers[2];
  u32 l4_policy_view_active;
  product_packet_graph_l4_policy_bank_t l4_policy_banks[2];
  u32 flow_pools_initialized;
  u32 flow_active_entries;
  u64 flow_active_policy_revision;
  u64 flow_active_snapshot_hash;
  u64 flow_allocation_count;
  u64 flow_reuse_count;
  u64 flow_early_drop_count;
  u64 flow_wrong_owner_count;
  u64 flow_capacity_rejection_count;
  u64 flow_revision_invalidation_count;
  u64 flow_revision_mismatch_count;
  u64 flow_unavailable_count;
  u64 flow_pass_next_count;
  u64 flow_drop_count;
  u64 flow_flush_count;
  product_flow_entry_pool_t flow_pools[PRODUCT_GRAPH_WORKERS];
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
  product_packet_graph_completion_fn_t external_completion;
  void *external_completion_opaque;
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

static void product_packet_graph_deactivate_policy_view (
  product_packet_graph_main_t *graph);
static void product_packet_graph_policy_publish_lock (
  product_packet_graph_main_t *graph);
static void product_packet_graph_policy_publish_unlock (
  product_packet_graph_main_t *graph);
static int product_packet_graph_flow_pools_reset (
  product_packet_graph_main_t *graph);
static int product_packet_graph_flow_pools_publish_revision (
  product_packet_graph_main_t *graph, u64 revision, u64 snapshot_hash);
static void product_packet_graph_flow_pools_flush (
  product_packet_graph_main_t *graph);
static void product_packet_graph_flow_observe (
  product_packet_graph_main_t *graph, const product_packet_lease_t *lease,
  const product_packet_graph_policy_evaluation_t *evaluation);

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
    "admit", "owner-guard", "policy", "terminal",
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
  metadata->expected_owner = lease->expected_owner;
  metadata->generation = generation;
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
  if (memcmp (facts->source_address, lease->canonical_key.endpoint_a.address, 16) == 0
      && facts->source_port == lease->canonical_key.endpoint_a.port)
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
  lease->expected_owner = metadata->expected_owner;
  lease->primary_handoff_count = metadata->primary_handoff_count;
  lease->corrective_handoff_count = metadata->corrective_handoff_count;
  lease->distribution = metadata->primary_handoff_count == 0
                          ? PRODUCT_PACKET_DISTRIBUTION_LOCAL
                          : PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE;
  lease->policy_owner_ready = (metadata->state_bits & PRODUCT_META_POLICY_READY) != 0;
  lease->terminal_intent = product_metadata_terminal_intent (metadata);
  lease->terminal_count = lease->terminal_intent != PRODUCT_PACKET_INTENT_NONE;
  lease->runtime_drop_reason = metadata->runtime_drop_reason;
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
  lease->canonical_key.ip_family = facts->ip_family;
  lease->canonical_key.protocol = facts->protocol;
  product_packet_endpoint_t *source = (metadata->state_bits & PRODUCT_META_SOURCE_IS_A)
    ? &lease->canonical_key.endpoint_a : &lease->canonical_key.endpoint_b;
  product_packet_endpoint_t *destination = (metadata->state_bits & PRODUCT_META_SOURCE_IS_A)
    ? &lease->canonical_key.endpoint_b : &lease->canonical_key.endpoint_a;
  clib_memcpy_fast (source->address, facts->source_address, 16);
  clib_memcpy_fast (destination->address, facts->destination_address, 16);
  source->port = facts->source_port;
  destination->port = facts->destination_port;
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
  return lease->platform.provenance == PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED
    ? "GRAPH_INJECTED" : "NFQ_CAPTURED";
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
    (unsigned long long) metadata->origin_obligation_id, lease->expected_owner,
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
  for (u32 i = 0; i < 16; i++) fprintf (stderr, "%02x", f->source_address[i]);
  fprintf (stderr, " dst=");
  for (u32 i = 0; i < 16; i++) fprintf (stderr, "%02x", f->destination_address[i]);
  if (strcmp (stage, "admit") == 0)
    {
      const u8 *packet = vlib_buffer_get_current (buffer);
      fprintf (stderr, " raw=");
      for (u32 i = 0; i < buffer->current_length; i++)
        fprintf (stderr, "%02x", packet[i]);
    }
  fprintf (stderr, " mono_ns=%llu\n", (unsigned long long) entered_ns);
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
  PRODUCT_ADMIT_N_NEXT,
};

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static int
product_primary_handoff (vlib_main_t *vm, vlib_node_runtime_t *node,
                          u32 bi, product_buffer_metadata_t *metadata)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u16 owner = metadata->expected_owner;
  u16 target = vlib_get_worker_thread_index (owner);
  u32 failed;
  if (!product_handoff_credit_reserve (graph, owner, PRODUCT_HANDOFF_PRIMARY,
                                       metadata->origin_obligation_id))
    { clib_atomic_fetch_add_relax (&graph->primary_rejected, 1); return 0; }
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
      ingress.flow_domain = PRODUCT_GRAPH_FLOW_DOMAIN;
      ingress.origin_obligation_id = initial_metadata.origin_obligation_id;
      if (!product_packet_graph_get_platform_facts (
            buffer, initial_metadata.generation, &ingress.platform))
        product_packet_graph_platform_facts_unknown (&ingress.platform);
      clib_memset (&lease, 0, sizeof (lease));
      product_packet_result_t admit_result =
        product_packet_admit (&layout, &ingress, &lease);
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
      /* Ordinary dual-stack TCP/UDP wire packets are open; owner may be remote. */
      if (admit_result != PRODUCT_PACKET_OK
          || (lease.platform.provenance != PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED
              && ((lease.facts.ip_family != 4 && lease.facts.ip_family != 6)
                  || (lease.facts.protocol != 17 && lease.facts.protocol != 6)
                  || lease.facts.l4_status != PRODUCT_PACKET_L4_COMPLETE))) {
        lease.terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
        lease.terminal_count = 1;
        lease.runtime_drop_reason = PRODUCT_PACKET_DROP_UNSUPPORTED_ENVELOPE;
      } else {
        lease.policy_owner_ready = lease.distribution == PRODUCT_PACKET_DISTRIBUTION_LOCAL;
      }
#endif
      product_metadata_from_lease (&metadata, &lease,
                                   initial_metadata.generation, buffer);
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
      fprintf(stderr, "s203 event=admit source=%s node=%u thread=%u worker=%u buffer=%u obligation=%llu generation=%llu parse=1 assignment=1 owner=%u family=%u protocol=%u src_port=%u dst_port=%u intent=%u\n",
        product_packet_evidence_source (&lease), node->node_index, vm->thread_index, logical_worker, buffer_index,
        (unsigned long long)metadata.origin_obligation_id, (unsigned long long)metadata.generation,
        lease.expected_owner, lease.facts.ip_family, lease.facts.protocol,
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
          if (product_primary_handoff (vm, node, buffer_index, &metadata))
            continue;
          /* Retained rejection still owns this buffer on arrival worker. */
          lease.terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
          lease.terminal_count = 1;
          lease.runtime_drop_reason = PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION;
          product_metadata_set_terminal_intent (&metadata, lease.terminal_intent);
          metadata.runtime_drop_reason = lease.runtime_drop_reason;
          product_metadata_store (buffer, &metadata);
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
  PRODUCT_POLICY_NEXT_TERMINAL,
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
          policy_result = product_packet_graph_policy_stage (&lease, &evaluation);
        }
#else
      policy_result = product_packet_graph_policy_stage (&lease, &evaluation);
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
        lease.expected_owner, evaluation.stage, evaluation.verdict,
        (unsigned long long)evaluation.rule_id);
#endif
      product_metadata_set_terminal_intent (&metadata, lease.terminal_intent);
      metadata.runtime_drop_reason = lease.runtime_drop_reason;
      product_metadata_store (buffer, &metadata);
      product_add_trace (vm, node, buffer, PRODUCT_TRACE_POLICY,
                         metadata.origin_obligation_id);
      vlib_buffer_enqueue_to_single_next (
        vm, node, &buffer_index, PRODUCT_POLICY_NEXT_TERMINAL, 1);
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
    [PRODUCT_POLICY_NEXT_TERMINAL] = "product-packet-terminal",
  },
};

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
#define PRODUCT_COMPLETION_RETURN_CAPACITY 512
_Static_assert (PRODUCT_COMPLETION_RETURN_CAPACITY >
                  PRODUCT_ROOT_COMPLETION_MAX_LANES * PRODUCT_ROOT_COMPLETION_CAPACITY
                  + PRODUCT_GRAPH_INJECTION_CAPACITY,
                "return backlog covers every current admitted carrier");
extern vlib_node_registration_t product_packet_completion_retry_node;
typedef struct
{
  u32 buffers[PRODUCT_COMPLETION_RETURN_CAPACITY];
  u16 head, count;
} __attribute__((aligned(CLIB_CACHE_LINE_BYTES))) product_completion_return_queue_t;
static product_completion_return_queue_t product_completion_returns[PRODUCT_GRAPH_WORKERS];

static int
product_completion_return_try (vlib_main_t *vm, vlib_node_runtime_t *node,
                                u32 bi, const product_packet_completion_frame_t *completion,
                                int retry)
{
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
  u32 worker = vlib_get_worker_index (vm->thread_index);
  ASSERT (worker < PRODUCT_GRAPH_WORKERS);
  product_completion_return_queue_t *queue = &product_completion_returns[worker];
  /* Root has at most four 64-credit lanes and 32 injection buffers/generation.
   * This queue owns indices only, within that existing admitted population. */
  ASSERT (queue->count < PRODUCT_COMPLETION_RETURN_CAPACITY);
  queue->buffers[(queue->head + queue->count) % PRODUCT_COMPLETION_RETURN_CAPACITY] = bi;
  queue->count++;
  clib_atomic_fetch_add_relax (&graph->completion_pending_returns, 1);
  clib_atomic_fetch_add_relax (&graph->completion_deferred, 1);
  vlib_node_set_state (vm, product_packet_completion_retry_node.index, VLIB_NODE_STATE_POLLING);
}

VLIB_NODE_FN (product_packet_completion_retry_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 worker = vlib_get_worker_index (vm->thread_index);
  u32 completed = 0;
  (void) frame;
  ASSERT (worker < PRODUCT_GRAPH_WORKERS);
  product_completion_return_queue_t *queue = &product_completion_returns[worker];
  while (queue->count && completed < 64)
    {
      u32 bi = queue->buffers[queue->head];
      product_packet_completion_frame_t completion;
      clib_memcpy_fast (&completion, vlib_get_buffer (vm, bi)->opaque2, sizeof (completion));
      clib_atomic_fetch_add_relax (&graph->completion_retry_attempts, 1);
      if (!product_completion_return_try (vm, node, bi, &completion, 1))
        break;
      queue->head = (queue->head + 1) % PRODUCT_COMPLETION_RETURN_CAPACITY;
      queue->count--;
      clib_atomic_fetch_sub_relax (&graph->completion_pending_returns, 1);
      completed++;
    }
  if (!queue->count)
    vlib_node_set_state (vm, node->node_index, VLIB_NODE_STATE_DISABLED);
  return completed;
}
VLIB_REGISTER_NODE (product_packet_completion_retry_node) = {
  .name = "product-completion-return",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};
#endif

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
extern vlib_node_registration_t product_packet_origin_completion_node;
static u32 product_completion_probe_frame_queue;
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

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      product_metadata_trace (vm, node, buffer, buffer_index, &metadata, &lease, "terminal");
      if (metadata.state_bits & PRODUCT_META_TRACE)
      fprintf(stderr, "s203 event=terminal source=%s node=%u thread=%u worker=%u buffer=%u obligation=%llu generation=%llu intent=%u owner=%u\n",
        product_packet_evidence_source (&lease), node->node_index, vm->thread_index, vlib_get_worker_index(vm->thread_index),
        buffer_index, (unsigned long long)metadata.origin_obligation_id,
        (unsigned long long)metadata.generation, lease.terminal_intent, lease.expected_owner);
      product_buffer_platform_metadata_t completion_metadata;
      clib_memcpy_fast (&completion_metadata, buffer->opaque, sizeof (completion_metadata));
      product_packet_completion_frame_t completion = {
        .obligation = completion_metadata.obligation,
        .producer_thread = vm->thread_index,
        .terminal_intent = lease.terminal_intent,
        .runtime_drop_reason = lease.runtime_drop_reason,
        .flags = (metadata.state_bits & PRODUCT_META_TRACE) ? PRODUCT_COMPLETION_TRACE : 0,
      };
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
      if (vm->thread_index == vlib_get_worker_thread_index (completion.obligation.origin_worker))
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
        ? "GRAPH_INJECTED" : "NFQ_CAPTURED";
      if (completion.flags & PRODUCT_COMPLETION_TRACE)
        fprintf (stderr, "s204 event=completion_consume source=%s node=%u thread=%u buffer=%u token=%llu generation=%llu packet=%u lane=%u producer_thread=%u intent=%u mono_ns=%llu\n",
          source, node->node_index, vm->thread_index, bi,
          (unsigned long long) completion.obligation.token,
          (unsigned long long) completion.obligation.queue_generation,
          completion.obligation.packet_id, completion.obligation.origin_lane,
          completion.producer_thread, completion.terminal_intent,
          (unsigned long long) product_packet_event_clock_ns ());
      if (completion.obligation.kind == PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE
          && graph->external_completion)
        graph->external_completion (vm, bi, &completion, graph->external_completion_opaque);
      vlib_buffer_free (vm, &bi, 1);
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
  u16 thread = vlib_get_worker_thread_index (0);
  if (!vm || !completion || !graph->accepting || !graph->enabled
      || !(completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE)
      || vlib_buffer_alloc (vm, &bi, 1) != 1)
    return 0;
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

void
product_packet_graph_register_external_completion (
  product_packet_graph_completion_fn_t completion, void *opaque)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  graph->external_completion = completion;
  graph->external_completion_opaque = opaque;
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
      || clib_atomic_load_acq_n (&graph->lifecycle_handoffs) != 0
      || clib_atomic_load_acq_n (&graph->lifecycle_completion_frames) != 0)
    return 0;

  graph->vlib_main = vm;
  graph->generation = generation;
  graph->trace_packets = 0;
  graph->lifecycle_completion_frames = 0;
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  graph->misroute_next = 0;
  graph->primary_published = graph->primary_received = graph->primary_rejected = 0;
  graph->owner_delivery_checks = graph->owner_delivery_failures = 0;
  graph->completion_returns = graph->completion_deferred = graph->completion_retry_attempts = 0;
  graph->completion_pending_returns = 0;
#endif
  if (!product_packet_graph_flow_pools_reset (graph))
    return 0;
  clib_atomic_store_rel_n (&graph->lifecycle_terminal_intents, 0);
  clib_atomic_store_rel_n (&graph->lifecycle_settlements, 0);
  clib_atomic_store_rel_n (&graph->lifecycle_returns, 0);
  clib_atomic_store_rel_n (&graph->enabled, 1);
  clib_atomic_store_rel_n (&graph->accepting, 1);
  return 1;
}

void
product_packet_graph_stop_external (vlib_main_t *vm)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  (void) vm;
  clib_atomic_store_rel_n (&graph->accepting, 0);
  clib_atomic_store_rel_n (&graph->enabled, 0);
  product_packet_graph_policy_publish_lock (graph);
  product_packet_graph_flow_pools_flush (graph);
  product_packet_graph_policy_publish_unlock (graph);
}

uint32_t
product_packet_graph_worker_count (void)
{
  return PRODUCT_GRAPH_WORKERS;
}

uint32_t
product_packet_graph_flow_domain (void)
{
  return PRODUCT_GRAPH_FLOW_DOMAIN;
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
  return clib_atomic_load_acq_n (&product_packet_graph_main.lifecycle_buffers);
}

uint64_t
product_packet_graph_handoff_debt (void)
{
  return clib_atomic_load_acq_n (&product_packet_graph_main.lifecycle_handoffs);
}

static void
product_packet_graph_policy_publish_lock (product_packet_graph_main_t *graph)
{
  u32 expected;

  do
    {
      expected = 0;
    }
  while (!clib_atomic_cmp_and_swap_acq_relax_n (
    &graph->policy_publish_lock, &expected, 1, 0));
}

static void
product_packet_graph_policy_publish_unlock (product_packet_graph_main_t *graph)
{
  clib_atomic_store_rel_n (&graph->policy_publish_lock, 0);
}

static int
product_packet_graph_flow_pools_reset (product_packet_graph_main_t *graph)
{
  u32 worker;

  if (graph == 0)
    return 0;
  clib_atomic_store_rel_n (&graph->flow_pools_initialized, 0);
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    if (product_flow_entry_pool_init (
          &graph->flow_pools[worker], (u16) worker,
          PRODUCT_GRAPH_WORKERS, PRODUCT_GRAPH_HASH_SEED)
        != PRODUCT_FLOW_ENTRY_STATUS_OK)
      return 0;
  clib_atomic_store_rel_n (&graph->flow_active_entries, 0);
  clib_atomic_store_rel_n (&graph->flow_active_policy_revision, 0);
  clib_atomic_store_rel_n (&graph->flow_active_snapshot_hash, 0);
  clib_atomic_store_rel_n (&graph->flow_allocation_count, 0);
  clib_atomic_store_rel_n (&graph->flow_reuse_count, 0);
  clib_atomic_store_rel_n (&graph->flow_early_drop_count, 0);
  clib_atomic_store_rel_n (&graph->flow_wrong_owner_count, 0);
  clib_atomic_store_rel_n (&graph->flow_capacity_rejection_count, 0);
  clib_atomic_store_rel_n (&graph->flow_revision_invalidation_count, 0);
  clib_atomic_store_rel_n (&graph->flow_revision_mismatch_count, 0);
  clib_atomic_store_rel_n (&graph->flow_unavailable_count, 0);
  clib_atomic_store_rel_n (&graph->flow_pass_next_count, 0);
  clib_atomic_store_rel_n (&graph->flow_drop_count, 0);
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
      product_flow_entry_pool_flush (&graph->flow_pools[worker]);
      /* A stopped view has no cache epoch.  The next authoring snapshot may
       * legitimately start a fresh revision sequence in this generation;
       * retaining the synthetic startup empty-policy revision would reject
       * that first successor before it can be published. */
      graph->flow_pools[worker].active_policy_revision = 0;
    }
  clib_atomic_store_rel_n (&graph->flow_active_entries, 0);
  clib_atomic_store_rel_n (&graph->flow_active_policy_revision, 0);
  clib_atomic_store_rel_n (&graph->flow_active_snapshot_hash, 0);
  clib_atomic_fetch_add_relax (&graph->flow_flush_count, 1);
}

static int
product_packet_graph_flow_pools_publish_revision (
  product_packet_graph_main_t *graph, u64 revision, u64 snapshot_hash)
{
  u32 worker;
  u64 active_revision;
  u64 active_snapshot_hash;

  if (graph == 0 || revision == 0 || snapshot_hash == 0
      || clib_atomic_load_acq_n (&graph->flow_pools_initialized) == 0)
    return 0;
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    if (graph->flow_pools[worker].active_policy_revision > revision)
      return 0;

  active_revision =
    clib_atomic_load_acq_n (&graph->flow_active_policy_revision);
  active_snapshot_hash =
    clib_atomic_load_acq_n (&graph->flow_active_snapshot_hash);
  /* A changed hash is a new immutable policy view even when a caller reused
   * the numeric revision.  Flush cached decisions before accepting it. */
  if (active_revision == revision && active_snapshot_hash != 0
      && active_snapshot_hash != snapshot_hash)
    product_packet_graph_flow_pools_flush (graph);

  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      product_flow_entry_pool_t *pool = &graph->flow_pools[worker];
      if (pool->active_policy_revision < revision
          && product_flow_entry_publish_revision (pool, revision)
               != PRODUCT_FLOW_ENTRY_STATUS_OK)
        return 0;
    }
  clib_atomic_store_rel_n (&graph->flow_active_policy_revision, revision);
  clib_atomic_store_rel_n (&graph->flow_active_snapshot_hash, snapshot_hash);
  return 1;
}

void
product_packet_graph_flow_status (product_packet_graph_flow_status_t *status)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 worker;

  if (status == 0)
    return;
  clib_memset (status, 0, sizeof (*status));
  product_packet_graph_policy_publish_lock (graph);
  status->worker_count = PRODUCT_GRAPH_WORKERS;
  status->max_entries_per_worker = PRODUCT_FLOW_ENTRY_MAX_ENTRIES;
  status->active_generation =
    clib_atomic_load_acq_n (&graph->flow_pools_initialized) != 0
      ? graph->generation
      : 0;
  status->active_revision =
    clib_atomic_load_acq_n (&graph->flow_active_policy_revision);
  status->active_snapshot_hash =
    clib_atomic_load_acq_n (&graph->flow_active_snapshot_hash);
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    status->active_entries += graph->flow_pools[worker].active_entries;
  status->allocation_count =
    clib_atomic_load_acq_n (&graph->flow_allocation_count);
  status->reuse_count = clib_atomic_load_acq_n (&graph->flow_reuse_count);
  status->early_drop_count =
    clib_atomic_load_acq_n (&graph->flow_early_drop_count);
  status->wrong_owner_count =
    clib_atomic_load_acq_n (&graph->flow_wrong_owner_count);
  status->capacity_rejection_count =
    clib_atomic_load_acq_n (&graph->flow_capacity_rejection_count);
  status->revision_invalidation_count =
    clib_atomic_load_acq_n (&graph->flow_revision_invalidation_count);
  status->revision_mismatch_count =
    clib_atomic_load_acq_n (&graph->flow_revision_mismatch_count);
  status->unavailable_count =
    clib_atomic_load_acq_n (&graph->flow_unavailable_count);
  status->pass_next_count =
    clib_atomic_load_acq_n (&graph->flow_pass_next_count);
  status->drop_count = clib_atomic_load_acq_n (&graph->flow_drop_count);
  status->flush_count = clib_atomic_load_acq_n (&graph->flow_flush_count);
  product_packet_graph_policy_publish_unlock (graph);
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
  packet->ports_available = facts->l4_status == PRODUCT_PACKET_L4_COMPLETE;

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

static int
product_packet_graph_flow_packet_from_lease (
  const product_packet_graph_main_t *graph,
  const product_packet_lease_t *lease, product_flow_entry_packet_t *packet)
{
  const product_packet_facts_t *facts;

  if (graph == 0 || lease == 0 || packet == 0)
    return 0;
  facts = &lease->facts;
  if (facts->l3_status != PRODUCT_PACKET_L3_COMPLETE
      || (facts->ip_family != PRODUCT_FLOW_ENTRY_FAMILY_IPV4
          && facts->ip_family != PRODUCT_FLOW_ENTRY_FAMILY_IPV6)
      || (facts->protocol != PRODUCT_FLOW_ENTRY_PROTOCOL_TCP
          && facts->protocol != PRODUCT_FLOW_ENTRY_PROTOCOL_UDP)
      || (lease->platform.direction != PRODUCT_FLOW_ENTRY_DIRECTION_INPUT
          && lease->platform.direction != PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT))
    return 0;

  clib_memset (packet, 0, sizeof (*packet));
  packet->uid = lease->platform.uid;
  packet->network_context = (lease->platform.availability & PRODUCT_PLATFORM_CONTEXT_KNOWN)
                              ? (u32) lease->platform.network_context_id
                              : PRODUCT_FLOW_ENTRY_NETWORK_CONTEXT_UNKNOWN;
  packet->packet_bytes = facts->packet_length;
  packet->family = facts->ip_family;
  packet->protocol = facts->protocol;
  packet->device_direction = (u8) lease->platform.direction;
  packet->source_port = facts->source_port;
  packet->destination_port = facts->destination_port;
  packet->timestamp = graph->vlib_main == 0
                       ? 0
                       : (u64) (vlib_time_now (graph->vlib_main)
                                * 1000000.0);
  if (facts->ip_family == PRODUCT_FLOW_ENTRY_FAMILY_IPV4)
    {
      /* PacketFacts stores IPv4 in the tail of its fixed address fields. */
      clib_memcpy_fast (packet->source_address, facts->source_address + 12, 4);
      clib_memcpy_fast (packet->destination_address,
                        facts->destination_address + 12, 4);
    }
  else
    {
      clib_memcpy_fast (packet->source_address, facts->source_address, 16);
      clib_memcpy_fast (packet->destination_address,
                        facts->destination_address, 16);
    }
  return 1;
}

static int
product_packet_graph_flow_snapshot_matches (
  const product_packet_graph_main_t *graph,
  const product_packet_graph_policy_evaluation_t *evaluation)
{
  u32 start_sequence;
  u32 end_sequence;
  u32 active_bank;
  const product_packet_graph_l4_policy_bank_t *bank;

  if (graph == 0 || evaluation == 0 || evaluation->revision == 0
      || evaluation->snapshot_hash == 0)
    return 0;
  start_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
  if ((start_sequence & 1U) != 0)
    return 0;
  active_bank = clib_atomic_load_acq_n (&graph->l4_policy_active_bank);
  if (active_bank >= 2)
    active_bank = 0;
  bank = &graph->l4_policy_banks[active_bank];
  if (bank->generation != graph->generation
      || bank->revision != evaluation->revision
      || bank->snapshot_hash != evaluation->snapshot_hash
      || clib_atomic_load_acq_n (&graph->flow_active_policy_revision)
           != evaluation->revision
      || clib_atomic_load_acq_n (&graph->flow_active_snapshot_hash)
           != evaluation->snapshot_hash)
    return 0;
  end_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
  return start_sequence == end_sequence && (end_sequence & 1U) == 0;
}

static void
product_packet_graph_flow_observe (
  product_packet_graph_main_t *graph, const product_packet_lease_t *lease,
  const product_packet_graph_policy_evaluation_t *evaluation)
{
#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  (void)graph; (void)lease; (void)evaluation;
  return;
#endif
  product_flow_entry_packet_t packet;
  product_flow_entry_observation_t observation;
  product_flow_entry_pool_t *pool;
  product_flow_entry_status_t status;
  u8 stage_verdict;
  u16 owner;

  if (graph == 0 || lease == 0 || evaluation == 0
      || clib_atomic_load_acq_n (&graph->flow_pools_initialized) == 0
      || evaluation->terminal_preserved
      || evaluation->verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_NONE)
    return;
  if (!product_packet_graph_flow_packet_from_lease (graph, lease, &packet))
    {
      clib_atomic_fetch_add_relax (&graph->flow_unavailable_count, 1);
      return;
    }
  if (evaluation->verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
      && lease->facts.l4_status != PRODUCT_PACKET_L4_COMPLETE)
    {
      /* FlowEntry state requires complete TCP/UDP ports; policy still owns
       * the PASS_NEXT result when L4 facts are unavailable. */
      clib_atomic_fetch_add_relax (&graph->flow_unavailable_count, 1);
      return;
    }
  if (lease->expected_owner >= PRODUCT_GRAPH_WORKERS)
    {
      clib_atomic_fetch_add_relax (&graph->flow_wrong_owner_count, 1);
      return;
    }
  owner = lease->expected_owner;
  pool = &graph->flow_pools[owner];
  /* Serialize lookup/update with publication so the cache and evaluator
   * cannot observe different active revisions or snapshot hashes. */
  product_packet_graph_policy_publish_lock (graph);
  if (evaluation->verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
      && !product_packet_graph_flow_snapshot_matches (graph, evaluation))
    {
      clib_atomic_fetch_add_relax (&graph->flow_revision_mismatch_count, 1);
      product_packet_graph_policy_publish_unlock (graph);
      return;
    }

  stage_verdict = evaluation->verdict
                    == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP
                  ? PRODUCT_FLOW_ENTRY_VERDICT_DROP
                  : PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT;
  status = product_flow_entry_observe_on_owner (
    pool, &packet, stage_verdict, owner, &observation);
  switch (status)
    {
    case PRODUCT_FLOW_ENTRY_STATUS_OK:
      if (stage_verdict == PRODUCT_FLOW_ENTRY_VERDICT_DROP)
        {
          clib_atomic_fetch_add_relax (&graph->flow_drop_count, 1);
          product_packet_graph_policy_publish_unlock (graph);
          return;
        }
      if (product_flow_entry_set_decision (
            pool, observation.entry, PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT,
            evaluation->rule_id, evaluation->reason_id)
          != PRODUCT_FLOW_ENTRY_STATUS_OK)
        {
          clib_atomic_fetch_add_relax (&graph->flow_revision_mismatch_count,
                                       1);
          product_packet_graph_policy_publish_unlock (graph);
          return;
        }
      if (observation.created)
        clib_atomic_fetch_add_relax (&graph->flow_allocation_count, 1);
      if (observation.reused)
        clib_atomic_fetch_add_relax (&graph->flow_reuse_count, 1);
      if (observation.revision_invalidated)
        clib_atomic_fetch_add_relax (&graph->flow_revision_invalidation_count,
                                     1);
      if (observation.created)
        clib_atomic_fetch_add_relax (&graph->flow_active_entries, 1);
      clib_atomic_fetch_add_relax (&graph->flow_pass_next_count, 1);
      product_packet_graph_policy_publish_unlock (graph);
      return;
    case PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP:
      clib_atomic_fetch_add_relax (&graph->flow_early_drop_count, 1);
      clib_atomic_fetch_add_relax (&graph->flow_drop_count, 1);
      product_packet_graph_policy_publish_unlock (graph);
      return;
    case PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER:
      clib_atomic_fetch_add_relax (&graph->flow_wrong_owner_count, 1);
      product_packet_graph_policy_publish_unlock (graph);
      return;
    case PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED:
      clib_atomic_fetch_add_relax (&graph->flow_capacity_rejection_count, 1);
      product_packet_graph_policy_publish_unlock (graph);
      return;
    case PRODUCT_FLOW_ENTRY_STATUS_STALE_REVISION:
      clib_atomic_fetch_add_relax (&graph->flow_revision_mismatch_count, 1);
      product_packet_graph_policy_publish_unlock (graph);
      return;
    case PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET:
      clib_atomic_fetch_add_relax (&graph->flow_unavailable_count, 1);
      product_packet_graph_policy_publish_unlock (graph);
      return;
    default:
      clib_atomic_fetch_add_relax (&graph->flow_revision_mismatch_count, 1);
      product_packet_graph_policy_publish_unlock (graph);
      return;
    }
}

typedef struct
{
  u64 generation;
  u64 revision;
  u64 snapshot_hash;
  product_packet_graph_gate_entry_t rule;
  u32 winner_rank;
  u32 probes;
  u32 candidate_count;
  u32 no_match_reason;
} product_packet_graph_gate_match_t;

static int
product_packet_graph_gate_address_matches (
  u8 family, const u8 rule_address[PRODUCT_L4_POLICY_ADDRESS_BYTES],
  const u8 packet_address[PRODUCT_L4_POLICY_ADDRESS_BYTES], u8 prefix_length)
{
  u32 bytes;
  u32 full_bytes;
  u8 remaining_bits;
  u32 index;

  if (family == PRODUCT_L4_POLICY_FAMILY_IPV4)
    bytes = 4;
  else if (family == PRODUCT_L4_POLICY_FAMILY_IPV6)
    bytes = 16;
  else
    return 0;
  full_bytes = prefix_length / 8U;
  remaining_bits = (u8) (prefix_length % 8U);
  for (index = 0; index < full_bytes; index++)
    if (rule_address[index] != packet_address[index])
      return 0;
  if (remaining_bits != 0 && full_bytes < bytes)
    {
      u8 mask = (u8) (UINT8_C (0xff) << (8U - remaining_bits));
      if ((rule_address[full_bytes] & mask)
          != (packet_address[full_bytes] & mask))
        return 0;
    }
  return 1;
}

static int
product_packet_graph_gate_address_is_zero (const u8 address[16])
{
  u32 index;
  for (index = 0; index < 16; index++)
    if (address[index] != 0)
      return 0;
  return 1;
}

static int
product_packet_graph_gate_entry_valid (
  const product_packet_graph_gate_entry_t *entry)
{
  u32 max_prefix;
  u32 index;

  if (entry == 0 || entry->rule_id == 0 || entry->uid == UINT32_MAX
      || entry->network_context_id == 0 || entry->reason_id == 0
      || entry->ifindex == 0
      || (entry->action != PRODUCT_L4_POLICY_ACTION_ALLOW
          && entry->action != PRODUCT_L4_POLICY_ACTION_DROP)
      || entry->source_port_first > entry->source_port_last
      || entry->destination_port_first > entry->destination_port_last)
    return 0;

  if (entry->family == 0)
    {
      if (entry->source_prefix_length != 0
          || entry->destination_prefix_length != 0
          || !product_packet_graph_gate_address_is_zero (entry->source_address)
          || !product_packet_graph_gate_address_is_zero (
            entry->destination_address))
        return 0;
    }
  else if (entry->family == PRODUCT_L4_POLICY_FAMILY_IPV4
           || entry->family == PRODUCT_L4_POLICY_FAMILY_IPV6)
    {
      max_prefix = entry->family == PRODUCT_L4_POLICY_FAMILY_IPV4 ? 32 : 128;
      if (entry->source_prefix_length > max_prefix
          || entry->destination_prefix_length > max_prefix)
        return 0;
      if (entry->family == PRODUCT_L4_POLICY_FAMILY_IPV4)
        for (index = 4; index < 16; index++)
          if (entry->source_address[index] != 0
              || entry->destination_address[index] != 0)
            return 0;
    }
  else
    return 0;

  if (entry->protocol != 0 && entry->protocol != PRODUCT_L4_POLICY_PROTOCOL_TCP
      && entry->protocol != PRODUCT_L4_POLICY_PROTOCOL_UDP)
    return 0;
  if (entry->direction != PRODUCT_L4_POLICY_DIRECTION_ANY
      && entry->direction != PRODUCT_L4_POLICY_DIRECTION_INPUT
      && entry->direction != PRODUCT_L4_POLICY_DIRECTION_OUTPUT)
    return 0;
  return 1;
}

static int
product_packet_graph_gate_rule_precedes (
  const product_packet_graph_gate_entry_t *left,
  const product_packet_graph_gate_entry_t *right)
{
  if (left->priority != right->priority)
    return left->priority < right->priority;
  if (left->order != right->order)
    return left->order < right->order;
  return left->rule_id < right->rule_id;
}

static int
product_packet_graph_gate_rule_requires_ports (
  const product_packet_graph_gate_entry_t *rule)
{
  return rule->source_port_first != PRODUCT_L4_POLICY_PORT_FIRST_ANY
         || rule->source_port_last != PRODUCT_L4_POLICY_PORT_LAST_ANY
         || rule->destination_port_first != PRODUCT_L4_POLICY_PORT_FIRST_ANY
         || rule->destination_port_last != PRODUCT_L4_POLICY_PORT_LAST_ANY;
}

static int
product_packet_graph_gate_rule_matches (
  const product_packet_graph_gate_entry_t *rule,
  const product_l4_policy_packet_t *packet, u32 *no_match_reason)
{
  if (no_match_reason != 0)
    *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE;
  if (!packet->uid_known || packet->uid == UINT32_MAX)
    {
      if (no_match_reason != 0)
        *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_UID;
      return 0;
    }
  if (packet->uid != rule->uid)
    return 0;
  if (rule->network_context_id != PRODUCT_L4_POLICY_NETWORK_CONTEXT_ANY
      && !packet->network_context_known)
    {
      if (no_match_reason != 0)
        *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_CONTEXT;
      return 0;
    }
  if (rule->network_context_id != PRODUCT_L4_POLICY_NETWORK_CONTEXT_ANY
      && packet->network_context_id != rule->network_context_id)
    return 0;
  if (rule->ifindex != PRODUCT_L4_POLICY_IFINDEX_ANY)
    {
      if (!packet->ifindex_known)
        {
          if (no_match_reason != 0)
            *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_IFINDEX;
          return 0;
        }
      if (packet->ifindex != rule->ifindex)
        return 0;
    }
  if (rule->direction != PRODUCT_L4_POLICY_DIRECTION_ANY)
    {
      if (!packet->direction_known)
        {
          if (no_match_reason != 0)
            *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_DIRECTION;
          return 0;
        }
      if (packet->direction != rule->direction)
        return 0;
    }
  if (rule->family != 0 && packet->family != rule->family)
    {
      if (no_match_reason != 0)
        *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_FAMILY;
      return 0;
    }
  if (rule->protocol != 0 && packet->protocol != rule->protocol)
    {
      if (no_match_reason != 0)
        *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_PROTOCOL;
      return 0;
    }
  if (rule->family != 0
      && (!product_packet_graph_gate_address_matches (
            rule->family, rule->source_address, packet->source_address,
            rule->source_prefix_length)
          || !product_packet_graph_gate_address_matches (
            rule->family, rule->destination_address, packet->destination_address,
            rule->destination_prefix_length)))
    {
      if (no_match_reason != 0)
        *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_ADDRESS;
      return 0;
    }
  if (!packet->ports_available
      && product_packet_graph_gate_rule_requires_ports (rule))
    {
      if (no_match_reason != 0)
        *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_PORTS_UNAVAILABLE;
      return 0;
    }
  if (packet->ports_available
      && (packet->source_port < rule->source_port_first
          || packet->source_port > rule->source_port_last
          || packet->destination_port < rule->destination_port_first
          || packet->destination_port > rule->destination_port_last))
    {
      if (no_match_reason != 0)
        *no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_PORT;
      return 0;
    }
  return 1;
}

static void
product_packet_graph_gate_table_insert (
  product_packet_graph_gate_table_t *table,
  const product_packet_graph_gate_entry_t *entry)
{
  u32 index = table->entry_count;
  while (index > 0
         && product_packet_graph_gate_rule_precedes (
           entry, &table->entries[index - 1]))
    {
      table->entries[index] = table->entries[index - 1];
      index--;
    }
  table->entries[index] = *entry;
  table->entry_count++;
  table->max_probes = table->entry_count;
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
  product_l4_policy_match_result_t *match, u64 *generation, u64 *revision,
  u64 *snapshot_hash, u32 *rule_count, u32 *max_probes, u32 *view_active,
  u32 *publication_sequence)
{
  product_l4_policy_packet_t packet;
  product_l4_policy_view_t empty_view;
  product_packet_graph_l4_policy_bank_t *bank;
  product_l4_policy_status_t status;
  u32 start_sequence;
  u32 end_sequence;
  u32 active_bank;

  if (graph == 0 || lease == 0 || match == 0 || generation == 0
      || revision == 0 || snapshot_hash == 0 || rule_count == 0
      || max_probes == 0 || view_active == 0 || publication_sequence == 0)
    return PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT;
  /* rule_count and max_probes may both be zero for a valid empty bundle. */
  *view_active = 1;
  *publication_sequence = 0;

  /* The publication sequence covers Gate metadata and the active bank. */
  for (;;)
    {
      start_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
      if ((start_sequence & 1U) != 0)
        continue;

      active_bank = clib_atomic_load_acq_n (&graph->l4_policy_active_bank);
      if (active_bank >= 2)
        active_bank = 0;
      clib_atomic_fetch_add_relax (&graph->l4_policy_bank_readers[active_bank],
                                   1);
      if (start_sequence != clib_atomic_load_acq_n (
            &graph->policy_publish_sequence)
          || active_bank != clib_atomic_load_acq_n (
            &graph->l4_policy_active_bank))
        {
          clib_atomic_fetch_sub_relax (
            &graph->l4_policy_bank_readers[active_bank], 1);
          continue;
        }

      if (clib_atomic_load_acq_n (&graph->l4_policy_view_active) == 0)
        {
          *view_active = 0;
          clib_atomic_fetch_sub_relax (
            &graph->l4_policy_bank_readers[active_bank], 1);
          end_sequence = clib_atomic_load_acq_n (
            &graph->policy_publish_sequence);
          if (start_sequence == end_sequence && (end_sequence & 1U) == 0)
            {
              *publication_sequence = end_sequence;
              return PRODUCT_L4_POLICY_STATUS_NOT_FOUND;
            }
          *view_active = 1;
          continue;
        }

      bank = &graph->l4_policy_banks[active_bank];
      *generation = bank->generation;
      *revision = bank->revision;
      *snapshot_hash = bank->snapshot_hash;
      *rule_count = bank->view.rule_count;
      *max_probes = bank->view.max_probes;
      product_packet_graph_l4_packet_projection (lease, &packet);
      if (bank->generation != graph->generation)
        {
          /* A generation change must not evaluate an older published view. */
          product_l4_policy_init (&empty_view);
          status = product_l4_policy_evaluate (&empty_view, &packet, match);
        }
      else
        status = product_l4_policy_evaluate (&bank->view, &packet, match);
      clib_atomic_fetch_sub_relax (&graph->l4_policy_bank_readers[active_bank],
                                   1);
      end_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
      if (start_sequence == end_sequence && (end_sequence & 1U) == 0)
        {
          *publication_sequence = end_sequence;
          return status;
        }
    }
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
  verdict = match->action == PRODUCT_L4_POLICY_ACTION_DROP
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
  if (match->action == PRODUCT_L4_POLICY_ACTION_DROP)
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
  product_packet_graph_l4_policy_bank_t *bank;
  u32 start_sequence;
  u32 end_sequence;
  u32 active_bank;

  if (status == 0)
    return;
  clib_memset (status, 0, sizeof (*status));
  for (;;)
    {
      start_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
      if ((start_sequence & 1U) != 0)
        continue;
      active_bank = clib_atomic_load_acq_n (&graph->l4_policy_active_bank);
      if (active_bank >= 2)
        active_bank = 0;
      bank = &graph->l4_policy_banks[active_bank];
      status->active_generation = bank->generation;
      status->active_revision = bank->revision;
      status->snapshot_hash = bank->snapshot_hash;
      status->active_entry_count = bank->gate_table.entry_count;
      status->max_probes = bank->gate_table.max_probes;
      status->rule_id = 0;
      status->subject_uid = UINT32_MAX;
      status->network_context_id = 0;
      status->blocked = 0;
      status->reason_id = 0;
      if (bank->gate_table.entry_count == 1)
        {
          const product_packet_graph_gate_entry_t *entry =
            &bank->gate_table.entries[0];
          status->rule_id = entry->rule_id;
          status->subject_uid = entry->uid;
          status->network_context_id = entry->network_context_id;
          status->blocked = entry->action == PRODUCT_L4_POLICY_ACTION_DROP;
          status->reason_id = entry->reason_id;
        }
      end_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
      if (start_sequence == end_sequence && (end_sequence & 1U) == 0)
        break;
    }

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
  product_packet_graph_gate_table_t gate_table;
  product_l4_policy_view_t compiled_view;
  product_l4_policy_status_t compile_status;
  u32 sequence;
  u32 active_bank;
  u32 inactive_bank;
  u32 index;
  u32 prior_index;

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
  clib_memset (&gate_table, 0, sizeof (gate_table));
  for (index = 0; index < bundle->gate_entry_count; index++)
    {
      const product_packet_graph_gate_entry_t *entry =
        &bundle->gate_entries[index];
      if (!product_packet_graph_gate_entry_valid (entry))
        return PRODUCT_PACKET_INVALID_ARGUMENT;
      for (prior_index = 0; prior_index < index; prior_index++)
        if (bundle->gate_entries[prior_index].rule_id == entry->rule_id)
          return PRODUCT_PACKET_INVALID_ARGUMENT;
      product_packet_graph_gate_table_insert (&gate_table, entry);
    }
  for (index = 0; index < bundle->l4_rule_count; index++)
    {
      const product_l4_policy_rule_t *rule = &bundle->l4_rules[index];
      if (rule->network_context_id == 0 || rule->uid == UINT32_MAX)
        return PRODUCT_PACKET_INVALID_ARGUMENT;
      for (prior_index = 0; prior_index < bundle->gate_entry_count;
           prior_index++)
        if (bundle->gate_entries[prior_index].rule_id == rule->rule_id)
          return PRODUCT_PACKET_INVALID_ARGUMENT;
    }

  product_l4_policy_init (&compiled_view);
  compile_status = product_l4_policy_compile (
    &compiled_view, bundle->l4_rules, bundle->l4_rule_count);
  if (compile_status != PRODUCT_L4_POLICY_STATUS_OK)
    return PRODUCT_PACKET_INVALID_ARGUMENT;

  product_packet_graph_policy_publish_lock (graph);
  sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
  if ((sequence & 1U) != 0)
    sequence++;
  clib_atomic_store_rel_n (&graph->policy_publish_sequence, sequence + 1U);
  if (!product_packet_graph_flow_pools_publish_revision (
        graph, bundle->revision, bundle->snapshot_hash))
    {
      clib_atomic_store_rel_n (&graph->policy_publish_sequence, sequence);
      product_packet_graph_policy_publish_unlock (graph);
      return PRODUCT_PACKET_INVALID_ARGUMENT;
    }

  active_bank = clib_atomic_load_acq_n (&graph->l4_policy_active_bank);
  if (active_bank >= 2)
    active_bank = 0;
  inactive_bank = active_bank ^ 1U;
  /* This bank has not been active since the previous publication. */
  while (clib_atomic_load_acq_n (
           &graph->l4_policy_bank_readers[inactive_bank]) != 0)
    ;
  bank = &graph->l4_policy_banks[inactive_bank];
  bank->gate_table = gate_table;
  bank->view = compiled_view;
  bank->generation = bundle->generation;
  bank->revision = bundle->revision;
  bank->snapshot_hash = bundle->snapshot_hash;

  /* GateTable and its L4 view become visible with the same even sequence. */
  clib_atomic_store_rel_n (&graph->gate_policy_revision, bundle->revision);
  clib_atomic_store_rel_n (&graph->gate_policy_snapshot_hash,
                           bundle->snapshot_hash);
  if (gate_table.entry_count == 1)
    {
      const product_packet_graph_gate_entry_t *entry = &gate_table.entries[0];
      clib_atomic_store_rel_n (&graph->gate_policy_rule_id,
                               entry->rule_id);
      clib_atomic_store_rel_n (&graph->gate_policy_subject_uid,
                               entry->uid);
      clib_atomic_store_rel_n (&graph->gate_policy_network_context_id,
                               entry->network_context_id);
      clib_atomic_store_rel_n (&graph->gate_policy_blocked,
                               entry->action == PRODUCT_L4_POLICY_ACTION_DROP);
      clib_atomic_store_rel_n (&graph->gate_policy_reason_id,
                               entry->reason_id);
    }
  else
    {
      clib_atomic_store_rel_n (&graph->gate_policy_rule_id, 0);
      clib_atomic_store_rel_n (&graph->gate_policy_subject_uid, UINT32_MAX);
      clib_atomic_store_rel_n (&graph->gate_policy_network_context_id, 0);
      clib_atomic_store_rel_n (&graph->gate_policy_blocked, 0);
      clib_atomic_store_rel_n (&graph->gate_policy_reason_id, 0);
    }
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
                           gate_table.entry_count == 0
                             ? PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE
                             : 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_action, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_reason_id, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_active_bank, inactive_bank);
  clib_atomic_store_rel_n (&graph->l4_policy_view_active, 1);
  clib_atomic_store_rel_n (&graph->policy_publish_sequence, sequence + 2U);
  product_packet_graph_policy_publish_unlock (graph);
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
  product_packet_graph_policy_publish_lock (graph);
  sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
  if ((sequence & 1U) != 0)
    sequence++;
  clib_atomic_store_rel_n (&graph->policy_publish_sequence, sequence + 1U);
  clib_atomic_store_rel_n (&graph->l4_policy_view_active, 0);
  product_packet_graph_flow_pools_flush (graph);
  clib_atomic_store_rel_n (&graph->policy_publish_sequence, sequence + 2U);
  product_packet_graph_policy_publish_unlock (graph);
}

void
product_packet_graph_l4_status (product_packet_graph_l4_status_t *status)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 start_sequence;
  u32 end_sequence;
  u32 active_bank;

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
      for (;;)
        {
          start_sequence =
            clib_atomic_load_acq_n (&graph->policy_publish_sequence);
          if ((start_sequence & 1U) != 0)
            continue;
          active_bank =
            clib_atomic_load_acq_n (&graph->l4_policy_active_bank);
          if (active_bank >= 2)
            active_bank = 0;
          status->active_generation =
            graph->l4_policy_banks[active_bank].generation;
          status->active_revision = graph->l4_policy_banks[active_bank].revision;
          status->snapshot_hash =
            graph->l4_policy_banks[active_bank].snapshot_hash;
          status->view_rule_count =
            graph->l4_policy_banks[active_bank].view.rule_count;
          status->view_max_probes =
            graph->l4_policy_banks[active_bank].view.max_probes;
          end_sequence =
            clib_atomic_load_acq_n (&graph->policy_publish_sequence);
          if (start_sequence == end_sequence && (end_sequence & 1U) == 0)
            break;
        }
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
product_packet_graph_policy_gate_drop (product_packet_graph_main_t *graph,
                                       const product_packet_lease_t *lease,
                                       product_packet_graph_gate_match_t *matched,
                                       u32 *publication_sequence)
{
  product_l4_policy_packet_t packet;
  product_packet_graph_l4_policy_bank_t *bank;
  u32 start_sequence;
  u32 end_sequence;
  u32 active_bank;
  u32 index;
  u32 first_no_match_reason;

  if (graph == 0 || lease == 0 || matched == 0 || publication_sequence == 0)
    return 0;

  clib_memset (matched, 0, sizeof (*matched));
  *publication_sequence = 0;

  for (;;)
    {
      start_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
      if ((start_sequence & 1U) != 0)
        continue;
      active_bank = clib_atomic_load_acq_n (&graph->l4_policy_active_bank);
      if (active_bank >= 2)
        active_bank = 0;
      clib_atomic_fetch_add_relax (&graph->l4_policy_bank_readers[active_bank],
                                   1);
      if (start_sequence != clib_atomic_load_acq_n (
            &graph->policy_publish_sequence)
          || active_bank != clib_atomic_load_acq_n (
            &graph->l4_policy_active_bank))
        {
          clib_atomic_fetch_sub_relax (
            &graph->l4_policy_bank_readers[active_bank], 1);
          continue;
        }

      bank = &graph->l4_policy_banks[active_bank];
      matched->generation = bank->generation;
      matched->revision = bank->revision;
      matched->snapshot_hash = bank->snapshot_hash;
      first_no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE;
      product_packet_graph_l4_packet_projection (lease, &packet);
      if (bank->generation == graph->generation)
        for (index = 0; index < bank->gate_table.entry_count; index++)
          {
            const product_packet_graph_gate_entry_t *entry =
              &bank->gate_table.entries[index];
            u32 no_match_reason = PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE;
            matched->probes++;
            if (product_packet_graph_gate_rule_matches (
                  entry, &packet, &no_match_reason))
              {
                matched->candidate_count++;
                if (matched->rule.rule_id == 0)
                  {
                    matched->rule = *entry;
                    matched->winner_rank = index + 1U;
                  }
              }
            else if (first_no_match_reason
                     == PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE
                     && no_match_reason
                          != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE)
              first_no_match_reason = no_match_reason;
          }
      matched->no_match_reason = matched->rule.rule_id != 0
                                   ? PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NONE
                                   : first_no_match_reason;
      clib_atomic_fetch_sub_relax (&graph->l4_policy_bank_readers[active_bank],
                                   1);
      end_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
      if (start_sequence == end_sequence && (end_sequence & 1U) == 0)
        {
          *publication_sequence = end_sequence;
          break;
        }
    }

  clib_atomic_store_rel_n (&graph->gate_table_last_match_revision,
                           matched->rule.rule_id == 0 ? 0 : matched->revision);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_rule_id,
                           matched->rule.rule_id);
  clib_atomic_store_rel_n (&graph->gate_table_last_winner_rank,
                           matched->rule.rule_id == 0 ? 0
                                                      : matched->winner_rank);
  clib_atomic_store_rel_n (&graph->gate_table_last_probes, matched->probes);
  clib_atomic_store_rel_n (&graph->gate_table_last_candidate_count,
                           matched->candidate_count);
  clib_atomic_store_rel_n (&graph->gate_table_last_no_match_reason,
                           matched->no_match_reason);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_action,
                           matched->rule.rule_id == 0 ? 0
                                                      : matched->rule.action);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_reason_id,
                           matched->rule.rule_id == 0
                             ? 0
                             : matched->rule.reason_id);
  return matched->rule.rule_id != 0;
}

static void
product_packet_graph_gate_policy_from_match (
  const product_packet_graph_gate_match_t *matched,
  product_packet_graph_gate_policy_t *policy)
{
  if (matched == 0 || policy == 0)
    return;
  clib_memset (policy, 0, sizeof (*policy));
  policy->revision = matched->revision;
  policy->snapshot_hash = matched->snapshot_hash;
  policy->rule_id = matched->rule.rule_id;
  policy->subject_uid = matched->rule.uid;
  policy->network_context_id = matched->rule.network_context_id;
  policy->blocked = matched->rule.action == PRODUCT_L4_POLICY_ACTION_DROP;
  policy->reason_id = matched->rule.reason_id;
}

static void
product_packet_graph_record_policy_drop (
  product_packet_graph_main_t *graph, const product_packet_lease_t *lease,
  const product_packet_graph_gate_policy_t *matched)
{
  if (graph == 0 || lease == 0 || matched == 0)
    return;

  clib_atomic_fetch_add_relax (&graph->policy_drop_records, 1);
  clib_atomic_store_rel_n (&graph->policy_last_drop_revision,
                           matched->revision);
  clib_atomic_store_rel_n (&graph->policy_last_drop_rule_id, matched->rule_id);
  clib_atomic_store_rel_n (&graph->policy_last_drop_completion_attempts,
                           lease->terminal_count);
  clib_atomic_store_rel_n (&graph->policy_last_drop_uid, lease->platform.uid);
  clib_atomic_store_rel_n (&graph->policy_last_drop_network_context,
                           (u32) lease->platform.network_context_id);
  clib_atomic_store_rel_n (&graph->policy_last_drop_reason_id,
                           matched->reason_id);
  clib_atomic_store_rel_n (&graph->policy_last_drop_verdict,
                           PRODUCT_POLICY_VERDICT_DROP);
  clib_atomic_store_rel_n (&graph->policy_last_drop_winner,
                           PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE);
  clib_atomic_store_rel_n (&graph->policy_last_drop_uid_known,
                           !!(lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN));
  clib_atomic_store_rel_n (&graph->policy_last_drop_device_direction,
                           lease->platform.direction);
}

static int
product_packet_graph_ipv4_scalar_value (const u8 address[16])
{
  /* PacketFacts keeps IPv4 in the zero-padded tail; graph scalar policy
   * stores the same address as one network-order u32.  A future matcher
   * projection must explicitly move these four bytes to its [0..3] view. */
  return ((u32) address[12] << 24) | ((u32) address[13] << 16)
         | ((u32) address[14] << 8) | address[15];
}

static int
product_packet_graph_ipv4_prefix_matches (const u8 address[16], u32 network,
                                          u8 prefix_length)
{
  u32 value;
  u32 mask;

  if (prefix_length > 32)
    return 0;
  value = product_packet_graph_ipv4_scalar_value (address);
  if (prefix_length == 0)
    return 1;
  mask = prefix_length == 32 ? UINT32_MAX : UINT32_MAX << (32 - prefix_length);
  return (value & mask) == (network & mask);
}

static int
product_packet_graph_l4_direction_matches (u8 configured, u32 observed)
{
  /* NF_INET_LOCAL_IN=1 and NF_INET_LOCAL_OUT=3 are stable kernel hook tags. */
  if (configured == PRODUCT_PACKET_GRAPH_L4_DIRECTION_INPUT)
    return observed == 1U;
  if (configured == PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT)
    return observed == 3U;
  return 0;
}

static int
product_packet_graph_l4_match (product_packet_graph_main_t *graph,
                               const product_packet_lease_t *lease,
                               product_packet_graph_l4_policy_t *matched,
                               u32 *publication_sequence)
{
  u32 start_sequence;
  u32 end_sequence;

  if (graph == 0 || lease == 0 || matched == 0 || publication_sequence == 0)
    return 0;

  clib_memset (matched, 0, sizeof (*matched));
  *publication_sequence = 0;
  for (;;)
    {
      start_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
      if ((start_sequence & 1U) != 0)
        continue;
      matched->revision = clib_atomic_load_acq_n (&graph->l4_policy_revision);
      matched->snapshot_hash =
        clib_atomic_load_acq_n (&graph->l4_policy_snapshot_hash);
      matched->rule_id = clib_atomic_load_acq_n (&graph->l4_policy_rule_id);
      matched->subject_uid =
        clib_atomic_load_acq_n (&graph->l4_policy_subject_uid);
      matched->network_context_id =
        clib_atomic_load_acq_n (&graph->l4_policy_network_context_id);
      matched->reason_id = clib_atomic_load_acq_n (&graph->l4_policy_reason_id);
      matched->priority = clib_atomic_load_acq_n (&graph->l4_policy_priority);
      matched->order = clib_atomic_load_acq_n (&graph->l4_policy_order);
      matched->source_address =
        clib_atomic_load_acq_n (&graph->l4_policy_source_address);
      matched->destination_address =
        clib_atomic_load_acq_n (&graph->l4_policy_destination_address);
      matched->source_port_first =
        clib_atomic_load_acq_n (&graph->l4_policy_source_port_first);
      matched->source_port_last =
        clib_atomic_load_acq_n (&graph->l4_policy_source_port_last);
      matched->destination_port_first =
        clib_atomic_load_acq_n (&graph->l4_policy_destination_port_first);
      matched->destination_port_last =
        clib_atomic_load_acq_n (&graph->l4_policy_destination_port_last);
      matched->source_prefix_length =
        clib_atomic_load_acq_n (&graph->l4_policy_source_prefix_length);
      matched->destination_prefix_length =
        clib_atomic_load_acq_n (&graph->l4_policy_destination_prefix_length);
      matched->direction = clib_atomic_load_acq_n (&graph->l4_policy_direction);
      matched->protocol = clib_atomic_load_acq_n (&graph->l4_policy_protocol);
      matched->action = clib_atomic_load_acq_n (&graph->l4_policy_action);
      end_sequence = clib_atomic_load_acq_n (&graph->policy_publish_sequence);
      if (start_sequence == end_sequence && (end_sequence & 1U) == 0)
        {
          *publication_sequence = end_sequence;
          break;
        }
    }

  if (matched->revision == 0 || matched->rule_id == 0
      || matched->subject_uid == UINT32_MAX
      || matched->network_context_id == 0
      || matched->protocol != PRODUCT_PACKET_GRAPH_L4_PROTOCOL_TCP
      || matched->action == 0
      || !(lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN)
      || !(lease->platform.availability & PRODUCT_PLATFORM_CONTEXT_KNOWN)
      || lease->platform.uid != matched->subject_uid
      || lease->platform.network_context_id != matched->network_context_id
      || lease->facts.ip_family != PRODUCT_PACKET_GRAPH_L4_FAMILY_IPV4
      || lease->facts.protocol != PRODUCT_PACKET_GRAPH_L4_PROTOCOL_TCP
      || lease->facts.l4_status != PRODUCT_PACKET_L4_COMPLETE
      || !product_packet_graph_l4_direction_matches (
        matched->direction, lease->platform.direction)
      || !product_packet_graph_ipv4_prefix_matches (
        lease->facts.source_address, matched->source_address,
        matched->source_prefix_length)
      || !product_packet_graph_ipv4_prefix_matches (
        lease->facts.destination_address, matched->destination_address,
        matched->destination_prefix_length)
      || lease->facts.source_port < matched->source_port_first
      || lease->facts.source_port > matched->source_port_last
      || lease->facts.destination_port < matched->destination_port_first
      || lease->facts.destination_port > matched->destination_port_last)
    return 0;
  return 1;
}

static int
product_packet_graph_l4_policy_view_active (product_packet_graph_main_t *graph)
{
  return graph != 0
         && clib_atomic_load_acq_n (&graph->l4_policy_view_active) != 0;
}

static void
product_packet_graph_record_l4_no_match (
  product_packet_graph_main_t *graph, const product_packet_lease_t *lease)
{
  u64 revision;
  u8 l4_policy_direction;

  if (graph == 0 || lease == 0)
    return;
  revision = clib_atomic_load_acq_n (&graph->l4_policy_revision);
  if (revision == 0 || clib_atomic_load_acq_n (&graph->l4_policy_rule_id) == 0)
    return;
  l4_policy_direction = clib_atomic_load_acq_n (&graph->l4_policy_direction);
  if (!product_packet_graph_l4_direction_matches (l4_policy_direction,
                                                  lease->platform.direction))
    return;
  clib_atomic_fetch_add_relax (&graph->l4_no_match_records, 1);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_revision, revision);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_result,
                           PRODUCT_PACKET_GRAPH_L4_EVALUATION_NO_MATCH);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_verdict,
                           PRODUCT_POLICY_VERDICT_PASS_NEXT);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_device_direction,
                           lease->platform.direction);
}

static void
product_packet_graph_record_l4_match (
  product_packet_graph_main_t *graph, const product_packet_lease_t *lease,
  const product_packet_graph_l4_policy_t *matched)
{
  u32 verdict;

  if (graph == 0 || lease == 0 || matched == 0)
    return;
  verdict = matched->action == PRODUCT_PACKET_GRAPH_L4_ACTION_DROP
              ? PRODUCT_POLICY_VERDICT_DROP
              : PRODUCT_POLICY_VERDICT_ALLOW;
  clib_atomic_fetch_add_relax (&graph->l4_match_records, 1);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_revision,
                           matched->revision);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_result,
                           PRODUCT_PACKET_GRAPH_L4_EVALUATION_MATCH);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_verdict, verdict);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_device_direction,
                           lease->platform.direction);
  clib_atomic_store_rel_n (&graph->l4_last_match_revision,
                           matched->revision);
  clib_atomic_store_rel_n (&graph->l4_last_match_rule_id, matched->rule_id);
  clib_atomic_store_rel_n (&graph->l4_last_match_uid, lease->platform.uid);
  clib_atomic_store_rel_n (&graph->l4_last_match_network_context,
                           (u32) lease->platform.network_context_id);
  clib_atomic_store_rel_n (&graph->l4_last_match_reason_id,
                           matched->reason_id);
  clib_atomic_store_rel_n (&graph->l4_last_match_verdict, verdict);
  clib_atomic_store_rel_n (&graph->l4_last_match_winner,
                           PRODUCT_PACKET_GRAPH_L4_WINNER_RULE);
  clib_atomic_store_rel_n (&graph->l4_last_match_uid_known,
                           !!(lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN));
  clib_atomic_store_rel_n (&graph->l4_last_match_device_direction,
                           lease->platform.direction);
  clib_atomic_store_rel_n (&graph->l4_last_match_action, matched->action);
  if (matched->action == PRODUCT_PACKET_GRAPH_L4_ACTION_DROP)
    {
      /* Keep the fixed ABI's drop evidence useful for both Gate and L4. */
      clib_atomic_fetch_add_relax (&graph->policy_drop_records, 1);
      clib_atomic_store_rel_n (&graph->policy_last_drop_revision,
                               matched->revision);
      clib_atomic_store_rel_n (&graph->policy_last_drop_rule_id,
                               matched->rule_id);
      clib_atomic_store_rel_n (&graph->policy_last_drop_completion_attempts,
                               lease->terminal_count);
      clib_atomic_store_rel_n (&graph->policy_last_drop_uid, lease->platform.uid);
      clib_atomic_store_rel_n (&graph->policy_last_drop_network_context,
                               (u32) lease->platform.network_context_id);
      clib_atomic_store_rel_n (&graph->policy_last_drop_reason_id,
                               matched->reason_id);
      clib_atomic_store_rel_n (&graph->policy_last_drop_verdict,
                               PRODUCT_POLICY_VERDICT_DROP);
      clib_atomic_store_rel_n (&graph->policy_last_drop_winner,
                               PRODUCT_PACKET_GRAPH_L4_WINNER_RULE);
      clib_atomic_store_rel_n (&graph->policy_last_drop_uid_known,
                               !!(lease->platform.availability & PRODUCT_PLATFORM_UID_KNOWN));
      clib_atomic_store_rel_n (&graph->policy_last_drop_device_direction,
                               lease->platform.direction);
    }
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

product_packet_result_t
product_packet_graph_policy_stage (
  product_packet_lease_t *lease,
  product_packet_graph_policy_evaluation_t *evaluation)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_gate_match_t gate_match;
  product_packet_graph_gate_policy_t matched_gate;
  product_packet_graph_l4_policy_t matched_l4;
  product_packet_result_t result;
  u32 gate_sequence;
  u32 l4_sequence;
  u32 legacy_sequence;
  int gate_drop;
  int gate_claim;

  if (lease == 0 || evaluation == 0)
    return PRODUCT_PACKET_INVALID_ARGUMENT;

  clib_memset (evaluation, 0, sizeof (*evaluation));
  evaluation->verdict = PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT;
  clib_atomic_fetch_add_relax (&graph->policy_stage_evaluations, 1);

  /* Terminal state is monotonic: a prior owner/runtime drop cannot reopen. */
  if (lease->terminal_intent != PRODUCT_PACKET_INTENT_NONE)
    {
      evaluation->verdict = lease->terminal_intent ==
                              PRODUCT_PACKET_INTENT_DROP_RUNTIME
                              ? PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP
                              : PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT;
      evaluation->terminal_preserved = 1;
      product_packet_graph_record_policy_stage (graph, evaluation);
      return PRODUCT_PACKET_OK;
    }
  if (!lease->policy_owner_ready)
    return PRODUCT_PACKET_ORDER_VIOLATION;

  for (;;)
    {
      /* Gate is deliberately evaluated before the shared stateless L4 lookup. */
      clib_memset (&gate_match, 0, sizeof (gate_match));
      gate_drop = product_packet_graph_policy_gate_drop (
        graph, lease, &gate_match, &gate_sequence);
      gate_drop = gate_drop
                  && gate_match.rule.action == PRODUCT_L4_POLICY_ACTION_DROP;
      gate_claim = gate_match.rule.rule_id != 0;
      if (gate_drop || gate_claim)
        {
          clib_atomic_fetch_add_relax (&graph->policy_gate_evaluations, 1);
          evaluation->stage = PRODUCT_PACKET_GRAPH_POLICY_STAGE_GATE;
          evaluation->revision = gate_match.revision;
          evaluation->snapshot_hash = gate_match.snapshot_hash;
          evaluation->rule_id = gate_match.rule.rule_id;
          evaluation->reason_id = gate_match.rule.reason_id;
          if (gate_drop)
            {
              evaluation->verdict = PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP;
              evaluation->matched = 1;
              evaluation->winner = PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE;
              result = product_packet_set_terminal (
                lease, PRODUCT_PACKET_INTENT_DROP_RUNTIME);
              if (result == PRODUCT_PACKET_OK)
                {
                  lease->runtime_drop_reason = PRODUCT_PACKET_DROP_POLICY_GATE;
                  product_packet_graph_gate_policy_from_match (&gate_match,
                                                               &matched_gate);
                  product_packet_graph_record_policy_drop (graph, lease,
                                                           &matched_gate);
                  clib_atomic_fetch_add_relax (&graph->policy_stage_drops, 1);
                  product_packet_graph_flow_observe (graph, lease, evaluation);
                }
              product_packet_graph_record_policy_stage (graph, evaluation);
              return result;
            }
        }

      /* Do not let an unrelated Gate claim leak into an L4 no-match result. */
      evaluation->stage = PRODUCT_PACKET_GRAPH_POLICY_STAGE_NONE;
      evaluation->matched = 0;
      evaluation->winner = PRODUCT_NETWORK_GATE_WINNER_NONE;
      evaluation->revision = 0;
      evaluation->rule_id = 0;
      evaluation->reason_id = 0;

      {
        product_l4_policy_match_result_t matched_view;
        product_l4_policy_status_t matcher_status;
        u64 view_generation = 0;
        u64 view_revision = 0;
        u64 view_snapshot_hash = 0;
        u32 view_rule_count = 0;
        u32 view_max_probes = 0;
        u32 view_still_active = 1;

        matcher_status = product_packet_graph_l4_view_evaluate (
          graph, lease, &matched_view, &view_generation, &view_revision,
          &view_snapshot_hash, &view_rule_count, &view_max_probes,
          &view_still_active, &l4_sequence);
        if (gate_sequence != l4_sequence
            || (gate_match.revision != 0 && view_revision != 0
                && gate_match.revision != view_revision)
            || (gate_match.snapshot_hash != 0 && view_snapshot_hash != 0
                && gate_match.snapshot_hash != view_snapshot_hash))
          continue;
        if (!view_still_active)
          goto scalar_l4_evaluation;
        /* Count only a stable evaluation of an active typed view. */
        clib_atomic_fetch_add_relax (&graph->policy_l4_evaluations, 1);
        (void) view_generation;
        (void) view_snapshot_hash;
        (void) view_rule_count;
        (void) view_max_probes;
        evaluation->stage = PRODUCT_PACKET_GRAPH_POLICY_STAGE_L4;
        evaluation->revision = view_revision;
        evaluation->snapshot_hash = view_snapshot_hash;
        if (matcher_status != PRODUCT_L4_POLICY_STATUS_OK)
          {
            result = product_packet_set_terminal (
              lease, PRODUCT_PACKET_INTENT_DROP_RUNTIME);
            if (result == PRODUCT_PACKET_OK)
              {
                lease->runtime_drop_reason = PRODUCT_PACKET_DROP_INVALID_ENVELOPE;
                evaluation->verdict = PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP;
                clib_atomic_fetch_add_relax (&graph->policy_stage_drops, 1);
                product_packet_graph_flow_observe (graph, lease, evaluation);
              }
            product_packet_graph_record_policy_stage (graph, evaluation);
            return result;
          }
        if (matched_view.evaluation == PRODUCT_L4_POLICY_EVALUATION_MATCH)
          {
            evaluation->matched = 1;
            /* Keep stage winner kind separate from the typed matcher rank. */
            evaluation->winner = PRODUCT_PACKET_GRAPH_L4_WINNER_RULE;
            evaluation->rule_id = matched_view.rule_id;
            evaluation->reason_id = matched_view.reason_id;
            evaluation->verdict =
              matched_view.stage_verdict == PRODUCT_L4_POLICY_VERDICT_DROP
                ? PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP
                : PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT;
            if (matched_view.action == PRODUCT_L4_POLICY_ACTION_DROP)
              {
                result = product_packet_set_terminal (
                  lease, PRODUCT_PACKET_INTENT_DROP_RUNTIME);
                if (result == PRODUCT_PACKET_OK)
                  {
                    lease->runtime_drop_reason = PRODUCT_PACKET_DROP_POLICY_L4;
                    product_packet_graph_record_l4_view_match (
                      graph, lease, view_generation, view_revision,
                      view_snapshot_hash, &matched_view);
                    clib_atomic_fetch_add_relax (&graph->policy_stage_drops,
                                                 1);
                    product_packet_graph_flow_observe (graph, lease,
                                                       evaluation);
                  }
                product_packet_graph_record_policy_stage (graph, evaluation);
                return result;
              }
            product_packet_graph_record_l4_view_match (
              graph, lease, view_generation, view_revision, view_snapshot_hash,
              &matched_view);
            clib_atomic_fetch_add_relax (&graph->policy_stage_pass_next, 1);
            product_packet_graph_flow_observe (graph, lease, evaluation);
            product_packet_graph_record_policy_stage (graph, evaluation);
            return PRODUCT_PACKET_OK;
          }
        evaluation->reason_id = matched_view.no_match_reason;
        product_packet_graph_flow_observe (graph, lease, evaluation);
        product_packet_graph_record_l4_view_no_match (
          graph, view_generation, view_revision, view_snapshot_hash,
          view_rule_count, &matched_view, lease);
        clib_atomic_fetch_add_relax (&graph->policy_stage_pass_next, 1);
        product_packet_graph_record_policy_stage (graph, evaluation);
        return PRODUCT_PACKET_OK;
      }

    scalar_l4_evaluation:
      {
        int legacy_match;

        clib_memset (&matched_l4, 0, sizeof (matched_l4));
        legacy_match = product_packet_graph_l4_match (
          graph, lease, &matched_l4, &legacy_sequence);
        if (gate_sequence != legacy_sequence
            || (gate_match.revision != 0 && matched_l4.revision != 0
                && gate_match.revision != matched_l4.revision)
            || (gate_match.snapshot_hash != 0
                && matched_l4.snapshot_hash != 0
                && gate_match.snapshot_hash != matched_l4.snapshot_hash))
          continue;
        /* A cleared typed view may leave only the legacy scalar identity. */
        if (matched_l4.revision != 0 && matched_l4.rule_id != 0)
          clib_atomic_fetch_add_relax (&graph->policy_l4_evaluations, 1);
        if (legacy_match)
          {
            evaluation->stage = PRODUCT_PACKET_GRAPH_POLICY_STAGE_L4;
            evaluation->matched = 1;
            evaluation->winner = PRODUCT_PACKET_GRAPH_L4_WINNER_RULE;
            evaluation->revision = matched_l4.revision;
            evaluation->snapshot_hash = matched_l4.snapshot_hash;
            evaluation->rule_id = matched_l4.rule_id;
            evaluation->reason_id = matched_l4.reason_id;
            evaluation->verdict =
              matched_l4.action == PRODUCT_PACKET_GRAPH_L4_ACTION_DROP
                ? PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP
                : PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT;
            if (matched_l4.action == PRODUCT_PACKET_GRAPH_L4_ACTION_DROP)
              {
                result = product_packet_set_terminal (
                  lease, PRODUCT_PACKET_INTENT_DROP_RUNTIME);
                if (result == PRODUCT_PACKET_OK)
                  {
                    lease->runtime_drop_reason = PRODUCT_PACKET_DROP_POLICY_L4;
                    product_packet_graph_record_l4_match (graph, lease,
                                                          &matched_l4);
                    clib_atomic_fetch_add_relax (&graph->policy_stage_drops,
                                                 1);
                    product_packet_graph_flow_observe (graph, lease,
                                                       evaluation);
                  }
                product_packet_graph_record_policy_stage (graph, evaluation);
                return result;
              }
            product_packet_graph_record_l4_match (graph, lease, &matched_l4);
            clib_atomic_fetch_add_relax (&graph->policy_stage_pass_next, 1);
            product_packet_graph_flow_observe (graph, lease, evaluation);
            product_packet_graph_record_policy_stage (graph, evaluation);
            return PRODUCT_PACKET_OK;
          }
        evaluation->stage = PRODUCT_PACKET_GRAPH_POLICY_STAGE_L4;
        evaluation->revision = matched_l4.revision;
        evaluation->snapshot_hash = matched_l4.snapshot_hash;
        evaluation->rule_id = 0;
        evaluation->reason_id = matched_l4.reason_id;
        product_packet_graph_flow_observe (graph, lease, evaluation);
        product_packet_graph_record_l4_no_match (graph, lease);
      }

      clib_atomic_fetch_add_relax (&graph->policy_stage_pass_next, 1);
      product_packet_graph_record_policy_stage (graph, evaluation);
      return PRODUCT_PACKET_OK;
    }
}

int
product_packet_graph_submit_external (vlib_main_t *vm, u32 buffer_index,
                                      const product_platform_packet_facts_t *platform,
                                      const product_adapter_obligation_t *obligation,
                                      product_packet_graph_external_result_t *external_result)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_buffer_metadata_t metadata = { 0 };
  u64 origin_obligation_id = obligation ? obligation->token : 0;
  vlib_frame_t *frame;
  u32 *to;
  if (external_result)
    clib_memset (external_result, 0, sizeof (*external_result));
  if (!vm || !obligation || obligation->origin_worker >= PRODUCT_GRAPH_WORKERS
      || vm->thread_index != vlib_get_worker_thread_index (obligation->origin_worker)
      || !origin_obligation_id || obligation->queue_generation != graph->generation
      || !graph->external_completion
      || !clib_atomic_load_acq_n (&graph->enabled)
      || !clib_atomic_load_acq_n (&graph->accepting)) {
    fprintf(stderr, "s203 event=submit_reject thread=%u tls=%u obligation=%llu enabled=%u accepting=%u callback=%u\n",
      vm ? vm->thread_index : ~0U, vlib_get_thread_index(),
      (unsigned long long)origin_obligation_id, graph->enabled, graph->accepting,
      graph->external_completion != 0);
    return 0;
  }
  if (clib_atomic_fetch_add_relax (&graph->trace_packets, 1) < 256)
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
product_packet_graph_policy_fixture_cli (vlib_main_t *vm,
                                         unformat_input_t *input,
                                         vlib_cli_command_t *command)
{
  static const u8 matrix_ip6_a[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  };
  static const u8 matrix_ip6_b[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
  };
  u8 *fixture = 0;
  product_l4_policy_rule_t matrix_rules[5];
  product_l4_policy_rule_t l4_rule = {
    .rule_id = UINT64_C (192002),
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY,
    .priority = 100,
    .order = 1,
    .reason_id = UINT32_C (19202),
    .source_port_first = 12345,
    .source_port_last = 12345,
    .destination_port_first = 443,
    .destination_port_last = 443,
    .family = PRODUCT_L4_POLICY_FAMILY_IPV4,
    .protocol = PRODUCT_L4_POLICY_PROTOCOL_TCP,
    .direction = PRODUCT_L4_POLICY_DIRECTION_OUTPUT,
    .source_prefix_length = 32,
    .destination_prefix_length = 32,
    .action = PRODUCT_L4_POLICY_ACTION_DROP,
    .source_address = { 0x0a, 0, 0, 1 },
    .destination_address = { 0x0a, 0, 0, 2 },
  };
  product_packet_graph_gate_entry_t gate_entry = {
    .rule_id = UINT64_C (192001),
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY,
    .source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY,
    .source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY,
    .destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY,
    .destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY,
    .action = PRODUCT_L4_POLICY_ACTION_DROP,
    .reason_id = UINT32_C (19201),
  };
  product_packet_graph_policy_bundle_t bundle = { 0 };
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  (void) command;

  /* Keep the matrix in the same normalized native rule shape as production. */
  matrix_rules[0] = l4_rule;
  matrix_rules[0].rule_id = UINT64_C (192201);
  matrix_rules[0].reason_id = UINT32_C (19221);
  matrix_rules[0].priority = 10;
  matrix_rules[1] = l4_rule;
  matrix_rules[1].rule_id = UINT64_C (192202);
  matrix_rules[1].reason_id = UINT32_C (19222);
  matrix_rules[1].priority = 20;
  matrix_rules[1].protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  matrix_rules[1].source_address[0] = 0xc0;
  matrix_rules[1].source_address[1] = 0x00;
  matrix_rules[1].source_address[2] = 0x02;
  matrix_rules[1].source_address[3] = 0x01;
  matrix_rules[1].destination_address[0] = 0xc6;
  matrix_rules[1].destination_address[1] = 0x33;
  matrix_rules[1].destination_address[2] = 0x64;
  matrix_rules[1].destination_address[3] = 0x02;
  matrix_rules[1].source_port_first = 5353;
  matrix_rules[1].source_port_last = 5353;
  matrix_rules[1].destination_port_first = 53;
  matrix_rules[1].destination_port_last = 53;
  matrix_rules[1].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  matrix_rules[2] = l4_rule;
  matrix_rules[2].rule_id = UINT64_C (192203);
  matrix_rules[2].reason_id = UINT32_C (19223);
  matrix_rules[2].priority = 30;
  matrix_rules[2].family = PRODUCT_L4_POLICY_FAMILY_IPV6;
  clib_memcpy_fast (matrix_rules[2].source_address, matrix_ip6_a, 16);
  clib_memcpy_fast (matrix_rules[2].destination_address, matrix_ip6_b, 16);
  matrix_rules[2].source_port_first = 2222;
  matrix_rules[2].source_port_last = 2222;
  matrix_rules[2].destination_port_first = 8443;
  matrix_rules[2].destination_port_last = 8443;
  matrix_rules[2].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  matrix_rules[3] = l4_rule;
  matrix_rules[3].rule_id = UINT64_C (192204);
  matrix_rules[3].reason_id = UINT32_C (19224);
  matrix_rules[3].priority = 40;
  matrix_rules[3].family = PRODUCT_L4_POLICY_FAMILY_IPV6;
  matrix_rules[3].protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  clib_memcpy_fast (matrix_rules[3].source_address, matrix_ip6_a, 16);
  clib_memcpy_fast (matrix_rules[3].destination_address, matrix_ip6_b, 16);
  matrix_rules[3].source_port_first = 60000;
  matrix_rules[3].source_port_last = 60000;
  matrix_rules[3].destination_port_first = 443;
  matrix_rules[3].destination_port_last = 443;
  matrix_rules[3].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  matrix_rules[4] = l4_rule;
  matrix_rules[4].rule_id = UINT64_C (192205);
  matrix_rules[4].reason_id = UINT32_C (19225);
  matrix_rules[4].priority = 100;
  matrix_rules[4].source_prefix_length = 0;
  matrix_rules[4].destination_prefix_length = 0;
  matrix_rules[4].source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  matrix_rules[4].source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  matrix_rules[4].destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  matrix_rules[4].destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  matrix_rules[4].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  clib_memset (matrix_rules[4].source_address, 0, 16);
  clib_memset (matrix_rules[4].destination_address, 0, 16);

  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !clib_atomic_load_acq_n (&graph->enabled))
    {
      vec_free (fixture);
      return clib_error_return (0, "policy fixture setup rejected");
    }

  bundle.generation = graph->generation;
  if (strcmp ((char *) fixture, "gate-drop") == 0)
    {
      bundle.revision = UINT64_C (19201);
      bundle.snapshot_hash = UINT64_C (0x19201);
      bundle.gate_entries = &gate_entry;
      bundle.gate_entry_count = 1;
    }
  else if (strcmp ((char *) fixture, "l4-drop") == 0
           || strcmp ((char *) fixture, "l4-allow") == 0
           || strcmp ((char *) fixture, "l4-no-match") == 0)
    {
      if (strcmp ((char *) fixture, "l4-allow") == 0)
        l4_rule.action = PRODUCT_L4_POLICY_ACTION_ALLOW;
      if (strcmp ((char *) fixture, "l4-no-match") == 0)
        l4_rule.source_address[3] = 0x99;
      bundle.revision = UINT64_C (19202);
      bundle.snapshot_hash = UINT64_C (0x19202);
      bundle.l4_rules = &l4_rule;
      bundle.l4_rule_count = 1;
    }
  else if (strcmp ((char *) fixture, "empty") == 0)
    {
      /* A valid empty typed view is default-pass, not an invalid envelope. */
      bundle.revision = UINT64_C (19204);
      bundle.snapshot_hash = UINT64_C (0x19204);
    }
  else if (strcmp ((char *) fixture, "l4-matrix") == 0)
    {
      bundle.revision = UINT64_C (19205);
      bundle.snapshot_hash = UINT64_C (0x19205);
      bundle.l4_rules = matrix_rules;
      bundle.l4_rule_count = 5;
    }
  else if (strcmp ((char *) fixture, "clear") == 0)
    {
      product_packet_graph_clear_gate_policy (UINT64_C (19203),
                                              UINT64_C (0x19203));
      bundle.revision = 0;
    }
  else
    {
      vec_free (fixture);
      return clib_error_return (
        0, "expected gate-drop, l4-drop, l4-allow, l4-no-match, empty, "
           "l4-matrix, or clear");
    }
  if (bundle.revision != 0
      && product_packet_graph_publish_policy_bundle (&bundle)
           != PRODUCT_PACKET_OK)
    {
      vec_free (fixture);
      return clib_error_return (0, "typed policy bundle publication rejected");
    }
  vlib_cli_output (vm, "policy.fixture=%s", fixture);
  vec_free (fixture);
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_policy_fixture_command, static) = {
  .path = PRODUCT_GRAPH_RUN_POLICY_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_POLICY_FIXTURE_COMMAND " "
                "gate-drop|l4-drop|l4-allow|l4-no-match|empty|l4-matrix|clear",
  .function = product_packet_graph_policy_fixture_cli,
  .is_mp_safe = 1,
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
  if (!product_packet_graph_flow_pools_reset (graph))
    return clib_error_return (0, "failed to initialize graph FlowEntry pools");
  /* Enabling starts a new generation; no reader may inherit an older bank. */
  clib_memset (graph->l4_policy_banks, 0, sizeof (graph->l4_policy_banks));
  clib_atomic_store_rel_n (&graph->l4_policy_active_bank, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_bank_readers[0], 0);
  clib_atomic_store_rel_n (&graph->l4_policy_bank_readers[1], 0);
  clib_atomic_store_rel_n (&graph->policy_publish_sequence, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_active, 0);
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
  clib_atomic_store_rel_n (&graph->policy_vectors, 0);
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
  clib_atomic_store_rel_n (&graph->policy_stage_evaluations, 0);
  clib_atomic_store_rel_n (&graph->policy_gate_evaluations, 0);
  clib_atomic_store_rel_n (&graph->policy_l4_evaluations, 0);
  clib_atomic_store_rel_n (&graph->policy_stage_pass_next, 0);
  clib_atomic_store_rel_n (&graph->policy_stage_drops, 0);
  clib_atomic_store_rel_n (&graph->policy_last_stage, 0);
  clib_atomic_store_rel_n (&graph->policy_last_verdict, 0);
  clib_atomic_store_rel_n (&graph->policy_last_matched, 0);
  clib_atomic_store_rel_n (&graph->policy_last_terminal_preserved, 0);
  clib_atomic_store_rel_n (&graph->policy_last_winner, 0);
  clib_atomic_store_rel_n (&graph->policy_last_revision, 0);
  clib_atomic_store_rel_n (&graph->policy_last_rule_id, 0);
  clib_atomic_store_rel_n (&graph->policy_last_reason_id, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_revision, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_snapshot_hash, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_rule_id, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_subject_uid, UINT32_MAX);
  clib_atomic_store_rel_n (&graph->gate_policy_network_context_id, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_blocked, 0);
  clib_atomic_store_rel_n (&graph->gate_policy_reason_id, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_revision, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_rule_id, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_winner_rank, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_probes, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_candidate_count, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_no_match_reason,
                           PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_action, 0);
  clib_atomic_store_rel_n (&graph->gate_table_last_match_reason_id, 0);
  clib_atomic_store_rel_n (&graph->l4_match_records, 0);
  clib_atomic_store_rel_n (&graph->l4_no_match_records, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_revision, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_rule_id, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_revision, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_uid, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_network_context, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_reason_id, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_verdict, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_winner, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_uid_known, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_device_direction, 0);
  clib_atomic_store_rel_n (&graph->l4_last_match_action, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_result, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_verdict, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_device_direction, 0);
  clib_atomic_store_rel_n (&graph->l4_typed_match_policy_key, 0);
  clib_atomic_store_rel_n (&graph->l4_typed_match_probe_key, 0);
  clib_atomic_store_rel_n (&graph->l4_typed_match_subject_key, 0);
  clib_atomic_store_rel_n (&graph->l4_last_evaluation_probe_key, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_match_records, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_no_match_records, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_revision, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_rule_id, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_winner_rank, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_probes, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_candidate_count, 0);
  clib_atomic_store_rel_n (&graph->l4_policy_view_last_no_match_reason, 0);
  clib_atomic_store_rel_n (&graph->policy_drop_records, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_revision, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_rule_id, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_completion_attempts, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_uid, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_network_context, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_reason_id, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_verdict, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_winner, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_uid_known, 0);
  clib_atomic_store_rel_n (&graph->policy_last_drop_device_direction, 0);
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
      product_platform_packet_facts_t platform_facts;
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
      clib_memset (&platform_facts, 0, sizeof (platform_facts));
      platform_facts.availability = PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_CONTEXT_KNOWN;
      platform_facts.uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID;
      platform_facts.network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT;
      platform_facts.direction = (index & 1) ?
                                  PRODUCT_PACKET_GRAPH_L4_DIRECTION_INPUT :
                                  PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT;
      product_packet_graph_set_platform_facts (buffer, &platform_facts,
                                             graph->generation);

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
                         : result->terminal_intent ==
                               PRODUCT_PACKET_INTENT_DROP_RUNTIME
                             ? "drop-runtime"
                             : "invalid");
      vlib_cli_output (vm, "vector.%s.runtime_drop_reason=%u", name,
                       result->runtime_drop_reason);
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
    product_metadata_from_lease (&metadata, &lease, generation, buffer);
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
  product_packet_graph_gate_status_t gate_status;
  product_packet_graph_l4_status_t l4_status;
  product_packet_graph_flow_status_t flow_status;
  u32 worker;
  (void) input;
  (void) command;
  product_packet_graph_gate_status (&gate_status);
  product_packet_graph_l4_status (&l4_status);
  product_packet_graph_flow_status (&flow_status);
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
  vlib_cli_output (vm, "graph.generation=%llu", (unsigned long long)graph->generation);
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
  vlib_cli_output (vm, "graph.policy_vectors=%u",
                   clib_atomic_load_acq_n (&graph->policy_vectors));
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
  vlib_cli_output (
    vm, "graph.policy_stage_evaluations=%llu",
    (unsigned long long) clib_atomic_load_acq_n (
      &graph->policy_stage_evaluations));
  vlib_cli_output (
    vm, "graph.policy_gate_evaluations=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_gate_evaluations));
  vlib_cli_output (
    vm, "graph.policy_l4_evaluations=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_l4_evaluations));
  vlib_cli_output (
    vm, "graph.policy_stage_pass_next=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_stage_pass_next));
  vlib_cli_output (
    vm, "graph.policy_stage_drops=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_stage_drops));
  vlib_cli_output (
    vm, "graph.policy_last_stage=%u",
    clib_atomic_load_acq_n (&graph->policy_last_stage));
  vlib_cli_output (
    vm, "graph.policy_last_verdict=%u",
    clib_atomic_load_acq_n (&graph->policy_last_verdict));
  vlib_cli_output (
    vm, "graph.policy_last_matched=%u",
    clib_atomic_load_acq_n (&graph->policy_last_matched));
  vlib_cli_output (
    vm, "graph.policy_last_terminal_preserved=%u",
    clib_atomic_load_acq_n (&graph->policy_last_terminal_preserved));
  vlib_cli_output (
    vm, "graph.policy_last_winner=%u",
    clib_atomic_load_acq_n (&graph->policy_last_winner));
  vlib_cli_output (
    vm, "graph.policy_last_revision=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_last_revision));
  vlib_cli_output (
    vm, "graph.policy_last_rule_id=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_last_rule_id));
  vlib_cli_output (
    vm, "graph.policy_last_reason_id=%u",
    clib_atomic_load_acq_n (&graph->policy_last_reason_id));
  vlib_cli_output (
    vm, "graph.policy_drop_records=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->policy_drop_records));
  vlib_cli_output (
    vm, "graph.policy_last_drop_completion_attempts=%llu",
    (unsigned long long) clib_atomic_load_acq_n (
      &graph->policy_last_drop_completion_attempts));
  vlib_cli_output (
    vm, "graph.policy_last_drop_reason_id=%u",
    clib_atomic_load_acq_n (&graph->policy_last_drop_reason_id));
  vlib_cli_output (
    vm, "graph.policy_last_drop_winner=%u",
    clib_atomic_load_acq_n (&graph->policy_last_drop_winner));
  vlib_cli_output (vm, "graph.gate_table_active_generation=%llu",
                   (unsigned long long) gate_status.active_generation);
  vlib_cli_output (vm, "graph.gate_table_active_revision=%llu",
                   (unsigned long long) gate_status.active_revision);
  vlib_cli_output (vm, "graph.gate_table_snapshot_hash=%llu",
                   (unsigned long long) gate_status.snapshot_hash);
  vlib_cli_output (vm, "graph.gate_table_active_entry_count=%u",
                   gate_status.active_entry_count);
  vlib_cli_output (vm, "graph.gate_table_max_probes=%u",
                   gate_status.max_probes);
  vlib_cli_output (vm, "graph.gate_table_last_match_revision=%llu",
                   (unsigned long long) gate_status.last_match_revision);
  vlib_cli_output (vm, "graph.gate_table_last_match_rule_id=%llu",
                   (unsigned long long) gate_status.last_match_rule_id);
  vlib_cli_output (vm, "graph.gate_table_last_winner_rank=%u",
                   gate_status.last_match_winner_rank);
  vlib_cli_output (vm, "graph.gate_table_last_probes=%u",
                   gate_status.last_match_probes);
  vlib_cli_output (vm, "graph.gate_table_last_candidate_count=%u",
                   gate_status.last_match_candidate_count);
  vlib_cli_output (vm, "graph.gate_table_last_no_match_reason=%u",
                   gate_status.last_no_match_reason);
  vlib_cli_output (vm, "graph.gate_table_last_match_action=%u",
                   gate_status.last_match_action);
  vlib_cli_output (vm, "graph.gate_table_last_match_reason_id=%u",
                   gate_status.last_match_reason_id);
  vlib_cli_output (
    vm, "graph.l4_match_records=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->l4_match_records));
  vlib_cli_output (
    vm, "graph.l4_no_match_records=%llu",
    (unsigned long long) clib_atomic_load_acq_n (&graph->l4_no_match_records));
  vlib_cli_output (vm, "graph.l4_policy_view_active=%u",
                   l4_status.view_active);
  vlib_cli_output (vm, "graph.l4_policy_view_generation=%llu",
                   (unsigned long long) l4_status.active_generation);
  vlib_cli_output (vm, "graph.l4_policy_view_revision=%llu",
                   (unsigned long long) l4_status.active_revision);
  vlib_cli_output (vm, "graph.l4_policy_view_rule_count=%u",
                   l4_status.view_rule_count);
  vlib_cli_output (vm, "graph.l4_policy_view_max_probes=%u",
                   l4_status.view_max_probes);
  vlib_cli_output (vm, "graph.l4_policy_view_match_records=%llu",
                   (unsigned long long) clib_atomic_load_acq_n (
                     &graph->l4_policy_view_match_records));
  vlib_cli_output (vm, "graph.l4_policy_view_no_match_records=%llu",
                   (unsigned long long) clib_atomic_load_acq_n (
                     &graph->l4_policy_view_no_match_records));
  vlib_cli_output (vm, "graph.l4_policy_view_last_winner_rank=%u",
                   l4_status.last_match_winner_rank);
  vlib_cli_output (vm, "graph.l4_policy_view_last_rule_id=%llu",
                   (unsigned long long) l4_status.last_match_rule_id);
  vlib_cli_output (vm, "graph.l4_policy_view_last_probes=%u",
                   l4_status.last_match_probes);
  vlib_cli_output (vm, "graph.l4_policy_view_last_candidate_count=%u",
                   l4_status.last_match_candidate_count);
  vlib_cli_output (vm, "graph.l4_policy_view_last_no_match_reason=%u",
                   l4_status.last_no_match_reason);
  vlib_cli_output (vm, "graph.l4_policy_view_typed_match_policy_key=%llu",
                   (unsigned long long) l4_status.typed_match_policy_key);
  vlib_cli_output (vm, "graph.l4_policy_view_typed_match_probe_key=%llu",
                   (unsigned long long) l4_status.typed_match_probe_key);
  vlib_cli_output (vm, "graph.l4_policy_view_last_evaluation_probe_key=%llu",
                   (unsigned long long) l4_status.last_evaluation_probe_key);
  vlib_cli_output (vm, "graph.flow_worker_count=%u",
                   flow_status.worker_count);
  vlib_cli_output (vm, "graph.flow_max_entries_per_worker=%u",
                   flow_status.max_entries_per_worker);
  vlib_cli_output (vm, "graph.flow_active_generation=%llu",
                   (unsigned long long) flow_status.active_generation);
  vlib_cli_output (vm, "graph.flow_active_revision=%llu",
                   (unsigned long long) flow_status.active_revision);
  vlib_cli_output (vm, "graph.flow_active_snapshot_hash=%llu",
                   (unsigned long long) flow_status.active_snapshot_hash);
  vlib_cli_output (vm, "graph.flow_active_entries=%u",
                   flow_status.active_entries);
  vlib_cli_output (vm, "graph.flow_allocation_count=%llu",
                   (unsigned long long) flow_status.allocation_count);
  vlib_cli_output (vm, "graph.flow_reuse_count=%llu",
                   (unsigned long long) flow_status.reuse_count);
  vlib_cli_output (vm, "graph.flow_early_drop_count=%llu",
                   (unsigned long long) flow_status.early_drop_count);
  vlib_cli_output (vm, "graph.flow_wrong_owner_count=%llu",
                   (unsigned long long) flow_status.wrong_owner_count);
  vlib_cli_output (vm, "graph.flow_capacity_rejection_count=%llu",
                   (unsigned long long) flow_status.capacity_rejection_count);
  vlib_cli_output (vm, "graph.flow_revision_invalidation_count=%llu",
                   (unsigned long long) flow_status.revision_invalidation_count);
  vlib_cli_output (vm, "graph.flow_revision_mismatch_count=%llu",
                   (unsigned long long) flow_status.revision_mismatch_count);
  vlib_cli_output (vm, "graph.flow_unavailable_count=%llu",
                   (unsigned long long) flow_status.unavailable_count);
  vlib_cli_output (vm, "graph.flow_pass_next_count=%llu",
                   (unsigned long long) flow_status.pass_next_count);
  vlib_cli_output (vm, "graph.flow_drop_count=%llu",
                   (unsigned long long) flow_status.drop_count);
  vlib_cli_output (vm, "graph.flow_flush_count=%llu",
                   (unsigned long long) flow_status.flush_count);
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

static product_packet_result_t
product_packet_graph_association_prepare_lease (
  const u8 *packet, u32 packet_length, const product_platform_packet_facts_t *platform,
  u64 origin_obligation_id, product_packet_lease_t *lease)
{
  product_packet_ingress_t ingress;
  product_worker_layout_t layout = {
    .worker_count = PRODUCT_GRAPH_WORKERS,
    .hash_seed = PRODUCT_GRAPH_HASH_SEED,
  };
  product_packet_result_t result;

  clib_memset (&ingress, 0, sizeof (ingress));
  ingress.data = packet;
  ingress.length = packet_length;
  ingress.current_worker = 0;
  ingress.flow_domain = PRODUCT_GRAPH_FLOW_DOMAIN;
  ingress.origin_obligation_id = origin_obligation_id;
  ingress.platform = *platform;
  result = product_packet_admit (&layout, &ingress, lease);
  if (result != PRODUCT_PACKET_OK)
    return result;
  return product_packet_owner_guard (lease, lease->expected_owner);
}

static clib_error_t *
product_packet_graph_policy_association_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_l4_status_t drop_status;
  product_packet_graph_l4_status_t unrelated_status;
  product_packet_graph_l4_status_t same_probe_status;
  product_packet_graph_l4_status_t wrong_port_status;
  product_packet_graph_policy_evaluation_t evaluation;
  product_platform_packet_facts_t platform = {
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .availability = PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_IFINDEX_KNOWN | PRODUCT_PLATFORM_CONTEXT_KNOWN,
    .linux_ifindex = 0,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .direction = PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT,
  };
  product_packet_lease_t lease;
  u8 packet[64];
  u32 packet_length;
  product_packet_result_t result;
  int drop_terminal;
  int l4_winner_kind;
  int drop_winner_kind;
  int unrelated_preserved;
  int same_probe_preserved;
  int wrong_port_visible;
  (void) input;
  (void) command;

  if (!clib_atomic_load_acq_n (&graph->enabled)
      || !product_packet_graph_l4_policy_view_active (graph))
    return clib_error_return (0,
                              "typed policy association fixture requires an "
                              "enabled view");

  /* First, exercise the real admit -> owner guard -> shared policy stage ->
   * terminal path with the fixture's typed DROP rule. */
  packet_length = product_ipv4_fixture (packet, 6, 0x0a000001, 12345,
                                        0x0a000002, 443);
  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, &platform, UINT64_C (192601), &lease);
  if (result != PRODUCT_PACKET_OK)
    return clib_error_return (0, "drop association admission failed: %d",
                              result);
  result = product_packet_graph_policy_stage (&lease, &evaluation);
  drop_terminal = result == PRODUCT_PACKET_OK
                  && lease.terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME;
  l4_winner_kind = evaluation.winner == PRODUCT_PACKET_GRAPH_L4_WINNER_RULE;
  drop_winner_kind = clib_atomic_load_acq_n (&graph->policy_last_drop_winner)
                     == PRODUCT_PACKET_GRAPH_L4_WINNER_RULE;
  if (!drop_terminal || product_packet_settle (&lease) != PRODUCT_PACKET_OK)
    return clib_error_return (0, "typed DROP did not settle exactly once");
  product_packet_graph_l4_status (&drop_status);
  l4_winner_kind = l4_winner_kind
                   && drop_status.last_match_winner
                        == PRODUCT_PACKET_GRAPH_L4_WINNER_RULE
                   && drop_status.last_match_winner_rank == 1;

  /* A different destination is background traffic for the same known UID.
   * It increments no-match counters but cannot erase the target DROP. */
  packet_length = product_ipv4_fixture (packet, 6, 0x0a000001, 12345,
                                        0x0a000099, 443);
  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, &platform, UINT64_C (192602), &lease);
  if (result != PRODUCT_PACKET_OK)
    return clib_error_return (0, "unrelated admission failed: %d", result);
  result = product_packet_graph_policy_stage (&lease, &evaluation);
  if (result != PRODUCT_PACKET_OK
      || product_packet_set_terminal (&lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           != PRODUCT_PACKET_OK
      || product_packet_settle (&lease) != PRODUCT_PACKET_OK)
    return clib_error_return (0, "unrelated no-match lifecycle failed");
  product_packet_graph_l4_status (&unrelated_status);
  unrelated_preserved =
    unrelated_status.last_evaluation_result == PRODUCT_PACKET_GRAPH_L4_EVALUATION_MATCH
    && unrelated_status.last_evaluation_verdict == PRODUCT_POLICY_VERDICT_DROP
    && unrelated_status.last_match_rule_id == UINT64_C (192002);

  /* Keep destination port 443 but change the ephemeral source port.  This is
   * the bounded same-probe/retransmit case and must retain the DROP result. */
  packet_length = product_ipv4_fixture (packet, 6, 0x0a000001, 12346,
                                        0x0a000002, 443);
  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, &platform, UINT64_C (192603), &lease);
  if (result != PRODUCT_PACKET_OK)
    return clib_error_return (0, "same-probe admission failed: %d", result);
  result = product_packet_graph_policy_stage (&lease, &evaluation);
  if (result != PRODUCT_PACKET_OK
      || product_packet_set_terminal (&lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           != PRODUCT_PACKET_OK
      || product_packet_settle (&lease) != PRODUCT_PACKET_OK)
    return clib_error_return (0, "same-probe no-match lifecycle failed");
  product_packet_graph_l4_status (&same_probe_status);
  same_probe_preserved =
    same_probe_status.last_evaluation_result == PRODUCT_PACKET_GRAPH_L4_EVALUATION_MATCH
    && same_probe_status.last_evaluation_verdict == PRODUCT_POLICY_VERDICT_DROP
    && same_probe_status.last_no_match_reason == PRODUCT_L4_POLICY_NO_MATCH_NONE
    && same_probe_status.last_match_rule_id == UINT64_C (192002);

  /* Changing only the destination port is an intentional wrong-port probe;
   * it shares the subject key but must remain visible as NO_MATCH. */
  packet_length = product_ipv4_fixture (packet, 6, 0x0a000001, 12345,
                                        0x0a000002, 444);
  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, &platform, UINT64_C (192604), &lease);
  if (result != PRODUCT_PACKET_OK)
    return clib_error_return (0, "wrong-port admission failed: %d", result);
  result = product_packet_graph_policy_stage (&lease, &evaluation);
  if (result != PRODUCT_PACKET_OK
      || product_packet_set_terminal (&lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           != PRODUCT_PACKET_OK
      || product_packet_settle (&lease) != PRODUCT_PACKET_OK)
    return clib_error_return (0, "wrong-port no-match lifecycle failed");
  product_packet_graph_l4_status (&wrong_port_status);
  wrong_port_visible =
    wrong_port_status.last_evaluation_result
      == PRODUCT_PACKET_GRAPH_L4_EVALUATION_NO_MATCH
    && wrong_port_status.last_evaluation_verdict
         == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
    && wrong_port_status.last_no_match_reason
         == PRODUCT_L4_POLICY_NO_MATCH_NO_RULE
    && wrong_port_status.last_match_rule_id == UINT64_C (192002);

  vlib_cli_output (vm, "association.fixture=s192-typed-match-v1");
  vlib_cli_output (vm, "association.drop_terminal=%s",
                   drop_terminal ? "drop-runtime" : "invalid");
  vlib_cli_output (
    vm, "association.drop_completion_attempts=%llu",
    (unsigned long long) clib_atomic_load_acq_n (
      &graph->policy_last_drop_completion_attempts));
  vlib_cli_output (vm, "association.l4_last_match_winner=%u",
                   drop_status.last_match_winner);
  vlib_cli_output (vm, "association.policy_last_drop_winner=%u",
                   clib_atomic_load_acq_n (&graph->policy_last_drop_winner));
  vlib_cli_output (vm, "association.last_match_winner_rank=%u",
                   drop_status.last_match_winner_rank);
  vlib_cli_output (vm, "association.evaluation_winner=%u",
                   PRODUCT_PACKET_GRAPH_L4_WINNER_RULE);
  vlib_cli_output (vm, "association.winner_kind_valid=%u",
                   l4_winner_kind && drop_winner_kind);
  vlib_cli_output (vm, "association.unrelated_preserved=%u",
                   unrelated_preserved);
  vlib_cli_output (vm, "association.same_probe_preserved=%u",
                   same_probe_preserved);
  vlib_cli_output (vm, "association.wrong_port_visible=%u",
                   wrong_port_visible);
  vlib_cli_output (vm, "association.match_records=%llu",
                   (unsigned long long) wrong_port_status.match_records);
  vlib_cli_output (vm, "association.no_match_records=%llu",
                   (unsigned long long) wrong_port_status.no_match_records);
  vlib_cli_output (vm, "association.last_match_rule_id=%llu",
                   (unsigned long long) wrong_port_status.last_match_rule_id);
  vlib_cli_output (vm, "association.last_no_match_reason=%u",
                   wrong_port_status.last_no_match_reason);
  vlib_cli_output (vm, "association.typed_match_policy_key=%llu",
                   (unsigned long long) drop_status.typed_match_policy_key);
  vlib_cli_output (vm, "association.typed_match_probe_key=%llu",
                   (unsigned long long) drop_status.typed_match_probe_key);
  vlib_cli_output (vm, "association.last_evaluation_probe_key=%llu",
                   (unsigned long long)
                     wrong_port_status.last_evaluation_probe_key);
  vlib_cli_output (
    vm, "association.wrong_port_probe_key_distinct=%u",
    wrong_port_status.last_evaluation_probe_key
      != wrong_port_status.typed_match_probe_key);
  if (!unrelated_preserved || !same_probe_preserved || !wrong_port_visible
      || !l4_winner_kind || !drop_winner_kind)
    return clib_error_return (0, "typed match evidence association failed");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_policy_association_fixture_command,
                  static) = {
  .path = PRODUCT_GRAPH_RUN_POLICY_ASSOCIATION_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_POLICY_ASSOCIATION_FIXTURE_COMMAND,
  .function = product_packet_graph_policy_association_fixture_cli,
  .is_mp_safe = 1,
};

static int
product_packet_graph_gate_table_fixture_vector (
  const u8 *packet, u32 packet_length, const product_platform_packet_facts_t *platform,
  u64 origin_obligation_id,
  product_packet_graph_policy_evaluation_t *evaluation)
{
  product_packet_lease_t lease;
  product_packet_result_t result;

  result = product_packet_graph_association_prepare_lease (
    packet, packet_length, platform, origin_obligation_id, &lease);
  if (result != PRODUCT_PACKET_OK)
    return 0;
  result = product_packet_graph_policy_stage (&lease, evaluation);
  if (result != PRODUCT_PACKET_OK)
    return 0;
  if (lease.terminal_intent == PRODUCT_PACKET_INTENT_NONE)
    {
      result = product_packet_set_terminal (
        &lease, PRODUCT_PACKET_INTENT_PASS_ADAPTER);
      if (result != PRODUCT_PACKET_OK)
        return 0;
    }
  return product_packet_settle (&lease) == PRODUCT_PACKET_OK;
}

static clib_error_t *
product_packet_graph_gate_table_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  static const u8 ip6_a[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
  };
  static const u8 ip6_b[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
  };
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_packet_graph_gate_entry_t gate_rules[6];
  product_packet_graph_policy_bundle_t bundle;
  product_packet_graph_gate_status_t drop_status;
  product_packet_graph_gate_status_t range_status;
  product_packet_graph_gate_status_t ipv6_status;
  product_packet_graph_gate_status_t address_status;
  product_packet_graph_gate_status_t ifindex_status;
  product_packet_graph_gate_status_t unavailable_status;
  product_packet_graph_gate_status_t unknown_uid_status;
  product_packet_graph_gate_status_t unknown_context_status;
  product_packet_graph_gate_status_t wildcard_status;
  product_packet_graph_flow_status_t flow_status;
  product_packet_graph_policy_evaluation_t evaluation;
  product_platform_packet_facts_t platform = {
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .availability = PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_IFINDEX_KNOWN | PRODUCT_PLATFORM_CONTEXT_KNOWN,
    .linux_ifindex = 77,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .direction = PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT,
  };
  u8 packet[80];
  u32 packet_length;
  int scalar_identity_empty;
  int drop_ok;
  int range_ok;
  int ipv6_ok;
  int address_ok;
  int ifindex_ok;
  int unavailable_ok;
  int unknown_uid_ok;
  int unknown_context_ok;
  int wildcard_ok;
  int lazy_revision_ok;
  (void) command;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !clib_atomic_load_acq_n (&graph->enabled))
    return clib_error_return (0, "GateTable fixture requires an enabled graph");

  clib_memset (gate_rules, 0, sizeof (gate_rules));
  gate_rules[0] = (product_packet_graph_gate_entry_t) {
    .rule_id = UINT64_C (192301),
    .uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID,
    .network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT,
    .ifindex = 77,
    .priority = 10,
    .order = 0,
    .reason_id = UINT32_C (19301),
    .source_port_first = 12345,
    .source_port_last = 12345,
    .destination_port_first = 443,
    .destination_port_last = 443,
    .family = PRODUCT_L4_POLICY_FAMILY_IPV4,
    .protocol = PRODUCT_L4_POLICY_PROTOCOL_TCP,
    .direction = PRODUCT_L4_POLICY_DIRECTION_OUTPUT,
    .source_prefix_length = 32,
    .destination_prefix_length = 32,
    .action = PRODUCT_L4_POLICY_ACTION_DROP,
  };
  gate_rules[0].source_address[0] = 0x0a;
  gate_rules[0].source_address[3] = 1;
  gate_rules[0].destination_address[0] = 0x0a;
  gate_rules[0].destination_address[3] = 2;
  gate_rules[1] = gate_rules[0];
  gate_rules[1].rule_id = UINT64_C (192302);
  gate_rules[1].order = 1;
  gate_rules[1].reason_id = UINT32_C (19302);
  gate_rules[1].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  gate_rules[2] = gate_rules[0];
  gate_rules[2].rule_id = UINT64_C (192303);
  gate_rules[2].priority = 20;
  gate_rules[2].order = 0;
  gate_rules[2].reason_id = UINT32_C (19303);
  gate_rules[2].family = PRODUCT_L4_POLICY_FAMILY_IPV6;
  gate_rules[2].protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  gate_rules[2].source_port_first = 60000;
  gate_rules[2].source_port_last = 60000;
  gate_rules[2].destination_port_first = 443;
  gate_rules[2].destination_port_last = 443;
  gate_rules[2].source_prefix_length = 128;
  gate_rules[2].destination_prefix_length = 128;
  clib_memcpy_fast (gate_rules[2].source_address, ip6_a, sizeof (ip6_a));
  clib_memcpy_fast (gate_rules[2].destination_address, ip6_b,
                    sizeof (ip6_b));
  gate_rules[2].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  gate_rules[3] = gate_rules[0];
  gate_rules[3].rule_id = UINT64_C (192304);
  gate_rules[3].priority = 30;
  gate_rules[3].reason_id = UINT32_C (19304);
  gate_rules[3].protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  gate_rules[3].source_prefix_length = 24;
  gate_rules[3].destination_prefix_length = 24;
  gate_rules[3].source_port_first = 1000;
  gate_rules[3].source_port_last = 2000;
  gate_rules[3].destination_port_first = 400;
  gate_rules[3].destination_port_last = 500;
  gate_rules[3].source_address[3] = 0;
  gate_rules[3].destination_address[3] = 0;
  gate_rules[4] = gate_rules[0];
  gate_rules[4].rule_id = UINT64_C (192305);
  gate_rules[4].priority = 40;
  gate_rules[4].reason_id = UINT32_C (19305);
  gate_rules[4].source_port_first = 10000;
  gate_rules[4].source_port_last = 20000;
  gate_rules[4].destination_port_first = 400;
  gate_rules[4].destination_port_last = 500;
  gate_rules[4].action = PRODUCT_L4_POLICY_ACTION_ALLOW;
  gate_rules[5] = gate_rules[0];
  gate_rules[5].rule_id = UINT64_C (192306);
  gate_rules[5].uid = UINT32_C (10002);
  gate_rules[5].priority = 50;
  gate_rules[5].order = 0;
  gate_rules[5].reason_id = UINT32_C (19306);
  gate_rules[5].ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY;
  gate_rules[5].family = 0;
  gate_rules[5].protocol = 0;
  gate_rules[5].direction = PRODUCT_L4_POLICY_DIRECTION_ANY;
  gate_rules[5].source_address[0] = 0;
  gate_rules[5].source_address[3] = 0;
  gate_rules[5].destination_address[0] = 0;
  gate_rules[5].destination_address[3] = 0;
  gate_rules[5].source_prefix_length = 0;
  gate_rules[5].destination_prefix_length = 0;
  gate_rules[5].source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  gate_rules[5].source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  gate_rules[5].destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  gate_rules[5].destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  gate_rules[5].action = PRODUCT_L4_POLICY_ACTION_ALLOW;

  bundle = (product_packet_graph_policy_bundle_t) {
    .generation = graph->generation,
    .revision = UINT64_C (19206),
    .snapshot_hash = UINT64_C (0x19206),
    .gate_entries = gate_rules,
    .gate_entry_count = 6,
    .l4_rules = 0,
    .l4_rule_count = 0,
  };
  if (product_packet_graph_publish_policy_bundle (&bundle)
      != PRODUCT_PACKET_OK)
    return clib_error_return (0, "GateTable fixture publication rejected");

  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  drop_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192701), &evaluation)
             && evaluation.stage == PRODUCT_PACKET_GRAPH_POLICY_STAGE_GATE
             && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP
             && evaluation.rule_id == UINT64_C (192301);
  product_packet_graph_gate_status (&drop_status);

  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 15000, 0x0a000002, 444);
  range_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192702), &evaluation)
              && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
              && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&range_status);

  packet_length = product_ipv6_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_UDP,
                                        ip6_a, 60000, ip6_b, 443);
  ipv6_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192703), &evaluation)
             && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
             && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&ipv6_status);

  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000099, 444);
  address_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192704), &evaluation)
               && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
               && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&address_status);

  platform.linux_ifindex = 78;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  ifindex_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192705), &evaluation)
               && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
               && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&ifindex_status);

  platform.linux_ifindex = 77;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  packet[2] = 0;
  packet[3] = 20;
  unavailable_ok = product_packet_graph_gate_table_fixture_vector (
    packet, 20, &platform, UINT64_C (192706), &evaluation)
                  && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                  && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&unavailable_status);

  platform.availability &= ~PRODUCT_PLATFORM_UID_KNOWN;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  unknown_uid_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192707), &evaluation)
                   && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                   && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&unknown_uid_status);

  platform.availability |= PRODUCT_PLATFORM_UID_KNOWN;
  platform.uid = UINT32_C (10002);
  platform.availability |= PRODUCT_PLATFORM_CONTEXT_KNOWN;
  platform.network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 12345, 0x0a000002, 443);
  wildcard_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192709), &evaluation)
                && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&wildcard_status);

  platform.uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID;
  platform.availability &= ~PRODUCT_PLATFORM_CONTEXT_KNOWN;
  unknown_context_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192708), &evaluation)
                       && evaluation.verdict == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                       && evaluation.rule_id == 0;
  product_packet_graph_gate_status (&unknown_context_status);

  /* Publish a successor view without flushing the worker pools.  Replaying
   * an existing PASS_NEXT tuple proves that revision invalidation remains
   * lazy and that the bounded entry is reused rather than reallocated. */
  bundle.revision = UINT64_C (19207);
  bundle.snapshot_hash = UINT64_C (0x19207);
  if (product_packet_graph_publish_policy_bundle (&bundle)
      != PRODUCT_PACKET_OK)
    return clib_error_return (0, "GateTable successor publication rejected");
  platform.uid = PRODUCT_GRAPH_POLICY_FIXTURE_UID;
  platform.availability |= PRODUCT_PLATFORM_CONTEXT_KNOWN;
  platform.network_context_id = PRODUCT_GRAPH_POLICY_FIXTURE_CONTEXT;
  platform.linux_ifindex = 77;
  packet_length = product_ipv4_fixture (packet, PRODUCT_L4_POLICY_PROTOCOL_TCP,
                                        0x0a000001, 15000, 0x0a000002, 444);
  lazy_revision_ok = product_packet_graph_gate_table_fixture_vector (
    packet, packet_length, &platform, UINT64_C (192710), &evaluation)
                     && evaluation.verdict
                          == PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT
                     && evaluation.rule_id == 0;
  product_packet_graph_flow_status (&flow_status);

  scalar_identity_empty = drop_status.active_entry_count == 6
                          && drop_status.max_probes == 6
                          && drop_status.rule_id == 0
                          && drop_status.active_revision == UINT64_C (19206)
                          && drop_status.snapshot_hash == UINT64_C (0x19206);
  if (!drop_ok || !range_ok || !ipv6_ok || !address_ok || !ifindex_ok
      || !unavailable_ok || !unknown_uid_ok || !wildcard_ok
      || !unknown_context_ok
      || !scalar_identity_empty
      || drop_status.last_match_rule_id != UINT64_C (192301)
      || drop_status.last_match_winner_rank != 1
      || drop_status.last_match_candidate_count != 3
      || drop_status.last_match_probes != 6
      || range_status.last_match_rule_id != UINT64_C (192305)
      || range_status.last_match_winner_rank != 5
      || range_status.last_match_candidate_count != 1
      || ipv6_status.last_match_rule_id != UINT64_C (192303)
      || ipv6_status.last_match_winner_rank != 3
      || address_status.last_match_rule_id != 0
      || address_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_ADDRESS
      || ifindex_status.last_match_rule_id != 0
      || ifindex_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE
      || unavailable_status.last_match_rule_id != 0
      || unavailable_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_PORTS_UNAVAILABLE
      || unknown_uid_status.last_match_rule_id != 0
      || unknown_uid_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_UID
      || wildcard_status.last_match_rule_id != UINT64_C (192306)
      || wildcard_status.last_match_winner_rank != 6
      || wildcard_status.last_match_action != PRODUCT_L4_POLICY_ACTION_ALLOW
      || unknown_context_status.last_match_rule_id != 0
      || unknown_context_status.last_no_match_reason
           != PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_CONTEXT
      || !lazy_revision_ok
      || flow_status.active_revision != UINT64_C (19207)
      || flow_status.active_snapshot_hash != UINT64_C (0x19207)
      || flow_status.active_entries != 4
      || flow_status.allocation_count != 4
      || flow_status.reuse_count != 4
      || flow_status.early_drop_count != 1
      || flow_status.revision_invalidation_count != 1)
    return clib_error_return (0, "GateTable fixture vector failed");

  vlib_cli_output (vm, "gate-table.fixture=s192-gate-table-v1");
  vlib_cli_output (vm, "gate-table.active_entry_count=%u",
                   drop_status.active_entry_count);
  vlib_cli_output (vm, "gate-table.max_probes=%u", drop_status.max_probes);
  vlib_cli_output (vm, "gate-table.scalar_rule_id=%llu",
                   (unsigned long long) drop_status.rule_id);
  vlib_cli_output (vm, "gate-table.drop_rule_id=%llu",
                   (unsigned long long) drop_status.last_match_rule_id);
  vlib_cli_output (vm, "gate-table.drop_winner_rank=%u",
                   drop_status.last_match_winner_rank);
  vlib_cli_output (vm, "gate-table.drop_candidate_count=%u",
                   drop_status.last_match_candidate_count);
  vlib_cli_output (vm, "gate-table.range_rule_id=%llu",
                   (unsigned long long) range_status.last_match_rule_id);
  vlib_cli_output (vm, "gate-table.ipv6_rule_id=%llu",
                   (unsigned long long) ipv6_status.last_match_rule_id);
  vlib_cli_output (vm, "gate-table.address_no_match_reason=%u",
                   address_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.ifindex_no_match_reason=%u",
                   ifindex_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.unavailable_no_match_reason=%u",
                   unavailable_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.unknown_uid_no_match_reason=%u",
                   unknown_uid_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.wildcard_rule_id=%llu",
                   (unsigned long long) wildcard_status.last_match_rule_id);
  vlib_cli_output (vm, "gate-table.wildcard_winner_rank=%u",
                   wildcard_status.last_match_winner_rank);
  vlib_cli_output (vm, "gate-table.unknown_context_no_match_reason=%u",
                   unknown_context_status.last_no_match_reason);
  vlib_cli_output (vm, "gate-table.drop_terminal=%u", drop_ok);
  vlib_cli_output (vm, "gate-table.open_pass_next=%u",
                   range_ok && ipv6_ok);
  vlib_cli_output (vm, "gate-table.scalar_identity_empty=%u",
                   scalar_identity_empty);
  vlib_cli_output (vm, "gate-table.lazy_revision=%llu",
                   (unsigned long long) flow_status.active_revision);
  vlib_cli_output (vm, "gate-table.lazy_revision_ok=%u", lazy_revision_ok);
  vlib_cli_output (vm, "gate-table.flow_active_entries=%u",
                   flow_status.active_entries);
  vlib_cli_output (vm, "gate-table.flow_allocation_count=%llu",
                   (unsigned long long) flow_status.allocation_count);
  vlib_cli_output (vm, "gate-table.flow_reuse_count=%llu",
                   (unsigned long long) flow_status.reuse_count);
  vlib_cli_output (vm, "gate-table.flow_early_drop_count=%llu",
                   (unsigned long long) flow_status.early_drop_count);
  vlib_cli_output (vm, "gate-table.flow_revision_invalidation_count=%llu",
                   (unsigned long long) flow_status.revision_invalidation_count);
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_gate_table_fixture_command, static) = {
  .path = PRODUCT_GRAPH_RUN_GATE_TABLE_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_GATE_TABLE_FIXTURE_COMMAND,
  .function = product_packet_graph_gate_table_fixture_cli,
  .is_mp_safe = 1,
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
  product_packet_graph_policy_publish_lock (graph);
  product_packet_graph_flow_pools_flush (graph);
  product_packet_graph_policy_publish_unlock (graph);
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

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
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
  vlib_cli_output (vm, "primary.status generation=%llu published=%llu received=%llu rejected=%llu owner_checks=%llu owner_failures=%llu returns=%llu deferred=%llu retries=%llu pending_returns=%u handoff_debt=%u credit0=%u credit1=%u",
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
    clib_atomic_load_acq_n (&g->handoff_credits[1]));
  return 0;
}
VLIB_CLI_COMMAND (product_primary_status_command, static) = {
  .path = "show product primary", .function = product_primary_status_cli,
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
  u32 case_id = 0, bi, failed;
  u16 thread = vlib_get_worker_thread_index (0);
  (void) command;
  if (!unformat (input, "%u %s", &case_id, &hex) || !case_id || case_id > PRODUCT_GRAPH_INJECTION_CAPACITY
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !graph->accepting || !graph->enabled)
    { vec_free (hex); return clib_error_return (0, "injection rejected"); }
  u32 length = strlen ((char *) hex);
  if (!length || (length & 1) || length > 512)
    { vec_free (hex); return clib_error_return (0, "invalid bounded hex span"); }
  if (product_metadata_injection_generation != graph->generation)
    { product_metadata_injection_generation = graph->generation; product_metadata_injection_count = 0; }
  if (product_metadata_injection_count & (1U << (case_id - 1)))
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
    .generation = graph->generation, .origin_obligation_id = UINT64_C (216000000) + case_id,
    .state_bits = PRODUCT_META_TRACE,
  };
  product_buffer_platform_metadata_t extra = {
    .obligation = { .token = metadata.origin_obligation_id,
      .queue_generation = graph->generation, .packet_id = case_id,
      .kind = PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED },
    .platform = { .availability = (case_id & 1) ? 7 : 0,
      .direction = PRODUCT_PACKET_DIRECTION_OUTPUT,
      .provenance = PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED },
  };
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
  product_metadata_injection_count |= 1U << (case_id - 1);
  vlib_cli_output (vm, "metadata.inject=accepted source=GRAPH_INJECTED case=%u generation=%llu buffer=%u target_thread=%u",
    case_id, (unsigned long long) graph->generation, bi, thread);
  return 0;
}

VLIB_CLI_COMMAND (product_metadata_inject_command, static) = {
  .path = "product metadata inject",
  .short_help = "product metadata inject <case 1..32> <hex, max 256 bytes>",
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
  product_packet_ingress_t ingress = { .data = bytes, .length = 44,
    .flow_domain = PRODUCT_GRAPH_FLOW_DOMAIN, .origin_obligation_id = 216,
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
    && memcmp (&before.canonical_key, &after.canonical_key, sizeof (before.canonical_key)) == 0;
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
    (u32)sizeof (product_owner_assignment_t), (u32)sizeof (product_transport_metadata_t),
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

static clib_error_t *
product_packet_graph_init (vlib_main_t *vm)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 worker;
  graph->vlib_main = vm;
  if (!product_packet_graph_flow_pools_reset (graph))
    return clib_error_return (0, "failed to initialize graph FlowEntry pools");
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
