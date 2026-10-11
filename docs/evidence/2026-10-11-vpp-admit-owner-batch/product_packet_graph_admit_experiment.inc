/* SPDX-License-Identifier: Apache-2.0 */
/* Compile-time opt-in experiment. Scratch is worker-private and is used only
 * during one admit-node invocation; it never owns a cross-callback backlog. */
#include "product_fragment.h"

#define PRODUCT_ADMIT_BATCH_PAD 16
typedef struct
{
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE];
  product_buffer_metadata_t initial[VLIB_FRAME_SIZE];
  product_buffer_metadata_t metadata[VLIB_FRAME_SIZE];
  product_packet_lease_t leases[VLIB_FRAME_SIZE];
  product_packet_result_t results[VLIB_FRAME_SIZE];
  u8 prepared[VLIB_FRAME_SIZE];
  /* Pinned native mask/compress helpers may read vector padding. */
  u32 indices[VLIB_FRAME_SIZE + PRODUCT_ADMIT_BATCH_PAD];
  u16 targets[VLIB_FRAME_SIZE + PRODUCT_ADMIT_BATCH_PAD];
  u16 slots[VLIB_FRAME_SIZE + PRODUCT_ADMIT_BATCH_PAD];
  u32 failed[VLIB_FRAME_SIZE + PRODUCT_ADMIT_BATCH_PAD];
  u32 count;
} __attribute__((aligned(CLIB_CACHE_LINE_BYTES))) product_admit_batch_scratch_t;

typedef struct
{
  u64 primary_calls, primary_packets, primary_transferred, primary_rejected;
  u64 prepared_quads, prepared_scalars, special_packets, external_frames;
} __attribute__((aligned(CLIB_CACHE_LINE_BYTES))) product_admit_experiment_stats_t;

static product_admit_batch_scratch_t product_admit_scratch[PRODUCT_GRAPH_WORKERS + 1];
static product_admit_experiment_stats_t product_admit_stats[PRODUCT_GRAPH_WORKERS + 1];
static u32 product_admit_experiment_enabled;
extern vlib_node_registration_t product_packet_admit_node;

int
product_packet_graph_admit_batch_enabled (void)
{
  return product_admit_experiment_enabled != 0;
}

static void
product_admit_experiment_primary_attempt (vlib_main_t *vm, u32 count)
{
  ASSERT (vm->thread_index <= PRODUCT_GRAPH_WORKERS);
  product_admit_stats[vm->thread_index].primary_calls++;
  product_admit_stats[vm->thread_index].primary_packets += count;
}

static void
product_admit_experiment_primary_result (vlib_main_t *vm, u32 transferred,
                                         u32 rejected)
{
  product_admit_stats[vm->thread_index].primary_transferred += transferred;
  product_admit_stats[vm->thread_index].primary_rejected += rejected;
}

static_always_inline void
product_admit_batch_prepare_one (vlib_main_t *vm, product_admit_batch_scratch_t *s,
                                 u32 index)
{
  vlib_buffer_t *b = s->buffers[index];
  product_fragment_piece_t piece;
  product_packet_facts_t fragment_facts;
  product_metadata_load (b, &s->initial[index]);
  s->prepared[index] = 0;
  /* Fragment state and side-event publication remain in the original ordered
   * path. This probe is pure; malformed fragment envelopes also fall back. */
  if (s->initial[index].fragment_bundle_count ||
      product_fragment_parse (vlib_buffer_get_current (b), b->current_length,
                              &piece, &fragment_facts) != 0)
    return;
  product_packet_ingress_t ingress = {
    .data = vlib_buffer_get_current (b), .length = b->current_length,
    .current_worker = vlib_get_worker_index (vm->thread_index),
    .origin_obligation_id = s->initial[index].origin_obligation_id,
  };
  product_worker_layout_t layout = {
    .worker_count = PRODUCT_GRAPH_WORKERS, .hash_seed = PRODUCT_GRAPH_HASH_SEED,
  };
  if (!product_packet_graph_get_platform_facts (
        b, s->initial[index].generation, &ingress.platform))
    product_packet_graph_platform_facts_unknown (&ingress.platform);
  clib_memset (&s->leases[index], 0, sizeof (s->leases[index]));
  s->results[index] = product_packet_admit (&layout, &ingress, &s->leases[index]);
  s->prepared[index] = 1;
}

static product_admit_batch_scratch_t *
product_admit_batch_prepare (vlib_main_t *vm, u32 *from, u32 count)
{
  ASSERT (vm->thread_index <= PRODUCT_GRAPH_WORKERS && count <= VLIB_FRAME_SIZE);
  product_admit_batch_scratch_t *s = &product_admit_scratch[vm->thread_index];
  ASSERT (s->count == 0);
  vlib_get_buffers (vm, from, s->buffers, count);
  u32 i = 0;
  for (; i + 8 <= count; i += 4)
    {
      for (u32 j = 0; j < 4; j++)
        {
          clib_prefetch_load (s->buffers[i + 4 + j]);
          CLIB_PREFETCH (vlib_buffer_get_current (s->buffers[i + 4 + j]),
                         2 * CLIB_CACHE_LINE_BYTES, LOAD);
        }
      for (u32 j = 0; j < 4; j++)
        product_admit_batch_prepare_one (vm, s, i + j);
      product_admit_stats[vm->thread_index].prepared_quads++;
    }
  for (; i < count; i++)
    {
      product_admit_batch_prepare_one (vm, s, i);
      product_admit_stats[vm->thread_index].prepared_scalars++;
    }
  return s;
}

static void
product_admit_batch_flush (vlib_main_t *vm, vlib_node_runtime_t *node,
                           product_admit_batch_scratch_t *s)
{
  u32 count = s->count;
  if (!count) return;
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u8 rejected[VLIB_FRAME_SIZE] = { 0 };
  product_admit_experiment_primary_attempt (vm, count);
  u32 transferred = vlib_buffer_enqueue_to_thread_retained (
    vm, node, graph->primary_frame_queue, s->indices, s->targets, count, s->failed);
  ASSERT (transferred <= count);
  u32 failed_count = count - transferred;
  /* Only local snapshots and index values are read after publication. Never
   * inspect a successfully transferred native buffer, even for diagnostics. */
  for (u32 f = 0; f < failed_count; f++)
    {
      u32 i = 0;
      while (i < count && s->indices[i] != s->failed[f]) i++;
      ASSERT (i < count && !rejected[i]);
      rejected[i] = 1;
    }
  s->count = 0;
  product_admit_experiment_primary_result (vm, transferred, failed_count);
  clib_atomic_fetch_add_relax (&graph->primary_published, transferred);
  for (u32 i = 0; i < count; i++)
    {
      u32 slot = s->slots[i], bi = s->indices[i];
      product_buffer_metadata_t *metadata = &s->metadata[slot];
      if (!rejected[i])
        {
          if (metadata->state_bits & PRODUCT_META_TRACE)
            fprintf (stderr, "s205 event=primary_accepted thread=%u buffer=%u token=%llu generation=%llu owner=%u target_thread=%u\n",
              vm->thread_index, bi, (unsigned long long)metadata->origin_obligation_id,
              (unsigned long long)metadata->generation, metadata->expected_owner, s->targets[i]);
          continue;
        }
      metadata->state_bits &= ~PRODUCT_META_HANDOFF_CREDIT;
      product_handoff_credit_release (graph, metadata->expected_owner);
      clib_atomic_fetch_add_relax (&graph->primary_rejected, 1);
      product_packet_lease_t *lease = &s->leases[slot];
      if (product_packet_bypass_primary_capacity (
            lease, PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED) != PRODUCT_PACKET_OK)
        {
          lease->terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
          lease->terminal_count = 1;
          lease->runtime_drop_reason = PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION;
        }
      product_metadata_set_terminal_intent (metadata, lease->terminal_intent);
      metadata->runtime_drop_reason = lease->runtime_drop_reason;
      metadata->processing_bypass_reason = lease->processing_bypass_reason;
      product_metadata_store (vlib_get_buffer (vm, bi), metadata);
      vlib_buffer_enqueue_to_single_next (vm, node, &bi, PRODUCT_ADMIT_NEXT_TERMINAL, 1);
    }
}

static int
product_admit_batch_stage_primary (vlib_main_t *vm, vlib_node_runtime_t *node,
                                   product_admit_batch_scratch_t *s, u32 slot,
                                   u32 bi, product_buffer_metadata_t *metadata,
                                   product_packet_processing_bypass_reason_t *reason)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u16 owner = metadata->expected_owner;
  u16 target = vlib_get_worker_thread_index (owner);
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
      target = vm->thread_index;
      metadata->state_bits |= PRODUCT_META_TRACE;
    }
  metadata->state_bits |= PRODUCT_META_HANDOFF_CREDIT;
  product_metadata_store (vlib_get_buffer (vm, bi), metadata);
  s->metadata[slot] = *metadata;
  if (metadata->state_bits & PRODUCT_META_TRACE)
    fprintf (stderr, "s205 event=primary_publish thread=%u buffer=%u token=%llu generation=%llu owner=%u target_thread=%u primary=%u corrective=%u\n",
      vm->thread_index, bi, (unsigned long long)metadata->origin_obligation_id,
      (unsigned long long)metadata->generation, owner, target,
      metadata->primary_handoff_count, metadata->corrective_handoff_count);
  ASSERT (s->count < VLIB_FRAME_SIZE);
  u32 position = s->count++;
  s->indices[position] = bi;
  s->targets[position] = target;
  s->slots[position] = slot;
  if (s->count == VLIB_FRAME_SIZE) product_admit_batch_flush (vm, node, s);
  return 1;
}

static clib_error_t *
product_admit_experiment_cli (vlib_main_t *vm, unformat_input_t *input,
                              vlib_cli_command_t *command)
{
  (void)command;
  u32 selected = product_admit_experiment_enabled;
  int change = 1;
  if (unformat (input, "baseline")) selected = 0;
  else if (unformat (input, "batch")) selected = 1;
  else if (unformat (input, "show")) change = 0;
  else return clib_error_return (0, "expected baseline, batch or show");
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unexpected argument");
  product_packet_graph_main_t *g = &product_packet_graph_main;
  if (!g->enabled || !g->accepting)
    return clib_error_return (0, "experiment requires an active graph");
  if (change)
    {
      if (g->lifecycle_buffers || g->lifecycle_obligations || g->lifecycle_handoffs ||
          g->lifecycle_completion_frames || g->completion_pending_returns ||
          !product_capacity_ring_empty (g->primary_frame_queue) ||
          !product_capacity_ring_empty (g->completion_return_frame_queue))
        return clib_error_return (0, "mode change requires an empty graph");
      product_admit_experiment_enabled = selected;
      clib_memset (product_admit_stats, 0, sizeof (product_admit_stats));
    }
  vlib_cli_output (vm, "admit.experiment mode=%s generation=%llu scratch_bytes=%u",
    selected ? "batch" : "baseline", (unsigned long long)g->generation,
    (u32)sizeof(product_admit_scratch));
  vlib_frame_queue_main_t *fqm = vec_elt_at_index (
    vlib_get_thread_main()->frame_queue_mains, g->primary_frame_queue);
  for (u32 t = 0; t <= PRODUCT_GRAPH_WORKERS; t++)
    {
      vlib_main_t *worker_vm = vlib_get_main_by_index (t);
      vlib_node_t *n = vlib_get_node (worker_vm, product_packet_admit_node.index);
      vlib_node_sync_stats (worker_vm, n);
      product_admit_experiment_stats_t *s = &product_admit_stats[t];
      vlib_cli_output (vm, "admit.experiment.thread thread=%u node_calls=%llu node_vectors=%llu node_clocks=%llu primary_calls=%llu primary_packets=%llu transferred=%llu rejected=%llu quads=%llu scalars=%llu special=%llu external_frames=%llu",
        t, (unsigned long long)n->stats_total.calls,
        (unsigned long long)n->stats_total.vectors, (unsigned long long)n->stats_total.clocks,
        (unsigned long long)s->primary_calls, (unsigned long long)s->primary_packets,
        (unsigned long long)s->primary_transferred, (unsigned long long)s->primary_rejected,
        (unsigned long long)s->prepared_quads, (unsigned long long)s->prepared_scalars,
        (unsigned long long)s->special_packets, (unsigned long long)s->external_frames);
      vlib_frame_queue_t *fq = fqm->vlib_frame_queues[t];
      if (fq) vlib_cli_output (vm, "admit.experiment.queue thread=%u head=%llu tail=%llu",
        t, (unsigned long long)fq->head, (unsigned long long)fq->tail);
    }
  return 0;
}
VLIB_CLI_COMMAND (product_admit_experiment_command, static) = {
  .path = "product admit-batch", .function = product_admit_experiment_cli,
  /* Default CLI worker barrier protects mode changes and statistics scraping. */
};
