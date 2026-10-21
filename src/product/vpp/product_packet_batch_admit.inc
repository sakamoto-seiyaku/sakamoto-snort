/* SPDX-License-Identifier: Apache-2.0 */
/* Private to product_packet_graph.c; synchronous, bounded source ownership. */
typedef struct
{
  u32 indices[64];
  u16 targets[64];
  product_buffer_metadata_t metadata[PRODUCT_PACKET_BATCH_SIZE];
  u32 count;
} product_primary_batch_t;

static_always_inline int
product_batch_metadata_span_valid (const product_buffer_metadata_t *metadata,
                                   const vlib_buffer_t *buffer)
{
  if (buffer->current_data != metadata->span_current_data ||
      buffer->current_length != metadata->span_length ||
      metadata->packet_length > buffer->current_length)
    return 0;
  if (metadata->l3_status == PRODUCT_PACKET_L3_COMPLETE)
    {
      u32 offset = metadata->ip_family == 4 ? 12 : 8;
      u32 width = metadata->ip_family == 4 ? 4 : 16;
      return (metadata->ip_family == 4 || metadata->ip_family == 6) &&
        offset + 2 * width <= metadata->packet_length &&
        metadata->l3_header_length <= metadata->packet_length &&
        metadata->l3_header_length + metadata->l4_header_length <= metadata->packet_length;
    }
  return 1;
}

static void
product_batch_terminal_lease (const product_buffer_metadata_t *metadata,
  const vlib_buffer_t *buffer, product_packet_lease_t *lease)
{
  clib_memset (lease, 0, sizeof (*lease));
  lease->origin_obligation_id = metadata->origin_obligation_id;
  lease->policy_owner_ready = !!(metadata->state_bits & PRODUCT_META_POLICY_READY);
  lease->terminal_intent = product_metadata_terminal_intent (metadata);
  lease->terminal_count = lease->terminal_intent != PRODUCT_PACKET_INTENT_NONE;
  lease->runtime_drop_reason = metadata->runtime_drop_reason;
  lease->processing_bypass_reason = metadata->processing_bypass_reason;
  lease->settled = !!(metadata->state_bits & PRODUCT_META_SETTLED);
  if (!product_batch_metadata_span_valid (metadata, buffer))
    {
      lease->policy_owner_ready = 0;
      lease->terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
      lease->terminal_count = 1;
      lease->runtime_drop_reason = PRODUCT_PACKET_DROP_INVALID_ENVELOPE;
      return;
    }
  lease->facts.l3_status = metadata->l3_status;
  lease->facts.l4_status = metadata->l4_status;
  lease->facts.ip_family = metadata->ip_family;
  lease->facts.protocol = metadata->protocol;
  lease->facts.packet_length = metadata->packet_length;
  product_packet_graph_get_platform_facts (buffer, metadata->generation, &lease->platform);
}

static void
product_batch_flow_prefetch (vlib_main_t *vm, vlib_buffer_t **buffers,
  u32 at, u32 count, product_flow_prefetch_stage_t stage)
{
  if (at >= count || product_buffer_is_flow_end (buffers[at])) return;
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_buffer_metadata_t metadata;
  vlib_buffer_t *buffer = buffers[at];
  product_metadata_load (buffer, &metadata);
  u16 worker = vlib_get_worker_index (vm->thread_index);
  if (metadata.generation != graph->generation || !metadata.assignment_valid ||
      metadata.l3_status != PRODUCT_PACKET_L3_COMPLETE ||
      metadata.expected_owner != worker ||
      product_metadata_terminal_intent (&metadata) != PRODUCT_PACKET_INTENT_NONE ||
      !product_batch_metadata_span_valid (&metadata, buffer))
    return;
  product_owner_assignment_t assignment = {
    .valid = 1, .execution_owner = worker, .canonical_hash = metadata.canonical_hash,
    .source_is_a = !!(metadata.state_bits & PRODUCT_META_SOURCE_IS_A),
    .key = { .kind = metadata.key_kind, .query_class = metadata.query_class,
      .ip_family = metadata.ip_family, .protocol = metadata.protocol },
  };
  if (stage != PRODUCT_FLOW_PREFETCH_BUCKET)
    {
      const u8 *packet = vlib_buffer_get_current (buffer);
      u32 width = metadata.ip_family == 4 ? 4 : 16;
      u32 offset = metadata.ip_family == 4 ? 12 : 8;
      u8 *source = assignment.source_is_a ? assignment.key.address_a : assignment.key.address_b;
      u8 *destination = assignment.source_is_a ? assignment.key.address_b : assignment.key.address_a;
      clib_memcpy_fast (source + 16 - width, packet + offset, width);
      clib_memcpy_fast (destination + 16 - width, packet + offset + width, width);
      if (metadata.key_kind == PRODUCT_OWNER_KEY_L4_PORTS)
        {
          assignment.key.transport.ports.a = assignment.source_is_a
            ? metadata.source_port : metadata.destination_port;
          assignment.key.transport.ports.b = assignment.source_is_a
            ? metadata.destination_port : metadata.source_port;
        }
      else if (metadata.key_kind == PRODUCT_OWNER_KEY_ICMP_QUERY)
        assignment.key.transport.query.identifier = metadata.transport.icmp.identifier;
    }
  product_flow_runtime_prefetch (graph->flow_pools[worker], &assignment, stage);
}

static void
product_primary_batch_flush (vlib_main_t *vm, vlib_node_runtime_t *node,
                              product_primary_batch_t *batch)
{
  if (!batch->count) return;
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 failed[PRODUCT_PACKET_BATCH_SIZE];
  u32 enqueued = vlib_buffer_enqueue_to_thread_retained (vm, node,
    graph->primary_frame_queue, batch->indices, batch->targets, batch->count, failed);
  u32 n_failed = batch->count - enqueued;
  u8 published[PRODUCT_GRAPH_WORKERS + 1] = {0};
  product_packet_batch_stats_t *stats = product_packet_batch_counters (vm);
  stats->primary_calls++;
  stats->primary_vectors += enqueued;
  stats->primary_failed += n_failed;
  clib_atomic_fetch_add_relax (&graph->primary_published, enqueued);
  for (u32 i = 0; i < batch->count; ++i)
    {
      u32 bi = batch->indices[i];
      int rejected = 0;
      for (u32 j = 0; j < n_failed; ++j) rejected |= failed[j] == bi;
      product_buffer_metadata_t *metadata = &batch->metadata[i];
      if (!rejected)
        {
          if (!published[batch->targets[i]])
            { published[batch->targets[i]] = 1; stats->primary_publications++; }
          if (metadata->state_bits & PRODUCT_META_TRACE)
            fprintf (stderr, "s205 event=primary_accepted thread=%u buffer=%u token=%llu generation=%llu owner=%u target_thread=%u\n",
              vm->thread_index, bi, (unsigned long long) metadata->origin_obligation_id,
              (unsigned long long) metadata->generation, metadata->expected_owner,
              batch->targets[i]);
          continue; /* Only the local value copy remains available. */
        }
      vlib_buffer_t *buffer = vlib_get_buffer (vm, bi);
      if (metadata->fragment_bundle_count && (metadata->state_bits & PRODUCT_META_TRACE))
        {
          vlib_frame_queue_main_t *fqm = vec_elt_at_index (
            vlib_get_thread_main ()->frame_queue_mains, graph->primary_frame_queue);
          vlib_frame_queue_t *fq = fqm->vlib_frame_queues[batch->targets[i]];
          fprintf (stderr, "s229 event=product_handoff_rejected thread=%u buffer=%u token=%llu generation=%llu family=%u reason=8 prepared=1 refs=1 queue=%u target_thread=%u slots=%u occupancy=%llu originals=%u\n",
            vm->thread_index, bi, (unsigned long long) metadata->origin_obligation_id,
            (unsigned long long) metadata->generation, metadata->ip_family,
            graph->primary_frame_queue, batch->targets[i], fq->nelts,
            (unsigned long long) (fq->tail - fq->head), metadata->fragment_bundle_count);
        }
      metadata->state_bits &= ~PRODUCT_META_HANDOFF_CREDIT;
      product_handoff_credit_release (graph, metadata->expected_owner);
      clib_atomic_fetch_add_relax (&graph->primary_rejected, 1);
      product_packet_lease_t lease;
      product_lease_from_metadata (metadata, buffer, &lease);
      if (product_packet_bypass_primary_capacity (
            &lease, PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED) != PRODUCT_PACKET_OK)
        {
          lease.terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
          lease.terminal_count = 1;
          lease.runtime_drop_reason = PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION;
        }
      product_metadata_set_terminal_intent (metadata, lease.terminal_intent);
      metadata->runtime_drop_reason = lease.runtime_drop_reason;
      metadata->processing_bypass_reason = lease.processing_bypass_reason;
      product_metadata_store (buffer, metadata);
      if (metadata->state_bits & PRODUCT_META_TRACE)
        fprintf (stderr, "s210 event=primary_rejected thread=%u buffer=%u token=%llu generation=%llu owner=%u intent=%u reason=%u retained=1 policy_evaluated=0\n",
          vm->thread_index, bi, (unsigned long long) metadata->origin_obligation_id,
          (unsigned long long) metadata->generation, metadata->expected_owner,
          lease.terminal_intent, PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED);
      vlib_buffer_enqueue_to_single_next (vm, node, &bi, PRODUCT_ADMIT_NEXT_TERMINAL, 1);
    }
  batch->count = 0;
}

static int
product_primary_batch_append (vlib_main_t *vm, vlib_node_runtime_t *node,
  product_primary_batch_t *batch, u32 bi, product_buffer_metadata_t *metadata,
  product_packet_processing_bypass_reason_t *reason)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u16 owner = metadata->expected_owner;
  if (batch->count == PRODUCT_PACKET_BATCH_SIZE)
    product_primary_batch_flush (vm, node, batch);
  int reserved = product_handoff_credit_reserve (graph, owner, PRODUCT_HANDOFF_PRIMARY,
                                                 metadata->origin_obligation_id);
  if (!reserved && batch->count)
    {
      product_primary_batch_flush (vm, node, batch);
      reserved = product_handoff_credit_reserve (graph, owner, PRODUCT_HANDOFF_PRIMARY,
                                                 metadata->origin_obligation_id);
    }
  if (!reserved)
    {
      *reason = PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED;
      clib_atomic_fetch_add_relax (&graph->primary_rejected, 1);
      return 0;
    }
  u16 target = vlib_get_worker_thread_index (owner);
  if (graph->misroute_next)
    { graph->misroute_next = 0; target = vm->thread_index; metadata->state_bits |= PRODUCT_META_TRACE; }
  metadata->state_bits |= PRODUCT_META_HANDOFF_CREDIT;
  product_metadata_store (vlib_get_buffer (vm, bi), metadata);
  u32 i = batch->count++;
  batch->indices[i] = bi; batch->targets[i] = target; batch->metadata[i] = *metadata;
  if (metadata->state_bits & PRODUCT_META_TRACE)
    fprintf (stderr, "s205 event=primary_publish thread=%u buffer=%u token=%llu generation=%llu owner=%u target_thread=%u primary=%u corrective=%u\n",
      vm->thread_index, bi, (unsigned long long) metadata->origin_obligation_id,
      (unsigned long long) metadata->generation, owner, target,
      metadata->primary_handoff_count, metadata->corrective_handoff_count);
  if (batch->count >= clib_min (PRODUCT_PACKET_BATCH_SIZE, graph->primary_credit_limit))
    product_primary_batch_flush (vm, node, batch);
  return 1; /* This dispatch owns queued items until flush publishes them. */
}

static_always_inline void
product_batch_prefetch_buffer (vlib_buffer_t **buffers, u32 at, u32 count,
                               int payload)
{
  if (at >= count) return;
  vlib_buffer_t *buffer = buffers[at];
  vlib_prefetch_buffer_header (buffer, LOAD);
  CLIB_PREFETCH (buffer->opaque2, sizeof (buffer->opaque2), LOAD);
  if (payload && !product_buffer_is_flow_end (buffer))
    vlib_prefetch_buffer_data (buffer, LOAD);
}

typedef struct
{
  product_buffer_metadata_t metadata;
  product_packet_lease_t lease;
  product_packet_result_t result;
  u8 ordinary, fragment;
} product_admit_prepared_t;

static void
product_admit_prepare_window (vlib_main_t *vm, vlib_buffer_t **buffers,
  u32 base, u32 count, product_admit_prepared_t *prepared)
{
  product_worker_layout_t layout = {
    .worker_count = PRODUCT_GRAPH_WORKERS, .hash_seed = PRODUCT_GRAPH_HASH_SEED,
  };
  product_packet_batch_stats_t *stats = product_packet_batch_counters (vm);
  stats->prepare_windows++;
  for (u32 i = 0; i < count; ++i)
    {
      product_admit_prepared_t *item = &prepared[i];
      clib_memset (item, 0, sizeof (*item));
      vlib_buffer_t *buffer = buffers[base + i];
      product_metadata_load (buffer, &item->metadata);
      if (item->metadata.fragment_bundle_count) continue;
      product_fragment_piece_t piece;
      product_packet_facts_t facts;
      item->fragment = product_fragment_parse (vlib_buffer_get_current (buffer),
        buffer->current_length, &piece, &facts) != 0;
      if (item->fragment) continue;
      product_packet_ingress_t ingress = {
        .data = vlib_buffer_get_current (buffer), .length = buffer->current_length,
        .current_worker = vlib_get_worker_index (vm->thread_index),
        .origin_obligation_id = item->metadata.origin_obligation_id,
      };
      if (!product_packet_graph_get_platform_facts (
            buffer, item->metadata.generation, &ingress.platform))
        product_packet_graph_platform_facts_unknown (&ingress.platform);
      item->result = product_packet_admit (&layout, &ingress, &item->lease);
      item->ordinary = 1;
      stats->prepared_packets++;
    }
}
