/* SPDX-License-Identifier: Apache-2.0 */
typedef struct
{
  u32 indices[PRODUCT_COMPLETION_BATCH_SIZE];
  product_packet_completion_frame_t completion[PRODUCT_COMPLETION_BATCH_SIZE];
  u32 count;
} product_completion_batch_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  product_completion_batch_t *active;
} product_completion_dispatch_t;
static product_completion_dispatch_t product_completion_dispatch[PRODUCT_GRAPH_WORKERS + 1];

/* All records are local values. Failed masks name original positions, never
 * an accepted prefix; no transferred native buffer is inspected afterwards. */
static u32
product_completion_batch_publish (vlib_main_t *vm, vlib_node_runtime_t *node,
  const product_completion_batch_t *batch, u8 *failed, int retry)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  u32 indices[PRODUCT_COMPLETION_BATCH_SIZE] = {0};
  u16 targets[PRODUCT_COMPLETION_BATCH_SIZE] = {0};
  u32 rejected[PRODUCT_COMPLETION_BATCH_SIZE], positions[PRODUCT_COMPLETION_BATCH_SIZE];
  u32 ready = 0;
  clib_memset (failed, 0, batch->count);
  for (u32 i = 0; i < batch->count; ++i)
    {
      const product_packet_completion_frame_t *completion = &batch->completion[i];
      if (product_vpn_tun_return_held (vm, completion))
        { failed[i] = 1; continue; }
      positions[ready] = i;
      indices[ready] = batch->indices[i];
      targets[ready++] = vlib_get_worker_thread_index (completion->obligation.origin_worker);
      if (completion->flags & PRODUCT_COMPLETION_TRACE)
        fprintf (stderr, "s205 event=%s thread=%u buffer=%u token=%llu generation=%llu target_thread=%u producer_thread=%u\n",
          retry ? "completion_return_retry" : "completion_return_publish",
          vm->thread_index, batch->indices[i],
          (unsigned long long) completion->obligation.token,
          (unsigned long long) completion->obligation.queue_generation,
          targets[ready - 1], completion->producer_thread);
    }
  if (!ready) return 0;
  u32 enqueued = vlib_buffer_enqueue_to_thread_retained (vm, node,
    graph->completion_return_frame_queue, indices, targets, ready, rejected);
  product_packet_batch_stats_t *stats = product_packet_batch_counters (vm);
  stats->completion_calls++;
  stats->completion_vectors += enqueued;
  u8 published[PRODUCT_GRAPH_WORKERS + 1] = {0};
  for (u32 i = 0; i < ready; ++i)
    {
      u32 position = positions[i];
      for (u32 j = 0; j < ready - enqueued; ++j)
        failed[position] |= rejected[j] == indices[i];
      if (failed[position]) continue;
      if (!published[targets[i]])
        { published[targets[i]] = 1; stats->completion_publications++; }
      const product_packet_completion_frame_t *completion = &batch->completion[position];
      if (completion->flags & PRODUCT_COMPLETION_TRACE)
        fprintf (stderr, "s205 event=completion_return_accepted thread=%u buffer=%u token=%llu generation=%llu target_thread=%u\n",
          vm->thread_index, indices[i],
          (unsigned long long) completion->obligation.token,
          (unsigned long long) completion->obligation.queue_generation, targets[i]);
    }
  clib_atomic_fetch_add_relax (&graph->completion_returns, enqueued);
  return enqueued;
}

static void
product_completion_defer (vlib_main_t *vm, u32 bi,
                          const product_packet_completion_frame_t *completion)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_completion_return_queue_t *queue = &product_completion_returns[vm->thread_index];
  ASSERT (queue->count < PRODUCT_COMPLETION_RETURN_CAPACITY);
  queue->buffers[(queue->head + queue->count) % PRODUCT_COMPLETION_RETURN_CAPACITY] = bi;
  queue->count++;
  clib_atomic_fetch_add_relax (&graph->completion_pending_returns, 1);
  clib_atomic_fetch_add_relax (&graph->completion_deferred, 1);
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s210 event=completion_deferred thread=%u buffer=%u token=%llu generation=%llu intent=%u drop_reason=%u pending=%u capacity=%u\n",
      vm->thread_index, bi, (unsigned long long) completion->obligation.token,
      (unsigned long long) completion->obligation.queue_generation,
      completion->terminal_intent, completion->runtime_drop_reason,
      queue->count, PRODUCT_COMPLETION_RETURN_CAPACITY);
  vlib_node_set_interrupt_pending (vm, product_packet_completion_retry_node.index);
}

static void
product_completion_batch_flush (vlib_main_t *vm, vlib_node_runtime_t *node,
                                 product_completion_batch_t *batch)
{
  if (!batch->count) return;
  u8 failed[PRODUCT_COMPLETION_BATCH_SIZE];
  product_completion_batch_publish (vm, node, batch, failed, 0);
  for (u32 i = 0; i < batch->count; ++i)
    if (failed[i]) product_completion_defer (vm, batch->indices[i], &batch->completion[i]);
  batch->count = 0;
}

static void
product_completion_batch_append (vlib_main_t *vm, vlib_node_runtime_t *node,
  product_completion_batch_t *batch, u32 bi,
  const product_packet_completion_frame_t *completion)
{
  if (batch->count == PRODUCT_PACKET_BATCH_SIZE)
    product_completion_batch_flush (vm, node, batch);
  u32 i = batch->count++;
  batch->indices[i] = bi; batch->completion[i] = *completion;
  if (batch->count == PRODUCT_PACKET_BATCH_SIZE)
    product_completion_batch_flush (vm, node, batch);
}

static void
product_completion_return (vlib_main_t *vm, vlib_node_runtime_t *node,
  u32 bi, const product_packet_completion_frame_t *completion)
{
  ASSERT (vm->thread_index <= PRODUCT_GRAPH_WORKERS);
  product_completion_batch_t *active = product_completion_dispatch[vm->thread_index].active;
  if (active)
    product_completion_batch_append (vm, node, active, bi, completion);
  else
    {
      product_completion_batch_t batch = {0};
      product_completion_batch_append (vm, node, &batch, bi, completion);
      product_completion_batch_flush (vm, node, &batch);
    }
}

/* Pop only an initial bounded prefix. Its retained/held items are returned to
 * the same ring, preserving candidate target order and existing held rotation.
 * New completions retain the old direct-try behaviour; no global FIFO is added. */
static u32
product_completion_retry_batch (vlib_main_t *vm, vlib_node_runtime_t *node)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_completion_return_queue_t *queue = &product_completion_returns[vm->thread_index];
  u32 budget = clib_min (queue->count, PRODUCT_COMPLETION_BATCH_SIZE);
  product_packet_batch_counters (vm)->retry_windows++;
  product_completion_batch_t batch = {0};
  u32 held[PRODUCT_COMPLETION_BATCH_SIZE], n_held = 0;
  u32 candidates[PRODUCT_COMPLETION_BATCH_SIZE];
  vlib_buffer_t *buffers[PRODUCT_COMPLETION_BATCH_SIZE];
  for (u32 i = 0; i < budget; ++i)
    {
      candidates[i] = queue->buffers[queue->head];
      queue->head = (queue->head + 1) % PRODUCT_COMPLETION_RETURN_CAPACITY;
      queue->count--;
    }
  if (budget)
    {
      for (u32 i = budget; i < round_pow2 (budget, 8); ++i)
        candidates[i] = candidates[0];
      vlib_get_buffers (vm, candidates, buffers, budget);
    }
  for (u32 i = 0; i < budget; ++i)
    {
      u32 bi = candidates[i];
      product_batch_prefetch_buffer (buffers, i + 4, budget, 0);
      product_packet_completion_frame_t completion;
      clib_memcpy_fast (&completion, buffers[i]->opaque2, sizeof (completion));
      if (product_vpn_tun_return_held (vm, &completion))
        { held[n_held++] = bi; continue; }
      u32 j = batch.count++;
      batch.indices[j] = bi; batch.completion[j] = completion;
    }
  u8 failed[PRODUCT_COMPLETION_BATCH_SIZE];
  clib_atomic_fetch_add_relax (&graph->completion_retry_attempts, batch.count);
  u32 accepted = product_completion_batch_publish (vm, node, &batch, failed, 1);
  clib_atomic_fetch_sub_relax (&graph->completion_pending_returns, accepted);
  for (u32 i = batch.count; i; --i)
    if (failed[i - 1])
      {
        queue->head = (queue->head + PRODUCT_COMPLETION_RETURN_CAPACITY - 1) %
          PRODUCT_COMPLETION_RETURN_CAPACITY;
        queue->buffers[queue->head] = batch.indices[i - 1]; queue->count++;
      }
  for (u32 i = 0; i < n_held; ++i)
    {
      queue->buffers[(queue->head + queue->count) % PRODUCT_COMPLETION_RETURN_CAPACITY] = held[i];
      queue->count++;
    }
  return accepted;
}
