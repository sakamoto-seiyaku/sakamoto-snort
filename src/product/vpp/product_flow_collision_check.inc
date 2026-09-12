/* SPDX-License-Identifier: Apache-2.0 */
/* Explicit diagnostic vectors, never NFQ_CAPTURED or application FlowEntries.
 * Control preallocates isolated runtimes; actual owner nodes exercise the same
 * Interface and free their independent, payload-free VPP carriers once. */
typedef struct {
  product_flow_runtime_t *runtime[PRODUCT_GRAPH_WORKERS];
  product_flow_runtime_snapshot_t counters[PRODUCT_GRAPH_WORKERS];
  u32 queue, initialized, armed, done;
  u32 failed_step[PRODUCT_GRAPH_WORKERS];
  u32 thread[PRODUCT_GRAPH_WORKERS];
  u64 generation;
} product_flow_collision_check_t;
static product_flow_collision_check_t product_flow_check;

static u32
product_flow_check_vectors (product_flow_runtime_t *runtime, u16 worker,
                            u64 generation)
{
  product_owner_assignment_t keys[9] = { 0 };
  product_packet_facts_t facts = {
    .l3_status = PRODUCT_PACKET_L3_COMPLETE,
    .l4_status = PRODUCT_PACKET_L4_COMPLETE,
    /* A valid midstream TCP fact vector, not the old unimplemented placeholder. */
    .tcp_flags = 16, .tcp_window = 8192,
    .l4_header_length = 20, .transport_length = 20,
  };
  product_flow_entry_packet_t packet = {
    .facts = &facts,
    .policy = { generation, 1, 1 }, .packet_bytes = 64,
    .device_direction = PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,
  };
  product_flow_entry_observation_t observation;
  const product_flow_entry_t *entries[8];
  for (u32 i = 0; i < 9; i++)
    {
      keys[i].valid = 1;
      keys[i].execution_owner = worker;
      keys[i].source_is_a = 1;
      /* Deliberate complete-hash collision, not a second owner selector. */
      keys[i].canonical_hash = UINT64_C (0x1122334455667700) | worker;
      keys[i].key.kind = PRODUCT_OWNER_KEY_L4_PORTS;
      keys[i].key.ip_family = 4;
      keys[i].key.protocol = 17;
      keys[i].key.address_a[15] = 1;
      keys[i].key.address_b[15] = 2;
      keys[i].key.transport.ports.a = 40000;
      keys[i].key.transport.ports.b = 443;
    }
  keys[1].key.transport.ports.a++;
  keys[2].key.transport.ports.b++;
  keys[3].key.ip_family = 6;
  keys[4].key.protocol = 6;
  keys[5].key.kind = PRODUCT_OWNER_KEY_ICMP_QUERY;
  keys[5].key.protocol = 1;
  keys[5].key.query_class = 1;
  keys[5].key.transport.query.identifier = 40000;
  keys[5].key.transport.query.reserved = 0;
  keys[6] = keys[5];
  keys[6].key.transport.query.identifier++;
  keys[7] = keys[5];
  keys[7].key.query_class++;
  keys[8].key.address_b[15]++;
  for (u32 i = 0; i < 8; i++)
    {
      facts.ip_family = keys[i].key.ip_family;
      facts.protocol = keys[i].key.protocol;
      packet.timestamp++;
      if (product_flow_entry_observe (runtime, &keys[i], &packet, 0, &observation)
            != PRODUCT_FLOW_ENTRY_STATUS_OK || !observation.created
          || !observation.entry || observation.slot >= 8)
        return 10 + i;
      entries[i] = observation.entry;
      for (u32 j = 0; j < i; j++)
        if (entries[j] == entries[i])
          return 20 + i;
    }
  for (u32 i = 0; i < 8; i++)
    {
      product_owner_assignment_t reverse = keys[i];
      facts.ip_family = keys[i].key.ip_family;
      facts.protocol = keys[i].key.protocol;
      reverse.source_is_a = 0;
      packet.timestamp++;
      if (product_flow_entry_observe (runtime, &reverse, &packet, 0, &observation)
            != PRODUCT_FLOW_ENTRY_STATUS_OK || !observation.reused
          || observation.entry != entries[i] || observation.flow_direction != 2
          || observation.entry->packets != 2)
        return 30 + i;
    }
  facts.ip_family = keys[8].key.ip_family;
  facts.protocol = keys[8].key.protocol;
  if (product_flow_entry_observe (runtime, &keys[8], &packet, 0, &observation)
        != PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED || observation.entry)
    return 40;
  if (product_flow_entry_observe (runtime, &keys[8], &packet, 1, &observation)
        != PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP || observation.entry)
    return 41;
  product_owner_assignment_t wrong = keys[0];
  wrong.execution_owner ^= 1;
  if (product_flow_entry_observe (runtime, &wrong, &packet, 0, &observation)
        != PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER)
    return 42;
  u64 incarnation = entries[0]->incarnation;
  product_flow_runtime_flush (runtime);
  if (product_flow_entry_pool_active_count (runtime)
      || product_flow_runtime_entry (runtime, 0))
    return 43;
  if (product_flow_entry_observe (runtime, &keys[0], &packet, 0, &observation)
        != PRODUCT_FLOW_ENTRY_STATUS_OK || !observation.created
      || observation.entry->incarnation <= incarnation)
    return 44;
  return 0;
}

VLIB_NODE_FN (product_flow_collision_check_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *buffers = vlib_frame_vector_args (frame);
  (void) node;
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      u32 bi = buffers[i];
      u32 expected = vlib_get_buffer (vm, bi)->opaque[0];
      u32 worker = vlib_get_worker_index (vm->thread_index);
      if (expected < PRODUCT_GRAPH_WORKERS)
        {
          product_flow_check.thread[expected] = vm->thread_index;
          product_flow_check.failed_step[expected] = worker == expected
            ? product_flow_check_vectors (product_flow_check.runtime[worker],
                                           worker, product_flow_check.generation)
            : 1;
          product_flow_check.counters[expected] = worker == expected
            ? product_flow_runtime_snapshot (product_flow_check.runtime[worker])
            : (product_flow_runtime_snapshot_t) { 0 };
        }
      vlib_buffer_free (vm, &bi, 1);
      if (expected < PRODUCT_GRAPH_WORKERS)
        __atomic_fetch_or (&product_flow_check.done, 1U << expected, __ATOMIC_RELEASE);
    }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (product_flow_collision_check_node) = {
  .name = "product-flow-collision-check", .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

static void
product_flow_check_destroy (void)
{
  for (u32 i = 0; i < PRODUCT_GRAPH_WORKERS; i++)
    {
      product_flow_runtime_destroy (product_flow_check.runtime[i]);
      product_flow_check.runtime[i] = 0;
    }
}

static clib_error_t *
product_flow_check_cli (vlib_main_t *vm, unformat_input_t *input,
                        vlib_cli_command_t *command)
{
  product_packet_graph_main_t *g = &product_packet_graph_main;
  u32 buffers[PRODUCT_GRAPH_WORKERS], failed[PRODUCT_GRAPH_WORKERS];
  u16 targets[PRODUCT_GRAPH_WORKERS];
  (void) input; (void) command;
  if (vlib_num_workers () != PRODUCT_GRAPH_WORKERS
      || g->enabled || g->lifecycle_buffers || g->lifecycle_obligations
      || g->lifecycle_handoffs || g->lifecycle_completion_frames
      || (product_flow_check.armed && __atomic_load_n (&product_flow_check.done, __ATOMIC_ACQUIRE) != 3))
    return clib_error_return (0, "flow collision check requires stopped, drained runtime and no pending check");
  product_flow_check_destroy ();
  product_flow_check.armed = 0;
  product_flow_check.done = 0;
  product_flow_check.generation = g->generation ? g->generation : 1;
  for (u32 i = 0; i < PRODUCT_GRAPH_WORKERS; i++)
    {
      product_flow_check.failed_step[i] = 0;
      product_flow_check.thread[i] = 0;
      if (product_flow_runtime_create (&product_flow_check.runtime[i], i,
            PRODUCT_GRAPH_WORKERS, product_flow_check.generation, 8)
            != PRODUCT_FLOW_ENTRY_STATUS_OK)
        {
          product_flow_check_destroy ();
          return clib_error_return (0, "flow collision check allocation failed");
        }
      targets[i] = vlib_get_worker_thread_index (i);
    }
  u32 allocated = vlib_buffer_alloc (vm, buffers, PRODUCT_GRAPH_WORKERS);
  if (allocated != PRODUCT_GRAPH_WORKERS)
    {
      if (allocated) vlib_buffer_free (vm, buffers, allocated);
      product_flow_check_destroy ();
      return clib_error_return (0, "flow collision check carrier allocation failed");
    }
  if (!product_flow_check.initialized)
    {
      product_flow_check.queue = vlib_frame_queue_main_init (product_flow_collision_check_node.index, 8);
      product_flow_check.initialized = 1;
    }
  for (u32 i = 0; i < PRODUCT_GRAPH_WORKERS; i++)
    vlib_get_buffer (vm, buffers[i])->opaque[0] = i;
  product_flow_check.armed = 1;
  u32 queued = vlib_buffer_enqueue_to_thread_retained (
    vm, vlib_node_get_runtime (vm, product_flow_collision_check_node.index),
    product_flow_check.queue, buffers, targets, PRODUCT_GRAPH_WORKERS, failed);
  for (u32 i = 0; i < PRODUCT_GRAPH_WORKERS - queued; i++)
    {
      u32 worker = vlib_get_buffer (vm, failed[i])->opaque[0];
      product_flow_check.failed_step[worker] = 2;
      vlib_buffer_free (vm, &failed[i], 1);
      __atomic_fetch_or (&product_flow_check.done, 1U << worker, __ATOMIC_RELEASE);
    }
  vlib_cli_output (vm, "flow.check armed=1 source=FLOW_RUNTIME_INJECTED queued=%u", queued);
  return 0;
}
VLIB_CLI_COMMAND (product_flow_check_command, static) = {
  .path = "product flow collision-check", .function = product_flow_check_cli,
  .short_help = "product flow collision-check (stopped, isolated owner vectors)",
};

static clib_error_t *
product_flow_check_show_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  (void) input; (void) command;
  u32 done = __atomic_load_n (&product_flow_check.done, __ATOMIC_ACQUIRE);
  vlib_cli_output (vm, "flow.check armed=%u done=%u source=FLOW_RUNTIME_INJECTED", product_flow_check.armed, done);
  if (product_flow_check.armed && done == 3)
    {
      for (u32 i = 0; i < PRODUCT_GRAPH_WORKERS; i++)
        {
          const product_flow_runtime_snapshot_t *s = &product_flow_check.counters[i];
          vlib_cli_output (vm, "flow.check.owner worker=%u thread=%u generation=%llu failed_step=%u creates=%llu hits=%llu capacity_misses=%llu early_drops=%llu wrong_owner=%llu flushes=%llu final_entries=%u carrier_freed=1",
            i, product_flow_check.thread[i], (unsigned long long) product_flow_check.generation,
            product_flow_check.failed_step[i], (unsigned long long) s->allocation_count,
            (unsigned long long) s->reuse_count, (unsigned long long) s->capacity_rejection_count,
            (unsigned long long) s->early_drop_count, (unsigned long long) s->wrong_owner_count,
            (unsigned long long) s->flush_count, s->active_entries);
        }
      product_flow_check_destroy ();
      vlib_cli_output (vm, "flow.check.resources runtimes=0 carriers=0 normal_flow_entries=%u",
        product_flow_entry_pool_active_count (product_packet_graph_main.flow_pools[0])
          + product_flow_entry_pool_active_count (product_packet_graph_main.flow_pools[1]));
    }
  return 0;
}
VLIB_CLI_COMMAND (product_flow_check_show_command, static) = {
  .path = "show product flow collision-check", .function = product_flow_check_show_cli,
};
