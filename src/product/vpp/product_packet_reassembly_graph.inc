/* SPDX-License-Identifier: Apache-2.0
 * Product-owned bounded reassembly. Originals have one exclusive buffer
 * reference throughout; the table owns descriptors, never Adapter verdicts. */
#include "product_fragment.h"
#define PRODUCT_FRAGMENT_NONE ((u32) ~0)
enum {
  PRODUCT_FRAGMENT_TRACE = 1 << 0,
  PRODUCT_FRAGMENT_PINNED = 1 << 1, /* historical completion flag; never set */
  PRODUCT_FRAGMENT_PREPARED = 1 << 3,
  PRODUCT_FRAGMENT_IPV6 = 1 << 4,
  PRODUCT_FRAGMENT_VALID = 1 << 7,
};
enum {
  PRODUCT_REASSEMBLY_ERROR_NONE,
  PRODUCT_REASSEMBLY_ERROR_TIMEOUT,
  PRODUCT_REASSEMBLY_ERROR_DUPLICATE_FRAGMENT,
  PRODUCT_REASSEMBLY_ERROR_FRAGMENT_CONFLICT,
  PRODUCT_REASSEMBLY_ERROR_INTERNAL,
  PRODUCT_REASSEMBLY_ERROR_CAPACITY,
  PRODUCT_REASSEMBLY_ERROR_BUNDLE_CAPACITY,
  PRODUCT_REASSEMBLY_ERROR_RESOURCE,
  PRODUCT_REASSEMBLY_ERROR_HANDOFF,
  PRODUCT_REASSEMBLY_ERROR_STOP,
  PRODUCT_REASSEMBLY_ERROR_MALFORMED,
};
typedef struct {
  product_adapter_obligation_t obligation;
  product_platform_packet_facts_t platform;
  u32 next_range;
  u32 reserved;
  u8 flow_stack_result, terminal_reserved[3];
  u16 reserved_count, flags;
} product_fragment_envelope_t;
_Static_assert(sizeof(product_fragment_envelope_t) ==
  sizeof(((vlib_buffer_t *)0)->opaque2), "fragment overlay");
typedef struct {
  u64 ingress, pins, duplicate_pins, success, error_groups;
  u64 completions, pinned_completions, resource_bypasses;
} __attribute__((aligned(CLIB_CACHE_LINE_BYTES))) product_fragment_counters_t;
static struct {
  u32 initialized, accepting, injected, timeout_ms, max_originals;
  u32 handoff_queues[2];
  product_fragment_counters_t threads[PRODUCT_GRAPH_WORKERS + 1];
  product_fragment_table_t tables[PRODUCT_GRAPH_WORKERS + 1];
  u64 next_expiry_us[PRODUCT_GRAPH_WORKERS + 1];
  u8 payload[PRODUCT_GRAPH_WORKERS + 1][65535];
} product_fragment_main;
static struct {
  u32 contexts, originals, timeout_ms;
} product_fragment_config = {
  PRODUCT_FRAGMENT_DEFAULT_CONTEXTS, PRODUCT_FRAGMENT_DEFAULT_ORIGINALS, 500
};
extern vlib_node_registration_t product_fragment_input_node;
extern vlib_node_registration_t product_fragment_expire_node;

static u32
product_fragment_contexts (void)
{
  u32 count = 0;
  for (u32 i = 1; i <= PRODUCT_GRAPH_WORKERS; i++)
    count += product_fragment_main.tables[i].active;
  return count;
}

static product_fragment_counters_t *
product_fragment_counters (vlib_main_t *vm)
{
  if (PREDICT_FALSE (vm->thread_index > PRODUCT_GRAPH_WORKERS))
    clib_panic ("fragment callback outside the configured VPP threads");
  return &product_fragment_main.threads[vm->thread_index];
}

static product_fragment_envelope_t
product_fragment_load (vlib_main_t *vm, u32 bi)
{
  product_fragment_envelope_t envelope;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  clib_memcpy_fast (&envelope, b->opaque2, sizeof (envelope));
  if (PREDICT_FALSE (!(envelope.flags & PRODUCT_FRAGMENT_VALID)
      || envelope.obligation.queue_generation != product_packet_graph_main.generation
      || !envelope.obligation.token || !b->ref_count
      || envelope.obligation.origin_worker >= PRODUCT_GRAPH_WORKERS
      || (envelope.obligation.kind != PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE
          && envelope.obligation.kind != PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED
          && envelope.obligation.kind != PRODUCT_ADAPTER_OBLIGATION_VPN_TUN)))
    clib_panic ("invalid fragment ownership envelope");
  return envelope;
}

static void
product_fragment_store (vlib_main_t *vm, u32 bi,
                         const product_fragment_envelope_t *envelope)
{
  clib_memcpy_fast (vlib_get_buffer (vm, bi)->opaque2, envelope,
                    sizeof (*envelope));
}

static void
product_fragment_to_node (vlib_main_t *vm, u32 node_index, u32 bi)
{
  vlib_frame_t *frame = vlib_get_frame_to_node (vm, node_index);
  u32 *indices = vlib_frame_vector_args (frame);
  indices[0] = bi;
  frame->n_vectors = 1;
  vlib_put_frame_to_node (vm, node_index, frame);
}

static int
product_fragment_resource_error (u32 reason)
{
  return reason == PRODUCT_REASSEMBLY_ERROR_CAPACITY
    || reason == PRODUCT_REASSEMBLY_ERROR_BUNDLE_CAPACITY
    || reason == PRODUCT_REASSEMBLY_ERROR_RESOURCE
    || reason == PRODUCT_REASSEMBLY_ERROR_HANDOFF;
}

static void
product_fragment_emit (vlib_main_t *vm, vlib_node_runtime_t *node, u32 bi,
                        product_fragment_envelope_t e, u8 intent,
                        u8 drop_reason, u8 bypass_reason)
{
  product_packet_graph_main_t *g = &product_packet_graph_main;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  if (PREDICT_FALSE (b->ref_count != 1))
    clib_panic ("fragment completion still has a extra reference");
  b->flags &= ~(VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID);
  b->next_buffer = 0;
  product_buffer_platform_metadata_t platform = {e.obligation, e.platform};
  clib_memcpy_fast (b->opaque, &platform, sizeof (platform));
  product_packet_completion_frame_t completion = {
    .obligation = e.obligation, .producer_thread = vm->thread_index,
    .terminal_intent = intent, .runtime_drop_reason = drop_reason,
    .processing_bypass_reason = bypass_reason,
    .flow_stack_result = e.flow_stack_result,
    .flags = PRODUCT_COMPLETION_FRAGMENT_MEMBER |
      ((e.flags & PRODUCT_FRAGMENT_TRACE) ? PRODUCT_COMPLETION_TRACE : 0) |
      ((e.flags & PRODUCT_FRAGMENT_PINNED) ? PRODUCT_COMPLETION_FRAGMENT_PINNED : 0),
  };
  if (e.platform.provenance == PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN)
    completion.flags |= PRODUCT_COMPLETION_FLOW_STACK_RETURN;
  clib_memcpy_fast (b->opaque2, &completion, sizeof (completion));
  clib_atomic_fetch_add_relax (&g->lifecycle_completion_frames, 1);
  clib_atomic_fetch_add_relax (&g->lifecycle_terminal_intents, 1);
  if (e.flags & PRODUCT_FRAGMENT_TRACE)
    fprintf (stderr, "s212 event=completion_publish thread=%u buffer=%u token=%llu generation=%llu origin_worker=%u lane=%u packet=%u kind=%u intent=%u drop_reason=%u bypass_reason=%u pinned=%u refs=1\n",
      vm->thread_index, bi, (unsigned long long) e.obligation.token,
      (unsigned long long) e.obligation.queue_generation, e.obligation.origin_worker,
      e.obligation.origin_lane, e.obligation.packet_id, e.obligation.kind,
      intent, drop_reason, bypass_reason, !!(e.flags & PRODUCT_FRAGMENT_PINNED));
  if (vm->thread_index == vlib_get_worker_thread_index (e.obligation.origin_worker))
    product_fragment_to_node (vm, product_packet_origin_completion_node.index, bi);
  else product_completion_return (vm, node, bi, &completion);
}

static void
product_fragment_error_emit (vlib_main_t *vm, vlib_node_runtime_t *node,
                             u32 bi, product_fragment_envelope_t e, u32 reason)
{
  u8 intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME, bypass = 0;
  u8 drop = PRODUCT_PACKET_DROP_REASSEMBLY_MALFORMED;
  if (reason == PRODUCT_REASSEMBLY_ERROR_TIMEOUT)
    drop = PRODUCT_PACKET_DROP_REASSEMBLY_TIMEOUT;
  else if (reason == PRODUCT_REASSEMBLY_ERROR_STOP)
    drop = PRODUCT_PACKET_DROP_REASSEMBLY_STOP;
  else if (reason == PRODUCT_REASSEMBLY_ERROR_INTERNAL)
    drop = PRODUCT_PACKET_DROP_REASSEMBLY_INTERNAL;
  else if (product_fragment_resource_error (reason))
    {
      if (e.obligation.kind == PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE)
        {
          intent = PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS;
          drop = PRODUCT_PACKET_DROP_NONE;
          bypass = PRODUCT_PACKET_BYPASS_REASSEMBLY_RESOURCE;
          product_fragment_counters (vm)->resource_bypasses++;
        }
      else drop = PRODUCT_PACKET_DROP_REASSEMBLY_NO_RETURN;
    }
  product_fragment_emit (vm, node, bi, e, intent, drop, bypass);
}


static void
product_fragment_fail_bundle (vlib_main_t *vm, vlib_node_runtime_t *node,
                              const product_fragment_bundle_t *bundle, u32 reason)
{
  product_fragment_counters(vm)->error_groups++;
  for (u32 i = 0; i < bundle->count; i++) {
    u32 bi = bundle->pieces[i].buffer_index;
    product_fragment_envelope_t e = product_fragment_load(vm, bi);
    if (e.flags & PRODUCT_FRAGMENT_TRACE)
      fprintf(stderr, "s229 event=product_error thread=%u buffer=%u token=%llu generation=%llu family=%u reason=%u prepared=%u refs=1\n",
        vm->thread_index, bi, (unsigned long long)e.obligation.token,
        (unsigned long long)e.obligation.queue_generation,
        (e.flags & PRODUCT_FRAGMENT_IPV6) ? 6 : 4, reason,
        !!(e.flags & PRODUCT_FRAGMENT_PREPARED));
    product_fragment_error_emit(vm, node, bi, e, reason);
  }
}

/* The detached table descriptors are consumed synchronously. No pointer into
 * the table escapes to the next graph node or crosses a worker boundary. */
static void
product_fragment_assemble (vlib_main_t *vm, vlib_node_runtime_t *node,
                           product_fragment_bundle_t *bundle)
{
  product_fragment_piece_t *first = &bundle->pieces[bundle->first];
  u32 bi = first->buffer_index;
  vlib_buffer_t *b = vlib_get_buffer(vm, bi);
  product_fragment_envelope_t e = product_fragment_load(vm, bi);
  u32 header = first->header_length - (first->key.family == 6 ? 8 : 0);
  u32 length = header + bundle->total_length;
  if (length > 65535 || length + b->current_data > vlib_buffer_get_default_data_size(vm)) {
    product_fragment_fail_bundle(vm, node, bundle, PRODUCT_REASSEMBLY_ERROR_RESOURCE);
    return;
  }
  u8 *payload = product_fragment_main.payload[vm->thread_index];
  for (u32 i = 0; i < bundle->count; i++) {
    product_fragment_piece_t *piece = &bundle->pieces[i];
    if (!piece->selected) continue;
    vlib_buffer_t *original = vlib_get_buffer(vm, piece->buffer_index);
    clib_memcpy_fast(payload + piece->offset,
      (u8 *)vlib_buffer_get_current(original) + piece->header_length, piece->length);
  }
  u8 *bytes = vlib_buffer_get_current(b);
  clib_memcpy_fast(bytes + header, payload, bundle->total_length);
  if (first->key.family == 4) {
    ip4_header_t *ip = (ip4_header_t *)bytes;
    ip->length = clib_host_to_net_u16(length);
    ip->flags_and_fragment_offset = 0;
    ip->checksum = ip4_header_checksum(ip);
  } else {
    bytes[first->previous_next_header] = first->key.protocol;
    u16 payload_length = length - 40;
    bytes[4] = payload_length >> 8; bytes[5] = payload_length;
  }
  b->current_length = length;
  product_packet_ingress_t ingress = {
    .data = bytes, .length = length,
    .current_worker = vlib_get_worker_index(vm->thread_index),
    .origin_obligation_id = e.obligation.token, .platform = e.platform
  };
  product_worker_layout_t layout = {
    .worker_count = PRODUCT_GRAPH_WORKERS, .hash_seed = PRODUCT_GRAPH_HASH_SEED
  };
  product_packet_lease_t lease = {0};
  if (product_packet_admit_selected(&layout, &ingress, &bundle->assignment, &lease)
      != PRODUCT_PACKET_OK) {
    /* The first-fragment walk already validated the extension chain. A
     * remaining recognized extension here means the shared parser exhausted
     * its processing budget, not that a protocol fault was established. */
    u8 protocol = lease.facts.protocol;
    int budget = lease.facts.ip_family == 6 && !lease.facts.l4_status &&
      (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 51);
    product_fragment_fail_bundle(vm, node, bundle,
      budget ? PRODUCT_REASSEMBLY_ERROR_RESOURCE : PRODUCT_REASSEMBLY_ERROR_MALFORMED);
    return;
  }
  u32 tail = bi;
  for (u32 i = 0; i < bundle->count; i++) {
    if (i == bundle->first) continue;
    product_fragment_envelope_t previous = product_fragment_load(vm, tail);
    previous.next_range = bundle->pieces[i].buffer_index;
    previous.flags |= PRODUCT_FRAGMENT_PREPARED;
    product_fragment_store(vm, tail, &previous);
    tail = previous.next_range;
  }
  product_fragment_envelope_t last = product_fragment_load(vm, tail);
  last.next_range = PRODUCT_FRAGMENT_NONE;
  last.flags |= PRODUCT_FRAGMENT_PREPARED;
  product_fragment_store(vm, tail, &last);
  e = product_fragment_load(vm, bi);
  product_buffer_platform_metadata_t platform = {e.obligation, e.platform};
  clib_memcpy_fast(b->opaque, &platform, sizeof(platform));
  product_buffer_metadata_t metadata;
  product_metadata_from_lease(&metadata, &lease, e.obligation.queue_generation, b);
  metadata.fragment_bundle_head = e.next_range;
  metadata.fragment_bundle_count = bundle->count;
  if (e.flags & PRODUCT_FRAGMENT_TRACE) metadata.state_bits |= PRODUCT_META_TRACE;
  product_metadata_store(b, &metadata);
  product_fragment_counters(vm)->success++;
  if (e.flags & PRODUCT_FRAGMENT_TRACE)
    fprintf(stderr, "s229 event=product_reassembled thread=%u survivor=%u token=%llu generation=%llu originals=%u bytes=%u owner=%u family=%u\n",
      vm->thread_index, bi, (unsigned long long)e.obligation.token,
      (unsigned long long)e.obligation.queue_generation, bundle->count, length,
      bundle->assignment.execution_owner, first->key.family);
  product_fragment_to_node(vm, product_packet_admit_node.index, bi);
}

static void
product_fragment_expire (vlib_main_t *vm, vlib_node_runtime_t *node, int flush)
{
  product_fragment_bundle_t bundle;
  if (!product_fragment_main.tables[vm->thread_index].active) return;
  u64 now = (u64)(vlib_time_now(vm) * 1e6);
  if (!flush && now < product_fragment_main.next_expiry_us[vm->thread_index]) return;
  product_fragment_main.next_expiry_us[vm->thread_index] = now + 50000;
  while (product_fragment_take_expired(&product_fragment_main.tables[vm->thread_index],
                                       now, flush, &bundle))
    product_fragment_fail_bundle(vm, node, &bundle,
      flush ? PRODUCT_REASSEMBLY_ERROR_STOP : PRODUCT_REASSEMBLY_ERROR_TIMEOUT);
}

VLIB_NODE_FN(product_fragment_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args(frame);
  product_fragment_expire(vm, node, !product_fragment_main.accepting);
  for (u32 i = 0; i < frame->n_vectors; i++) {
    u32 bi = from[i];
    vlib_buffer_t *b = vlib_get_buffer(vm, bi);
    product_fragment_envelope_t e = product_fragment_load(vm, bi);
    product_fragment_piece_t piece;
    product_packet_facts_t facts;
    product_owner_assignment_t assignment = {0};
    if (!product_fragment_main.accepting) {
      product_fragment_error_emit(vm, node, bi, e, PRODUCT_REASSEMBLY_ERROR_STOP);
      continue;
    }
    if (product_fragment_parse(vlib_buffer_get_current(b), b->current_length, &piece, &facts) != 1) {
      product_fragment_error_emit(vm, node, bi, e, PRODUCT_REASSEMBLY_ERROR_MALFORMED);
      continue;
    }
    product_worker_layout_t layout = {
      .worker_count = PRODUCT_GRAPH_WORKERS, .hash_seed = PRODUCT_GRAPH_HASH_SEED
    };
    if (!piece.offset && product_owner_assign(&layout, &facts, &assignment) != PRODUCT_PACKET_OK) {
      product_fragment_error_emit(vm, node, bi, e, PRODUCT_REASSEMBLY_ERROR_MALFORMED);
      continue;
    }
    piece.buffer_index = bi;
    product_fragment_bundle_t bundle;
    product_fragment_result_t result = product_fragment_push(
      &product_fragment_main.tables[vm->thread_index], &piece,
      piece.offset ? 0 : &assignment, (u64)(vlib_time_now(vm)*1e6), &bundle);
    if (result == PRODUCT_FRAGMENT_WAIT) continue;
    if (result == PRODUCT_FRAGMENT_COMPLETE) product_fragment_assemble(vm, node, &bundle);
    else product_fragment_fail_bundle(vm, node, &bundle,
      result == PRODUCT_FRAGMENT_CONTEXT_FULL ? PRODUCT_REASSEMBLY_ERROR_CAPACITY :
      result == PRODUCT_FRAGMENT_BUNDLE_FULL ? PRODUCT_REASSEMBLY_ERROR_BUNDLE_CAPACITY :
      PRODUCT_REASSEMBLY_ERROR_FRAGMENT_CONFLICT);
  }
  /* Expiry is deadline work, not a reason to keep an idle worker polling.
   * Preserve the existing 50 ms scan cadence while contexts are live. */
  if (product_fragment_main.tables[vm->thread_index].active &&
      !vlib_node_is_scheduled(vm, product_fragment_expire_node.index))
    vlib_node_schedule(vm, product_fragment_expire_node.index, 0.05);
  return frame->n_vectors;
}
VLIB_REGISTER_NODE(product_fragment_input_node) = {
  .name = "product-reassembly", .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_NODE_FN(product_fragment_expire_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  (void)frame;
  if (vm->thread_index && product_fragment_main.initialized)
    product_fragment_expire(vm, node, !product_fragment_main.accepting);
  if (vm->thread_index && product_fragment_main.tables[vm->thread_index].active)
    vlib_node_schedule(vm, node->node_index, 0.05);
  return 0;
}
VLIB_REGISTER_NODE(product_fragment_expire_node) = {
  .name = "product-reassembly-expire", .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_SCHED, .state = VLIB_NODE_STATE_INTERRUPT,
};

static int
product_fragment_dispatch (vlib_main_t *vm, vlib_node_runtime_t *node, u32 bi,
                            const product_buffer_metadata_t *metadata)
{
  if (metadata->fragment_bundle_count) return 0;
  vlib_buffer_t *b = vlib_get_buffer(vm, bi);
  product_fragment_piece_t piece;
  product_packet_facts_t facts;
  int parsed = product_fragment_parse(vlib_buffer_get_current(b), b->current_length,
                                      &piece, &facts);
  if (!parsed) return 0;
  product_buffer_platform_metadata_t saved;
  clib_memcpy_fast(&saved, b->opaque, sizeof(saved));
  u32 family = ((u8 *)vlib_buffer_get_current(b))[0] >> 4;
  product_fragment_envelope_t e = {
    .obligation = saved.obligation, .platform = saved.platform,
    .next_range = PRODUCT_FRAGMENT_NONE,
    .flags = PRODUCT_FRAGMENT_VALID | (family == 6 ? PRODUCT_FRAGMENT_IPV6 : 0) |
      ((metadata->state_bits & PRODUCT_META_TRACE) ? PRODUCT_FRAGMENT_TRACE : 0)
  };
  product_fragment_store(vm, bi, &e);
  product_fragment_counters(vm)->ingress++;
  if (e.flags & PRODUCT_FRAGMENT_TRACE)
    fprintf(stderr, "s212 event=fragment_ingress thread=%u buffer=%u token=%llu generation=%llu kind=%u origin_worker=%u lane=%u packet=%u offset=%u more=%u bytes=%u refs=%u uid=%u availability=%u family=%u ifindex=%u context=%u direction=%u provenance=%u\n",
      vm->thread_index, bi, (unsigned long long)e.obligation.token,
      (unsigned long long)e.obligation.queue_generation, e.obligation.kind,
      e.obligation.origin_worker, e.obligation.origin_lane, e.obligation.packet_id,
      piece.offset, piece.more, b->current_length, b->ref_count, e.platform.uid,
      e.platform.availability, family, e.platform.linux_ifindex,
      e.platform.network_context_id, e.platform.direction, e.platform.provenance);
  if (!product_fragment_main.accepting)
    product_fragment_error_emit(vm, node, bi, e, PRODUCT_REASSEMBLY_ERROR_STOP);
  else if (parsed < 0)
    product_fragment_error_emit(vm, node, bi, e, PRODUCT_REASSEMBLY_ERROR_MALFORMED);
  else if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    product_fragment_error_emit(vm, node, bi, e, PRODUCT_REASSEMBLY_ERROR_RESOURCE);
  else {
    product_worker_layout_t layout = {
      .worker_count = PRODUCT_GRAPH_WORKERS, .hash_seed = PRODUCT_GRAPH_HASH_SEED
    };
    u16 target = vlib_get_worker_thread_index(product_fragment_worker(&layout, &piece.key));
    if (target == vm->thread_index)
      product_fragment_to_node(vm, product_fragment_input_node.index, bi);
    else {
      u32 failed;
      u32 queue = product_fragment_main.handoff_queues[family == 6];
      if (vlib_buffer_enqueue_to_thread_retained(vm, node, queue, &bi, &target, 1, &failed) != 1) {
        ASSERT(failed == bi);
        if (e.flags & PRODUCT_FRAGMENT_TRACE) {
          vlib_frame_queue_main_t *fqm = vec_elt_at_index(vlib_get_thread_main()->frame_queue_mains, queue);
          vlib_frame_queue_t *fq = fqm->vlib_frame_queues[target];
          fprintf(stderr, "s229 event=product_handoff_rejected thread=%u buffer=%u token=%llu generation=%llu family=%u reason=8 prepared=0 refs=1 queue=%u target_thread=%u slots=%u occupancy=%llu\n",
            vm->thread_index, bi, (unsigned long long)e.obligation.token,
            (unsigned long long)e.obligation.queue_generation, family, queue, target,
            fq->nelts, (unsigned long long)(fq->tail-fq->head));
        }
        product_fragment_error_emit(vm, node, bi, e, PRODUCT_REASSEMBLY_ERROR_HANDOFF);
      }
    }
  }
  return 1;
}

static void
product_fragment_terminal (vlib_main_t *vm, vlib_node_runtime_t *node,
                            u32 bi, const product_buffer_metadata_t *metadata,
                            const product_packet_lease_t *lease)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  product_metadata_trace (vm, node, b, bi, metadata, lease, "terminal");
  product_buffer_platform_metadata_t platform;
  clib_memcpy_fast (&platform, b->opaque, sizeof (platform));
  product_fragment_envelope_t first = {
    .obligation = platform.obligation, .platform = platform.platform,
    .flags = PRODUCT_FRAGMENT_VALID |
      ((metadata->state_bits & PRODUCT_META_TRACE) ? PRODUCT_FRAGMENT_TRACE : 0),
  };
  if (lease->platform.provenance == PRODUCT_PACKET_PROVENANCE_VPN_TUN &&
      (lease->facts.ip_family == 4 || lease->facts.ip_family == 6) &&
      (lease->facts.protocol == 6 || lease->facts.protocol == 17))
    first.flow_stack_result = metadata->flow_stack_result;
  u32 next = metadata->fragment_bundle_head;
  product_fragment_emit (vm, node, bi, first, lease->terminal_intent,
                         lease->runtime_drop_reason, lease->processing_bypass_reason);
  for (u32 i = 1; i < metadata->fragment_bundle_count; i++)
    {
      if (PREDICT_FALSE (next == PRODUCT_FRAGMENT_NONE))
        clib_panic ("fragment terminal bundle ended early");
      u32 member = next;
      product_fragment_envelope_t e = product_fragment_load (vm, member);
      next = e.next_range;
      e.flow_stack_result = first.flow_stack_result;
      product_fragment_emit (vm, node, member, e, lease->terminal_intent,
                             lease->runtime_drop_reason, lease->processing_bypass_reason);
    }
  if (PREDICT_FALSE (next != PRODUCT_FRAGMENT_NONE))
    clib_panic ("fragment terminal bundle exceeded its bound");
}

static void
product_fragment_origin_check (vlib_main_t *vm, u32 bi,
                                const product_packet_completion_frame_t *completion)
{
  if (!(completion->flags & PRODUCT_COMPLETION_FRAGMENT_MEMBER)
      || (completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE)) return;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  if (PREDICT_FALSE (b->ref_count != 1 || (b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    clib_panic ("fragment original did not reach physical return exclusively");
  product_fragment_counters_t *stats = product_fragment_counters (vm);
  stats->completions++;
  if (completion->flags & PRODUCT_COMPLETION_FRAGMENT_PINNED) stats->pinned_completions++;
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s212 event=origin_release thread=%u buffer=%u token=%llu generation=%llu refs=1 kind=%u\n",
      vm->thread_index, bi, (unsigned long long) completion->obligation.token,
      (unsigned long long) completion->obligation.queue_generation, completion->obligation.kind);
}


static clib_error_t *
product_fragment_startup_config (vlib_main_t *vm, unformat_input_t *input)
{
  (void)vm;
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "contexts %u", &product_fragment_config.contexts)) ;
    else if (unformat(input, "originals %u", &product_fragment_config.originals)) ;
    else if (unformat(input, "timeout-ms %u", &product_fragment_config.timeout_ms)) ;
    else return clib_error_return(0, "unknown product-reassembly configuration: %U",
                                  format_unformat_error, input);
  }
  if (!product_fragment_config.contexts || !product_fragment_config.originals ||
      !product_fragment_config.timeout_ms)
    return clib_error_return(0, "product-reassembly configuration must be positive");
  return 0;
}
VLIB_CONFIG_FUNCTION(product_fragment_startup_config, "product-reassembly");

static void
product_fragment_start (vlib_main_t *vm)
{
  if (!product_fragment_main.initialized) {
    for (u32 i = 0; i < 2; i++)
      product_fragment_main.handoff_queues[i] =
        vlib_frame_queue_main_init(product_fragment_input_node.index, 64);
    product_fragment_main.initialized = 1;
  }
  if (product_fragment_contexts()) clib_panic("fragment contexts survived retirement");
  for (u32 i = 0; i < 2; i++) {
    u32 index = product_fragment_main.handoff_queues[i];
    vlib_frame_queue_main_t *queue = vec_elt_at_index(vlib_get_thread_main()->frame_queue_mains, index);
    if (!product_capacity_ring_empty(index)) clib_panic("fragment queue survived retirement");
    product_capacity_set_empty_ring(index, queue->frame_queue_nelts);
  }
  for (u32 i = 1; i <= PRODUCT_GRAPH_WORKERS; i++) {
    product_fragment_table_destroy(&product_fragment_main.tables[i]);
    if (!product_fragment_table_init(&product_fragment_main.tables[i],
          product_fragment_config.contexts, product_fragment_config.originals,
          (u64)product_fragment_config.timeout_ms*1000))
      clib_panic("product reassembly startup allocation/configuration failed");
  }
  clib_memset(product_fragment_main.threads, 0, sizeof(product_fragment_main.threads));
  product_fragment_main.injected = 0;
  product_fragment_main.timeout_ms = product_fragment_config.timeout_ms;
  product_fragment_main.max_originals = product_fragment_config.originals;
  product_fragment_main.accepting = 1;
  (void)vm;
}

void
product_packet_graph_quiesce_reassembly (vlib_main_t *vm)
{
  product_fragment_main.accepting = 0;
  if (product_fragment_main.initialized)
    for (u32 i = 1; i <= PRODUCT_GRAPH_WORKERS; i++) {
      vlib_main_t *worker_vm = vlib_get_main_by_index(i);
      product_fragment_expire(worker_vm,
        vlib_node_get_runtime(worker_vm, product_fragment_expire_node.index), 1);
    }
  (void)vm;
}

static clib_error_t *
product_fragment_status_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  (void) input; (void) command;
  u64 ingress = 0, completed = 0, pins = 0, released = 0;
  for (u32 t = 0; t <= PRODUCT_GRAPH_WORKERS; t++)
    {
      product_fragment_counters_t *s = &product_fragment_main.threads[t];
      ingress += s->ingress; completed += s->completions;
      pins += s->pins; released += s->pinned_completions;
      vlib_cli_output (vm, "reassembly.thread thread=%u ingress=%llu pins=%llu duplicates=%llu success=%llu errors=%llu completions=%llu pinned_completions=%llu resource_bypasses=%llu",
        t, (unsigned long long) s->ingress, (unsigned long long) s->pins,
        (unsigned long long) s->duplicate_pins, (unsigned long long) s->success,
        (unsigned long long) s->error_groups, (unsigned long long) s->completions,
        (unsigned long long) s->pinned_completions, (unsigned long long) s->resource_bypasses);
    }
  for (u32 i = 0; product_fragment_main.initialized && i < 2; i++)
    {
      u32 index = product_fragment_main.handoff_queues[i];
      vlib_frame_queue_main_t *fqm = vec_elt_at_index (vlib_get_thread_main ()->frame_queue_mains, index);
      u64 pending = 0; u32 slots = 0;
      for (u32 t = 0; t < vec_len (fqm->vlib_frame_queues); t++)
        if (fqm->vlib_frame_queues[t])
          { pending += fqm->vlib_frame_queues[t]->tail - fqm->vlib_frame_queues[t]->head; slots = fqm->vlib_frame_queues[t]->nelts; }
      vlib_cli_output (vm, "reassembly.handoff family=%u queue=%u slots=%u default_slots=%u pending=%llu",
        i ? 6 : 4, index, slots, fqm->frame_queue_nelts, (unsigned long long) pending);
    }
  vlib_cli_output (vm, "reassembly.status generation=%llu accepting=%u contexts=%u originals=%llu retained=%llu completed=%llu timeout_ms=%u max_originals=%u",
    (unsigned long long) product_packet_graph_main.generation,
    product_fragment_main.accepting,
    product_fragment_contexts (),
    (unsigned long long) (ingress - completed), (unsigned long long) (pins - released),
    (unsigned long long) completed, product_fragment_main.timeout_ms,
    product_fragment_main.max_originals);
  return 0;
}
VLIB_CLI_COMMAND (product_fragment_status_command, static) = {
  .path = "show product reassembly", .function = product_fragment_status_cli,
};

/* Diagnostic timeout/capacity setup remains available only on an empty graph.
 * Production capacity is supplied by the startup stanza above. */
static clib_error_t *
product_fragment_config_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  (void)command;
  u32 timeout, contexts, originals = product_fragment_config.originals;
  if (!unformat(input, "timeout-ms %u contexts %u", &timeout, &contexts) ||
      (!unformat(input, "originals %u", &originals) &&
       unformat_check_input(input) != UNFORMAT_END_OF_INPUT) ||
      unformat_check_input(input) != UNFORMAT_END_OF_INPUT ||
      !timeout || !contexts || !originals)
    return clib_error_return(0, "expected positive timeout-ms, contexts and optional originals");
  product_packet_graph_main_t *g = &product_packet_graph_main;
  if (!g->accepting || !product_fragment_main.accepting ||
      g->lifecycle_buffers || g->lifecycle_obligations || product_fragment_contexts())
    return clib_error_return(0, "diagnostic reassembly configuration requires active empty graph");
  product_fragment_table_t tables[PRODUCT_GRAPH_WORKERS] = {0};
  for (u32 i = 0; i < PRODUCT_GRAPH_WORKERS; i++)
    if (!product_fragment_table_init(&tables[i], contexts, originals, (u64)timeout*1000)) {
      for (u32 j = 0; j < PRODUCT_GRAPH_WORKERS; j++) product_fragment_table_destroy(&tables[j]);
      return clib_error_return(0, "reassembly configuration/allocation failed");
    }
  for (u32 i = 0; i < PRODUCT_GRAPH_WORKERS; i++) {
    product_fragment_table_destroy(&product_fragment_main.tables[i+1]);
    product_fragment_main.tables[i+1] = tables[i];
  }
  product_fragment_main.timeout_ms = timeout;
  product_fragment_main.max_originals = originals;
  vlib_cli_output(vm, "reassembly.configured timeout_ms=%u contexts_per_thread=%u max_originals=%u",
    timeout, contexts, originals);
  return 0;
}
VLIB_CLI_COMMAND(product_fragment_config_command, static) = {
  .path = "product reassembly configure", .function = product_fragment_config_cli,
};

/* The normal CLI barrier protects fragment ring configuration. Only reducing
 * an empty, already allocated ring is supported; no new queue or buffer. */
static clib_error_t *
product_fragment_handoff_capacity_cli (vlib_main_t *vm, unformat_input_t *input,
                                      vlib_cli_command_t *command)
{
  (void) command;
  u32 slots = 0;
  if (unformat (input, "default")) slots = 0;
  else if (!unformat (input, "slots %u", &slots) || slots != 2)
    return clib_error_return (0, "expected default or slots 2");
  product_packet_graph_main_t *g = &product_packet_graph_main;
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !product_fragment_main.initialized || !g->accepting
      || g->lifecycle_buffers || g->lifecycle_obligations || g->lifecycle_handoffs
      || g->lifecycle_completion_frames || g->completion_pending_returns
      || product_fragment_contexts ())
    return clib_error_return (0, "fragment capacity requires an active empty graph");
  for (u32 i = 0; i < 2; i++)
    if (!product_capacity_ring_empty (product_fragment_main.handoff_queues[i]))
      return clib_error_return (0, "fragment reassembly ring is not empty");
  for (u32 i = 0; i < 2; i++)
    {
      u32 index = product_fragment_main.handoff_queues[i];
      vlib_frame_queue_main_t *fqm = vec_elt_at_index (vlib_get_thread_main ()->frame_queue_mains, index);
      product_capacity_set_empty_ring (index, slots ? slots : fqm->frame_queue_nelts);
    }
  vlib_cli_output (vm, "reassembly.handoff_capacity generation=%llu mode=%s ip4_queue=%u ip6_queue=%u",
    (unsigned long long) g->generation, slots ? "two-slots" : "default",
    product_fragment_main.handoff_queues[0], product_fragment_main.handoff_queues[1]);
  return 0;
}
VLIB_CLI_COMMAND (product_fragment_handoff_capacity_command, static) = {
  .path = "product reassembly handoff-capacity", .function = product_fragment_handoff_capacity_cli,
};
