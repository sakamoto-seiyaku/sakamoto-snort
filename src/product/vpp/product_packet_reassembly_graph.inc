/* SPDX-License-Identifier: Apache-2.0
 * Native Product reassembly ownership. Included inside the private graph TU.
 * No fragment lookup table: VPP owns range/context identity and handoff. */
#define PRODUCT_FRAGMENT_MAX_ORIGINALS 32
#define PRODUCT_FRAGMENT_MAX_CONTEXTS 64
#define PRODUCT_FRAGMENT_NONE ((u32) ~0)

enum
{
  PRODUCT_FRAGMENT_TRACE = 1 << 0,
  PRODUCT_FRAGMENT_PINNED = 1 << 1,
  PRODUCT_FRAGMENT_DUPLICATE = 1 << 2,
  PRODUCT_FRAGMENT_PREPARED = 1 << 3,
  PRODUCT_FRAGMENT_VALID = 1 << 7,
};

typedef struct
{
  product_adapter_obligation_t obligation;
  product_platform_packet_facts_t platform;
  u32 next_range;
  u32 duplicate_head, duplicate_tail;
  u16 duplicate_count, flags;
} product_fragment_envelope_t;

_Static_assert (sizeof (product_fragment_envelope_t) == 56,
                "fragment envelope uses the existing opaque2 lifetime");
_Static_assert (sizeof (product_fragment_envelope_t) ==
                  sizeof (((vlib_buffer_t *) 0)->opaque2), "fragment overlay");

typedef struct
{
  u64 ingress, pins, duplicate_pins, success, error_groups;
  u64 completions, pinned_completions, resource_bypasses;
} __attribute__((aligned(CLIB_CACHE_LINE_BYTES))) product_fragment_counters_t;

static struct
{
  u32 initialized, accepting, success_next, error_next, native_node;
  u32 injected, timeout_ms;
  product_fragment_counters_t threads[PRODUCT_GRAPH_WORKERS + 1];
} product_fragment_main;

extern vlib_node_registration_t product_fragment_success_node;
extern vlib_node_registration_t product_fragment_error_node;

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
          && envelope.obligation.kind != PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED)))
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

static void
product_fragment_pin (vlib_main_t *vm, u32 bi,
                       product_fragment_envelope_t *envelope)
{
  if (PREDICT_FALSE (envelope->flags & PRODUCT_FRAGMENT_PINNED))
    clib_panic ("fragment original pinned twice");
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  if (PREDICT_FALSE (clib_atomic_add_fetch (&b->ref_count, 1) != 2))
    clib_panic ("fragment original was not exclusively owned");
  envelope->flags |= PRODUCT_FRAGMENT_PINNED;
  product_fragment_counters (vm)->pins++;
  if (envelope->flags & PRODUCT_FRAGMENT_TRACE)
    fprintf (stderr, "s212 event=pin thread=%u buffer=%u token=%llu generation=%llu refs=2\n",
      vm->thread_index, bi, (unsigned long long) envelope->obligation.token,
      (unsigned long long) envelope->obligation.queue_generation);
}

/* VPP calls this before it can free any range head. Prepare all range pins
 * atomically with respect to expected capacity failures. Range ownership is
 * still separate until the native success continuation actually runs. */
static ip4_full_reass_custom_consume_result_t
product_fragment_consume (vlib_main_t *vm, u32 survivor, u32 consumed,
                           void *opaque)
{
  (void) opaque;
  product_fragment_envelope_t first = product_fragment_load (vm, survivor);
  if (survivor == consumed)
    {
      u32 ranges[PRODUCT_FRAGMENT_MAX_ORIGINALS], count = 0, originals = 0;
      u32 next = survivor, data_end = 0;
      while (next != PRODUCT_FRAGMENT_NONE)
        {
          if (count == PRODUCT_FRAGMENT_MAX_ORIGINALS)
            return IP4_FULL_REASS_CUSTOM_CONSUME_CAPACITY;
          vlib_buffer_t *b = vlib_get_buffer (vm, next);
          product_fragment_envelope_t e = product_fragment_load (vm, next);
          if (PREDICT_FALSE (e.flags & PRODUCT_FRAGMENT_PINNED))
            clib_panic ("native range already has a lifetime pin");
          if (e.obligation.kind != first.obligation.kind
              || e.duplicate_count >= PRODUCT_FRAGMENT_MAX_ORIGINALS
              || (b->flags & VLIB_BUFFER_NEXT_PRESENT))
            return IP4_FULL_REASS_CUSTOM_CONSUME_CAPACITY;
          originals += 1 + e.duplicate_count;
          if (originals > PRODUCT_FRAGMENT_MAX_ORIGINALS)
            return IP4_FULL_REASS_CUSTOM_CONSUME_CAPACITY;
          ranges[count++] = next;
          data_end = clib_max (data_end,
            vnet_buffer (b)->ip.reass.range_last + 1);
          next = vnet_buffer (b)->ip.reass.next_range_bi;
        }
      vlib_buffer_t *head = vlib_get_buffer (vm, survivor);
      u32 header = ip4_header_bytes (vlib_buffer_get_current (head));
      if (header + data_end > head->current_length +
                              vlib_buffer_space_left_at_end (vm, head))
        return IP4_FULL_REASS_CUSTOM_CONSUME_CAPACITY;
      for (u32 i = 0; i < count; i++)
        {
          product_fragment_envelope_t e = product_fragment_load (vm, ranges[i]);
          e.next_range = i + 1 < count ? ranges[i + 1] : PRODUCT_FRAGMENT_NONE;
          if (i) product_fragment_pin (vm, ranges[i], &e);
          else e.flags |= PRODUCT_FRAGMENT_PREPARED;
          product_fragment_store (vm, ranges[i], &e);
        }
      if (first.flags & PRODUCT_FRAGMENT_TRACE)
        fprintf (stderr, "s212 event=native_finalize_prepare thread=%u survivor=%u token=%llu generation=%llu ranges=%u originals=%u bytes=%u\n",
          vm->thread_index, survivor, (unsigned long long) first.obligation.token,
          (unsigned long long) first.obligation.queue_generation, count,
          originals, header + data_end);
      return IP4_FULL_REASS_CUSTOM_CONSUME_OK;
    }
  if (first.flags & PRODUCT_FRAGMENT_PREPARED)
    {
      product_fragment_envelope_t e = product_fragment_load (vm, consumed);
      if (PREDICT_FALSE (!(e.flags & PRODUCT_FRAGMENT_PINNED)))
        clib_panic ("native finalize range was not prepared");
      return IP4_FULL_REASS_CUSTOM_CONSUME_OK;
    }

  /* Exact duplicate: retain its original native buffer for the eventual
   * datagram decision. The native seam releases its engine reference now. */
  product_fragment_envelope_t duplicate = product_fragment_load (vm, consumed);
  if (first.duplicate_count + 2 > PRODUCT_FRAGMENT_MAX_ORIGINALS
      || duplicate.duplicate_count
      || duplicate.obligation.kind != first.obligation.kind)
    return IP4_FULL_REASS_CUSTOM_CONSUME_CAPACITY;
  product_fragment_pin (vm, consumed, &duplicate);
  duplicate.flags |= PRODUCT_FRAGMENT_DUPLICATE;
  duplicate.next_range = PRODUCT_FRAGMENT_NONE;
  product_fragment_store (vm, consumed, &duplicate);
  if (first.duplicate_tail != PRODUCT_FRAGMENT_NONE)
    {
      product_fragment_envelope_t tail = product_fragment_load (vm, first.duplicate_tail);
      tail.next_range = consumed;
      product_fragment_store (vm, first.duplicate_tail, &tail);
    }
  else first.duplicate_head = consumed;
  first.duplicate_tail = consumed;
  first.duplicate_count++;
  product_fragment_store (vm, survivor, &first);
  product_fragment_counters (vm)->duplicate_pins++;
  if (duplicate.flags & PRODUCT_FRAGMENT_TRACE)
    fprintf (stderr, "s212 event=native_duplicate_retain thread=%u survivor=%u buffer=%u token=%llu generation=%llu\n",
      vm->thread_index, survivor, consumed,
      (unsigned long long) duplicate.obligation.token,
      (unsigned long long) duplicate.obligation.queue_generation);
  return IP4_FULL_REASS_CUSTOM_CONSUME_OK;
}

static void
product_fragment_error_hook (vlib_main_t *vm, u32 bi,
                             ip4_full_reass_custom_error_reason_t reason,
                             void *opaque)
{
  (void) opaque;
  product_fragment_envelope_t e = product_fragment_load (vm, bi);
  e.flags = (e.flags & 255) | ((u16) reason << 8);
  product_fragment_store (vm, bi, &e);
}

static int
product_fragment_resource_error (u32 reason)
{
  return reason == IP4_FULL_REASS_CUSTOM_ERROR_CAPACITY
    || reason == IP4_FULL_REASS_CUSTOM_ERROR_BUNDLE_CAPACITY
    || reason == IP4_FULL_REASS_CUSTOM_ERROR_RESOURCE
    || reason == IP4_FULL_REASS_CUSTOM_ERROR_HANDOFF;
}

static void
product_fragment_emit (vlib_main_t *vm, vlib_node_runtime_t *node, u32 bi,
                        product_fragment_envelope_t e, u8 intent,
                        u8 drop_reason, u8 bypass_reason)
{
  product_packet_graph_main_t *g = &product_packet_graph_main;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  if (PREDICT_FALSE (b->ref_count != 1))
    clib_panic ("fragment completion still has a native engine reference");
  b->flags &= ~(VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID);
  b->next_buffer = 0;
  product_buffer_platform_metadata_t platform = {e.obligation, e.platform};
  clib_memcpy_fast (b->opaque, &platform, sizeof (platform));
  product_packet_completion_frame_t completion = {
    .obligation = e.obligation, .producer_thread = vm->thread_index,
    .terminal_intent = intent, .runtime_drop_reason = drop_reason,
    .processing_bypass_reason = bypass_reason,
    .flags = PRODUCT_COMPLETION_FRAGMENT_MEMBER |
      ((e.flags & PRODUCT_FRAGMENT_TRACE) ? PRODUCT_COMPLETION_TRACE : 0) |
      ((e.flags & PRODUCT_FRAGMENT_PINNED) ? PRODUCT_COMPLETION_FRAGMENT_PINNED : 0),
  };
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
  if (reason == IP4_FULL_REASS_CUSTOM_ERROR_TIMEOUT)
    drop = PRODUCT_PACKET_DROP_REASSEMBLY_TIMEOUT;
  else if (reason == IP4_FULL_REASS_CUSTOM_ERROR_STOP)
    drop = PRODUCT_PACKET_DROP_REASSEMBLY_STOP;
  else if (reason == IP4_FULL_REASS_CUSTOM_ERROR_INTERNAL)
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

/* Called only after native success, when every absorbed range retains its
 * one original-completion reference and the native context is gone. */
static u32
product_fragment_flatten (vlib_main_t *vm, u32 survivor)
{
  u32 range = survivor, tail = PRODUCT_FRAGMENT_NONE, count = 0;
  while (range != PRODUCT_FRAGMENT_NONE)
    {
      product_fragment_envelope_t e = product_fragment_load (vm, range);
      u32 next_range = e.next_range, member = range;
      u32 duplicate = e.duplicate_head;
      for (;;)
        {
          if (PREDICT_FALSE (++count > PRODUCT_FRAGMENT_MAX_ORIGINALS
                            || vlib_get_buffer (vm, member)->ref_count != 1))
            clib_panic ("invalid completed fragment bundle");
          if (tail != PRODUCT_FRAGMENT_NONE)
            {
              product_fragment_envelope_t previous = product_fragment_load (vm, tail);
              previous.next_range = member;
              product_fragment_store (vm, tail, &previous);
            }
          tail = member;
          if (duplicate == PRODUCT_FRAGMENT_NONE) break;
          member = duplicate;
          product_fragment_envelope_t d = product_fragment_load (vm, member);
          duplicate = d.next_range;
        }
      range = next_range;
    }
  product_fragment_envelope_t last = product_fragment_load (vm, tail);
  last.next_range = PRODUCT_FRAGMENT_NONE;
  product_fragment_store (vm, tail, &last);
  return count;
}

VLIB_NODE_FN (product_fragment_success_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      u32 bi = from[i];
      product_fragment_envelope_t first = product_fragment_load (vm, bi);
      if (PREDICT_FALSE (!(first.flags & PRODUCT_FRAGMENT_PREPARED)))
        clib_panic ("native success without prepared obligations");
      u32 count = product_fragment_flatten (vm, bi);
      first = product_fragment_load (vm, bi);
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      product_buffer_platform_metadata_t platform = {first.obligation, first.platform};
      clib_memcpy_fast (b->opaque, &platform, sizeof (platform));
      product_buffer_metadata_t metadata = {0};
      metadata.origin_obligation_id = first.obligation.token;
      metadata.generation = first.obligation.queue_generation;
      metadata.fragment_bundle_head = first.next_range;
      metadata.fragment_bundle_count = count;
      metadata.fragment_flags = 1;
      if (first.flags & PRODUCT_FRAGMENT_TRACE) metadata.state_bits |= PRODUCT_META_TRACE;
      product_metadata_store (b, &metadata);
      product_fragment_counters (vm)->success++;
      if (first.flags & PRODUCT_FRAGMENT_TRACE)
        fprintf (stderr, "s212 event=native_success thread=%u survivor=%u token=%llu generation=%llu originals=%u bytes=%u uid=%u availability=%u direction=%u provenance=%u\n",
          vm->thread_index, bi, (unsigned long long) first.obligation.token,
          (unsigned long long) first.obligation.queue_generation, count,
          b->current_length, first.platform.uid, first.platform.availability,
          first.platform.direction, first.platform.provenance);
      vlib_buffer_enqueue_to_single_next (vm, node, &bi, 0, 1);
    }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (product_fragment_success_node) = {
  .name = "product-ip4-reassembly-success", .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL, .n_next_nodes = 1,
  .next_nodes = { [0] = "product-packet-admit" },
};

VLIB_NODE_FN (product_fragment_error_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  for (u32 i = 0; i < frame->n_vectors; i++)
    {
      u32 bi = from[i];
      product_fragment_envelope_t first = product_fragment_load (vm, bi);
      u32 reason = first.flags >> 8;
      product_fragment_counters (vm)->error_groups++;
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);
      ip4_header_t *ip = vlib_buffer_get_current (b);
      int finalized_handoff = reason == IP4_FULL_REASS_CUSTOM_ERROR_HANDOFF
        && (first.flags & PRODUCT_FRAGMENT_PREPARED)
        && !ip4_get_fragment_more (ip) && !ip4_get_fragment_offset (ip);
      u32 member = bi, left = 1 + first.duplicate_count;
      if (finalized_handoff)
        {
          left = product_fragment_flatten (vm, bi);
          first = product_fragment_load (vm, bi);
        }
      else if (first.flags & PRODUCT_FRAGMENT_PINNED)
        {
          if (b->ref_count == 2) vlib_buffer_free_no_next (vm, &bi, 1);
          else if (PREDICT_FALSE (b->ref_count != 1))
            clib_panic ("invalid native error reference count");
        }
      for (u32 n = 0; n < left; n++)
        {
          product_fragment_envelope_t e = product_fragment_load (vm, member);
          u32 next = finalized_handoff || n ? e.next_range : first.duplicate_head;
          product_fragment_error_emit (vm, node, member, e, reason);
          member = next;
        }
      if (PREDICT_FALSE (member != PRODUCT_FRAGMENT_NONE))
        clib_panic ("fragment error bundle length mismatch");
    }
  return frame->n_vectors;
}
VLIB_REGISTER_NODE (product_fragment_error_node) = {
  .name = "product-ip4-reassembly-error", .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

static int
product_fragment_dispatch (vlib_main_t *vm, vlib_node_runtime_t *node, u32 bi,
                            const product_buffer_metadata_t *metadata)
{
  if (metadata->fragment_bundle_count) return 0;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  u8 *bytes = vlib_buffer_get_current (b);
  if (b->current_length < 8 || bytes[0] >> 4 != 4
      || !(clib_net_to_host_u16 (((ip4_header_t *) bytes)->flags_and_fragment_offset) & 0x3fff))
    return 0;
  product_buffer_platform_metadata_t saved;
  clib_memcpy_fast (&saved, b->opaque, sizeof (saved));
  product_fragment_envelope_t e = {
    .obligation = saved.obligation, .platform = saved.platform,
    .next_range = PRODUCT_FRAGMENT_NONE,
    .duplicate_head = PRODUCT_FRAGMENT_NONE, .duplicate_tail = PRODUCT_FRAGMENT_NONE,
    .flags = PRODUCT_FRAGMENT_VALID |
      ((metadata->state_bits & PRODUCT_META_TRACE) ? PRODUCT_FRAGMENT_TRACE : 0),
  };
  product_fragment_store (vm, bi, &e);
  product_fragment_counters (vm)->ingress++;
  u32 header = (bytes[0] & 15) * 4, length = b->current_length;
  u32 declared = clib_net_to_host_u16 (((ip4_header_t *) bytes)->length);
  if (e.flags & PRODUCT_FRAGMENT_TRACE)
    fprintf (stderr, "s212 event=fragment_ingress thread=%u buffer=%u token=%llu generation=%llu kind=%u origin_worker=%u lane=%u packet=%u offset=%u more=%u bytes=%u refs=%u uid=%u availability=%u\n",
      vm->thread_index, bi, (unsigned long long) e.obligation.token,
      (unsigned long long) e.obligation.queue_generation, e.obligation.kind,
      e.obligation.origin_worker, e.obligation.origin_lane, e.obligation.packet_id,
      ip4_get_fragment_offset_bytes ((ip4_header_t *) bytes),
      !!ip4_get_fragment_more ((ip4_header_t *) bytes), length, b->ref_count,
      e.platform.uid, e.platform.availability);
  if (!product_fragment_main.accepting)
    product_fragment_error_emit (vm, node, bi, e, IP4_FULL_REASS_CUSTOM_ERROR_STOP);
  else if (length < 20 || header < 20 || header > length
           || declared < header || declared > length)
    product_fragment_error_emit (vm, node, bi, e, IP4_FULL_REASS_CUSTOM_ERROR_MALFORMED);
  else if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    product_fragment_error_emit (vm, node, bi, e, IP4_FULL_REASS_CUSTOM_ERROR_RESOURCE);
  else
    {
      clib_memset (b->opaque, 0, sizeof (b->opaque));
      vnet_buffer (b)->sw_if_index[VLIB_TX] = 0; /* Native FIB context, not Linux ifindex. */
      vnet_buffer (b)->ip.reass.next_index = product_fragment_main.success_next;
      vnet_buffer (b)->ip.reass.error_next_index = product_fragment_main.error_next;
      if ((e.flags & PRODUCT_FRAGMENT_TRACE) && !(b->flags & VLIB_BUFFER_IS_TRACED))
        {
          int traced = vlib_trace_buffer (vm, node, PRODUCT_ADMIT_NEXT_REASSEMBLY, b, 1);
          (void) traced;
        }
      vlib_buffer_enqueue_to_single_next (vm, node, &bi, PRODUCT_ADMIT_NEXT_REASSEMBLY, 1);
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

static void
product_fragment_start (vlib_main_t *vm)
{
  if (!product_fragment_main.initialized)
    {
      vlib_node_t *native = vlib_get_node_by_name (vm, (u8 *) "ip4-full-reassembly-custom");
      if (!native) clib_panic ("native IPv4 reassembly custom node missing");
      product_fragment_main.native_node = native->index;
      product_fragment_main.success_next = ip4_full_reass_custom_register_next_node (product_fragment_success_node.index);
      product_fragment_main.error_next = ip4_full_reass_custom_register_next_node (product_fragment_error_node.index);
      ip4_full_reass_custom_register_consume_hook (product_fragment_consume, 0);
      ip4_full_reass_custom_register_error_hook (product_fragment_error_hook, 0);
      product_fragment_main.initialized = 1;
    }
  if (ip4_full_reass_custom_count (product_fragment_main.error_next))
    clib_panic ("native fragments survived generation retirement");
  clib_memset (product_fragment_main.threads, 0, sizeof (product_fragment_main.threads));
  product_fragment_main.injected = 0;
  product_fragment_main.accepting = 1;
  product_fragment_main.timeout_ms = 500;
  if (ip4_full_reass_set (500, PRODUCT_FRAGMENT_MAX_CONTEXTS,
                          PRODUCT_FRAGMENT_MAX_ORIGINALS, 50))
    clib_panic ("cannot configure bounded native reassembly");
}

void
product_packet_graph_quiesce_reassembly (vlib_main_t *vm)
{
  product_fragment_main.accepting = 0;
  if (product_fragment_main.initialized)
    ip4_full_reass_custom_flush (vm, product_fragment_main.error_next);
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
  vlib_cli_output (vm, "reassembly.status generation=%llu accepting=%u contexts=%u originals=%llu retained=%llu completed=%llu timeout_ms=%u max_originals=%u",
    (unsigned long long) product_packet_graph_main.generation,
    product_fragment_main.accepting,
    product_fragment_main.initialized ? ip4_full_reass_custom_count (product_fragment_main.error_next) : 0,
    (unsigned long long) (ingress - completed), (unsigned long long) (pins - released),
    (unsigned long long) completed, product_fragment_main.timeout_ms, PRODUCT_FRAGMENT_MAX_ORIGINALS);
  return 0;
}
VLIB_CLI_COMMAND (product_fragment_status_command, static) = {
  .path = "show product reassembly", .function = product_fragment_status_cli,
};

static clib_error_t *
product_fragment_config_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  (void) command;
  u32 timeout, contexts;
  if (!unformat (input, "timeout-ms %u contexts %u", &timeout, &contexts)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || timeout < 100 || timeout > 30000 || !contexts
      || contexts > PRODUCT_FRAGMENT_MAX_CONTEXTS)
    return clib_error_return (0, "expected timeout-ms 100..30000 contexts 1..64");
  product_packet_graph_main_t *g = &product_packet_graph_main;
  if (!g->accepting || !product_fragment_main.accepting
      || g->lifecycle_buffers || g->lifecycle_obligations
      || ip4_full_reass_custom_count (product_fragment_main.error_next))
    return clib_error_return (0, "reassembly configuration requires an active empty graph");
  if (ip4_full_reass_set (timeout, contexts, PRODUCT_FRAGMENT_MAX_ORIGINALS, 50))
    return clib_error_return (0, "native configuration rejected");
  product_fragment_main.timeout_ms = timeout;
  vlib_cli_output (vm, "reassembly.configured timeout_ms=%u contexts_per_thread=%u", timeout, contexts);
  return 0;
}
VLIB_CLI_COMMAND (product_fragment_config_command, static) = {
  .path = "product reassembly configure", .function = product_fragment_config_cli,
};
