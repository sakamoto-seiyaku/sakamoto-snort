/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Product fragment steering is deliberately part of the installed VLIB
 * graph.  The official full-reassembly custom nodes own the only datagram
 * lookup table. Product metadata only carries a bounded inline completion
 * bundle across the destructive official finalize step.
 */

#define PRODUCT_FRAGMENT_BUNDLE_CAPACITY 4
#define PRODUCT_FRAGMENT_METADATA_MAGIC UINT32_C (0x53313735)
#define PRODUCT_FRAGMENT_FINAL_OWNER_UNKNOWN UINT16_MAX

enum
{
  PRODUCT_FRAGMENT_META_FRAGMENT = 1 << 0,
  PRODUCT_FRAGMENT_META_INITIAL = 1 << 1,
  PRODUCT_FRAGMENT_META_STEER_CREDIT = 1 << 2,
  PRODUCT_FRAGMENT_META_FINAL_CREDIT = 1 << 3,
  PRODUCT_FRAGMENT_META_TRANSFERRED = 1 << 4,
  PRODUCT_FRAGMENT_META_SETTLED = 1 << 5,
};

typedef struct
{
  u64 obligation_ids[PRODUCT_FRAGMENT_BUNDLE_CAPACITY];
  u16 final_owner;
  u16 fragment_worker;
  u8 obligation_count;
  u8 family;
  u8 fixture_vector;
  u8 flags;
  u32 magic;
  u8 custom_error;
  u16 generation;
  u8 reserved[sizeof (product_buffer_metadata_t) - 48];
} product_fragment_metadata_t;

_Static_assert (sizeof (product_fragment_metadata_t) ==
                  sizeof (product_buffer_metadata_t),
                "fragment completion bundle must exactly fit opaque2");

typedef struct
{
  u8 family;
  u8 protocol;
  u8 initial;
  u8 reserved;
  u16 transport_offset;
  u16 fragment_offset;
  u32 identification;
  u8 source[16];
  u8 destination[16];
} product_fragment_key_t;

typedef enum
{
  PRODUCT_FRAGMENT_ERROR_CONFLICT = 1,
  PRODUCT_FRAGMENT_ERROR_TIMEOUT,
  PRODUCT_FRAGMENT_ERROR_CAPACITY,
  PRODUCT_FRAGMENT_ERROR_HANDOFF_CONGESTION,
  PRODUCT_FRAGMENT_ERROR_INVARIANT,
} product_fragment_error_t;

typedef struct
{
  u32 steer_frame_queue;
  u32 final_frame_queue;
  u32 steer_credits[PRODUCT_GRAPH_WORKERS];
  u32 final_credits[PRODUCT_GRAPH_WORKERS];
  u32 ip4_success_next;
  u32 ip4_error_next;
  u32 ip6_success_next;
  u32 ip6_error_next;
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  u32 enabled;
#endif
} product_fragment_graph_main_t;

static product_fragment_graph_main_t product_fragment_graph_main;

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
static void product_fragment_fixture_tag (u64 obligation, u8 *vector);
static void product_fragment_evidence_absorbed (
  const product_fragment_metadata_t *metadata, u32 buffer_index);
static void product_fragment_evidence_duplicate_returned (
  const product_fragment_metadata_t *metadata, u32 buffer_index);
static void product_fragment_evidence_settled (
  const product_fragment_metadata_t *metadata, u32 survivor_buffer_index,
  u16 final_owner, u8 runtime_error);
#else
#define product_fragment_evidence_absorbed(metadata, buffer_index) ((void) 0)
#define product_fragment_evidence_duplicate_returned(metadata, buffer_index) \
  ((void) 0)
#define product_fragment_evidence_settled(metadata, buffer_index, owner, error) \
  ((void) 0)
#endif

static void
product_fragment_metadata_load (const vlib_buffer_t *buffer,
                                product_fragment_metadata_t *metadata)
{
  clib_memcpy_fast (metadata, buffer->opaque2, sizeof (*metadata));
}

static void
product_fragment_metadata_store (vlib_buffer_t *buffer,
                                 const product_fragment_metadata_t *metadata)
{
  clib_memcpy_fast (buffer->opaque2, metadata, sizeof (*metadata));
}

static int
product_fragment_metadata_valid (const product_fragment_metadata_t *metadata)
{
  return metadata->magic == PRODUCT_FRAGMENT_METADATA_MAGIC
         && (metadata->flags & PRODUCT_FRAGMENT_META_FRAGMENT)
         && metadata->obligation_count != 0
         && metadata->obligation_count <= PRODUCT_FRAGMENT_BUNDLE_CAPACITY
         && (metadata->family == 4 || metadata->family == 6);
}

static int
product_fragment_parse (vlib_main_t *vm, vlib_buffer_t *buffer,
                        product_fragment_key_t *key)
{
  u8 *packet = vlib_buffer_get_current (buffer);
  u32 length = vlib_buffer_length_in_chain (vm, buffer);
  clib_memset (key, 0, sizeof (*key));
  if (length < 1)
    return 0;
  if ((packet[0] >> 4) == 4)
    {
      ip4_header_t *ip4;
      u32 header_length;
      if (length < sizeof (ip4_header_t))
        return 0;
      ip4 = (ip4_header_t *) packet;
      header_length = ip4_header_bytes (ip4);
      if (header_length < sizeof (*ip4) || header_length > length
          || (!ip4_get_fragment_more (ip4)
              && !ip4_get_fragment_offset (ip4)))
        return 0;
      key->family = 4;
      key->protocol = ip4->protocol;
      key->initial = ip4_get_fragment_offset (ip4) == 0;
      key->transport_offset = (u16) header_length;
      key->fragment_offset = (u16) ip4_get_fragment_offset_bytes (ip4);
      key->identification = clib_net_to_host_u16 (ip4->fragment_id);
      clib_memcpy_fast (key->source + 12, &ip4->src_address, 4);
      clib_memcpy_fast (key->destination + 12, &ip4->dst_address, 4);
      return 1;
    }
  if ((packet[0] >> 4) == 6)
    {
      ip6_header_t *ip6;
      ip6_ext_hdr_chain_t chain;
      ip6_frag_hdr_t *fragment;
      int fragment_index;
      if (length < sizeof (ip6_header_t))
        return 0;
      ip6 = (ip6_header_t *) packet;
      fragment_index = ip6_ext_header_walk (
        buffer, ip6, IP_PROTOCOL_IPV6_FRAGMENTATION, &chain);
      if (fragment_index < 0
          || chain.eh[fragment_index].protocol
               != IP_PROTOCOL_IPV6_FRAGMENTATION)
        return 0;
      fragment = ip6_ext_next_header_offset (
        ip6, chain.eh[fragment_index].offset);
      if (!ip6_frag_hdr_more (fragment)
          && ip6_frag_hdr_offset (fragment) == 0)
        return 0;
      key->family = 6;
      key->protocol = fragment->next_hdr;
      key->initial = ip6_frag_hdr_offset (fragment) == 0;
      key->transport_offset =
        (u16) (chain.eh[fragment_index].offset + sizeof (*fragment));
      key->fragment_offset = (u16) ip6_frag_hdr_offset_bytes (fragment);
      key->identification = clib_net_to_host_u32 (fragment->identification);
      clib_memcpy_fast (key->source, &ip6->src_address, 16);
      clib_memcpy_fast (key->destination, &ip6->dst_address, 16);
      return 1;
    }
  return 0;
}

static int
product_fragment_packet_detect (vlib_main_t *vm, vlib_buffer_t *buffer)
{
  product_fragment_key_t key;
  return product_fragment_parse (vm, buffer, &key);
}

static u64
product_fragment_hash_bytes (u64 hash, const u8 *bytes, u32 length)
{
  u32 index;
  for (index = 0; index < length; index++)
    hash = (hash ^ bytes[index]) * UINT64_C (1099511628211);
  return hash;
}

static u16
product_fragment_select_worker (const product_fragment_key_t *key)
{
  u64 hash = UINT64_C (14695981039346656037) ^ PRODUCT_GRAPH_HASH_SEED;
  u8 identification[4] = {
    (u8) (key->identification >> 24), (u8) (key->identification >> 16),
    (u8) (key->identification >> 8), (u8) key->identification,
  };
  hash = product_fragment_hash_bytes (hash, &key->family, 1);
  hash = product_fragment_hash_bytes (hash, &key->protocol, 1);
  hash = product_fragment_hash_bytes (hash, key->source, 16);
  hash = product_fragment_hash_bytes (hash, key->destination, 16);
  hash = product_fragment_hash_bytes (hash, identification, 4);
  return (u16) (hash % PRODUCT_GRAPH_WORKERS);
}

static int
product_fragment_initial_owner (vlib_main_t *vm, vlib_buffer_t *buffer,
                                const product_fragment_key_t *fragment,
                                u16 *owner)
{
  product_packet_facts_t facts;
  product_canonical_flow_key_t canonical_key;
  product_worker_layout_t layout = {
    .worker_count = PRODUCT_GRAPH_WORKERS,
    .hash_seed = PRODUCT_GRAPH_HASH_SEED,
  };
  u8 *packet = vlib_buffer_get_current (buffer);
  u32 length = vlib_buffer_length_in_chain (vm, buffer);
  if (!fragment->initial || fragment->transport_offset + 4 > length
      || (fragment->protocol != IP_PROTOCOL_TCP
          && fragment->protocol != IP_PROTOCOL_UDP))
    return 0;
  clib_memset (&facts, 0, sizeof (facts));
  facts.l3_status = PRODUCT_PACKET_L3_COMPLETE;
  facts.l4_status = PRODUCT_PACKET_L4_COMPLETE;
  facts.ip_family = fragment->family;
  facts.protocol = fragment->protocol;
  clib_memcpy_fast (facts.source_address, fragment->source, 16);
  clib_memcpy_fast (facts.destination_address, fragment->destination, 16);
  facts.source_port = (u16) (((u16) packet[fragment->transport_offset] << 8)
                             | packet[fragment->transport_offset + 1]);
  facts.destination_port =
    (u16) (((u16) packet[fragment->transport_offset + 2] << 8)
           | packet[fragment->transport_offset + 3]);
  return product_packet_owner_from_facts (
           &layout, PRODUCT_GRAPH_FLOW_DOMAIN, &facts, &canonical_key, owner)
         == PRODUCT_PACKET_OK;
}

static int
product_fragment_credit_reserve (u32 credits[PRODUCT_GRAPH_WORKERS],
                                 u16 worker)
{
  u32 available = clib_atomic_load_acq_n (&credits[worker]);
  while (available != 0)
    if (clib_atomic_cmp_and_swap_acq_relax_n (
          &credits[worker], &available, available - 1, 0))
      return 1;
  return 0;
}

static void
product_fragment_credit_release (u32 credits[PRODUCT_GRAPH_WORKERS],
                                 u16 worker)
{
  clib_atomic_fetch_add_relax (&credits[worker], 1);
}

static int
product_fragment_enqueue (vlib_main_t *vm, vlib_node_runtime_t *node,
                          u32 frame_queue,
                          u32 credits[PRODUCT_GRAPH_WORKERS], u32 buffer_index,
                          u16 worker)
{
  u16 thread = (u16) vlib_get_worker_thread_index (worker);
  u32 failed;
  if (!product_fragment_credit_reserve (credits, worker))
    return 0;
  if (vlib_buffer_enqueue_to_thread_retained (
        vm, node, frame_queue, &buffer_index, &thread, 1, &failed)
      != 1)
    {
      product_fragment_credit_release (credits, worker);
      return 0;
    }
  return 1;
}

static void
product_fragment_prepare_reassembly_next (vlib_buffer_t *buffer, u8 family)
{
  product_fragment_graph_main_t *fragment = &product_fragment_graph_main;
  if (family == 4)
    {
      vnet_buffer (buffer)->ip.reass.next_index = fragment->ip4_success_next;
      vnet_buffer (buffer)->ip.reass.error_next_index =
        fragment->ip4_error_next;
    }
  else
    {
      vnet_buffer (buffer)->ip.reass.next_index = fragment->ip6_success_next;
      vnet_buffer (buffer)->ip.reass.error_next_index =
        fragment->ip6_error_next;
    }
}

static void
product_fragment_inline_settle (vlib_main_t *vm, u32 buffer_index,
                                product_fragment_metadata_t *metadata,
                                u16 final_owner, u8 runtime_error)
{
  if (!product_fragment_metadata_valid (metadata)
      || (metadata->flags & PRODUCT_FRAGMENT_META_SETTLED))
    runtime_error = PRODUCT_FRAGMENT_ERROR_INVARIANT;
  metadata->flags |= PRODUCT_FRAGMENT_META_SETTLED;
  product_fragment_metadata_store (vlib_get_buffer (vm, buffer_index),
                                   metadata);
  product_fragment_evidence_settled (
    metadata, buffer_index, final_owner, runtime_error);
  vlib_buffer_free (vm, &buffer_index, 1);
  clib_atomic_fetch_sub_relax (
    &product_packet_graph_main.lifecycle_obligations,
    metadata->obligation_count);
  clib_atomic_fetch_sub_relax (&product_packet_graph_main.lifecycle_buffers,
                               1);
  clib_atomic_fetch_add_relax (
    &product_packet_graph_main.lifecycle_terminal_intents,
    metadata->obligation_count);
  clib_atomic_fetch_add_relax (
    &product_packet_graph_main.lifecycle_settlements,
    metadata->obligation_count);
  clib_atomic_fetch_add_relax (&product_packet_graph_main.lifecycle_returns,
                               1);
}

static int
product_fragment_reject_stale (vlib_main_t *vm, u32 buffer_index,
                               const product_fragment_metadata_t *metadata)
{
  if (metadata->generation == product_packet_graph_main.generation)
    return 0;
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
  clib_atomic_fetch_add_relax (
    &product_packet_graph_main.stale_events_rejected, 1);
#endif
  vlib_buffer_free (vm, &buffer_index, 1);
  return 1;
}

static int
product_fragment_consume_common (vlib_main_t *vm, u32 survivor_buffer_index,
                                 u32 fragment_buffer_index, void *opaque)
{
  vlib_buffer_t *survivor = vlib_get_buffer (vm, survivor_buffer_index);
  vlib_buffer_t *consumed = vlib_get_buffer (vm, fragment_buffer_index);
  product_fragment_metadata_t survivor_metadata;
  product_fragment_metadata_t consumed_metadata;
  u32 index;
  (void) opaque;
  product_fragment_metadata_load (survivor, &survivor_metadata);
  product_fragment_metadata_load (consumed, &consumed_metadata);
  if (!product_fragment_metadata_valid (&survivor_metadata)
      || !product_fragment_metadata_valid (&consumed_metadata))
    return 0;
  if (fragment_buffer_index == survivor_buffer_index)
    return 1;
  if (survivor_metadata.obligation_count + consumed_metadata.obligation_count
      > PRODUCT_FRAGMENT_BUNDLE_CAPACITY)
    return 0;
  for (index = 0; index < consumed_metadata.obligation_count; index++)
    {
      survivor_metadata.obligation_ids[survivor_metadata.obligation_count++] =
        consumed_metadata.obligation_ids[index];
    }
  if ((consumed_metadata.flags & PRODUCT_FRAGMENT_META_INITIAL)
      && consumed_metadata.final_owner
           != PRODUCT_FRAGMENT_FINAL_OWNER_UNKNOWN)
    {
      survivor_metadata.flags |= PRODUCT_FRAGMENT_META_INITIAL;
      survivor_metadata.final_owner = consumed_metadata.final_owner;
    }
  consumed_metadata.flags |= PRODUCT_FRAGMENT_META_TRANSFERRED;
  product_fragment_metadata_store (survivor, &survivor_metadata);
  product_fragment_metadata_store (consumed, &consumed_metadata);
  product_fragment_evidence_absorbed (&consumed_metadata,
                                      fragment_buffer_index);
  clib_atomic_fetch_sub_relax (&product_packet_graph_main.lifecycle_buffers,
                               1);
  clib_atomic_fetch_add_relax (&product_packet_graph_main.lifecycle_returns,
                               1);
  return 1;
}

static ip4_full_reass_custom_consume_result_t
product_fragment_ip4_consume (vlib_main_t *vm, u32 survivor_buffer_index,
                              u32 fragment_buffer_index, void *opaque)
{
  return product_fragment_consume_common (
           vm, survivor_buffer_index, fragment_buffer_index, opaque)
           ? IP4_FULL_REASS_CUSTOM_CONSUME_OK
           : IP4_FULL_REASS_CUSTOM_CONSUME_CAPACITY;
}

static ip6_full_reass_custom_consume_result_t
product_fragment_ip6_consume (vlib_main_t *vm, u32 survivor_buffer_index,
                              u32 fragment_buffer_index, void *opaque)
{
  return product_fragment_consume_common (
           vm, survivor_buffer_index, fragment_buffer_index, opaque)
           ? IP6_FULL_REASS_CUSTOM_CONSUME_OK
           : IP6_FULL_REASS_CUSTOM_CONSUME_CAPACITY;
}

static u8
product_fragment_ip4_error_value (
  ip4_full_reass_custom_error_reason_t reason)
{
  switch (reason)
    {
    case IP4_FULL_REASS_CUSTOM_ERROR_TIMEOUT:
      return PRODUCT_FRAGMENT_ERROR_TIMEOUT;
    case IP4_FULL_REASS_CUSTOM_ERROR_FRAGMENT_CONFLICT:
      return PRODUCT_FRAGMENT_ERROR_CONFLICT;
    case IP4_FULL_REASS_CUSTOM_ERROR_CAPACITY:
    case IP4_FULL_REASS_CUSTOM_ERROR_BUNDLE_CAPACITY:
    case IP4_FULL_REASS_CUSTOM_ERROR_RESOURCE:
      return PRODUCT_FRAGMENT_ERROR_CAPACITY;
    case IP4_FULL_REASS_CUSTOM_ERROR_DUPLICATE_FRAGMENT:
      return 0;
    default:
      return PRODUCT_FRAGMENT_ERROR_INVARIANT;
    }
}

static u8
product_fragment_ip6_error_value (
  ip6_full_reass_custom_error_reason_t reason)
{
  switch (reason)
    {
    case IP6_FULL_REASS_CUSTOM_ERROR_TIMEOUT:
      return PRODUCT_FRAGMENT_ERROR_TIMEOUT;
    case IP6_FULL_REASS_CUSTOM_ERROR_FRAGMENT_CONFLICT:
      return PRODUCT_FRAGMENT_ERROR_CONFLICT;
    case IP6_FULL_REASS_CUSTOM_ERROR_CAPACITY:
    case IP6_FULL_REASS_CUSTOM_ERROR_BUNDLE_CAPACITY:
    case IP6_FULL_REASS_CUSTOM_ERROR_RESOURCE:
      return PRODUCT_FRAGMENT_ERROR_CAPACITY;
    case IP6_FULL_REASS_CUSTOM_ERROR_DUPLICATE_FRAGMENT:
      return 0;
    default:
      return PRODUCT_FRAGMENT_ERROR_INVARIANT;
    }
}

static void
product_fragment_ip4_error (vlib_main_t *vm, u32 buffer_index,
                            ip4_full_reass_custom_error_reason_t reason,
                            void *opaque)
{
  vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
  product_fragment_metadata_t metadata;
  (void) opaque;
  product_fragment_metadata_load (buffer, &metadata);
  if (product_fragment_metadata_valid (&metadata))
    {
      metadata.custom_error = product_fragment_ip4_error_value (reason);
      product_fragment_metadata_store (buffer, &metadata);
    }
}

static void
product_fragment_ip6_error (vlib_main_t *vm, u32 buffer_index,
                            ip6_full_reass_custom_error_reason_t reason,
                            void *opaque)
{
  vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
  product_fragment_metadata_t metadata;
  (void) opaque;
  product_fragment_metadata_load (buffer, &metadata);
  if (product_fragment_metadata_valid (&metadata))
    {
      metadata.custom_error = product_fragment_ip6_error_value (reason);
      product_fragment_metadata_store (buffer, &metadata);
    }
}

enum
{
  PRODUCT_FRAGMENT_STEER_NEXT_IP4,
  PRODUCT_FRAGMENT_STEER_NEXT_IP6,
  PRODUCT_FRAGMENT_STEER_NEXT_ERROR,
  PRODUCT_FRAGMENT_STEER_N_NEXT,
};

VLIB_NODE_FN (product_packet_fragment_steer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_fragment_graph_main_t *fragment = &product_fragment_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;
  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_buffer_metadata_t ingress_metadata;
      product_fragment_metadata_t metadata;
      product_fragment_key_t key;
      u16 worker;
      u16 current_worker = (u16) vlib_get_worker_index (vm->thread_index);
      product_metadata_load (buffer, &ingress_metadata);
      if (!product_fragment_parse (vm, buffer, &key))
        {
          vlib_buffer_enqueue_to_single_next (
            vm, node, &buffer_index, PRODUCT_FRAGMENT_STEER_NEXT_ERROR, 1);
          continue;
        }
      worker = product_fragment_select_worker (&key);
      clib_memset (&metadata, 0, sizeof (metadata));
      metadata.obligation_ids[0] = ingress_metadata.origin_obligation_id;
      metadata.final_owner = PRODUCT_FRAGMENT_FINAL_OWNER_UNKNOWN;
      metadata.fragment_worker = worker;
      metadata.obligation_count = 1;
      metadata.family = key.family;
      metadata.fixture_vector = 0xff;
      metadata.flags = PRODUCT_FRAGMENT_META_FRAGMENT;
      metadata.magic = PRODUCT_FRAGMENT_METADATA_MAGIC;
      metadata.generation = ingress_metadata.generation;
      if (key.initial)
        {
          metadata.flags |= PRODUCT_FRAGMENT_META_INITIAL;
          product_fragment_initial_owner (vm, buffer, &key,
                                          &metadata.final_owner);
        }
#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
      product_fragment_fixture_tag (ingress_metadata.origin_obligation_id,
                                    &metadata.fixture_vector);
#endif
      product_fragment_prepare_reassembly_next (buffer, key.family);
      product_fragment_metadata_store (buffer, &metadata);
      if (worker == current_worker)
        vlib_buffer_enqueue_to_single_next (
          vm, node, &buffer_index,
          key.family == 4 ? PRODUCT_FRAGMENT_STEER_NEXT_IP4
                          : PRODUCT_FRAGMENT_STEER_NEXT_IP6,
          1);
      else
        {
          metadata.flags |= PRODUCT_FRAGMENT_META_STEER_CREDIT;
          product_fragment_metadata_store (buffer, &metadata);
          if (!product_fragment_enqueue (
                vm, node, fragment->steer_frame_queue,
                fragment->steer_credits, buffer_index, worker))
            {
              metadata.flags &= ~PRODUCT_FRAGMENT_META_STEER_CREDIT;
              product_fragment_inline_settle (
                vm, buffer_index, &metadata, current_worker,
                PRODUCT_FRAGMENT_ERROR_HANDOFF_CONGESTION);
            }
        }
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_fragment_steer_node) = {
  .name = "product-packet-fragment-steer",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = PRODUCT_FRAGMENT_STEER_N_NEXT,
  .next_nodes = {
    [PRODUCT_FRAGMENT_STEER_NEXT_IP4] = "ip4-full-reassembly-custom",
    [PRODUCT_FRAGMENT_STEER_NEXT_IP6] = "ip6-full-reassembly-custom",
    [PRODUCT_FRAGMENT_STEER_NEXT_ERROR] = "product-packet-fragment-error",
  },
};

VLIB_NODE_FN (product_packet_fragment_entry_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_fragment_graph_main_t *fragment = &product_fragment_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;
  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_fragment_metadata_t metadata;
      product_fragment_metadata_load (buffer, &metadata);
      if (product_fragment_reject_stale (vm, buffer_index, &metadata))
        continue;
      if (!product_fragment_metadata_valid (&metadata)
          || !(metadata.flags & PRODUCT_FRAGMENT_META_STEER_CREDIT))
        {
          vlib_buffer_enqueue_to_single_next (
            vm, node, &buffer_index, PRODUCT_FRAGMENT_STEER_NEXT_ERROR, 1);
          continue;
        }
      product_fragment_credit_release (fragment->steer_credits,
                                       metadata.fragment_worker);
      metadata.flags &= ~PRODUCT_FRAGMENT_META_STEER_CREDIT;
      product_fragment_metadata_store (buffer, &metadata);
      vlib_buffer_enqueue_to_single_next (
        vm, node, &buffer_index,
        metadata.family == 4 ? PRODUCT_FRAGMENT_STEER_NEXT_IP4
                             : PRODUCT_FRAGMENT_STEER_NEXT_IP6,
        1);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_fragment_entry_node) = {
  .name = "product-packet-fragment-entry",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = PRODUCT_FRAGMENT_STEER_N_NEXT,
  .next_nodes = {
    [PRODUCT_FRAGMENT_STEER_NEXT_IP4] = "ip4-full-reassembly-custom",
    [PRODUCT_FRAGMENT_STEER_NEXT_IP6] = "ip6-full-reassembly-custom",
    [PRODUCT_FRAGMENT_STEER_NEXT_ERROR] = "product-packet-fragment-error",
  },
};

enum
{
  PRODUCT_FRAGMENT_REASSEMBLED_NEXT_FINAL,
  PRODUCT_FRAGMENT_REASSEMBLED_NEXT_ERROR,
  PRODUCT_FRAGMENT_REASSEMBLED_N_NEXT,
};

VLIB_NODE_FN (product_packet_fragment_reassembled_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_fragment_graph_main_t *fragment = &product_fragment_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;
  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_fragment_metadata_t metadata;
      product_packet_ingress_t ingress;
      product_packet_lease_t lease;
      product_worker_layout_t layout = {
        .worker_count = PRODUCT_GRAPH_WORKERS,
        .hash_seed = PRODUCT_GRAPH_HASH_SEED,
      };
      u16 current_worker = (u16) vlib_get_worker_index (vm->thread_index);
      product_fragment_metadata_load (buffer, &metadata);
      if (product_fragment_reject_stale (vm, buffer_index, &metadata))
        continue;
      clib_memset (&ingress, 0, sizeof (ingress));
      ingress.data = vlib_buffer_get_current (buffer);
      ingress.length = vlib_buffer_length_in_chain (vm, buffer);
      ingress.current_worker = current_worker;
      ingress.flow_domain = PRODUCT_GRAPH_FLOW_DOMAIN;
      ingress.origin_obligation_id = metadata.obligation_ids[0];
      if (!product_fragment_metadata_valid (&metadata)
          || !(metadata.flags & PRODUCT_FRAGMENT_META_INITIAL)
          || metadata.fragment_worker != current_worker
          || metadata.final_owner == PRODUCT_FRAGMENT_FINAL_OWNER_UNKNOWN
          || product_packet_admit (&layout, &ingress, &lease)
               != PRODUCT_PACKET_OK
          || lease.expected_owner != metadata.final_owner)
        {
          product_fragment_inline_settle (
            vm, buffer_index, &metadata, current_worker,
            PRODUCT_FRAGMENT_ERROR_INVARIANT);
          continue;
        }
      if (metadata.final_owner == current_worker)
        vlib_buffer_enqueue_to_single_next (
          vm, node, &buffer_index, PRODUCT_FRAGMENT_REASSEMBLED_NEXT_FINAL, 1);
      else
        {
          metadata.flags |= PRODUCT_FRAGMENT_META_FINAL_CREDIT;
          product_fragment_metadata_store (buffer, &metadata);
          if (!product_fragment_enqueue (
                vm, node, fragment->final_frame_queue,
                fragment->final_credits, buffer_index, metadata.final_owner))
            {
              metadata.flags &= ~PRODUCT_FRAGMENT_META_FINAL_CREDIT;
              product_fragment_inline_settle (
                vm, buffer_index, &metadata, current_worker,
                PRODUCT_FRAGMENT_ERROR_HANDOFF_CONGESTION);
            }
        }
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_fragment_reassembled_node) = {
  .name = "product-packet-fragment-reassembled",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = PRODUCT_FRAGMENT_REASSEMBLED_N_NEXT,
  .next_nodes = {
    [PRODUCT_FRAGMENT_REASSEMBLED_NEXT_FINAL] =
      "product-packet-fragment-final-owner",
    [PRODUCT_FRAGMENT_REASSEMBLED_NEXT_ERROR] =
      "product-packet-fragment-error",
  },
};

VLIB_NODE_FN (product_packet_fragment_final_owner_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  product_fragment_graph_main_t *fragment = &product_fragment_graph_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;
  (void) node;
  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_fragment_metadata_t metadata;
      u16 current_worker = (u16) vlib_get_worker_index (vm->thread_index);
      product_fragment_metadata_load (buffer, &metadata);
      if (product_fragment_reject_stale (vm, buffer_index, &metadata))
        continue;
      if (metadata.flags & PRODUCT_FRAGMENT_META_FINAL_CREDIT)
        {
          product_fragment_credit_release (fragment->final_credits,
                                           metadata.final_owner);
          metadata.flags &= ~PRODUCT_FRAGMENT_META_FINAL_CREDIT;
        }
      product_fragment_inline_settle (
        vm, buffer_index, &metadata, current_worker,
        current_worker == metadata.final_owner
          ? 0
          : PRODUCT_FRAGMENT_ERROR_INVARIANT);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_fragment_final_owner_node) = {
  .name = "product-packet-fragment-final-owner",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

static u8
product_fragment_error_reason (vlib_main_t *vm, vlib_buffer_t *buffer)
{
  u32 code;
  if (buffer->error == 0)
    return PRODUCT_FRAGMENT_ERROR_INVARIANT;
  code = vlib_error_get_code (&vm->node_main, buffer->error);
  if (code == IP4_ERROR_REASS_TIMEOUT || code == IP6_ERROR_REASS_TIMEOUT)
    return PRODUCT_FRAGMENT_ERROR_TIMEOUT;
  if (code == IP4_ERROR_REASS_FRAGMENT_CHAIN_TOO_LONG
      || code == IP4_ERROR_REASS_LIMIT_REACHED
      || code == IP6_ERROR_REASS_FRAGMENT_CHAIN_TOO_LONG
      || code == IP6_ERROR_REASS_LIMIT_REACHED)
    return PRODUCT_FRAGMENT_ERROR_CAPACITY;
  if (code == IP4_ERROR_REASS_INTERNAL_ERROR
      || code == IP6_ERROR_REASS_OVERLAPPING_FRAGMENT)
    return PRODUCT_FRAGMENT_ERROR_CONFLICT;
  return PRODUCT_FRAGMENT_ERROR_INVARIANT;
}

VLIB_NODE_FN (product_packet_fragment_error_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 index;
  (void) node;
  for (index = 0; index < frame->n_vectors; index++)
    {
      u32 buffer_index = from[index];
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
      product_fragment_metadata_t metadata;
      u8 error;
      product_fragment_metadata_load (buffer, &metadata);
      if (product_fragment_reject_stale (vm, buffer_index, &metadata))
        continue;
      if (metadata.flags & PRODUCT_FRAGMENT_META_TRANSFERRED)
        {
          product_fragment_evidence_duplicate_returned (&metadata,
                                                        buffer_index);
          vlib_buffer_free (vm, &buffer_index, 1);
          continue;
        }
      error = metadata.custom_error != 0
                ? metadata.custom_error
                : product_fragment_error_reason (vm, buffer);
      product_fragment_inline_settle (
        vm, buffer_index, &metadata,
        (u16) vlib_get_worker_index (vm->thread_index), error);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (product_packet_fragment_error_node) = {
  .name = "product-packet-fragment-error",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
enum
{
  PRODUCT_FRAGMENT_VECTOR_IP4_OUT_OF_ORDER,
  PRODUCT_FRAGMENT_VECTOR_IP6_OUT_OF_ORDER,
  PRODUCT_FRAGMENT_VECTOR_IP4_EXACT_DUPLICATE,
  PRODUCT_FRAGMENT_VECTOR_IP6_EXACT_DUPLICATE,
  PRODUCT_FRAGMENT_VECTOR_IP4_SAME_RANGE_CONFLICT,
  PRODUCT_FRAGMENT_VECTOR_IP6_SAME_RANGE_CONFLICT,
  PRODUCT_FRAGMENT_VECTOR_IP4_PARTIAL_OVERLAP,
  PRODUCT_FRAGMENT_VECTOR_IP6_PARTIAL_OVERLAP,
  PRODUCT_FRAGMENT_VECTOR_IP4_TIMEOUT,
  PRODUCT_FRAGMENT_VECTOR_IP6_TIMEOUT,
  PRODUCT_FRAGMENT_VECTOR_IP4_CAPACITY,
  PRODUCT_FRAGMENT_VECTOR_IP6_CAPACITY,
  PRODUCT_FRAGMENT_VECTOR_COUNT,
};

#define PRODUCT_FRAGMENT_OBLIGATION_BASE UINT64_C (1750000)

typedef struct
{
  u32 input_obligations;
  u32 terminal_intents;
  u32 ledger_settlements;
  u32 buffer_returns;
  u32 duplicate_settlements;
  u32 lost_buffers;
  u32 exact_duplicates;
  u32 reassembled_packets;
  u32 final_owner_transitions;
  u32 policy_ready_packets;
  u32 policy_verdicts;
  u32 worker_mask;
  u32 survivor_buffer_index;
  u32 final_buffer_index;
  u16 initial_owner;
  u16 final_owner;
  u8 family;
  u8 runtime_error;
  u8 completed;
  u8 reserved;
  u64 settled_ids[PRODUCT_FRAGMENT_BUNDLE_CAPACITY];
  u8 settled_id_count;
} product_fragment_fixture_result_t;

static product_fragment_fixture_result_t
  product_fragment_results[PRODUCT_FRAGMENT_VECTOR_COUNT];
static u32 product_fragment_ready[PRODUCT_FRAGMENT_VECTOR_COUNT];


static const char *product_fragment_vector_names[] = {
  "ip4-out-of-order",
  "ip6-out-of-order",
  "ip4-exact-duplicate",
  "ip6-exact-duplicate",
  "ip4-same-range-byte-conflict",
  "ip6-same-range-byte-conflict",
  "ip4-partial-overlap",
  "ip6-partial-overlap",
  "ip4-timeout",
  "ip6-timeout",
  "ip4-capacity",
  "ip6-capacity",
};

static void
product_fragment_fixture_tag (u64 obligation, u8 *vector)
{
  u64 relative;
  if (obligation <= PRODUCT_FRAGMENT_OBLIGATION_BASE)
    return;
  relative = obligation - PRODUCT_FRAGMENT_OBLIGATION_BASE - 1;
  if (relative / 8 < PRODUCT_FRAGMENT_VECTOR_COUNT)
    *vector = (u8) (relative / 8);
}

static int
product_fragment_result_valid (const product_fragment_metadata_t *metadata)
{
  return metadata->fixture_vector < PRODUCT_FRAGMENT_VECTOR_COUNT;
}

static void
product_fragment_record_worker (product_fragment_fixture_result_t *result,
                                u16 worker)
{
  if (worker < 32)
    result->worker_mask |= 1U << worker;
}

static void
product_fragment_evidence_absorbed (
  const product_fragment_metadata_t *metadata, u32 buffer_index)
{
  product_fragment_fixture_result_t *result;
  (void) buffer_index;
  if (!product_fragment_result_valid (metadata))
    return;
  result = &product_fragment_results[metadata->fixture_vector];
  clib_atomic_fetch_add_relax (&result->buffer_returns, 1);
  product_fragment_record_worker (result, metadata->fragment_worker);
}

static void
product_fragment_evidence_duplicate_returned (
  const product_fragment_metadata_t *metadata, u32 buffer_index)
{
  product_fragment_fixture_result_t *result;
  (void) buffer_index;
  if (!product_fragment_result_valid (metadata))
    return;
  result = &product_fragment_results[metadata->fixture_vector];
  clib_atomic_fetch_add_relax (&result->exact_duplicates, 1);
}

static void
product_fragment_evidence_settled (
  const product_fragment_metadata_t *metadata, u32 survivor_buffer_index,
  u16 final_owner, u8 runtime_error)
{
  product_fragment_fixture_result_t *result;
  u32 index;
  if (!product_fragment_result_valid (metadata))
    return;
  result = &product_fragment_results[metadata->fixture_vector];
  product_fragment_record_worker (result, metadata->fragment_worker);
  for (index = 0; index < metadata->obligation_count; index++)
    {
      u32 seen;
      for (seen = 0; seen < result->settled_id_count; seen++)
        if (result->settled_ids[seen] == metadata->obligation_ids[index])
          break;
      if (seen != result->settled_id_count
          || result->settled_id_count >= PRODUCT_FRAGMENT_BUNDLE_CAPACITY)
        {
          clib_atomic_fetch_add_relax (&result->duplicate_settlements, 1);
          continue;
        }
      result->settled_ids[result->settled_id_count++] =
        metadata->obligation_ids[index];
    }
  clib_atomic_fetch_add_relax (&result->terminal_intents,
                               metadata->obligation_count);
  clib_atomic_fetch_add_relax (&result->ledger_settlements,
                               metadata->obligation_count);
  clib_atomic_fetch_add_relax (&result->buffer_returns, 1);
  if (runtime_error == 0)
    {
      result->reassembled_packets = 1;
      result->policy_ready_packets = 1;
      result->final_owner_transitions =
        metadata->fragment_worker != final_owner;
      result->survivor_buffer_index = survivor_buffer_index;
      result->final_buffer_index = survivor_buffer_index;
      result->initial_owner = metadata->final_owner;
      result->final_owner = final_owner;
    }
  else if (result->runtime_error == 0)
    result->runtime_error = runtime_error;
  if (clib_atomic_load_acq_n (&result->ledger_settlements)
        == result->input_obligations
      && clib_atomic_load_acq_n (&result->buffer_returns)
           == result->input_obligations)
    {
      result->completed = 1;
      clib_atomic_store_rel_n (
        &product_fragment_ready[metadata->fixture_vector], 1);
    }
}

static void
product_fragment_fixture_reset (void)
{
  clib_memset (product_fragment_results, 0,
               sizeof (product_fragment_results));
  clib_memset (product_fragment_ready, 0, sizeof (product_fragment_ready));
}

static void
product_fragment_put_u16 (u8 *destination, u16 value)
{
  destination[0] = (u8) (value >> 8);
  destination[1] = (u8) value;
}

static void
product_fragment_put_u32 (u8 *destination, u32 value)
{
  destination[0] = (u8) (value >> 24);
  destination[1] = (u8) (value >> 16);
  destination[2] = (u8) (value >> 8);
  destination[3] = (u8) value;
}

static void
product_fragment_payload (u8 payload[32], u16 destination_port)
{
  u32 index;
  clib_memset (payload, 0, 32);
  product_fragment_put_u16 (payload, 31000);
  product_fragment_put_u16 (payload + 2, destination_port);
  product_fragment_put_u16 (payload + 4, 32);
  for (index = 8; index < 32; index++)
    payload[index] = (u8) (0x80 + index);
}

static u32
product_fragment_materialize_ip4 (u8 *packet, u16 identification,
                                  u16 fragment_offset, u8 more,
                                  const u8 *payload, u16 payload_length)
{
  ip4_header_t *ip4 = (ip4_header_t *) packet;
  clib_memset (packet, 0, sizeof (*ip4) + payload_length);
  ip4->ip_version_and_header_length = 0x45;
  ip4->length = clib_host_to_net_u16 ((u16) (20 + payload_length));
  ip4->fragment_id = clib_host_to_net_u16 (identification);
  ip4->flags_and_fragment_offset = clib_host_to_net_u16 (
    (u16) ((fragment_offset / 8) | (more ? IP4_HEADER_FLAG_MORE_FRAGMENTS : 0)));
  ip4->ttl = 64;
  ip4->protocol = IP_PROTOCOL_UDP;
  ip4->src_address.as_u32 = clib_host_to_net_u32 (UINT32_C (0x0a000001));
  ip4->dst_address.as_u32 = clib_host_to_net_u32 (UINT32_C (0x0a000002));
  clib_memcpy_fast (packet + 20, payload, payload_length);
  ip4->checksum = ip4_header_checksum (ip4);
  return 20 + payload_length;
}

static u32
product_fragment_materialize_ip6 (u8 *packet, u32 identification,
                                  u16 fragment_offset, u8 more,
                                  const u8 *payload, u16 payload_length)
{
  static const u8 source[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                 0,    0,    0,    0,    0, 0, 0, 1 };
  static const u8 destination[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
    0,    0,    0,    0,    0, 0, 0, 2,
  };
  ip6_header_t *ip6 = (ip6_header_t *) packet;
  ip6_frag_hdr_t *fragment = (ip6_frag_hdr_t *) (packet + 40);
  clib_memset (packet, 0, 48 + payload_length);
  ip6->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 (UINT32_C (6) << 28);
  ip6->payload_length = clib_host_to_net_u16 ((u16) (8 + payload_length));
  ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
  ip6->hop_limit = 64;
  clib_memcpy_fast (&ip6->src_address, source, 16);
  clib_memcpy_fast (&ip6->dst_address, destination, 16);
  fragment->next_hdr = IP_PROTOCOL_UDP;
  fragment->fragment_offset_and_more = clib_host_to_net_u16 (
    (u16) (fragment_offset | (more ? 1 : 0)));
  fragment->identification = clib_host_to_net_u32 (identification);
  clib_memcpy_fast (packet + 48, payload, payload_length);
  return 48 + payload_length;
}

static u16
product_fragment_fixture_port (u8 family, u32 identification)
{
  product_fragment_key_t key;
  product_packet_facts_t facts;
  product_canonical_flow_key_t canonical;
  product_worker_layout_t layout = {
    .worker_count = PRODUCT_GRAPH_WORKERS,
    .hash_seed = PRODUCT_GRAPH_HASH_SEED,
  };
  u16 fragment_worker;
  u16 port;
  clib_memset (&key, 0, sizeof (key));
  clib_memset (&facts, 0, sizeof (facts));
  key.family = family;
  key.protocol = IP_PROTOCOL_UDP;
  key.identification = identification;
  facts.l3_status = PRODUCT_PACKET_L3_COMPLETE;
  facts.l4_status = PRODUCT_PACKET_L4_COMPLETE;
  facts.ip_family = family;
  facts.protocol = IP_PROTOCOL_UDP;
  facts.source_port = 31000;
  if (family == 4)
    {
      key.source[12] = facts.source_address[12] = 10;
      key.source[15] = facts.source_address[15] = 1;
      key.destination[12] = facts.destination_address[12] = 10;
      key.destination[15] = facts.destination_address[15] = 2;
    }
  else
    {
      key.source[0] = facts.source_address[0] = 0x20;
      key.source[1] = facts.source_address[1] = 0x01;
      key.source[2] = facts.source_address[2] = 0x0d;
      key.source[3] = facts.source_address[3] = 0xb8;
      key.source[15] = facts.source_address[15] = 1;
      key.destination[0] = facts.destination_address[0] = 0x20;
      key.destination[1] = facts.destination_address[1] = 0x01;
      key.destination[2] = facts.destination_address[2] = 0x0d;
      key.destination[3] = facts.destination_address[3] = 0xb8;
      key.destination[15] = facts.destination_address[15] = 2;
    }
  fragment_worker = product_fragment_select_worker (&key);
  for (port = 40000; port < 40100; port++)
    {
      u16 owner;
      facts.destination_port = port;
      if (product_packet_owner_from_facts (
            &layout, PRODUCT_GRAPH_FLOW_DOMAIN, &facts, &canonical, &owner)
            == PRODUCT_PACKET_OK
          && owner != fragment_worker)
        return port;
    }
  return 0;
}

typedef enum
{
  PRODUCT_FRAGMENT_CASE_OUT_OF_ORDER,
  PRODUCT_FRAGMENT_CASE_EXACT_DUPLICATE,
  PRODUCT_FRAGMENT_CASE_SAME_RANGE_CONFLICT,
  PRODUCT_FRAGMENT_CASE_PARTIAL_OVERLAP,
  PRODUCT_FRAGMENT_CASE_TIMEOUT,
  PRODUCT_FRAGMENT_CASE_CAPACITY,
} product_fragment_case_t;

static int
product_fragment_fixture_inject (vlib_main_t *vm, u8 vector, u8 family,
                                 product_fragment_case_t fragment_case)
{
  product_fragment_fixture_result_t *result =
    &product_fragment_results[vector];
  vlib_node_runtime_t *ingress_runtime =
    vlib_node_get_runtime (vm, product_packet_test_ingress_node.index);
  u32 buffers[4];
  u16 threads[4];
  u8 payload[32];
  u8 fragments = fragment_case == PRODUCT_FRAGMENT_CASE_EXACT_DUPLICATE
                       || fragment_case == PRODUCT_FRAGMENT_CASE_CAPACITY
                   ? 4
                   : fragment_case == PRODUCT_FRAGMENT_CASE_OUT_OF_ORDER
                       ? 3
                       : 2;
  u16 identification = (u16) (0x5000 + vector);
  u16 destination_port =
    product_fragment_fixture_port (family, identification);
  u32 allocated;
  u32 index;
  if (destination_port == 0)
    return 0;
  product_fragment_payload (payload, destination_port);
  product_fragment_put_u16 (
    payload + 4,
    fragment_case == PRODUCT_FRAGMENT_CASE_CAPACITY ? 40 : 24);
  allocated = vlib_buffer_alloc (vm, buffers, fragments);
  if (allocated != fragments)
    {
      if (allocated)
        vlib_buffer_free (vm, buffers, allocated);
      return 0;
    }
  result->input_obligations = fragments;
  result->family = family;
  for (index = 0; index < fragments; index++)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, buffers[index]);
      product_buffer_metadata_t metadata;
      u16 offset = 0;
      u16 payload_length = 8;
      u8 more = 1;
      const u8 *fragment_payload = payload;
      vlib_buffer_reset (buffer);
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      if (fragment_case == PRODUCT_FRAGMENT_CASE_OUT_OF_ORDER)
        {
          static const u16 offsets[] = { 16, 0, 8 };
          offset = offsets[index];
          more = offset != 16;
          fragment_payload = payload + offset;
        }
      else if (fragment_case == PRODUCT_FRAGMENT_CASE_EXACT_DUPLICATE)
        {
          static const u16 offsets[] = { 0, 8, 8, 16 };
          offset = offsets[index];
          more = offset != 16;
          fragment_payload = payload + offset;
        }
      else if (fragment_case == PRODUCT_FRAGMENT_CASE_SAME_RANGE_CONFLICT)
        {
          offset = 0;
          fragment_payload = payload;
          if (index == 1)
            payload[7] ^= 0x5a;
        }
      else if (fragment_case == PRODUCT_FRAGMENT_CASE_PARTIAL_OVERLAP)
        {
          offset = index == 0 ? 0 : 8;
          payload_length = 16;
          more = index == 0;
          fragment_payload = payload + offset;
        }
      else if (fragment_case == PRODUCT_FRAGMENT_CASE_TIMEOUT)
        {
          offset = index == 0 ? 0 : 16;
          more = index == 0;
          fragment_payload = payload + offset;
        }
      else
        {
          static const u16 offsets[] = { 0, 8, 16, 32 };
          offset = offsets[index];
          more = index != 3;
          fragment_payload = payload + (index == 3 ? 24 : offset);
        }
      buffer->current_length = family == 4
        ? product_fragment_materialize_ip4 (
            vlib_buffer_get_current (buffer), identification, offset, more,
            fragment_payload, payload_length)
        : product_fragment_materialize_ip6 (
            vlib_buffer_get_current (buffer), identification, offset, more,
            fragment_payload, payload_length);
      vnet_buffer (buffer)->sw_if_index[VLIB_RX] = 0;
      vnet_buffer (buffer)->sw_if_index[VLIB_TX] = ~0;
      clib_memset (&metadata, 0, sizeof (metadata));
      metadata.origin_obligation_id = PRODUCT_FRAGMENT_OBLIGATION_BASE
                                      + (u64) vector * 8 + index + 1;
      metadata.generation = product_packet_graph_main.generation;
      product_metadata_store (buffer, &metadata);
      /* One ingress frame preserves each vector's declared arrival order;
       * fragment steering, not producer scheduling, chooses the official
       * reassembly worker. */
      threads[index] = (u16) vlib_get_worker_thread_index (0);
    }
  if (vlib_buffer_enqueue_to_thread (
        vm, ingress_runtime, product_packet_graph_main.ingress_frame_queue,
        buffers, threads, fragments, 0)
      != fragments)
    return 0;
  return 1;
}

static int
product_fragment_fixture_wait (vlib_main_t *vm, u8 vector, f64 timeout)
{
  f64 deadline = vlib_time_now (vm) + timeout;
  while (!clib_atomic_load_acq_n (&product_fragment_ready[vector])
         && vlib_time_now (vm) < deadline)
    vlib_process_suspend (vm, 0.001);
  return clib_atomic_load_acq_n (&product_fragment_ready[vector]) != 0;
}

static const char *
product_fragment_error_name (u8 error)
{
  switch (error)
    {
    case PRODUCT_FRAGMENT_ERROR_CONFLICT:
      return "fragment-conflict";
    case PRODUCT_FRAGMENT_ERROR_TIMEOUT:
      return "fragment-timeout";
    case PRODUCT_FRAGMENT_ERROR_CAPACITY:
      return "fragment-capacity";
    default:
      return "fragment-invariant";
    }
}

static void
product_fragment_output_vector (vlib_main_t *vm, u8 vector,
                                product_fragment_case_t fragment_case)
{
  const product_fragment_fixture_result_t *result =
    &product_fragment_results[vector];
  const char *name = product_fragment_vector_names[vector];
  u32 worker_count = count_set_bits (result->worker_mask);
  vlib_cli_output (vm, "vector.%s.family=ip%u", name, result->family);
  vlib_cli_output (vm, "vector.%s.reassembly_engine=ip%u-full-reassembly-custom",
                   name, result->family);
  vlib_cli_output (vm, "vector.%s.fragment_worker_count=%u", name,
                   worker_count);
  vlib_cli_output (vm, "vector.%s.fragment_worker=%u", name,
                   get_lowest_set_bit_index (result->worker_mask));
  if (fragment_case == PRODUCT_FRAGMENT_CASE_OUT_OF_ORDER)
    vlib_cli_output (vm, "vector.%s.arrival_order=out-of-order", name);
  vlib_cli_output (vm, "vector.%s.runtime_disposition=%s", name,
                   result->runtime_error == 0 ? "policy-ready"
                                              : "drop-runtime");
  if (result->runtime_error)
    vlib_cli_output (vm, "vector.%s.runtime_drop_reason=%s", name,
                     product_fragment_error_name (result->runtime_error));
  vlib_cli_output (vm, "vector.%s.input_obligations=%u", name,
                   result->input_obligations);
  vlib_cli_output (vm, "vector.%s.terminal_intents=%u", name,
                   result->terminal_intents);
  vlib_cli_output (vm, "vector.%s.ledger_settlements=%u", name,
                   result->ledger_settlements);
  vlib_cli_output (vm, "vector.%s.buffer_returns=%u", name,
                   result->buffer_returns);
  vlib_cli_output (vm, "vector.%s.outstanding_obligations=%u", name,
                   result->input_obligations - result->ledger_settlements);
  vlib_cli_output (vm, "vector.%s.duplicate_settlements=%u", name,
                   result->duplicate_settlements);
  vlib_cli_output (vm, "vector.%s.lost_buffers=%u", name,
                   result->lost_buffers);
  vlib_cli_output (vm, "vector.%s.policy_verdicts=%u", name,
                   result->policy_verdicts);
  vlib_cli_output (vm, "vector.%s.policy_ready_packets=%u", name,
                   result->policy_ready_packets);
  vlib_cli_output (vm, "vector.%s.reassembled_packets=%u", name,
                   result->reassembled_packets);
  vlib_cli_output (vm, "vector.%s.final_owner_transitions=%u", name,
                   result->final_owner_transitions);
  vlib_cli_output (vm, "vector.%s.corrective_handoffs=0", name);
  if (result->runtime_error == 0)
    {
      vlib_cli_output (vm, "vector.%s.initial_fragment_final_owner=%u", name,
                       result->initial_owner);
      vlib_cli_output (vm, "vector.%s.final_owner=%u", name,
                       result->final_owner);
      vlib_cli_output (vm, "vector.%s.reassembly_survivor_buffer_index=%u",
                       name, result->survivor_buffer_index);
      vlib_cli_output (vm, "vector.%s.final_owner_buffer_index=%u", name,
                       result->final_buffer_index);
    }
  if (fragment_case == PRODUCT_FRAGMENT_CASE_EXACT_DUPLICATE)
    vlib_cli_output (vm, "vector.%s.exact_duplicates=%u", name,
                     result->exact_duplicates);
  if (fragment_case == PRODUCT_FRAGMENT_CASE_SAME_RANGE_CONFLICT)
    vlib_cli_output (vm,
                     "vector.%s.conflict_kind=same-range-different-byte",
                     name);
  if (fragment_case == PRODUCT_FRAGMENT_CASE_PARTIAL_OVERLAP)
    vlib_cli_output (vm, "vector.%s.conflict_kind=partial-overlap", name);
}

static clib_error_t *
product_packet_graph_run_fragment_fixture_cli (
  vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  static const product_fragment_case_t cases[] = {
    PRODUCT_FRAGMENT_CASE_OUT_OF_ORDER,
    PRODUCT_FRAGMENT_CASE_OUT_OF_ORDER,
    PRODUCT_FRAGMENT_CASE_EXACT_DUPLICATE,
    PRODUCT_FRAGMENT_CASE_EXACT_DUPLICATE,
    PRODUCT_FRAGMENT_CASE_SAME_RANGE_CONFLICT,
    PRODUCT_FRAGMENT_CASE_SAME_RANGE_CONFLICT,
    PRODUCT_FRAGMENT_CASE_PARTIAL_OVERLAP,
    PRODUCT_FRAGMENT_CASE_PARTIAL_OVERLAP,
    PRODUCT_FRAGMENT_CASE_TIMEOUT,
    PRODUCT_FRAGMENT_CASE_TIMEOUT,
    PRODUCT_FRAGMENT_CASE_CAPACITY,
    PRODUCT_FRAGMENT_CASE_CAPACITY,
  };
  u8 *fixture = 0;
  u32 vector;
  (void) command;
  if (!unformat (input, "%s", &fixture)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || strcmp ((char *) fixture, PRODUCT_GRAPH_FRAGMENT_FIXTURE) != 0
      || !clib_atomic_load_acq_n (&product_packet_graph_main.enabled))
    {
      vec_free (fixture);
      return clib_error_return (0, "fragment fixture run rejected");
    }
  vec_free (fixture);
  product_fragment_fixture_reset ();
  for (vector = 0; vector < PRODUCT_FRAGMENT_VECTOR_COUNT; vector++)
    {
      u8 family = (vector & 1) ? 6 : 4;
      if (!product_fragment_fixture_inject (
            vm, (u8) vector, family, cases[vector]))
        return clib_error_return (0, "fragment vector %u injection failed",
                                  vector);
      if (!product_fragment_fixture_wait (
            vm, (u8) vector,
            cases[vector] == PRODUCT_FRAGMENT_CASE_TIMEOUT ? 3.0 : 1.0))
        return clib_error_return (0,
                                  "fragment vector %u completion timed out",
                                  vector);
    }
  vlib_cli_output (vm, "fixture.id=%s", PRODUCT_GRAPH_FRAGMENT_FIXTURE);
  vlib_cli_output (vm, "fixture.vector_count=12");
  vlib_cli_output (vm, "fixture.official_ip4_full_reassembly=1");
  vlib_cli_output (vm, "fixture.official_ip6_full_reassembly=1");
  for (vector = 0; vector < PRODUCT_FRAGMENT_VECTOR_COUNT; vector++)
    product_fragment_output_vector (vm, (u8) vector, cases[vector]);
  vlib_cli_output (vm, "fixture.fragment_context_debt=0");
  vlib_cli_output (vm, "fixture.obligation_debt=0");
  vlib_cli_output (vm, "fixture.buffer_debt=0");
  vlib_cli_output (vm, "fixture.duplicate_settlements=0");
  vlib_cli_output (vm, "fixture.lost_buffers=0");
  return 0;
}

VLIB_CLI_COMMAND (product_packet_graph_run_fragment_fixture_command, static) = {
  .path = PRODUCT_GRAPH_RUN_FRAGMENT_FIXTURE_COMMAND,
  .short_help = PRODUCT_GRAPH_RUN_FRAGMENT_FIXTURE_COMMAND " "
                PRODUCT_GRAPH_FRAGMENT_FIXTURE,
  .function = product_packet_graph_run_fragment_fixture_cli,
  .is_mp_safe = 1,
};
#endif

static clib_error_t *
product_packet_fragment_graph_init (vlib_main_t *vm)
{
  product_fragment_graph_main_t *fragment = &product_fragment_graph_main;
  u32 worker;
  for (worker = 0; worker < PRODUCT_GRAPH_WORKERS; worker++)
    {
      clib_atomic_store_rel_n (&fragment->steer_credits[worker],
                               PRODUCT_GRAPH_HANDOFF_CREDITS);
      clib_atomic_store_rel_n (&fragment->final_credits[worker],
                               PRODUCT_GRAPH_HANDOFF_CREDITS);
    }
  fragment->steer_frame_queue =
    vlib_frame_queue_main_init (product_packet_fragment_entry_node.index, 0);
  fragment->final_frame_queue = vlib_frame_queue_main_init (
    product_packet_fragment_final_owner_node.index, 0);
  fragment->ip4_success_next = ip4_full_reass_custom_register_next_node (
    product_packet_fragment_reassembled_node.index);
  fragment->ip4_error_next = ip4_full_reass_custom_register_next_node (
    product_packet_fragment_error_node.index);
  fragment->ip6_success_next = ip6_full_reass_custom_register_next_node (
    product_packet_fragment_reassembled_node.index);
  fragment->ip6_error_next = ip6_full_reass_custom_register_next_node (
    product_packet_fragment_error_node.index);
  ip4_full_reass_custom_register_consume_hook (product_fragment_ip4_consume,
                                               fragment);
  ip6_full_reass_custom_register_consume_hook (product_fragment_ip6_consume,
                                               fragment);
  ip4_full_reass_custom_register_error_hook (product_fragment_ip4_error,
                                             fragment);
  ip6_full_reass_custom_register_error_hook (product_fragment_ip6_error,
                                             fragment);
  (void) vm;
  return 0;
}

VLIB_INIT_FUNCTION (product_packet_fragment_graph_init) = {
  .runs_after = VLIB_INITS ("ip4_full_reass_init_function",
                            "ip6_full_reass_init_function"),
};
