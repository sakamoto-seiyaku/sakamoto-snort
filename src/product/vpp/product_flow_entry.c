/* SPDX-License-Identifier: Apache-2.0 */

#include "product_flow_entry.h"

#include <string.h>

static int
supported_family (uint8_t family)
{
  return family == PRODUCT_FLOW_ENTRY_FAMILY_IPV4
         || family == PRODUCT_FLOW_ENTRY_FAMILY_IPV6;
}

static int
supported_protocol (uint8_t protocol)
{
  return protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_TCP
         || protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_UDP;
}

static int
supported_direction (uint8_t direction)
{
  return direction == PRODUCT_FLOW_ENTRY_DIRECTION_INPUT
         || direction == PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT;
}

static int
packet_is_valid (const product_flow_entry_packet_t *packet)
{
  size_t index;

  if (packet == NULL || !supported_family (packet->family)
      || !supported_protocol (packet->protocol)
      || !supported_direction (packet->device_direction))
    return 0;

  if (packet->family == PRODUCT_FLOW_ENTRY_FAMILY_IPV4)
    for (index = 4U; index < PRODUCT_FLOW_ENTRY_ADDRESS_BYTES; ++index)
      if (packet->source_address[index] != 0U
          || packet->destination_address[index] != 0U)
        return 0;
  return 1;
}

static int
endpoint_compare (const uint8_t *left_address, uint16_t left_port,
                  const uint8_t *right_address, uint16_t right_port)
{
  int address_order = memcmp (left_address, right_address,
                              PRODUCT_FLOW_ENTRY_ADDRESS_BYTES);
  if (address_order != 0)
    return address_order < 0 ? -1 : 1;
  if (left_port < right_port)
    return -1;
  if (left_port > right_port)
    return 1;
  return 0;
}

static int
canonical_key_matches (const product_flow_entry_t *entry,
                       const product_flow_entry_packet_t *packet)
{
  int source_is_a;

  if (entry->family != packet->family || entry->protocol != packet->protocol)
    return 0;
  source_is_a = endpoint_compare (
    packet->source_address, packet->source_port,
    entry->endpoint_a_address, entry->endpoint_a_port) == 0;
  if (source_is_a
      && endpoint_compare (packet->destination_address, packet->destination_port,
                           entry->endpoint_b_address,
                           entry->endpoint_b_port) == 0)
    return 1;
  return endpoint_compare (packet->source_address, packet->source_port,
                           entry->endpoint_b_address,
                           entry->endpoint_b_port) == 0
         && endpoint_compare (packet->destination_address,
                              packet->destination_port,
                              entry->endpoint_a_address,
                              entry->endpoint_a_port) == 0;
}

static uint64_t
hash_bytes (uint64_t hash, const uint8_t *bytes, size_t length)
{
  size_t index;
  for (index = 0U; index < length; ++index)
    {
      hash ^= bytes[index];
      hash *= UINT64_C (1099511628211);
    }
  return hash;
}

static uint64_t
canonical_hash (uint64_t seed, const product_flow_entry_packet_t *packet)
{
  const uint8_t *first_address = packet->source_address;
  const uint8_t *second_address = packet->destination_address;
  uint16_t first_port = packet->source_port;
  uint16_t second_port = packet->destination_port;
  uint8_t family = packet->family;
  uint8_t protocol = packet->protocol;
  uint8_t port_bytes[4];
  int order = endpoint_compare (first_address, first_port,
                                second_address, second_port);
  uint64_t hash = UINT64_C (1469598103934665603) ^ seed;

  if (order > 0)
    {
      const uint8_t *address_swap = first_address;
      uint16_t port_swap = first_port;
      first_address = second_address;
      first_port = second_port;
      second_address = address_swap;
      second_port = port_swap;
    }
  hash = hash_bytes (hash, &family, sizeof (family));
  hash = hash_bytes (hash, &protocol, sizeof (protocol));
  hash = hash_bytes (hash, first_address, PRODUCT_FLOW_ENTRY_ADDRESS_BYTES);
  port_bytes[0] = (uint8_t) (first_port >> 8U);
  port_bytes[1] = (uint8_t) first_port;
  hash = hash_bytes (hash, port_bytes, 2U);
  hash = hash_bytes (hash, second_address, PRODUCT_FLOW_ENTRY_ADDRESS_BYTES);
  port_bytes[2] = (uint8_t) (second_port >> 8U);
  port_bytes[3] = (uint8_t) second_port;
  return hash_bytes (hash, &port_bytes[2], 2U);
}

static uint8_t
flow_direction_for_packet (const product_flow_entry_t *entry,
                           const product_flow_entry_packet_t *packet)
{
  int source_is_a = endpoint_compare (
    packet->source_address, packet->source_port,
    entry->endpoint_a_address, entry->endpoint_a_port) == 0;
  return (source_is_a == (entry->origin_is_endpoint_a != 0U))
           ? PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG
           : PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY;
}

static product_flow_entry_t *
find_entry (product_flow_entry_pool_t *pool,
            const product_flow_entry_packet_t *packet)
{
  uint32_t index;
  for (index = 0U; index < PRODUCT_FLOW_ENTRY_MAX_ENTRIES; ++index)
    if (pool->entries[index].in_use
        && canonical_key_matches (&pool->entries[index], packet))
      return &pool->entries[index];
  return NULL;
}

static product_flow_entry_t *
free_entry (product_flow_entry_pool_t *pool)
{
  uint32_t index;
  for (index = 0U; index < PRODUCT_FLOW_ENTRY_MAX_ENTRIES; ++index)
    if (!pool->entries[index].in_use)
      return &pool->entries[index];
  return NULL;
}

static void
copy_canonical_key (product_flow_entry_t *entry,
                    const product_flow_entry_packet_t *packet)
{
  int order = endpoint_compare (packet->source_address, packet->source_port,
                                packet->destination_address,
                                packet->destination_port);
  if (order <= 0)
    {
      memcpy (entry->endpoint_a_address, packet->source_address,
              PRODUCT_FLOW_ENTRY_ADDRESS_BYTES);
      memcpy (entry->endpoint_b_address, packet->destination_address,
              PRODUCT_FLOW_ENTRY_ADDRESS_BYTES);
      entry->endpoint_a_port = packet->source_port;
      entry->endpoint_b_port = packet->destination_port;
      entry->origin_is_endpoint_a = 1U;
    }
  else
    {
      memcpy (entry->endpoint_a_address, packet->destination_address,
              PRODUCT_FLOW_ENTRY_ADDRESS_BYTES);
      memcpy (entry->endpoint_b_address, packet->source_address,
              PRODUCT_FLOW_ENTRY_ADDRESS_BYTES);
      entry->endpoint_a_port = packet->destination_port;
      entry->endpoint_b_port = packet->source_port;
      entry->origin_is_endpoint_a = 0U;
    }
}

product_flow_entry_status_t
product_flow_entry_pool_init (product_flow_entry_pool_t *pool,
                              uint16_t worker_index, uint16_t worker_count,
                              uint64_t hash_seed)
{
  if (pool == NULL)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  memset (pool, 0, sizeof (*pool));
  if (worker_count == 0U || worker_index >= worker_count)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  pool->worker_index = worker_index;
  pool->worker_count = worker_count;
  pool->hash_seed = hash_seed;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t
product_flow_entry_publish_revision (product_flow_entry_pool_t *pool,
                                     uint64_t policy_revision)
{
  if (pool == NULL || pool->worker_count == 0U)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (policy_revision == 0U)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_REVISION;
  if (policy_revision <= pool->active_policy_revision)
    return PRODUCT_FLOW_ENTRY_STATUS_REVISION_NOT_ADVANCING;
  /* Deliberately no entry-table loop: invalidation is lazy on next packet. */
  pool->active_policy_revision = policy_revision;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t
product_flow_entry_owner_for_packet (uint16_t worker_count, uint64_t hash_seed,
                                     const product_flow_entry_packet_t *packet,
                                     uint16_t *owner_worker)
{
  if (owner_worker == NULL || worker_count == 0U)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (!packet_is_valid (packet))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET;
  *owner_worker = (uint16_t) (canonical_hash (hash_seed, packet)
                              % worker_count);
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

static product_flow_entry_status_t
product_flow_entry_observe_owned (
  product_flow_entry_pool_t *pool, const product_flow_entry_packet_t *packet,
  uint8_t stage_verdict, uint16_t owner_worker,
  product_flow_entry_observation_t *observation)
{
  product_flow_entry_t *entry;

  if (pool == NULL || observation == NULL || pool->worker_count == 0U
      || pool->active_policy_revision == 0U
      || owner_worker >= pool->worker_count)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  memset (observation, 0, sizeof (*observation));
  if (!packet_is_valid (packet))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET;
  if (stage_verdict == PRODUCT_FLOW_ENTRY_VERDICT_DROP)
    {
      pool->early_drop_count++;
      return PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP;
    }
  if (stage_verdict != PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;

  observation->owner_worker = owner_worker;
  if (owner_worker != pool->worker_index)
    {
      pool->wrong_owner_count++;
      return PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER;
    }

  entry = find_entry (pool, packet);
  if (entry == NULL)
    {
      entry = free_entry (pool);
      if (entry == NULL)
        {
          pool->capacity_rejection_count++;
          return PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED;
        }
      memset (entry, 0, sizeof (*entry));
      entry->in_use = 1U;
      entry->family = packet->family;
      entry->protocol = packet->protocol;
      entry->uid = packet->uid;
      entry->network_context = packet->network_context;
      entry->flow_origin_device_direction = packet->device_direction;
      entry->last_device_direction = packet->device_direction;
      entry->last_flow_direction = PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG;
      entry->first_seen = packet->timestamp;
      copy_canonical_key (entry, packet);
      entry->policy_revision = pool->active_policy_revision;
      pool->active_entries++;
      pool->allocation_count++;
      observation->created = 1U;
    }
  else
    {
      pool->reuse_count++;
      observation->reused = 1U;
      if (entry->policy_revision != pool->active_policy_revision)
        {
          /* Preserve identity/facts/counters; invalidate only policy cache. */
          entry->decision = PRODUCT_FLOW_ENTRY_DECISION_NONE;
          entry->winner_rule_id = 0U;
          entry->reason_id = 0U;
          entry->policy_revision = pool->active_policy_revision;
          observation->revision_invalidated = 1U;
          pool->revision_invalidation_count++;
        }
    }
  entry->last_seen = packet->timestamp;
  entry->packets++;
  entry->bytes += packet->packet_bytes;
  entry->last_device_direction = packet->device_direction;
  entry->last_flow_direction = flow_direction_for_packet (entry, packet);
  observation->entry = entry;
  observation->flow_direction = entry->last_flow_direction;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t
product_flow_entry_observe (product_flow_entry_pool_t *pool,
                            const product_flow_entry_packet_t *packet,
                            uint8_t stage_verdict,
                            product_flow_entry_observation_t *observation)
{
  product_flow_entry_status_t status;
  uint16_t owner_worker;

  if (pool == NULL || observation == NULL || pool->worker_count == 0U)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  status = product_flow_entry_owner_for_packet (
    pool->worker_count, pool->hash_seed, packet, &owner_worker);
  if (status != PRODUCT_FLOW_ENTRY_STATUS_OK)
    return status;
  return product_flow_entry_observe_owned (pool, packet, stage_verdict,
                                           owner_worker, observation);
}

product_flow_entry_status_t
product_flow_entry_observe_on_owner (
  product_flow_entry_pool_t *pool, const product_flow_entry_packet_t *packet,
  uint8_t stage_verdict, uint16_t owner_worker,
  product_flow_entry_observation_t *observation)
{
  return product_flow_entry_observe_owned (pool, packet, stage_verdict,
                                           owner_worker, observation);
}

product_flow_entry_status_t
product_flow_entry_set_decision (product_flow_entry_pool_t *pool,
                                 product_flow_entry_t *entry,
                                 uint8_t decision, uint64_t winner_rule_id,
                                 uint32_t reason_id)
{
  if (pool == NULL || entry == NULL || pool->worker_count == 0U
      || !entry->in_use)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (entry->policy_revision != pool->active_policy_revision)
    return PRODUCT_FLOW_ENTRY_STATUS_STALE_REVISION;
  if (decision > PRODUCT_FLOW_ENTRY_DECISION_DROP)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_DECISION;
  if (decision == PRODUCT_FLOW_ENTRY_DECISION_NONE
      && (winner_rule_id != 0U || reason_id != 0U))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_DECISION;
  entry->decision = decision;
  entry->winner_rule_id = winner_rule_id;
  entry->reason_id = reason_id;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

void
product_flow_entry_pool_flush (product_flow_entry_pool_t *pool)
{
  if (pool == NULL)
    return;
  memset (pool->entries, 0, sizeof (pool->entries));
  pool->active_entries = 0U;
  pool->flush_count++;
}

uint32_t
product_flow_entry_pool_active_count (const product_flow_entry_pool_t *pool)
{
  return pool == NULL ? 0U : pool->active_entries;
}
