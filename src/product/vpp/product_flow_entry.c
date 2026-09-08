/* SPDX-License-Identifier: Apache-2.0 */

#include "product_flow_entry.h"

#include <string.h>

static int
assignment_is_eligible (const product_owner_assignment_t *assignment)
{
  return assignment && assignment->valid == 1 && assignment->source_is_a <= 1
         && assignment->key.kind == PRODUCT_OWNER_KEY_L4_PORTS
         && (assignment->key.ip_family == 4 || assignment->key.ip_family == 6)
         && (assignment->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_TCP
             || assignment->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_UDP);
}

static product_flow_entry_t *
find_entry (product_flow_entry_pool_t *pool,
            const product_owner_assignment_t *assignment)
{
  for (uint32_t index = 0; index < PRODUCT_FLOW_ENTRY_MAX_ENTRIES; index++)
    {
      product_flow_entry_t *entry = &pool->entries[index];
      if (entry->in_use && entry->canonical_hash == assignment->canonical_hash
          && memcmp (&entry->key, &assignment->key, sizeof (entry->key)) == 0)
        return entry;
    }
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

product_flow_entry_status_t
product_flow_entry_pool_init (product_flow_entry_pool_t *pool,
                              uint16_t worker_index, uint16_t worker_count)
{
  if (pool == NULL)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  memset (pool, 0, sizeof (*pool));
  if (worker_count == 0U || worker_index >= worker_count)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  pool->worker_index = worker_index;
  pool->worker_count = worker_count;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

static int
policy_identity_valid (const product_flow_policy_identity_t *policy)
{
  return policy && policy->generation != 0
         && ((policy->revision == 0) == (policy->snapshot_hash == 0));
}

static int
policy_identity_matches (const product_flow_entry_t *entry,
                          const product_flow_policy_identity_t *policy)
{
  return entry->policy_generation == policy->generation
         && entry->policy_revision == policy->revision
         && entry->policy_snapshot_hash == policy->snapshot_hash;
}

product_flow_entry_status_t
product_flow_entry_observe (
  product_flow_entry_pool_t *pool, const product_owner_assignment_t *assignment,
  const product_flow_entry_packet_t *packet, uint8_t stage_verdict,
  product_flow_entry_observation_t *observation)
{
  product_flow_entry_t *entry;

  if (observation != NULL)
    memset (observation, 0, sizeof (*observation));
  if (pool == NULL || observation == NULL || pool->worker_count == 0U
      || packet == NULL)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  observation->owner_worker = pool->worker_index;
  if (!assignment_is_eligible (assignment)
      || (packet->device_direction != PRODUCT_PACKET_DIRECTION_UNKNOWN
          && packet->device_direction != PRODUCT_FLOW_ENTRY_DIRECTION_INPUT
          && packet->device_direction != PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET;
  if (stage_verdict == PRODUCT_FLOW_ENTRY_VERDICT_DROP)
    {
      pool->early_drop_count++;
      return PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP;
    }
  if (stage_verdict != PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (!policy_identity_valid (&packet->policy))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_REVISION;

  observation->owner_worker = pool->worker_index;
  if (assignment->execution_owner != pool->worker_index)
    {
      pool->wrong_owner_count++;
      return PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER;
    }

  entry = find_entry (pool, assignment);
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
      entry->key = assignment->key;
      entry->canonical_hash = assignment->canonical_hash;
      entry->origin_is_endpoint_a = assignment->source_is_a;
      entry->uid = packet->uid;
      entry->network_context = packet->network_context;
      entry->flow_origin_device_direction = packet->device_direction;
      entry->last_device_direction = packet->device_direction;
      entry->last_flow_direction = PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG;
      entry->first_seen = packet->timestamp;
      entry->policy_generation = packet->policy.generation;
      entry->policy_revision = packet->policy.revision;
      entry->policy_snapshot_hash = packet->policy.snapshot_hash;
      pool->active_entries++;
      pool->allocation_count++;
      observation->created = 1U;
    }
  else
    {
      pool->reuse_count++;
      observation->reused = 1U;
      if (!policy_identity_matches (entry, &packet->policy))
        {
          /* Preserve identity/facts/counters; invalidate only policy cache. */
          entry->decision = PRODUCT_FLOW_ENTRY_DECISION_NONE;
          entry->winner_rule_id = 0U;
          entry->reason_id = 0U;
          entry->policy_generation = packet->policy.generation;
          entry->policy_revision = packet->policy.revision;
          entry->policy_snapshot_hash = packet->policy.snapshot_hash;
          observation->revision_invalidated = 1U;
          pool->revision_invalidation_count++;
        }
    }
  entry->last_seen = packet->timestamp;
  entry->packets++;
  entry->bytes += packet->packet_bytes;
  entry->last_device_direction = packet->device_direction;
  /* Equal endpoints have one projection and remain ORIG; no device direction,
   * port magnitude or TCP flag is used to infer a client/server role. */
  entry->last_flow_direction = assignment->source_is_a == entry->origin_is_endpoint_a
    ? PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG : PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY;
  observation->entry = entry;
  observation->flow_direction = entry->last_flow_direction;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t
product_flow_entry_set_decision (product_flow_entry_pool_t *pool,
                                 product_flow_entry_t *entry,
                                 const product_flow_policy_identity_t *policy,
                                 uint8_t decision, uint64_t winner_rule_id,
                                 uint32_t reason_id)
{
  if (pool == NULL || entry == NULL || pool->worker_count == 0U)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  uintptr_t address = (uintptr_t) entry, begin = (uintptr_t) pool->entries;
  if (address < begin || address - begin >= sizeof (pool->entries)
      || (address - begin) % sizeof (*entry) != 0 || !entry->in_use)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (!policy_identity_valid (policy) || policy->revision == 0)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_REVISION;
  if (!policy_identity_matches (entry, policy))
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
