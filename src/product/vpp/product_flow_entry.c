/* SPDX-License-Identifier: Apache-2.0 */

#include "product_flow_entry.h"

#include <string.h>
#include <stdlib.h>

#define NO_SLOT UINT32_MAX
typedef struct {
  product_flow_entry_t entry;
  uint32_t next;
} flow_slot_t;

struct product_flow_runtime {
  product_flow_runtime_snapshot_t stats;
  flow_slot_t *slots;
  uint32_t *buckets;
  uint32_t bucket_count;
  uint32_t free_head;
  uint64_t next_incarnation;
};

static int
assignment_is_eligible (const product_owner_assignment_t *assignment)
{
  return assignment && assignment->valid == 1 && assignment->source_is_a <= 1
         && (assignment->key.ip_family == 4 || assignment->key.ip_family == 6)
         && ((assignment->key.kind == PRODUCT_OWNER_KEY_L4_PORTS
              && (assignment->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_TCP
                  || assignment->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_UDP))
             || (assignment->key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY
                 && ((assignment->key.ip_family == 4 && assignment->key.protocol == 1)
                     || (assignment->key.ip_family == 6 && assignment->key.protocol == 58))));
}

static unsigned
protocol_index (const product_owner_assignment_t *assignment)
{
  return assignment->key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY ? 2
    : assignment->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_TCP ? 0 : 1;
}

static int
key_equal (const product_canonical_owner_key_t *a,
           const product_canonical_owner_key_t *b)
{
  if (a->kind != b->kind || a->ip_family != b->ip_family
      || a->protocol != b->protocol
      || memcmp (a->address_a, b->address_a, 16)
      || memcmp (a->address_b, b->address_b, 16))
    return 0;
  if (a->kind == PRODUCT_OWNER_KEY_L4_PORTS)
    return a->transport.ports.a == b->transport.ports.a
      && a->transport.ports.b == b->transport.ports.b;
  return a->query_class == b->query_class
    && a->transport.query.identifier == b->transport.query.identifier;
}

static uint32_t
bucket_for (const product_flow_runtime_t *pool, uint64_t hash)
{
  /* Fold the supplied hash for the index only; never select an owner here. */
  return (uint32_t) (hash ^ (hash >> 32) ^ (hash >> 16))
    & (pool->bucket_count - 1);
}

static uint32_t
find_entry (product_flow_runtime_t *pool,
            const product_owner_assignment_t *assignment)
{
  for (uint32_t index = pool->buckets[bucket_for (pool, assignment->canonical_hash)];
       index != NO_SLOT; index = pool->slots[index].next)
    {
      const product_flow_entry_t *entry = &pool->slots[index].entry;
      if (entry->in_use && entry->canonical_hash == assignment->canonical_hash
          && key_equal (&entry->key, &assignment->key))
        return index;
    }
  return NO_SLOT;
}

static void
reset_storage (product_flow_runtime_t *pool)
{
  memset (pool->slots, 0, sizeof (*pool->slots) * pool->stats.capacity);
  for (uint32_t i = 0; i < pool->stats.capacity; i++)
    pool->slots[i].next = i + 1 < pool->stats.capacity ? i + 1 : NO_SLOT;
  for (uint32_t i = 0; i < pool->bucket_count; i++)
    pool->buckets[i] = NO_SLOT;
  pool->free_head = 0;
}

product_flow_entry_status_t
product_flow_runtime_create (product_flow_runtime_t **runtime,
                             uint16_t worker_index, uint16_t worker_count,
                             uint64_t generation, uint32_t capacity)
{
  if (!runtime || *runtime || !generation || !capacity
      || !worker_count || worker_index >= worker_count
      || capacity > UINT32_MAX / 4)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  uint32_t buckets = 1;
  while (buckets < capacity * 2)
    buckets <<= 1;
  if ((uint64_t) capacity * sizeof (flow_slot_t) > SIZE_MAX
      || (uint64_t) buckets * sizeof (uint32_t) > SIZE_MAX)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  product_flow_runtime_t *pool = calloc (1, sizeof (*pool));
  if (!pool)
    return PRODUCT_FLOW_ENTRY_STATUS_ALLOCATION_FAILED;
  pool->slots = calloc (capacity, sizeof (*pool->slots));
  pool->buckets = calloc (buckets, sizeof (*pool->buckets));
  if (!pool->slots || !pool->buckets)
    {
      product_flow_runtime_destroy (pool);
      return PRODUCT_FLOW_ENTRY_STATUS_ALLOCATION_FAILED;
    }
  pool->stats.worker_index = worker_index;
  pool->stats.worker_count = worker_count;
  pool->stats.generation = generation;
  pool->stats.capacity = capacity;
  pool->stats.allocated_bytes = sizeof (*pool)
    + (uint64_t) capacity * sizeof (*pool->slots)
    + (uint64_t) buckets * sizeof (*pool->buckets);
  pool->bucket_count = buckets;
  reset_storage (pool);
  *runtime = pool;
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
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_flow_entry_packet_t *packet, uint8_t stage_verdict,
  product_flow_entry_observation_t *observation)
{
  product_flow_entry_t *entry;

  if (observation != NULL)
    memset (observation, 0, sizeof (*observation));
  if (pool == NULL || observation == NULL || pool->stats.worker_count == 0U
      || packet == NULL)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  observation->owner_worker = pool->stats.worker_index;
  observation->slot = NO_SLOT;
  if (!assignment_is_eligible (assignment)
      || (packet->device_direction != PRODUCT_PACKET_DIRECTION_UNKNOWN
          && packet->device_direction != PRODUCT_FLOW_ENTRY_DIRECTION_INPUT
          && packet->device_direction != PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET;
  if (stage_verdict == PRODUCT_FLOW_ENTRY_VERDICT_DROP)
    {
      pool->stats.early_drop_count++;
      return PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP;
    }
  if (stage_verdict != PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (!policy_identity_valid (&packet->policy))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_REVISION;

  if (assignment->execution_owner != pool->stats.worker_index)
    {
      pool->stats.wrong_owner_count++;
      return PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER;
    }

  if (packet->policy.generation != pool->stats.generation)
    {
      pool->stats.revision_mismatch_count++;
      return PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION;
    }
  unsigned protocol = protocol_index (assignment);
  uint32_t slot = find_entry (pool, assignment);
  if (slot == NO_SLOT)
    {
      slot = pool->free_head;
      if (slot == NO_SLOT)
        {
          pool->stats.capacity_rejection_count++;
          pool->stats.protocol[protocol].capacity_misses++;
          return PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED;
        }
      pool->free_head = pool->slots[slot].next;
      uint32_t bucket = bucket_for (pool, assignment->canonical_hash);
      pool->slots[slot].next = pool->buckets[bucket];
      pool->buckets[bucket] = slot;
      entry = &pool->slots[slot].entry;
      memset (entry, 0, sizeof (*entry));
      entry->in_use = 1U;
      entry->incarnation = ++pool->next_incarnation;
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
      pool->stats.active_entries++;
      if (pool->stats.active_entries > pool->stats.high_watermark)
        pool->stats.high_watermark = pool->stats.active_entries;
      pool->stats.allocation_count++;
      pool->stats.protocol[protocol].active++;
      pool->stats.protocol[protocol].creates++;
      observation->created = 1U;
    }
  else
    {
      entry = &pool->slots[slot].entry;
      pool->stats.reuse_count++;
      pool->stats.protocol[protocol].hits++;
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
          pool->stats.revision_invalidation_count++;
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
  observation->slot = slot;
  observation->flow_direction = entry->last_flow_direction;
  unsigned side = entry->last_flow_direction == PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY;
  entry->side_packets[side]++;
  entry->side_bytes[side] += packet->packet_bytes;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t
product_flow_entry_set_decision (product_flow_runtime_t *pool,
                                 const product_flow_entry_t *borrowed,
                                 const product_flow_policy_identity_t *policy,
                                 uint8_t decision, uint64_t winner_rule_id,
                                 uint32_t reason_id)
{
  if (pool == NULL || borrowed == NULL || pool->stats.worker_count == 0U)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  uintptr_t address = (uintptr_t) borrowed, begin = (uintptr_t) pool->slots;
  if (address < begin || address - begin >= sizeof (*pool->slots) * pool->stats.capacity
      || (address - begin) % sizeof (*pool->slots) != 0 || !borrowed->in_use)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  product_flow_entry_t *entry = &pool->slots[(address - begin) / sizeof (*pool->slots)].entry;
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
product_flow_runtime_flush (product_flow_runtime_t *pool)
{
  if (pool == NULL)
    return;
  reset_storage (pool);
  pool->stats.active_entries = 0U;
  for (unsigned i = 0; i < 3; i++)
    pool->stats.protocol[i].active = 0;
  pool->stats.flush_count++;
}

void
product_flow_runtime_destroy (product_flow_runtime_t *pool)
{
  if (!pool)
    return;
  free (pool->slots);
  free (pool->buckets);
  free (pool);
}

product_flow_runtime_snapshot_t
product_flow_runtime_snapshot (const product_flow_runtime_t *pool)
{
  return pool ? pool->stats : (product_flow_runtime_snapshot_t) { 0 };
}

const product_flow_entry_t *
product_flow_runtime_entry (const product_flow_runtime_t *pool, uint32_t slot)
{
  return pool && slot < pool->stats.capacity && pool->slots[slot].entry.in_use
    ? &pool->slots[slot].entry : NULL;
}

uint32_t
product_flow_entry_pool_active_count (const product_flow_runtime_t *pool)
{
  return pool == NULL ? 0U : pool->stats.active_entries;
}
