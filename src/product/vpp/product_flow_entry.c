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
  uint32_t *heap;
  uint32_t bucket_count;
  uint32_t free_head;
  uint64_t next_incarnation;
  product_flow_end_callback_t end_callback;
  void *end_context;
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
                 && assignment->key.query_class == PRODUCT_ICMP_QUERY_ECHO
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
      if (entry->linked && entry->canonical_hash == assignment->canonical_hash
          && key_equal (&entry->key, &assignment->key))
        return index;
    }
  return NO_SLOT;
}

static unsigned
entry_protocol (const product_flow_entry_t *entry)
{
  return entry->key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY ? 2
    : entry->key.protocol == PRODUCT_FLOW_ENTRY_PROTOCOL_TCP ? 0 : 1;
}

static int
timer_before (const product_flow_runtime_t *pool, uint32_t a, uint32_t b)
{
  uint64_t first = pool->slots[a].entry.deadline_us;
  uint64_t second = pool->slots[b].entry.deadline_us;
  return first < second || (first == second && a < b);
}

static void
timer_swap (product_flow_runtime_t *pool, uint32_t a, uint32_t b)
{
  uint32_t slot = pool->heap[a];
  pool->heap[a] = pool->heap[b];
  pool->heap[b] = slot;
  pool->slots[pool->heap[a]].entry.heap_position = a;
  pool->slots[slot].entry.heap_position = b;
}

static void
timer_reorder (product_flow_runtime_t *pool, uint32_t position)
{
  if (position && timer_before (pool, pool->heap[position],
                               pool->heap[(position - 1) / 2]))
    {
      do {
        uint32_t parent = (position - 1) / 2;
        if (!timer_before (pool, pool->heap[position], pool->heap[parent]))
          break;
        timer_swap (pool, position, parent);
        position = parent;
      } while (position);
      return;
    }
  while (position < pool->stats.timer_entries / 2)
    {
      uint32_t child = position * 2 + 1;
      if (child + 1 < pool->stats.timer_entries &&
          timer_before (pool, pool->heap[child + 1], pool->heap[child]))
        child++;
      if (!timer_before (pool, pool->heap[child], pool->heap[position]))
        break;
      timer_swap (pool, position, child);
      position = child;
    }
  /* For odd counts the last internal node has two children; for even counts
   * it has one. The condition above includes that single-child node. */
}

static void
timer_remove (product_flow_runtime_t *pool, product_flow_entry_t *entry)
{
  if (!entry->deadline_us || entry->heap_position == NO_SLOT)
    return;
  uint32_t position = entry->heap_position;
  uint32_t last = --pool->stats.timer_entries;
  entry->heap_position = NO_SLOT;
  if (position != last)
    {
      pool->heap[position] = pool->heap[last];
      pool->slots[pool->heap[position]].entry.heap_position = position;
      timer_reorder (pool, position);
    }
}

static void
release_slot (product_flow_runtime_t *pool, uint32_t slot)
{
  flow_slot_t *old = &pool->slots[slot];
  unsigned protocol = entry_protocol (&old->entry);
  timer_remove (pool, &old->entry);
  /* Common cleanup for native END free and drained administrative cleanup.
   * Current entries own only inline state: there are no attachment objects or
   * retained packets to free. Future actual attachments belong at this seam. */
  if (old->entry.linked)
    --pool->stats.linked_entries;
  else
    --pool->stats.ending_entries;
  memset (&old->entry, 0, sizeof (old->entry));
  old->next = pool->free_head;
  pool->free_head = slot;
  --pool->stats.active_entries;
  --pool->stats.protocol[protocol].active;
  ++pool->stats.release_count;
}

product_flow_entry_status_t
product_flow_runtime_set_end_callback (
  product_flow_runtime_t *pool, product_flow_end_callback_t callback,
  void *context)
{
  if (!pool || !callback)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (pool->stats.active_entries || pool->end_callback)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  pool->end_callback = callback;
  pool->end_context = context;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

static product_flow_entry_status_t
validate_end_identity (const product_flow_runtime_t *pool, uint32_t slot,
                       uint64_t generation, uint64_t incarnation,
                       product_flow_end_reason_t reason)
{
  if (!pool || reason <= PRODUCT_FLOW_END_NONE || reason > PRODUCT_FLOW_END_REPLACED)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (pool->stats.generation != generation)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION;
  if (slot >= pool->stats.capacity || !pool->slots[slot].entry.in_use
      || pool->slots[slot].entry.incarnation != incarnation)
    return PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t
product_flow_runtime_close (product_flow_runtime_t *pool, uint32_t slot,
                            uint64_t generation, uint64_t incarnation,
                            product_flow_end_reason_t reason)
{
  product_flow_entry_status_t status = validate_end_identity (
    pool, slot, generation, incarnation, reason);
  if (status != PRODUCT_FLOW_ENTRY_STATUS_OK)
    return status;
  flow_slot_t *old = &pool->slots[slot];
  if (!old->entry.linked || !pool->end_callback)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  uint32_t *link = &pool->buckets[bucket_for (pool, old->entry.canonical_hash)];
  while (*link != slot)
    {
      if (*link == NO_SLOT)
        return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
      link = &pool->slots[*link].next;
    }
  *link = old->next;
  old->next = NO_SLOT;
  old->entry.linked = 0;
  old->entry.end_reason = reason;
  if (!old->entry.lpi.stop_reason)
    old->entry.lpi.stop_reason = PRODUCT_LPI_STOP_FLOW_END;
  --pool->stats.linked_entries;
  ++pool->stats.ending_entries;
  ++pool->stats.protocol[entry_protocol (&old->entry)].closed;
  timer_remove (pool, &old->entry);
  pool->end_callback (pool->end_context, &old->entry, slot, reason);
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t
product_flow_runtime_set_deadline (
  product_flow_runtime_t *pool, uint32_t slot, uint64_t generation,
  uint64_t incarnation, uint64_t deadline_us, product_ct_timeout_t timeout_class)
{
  product_flow_entry_status_t status = validate_end_identity (
    pool, slot, generation, incarnation, PRODUCT_FLOW_END_EXPIRED);
  if (status != PRODUCT_FLOW_ENTRY_STATUS_OK)
    return status;
  if (!deadline_us || timeout_class <= PRODUCT_CT_TIMEOUT_NONE ||
      timeout_class > PRODUCT_CT_TIMEOUT_ICMP_REPLY)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  product_flow_entry_t *entry = &pool->slots[slot].entry;
  if (!entry->linked)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  if (!entry->deadline_us)
    {
      entry->heap_position = pool->stats.timer_entries++;
      pool->heap[entry->heap_position] = slot;
    }
  entry->deadline_us = deadline_us;
  entry->timeout_class = (uint8_t) timeout_class;
  timer_reorder (pool, entry->heap_position);
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

uint64_t
product_flow_runtime_next_deadline (const product_flow_runtime_t *pool)
{
  return pool && pool->stats.timer_entries
    ? pool->slots[pool->heap[0]].entry.deadline_us : UINT64_MAX;
}

product_flow_entry_status_t
product_flow_runtime_run_due (product_flow_runtime_t *pool, uint64_t now_us,
                              uint32_t budget, uint32_t *closed)
{
  if (!pool || !closed || !budget)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  *closed = 0;
  while (*closed < budget && pool->stats.timer_entries &&
         product_flow_runtime_next_deadline (pool) <= now_us)
    {
      uint32_t slot = pool->heap[0];
      product_flow_entry_status_t status = product_flow_runtime_close (
        pool, slot, pool->stats.generation, pool->slots[slot].entry.incarnation,
        PRODUCT_FLOW_END_EXPIRED);
      if (status != PRODUCT_FLOW_ENTRY_STATUS_OK)
        return status;
      ++*closed;
    }
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

product_flow_entry_status_t
product_flow_runtime_release_end (product_flow_runtime_t *pool, uint32_t slot,
                                  uint64_t generation, uint64_t incarnation,
                                  product_flow_end_reason_t reason)
{
  product_flow_entry_status_t status = validate_end_identity (
    pool, slot, generation, incarnation, reason);
  if (status != PRODUCT_FLOW_ENTRY_STATUS_OK)
    return status;
  const product_flow_entry_t *entry = &pool->slots[slot].entry;
  if (entry->linked || entry->end_reason != reason)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  release_slot (pool, slot);
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
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
  pool->stats.timer_entries = 0;
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
  pool->heap = calloc (capacity, sizeof (*pool->heap));
  if (!pool->slots || !pool->buckets || !pool->heap)
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
    + (uint64_t) capacity * sizeof (*pool->heap)
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
  observation->previous_slot = NO_SLOT;
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
  /* A tracker consumes the shared parser's facts, never a key-derived stand-in.
   * Missing/unavailable facts are an Interface error, not capacity bypass. */
  if (!packet->facts || packet->facts->protocol != assignment->key.protocol
          || packet->facts->ip_family != assignment->key.ip_family
          || packet->facts->l3_status != PRODUCT_PACKET_L3_COMPLETE
          || packet->facts->l4_status != (protocol == 2
               ? PRODUCT_PACKET_L4_OTHER_TERMINAL : PRODUCT_PACKET_L4_COMPLETE)
          || (protocol == 2 && (!packet->facts->icmp_identity_known
              || packet->facts->icmp_identifier != assignment->key.transport.query.identifier)))
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET;
  uint32_t slot = find_entry (pool, assignment);
  uint64_t previous_incarnation = 0;
  if (slot != NO_SLOT && pool->slots[slot].entry.deadline_us &&
      pool->slots[slot].entry.deadline_us <= packet->timestamp)
    {
      /* Logical expiry is immediate even while a bounded cleanup batch is
       * still pending. The old END retains its slot; normal capacity rules
       * apply to the new instance. Early policy DROP never reaches lookup. */
      previous_incarnation = pool->slots[slot].entry.incarnation;
      observation->previous_slot = slot;
      observation->previous_deadline_us = pool->slots[slot].entry.deadline_us;
      product_flow_entry_status_t status = product_flow_runtime_close (
        pool, slot, pool->stats.generation, pool->slots[slot].entry.incarnation,
        PRODUCT_FLOW_END_EXPIRED);
      if (status != PRODUCT_FLOW_ENTRY_STATUS_OK)
        return status;
      observation->expired_before_observe = 1;
      observation->previous_incarnation = previous_incarnation;
      slot = NO_SLOT;
    }
  product_tcp_state_t tcp_candidate = {0};
  product_tracker_result_t tcp_result = {0};
  product_icmp_state_t icmp_candidate = {0};
  product_tracker_result_t icmp_result = {0};
  if (protocol == 0)
    {
      product_flow_direction_t direction = PRODUCT_FLOW_DIRECTION_ORIG;
      if (slot != NO_SLOT)
        {
          const product_flow_entry_t *old = &pool->slots[slot].entry;
          tcp_candidate = old->protocol_state.tcp;
          direction = assignment->source_is_a == old->origin_is_endpoint_a
            ? PRODUCT_FLOW_DIRECTION_ORIG : PRODUCT_FLOW_DIRECTION_REPLY;
        }
      tcp_result = product_tcp_update(&tcp_candidate, packet->facts, direction);
      if (tcp_result.update == PRODUCT_CT_UPDATE_INVALID)
        {
          ++pool->stats.protocol[protocol].invalid_packets;
          if (slot == NO_SLOT)
            {
              observation->tracker = tcp_result;
              observation->tracker.facts.direction = PRODUCT_FLOW_DIRECTION_UNKNOWN;
              return PRODUCT_FLOW_ENTRY_STATUS_OK;
            }
        }
      else if (tcp_result.create_replacement)
        {
          previous_incarnation = pool->slots[slot].entry.incarnation;
          product_flow_entry_status_t close_status = product_flow_runtime_close (
            pool, slot, pool->stats.generation, previous_incarnation,
            PRODUCT_FLOW_END_REPLACED);
          if (close_status != PRODUCT_FLOW_ENTRY_STATUS_OK)
            return close_status;
          slot = NO_SLOT;
          tcp_candidate = (product_tcp_state_t){0};
          tcp_result = product_tcp_update(&tcp_candidate, packet->facts, PRODUCT_FLOW_DIRECTION_ORIG);
          tcp_result.close_old_instance = tcp_result.create_replacement = 1;
        }
    }
  if (protocol == 2)
    {
      product_flow_direction_t direction = PRODUCT_FLOW_DIRECTION_ORIG;
      if (slot != NO_SLOT)
        {
          const product_flow_entry_t *old = &pool->slots[slot].entry;
          icmp_candidate = old->protocol_state.icmp;
          direction = assignment->source_is_a == old->origin_is_endpoint_a
            ? PRODUCT_FLOW_DIRECTION_ORIG : PRODUCT_FLOW_DIRECTION_REPLY;
        }
      icmp_result = product_icmp_update (&icmp_candidate, packet->facts, direction);
      if (icmp_result.update == PRODUCT_CT_UPDATE_INVALID)
        {
          ++pool->stats.protocol[protocol].invalid_packets;
          if (slot == NO_SLOT)
            {
              observation->tracker = icmp_result;
              observation->tracker.facts.direction = PRODUCT_FLOW_DIRECTION_UNKNOWN;
              return PRODUCT_FLOW_ENTRY_STATUS_OK;
            }
        }
    }
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
      entry->heap_position = NO_SLOT;
      entry->linked = 1U;
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
      pool->stats.linked_entries++;
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
  observation->previous_incarnation = previous_incarnation;
  unsigned side = entry->last_flow_direction == PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY;
  entry->side_packets[side]++;
  entry->side_bytes[side] += packet->packet_bytes;
  if (protocol == 0)
    {
      entry->protocol_state.tcp = tcp_candidate;
      observation->tracker = tcp_result;
    }
  else if (protocol == 1)
    observation->tracker = product_udp_update (
      &entry->protocol_state.udp, packet->facts, observation->flow_direction);
  else
    {
      entry->protocol_state.icmp = icmp_candidate;
      observation->tracker = icmp_result;
    }
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
      || (address - begin) % sizeof (*pool->slots) != 0 || !borrowed->linked)
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

product_flow_entry_status_t
product_flow_runtime_flush (product_flow_runtime_t *pool)
{
  if (pool == NULL)
    return PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT;
  if (pool->stats.ending_entries)
    return PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE;
  for (uint32_t slot = 0; slot < pool->stats.capacity; slot++)
    if (pool->slots[slot].entry.in_use)
      {
        release_slot (pool, slot);
        ++pool->stats.administrative_release_count;
      }
  reset_storage (pool);
  pool->stats.flush_count++;
  return PRODUCT_FLOW_ENTRY_STATUS_OK;
}

void
product_flow_runtime_destroy (product_flow_runtime_t *pool)
{
  if (!pool)
    return;
  /* Destruction is only legal after the native graph has drained. */
  if (pool->stats.ending_entries)
    abort ();
  if (pool->slots && pool->buckets)
    (void) product_flow_runtime_flush (pool);
  free (pool->slots);
  free (pool->buckets);
  free (pool->heap);
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
