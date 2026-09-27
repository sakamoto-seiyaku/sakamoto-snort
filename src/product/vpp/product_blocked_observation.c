/* SPDX-License-Identifier: Apache-2.0 */
#include "product_blocked_observation.h"
#include "product_flow_tracker.h"
#include <stdlib.h>
#include <string.h>

#define NO_SLOT UINT32_MAX
#define IDLE_US UINT64_C (30000000)
#define FLUSH_US UINT64_C (1000000)

typedef struct {
  product_canonical_owner_key_t key;
  uint64_t hash, incarnation, sequence, first_seen, last_seen, utc_us;
  uint64_t packets[2], bytes[2], exported_packets, exported_bytes;
  uint64_t due;
  product_observation_attribution_t attribution[2];
  uint32_t uid, network, next;
  uint8_t used, origin_is_a, origin_direction, last_direction, flow_direction;
  uint8_t clock_changed;
} blocked_slot_t;

struct product_blocked_observation {
  blocked_slot_t *slots;
  uint32_t *buckets;
  uint32_t capacity, bucket_count, free_head, active;
  uint64_t generation, next_incarnation, next_deadline, misses, retired;
  uint16_t owner;
  product_blocked_emit_t emit;
  void *context;
};

static int key_equal (const product_canonical_owner_key_t *a,
                      const product_canonical_owner_key_t *b) {
  if (a->kind != b->kind || a->ip_family != b->ip_family || a->protocol != b->protocol
      || memcmp (a->address_a, b->address_a, 16)
      || memcmp (a->address_b, b->address_b, 16)) return 0;
  if (a->kind == PRODUCT_OWNER_KEY_L4_PORTS)
    return a->transport.ports.a == b->transport.ports.a
      && a->transport.ports.b == b->transport.ports.b;
  return a->kind == PRODUCT_OWNER_KEY_ICMP_QUERY && a->query_class == b->query_class
    && a->transport.query.identifier == b->transport.query.identifier;
}

static uint32_t bucket (const product_blocked_observation_t *o, uint64_t hash,
                        uint32_t uid, uint32_t network) {
  uint64_t mixed = hash ^ ((uint64_t) uid << 32) ^ network;
  return (uint32_t) (mixed ^ (mixed >> 32) ^ (mixed >> 16)) & (o->bucket_count - 1);
}

static void export_record (product_blocked_observation_t *o, uint32_t index,
                           uint8_t flags) {
  blocked_slot_t *s = &o->slots[index];
  if (s->sequence == UINT64_MAX) return;
  product_observation_record_t r = {
    .length = s->key.ip_family == 4 ? 456 : 480,
    .version = PRODUCT_OBSERVATION_VERSION,
    .flags = PRODUCT_OBSERVATION_BLOCKED | flags
      | (s->clock_changed ? PRODUCT_OBSERVATION_CLOCK_CHANGED : 0),
    .owner = o->owner, .slot = index, .uid = s->uid,
    .generation = o->generation, .incarnation = s->incarnation,
    .sequence = ++s->sequence, .first_seen = s->first_seen,
    .last_seen = s->last_seen, .network = s->network,
    .family = s->key.ip_family, .protocol = s->key.protocol,
    .origin_direction = s->origin_direction, .last_direction = s->last_direction,
    .flow_direction = s->flow_direction,
    .end_reason = flags & PRODUCT_OBSERVATION_END ? PRODUCT_OBSERVATION_END_IDLE : 0,
    .activity_utc_us = s->utc_us,
  };
  memcpy (r.packets, s->packets, sizeof (r.packets));
  memcpy (r.bytes, s->bytes, sizeof (r.bytes));
  memcpy (r.attribution, s->attribution, sizeof (r.attribution));
  unsigned side = s->flow_direction == PRODUCT_FLOW_DIRECTION_REPLY;
  r.policy_revision = s->attribution[side].policy_revision;
  r.winner = s->attribution[side].winner;
  r.uid = s->attribution[side].uid;
  r.network = s->attribution[side].network;
  unsigned address_bytes = s->key.ip_family == 4 ? 4 : 16;
  const uint8_t *origin = s->origin_is_a ? s->key.address_a : s->key.address_b;
  const uint8_t *reply = s->origin_is_a ? s->key.address_b : s->key.address_a;
  if (address_bytes == 4) { origin += 12; reply += 12; }
  memcpy (r.address, origin, address_bytes);
  memcpy (r.address + address_bytes, reply, address_bytes);
  if (s->key.kind == PRODUCT_OWNER_KEY_L4_PORTS) {
    r.ports[0] = s->origin_is_a ? s->key.transport.ports.a : s->key.transport.ports.b;
    r.ports[1] = s->origin_is_a ? s->key.transport.ports.b : s->key.transport.ports.a;
  } else r.ports[0] = s->key.transport.query.identifier;
  o->emit (o->context, &r);
  /* A failed queue write loses this snapshot. Subsequent growth remains
   * cumulative; no retry or packet wait is introduced. */
  s->exported_packets = s->packets[0] + s->packets[1];
  s->exported_bytes = s->bytes[0] + s->bytes[1];
  s->due = 0;
}

product_blocked_observation_t *product_blocked_observation_create (
  uint32_t capacity, uint64_t generation, uint16_t owner,
  product_blocked_emit_t emit, void *context) {
  if (!capacity || capacity > 65536 || !generation || !emit) return NULL;
  product_blocked_observation_t *o = calloc (1, sizeof (*o));
  if (!o) return NULL;
  o->capacity = capacity; o->generation = generation; o->owner = owner;
  o->emit = emit; o->context = context; o->next_deadline = UINT64_MAX;
  o->bucket_count = 1;
  while (o->bucket_count < capacity * 2) o->bucket_count <<= 1;
  o->slots = calloc (capacity, sizeof (*o->slots));
  o->buckets = malloc (o->bucket_count * sizeof (*o->buckets));
  if (!o->slots || !o->buckets) { product_blocked_observation_destroy (o); return NULL; }
  for (uint32_t i = 0; i < o->bucket_count; i++) o->buckets[i] = NO_SLOT;
  for (uint32_t i = 0; i < capacity; i++) o->slots[i].next = i + 1;
  o->slots[capacity - 1].next = NO_SLOT;
  return o;
}

void product_blocked_observation_destroy (product_blocked_observation_t *o) {
  if (!o) return;
  free (o->slots); free (o->buckets); free (o);
}

static void unlink_slot (product_blocked_observation_t *o, uint32_t index) {
  blocked_slot_t *s = &o->slots[index];
  uint32_t *link = &o->buckets[bucket (o, s->hash, s->uid, s->network)];
  while (*link != NO_SLOT && *link != index) link = &o->slots[*link].next;
  if (*link == index) *link = s->next;
  s->used = 0; s->next = o->free_head; o->free_head = index;
  __atomic_sub_fetch (&o->active, 1, __ATOMIC_RELAXED);
  __atomic_add_fetch (&o->retired, 1, __ATOMIC_RELAXED);
}

void product_blocked_observation_observe (
  product_blocked_observation_t *o, const product_owner_assignment_t *assignment,
  uint32_t uid, uint32_t network, uint8_t device_direction, uint32_t bytes,
  uint64_t mono_us, uint64_t utc_us,
  const product_observation_attribution_t *context) {
  if (!o || !assignment || !assignment->valid || !context || !mono_us || !utc_us
      || assignment->execution_owner != o->owner || assignment->source_is_a > 1
      || (assignment->key.kind != PRODUCT_OWNER_KEY_L4_PORTS
          && assignment->key.kind != PRODUCT_OWNER_KEY_ICMP_QUERY)) return;
  uint32_t b = bucket (o, assignment->canonical_hash, uid, network);
  uint32_t index = o->buckets[b];
  while (index != NO_SLOT) {
    blocked_slot_t *s = &o->slots[index];
    if (s->hash == assignment->canonical_hash && s->uid == uid && s->network == network
        && key_equal (&s->key, &assignment->key)) break;
    index = s->next;
  }
  if (index != NO_SLOT && mono_us >= o->slots[index].last_seen + IDLE_US) {
    export_record (o, index, PRODUCT_OBSERVATION_END);
    unlink_slot (o, index);
    index = NO_SLOT;
  }
  int created = index == NO_SLOT;
  if (created) {
    if (o->free_head == NO_SLOT || o->next_incarnation == UINT64_MAX) {
      __atomic_add_fetch (&o->misses, 1, __ATOMIC_RELAXED); return;
    }
    index = o->free_head;
    o->free_head = o->slots[index].next;
    blocked_slot_t *s = &o->slots[index];
    *s = (blocked_slot_t) {
      .key = assignment->key, .hash = assignment->canonical_hash,
      .incarnation = ++o->next_incarnation, .first_seen = mono_us,
      .uid = uid, .network = network, .used = 1,
      .origin_is_a = assignment->source_is_a,
      .origin_direction = device_direction,
      .next = o->buckets[b],
    };
    o->buckets[b] = index; __atomic_add_fetch (&o->active, 1, __ATOMIC_RELAXED);
  }
  blocked_slot_t *s = &o->slots[index];
  unsigned side = assignment->source_is_a != s->origin_is_a;
  product_observation_attribution_t *a = &s->attribution[side];
  product_observation_attribution_t current = *context;
  /* PRE drops never enter the Flow/LPI producer. */
  current.protocol_set = 0;
  current.protocols_available = 0;
  int changed = !a->segment || memcmp (&a->policy_generation, &current.policy_generation,
    sizeof (*a) - offsetof (product_observation_attribution_t, policy_generation));
  if (changed) {
    if (a->segment) export_record (o, index, 0);
    uint64_t segment = a->segment == UINT64_MAX ? UINT64_MAX : a->segment + 1;
    *a = current;
    a->segment = segment; a->start_packets = s->packets[side];
    a->start_bytes = s->bytes[side];
    if (segment == UINT64_MAX) a->valid = 0;
  }
  if (s->utc_us && mono_us >= s->last_seen) {
    uint64_t expected = s->utc_us + mono_us - s->last_seen;
    uint64_t difference = utc_us > expected ? utc_us - expected : expected - utc_us;
    if (difference > UINT64_C (1000000)) s->clock_changed = 1;
  }
  s->last_seen = mono_us; s->utc_us = utc_us;
  s->last_direction = device_direction;
  s->flow_direction = side ? PRODUCT_FLOW_DIRECTION_REPLY : PRODUCT_FLOW_DIRECTION_ORIG;
  a->activity_utc_us = utc_us;
  s->packets[side]++; s->bytes[side] += bytes;
  uint64_t total_packets = s->packets[0] + s->packets[1];
  uint64_t total_bytes = s->bytes[0] + s->bytes[1];
  if (created || changed || total_packets - s->exported_packets >= 32
      || total_bytes - s->exported_bytes >= 65536)
    export_record (o, index, created ? PRODUCT_OBSERVATION_CREATE : 0);
  else if (!s->due) s->due = mono_us + FLUSH_US;
  uint64_t next = s->due && s->due < mono_us + IDLE_US ? s->due : mono_us + IDLE_US;
  if (next < o->next_deadline) o->next_deadline = next;
}

uint64_t product_blocked_observation_deadline (const product_blocked_observation_t *o) {
  return o ? o->next_deadline : UINT64_MAX;
}

void product_blocked_observation_flush_due (product_blocked_observation_t *o,
                                             uint64_t now_us, uint32_t budget) {
  if (!o || now_us < o->next_deadline) return;
  uint32_t emitted = 0;
  uint64_t next = UINT64_MAX;
  for (uint32_t i = 0; i < o->capacity; i++) {
    blocked_slot_t *s = &o->slots[i];
    if (!s->used) continue;
    uint64_t idle = s->last_seen + IDLE_US;
    if (idle <= now_us && emitted < budget) {
      export_record (o, i, PRODUCT_OBSERVATION_END);
      unlink_slot (o, i);
      emitted++;
      continue;
    }
    if (s->due && s->due <= now_us && emitted < budget) {
      export_record (o, i, 0);
      emitted++;
    }
    uint64_t deadline = s->due && s->due < idle ? s->due : idle;
    if (deadline < next) next = deadline;
  }
  o->next_deadline = next;
}

uint32_t product_blocked_observation_active (const product_blocked_observation_t *o) {
  return o ? __atomic_load_n (&o->active, __ATOMIC_RELAXED) : 0;
}
uint64_t product_blocked_observation_misses (const product_blocked_observation_t *o) {
  return o ? __atomic_load_n (&o->misses, __ATOMIC_RELAXED) : 0;
}
uint64_t product_blocked_observation_retired (const product_blocked_observation_t *o) {
  return o ? __atomic_load_n (&o->retired, __ATOMIC_RELAXED) : 0;
}
