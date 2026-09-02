/* SPDX-License-Identifier: Apache-2.0 */

#include "product_flow_entry.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(condition, message)                                             \
  do                                                                          \
    {                                                                         \
      if (!(condition))                                                        \
        {                                                                     \
          fprintf (stderr, "FAIL: %s\n", (message));                         \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)

#define CHECK_STATUS(actual, expected, message)                               \
  CHECK ((actual) == (expected), (message))

static product_flow_entry_packet_t
packet_template (uint8_t family, uint8_t protocol)
{
  product_flow_entry_packet_t packet = {0};
  packet.uid = 10001U;
  packet.network_context = 7U;
  packet.packet_bytes = 120U;
  packet.family = family;
  packet.protocol = protocol;
  packet.device_direction = PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT;
  packet.source_port = 40000U;
  packet.destination_port = 443U;
  packet.timestamp = 10U;
  if (family == PRODUCT_FLOW_ENTRY_FAMILY_IPV4)
    {
      packet.source_address[0] = 10U;
      packet.source_address[1] = 0U;
      packet.source_address[2] = 0U;
      packet.source_address[3] = 1U;
      packet.destination_address[0] = 192U;
      packet.destination_address[1] = 0U;
      packet.destination_address[2] = 2U;
      packet.destination_address[3] = 10U;
    }
  else
    {
      packet.source_address[0] = 0x20U;
      packet.source_address[1] = 0x01U;
      packet.source_address[2] = 0x0dU;
      packet.source_address[3] = 0xb8U;
      packet.source_address[15] = 1U;
      packet.destination_address[0] = 0x20U;
      packet.destination_address[1] = 0x01U;
      packet.destination_address[2] = 0x0dU;
      packet.destination_address[3] = 0xb8U;
      packet.destination_address[15] = 2U;
    }
  return packet;
}

static void
reverse_packet (product_flow_entry_packet_t *packet)
{
  uint8_t address[PRODUCT_FLOW_ENTRY_ADDRESS_BYTES];
  uint16_t port;
  memcpy (address, packet->source_address, sizeof (address));
  memcpy (packet->source_address, packet->destination_address, sizeof (address));
  memcpy (packet->destination_address, address, sizeof (address));
  port = packet->source_port;
  packet->source_port = packet->destination_port;
  packet->destination_port = port;
}

static void
test_drop_and_pass_next (void)
{
  product_flow_entry_pool_t pool;
  product_flow_entry_packet_t packet = packet_template (
    PRODUCT_FLOW_ENTRY_FAMILY_IPV4, PRODUCT_FLOW_ENTRY_PROTOCOL_TCP);
  product_flow_entry_observation_t observation;
  product_flow_entry_t *entry;

  CHECK_STATUS (product_flow_entry_pool_init (&pool, 0U, 1U, 0x11U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "one-worker pool initializes");
  CHECK_STATUS (product_flow_entry_publish_revision (&pool, 1U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "first policy revision publishes");
  CHECK_STATUS (product_flow_entry_observe (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_DROP, &observation),
                PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP,
                "early DROP returns before FlowEntry lookup");
  CHECK (observation.entry == NULL && pool.active_entries == 0U
           && pool.allocation_count == 0U && pool.early_drop_count == 1U,
         "early DROP creates no FlowEntry or allocation");

  CHECK_STATUS (product_flow_entry_observe (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "PASS_NEXT creates a FlowEntry");
  CHECK (observation.created && !observation.reused
           && observation.flow_direction == PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG,
         "first PASS_NEXT packet is one ORIG allocation");
  entry = observation.entry;
  CHECK (entry != NULL && entry->uid == packet.uid
           && entry->network_context == packet.network_context
           && entry->policy_revision == 1U && entry->packets == 1U
           && entry->bytes == packet.packet_bytes,
         "entry stores bounded facts, counters, and active revision");
  CHECK_STATUS (product_flow_entry_set_decision (
                  &pool, entry, PRODUCT_FLOW_ENTRY_DECISION_DROP, 9001U, 77U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "later stage decision can be cached");
  CHECK (entry->decision == PRODUCT_FLOW_ENTRY_DECISION_DROP
           && entry->winner_rule_id == 9001U && entry->reason_id == 77U,
         "decision cache stores winner attribution");
}

static void
test_reverse_reuse_and_identity_exclusions (void)
{
  product_flow_entry_pool_t pool;
  product_flow_entry_packet_t packet = packet_template (
    PRODUCT_FLOW_ENTRY_FAMILY_IPV4, PRODUCT_FLOW_ENTRY_PROTOCOL_TCP);
  product_flow_entry_packet_t reverse = packet;
  product_flow_entry_observation_t first;
  product_flow_entry_observation_t second;

  CHECK_STATUS (product_flow_entry_pool_init (&pool, 0U, 1U, 0x22U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "reverse test pool initializes");
  CHECK_STATUS (product_flow_entry_publish_revision (&pool, 1U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "reverse test revision publishes");
  CHECK_STATUS (product_flow_entry_observe (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &first),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "forward packet creates entry");
  reverse_packet (&reverse);
  reverse.uid = 20002U;
  reverse.network_context = 99U;
  reverse.device_direction = PRODUCT_FLOW_ENTRY_DIRECTION_INPUT;
  reverse.timestamp = 11U;
  reverse.packet_bytes = 80U;
  CHECK_STATUS (product_flow_entry_observe (
                  &pool, &reverse, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &second),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "reverse packet finds canonical entry");
  CHECK (second.reused && !second.created
           && second.entry == first.entry
           && second.flow_direction == PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY,
         "reverse packet reuses one canonical entry as REPLY");
  CHECK (pool.active_entries == 1U && pool.allocation_count == 1U
           && pool.reuse_count == 1U && second.entry->packets == 2U
           && second.entry->bytes == 200U,
         "reverse reuse does not allocate a second entry");
  CHECK (second.entry->uid == packet.uid
           && second.entry->network_context == packet.network_context
           && second.entry->flow_origin_device_direction
                == packet.device_direction,
         "UID/context/device origin are facts, not canonical identity");
}

static void
test_lazy_revision_invalidation (void)
{
  product_flow_entry_pool_t pool;
  product_flow_entry_packet_t packet = packet_template (
    PRODUCT_FLOW_ENTRY_FAMILY_IPV4, PRODUCT_FLOW_ENTRY_PROTOCOL_UDP);
  product_flow_entry_observation_t observation;
  product_flow_entry_t *entry;

  CHECK_STATUS (product_flow_entry_pool_init (&pool, 0U, 1U, 0x33U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "revision test pool initializes");
  CHECK_STATUS (product_flow_entry_publish_revision (&pool, 10U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "revision ten publishes");
  CHECK_STATUS (product_flow_entry_observe (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "revision ten creates entry");
  entry = observation.entry;
  CHECK_STATUS (product_flow_entry_set_decision (
                  &pool, entry, PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT, 123U, 45U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "revision ten decision caches");
  CHECK_STATUS (product_flow_entry_publish_revision (&pool, 11U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "successor revision publishes without a table walk");
  CHECK (entry->policy_revision == 10U
           && entry->decision == PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT
           && pool.revision_invalidation_count == 0U,
         "publish leaves existing entry untouched until its next packet");
  CHECK_STATUS (product_flow_entry_observe (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "next packet lazily revisits existing entry");
  CHECK (observation.reused && observation.revision_invalidated
           && entry->policy_revision == 11U
           && entry->decision == PRODUCT_FLOW_ENTRY_DECISION_NONE
           && entry->winner_rule_id == 0U && entry->reason_id == 0U
           && pool.revision_invalidation_count == 1U,
         "revision mismatch clears only decision cache and preserves entry");
  CHECK_STATUS (product_flow_entry_set_decision (
                  &pool, entry, PRODUCT_FLOW_ENTRY_DECISION_NONE, 1U, 0U),
                PRODUCT_FLOW_ENTRY_STATUS_INVALID_DECISION,
                "empty decision cannot carry stale attribution");
  CHECK_STATUS (product_flow_entry_set_decision (
                  &pool, entry, PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT, 124U, 46U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "new packet can cache a decision for the successor revision");
}

static void
make_unique_packet (product_flow_entry_packet_t *packet, uint32_t index)
{
  *packet = packet_template (PRODUCT_FLOW_ENTRY_FAMILY_IPV4,
                             PRODUCT_FLOW_ENTRY_PROTOCOL_TCP);
  packet->source_address[3] = (uint8_t) (index + 1U);
  packet->destination_address[3] = (uint8_t) (index + 101U);
  packet->source_port = (uint16_t) (1000U + index);
  packet->destination_port = (uint16_t) (2000U + index);
  packet->timestamp = index + 1U;
}

static void
test_capacity_and_flush (void)
{
  product_flow_entry_pool_t pool;
  product_flow_entry_packet_t packet;
  product_flow_entry_observation_t observation;
  product_flow_entry_t *first;
  uint32_t index;

  CHECK_STATUS (product_flow_entry_pool_init (&pool, 0U, 1U, 0x44U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "capacity test pool initializes");
  CHECK_STATUS (product_flow_entry_publish_revision (&pool, 1U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "capacity test revision publishes");
  for (index = 0U; index < PRODUCT_FLOW_ENTRY_MAX_ENTRIES; ++index)
    {
      make_unique_packet (&packet, index);
      CHECK_STATUS (product_flow_entry_observe (
                      &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,
                      &observation),
                    PRODUCT_FLOW_ENTRY_STATUS_OK,
                    "bounded pool admits each slot");
    }
  first = pool.entries;
  CHECK (pool.active_entries == PRODUCT_FLOW_ENTRY_MAX_ENTRIES
           && pool.allocation_count == PRODUCT_FLOW_ENTRY_MAX_ENTRIES,
         "pool reaches its fixed capacity without growing");
  make_unique_packet (&packet, PRODUCT_FLOW_ENTRY_MAX_ENTRIES + 1U);
  CHECK_STATUS (product_flow_entry_observe (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED,
                "full pool rejects a new entry");
  CHECK (pool.active_entries == PRODUCT_FLOW_ENTRY_MAX_ENTRIES
           && pool.allocation_count == PRODUCT_FLOW_ENTRY_MAX_ENTRIES
           && pool.capacity_rejection_count == 1U && first->in_use,
         "capacity rejection neither evicts nor spills existing entries");

  product_flow_entry_pool_flush (&pool);
  CHECK (product_flow_entry_pool_active_count (&pool) == 0U
           && pool.entries[0].in_use == 0U && pool.flush_count == 1U,
         "flush clears every worker-local slot and leaves no residue");
}

static void
test_owner_symmetry_and_ipv6 (void)
{
  product_flow_entry_packet_t packet = packet_template (
    PRODUCT_FLOW_ENTRY_FAMILY_IPV6, PRODUCT_FLOW_ENTRY_PROTOCOL_UDP);
  product_flow_entry_packet_t reverse = packet;
  product_flow_entry_pool_t owner_pool;
  product_flow_entry_pool_t wrong_pool;
  product_flow_entry_observation_t observation;
  uint16_t owner;
  uint16_t reverse_owner;
  uint16_t wrong_owner;

  CHECK_STATUS (product_flow_entry_owner_for_packet (4U, 0x55U, &packet, &owner),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "IPv6 packet selects an owner");
  reverse_packet (&reverse);
  CHECK_STATUS (product_flow_entry_owner_for_packet (
                  4U, 0x55U, &reverse, &reverse_owner),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "reverse IPv6 packet selects an owner");
  CHECK (owner == reverse_owner,
         "canonical owner is symmetric for forward and reverse packets");
  CHECK_STATUS (product_flow_entry_pool_init (&owner_pool, owner, 4U, 0x55U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "canonical owner pool initializes");
  CHECK_STATUS (product_flow_entry_publish_revision (&owner_pool, 1U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "IPv6 owner revision publishes");
  CHECK_STATUS (product_flow_entry_observe (
                  &owner_pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "IPv6 UDP PASS_NEXT enters its owner pool");
  wrong_owner = (uint16_t) ((owner + 1U) % 4U);
  CHECK_STATUS (product_flow_entry_pool_init (
                  &wrong_pool, wrong_owner, 4U, 0x55U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "non-owner pool initializes");
  CHECK_STATUS (product_flow_entry_publish_revision (&wrong_pool, 1U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "non-owner revision publishes");
  CHECK_STATUS (product_flow_entry_observe (
                  &wrong_pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER,
                "packet is rejected before state update on wrong owner");
  CHECK (wrong_pool.active_entries == 0U && wrong_pool.allocation_count == 0U
           && wrong_pool.wrong_owner_count == 1U,
         "wrong owner cannot create cross-worker mutable state");
}

static void
test_invalid_inputs (void)
{
  product_flow_entry_pool_t pool;
  product_flow_entry_packet_t packet = packet_template (
    PRODUCT_FLOW_ENTRY_FAMILY_IPV4, PRODUCT_FLOW_ENTRY_PROTOCOL_TCP);
  product_flow_entry_observation_t observation;
  uint16_t owner = 0U;

  CHECK_STATUS (product_flow_entry_pool_init (&pool, 0U, 0U, 0U),
                PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT,
                "zero worker count is invalid");
  CHECK_STATUS (product_flow_entry_pool_init (&pool, 2U, 2U, 0U),
                PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT,
                "worker index outside layout is invalid");
  CHECK_STATUS (product_flow_entry_owner_for_packet (0U, 0U, &packet, &owner),
                PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT,
                "zero owner layout is invalid");
  packet.family = 5U;
  CHECK_STATUS (product_flow_entry_owner_for_packet (1U, 0U, &packet, &owner),
                PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET,
                "unsupported family is rejected");
  packet = packet_template (PRODUCT_FLOW_ENTRY_FAMILY_IPV4,
                            PRODUCT_FLOW_ENTRY_PROTOCOL_TCP);
  packet.source_address[15] = 1U;
  CHECK_STATUS (product_flow_entry_owner_for_packet (1U, 0U, &packet, &owner),
                PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET,
                "noncanonical IPv4 padding is rejected");
  packet = packet_template (PRODUCT_FLOW_ENTRY_FAMILY_IPV4,
                            PRODUCT_FLOW_ENTRY_PROTOCOL_TCP);
  CHECK_STATUS (product_flow_entry_pool_init (&pool, 0U, 1U, 0U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "invalid input test pool initializes");
  CHECK_STATUS (product_flow_entry_publish_revision (&pool, 0U),
                PRODUCT_FLOW_ENTRY_STATUS_INVALID_REVISION,
                "zero policy revision is rejected");
  CHECK_STATUS (product_flow_entry_observe (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT,
         "observe requires an active revision");
}

static void
test_owner_override (void)
{
  product_flow_entry_pool_t pool;
  product_flow_entry_packet_t packet = packet_template (
    PRODUCT_FLOW_ENTRY_FAMILY_IPV4, PRODUCT_FLOW_ENTRY_PROTOCOL_TCP);
  product_flow_entry_observation_t observation;

  CHECK_STATUS (product_flow_entry_pool_init (&pool, 1U, 2U, 0x66U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "graph owner pool initializes");
  CHECK_STATUS (product_flow_entry_publish_revision (&pool, 1U),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "graph owner revision publishes");
  CHECK_STATUS (product_flow_entry_observe_on_owner (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, 1U,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_OK,
                "already guarded owner can enter its worker pool");
  CHECK (observation.created && observation.owner_worker == 1U
           && pool.active_entries == 1U,
         "graph owner override creates only in the guarded worker pool");
  CHECK_STATUS (product_flow_entry_observe_on_owner (
                  &pool, &packet, PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, 0U,
                  &observation),
                PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER,
                "a mismatched guarded owner cannot cross worker pools");
  CHECK (pool.active_entries == 1U && pool.allocation_count == 1U
           && pool.wrong_owner_count == 1U,
         "owner mismatch leaves graph pool state bounded");
}

int
main (void)
{
  CHECK (PRODUCT_FLOW_ENTRY_MAX_ENTRIES == 64U,
         "S193 pool capacity is a fixed bounded value");
  test_drop_and_pass_next ();
  test_reverse_reuse_and_identity_exclusions ();
  test_lazy_revision_invalidation ();
  test_capacity_and_flush ();
  test_owner_symmetry_and_ipv6 ();
  test_invalid_inputs ();
  test_owner_override ();
  if (failures != 0)
    return 1;
  puts ("sakamoto Product bounded FlowEntry semantic vectors: PASS");
  return 0;
}
