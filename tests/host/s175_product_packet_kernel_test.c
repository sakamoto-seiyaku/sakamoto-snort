/* SPDX-License-Identifier: Apache-2.0 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "product_packet.h"

static int failures;

#define CHECK(condition, message)                                             \
  do                                                                          \
    {                                                                         \
      if (!(condition))                                                       \
        {                                                                     \
          fprintf (stderr, "FAIL: %s\n", message);                           \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)

typedef struct
{
  const char *name;
  const uint8_t *packet;
  size_t length;
  product_packet_result_t expected_result;
  product_packet_runtime_drop_reason_t expected_reason;
  uint64_t obligation_id;
} rejected_envelope_vector_t;

static void
check_rejected_envelope (const rejected_envelope_vector_t *vector)
{
  const product_worker_layout_t layout = {
    .worker_count = 2,
    .hash_seed = UINT64_C (0x733137352d726564),
  };
  const product_packet_ingress_t ingress = {
    .data = vector->packet,
    .length = vector->length,
    .current_worker = 0,
    .origin_obligation_id = vector->obligation_id,
    .platform = { 0 },
  };
  product_packet_lease_t lease = { 0 };

  CHECK (product_packet_admit (&layout, &ingress, &lease)
           == vector->expected_result,
         vector->name);
  CHECK (lease.origin_obligation_id == vector->obligation_id,
         "identified ingress must retain its obligation");
  CHECK (lease.facts.l3_status == PRODUCT_PACKET_L3_UNAVAILABLE,
         "rejected envelope must expose no partial L3 facts");
  CHECK (lease.facts.l4_status == PRODUCT_PACKET_L4_UNAVAILABLE,
         "rejected envelope must expose no partial L4 facts");
  CHECK (lease.terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME
           && lease.terminal_count == 1 && lease.settled == 0,
         "rejected envelope must have one runtime-drop and no policy verdict");
  CHECK (lease.runtime_drop_reason == vector->expected_reason,
         "runtime-drop reason must identify the rejected envelope class");
  CHECK (product_packet_settle (&lease) == PRODUCT_PACKET_OK,
         "rejected envelope obligation must settle exactly once");
  CHECK (product_packet_settle (&lease) == PRODUCT_PACKET_ALREADY_SETTLED,
         "rejected envelope obligation must reject duplicate settlement");
}

typedef struct
{
  const char *name;
  const uint8_t *packet;
  size_t length;
  uint8_t expected_family;
  uint8_t expected_protocol;
  product_packet_l4_status_t expected_l4_status;
  const uint8_t *expected_source;
  const uint8_t *expected_destination;
  uint64_t obligation_id;
} l3_only_vector_t;

static void
check_l3_only_packet (const l3_only_vector_t *vector)
{
  const product_worker_layout_t layout = {
    .worker_count = 2,
    .hash_seed = UINT64_C (0x733137352d6c3378),
  };
  const product_packet_ingress_t ingress = {
    .data = vector->packet,
    .length = vector->length,
    .current_worker = 0,
    .origin_obligation_id = vector->obligation_id,
    .platform = { 0 },
  };
  product_packet_lease_t lease = { 0 };

  CHECK (product_packet_admit (&layout, &ingress, &lease)
           == PRODUCT_PACKET_OK,
         vector->name);
  CHECK (lease.facts.l3_status == PRODUCT_PACKET_L3_COMPLETE,
         "valid envelope must preserve complete L3 status");
  CHECK (lease.facts.l4_status == vector->expected_l4_status,
         "valid envelope must classify unavailable deeper facts");
  CHECK (lease.facts.ip_family == vector->expected_family
           && lease.facts.protocol == vector->expected_protocol,
         "valid envelope must preserve family and terminal protocol");
  CHECK (lease.facts.l3_header_length
           == (vector->expected_family == 4 ? 20 : 40)
           && lease.facts.packet_length == vector->length,
         "valid envelope must preserve its complete L3 lengths");
  CHECK (memcmp (lease.facts.source_address, vector->expected_source, 16)
           == 0
           && memcmp (lease.facts.destination_address,
                      vector->expected_destination, 16)
                == 0,
         "valid envelope must preserve its L3 endpoints");
  CHECK (lease.facts.source_port == 0 && lease.facts.destination_port == 0
           && lease.facts.l4_header_length == 0,
         "unavailable L4 facts must not fabricate ports or header length");
  CHECK (lease.origin_obligation_id == vector->obligation_id,
         "admitted L3-only packet must retain its obligation");
  CHECK (lease.runtime_drop_reason == PRODUCT_PACKET_DROP_NONE
           && lease.terminal_intent == PRODUCT_PACKET_INTENT_NONE
           && lease.terminal_count == 0 && lease.settled == 0,
         "admitted L3-only packet must not fabricate a runtime drop");
  CHECK (product_packet_owner_guard (&lease, lease.assignment.execution_owner)
           == PRODUCT_PACKET_OK,
         "admitted L3-only packet must reach its normal owner");
  CHECK (product_packet_set_terminal (&lease,
                                      PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           == PRODUCT_PACKET_OK,
         "owner-guarded L3-only packet must accept a normal terminal intent");
  CHECK (product_packet_settle (&lease) == PRODUCT_PACKET_OK,
         "L3-only packet obligation must settle normally");
  CHECK (product_packet_settle (&lease) == PRODUCT_PACKET_ALREADY_SETTLED,
         "L3-only packet obligation must reject duplicate settlement");
}

static product_packet_lease_t
admit_for_corrective_handoff (const uint8_t *packet, size_t length,
                              uint64_t obligation_id)
{
  const product_worker_layout_t layout = {
    .worker_count = 3,
    .hash_seed = UINT64_C (0x733137352d6f776e),
  };
  const product_packet_ingress_t ingress = {
    .data = packet,
    .length = length,
    .current_worker = 0,
    .origin_obligation_id = obligation_id,
    .platform = { 0 },
  };
  product_packet_lease_t lease = { 0 };

  CHECK (product_packet_admit (&layout, &ingress, &lease)
           == PRODUCT_PACKET_OK,
         "corrective-handoff vector must be admitted");
  return lease;
}

static void
check_corrective_handoff (const uint8_t *packet, size_t length)
{
  product_packet_lease_t corrected =
    admit_for_corrective_handoff (packet, length, UINT64_C (175021));
  product_packet_lease_t repeated =
    admit_for_corrective_handoff (packet, length, UINT64_C (175022));
  uint16_t first_wrong_worker =
    (uint16_t) ((corrected.assignment.execution_owner + 1U) % 3U);
  uint16_t second_wrong_worker =
    (uint16_t) ((corrected.assignment.execution_owner + 2U) % 3U);

  CHECK (memcmp (&corrected.assignment.key, &repeated.assignment.key,
                 sizeof (corrected.assignment.key)) == 0
           && corrected.assignment.execution_owner == repeated.assignment.execution_owner,
         "same key, selector, and layout must retain one expected owner");

  CHECK (product_packet_owner_guard (&corrected, first_wrong_worker)
           == PRODUCT_PACKET_CORRECTIVE_HANDOFF,
         "first owner mismatch must request one corrective handoff");
  CHECK (corrected.corrective_handoff_count == 1,
         "first owner mismatch must count exactly one corrective handoff");
  CHECK (corrected.policy_owner_ready == 0
           && corrected.runtime_drop_reason == PRODUCT_PACKET_DROP_NONE
           && corrected.terminal_intent == PRODUCT_PACKET_INTENT_NONE
           && corrected.terminal_count == 0,
         "corrective handoff must not fabricate guard success or terminal");
  CHECK (product_packet_owner_guard (&corrected, corrected.assignment.execution_owner)
           == PRODUCT_PACKET_OK,
         "corrected packet arriving at expected owner must pass guard");
  CHECK (corrected.corrective_handoff_count == 1
           && corrected.policy_owner_ready == 1,
         "successful correction must retain one handoff and guarded state");
  CHECK (product_packet_set_terminal (&corrected,
                                      PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           == PRODUCT_PACKET_OK
           && product_packet_settle (&corrected) == PRODUCT_PACKET_OK,
         "successfully corrected obligation must settle normally");

  CHECK (product_packet_owner_guard (&repeated, first_wrong_worker)
           == PRODUCT_PACKET_CORRECTIVE_HANDOFF,
         "repeated-mismatch vector must first request correction");
  CHECK (product_packet_owner_guard (&repeated, second_wrong_worker)
           == PRODUCT_PACKET_REPEATED_OWNER_MISMATCH,
         "second wrong worker must become a repeated-owner runtime drop");
  CHECK (repeated.corrective_handoff_count == 1,
         "repeated mismatch must not request a second corrective handoff");
  CHECK (repeated.policy_owner_ready == 0
           && repeated.terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME
           && repeated.terminal_count == 1 && repeated.settled == 0,
         "repeated mismatch must create one unsettled runtime-drop terminal");
  CHECK (repeated.runtime_drop_reason
           == PRODUCT_PACKET_DROP_REPEATED_OWNER_MISMATCH,
         "repeated mismatch must retain its explicit runtime-drop reason");
  CHECK (product_packet_settle (&repeated) == PRODUCT_PACKET_OK,
         "repeated-mismatch obligation must settle exactly once");
  CHECK (product_packet_settle (&repeated)
           == PRODUCT_PACKET_ALREADY_SETTLED,
         "repeated-mismatch obligation must reject duplicate settlement");
}

int
main (void)
{
  static const uint8_t ipv4_source[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0x00, 0x02, 0x01,
  };
  static const uint8_t ipv4_destination[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc6, 0x33, 0x64, 0x02,
  };
  static const uint8_t ipv6_source[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
  };
  static const uint8_t ipv6_destination[16] = {
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
  };
  /* IPv4 IHL=4 is intrinsically invalid even though 20 bytes are present. */
  static const uint8_t invalid_ipv4_header[20] = {
    0x44, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
    0x00, 0x00, 0xc0, 0x00, 0x02, 0x01, 0xc6, 0x33, 0x64, 0x02,
  };
  /* The envelope declares 40 bytes, but this ingress buffer contains 20. */
  static const uint8_t truncated_ipv4_envelope[20] = {
    0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
    0x00, 0x00, 0xc0, 0x00, 0x02, 0x01, 0xc6, 0x33, 0x64, 0x02,
  };
  /* Version 5 is outside the product IPv4/IPv6 envelope contract. */
  static const uint8_t unsupported_ip_version[20] = {
    0x50, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
    0x00, 0x00, 0xc0, 0x00, 0x02, 0x01, 0xc6, 0x33, 0x64, 0x02,
  };
  /* Valid IPv4 envelope with legal SCTP as an unsupported other terminal. */
  static const uint8_t ipv4_other_terminal[20] = {
    0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x84,
    0x00, 0x00, 0xc0, 0x00, 0x02, 0x01, 0xc6, 0x33, 0x64, 0x02,
  };
  /* Valid IPv6 envelope with No Next Header as a legal terminal protocol. */
  static const uint8_t ipv6_other_terminal[40] = {
    0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x40,
    0x20, 0x01, 0x0d, 0xb8, 0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    1,
    0x20, 0x01, 0x0d, 0xb8, 0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    2,
  };
  /* Valid IPv4 L3 envelope whose declared TCP header is only four bytes. */
  static const uint8_t ipv4_truncated_tcp[24] = {
    0x45, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06,
    0x00, 0x00, 0xc0, 0x00, 0x02, 0x01, 0xc6, 0x33, 0x64, 0x02,
    0x30, 0x39, 0x01, 0xbb,
  };
  /* Valid IPv6 L3 envelope whose declared TCP header is only four bytes. */
  static const uint8_t ipv6_truncated_tcp[44] = {
    0x60, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0x40,
    0x20, 0x01, 0x0d, 0xb8, 0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    1,
    0x20, 0x01, 0x0d, 0xb8, 0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    2,
    0x30, 0x39, 0x01, 0xbb,
  };
  /* An extension claiming more bytes than the complete L3 envelope contains
   * must not expose ports from the following bytes. */
  static const uint8_t ipv6_deeper_transport[56] = {
    0x60, 0, 0, 0, 0, 16, 0, 64,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    17, 7, 0, 0, 0, 0, 0, 0, 0x30, 0x39, 0x01, 0xbb, 0, 8, 0, 0,
  };
  static const rejected_envelope_vector_t vectors[] = {
    {
      .name = "invalid IPv4 header must have an explicit runtime result",
      .packet = invalid_ipv4_header,
      .length = sizeof (invalid_ipv4_header),
      .expected_result = PRODUCT_PACKET_INVALID_L3,
      .expected_reason = PRODUCT_PACKET_DROP_INVALID_ENVELOPE,
      .obligation_id = UINT64_C (175001),
    },
    {
      .name = "truncated IPv4 envelope must have an explicit runtime result",
      .packet = truncated_ipv4_envelope,
      .length = sizeof (truncated_ipv4_envelope),
      .expected_result = PRODUCT_PACKET_TRUNCATED_ENVELOPE,
      .expected_reason = PRODUCT_PACKET_DROP_TRUNCATED_ENVELOPE,
      .obligation_id = UINT64_C (175002),
    },
    {
      .name = "unsupported IP version must have an explicit runtime result",
      .packet = unsupported_ip_version,
      .length = sizeof (unsupported_ip_version),
      .expected_result = PRODUCT_PACKET_UNSUPPORTED_ENVELOPE,
      .expected_reason = PRODUCT_PACKET_DROP_UNSUPPORTED_ENVELOPE,
      .obligation_id = UINT64_C (175003),
    },
  };
  static const l3_only_vector_t l3_only_vectors[] = {
    {
      .name = "truncated IPv6 extension keeps deeper transport unavailable",
      .packet = ipv6_deeper_transport,
      .length = sizeof (ipv6_deeper_transport),
      .expected_family = 6,
      .expected_protocol = 0,
      .expected_l4_status = PRODUCT_PACKET_L4_UNAVAILABLE,
      .expected_source = ipv6_source,
      .expected_destination = ipv6_destination,
      .obligation_id = UINT64_C (198001),
    },
    {
      .name = "valid IPv4 other-terminal packet must be admitted",
      .packet = ipv4_other_terminal,
      .length = sizeof (ipv4_other_terminal),
      .expected_family = 4,
      .expected_protocol = 132,
      .expected_l4_status = PRODUCT_PACKET_L4_OTHER_TERMINAL,
      .expected_source = ipv4_source,
      .expected_destination = ipv4_destination,
      .obligation_id = UINT64_C (175011),
    },
    {
      .name = "valid IPv6 other-terminal packet must be admitted",
      .packet = ipv6_other_terminal,
      .length = sizeof (ipv6_other_terminal),
      .expected_family = 6,
      .expected_protocol = 59,
      .expected_l4_status = PRODUCT_PACKET_L4_OTHER_TERMINAL,
      .expected_source = ipv6_source,
      .expected_destination = ipv6_destination,
      .obligation_id = UINT64_C (175012),
    },
    {
      .name = "valid IPv4 with truncated TCP must remain admitted",
      .packet = ipv4_truncated_tcp,
      .length = sizeof (ipv4_truncated_tcp),
      .expected_family = 4,
      .expected_protocol = 6,
      .expected_l4_status = PRODUCT_PACKET_L4_INVALID_OR_UNAVAILABLE,
      .expected_source = ipv4_source,
      .expected_destination = ipv4_destination,
      .obligation_id = UINT64_C (175013),
    },
    {
      .name = "valid IPv6 with truncated TCP must remain admitted",
      .packet = ipv6_truncated_tcp,
      .length = sizeof (ipv6_truncated_tcp),
      .expected_family = 6,
      .expected_protocol = 6,
      .expected_l4_status = PRODUCT_PACKET_L4_INVALID_OR_UNAVAILABLE,
      .expected_source = ipv6_source,
      .expected_destination = ipv6_destination,
      .obligation_id = UINT64_C (175014),
    },
  };
  size_t index;

  for (index = 0; index < sizeof (vectors) / sizeof (vectors[0]); index++)
    check_rejected_envelope (&vectors[index]);
  for (index = 0;
       index < sizeof (l3_only_vectors) / sizeof (l3_only_vectors[0]); index++)
    check_l3_only_packet (&l3_only_vectors[index]);
  check_corrective_handoff (ipv4_other_terminal,
                            sizeof (ipv4_other_terminal));

  if (failures != 0)
    return 1;
  puts ("s175 packet kernel exceptional semantics: PASS");
  return 0;
}
