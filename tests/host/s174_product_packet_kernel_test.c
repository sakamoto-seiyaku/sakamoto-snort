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

static size_t
ipv4_packet (uint8_t *packet, uint8_t protocol, uint32_t source,
             uint16_t source_port, uint32_t destination,
             uint16_t destination_port)
{
  memset (packet, 0, 64);
  packet[0] = 0x45;
  packet[2] = 0;
  packet[3] = protocol == 6 ? 40 : 28;
  packet[8] = 64;
  packet[9] = protocol;
  packet[12] = (uint8_t) (source >> 24);
  packet[13] = (uint8_t) (source >> 16);
  packet[14] = (uint8_t) (source >> 8);
  packet[15] = (uint8_t) source;
  packet[16] = (uint8_t) (destination >> 24);
  packet[17] = (uint8_t) (destination >> 16);
  packet[18] = (uint8_t) (destination >> 8);
  packet[19] = (uint8_t) destination;
  packet[20] = (uint8_t) (source_port >> 8);
  packet[21] = (uint8_t) source_port;
  packet[22] = (uint8_t) (destination_port >> 8);
  packet[23] = (uint8_t) destination_port;
  if (protocol == 6)
    packet[32] = 0x50;
  else
    {
      packet[24] = 0;
      packet[25] = 8;
    }
  return protocol == 6 ? 40U : 28U;
}

static size_t
ipv6_packet (uint8_t *packet, uint8_t protocol, const uint8_t source[16],
             uint16_t source_port, const uint8_t destination[16],
             uint16_t destination_port)
{
  const uint16_t payload_length = protocol == 6 ? 20 : 8;
  memset (packet, 0, 80);
  packet[0] = 0x60;
  packet[4] = (uint8_t) (payload_length >> 8);
  packet[5] = (uint8_t) payload_length;
  packet[6] = protocol;
  packet[7] = 64;
  memcpy (packet + 8, source, 16);
  memcpy (packet + 24, destination, 16);
  packet[40] = (uint8_t) (source_port >> 8);
  packet[41] = (uint8_t) source_port;
  packet[42] = (uint8_t) (destination_port >> 8);
  packet[43] = (uint8_t) destination_port;
  if (protocol == 6)
    packet[52] = 0x50;
  else
    {
      packet[44] = 0;
      packet[45] = 8;
    }
  return 40U + payload_length;
}

static product_packet_lease_t
admit (const uint8_t *packet, size_t length, uint16_t current_worker,
       product_packet_hints_t hints, uint64_t obligation_id)
{
  const product_worker_layout_t layout = {
    .worker_count = 4,
    .hash_seed = UINT64_C (0x6f776e65722d3137),
  };
  const product_packet_ingress_t ingress = {
    .data = packet,
    .length = length,
    .current_worker = current_worker,
    .flow_domain = 7,
    .origin_obligation_id = obligation_id,
    .hints = hints,
  };
  product_packet_lease_t lease;
  memset (&lease, 0, sizeof (lease));
  CHECK (product_packet_admit (&layout, &ingress, &lease)
           == PRODUCT_PACKET_OK,
         "valid packet must be admitted");
  return lease;
}

static void
check_pair (const uint8_t *forward, size_t forward_length,
            const uint8_t *reverse, size_t reverse_length, uint8_t family,
            uint8_t protocol, uint16_t source_port,
            uint16_t destination_port, uint64_t obligation_base)
{
  product_packet_hints_t hints = {
    .uid = 10001,
    .queue_id = 3,
    .interface_id = 11,
    .network_context_id = 21,
    .profile_id = 1,
  };
  product_packet_lease_t a =
    admit (forward, forward_length, 0, hints, obligation_base);
  product_packet_lease_t b =
    admit (reverse, reverse_length, 0, hints, obligation_base + 1);

  CHECK (a.facts.l3_status == PRODUCT_PACKET_L3_COMPLETE,
         "L3 status must be complete");
  CHECK (a.facts.l4_status == PRODUCT_PACKET_L4_COMPLETE,
         "L4 status must be complete");
  CHECK (a.facts.ip_family == family, "IP family must match vector");
  CHECK (a.facts.protocol == protocol, "protocol must match vector");
  CHECK (a.facts.source_port == source_port,
         "source port must match vector");
  CHECK (a.facts.destination_port == destination_port,
         "destination port must match vector");
  CHECK (memcmp (&a.canonical_key, &b.canonical_key,
                 sizeof (a.canonical_key)) == 0,
         "forward and reverse must have one canonical key");
  CHECK (a.expected_owner == b.expected_owner,
         "forward and reverse must have one owner");

  hints.uid = UINT32_MAX;
  hints.queue_id = UINT32_MAX;
  hints.interface_id = UINT32_MAX;
  hints.network_context_id = UINT64_MAX;
  hints.profile_id = UINT32_MAX;
  product_packet_lease_t changed =
    admit (forward, forward_length, 0, hints, obligation_base + 2);
  CHECK (memcmp (&a.canonical_key, &changed.canonical_key,
                 sizeof (a.canonical_key)) == 0,
         "platform hints must not alter canonical key");
  CHECK (a.expected_owner == changed.expected_owner,
         "platform hints must not alter owner");
}

static void
check_distribution_and_ledger (const uint8_t *packet, size_t length)
{
  product_packet_hints_t hints = { 0 };
  product_packet_lease_t probe = admit (packet, length, 0, hints, 91);
  product_packet_lease_t local =
    admit (packet, length, probe.expected_owner, hints, 92);
  CHECK (local.distribution == PRODUCT_PACKET_DISTRIBUTION_LOCAL,
         "owner-local path must stay local");
  CHECK (local.primary_handoff_count == 0,
         "owner-local path must not enqueue");

  uint16_t remote_worker = (uint16_t) ((probe.expected_owner + 1U) % 4U);
  product_packet_lease_t remote =
    admit (packet, length, remote_worker, hints, 93);
  CHECK (remote.distribution == PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE,
         "non-owner initial placement must select Primary Distribution");
  CHECK (remote.primary_handoff_count == 1,
         "remote initial placement must request exactly one primary handoff");

  CHECK (product_packet_set_terminal (&remote,
                                      PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           == PRODUCT_PACKET_ORDER_VIOLATION,
         "terminal mutation before Owner Guard must fail");
  CHECK (product_packet_owner_guard (&remote, remote.expected_owner)
           == PRODUCT_PACKET_OK,
         "packet arriving at expected owner must pass Owner Guard");
  CHECK (product_packet_set_terminal (&remote,
                                      PRODUCT_PACKET_INTENT_PASS_ADAPTER)
           == PRODUCT_PACKET_OK,
         "guarded packet must receive one terminal intent");
  CHECK (product_packet_settle (&remote) == PRODUCT_PACKET_OK,
         "terminal obligation must settle exactly once");
  CHECK (remote.origin_obligation_id == 93,
         "origin obligation must survive distribution");
  CHECK (remote.settled == 1, "settled lease must have zero obligation debt");
  CHECK (product_packet_settle (&remote) == PRODUCT_PACKET_ALREADY_SETTLED,
         "duplicate ledger settlement must fail");
}

int
main (void)
{
  uint8_t a[80], b[80], c[80], d[80];
  const uint8_t ip6a[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                             0,    0,    0,    0,    0, 0, 0, 1 };
  const uint8_t ip6b[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                             0,    0,    0,    0,    0, 0, 0, 2 };

  size_t alen = ipv4_packet (a, 6, 0x0a000001, 12345, 0x0a000002, 443);
  size_t blen = ipv4_packet (b, 6, 0x0a000002, 443, 0x0a000001, 12345);
  check_pair (a, alen, b, blen, 4, 6, 12345, 443, 10);

  alen = ipv4_packet (a, 17, 0xc0000201, 5353, 0xc6336402, 53);
  blen = ipv4_packet (b, 17, 0xc6336402, 53, 0xc0000201, 5353);
  check_pair (a, alen, b, blen, 4, 17, 5353, 53, 20);

  size_t clen = ipv6_packet (c, 6, ip6a, 2222, ip6b, 8443);
  size_t dlen = ipv6_packet (d, 6, ip6b, 8443, ip6a, 2222);
  check_pair (c, clen, d, dlen, 6, 6, 2222, 8443, 30);

  clen = ipv6_packet (c, 17, ip6a, 60000, ip6b, 443);
  dlen = ipv6_packet (d, 17, ip6b, 443, ip6a, 60000);
  check_pair (c, clen, d, dlen, 6, 17, 60000, 443, 40);

  alen = ipv4_packet (a, 6, 0x0a000001, 12345, 0x0a000002, 443);
  blen = ipv4_packet (b, 17, 0x0a000001, 12345, 0x0a000002, 443);
  product_packet_hints_t hints = { 0 };
  product_packet_lease_t tcp = admit (a, alen, 0, hints, 50);
  product_packet_lease_t udp = admit (b, blen, 0, hints, 51);
  CHECK (memcmp (&tcp.canonical_key, &udp.canonical_key,
                 sizeof (tcp.canonical_key)) != 0,
         "IP protocol must participate in canonical key");
  check_distribution_and_ledger (a, alen);

  if (failures != 0)
    return 1;
  puts ("s174 product packet kernel semantic vectors: PASS");
  return 0;
}
