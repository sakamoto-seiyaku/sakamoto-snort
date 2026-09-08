/* SPDX-License-Identifier: Apache-2.0 */

#include "product_packet.h"

#include <limits.h>
#include <string.h>

enum
{
  PRODUCT_IP_PROTOCOL_TCP = 6,
  PRODUCT_IP_PROTOCOL_UDP = 17,
};

static uint16_t
read_be16 (const uint8_t *value)
{
  return (uint16_t) (((uint16_t) value[0] << 8) | value[1]);
}

static uint32_t
read_be32 (const uint8_t *value)
{
  return ((uint32_t) read_be16 (value) << 16) | read_be16 (value + 2);
}

static int
endpoint_compare (const product_packet_endpoint_t *left,
                  const product_packet_endpoint_t *right)
{
  int address_order = memcmp (left->address, right->address,
                              sizeof (left->address));
  if (address_order != 0)
    return address_order;
  if (left->port < right->port)
    return -1;
  return left->port > right->port;
}

static void
make_canonical_key (const product_packet_facts_t *facts,
                    product_canonical_flow_key_t *key)
{
  product_packet_endpoint_t source;
  product_packet_endpoint_t destination;

  memset (key, 0, sizeof (*key));
  memset (&source, 0, sizeof (source));
  memset (&destination, 0, sizeof (destination));
  memcpy (source.address, facts->source_address, sizeof (source.address));
  memcpy (destination.address, facts->destination_address,
          sizeof (destination.address));
  source.port = facts->source_port;
  destination.port = facts->destination_port;

  key->ip_family = facts->ip_family;
  key->protocol = facts->protocol;
  if (endpoint_compare (&source, &destination) <= 0)
    {
      key->endpoint_a = source;
      key->endpoint_b = destination;
    }
  else
    {
      key->endpoint_a = destination;
      key->endpoint_b = source;
    }
}

static uint64_t
hash_byte (uint64_t hash, uint8_t value)
{
  return (hash ^ value) * UINT64_C (1099511628211);
}

static uint64_t
hash_bytes (uint64_t hash, const uint8_t *value, size_t length)
{
  size_t index;
  for (index = 0; index < length; index++)
    hash = hash_byte (hash, value[index]);
  return hash;
}

static uint16_t
select_owner (const product_worker_layout_t *layout, uint32_t flow_domain,
              const product_canonical_flow_key_t *key)
{
  uint64_t hash = UINT64_C (14695981039346656037) ^ layout->hash_seed;
  uint8_t domain[4] = {
    (uint8_t) (flow_domain >> 24),
    (uint8_t) (flow_domain >> 16),
    (uint8_t) (flow_domain >> 8),
    (uint8_t) flow_domain,
  };
  uint8_t port[2];

  hash = hash_bytes (hash, domain, sizeof (domain));
  hash = hash_byte (hash, key->ip_family);
  hash = hash_byte (hash, key->protocol);
  hash = hash_bytes (hash, key->endpoint_a.address,
                     sizeof (key->endpoint_a.address));
  port[0] = (uint8_t) (key->endpoint_a.port >> 8);
  port[1] = (uint8_t) key->endpoint_a.port;
  hash = hash_bytes (hash, port, sizeof (port));
  hash = hash_bytes (hash, key->endpoint_b.address,
                     sizeof (key->endpoint_b.address));
  port[0] = (uint8_t) (key->endpoint_b.port >> 8);
  port[1] = (uint8_t) key->endpoint_b.port;
  hash = hash_bytes (hash, port, sizeof (port));
  return (uint16_t) (hash % layout->worker_count);
}

product_packet_result_t
product_packet_owner_from_facts (const product_worker_layout_t *layout,
                                 uint32_t flow_domain,
                                 const product_packet_facts_t *facts,
                                 product_canonical_flow_key_t *key,
                                 uint16_t *owner)
{
  if (layout == NULL || facts == NULL || key == NULL || owner == NULL
      || layout->worker_count == 0
      || facts->l3_status != PRODUCT_PACKET_L3_COMPLETE
      || facts->l4_status != PRODUCT_PACKET_L4_COMPLETE)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  make_canonical_key (facts, key);
  *owner = select_owner (layout, flow_domain, key);
  return PRODUCT_PACKET_OK;
}

static product_packet_result_t
parse_transport (const uint8_t *packet, size_t packet_length,
                 size_t transport_offset, product_packet_facts_t *facts)
{
  size_t transport_length;
  uint16_t declared_length;

  if (transport_offset > packet_length)
    {
      facts->l4_status = PRODUCT_PACKET_L4_INVALID_OR_UNAVAILABLE;
      return PRODUCT_PACKET_OK;
    }
  transport_length = packet_length - transport_offset;
  facts->transport_offset = (uint16_t) transport_offset;
  facts->transport_length = (uint16_t) transport_length;
  if (facts->protocol == PRODUCT_IP_PROTOCOL_TCP)
    {
      uint8_t header_length;
      if (transport_length < 20)
        {
          facts->l4_status = PRODUCT_PACKET_L4_INVALID_OR_UNAVAILABLE;
          return PRODUCT_PACKET_OK;
        }
      header_length = (uint8_t) ((packet[transport_offset + 12] >> 4) * 4U);
      if (header_length < 20 || header_length > transport_length)
        {
          facts->l4_status = PRODUCT_PACKET_L4_INVALID_OR_UNAVAILABLE;
          return PRODUCT_PACKET_OK;
        }
      /* Validate options before exposing any complete TCP facts. */
      size_t option = 20;
      uint8_t scale = 0, scale_known = 0;
      while (option < header_length)
        {
          const uint8_t *value = packet + transport_offset + option;
          if (value[0] == 0)
            break;
          if (value[0] == 1)
            {
              option++;
              continue;
            }
          if (option + 2 > header_length || value[1] < 2
              || option + value[1] > header_length
              || (value[0] == 3 && (value[1] != 3 || scale_known)))
            return PRODUCT_PACKET_OK;
          if (value[0] == 3)
            {
              scale = value[2] > 14 ? 14 : value[2];
              scale_known = 1;
            }
          option += value[1];
        }
      facts->tcp_sequence = read_be32 (packet + transport_offset + 4);
      facts->tcp_acknowledgment = read_be32 (packet + transport_offset + 8);
      facts->tcp_flags = packet[transport_offset + 13];
      facts->tcp_window = read_be16 (packet + transport_offset + 14);
      facts->tcp_window_scale = scale;
      facts->tcp_window_scale_known = scale_known;
      facts->l4_header_length = header_length;
    }
  else if (facts->protocol == PRODUCT_IP_PROTOCOL_UDP)
    {
      if (transport_length < 8)
        {
          facts->l4_status = PRODUCT_PACKET_L4_INVALID_OR_UNAVAILABLE;
          return PRODUCT_PACKET_OK;
        }
      declared_length = read_be16 (packet + transport_offset + 4);
      if (declared_length < 8 || declared_length > transport_length)
        {
          facts->l4_status = PRODUCT_PACKET_L4_INVALID_OR_UNAVAILABLE;
          return PRODUCT_PACKET_OK;
        }
      facts->l4_header_length = 8;
    }
  else if ((facts->ip_family == 4 && facts->protocol == 1)
           || (facts->ip_family == 6 && facts->protocol == 58))
    {
      if (transport_length < 8)
        return PRODUCT_PACKET_OK;
      facts->icmp_type = packet[transport_offset];
      facts->icmp_code = packet[transport_offset + 1];
      facts->l4_header_length = 8;
      if (facts->icmp_code == 0
          && ((facts->ip_family == 4
               && (facts->icmp_type == 0 || facts->icmp_type == 8))
              || (facts->ip_family == 6
                  && (facts->icmp_type == 128 || facts->icmp_type == 129))))
        {
          facts->icmp_identifier = read_be16 (packet + transport_offset + 4);
          facts->icmp_sequence = read_be16 (packet + transport_offset + 6);
          facts->icmp_identity_known = 1;
        }
      facts->l4_status = PRODUCT_PACKET_L4_OTHER_TERMINAL;
      return PRODUCT_PACKET_OK;
    }
  else
    {
      facts->l4_status = PRODUCT_PACKET_L4_OTHER_TERMINAL;
      return PRODUCT_PACKET_OK;
    }

  facts->source_port = read_be16 (packet + transport_offset);
  facts->destination_port = read_be16 (packet + transport_offset + 2);
  facts->l4_status = PRODUCT_PACKET_L4_COMPLETE;
  return PRODUCT_PACKET_OK;
}

static product_packet_result_t
parse_ipv4 (const uint8_t *packet, size_t length,
            product_packet_facts_t *facts)
{
  size_t header_length;
  uint16_t packet_length;
  uint16_t fragment;

  if (length < 20)
    return PRODUCT_PACKET_TRUNCATED_ENVELOPE;
  header_length = (size_t) (packet[0] & 0x0fU) * 4U;
  packet_length = read_be16 (packet + 2);
  if (header_length < 20 || packet_length < header_length)
    return PRODUCT_PACKET_INVALID_L3;
  if (header_length > length || packet_length > length)
    return PRODUCT_PACKET_TRUNCATED_ENVELOPE;
  fragment = read_be16 (packet + 6);
  if ((fragment & UINT16_C (0x3fff)) != 0)
    return PRODUCT_PACKET_INVALID_L3;

  facts->ip_family = 4;
  facts->protocol = packet[9];
  memcpy (facts->source_address + 12, packet + 12, 4);
  memcpy (facts->destination_address + 12, packet + 16, 4);
  facts->l3_header_length = (uint16_t) header_length;
  facts->packet_length = packet_length;
  facts->l3_status = PRODUCT_PACKET_L3_COMPLETE;
  return parse_transport (packet, packet_length, header_length, facts);
}

static product_packet_result_t
parse_ipv6 (const uint8_t *packet, size_t length,
            product_packet_facts_t *facts)
{
  size_t packet_length;

  if (length < 40)
    return PRODUCT_PACKET_TRUNCATED_ENVELOPE;
  packet_length = 40U + read_be16 (packet + 4);
  if (packet_length > length)
    return PRODUCT_PACKET_TRUNCATED_ENVELOPE;
  if (packet_length > UINT32_MAX)
    return PRODUCT_PACKET_INVALID_L3;

  facts->ip_family = 6;
  facts->protocol = packet[6];
  memcpy (facts->source_address, packet + 8, 16);
  memcpy (facts->destination_address, packet + 24, 16);
  facts->l3_header_length = 40;
  facts->packet_length = (uint32_t) packet_length;
  facts->l3_status = PRODUCT_PACKET_L3_COMPLETE;
  return parse_transport (packet, packet_length, 40, facts);
}

product_packet_result_t
product_packet_admit (const product_worker_layout_t *layout,
                      const product_packet_ingress_t *ingress,
                      product_packet_lease_t *lease)
{
  product_packet_result_t result;
  uint8_t version;

  if (layout == NULL || ingress == NULL || lease == NULL
      || ingress->data == NULL || layout->worker_count == 0
      || ingress->current_worker >= layout->worker_count
      || ingress->origin_obligation_id == 0)
    return PRODUCT_PACKET_INVALID_ARGUMENT;

  memset (lease, 0, sizeof (*lease));
  lease->origin_obligation_id = ingress->origin_obligation_id;
  lease->platform = ingress->platform;
  if (ingress->length == 0)
    result = PRODUCT_PACKET_TRUNCATED_ENVELOPE;
  else
    {
      version = ingress->data[0] >> 4;
      if (version == 4)
        result = parse_ipv4 (ingress->data, ingress->length, &lease->facts);
      else if (version == 6)
        result = parse_ipv6 (ingress->data, ingress->length, &lease->facts);
      else
        result = PRODUCT_PACKET_UNSUPPORTED_ENVELOPE;
    }
  if (result != PRODUCT_PACKET_OK)
    {
      if (result == PRODUCT_PACKET_INVALID_L3
          || result == PRODUCT_PACKET_TRUNCATED_ENVELOPE
          || result == PRODUCT_PACKET_UNSUPPORTED_ENVELOPE)
        {
          memset (&lease->facts, 0, sizeof (lease->facts));
          lease->expected_owner = ingress->current_worker;
          lease->terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
          lease->terminal_count = 1;
          if (result == PRODUCT_PACKET_INVALID_L3)
            lease->runtime_drop_reason =
              PRODUCT_PACKET_DROP_INVALID_ENVELOPE;
          else if (result == PRODUCT_PACKET_TRUNCATED_ENVELOPE)
            lease->runtime_drop_reason =
              PRODUCT_PACKET_DROP_TRUNCATED_ENVELOPE;
          else
            lease->runtime_drop_reason =
              PRODUCT_PACKET_DROP_UNSUPPORTED_ENVELOPE;
        }
      return result;
    }

  make_canonical_key (&lease->facts, &lease->canonical_key);
  lease->expected_owner = select_owner (layout, ingress->flow_domain,
                                        &lease->canonical_key);
  if (lease->expected_owner == ingress->current_worker)
    lease->distribution = PRODUCT_PACKET_DISTRIBUTION_LOCAL;
  else
    {
      lease->distribution = PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE;
      lease->primary_handoff_count = 1;
    }
  return PRODUCT_PACKET_OK;
}

product_packet_result_t
product_packet_owner_guard (product_packet_lease_t *lease,
                            uint16_t current_worker)
{
  if (lease == NULL)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  if (current_worker != lease->expected_owner)
    {
      if (lease->corrective_handoff_count == 0)
        {
          lease->corrective_handoff_count = 1;
          return PRODUCT_PACKET_CORRECTIVE_HANDOFF;
        }
      if (lease->terminal_count == 0 && !lease->settled)
        {
          lease->terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
          lease->terminal_count = 1;
          lease->runtime_drop_reason =
            PRODUCT_PACKET_DROP_REPEATED_OWNER_MISMATCH;
        }
      return PRODUCT_PACKET_REPEATED_OWNER_MISMATCH;
    }
  lease->policy_owner_ready = 1;
  return PRODUCT_PACKET_OK;
}

product_packet_result_t
product_packet_set_terminal (product_packet_lease_t *lease,
                             product_packet_terminal_intent_t intent)
{
  if (lease == NULL || intent == PRODUCT_PACKET_INTENT_NONE)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  if (!lease->policy_owner_ready || lease->terminal_count != 0 || lease->settled)
    return PRODUCT_PACKET_ORDER_VIOLATION;
  lease->terminal_intent = (uint8_t) intent;
  lease->terminal_count = 1;
  return PRODUCT_PACKET_OK;
}

product_packet_result_t
product_packet_settle (product_packet_lease_t *lease)
{
  if (lease == NULL)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  if (lease->settled)
    return PRODUCT_PACKET_ALREADY_SETTLED;
  if (lease->terminal_count != 1
      || lease->terminal_intent == PRODUCT_PACKET_INTENT_NONE)
    return PRODUCT_PACKET_ORDER_VIOLATION;
  if (!lease->policy_owner_ready
      && !(lease->terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME
           && lease->runtime_drop_reason != PRODUCT_PACKET_DROP_NONE))
    return PRODUCT_PACKET_ORDER_VIOLATION;
  lease->settled = 1;
  return PRODUCT_PACKET_OK;
}
