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

static uint64_t
hash_byte (uint64_t hash, uint8_t value)
{
  return (hash ^ value) * UINT64_C (1099511628211);
}

static uint64_t
hash_bytes (uint64_t hash, const uint8_t *value, size_t length)
{
  for (size_t index = 0; index < length; index++)
    hash = hash_byte (hash, value[index]);
  return hash;
}

static uint64_t
hash_u16 (uint64_t hash, uint16_t value)
{
  return hash_byte (hash_byte (hash, (uint8_t) (value >> 8)), (uint8_t) value);
}

product_packet_result_t
product_owner_assign (const product_worker_layout_t *layout,
                      const product_packet_facts_t *facts,
                      product_owner_assignment_t *assignment)
{
  if (assignment == NULL)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  memset (assignment, 0, sizeof (*assignment));
  assignment->execution_owner = PRODUCT_EXECUTION_OWNER_UNKNOWN;
  if (layout == NULL || facts == NULL || layout->worker_count == 0)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  if (facts->l3_status != PRODUCT_PACKET_L3_COMPLETE
      || (facts->ip_family != 4 && facts->ip_family != 6))
    return PRODUCT_PACKET_INVALID_L3;

  product_canonical_owner_key_t *key = &assignment->key;
  product_packet_endpoint_t source = {0}, destination = {0};
  key->kind = PRODUCT_OWNER_KEY_L3;
  key->ip_family = facts->ip_family;
  key->protocol = facts->protocol;
  if (facts->l4_status == PRODUCT_PACKET_L4_COMPLETE
      && (facts->protocol == PRODUCT_IP_PROTOCOL_TCP
          || facts->protocol == PRODUCT_IP_PROTOCOL_UDP))
    {
      key->kind = PRODUCT_OWNER_KEY_L4_PORTS;
      source.port = facts->source_port;
      destination.port = facts->destination_port;
    }
  else if (facts->icmp_identity_known && facts->icmp_code == 0
           && ((facts->ip_family == 4 && facts->protocol == 1
                && (facts->icmp_type == 8 || facts->icmp_type == 0))
               || (facts->ip_family == 6 && facts->protocol == 58
                   && (facts->icmp_type == 128 || facts->icmp_type == 129))))
    {
      key->kind = PRODUCT_OWNER_KEY_ICMP_QUERY;
      key->query_class = PRODUCT_ICMP_QUERY_ECHO;
      key->transport.query.identifier = facts->icmp_identifier;
    }
  memcpy (source.address, facts->source_address, 16);
  memcpy (destination.address, facts->destination_address, 16);
  assignment->source_is_a = endpoint_compare (&source, &destination) <= 0;
  const product_packet_endpoint_t *a = assignment->source_is_a ? &source : &destination;
  const product_packet_endpoint_t *b = assignment->source_is_a ? &destination : &source;
  memcpy (key->address_a, a->address, 16);
  memcpy (key->address_b, b->address, 16);
  if (key->kind == PRODUCT_OWNER_KEY_L4_PORTS)
    {
      key->transport.ports.a = a->port;
      key->transport.ports.b = b->port;
    }

  uint64_t hash = UINT64_C (14695981039346656037) ^ layout->hash_seed;
  hash = hash_byte (hash, key->kind);
  hash = hash_byte (hash, key->ip_family);
  hash = hash_byte (hash, key->protocol);
  hash = hash_bytes (hash, key->address_a, 16);
  hash = hash_bytes (hash, key->address_b, 16);
  if (key->kind == PRODUCT_OWNER_KEY_L4_PORTS)
    {
      hash = hash_u16 (hash, key->transport.ports.a);
      hash = hash_u16 (hash, key->transport.ports.b);
    }
  else if (key->kind == PRODUCT_OWNER_KEY_ICMP_QUERY)
    {
      hash = hash_byte (hash, key->query_class);
      hash = hash_u16 (hash, key->transport.query.identifier);
    }
  assignment->canonical_hash = hash;
  assignment->execution_owner = (uint16_t) (hash % layout->worker_count);
  assignment->valid = 1;
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
  lease->assignment.execution_owner = PRODUCT_EXECUTION_OWNER_UNKNOWN;
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

  result = product_owner_assign (layout, &lease->facts, &lease->assignment);
  if (result != PRODUCT_PACKET_OK)
    return result;
  if (lease->assignment.execution_owner == ingress->current_worker)
    lease->distribution = PRODUCT_PACKET_DISTRIBUTION_LOCAL;
  else
    {
      lease->distribution = PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE;
      lease->primary_handoff_count = 1;
    }
  return PRODUCT_PACKET_OK;
}

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
product_packet_result_t
product_packet_owner_guard (product_packet_lease_t *lease,
                            uint16_t current_worker)
{
  if (lease == NULL)
    return PRODUCT_PACKET_INVALID_ARGUMENT;
  if (current_worker != lease->assignment.execution_owner)
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
#endif

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
