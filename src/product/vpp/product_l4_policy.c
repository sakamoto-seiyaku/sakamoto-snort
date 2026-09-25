/* SPDX-License-Identifier: Apache-2.0 */

#include "product_l4_policy.h"

#include <string.h>

static int
supported_family (uint8_t family)
{
  return family == PRODUCT_L4_POLICY_FAMILY_IPV4
         || family == PRODUCT_L4_POLICY_FAMILY_IPV6;
}

static int
supported_protocol (uint8_t protocol)
{
  return protocol == PRODUCT_L4_POLICY_PROTOCOL_TCP
         || protocol == PRODUCT_L4_POLICY_PROTOCOL_UDP;
}

static int
supported_direction (uint8_t direction)
{
  return direction == PRODUCT_L4_POLICY_DIRECTION_ANY
         || direction == PRODUCT_L4_POLICY_DIRECTION_INPUT
         || direction == PRODUCT_L4_POLICY_DIRECTION_OUTPUT;
}

static size_t
address_bytes (uint8_t family)
{
  return family == PRODUCT_L4_POLICY_FAMILY_IPV4 ? 4U : 16U;
}

static int
ipv4_address_is_canonical (const uint8_t address[PRODUCT_L4_POLICY_ADDRESS_BYTES])
{
  size_t index;
  for (index = 4; index < PRODUCT_L4_POLICY_ADDRESS_BYTES; index++)
    if (address[index] != 0)
      return 0;
  return 1;
}

static int
ports_are_valid (uint16_t first, uint16_t last)
{
  return first <= last;
}

static int
rule_precedes (const product_l4_policy_rule_t *left,
               const product_l4_policy_rule_t *right)
{
  if (left->uid != right->uid)
    return left->uid < right->uid;
  if (left->priority != right->priority)
    return left->priority < right->priority;
  if (left->order != right->order)
    return left->order < right->order;
  return left->rule_id < right->rule_id;
}

static product_l4_policy_status_t
validate_rule (const product_l4_policy_rule_t *rule)
{
  if (rule == NULL || (rule->family && !supported_family (rule->family))
      || (rule->protocol && !supported_protocol (rule->protocol))
      || !supported_direction (rule->direction)
      || rule->uid == UINT32_MAX || rule->rule_id == 0
      || rule->reason_id == 0 || rule->mode > 1
      || (rule->action != PRODUCT_L4_POLICY_ACTION_ALLOW
          && rule->action != PRODUCT_L4_POLICY_ACTION_DROP)
      || rule->source_prefix_length
           > (rule->family == PRODUCT_L4_POLICY_FAMILY_IPV4 ? 32U : 128U)
      || rule->destination_prefix_length
           > (rule->family == PRODUCT_L4_POLICY_FAMILY_IPV4 ? 32U : 128U)
      || !ports_are_valid (rule->source_port_first,
                           rule->source_port_last)
      || !ports_are_valid (rule->destination_port_first,
                           rule->destination_port_last))
    return PRODUCT_L4_POLICY_STATUS_INVALID_RULE;

  if ((!rule->family && (rule->source_prefix_length || rule->destination_prefix_length
                        || memcmp(rule->source_address, (uint8_t[16]){0}, 16)
                        || memcmp(rule->destination_address, (uint8_t[16]){0}, 16))))
    return PRODUCT_L4_POLICY_STATUS_INVALID_RULE;
  if (rule->family == PRODUCT_L4_POLICY_FAMILY_IPV4
      && (!ipv4_address_is_canonical (rule->source_address)
          || !ipv4_address_is_canonical (rule->destination_address)))
    return PRODUCT_L4_POLICY_STATUS_INVALID_RULE;

  return PRODUCT_L4_POLICY_STATUS_OK;
}

static void
insert_compiled_rule (product_l4_policy_view_t *view,
                      const product_l4_policy_rule_t *rule)
{
  uint32_t index = view->rule_count;
  while (index > 0
         && rule_precedes (rule, &view->rules[index - 1].source))
    {
      view->rules[index] = view->rules[index - 1];
      index--;
    }
  view->rules[index].source = *rule;
  view->rules[index].winner_rank = 0;
  view->rule_count++;
}

void
product_l4_policy_init (product_l4_policy_view_t *view)
{
  if (view != NULL)
    memset (view, 0, sizeof (*view));
}

product_l4_policy_status_t
product_l4_policy_compile (product_l4_policy_view_t *view,
                           const product_l4_policy_rule_t *rules,
                           size_t rule_count)
{
  size_t input_index;
  uint32_t bucket_index;
  uint32_t rule_index;

  if (view == NULL || (rule_count != 0 && rules == NULL))
    return PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT;
  if (rule_count > PRODUCT_L4_POLICY_MAX_RULES)
    return PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED;

  for (input_index = 0; input_index < rule_count; input_index++)
    {
      product_l4_policy_status_t status = validate_rule (&rules[input_index]);
      size_t prior_index;
      if (status != PRODUCT_L4_POLICY_STATUS_OK)
        return status;
      for (prior_index = 0; prior_index < input_index; prior_index++)
        if (rules[prior_index].rule_id == rules[input_index].rule_id
            && rules[prior_index].uid == rules[input_index].uid)
          return PRODUCT_L4_POLICY_STATUS_DUPLICATE_RULE_ID;
    }

  /* All validation completes before replacing the caller's old view. */
  product_l4_policy_init (view);
  for (input_index = 0; input_index < rule_count; input_index++)
    insert_compiled_rule (view, &rules[input_index]);

  bucket_index = 0;
  rule_index = 0;
  while (rule_index < view->rule_count)
    {
      uint32_t first_rule = rule_index;
      uint32_t rank = 1;
      uint32_t uid = view->rules[rule_index].source.uid;

      while (rule_index < view->rule_count
             && view->rules[rule_index].source.uid == uid)
        {
          view->rules[rule_index].winner_rank = rank++;
          rule_index++;
        }

      view->uid_buckets[bucket_index].uid = uid;
      view->uid_buckets[bucket_index].first_rule = first_rule;
      view->uid_buckets[bucket_index].rule_count = rule_index - first_rule;
      if (view->uid_buckets[bucket_index].rule_count > view->max_probes)
        view->max_probes = view->uid_buckets[bucket_index].rule_count;
      bucket_index++;
    }
  view->uid_bucket_count = bucket_index;
  return PRODUCT_L4_POLICY_STATUS_OK;
}

static int
address_matches (uint8_t family,
                 const uint8_t rule_address[PRODUCT_L4_POLICY_ADDRESS_BYTES],
                 const uint8_t packet_address[PRODUCT_L4_POLICY_ADDRESS_BYTES],
                 uint8_t prefix_length)
{
  /* Both supported families use the same 16-byte, first-byte-aligned shape. */
  const size_t offset = 0;
  size_t bytes = address_bytes (family);
  size_t full_bytes = prefix_length / 8U;
  uint8_t remaining_bits = (uint8_t) (prefix_length % 8U);
  size_t index;

  for (index = 0; index < full_bytes; index++)
    if (rule_address[offset + index] != packet_address[offset + index])
      return 0;
  if (remaining_bits != 0 && full_bytes < bytes)
    {
      uint8_t mask = (uint8_t) (UINT8_C (0xff) << (8U - remaining_bits));
      if ((rule_address[offset + full_bytes] & mask)
          != (packet_address[offset + full_bytes] & mask))
        return 0;
    }
  return 1;
}

static int
port_matches (uint16_t value, uint16_t first, uint16_t last)
{
  return value >= first && value <= last;
}

static int
rule_requires_ports (const product_l4_policy_rule_t *rule)
{
  return rule->source_port_first != PRODUCT_L4_POLICY_PORT_FIRST_ANY
         || rule->source_port_last != PRODUCT_L4_POLICY_PORT_LAST_ANY
         || rule->destination_port_first != PRODUCT_L4_POLICY_PORT_FIRST_ANY
         || rule->destination_port_last != PRODUCT_L4_POLICY_PORT_LAST_ANY;
}

static int
rule_matches (const product_l4_policy_rule_t *rule,
              const product_l4_policy_packet_t *packet)
{
  if ((rule->family && rule->family != packet->family)
      || (rule->protocol && rule->protocol != packet->protocol))
    return 0;
  if (rule->direction != PRODUCT_L4_POLICY_DIRECTION_ANY
      && (!packet->direction_known || rule->direction != packet->direction))
    return 0;
  if (rule->network_context_id != PRODUCT_L4_POLICY_NETWORK_CONTEXT_ANY
      && (!packet->network_context_known
          || rule->network_context_id != packet->network_context_id))
    return 0;
  if (rule->ifindex != PRODUCT_L4_POLICY_IFINDEX_ANY
      && (!packet->ifindex_known || rule->ifindex != packet->ifindex))
    return 0;
  int ports_available = packet->ports_available && supported_protocol (packet->protocol);
  if (!ports_available && rule_requires_ports (rule))
    return 0;
  return address_matches (rule->family, rule->source_address,
                          packet->source_address,
                          rule->source_prefix_length)
         && address_matches (rule->family, rule->destination_address,
                             packet->destination_address,
                             rule->destination_prefix_length)
         && (!ports_available
             || (port_matches (packet->source_port, rule->source_port_first,
                               rule->source_port_last)
                 && port_matches (packet->destination_port,
                                  rule->destination_port_first,
                                  rule->destination_port_last)));
}

static const product_l4_policy_uid_bucket_t *
find_uid_bucket (const product_l4_policy_view_t *view, uint32_t uid,
                 uint32_t *subject_probes)
{
  uint32_t low = 0;
  uint32_t high = view->uid_bucket_count;
  while (low < high)
    {
      uint32_t middle = low + (high - low) / 2U;
      (*subject_probes)++;
      if (view->uid_buckets[middle].uid == uid)
        return &view->uid_buckets[middle];
      if (view->uid_buckets[middle].uid < uid)
        low = middle + 1U;
      else
        high = middle;
    }
  return NULL;
}

static void
set_no_match (product_l4_policy_match_result_t *result,
              uint8_t reason, uint32_t probe_limit)
{
  memset (result, 0, sizeof (*result));
  result->evaluation = PRODUCT_L4_POLICY_EVALUATION_NO_MATCH;
  result->stage_verdict = PRODUCT_L4_POLICY_VERDICT_PASS_NEXT;
  result->action = PRODUCT_L4_POLICY_ACTION_NONE;
  result->no_match_reason = reason;
  result->probe_limit = probe_limit;
}

product_l4_policy_status_t
product_l4_policy_match (const product_l4_policy_view_t *view,
                         const product_l4_policy_packet_t *packet,
                         product_l4_policy_match_result_t *result)
{
  const product_l4_policy_uid_bucket_t *bucket;
  uint32_t index;

  if (view == NULL || packet == NULL || result == NULL)
    return PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT;

  set_no_match (result, PRODUCT_L4_POLICY_NO_MATCH_NO_RULE,
                view->max_probes);
  if (!packet->uid_known || packet->uid == UINT32_MAX)
    {
      result->no_match_reason = PRODUCT_L4_POLICY_NO_MATCH_UNKNOWN_UID;
      return PRODUCT_L4_POLICY_STATUS_OK;
    }
  if (!supported_family (packet->family))
    {
      result->no_match_reason = PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_FAMILY;
      return PRODUCT_L4_POLICY_STATUS_OK;
    }
  if (packet->direction_known && !supported_direction (packet->direction))
    {
      result->no_match_reason = PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_DIRECTION;
      return PRODUCT_L4_POLICY_STATUS_OK;
    }

  bucket = find_uid_bucket (view, packet->uid, &result->subject_probes);
  if (bucket == NULL)
    {
      result->no_match_reason = PRODUCT_L4_POLICY_NO_MATCH_NO_SUBJECT;
      return PRODUCT_L4_POLICY_STATUS_OK;
    }

  result->candidate_count = bucket->rule_count;
  result->probe_limit = bucket->rule_count;
  for (index = 0; index < bucket->rule_count; index++)
    {
      const product_l4_policy_compiled_rule_t *compiled =
        &view->rules[bucket->first_rule + index];
      result->probes++;
      if (rule_matches (&compiled->source, packet))
        {
          result->evaluation = PRODUCT_L4_POLICY_EVALUATION_MATCH;
          result->action = compiled->source.action;
          result->mode = compiled->source.mode;
          result->actual_action = result->mode ? PRODUCT_L4_POLICY_ACTION_ALLOW : result->action;
          result->stage_verdict =
            result->actual_action == PRODUCT_L4_POLICY_ACTION_DROP
              ? PRODUCT_L4_POLICY_VERDICT_DROP
              : PRODUCT_L4_POLICY_VERDICT_PASS_NEXT;
          result->no_match_reason = PRODUCT_L4_POLICY_NO_MATCH_NONE;
          result->rule_id = compiled->source.rule_id;
          result->reason_id = compiled->source.reason_id;
          result->priority = compiled->source.priority;
          result->order = compiled->source.order;
          result->winner_rank = compiled->winner_rank;
          return PRODUCT_L4_POLICY_STATUS_OK;
        }
    }
  result->no_match_reason = packet->ports_available
                              ? PRODUCT_L4_POLICY_NO_MATCH_NO_RULE
                              : PRODUCT_L4_POLICY_NO_MATCH_L4_UNAVAILABLE;
  return PRODUCT_L4_POLICY_STATUS_OK;
}

product_l4_policy_status_t
product_l4_policy_evaluate (const product_l4_policy_view_t *view,
                            const product_l4_policy_packet_t *packet,
                            product_l4_policy_match_result_t *result)
{
  return product_l4_policy_match (view, packet, result);
}

product_l4_policy_status_t
product_l4_policy_rule_rank (const product_l4_policy_view_t *view,
                             uint64_t rule_id, uint32_t *winner_rank)
{
  uint32_t index;
  if (view == NULL || winner_rank == NULL)
    return PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT;
  for (index = 0; index < view->rule_count; index++)
    if (view->rules[index].source.rule_id == rule_id)
      {
        *winner_rank = view->rules[index].winner_rank;
        return PRODUCT_L4_POLICY_STATUS_OK;
      }
  *winner_rank = 0;
  return PRODUCT_L4_POLICY_STATUS_NOT_FOUND;
}
