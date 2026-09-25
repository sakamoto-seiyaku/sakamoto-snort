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

  return product_static_expression_validate (rule->expression, rule->expression_length);
}

static unsigned
expression_operand_bytes (unsigned op)
{
  if ((op >= PRODUCT_STATIC_FAMILY && op <= PRODUCT_STATIC_DIRECTION)
      || op == PRODUCT_EXPRESSION_CT_STATE || op == PRODUCT_EXPRESSION_FLOW_DIRECTION)
    return 1;
  if (op == PRODUCT_STATIC_NETWORK || op == PRODUCT_STATIC_INTERFACE
      || op == PRODUCT_STATIC_SOURCE_PORT || op == PRODUCT_STATIC_DESTINATION_PORT)
    return 4;
  if (op == PRODUCT_STATIC_SOURCE_CIDR || op == PRODUCT_STATIC_DESTINATION_CIDR)
    return 18;
  return 0;
}

/* Validated source only; skip operands so data bytes cannot become dependencies. */
static int
expression_requires_flow (const product_l4_policy_rule_t *rule)
{
  for (unsigned at = 0; at < rule->expression_length;)
    {
      unsigned op = rule->expression[at++];
      if (op == PRODUCT_EXPRESSION_CT_STATE || op == PRODUCT_EXPRESSION_FLOW_DIRECTION)
        return 1;
      if (op <= PRODUCT_STATIC_NOT) continue;
      at += expression_operand_bytes (op);
    }
  return 0;
}

/* Rectangular over-approximation of packets for which the whole rule may be
 * true. NOT and non-static leaves widen to universal. AND intersects and OR
 * takes the hull; no distribution, SAT search or CT-history assumption. */
enum envelope_axis {
  ENVELOPE_FAMILY, ENVELOPE_PROTOCOL, ENVELOPE_DIRECTION,
  ENVELOPE_SOURCE_PORT, ENVELOPE_DESTINATION_PORT, ENVELOPE_AXES
};

typedef struct {
  uint16_t low[ENVELOPE_AXES], high[ENVELOPE_AXES];
  uint8_t address_low[2][16], address_high[2][16];
  uint8_t empty;
} static_envelope_t;

static static_envelope_t
envelope_any (void)
{
  static_envelope_t e = {0};
  for (unsigned i = 0; i < ENVELOPE_AXES; ++i) e.high[i] = UINT16_MAX;
  memset (e.address_high, 255, sizeof e.address_high);
  return e;
}

static static_envelope_t
envelope_combine (static_envelope_t a, static_envelope_t b, int intersection)
{
  if (a.empty) return intersection ? a : b;
  if (b.empty) return intersection ? b : a;
  for (unsigned i = 0; i < ENVELOPE_AXES; ++i)
    {
      if ((a.low[i] < b.low[i]) == intersection) a.low[i] = b.low[i];
      if ((a.high[i] > b.high[i]) == intersection) a.high[i] = b.high[i];
      if (a.low[i] > a.high[i]) a.empty = 1;
    }
  for (unsigned i = 0; i < 2; ++i)
    {
      if ((memcmp (a.address_low[i], b.address_low[i], 16) < 0) == intersection)
        memcpy (a.address_low[i], b.address_low[i], 16);
      if ((memcmp (a.address_high[i], b.address_high[i], 16) > 0) == intersection)
        memcpy (a.address_high[i], b.address_high[i], 16);
      if (memcmp (a.address_low[i], a.address_high[i], 16) > 0) a.empty = 1;
    }
  return a;
}

static void
envelope_cidr (static_envelope_t *e, unsigned side, unsigned family,
               unsigned prefix, const uint8_t *address)
{
  e->low[ENVELOPE_FAMILY] = e->high[ENVELOPE_FAMILY] = family;
  for (unsigned i = 0; i < 16; ++i)
    {
      unsigned bits = prefix > 8 ? 8 : prefix;
      uint8_t mask = bits ? (uint8_t) (255U << (8 - bits)) : 0;
      e->address_low[side][i] = address[i] & mask;
      e->address_high[side][i] = address[i] | (uint8_t) ~mask;
      prefix -= bits;
    }
}

static static_envelope_t
rule_envelope (const product_l4_policy_rule_t *rule)
{
  static_envelope_t base = envelope_any ();
  if (rule->family) base.low[ENVELOPE_FAMILY] = base.high[ENVELOPE_FAMILY] = rule->family;
  if (rule->protocol) base.low[ENVELOPE_PROTOCOL] = base.high[ENVELOPE_PROTOCOL] = rule->protocol;
  if (rule->direction) base.low[ENVELOPE_DIRECTION] = base.high[ENVELOPE_DIRECTION] = rule->direction;
  base.low[ENVELOPE_SOURCE_PORT] = rule->source_port_first; base.high[ENVELOPE_SOURCE_PORT] = rule->source_port_last;
  base.low[ENVELOPE_DESTINATION_PORT] = rule->destination_port_first; base.high[ENVELOPE_DESTINATION_PORT] = rule->destination_port_last;
  if (rule->source_prefix_length)
    envelope_cidr (&base, 0, rule->family, rule->source_prefix_length, rule->source_address);
  if (rule->destination_prefix_length)
    envelope_cidr (&base, 1, rule->family, rule->destination_prefix_length, rule->destination_address);
  static_envelope_t stack[PRODUCT_STATIC_EXPRESSION_BYTES];
  unsigned depth = 0;
  for (unsigned at = 0; at < rule->expression_length;)
    {
      unsigned op = rule->expression[at++];
      const uint8_t *arg = rule->expression + at;
      static_envelope_t e = envelope_any ();
      if (op == PRODUCT_STATIC_NOT) --depth;
      else if (op == PRODUCT_STATIC_AND || op == PRODUCT_STATIC_OR)
        {
          static_envelope_t right = stack[--depth], left = stack[--depth];
          e = envelope_combine (left, right, op == PRODUCT_STATIC_AND);
        }
      else
        {
          if (op >= PRODUCT_STATIC_FAMILY && op <= PRODUCT_STATIC_DIRECTION)
            {
              enum envelope_axis axis = op == PRODUCT_STATIC_FAMILY ? ENVELOPE_FAMILY
                : op == PRODUCT_STATIC_PROTOCOL ? ENVELOPE_PROTOCOL : ENVELOPE_DIRECTION;
              e.low[axis] = e.high[axis] = arg[0];
            }
          else if (op == PRODUCT_STATIC_SOURCE_PORT || op == PRODUCT_STATIC_DESTINATION_PORT)
            {
              enum envelope_axis i = op == PRODUCT_STATIC_SOURCE_PORT
                ? ENVELOPE_SOURCE_PORT : ENVELOPE_DESTINATION_PORT;
              e.low[i] = arg[0] | (uint16_t) arg[1] << 8;
              e.high[i] = arg[2] | (uint16_t) arg[3] << 8;
            }
          else if (op == PRODUCT_STATIC_SOURCE_CIDR || op == PRODUCT_STATIC_DESTINATION_CIDR)
            envelope_cidr (&e, op == PRODUCT_STATIC_DESTINATION_CIDR, arg[0], arg[1], arg + 2);
          at += expression_operand_bytes (op);
        }
      stack[depth++] = e;
    }
  return depth ? envelope_combine (base, stack[0], 1) : base;
}

static void
place_rules (product_l4_policy_view_t *view)
{
  static_envelope_t envelopes[PRODUCT_L4_POLICY_MAX_RULES];
  /* Fixed compile-only proof budget. Exhaustion defers, never rejects or
   * truncates matching. Every propagated rule remains a constraint. */
  unsigned budget = 4096;
  for (unsigned i = 0; i < view->rule_count; ++i)
    {
      product_l4_policy_compiled_rule_t *rule = &view->rules[i];
      envelopes[i] = rule_envelope (&rule->source);
      rule->position = expression_requires_flow (&rule->source)
        ? PRODUCT_L4_POLICY_POSITION_POST : PRODUCT_L4_POLICY_POSITION_PRE;
      for (unsigned j = 0; rule->position == PRODUCT_L4_POLICY_POSITION_PRE && j < i; ++j)
        if (view->rules[j].source.uid == rule->source.uid
            && view->rules[j].position == PRODUCT_L4_POLICY_POSITION_POST)
          {
            if (!budget || !envelope_combine (envelopes[i], envelopes[j], 1).empty)
              rule->position = PRODUCT_L4_POLICY_POSITION_POST;
            if (budget) --budget;
          }
    }
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

  place_rules (view);
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
          view->uid_buckets[bucket_index].requires_flow |=
            view->rules[rule_index].position == PRODUCT_L4_POLICY_POSITION_POST;
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

/* Source bytecode uses postfix operators and little-endian numeric operands.
 * Validation runs before publication; workers use only fixed query-local state. */
static uint32_t
expression_number (const uint8_t *at, unsigned bytes)
{
  uint32_t value = 0;
  for (unsigned i = 0; i < bytes; ++i)
    value |= (uint32_t) at[i] << (8 * i);
  return value;
}

product_l4_policy_status_t
product_static_expression_validate (const uint8_t *bytes, uint32_t length)
{
  if ((!bytes && length) || length > PRODUCT_STATIC_EXPRESSION_BYTES)
    return PRODUCT_L4_POLICY_STATUS_INVALID_RULE;
  if (!length)
    return PRODUCT_L4_POLICY_STATUS_OK;
  unsigned stack = 0, depths[PRODUCT_STATIC_EXPRESSION_BYTES], max_depth = 0;
  for (unsigned at = 0; at < length;)
    {
      unsigned op = bytes[at++], size = 0;
      if (op >= PRODUCT_STATIC_AND && op <= PRODUCT_STATIC_NOT)
        {
          unsigned arity = op == PRODUCT_STATIC_NOT ? 1 : 2;
          if (stack < arity)
            return PRODUCT_L4_POLICY_STATUS_INVALID_RULE;
          unsigned depth = depths[--stack];
          if (arity == 2)
            {
              unsigned left = depths[--stack];
              if (left > depth) depth = left;
            }
          depths[stack++] = ++depth;
          if (depth > max_depth) max_depth = depth;
          continue;
        }
      size = expression_operand_bytes (op);
      if (!size || size > length - at)
        return PRODUCT_L4_POLICY_STATUS_INVALID_RULE;
      const uint8_t *arg = bytes + at;
      if ((op == PRODUCT_EXPRESSION_CT_STATE && (arg[0] < 1 || arg[0] > 3))
          || (op == PRODUCT_EXPRESSION_FLOW_DIRECTION && (arg[0] < 1 || arg[0] > 2))
          || (op == PRODUCT_STATIC_FAMILY && !supported_family (arg[0]))
          || (op == PRODUCT_STATIC_DIRECTION && arg[0] != 1 && arg[0] != 3)
          || ((op == PRODUCT_STATIC_SOURCE_PORT || op == PRODUCT_STATIC_DESTINATION_PORT)
              && expression_number (arg, 2) > expression_number (arg + 2, 2))
          || ((op == PRODUCT_STATIC_SOURCE_CIDR || op == PRODUCT_STATIC_DESTINATION_CIDR)
              && (!supported_family (arg[0]) || arg[1] > (arg[0] == 4 ? 32 : 128)
                  || (arg[0] == 4 && !ipv4_address_is_canonical (arg + 2)))))
        return PRODUCT_L4_POLICY_STATUS_INVALID_RULE;
      at += size;
      depths[stack++] = 1;
      if (!max_depth) max_depth = 1;
    }
  if (stack != 1)
    return PRODUCT_L4_POLICY_STATUS_INVALID_RULE;
  return max_depth > PRODUCT_STATIC_EXPRESSION_DEPTH
           ? PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED : PRODUCT_L4_POLICY_STATUS_OK;
}

/* 0 false, 1 true, 2 unavailable: strong Kleene AND/OR/NOT. */
static int
expression_matches (const product_l4_policy_rule_t *rule,
                    const product_l4_policy_packet_t *packet)
{
  if (!rule->expression_length) return 1;
  uint8_t values[PRODUCT_STATIC_EXPRESSION_BYTES];
  unsigned stack = 0;
  for (unsigned at = 0; at < rule->expression_length;)
    {
      unsigned op = rule->expression[at++];
      const uint8_t *arg = rule->expression + at;
      uint8_t value = 2;
      if (op <= PRODUCT_STATIC_NOT)
        {
          uint8_t right = values[--stack];
          if (op == PRODUCT_STATIC_NOT) value = right == 2 ? 2 : !right;
          else
            {
              uint8_t left = values[--stack];
              value = op == PRODUCT_STATIC_AND ? (left == 0 || right == 0 ? 0 : left == 1 && right == 1 ? 1 : 2)
                              : (left == 1 || right == 1 ? 1 : left == 0 && right == 0 ? 0 : 2);
            }
        }
      else if (op == PRODUCT_EXPRESSION_CT_STATE || op == PRODUCT_EXPRESSION_FLOW_DIRECTION)
        {
          if (op == PRODUCT_EXPRESSION_CT_STATE && packet->ct_state_known)
            value = packet->ct_state == arg[0];
          if (op == PRODUCT_EXPRESSION_FLOW_DIRECTION && packet->flow_direction_known)
            value = packet->flow_direction == arg[0];
          ++at;
        }
      else if (op <= PRODUCT_STATIC_DIRECTION)
        {
          if (op == PRODUCT_STATIC_FAMILY) value = packet->family == arg[0];
          if (op == PRODUCT_STATIC_PROTOCOL) value = packet->protocol == arg[0];
          if (op == PRODUCT_STATIC_DIRECTION && packet->direction_known) value = packet->direction == arg[0];
          ++at;
        }
      else if (op == PRODUCT_STATIC_NETWORK || op == PRODUCT_STATIC_INTERFACE)
        {
          if (op == PRODUCT_STATIC_NETWORK && packet->network_context_known)
            value = packet->network_context_id == expression_number (arg, 4);
          if (op == PRODUCT_STATIC_INTERFACE && packet->ifindex_known)
            value = packet->ifindex == expression_number (arg, 4);
          at += 4;
        }
      else if (op == PRODUCT_STATIC_SOURCE_CIDR || op == PRODUCT_STATIC_DESTINATION_CIDR)
        {
          value = packet->family == arg[0] && address_matches (arg[0], arg + 2,
                    op == PRODUCT_STATIC_SOURCE_CIDR ? packet->source_address : packet->destination_address, arg[1]);
          at += 18;
        }
      else
        {
          if (packet->ports_available && supported_protocol (packet->protocol))
            value = port_matches (op == PRODUCT_STATIC_SOURCE_PORT ? packet->source_port : packet->destination_port,
                                  expression_number (arg, 2), expression_number (arg + 2, 2));
          at += 4;
        }
      values[stack++] = value;
    }
  return values[0] == 1;
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

int
product_l4_policy_requires_flow (const product_l4_policy_view_t *view, uint32_t uid)
{
  if (!view || uid == UINT32_MAX) return 0;
  uint32_t probes = 0;
  const product_l4_policy_uid_bucket_t *bucket = find_uid_bucket (view, uid, &probes);
  return bucket && bucket->requires_flow;
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
product_l4_policy_match_position (const product_l4_policy_view_t *view,
                         const product_l4_policy_packet_t *packet,
                         product_l4_policy_position_t position,
                         product_l4_policy_match_result_t *result)
{
  const product_l4_policy_uid_bucket_t *bucket;
  uint32_t index;

  if (view == NULL || packet == NULL || result == NULL
      || position < PRODUCT_L4_POLICY_POSITION_ALL
      || position > PRODUCT_L4_POLICY_POSITION_POST)
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
      if (position && compiled->position != position) continue;
      result->probes++;
      if (rule_matches (&compiled->source, packet)
          && expression_matches (&compiled->source, packet))
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
product_l4_policy_match (const product_l4_policy_view_t *view,
                         const product_l4_policy_packet_t *packet,
                         product_l4_policy_match_result_t *result)
{
  return product_l4_policy_match_position (view, packet, PRODUCT_L4_POLICY_POSITION_ALL, result);
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
