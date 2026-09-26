/* SPDX-License-Identifier: Apache-2.0 */

#include "product_l4_policy.h"
#include "product_protocol_catalog.h"

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
      || op == PRODUCT_EXPRESSION_CT_STATE || op == PRODUCT_EXPRESSION_FLOW_DIRECTION
      || op == PRODUCT_EXPRESSION_SNI_ABSENT || op == PRODUCT_EXPRESSION_DOMAIN_LIST)
    return 1;
  if (op == PRODUCT_EXPRESSION_APPLICATION_PROTOCOL
      || op == PRODUCT_STATIC_NETWORK || op == PRODUCT_STATIC_INTERFACE
      || op == PRODUCT_STATIC_SOURCE_PORT || op == PRODUCT_STATIC_DESTINATION_PORT)
    return 4;
  if (op == PRODUCT_STATIC_SOURCE_CIDR || op == PRODUCT_STATIC_DESTINATION_CIDR)
    return 18;
  return 0;
}

uint64_t
product_static_expression_domain_references (const uint8_t *bytes, uint32_t length)
{
  if (product_static_expression_validate (bytes, length)) return 0;
  uint64_t references = 0;
  for (unsigned at = 0; at < length;)
    {
      unsigned op = bytes[at++];
      if (op == PRODUCT_EXPRESSION_DOMAIN_LIST) references |= UINT64_C(1) << bytes[at];
      if (op > PRODUCT_STATIC_NOT) at += expression_operand_bytes (op);
    }
  return references;
}

/* Validated source only; skip operands so data bytes cannot become dependencies. */
static int
expression_dependencies (const product_l4_policy_rule_t *rule)
{
  unsigned dependencies = 0;
  for (unsigned at = 0; at < rule->expression_length;)
    {
      unsigned op = rule->expression[at++];
      if (op == PRODUCT_EXPRESSION_CT_STATE || op == PRODUCT_EXPRESSION_FLOW_DIRECTION)
        dependencies |= PRODUCT_POLICY_DEP_CT;
      if (op == PRODUCT_EXPRESSION_APPLICATION_PROTOCOL)
        dependencies |= PRODUCT_POLICY_DEP_LPI;
      if (op == PRODUCT_EXPRESSION_SNI_ABSENT || op == PRODUCT_EXPRESSION_DOMAIN_LIST)
        dependencies |= PRODUCT_POLICY_DEP_SNI | PRODUCT_POLICY_DEP_LPI;
      if (op <= PRODUCT_STATIC_NOT) continue;
      at += expression_operand_bytes (op);
    }
  return dependencies;
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
      rule->position = expression_dependencies (&rule->source)
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

/* Canonical network-order bytes avoid padding, alignment and host-endian keys.
 * Interval common prefixes are supersets: complete residual checks decide. */
static void
index_bounds (const static_envelope_t *e, uint8_t *low, uint8_t *high)
{
  for (unsigned i = 0; i < ENVELOPE_AXES; ++i)
    {
      low[2*i] = (uint8_t) (e->low[i] >> 8);
      low[2*i+1] = (uint8_t) e->low[i];
      high[2*i] = (uint8_t) (e->high[i] >> 8);
      high[2*i+1] = (uint8_t) e->high[i];
    }
  memcpy (low + 10, e->address_low, 32);
  memcpy (high + 10, e->address_high, 32);
}

static unsigned
index_hash (const uint8_t *key)
{
  uint32_t hash = UINT32_C (2166136261);
  for (unsigned i = 0; i < PRODUCT_L4_INDEX_KEY_BYTES; ++i)
    hash = (hash ^ key[i]) * UINT32_C (16777619);
  return hash % PRODUCT_L4_INDEX_SLOTS;
}

static void
index_mask (const static_envelope_t *e, uint8_t *mask, uint8_t *key)
{
  uint8_t low[PRODUCT_L4_INDEX_KEY_BYTES], high[PRODUCT_L4_INDEX_KEY_BYTES];
  index_bounds (e, low, high);
  /* Each numeric axis/address has its own interval prefix. */
  for (unsigned field = 0; field < 7; ++field)
    {
      unsigned start = field < 5 ? field * 2 : 10 + (field - 5) * 16;
      unsigned length = field < 5 ? 2 : 16;
      int differing = e->empty;
      for (unsigned i = start; i < start + length; ++i)
        {
          uint8_t m = 0;
          for (unsigned bit = 128; bit; bit >>= 1)
            {
              differing |= (low[i] & bit) != (high[i] & bit);
              if (!differing) m |= (uint8_t) bit;
            }
          mask[i] = m;
          key[i] = low[i] & m;
        }
    }
}

/* Minimal disjoint prefix cover of one inclusive 16-bit interval. At most
 * 30 pieces; arithmetic uses 32 bits so 0..65535 cannot wrap. */
static unsigned
range_cover (uint16_t first, uint16_t last, uint16_t low[32], uint16_t high[32])
{
  unsigned count = 0;
  for (uint32_t at = first; at <= last;)
    {
      uint32_t size = at ? at & (0U - at) : 65536U;
      while (size > (uint32_t) last - at + 1) size >>= 1;
      low[count] = (uint16_t) at;
      high[count++] = (uint16_t) (at + size - 1);
      at += size;
    }
  return count;
}

static void
index_insert (product_l4_policy_view_t *view, unsigned subject,
              unsigned rule, const static_envelope_t *envelope)
{
  unsigned number = view->entry_count++;
  product_l4_policy_index_entry_t *entry = &view->entries[number];
  uint8_t mask[PRODUCT_L4_INDEX_KEY_BYTES];
  index_mask (envelope, mask, entry->key);
  unsigned table = 0;
  while (table < view->subtable_count
         && (view->subtables[table].subject != subject
             || memcmp (view->subtables[table].mask, mask, sizeof mask))) ++table;
  product_l4_policy_subtable_t *t = &view->subtables[table];
  if (table == view->subtable_count)
    {
      ++view->subtable_count;
      memcpy (t->mask, mask, sizeof mask);
      t->subject = (uint16_t) subject;
      for (unsigned h = 0; h < PRODUCT_L4_INDEX_SLOTS; ++h)
        t->heads[h] = PRODUCT_L4_INDEX_NONE;
    }
  t->first_rank = (uint16_t) view->rules[rule].winner_rank;
  unsigned slot = index_hash (entry->key);
  entry->rule = (uint16_t) rule;
  entry->next = t->heads[slot];
  t->heads[slot] = (uint16_t) number;
}

/* General disjunction/negation retains its bounded source program. We do not
 * distribute AND over OR or pretend a hull is an exact Boolean expansion. */
static int
range_plan_eligible (const product_l4_policy_rule_t *rule)
{
  for (unsigned at = 0; at < rule->expression_length;)
    {
      unsigned op = rule->expression[at++];
      if (op == PRODUCT_STATIC_OR || op == PRODUCT_STATIC_NOT) return 0;
      at += expression_operand_bytes (op);
    }
  return 1;
}

static void
build_index (product_l4_policy_view_t *view, const product_l4_policy_compile_budget_t *budget)
{
  /* Reserve one legal residual entry for every remaining rule before spending
   * spare entries. Reverse insertion keeps collision chains in complete Rank.
   * Exhausting an optimization budget falls back, never truncates a rule. */
  unsigned remaining = view->rule_count, factors = 0;
  for (unsigned subject = 0; subject < view->uid_bucket_count; ++subject)
    {
      const product_l4_policy_uid_bucket_t *bucket = &view->uid_buckets[subject];
      for (unsigned n = bucket->rule_count; n; --n)
        {
          unsigned rule = bucket->first_rule + n - 1;
          static_envelope_t e = rule_envelope (&view->rules[rule].source);
          uint16_t low[2][32], high[2][32];
          unsigned a = range_cover (e.low[ENVELOPE_SOURCE_PORT], e.high[ENVELOPE_SOURCE_PORT], low[0], high[0]);
          unsigned b = range_cover (e.low[ENVELOPE_DESTINATION_PORT], e.high[ENVELOPE_DESTINATION_PORT], low[1], high[1]);
          --remaining;
          int eligible = range_plan_eligible (&view->rules[rule].source);
          if (eligible && !e.empty && a * b <= budget->direct_entries
              && a * b + view->entry_count + remaining <= budget->index_entries)
            {
              view->rules[rule].plan = PRODUCT_L4_PLAN_DIRECT;
              for (unsigned i = 0; i < a; ++i)
              for (unsigned j = 0; j < b; ++j)
                {
                  static_envelope_t piece = e;
                  piece.low[ENVELOPE_SOURCE_PORT] = low[0][i];
                  piece.high[ENVELOPE_SOURCE_PORT] = high[0][i];
                  piece.low[ENVELOPE_DESTINATION_PORT] = low[1][j];
                  piece.high[ENVELOPE_DESTINATION_PORT] = high[1][j];
                  index_insert (view, subject, rule, &piece);
                }
            }
          else
            {
              product_l4_policy_compiled_rule_t *compiled = &view->rules[rule];
              compiled->plan = PRODUCT_L4_PLAN_RESIDUAL;
              if (eligible && !e.empty && factors < budget->factor_rules
                  && (e.low[ENVELOPE_SOURCE_PORT] || e.high[ENVELOPE_SOURCE_PORT] != UINT16_MAX
                      || e.low[ENVELOPE_DESTINATION_PORT] || e.high[ENVELOPE_DESTINATION_PORT] != UINT16_MAX))
                {
                  compiled->plan = PRODUCT_L4_PLAN_FACTORIZED;
                  ++factors;
                  for (unsigned side = 0; side < 2; ++side)
                    {
                      compiled->factor_first[side] = e.low[ENVELOPE_SOURCE_PORT + side];
                      compiled->factor_last[side] = e.high[ENVELOPE_SOURCE_PORT + side];
                    }
                }
              index_insert (view, subject, rule, &e);
            }
        }
    }
}

void
product_l4_policy_index_resources (const product_l4_policy_view_t *view,
                                   product_l4_policy_index_resources_t *resources)
{
  if (!resources) return;
  memset (resources, 0, sizeof *resources);
  if (!view) return;
  resources->subtables = view->subtable_count;
  resources->entries = view->entry_count;
  resources->storage_bytes = sizeof *view;
  /* Subject binary search + all table inspections + all chained keys + all
   * complete residuals. No query truncation or partial-best return. */
  resources->max_query_work = PRODUCT_L4_POLICY_MAX_SUBJECT_PROBES
    + view->subtable_count + view->entry_count + view->max_probes;
}

/* These are representation bytes, not process RSS or a latency promise.
 * Four views cover two protected banks, management preflight and publication.
 * The two caller source arrays are conservatively at the 256-source capacity.
 * Fixed frame reserves cover scalar/validation scratch; allocator metadata
 * and existing thread-stack reservation are outside these storage totals. */
static uint32_t
compile_scratch_bytes (void)
{
  return (PRODUCT_L4_POLICY_MAX_RULES + PRODUCT_STATIC_EXPRESSION_BYTES + 4)
    * sizeof (static_envelope_t) + 4 * 32 * sizeof (uint16_t)
    + 4 * PRODUCT_L4_INDEX_KEY_BYTES + 4096;
}

static uint32_t
query_state_bytes (void)
{
  return PRODUCT_L4_POLICY_MAX_RULES + PRODUCT_STATIC_EXPRESSION_BYTES
    + 3 * PRODUCT_L4_INDEX_KEY_BYTES + sizeof (static_envelope_t) + 512;
}

static uint32_t
publication_peak_bytes (void)
{
  return 4 * sizeof (product_l4_policy_view_t)
    + 2 * 256 * sizeof (product_l4_policy_rule_t)
    + compile_scratch_bytes () + query_state_bytes ();
}

product_l4_policy_compile_budget_t
product_l4_policy_default_budget (void)
{
  return (product_l4_policy_compile_budget_t) {
    PRODUCT_L4_DIRECT_ENTRIES, PRODUCT_L4_INDEX_ENTRIES,
    PRODUCT_L4_POLICY_MAX_RULES, PRODUCT_L4_CONDITION_ITEMS,
    PRODUCT_L4_COMPILE_PEAK_LIMIT
  };
}

static unsigned
condition_items (const product_l4_policy_rule_t *rule)
{
  /* Nine fixed source predicate slots plus every bytecode operator/leaf. */
  unsigned count = 9;
  for (unsigned at = 0; at < rule->expression_length; ++count)
    at += 1 + expression_operand_bytes (rule->expression[at]);
  return count;
}

void
product_l4_policy_plan_resources (const product_l4_policy_view_t *view,
                                  product_l4_policy_plan_resources_t *resources)
{
  if (!resources) return;
  memset (resources, 0, sizeof *resources);
  resources->query_state_bytes = query_state_bytes ();
  resources->compile_scratch_bytes = compile_scratch_bytes ();
  resources->publication_peak_bytes = publication_peak_bytes ();
  if (!view) return;
  for (unsigned i = 0; i < view->rule_count; ++i)
    {
      if (view->rules[i].plan == PRODUCT_L4_PLAN_DIRECT) ++resources->direct_rules;
      else if (view->rules[i].plan == PRODUCT_L4_PLAN_FACTORIZED) ++resources->factorized_rules;
      else ++resources->residual_rules;
      resources->condition_items += condition_items (&view->rules[i].source);
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
product_l4_policy_compile_with_budget (product_l4_policy_view_t *view,
                           const product_l4_policy_rule_t *rules,
                           size_t rule_count, const product_l4_policy_compile_budget_t *budget)
{
  size_t input_index;
  uint32_t bucket_index;
  uint32_t rule_index;

  if (view == NULL || budget == NULL || (rule_count != 0 && rules == NULL)
      || budget->direct_entries > PRODUCT_L4_DIRECT_ENTRIES
      || budget->index_entries > PRODUCT_L4_INDEX_ENTRIES
      || budget->factor_rules > PRODUCT_L4_POLICY_MAX_RULES)
    return PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT;
  if (rule_count > PRODUCT_L4_POLICY_MAX_RULES
      || rule_count > budget->index_entries
      || publication_peak_bytes () > budget->peak_bytes)
    return PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED;

  unsigned items = 0;
  for (input_index = 0; input_index < rule_count; input_index++)
    {
      product_l4_policy_status_t status = validate_rule (&rules[input_index]);
      size_t prior_index;
      if (status != PRODUCT_L4_POLICY_STATUS_OK)
        return status;
      items += condition_items (&rules[input_index]);
      if (items > budget->condition_items)
        return PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED;
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
          view->uid_buckets[bucket_index].dependencies |= PRODUCT_POLICY_DEP_STATIC;
          view->uid_buckets[bucket_index].dependencies |=
            expression_dependencies (&view->rules[rule_index].source);
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
  build_index (view, budget);
  return PRODUCT_L4_POLICY_STATUS_OK;
}

product_l4_policy_status_t
product_l4_policy_compile (product_l4_policy_view_t *view,
                           const product_l4_policy_rule_t *rules, size_t count)
{
  product_l4_policy_compile_budget_t budget = product_l4_policy_default_budget ();
  return product_l4_policy_compile_with_budget (view, rules, count, &budget);
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
      if ((op == PRODUCT_EXPRESSION_DOMAIN_LIST && arg[0] >= 64)
          || (op == PRODUCT_EXPRESSION_SNI_ABSENT && arg[0] != 1)
          || (op == PRODUCT_EXPRESSION_APPLICATION_PROTOCOL && !product_protocol_bit (expression_number (arg, 4)))
          || (op == PRODUCT_EXPRESSION_CT_STATE && (arg[0] < 1 || arg[0] > 3))
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
  if ((expression_dependencies(rule) & PRODUCT_POLICY_DEP_SNI)
      && (!packet->protocol_set_known || !(packet->protocol_set &
          (product_protocol_bit(1003) | product_protocol_bit(1004))))) return 0;
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
      else if (op == PRODUCT_EXPRESSION_DOMAIN_LIST)
        {
          if (packet->sni_result == PRODUCT_SNI_ABSENT) value = 0;
          else if (packet->sni_result == PRODUCT_SNI_NAME)
            value = !!(packet->domain_lists & (UINT64_C(1) << arg[0]));
          ++at;
        }
      else if (op == PRODUCT_EXPRESSION_SNI_ABSENT)
        {
          if (packet->sni_result == PRODUCT_SNI_NAME || packet->sni_result == PRODUCT_SNI_ABSENT)
            value = packet->sni_result == PRODUCT_SNI_ABSENT;
          ++at;
        }
      else if (op == PRODUCT_EXPRESSION_APPLICATION_PROTOCOL)
        {
          if (packet->protocol_set_known)
            value = !!(packet->protocol_set & product_protocol_bit (expression_number (arg, 4)));
          at += 4;
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
  uint8_t packet_key[PRODUCT_L4_INDEX_KEY_BYTES], unused[PRODUCT_L4_INDEX_KEY_BYTES];
  static_envelope_t values = envelope_any ();
  values.low[ENVELOPE_FAMILY] = packet->family;
  values.low[ENVELOPE_PROTOCOL] = packet->protocol;
  values.low[ENVELOPE_DIRECTION] = packet->direction;
  values.low[ENVELOPE_SOURCE_PORT] = packet->source_port;
  values.low[ENVELOPE_DESTINATION_PORT] = packet->destination_port;
  memcpy (values.address_low[0], packet->source_address, 16);
  memcpy (values.address_low[1], packet->destination_address, 16);
  index_bounds (&values, packet_key, unused);
  unsigned best = UINT32_MAX;
  uint8_t checked[PRODUCT_L4_POLICY_MAX_RULES] = {0};
  for (index = 0; index < view->subtable_count; ++index)
    {
      const product_l4_policy_subtable_t *table = &view->subtables[index];
      ++result->subtable_probes;
      if (table->subject != (unsigned) (bucket - view->uid_buckets)
          || table->first_rank >= best) continue;
      uint8_t key[PRODUCT_L4_INDEX_KEY_BYTES];
      for (unsigned i = 0; i < sizeof key; ++i) key[i] = packet_key[i] & table->mask[i];
      for (unsigned entry = table->heads[index_hash (key)];
           entry != PRODUCT_L4_INDEX_NONE; entry = view->entries[entry].next)
        {
          unsigned rule = view->entries[entry].rule;
          const product_l4_policy_compiled_rule_t *compiled = &view->rules[rule];
          if (compiled->winner_rank >= best) break;
          ++result->key_probes;
          if ((position && compiled->position != position)
              || memcmp (key, view->entries[entry].key, sizeof key) || checked[rule]) continue;
          checked[rule] = 1;
          ++result->probes;
          /* These independent interval factors are a necessary candidate test.
           * Only the complete source evaluator supplies availability, Boolean
           * truth, winner identity and actions. All conjunction state is local. */
          if (compiled->plan == PRODUCT_L4_PLAN_FACTORIZED
              && (!port_matches (packet->source_port, compiled->factor_first[0], compiled->factor_last[0])
                  || !port_matches (packet->destination_port, compiled->factor_first[1], compiled->factor_last[1]))) continue;
          if (!rule_matches (&compiled->source, packet)
              || !expression_matches (&compiled->source, packet)) continue;
          best = compiled->winner_rank;
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
          break;
        }
    }
  if (result->evaluation == PRODUCT_L4_POLICY_EVALUATION_MATCH)
    return PRODUCT_L4_POLICY_STATUS_OK;
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

/* Canonical bytes avoid caller padding/uninitialized irrelevant dynamic data.
 * Static over-guarding is intentional: application/platform changes and opposite
 * packet endpoints/directions cannot silently share a result. */
static void
cache_guard (product_policy_cache_guard_t *guard,
             const product_l4_policy_packet_t *packet,
             const product_policy_cache_identity_t *identity,
             product_l4_policy_position_t position, unsigned dependencies)
{
  memset (guard, 0, sizeof (*guard));
  guard->identity = *identity;
  guard->position = position;
  guard->dependencies = dependencies;
#define COPY(field) guard->packet.field = packet->field
  COPY(uid); COPY(uid_known); COPY(family); COPY(protocol);
  COPY(direction); COPY(direction_known); COPY(network_context_id);
  COPY(network_context_known); COPY(ifindex); COPY(ifindex_known);
  COPY(source_port); COPY(destination_port); COPY(ports_available);
  memcpy (guard->packet.source_address, packet->source_address, 16);
  memcpy (guard->packet.destination_address, packet->destination_address, 16);
  if (dependencies & PRODUCT_POLICY_DEP_CT)
    {
      COPY(ct_state); COPY(ct_state_known);
      COPY(flow_direction); COPY(flow_direction_known);
    }
  if (dependencies & PRODUCT_POLICY_DEP_LPI)
    {
      COPY(protocol_set); COPY(protocol_set_known);
    }
  if (dependencies & PRODUCT_POLICY_DEP_SNI) { COPY(sni_result); COPY(domain_lists); }
#undef COPY
}

product_l4_policy_status_t
product_l4_policy_match_cached (
  product_policy_cache_t *cache, const product_l4_policy_view_t *view,
  const product_l4_policy_packet_t *packet,
  const product_policy_cache_identity_t *identity,
  product_l4_policy_position_t position, product_l4_policy_match_result_t *result)
{
  if (!cache)
    return product_l4_policy_match_position (view, packet, position, result);
  if (!view || !packet || !identity || !result
      || position < PRODUCT_L4_POLICY_POSITION_ALL
      || position > PRODUCT_L4_POLICY_POSITION_POST
      || cache->capacity > PRODUCT_POLICY_CACHE_MAX_CAPACITY)
    return PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT;
  uint32_t probes = 0;
  const product_l4_policy_uid_bucket_t *bucket = packet->uid_known
    ? find_uid_bucket (view, packet->uid, &probes) : NULL;
  product_policy_cache_guard_t guard;
  cache_guard (&guard, packet, identity, position,
               bucket ? bucket->dependencies : PRODUCT_POLICY_DEP_STATIC);
  uint64_t hash = UINT64_C (14695981039346656037);
  const unsigned char *bytes = (const unsigned char *) &guard;
  for (size_t i = 0; i < sizeof (guard); ++i)
    hash = (hash ^ bytes[i]) * UINT64_C (1099511628211);
  /* Mix high bits before reducing to a power-of-two capacity. Sequential Flow
   * incarnations correlated with endpoint ports otherwise cluster in low bits. */
  hash ^= hash >> 33;
  hash *= UINT64_C (0xff51afd7ed558ccd);
  hash ^= hash >> 33;
  hash *= UINT64_C (0xc4ceb9fe1a85ec53);
  hash ^= hash >> 33;
  unsigned capacity = cache->capacity ? cache->capacity : PRODUCT_POLICY_CACHE_CAPACITY;
  product_policy_cache_entry_t *entry = &cache->entries[hash % capacity];
  if (entry->valid && !memcmp (&entry->guard, &guard, sizeof (guard)))
    {
      ++cache->hits;
      *result = entry->result;
      result->probes = 0;
      result->subject_probes = probes;
      result->subtable_probes = result->key_probes = 0;
      return PRODUCT_L4_POLICY_STATUS_OK;
    }
  ++cache->misses;
  product_l4_policy_status_t status = product_l4_policy_match_position (
    view, packet, position, result);
  if (status == PRODUCT_L4_POLICY_STATUS_OK)
    {
      result->subject_probes += probes;
      if (entry->valid) ++cache->replacements;
      else ++cache->occupied;
      entry->guard = guard;
      entry->result = *result;
      entry->valid = 1;
    }
  return status;
}
