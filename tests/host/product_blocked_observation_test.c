/* SPDX-License-Identifier: Apache-2.0 */
#include "product_blocked_observation.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_observation_record_t records[32];
static unsigned count;
static void capture (void *unused, const product_observation_record_t *record) {
  (void) unused;
  assert (count < 32);
  records[count++] = *record;
}
static product_owner_assignment_t assignment (uint16_t port) {
  product_owner_assignment_t a = {
    .valid = 1, .execution_owner = 0, .source_is_a = 1,
    .canonical_hash = port,
    .key = { .kind = PRODUCT_OWNER_KEY_L4_PORTS, .ip_family = 4, .protocol = 17,
             .transport.ports = { .a = port, .b = 443 } },
  };
  a.key.address_a[12] = 10; a.key.address_a[15] = 1;
  a.key.address_b[12] = 10; a.key.address_b[15] = 2;
  return a;
}
static product_observation_attribution_t attribution (uint64_t winner,
                                                        uint64_t revision) {
  product_observation_attribution_t a = {
    .policy_generation = 77, .policy_revision = revision, .policy_hash = revision * 100,
    .winner = winner, .uid = 1001, .network = 3,
    .declared_action = 2, .actual_action = 2, .valid = 1,
  };
  memcpy (a.name, "drop", 5);
  return a;
}
static void observe (product_blocked_observation_t *o,
                     const product_owner_assignment_t *key,
                     const product_observation_attribution_t *rule,
                     uint64_t now) {
  product_blocked_observation_observe (o, key, 1001, 3, 3, 60, now,
                                        now + 1700000000000000ULL, rule);
}
int main (void) {
  product_blocked_observation_t *o = product_blocked_observation_create (2, 77, 0, capture, 0);
  assert (o);
  product_owner_assignment_t a = assignment (40001), b = assignment (40002), c = assignment (40003);
  product_observation_attribution_t first = attribution (65537, 1);
  product_observation_attribution_t second = attribution (131073, 2);
  observe (o, &a, &first, 1000000);
  assert (count == 1 && records[0].flags == (PRODUCT_OBSERVATION_BLOCKED | PRODUCT_OBSERVATION_CREATE));
  assert (records[0].packets[0] == 1 && records[0].bytes[0] == 60);
  uint64_t original = records[0].incarnation;
  observe (o, &a, &first, 1100000);
  assert (count == 1); /* ordinary growth coalesces */
  observe (o, &b, &first, 1200000);
  observe (o, &c, &first, 1300000);
  assert (product_blocked_observation_active (o) == 2);
  assert (product_blocked_observation_misses (o) == 1);
  assert (count == 2); /* capacity pressure loses only C's evidence */
  observe (o, &a, &second, 1400000);
  assert (count == 4); /* old boundary, new first contribution */
  assert (records[2].packets[0] == 2 && records[2].attribution[0].winner == 65537);
  assert (records[3].packets[0] == 3 && records[3].attribution[0].winner == 131073);
  a.source_is_a = 0;
  observe (o, &a, &second, 1500000);
  assert (records[4].packets[0] == 3 && records[4].packets[1] == 1);
  assert (records[4].attribution[0].winner == 131073);
  assert (records[4].attribution[1].winner == 131073);
  product_blocked_observation_flush_due (o, 2600000, 64);
  assert (count == 5); /* no duplicate time flush after immediate export */
  product_blocked_observation_flush_due (o, 32000000, 64);
  assert (product_blocked_observation_active (o) == 0);
  assert (product_blocked_observation_retired (o) == 2);
  assert (records[count - 1].flags & PRODUCT_OBSERVATION_END);
  assert (records[count - 1].end_reason == PRODUCT_OBSERVATION_END_IDLE);
  assert (records[count - 1].last_seen < 32000000); /* timer never fakes activity */
  a.source_is_a = 1;
  observe (o, &a, &first, 33000000);
  assert (records[count - 1].incarnation > original);
  assert (records[count - 1].sequence == 1);
  assert (records[count - 1].packets[0] == 1);
  product_blocked_observation_destroy (o);

  count = 0;
  o = product_blocked_observation_create (1, 78, 0, capture, 0);
  assert (o);
  a = assignment (40004);
  first.policy_generation = 78;
  observe (o, &a, &first, 1000000);
  observe (o, &a, &first, 1100000);
  assert (count == 1);
  product_blocked_observation_flush_due (o, 2000000, 64);
  assert (count == 1);
  product_blocked_observation_flush_due (o, 2100000, 64);
  assert (count == 2 && records[1].packets[0] == 2); /* pending flush */
  for (unsigned i = 0; i < 32; i++) observe (o, &a, &first, 3000000 + i * 100);
  assert (count == 3 && records[2].packets[0] == 34); /* growth threshold */
  observe (o, &a, &first, 3100000);
  assert (count == 3);
  product_blocked_observation_flush_due (o, 33100000, 64);
  assert (count == 4 && records[3].packets[0] == 35);
  assert ((records[3].flags & PRODUCT_OBSERVATION_END)
          && records[3].end_reason == PRODUCT_OBSERVATION_END_IDLE);
  product_blocked_observation_destroy (o);
  puts ("blocked observation identity, capacity, direction, attribution, idle END: PASS");
  return 0;
}
