/* SPDX-License-Identifier: Apache-2.0 */
#include "product_packet.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_packet_lease_t
remote_root (void)
{
  product_packet_lease_t lease = {0};
  lease.platform.provenance = PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE;
  lease.assignment.valid = 1;
  lease.assignment.execution_owner = 1;
  lease.facts.l3_status = PRODUCT_PACKET_L3_COMPLETE;
  lease.facts.l4_status = PRODUCT_PACKET_L4_COMPLETE;
  lease.distribution = PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE;
  lease.primary_handoff_count = 1;
  lease.origin_obligation_id = UINT64_C (0x100000007);
  return lease;
}

int main (void)
{
  for (unsigned reason = PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED;
       reason <= PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED; reason++)
    {
      product_packet_lease_t lease = remote_root ();
      assert (product_packet_bypass_primary_capacity (&lease, reason) == PRODUCT_PACKET_OK);
      assert (lease.terminal_intent == PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS);
      assert (lease.processing_bypass_reason == reason && lease.terminal_count == 1);
      assert (!lease.policy_owner_ready && lease.runtime_drop_reason == PRODUCT_PACKET_DROP_NONE);
      assert (lease.origin_obligation_id == UINT64_C (0x100000007));
      assert (lease.assignment.execution_owner == 1 && lease.primary_handoff_count == 1);
      assert (product_packet_bypass_primary_capacity (&lease, reason) == PRODUCT_PACKET_ORDER_VIOLATION);
      assert (product_packet_settle (&lease) == PRODUCT_PACKET_OK);
      assert (product_packet_settle (&lease) == PRODUCT_PACKET_ALREADY_SETTLED);
    }
  for (unsigned invalid = 0; invalid < 11; invalid++)
    {
      product_packet_lease_t lease = remote_root ();
      switch (invalid)
        {
        case 0: lease.platform.provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN; break;
        case 1: lease.assignment.valid = 0; break;
        case 2: lease.facts.l3_status = PRODUCT_PACKET_L3_UNAVAILABLE; break;
        case 3: lease.facts.l4_status = PRODUCT_PACKET_L4_FRAGMENT; break;
        case 4: lease.distribution = PRODUCT_PACKET_DISTRIBUTION_LOCAL; break;
        case 5: lease.policy_owner_ready = 1; break;
        case 6: lease.terminal_count = 1; break;
        case 7: lease.settled = 1; break;
        case 8: lease.terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
                lease.runtime_drop_reason = PRODUCT_PACKET_DROP_POLICY_GATE; break;
        case 9: lease.terminal_intent = PRODUCT_PACKET_INTENT_DROP_RUNTIME;
                lease.runtime_drop_reason = PRODUCT_PACKET_DROP_POLICY_L4; break;
        case 10: lease.runtime_drop_reason = PRODUCT_PACKET_DROP_INVALID_ENVELOPE; break;
        }
      product_packet_lease_t before = lease;
      assert (product_packet_bypass_primary_capacity (&lease,
        PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED) == PRODUCT_PACKET_ORDER_VIOLATION);
      assert (memcmp (&lease, &before, sizeof lease) == 0);
    }
  product_packet_lease_t lease = remote_root ();
  lease.policy_owner_ready = 1;
  assert (product_packet_set_terminal (&lease, PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS)
          == PRODUCT_PACKET_INVALID_ARGUMENT);
  puts ("S210 capacity disposition: retained identity, single settlement, DROP/VPN/content guards PASS");
  return 0;
}
