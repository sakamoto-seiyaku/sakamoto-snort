/* SPDX-License-Identifier: Apache-2.0 */

#include "sakamoto_product_abi.h"

#include <stddef.h>
#include <stdint.h>

_Static_assert (SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES == 64U,
                "Gate bundle capacity changed");
_Static_assert (SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES == 64U,
                "L4 bundle capacity changed");
_Static_assert (SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES == 128U,
                "total bundle capacity changed");
_Static_assert (sizeof (sakamoto_product_policy_rule_entry_t) == 120U,
                "typed policy rule layout changed");
_Static_assert (offsetof (sakamoto_product_policy_rule_entry_t, rule_id) == 80U,
                "typed policy rule identity offset changed");
_Static_assert (offsetof (sakamoto_product_policy_rule_entry_t, source_address) == 88U,
                "typed policy source address offset changed");
_Static_assert (offsetof (sakamoto_product_policy_rule_entry_t, destination_address) == 104U,
                "typed policy destination address offset changed");
_Static_assert (sizeof (sakamoto_product_policy_bundle_t) == 15496U,
                "complete policy bundle layout changed");
_Static_assert (offsetof (sakamoto_product_policy_bundle_t, snapshot_identity) == 40U,
                "complete policy identity offset changed");
_Static_assert (offsetof (sakamoto_product_policy_bundle_t, gate_entries) == 136U,
                "complete policy Gate array offset changed");
_Static_assert (offsetof (sakamoto_product_policy_bundle_t, l4_entries) == 7816U,
                "complete policy L4 array offset changed");

int
main (void)
{
  sakamoto_product_policy_bundle_t bundle = {0};
  bundle.abi_version = SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION;
  bundle.struct_size = (uint32_t) sizeof (bundle);
  bundle.gate_entry_count = SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES;
  bundle.l4_rule_count = SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES;
  return bundle.gate_entry_count + bundle.l4_rule_count
    == SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES ? 0 : 1;
}
