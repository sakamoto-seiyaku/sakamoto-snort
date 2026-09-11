/* SPDX-License-Identifier: Apache-2.0 */
/* UDP semantics: OVS v3.1.0, commit 3c2bea086ef8912d57331173af266f21d36740a0,
 * lib/conntrack-other.c. See docs/reference/OVS_CONNTRACK_BASELINE.md.
 * This module does not import OVS connection storage or expiration machinery. */
#include "product_flow_tracker.h"

product_tracker_result_t
product_udp_update (product_udp_state_t *state,
                    const product_packet_facts_t *packet,
                    product_flow_direction_t direction)
{
  product_tracker_result_t result = {
    .facts = { PRODUCT_CT_INVALID, direction },
    .update = PRODUCT_CT_UPDATE_INVALID,
  };
  if (!state || !packet || state->phase > PRODUCT_UDP_BIDIR
      || (direction != PRODUCT_FLOW_DIRECTION_ORIG
          && direction != PRODUCT_FLOW_DIRECTION_REPLY)
      || (state->phase == PRODUCT_UDP_EMPTY
          && direction != PRODUCT_FLOW_DIRECTION_ORIG)
      || packet->l3_status != PRODUCT_PACKET_L3_COMPLETE
      || packet->l4_status != PRODUCT_PACKET_L4_COMPLETE
      || (packet->ip_family != 4 && packet->ip_family != 6)
      || packet->protocol != 17)
    return result;

  product_udp_state_t candidate = *state;
  if (candidate.phase == PRODUCT_UDP_EMPTY)
    candidate.phase = PRODUCT_UDP_FIRST;
  else if (direction == PRODUCT_FLOW_DIRECTION_REPLY)
    candidate.phase = PRODUCT_UDP_BIDIR;
  else if (candidate.phase == PRODUCT_UDP_FIRST)
    candidate.phase = PRODUCT_UDP_MULTIPLE;
  result.facts.state = candidate.phase == PRODUCT_UDP_BIDIR
    ? PRODUCT_CT_ESTABLISHED : PRODUCT_CT_NEW;
  result.update = candidate.phase == PRODUCT_UDP_BIDIR
    ? PRODUCT_CT_UPDATE_VALID : PRODUCT_CT_UPDATE_VALID_NEW;
  result.timeout = candidate.phase == PRODUCT_UDP_FIRST
    ? PRODUCT_CT_TIMEOUT_OTHER_FIRST : candidate.phase == PRODUCT_UDP_MULTIPLE
    ? PRODUCT_CT_TIMEOUT_OTHER_MULTIPLE : PRODUCT_CT_TIMEOUT_OTHER_BIDIR;
  result.refresh_deadline = 1;
  *state = candidate;
  return result;
}
