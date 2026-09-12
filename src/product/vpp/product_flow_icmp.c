/* SPDX-License-Identifier: Apache-2.0 */
/* ICMP phase/timeout semantics: OVS v3.1.0,
 * 3c2bea086ef8912d57331173af266f21d36740a0, lib/conntrack-icmp.c.
 * Product deliberately limits queries to Echo and permits reply-first pickup.
 * No OVS connection storage, parser, RELATED lookup or timer is imported. */
#include "product_flow_tracker.h"

product_tracker_result_t
product_icmp_update (product_icmp_state_t *state,
                     const product_packet_facts_t *packet,
                     product_flow_direction_t direction)
{
  product_tracker_result_t result = {
    .facts = { PRODUCT_CT_INVALID, direction },
    .update = PRODUCT_CT_UPDATE_INVALID,
  };
  if (!state || !packet || state->phase > PRODUCT_ICMP_REPLY
      || state->seen_request > 1 || state->seen_reply > 1
      || (state->phase == PRODUCT_ICMP_EMPTY
          ? (state->seen_request || state->seen_reply)
          : !(state->seen_request || state->seen_reply))
      || (direction != PRODUCT_FLOW_DIRECTION_ORIG
          && direction != PRODUCT_FLOW_DIRECTION_REPLY)
      || (state->phase == PRODUCT_ICMP_EMPTY
          && direction != PRODUCT_FLOW_DIRECTION_ORIG)
      || packet->l3_status != PRODUCT_PACKET_L3_COMPLETE
      || packet->l4_status != PRODUCT_PACKET_L4_OTHER_TERMINAL
      || !packet->icmp_identity_known || packet->icmp_code != 0)
    return result;

  int request;
  if (packet->ip_family == 4 && packet->protocol == 1
      && (packet->icmp_type == 8 || packet->icmp_type == 0))
    request = packet->icmp_type == 8;
  else if (packet->ip_family == 6 && packet->protocol == 58
           && (packet->icmp_type == 128 || packet->icmp_type == 129))
    request = packet->icmp_type == 128;
  else
    return result;

  product_icmp_state_t candidate = *state;
  if (candidate.phase == PRODUCT_ICMP_EMPTY)
    candidate.phase = PRODUCT_ICMP_FIRST;
  else if (direction == PRODUCT_FLOW_DIRECTION_REPLY)
    candidate.phase = PRODUCT_ICMP_REPLY;
  if (request) candidate.seen_request = 1;
  else candidate.seen_reply = 1;
  result.facts.state = candidate.phase == PRODUCT_ICMP_REPLY
    ? PRODUCT_CT_ESTABLISHED : PRODUCT_CT_NEW;
  result.update = candidate.phase == PRODUCT_ICMP_REPLY
    ? PRODUCT_CT_UPDATE_VALID : PRODUCT_CT_UPDATE_VALID_NEW;
  result.timeout = candidate.phase == PRODUCT_ICMP_REPLY
    ? PRODUCT_CT_TIMEOUT_ICMP_REPLY : PRODUCT_CT_TIMEOUT_ICMP_FIRST;
  result.refresh_deadline = 1;
  *state = candidate;
  return result;
}
