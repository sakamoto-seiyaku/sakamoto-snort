/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_tracker.h"
#include "product_flow_entry.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void runtime_udp (void)
{
  product_packet_facts_t packet = {
    .l3_status = PRODUCT_PACKET_L3_COMPLETE,
    .l4_status = PRODUCT_PACKET_L4_COMPLETE,
    .ip_family = 6, .protocol = 17,
    .source_port = 53, .destination_port = 40000,
    .source_address = { 0x20, 1 }, .destination_address = { 0x20, 2 },
  };
  product_worker_layout_t layout = { 2, 123 };
  product_owner_assignment_t assignment;
  assert (product_owner_assign (&layout, &packet, &assignment) == PRODUCT_PACKET_OK);
  product_flow_runtime_t *runtime = NULL;
  assert (product_flow_runtime_create (&runtime, assignment.execution_owner,
    2, 1, 3) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_flow_entry_packet_t observation_packet = {
    .facts = &packet, .policy = { 1, 1, 101 },
    .packet_bytes = 48, .device_direction = PRODUCT_PACKET_DIRECTION_INPUT,
  };
  product_flow_entry_observation_t observed;
  assert (product_flow_entry_observe (runtime, &assignment, &observation_packet,
    0, &observed) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (observed.created && observed.entry->protocol_state.udp.phase == PRODUCT_UDP_FIRST);
  assert (observed.tracker.facts.state == PRODUCT_CT_NEW);
  const product_flow_entry_t *entry = observed.entry;
  uint64_t serial = entry->incarnation;
  observation_packet.policy = (product_flow_policy_identity_t) { 1, 2, 202 };
  assert (product_flow_entry_observe (runtime, &assignment, &observation_packet,
    0, &observed) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (observed.entry == entry && observed.revision_invalidated);
  assert (entry->protocol_state.udp.phase == PRODUCT_UDP_MULTIPLE);
  assert (observed.tracker.timeout == PRODUCT_CT_TIMEOUT_OTHER_MULTIPLE);
  assert (entry->packets == 2 && entry->incarnation == serial);
  product_flow_entry_t before = *entry;
  assert (product_flow_entry_observe (runtime, &assignment, &observation_packet,
    1, &observed) == PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
  assert (!observed.entry && observed.tracker.update == PRODUCT_CT_UPDATE_NONE);
  assert (!memcmp (&before, entry, sizeof before));
  unsigned char address[16];
  memcpy (address, packet.source_address, 16);
  memcpy (packet.source_address, packet.destination_address, 16);
  memcpy (packet.destination_address, address, 16);
  packet.source_port = 40000; packet.destination_port = 53;
  assert (product_owner_assign (&layout, &packet, &assignment) == PRODUCT_PACKET_OK);
  /* Device direction deliberately remains INPUT: it cannot define REPLY. */
  assert (product_flow_entry_observe (runtime, &assignment, &observation_packet,
    0, &observed) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (observed.entry == entry && entry->incarnation == serial);
  assert (entry->protocol_state.udp.phase == PRODUCT_UDP_BIDIR);
  assert (observed.tracker.facts.state == PRODUCT_CT_ESTABLISHED);
  assert (observed.tracker.facts.direction == PRODUCT_FLOW_DIRECTION_REPLY);
  assert (entry->side_packets[0] == 2 && entry->side_packets[1] == 1);
  observation_packet.policy = (product_flow_policy_identity_t) { 1, 3, 303 };
  assert (product_flow_entry_observe (runtime, &assignment, &observation_packet,
    0, &observed) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (observed.revision_invalidated && entry->protocol_state.udp.phase == PRODUCT_UDP_BIDIR);
  before = *entry;
  observation_packet.facts = NULL;
  assert (product_flow_entry_observe (runtime, &assignment, &observation_packet,
    0, &observed) == PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  assert (!observed.entry && !memcmp (&before, entry, sizeof before));
  observation_packet.facts = &packet;
  product_flow_runtime_flush (runtime);
  assert (product_flow_entry_observe (runtime, &assignment, &observation_packet,
    0, &observed) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (observed.created && observed.entry->incarnation > serial);
  assert (observed.entry->protocol_state.udp.phase == PRODUCT_UDP_FIRST);
  assert (observed.tracker.facts.direction == PRODUCT_FLOW_DIRECTION_ORIG);
  product_flow_runtime_destroy (runtime);
}

static void invalid_inputs (void)
{
  product_packet_facts_t valid = {
    .l3_status = PRODUCT_PACKET_L3_COMPLETE,
    .l4_status = PRODUCT_PACKET_L4_COMPLETE, .ip_family = 4, .protocol = 17,
  };
  product_udp_state_t empty = { 0 };
  assert (product_udp_update (NULL, &valid, PRODUCT_FLOW_DIRECTION_ORIG).update
          == PRODUCT_CT_UPDATE_INVALID);
  assert (product_udp_update (&empty, &valid, PRODUCT_FLOW_DIRECTION_REPLY).update
          == PRODUCT_CT_UPDATE_INVALID);
  assert (empty.phase == PRODUCT_UDP_EMPTY);
  for (unsigned phase = PRODUCT_UDP_EMPTY; phase <= PRODUCT_UDP_BIDIR; phase++)
    for (unsigned failure = 0; failure < 9; failure++)
      {
        product_udp_state_t state = { phase };
        product_packet_facts_t packet = {
          .l3_status = PRODUCT_PACKET_L3_COMPLETE,
          .l4_status = PRODUCT_PACKET_L4_COMPLETE,
          .ip_family = 4, .protocol = 17,
        };
        product_flow_direction_t direction = PRODUCT_FLOW_DIRECTION_ORIG;
        switch (failure)
          {
          case 0: packet.l3_status = PRODUCT_PACKET_L3_UNAVAILABLE; break;
          case 1: packet.l4_status = PRODUCT_PACKET_L4_UNAVAILABLE; break;
          case 2: packet.l4_status = PRODUCT_PACKET_L4_FRAGMENT; break;
          case 3: packet.protocol = 6; break;
          case 4: packet.ip_family = 5; break;
          case 5: direction = PRODUCT_FLOW_DIRECTION_UNKNOWN; break;
          case 6: direction = 99; break;
          case 7: state.phase = 255; break;
          case 8: break; /* NULL facts */
          }
        product_udp_state_t before = state;
        product_tracker_result_t result = product_udp_update (
          &state, failure == 8 ? NULL : &packet, direction);
        assert (result.update == PRODUCT_CT_UPDATE_INVALID);
        assert (result.facts.state == PRODUCT_CT_INVALID);
        assert (result.timeout == PRODUCT_CT_TIMEOUT_NONE);
        assert (!result.refresh_deadline && !result.close_old_instance && !result.create_replacement);
        assert (!memcmp (&before, &state, sizeof before));
      }
}

int main (void)
{
  runtime_udp ();
  invalid_inputs ();
  /* OVS v3.1.0 other_new_conn: first accepted observation is NEW/FIRST. */
  for (unsigned family = 4; family <= 6; family += 2)
    {
      product_packet_facts_t packet = {
        .l3_status = PRODUCT_PACKET_L3_COMPLETE,
        .l4_status = PRODUCT_PACKET_L4_COMPLETE,
        .ip_family = family, .protocol = 17,
        .source_port = 53, .destination_port = 40000,
      };
      product_udp_state_t state = { 0 };
      product_tracker_result_t result = product_udp_update (
        &state, &packet, PRODUCT_FLOW_DIRECTION_ORIG);
      assert (state.phase == PRODUCT_UDP_FIRST);
      assert (result.update == PRODUCT_CT_UPDATE_VALID_NEW);
      assert (result.facts.state == PRODUCT_CT_NEW);
      assert (result.facts.direction == PRODUCT_FLOW_DIRECTION_ORIG);
      assert (result.timeout == PRODUCT_CT_TIMEOUT_OTHER_FIRST);
      assert (result.refresh_deadline);
      assert (!result.close_old_instance && !result.create_replacement);
      /* Identical payload/tuple again is another same-side observation. */
      result = product_udp_update (&state, &packet, PRODUCT_FLOW_DIRECTION_ORIG);
      assert (state.phase == PRODUCT_UDP_MULTIPLE);
      assert (result.update == PRODUCT_CT_UPDATE_VALID_NEW);
      assert (result.facts.state == PRODUCT_CT_NEW);
      assert (result.timeout == PRODUCT_CT_TIMEOUT_OTHER_MULTIPLE);
      assert (result.refresh_deadline);
      result = product_udp_update (&state, &packet, PRODUCT_FLOW_DIRECTION_ORIG);
      assert (state.phase == PRODUCT_UDP_MULTIPLE);
      assert (result.facts.state == PRODUCT_CT_NEW);
      result = product_udp_update (&state, &packet, PRODUCT_FLOW_DIRECTION_REPLY);
      assert (state.phase == PRODUCT_UDP_BIDIR);
      assert (result.update == PRODUCT_CT_UPDATE_VALID);
      assert (result.facts.state == PRODUCT_CT_ESTABLISHED);
      assert (result.facts.direction == PRODUCT_FLOW_DIRECTION_REPLY);
      assert (result.timeout == PRODUCT_CT_TIMEOUT_OTHER_BIDIR);
      assert (result.refresh_deadline);
      for (unsigned direction = 1; direction <= 2; direction++)
        {
          result = product_udp_update (&state, &packet, direction);
          assert (state.phase == PRODUCT_UDP_BIDIR);
          assert (result.update == PRODUCT_CT_UPDATE_VALID);
          assert (result.facts.state == PRODUCT_CT_ESTABLISHED);
          assert (result.facts.direction == direction);
          assert (result.timeout == PRODUCT_CT_TIMEOUT_OTHER_BIDIR);
          assert (result.refresh_deadline);
        }
      state.phase = PRODUCT_UDP_FIRST;
      result = product_udp_update (&state, &packet, PRODUCT_FLOW_DIRECTION_REPLY);
      assert (state.phase == PRODUCT_UDP_BIDIR);
      assert (result.facts.state == PRODUCT_CT_ESTABLISHED);
      assert (result.timeout == PRODUCT_CT_TIMEOUT_OTHER_BIDIR);
    }
  puts ("S223 UDP tracker: PASS");
}
