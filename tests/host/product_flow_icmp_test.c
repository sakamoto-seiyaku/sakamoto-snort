/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_packet_facts_t
echo (unsigned family, int reply)
{
  product_packet_facts_t f = {
    .l3_status = PRODUCT_PACKET_L3_COMPLETE,
    .l4_status = PRODUCT_PACKET_L4_OTHER_TERMINAL,
    .ip_family = family, .protocol = family == 4 ? 1 : 58,
    .l4_header_length = 8, .transport_length = 40,
    .icmp_identity_known = 1, .icmp_identifier = 321,
    .icmp_type = family == 4 ? (reply ? 0 : 8) : (reply ? 129 : 128),
  };
  f.source_address[15] = reply ? 2 : 1;
  f.destination_address[15] = reply ? 1 : 2;
  if (family == 6) f.source_address[0] = f.destination_address[0] = 0xfd;
  return f;
}

static void
result_is (product_tracker_result_t r, unsigned phase, unsigned direction)
{
  assert (r.facts.direction == direction);
  assert (r.facts.state == (phase == PRODUCT_ICMP_REPLY ? PRODUCT_CT_ESTABLISHED : PRODUCT_CT_NEW));
  assert (r.update == (phase == PRODUCT_ICMP_REPLY ? PRODUCT_CT_UPDATE_VALID : PRODUCT_CT_UPDATE_VALID_NEW));
  assert (r.timeout == (phase == PRODUCT_ICMP_REPLY ? PRODUCT_CT_TIMEOUT_ICMP_REPLY : PRODUCT_CT_TIMEOUT_ICMP_FIRST));
  assert (r.refresh_deadline && !r.close_old_instance && !r.create_replacement);
}

static void
transitions (unsigned family, int reply_first)
{
  product_icmp_state_t state = {0};
  product_packet_facts_t first = echo (family, reply_first), opposite = echo (family, !reply_first);
  for (unsigned sequence = 0; sequence < 4; sequence++)
    {
      first.icmp_sequence = sequence == 3 ? 65535 : sequence;
      result_is (product_icmp_update (&state, &first, PRODUCT_FLOW_DIRECTION_ORIG),
                 PRODUCT_ICMP_FIRST, PRODUCT_FLOW_DIRECTION_ORIG);
      assert (state.phase == PRODUCT_ICMP_FIRST);
      assert (state.seen_request == !reply_first && state.seen_reply == reply_first);
    }
  result_is (product_icmp_update (&state, &opposite, PRODUCT_FLOW_DIRECTION_REPLY),
             PRODUCT_ICMP_REPLY, PRODUCT_FLOW_DIRECTION_REPLY);
  assert (state.phase == PRODUCT_ICMP_REPLY && state.seen_request && state.seen_reply);
  for (unsigned direction = 1; direction <= 2; direction++)
    result_is (product_icmp_update (&state, direction == 1 ? &first : &opposite, direction),
               PRODUCT_ICMP_REPLY, direction);

  /* Packet kind is not a direction selector: degenerate ORIG projection is
   * still FIRST, but the actual reply observation is never lost or invented. */
  state = (product_icmp_state_t){0};
  (void) product_icmp_update (&state, &first, PRODUCT_FLOW_DIRECTION_ORIG);
  result_is (product_icmp_update (&state, &opposite, PRODUCT_FLOW_DIRECTION_ORIG),
             PRODUCT_ICMP_FIRST, PRODUCT_FLOW_DIRECTION_ORIG);
  assert (state.seen_request && state.seen_reply);
}

static void
invalid_inputs (unsigned family)
{
  product_packet_facts_t valid = echo (family, 0);
  assert (product_icmp_update (NULL, &valid, 1).update == PRODUCT_CT_UPDATE_INVALID);
  product_icmp_state_t empty = {0};
  assert (product_icmp_update (&empty, &valid, 2).update == PRODUCT_CT_UPDATE_INVALID);
  assert (!empty.phase && !empty.seen_request && !empty.seen_reply);
  for (unsigned phase = PRODUCT_ICMP_EMPTY; phase <= PRODUCT_ICMP_REPLY; phase++)
    for (unsigned failure = 0; failure < 15; failure++)
      {
        product_icmp_state_t state = {phase, phase != 0, phase == PRODUCT_ICMP_REPLY};
        product_packet_facts_t packet = valid;
        product_flow_direction_t direction = PRODUCT_FLOW_DIRECTION_ORIG;
        switch (failure)
          {
          case 0: packet.l3_status = PRODUCT_PACKET_L3_UNAVAILABLE; break;
          case 1: packet.l4_status = PRODUCT_PACKET_L4_UNAVAILABLE; break;
          case 2: packet.l4_status = PRODUCT_PACKET_L4_COMPLETE; break;
          case 3: packet.protocol = family == 4 ? 58 : 1; break;
          case 4: packet.ip_family = 5; break;
          case 5: packet.icmp_identity_known = 0; break;
          case 6: packet.icmp_code = 1; break;
          case 7: packet.icmp_type = family == 4 ? 3 : 1; break; /* error, not RELATED */
          case 8: packet.icmp_type = family == 4 ? 13 : 133; break; /* timestamp/router */
          case 9: direction = PRODUCT_FLOW_DIRECTION_UNKNOWN; break;
          case 10: direction = 99; break;
          case 11: state.phase = 255; break;
          case 12: state.seen_request = 2; break;
          case 13: state.seen_reply = 2; break;
          case 14: break;
          }
        product_icmp_state_t before = state;
        product_tracker_result_t r = product_icmp_update (&state, failure == 14 ? NULL : &packet, direction);
        assert (r.facts.state == PRODUCT_CT_INVALID && r.update == PRODUCT_CT_UPDATE_INVALID);
        assert (r.timeout == PRODUCT_CT_TIMEOUT_NONE && !r.refresh_deadline);
        assert (!r.close_old_instance && !r.create_replacement && !memcmp (&before, &state, sizeof state));
      }
}

static const product_worker_layout_t layout = {2, UINT64_C (0x6f776e65722d3137)};

static product_owner_assignment_t
assign (const product_packet_facts_t *packet)
{
  product_owner_assignment_t assignment;
  assert (product_owner_assign (&layout, packet, &assignment) == PRODUCT_PACKET_OK);
  assert (assignment.key.kind == PRODUCT_OWNER_KEY_ICMP_QUERY);
  return assignment;
}

static void
ended (void *context, const product_flow_entry_t *entry, uint32_t slot, product_flow_end_reason_t reason)
{
  (void) slot;
  assert (reason == PRODUCT_FLOW_END_CLOSED && entry->in_use && !entry->linked);
  assert (entry->protocol_state.icmp.phase == PRODUCT_ICMP_REPLY);
  ++*(unsigned *) context;
}

static void
runtime_query (unsigned family, int reply_first)
{
  product_packet_facts_t first = echo (family, reply_first), reply = echo (family, !reply_first);
  product_owner_assignment_t a = assign (&first), reverse = assign (&reply);
  assert (a.canonical_hash == reverse.canonical_hash && a.execution_owner == reverse.execution_owner);
  assert (a.source_is_a != reverse.source_is_a);
  product_flow_runtime_t *runtime = NULL;
  assert (product_flow_runtime_create (&runtime, a.execution_owner, 2, 224, 1) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  unsigned end_count = 0;
  assert (product_flow_runtime_set_end_callback (runtime, ended, &end_count) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_flow_entry_packet_t p = {.facts = &first, .policy = {224, 1, 101}, .packet_bytes = 64,
    .device_direction = PRODUCT_PACKET_DIRECTION_INPUT, .timestamp = 1};
  product_flow_entry_observation_t o;
  assert (product_flow_entry_observe (runtime, &a, &p, 1, &o) == PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
  assert (!product_flow_runtime_snapshot (runtime).active_entries);
  assert (product_flow_entry_observe (runtime, &a, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK && o.created);
  const product_flow_entry_t *entry = o.entry;
  uint64_t incarnation = entry->incarnation;
  uint32_t slot = o.slot;
  assert (entry->origin_is_endpoint_a == a.source_is_a && o.flow_direction == PRODUCT_FLOW_DIRECTION_ORIG);
  assert (entry->protocol_state.icmp.seen_request == !reply_first && entry->protocol_state.icmp.seen_reply == reply_first);
  for (unsigned sequence = 1; sequence <= 3; sequence++)
    {
      first.icmp_sequence = sequence == 3 ? 65535 : sequence;
      product_owner_assignment_t same = assign (&first);
      assert (!memcmp (&same.key, &a.key, sizeof a.key) && same.canonical_hash == a.canonical_hash);
      ++p.timestamp;
      assert (product_flow_entry_observe (runtime, &same, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK && o.reused);
      assert (o.entry == entry && entry->incarnation == incarnation && o.slot == slot);
      result_is (o.tracker, PRODUCT_ICMP_FIRST, PRODUCT_FLOW_DIRECTION_ORIG);
    }
  p.facts = &reply; p.policy = (product_flow_policy_identity_t){224, 2, 202}; ++p.timestamp;
  assert (product_flow_entry_observe (runtime, &reverse, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (o.reused && o.revision_invalidated && o.entry == entry && entry->incarnation == incarnation);
  result_is (o.tracker, PRODUCT_ICMP_REPLY, PRODUCT_FLOW_DIRECTION_REPLY);
  assert (entry->protocol_state.icmp.seen_request && entry->protocol_state.icmp.seen_reply);
  assert (entry->side_packets[0] == 4 && entry->side_packets[1] == 1);
  assert (entry->side_bytes[0] == 256 && entry->side_bytes[1] == 64);
  assert (!entry->deadline_us && !product_flow_runtime_snapshot (runtime).timer_entries); /* S236 */

  product_icmp_state_t accepted = entry->protocol_state.icmp;
  reply.icmp_code = 1; ++p.timestamp;
  assert (product_flow_entry_observe (runtime, &reverse, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (o.tracker.update == PRODUCT_CT_UPDATE_INVALID && !o.tracker.refresh_deadline);
  assert (!memcmp (&accepted, &entry->protocol_state.icmp, sizeof accepted));
  assert (entry->packets == 6 && product_flow_runtime_snapshot (runtime).protocol[2].invalid_packets == 1);
  reply.icmp_code = 0;
  product_flow_entry_t before = *entry;
  p.policy.generation++;
  assert (product_flow_entry_observe (runtime, &reverse, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
  p.policy.generation--;
  product_owner_assignment_t wrong = reverse; wrong.execution_owner ^= 1;
  assert (product_flow_entry_observe (runtime, &wrong, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER);
  wrong = reverse; wrong.key.query_class = 2;
  assert (product_flow_entry_observe (runtime, &wrong, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  p.facts = NULL;
  assert (product_flow_entry_observe (runtime, &reverse, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  p.facts = &reply;
  reply.icmp_identifier++;
  assert (product_flow_entry_observe (runtime, &reverse, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  assert (!memcmp (&before, entry, sizeof before));
  /* Explicit complete-hash collision on the same owner, not a second owner
   * selection: identifier must still distinguish the candidate. */
  product_owner_assignment_t different = reverse;
  different.key.transport.query.identifier = reply.icmp_identifier;
  assert (product_flow_entry_observe (runtime, &different, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED);
  assert (!o.entry && o.tracker.update == PRODUCT_CT_UPDATE_NONE);
  assert (product_flow_runtime_close (runtime, slot, 224, incarnation, PRODUCT_FLOW_END_CLOSED) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (end_count == 1 && entry->in_use && entry->protocol_state.icmp.seen_request && entry->protocol_state.icmp.seen_reply);
  assert (product_flow_entry_observe (runtime, &different, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED);
  assert (product_flow_runtime_release_end (runtime, slot, 224, incarnation, PRODUCT_FLOW_END_CLOSED) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (!product_flow_runtime_snapshot (runtime).active_entries);
  reply.icmp_code = 1;
  assert (product_flow_entry_observe (runtime, &different, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (o.tracker.update == PRODUCT_CT_UPDATE_INVALID && !o.entry && !product_flow_runtime_snapshot (runtime).active_entries);
  reply.icmp_code = 0;
  assert (product_flow_entry_observe (runtime, &different, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK && o.created);
  assert (o.entry->incarnation > incarnation && o.entry->protocol_state.icmp.phase == PRODUCT_ICMP_FIRST);
  product_flow_runtime_flush (runtime);
  product_flow_runtime_snapshot_t s = product_flow_runtime_snapshot (runtime);
  /* Total releases include both the one END and one drained admin release. */
  assert (!s.active_entries && !s.ending_entries && !s.timer_entries && s.release_count == 2 && s.administrative_release_count == 1);
  product_flow_runtime_destroy (runtime);
}

int main (void)
{
  for (unsigned family = 4; family <= 6; family += 2)
    {
      invalid_inputs (family);
      for (int reply_first = 0; reply_first <= 1; reply_first++)
        {
          transitions (family, reply_first);
          runtime_query (family, reply_first);
        }
    }
  printf ("S224 ICMP Echo: pinned phases, reply-first facts, shared identity/capacity/END PASS; entry_bytes=%zu\n", sizeof (product_flow_entry_t));
  return 0;
}
