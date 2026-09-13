/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include "product_flow_timeout.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { CAPACITY = 4096 };
typedef struct {
  uint32_t slots[CAPACITY], count;
  uint64_t incarnations[CAPACITY], deadlines[CAPACITY];
} ends_t;

static void
ended (void *context, const product_flow_entry_t *entry, uint32_t slot,
       product_flow_end_reason_t reason)
{
  ends_t *ends = context;
  assert (!entry->linked && entry->in_use && entry->heap_position == UINT32_MAX);
  assert (reason == PRODUCT_FLOW_END_EXPIRED && ends->count < CAPACITY);
  unsigned at = ends->count++;
  ends->slots[at] = slot;
  ends->incarnations[at] = entry->incarnation;
  ends->deadlines[at] = entry->deadline_us;
}

static uint32_t
random32 (uint32_t *state)
{
  *state ^= *state << 13;
  *state ^= *state >> 17;
  *state ^= *state << 5;
  return *state;
}

static product_flow_entry_observation_t
observe (product_flow_runtime_t *runtime, unsigned index, uint64_t now)
{
  product_packet_facts_t facts = {
    .l3_status = PRODUCT_PACKET_L3_COMPLETE, .l4_status = PRODUCT_PACKET_L4_COMPLETE,
    .ip_family = index & 1 ? 6 : 4, .protocol = 17,
    .source_port = 10000 + index, .destination_port = 40626,
  };
  facts.source_address[15] = 1;
  facts.destination_address[15] = 2;
  if (facts.ip_family == 6)
    facts.source_address[0] = facts.destination_address[0] = 0x20;
  product_worker_layout_t layout = {1, 226};
  product_owner_assignment_t assignment;
  assert (product_owner_assign (&layout, &facts, &assignment) == PRODUCT_PACKET_OK);
  product_flow_entry_packet_t packet = {
    .facts = &facts, .policy = {226, 0, 0}, .timestamp = now,
    .packet_bytes = 64, .device_direction = PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,
  };
  product_flow_entry_observation_t observation;
  assert (product_flow_entry_observe (runtime, &assignment, &packet,
    PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &observation) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  return observation;
}

static void
indexed_order (unsigned capacity)
{
  product_flow_runtime_t *runtime = NULL;
  ends_t ends = {0};
  assert (!product_flow_runtime_create (&runtime, 0, 1, 226, capacity));
  assert (!product_flow_runtime_set_end_callback (runtime, ended, &ends));
  uint64_t deadlines[CAPACITY] = {0}, incarnations[CAPACITY] = {0};
  uint32_t slots[CAPACITY] = {0}, state = 226;
  for (unsigned i = 0; i < capacity; i++)
    {
      product_flow_entry_observation_t o = observe (runtime, i, 1);
      slots[i] = o.slot;
      incarnations[i] = o.entry->incarnation;
      deadlines[i] = 100 + random32 (&state) % 10000;
      assert (!product_flow_runtime_set_deadline (runtime, o.slot, 226,
        o.entry->incarnation, deadlines[i], PRODUCT_CT_TIMEOUT_OTHER_FIRST));
    }
  uint64_t allocated = product_flow_runtime_snapshot (runtime).allocated_bytes;
  for (unsigned iteration = 0; iteration < 10000; iteration++)
    {
      unsigned i = random32 (&state) % capacity;
      deadlines[i] = iteration % 13 == 0 ? UINT64_MAX : 100 + random32 (&state) % 10000;
      assert (!product_flow_runtime_set_deadline (runtime, slots[i], 226,
        incarnations[i], deadlines[i], PRODUCT_CT_TIMEOUT_OTHER_BIDIR));
      uint64_t minimum = UINT64_MAX;
      for (unsigned j = 0; j < capacity; j++)
        if (deadlines[j] < minimum) minimum = deadlines[j];
      assert (product_flow_runtime_next_deadline (runtime) == minimum);
      product_flow_runtime_snapshot_t snapshot = product_flow_runtime_snapshot (runtime);
      assert (snapshot.timer_entries == capacity && snapshot.allocated_bytes == allocated);
    }
  assert (product_flow_runtime_set_deadline (runtime, slots[0], 225,
    incarnations[0], 1, PRODUCT_CT_TIMEOUT_OTHER_FIRST) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
  assert (product_flow_runtime_set_deadline (runtime, slots[0], 226,
    incarnations[0] + 10000, 1, PRODUCT_CT_TIMEOUT_OTHER_FIRST) == PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND);
  assert (product_flow_runtime_set_deadline (runtime, slots[0], 226,
    incarnations[0], 0, PRODUCT_CT_TIMEOUT_OTHER_FIRST) == PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT);
  uint32_t closed;
  assert (!product_flow_runtime_run_due (runtime, 99, 100, &closed) && !closed);
  while (ends.count < capacity)
    {
      unsigned previous = ends.count;
      uint64_t deadline = product_flow_runtime_next_deadline (runtime);
      unsigned budget = 1 + random32 (&state) % 100;
      assert (!product_flow_runtime_run_due (runtime, deadline, budget, &closed));
      assert (closed > 0 && closed <= budget && ends.count == previous + closed);
      for (unsigned i = previous; i < ends.count; i++)
        {
          assert (ends.deadlines[i] <= deadline);
          if (i) assert (ends.deadlines[i - 1] <= ends.deadlines[i]);
          assert (!product_flow_runtime_release_end (runtime, ends.slots[i], 226,
            ends.incarnations[i], PRODUCT_FLOW_END_EXPIRED));
        }
    }
  product_flow_runtime_snapshot_t snapshot = product_flow_runtime_snapshot (runtime);
  assert (!snapshot.active_entries && !snapshot.timer_entries && !snapshot.ending_entries);
  assert (snapshot.release_count == capacity && !snapshot.administrative_release_count);
  assert (product_flow_runtime_next_deadline (runtime) == UINT64_MAX);
  product_flow_runtime_destroy (runtime);
}

static void
logical_expiry (void)
{
  product_flow_runtime_t *runtime = NULL;
  ends_t ends = {0};
  assert (!product_flow_runtime_create (&runtime, 0, 1, 226, 2));
  assert (!product_flow_runtime_set_end_callback (runtime, ended, &ends));
  product_flow_entry_observation_t first = observe (runtime, 0, 1);
  uint32_t slot = first.slot;
  uint64_t incarnation = first.entry->incarnation;
  assert (!product_flow_runtime_set_deadline (runtime, slot, 226, incarnation,
    60000001, PRODUCT_CT_TIMEOUT_OTHER_FIRST));
  assert (observe (runtime, 0, 60000000).reused);
  product_flow_entry_observation_t next = observe (runtime, 0, 60000001);
  assert (next.created && next.slot != slot && ends.count == 1);
  assert (next.expired_before_observe && next.previous_slot == slot);
  assert (next.previous_incarnation == incarnation && next.previous_deadline_us == 60000001);
  assert (first.entry->incarnation == incarnation && !first.entry->linked);
  assert (!product_flow_runtime_snapshot (runtime).timer_entries);
  assert (product_flow_runtime_set_deadline (runtime, slot, 226, incarnation,
    UINT64_MAX, PRODUCT_CT_TIMEOUT_OTHER_FIRST) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  assert (!product_flow_runtime_release_end (runtime, slot, 226, incarnation, PRODUCT_FLOW_END_EXPIRED));
  assert (!product_flow_runtime_set_deadline (runtime, next.slot, 226,
    next.entry->incarnation, UINT64_MAX, PRODUCT_CT_TIMEOUT_OTHER_BIDIR));
  assert (!product_flow_runtime_flush (runtime));
  assert (!product_flow_runtime_snapshot (runtime).timer_entries);
  product_flow_runtime_destroy (runtime);
}

static void
icmp_tracker_deadlines (void)
{
  /* Real call-site seam: typed packet -> tracker -> pinned duration -> heap.
   * A duration-only test cannot detect the heap API's stale enum ceiling. */
  for (unsigned family = 4; family <= 6; family += 2)
    {
      product_flow_runtime_t *runtime = NULL;
      ends_t ends = {0};
      assert (!product_flow_runtime_create (&runtime, 0, 1, 226, 2));
      assert (!product_flow_runtime_set_end_callback (runtime, ended, &ends));
      product_packet_facts_t facts = {
        .l3_status = PRODUCT_PACKET_L3_COMPLETE,
        .l4_status = PRODUCT_PACKET_L4_OTHER_TERMINAL,
        .ip_family = family, .protocol = family == 4 ? 1 : 58,
        .icmp_type = family == 4 ? 8 : 128,
        .icmp_identity_known = 1, .icmp_identifier = 236,
        .l4_header_length = 8, .transport_length = 8,
      };
      facts.source_address[15] = 1;
      facts.destination_address[15] = 2;
      product_worker_layout_t layout = {1, 226};
      product_owner_assignment_t assignment;
      product_flow_entry_packet_t packet = {
        .facts = &facts, .policy = {226, 0, 0}, .timestamp = 100,
        .packet_bytes = 64, .device_direction = PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,
      };
      product_flow_entry_observation_t observation;
      for (unsigned reply = 0; reply < 2; reply++)
        {
          assert (!product_owner_assign (&layout, &facts, &assignment));
          assert (!product_flow_entry_observe (runtime, &assignment, &packet,
            PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &observation));
          assert (observation.tracker.timeout == (reply ? PRODUCT_CT_TIMEOUT_ICMP_REPLY : PRODUCT_CT_TIMEOUT_ICMP_FIRST));
          uint64_t deadline;
          assert (product_flow_deadline (observation.tracker.timeout, packet.timestamp, &deadline));
          assert (!product_flow_runtime_set_deadline (runtime, observation.slot, 226,
            observation.entry->incarnation, deadline, observation.tracker.timeout));
          assert (product_flow_runtime_snapshot (runtime).timer_entries == 1);
          assert (product_flow_runtime_next_deadline (runtime) == deadline);
          facts.source_address[15] = 2; facts.destination_address[15] = 1;
          facts.icmp_type = family == 4 ? 0 : 129;
          packet.timestamp = 200;
        }
      const product_flow_entry_t *entry = observation.entry;
      assert (entry->deadline_us == 30000200);
      const int unknown[] = {-1, PRODUCT_CT_TIMEOUT_NONE, PRODUCT_CT_TIMEOUT_ICMP_REPLY+1, 255};
      for (unsigned i = 0; i < sizeof (unknown) / sizeof (unknown[0]); i++)
        {
          assert (product_flow_runtime_set_deadline (runtime, observation.slot, 226,
            entry->incarnation, 1, (product_ct_timeout_t) unknown[i]) == PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT);
          assert (entry->deadline_us == 30000200 && entry->timeout_class == PRODUCT_CT_TIMEOUT_ICMP_REPLY);
        }
      uint32_t closed;
      assert (!product_flow_runtime_run_due (runtime, 30000199, 100, &closed) && !closed);
      assert (!product_flow_runtime_run_due (runtime, 30000200, 100, &closed) && closed == 1);
      assert (ends.count == 1);
      assert (!product_flow_runtime_release_end (runtime, observation.slot, 226,
        entry->incarnation, PRODUCT_FLOW_END_EXPIRED));
      assert (!product_flow_runtime_snapshot (runtime).timer_entries);
      product_flow_runtime_destroy (runtime);
    }
}

static void
mixed_owner_deadlines (void)
{
  /* Host boundary vector only; device proof uses unchanged real deadlines.
   * Both owners mix typed TCP/UDP/ICMP in one runtime and one indexed heap. */
  for (unsigned owner = 0; owner < 2; owner++)
    for (unsigned family = 4; family <= 6; family += 2)
      {
        product_flow_runtime_t *runtime = NULL;
        ends_t ends = {0};
        assert (!product_flow_runtime_create (&runtime, owner, 2, 226, 4));
        assert (!product_flow_runtime_set_end_callback (runtime, ended, &ends));
        product_packet_facts_t packets[3] = {0};
        product_owner_assignment_t assignments[3];
        product_flow_entry_observation_t observations[3];
        product_worker_layout_t layout = {2, 226};
        product_flow_entry_packet_t packet = {
          .policy = {226, 0, 0}, .timestamp = 100,
          .packet_bytes = 64, .device_direction = PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,
        };
        for (unsigned p = 0; p < 3; p++)
          {
            product_packet_facts_t *facts = &packets[p];
            *facts = (product_packet_facts_t) {
              .l3_status = PRODUCT_PACKET_L3_COMPLETE,
              .l4_status = p == 2 ? PRODUCT_PACKET_L4_OTHER_TERMINAL : PRODUCT_PACKET_L4_COMPLETE,
              .ip_family = family, .protocol = p == 0 ? 6 : p == 1 ? 17 : family == 4 ? 1 : 58,
              .source_port = 12000, .destination_port = 40636,
              .tcp_flags = 2, .tcp_sequence = 100, .tcp_window = 8192,
              .l4_header_length = p ? 8 : 20, .transport_length = p ? 8 : 20,
              .icmp_identity_known = p == 2, .icmp_identifier = 236,
              .icmp_type = family == 4 ? 8 : 128,
            };
            facts->source_address[15] = 1; facts->destination_address[15] = 2;
            do
              {
                facts->source_port++; facts->icmp_identifier++;
                assert (!product_owner_assign (&layout, facts, &assignments[p]));
              }
            while (assignments[p].execution_owner != owner);
            packet.facts = facts;
            assert (!product_flow_entry_observe (runtime, &assignments[p], &packet,
              PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &observations[p]));
            if (p)
              {
                unsigned char address[16];
                memcpy (address, facts->source_address, sizeof address);
                memcpy (facts->source_address, facts->destination_address, sizeof address);
                memcpy (facts->destination_address, address, sizeof address);
                uint16_t port = facts->source_port;
                facts->source_port = facts->destination_port; facts->destination_port = port;
                facts->icmp_type = family == 4 ? 0 : 129;
                assert (!product_owner_assign (&layout, facts, &assignments[p]));
                assert (!product_flow_entry_observe (runtime, &assignments[p], &packet,
                  PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &observations[p]));
              }
            uint64_t deadline;
            assert (observations[p].tracker.refresh_deadline);
            assert (product_flow_deadline (observations[p].tracker.timeout, packet.timestamp, &deadline));
            assert (deadline == 30000100);
            assert (!product_flow_runtime_set_deadline (runtime, observations[p].slot, 226,
              observations[p].entry->incarnation, deadline, observations[p].tracker.timeout));
          }
        assert (product_flow_runtime_snapshot (runtime).timer_entries == 3);
        packet.facts = &packets[0]; packet.timestamp = 200;
        assert (!product_flow_entry_observe (runtime, &assignments[0], &packet,
          PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &observations[0]));
        uint64_t deadline;
        assert (observations[0].reused && observations[0].tracker.refresh_deadline);
        assert (product_flow_deadline (observations[0].tracker.timeout, packet.timestamp, &deadline));
        assert (!product_flow_runtime_set_deadline (runtime, observations[0].slot, 226,
          observations[0].entry->incarnation, deadline, observations[0].tracker.timeout));
        product_tcp_state_t accepted = observations[0].entry->protocol_state.tcp;
        packets[0].tcp_flags = 3; packet.timestamp = 210;
        assert (!product_flow_entry_observe (runtime, &assignments[0], &packet,
          PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &observations[0]));
        assert (!observations[0].tracker.refresh_deadline);
        assert (!memcmp (&accepted, &observations[0].entry->protocol_state.tcp, sizeof accepted));
        assert (observations[0].entry->deadline_us == 30000200);
        uint32_t count;
        assert (!product_flow_runtime_run_due (runtime, 30000099, 100, &count) && !count);
        assert (!product_flow_runtime_run_due (runtime, 30000100, 100, &count) && count == 2);
        assert (ends.count == 2 && product_flow_runtime_snapshot (runtime).timer_entries == 1);
        uint64_t old_incarnation = observations[0].entry->incarnation;
        packets[0].tcp_flags = 2; packet.timestamp = 30000200;
        assert (!product_flow_entry_observe (runtime, &assignments[0], &packet,
          PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT, &observations[0]));
        assert (observations[0].created && observations[0].expired_before_observe &&
          observations[0].previous_incarnation == old_incarnation && ends.count == 3);
        for (unsigned i = 0; i < ends.count; i++)
          assert (!product_flow_runtime_release_end (runtime, ends.slots[i], 226,
            ends.incarnations[i], PRODUCT_FLOW_END_EXPIRED));
        assert (!product_flow_runtime_flush (runtime));
        product_flow_runtime_snapshot_t final = product_flow_runtime_snapshot (runtime);
        assert (!final.active_entries && !final.timer_entries && !final.ending_entries &&
          final.release_count == 4 && final.administrative_release_count == 1);
        product_flow_runtime_destroy (runtime);
      }
}

int main (void)
{
  icmp_tracker_deadlines ();
  mixed_owner_deadlines ();
  const unsigned sizes[] = {1, 2, 3, 4, 99, 100, 1000, CAPACITY};
  for (unsigned i = 0; i < sizeof (sizes) / sizeof (sizes[0]); i++) indexed_order (sizes[i]);
  logical_expiry ();
  puts ("FlowRuntime indexed expiry: fixed memory, refresh/shorten/order/budget/END/lookup/generation/flush PASS");
  return 0;
}
