/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
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

int main (void)
{
  const unsigned sizes[] = {1, 2, 3, 4, 99, 100, 1000, CAPACITY};
  for (unsigned i = 0; i < sizeof (sizes) / sizeof (sizes[0]); i++) indexed_order (sizes[i]);
  logical_expiry ();
  puts ("FlowRuntime indexed expiry: fixed memory, refresh/shorten/order/budget/END/lookup/generation/flush PASS");
  return 0;
}
