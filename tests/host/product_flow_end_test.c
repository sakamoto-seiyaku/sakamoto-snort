/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Storage-lifetime vectors only. This callback is not evidence of VPP graph
 * traversal, native allocation, native free callbacks, or platform verdicts. */
typedef struct
{
  const product_flow_entry_t *entry;
  product_flow_entry_t snapshot;
  uint32_t slot, calls;
  product_flow_end_reason_t reason;
} observation_t;

static void
prefetch (product_flow_runtime_t *runtime, const product_owner_assignment_t *assignment)
{
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
  product_flow_runtime_prefetch (runtime, assignment, PRODUCT_FLOW_PREFETCH_BUCKET);
  product_flow_runtime_prefetch (runtime, assignment, PRODUCT_FLOW_PREFETCH_INDEX);
  product_flow_runtime_prefetch (runtime, assignment, PRODUCT_FLOW_PREFETCH_STATE);
#else
  (void) runtime; (void) assignment;
#endif
}

static void
ended (void *context, const product_flow_entry_t *entry, uint32_t slot,
        product_flow_end_reason_t reason)
{
  observation_t *o = context;
  assert (entry->in_use && !entry->linked && entry->end_reason == reason);
  o->entry = entry;
  o->snapshot = *entry;
  o->slot = slot;
  o->reason = reason;
  o->calls++;
}

static void
lifetime (unsigned family, unsigned capacity)
{
  product_packet_facts_t f = {
    .l3_status = PRODUCT_PACKET_L3_COMPLETE, .l4_status = PRODUCT_PACKET_L4_COMPLETE,
    .ip_family = family, .protocol = 17, .source_port = 22500, .destination_port = 53,
  };
  f.source_address[15] = 1;
  f.destination_address[15] = 2;
  if (family == 6) f.source_address[0] = f.destination_address[0] = 0x20;
  const product_worker_layout_t layout = {2, 225};
  product_owner_assignment_t a;
  assert (product_owner_assign (&layout, &f, &a) == PRODUCT_PACKET_OK);
  product_flow_runtime_t *runtime = NULL;
  assert (product_flow_runtime_create (&runtime, a.execution_owner, 2, 5, capacity)
          == PRODUCT_FLOW_ENTRY_STATUS_OK);
  observation_t end = {0};
  assert (product_flow_runtime_set_end_callback (runtime, ended, &end)
          == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (product_flow_runtime_set_end_callback (runtime, ended, &end)
          == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  product_flow_entry_packet_t p = {
    .facts = &f, .policy = {5, 1, 225}, .uid = 10001, .network_context = 1,
    .packet_bytes = 64, .timestamp = 100, .device_direction = 3,
  };
  product_flow_entry_observation_t o;
  prefetch (runtime, &a); /* Prepared miss must not prevent the first create. */
  assert (product_flow_entry_observe (runtime, &a, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  uint32_t slot = o.slot;
  uint64_t incarnation = o.entry->incarnation;
  a.source_is_a ^= 1;
  p.timestamp = 200; p.device_direction = 1;
  assert (product_flow_entry_observe (runtime, &a, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (o.entry->side_packets[0] == 1 && o.entry->side_packets[1] == 1);
  assert (product_flow_runtime_close (runtime, slot, 4, incarnation, PRODUCT_FLOW_END_CLOSED)
          == PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
  assert (product_flow_runtime_close (runtime, slot, 5, incarnation + 1, PRODUCT_FLOW_END_CLOSED)
          == PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND);
  assert (product_flow_runtime_release_end (runtime, slot, 5, incarnation, PRODUCT_FLOW_END_CLOSED)
          == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  assert (end.calls == 0 && o.entry->linked);
  prefetch (runtime, &a); /* Candidate prepared before this tuple is unlinked. */
  assert (product_flow_runtime_close (runtime, slot, 5, incarnation, PRODUCT_FLOW_END_EXPIRED)
          == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (end.calls == 1 && end.entry == o.entry && end.slot == slot);
  assert (end.snapshot.first_seen == 100 && end.snapshot.last_seen == 200);
  assert (end.snapshot.protocol_state.udp.phase == PRODUCT_UDP_BIDIR);
  assert (product_flow_runtime_close (runtime, slot, 5, incarnation, PRODUCT_FLOW_END_EXPIRED)
          == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  assert (end.calls == 1);
  assert (product_flow_entry_set_decision (runtime, end.entry, &p.policy, 1, 1, 0)
          == PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT);
  assert (product_flow_runtime_flush (runtime) == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  assert (!memcmp (end.entry, &end.snapshot, sizeof (end.snapshot)));
  product_flow_runtime_snapshot_t s = product_flow_runtime_snapshot (runtime);
  assert (s.active_entries == 1 && !s.linked_entries && s.ending_entries == 1 && !s.release_count);
  p.timestamp = 300;
  prefetch (runtime, &a);
  product_flow_entry_status_t status = product_flow_entry_observe (runtime, &a, &p, 0, &o);
  if (capacity == 1)
    assert (status == PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED && !o.entry);
  else
    {
      assert (status == PRODUCT_FLOW_ENTRY_STATUS_OK && o.created && o.slot != slot);
      assert (o.entry->incarnation != incarnation && o.entry->packets == 1);
    }
  assert (!memcmp (end.entry, &end.snapshot, sizeof (end.snapshot)));
  assert (product_flow_runtime_release_end (runtime, slot, 5, incarnation, PRODUCT_FLOW_END_CLOSED)
          == PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE);
  prefetch (runtime, &a);
  assert (product_flow_runtime_release_end (runtime, slot, 5, incarnation, PRODUCT_FLOW_END_EXPIRED)
          == PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert (!product_flow_runtime_entry (runtime, slot));
  assert (product_flow_runtime_release_end (runtime, slot, 5, incarnation, PRODUCT_FLOW_END_EXPIRED)
          == PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND);
  if (capacity == 1)
    {
      /* The earlier candidate's address is reused, but its incarnation is not. */
      assert (product_flow_entry_observe (runtime, &a, &p, 0, &o) == PRODUCT_FLOW_ENTRY_STATUS_OK);
      assert (o.created && o.slot == slot && o.entry->incarnation != incarnation);
      assert (product_flow_runtime_release_end (runtime, slot, 5, incarnation, PRODUCT_FLOW_END_EXPIRED)
              == PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND);
    }
  assert (product_flow_runtime_flush (runtime) == PRODUCT_FLOW_ENTRY_STATUS_OK);
  s = product_flow_runtime_snapshot (runtime);
  assert (!s.active_entries && !s.ending_entries && !s.linked_entries);
  assert (s.release_count == 2 && s.administrative_release_count == 1);
  prefetch (runtime, &a);
  product_flow_runtime_destroy (runtime);
}

static void
colliding_close (void)
{
  /* A full-hash collision chain must preserve unrelated identities when a
   * middle flow is unlinked and its END is released after tuple replacement. */
  product_flow_runtime_t *runtime = NULL;
  assert (!product_flow_runtime_create (&runtime, 0, 2, 5, 4));
  observation_t end = {0};
  assert (!product_flow_runtime_set_end_callback (runtime, ended, &end));
  product_worker_layout_t layout = {2, 225};
  product_packet_facts_t f = {
    .l3_status = PRODUCT_PACKET_L3_COMPLETE, .l4_status = PRODUCT_PACKET_L4_COMPLETE,
    .ip_family = 4, .protocol = 17, .source_port = 22000, .destination_port = 53,
  };
  f.source_address[15] = 1; f.destination_address[15] = 2;
  product_flow_entry_packet_t p = {
    .facts = &f, .policy = {5, 1, 225}, .uid = 10001,
    .packet_bytes = 64, .timestamp = 100, .device_direction = 3,
  };
  product_owner_assignment_t keys[4];
  product_flow_entry_observation_t flows[3], replacement;
  uint64_t incarnations[3];
  for (unsigned i = 0; i < 4; i++)
    {
      f.source_port++;
      assert (!product_owner_assign (&layout, &f, &keys[i]));
      keys[i].execution_owner = 0;
      keys[i].canonical_hash = UINT64_C (0x424200004242);
      prefetch (runtime, &keys[i]);
      if (i < 3)
        {
          assert (!product_flow_entry_observe (runtime, &keys[i], &p, 0, &flows[i]));
          incarnations[i] = flows[i].entry->incarnation;
        }
    }
  prefetch (runtime, &keys[1]);
  assert (!product_flow_runtime_close (runtime, flows[1].slot, 5, incarnations[1],
    PRODUCT_FLOW_END_CLOSED));
  assert (!product_flow_entry_current_incarnation (runtime, &keys[1], 5, 100));
  assert (product_flow_entry_current_incarnation (runtime, &keys[0], 5, 100) == incarnations[0]);
  assert (product_flow_entry_current_incarnation (runtime, &keys[2], 5, 100) == incarnations[2]);
  prefetch (runtime, &keys[1]);
  assert (!product_flow_entry_observe (runtime, &keys[1], &p, 0, &replacement));
  assert (replacement.created && replacement.slot != flows[1].slot);
  assert (!memcmp (end.entry, &end.snapshot, sizeof end.snapshot));
  assert (!product_flow_runtime_release_end (runtime, flows[1].slot, 5,
    incarnations[1], PRODUCT_FLOW_END_CLOSED));
  prefetch (runtime, &keys[1]);
  assert (product_flow_entry_current_incarnation (runtime, &keys[1], 5, 100)
          == replacement.entry->incarnation);
  for (unsigned i = 0; i < 3; i += 2)
    {
      product_flow_entry_observation_t hit;
      prefetch (runtime, &keys[i]);
      assert (!product_flow_entry_observe (runtime, &keys[i], &p, 0, &hit));
      assert (hit.reused && hit.entry->incarnation == incarnations[i]);
    }
  uint64_t replaced = replacement.entry->incarnation;
  uint32_t reused_slot = replacement.slot;
  prefetch (runtime, &keys[1]);
  assert (!product_flow_runtime_close (runtime, reused_slot, 5, replaced,
    PRODUCT_FLOW_END_CLOSED));
  assert (!product_flow_runtime_release_end (runtime, reused_slot, 5, replaced,
    PRODUCT_FLOW_END_CLOSED));
  assert (!product_flow_entry_observe (runtime, &keys[3], &p, 0, &replacement));
  assert (replacement.created && replacement.slot == reused_slot);
  assert (!product_flow_entry_current_incarnation (runtime, &keys[1], 5, 100));
  assert (!product_flow_runtime_flush (runtime));
  product_flow_runtime_snapshot_t state = product_flow_runtime_snapshot (runtime);
  assert (!state.active_entries && !state.linked_entries && !state.ending_entries
          && state.release_count == 5 && state.administrative_release_count == 3);
  product_flow_runtime_destroy (runtime);
}

int
main (void)
{
  colliding_close ();
  for (unsigned family = 4; family <= 6; family += 2)
    for (unsigned capacity = 1; capacity <= 2; capacity++)
      lifetime (family, capacity);
  puts ("FlowRuntime END: unlink, immutable retention, bounded replacement, guarded final release and drain PASS");
  return 0;
}
