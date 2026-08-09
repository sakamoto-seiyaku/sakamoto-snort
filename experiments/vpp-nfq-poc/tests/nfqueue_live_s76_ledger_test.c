/* SPDX-License-Identifier: Apache-2.0 */

/* Deterministic S76 ledger model.  It deliberately carries only a buffer
 * index plus inline identity; there is no packet byte storage or side lease
 * table.  The runtime plugin supplies the VPP/native implementation, while
 * this test makes each bounded route and exactly-once rule executable without
 * a kernel namespace. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum
{
  MODE_MIXED,
  MODE_LOCAL,
  MODE_REMOTE,
  CREDIT_CAPACITY = 8,
};

typedef struct
{
  uint32_t buffer_index;
  uintptr_t buffer_base;
  uint32_t packet_id;
  uint32_t payload_offset;
  uint32_t payload_length;
  uint64_t generation;
  uint32_t origin_lane;
  uint32_t obligation_nonce;
  uint32_t references;
  uint32_t verdict_attempted;
} identity_t;

typedef struct
{
  identity_t before;
  identity_t after;
  uint32_t source_worker;
  uint32_t destination_worker;
  uint32_t slot;
  uint8_t before_stage;
  uint8_t after_stage;
} handoff_pair_t;

typedef struct
{
  uint64_t local;
  uint64_t remote;
  uint64_t handoffs;
  uint64_t queue_full;
  uint64_t terminal_intents;
  uint64_t credit_acquired;
  uint64_t credit_released;
  uint64_t credit_exhausted;
  uint32_t credits_held;
  uint64_t proof_checks;
  uint64_t proof_matches;
  uint64_t proof_failures;
  uint64_t stale;
  uint64_t duplicate;
  uint64_t verdicts;
  uint64_t native_returns;
} ledger_t;

static void
fail (const char *what)
{
  fprintf (stderr, "S76 deterministic failure: %s\n", what);
  exit (1);
}

static void
expect (int condition, const char *what)
{
  if (!condition)
    fail (what);
}

static uint32_t
initial_worker (uint32_t origin_lane)
{
  return (origin_lane & 1u) ? 2u : 1u;
}

static uint32_t
canonical_worker (uint32_t mode, uint32_t origin_lane, uint32_t packet_id)
{
  uint32_t initial = initial_worker (origin_lane);
  if (mode == MODE_LOCAL)
    return initial;
  if (mode == MODE_REMOTE)
    return initial == 1u ? 2u : 1u;
  return ((packet_id ^ origin_lane) & 1u) == 0 ? initial :
                                                (initial == 1u ? 2u : 1u);
}

static int
same_identity (const identity_t *before, const identity_t *after)
{
  return before->buffer_index == after->buffer_index &&
         before->buffer_base == after->buffer_base &&
         before->packet_id == after->packet_id &&
         before->payload_offset == after->payload_offset &&
         before->payload_length == after->payload_length &&
         before->generation == after->generation &&
         before->origin_lane == after->origin_lane &&
         before->obligation_nonce == after->obligation_nonce;
}

static int
same_handoff_pair (const handoff_pair_t *pair, uint32_t expected_source,
                   uint32_t expected_destination)
{
  return pair->source_worker == expected_source &&
         pair->destination_worker == expected_destination &&
         pair->slot < 127u && pair->before_stage == 0u &&
         (pair->after_stage & 0x80u) != 0 &&
         (pair->after_stage & 0x7fu) == pair->slot &&
         same_identity (&pair->before, &pair->after);
}

static int
acquire_credit (ledger_t *ledger, int inject_exhaustion)
{
  if (inject_exhaustion || ledger->credits_held == CREDIT_CAPACITY)
    {
      ledger->credit_exhausted++;
      return 0;
    }
  ledger->credits_held++;
  ledger->credit_acquired++;
  return 1;
}

static void
release_credit (ledger_t *ledger)
{
  expect (ledger->credits_held != 0, "credit underflow");
  ledger->credits_held--;
  ledger->credit_released++;
}

static void
settle (ledger_t *ledger, identity_t *current, const identity_t *entry,
        int terminal)
{
  if (!same_identity (current, entry) || current->references == 0)
    {
      ledger->stale++;
      return;
    }
  if (current->verdict_attempted)
    {
      ledger->duplicate++;
      current->references--;
    }
  else
    {
      current->verdict_attempted = 1;
      ledger->verdicts++;
      current->references--;
    }
  if (current->references == 0)
    {
      ledger->native_returns++;
      release_credit (ledger);
    }
  (void) terminal;
}

static void
admit_and_complete (ledger_t *ledger, uint32_t mode, uint32_t lane,
                    uint32_t packet_id, uint32_t buffer_index,
                    int queue_full)
{
  identity_t current = {
    .buffer_index = buffer_index,
    .buffer_base = 0x10000000u + buffer_index * 0x1000u,
    .packet_id = packet_id,
    .payload_offset = 64u,
    .payload_length = 96u,
    .generation = 7u,
    .origin_lane = lane,
    .obligation_nonce = packet_id + 1000u,
    .references = 1,
  };
  identity_t before = current;
  expect (acquire_credit (ledger, 0), "normal admission credit");
  uint32_t initial = initial_worker (lane);
  uint32_t canonical = canonical_worker (mode, lane, packet_id);
  if (canonical == initial)
    ledger->local++;
  else
    {
      ledger->remote++;
      ledger->handoffs++;
      if (queue_full)
        {
          ledger->queue_full++;
          ledger->terminal_intents++;
          settle (ledger, &current, &before, 1);
          return;
        }
      identity_t after = current;
      handoff_pair_t pair = {
        .before = before,
        .after = after,
        .source_worker = initial,
        .destination_worker = canonical,
        .slot = (packet_id + lane) % 127u,
        .before_stage = 0u,
        .after_stage = (uint8_t) (0x80u | ((packet_id + lane) % 127u)),
      };
      ledger->proof_checks++;
      if (same_handoff_pair (&pair, initial, canonical))
        ledger->proof_matches++;
      else
        ledger->proof_failures++;
    }
  settle (ledger, &current, &before, 0);
}

static void
run_identity_pair (void)
{
  identity_t before = {
    .buffer_index = 41,
    .buffer_base = 0x1000,
    .packet_id = 501,
    .payload_offset = 44,
    .payload_length = 104,
    .generation = 9,
    .origin_lane = 2,
    .obligation_nonce = 1501,
  };
  handoff_pair_t pair = {
    .before = before,
    .after = before,
    .source_worker = 1,
    .destination_worker = 2,
    .slot = 11,
    .before_stage = 0,
    .after_stage = 0x80u | 11u,
  };
  expect (same_handoff_pair (&pair, 1, 2),
          "full identity handoff pair");
  pair.after.obligation_nonce++;
  expect (!same_handoff_pair (&pair, 1, 2),
          "handoff obligation mismatch detection");
  printf ("identity pair: full-fields=1 mismatch-detected=1\n");
}

static void
run_normal_mixed (void)
{
  ledger_t ledger = { 0 };
  for (uint32_t i = 0; i < 8; i++)
    admit_and_complete (&ledger, MODE_MIXED, i % 4, 100u, i + 1, 0);
  expect (ledger.local == 4 && ledger.remote == 4, "mixed local/remote split");
  expect (ledger.handoffs == 4 && ledger.proof_checks == 4 &&
            ledger.proof_matches == 4 && ledger.proof_failures == 0,
          "mixed identity proof");
  expect (ledger.verdicts == 8 && ledger.native_returns == 8,
          "mixed exactly-once settlement");
  expect (ledger.credit_acquired == 8 && ledger.credit_released == 8 &&
            ledger.credits_held == 0,
          "mixed credit residue");
  printf ("normal mixed: local=%llu remote=%llu handoffs=%llu proof=%llu/%llu "
          "verdicts=%llu native-returns=%llu credits=%llu/%llu residue=%u\n",
          (unsigned long long) ledger.local,
          (unsigned long long) ledger.remote,
          (unsigned long long) ledger.handoffs,
          (unsigned long long) ledger.proof_matches,
          (unsigned long long) ledger.proof_checks,
          (unsigned long long) ledger.verdicts,
          (unsigned long long) ledger.native_returns,
          (unsigned long long) ledger.credit_acquired,
          (unsigned long long) ledger.credit_released, ledger.credits_held);
}

static void
run_queue_full (void)
{
  ledger_t ledger = { 0 };
  admit_and_complete (&ledger, MODE_REMOTE, 0, 200u, 10u, 1);
  expect (ledger.queue_full == 1 && ledger.terminal_intents == 1,
          "queue-full terminal intent");
  expect (ledger.verdicts == 1 && ledger.native_returns == 1 &&
            ledger.credits_held == 0,
          "queue-full closure");
  printf ("queue-full fault: queue-full=%llu terminal-intents=%llu verdicts=%llu "
          "native-returns=%llu residue=%u\n",
          (unsigned long long) ledger.queue_full,
          (unsigned long long) ledger.terminal_intents,
          (unsigned long long) ledger.verdicts,
          (unsigned long long) ledger.native_returns, ledger.credits_held);
}

static void
run_credit_exhaustion (void)
{
  ledger_t ledger = { 0 };
  expect (!acquire_credit (&ledger, 1), "injected credit exhaustion");
  admit_and_complete (&ledger, MODE_LOCAL, 0, 300u, 11u, 0);
  expect (ledger.credit_exhausted == 1 && ledger.credit_acquired == 1 &&
            ledger.credit_released == 1 && ledger.credits_held == 0,
          "credit exhaustion closure");
  printf ("credit exhaustion fault: exhausted=%llu acquired=%llu released=%llu "
          "residue=%u\n",
          (unsigned long long) ledger.credit_exhausted,
          (unsigned long long) ledger.credit_acquired,
          (unsigned long long) ledger.credit_released, ledger.credits_held);
}

static void
run_stale_duplicate (void)
{
  ledger_t ledger = { 0 };
  identity_t current = {
    .buffer_index = 12,
    .buffer_base = 0x1000,
    .packet_id = 400,
    .payload_offset = 64,
    .payload_length = 96,
    .generation = 8,
    .origin_lane = 1,
    .references = 2,
  };
  identity_t stale = current;
  stale.generation++;
  identity_t primary = current;
  identity_t duplicate = current;
  expect (acquire_credit (&ledger, 0), "duplicate admission credit");
  settle (&ledger, &current, &stale, 0);
  settle (&ledger, &current, &primary, 0);
  settle (&ledger, &current, &duplicate, 0);
  expect (ledger.stale == 1 && ledger.duplicate == 1 && ledger.verdicts == 1 &&
            ledger.native_returns == 1 && ledger.credits_held == 0,
          "stale/duplicate exactly-once closure");
  printf ("stale+duplicate fault: stale=%llu duplicate=%llu verdicts=%llu "
          "native-returns=%llu residue=%u\n",
          (unsigned long long) ledger.stale,
          (unsigned long long) ledger.duplicate,
          (unsigned long long) ledger.verdicts,
          (unsigned long long) ledger.native_returns, ledger.credits_held);
}

int
main (void)
{
  run_identity_pair ();
  run_normal_mixed ();
  run_queue_full ();
  run_credit_exhaustion ();
  run_stale_duplicate ();
  puts ("S76 deterministic ledger: PASS");
  return 0;
}
