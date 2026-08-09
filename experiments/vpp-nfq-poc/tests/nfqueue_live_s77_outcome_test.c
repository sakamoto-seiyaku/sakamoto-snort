/* SPDX-License-Identifier: Apache-2.0 */

/* Deterministic S77 completion model.  It mirrors the VPP probe's bounded
 * inline identity and origin-only completion rule without storing packet
 * bytes.  Each outcome is a one-shot physical attempt; stale and duplicate
 * requests are accounting-only events. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum
{
  OUTCOME_NONE,
  OUTCOME_SUCCEEDED,
  OUTCOME_FAILED_DEFINITE,
  OUTCOME_UNKNOWN,
  POLICY_ACCEPT = 1,
};

typedef struct
{
  uint32_t buffer_index;
  uint32_t packet_id;
  uint64_t generation;
  uint32_t origin_lane;
  uint32_t obligation_nonce;
  uint32_t policy_verdict;
  uint32_t terminal_intent;
  uint32_t references;
  uint32_t attempted;
  uint32_t outcome;
} identity_t;

typedef struct
{
  uint64_t physical_attempts;
  uint64_t succeeded;
  uint64_t failed_definite;
  uint64_t unknown;
  uint64_t stale;
  uint64_t stale_generation;
  uint64_t duplicate;
  uint64_t duplicate_attempts;
  uint64_t native_returns;
  uint64_t debt_raised;
  uint64_t debt_settled;
  uint32_t debt;
  uint64_t terminal_intents;
  uint64_t worker_reentries;
  uint64_t policy_re_evaluations;
  uint64_t retry_attempts;
  uint64_t replacement_payloads;
  uint64_t policy_verdict_rewrites;
  uint64_t terminal_intent_rewrites;
  uint32_t attempted_generation;
  uint32_t attempted_packet_id;
  uint32_t attempted_lane;
} ledger_t;

static void
fail (const char *what)
{
  fprintf (stderr, "S77 deterministic failure: %s\n", what);
  exit (1);
}

static void
expect (int condition, const char *what)
{
  if (!condition)
    fail (what);
}

static int
same_identity (const identity_t *left, const identity_t *right)
{
  return left->buffer_index == right->buffer_index &&
         left->packet_id == right->packet_id &&
         left->generation == right->generation &&
         left->origin_lane == right->origin_lane &&
         left->obligation_nonce == right->obligation_nonce;
}

static void
admit (ledger_t *ledger, identity_t *identity)
{
  identity->references = 1;
  ledger->debt++;
  ledger->debt_raised++;
}

static void
return_buffer (ledger_t *ledger, identity_t *identity)
{
  expect (identity->references == 0, "return before references drain");
  expect (ledger->debt != 0, "completion debt underflow");
  ledger->debt--;
  ledger->debt_settled++;
  ledger->native_returns++;
}

static void
physical_attempt (ledger_t *ledger, identity_t *identity,
                  uint32_t outcome)
{
  expect (!identity->attempted, "second physical verdict attempt");
  identity->attempted = 1;
  identity->outcome = outcome;
  ledger->physical_attempts++;
  ledger->attempted_generation = (uint32_t) identity->generation;
  ledger->attempted_packet_id = identity->packet_id;
  ledger->attempted_lane = identity->origin_lane;
  if (outcome == OUTCOME_SUCCEEDED)
    ledger->succeeded++;
  else if (outcome == OUTCOME_FAILED_DEFINITE)
    ledger->failed_definite++;
  else if (outcome == OUTCOME_UNKNOWN)
    ledger->unknown++;
  else
    fail ("invalid completion outcome");
}

static void
settle (ledger_t *ledger, identity_t *current, const identity_t *entry,
        uint32_t outcome)
{
  if (!same_identity (current, entry) || current->references == 0)
    {
      ledger->stale++;
      if (current->generation != entry->generation)
        ledger->stale_generation++;
      return;
    }
  if (current->attempted)
    {
      ledger->duplicate++;
      ledger->duplicate_attempts++;
      current->references--;
    }
  else
    {
      physical_attempt (ledger, current, outcome);
      current->references--;
    }
  if (current->references == 0)
    return_buffer (ledger, current);
}

static identity_t
new_identity (uint32_t packet_id, uint64_t generation, uint32_t lane,
              uint32_t nonce, uint32_t terminal_intent)
{
  identity_t identity = {
    .buffer_index = 9000u + packet_id,
    .packet_id = packet_id,
    .generation = generation,
    .origin_lane = lane,
    .obligation_nonce = nonce,
    .policy_verdict = POLICY_ACCEPT,
    .terminal_intent = terminal_intent,
  };
  return identity;
}

static void
expect_quiet (const ledger_t *ledger)
{
  expect (ledger->retry_attempts == 0 && ledger->worker_reentries == 0 &&
            ledger->policy_re_evaluations == 0 &&
            ledger->replacement_payloads == 0,
          "completion outcome triggered forbidden re-entry");
  expect (ledger->policy_verdict_rewrites == 0 &&
            ledger->terminal_intent_rewrites == 0,
          "completion rewrote terminal policy intent");
}

static void
run_normal_duplicate_stale (void)
{
  ledger_t ledger = { 0 };
  identity_t current = new_identity (71u, 19u, 2u, 1071u, 0u);
  identity_t stale = current;
  identity_t primary = current;
  identity_t duplicate = current;
  const uint32_t policy_before = current.policy_verdict;
  const uint32_t terminal_before = current.terminal_intent;
  stale.generation++;
  admit (&ledger, &current);
  current.references++; /* exact duplicate owns one inline reference */
  settle (&ledger, &current, &stale, OUTCOME_SUCCEEDED);
  settle (&ledger, &current, &primary, OUTCOME_SUCCEEDED);
  settle (&ledger, &current, &duplicate, OUTCOME_SUCCEEDED);
  expect (ledger.physical_attempts == 1 && ledger.succeeded == 1,
          "normal exactly-once success");
  expect (ledger.stale == 1 && ledger.stale_generation == 1 &&
            ledger.duplicate == 1 && ledger.duplicate_attempts == 1,
          "normal stale/duplicate ledger");
  expect (ledger.native_returns == 1 && ledger.debt == 0 &&
            ledger.debt_raised == 1 && ledger.debt_settled == 1,
          "normal ownership closure");
  expect (ledger.attempted_generation == 19u &&
            ledger.attempted_packet_id == 71u && ledger.attempted_lane == 2u,
          "normal original completion identity");
  expect (current.policy_verdict == policy_before &&
            current.terminal_intent == terminal_before,
          "normal terminal intent rewrite");
  expect_quiet (&ledger);
  printf ("normal: attempts=%llu succeeded=%llu stale=%llu stale-generation=%llu "
          "duplicate=%llu native-returns=%llu debt=%u original=%u/%u/%u\n",
          (unsigned long long) ledger.physical_attempts,
          (unsigned long long) ledger.succeeded,
          (unsigned long long) ledger.stale,
          (unsigned long long) ledger.stale_generation,
          (unsigned long long) ledger.duplicate,
          (unsigned long long) ledger.native_returns, ledger.debt,
          ledger.attempted_generation, ledger.attempted_packet_id,
          ledger.attempted_lane);
}

static void
run_failed_definite (void)
{
  ledger_t ledger = { 0 };
  identity_t current = new_identity (72u, 20u, 1u, 1072u, 1u);
  const uint32_t policy_before = current.policy_verdict;
  const uint32_t terminal_before = current.terminal_intent;
  identity_t completion = current;
  admit (&ledger, &current);
  settle (&ledger, &current, &completion, OUTCOME_FAILED_DEFINITE);
  expect (ledger.physical_attempts == 1 && ledger.failed_definite == 1 &&
            ledger.succeeded == 0 && ledger.unknown == 0,
          "definite failure classification");
  expect (ledger.native_returns == 1 && ledger.debt == 0,
          "definite failure ownership closure");
  expect (current.policy_verdict == policy_before &&
            current.terminal_intent == terminal_before,
          "definite failure rewrote terminal intent");
  expect_quiet (&ledger);
  printf ("failed-definite: attempts=%llu failed-definite=%llu native-returns=%llu "
          "debt=%u terminal-intent=%u policy-verdict=%u\n",
          (unsigned long long) ledger.physical_attempts,
          (unsigned long long) ledger.failed_definite,
          (unsigned long long) ledger.native_returns, ledger.debt,
          current.terminal_intent, current.policy_verdict);
}

static void
run_outcome_unknown (void)
{
  ledger_t ledger = { 0 };
  identity_t current = new_identity (73u, 21u, 3u, 1073u, 0u);
  identity_t completion = current;
  admit (&ledger, &current);
  settle (&ledger, &current, &completion, OUTCOME_UNKNOWN);
  expect (ledger.physical_attempts == 1 && ledger.unknown == 1 &&
            ledger.succeeded == 0 && ledger.failed_definite == 0,
          "unknown outcome classification");
  expect (ledger.native_returns == 1 && ledger.debt == 0,
          "unknown outcome ownership closure");
  expect_quiet (&ledger);
  printf ("outcome-unknown: attempts=%llu unknown=%llu native-returns=%llu "
          "debt=%u\n",
          (unsigned long long) ledger.physical_attempts,
          (unsigned long long) ledger.unknown,
          (unsigned long long) ledger.native_returns, ledger.debt);
}

int
main (void)
{
  run_normal_duplicate_stale ();
  run_failed_definite ();
  run_outcome_unknown ();
  puts ("S77 deterministic outcome ledger: PASS");
  return 0;
}
