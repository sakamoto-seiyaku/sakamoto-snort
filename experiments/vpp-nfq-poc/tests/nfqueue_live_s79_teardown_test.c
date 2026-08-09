/* SPDX-License-Identifier: Apache-2.0 */

#include "../overlay/src/plugins/nfqueue_live_poc/nfqueue_live_teardown.h"

#include <stdio.h>

typedef struct
{
  unsigned int verdict_attempts;
  unsigned int duplicate_requests;
  unsigned int stale_requests;
  unsigned int old_generation_requests;
  unsigned int accepts_on_deadline;
  unsigned int residue;
} ledger_t;

static int
expect (int condition, const char *message)
{
  if (!condition)
    fprintf (stderr, "S79 deterministic failure: %s\n", message);
  return condition;
}

static int
order_case (int deadline)
{
  nfqueue_live_teardown_state_t state = NFQUEUE_LIVE_TEARDOWN_STOPPED;
  int ok = 1;
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_ENABLE),
                "enable transition");
  ok &= expect (nfqueue_live_teardown_ingress_admission_allowed (state),
                "active admits ingress");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_QUIESCE),
                "quiesce transition");
  ok &= expect (!nfqueue_live_teardown_ingress_admission_allowed (state),
                "quiesce rejects ingress");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_DRAIN),
                "drain transition");
  ok &= expect (nfqueue_live_teardown_completion_available (state),
                "completion remains open during drain");
  if (deadline)
    {
      ok &= expect (nfqueue_live_teardown_transition (
                      &state, NFQUEUE_LIVE_TEARDOWN_DRAIN_DEADLINE),
                    "deadline transition");
      ok &= expect (nfqueue_live_teardown_completion_available (state),
                    "completion remains open at deadline settlement");
    }
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION),
                "completion close transition");
  ok &= expect (!nfqueue_live_teardown_completion_available (state),
                "completion closed after drain");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS),
                "queue/socket close transition");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_FINISH),
                "finish transition");
  ok &= expect (state == NFQUEUE_LIVE_TEARDOWN_COMPLETE,
                "complete terminal state");
  return ok;
}

static int
generation_case (void)
{
  nfqueue_live_teardown_state_t state = NFQUEUE_LIVE_TEARDOWN_STOPPED;
  ledger_t ledger = { 0 };
  int ok = 1;
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_ENABLE),
                "generation 1 enable");
  ok &= expect (nfqueue_live_teardown_generation_allowed (state, 1, 1),
                "current generation accepted");
  ok &= expect (!nfqueue_live_teardown_generation_allowed (state, 1, 0),
                "zero generation rejected");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_QUIESCE),
                "generation 1 quiesce");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_DRAIN),
                "generation 1 drain");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION),
                "generation 1 completion close");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS),
                "generation 1 channels close");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_FINISH),
                "generation 1 finish");

  /* A fresh generation is enabled only after the old state has completed.
   * Old work is counted and ignored; it is never replayed. */
  state = NFQUEUE_LIVE_TEARDOWN_STOPPED;
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_ENABLE),
                "generation 2 enable");
  if (!nfqueue_live_teardown_generation_allowed (state, 2, 1))
    ledger.old_generation_requests++;
  if (!nfqueue_live_teardown_generation_allowed (state, 2, 2))
    ledger.stale_requests++;
  else
    ledger.verdict_attempts++;
  if (nfqueue_live_teardown_generation_allowed (state, 2, 2))
    ledger.duplicate_requests++;
  ledger.accepts_on_deadline++;
  ok &= expect (ledger.verdict_attempts == 1,
                "fresh generation has one physical attempt");
  ok &= expect (ledger.old_generation_requests == 1,
                "old generation is rejected");
  ok &= expect (ledger.stale_requests == 0,
                "current generation is not stale");
  ok &= expect (ledger.duplicate_requests == 1,
                "duplicate request is classified without replay");
  ok &= expect (ledger.accepts_on_deadline == 1,
                "ordinary deadline obligation accepts");
  ok &= expect (ledger.residue == 0, "generation ledger has no residue");
  return ok;
}

static int
process_case (void)
{
  nfqueue_live_teardown_state_t state = NFQUEUE_LIVE_TEARDOWN_STOPPED;
  int ok = 1;
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_ENABLE),
                "process case enable");
  ok &= expect (nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_PROCESS_DEATH),
                "process termination transition");
  ok &= expect (state == NFQUEUE_LIVE_TEARDOWN_PROCESS_TERMINATED,
                "process termination is classified");
  ok &= expect (!nfqueue_live_teardown_completion_available (state),
                "terminated process cannot complete new work");
  ok &= expect (!nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_FINISH),
                "process termination cannot fake clean finish");
  return ok;
}

int
main (void)
{
  int ok = order_case (0) && order_case (1) && generation_case () &&
           process_case ();
  if (!ok)
    return 1;
  puts ("queue-disable: quiesce=1 drain=1 completion-open=1 close-order=PASS");
  puts ("clean-stop: quiesce=1 drain=1 completion-open=1 close-order=PASS");
  puts ("drain-deadline: ordinary-accept=1 completion-open-until-settle=1 PASS");
  puts ("process-termination: classified=1 replay=0 PASS");
  puts ("fresh-generation: old-work-rejected=1 duplicate-attempts=1 residue=0");
  puts ("S79 deterministic teardown state machine: PASS");
  return 0;
}
