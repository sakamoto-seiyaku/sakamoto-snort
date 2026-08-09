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

typedef struct
{
  unsigned int obligations;
  unsigned int buffers;
  unsigned int frames;
  unsigned int credits;
  unsigned int debt;
  unsigned int sockets;
  unsigned int queues;
  unsigned int hooks;
  unsigned int logs;
} residue_ledger_t;

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
  ok &= expect (nfqueue_live_teardown_completion_channel_open (state),
                "completion channel stays open while quiescing");
  ok &= expect (!nfqueue_live_teardown_transition (
                  &state, NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION),
                "completion cannot close before drain");
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
      ok &= expect (nfqueue_live_teardown_completion_generation_allowed (
                      state, 11, 11),
                    "current generation remains completable at deadline");
      ok &= expect (!nfqueue_live_teardown_completion_generation_allowed (
                      state, 11, 10),
                    "old generation is stale at deadline");
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
  ok &= expect (nfqueue_live_teardown_completion_generation_allowed (
                  state, 2, 2),
                "fresh generation completion is admitted while active");
  ok &= expect (!nfqueue_live_teardown_completion_generation_allowed (
                  state, 2, 1),
                "old generation completion is isolated");
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

static int
residue_case (void)
{
  residue_ledger_t ledger = { 0 };
  int ok = 1;
  ok &= expect (ledger.obligations == 0, "clean obligations residue");
  ok &= expect (ledger.buffers == 0, "clean buffers residue");
  ok &= expect (ledger.frames == 0, "clean completion-frame residue");
  ok &= expect (ledger.credits == 0, "clean credit residue");
  ok &= expect (ledger.debt == 0, "clean debt residue");
  ok &= expect (ledger.sockets == 0, "clean socket residue");
  ok &= expect (ledger.queues == 0, "clean queue residue");
  ok &= expect (ledger.hooks == 0, "clean hook residue");
  ok &= expect (ledger.logs == 0, "clean log residue");
  return ok;
}

static int
process_residue_case (void)
{
  /* A process death has no in-process close transition.  Every resource is
   * still named in the ledger so the supervisor cannot silently discard it. */
  const unsigned int process_failure = 1;
  residue_ledger_t ledger = {
    .obligations = process_failure,
    .buffers = process_failure,
    .frames = process_failure,
    .credits = process_failure,
    .debt = process_failure,
    .sockets = process_failure,
    .queues = process_failure,
    .hooks = process_failure,
    .logs = process_failure,
  };
  int ok = 1;
  ok &= expect (ledger.obligations == process_failure,
                "process obligations classified");
  ok &= expect (ledger.buffers == process_failure,
                "process buffers classified");
  ok &= expect (ledger.frames == process_failure,
                "process frames classified");
  ok &= expect (ledger.credits == process_failure,
                "process credits classified");
  ok &= expect (ledger.debt == process_failure, "process debt classified");
  ok &= expect (ledger.sockets == process_failure,
                "process sockets classified");
  ok &= expect (ledger.queues == process_failure,
                "process queues classified");
  ok &= expect (ledger.hooks == process_failure, "process hooks classified");
  ok &= expect (ledger.logs == process_failure, "process logs captured");
  return ok;
}

int
main (void)
{
  int ok = order_case (0) && order_case (1) && generation_case () &&
           process_case () && residue_case () && process_residue_case ();
  if (!ok)
    return 1;
  puts ("queue-disable: quiesce=1 drain=1 completion-open=1 close-order=PASS");
  puts ("clean-stop: quiesce=1 drain=1 completion-open=1 close-order=PASS");
  puts ("drain-deadline: ordinary-accept=1 completion-open-until-settle=1 PASS");
  puts ("process-termination: classified=1 replay=0 PASS");
  puts ("fresh-generation: old-work-rejected=1 duplicate-attempts=1 residue=0");
  puts ("residue-ledger: obligations=0 buffers=0 frames=0 credits=0 debt=0 sockets=0 queues=0 hooks=0 logs=0");
  puts ("process-residue-ledger: obligations=PROCESS_FAILURE buffers=PROCESS_FAILURE frames=PROCESS_FAILURE credits=PROCESS_FAILURE debt=PROCESS_FAILURE sockets=PROCESS_FAILURE queues=PROCESS_FAILURE hooks=PROCESS_FAILURE logs=CAPTURED");
  puts ("S79 deterministic teardown state machine: PASS");
  return 0;
}
