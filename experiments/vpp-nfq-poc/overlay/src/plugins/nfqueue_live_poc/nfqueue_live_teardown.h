/* SPDX-License-Identifier: Apache-2.0 */

#ifndef included_nfqueue_live_teardown_h
#define included_nfqueue_live_teardown_h

/*
 * SAKAMOTO-79 teardown contract.
 *
 * This header deliberately has no VPP or libc dependency.  The live plugin
 * and the deterministic runner share the same transition table, so the
 * ordering proof does not depend on a particular VPP build or scheduler.
 */

typedef unsigned char nfqueue_live_teardown_state_t;

/* The transition log is deliberately fixed-size.  It is diagnostic evidence
 * only; lifecycle correctness never depends on allocating a log record. */
#define NFQUEUE_LIVE_TEARDOWN_MAX_TRANSITIONS 16u

enum
{
  NFQUEUE_LIVE_TEARDOWN_STOPPED = 0,
  NFQUEUE_LIVE_TEARDOWN_ACTIVE,
  NFQUEUE_LIVE_TEARDOWN_QUIESCING,
  NFQUEUE_LIVE_TEARDOWN_DRAINING,
  /* Deadline is still a drain state: the completion channel remains open
   * while the ordinary Root fallback is settled. */
  NFQUEUE_LIVE_TEARDOWN_DEADLINE,
  NFQUEUE_LIVE_TEARDOWN_COMPLETION_CLOSED,
  NFQUEUE_LIVE_TEARDOWN_CHANNELS_CLOSED,
  NFQUEUE_LIVE_TEARDOWN_COMPLETE,
  NFQUEUE_LIVE_TEARDOWN_PROCESS_TERMINATED,
};

typedef unsigned char nfqueue_live_teardown_event_t;

enum
{
  NFQUEUE_LIVE_TEARDOWN_ENABLE = 0,
  NFQUEUE_LIVE_TEARDOWN_QUIESCE,
  NFQUEUE_LIVE_TEARDOWN_DRAIN,
  NFQUEUE_LIVE_TEARDOWN_DRAIN_DEADLINE,
  NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION,
  NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS,
  NFQUEUE_LIVE_TEARDOWN_FINISH,
  NFQUEUE_LIVE_TEARDOWN_PROCESS_DEATH,
};

static inline unsigned char
nfqueue_live_teardown_completion_available (nfqueue_live_teardown_state_t state)
{
  return state == NFQUEUE_LIVE_TEARDOWN_DRAINING ||
         state == NFQUEUE_LIVE_TEARDOWN_DEADLINE;
}

/* A worker may publish a terminal intent while quiescing.  The completion
 * channel must remain usable from the first quiesce edge through the bounded
 * drain and deadline settlement; only CLOSE_COMPLETION removes this right. */
static inline unsigned char
nfqueue_live_teardown_completion_channel_open (
  nfqueue_live_teardown_state_t state)
{
  return state == NFQUEUE_LIVE_TEARDOWN_ACTIVE ||
         state == NFQUEUE_LIVE_TEARDOWN_QUIESCING ||
         state == NFQUEUE_LIVE_TEARDOWN_DRAINING ||
         state == NFQUEUE_LIVE_TEARDOWN_DEADLINE;
}

static inline unsigned char
nfqueue_live_teardown_ingress_admission_allowed (
  nfqueue_live_teardown_state_t state)
{
  return state == NFQUEUE_LIVE_TEARDOWN_ACTIVE;
}

/* Generation equality is required in addition to the state check.  A
 * delayed completion from a prior generation must never become work in a
 * fresh generation, even when a VPP buffer index was reused. */
static inline unsigned char
nfqueue_live_teardown_generation_allowed (
  nfqueue_live_teardown_state_t state, unsigned long long active_generation,
  unsigned long long work_generation)
{
  return state == NFQUEUE_LIVE_TEARDOWN_ACTIVE && active_generation != 0 &&
         active_generation == work_generation;
}

/* Completion is allowed to finish current-generation work during teardown,
 * but never admits a delayed token from an older generation. */
static inline unsigned char
nfqueue_live_teardown_completion_generation_allowed (
  nfqueue_live_teardown_state_t state, unsigned long long active_generation,
  unsigned long long work_generation)
{
  return nfqueue_live_teardown_completion_channel_open (state) &&
         active_generation != 0 && active_generation == work_generation;
}

static inline unsigned char
nfqueue_live_teardown_transition (nfqueue_live_teardown_state_t *state,
                                  nfqueue_live_teardown_event_t event)
{
  if (!state)
    return 0;

  switch (event)
    {
    case NFQUEUE_LIVE_TEARDOWN_ENABLE:
      if (*state != NFQUEUE_LIVE_TEARDOWN_STOPPED)
        return 0;
      *state = NFQUEUE_LIVE_TEARDOWN_ACTIVE;
      return 1;
    case NFQUEUE_LIVE_TEARDOWN_QUIESCE:
      if (*state != NFQUEUE_LIVE_TEARDOWN_ACTIVE)
        return 0;
      *state = NFQUEUE_LIVE_TEARDOWN_QUIESCING;
      return 1;
    case NFQUEUE_LIVE_TEARDOWN_DRAIN:
      if (*state != NFQUEUE_LIVE_TEARDOWN_QUIESCING)
        return 0;
      *state = NFQUEUE_LIVE_TEARDOWN_DRAINING;
      return 1;
    case NFQUEUE_LIVE_TEARDOWN_DRAIN_DEADLINE:
      if (*state != NFQUEUE_LIVE_TEARDOWN_DRAINING)
        return 0;
      *state = NFQUEUE_LIVE_TEARDOWN_DEADLINE;
      return 1;
    case NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION:
      if (!nfqueue_live_teardown_completion_available (*state))
        return 0;
      *state = NFQUEUE_LIVE_TEARDOWN_COMPLETION_CLOSED;
      return 1;
    case NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS:
      if (*state != NFQUEUE_LIVE_TEARDOWN_COMPLETION_CLOSED)
        return 0;
      *state = NFQUEUE_LIVE_TEARDOWN_CHANNELS_CLOSED;
      return 1;
    case NFQUEUE_LIVE_TEARDOWN_FINISH:
      if (*state != NFQUEUE_LIVE_TEARDOWN_CHANNELS_CLOSED)
        return 0;
      *state = NFQUEUE_LIVE_TEARDOWN_COMPLETE;
      return 1;
    case NFQUEUE_LIVE_TEARDOWN_PROCESS_DEATH:
      if (*state == NFQUEUE_LIVE_TEARDOWN_COMPLETE ||
          *state == NFQUEUE_LIVE_TEARDOWN_PROCESS_TERMINATED ||
          *state == NFQUEUE_LIVE_TEARDOWN_STOPPED)
        return 0;
      *state = NFQUEUE_LIVE_TEARDOWN_PROCESS_TERMINATED;
      return 1;
    default:
      return 0;
    }
}

#endif /* included_nfqueue_live_teardown_h */
