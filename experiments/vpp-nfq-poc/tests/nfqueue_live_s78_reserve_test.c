/* SPDX-License-Identifier: Apache-2.0 */

/* Deterministic S78 public-capacity ledger.  The model deliberately exposes
 * only the observable seam used by the live probe: normal ingress is held at
 * its startup capacity, each origin lane owns a startup-fixed set of buffers
 * from the same contiguous envelope, reserve packets complete directly with
 * their original identity, and reserve exhaustion is explicit loss. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

enum
{
  LANES = 4,
  NORMAL_CAPACITY = 3,
  RESERVE_CAPACITY = 2,
  CONTIGUOUS_ENVELOPE_BYTES = 9000,
  PACKET_ID_BASE = 1000,
};

typedef struct
{
  uint64_t normal_admitted;
  uint64_t normal_peak;
  uint64_t normal_exhaustions;
  uint64_t reserve_startup_reservations;
  uint64_t reserve_admitted;
  uint64_t reserve_peak_occupancy;
  uint64_t reserve_peak_inflight;
  uint64_t reserve_exhaustions;
  uint64_t reserve_losses;
  uint64_t reserve_direct_attempts;
  uint64_t reserve_outcomes_succeeded;
  uint64_t native_returns;
  uint64_t policy_verdicts;
  uint64_t delivery_claims;
  uint64_t copies;
  uint64_t outstanding;
  uint64_t residue;
  uint32_t reserve_remaining[LANES];
  uint32_t reserve_reserved[LANES];
  uint32_t reserve_inflight[LANES];
} model_t;

static void
fail (const char *what)
{
  fprintf (stderr, "S78 deterministic failure: %s\n", what);
  exit (1);
}

static void
expect (int condition, const char *what)
{
  if (!condition)
    fail (what);
}

static void
startup_reserve (model_t *model)
{
  for (uint32_t lane = 0; lane < LANES; lane++)
    {
      model->reserve_remaining[lane] = RESERVE_CAPACITY;
      model->reserve_reserved[lane] = RESERVE_CAPACITY;
      model->reserve_startup_reservations += RESERVE_CAPACITY;
    }
  expect (model->reserve_startup_reservations == LANES * RESERVE_CAPACITY,
          "startup reserve was not fixed per origin lane");
  /* Normal and reserve buffers are both VPP-owned and use the same measured
   * contiguous envelope; the POC never introduces an alternate packet store. */
  expect (CONTIGUOUS_ENVELOPE_BYTES == 9000,
          "contiguous envelope provenance changed");
}

static void
admit_normal (model_t *model)
{
  expect (model->normal_admitted < NORMAL_CAPACITY,
          "normal admission exceeded fixed capacity");
  model->normal_admitted++;
  if (model->normal_admitted > model->normal_peak)
    model->normal_peak = model->normal_admitted;
  model->outstanding++;
}

static void
reserve_complete_directly (model_t *model, uint32_t lane, uint32_t packet_id)
{
  (void) packet_id;
  expect (lane < LANES, "reserve lane out of range");
  expect (model->reserve_remaining[lane] != 0,
          "direct reserve completion without a startup reservation");
  model->reserve_remaining[lane]--;
  model->reserve_inflight[lane]++;
  model->reserve_admitted++;
  uint64_t used = model->reserve_reserved[lane] -
                  model->reserve_remaining[lane];
  if (used > model->reserve_peak_occupancy)
    model->reserve_peak_occupancy = used;
  if (model->reserve_inflight[lane] > model->reserve_peak_inflight)
    model->reserve_peak_inflight = model->reserve_inflight[lane];
  model->outstanding++;

  /* Root reserve completion performs exactly one original-identity ACCEPT
   * operation and immediately returns the same VPP buffer.  It does not enter
   * parser, flow, policy, worker, or a copy path. */
  model->reserve_direct_attempts++;
  model->reserve_outcomes_succeeded++;
  model->native_returns++;
  model->outstanding--;
  model->reserve_inflight[lane]--;
}

static void
record_reserve_loss (model_t *model, uint32_t lane, uint32_t packet_id)
{
  (void) packet_id;
  expect (lane < LANES, "loss lane out of range");
  model->normal_exhaustions++;
  model->reserve_exhaustions++;
  model->reserve_losses++;
  /* No reserve identity exists here: no Policy Verdict, native ACCEPT, or
   * delivery-success claim is manufactured for an explicitly lost packet. */
  expect (model->reserve_direct_attempts == model->reserve_admitted,
          "reserve loss changed direct-attempt cardinality");
}

static void
settle_normal (model_t *model)
{
  expect (model->normal_admitted != 0, "normal settlement underflow");
  model->normal_admitted--;
  expect (model->outstanding != 0, "normal outstanding underflow");
  model->outstanding--;
  model->native_returns++;
}

static void
run_capacity_and_reserve (void)
{
  model_t model = { 0 };
  startup_reserve (&model);

  /* Hold normal ingress full before asking every lane for its reserve. */
  for (uint32_t i = 0; i < NORMAL_CAPACITY; i++)
    admit_normal (&model);
  expect (model.normal_peak == NORMAL_CAPACITY,
          "normal peak did not reach fixed capacity");

  /* Each lane owns exactly its own two entries.  A third packet is lost; it
   * cannot borrow an entry from a lane with remaining capacity. */
  for (uint32_t lane = 0; lane < LANES; lane++)
    {
      reserve_complete_directly (&model, lane,
                                 PACKET_ID_BASE + lane * 10u);
      reserve_complete_directly (&model, lane,
                                 PACKET_ID_BASE + lane * 10u + 1u);
      record_reserve_loss (&model, lane,
                           PACKET_ID_BASE + lane * 10u + 2u);
    }
  expect (model.normal_exhaustions == LANES,
          "normal capacity exhaustion count");
  expect (model.reserve_startup_reservations == LANES * RESERVE_CAPACITY,
          "reserve startup reservation cardinality");
  expect (model.reserve_admitted == LANES * RESERVE_CAPACITY,
          "reserve admission count");
  expect (model.reserve_exhaustions == LANES,
          "reserve exhaustion count");
  expect (model.reserve_losses == LANES,
          "reserve loss count");
  expect (model.reserve_peak_occupancy == RESERVE_CAPACITY,
          "reserve occupancy watermark");
  expect (model.reserve_peak_inflight == 1,
          "direct reserve completion was not immediate");
  expect (model.reserve_direct_attempts == model.reserve_admitted,
          "reserve direct operation cardinality");
  expect (model.reserve_outcomes_succeeded == model.reserve_admitted,
          "reserve completion outcome cardinality");
  expect (model.policy_verdicts == 0 && model.delivery_claims == 0,
          "reserve path fabricated policy/delivery evidence");
  expect (model.copies == 0, "reserve path copied packet bytes");

  while (model.normal_admitted != 0)
    settle_normal (&model);
  expect (model.outstanding == 0 && model.residue == 0,
          "normal/reserve outstanding residue");
  expect (model.native_returns == NORMAL_CAPACITY + model.reserve_admitted,
          "final native return cardinality");
  for (uint32_t lane = 0; lane < LANES; lane++)
    expect (model.reserve_inflight[lane] == 0,
            "lane-local reserve inflight residue");
  printf ("capacity: normal-peak=%llu/%u normal-exhaustions=%llu "
          "reserve-startup=%llu reserve-peak=%llu/%u "
          "reserve-inflight-peak=%llu reserve-exhaustions=%llu losses=%llu "
          "direct-attempts=%llu outcomes=%llu native-returns=%llu "
          "outstanding=%llu residue=%llu copies=%llu\n",
          (unsigned long long) model.normal_peak, NORMAL_CAPACITY,
          (unsigned long long) model.normal_exhaustions,
          (unsigned long long) model.reserve_startup_reservations,
          (unsigned long long) model.reserve_peak_occupancy, RESERVE_CAPACITY,
          (unsigned long long) model.reserve_peak_inflight,
          (unsigned long long) model.reserve_exhaustions,
          (unsigned long long) model.reserve_losses,
          (unsigned long long) model.reserve_direct_attempts,
          (unsigned long long) model.reserve_outcomes_succeeded,
          (unsigned long long) model.native_returns,
          (unsigned long long) model.outstanding,
          (unsigned long long) model.residue,
          (unsigned long long) model.copies);
}

int
main (void)
{
  run_capacity_and_reserve ();
  puts ("S78 deterministic reserve ledger: PASS");
  return 0;
}
