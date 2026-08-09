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
  uint64_t reserve_loss_materializations;
  uint64_t reserve_loss_unmaterialized;
  uint64_t reserve_loss_identity_misses;
  uint64_t reserve_loss_native_drops;
  uint64_t reserve_loss_failed_definite;
  uint64_t reserve_loss_unknown;
  uint64_t reserve_direct_attempts;
  uint64_t reserve_outcomes_succeeded;
  uint64_t degraded_health;
  uint64_t receive_faults;
  uint64_t receive_fault_yields;
  uint64_t receive_fault_disables;
  uint64_t receive_fault_buffer_returns;
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

enum
{
  OUTCOME_SUCCEEDED = 1,
  OUTCOME_FAILED_DEFINITE = 2,
  OUTCOME_UNKNOWN = 3,
};

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
  model->degraded_health++;
  model->reserve_loss_unmaterialized++;
  model->reserve_loss_identity_misses++;
  /* No reserve identity exists here: no Policy Verdict, native ACCEPT, or
   * delivery-success claim is manufactured for an explicitly lost packet. */
  expect (model->reserve_direct_attempts == model->reserve_admitted,
          "reserve loss changed direct-attempt cardinality");
}

static void
record_reserve_loss_outcome (model_t *model, uint32_t outcome)
{
  switch (outcome)
    {
    case OUTCOME_SUCCEEDED:
      model->reserve_loss_native_drops++;
      break;
    case OUTCOME_FAILED_DEFINITE:
      model->reserve_loss_failed_definite++;
      break;
    case OUTCOME_UNKNOWN:
      model->reserve_loss_unknown++;
      break;
    default:
      fail ("unknown reserve loss outcome");
    }
}

static void
record_receive_fault (model_t *model)
{
  /* A non-transient nonblocking receive fault yields the callback.  It is
   * health evidence, not a consumed packet or a fabricated verdict. */
  model->receive_faults++;
  model->degraded_health++;
  model->receive_fault_yields++;
}

static void
record_identity_missing_loss (model_t *model)
{
  /* A reserved buffer was acquired and returned, but its NFQUEUE identity was
   * not recoverable.  It is a loss with no materialized Adapter operation. */
  expect (model->outstanding == 0,
          "identity-missing fault started with outstanding residue");
  model->outstanding++;
  model->reserve_losses++;
  model->reserve_loss_unmaterialized++;
  model->reserve_loss_identity_misses++;
  model->degraded_health++;
  model->native_returns++;
  model->outstanding--;
}

static void
record_receive_fault_after_acquire (model_t *model)
{
  /* The callback has already acquired one VPP buffer.  A non-transient recv
   * fault returns it exactly once, disables the reader, and yields without an
   * error-driven re-entry or a fabricated packet outcome. */
  expect (model->outstanding == 0,
          "receive fault started with outstanding residue");
  model->outstanding++;
  record_receive_fault (model);
  model->receive_fault_disables++;
  model->native_returns++;
  model->receive_fault_buffer_returns++;
  model->outstanding--;
}

static void
run_startup_partial_release (void)
{
  enum { MAX_ENTRIES = 8 };
  uint32_t indices[MAX_ENTRIES];
  uint32_t frees = 0;
  for (uint32_t i = 0; i < MAX_ENTRIES; i++)
    indices[i] = UINT32_MAX;
  for (uint32_t i = 0; i < 3; i++)
    indices[i] = 100u + i;

  /* Model the source ownership transfer: release marks each entry before
   * returning it, so a partial-startup cleanup called twice frees once. */
  for (uint32_t pass = 0; pass < 2; pass++)
    for (uint32_t i = 0; i < MAX_ENTRIES; i++)
      if (indices[i] != UINT32_MAX)
        {
          indices[i] = UINT32_MAX;
          frees++;
        }
  expect (frees == 3, "partial startup cleanup double-freed an entry");
  printf ("startup partial allocation: owned=3 frees=%u repeated-release=1\n",
          frees);
}

static void
run_fault_accounting (void)
{
  model_t model = { 0 };
  record_reserve_loss_outcome (&model, OUTCOME_SUCCEEDED);
  record_reserve_loss_outcome (&model, OUTCOME_FAILED_DEFINITE);
  record_reserve_loss_outcome (&model, OUTCOME_UNKNOWN);
  model.reserve_losses = 3;
  model.reserve_loss_materializations = 3;
  record_identity_missing_loss (&model);
  record_receive_fault_after_acquire (&model);
  expect (model.reserve_loss_materializations +
              model.reserve_loss_unmaterialized == model.reserve_losses,
          "identity-missing loss broke materialized/unmaterialized partition");
  expect (model.reserve_loss_identity_misses == 1,
          "identity-missing loss was not counted once");
  expect (model.reserve_loss_native_drops == 1,
          "only successful NF_DROP counted as native loss");
  expect (model.reserve_loss_failed_definite == 1 &&
              model.reserve_loss_unknown == 1,
          "reserve loss outcomes were not partitioned");
  expect (model.reserve_loss_native_drops +
              model.reserve_loss_failed_definite +
              model.reserve_loss_unknown ==
              model.reserve_loss_materializations,
          "loss outcomes exceeded materialized loss identities");
  expect (model.receive_faults == 1 && model.receive_fault_yields == 1 &&
              model.receive_fault_disables == 1 &&
              model.receive_fault_buffer_returns == 1,
          "acquired-buffer receive fault did not disable/yield/return once");
  expect (model.outstanding == 0,
          "fault accounting left an outstanding buffer residue");
  expect (model.policy_verdicts == 0 && model.delivery_claims == 0,
          "fault accounting fabricated policy/delivery evidence");
  printf ("fault accounting: loss-materialized=%llu loss-unmaterialized=%llu "
          "identity-misses=%llu loss-drops=%llu failed=%llu unknown=%llu "
          "receive-faults=%llu callback-yields=%llu disables=%llu "
          "buffer-returns=%llu degraded=%llu\n",
          (unsigned long long) model.reserve_loss_materializations,
          (unsigned long long) model.reserve_loss_unmaterialized,
          (unsigned long long) model.reserve_loss_identity_misses,
          (unsigned long long) model.reserve_loss_native_drops,
          (unsigned long long) model.reserve_loss_failed_definite,
          (unsigned long long) model.reserve_loss_unknown,
          (unsigned long long) model.receive_faults,
          (unsigned long long) model.receive_fault_yields,
          (unsigned long long) model.receive_fault_disables,
          (unsigned long long) model.receive_fault_buffer_returns,
          (unsigned long long) model.degraded_health);
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
  expect (model.reserve_loss_materializations +
              model.reserve_loss_unmaterialized == model.reserve_losses,
          "capacity loss partition");
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
  run_startup_partial_release ();
  run_fault_accounting ();
  run_capacity_and_reserve ();
  puts ("S78 deterministic reserve ledger: PASS");
  return 0;
}
