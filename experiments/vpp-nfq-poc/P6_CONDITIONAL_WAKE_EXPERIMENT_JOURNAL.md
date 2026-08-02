# P6 conditional-wake redesign experiment journal

Status: running throwaway POC; not production admission.

Protocol authority: `/tmp/sakamoto-conditional-wake-redesign-poc-handoff-2026-08-02.md`.
Branch: `poc/p6-conditional-wake-redesign`.

The sample counts, arm orders, estimators, validity rules, restart rules, seed, and gate thresholds in the
protocol authority are pre-registered. This journal may record observations and decisions but must not alter
them after data is observed.

## 2026-08-02 23:28:51 +0800 — P6a pre-registration

### Question

Can one selected lighter conditional-wake state word close every publish-versus-sleep interleaving without
the corrected flag protocol's fixed worker-side sequentially-consistent sleep fence, while preserving
coalescing, drain-before-clear ownership, bounded write-failure recovery, and teardown closure?

P6a compares exactly two protocols:

1. `corrected_flag`: the currently tested P5 protocol reconstructed directly from
   `overlay/patches/0001-vlib-frame-queue-wakeup-handshake.patch` plus diagnostics-disabled patch 0002.
2. `epoch_state`: the single selected lighter candidate below.

No third candidate will be introduced after enumeration begins. P6a is a bounded state/interleaving
prototype, not a general scheduler or model checker.

### Common visible state

The prototype exposes after every action:

- worker phase: `AWAKE`, `PREPARING_TO_SLEEP`, `SLEEPING`, `NOTIFIED`, or `DRAINING`;
- queued work, terminal work, and the two producers' publication state;
- notification ownership, eventfd count, write attempts/outcome, channel fault, and teardown state;
- epoch/state-word value where applicable;
- invariant violations and the action trace.

The required exposed actions are publish, announce, recheck, block, notify claim, eventfd write success or
failure, epoll return, eventfd drain, notification clear, spurious wake, work processing, and teardown.

### Corrected-flag reference

- Worker announces sleep, executes the P5 sequentially-consistent transition, and rechecks published work
  before a blocking epoll wait.
- A remote producer publishes work before observing the sleep flag and claiming `wakeup_pending`.
- At most one producer owns the pending claim. A successful write makes eventfd readable.
- The worker drains eventfd before clearing the claim. Clear-before-drain is not modelled as a legal corrected
  transition.
- The reference protocol deliberately retains its current unproven definite-write-failure behavior: a failed
  write can leave the claim owned. P6a must report this; it must not silently repair the reference arm.

### Selected epoch/state candidate

One atomic word contains a monotonically advancing sleep epoch and the worker phase/notification ownership.
The prototype uses unbounded integers; P6b must choose a representation with an explicit wrap argument.

- Every remote publish first makes its queue item visible and, in the same model action, advances the atomic
  epoch with release semantics. Advancing the epoch occurs even while the worker is `AWAKE`.
- Worker announce changes `AWAKE(epoch)` to `PREPARING_TO_SLEEP(epoch)` with an acquire/release transition.
  If it observes an epoch advanced by an earlier publisher, that acquire edge must make the queued work
  visible to the following recheck.
- Worker recheck reads queue visibility with acquire semantics.
- Worker may change `PREPARING_TO_SLEEP(epoch)` to `SLEEPING(epoch)` only if the recheck found no work and
  the complete expected state word, including epoch, is unchanged. A failed transition returns to draining /
  recheck behavior and never blocks.
- Notify claim coalesces `PREPARING_TO_SLEEP` or `SLEEPING` into `NOTIFIED`. A claim against
  `PREPARING_TO_SLEEP` needs no eventfd write because the worker cannot complete its sleep transition. A
  claim against `SLEEPING` owns exactly one bounded eventfd notification attempt sequence. Publish against
  `AWAKE`, `NOTIFIED`, or `DRAINING` advances the epoch but does not create a redundant write.
- Eventfd is drained before notification ownership is cleared. Clear returns the worker to `AWAKE` or
  `DRAINING` according to queued work; it never discards work.
- `EINTR` retains ownership for at most three total immediate attempts. Exhaustion becomes a channel fault
  and controlled teardown. `EAGAIN` retains ownership because the saturated fd is already readable.
  `EBADF`/`EINVAL` retire the claim, expose a channel fault, and force bounded teardown. These frozen outcomes
  are part of the candidate from the start rather than a post-result repair.

This candidate is lighter only as a hypothesis. P6a proves logical eligibility; P6d alone may establish an
idle-cost improvement.

### Bounded exploration and invariants

The automatic exploration contains one worker, two producers, and one work item per producer. It preserves
each actor's program order while enumerating legal cross-actor interleavings of atomic publish, announce,
recheck, block, claim, write outcome, epoll return, drain, clear, process, and teardown steps. Equivalent
states may be memoized; no random stress result substitutes for enumeration.

Every reached state must reject or report:

1. `lost_wake`: queued work is positive while the worker is blocked and there is neither a readable eventfd
   nor a notification transition that prevents/ends the block;
2. `orphaned_claim`: notification ownership remains permanently claimed after a definite dead-channel write
   failure, exhausted EINTR budget, completed drain/clear, or teardown;
3. `double_notification`: more than one successful notification is issued for one undrained sleep edge;
4. `publish_order`: a notification becomes observable before its corresponding queued work;
5. `illegal_block`: the worker blocks without an announced, successfully rechecked, unchanged sleep epoch;
6. `teardown_residue`: terminal exploration leaves queued work, notification ownership, eventfd count,
   sleeping/preparing phase, or an unretired obligation after bounded teardown;
7. `ledger`: published work is lost or processed more than once.

Expected interpretation is frozen before execution:

- any lost wake, illegal block, candidate orphaned claim, double notification, ordering failure, or teardown
  residue rejects `epoch_state` and stops before VLIB modification;
- the known corrected-flag definite-write-failure orphan is recorded as a reference limitation, not treated as
  a surprise candidate failure;
- if `epoch_state` closes all candidate cases, P6a may select it for P6b, subject to an independent read-only
  review; this does not satisfy the later C11, litmus, stress, fault-injection, idle, or latency gates.

## 2026-08-02 23:48:53 +0800 — first model run and Luna review

The first implementation enumerated 351–371 candidate states per homogeneous write outcome and reported no
`epoch_state` counterexample. It also reproduced `corrected_flag` orphaned-claim and lost-wake traces after
homogeneous `EINTR`, `EBADF`, and `EINVAL` failures. This result is preserved but is not accepted as P6a
evidence.

Luna's independent read-only pre-gate review returned **HOLD** for three concrete model-coverage defects:

1. the candidate's dead-channel/exhausted-EINTR write action incorrectly cleared `blocked` and moved the
   worker to `DRAINING`; a failed producer write cannot itself unblock the worker, and controlled teardown
   must be represented as a separate causal sequence;
2. teardown was enabled only after normal processing and then atomically erased every residue field, omitting
   teardown during prepare/sleep, with queued work, and after a channel fault;
3. each exploration repeated one homogeneous write outcome and therefore omitted the bounded mixed retry
   sequences `EINTR -> success/EAGAIN/EBADF/EINVAL` and
   `EINTR -> EINTR -> success/EAGAIN/EBADF/EINVAL`.

The review also noted that P6a structurally orders publication before notification rather than independently
proving visibility. That limitation is expected for this logic prototype and remains reserved for P6c's C11
happens-before document and litmus; no P6a result may be cited as a memory-order proof.

Corrective work is limited to model fidelity: keep the worker blocked after producer write failure, add an
explicit bounded teardown sequence reachable from transition/queued/fault states, and enumerate each legal
per-attempt write outcome. The candidate protocol and frozen interpretation above are unchanged.

Evidence limitation: the rejected first implementation was modified before its source hashes were captured.
Its counts, counterexamples, review findings, and HOLD decision are preserved above, but its exact source hash
cannot be reconstructed and must not be presented as a reproducible accepted artifact.

## 2026-08-02 23:54:00 +0800 — corrected enumeration and P6a gate

Command:

```sh
PYTHONPATH=experiments/vpp-nfq-poc/prototypes \
  python3 -m conditional_wake_p6.cli --enumerate
```

Environment and accepted prototype hashes:

```text
base_commit=e0114366578ab850adafd12d853b0ea83b39709f
python=3.13.11
model.py=cb08f0e2c33b8a31edd10fdd223f20947ab42faa9a214705626b015e87d12946
cli.py=b137fcf1ace1fa8d2ab54793608280195cc128fae54f2b1780ab5c2c54676179
Makefile=2bc942cdcef4fa79b8e43850466a89f1b89e675839880592a5c75234cfccb160
```

Results:

- `corrected_flag`: 2,130 unique states, 259 terminal states. Successful write and saturated `EAGAIN`
  paths close. The reference retains shortest `orphaned_claim` and sleeping-worker `lost_wake`
  counterexamples for one-attempt `EINTR`, `EBADF`, and `EINVAL`, matching the frozen limitation.
- `epoch_state`: 3,760 unique states, 468 terminal states, zero invariant counterexamples.
- The candidate exploration contains exactly 15 bounded write histories: five first-attempt outcomes; the
  retained first-`EINTR` prefix plus its five second-attempt outcomes; the retained two-`EINTR` prefix plus
  its five third-attempt outcomes. This covers success, saturated `EAGAIN`, definite-dead `EBADF`/`EINVAL`,
  and three-attempt `EINTR` exhaustion at every permitted attempt.
- Teardown is reachable from all five worker phases and with queued work, a blocked worker, notification
  ownership, readable eventfd, or channel fault. Its only path is the bounded six-step sequence begin,
  unblock, drain/cancel, settle, clear, finish. A failed producer write does not itself unblock the worker.
- Manual scripted dead-channel trace closed one published item to one terminal item with zero queue,
  notification, eventfd, sleep, or block residue.

Luna's second read-only review independently reran the model, confirmed closure of all three prior HIGH
findings, confirmed the exact 15 retry histories, and returned **GO for P6a only** with no remaining blocking
finding.

### P6a decision

**GO for logic eligibility.** Select `epoch_state` as the only candidate permitted to enter P6b.

This decision does not claim a C11 happens-before proof, real atomic representation or wrap safety, litmus,
million-transition stress, injected platform-fault behavior, idle improvement, latency improvement, or
production admission. Publication visibility is structurally ordered in P6a and remains a mandatory P6c
proof. Do not modify VLIB except to implement this selected state transition for the next throwaway artifact.

## 2026-08-02 23:55:24 +0800 — P6a post-gate audit

Luna's bounded post-gate read-only audit returned **PASS**. It independently verified the recorded base
commit, Python version, all three file hashes, the 2,130/259 reference counts, the 3,760/468 candidate counts,
the 15 retry histories, the six expected reference counterexamples, and zero candidate counterexamples. It
confirmed that the decision language grants only P6a logical eligibility and does not overclaim any later
gate.
