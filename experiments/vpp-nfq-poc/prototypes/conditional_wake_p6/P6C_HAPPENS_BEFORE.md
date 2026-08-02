# P6c happens-before map

This note maps only the current
`overlay/patches/0003-vlib-frame-queue-wakeup-epoch-state.patch`. Patch line
numbers below are stable review anchors; the applied-source lines shown in
parentheses are from the isolated P6 build used on 2026-08-02 and may move when
the upstream VPP baseline changes.

## Publication and sleep-confirmation chain

1. The producer fills the frame payload, then release-publishes `hf->valid` and
   `check_frame_queues` in `vlib_buffer_enqueue_to_thread_inline`
   (`src/vlib/buffer_funcs.c:311-320` in the isolated tree). The call to
   `vlib_thread_wakeup()` is sequenced after both release stores.
2. `vlib_thread_wakeup()` relaxed-loads the packed state, then release-CASes the
   incremented epoch while preserving the observed phase, or changes
   `PREPARING -> NOTIFIED` / `SLEEPING -> NOTIFYING` (patch lines 322-355;
   applied `src/vlib/threads.h:755-785`). The frame publication is therefore
   sequenced-before this release CAS.
3. The worker acquire-loads the complete packed state and acq_rel-CASes
   `AWAKE -> PREPARING` (patch lines 480-502; applied
   `src/vlib/file.c:181-203`). A successful acquire that reads a producer's
   release sequence imports the preceding frame/payload publication.
4. The worker then acquire-rechecks `check_frame_queues` (patch lines 517-522;
   applied `src/vlib/file.c:215-225`). Independently of the epoch chain, a load
   observing the release store directly imports the frame publication.
5. Only an exact acq_rel CAS of the unchanged complete PREPARING word may set
   `SLEEPING` (patch lines 544-558; applied `src/vlib/file.c:247-260`). Thus a
   producer release-CAS between announce/recheck and sleep confirmation changes
   the expected packed word and makes sleep confirmation fail. A producer after
   confirmation observes `SLEEPING`, atomically moves it to `NOTIFYING`, and
   owns the sole eventfd write.
6. While `NOTIFYING`, `vlib_wakeup_epoch_begin_draining()` refuses to clear the
   claim (patch lines 137-158). The owner performs at most three writes, then
   acq_rel-CASes `NOTIFYING -> NOTIFIED` for success/EAGAIN or
   `NOTIFYING -> DRAINING` for a terminal fault (patch lines 160-184 and
   374-434; applied `src/vlib/threads.h:587-631,804-852`). Failed CAS updates
   the expected word, so concurrent producer epoch increments are retained.
7. On every epoll return, the worker first acquire/acq_rel-CASes to `DRAINING`
   (patch lines 555-572; applied `src/vlib/file.c:291-304` plus
   `src/vlib/threads.h:569-583`). For a normal return, file callbacks drain only
   the eventfd, then file.c acq_rel-CASes the phase to `AWAKE` (patch lines
   580-588; applied `src/vlib/file.c:310-388`). Frame queues are not consumed in
   file.c; the subsequent awake main-loop dispatch consumes them with the
   existing acquire path. If epoll returns EINTR, file.c returns immediately
   while still `DRAINING`, without callback or clear. The next file poll sees a
   non-AWAKE phase, performs a zero-timeout service pass, and only then clears.
   Each `file_poll` invocation calls begin-draining only once. If that call sees
   a concurrent `NOTIFYING` owner, it returns false and the current invocation
   finishes without clearing; it does not wait and retry in place. The owner may
   then retire to `NOTIFIED`. A later zero-timeout `file_poll` makes one fresh
   begin-draining attempt; it may be rejected and return again if retirement is
   still incomplete.
8. A publisher racing while the worker is `DRAINING` release-CASes a new epoch
   while preserving `DRAINING`. The later clear CAS preserves that epoch and
   changes only the phase. Once `AWAKE`, the worker's main-loop frame-queue
   acquire observes and dispatches the published work before another successful
   unchanged-word sleep confirmation, so clearing before frame dispatch does
   not sleep past the queued item.

## Evidence boundaries

`p6c_exhaustive.py` is the bounded proof artifact for exactly one worker, two
producers, and one item per producer. It splits payload write, frame release,
epoch load, CAS failure/retry, announce load/CAS, both acquire rechecks, exact
sleep CAS, `NOTIFYING` ownership, write, owner-retirement acquire load and
CAS failure/retry/success, readable/spurious/EINTR epoll return, begin-draining
acquire load and CAS failure/retry/success, eventfd-only callback, EINTR's
no-clear return and next zero-timeout service, clear acquire load and CAS
failure/retry/success, subsequent awake frame dispatch, retained-event service,
and six teardown steps. Both EINTR without an owner, EINTR racing a
`NOTIFYING` owner, and rejection again on the following poll are explicit
coverage outputs. Permanent lost wake is checked
per queued producer before every state expansion: only that producer's pending
epoch publish or an active notification claim covering that item can defer the
failure, so an unrelated future publisher cannot conceal it.
Every terminal state is checked for lost wake, publication visibility,
notification ownership, at-most-one successful write per drain, ledger
conservation, and zero residue. State deduplication excludes only the trace.

`p6c_litmus.c` is a focused real-thread C11 litmus and supplemental stress. Its
payload relaxed store is sequenced-before a frame release store; the worker
reads the frame with acquire before checking payload. Producer epoch CAS is
release; worker announce, sleep-confirm, drain, and owner-retirement CASes use
acq_rel with acquire failures. CAS loops that correspond to implementation
helpers have the same 64-attempt budget and report `cas_exhaustions`; worker
announce performs one CAS and takes the service/drain path after failure.
Deterministic yield widening changes schedules without introducing data races.
A passing million-transition run increases confidence but is not a proof of all
C11 executions.

`fault_scenarios.py` is deterministic protocol-level coverage. It proves only
the frozen local state transitions: one/two EINTR retries retain ownership,
the third faults; EAGAIN retains a readable notification; EBADF/EINVAL/short
retire the claim and tear down; epoll EINTR without an owner leaves DRAINING
until the next zero-timeout service; concurrent NOTIFYING rejects the current
poll's single begin-drain attempt, and a following poll may also reject before
owner retirement; spurious return follows the
same begin-drain/callback/clear ordering;
bursts coalesce; awake traffic writes zero notifications; teardown settles
transition and queued residue.

Still pending outside this directory is runtime evidence against the actual
injector-enabled VPP binary: each frozen write outcome, epoll behavior,
diagnostic counters, bounded controlled exit, and final zero live/outstanding
packet and wake-state residue. The main POC thread must run and record those
campaigns; this document does not claim they have passed.
