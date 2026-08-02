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

## 2026-08-03 00:00:20 +0800 — P6b implementation pre-registration

P6b will add one delta patch after the preserved P5 patches. The resulting source is a new artifact; the old
patch files and exact-unpatched source/build remain unchanged. No alternative candidate will be implemented.

Baseline hashes before the P6 delta:

```text
P5 patch 0001=0b33d8d502dfe531f51f06b4e3a4c376b9960f3d7b64059eee8d38b848360c52
P5 patch 0002=18c16075c2fe4ce9ca5dfa8171b628788d4668cac03932749fc137a44a702ccc
handoff_perf_poc.c=2e16456fa44797d30e04988640066046a3e7693ff0ab4a8899fddf151fd17b50
apply-vpp-overlay.sh=abea0d8659885c63c89630323403b89e9073e6482e3772a309a56104d2a6dece
build-vpp-handoff-perf.sh=333ea9fedc7a3473de1b4874fab68f45f48135d6116cdebdaec82a0ab69cff38
P5-patched main.h=08245a39c38e410ffb8b88b2015576fd2f7b48d5fa38c4cffd16110970f9c521
P5-patched threads.h=3ac61937ab28521ca080427e9aa9da1ec49cd1515b590e41bfc62dbca3a77260
P5-patched file.c=4dd876712fa7d63d9b8c0e49380bfcb40f6e9d6821231c763147e0f8b6e9d31d
P5-patched buffer_funcs.c=dd37a6d61fa6cb284d9ef7e261ee5135403d7c2d190f7902785543d56e257851
P5-patched main.c=a10b3546508516d7ff45d861f587137e52a692a220a8c393fdf0ebab4fa924fc
exact-unpatched main.h=6aec09608eef07d864f4782571f93362f220b2dec72c51f3d2e315541f3d46f4
exact-unpatched threads.h=f99e39b930e8d3ea904ab8b560d6fb46721b209e87304606132cb295b25803ae
exact-unpatched file.c=529893fd1e64741d9574ed6c9f3022815dd5de48da91623365775979cb3b4b00
exact-unpatched buffer_funcs.c=31fdb973cb39ae965b1b6188ca2223a1a9c5ace9f2cf5cd5f9a4c0660395237f
exact-unpatched main.c=174afcf067798e31b4d6b21ad2ce7016e4660415262f977a20e6e4ea847fa1c6
exact-unpatched CMakeCache=a5cfb7c97f761b77d6d3cc63ba4c0497dcbff3b4f0d4436f93ed02474d96f13a
```

Selected C representation and transitions:

- One aligned `u64` state word uses the low three bits for `AWAKE`, `PREPARING_TO_SLEEP`, `SLEEPING`,
  `NOTIFIED`, or `DRAINING`; the upper 61 bits are the monotonically advancing publish epoch.
- Every conditional remote publish occurs after the frame-valid and `check_frame_queues` release stores, then
  CAS-advances the epoch. It changes `PREPARING_TO_SLEEP` or `SLEEPING` to `NOTIFIED`; only the successful
  `SLEEPING -> NOTIFIED` owner writes eventfd. `AWAKE`, `NOTIFIED`, and `DRAINING` advance the epoch without a
  write.
- Worker announce CASes the complete `AWAKE(epoch)` word to `PREPARING_TO_SLEEP(epoch)`, performs the frozen
  acquire rechecks, and may CAS to `SLEEPING(epoch)` only if the complete word is unchanged. Failure uses a
  zero-timeout epoll/drain pass and never blocks. After epoll return the worker publishes `DRAINING`; only
  after event handling/drain does it publish `AWAKE` while preserving the latest epoch.
- The 61-bit epoch must not wrap silently. A publish that would wrap records `EPOCH_EXHAUSTED`, retires the
  notification path, and requests the same bounded VPP process teardown used for a dead channel. This avoids
  ABA; it is an operational fail-stop after more publications than the device lifetime can reach, not a
  claim that modular wrap is safe.
- The notification owner retries `EINTR` immediately at most twice after the first attempt. `EAGAIN` retains
  the `NOTIFIED` state because eventfd is already readable. `EBADF`, `EINVAL`, a short write, or third `EINTR`
  records a stable low-cardinality channel fault and atomically requests VPP main-loop exit with nonzero
  status. The write failure itself does not change the target's sleeping state. With the current Android idle
  profile, the target epoll timeout remains bounded at 1000 ms, after which the normal shutdown barrier can
  retire the worker. No producer blocks, sleeps, performs packet I/O, or retries beyond the fixed budget.
- Diagnostics and fault injection remain compile-time selectable. The P6d artifact must compile diagnostics
  and injection out; stable channel-fault state and bounded recovery remain correctness fields, not optional
  diagnostics.

P6b acceptance requires a clean full VLIB/plugin rebuild from a separately preserved P6 source/build tree,
warnings treated as findings, source/build-cache/binary/plugin/runner hashes, and smoke startup. It does not
grant correctness or performance gates.

### P6b build and startup evidence

Status: **candidate built; gate HOLD**. This section records compilation and startup only. No P6c
correctness gate and no P6d performance campaign has run.

The isolated candidate source lives under `/tmp/sakamoto-p6-epoch-work/vpp`. The repository's formal P5 tree
was not rebuilt or modified. The P6 source was obtained by applying only patch 0003 to a source tree already
verified to contain the P5 patch set, because the overlay helper's reverse check for patch 0001 overlaps patch
0002 and cannot classify that already-patched tree. `git apply --check` and `git diff --check` passed for the
P6 delta.

Build ledger, including unsuccessful setup attempts:

1. Removing the isolated tree's temporary `build-root` also removed tracked VPP build infrastructure. It was
   restored from that isolated tree's `HEAD`; the formal P5 tree and its recorded cache were untouched.
2. The container build first lacked `.deps.ok`, then attempted offline package installation. After restoring
   the marker and permissions, a clean container build reached the candidate VLIB sources with `-Werror` but
   failed in unrelated targets: first a Git `safe.directory` external rebuild, then the optional Prometheus
   plugin because the minimal image lacks OpenSSL headers.
3. The host toolchain matched the preserved P5 environment. A fresh host build first needed the existing
   `ply` module path, then an uncached all-target configure selected `/opt/vpp/external` and failed the
   unrelated AF_XDP link on non-PIC libbpf.
4. The preserved P5 `CMakeCache.txt` was copied into an otherwise empty P6 build directory and only its old
   absolute source/build root was rewritten to the isolated P6 root. This restored the frozen external-library
   selection. The unrestricted `all` target was still unusable because its cached optional NFQUEUE library
   path no longer exists on the host.
5. The preregistered code boundary was therefore built explicitly with Ninja targets `vpp` and
   `handoff_perf_poc_plugin`, followed by `vppctl`, using
   `PYTHONPATH=/home/js/android/lineage/external/ply/ply`. The primary invocation rebuilt 1417 targets from the
   empty P6 output directory, including `vlib/file.c`, `vlib/threads.c`, all enabled VLIB variants, the plugin,
   and final VPP link, with warnings treated as errors. It completed 1417/1417 with exit status 0. `vppctl`
   completed 31/31 with exit status 0. This is a full rebuild of the P6 VLIB/plugin runtime boundary, not a
   claim that unrelated optional repository targets built.

Frozen candidate hashes:

```text
P6 patch 0003=f84ff614049e57df7ff344464ecf518b4e3c85a8df10af3dda78fa4b8b752eb1
handoff_perf_poc.c=85ee29117c39ab1458c30fc72ab2e50b5261f731d536072320b9bd74e64a6a21
P6 main.h=18530d0be0f536f92a414add16f2bb2b1c403b8c069c6093a20ca37166f6fdaf
P6 threads.h=cd39df7113cc1eb2205082773f3595699fc8d16ca90ee2f0b33af249618306fa
P6 file.c=5dfd7709c8c8ec6f7a3f1d5c9a0b75167afd8c48e940d30c13c368b96dc8b3cc
CMakeCache=ea47ec2a30e23475816396246538e058ace27bf2918800470b2df02b4e528711
vpp=34efc38a38571207dae95316373f832940f128d0c50c6afe55fc69d140d80448
vppctl=4af2ddceeaf3d21e1d2e17124eda32ddf641adee4964ac6b3a7e624b432a07e7
handoff_perf_poc_plugin.so=ad282b565690ec44731ae04fc4d04b7f919312e61175eb1664718e9f6605fa44
run-vpp-handoff-perf-poc.py=965fe5e58c0f206be836352bd485f31fe628f08d570d5792b5727930dd797b0d
```

The non-performance smoke used the build-tree `vpp`, `vppctl`, libraries, and plugin. It started main plus one
worker, loaded only `handoff_perf_poc_plugin.so` through the explicit `plugins { path ... }` configuration,
waited for the CLI, ran `show version`, `show plugins`, and `show handoff-perf`, then sent SIGTERM and observed
VPP exit status 0. The initial diagnostic state was `faults 0`, `fault-code 0`, `awake 2`, with all other wake
phases and counters zero. No traffic generator, timed measurement, or CPU sampler ran.

An earlier smoke attempt is retained as negative setup evidence: supplying only the early `plugin_path`
argument left the plugin manager path empty in this build-tree invocation, so the plugin was not registered
and `show handoff-perf` was unknown. The corrected explicit `plugins { path ... }` invocation passed. Evidence
directories are `/tmp/sakamoto-p6b-smoke.7PwZR0`, `/tmp/sakamoto-p6b-load.wnDLqP`, and the passing
`/tmp/sakamoto-p6b-load2.b8cQiB`.

### P6b post-build gate review: HOLD

Luna performed a bounded read-only review of the authority handoff, frozen P6a model, journal, patch, plugin,
hashes, and smoke evidence. Verdict: **HOLD**. The built hashes above are retained as failed-candidate evidence
and must not be used for P6c or performance work.

Blocking findings:

1. The candidate returned immediately from `vlib_thread_wakeup()` in mode 0 even though the worker retained
   the P5 legacy `thread_sleeps` path. A direct barrier wake therefore lost the P5 eventfd behavior and could
   collide with the one-second barrier timeout.
2. A producer changed `SLEEPING` to `NOTIFIED` before its eventfd write. A timeout or spurious worker return
   could then change `NOTIFIED` to `DRAINING` and `AWAKE` before that write completed. This omits the frozen
   model's `write_required` state, violates drain-before-clear, and permits two successful notifications before
   one drain.
3. The preregistered compile-time fault injector did not exist; only diagnostics were compile-time selectable.
4. Terminal write failures recorded a fault and requested exit but left the notification claim in `NOTIFIED`,
   rather than explicitly retiring it before bounded teardown.

The allowed correction remains the same epoch-state candidate: restore exact P5 mode-0 wake semantics,
atomically represent the model's outstanding write ownership, retire terminal claims, and add a compile-time
removable deterministic injector. Then freeze new hashes, redo the scoped clean build and non-performance
smoke, and repeat the read-only P6b gate. P6c and all performance work remain prohibited meanwhile.

### P6b HOLD correction candidate

Status: **corrected candidate built; repeat gate review pending**. The original failed-candidate hashes and
smoke evidence above remain immutable negative evidence.

The correction stays within the selected epoch-state design. It encodes the frozen model's combined
`NOTIFIED + write_required` condition as internal phase value `NOTIFYING=5` in the same `u64`; the public model
state remains `NOTIFIED`. A `SLEEPING` owner CASes to `NOTIFYING`, while concurrent publishers only advance the
epoch and preserve that phase. The worker cannot begin drain from `NOTIFYING`. After an actual successful
write, or an injected/real `EAGAIN` for which the fd is readable, the owner release-CASes `NOTIFYING` to
`NOTIFIED`, preserving the latest epoch. A terminal outcome first release-CASes `NOTIFYING` to `DRAINING`,
then records the stable fault and requests controlled exit. This restores the model's write-before-drain and
bounded claim-retirement rules.

Mode mapping is now explicit:

- mode 0 uses the complete P5 conditional legacy helper and worker sleep path, including direct barrier wakes;
- modes 1 and 2 use the epoch candidate;
- mode 3 uses the P5 unconditional/persistent positive-control helper and legacy worker path.

`VLIB_WAKE_FAULT_INJECTION` defaults to zero and preprocessing removes its per-thread control fields and write
wrapper branches. When compiled in, `handoff-perf wake-fault` selects deterministic success, `EINTR`,
`EAGAIN`, `EBADF`, `EINVAL`, or short-write outcomes for one to three attempts. Synthetic `EAGAIN` first does
a real eventfd write (or observes a real `EAGAIN`) so the required readable-fd meaning is preserved. The
diagnostics/injector combinations 0/0, 0/1, 1/0, and 1/1 passed syntax compilation with the actual VPP
`-Wall -Werror` flags; the plugin also compiled without the wake-patch macro.

The isolated source was reset to the three hash-verified P5 baseline files, the corrected patch passed
`git apply --check`, and the corrected source passed `git diff --check`. Ninja then removed 2,606 scoped
dependency outputs and rebuilt `vpp`, `vppctl`, and `handoff_perf_poc_plugin` from the preserved cache. The
clean scoped build completed 1422/1422 with exit status 0.

Corrected candidate hashes:

```text
P6 patch 0003=22a18ae02a2b57222f4ff9a0b2c5700aa5a606c9c002fe71f28ae59477aa176c
handoff_perf_poc.c=21974f76c5de29212347c612719a00d50f512ad30062c5d7f17254925d700f77
P6 main.h=1c3408d159daf1ac9c55c2636eb4619f431d46d953b634d0a988cba9d1abdcd0
P6 threads.h=f77562470112965d576eb11a45b48646a0ae0a0448de199709eaceeda6147a43
P6 file.c=9072a41dfe0de5f9faa8e509429981ea1d0e0b6ce642f0f94bed3003a3b2e4e5
CMakeCache=ea47ec2a30e23475816396246538e058ace27bf2918800470b2df02b4e528711
vpp=e35bacb16c1b361032a6aa414d683678e948fcf8a0fdb82a64551c5358d8285f
vppctl=4af2ddceeaf3d21e1d2e17124eda32ddf641adee4964ac6b3a7e624b432a07e7
handoff_perf_poc_plugin.so=3205a59b4dfc531b63d8608aa2069eb559ed8c7a2b3c0d2d3ea0d023fc4019d1
run-vpp-handoff-perf-poc.py=965fe5e58c0f206be836352bd485f31fe628f08d570d5792b5727930dd797b0d
```

The corrected non-performance smoke is `/tmp/sakamoto-p6b-final-smoke.XhWr7d`. It used build-tree `vpp` and
`vppctl`, main core 0, one worker on core 1, and an explicit plugins block containing the build-tree path,
default-disable, and only `handoff_perf_poc_plugin.so` enabled. Preserved outputs include `show-version.txt`,
`show-plugins.txt`, `show-handoff.txt`, `wake-fault.txt`, all three mode-setting outputs, `show-threads.txt`,
VPP stdout, and VPP log. The checks observed the plugin, two graph threads, `faults 0`, `awake 2`, all other
phases including `notifying` zero, injector reported unavailable in the final compiled-out build, mode 0/3/2
each accepted, and SIGTERM exit status 0. No traffic generator, timed interval, or CPU sampler ran.

### P6b corrected-candidate repeat review: HOLD

Luna's second bounded read-only review confirmed that all four first-review blockers were substantively
closed, and independently reproduced every corrected hash and the clean-build/smoke evidence. It nevertheless
found two new control-plane blockers, so this candidate also remains prohibited for P6c or performance work:

1. `handoff-perf start` and `handoff-perf wake-mode` changed the global protocol mode without first waking and
   quiescing workers. A worker could still be physically blocked in the legacy epoll path when producers began
   using an `AWAKE` epoch word, allowing queued work with no readable notification until timeout. The reverse
   transition could also retain an epoch phase. Every mode change must use the old mode to bring workers into a
   barrier, normalize protocol state while they are held, publish the new mode, and then release them.
2. The injector used separate outcome and remaining atomics, load-then-decrement consumption, no quiescence
   guard, and broadcast configuration. A concurrent control write could mix plan generations or underflow the
   counter, while aggregate reporting did not uniquely prove one target's consumption. It requires one packed
   CAS-consumed plan, quiescent configuration, explicit target-thread semantics, and per-target observation.

The first-review `NOTIFYING`, mode0/mode3, readable synthetic-EAGAIN, and terminal-retirement fixes remain the
base for this bounded correction. The new correction is limited to mode-transition and injection control-plane
atomicity; it does not authorize P6c.

### P6b control-plane correction candidate

Status: **candidate built and control-plane smoke passed; third read-only gate review pending**. Both earlier
HOLD candidates and their hashes remain immutable negative evidence. P6c and all performance work remain
prohibited until this gate returns GO.

All wake-mode mutation now goes through `handoff_perf_set_wake_mode()`. The helper requires the main thread, a
stopped benchmark, zero live tokens, and zero outstanding packets. It acquires the VPP worker barrier before
changing the global mode, so direct barrier wakes still use the old protocol. While workers are held it rejects
any VM in `NOTIFYING` or stable fault, clears the legacy sleep/pending controls, normalizes each epoch word to
`AWAKE` while preserving its epoch, release-stores the new mode, and releases the barrier on every exit path.
The start, allocation-failure, cleanup, and explicit wake-mode paths use this single helper.

The fault-injection plan is now one per-target packed `u32`: the low eight bits hold the outcome and the high
24 bits hold the remaining count. Configuration requires the same stopped, zero-live-token, zero-outstanding,
main-thread quiescence and occurs under the worker barrier. The CLI names exactly one worker thread and either
sets one to three attempts or disables that worker's plan. A writer acquire-loads the plan and consumes one
attempt with a bounded acquire-release CAS, preventing mixed generations and counter underflow. Barrier-direct
wakes bypass the injector. The final build still compiles the injector out.

The isolated source was again reset to the hash-verified P5 baseline, the current patch applied cleanly, and
the isolated diff check passed. Ninja removed 2,606 scoped dependency outputs and rebuilt `vpp`, `vppctl`, and
`handoff_perf_poc_plugin`. The clean scoped build completed 1422/1422 with exit status 0.

Current candidate hashes:

```text
P6 patch 0003=153a29a881dab982b83c4d40f797648d60827aa085b59f1493ff1b9885be7193
handoff_perf_poc.c=cb1a0842cb17a7f292bc1609c3bdda1ba87969dd28897786da5f5e73ea8dd7af
P6 main.h=0765897cea9c600c5ec9a65cc99d5ed3c29e727da2732560365f812882c19652
P6 threads.h=6700e2f24941ca9333c0318d7ddfae706ea49991c820520dccd12f537a6153dd
P6 file.c=9072a41dfe0de5f9faa8e509429981ea1d0e0b6ce642f0f94bed3003a3b2e4e5
CMakeCache=ea47ec2a30e23475816396246538e058ace27bf2918800470b2df02b4e528711
vpp=02612f6767ede885c6b93fbd4ec99aac36747309d29b136da84d9c689711eac2
vppctl=4af2ddceeaf3d21e1d2e17124eda32ddf641adee4964ac6b3a7e624b432a07e7
handoff_perf_poc_plugin.so=5894e7dfc582ad29d0af29f97b7c0a2baa49fd9829f5da1d3e936cedacc62bff
run-vpp-handoff-perf-poc.py=965fe5e58c0f206be836352bd485f31fe628f08d570d5792b5727930dd797b0d
```

The non-performance control-plane smoke is `/tmp/sakamoto-p6b-control-smoke.7GsJJ1`. It ran the build-tree
VPP with main core 0, one worker on core 1, and only the build-tree `handoff_perf_poc_plugin.so` enabled. It
observed two AWAKE graph threads, zero faults, zero `NOTIFYING`, accepted the complete 0 -> 3 -> 2 -> 0 mode
sequence, reported fault injection unavailable in the compiled-out build, and exited with status 0 on
SIGTERM. No traffic generator, timed interval, latency measurement, or CPU sampler ran.

### P6b third read-only gate: GO

Luna independently reproduced all ten current candidate hashes and verified the clean scoped build and
control-plane smoke evidence. The review found both second-HOLD blockers closed: all mode mutation is routed
through the old-mode worker-barrier transition helper, and the injector uses quiescent single-target packed
plans with bounded CAS consumption. It also rechecked the four first-HOLD items: complete mode-0 P5 barrier
wakes, `NOTIFYING` write ownership, compile-time removal, and terminal claim retirement.

Verdict: **GO for the current P6b implementation, clean build, and non-performance smoke only**. This does
not accept the candidate's full correctness. P6c must still supply the exhaustive atomic-step enumeration,
C11 happens-before argument, focused litmus, million-transition widened stress, injected eventfd outcomes,
spurious wake/EINTR, coalescing, sustained-awake, and teardown evidence before any performance experiment.
