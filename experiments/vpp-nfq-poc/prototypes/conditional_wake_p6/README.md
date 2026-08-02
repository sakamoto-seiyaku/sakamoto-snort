# P6c conditional-wake correctness harness

This directory is throwaway POC evidence. It does not replace the VPP runtime
fault-injection campaigns or prove unbounded C11 executions.

Run the bounded exhaustive model, deterministic fault matrix, a 5,000-round
focused C11 litmus, and a 200-round ASan/UBSan smoke:

```sh
./experiments/vpp-nfq-poc/prototypes/conditional_wake_p6/run_p6c.sh
```

Run the required supplemental million-transition stress explicitly:

```sh
./experiments/vpp-nfq-poc/prototypes/conditional_wake_p6/run_p6c.sh --long
```

An arbitrary short count is available as `--transitions N`. The fixed default
seed is `0x5A4B20260802`.

Files:

- `p6c_exhaustive.py`: BFS over atomic producer, worker, notification, epoll,
  drain, clear, and teardown steps. Its semantic key retains every PC, CAS
  expected snapshot (including retire/drain/clear retries), and
  memory-visibility mask. Permanent lost wake is checked before expanding any
  state. EINTR coverage includes no-owner recovery, a current-poll NOTIFYING
  rejection, and rejection again on the following zero-timeout poll. JSON counterexamples are
  shortest because BFS visits by trace length.
- `p6c_litmus.c`: three persistent real threads (two producers and one worker)
  using the same release/acquire/acq_rel structure and deterministic
  `sched_yield()` widening. Implementation helper loops use the same 64-CAS
  budget and report exhaustion. Stress is supplemental evidence, not proof.
- `fault_scenarios.py`: frozen `EINTR`, `EAGAIN`, `EBADF`, `EINVAL`, short-write,
  epoll, coalescing, sustained-awake, and teardown checks (14 deterministic
  cases, including EINTR with and without a concurrent NOTIFYING owner).
- `P6C_HAPPENS_BEFORE.md`: mapping from the current overlay patch to the model
  and focused litmus.

The final-build and injector-enabled VPP campaigns are intentionally not run by
this local harness. They require the main POC controller to build and drive the
actual VPP process.

After producing an injector-enabled build, run the isolated real-VPP correctness
campaign into a new result directory:

```sh
./experiments/vpp-nfq-poc/prototypes/conditional_wake_p6/run_vpp_p6c_faults.py \
  --build-dir /tmp/sakamoto-p6-epoch-work/vpp/build-root/build-vpp-native/vpp \
  --result-dir /tmp/p6c-vpp-runtime-20260802 \
  --seed 0x5A4B20260802
```

The result directory must not already exist. Each case gets an independent VPP
process, startup configuration, stdout and VPP logs, CLI transcript, input
hashes, and `case.json`; the root receives `summary.json` and `summary.md`.
Fixed one/three-second waits only trigger correctness paths and are not reported
as performance measurements.

The sanitizer smoke disables LeakSanitizer only. This harness performs no heap
allocation, and this host's LeakSanitizer exit scan recursively faults inside
`__lsan::CheckForLeaks()`. ASan memory checks and UBSan remain enabled; the
diagnosis was reproduced separately with plain, UBSan-only, and ASan-only
builds.
