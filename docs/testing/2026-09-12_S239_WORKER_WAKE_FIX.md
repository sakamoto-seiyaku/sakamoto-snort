# S239 native worker notification fix — 2026-09-12

The reproduced seconds-long dispatch defect is fixed in the tested scope.
This is not full S239 or release-performance acceptance. Authoritative task:
SAKAMOTO-239; evidence comment `f47e4a84-a874-4cf5-af85-19059245e6c0`.

The later [build-g W2 evidence](2026-09-12_S239_W2_NATIVE_ACCEPTANCE.md) uses the
same VPP core with additional Product validation seams. The build-d hashes
below identify this earlier wake-regression record, not the latest Product
source closure.

## Final artifact

- VPP remains `9258530f3804a152578ce11cc7c8a1e9eab88ed0` (26.02).
- Android stage: `/tmp/s239-wake-vpp-stage`, built with NDK r29/API31/arm64.
- Android patches: 19;
  `884aa3aac9457d8b34482f0d0c0faeb933831653f37e0f856fd8a6756a4ea400`.
- Common-core patches: 5;
  `4e6569b35c7b58246448f5260735bf766830483f9323fbb62fde3d4151e46247`.
- Product source closure:
  `87d4f029b8f3229d13073e091017eaa9600f430c36dcfa714d04d8a99ae9fda7`.
- Installed APK:
  `92505a03e0776c1ff4bec01198777d0c42f34c4466d20c762da5d4614160b191`.
- Manifest: `build-output/s239-20260912/pixel-build-d/build.json`.
- Device: Pixel `28201JEGR0XPAJ`; all operations used `./dev/adb`.

The manifest captures current source files, dirty diff and native closure;
this is not a clean-worktree claim. The earlier build-c demonstrated wake
recovery, but build-d supersedes it after correcting the plugin's inline
timer tick definition to match the staged Android VPP core.

## Cause and implementation

[The original repro](2026-09-11_S239_W2_DISPATCH_EVIDENCE.md) failed twice on
owner 1 while owner 0 passed. Native queue publication did not wake the target;
the idle gate also allowed sleeping with already-dequeued local graph frames.
The existing application timeout was not increased.

New Android patch `0019-vpp-worker-notification-latch.patch` implements the
accepted ADR-0006 decision on the pinned source:

1. Native frame publication marks queue readiness atomically and calls the
   shared worker notifier. Every call executes a seq_cst pending-latch RMW;
   only the first publication in an acknowledgement epoch writes eventfd.
2. Before checking whether to block, the destination reads its normal
   nonblocking eventfd once, acknowledges the latch, then checks remote queue
   readiness, local pending frames, scheduled work, interrupts and barriers.
3. The fd-ready callback no longer drains notifications after the final work
   check, and the old post-wait latch clear is removed. Late notifications may
   leave harmless readiness instead of losing work.
4. Node interrupts and initial/normal barrier wakes use the same notifier.
   No separate packet wake flag or new packet queue is added. Unexpected
   notification errors fail explicitly; EINTR is retried and EAGAIN handled
   according to ordinary nonblocking eventfd semantics.
5. Real polling nodes again veto blocking. Product reassembly expiry uses a
   scheduled node on the existing 50 ms cadence only while contexts exist.
   Dependency-blocked completion retries use a bounded 1 ms native deadline,
   rather than forcing a permanently polling input node.
6. The Android plugin defines the same idle-profile timer tick as the staged
   core. Without that agreement, inline timer scheduling would use the host
   default tick and delay deadline work. The final artifact includes this fix.

Native wake descriptors remain worker/process-lifetime resources. Product
generation shutdown retains worker progress until obligated buffers drain,
then the supervised process exits; this change does not close and reuse a
worker notification fd while live publishers retain its destination.

The Android patch allowlist and its affected-path allowlist were updated.
No upstream queue rewrite, optional membarrier requirement, extra payload copy,
or change to policy/FlowOwner identity was introduced.

## Executed regression evidence

### Native/host and primitive tests

- `vpp_worker_sleep_gate_test.py` extracts the actual pre-epoll decision.
  The original source reproduces wrong blocking with queued/local work.
  The fixed source passes idle, node interrupt, local frame, remote frame,
  due scheduled node and runnable polling-node cases. This substitutes VPP
  environment types and records timeout selection; it is not a kernel test.
- `vpp_worker_notify_test.py` extracts the actual notifier and acknowledgement
  functions and exercises real eventfd/epoll. Host runs passed retention,
  LT readiness, 100 publications coalescing to one write before acknowledgement,
  EINTR/EAGAIN, an elected but delayed writer, and two publishers with 50,000
  publications each. A safety timeout fails rather than rescuing the test.
- The same generated C was compiled with NDK API31 and executed on Pixel as
  `/data/local/tmp/s239-native-notify-test`; passed. This is a standalone shell
  process test, not the app-owned VPP integration. Its reported write count
  varied with scheduling and is not a performance target.
- `vpp_initial_barrier_test.py` executes the actual initial-barrier function
  with the new notifier and passed against a sleeping worker.
- Existing HEV host suite: 10/10 passed. Android mempolicy/stage contract passed.
- `s239_wake_verifier_negative_test.py` rejects a missing credit release,
  wrong return-policy worker and injected two-second completion delay.

### Final installed APK: independent verifiers passed

All paths below are under `build-output/s239-20260912/`.

| Run | Generation | Verified outcome |
| --- | --- | --- |
| `d-root-reassembly-basic` | 1110 | 32 original buffers; basic dual-stack reassembly/failure/timeout matrix; exactly-once completion/free |
| `d-root-completion-pressure` | 1111 | 24 originals; policy-return congestion; retained completion and clean drain |
| `d-owner1-sleep-udp4` | 1112 | Sleeping remote owner, exact UDP4 echoes |
| `d-owner1-sleep-udp6-policy` | 1113 | Sleeping remote owner, UDP6 echo, return Policy DROP and recovery |
| `d-owner0-sleep-overlap` | 1114 | Sleeping local owner, UDP4 echo, stop with actual queued HEV input |
| `d-owner0-sleep-udp6-preaccept` | 1115 | Sleeping local owner, UDP6 pre-accept rejection and same-session recovery |

Root rows use `verify-s229-reassembly.py`, preserving their GRAPH_INJECTED
reassembly witness scope rather than claiming every fragment came from real
network capture. VPN rows use `verify-s239-wake.py` against real application
UDP, TUN, HEV, broker and underlay endpoints. It verifies canonical ownership,
thread/TLS for mutable callbacks, original native buffer identity through
graph/completion/free, return-credit settlement and both shard shutdowns.

For each final VPN row the selected worker was observed in `do_epoll_wait`
after a quiet interval before the probe. The observation reads kernel state;
it does not issue a VPP CLI command or barrier in that window. It establishes
observed sleep before the probe, not exact continuous residency until enqueue.

Per-run maximum measured admit-to-policy or terminal-to-origin-completion
intervals were respectively **0.898, 5.164, 1.387 and 2.168 ms**. These are small,
traced diagnostic samples, not p95/p99, hard-real-time or power qualification.
They do not reproduce the previous roughly 1–2 second stage delays.

Two short idle samples also preserve process/selected-thread CPU tick deltas.
They are coarse, non-simultaneous observations and not the formal P6 idle gate
or battery-energy evidence. Eventfd syscall counts from the standalone test
must not be substituted for integrated VPP scheduling counts.

Every final run stopped cleanly. Last observed device state: generation 1115,
`state=stopped`, `mayBeActive=false`, `pid=-1`, empty error code. Both VPN shards
reported zero sessions, inputs, pbufs, graph buffers, obligations and frames;
sockets balanced and timer/broker descriptors closed.

## Reproduction commands

```sh
rtk proxy python3 tests/host/vpp_worker_sleep_gate_test.py \
  --source /tmp/s239-wake-candidate-source-b/src/vlib/file.c
rtk proxy python3 tests/host/vpp_worker_notify_test.py \
  --source /tmp/s239-wake-candidate-source-b/src/vlib/file.c
rtk proxy python3 tests/device/verify-s239-wake.py \
  --build build-output/s239-20260912/pixel-build-d/build.json \
  --run build-output/s239-20260912/d-owner1-sleep-udp4
```

## Acceptance boundary

The reproduced dispatch defect and these regressions are closed in this
artifact. At this earlier checkpoint S239 remained In Progress: sustained simultaneous W2 dual-stack,
swapped native return-credit exhaustion with other-owner progress, fuller race
and lifecycle stress, screen-off/Doze, and pre-registered idle/tail-latency
qualification still need their own evidence. Neither this result nor the
accepted design retroactively passes the old P6 campaign. No release readiness
or TCP transport acceptance is claimed.

The later [build-g record](2026-09-12_S239_W2_NATIVE_ACCEPTANCE.md) closes those
correctness scenarios. On 2026-09-12 the user split formal CPU/p99 comparison
into SAKAMOTO-248, allowing S239's functional completion without a performance
or release PASS claim.
