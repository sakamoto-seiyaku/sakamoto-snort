# SAKAMOTO-205 — single-lane remote Primary Handoff

Acceptance: **functional PASS**, 2026-09-08, generations 657/658. Scope is real
Pixel Root NFQUEUE, one app-UID IPv4 UDP OUTPUT lane on logical worker 0.
Owner-local and one-hop remote-owner completion are proven. This is not a
release, latency, queue-pressure, dual-stack, INPUT or VPN acceptance.

## One assignment and one handoff

The shared admit parser computes the canonical owner once. A local assignment
continues directly to policy. A remote assignment reserves a bounded primary
credit and transfers the original buffer index with the pinned retained-enqueue
primitive into a private FQM targeting `product-packet-policy` directly.

The receiver releases that primary credit and consumes the existing typed
metadata. It neither reparses, rehashes, rewrites the owner nor performs a
corrective handoff. The policy node uses its actual VPP worker and marks policy
ownership ready after arrival. In bounded trace/evidence mode it compares actual
receiver to the stored assignment; mismatch is an implementation-error runtime
DROP, with no policy evaluation and no second handoff.

The legacy Owner Guard node, corrective route and historical fragment graph are
compiled only for Host evidence. The installed Product plugin does not register
`product-packet-owner-guard`; the actual CLI reports that node as unknown. The
pure C historical test helper does not constitute a product graph route.

The reference fork's `src/vnet/handoff.c` computes a worker and passes its thread
index to the native handoff queue. Its `stellar_session_manager` (the external
plugin's actual name, not a Product module) selects runtime from
`vlib_get_thread_index()`. These were read as behavioral references. No fork
implementation, expanded overlay, exdata, POC source or removed C++ code was
imported.

## Same Completion Frame back to origin

Terminal seals the same 32-byte S204 Completion Frame in the retained buffer's
opaque2. Local completion uses the native next frame; remote completion returns
the same buffer index through a private FQM to the existing origin-completion
node on worker 0. Worker 1 never invokes the Root consumer or accesses its fd.
The origin consumer uses the original queue generation, packet ID, lane and
opaque token for one verdict attempt and one buffer return.

There is no new packet allocation or payload copy on either ordinary transfer.
A retained return enqueue failure keeps ownership in a fixed per-worker queue
of buffer indices. A budgeted native input node retries only that transfer and
is disabled when the queue empties; it does not re-enter parser/policy or retry a
verdict. The queue capacity is 128, above the current one-lane 64-obligation plus
32-test-injection carrier bound. Primary rejection similarly stays owned on
arrival and completes a runtime DROP. These are ownership/failure paths, not a
claim that queue pressure has been qualified; S210 still owns those tests and
capacity tuning.

## Real Pixel matrix

| Case | Admit | Policy / terminal | Origin completion | Result |
| --- | --- | --- | --- | --- |
| Local baseline, source port 30001 | worker 0, owner 0 | worker 0 | worker 0 | Echo |
| Remote, source port 30000 | worker 0, owner 1 | worker 1 | worker 0 | Echo |
| Same remote flow again | worker 0, owner 1 | worker 1 | worker 0 | Echo |
| Forced delivery mismatch | worker 0, owner 1, one FQM publication deliberately targets worker 0 | Actual worker 0 detects mismatch; runtime DROP, no policy verdict | worker 0 | No echo |
| Remote recovery | worker 0, owner 1 | worker 1 | worker 0 | Echo |
| Restart with new generation | worker 0, owner 1 | worker 1 | worker 0 | Echo |

The negative delivery case never changes the selected owner. Its metadata still
says owner 1 and primary=1/corrective=0 at receipt on worker 0. The next normal
remote packet executes on worker 1 again. This negative case is not counted as
successful remote execution.

Two separate descriptor replays exercise S204 again using completed remote
identities: a non-last duplicate and a generation differing above bit 32. Both
are rejected at origin without another NFQUEUE verdict; their fresh diagnostic
carriers are returned independently.

First generation actual VLIB vectors:

- Thread 1 / worker 0: admit 5, policy 2, terminal 2, origin completion 7
  (five real packets plus two descriptor replays).
- Thread 2 / worker 1: policy 3, terminal 3. No remote admit, origin verdict node,
  Owner Guard or corrective node visit.
- Primary publications/receipts 4/4, delivery checks/failures 5/1, successful
  remote completion returns 3, rejected enqueue/deferred return/retries 0.
- Origin consumer: five real verdicts, local=2, remote=3, duplicate=1, stale=1.
  Pending returns, primary credit debt, frames, buffers and obligations are zero;
  both primary credit pools are restored to 32.

Restart has one remote handoff, one policy/terminal on worker 1 and one completion
on worker 0. All ledgers are zero before each stop; hook/socket/process cleanup
is verified after both stops. There is no FlowEntry mutation, tracker or broader
FlowRuntime claim (S208 remains separate).

## Latency finding — functional scope only

The first attempt (`pixel-a`, generation 652) used a 1.5-second application wait
and timed out after a real remote handoff. It is retained as HOLD, with cleanup.
The next run used an explicit 8-second functional wait and completed the matrix.
The final artifact adds monotonic native event timestamps to distinguish delayed
processing from missing/corrupt frames.

Final samples show roughly 1.09–1.16 seconds admit-to-remote-policy and 2.00 seconds
remote-terminal-to-origin, totaling about **3.10–3.16 seconds**. The local sample
is about 0.78 ms. These six diagnostic samples are not a latency benchmark.

The retained Android stage includes
`src/product/vpp/android/patches/0017-vpp-android-idle-profile.patch`, which sets
`vlib_file_poll`'s maximum idle wait to 1000 ms and lets workers ignore cloned
polling-node state/recent-barrier holdoff. The pinned main loop can poll files
between FQM dequeue and internal-node dispatch. That behavior is consistent with
the observed whole-second delays. This task preserves that accepted idle
profile and introduces no worker wake mechanism. Low-latency and power acceptance
remain open; a functional PASS here must not be read as acceptable app latency.

## Final artifact and evidence

- Build witness: `build-output/s205-handoff/build-c/build.json`; source snapshot
  and dirty diff are retained beside it.
- Request: `build-output/s205-handoff/request-c.json`, post-build and before all
  accepted packet nonces.
- Accepted run: `build-output/s205-handoff/pixel-c`, generations 657/658.
- Commit: `9c67175713baceb46cef015f3464893fa3d69950` plus recorded dirty source.
- Source SHA-256: `a1b545aa6c2b07f99b9aaf147e5bf4603377ec81ec83fa4992b8cf89d737fa8d`.
- APK SHA-256: `4eefc0327428939df711e91bb9b8161127b51f03ec932ac0185a37d0d323eb9d`.
- Plugin SHA-256: `831219b0242e106a1dde9cb57734257803eef716e2ae71451b2c559e4cd44825`.
- Artifact ID: `sakamoto-product-vpp-s205-v1`; readiness is explicitly
  `root-nfqueue-udp4-owner-directed` with the single-lane OUTPUT scope above.
- `tests/device/verify-s205-primary-handoff.py` with the request returns PASS.
  It binds source, installed APK/all twelve native libraries, fresh generation
  and nonces, actual per-worker node vectors, one immutable assignment, retained
  buffer identity, causal handoff/return events, verdicts and final ledgers.
- Android runtime contract suite, Host-evidence plugin compilation, S192 source
  contract, Python syntax and diff checks passed. Native C adds no warnings.

The complete acceptance report is also recorded in the private Plane instance. Earlier source/run
witnesses remain historical: their strict current-source checks are expected to
reject after later product changes.

Evidence clones in `build-output/s205-handoff/negative-b` reject a fake policy
worker, a corrective hop, and a rewritten owner assignment.
