# Android/VPP POC Decision Memo

Status: active; evidence is being collected.

This memo contains only durable problems, decisions, conclusions, and recurring pitfalls from the Android/VPP POC series. Command-by-command history stays in the corresponding execution ledgers under `experiments/vpp-nfq-poc/results/`.

## Scope and operating rules

- Start with real-device evidence; do not promote a POC result to production architecture without a reproducible device run.
- Treat the primary software distribution as direct-to-owner. Use one corrective handoff for an ownership mismatch; drop on a second mismatch.
- Keep adapter completion routing separate from packet ownership.

## SAKAMOTO-32 — NFQUEUE plugin audit baseline

Status: PASS for the current experimental synchronous NFQUEUE baseline; not a production async PacketLease approval.

On the real Pixel 6a root profile, the plugin passed IPv4 and IPv6 INPUT/OUTPUT accept, drop, and 50% ratio cases. Verdict counters matched ping/ping6 outcomes (`4/4/0`, `4/0/4`, and `20/10/10` patterns), packet event logs exposed IDs and bounded copy range 512, and active disable removed the queue. Ten-second idle samples showed no traffic/error growth; final VPP process, NFQUEUE queue, and iptables/ip6tables hooks were absent.

This only proves the existing callback/verdict baseline. It does not prove SAKAMOTO-38's asynchronous PacketLease, lane-generation identity, stale/missing IDs, deadline handling, or multi-lane completion ownership. Those remain independent follow-up POCs.

## SAKAMOTO-33 — TUN canonical direct-to-owner

Status: GO for the narrow POC scope.

Question: can the Android `VpnService` TUN ingress classify a canonical direction-independent five-tuple and enqueue directly to its final worker owner, with an observable owner guard and bounded corrective fallback?

On Pixel 6a / Android 16 / arm64-v8a, IPv4 and IPv6 TCP/UDP bursts reached two fixed workers through direct software distribution. Both runs had zero Owner Guard mismatches, zero congestion/alloc errors, zero corrective handoffs, and stable reverse-owner projections. HTTP and UDP probes completed, and teardown left no VPP process.

First device run established the direct path counters (two workers, clean Owner Guard, no corrective handoff) but also exposed a lane boundary: Android `VpnService` outbound packets arrive on the primary TUN fd, while HEV responses arrive on the shim fd and are written back to TUN. A live reverse packet therefore does not re-enter the primary direct-owner classifier. The POC now proves reverse-owner equality by projecting the parsed tuple with source/destination swapped, while keeping live reverse-ingress matches as a separate counter. This must not be described as bidirectional primary-TUN ingress.

## SAKAMOTO-34 — selected polling thread

Status: GO for the selected-thread POC; production performance sizing remains open.

The corrected startup configuration (`unix { cli-no-pager }`) produced complete evidence on the Pixel 6a. IPv4 and IPv6 runs both configured TUN and shim `clib_file` callbacks on polling thread 1, showed callback hits on thread 1, reached both fixed workers, and completed with zero Owner Guard mismatches, zero reverse-projection mismatches, and zero corrective handoffs. The selected-thread path therefore works on the real Android device for this bounded workload.

An idle sample over five seconds showed low, sleep/wakeup-style CPU activity (main and two worker threads each advanced roughly 29–30 scheduler ticks at `USER_HZ=100`); it did not show a busy-spin. This is only a no-busy-polling sanity check, not a performance target. A deliberately long startup wait later made the monitor counters remain at startup while external probes still completed, so the harness must use the normal short startup window for acceptance and treat long-idle runs as a lifecycle/timing pitfall.

## SAKAMOTO-35 — Owner Guard fault injection

Status: GO for the bounded fault contract; implementation remains throwaway.

On the same Pixel 6a, IPv4 and IPv6 runs injected two wrong-worker placements. The first mismatch was corrected exactly once and continued (`corrective-handoff 2`, `corrective-drop 0`, `single-completed 1`); the deliberately repeated mismatch was dropped (`second-mismatch-drop 1`) with no loop or third enqueue. Final runs showed Owner Guard pass/mismatch `37/3`, reverse projection `38/0`, and successful HTTP/UDP probes with clean teardown. This validates the one-correction-then-drop contract at the worker boundary, not a production fault policy.

## SAKAMOTO-36 — transport-return direct-to-owner

Status: GO for the bounded two-lane Android POC; completion routing remains a separate concern.

The real Pixel 6a IPv4 and IPv6 runs routed shim/transport-return packets through the same canonical OwnerSelector and worker guard instead of writing them directly to TUN. IPv4 had 25 return packets enqueued, processed, and completed to TUN; IPv6 had 28. Both had zero Owner Guard mismatches, zero reverse-owner mismatches, zero congestion drops, and successful HTTP/UDP probes with clean teardown. The implementation records the return lane separately from primary TUN ingress and keeps the completion writer distinct from flow ownership.

## SAKAMOTO-37 — VPN single-writer backpressure and teardown

Status: GO for the bounded Android completion-owner POC; production capacity and revoke-drain work remain open.

On the real Pixel 6a, primary TUN output and transport-return output both crossed a dedicated `tun-poc-completion` owner. IPv4 and explicit IPv6 runs reached two fixed workers with zero Owner Guard mismatches and zero reverse-projection mismatches. Completion enqueue/processing closed exactly (`68/68` IPv4; `71/71` IPv6), and a deterministic two-packet EAGAIN budget produced exactly two terminal drops without alternate-worker routing. Return-lane packets were written back to TUN only by the completion owner; HTTP/UDP probes and a repeated start/traffic/stop cycle completed with no VPP residue.

This is a bounded ownership/lifecycle result, not proof of kernel-level `EAGAIN` under a full pending queue or VpnService revoke drain. The next implementation must retain a bounded pending credit, explicit fd-revoke state, and one terminal outcome per buffer. The completion owner must remain separate from the canonical flow owner.

## SAKAMOTO-38 — NFQUEUE single-lane asynchronous PacketLease

Status: GO for the bounded throwaway Android root POC; production async I/O and capacity remain open.

On the real Pixel 6a, one NFQUEUE queue and one netlink socket were modeled as a bounded 64-slot PacketLease lane with two asynchronous workers and a VPP-main-thread completion owner. IPv4 and IPv6 OUTPUT runs both produced the same contract: 16 packets seen, 15 asynchronous leases, 15 worker dispatches, 16 terminal outcomes including one missing-ID fallback, and zero verdict/pipe errors. Injected duplicate, stale-generation, missing-completion/deadline, and missing-ID cases each produced an explicit count of one. Worker completions were allowed to arrive out of order; stale generations and duplicate completions never sent a second verdict.

An active shutdown with a 200 ms worker delay drained one in-flight lease as a DROP before queue teardown (`shutdown-drops 1`, `verdict-errors 0`). The first shutdown attempt exposed a real lifecycle rule: deleting the VPP `clib_file` for the NFQUEUE fd before draining async leases closes the netlink fd and returns `EBADF`. The final ordering is therefore: stop ingress, join workers, drain/close every lease with the still-open queue socket, then delete the fd registration and destroy the queue.

This is a GO for the single-lane ownership/lifecycle seam only. It is not evidence for sustained overload capacity, multiple NFQUEUE lanes, VpnService fd mode, or production retry/backpressure policy. The throwaway implementation must not be promoted unchanged.

## SAKAMOTO-39 — NFQUEUE congestion and policy separation

Status: GO for bounded userspace backpressure and listener-missing separation; kernel `ENOBUFS` remains unproven on this device.

On the Pixel 6a root profile, a 64-slot async lease ring with 500 ms workers was filled by 128 concurrent one-packet processes. IPv4 reached `seen 128`, `ingress 64`, `pending-peak 64`, `overload/worker-backpressure 64`, and zero verdict/pipe errors. IPv6 reached `seen 132`, `ingress 67`, `pending-peak 64`, `overload/worker-backpressure 65`, and zero verdict/pipe errors. Rejected descriptors were dropped on the originating lane; no alternate-worker route was used. This validates userspace worker backpressure preserving lease identity and a unique terminal outcome.

The three policies stayed separate: with the listener removed and `--queue-bypass`, four pings succeeded while the kernel reported no NFQUEUE listener; with queue maxlen 8 and a 20 ms ingress delay, only eight of 128 submitted packets reached userspace, but `enobufs` stayed zero. The latter is supporting queue-capacity evidence, not proof of a socket `ENOBUFS` event. A production policy must expose kernel queue overflow independently instead of folding it into worker backpressure.

This result is a GO for the bounded userspace seam, not a capacity target. Completion-credit accounting, sustained traffic generation, and a reproducible kernel-overflow signal remain open.

## SAKAMOTO-40 — NFQUEUE two-lane direct distribution

Status: GO for the bounded two-lane ingress/owner seam; asynchronous worker completion and queue-count selection remain open.

On the Pixel 6a, queue pairs 56/57 (IPv4) and 58/59 (IPv6) each used independent NFQUEUE handles, sockets, and VPP file callbacks. Both lanes fed one direction-independent canonical address/protocol/port hash; queue number and polling context were not part of the owner key. IPv4 exercised both lanes evenly (`32/32` packets) with both owner buckets active and zero verdict errors. IPv6 exercised both lanes (`64/32`) and both owner buckets (`32/64`) with zero verdict errors. A bounded stale-completion fault was counted once per run without sending a second verdict.

The first run caught a lifecycle bug in the throwaway mode: when the two lane file indices were `~0`, disable freed both lane handles but did not clear `enabled`, blocking the next family. Clearing enabled independently of the primary file index fixed the rerun. This is now a recurring teardown rule for modes with multiple fd registrations.

This POC performs owner/verdict work in the lane callback; it demonstrates lane isolation and canonical owner selection, not asynchronous worker completion returning to the original lane. Production multi-lane completion remains open.

## SAKAMOTO-41 — VPN/TUN Fragment Owner → Flow Owner

Status: NO-GO for real-device fragment evidence; parser/state code is compile-verified only.

The throwaway `fragment-owner` mode now contains a bounded IPv4/IPv6 fragment-key table, non-overlapping range tracking, malformed/overlap/duplicate/capacity/timeout terminal counters, and a single contiguous Fragment Owner → Flow Owner transition. Android JNI/Java wiring and a no-HEV TUN-only variant both build and start on the Pixel 6a. The acceptance run used app-owned 4000-byte UDP sends and attempted large-payload ping; ordinary TCP packets reached the direct workers and teardown was clean, but every TUN snapshot reported `fragment packets 0`. HEV's SOCKS UDP path did not expose its original datagram as TUN fragments, and an app-launched ping exited without raw-socket capability. A no-HEV run and a VPN-local UDP destination reproduced the absence, so this is recorded as a traffic-generation/observation blocker rather than a worker-owner result.

Do not promote the fragment implementation or claim reassembly correctness yet. Revisit with a controlled VPN peer or dedicated packet generator. Root/NFQUEUE fragmentation remains independent and should continue.

## SAKAMOTO-42 — Root/NFQUEUE Fragment Owner → Flow Owner

Status: NO-GO for real-device multi-packet fragment observation; implementation remains unstarted beyond a controlled preflight.

The Pixel 6a root profile was tested with a dedicated Android NDK raw IPv4 sender that emits aligned fragments for a 4000-byte ICMP payload, avoiding Android `ping` as the only generator. The sender completed successfully, but the NFQUEUE `async-lease` path exposed exactly one packet ID per datagram (`seen/ingress=2` for two datagrams), not multiple packet IDs for the constituent fragments. A preliminary `ping -s 4000` control showed the same coalesced observation. The first sender run's push failure was a root-owned staging-directory issue and was corrected before interpreting datapath results; the corrected run ended with no VPP, queue, or iptables residue.

This does not prove that the kernel always reassembles before NFQUEUE, but it is sufficient to mark the requested device/profile acceptance as unavailable: no Fragment Owner table, bounded reassembly, or Flow Owner transition can be validated without independently observable fragment packet IDs. Keep fragment parsing/reassembly out of the production path. Revisit with a controlled netfilter namespace/hook or a device/kernel profile that preserves fragments into NFQUEUE, while continuing the independent worker-profile and topology POCs.

## SAKAMOTO-43 — VPN main versus I/O-worker profile

Status: GO for bounded functional comparison; compact/main polling is the default candidate and worker polling remains a fallback/benchmark.

The same installed Android APK, direct-owner `OwnerSelector`, two-worker map, HEV path, and ten-flow HTTP plus 8-packet UDP workload were run on the Pixel 6a in both profiles. Compact/main kept TUN/shim callbacks on `polling-thread main 0 shim 0`; worker polling used `main 1 shim 1`. Both returned ten HTTP `200 OK` responses and all 8 UDP sends, had zero owner-guard mismatches/corrective handoffs/congestion errors, and stopped without VPP residue. HTTP latency was `p50/p95/p99=14/50/50 ms` versus `11/53/53 ms`; UDP completion was `3006 ms` versus `3004 ms`. Three-thread VPP samples were effectively equal (aggregate active ticks `182→1152` versus `181→1152`; context switches `293→5395` versus `197→5306`), and sampled peak skin temperature was about `37.8 C` versus `37.6 C`.

The initial short polling run sent all packets to one worker, exposing hash/sample-size skew; the paired rerun used ten independent flows and reached both workers. The sample is not long or instrumented enough to claim throughput, p99, power, Doze, residency, or thermal superiority. Keep main polling as the default for simpler ownership and no demonstrated benefit from moving fd callbacks; retain worker polling for a later sustained-load campaign if main-loop pressure appears.

## SAKAMOTO-44 — NFQUEUE queue and polling topology matrix

Status: GO for bounded lane/owner matrix; 2 queues is the default candidate, 4 queues is benchmark-only until sustained capacity evidence exists.

The real Pixel 6a root profile ran 2/1, 2/2, 4/1, and 4/2 cases with the same queue capacity, owner hash, four destination-specific OUTPUT rules, and eight rounds of one-packet ICMP probes per active lane. Every case accepted all submitted packets with zero verdict errors and zero ENOBUFS. The 2-lane cases observed `8/8` packets per lane; the 4-lane cases observed `8/8/8/8`. A stale-completion identity fault was counted once per case without a duplicate verdict, and every case ended with no VPP, NFQUEUE, or iptables residue.

The `lane-matrix` extension is throwaway. Its `polling-contexts` value records the requested topology for comparison, but each `clib_file` callback still runs in VPP's main polling context; this is not evidence that true 2/2 or 4/2 worker polling has been implemented. Select 2 queues for the Android default to limit fd/ring overhead while preserving lane isolation and canonical owner hashing. Keep 4 queues behind benchmark configuration and do not derive queue count from `hardware_concurrency`.

## Recurring pitfalls

- The Android VPP build harness can re-run CMake and then fail in `vppapigen` when the host Python environment does not provide `ply`. This is a build prerequisite; keep the dependency isolated and reproducible rather than treating it as a datapath failure.
- The configured Android VPP build uses a copied `work/vpp` source tree. After editing the repository overlay, apply it to that work tree before an incremental build; otherwise a successful build can package the previous plugin.
- VPP CLI `unformat` accepts prefixes, so longer experimental mode names must be parsed before shorter names (for example, `direct-owner-fault` before `direct-owner`).
- The same prefix rule applies to async fault flags: parse `async-missing-id` before `async-missing`, or the CLI leaves `-id` as an unknown token.
- Refresh the Android stage after an incremental plugin build. A fresh `vpp-android-configure-probe` artifact does not update `work/android-vpp-direct-owner-stage` automatically; comparing staged-plugin and APK hashes catches this packaging false negative before a device run.
- The Android push helper needs absolute WSL stage paths for `startup.conf`; relative paths can push binaries and then fail to resolve the config. Use an absolute `BUILD_DIR`/`STAGE_DIR` for root-profile audits.
- For asynchronous NFQUEUE teardown, the queue/netlink fd must remain open until all worker completions and shutdown DROP verdicts are sent. Removing its `clib_file` first causes `nfq_set_verdict` to fail with `EBADF` and can leave a kernel packet unresolved.
- Android `ping -f` does not guarantee a high-rate flood when the destination is unreachable; use a bounded concurrent local workload (or a dedicated packet generator) before concluding that worker backpressure is absent. Keep queue capacity, listener absence, and worker capacity as separate measurements.
- A multi-fd mode must clear its global enabled state even when no primary `file_index` exists; otherwise freeing secondary lane registrations still leaves the mode logically enabled and blocks the next family/run.
- A successful Android plugin build can still package an older mode list when the repository overlay was not copied into the configured `work/vpp/src` tree; compare source and staged-plugin hashes/strings before a device run. Android app-owned UDP `send()` success is not proof that a datagram reached the TUN fd, and shell/raw-ICMP traffic is not valid evidence when the VPN is scoped to the app UID.
- A root-owned staged VPP directory is not writable by the ADB transport user after the push helper tightens permissions. Push auxiliary probe binaries through `/data/local/tmp` and move them with `su 0`; otherwise a sender setup error can be mistaken for a packet-path result.
- A matrix case must terminate the previous VPP instance even when its runtime directory differs; otherwise the next CLI can connect to a stale disabled instance and produce a false topology failure. Kill the recorded PID and verify `pidof vpp` before starting the next case.

## Plane project DOC synchronization

Synced to the Plane project DOC page `Android/VPP POC Decision Memo` (page id `f2e22ef3-783c-4bdb-8a89-bd153fd9b86e`) on 2026-07-20 after the SAKAMOTO-44 update.
