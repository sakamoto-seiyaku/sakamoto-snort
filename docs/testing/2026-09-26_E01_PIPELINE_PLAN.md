# E01 preregistered pipeline experiment — 2026-09-26

SAKAMOTO-274 is an experiment and user decision gate. Results cannot close the
issue or unblock T23 before the user reviews the evidence and chooses a direction.
No numeric performance acceptance threshold is presumed.

## Questions and controls

Measure the actual VPP Flow producer → selected svm_msg_q → Rust overview →
transactional minute store → normal query path. Compare (A) basic accounting with
record production disabled, (B) ordinary records and Rust overview without the
store, and (C) the complete current store. All retain the same packet/policy path,
Flow state, basic counters, queue capacities, wire, worker layout and payloads.
A intentionally removes activity clock sampling together with export bookkeeping;
A/B is their combined cost, not an isolated clock-cost estimate. Supplemental
clock microbenchmarks cannot substitute for that end-to-end comparison.

Use one explicitly experimental source overlay for measurement controls, isolated
store paths and aggregate diagnostic timing. Retain its exact source and binaries.
The overlay is not a Product configuration API or a chosen release change. Restore
Product source after builds; never modify the accepted Android history. The default
C arm uses the original 32-packet/65536-byte growth thresholds, 1-second refresh,
128 records per channel drain, 64 due-flush budget and each-batch durable save.

Small sensitivity arms change one factor: growth 128 packets; refresh 250 ms;
consumer drain 16 versus 128 per channel. These vary write batching indirectly,
without introducing delayed-commit semantics or ACK/replay. Keep queue capacity
fixed; recommend a later queue change only if the measured loss/cost justifies it.

## Fixed workload and evidence

Linux and physical Android ARM64 use real UDP4 packets. Main A/B/C comparisons
run twice in alternating order, with fresh runtime generations and experiment
stores. Each campaign has idle (10 s), low rate (20 echo pairs spaced 100 ms),
burst (256 echo pairs without intentional pacing), sustained (1000 echo pairs paced 2 ms),
active-set (128 simultaneously retained sockets, 4 rounds), short-flow turnover
(128 socket lifetimes), and consumer pause (1024 new socket lifetimes while the consumer is parked).
Echoes use one in-flight packet to reduce the known Android network-loss confound;
the burst is not a maximum-rate capacity estimate. Short UDP socket lifetimes
are not asserted to immediately end Product Flow lifetimes.
A bounded representative Root and controlled VPN Android scope is sufficient;
record which arm ran in each profile instead of generalising Host results.
Network or harness failures remain retained HOLD evidence, with endpoint/payload
and capture boundaries distinguishing missing replies from observation loss.

Collect process/thread CPU ticks, RSS/HWM, voluntary/involuntary context switches,
I/O bytes, consumer waits, producer notifications and queue counters before/after
phases. These are scheduler/wake proxies, not electrical energy. Collect Android
battery/temperature/charging state as context; USB-connected short runs cannot
prove energy efficiency, Doze or sustained thermal behavior. Freshness uses
monotonic packet-send-to-query-visible time with polling interval reported;
UTC activity placement is checked independently against packets and minutes.

Store pressure uses explicitly labelled synthetic pre-existing valid store state
at increasing sizes, plus an actual failed-write boundary. Synthetic historical
baselines are not an implemented attribution/multilabel workload or a real upper
bound. New contributions still come from real packets through the full chain.
Measure copy/serialize/write cost, snapshot bytes, I/O amplification and startup.
Never delete active baselines, fabricate replay, or force history to basic totals.

## Interpretation and review

Deterministic Host calibration covers duplicate/stale/END/gap, failed-write and
minute conservation behavior before interpreting throughput. Raw data retain
source/artifact hashes, run generation/config/profile, packet identities, API
snapshots and cleanup. An independent verifier checks accounting, loss visibility,
source binding and negative evidence mutations. Independent Standards and Spec
review precede a scoped commit and Plane result/readback.

Report separately: usable for the measured next step; adjustment then remeasure;
or insufficient evidence with a bounded distinguishing next experiment. Correctness,
nonblocking and bounds cannot be traded for throughput. Full attribution, Blocked
Observation, multi-label, complete retention and the release storage budget remain
outside this implemented chain. Proposed parameters/storage choices await user
review; the experiment never silently selects a replacement engine.

## Calibration addendum, before formal comparison

The first Android C calibration retained a sender-side 150.59-second receive
duration during the 1024-socket paused-consumer phase. Its matching request/reply
were 3.80 ms apart in the device capture, so that application elapsed time cannot
be labelled packet-pipeline latency. The collector reached its 160-second phase
deadline. The exact cause of the post-ingress sender delay is not isolated.
Formal Android sustained/active/short/pause arms keep the diagnostic sender Activity
foreground; idle/low/short-burst arms return HOME and retain background evidence.
This controls an observed generator scheduling confound without changing Product
semantics. No Android background sustained-load/Doze claim follows.

The initial Linux collector read JSON one byte per select/read call. Its retained
A/B/C pilot exposes excessive collector duration and timer/expiry opportunities.
Formal collectors use buffered reads; pilot timings are not pooled with final
comparisons. All raw pilot outcomes and gaps remain evidence.
