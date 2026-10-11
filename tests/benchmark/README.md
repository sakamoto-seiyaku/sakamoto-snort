# Pixel 6a quick baseline

This is test traffic tooling, not a Product packet-domain implementation.
All main scores come from the actual Pixel 6a, serial `28201JEGR0XPAJ`.
The LAN peer's Linux numbers are only delivery and generator-headroom witnesses.

Each daily run has a **120-second global deadline**, including identity reads,
runtime starts, warmup, diagnostics, mode switches, normal teardown and JSON output.
The fixed measurement window is **5 seconds × 8 cells = 40 seconds**. No repeats,
rate sweeps, TLS, SNI or QUIC are included. Profiling is concurrent with the same
cells; pulling and rendering raw perf is a separate offline operation.

## One-time preparation

Use a unique output directory. Preparation builds C host/NDK helpers and uploads
only the test helper; it preserves the installed APK and rule source. It requires
an initially stopped runtime, existing KernelSU app authorization, existing
ordinary VPN consent, and a phone-reachable IPv4 LAN peer.

```sh
rtk proxy python3 tests/benchmark/pixel_quick.py prepare \
  --peer 192.168.4.5 --port 41020 \
  --output /tmp/pixel-baseline-prepared
rtk proxy /tmp/pixel-baseline-prepared/socket-load-host server 192.168.4.5 41020
```

Keep that peer running in its own terminal. TCP uses the selected port; UDP uses
that port through port+63. The phone helper sends actual sockets through Root
with the recorded app UID (KernelSU `su <uid>`, since `run-as` cannot execute
`/data/local/tmp` binaries), and through ordinary Product VPN with shell UID 2000.
The warmup requires a matching UID-attributed VPP FlowEntry at the real peer.
No controlled/validation VPN extras, worker resizing, flow-capacity changes or
rule writes are used. Android operations always use repo-local `./dev/adb`.

The manifest freezes APK/rule/helper identity, concurrency (4 I/O threads,
16 fixed TCP/UDP sockets or TCP-new window slots per thread), peer and profiling.
`--no-profile` is a distinct collection configuration; do not compare it with
profiled B0 as if the collection cost were identical. `--cell-ms 10000` is available
for an independently frozen configuration, but it must also pass the whole-run
deadline before becoming a baseline.

## Daily entry

```sh
rtk proxy python3 tests/benchmark/pixel_quick.py run \
  --manifest /tmp/pixel-baseline-prepared/manifest.json \
  --output build-output/pixel-quick-B0
```

It runs Root, then ordinary VPN. Each mode uses this fixed order:

1. Start normally; warm the actual LAN/trace path; TCP fixed multi-flow download.
2. UDP fixed multi-flow, 1200-byte datagrams sent as fast as possible.
3. TCP new: bounded concurrency, connect → 24-byte echo → close.
4. Stop normally and start a fresh lifetime; UDP new: new source-port/destination-
   port combinations, four 1200-byte datagrams per tuple, then close.

The two churn cases never share a full Flow table. The first lifetime contains
both fixed groups before TCP churn; initial occupancy is recorded and must stay
below 10% of capacity before each measured group. This avoids eight costly
whole-runtime restarts. After normal native teardown and VPP process exit, the
test app is force-stopped before the next lifetime, preventing delayed Android
Service callbacks from racing with the next start. Natural background VPN traffic remains part of the actual
device environment and is visible in the counters; initial occupancy is not
claimed to be literally zero. Each Root stop checks native zero debts and the
product's hook/queue residue audit. Any deadline, transport, identity or lifecycle
failure produces `INCOMPLETE`; cells are never shortened or omitted for a PASS.

Each cell retains client/peer JSON, sampled per-thread VPP CPU/RSS, actual runtime
generation/PID, before/after CLI counters and sampler logs. UDP loss uses received
unique packets rather than send success; duplicates are separate. UDP input tuple
counts differ from peer underlay tuples, especially through VPN. TCP completed CPS
differs from VPP Flow creates. Flow creates and capacity misses are counter deltas,
including any simultaneous background traffic. Endpoint delivery is not asserted
to be fully admitted policy-path goodput; Root unadmitted accepts, queue/lane facts,
Flow-capacity bypass and TUN counters must accompany interpretation.

Busy Root windows must show capture-counter progress in the same generation;
new-connection windows must show actual VPP Flow creation. Endpoint success with
no native progress is `INCOMPLETE`. The comparison also revalidates older raw
CLI records, so a historical `COMPLETE` label alone cannot qualify such a run.
These checks establish some native progress, not full policy-path coverage.

Fixed TCP latency uses separate persistent echo probes. UDP latency uses separate
echo probes; TCP-new latency includes connect through the matching response.
Histogram upper bounds have 100 µs resolution up to one second; p99 is `null` if
the selected percentile overflows. Timeouts, errors and deadline cancellations
remain separate from successful latency samples. The fast run describes trends,
not thermal steady state, formal p99 qualification or electrical energy.

## Offline graphs and comparisons

```sh
rtk proxy python3 tests/benchmark/report.py collect \
  --run build-output/pixel-quick-B0/result.json \
  --output build-output/pixel-quick-B0-graphs \
  --symfs /path/to/matching-binary-cache
rtk proxy python3 tests/benchmark/report.py compare \
  --runs build-output/pixel-quick-B0/result.json build-output/pixel-quick-B1/result.json \
  --output build-output/pixel-quick-comparison
```

Collection uses the SDK's offline Inferno renderer (`--skip_collection`) and the
phone helper's actual monotonic start/end to exclude setup/teardown samples. It
checks Pixel metadata and reports unknown symbols. Use a cache with matching ELF
build IDs; a cache from another APK is not a symbol identity proof. The comparison
rejects incomplete or over-budget runs and changed benchmark parameters. APK
identity may differ across optimizations; device, rules, helper, load and collection
parameters must stay fixed. It produces standalone HTML and machine-readable JSON.

## Tool correctness

```sh
rtk proxy python3 tests/benchmark/check_socket_load.py
rtk proxy python3 tests/benchmark/check_capture.py
```

These local loopback checks verify socket workloads, connection/tuple ledgers,
duplicate accounting and peer reset between repeated runs. Their rates are never
used as Android performance results. Peer sequence/tuple sets are bounded and
report overflow explicitly. Failed calibration artifacts should be retained in
their own directories, not relabeled or overwritten as B0.

For a separately frozen mechanism experiment, the helper accepts optional
`UDP_FIXED_SOURCE_PORT_BASE [UDP_FIXED_SOURCE_PORT_STRIDE]` after the existing
`udp-fixed` client arguments. It binds all data sockets and four thread probes
before connecting; an occupied port fails explicitly. Without these arguments,
the four original workloads retain their existing socket behavior. The stride
defaults to 1; stride 2 avoids synchronized source/destination port low bits
putting this controlled cohort on one canonical owner. Freeze the new helper
hash and actual owner distribution before comparison; these runs are distinct
from historical B0. See the [withdrawn admit/owner experiment](../../docs/testing/2026-10-11_PIXEL6A_VPP_ADMIT_OWNER_BATCH.md)
for the qualified fixed-tuple setup and failed effectiveness gate.

The socket helper accepts client windows up to 60 seconds and monitor windows
up to 61 seconds. Its bounded duplicate bitmap covers 2^27 sequence values and
still reports overflow explicitly. These limits support separately frozen longer
experiments; the daily quick runner retains its existing window choices and
120-second deadline. See the [30-second repeated comparison](../../docs/testing/2026-10-11_PIXEL6A_VPP_ADMIT_OWNER_LONG.md).
