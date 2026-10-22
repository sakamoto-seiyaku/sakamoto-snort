# S308 fixed TCP download CPU protocol

Frozen before the first measurement window, following the user's additional
single-flow/multi-flow CPU and flamegraph request. This is a separate phase from
the [completed unified64 functional qualification](2026-10-22_S308_ADOPTED_UNIFIED_WINDOWS.md).
No result changes the preselected workload, order or parameters below.

## Direction and identities

The existing `tcp-fixed` transport sends one24-byte `D` request per connection;
the Host then continuously sends bulk data and the Pixel receiver counts
successful `recv` bytes. This is server-to-Pixel download. Optional `E` echo
latency connections are explicitly disabled through `tcp_latency_probes=false`.
Client and server must report exactly the requested bulk connection count,
zero probe connections and zero latency samples. Separate `Q`/`R` control
connections and short warmup occur outside the timed download window.

| Identity | Frozen value |
| --- | --- |
| A: prior scalar/getenv APK | `0c5764c9204b830c3b32c0a3a059ab2cf408105910124fc72f590e2b90110c35` |
| A: Product plugin | `99858b739d84aab6e462ccb328babf98032b95d669cf9e262bfe16992dca877d` |
| B: adopted unified64 APK | `fbb5cd3bf98ad2df0304572bbdcf564b485336f3f4e8cfb6b8f76a348169c1a2` |
| B: Product plugin | `798c1f42a5768a1c21db4e7c02bad466bb1b272aced4b71d042bfc75ea8e075d` |
| Common ARM64 traffic helper | `075e780dd4c5aa1de34d654ef8ec7cd698399c2112638662e5f4913b2ba53015` |
| Common Host traffic helper | `1debf988c55135151e2e0f4dc6783ee43149e54bc435ae7aa964c639ea32ce95` |
| Collector | `63881bc630f594da0d4c2252d1b7fcff4f9ae0d725f9569b4d24327402f1c531` |

The APK native ZIP member sets and hashes were compared: the Product plugin is
the only differing native member. VPP/native closure and embedded stage settings
are checked again in the retained protocol manifest. A explicitly requests
capture1 and primary credits32. B omits those overrides to test native48/64
defaults. Both use unchanged TCP-experiment-OFF builds, MTU10000/MSS9940,
buffer data10240 and exactly2048 native buffers.

Helpers, compile commands, loopback1/4 plus legacy regression results and preserved
old/new collector identities:
`build-output/s308-tcp-download-helper-20261022/`.
Historical CPU schemas remain compatible; all56 retained S307 CPU/score rows
recompute exactly. New interval metadata is opt-in and independently checked.

## Fixed workloads and sequence

Pixel6a `28201JEGR0XPAJ`; saved controlled `Openwrt_5G`; Host192.168.4.5:41723.
N2 topology: main CPU0, owner CPUs1/2, dedicated I/O CPU3, receiver affinity CPU4
(`10` hexadecimal mask). Original rules SHA-256 remains
`2b24ea2630d231e9f52f014aa8a64ae1ba593d1f1371389f05c92b97517a450f`.

One receiving thread uses either one or four persistent bulk connections. Four
is selected upfront as twice the owner count, without a connection-count scan.

| Workload | Source ports on TUN10.111.0.2 | Canonical owners expected from existing selector oracle |
| --- | --- | --- |
| Single download | 31000 | 0 |
| Four downloads | 31100,31101,31102,31103 | 0,1,0,1 |

Every connection targets the same192.168.4.5:41723 endpoint. Source stride1 and
the exact tuples remain fixed across both artifacts and repeated windows.
Observed Product flow/owner evidence is retained; no owner/hash is changed.
Before each reuse, inspect Pixel TCP/TCP6 tables until the selected source ports
are absent, including TIME_WAIT. Wait evidence and elapsed time are retained;
a bounded120s setup deadline fails the attempt instead of substituting ports.

Each timed client window is20s, with a fresh Product generation. Strict no-probe
preparation uses a separate2s warm download with the same1/4 bulk connections,
zero E probes and ephemeral ports. While those sockets are alive, retain a
Product TCP FlowEntry attributed to the actual UID2000 and peer; the warm client
must still be alive before and after that snapshot. Join it before any timed CPU
window. This preserves strict attribution after disabling probes: the earlier
250ms warm client closed before its FlowEntry snapshot, leaving only an
unattributed tail RST. The two zero-case setup attempts remain retained; neither
is a valid20s measurement. Legacy probe-enabled warmup remains unchanged.
Preselected order:

1. Single download, unprofiled: A1,B1,B2,A2.
2. Four downloads, unprofiled: A1,B1,B2,A2.
3. Separate CPU profiles: A-single,B-single,A-four,B-four.

This is exactly eight unprofiled and four profiled windows. Every failed attempt
is retained and identified; retries repair concrete setup/tool failures without
silently discarding successful observations or tuning workloads from results.

## CPU, throughput and profile interpretation

The delivery denominator is Pixel bulk `recv` bytes. Host successful `send`
bytes can include buffered data and are not a delivery substitute. Throughput
uses the client's recorded monotonic begin/end interval.

Product VPP CPU is the sum of its recorded task CPU deltas. Main, each owner,
I/O and other Product threads are also reported separately.100% means one fully
occupied CPU core; a process/thread sum can exceed100%. Receiver/generator CPU
is separate and includes its main/worker setup and cleanup bracket. Host CPU
has its own enclosing control-query interval.

The external monitor's first/last samples inside the client window cover a
shorter interval, normally trimmed by its200ms cadence. Report its exact begin,
end and coverage; thread CPU% uses that observed interval. Raw observed CPU
seconds and full-window receiver GiB are different intervals and must not be
presented as an exact same-interval CPU/GiB measurement. The legacy full-window
CPU extrapolation may be shown only as an explicitly labelled stationary-load
estimate, with coverage; it is not measured full-window CPU. Preserve both raw
and estimated fields rather than replacing historical formulas silently.

Retain per-core frequency residency in the collector's enclosing before/after
bracket, plus fixed-cadence current-frequency/thermal snapshots. These describe
frequency/temperature conditions, not per-thread cycles or energy. Background
traffic, wireless conditions, thermal management and frequency are not fully
controlled. Pairing/order reduces drift exposure but does not remove it.

Profile windows use `cpu-clock`,199Hz and DWARF call graphs. Their overhead and
throughput are separate from the unprofiled A/B comparison. Every relevant
plugin/VPP/libc/linker DSO is matched by recorded build ID and exact symbols;
report sample/period coverage, unresolved leaves/chains and the recorded time
span. Produce per-owner and I/O flamegraphs, keeping main/other costs visible.
Samples describe sampled CPU execution, not waiting, energy or a complete CPU
budget. No off-CPU inference is made from these profiles.

Approximately500Mbit/s is the user's observed Wi-Fi reference, not a demonstrated
Product limit. Compare measured CPU occupancy/cost alongside actual throughput.
If A/B rates differ, report that difference and do not claim a strict equal-rate
CPU saving. Eight windows support descriptive evidence, not a statistical optimum
or an invented adoption threshold. Memory, retries/rejections, generation and
zero-debt stop remain part of every window's evidence.

## Preservation and restoration

Before the first window, retain this protocol's SHA-256, exact plan/manifests,
native closure comparison and helper/collector identities in
`build-output/s308-tcp-download-protocol-20261022/`. Product source/native/APK
identities remain frozen. Profile symfs trees are separate for A/B plugins;
unchanged DSOs may be reused only after identity checks.

Use only repository `./dev/adb`; one device operator; KernelSU grants handled
before treating authorization errors as Product failures. Stop owned endpoints
and samplers. Finally restore the original APK, exact rules, saved
`CU_7WFb_5G`, stopped runtime and no VPP/NFQUEUE/helper/profiler state. S308 stays
In Progress until the new combined acceptance and reviews finish; S293 stays open.
