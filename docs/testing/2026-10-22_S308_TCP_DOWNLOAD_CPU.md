# S308 single and four-flow TCP download CPU

2026-10-22, Pixel6a `28201JEGR0XPAJ`, SAKAMOTO-308.
The [frozen protocol](2026-10-22_S308_TCP_DOWNLOAD_PROTOCOL.md) was executed after
the [unified64 functional qualification and intermediate restoration](2026-10-22_S308_ADOPTED_UNIFIED_WINDOWS.md).
All eight unprofiled and four separate DWARF windows completed successfully.

**This run does not establish an equal-throughput whole-path CPU saving.**
The adopted package's lower unprofiled CPU occupancy coincided with lower
throughput; the rates varied materially across the ABBA windows. Single download
used approximately0.74–0.86 VPP CPU cores, and four downloads approximately1.00–1.30.
The profiles identify CPU work and show the old environment-parsing hotspot;
they are separate evidence from the unprofiled comparison.

## Frozen workload and artifacts

The Host continuously sends bulk data after each `D` request. Pixel successful
bulk `recv` bytes are delivery; this is TCP download, not echo traffic. There is
one receiver thread and exactly1 or4 persistent payload connections, with no
`E` probe connections or latency samples. Control queries and the live2s warmup
are outside each20s client window. A live Product TCP FlowEntry attributed to
UID2000 and the actual peer was required during warmup, followed by client join
before measurement. No attribution gate was relaxed.

N2: main CPU0, owners1/2, I/O3, receiver4. Both arms use the same rules,
MTU10000/MSS9940,2048 buffers with10240-byte data, VPP closure and frozen traffic
helper bytes. Single source31000 maps to owner0. Four sources31100–31103 map to
owners0,1,0,1; all target192.168.4.5:41723. Tuples were identical across arms.
The source ports were checked absent, including TIME_WAIT, before reuse; no
random port substitution occurred. Equal flow counts do not imply equal bytes
or CPU across the two owners.

| Arm | APK SHA-256 | Product plugin SHA-256 |
| --- | --- | --- |
| A: prior scalar capture1, credits32, packet-path getenv | `0c5764c9204b830c3b32c0a3a059ab2cf408105910124fc72f590e2b90110c35` | `99858b739d84aab6e462ccb328babf98032b95d669cf9e262bfe16992dca877d` |
| B: adopted native48/64/unified64 defaults | `fbb5cd3bf98ad2df0304572bbdcf564b485336f3f4e8cfb6b8f76a348169c1a2` | `798c1f42a5768a1c21db4e7c02bad466bb1b272aced4b71d042bfc75ea8e075d` |

Only the Product plugin differs in the native ZIP member sets/hashes. Embedded
stage properties are byte-identical. Matching unstripped plugins and common
VPP/system symbols were retained and checked against recorded build IDs.
Helper hashes, compiler commands and collector source snapshots are under
`build-output/s308-tcp-download-helper-20261022/`.
Final collector SHA-256:
`63881bc630f594da0d4c2252d1b7fcff4f9ae0d725f9569b4d24327402f1c531`.
Protocol revision2 SHA-256:
`929c072f072297805d0491e6dd39d1cb4bb35d788899f292b5238c3e5cafb2a6`.

## Eight unprofiled observations

CPU percentages below use raw task tick deltas over the monitor's exact observed
interval.100% is one occupied core, so totals can exceed100%. Main contributes
approximately0.00–0.11% and is included in VPP total. The receiver/generator is a
separate process and is not included in VPP CPU.

| Window | Download Mbps | VPP CPU% | Owner0% | Owner1% | I/O% | CPU coverage% | Estimated CPU s/GiB* |
| --- | --- | --- | --- | --- | --- | --- | --- |
| download1-A1 | 274.66 | 86.24 | 48.86 | 0.10 | 37.23 | 98.43 | 26.97 |
| download1-B2 | 229.21 | 74.00 | 40.61 | 0.00 | 33.34 | 98.34 | 27.73 |
| download1-B3 | 253.87 | 79.74 | 44.27 | 0.10 | 35.32 | 98.37 | 26.98 |
| download1-A4 | 231.64 | 74.01 | 41.27 | 0.10 | 32.53 | 98.37 | 27.44 |
| download4-A1 | 367.68 | 119.42 | 37.89 | 37.84 | 43.69 | 97.37 | 27.90 |
| download4-B2 | 320.30 | 99.89 | 31.62 | 29.99 | 38.28 | 98.34 | 26.79 |
| download4-B3 | 346.83 | 109.10 | 33.74 | 34.15 | 41.21 | 98.39 | 27.02 |
| download4-A4 | 479.72 | 129.98 | 48.30 | 32.10 | 49.47 | 98.43 | 23.27 |

\* The last column is the retained legacy stationary-load estimate: observed CPU
seconds multiplied by full client duration/observed duration, divided by full
client received GiB. It is not measured same-interval CPU/GiB. The200ms monitor
cadence trims the first/last samples: coverage is97.37–98.43%. Exact timestamps,
raw CPU seconds, bytes and the formula were independently recomputed in
`build-output/s308-tcp-download-review-20261022/numeric-audit.json`.

Single-flow normalized estimates overlap. Four-flow A's final observation is
both markedly faster and lower estimated cost/GiB than its first observation;
it is retained. These are two observations per arm/workload, not a statistical
optimum. Different actual rates prevent a strict equal-rate CPU-saving claim.

Per-core frequency residency was observed rather than fixed. The small-core
policy's enclosing before/after weighted frequency was approximately1.26–1.35GHz
across these windows; receiver-core residency also varied. Fixed-cadence thermal
and current-frequency observations are retained in `conditions-*.jsonl`.
Frequency, temperature, background work and wireless conditions are not fully
controlled. Their observations do not establish a cause for the rate changes
and do not measure energy.

Product RSS peaks were124792832–125366272 bytes (about119.0–119.6MiB).
Generator CPU/rusage and Host CPU have their own setup/cleanup/control brackets
and are retained separately. Host successful `send` bytes can exceed receiver
bytes because of buffering; that difference is not treated as packet loss.

### Admission, completion and graph evidence

All eight unprofiled windows had zero deltas for primary credit rejection,
primary enqueue rejection, owner failure, TUN runtime/policy drops, TUN errors,
capture rejection, allocation failure, write failure and completion deferred/
retry counters. Published primary packets equalled received packets, and native
stop settled all generations with zero buffers/frames/obligations/pending debt.
The B windows therefore provide no explicit credit48/ring-capacity rejection
evidence explaining their lower rates. No Wi-Fi-only or Product-regression
cause is inferred from throughput alone.

| Window | Captured/submitted/primary received | TUN writes | Completion returns |
| --- | --- | --- | --- |
| download1-A1 | 63954 | 83451 | 147405 |
| download1-B2 | 50954 | 69797 | 120751 |
| download1-B3 | 57253 | 77226 | 134479 |
| download1-A4 | 51947 | 70479 | 122426 |
| download4-A1 | 87551 | 114411 | 201962 |
| download4-B2 | 75061 | 101197 | 176258 |
| download4-B3 | 83313 | 108954 | 192267 |
| download4-A4 | 112702 | 147477 | 260179 |

These are before/after graph counters, with their own enclosing CLI bracket,
not wire TCP retransmission counts. Completed graph returns include originals
as well as independently produced returns; they are not TUN syscall counts.
TCP wire retransmission/loss was not independently measured.
Warm live-UID attribution is distinct from post-close metadata: one B four-flow
snapshot has an unknown-UID31101 entry containing one40-byte outbound packet.
The report does not claim known UID for every post-close entry.

## Four separate CPU profiles and flamegraphs

`cpu-clock`,199Hz, DWARF; the same1/4 download connection rules apply.
The following profiled observations are excluded from the eight-window
comparison and are not used as CPU-benefit estimates:

| Profile | Download Mbps | Observed VPP CPU% | Filtered samples |
| --- | --- | --- | --- |
| A single | 251.44 | 82.43 | 3265 |
| B single | 250.88 | 78.57 | 3107 |
| A four | 456.51 | 129.18 | 5229 |
| B four | 481.12 | 126.86 | 5145 |

The B four-flow profile reached481.12Mbps. This is not evidence that profiling
improves throughput; it demonstrates why the earlier320–347Mbps observations
must not be declared a fixed Product limit. About500Mbps remains the user's
wireless reference, not a proven bottleneck or Product ceiling.

Readable CPU charts and flamegraph index:
`build-output/s308-tcp-download-profile-analysis-20261022/index.html`.
There are16 actual per-thread flame SVGs and period-weighted folded stacks,
plus4 observed-thread-CPU charts. Each flame's width represents its thread's
sampled CPU periods, not that thread's percent of a core. The adjacent CPU chart
uses measured task ticks. Tiny idle-thread flames are not100% CPU occupancy.

All32 recorded userspace ELF identities across the four records match supplied
symbols and native strip bytes. Sixteen kernel/module/vDSO identity entries are
retained as device-recorded evidence, without independent kernel ELF matching.
The16746 filtered samples have no reported loss or stack truncation. Observed
leaves/chains resolve, but this does not prove complete unwinding through all
logical/coroutine callers or complete phase attribution.

In A, `getenv` accounts for6.1% of owner0 self periods and2.3% of I/O self periods
in the single-flow profile; four-flow owner0/owner1/I/O values are4.9/5.4/2.9%.
That symbol is absent from B's corresponding hot self-symbol lists. This agrees
with the source change removing repeated topology parsing; it is not a complete
whole-path saving calculation.

The B I/O `completion_write_free` call-chain family accounts for53.1%/65.8% of
that thread's sampled CPU periods in single/four-flow profiles. It includes
completion, write and reclamation work; it is neither pure TUN-write time nor a
whole-process fraction. B I/O admission/publication/wakeup maps to about7%.
Resolved hot leaves include kernel user copies, spinlock paths, TCP/netfilter,
checksums, VPP frame dequeue and memory moves. Kernel spinlock function samples
are CPU execution, not a measured waiting-time budget.

Phase mapping remains partial: B owner0's single-flow `other_unknown` phase is
56.4%; four-flow owner0/owner1 values are54.8/52.4%. These are classification
gaps despite resolved symbols. Full per-thread periods, observed chain depths,
unresolved diagnostics, kernel groups and all exact DSO IDs are in each
`attribution.json`, `dso-identities.json` and `summary.json`. No sampled time is
claimed as energy, off-CPU waiting or a complete CPU budget.

## Failed setup preservation, gates and restoration

Two earlier attempts contain zero timed cases and remain INCOMPLETE:

1. `build-output/s308-tcp-download-20261022/`: helper publication used a file
   where the collector expected a directory containing `socket-load`.
2. `build-output/s308-tcp-download-attempt2-20261022/`:250ms no-probe warmup
   delivered data, but its FlowEntry disappeared before the later UID snapshot.

The third attempt retains strict live UID/peer proof before warmup join and
executes the unchanged20s/fixed-tuple/ABBA plan. The protocol's earlier revision
and collector source identities are preserved. No successful measurement was
dropped to repair these setup failures.

Final local gates after the shared benchmark/tool changes: Host69/69, both
Android contract scripts,15 benchmark unit tests and the S307 tuning check all
passed. The exact frozen Host artifact was supplied via `PRODUCT_ARTIFACT_DIR`,
with builder stage environment unset. Product source identities stayed frozen;
no native rebuild was needed. Prior persistent-cache repeat proofs remain valid.
Result: `build-output/s308-final-closeout-gates-20261022/result.json`.

All12 windows stopped cleanly. Owned samplers and the command-verified Host peer
exited. Final original APK, exact rules, saved `CU_7WFb_5G`, stopped runtime,
absent VPP/runtime-service/NFQUEUE/helpers/profilers and gone Host endpoint were
verified in `build-output/s308-tcp-download-final-restoration-20261022/result.json`.

Raw campaign: `build-output/s308-tcp-download-attempt3-20261022/campaign.json`.
Raw data, APKs, symbols, charts and flamegraphs are preserved locally under
gitignored `build-output`, not packaged as a portable archive. The committed
protocol/report/tests retain exact identities and evidence paths. S293 remains
open; this report creates no new adoption threshold or follow-on task chain.
