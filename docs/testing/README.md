# Testing and evidence

The current product is VPP-native C with Rust control and Java supervision.
The former C++ daemon/model suite was removed by ADR-0008.

## Current acceptance entry

Start with the [2026-09-13 foundation joint report](2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md):
`PASS_WITH_EXPLICIT_LIMITS`, with independent Linux Root / Pixel Root / controlled
VPN checks, source-bound artifacts, 64 Pixel generations and retained failures.
This is not a release gate or ordinary-user VPN protection claim.

The independent checker can re-evaluate retained raw evidence without operating
a device. Write the new report separately from frozen evidence:

```sh
python3 tests/evidence/verify_foundation_joint.py \
  --input build-output/foundation-joint-20260913/acceptance-input.json \
  --output build-output/host-tests/foundation-recheck.json
```

Local raw files and matching build witnesses are required. A missing file is not
a passing or skipped acceptance branch. See [test layout](../../tests/README.md)
and [build commands](../tooling/README.md) for Host checks.

## Focused evidence

| Scope | Record |
| --- | --- |
| Ordinary VPN long TCP download (2026-10-21): three TCP-only20s ABBA campaigns. Large segments give endpoint102.32→206.35Mbps/CPU per GiB−47.70%; readiness gating saves another5.63% CPU with similar throughput. 65528-byte buffering gives205.58→218.13Mbps but increases return-credit rejection39→1620. Common1517-buffer pool, all candidates defaultOFF; initial allocation failure retained, original APK/rules/Stopped restored, Wi-Fi retained | [Large segments, readiness and buffering](2026-10-21_VPN_LONG_TCP_SEGMENTS_AND_PROGRESS.md) |
| Ordinary VPN fixed TCP batch (2026-10-21): four TCP-only ABBA windows; readv/GiB−62.03%, receive rounds/GiB−52.97%, VPP CPU/GiB−6.17%; endpoint means110.44→103.48Mbps, no throughput benefit established. Same MTU/MSS/capacity, candidate defaultsOFF; original APK/rules/Stopped restored, Wi-Fi retained; two premeasurement ADB failures preserved | [TCP batch implementation and evidence](2026-10-21_VPN_FIXED_TCP_BATCH.md) |
| Ordinary VPN baseline and UDP ready-send candidate (2026-10-21): current installed APK baseline with exact symbols; separate four-lifetime ABBA completes16 windows, UDP endpoint means237.23→357.22Mbps and estimated VPP CPU/delivered GiB−33.81%. Admission/loss and sparse p99 remain; TCP-new no-regression unproved. Candidate defaultsOFF, original APK/rules/Stopped restored, Wi-Fi kept at user's request; aborted two-lifetime attempt retained | [VPN baseline and all experiment outcomes](2026-10-21_ORDINARY_VPN_BASELINE_AND_UDP_SEND.md) |
| Product compilation cache (2026-10-21): Android/Host native repeat builds perform zero compilation; APK Java/DEX reuse and input invalidation checked. Artifact deduplication and 1,607 obsolete C++ object removals release 18.81 GiB; 969 artifact/evidence paths and hashes retained. Audited `/tmp` duplicate groups cleared; source/build-input exclusions recorded. No new device/performance acceptance | [Cache and storage verification](2026-10-21_BUILD_CACHE_AND_STORAGE.md) |
| User-selected Root composite defaults (2026-10-13): 128 receive/pending slots, 48 credits, 16-read budget, 1 MiB socket request (Pixel 2 MiB effective), maxlen 4096 and default batch+packed installed. Mixed ALLOW/DROP and 8k startup check pass; 16k delivers all payload but retains 4 primary rejections. Production queue placement retained; ordinary VPN 6000/6000 and 32 credits verified, stopped native-zero log unassessed. Original rules restored, new APK retained, Stopped | [Defaults, regression and evidence limits](2026-10-13_ROOT_COMPOSITE_DEFAULTS.md) |
| Root NFQUEUE capacity/service/placement diagnostic (2026-10-13):37 frozen six-second windows and exact CPU flamegraphs retained; one expanded composite16k UDP window fully supported (actual15.87kpps/152.32Mbps), no whole-path CPU benefit established;32k/64k and TCP unqualified; nominal TCP dual-lane windows actually single-lane. Original APK/config/Stopped restored | [Results and all qualifications](2026-10-13_ROOT_NFQUEUE_CAPACITY_TUNING.md) |
| Current batch+packed TCP/UDP Pixel baseline (2026-10-13):14 traffic windows+1 failed start retained. TCP download305–444Mbps / UDP upload537–554Mbps endpoints include bypass; fully supported highest tested UDP point8000pps/76.74Mbps,16k begins direct ACCEPT/reordering. Kernel CPU samples83.41% TCP /77.25% UDP, exact14 flamegraphs/function tables; original APK/config/Stopped restored | [Actual baseline, CPU and limits](2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#当前tcp与udp吞吐基线--2026-10-13) |
| L4 match-evidence reuse (2026-10-13):4864 Host equivalence inputs, Android OFF/ON and ARM64 checks; now physically installed before/after onPixel, both256 ALLOW/256 DROP tests pass, all60000 payload packets delivered across six AB/BA/AB windows. Match-record profile2.15%→1.22%; no whole-path CPU benefit established (all-window descriptive CPU/Q +4.82%, one kernel snapshot unassessed, no retries); original APK/config/Stopped restored | [Implementation](2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#匹配证据计算复用--2026-10-13) · [Real-device evidence](2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#匹配证据真机前后对照--2026-10-13) |
| Root portable I/O attempt (2026-10-13): 7 traffic windows then owner-live start failure; all delivery guards failed, remaining traffic/idle/pressure unexecuted; no adoption result, original APK/config/Stopped restored. Previous whole-path batch: completion-slot fix verified; nine new windows retained, fixed packed CPU/Q −8.69% vs scalar; final p99 25.2 vs15.7 ms (+9.5 ms); user confirmed this latency scale does not block packed progress; original protocol failures and snapshot limit retained, device restored; prior twelve windows preserved | [Whole-path experiment record](2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md) |
| User-confirmed B0 (2026-10-11): Pixel 6a Root/ordinary VPN eight-cell quick baseline, 105.9-second run and exact-window CPU flamegraphs | [B0 and hotspots](2026-10-09_PIXEL6A_QUICK_BASELINE_AND_HOTSPOTS.md) |
| Pixel 6a batching experiment, withdrawn (2026-10-11): per-step results retained; separate Root recovery correction retained; rollback verification and VPP mechanism audit | [Incremental batch results](2026-10-11_PIXEL6A_INCREMENTAL_BATCH.md) |
| VPP admit/owner bulk experiment, withdrawn (2026-10-11): actual frames and queue publications verified; local VPN node improvement, overall CPU gate failed; ordinary rollback checked | [VPP mechanism experiment](2026-10-11_PIXEL6A_VPP_ADMIT_OWNER_BATCH.md) |
| VPP admit/owner 30-second repeats (2026-10-11): two reversed pairs per profile, delivery and CPU/GiB re-evaluation; inconsistent gains and observed time drift | [Longer throughput repeats](2026-10-11_PIXEL6A_VPP_ADMIT_OWNER_LONG.md) |
| Combined rule/protocol/observation CPU, memory, wakeup and storage calibration | [T30](2026-09-27_T30_COMBINED_COST_RESULTS.md) |
| Combined Root/VPN protocol, CT, rule publication, observation stress and debug writer regression | [T29](2026-09-27_T29_COMBINED_RESULTS.md) |
| Directional Flow effects and query freshness | [T23](2026-09-27_T23_DIRECTIONAL_ATTRIBUTION_RESULTS.md) |
| Pre-Flow Blocked observations and independent windows | [T24](2026-09-27_T24_BLOCKED_OBSERVATION_RESULTS.md) |
| L4 and multi-label L7 protocol windows, Root/VPN and R1–R4 integration | [T25](2026-09-27_T25_PROTOCOL_WINDOWS_RESULTS.md) |
| Recent rule identity, names, actions and counts across edit/delete/restart | [T26](2026-09-27_T26_RECENT_RULE_HISTORY_RESULTS.md) |
| Bounded observation retention across minute/hour/day tiers and restarts | [T27](2026-09-27_T27_OBSERVATION_RETENTION_RESULTS.md) |
| Live Flow pages and separate runtime, VPP, producer and consumer health | [T28](2026-09-27_T28_DASHBOARD_RESULTS.md) |
| SQLite observation migration, bounded live batching and matched Host/Pixel costs | [E02](2026-09-26_E02_SQLITE_RESULTS.md) |
| TLS/QUIC exact and descendant domain lists, real packet winners and bounded matcher | [T18](2026-09-26_T18_DOMAIN_LISTS.md) |
| Ordinary network-disable rules, scoped switches and shared observe behavior | [T05](2026-09-25_T05_NETWORK_DISABLE.md) |
| Bounded static Boolean conditions and field availability | [T06](2026-09-25_T06_STATIC_EXPRESSIONS.md) |
| Published protocol sets, NOT/availability, bounded LPI and complete-cache integration | [T12](2026-09-25_T12_PUBLISHED_PROTOCOL_FACTS.md) |
| Proxy/VPN/remote-access recognition, actual rules and bounded state | [R3](2026-09-25_R3_PROXY_VPN_RECOGNITION.md) |
| CT state/direction, conservative placement and real TCP/UDP rule changes | [T07](2026-09-25_T07_CT_EXPRESSIONS.md) |
| Startup compilation failure, online management repair and policy-before-capture lifecycle | [T03](2026-09-25_T03_STARTUP_REPAIR.md) |
| Complete VPP-owned direct rules, versions, failures and Root/VPN source lifecycle | [T02](2026-09-25_T02_COMPLETE_RULE_CONFIGURATION.md) |
| Protocol expiry and deferred real 24-hour TCP test | [S236](2026-09-13_S236_PROTOCOL_EXPIRY.md) |
| Linux network classification and projection limits | [S235](2026-09-13_S235_LINUX_NETWORK_SNAPSHOT.md) |
| Canonical owner versus CPU placement | [S220](2026-09-13_S220_WORKER_CPU_PLACEMENT.md) |
| FlowRuntime and protocol trackers | [S221](2026-09-11_S221_FLOW_RUNTIME.md), [TCP](2026-09-12_S222_TCP_TRACKER.md), [UDP](2026-09-11_S223_UDP_TRACKER.md), [ICMP](2026-09-13_S224_ICMP_TRACKER.md) |
| Independent bounded reassembly | [S229](2026-09-11_S229_INDEPENDENT_REASSEMBLY.md) |
| Artifact/source/raw witness chain | [S244](SAKAMOTO_244_EVIDENCE_CHAIN.md) |

The dated foundation report records HEV 36/36 and root CTest 35/40 at that time.
Later test maintenance does not rewrite those observations; see the
[repository organization record](../maintenance/2026-09-13_REPOSITORY_ORGANIZATION.md)
for obsolete contract replacement and its separate regression result.

## Earlier baselines and history

[Product Spine acceptance](SAKAMOTO_171_172_DEVICE_ACCEPTANCE.md), installed through
the debug APK, established the first combined S171/S172 seam.
[Host-only supporting evidence](SAKAMOTO_171_HOST_EVIDENCE.md) is not equivalent
to that Product Spine acceptance or the ADR-0007 Flow Stack.
The [S195 recovery dossier](SAKAMOTO_195_RECOVERY_ACCEPTANCE_DOSSIER.md) retains the
S176–S196 baseline and its limits.

Older unnumbered DX/IP casebooks and surveys may describe the removed daemon.
Use them as dated history, not commands to run. Their isolated scripts are in
[the test archive](../../tests/archive/README.md). Do not import C++ or POC code.
Current numbered collectors and verifier dependencies keep their original paths;
not every older filename is obsolete. Open work and deferred gates live in Plane.
