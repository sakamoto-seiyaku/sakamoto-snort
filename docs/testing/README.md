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
| Ordered ordinary DNS resolvers and local exceptions (2026-10-29): VPP persistence/8–8–32 bounds, candidate cache/demand recovery/effective RCODEs/view fences; scoped Root/VPN N1/N3 client transport/family matrix, advertised LAN resolver and mDNS; 246 whole case records in MAIN727, original APK/all4861 restored at fresh BOTH2922; independent review/delivery separately linked | [S321 scoped qualification record](2026-10-29_S321_ORDERED_DNS_ROUTING.md) |
| Authenticated DoT and original-network service address discovery (2026-10-31): TLS 1.2 chain/SAN identity, ABI5 observation v10, bounded TLS memory; owner-budget-slot fix for a trust-anchor cache use-after-free; Root N1 full matrix 17 cases/76 whole records, Root and VPN N1 bootstrap, Stop during handshake; original APK/all4861 restored at fresh BOTH2947 | [S322 scoped qualification record](2026-10-29_S322_DOT_BOOTSTRAP.md) |
| Simultaneous DNS data sharing with independent policy/delivery (2026-10-27; reviewed 2026-10-29): current R4 Root/VPN N1/N3 four-entry matrix, 65/129 capacity, pending Stop/late/restart,52 scoped groups/1448 whole target records in MAIN1844; original APK/all4861 restored at fresh BOTH2904, independent Standards/Spec and behavior/recovery checks passed; older policy/cancel/view artifacts and original HOLDs kept separate | [S320 scoped qualification record](2026-10-27_S320_DNS_COALESCING.md) |
| Shared valid DNS answer data cache (2026-10-27):393 scoped groups/5643 whole records, current policy/view/TTL/SOA, conservative names/compression, actual512-entry/2MiB bounds and natural4096 history; bounded shutdown-prefix and real allocator-failure history regressions, original APK/all4861 restored at fresh BOTH2867; retained failures and separate artifact scopes | [S319 scoped qualification record](2026-10-27_S319_DNS_ANSWER_CACHE.md) |
| VPN client TCP DNS replacement (2026-10-26): bounded local HEV before Direct, current per-message policy, same-session OFF/ON; R4/R5 78 groups/583 whole records and scoped R6 progress/Stop/N3 19 groups/92 whole records in separate MAIN301; original APK/all4861 restored at fresh BOTH2809, raw HOLDs retained | [S318 implementation and qualification](2026-10-26_S318_VPN_TCP_DNS_REPLACEMENT.md) |
| Root TCP DNS replacement (2026-10-25): bounded transparent client TCP53, per-message QName/CNAME policy, N1/N3 dual-stack pipeline, client UDP-TC→TCP, capacity and late/Stop;70 composed R3 groups/654 required whole plus8 original-path records; original APK/all4861 restored at BOTH2778, retained failures and scoped Host/VPN limits | [S317 implementation and qualification](2026-10-25_S317_ROOT_TCP_DNS_REPLACEMENT.md) |
| Root UDP DNS replacement (2026-10-24): explicit ordinary upstream, current policy, TC/TCP and bounded cancellation/capacity;35 composed N1/N3 groups with independent normal SQLite/native-zero; original APK/all4861 members restored at BOTH2727. Failed full attempts, unexplained earlier peer loss and stop-history gaps remain explicit | [S315 implementation and scoped qualification](2026-10-24_S315_ROOT_UDP_DNS_REPLACEMENT.md) |
| VPN TCP DNS (2026-10-23): shared original Direct framing, exact session/epoch return lineage, normal SQLite and 104 current R5 groups across both modes/transports/families at N1/N3; original APK/all4861 data members restored with both generations2695. Seven completed public attempts, one public transport limit and Root active-socket scope remain explicit, with R4/R3 retained separately | [S314 implementation and qualification](2026-10-23_S314_VPN_TCP_DNS.md) |
| Root TCP DNS (2026-10-23): bounded split/coalesced/pipelined framing, original-path QName/CNAME policy, per-message normal SQLite, N1/N3 dual-stack wire, native-zero stop and full original-state restoration; R2/R3 artifact scopes remain explicit | [S313 implementation and qualification](2026-10-23_S313_ROOT_TCP_DNS.md) |
| UDP DNS replies (2026-10-22): Root/VPN tuple/session/context correlation, complete per-name CNAME Rank policy, original wire and normal SQLite error/answer records; artifact identities and controlled-device scope remain explicit | [S312 implementation and qualification record](2026-10-22_S312_UDP_DNS_RESPONSES.md) |
| VPN original-path UDP DNS (2026-10-22): normal Pixel N1/N3 dual-stack LAN/public-destination query policy, 42 ordinary messages plus system-UID fixtures and actual Android resolver Unknown-query evidence; normal SQLite observations, protected Direct, same-artifact native-zero stops and original device restoration. Cold public/system timeouts and an isolated supplemental transport failure remain explicit | [S311 implementation and scoped qualification](2026-10-22_S311_VPN_UDP_DNS.md) |
| Root original-path UDP DNS (2026-10-22): controlled Pixel N1/N3 dual-stack 22 ordinary App queries plus two known system-UID fixtures on the same APK; whole-rule decisions, unchanged allowed wire/resolver, normal SQLite observations, bounded resources, clean stops and original device restoration. VPN/TCP/replacement/association/netd IPC remain later work | [S310 implementation and scoped qualification](2026-10-22_S310_ROOT_UDP_DNS.md) |
| Current APK multiflow at unchanged post-toggle conditions (2026-10-22): N1/default65528/48/64 and1.803 GHz, 4D0E479.31/461.85 Mbps with all target gates passing; 64D0E440.52/469.51 Mbps are diagnostics because final target UID gates fail despite64 data streams and zero client errors/timeouts. No further network action; original nonnetwork state restored/Openwrt retained | [Current multiflow rates, CPU and failed gates](2026-10-22_CURRENT_MULTIFLOW_MAXFREQ.md) |
| Current APK single flow before/after a requested Wi-Fi toggle (2026-10-22): same N1/default65528/48/64 profile at1.803 GHz, four20s downloads303.62/335.54 then257.50/300.00 Mbps, all complete with zero client errors/timeouts and recorded native rejection/drop/write-failure counters0. High PHY rates and radio reconnect did not restore500 Mbps in these repeats; full nonnetwork restoration/Openwrt retained | [Current single-flow results, CPU and toggle evidence](2026-10-22_POSTWIFI_CURRENT_SINGLE.md) |
| Post-reconnect historical single-flow check (2026-10-22): verified 1.803 GHz, pre-test Tx/Rx1814/2161 and1814/2401 Mbps; two old N2/32 KiB downloads306.74/333.05 Mbps (mean319.89) pass strict gates. Conditional latest-APK stage not run because the frozen approximately500 Mbps trigger was not met; original nonnetwork state restored and Openwrt_5G retained | [Single-flow results and conditional decision](2026-10-22_POSTWIFI_SINGLE_OLD_AND_CURRENT.md) |
| Historical VPN concurrency and Wi-Fi reconnect (2026-10-22): old N2/32 KiB configuration at 1.803 GHz gives collector-complete 4/64-flow endpoints348.63/453.57 Mbps; second repeats fail strict gates. After requested radio reconnect, four-flow endpoints541.53 Mbps (probe UID gate failed) and494.62 Mbps (collector complete), with pre-test negotiated Tx/Rx1921/2401 and2161/2161 Mbps. Original nonnetwork state restored; Openwrt_5G retained | [All windows, PHY rates and qualification limits](2026-10-22_OLD_500_MULTIFLOW_MAXFREQ.md) |
| Historical 500 Mbps reproduction at fixed frequency (2026-10-22): exact retained N2/32 KiB APK/configuration, verified little-cluster 1.803 GHz, two unprofiled 20s single downloads deliver 313.86/303.05 Mbps; prior 496.62/535.54 Mbps not reproduced. Original device state restored after a retained SELinux-label restoration failure and repair | [Replay conditions, results and restoration](2026-10-22_OLD_500_MAXFREQ_REPRODUCTION.md) |
| N1 maximum-frequency little-core baseline (2026-10-22): current 65,528-byte profile, main/owner/I/O/receiver on CPU0/1/2/3, three unprofiled 20s downloads at verified 1.803 GHz give 306.9–316.5 Mbps and VPP 53.9–55.8% of one core; zero recorded Product rejects/drops/write failures, clean stops and original device settings restored | [Baseline, frequency and affinity evidence](2026-10-22_TCP_SINGLE_LITTLE_MAXFREQ_BASELINE.md) |
| User-selected TCP send capacity (2026-10-22): default 65,528-byte HEV ring/sndbuf, explicit 32,768-byte override; 54 real transport checks, Host/Android/APK cache and stale-stage packaging checks pass. No new device or performance campaign | [Default implementation and local verification](2026-10-22_TCP_SEND64_DEFAULT.md) |
| Historical approximately 500 Mbps conditions (2026-10-22 investigation of October 21 records): ordinary dynamic-frequency, little-core N2/TUN-owner0, 32 KiB, one download plus one probe; separate frequency interventions, native controls and current N1 differences | [Complete conditions and original evidence](2026-10-22_PREVIOUS_500MBPS_CONDITIONS.md) |
| ADR-0012 Product function (2026-10-22): controlled Pixel Root/VPN `N=1` and `N=3`, dedicated VPN I/O, original-buffer completion, bounded faults, fragments, ordinary protection and clean stop; release and performance remain separate | [S303 Android qualification](2026-10-22_S303_ANDROID_CONFIGURABLE_TOPOLOGY.md) |
| ADR-0012 VPN performance (2026-10-22): matched N=2 old local-owner/new dedicated-I/O A/B/B/A windows show similar measured throughput with higher new VPP CPU cost and paced-UDP loss; N=1/N=3 are separate observations. No adoption or rollback threshold selected | [S304 Product comparison and raw evidence](2026-10-22_S304_VPN_IO_PERFORMANCE.md) |
| Dedicated VPN TUN I/O worker feasibility (2026-10-21): pinned Host VPP `N=1` and prototype-only duplicate-CPU `N=3` runs preserve a VPP buffer index through I/O→owner→I/O and return identical bytes. The duplicate-CPU run needs a throwaway `libvlib` relink; no Product or Android qualification | [Bounded prototype and artifacts](2026-10-21_VPN_TUN_IO_WORKER_PROTOTYPE.md) |
| Ordinary VPN long TCP download (2026-10-21): MTU10000 now defaultsON with a2048-buffer software pool on ordinary4KiB pages. Same-pool20s TCP ABBA gives endpoint206.58→521.51Mbps, CPU/GiB−45.01%, TUN writes/GiB−65.22%, return-credit rejection40→0; separate default-profile window519.32Mbps. Earlier3000/readiness/64KiB-buffer experiments and allocation failures retained. Other TCP optimizations remain opt-in; original APK/rules/Stopped restored, Wi-Fi retained | [Large segments, readiness and buffering](2026-10-21_VPN_LONG_TCP_SEGMENTS_AND_PROGRESS.md) |
| VPN progression diagnosis (2026-10-21): three separate20s ABBA contrasts distinguish primary credit from queue slots, capture pacing and client CPU placement. Smaller capture reduces CPU with lower throughput; credit32→48 gives+4.01%Mbps/+3.55%CPU/GiB. Defaults retained. Twelve on-CPU profiles lost0; independent off-CPU window has1738 lost and only partial attribution. Thirteen native stops and device/peer cleanup audited | [Owner progression, credit pressure and off-CPU limits](2026-10-21_VPN_LONG_TCP_SEGMENTS_AND_PROGRESS.md) |
| Single-flow VPN diagnosis (2026-10-21): native controls expose a gap hidden by64-flow aggregate. At138Mbps,99.6% of TUN-path preemptions switch to the measured receiver TID. Keeping VPP onCPU1,2 and moving only receiver toCPU3 restores503/505Mbps; ordinary default APK repeats497/536Mbps versus252/265 unbound, native507Mbps. Exact151.77Mbps packet timeline, negative64KiB counterfactual, DVFS limits and18-window restoration audit retained | [TUN write preemption and receiver placement](2026-10-21_VPN_LONG_TCP_SEGMENTS_AND_PROGRESS.md#定位130160-mbps单流瓶颈tun写入期间被接收线程抢占) |
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
