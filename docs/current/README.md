# Current mainline

Baseline: 2026-10-25. This short implementation entry is not a release announcement; current task state belongs to Plane.

Accepted 2026-09-24: [ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md) and the
[unified rule specification](../product/UNIFIED_RULE_ENGINE_SPEC.md) define
policy/configuration/observation behavior; they do not extend implementation claims.

Accepted 2026-10-07: [ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md) defines shared Root/VPN application DNS query and subsequent-connection control.
[S310 Root](../testing/2026-10-22_S310_ROOT_UDP_DNS.md) and [S311 VPN](../testing/2026-10-22_S311_VPN_UDP_DNS.md) qualify controlled original-path UDP53 query filtering and normal observations.
[S312](../testing/2026-10-22_S312_UDP_DNS_RESPONSES.md) adds bounded UDP reply correlation, connected CNAME rules and normal reply observations; its report keeps artifact and device qualification scopes explicit.
[S313](../testing/2026-10-23_S313_ROOT_TCP_DNS.md) adds bounded Root TCP DNS framing and QName/CNAME policy; its R2/R3 artifact qualifications remain separate.
[S314](../testing/2026-10-23_S314_VPN_TCP_DNS.md) connects VPN Direct TCP to the shared core and qualifies 104 current R5 groups across Root/VPN, UDP/TCP, IPv4/IPv6 and N1/N3, with normal SQLite and clean stops. Root active-socket capture and one incomplete public attempt remain explicit limits. Its scope excludes replacement, association consumption and KSU/libnetd integration.
[S315](../testing/2026-10-24_S315_ROOT_UDP_DNS_REPLACEMENT.md) adds explicitly configured Root UDP53 replacement with ordinary dual-stack upstreams, same-resolver TC→TCP, current query/response policy and bounded resources. Its 35 composed N1/N3 groups have independent normal SQLite and native-zero cleanup; failed attempts, unexplained earlier peer loss and bounded stop-history gaps remain explicit. Original APK/all4861 members are restored with BOTH2727. VPN/TCP-client replacement, cache, encrypted upstreams, association consumption and KSU/libnetd integration remain unestablished.

[S316](../testing/2026-10-25_S316_VPN_UDP_DNS_REPLACEMENT.md) connects optional VPN UDP DNS replacement before Direct, retaining shared policy, broker and TUN return/completion semantics. Its 52 composed N1/N3 groups include capacity, pending Stop and old-generation late answers, with 685 whole records in one final SQLite MAIN. Current Root idle health and first-input recovery also pass. Original APK/all4861 members are restored with BOTH2755; failed attempts and scope limits remain explicit.

Accepted design update, 2026-10-21: [ADR-0012](../adr/0012-configurable-flow-owners-and-dedicated-vpn-tun-io.md)
selects configurable `N >= 1` FlowOwners and a separate VPN-only TUN I/O VPP
worker, with direct TUN reads into VPP buffers and index-only owner transfer.
Root Product now supports a startup-configured owner count and ordered CPU
bindings, including repeated owner CPUs. VPN Product also supports resource-bounded
`N >= 1` FlowOwners and a dedicated TUN I/O worker. Controlled Pixel 6a Root
and VPN `N=1`/`N=3` paths passed the scoped [S303 functional qualification](../testing/2026-10-22_S303_ANDROID_CONFIGURABLE_TOPOLOGY.md),
including ordinary VPN protection, bounded faults and clean stops. The
[S304 performance comparison](../testing/2026-10-22_S304_VPN_IO_PERFORMANCE.md)
records a CPU-cost and paced-UDP loss trade-off against the former local-owner
VPN path. Adoption or rollback after those measurements remains the user's
decision; neither ADR acceptance nor functional qualification chooses it.

[S307 tuning](../testing/2026-10-22_S307_VPN_HANDOFF_TUNING.md) retained dedicated I/O and original-buffer transfer.
[S308 attribution](../testing/2026-10-22_S308_VPN_IO_CPU_ATTRIBUTION.md) led to user-adopted topology parsing removal,
48 default VPN primary credits, capture threshold/budget64, return frames256 and shared primary/completion/reclaim windows64.
[Combined qualification](../testing/2026-10-22_S308_ADOPTED_UNIFIED_WINDOWS.md) and [TCP CPU attribution](../testing/2026-10-22_S308_TCP_DOWNLOAD_CPU.md)
retain their separate scopes; equal-throughput whole-path gains remain unestablished. Optional TUN capture-batch diagnostics remain independent of TCP experiments.

## What exists

The product packet domain is VPP-native C. Root uses native NFQUEUE lanes; the
controlled Android VPN validation path uses TUN and the owner-local HEV/lwIP
transport stack. Shared parsing, canonical worker ownership, L4 policy,
FlowRuntime/protocol trackers, bounded reassembly, expiry and network facts have
separately scoped evidence. Rust owns control-plane sessions; Java RuntimeService
owns Android supervision. POC source and the removed C++ implementation are not
product code or compatibility fallbacks.

Root defaults selected on 2026-10-13 now use 128 ordinary receive/pending slots,
48 primary credits, a 16-datagram callback budget, a 1 MiB socket buffer request
(Pixel 2 MiB effective) and NFQUEUE maxlen 4096. Build entrypoints default to the
existing batch+packed implementation; production connection-stable queue placement
is retained. The installed Pixel artifact passed mixed ALLOW/DROP and the 8kpps
startup check; 16kpps still had four primary rejections. This is a user-selected
capacity change, with no whole-path CPU benefit claim. See the scoped
[implementation and regression record](../testing/2026-10-13_ROOT_COMPOSITE_DEFAULTS.md).

VPN builds default to inner MTU10000/MSS9940 from October 21. The software-only
VPP pool uses ordinary pages, 10240-byte data and exactly 2048 buffers; Root keeps
its existing buffer profile. From October 22, the user selects a 65,528-byte
TCP ring/sndbuf default (approximately 64 KiB), retaining the explicit 32,768-byte
override and unchanged 32,768-byte receive window; see the
[capacity decision](../adr/0007-owner-local-lwip-direct-egress.md#2026-10-22-user-selected-tcp-send-buffer-capacity).
TCP batch and readiness gating remain opt-in. The [large-MTU implementation](../testing/2026-10-21_VPN_LONG_TCP_SEGMENTS_AND_PROGRESS.md)
records the earlier 32 KiB download and same-pool MTU3000/10000 ABBA checks.
Current measurements remain scoped observations: [N1 fixed-frequency baseline](../testing/2026-10-22_TCP_SINGLE_LITTLE_MAXFREQ_BASELINE.md),
[historical N2 replay](../testing/2026-10-22_OLD_500_MAXFREQ_REPRODUCTION.md), [old multiflow/reconnect](../testing/2026-10-22_OLD_500_MULTIFLOW_MAXFREQ.md),
[old/current single-flow checks](../testing/2026-10-22_POSTWIFI_SINGLE_OLD_AND_CURRENT.md), [current single-flow cohort](../testing/2026-10-22_POSTWIFI_CURRENT_SINGLE.md)
and [current multiflow cohort](../testing/2026-10-22_CURRENT_MULTIFLOW_MAXFREQ.md).
Those reports retain raw identities, failed UID gates and explicit limits; they do not establish Wi-Fi causation, a capacity/frequency benefit or approximately500 Mbps single-flow recovery.

The [foundation joint report](../testing/2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md)
records `PASS_WITH_EXPLICIT_LIMITS` across Linux Root and 64 distinct Pixel
generations, with independent verifiers and retained failed attempts. Its Product
source closure is `ab278ba6c69555a0772277f17d9350bc73ced8312d061a663d52fe3b06b05b96`.
That identity describes the frozen Product sources, not every later docs/test commit.

## What that does not establish

- Ordinary VPN `protectionRunning=true` passed S303's controlled Product functional
  matrix; this does not establish a general release or supported-device promise.
- The real 24-hour TCP ESTABLISHED expiry/reuse test is user-deferred and unverified.
- Pixel cellular handover and real Linux physical Wi-Fi/Wired/Mobile coverage are
  not proved by the available hardware or controlled projections.
- Signed release, supported-device coverage, complete UI scenarios and performance,
  power and thermal budgets remain separate release requirements.

## Source and reading map

| Area | Source / entry |
| --- | --- |
| Packet graph, policy, flows, adapters | [`src/product/vpp/`](../../src/product/vpp/) |
| C ABI, VAPI and native platform bridge | [`src/product/include/`](../../src/product/include/), [`src/product/native/`](../../src/product/native/) |
| Control-plane sessions | [`crates/product-core/`](../../crates/product-core/) |
| Android supervision, platform facts, validation UI | [`app/android-runtime/`](../../app/android-runtime/) |
| Owner-local transport dependency | [`third_party/hev/`](../../third_party/hev/) |
| Artifact build and launch | [`tools/product/`](../../tools/product/), [tooling guide](../tooling/README.md) |
| Architecture constraints | [Decision map](../decisions/README.md), ADRs [0006](../adr/0006-vpp-native-packet-io-adapters.md), [0007](../adr/0007-owner-local-lwip-direct-egress.md), [0008](../adr/0008-remove-snort-cpp-mainline.md) |
| Verification | [Testing map](../testing/README.md), [test layout](../../tests/README.md) |
| Intended product | [Product docs](../product/README.md) |

Use the [documentation map](../README.md) for older reasoning and measurements.
See [KISS code organization](../maintenance/2026-09-13_KISS_CODE_ORGANIZATION.md) for source organization and regression evidence.
