# Current mainline

Baseline: 2026-10-29. This short implementation entry is not a release announcement; current task state belongs to Plane.

Accepted 2026-09-24: [ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md) and the [unified rule specification](../product/UNIFIED_RULE_ENGINE_SPEC.md) define policy/configuration/observation behavior; they do not extend implementation claims.

Accepted 2026-10-07: [ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md) defines shared Root/VPN application DNS query and subsequent-connection control.
- [S310 Root](../testing/2026-10-22_S310_ROOT_UDP_DNS.md) and [S311 VPN](../testing/2026-10-22_S311_VPN_UDP_DNS.md) qualify controlled original-path UDP53 query filtering and normal observations.
- [S312](../testing/2026-10-22_S312_UDP_DNS_RESPONSES.md) adds bounded UDP reply correlation, connected CNAME rules and normal reply observations; its report keeps artifact and device qualification scopes explicit.
- [S313](../testing/2026-10-23_S313_ROOT_TCP_DNS.md) adds bounded Root TCP DNS framing and QName/CNAME policy; its R2/R3 artifact qualifications remain separate.
- [S314](../testing/2026-10-23_S314_VPN_TCP_DNS.md) connects VPN Direct TCP to the shared core and qualifies 104 current R5 groups across Root/VPN, UDP/TCP, IPv4/IPv6 and N1/N3, with normal SQLite and clean stops. Root active-socket capture and one incomplete public attempt remain explicit limits. Its scope excludes replacement, association consumption and KSU/libnetd integration.
- [S315](../testing/2026-10-24_S315_ROOT_UDP_DNS_REPLACEMENT.md) adds explicitly configured Root UDP53 replacement with ordinary dual-stack upstreams, same-resolver TC→TCP, current query/response policy and bounded resources. Its 35 composed N1/N3 groups have independent normal SQLite and native-zero cleanup; failed attempts, unexplained earlier peer loss and bounded stop-history gaps remain explicit. Original APK/all4861 members are restored with BOTH2727. VPN/TCP-client replacement, cache, encrypted upstreams, association consumption and KSU/libnetd integration remain unestablished.
- [S316](../testing/2026-10-25_S316_VPN_UDP_DNS_REPLACEMENT.md) connects optional VPN UDP DNS replacement before Direct, retaining shared policy, broker and TUN return/completion semantics. Its 52 composed N1/N3 groups include capacity, pending Stop and old-generation late answers, with 685 whole records in one final SQLite MAIN. Current Root idle health and first-input recovery also pass. Original APK/all4861 members are restored with BOTH2755; failed attempts and scope limits remain explicit. [S317](../testing/2026-10-25_S317_ROOT_TCP_DNS_REPLACEMENT.md) adds optional Root client TCP53 replacement with bounded transparent socket I/O, per-message policy and normal SQLite. Its 70 composed R3 groups cover N1/N3 dual-stack pipeline, real client UDP-TC→TCP retry, cancellation, Stop/late answers and capacity; 654 required whole records plus8 original-path records remain in one final MAIN. Original APK/all4861 members are restored with BOTH2778; Host baseline and transport/evidence limits stay explicit.
- [S318](../testing/2026-10-26_S318_VPN_TCP_DNS_REPLACEMENT.md) adds optional VPN client TCP53 replacement before Direct through bounded local HEV/lwIP messages and the shared current-policy proxy. R4/R5 qualify78 groups/583 whole records in MAIN1656; R6 adds event/deadline-driven progress and19 scoped groups/92 whole records in separate MAIN301, including real pending Stop/new-TUN late fencing and N3 dual-stack progress. Original APK/all4861 members are restored at fresh BOTH2809; original HOLDs and deferred cache/encrypted-upstream/association scope remain explicit.
- [S319](../testing/2026-10-27_S319_DNS_ANSWER_CACHE.md) adds owner-local valid-answer data reuse with current policy, exact resolution-view keys, TTL/SOA aging and512-entry/2MiB limits. Its393 scoped groups/5643 whole records compose separate Root/VPN artifacts and MAINs, with normal4096 history, bounded shutdown-prefix and allocator-failure history regressions. Original APK/all4861 members are restored at fresh BOTH2867; original HOLDs and artifact limits remain explicit. [S320](../testing/2026-10-27_S320_DNS_COALESCING.md) adds simultaneous equivalent-query data sharing with independent current policy and delivery, 64 exchanges/128 waiters and bounded TCP backpressure. Current R4 qualifies52 groups/1448 whole target records in MAIN1844 across Root/VPN N1/N3 and both client transports/families, with pending Stop/late fences; earlier policy/cancellation/view captures retain their own artifact scopes and original HOLDs. Independent Standards/Spec and behavior/recovery checks passed on October 29. Original APK/all4861 members are restored at BOTH2904, with only the two generation fields changed.
- [S321](../testing/2026-10-29_S321_ORDERED_DNS_ROUTING.md) adds VPP-persisted ordered ordinary resolvers, bounded demand recovery, exact/longest-label exceptions and resolution-view fencing. Its self-tests cover Root/VPN N1/N3 client UDP/TCP and both families, candidate cache/RCODE/view behavior, actual advertised LAN resolver and scoped original-network mDNS; 246 whole case records remain in MAIN727. The standard5353 feedback regression and original HOLDs keep their actual artifact scopes. The original APK/all4861 nodes are restored at fresh BOTH2922; independent review and delivery have a separate linked receipt.
- [S322](../testing/2026-10-29_S322_DOT_BOOTSTRAP.md) adds authenticated DoT, original-network service address discovery and bounded normal identity/error observations through the shared Root/VPN owner. The record distinguishes earlier minimal device artifacts, current ABI5/TLS1.2 contracts, controlled trust and actual wire scopes. Final Root N1 full, Root/VPN N1 bootstrap and handshake-Stop device results use one rebuilt artifact after a TLS owner budget fix; N3 and VPN full matrices keep their earlier scopes.
- [S323](../testing/2026-10-31_S323_DOH.md) adds bounded DoH over the same Root/VPN owner: an https URL upstream with original-network address discovery, HTTP/1.1 POST with ALPN `http/1.1` only, bounded HTTP framing with no redirect or compression, HTTP Age subtracted before caching, and HTTP/ALPN failures in observation version 11. Pixel 6a Root and VPN N1 30-case matrices pass with 140 whole records each; N3, handover and public-service scopes are not claimed.
- [S324](../testing/2026-10-31_S324_ASSOCIATION.md) adds domain-IP association facts to the shared DNS proxy: pairs from the answer section's QName/connected-CNAME addresses, a per-pair two-hour life independent of the answer TTL that only allowed answers refresh, bounded capacity with view/Stop invalidation, a read-only qualification hook with enforcement disabled (cross-App/profile scope is undecided), admission evidence in the existing DNS observation record and a `dns.assoc` status line. Qualified on Host and on Pixel 6a Root/VPN N1; no consumer of the hook exists, so no fallback acceptance is claimed.
- [S325](../testing/2026-10-31_S325_HTTP_TARGETS.md) tracks visible cleartext HTTP/1.x request targets per TCP flow as a third domain source with sticky connection-level DROP. Qualified on Host and Pixel 6a Root/VPN N1; on VPN App-bound rules apply once the asynchronous App UID is known.
- [S326](../testing/2026-10-31_S326_SOCKS_TARGETS.md) adds SOCKS4/4a/5 CONNECT targets, proven by the real negotiation, as a direct domain source on the same Flow storage and sticky DROP. Qualified on Host and Pixel 6a Root/VPN N1.
- [S327](../testing/2026-10-31_S327_DTLS_SNI.md) adds DTLS 1.0/1.2 ClientHello SNI from real handshake fragments; SNI rules now apply to DTLS. Qualified on Host and Pixel 6a Root/VPN N1; on VPN the first datagram of a new flow precedes the App UID.
- [S328](../testing/2026-11-01_S328_DNS_COMBINED.md) qualifies the delivered DNS capabilities together on one artifact: combined Root/VPN N1/N3 runs across two generations and per-capability N3 runs. Association enforcement stays deferred.
Accepted design update, 2026-10-21: [ADR-0012](../adr/0012-configurable-flow-owners-and-dedicated-vpn-tun-io.md)
selects configurable `N >= 1` FlowOwners and a separate VPN-only TUN I/O VPP
worker, with direct TUN reads into VPP buffers and index-only owner transfer.
Root Product now supports a startup-configured owner count and ordered CPU
bindings, including repeated owner CPUs. VPN Product also supports resource-bounded
`N >= 1` FlowOwners and a dedicated TUN I/O worker. Controlled Pixel 6a Root
and VPN `N=1`/`N=3` paths passed the scoped [S303 functional qualification](../testing/2026-10-22_S303_ANDROID_CONFIGURABLE_TOPOLOGY.md),
including ordinary VPN protection, bounded faults and clean stops. The
- [S304 performance comparison](../testing/2026-10-22_S304_VPN_IO_PERFORMANCE.md)
records a CPU-cost and paced-UDP loss trade-off against the former local-owner
VPN path. Adoption or rollback after those measurements remains the user's
decision; neither ADR acceptance nor functional qualification chooses it.
- [S307 tuning](../testing/2026-10-22_S307_VPN_HANDOFF_TUNING.md) retained dedicated I/O and original-buffer transfer.
- [S308 attribution](../testing/2026-10-22_S308_VPN_IO_CPU_ATTRIBUTION.md) led to user-adopted topology parsing removal,
48 default VPN primary credits, capture threshold/budget64, return frames256 and shared primary/completion/reclaim windows64.
[Combined qualification](../testing/2026-10-22_S308_ADOPTED_UNIFIED_WINDOWS.md) and [TCP CPU attribution](../testing/2026-10-22_S308_TCP_DOWNLOAD_CPU.md)
retain their separate scopes; equal-throughput whole-path gains remain unestablished. Optional TUN capture-batch diagnostics remain independent of TCP experiments.

## What exists

The product packet domain is VPP-native C. Root uses native NFQUEUE lanes; the controlled Android VPN validation path uses TUN and the owner-local HEV/lwIP transport stack. Shared parsing, canonical worker ownership, L4 policy, FlowRuntime/protocol trackers, bounded reassembly, expiry and network facts have separately scoped evidence.
Rust owns control-plane sessions; Java RuntimeService owns Android supervision. POC source and the removed C++ implementation are not product code or compatibility fallbacks.

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

The [foundation joint report](../testing/2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md) records `PASS_WITH_EXPLICIT_LIMITS` across Linux Root and 64 distinct Pixel generations, with independent verifiers and retained failed attempts. Its Product source closure is `ab278ba6c69555a0772277f17d9350bc73ced8312d061a663d52fe3b06b05b96`. That identity describes the frozen Product sources, not every later docs/test commit.

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
