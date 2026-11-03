# Current mainline

Checked: 2026-11-02, source HEAD `a02c74021f92ddd5db8d99edc895a13906e16757`.
This is an implementation map. Dated reports retain their own source/artifact identities;
this documentation update adds no build, device or release qualification. Plane owns work state.

## Capabilities and evidence

| Area | Current implementation and qualification |
| --- | --- |
| Shared packet runtime | VPP-native C, Root NFQUEUE and VPN TUN with owner-local HEV/lwIP Direct Egress; configurable FlowOwners and dedicated VPN TUN I/O. Controlled Pixel Root/VPN N1/N3 function: [S303](../testing/2026-10-22_S303_ANDROID_CONFIGURABLE_TOPOLOGY.md). Earlier Linux/Pixel foundation: [scoped joint report](../testing/2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md). |
| Rules and configuration | VPP-owned persistent configuration, unified whole-rule priority, groups/bindings, Boolean/static/CT/protocol/domain conditions, bounded compilation and result caches. T01–T19/R1–R4 records are indexed in [testing](../testing/README.md); the [specification](../product/UNIFIED_RULE_ENGINE_SPEC.md) defines intent. |
| Original-path DNS | Root/VPN UDP/TCP, IPv4/IPv6, QName/CNAME policy and normal query/reply observations. [S314](../testing/2026-10-23_S314_VPN_TCP_DNS.md) composes the first-stage qualification; S310–S313 retain individual scopes. |
| Optional DNS proxy | Root/VPN client UDP/TCP replacement, current policy, ordinary upstreams and bounded cancellation/return paths. S315–S318 records in [testing](../testing/README.md) retain each Adapter's qualification. Original-path denial is DROP; complete-message proxy denial is REFUSED, resolution failure SERVFAIL. |
| DNS data and routing | Owner-local answer cache, independent policy for coalesced queries, ordered primary/backup resolvers, resolution views and local exceptions: [S319](../testing/2026-10-27_S319_DNS_ANSWER_CACHE.md), [S320](../testing/2026-10-27_S320_DNS_COALESCING.md), [S321](../testing/2026-10-29_S321_ORDERED_DNS_ROUTING.md). |
| Encrypted DNS upstreams | Authenticated [DoT/bootstrap](../testing/2026-10-29_S322_DOT_BOOTSTRAP.md) and [DoH](../testing/2026-10-31_S323_DOH.md) through the shared owner. DoH uses HTTP/1.1 POST and ALPN `http/1.1`; H2/H3-only endpoints are outside qualified scope. |
| Connection domain facts | TLS/QUIC/DTLS SNI, visible HTTP request targets and SOCKS CONNECT targets feed policy. DNS association pairs are collected with an independent two-hour life; association enforcement is disabled and cross-App/profile use remains deferred. See [S324](../testing/2026-10-31_S324_ASSOCIATION.md) and [S325–S328](../testing/2026-11-01_S328_DNS_COMBINED.md). |
| Observation and App display | VPP exports bounded observations; Rust maintains SQLite history, windows and current-flow queries (T21–T28/E02 in [testing](../testing/README.md)). The old Java Activity/AppDetail path has no current producer: [confirmed channel gap](../reviews/2026-11-01_ACTIVITY_CHANNEL_GAP.md). Debug query output is not a completed Product Activity UI. |
| Android lifecycle and identity | Java RuntimeService supervises one active Root/VPN runtime. Ordinary VPN Start: [S289](../testing/2026-09-28_S289_VPN_NORMAL_START.md). UID/incarnation ownership refactor: [S290](../testing/2026-11-01_S290_VPN_UID_RESOLVER.md); its report distinguishes device-tested code from later review fixes and Host coverage. |

The user accepted [S328 DNS combined qualification](../testing/2026-11-01_S328_DNS_COMBINED.md)
on 2026-11-01: one artifact, Root/VPN × N1/N3, two generations and scoped per-capability
runs. Observation backpressure, handover and the N>1 view/semantics/capacity matrices remain
explicitly uncovered. The result does not qualify association enforcement or close parent S309.
S290's subsequent refactor and fixes have their own narrower qualification above.

## Code responsibilities

All filenames below are in [`src/product/vpp/`](../../src/product/vpp/) unless a directory is given.
Root/VPN ingress enters the shared packet graph and canonical FlowOwner, then policy/Flow processing
and Adapter completion; VPN ALLOW uses the owner-local transport stack and the shared return path.

| Responsibility | Source entry |
| --- | --- |
| Graph, ownership, completion, reassembly | `product_packet_graph.c`, `product_packet*.h`, `product_fragment.*` and private graph includes |
| Rule management and matching | `product_rule_config.*`, `product_l4_policy.*`, `product_domains*` |
| Flow lifetime and protocol/domain facts | `product_flow_entry.*`, `product_flow_expiry.*`, `product_flow_{tcp,udp,icmp,lpi,sni,quic,dtls,http}.c`, `product_{http,socks}_target.*` |
| Shared DNS semantics and proxy state | `product_dns.*`, `product_dns_tcp.*`, `product_dns_proxy.*`, `product_dns_cache.inc`, `product_dns_route.h`, `product_dns_assoc.*` |
| Encrypted upstream transport | `product_dns_tls.*`, `product_dns_bootstrap.*`, `product_dns_http.*`; pinned Mbed TLS in [`third_party/`](../../third_party/) |
| Root capture and DNS I/O | `product_root_nfqueue_adapter.*`, `product_root_dns_adapter.inc`, `product_root_dns_{io,tcp_io}.*` |
| VPN capture, forwarding and App identity | `product_vpn_tun_adapter.*`, `product_vpn_flow_stack*`, `product_vpn_socket_broker.*`, `product_vpn_uid_resolver.*`; [`third_party/hev/`](../../third_party/hev/) |
| Typed ABI and native control/observation transport | [`src/product/include/`](../../src/product/include/), [`src/product/native/`](../../src/product/native/), [interface map](../INTERFACE_SPECIFICATION.md) |
| Rust control, queries and observation storage | [`crates/product-core/src/`](../../crates/product-core/src/): `session.rs`, `rule_config.rs`, `rule_import.rs`, `observation_service.rs`, `observation_store.rs`, `dns_observation.rs`, `ffi.rs` |
| Android supervision and validation UI | [`app/android-runtime/`](../../app/android-runtime/): `RuntimeService`, control/broker classes and JNI; `DebugControlActivity` is the validation UI |
| Builds and verification | [`tools/product/`](../../tools/product/), [APK builder](../../app/android-runtime/scripts/build-debug-apk.sh), [test layout](../../tests/README.md), [tooling](../tooling/README.md) |

The observation path is VPP producer → native transport → Rust observation service/SQLite → query API.
Activity/AppDetail still reading `policyDropActivity`/`allowedFlowActivity` is the gap described above.
POCs and the removed Snort C++ implementation are not product code or compatibility fallbacks
([ADRs 0006–0008](../decisions/README.md)).

## Runtime defaults and limits

Root uses batch+packed, 128 ordinary receive/pending slots, 48 primary credits, a 16-datagram
callback budget, a 1 MiB socket request and NFQUEUE maxlen4096. The scoped
[October 13 record](../testing/2026-10-13_ROOT_COMPOSITE_DEFAULTS.md) retains the 16kpps
primary rejections and does not establish a whole-path CPU gain.

VPN defaults include MTU10000/MSS9940, 2048 ordinary-page VPP buffers with 10240-byte data,
a 65,528-byte TCP send profile, 48 primary credits and 64-packet shared windows. See
[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md),
[ADR-0012](../adr/0012-configurable-flow-owners-and-dedicated-vpn-tun-io.md) and
[adopted-window qualification](../testing/2026-10-22_S308_ADOPTED_UNIFIED_WINDOWS.md).
TCP batch/readiness experiments remain opt-in; dated throughput results do not promise a current rate.

- VPN App identity is asynchronous: early packets can precede a known UID. A system resolver UID
  is not the original App; system/App cache hits that never reach ingress are not query decisions.
- The real 24-hour TCP ESTABLISHED expiry/reuse test remains user-deferred and unverified.
- Pixel cellular handover and real Linux physical Wi-Fi/Wired/Mobile coverage remain unproved.
- Signed releases, supported-device coverage, complete Product UI, power/thermal budgets and
  formal performance gates remain separate from the scoped functional results.

## Work and further reading

Use Plane for priorities, dependencies and acceptance decisions; these are topic routes, not a second backlog:

- DNS scope and deferred association use: [S309](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/0b382ead-4049-4448-8d4a-149a05aef43e).
- Planned activity-data query contract: [S329 specification](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/6c736721-8779-4888-8853-d57881ac146d); recognition facts remain associated with [S61](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/c7e0c179-b64c-47d3-99b7-e0dd05bf2842). Specification publication is not implementation evidence.
- Product/Protocol release contracts: [S59](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/32a7eb03-f251-4070-a43e-1c3ddb5c0699), [S63](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/aec4ffdf-7a27-4fde-9f49-95e5c51afb10).
- Separate performance questions: [Root whole-path S291](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/e03a4efc-32c0-4b7a-b529-12e06ee730bc), [VPN scheduling S292](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/0a35cbe1-ce1e-4531-b413-d6d8edc8a94c), [worker-notification S248](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/e0fa48f8-bde5-40c4-b2a0-31a67fe7428f).

Read the [documentation map](../README.md), [accepted decisions](../decisions/README.md),
[typed interfaces](../INTERFACE_SPECIFICATION.md), [product goals](../product/README.md)
and [dated evidence](../testing/README.md) as needed. Long roadmaps and handoffs retain historical context.
