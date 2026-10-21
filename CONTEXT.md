# Sakamoto Snort

Sakamoto Snort is a local-endpoint firewall project for Android and Linux, providing DNS/domain policy, IP packet policy, and bounded observability. This glossary captures project-specific language used across the current docs so agents do not drift back to legacy or OpenSpec-era terminology.

Accepted rule/observation terminology was synchronized on 2026-09-24 with [ADR-0009](docs/adr/0009-unified-rules-and-vpp-owned-configuration.md) and the [unified rule specification](docs/product/UNIFIED_RULE_ENGINE_SPEC.md). These definitions express the accepted target; current code and dated evidence remain the authority for implemented capability. Explicitly historical terms do not add requirements to the new design.

## Language

### Architecture Surfaces

**vNext control plane**:
Historical name for the retired daemon command surface. Current product control is defined by the typed Interfaces and accepted VPP-native rule-management design.
_Avoid_: current API name, C++ compatibility surface

**Control Plane**:
The product configuration, status and diagnostic surface. VPP owns online rule management and its persistent configuration source; Rust adapts requests and separately maintains observation history.
_Avoid_: packet worker, shared analytics database, UI-owned policy

**QUIT**:
The vNext control-plane command for ending the current control session after its response is written. It is not Daemon lifecycle and must not be used as the native daemon process shutdown signal.
_Avoid_: daemon shutdown, process stop, RuntimeService stop

**Dataplane**:
The runtime packet and DNS execution path that produces verdicts and maintains only bounded hot-path state.
_Avoid_: storage layer, reporting backend

**RuntimeService**:
The Android-side lifecycle owner of the active Runtime Profile's supervised VPP Runtime, including startup, shutdown, artifact handoff, configuration sync, and post-start health checks.
_Avoid_: UI directly managing the native dataplane, generic runtime owner

**VPP Runtime**:
The single supervised native instance for the active Runtime Profile, owning the VPP graph, worker state and online rule management. Management availability is distinct from policy and Adapter readiness to capture product traffic.
_Avoid_: surrounding C++ daemon, parallel Root/VPN dataplanes, process alive means protection running

**Retired C++ Mainline**:
The removed Snort C++ daemon, host model, tests, NDK artifact, and archived source. It is not a product implementation option, compatibility fallback, or design input; only its explicitly recorded evidence may be cited.
_Avoid_: C++ compatibility path, C++ Flow Stack facade, translating the old daemon

**Debug Control Activity**:
The minimal Android UI used during Functional Closure to select a Runtime Profile, start or stop the supervised runtime, operate the smallest test policy, and inspect bounded current or recent status and verdict evidence. It is not the release Product UI, the durable Activity Store, or an authority for policy, lifecycle, or packet state.
_Avoid_: Product Activity, Activity Store, release UI, runtime owner, policy database

**Runtime Profile**:
The mutually exclusive product choice of Android `root` or `vpn` packet capture and lifecycle behavior. Exactly one VPP Runtime is active; changing Runtime Profile replaces its platform Adapter and privilege topology, not the shared dataplane, policy identity, or Product UI information architecture.
_Avoid_: separate Root product, separate VPN policy database, parallel Root/VPN dataplanes, packet worker topology

**VPP-native Packet I/O Adapter**:
The target VPP plugin form of a Packet capture Adapter, owning platform ingress, Adapter Completion, and live-buffer lifecycle around the shared VPP graph. It is not the surrounding daemon or a generic glue layer; the pinned target language is fixed by ADR-0006.
_Avoid_: hot-path glue, C glue, C++ daemon Adapter, Rust packet bridge, second policy engine

**Direct Egress**:
The sole first-release VPN forwarding mode, in which allowed IPv4/IPv6 TCP and UDP traffic is sent to its original destination without requiring an upstream proxy. All four IP-family/transport combinations are release requirements even when feasibility work starts with TCP only.
_Avoid_: built-in relay, mandatory SOCKS5 dependency, proxy bypass fallback, treating the TCP prototype as release-complete

**Direct DNS Handling**:
The original forwarding baseline where DNS remains TCP or UDP traffic sent to its original destination. Forwarding alone does not establish the selected Application DNS Filtering, association collection or optional upstream-relay behavior.
_Avoid_: treating forwarding alone as complete DNS filtering, assuming application filtering requires resolver replacement

**VPN DNS Relay**:
The optional product-managed resolution path within VPN DNS handling, distinct from filtering ordinary queries on their original resolver path. Its user-selected upstream can use ordinary UDP/TCP DNS or explicitly enabled DoT/DoH; DoQ is excluded.
_Avoid_: automatic resolver replacement, mandatory encrypted upstream, all DNS must use the relay, complete recursive resolver, cached permission reused across applications, replacing the general VPN forwarding mode

**DNS Upstream Bootstrap**:
Product-generated address acquisition used to connect to a configured DoT/DoH service, using configured connection IPs or system/original-network resolution of the service hostname. Its scope is separate from application DNS queries and ordinary-DNS fallback after an encrypted-upstream failure.
_Avoid_: application-query fallback, hostname-based permission exemption for other apps, silently chosen public bootstrap resolver

**POC Performance Guardrail**:
A feasibility-stage stop rule used to detect architecture-level cliffs before importing a POC finding into main-stack design. It is not a release SLO, product performance promise, or optimization target. Historical POC arms may satisfy the guardrail by proving correctness, cleanup, bounded CPU, and absence of repeated severe tail regressions for their registered scope, while broader throughput, power, thermal, and soak budgets remain deferred until the real product Direct Egress seam exists.
_Avoid_: final release SLA, user-facing performance guarantee, continuing historical POC performance work after the architecture question is answered

**VPN Userspace Flow Stack**:
The VPN-only packet-in/packet-out Module that reconstructs allowed L3 packets into TCP/UDP transport flows, operates Protected Egress Sockets, and synthesizes return L3 packets for reinjection into the same canonical FlowOwner and shared VPP graph. The selected implementation family is the Sakamoto HEV Fork/lwIP; it owns transport state and resources, not FlowEntry, Policy Verdict, shared packet policy, or direct TUN-write authority.
_Avoid_: lightweight packet sender, Direct Connector alone, shared VPP policy engine, direct lwIP-to-TUN return, inbound policy bypass, Root Profile dependency, assuming Android can transmit post-policy L3 packets without flow reconstruction

**FlowOwner-local Egress Shard**:
The VPN egress ownership locality aligned with one canonical FlowOwner, with no second egress hash, cross-owner spill, or flow migration. It does not fix internal mutable-state partitioning, shard count, or OS-thread topology; those remain evidence-selected.
_Avoid_: global HEV bottleneck, independent egress hash, live reshard, overload spillover, flow migration between shards, treating shard as an OS thread or settled instance layout

**VPN Packet Provenance**:
The immutable PacketLease metadata that distinguishes an Android TUN-origin packet from a VPN Userspace Flow Stack-origin packet without changing Canonical Flow Key or FlowOwner selection. After the normal shared graph permits forwarding, TUN-origin traffic terminates at its owner-local egress shard while flow-stack-origin traffic terminates at Android TUN completion. Endpoint routing never infers provenance from flow-relative `ORIG/REPLY`, preventing a VPP-to-lwIP return loop while preserving one bidirectional flow owner.
_Avoid_: provenance in the flow hash, ORIG as TUN source, REPLY as lwIP source, return packet re-entering egress, direct lwIP-to-TUN bypass

**Protected Egress Socket**:
A VPN Userspace Flow Stack TCP or UDP socket bound to the selected Android underlay and successfully excluded by Android `VpnService` from the active VPN before `connect()` or the first send, preventing its outer traffic from re-entering the TUN. Its underlay epoch is fixed at creation: new flows use the latest Network Context Snapshot, while an invalidated TCP underlay ends the transport flow so the application can reconnect rather than transparently migrating or reconnecting its byte stream. An invalidated UDP transport closes its old PCB, socket and unsent queue; after cleanup a later permitted datagram, including the same five-tuple from the same application socket, may create a fresh protected/bound transport on the latest available underlay. This never replays the old queue, reuses the old socket or guarantees remote-session continuity, and does not itself end the independently managed VPP FlowEntry. Protection or underlay-binding failure closes the socket with no unprotected fallback and remains an Infrastructure Fault and failed Transport Outcome without rewriting the Policy Verdict.
_Avoid_: protect after connect, per-packet protect, unprotected retry, VPN-loop fallback, policy drop

**VPN Egress Overload**:
The bounded failure behavior when an owner-local egress shard cannot admit more work. Exhausted flow capacity rejects creation of a new lwIP session, PCB, or protected socket without evicting an existing flow or spilling to another shard. Exhausted packet-handoff or buffer credit discards only the current packet without implicitly terminating an existing transport flow. Both remain explicit Transport or Runtime failures rather than Policy Verdicts: VPP workers never wait, TCP may recover through retransmission, UDP may lose the datagram, and sustained overload is surfaced through Runtime health without policy bypass.
_Avoid_: blocking a VPP worker, cross-shard spill, implicit flow eviction, overload as policy DROP, Direct bypass, hiding sustained saturation

**VPN Egress Recovery Policy**:
The connectivity-first response when the VPN Userspace Flow Stack cannot start or crashes: attempt one bounded automatic restart, then tear down the unusable VPN runtime and visibly report that protection stopped so ordinary connectivity can resume. Android always-on lockdown remains authoritative and may keep connectivity blocked; Sakamoto never reports a stopped or dead egress stack as active protection.
_Avoid_: permanent dead-TUN blackhole, silent policy bypass, unlimited restart loop, reporting protection as running, overriding Android lockdown

**SOCKS5 Egress**:
A possible future, explicitly selected VPN forwarding mode in which allowed traffic uses a configured SOCKS5 upstream. It is outside the current product, implementation, and acceptance scope; the internal connector seam may preserve the existing adapter without creating a current roadmap obligation. If later enabled, failure never falls back implicitly to Direct Egress and changing modes requires an explicit user choice.
_Avoid_: current requirement, first-release feature, current implementation focus, default egress, transparent direct fallback, `socket5`

**2026 Local Endpoint Deployment Scope**:
The current planning boundary in which Sakamoto protects traffic on the user's own Android or Linux endpoint for an individual or very small team. It is not deployed as a network gateway, router, shared security appliance, or hostile multi-tenant enforcement point. Runtime behavior may preserve continuity with the modified VPP fork, but design choices within this release scope are justified by local correctness, bounded resources, and preservation of the user's connectivity rather than by an Internet-facing attacker model. Gateway and hostile multi-tenant requirements require a later explicit scope decision.
_Avoid_: gateway threat assumptions, router/appliance semantics, hostile multi-tenant hardening as a 2026 release requirement, claiming that the endpoint has no malformed-input correctness requirements

**Runtime Profile Initialization**:
The recoverable Android first-run flow that detects Root/VPN capabilities, recommends and authorizes an available Runtime Profile, requires a visible ongoing runtime notification, starts and verifies runtime readiness, and reports an actionable result before normal product use. Detection may recommend but never silently chooses or switches a profile; later profile changes preserve the Authoring Policy Bundle. Policy initialization is not a separate onboarding stage.
_Avoid_: one permission popup, automatic privileged-mode selection, generic startup failure, policy reset on profile switch

**Visible Runtime Notification**:
The user-visible ongoing Android notification required for product-ready persistent protection. Android may technically permit some runtime behavior when notification permission is denied, but Sakamoto initialization remains incomplete until the ongoing protection notification can be shown. It communicates runtime status and is not a marketing notification.
_Avoid_: optional onboarding decoration, advertising permission, treating daemon-start success alone as product readiness

**Linux Host Firewall**:
The first Linux product target: the Linux host kernel continues to own the network interfaces, while a Packet capture Adapter delivers selected local-host traffic to the shared packet runtime. Per-application policy, activity, and control are baseline product capabilities; host-wide rules may complement them but are not a substitute. Its first implemented Adapter is Linux NFQUEUE; other Linux ingress mechanisms remain future Adapter extensions rather than current release scope.
_Avoid_: native-VPP gateway, router/appliance mode, host-wide-only firewall, treating every planned Linux ingress mechanism as implemented

**Linux Host Firewall Hook Scope**:
The Linux v1 NFQUEUE coverage installed on the host netfilter `INPUT` (`LOCAL_IN`) and `OUTPUT` (`LOCAL_OUT`) paths. It provides both inbound and outbound host application control while excluding `FORWARD`, hotspot, bridge-forwarding, container-forwarding, and router/gateway semantics. Loopback traffic is bypassed before NFQUEUE and produces no policy decision or product statistics. Hook or queue identity supplies packet direction but never flow ownership.
_Avoid_: outbound-only application firewall, FORWARD capture, loopback interception, local-IPC firewall claim, gateway product scope, INPUT/OUTPUT queue as owner

**Linux Netfilter Hook Backend**:
The startup-selected Hook Manager implementation that installs the Linux Host Firewall Hook Scope using capabilities available on the host. Native nftables is preferred when usable, with iptables/ip6tables variants as fallbacks; exactly one backend owns Sakamoto's private rules for a runtime. Selection requires the complete dual-stack INPUT/OUTPUT NFQUEUE contract rather than command presence alone, and the active backend is reported through Runtime health. Backend differences never enter policy or packet-worker semantics.
_Avoid_: user-facing backend mode, mixing nftables and iptables ownership in one runtime, partial-family readiness, treating an installed command as capability proof

**Linux NFQUEUE Adapter**:
The first Packet capture Adapter for Linux Host Firewall. It owns NFQUEUE-specific packet ingress, metadata normalization, bounded packet-buffer lifetime, verdict completion, and queue lifecycle; policy evaluation, flow ownership, session state, and rule persistence remain in shared modules.
_Avoid_: Linux policy engine, NFQUEUE-owned session table, Linux-only rule model, generic name for all Linux ingress

**Application Identity Provider**:
The narrow platform-owned module that resolves packet and runtime identity evidence into an application subject usable by the shared packet runtime. Linux may combine NFQUEUE UID, eBPF-maintained indexes, and bounded socket/process inspection; Android Root and VPN may use different evidence. Packet capture Adapters supply evidence but do not own application discovery, while policy and session modules consume only the resolved runtime subject. The first implementation uses a fixed interface and platform implementations, not a dynamic provider plugin framework.
_Avoid_: NFQUEUE-owned application database, policy-engine process lookup, dynamic identity-provider ABI, comparing executable paths in the packet matcher

**Application Catalog Provider**:
The platform-owned product discovery boundary that supplies ApplicationSubjectId descriptors, labels, icons, availability, and display metadata to Local Product Backend and Product UI. Android obtains catalog data from PackageManager; Linux merges supported desktop/package/service metadata with applications observed in real traffic. It is separate from hot-path Application Identity Provider, does not scan every executable on the filesystem, and does not make the frontend an authoritative application database.
_Avoid_: PackageManager-shaped Linux catalog, UI-owned policy identity, exhaustive executable scan, mixing display lookup into packet attribution

**Identity Hints**:
Normalized packet-local evidence offered to the Application Identity Provider, such as UID, tuple, hook, ingress interface, or socket cookie when available. Hints may be incomplete and are not themselves persisted application identity or policy keys.
_Avoid_: guaranteed application identity, Canonical Owner Key or Canonical Flow Key fields, Adapter-specific handles escaping into policy code

**ApplicationSubjectId**:
The persisted tagged logical-application identity referenced by Authoring Policy Bundle bindings. Android uses an `android_uid` variant carrying the complete Linux UID; Linux uses a `linux_app` variant that may map multiple deterministic Execution Identities to one user-managed application. Shared rules and groups do not imply that bindings are portable between variants: cross-platform binding requires an explicit application mapping. Apply compiles the persisted identity to a platform-optimized runtime representation.
_Avoid_: untagged UID, executable path as the universal final policy subject, automatic parent-child permission inheritance, automatic Android/Linux app equivalence, Runtime Subject Handle, string comparison in the packet hot path

**Execution Identity**:
A platform runtime identity used by Application Identity Provider to attribute one process or execution scope to a logical ApplicationSubjectId. Linux evidence may include UID, executable, cgroup, package, or service metadata; one logical application may have several execution identities. Automatic grouping requires deterministic trusted evidence, while unresolved executables remain separate rather than being merged heuristically.
_Avoid_: policy binding target, fuzzy process-name grouping, permanent parent-process inheritance, Product UI top-level duplicate for every helper process

**Runtime Subject Handle**:
The compact runtime identifier returned by the Application Identity Provider and consumed by shared policy, activity, and session modules. Persisted platform application identities compile or resolve to handles; the hot path does not compare package names, executable paths, Flatpak IDs, or systemd units. A Runtime Subject Handle never participates in Canonical Owner Key or Canonical Flow Key construction or worker selection.
_Avoid_: persistent cross-device application ID, process ID, socket cookie, worker ownership key

**Unknown Application**:
The built-in application subject used when Non-blocking Application Attribution has no resolved identity for the current packet. Its shipped default is allow, with an explicit global block control for strict users. A packet blocked as Unknown Application creates no FlowEntry or per-flow attribution state; if it passes into a FlowEntry, later identity enrichment may cause subsequent packets to use the resolved application's policy.
_Avoid_: unconditional fail-open hidden from the user, synchronous identity wait, session allocation for an already-dropped packet, retroactively changing the first verdict

**Non-blocking Application Attribution**:
The packet-path rule that immediately uses application identity available from packet metadata or runtime caches, but never holds an ingress queue or an individual packet waiting for a missing identity. An unresolved packet executes with an explicit unknown subject. If that packet proceeds into a FlowEntry, later provider results may enrich the worker-owned flow and affect subsequent packets without changing the completed verdict retroactively. A packet dropped before FlowEntry creation creates no session or per-flow attribution state; independently maintained eBPF/socket identity indexes may still make a later attempt immediately attributable. Android VPN follows the same rule: a `getConnectionOwnerUid` cache miss must not create a pending-packet table or delay/replay the packet.
_Avoid_: synchronous `/proc` scan, holding PacketLease for identity lookup, pending packet until UID resolution, AttributionCache for already-dropped flows, unbounded first-packet wait, packet replay after attribution, retroactive verdict change

**No Recognition Hold**:
The cross-platform packet-path guarantee that ordinary packets are never buffered, delayed, or replayed merely to await application attribution, protocol identification, DNS correlation, or future L7 metadata. A packet is evaluated with facts available at that moment; facts learned later affect only later packets. Neither Android nor Linux promises zero leakage before recognition, and a short flow may finish before it can be classified. Bounded packet retention required by a network protocol itself, notably IP fragment reassembly, is a separate datapath function. Caching flow facts or recognition results is permitted and is not packet caching.
_Avoid_: zero-leak recognition claim, pending classification packets, identification timeout as packet lifetime, conflating metadata cache with packet buffer, treating IP fragment reassembly as DPI hold

**Application Protocol Identity**:
The project-owned canonical catalog identity to which libprotoident and future recognizers normalize their provider-specific names or results. Each identity has one stable `ApplicationProtocolId` and one stable `ApplicationProtocolKey`; recognition source and evidence remain separate attributes, so the same protocol does not acquire different policy identities when recognized by different engines. The catalog does not inherit Qosmos/qDPI, Junos, MAAT, or another vendor's private numeric AppID space merely because the inspected fork used it. A standards-assigned value is retained only in its own typed namespace, such as IP protocol number, service/port, ALPN token, or QUIC version; none of those values is treated as the project's application protocol ID.
_Avoid_: libprotoident enum as persistent ID, `lpi:`-namespaced policy identity, Qosmos `Q_PROTO_*` compatibility without Qosmos, port number as application identity, provider origin embedded in protocol identity

**ApplicationProtocolId**:
The stable project-wide integer assigned once to an Application Protocol Identity in the authoritative protocol catalog. Packet workers and internal records may use it directly; released values are append-only and are never renumbered, reassigned, or made snapshot-local.
_Avoid_: RuntimeProtocolHandle, upstream enum ordinal, runtime-configurable number, reusable deleted ID, RFC/IANA value outside its typed namespace

**ApplicationProtocolKey**:
The stable lowercase symbolic companion to an ApplicationProtocolId in Sakamoto's authoritative protocol catalog, used by authoring, import/export, diagnostics, and product APIs. A key names the recognized protocol rather than the recognizer that produced it; released keys retain their mapping, while provider aliases are catalog inputs rather than additional policy identities.
_Avoid_: provider prefix, display label as identity, localized key, upstream enum name as implicit identity, mutable alias

**Application Protocol Category**:
A project-owned authoring and presentation grouping over exact Application Protocol Identities, such as a Web or Messaging selection. Authoring Policy Bundles and Checkpoints retain the category selector; Policy Apply and Checkpoint Restore expand it using the current built-in catalog into the matching stable ApplicationProtocolId set. It is not a recognized flow fact, parent protocol, runtime inheritance relation, or catalog-version-pinned policy.
_Avoid_: protocol parent ID, frozen historical category expansion, catalog pinning in the first release, dynamic hot-path hierarchy walk, replacing exact recognition results, category string comparison in packet workers

**Product UI**:
The thin shared Tauri user experience for Android first and later Linux, backed by UI-facing product state rather than VPP graph internals. It owns presentation and transient interaction state, not the authoritative policy database.
_Avoid_: VPP control panel, frontend-owned policy backend, platform-specific duplicate UI

**Local Product Backend**:
The on-device product boundary adapting frontend requests and maintaining normal observations and query projections. Its Rust responsibilities do not duplicate the editable rule model owned by VPP, and Android ingestion remains under RuntimeService rather than UI lifecycle.
_Avoid_: remote backend, UI-owned history, second editable rule database

**App-first Control**:
The product control model where network access, L4 rules, activity, and statistics remain organized around a platform application. Android preserves multi-user identity through complete Linux UID; Linux resolves its own application identity through the Application Identity Provider. It does not prescribe which screen opens first.
_Avoid_: rule-inventory-first control model, device-wide expert console, UID-only Linux application identity, treating launch destination as control ownership

**Progressive Control Disclosure**:
The contextual disclosure of controls, evidence and diagnostics within the selected Product Protection Mode. Modes may have different default tasks and screens; ordinary protection does not require full rule authoring.
_Avoid_: identical default work for every mode, mandatory expert authoring for ordinary users

**Product Protection Mode**:
The user's choice of filtering strategy and control responsibility: Standard is the intended everyday mode for most users, providing maintained conventional rules and advertising filters; Enhanced provides stronger application filtering and broader lists; Custom/Advanced enables full rule authoring. Ordinary use follows authorization, mode selection and background protection, with guided diagnosis and exceptions for misblocking; the Custom/Advanced label, exact presets and switching semantics remain undecided, and this product choice is distinct from Runtime Profile and rule binding mode.
_Avoid_: Root/VPN privilege level, rule execution mode, all users as rule authors

**Daemon lifecycle**:
Whether the native daemon process is running under the Android-side service owner. It is separate from daemon feature gates such as policy or observability switches.
_Avoid_: `block.enabled`, component gate, empty daemon mode

**Bounded Runtime Recovery**:
The Android RuntimeService policy for an unexpected active VPP runtime exit: clean profile-owned hooks, fds, sockets, and partial state, then attempt automatic recovery with bounded retries and backoff. Repeated failure within the configured recovery window stops further restart, releases Root/VPN resources, preserves diagnostics, and requires user intervention through the Visible Runtime Notification and product status. Exact thresholds are release-tested implementation constants, not ordinary-user settings.
_Avoid_: infinite crash loop, silent permanent stop after one fault, restarting without cleanup, UI Activity as restart owner

**Protection Pause**:
A user-requested clean stop of the active Runtime Profile and its packet-capture resources, with selected profile and saved configuration retained for restart. It differs from a healthy VPP management process awaiting correction of a startup policy error.
_Avoid_: pass-through pause, collecting packet activity while paused, guaranteed retained in-memory snapshot

**packet-pass-through**:
The base runtime capability that means the daemon can receive hooked IPv4 and IPv6 packets through its current packet capture Adapter and fail-open accept them. It is not an NFQUEUE Implementation name, listener-thread-started signal, or best-effort hook state; hook installation failure or unavailable setup for either family means the capability is not ready.
_Avoid_: `nfqueue-pass-through`, listener started, best-effort hook state, partial datapath readiness

**HELLO capabilities**:
The vNext `HELLO.capabilities[]` list of runtime capabilities that are currently usable by clients. Build-supported but failed, disabled, or not-ready capabilities are explained through Runtime health instead of appearing as usable capabilities.
_Avoid_: build feature list, error channel, planned module list, development milestone names such as `snort10-base`

**Runtime health**:
Low-cardinality status for active daemon runtime capabilities that explains whether each owned runtime capability is `ok` or `error`. Its reason codes are diagnostic and may name the failing active Adapter; dual-stack runtime capabilities should expose per-family status when one family can fail independently. Adapter completion failures are exposed rather than hidden by automatic retries. Functional Closure requires bounded failure evidence and a health-visible reason, but deliberately defers health latching/automatic-recovery timing and detailed Product UI presentation. Control Plane may remain available to report runtime health even when a runtime capability failed startup.
_Avoid_: capability list, metrics stream, telemetry records, daemon lifecycle

**Component gate**:
A daemon configuration switch that enables or disables a specific policy or observability component while the daemon process remains running.
_Avoid_: daemon lifecycle, process stop/start

**block.enabled**:
The device-level gate for verdict-affecting filtering work across domain and IP policy. It is not the daemon lifecycle switch.
_Avoid_: daemon stop, daemon idle mode

**Device / DX**:
The rooted Android integration lane driven by host and ADB scripts, split into smoke gates, diagnostics, and targeted device modules.
_Avoid_: old phase labels such as p0/p1/p2

### Domain Policy

**Application DNS Filtering / 按应用 DNS 过滤**:
The application-scoped domain-control behavior shared by Root and VPN, combining policy checks on reliably attributed DNS queries and their available CNAME answer evidence with subsequent connection checks using the connection's own application identity and available domain/address evidence. Query denial and connection denial are separate control outcomes.
_Avoid_: promising every lookup is intercepted before its answer, treating DNS allow as permanent connection permission, a separate rule-priority system

**DNS Query Decision**:
An actual allow/deny policy decision about forwarding a handled DNS request or delivering its answer, distinct from upstream resolution success and the verdict of a subsequent business connection.
_Avoid_: reporting connection denial as DNS denial, inventing a decision for a lookup that never reached product ingress

**Local DNS Resolution Exception**:
An explicit hostname or name-and-descendants routing selection that preserves the network-original or selected local resolver view while the configured default upstream applies elsewhere. Its routing role is distinct from permission to resolve a query or establish a connection.
_Avoid_: domain allowlist, complete automatic private-domain classifier, upstream-failure fallback, a second policy priority system

**DomainPolicy**:
Historical terminology for domain allow/block configuration at app or device scope. The current Application DNS Filtering model uses unified Policy Rules and DomainLists.
_Avoid_: a separate editable domain-policy model, stage-owned priority

**DomainRules**:
Historical domain-specific rules referenced by DomainPolicy payloads. Current domain conditions and lists belong to the unified Policy Rule/RuleGroup model.
_Avoid_: treating old wildcard/regex syntax as a current support promise, equating a DomainList entry with a policy rule

**DomainLists**:
A reusable named collection of domains that can be maintained by the user, imported as a snapshot, or refreshed from a subscription. A list may be consumed by DNS filtering or referenced by policy rules; its source and maintenance mode are distinct from the context that uses it.
_Avoid_: treating every domain list as a blocklist, equating a domain list with a policy rule, `BLOCKLIST.*`

**Domain List Import**:
A one-time addition of domain-list content from a file or another supported source, without establishing an automatic update relationship.
_Avoid_: subscription, automatic refresh

**Domain List Subscription**:
A maintained source relationship through which domain-list content can be refreshed from a subscribed file according to the user's update settings.
_Avoid_: one-time import, policy action, treating refreshed content as proof that a consuming policy is active

**policySource**:
A stable DNS-domain attribution enum that explains which DomainPolicy branch produced a DNS verdict.
_Avoid_: using it for IPRULES, packet, or Flow Telemetry verdict attribution

**DOMAIN_DEVICE_WIDE**:
The current name for domain-only device-scope allow/block policy sources.
_Avoid_: `GLOBAL_*`

**MASK_FALLBACK**:
The final DomainPolicy fallback that decides from the app mask and domain mask when explicit app or device-wide policy does not decide.
_Avoid_: default allow, global fallback

**Domain-IP Association**:
Evidence relating a DNS-learned domain to returned IP addresses within its network/resolver context, with known or unknown application provenance and validity independent of DNS answer-cache TTL. Only one admissible candidate supplies a fallback name for the selected TLS/QUIC/DTLS path or an HTTP/SOCKS request's IP target; multiple candidates remain observation evidence without establishing the actual flow domain or an unknown original DNS caller.
_Avoid_: DomainPolicy itself, Basic IPRULES matcher, RDNS, Host cache, direct SNI, guaranteed unique domain attribution

**HTTP Target Domain**:
A protocol-visible hostname identifying the effective target of one HTTP request, taken from the request target or Host as HTTP semantics require. It is a request-level direct fact distinct from earlier requests on the same connection, TLS SNI and DNS-derived association.
_Avoid_: Host as SNI, an email or authentication domain as the HTTP target, one name necessarily identifying every request in a flow

**SOCKS Target Domain**:
A direct hostname carried by a visible SOCKS4a or domain-address SOCKS5 request, identifying the requested remote destination separately from the proxy server. A DNS-derived name for an IP-only request is association evidence rather than this direct protocol fact.
_Avoid_: the proxy server's hostname as the requested target, protocol identification as target-name evidence

**Resolved-IP Policy**:
Historical terminology for connection enforcement using DNS-learned Domain-IP Association evidence. The current Application DNS Filtering direction uses applicable unified Policy Rules rather than an independent enforcement or priority system.
_Avoid_: ip-leak, IP link, Basic IPRULES, a separate DomainPolicy engine

### IP And L4 Policy

**IPRULES**:
Historical product terminology for IP packet rules. Use L4 Traffic Rule and Policy Rule for the current unified rule model; old IPRULES command shapes are not current API requirements.
_Avoid_: IPv4-only rules, mandatory legacy command compatibility

**NetworkContextId**:
The bounded platform-provided network category used by Network Gate: Android supplies Wi-Fi, Mobile, and VPN; Linux supplies Wired, Wi-Fi, Mobile, and VPN from reliable facts about the packet's actual interface, with unavailable classification remaining explicitly unknown. This category is separate from concrete interface matching and Runtime Profile, and the shared Product UI presents the platform's available categories.
_Avoid_: hard-coding Android columns into shared UI, unbounded user-created hot-path dimensions, ifindex as a persisted cross-reboot identity, Runtime Profile

**Network Context Snapshot**:
The event-driven platform facts used to associate a packet with a reliable NetworkContextId: Android VPN uses its bound underlying network, while Linux NFQUEUE uses the packet's actual ingress or egress interface. Concurrent networks retain their own classifications; the system default network does not replace a packet's actual network facts, and unavailable classification remains unknown.
_Avoid_: synchronous per-packet platform query, UI Activity state, VPN Runtime Profile as network context, guessing an unavailable context, treating every virtual interface as VPN

**Unknown Network Context**:
The explicit absence of a reliable NetworkContextId for the current packet. Network-dependent conditions are unavailable rather than false; other sufficient Boolean branches remain evaluable under the ordinary rule-availability contract.
_Avoid_: guessing Wi-Fi/Mobile/VPN, holding the packet for a platform query, skipping all policy, infrastructure bypass

**Network Gate**:
The application/network disabling control, represented in the unified model by a highest-priority ordinary DROP rule maintained by its configuration entrypoint. It has no independent matcher privilege or priority space.
_Avoid_: special backend Gate branch, separate policy family, Root/VPN selector

**L4 Traffic Rule**:
A policy rule using packet and available platform facts such as addresses, ports, protocol, direction and network context. Its physical execution position is chosen by the compiler in the complete effective rule set, not by its name.
_Avoid_: ACL as the user rule name, necessarily pre-flow, separate priority space

**Protocol Rule**:
A policy rule whose expression uses currently published application-protocol facts, optionally combined with other available facts. It competes under the same complete ordering as other applicable rules rather than in a separate protocol priority space.
_Avoid_: isolated verdict per recognized protocol, mandatory AppID-only template, flow termination action

**Policy Rule**:
A versioned logical condition with explicit precedence and a declared packet action, applied through an effective binding mode. Its full Boolean expression and whole-rule applicability determine matching; physical execution position adds no priority.
_Avoid_: compiler fragment, group winner, stage-owned verdict

**Rule Group (规则组)**:
A reusable collection of Policy Rules and child Rule Groups that can expose common conditions and whose overall observed effects can be inspected separately from individual members. Nesting is limited to three group levels, counting the outermost group as level one and excluding individual rules from that count; a group does not introduce an independent policy winner.
_Avoid_: Application Group, domain list, independent group verdict

**Rule Group Condition (规则组公共条件)**:
A group-level expression or editing facility for conditions shared by member rules. Whether it continuously constrains group use or only edits current member conditions remains under discussion in the [product baseline](docs/product/NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-02-规则组公共条件与设计依据).
_Avoid_: application-group membership, silently replacing a member rule's own condition, a new independent group verdict

**Rule Effects (规则执行效果)**:
Observed activity actually handled under a Policy Rule, interpreted within the selected time span and usage scope. These effects are distinct from whether the rule is currently in use and from merely satisfying its conditions.
_Avoid_: enabled status as execution evidence, candidate-match count, packet hits relabeled as connections

**Rule Group Effects (规则组整体效果)**:
Observed activity attributable to the use of a Rule Group within the selected time span and scope, including its nested members without counting duplicate references as additional executions. It is distinct from each member rule's effects across all of that rule's uses.
_Avoid_: sum of members' unrestricted totals, independent group verdict, application-group effects

**Application Group (应用组)**:
A collection of applications that can be selected as the common target of a Policy Rule or rule group. It represents which applications receive shared policy; naming, membership-change and overlap semantics remain under discussion in [the product baseline](docs/product/NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-01-用户确认的交互基线).
_Avoid_: rule group, domain list, merged application identity

**Application-specific Rule (应用专属规则)**:
A rule whose intended scope is one application. A change initiated inside that application applies only to it; sharing with other applications or an application group is a subsequent explicit choice.
_Avoid_: silently editing shared content for other applications, equating the editing entrypoint with shared scope

**Shared Rule (共用规则)**:
A rule jointly used by multiple applications or an application group. Shared and application-specific rules coexist in the product; they are not mutually exclusive operating modes.
_Avoid_: replacing all application-specific rules, requiring all rule work to start from a single entrypoint

**Effective Rule Set**:
The applicable rules for one application after group expansion and same-source, same-mode deduplication. All entries compete under one complete order regardless of their eventual execution position.
_Avoid_: one winner per group, duplicated multi-path occurrences, global cross-application verdict

**Match Result**:
A completed logical Match carrying winner identity, Rank, declared action, effective mode and attribution, or a completed NoMatch. It is reusable only under the matching input and snapshot guards.
_Avoid_: partial conjunction, infrastructure error as NoMatch, action-only cache

**Confirmed No SNI**:
An available fact from a valid completed SNI parse that found no SNI, within a flow already recognized as TLS, QUIC or DTLS with the applicable producer. Missing data, an unattempted parse, failure or exhaustion does not establish this fact.
_Avoid_: unrelated protocol traffic, empty string for every failure, timeout as absence

**Blocked Observation**:
A bounded observation instance for actual pre-flow policy drops, with cumulative accounting and attribution and its own idle-ended lifecycle. It is independent of FlowEntry and never causes CT/LPI or stream processing for a dropped packet.
_Avoid_: flow allocation, rule identity as instance identity, upgrading the object into a Flow

**Policy Readiness**:
The presence of a successfully compiled and published policy snapshot required before product traffic capture can begin. A healthy rule-management API may remain available for user repair when this condition is false; platform and Adapter readiness are separate requirements.
_Avoid_: process alive equals protection, compiler failure ends all management, old snapshot survives process restart

**Policy Rule Family**:
A descriptive grouping by predicate capability within the unified policy model. Such grouping does not create independent precedence, default actions or separately applied policy.
_Avoid_: stage-owned priority, special Gate privilege, separate frontend databases

**Enforcement Stage**:
A physical rule-execution position before or after the required flow/fact processing. Position constrains available inputs but does not add priority or permit splitting a logical rule across positions.
_Avoid_: user-selected rule type, independent winner space, partial-rule continuation

**Compiled Policy View**:
An immutable execution projection belonging to a complete Runtime Snapshot. Different pre-flow and post-flow representations preserve the same effective-rule ordering, source attribution and snapshot identity.
_Avoid_: authoritative source configuration, independently edited stage table, local re-ranking

**Stage Verdict**:
Historical DROP/PASS_NEXT stage outcome. The unified rule design instead preserves a complete Match or NoMatch result, with an early winner retaining its logical precedence through later required processing.
_Avoid_: early ALLOW loses its winner, lower-ranked post-flow rule overrides a proven early winner

**Policy Verdict**:
The actual packet-policy ALLOW or DROP produced from the logical winner and effective mode, or default ALLOW after a complete NoMatch. It is separate from runtime failure and transport outcome; policy not evaluated remains distinguishable.
_Avoid_: NFQUEUE completion result, delivery guarantee, infrastructure bypass as policy ALLOW

**Policy-Qualified Packet（有效策略处理包）**:
A captured network packet whose applicable policy evaluation has completed and whose Adapter Completion is `SUCCEEDED`. Normal policy ALLOW and DROP qualify; infrastructure bypass, runtime-drop without a Policy Verdict, unadmitted traffic and internal END/completion carriers do not.
_Avoid_: admitted packet, endpoint-delivered packet, fail-open accept, FlowEnd signal counted as a network packet

**Runtime Disposition**:
The shared dataplane's terminal handling of a packet after accounting for both Policy Verdict and runtime faults. A runtime fault may discard a packet without creating a policy `DROP`.
_Avoid_: policy reason, Adapter completion, transport delivery result

**Adapter Completion**:
The exactly-once terminal operation and single physical attempt by the active Packet capture Adapter to release, discard, or otherwise finish its platform-owned packet obligation. Its outcome is `SUCCEEDED` when the Adapter's platform-defined terminal operation reports successful completion, `FAILED_DEFINITE` when that operation is known not to have completed, or `OUTCOME_UNKNOWN` when no trustworthy terminal result is available. An observed successful terminal result is not downgraded merely because the platform provides no additional acknowledgement. `SUCCEEDED` proves only Adapter-operation completion, not later transport delivery, downstream traffic success, or end-to-end behavior. The first release performs no automatic completion retry for any outcome: failure or uncertainty is accounted and surfaced through Runtime health, never re-enters VPP, and never re-evaluates policy. The outcome does not rewrite the Policy Verdict or Runtime Disposition.
_Avoid_: policy verdict, proof of end-to-end delivery, VPN transport outcome, automatic retry, graph recirculation, policy re-evaluation

**Buffer-Resident PacketLease**:
The first-release VPP-internal ownership model aligned with the modified VPP's buffer/opaque-metadata conventions: while a packet is being processed by the VPP graph, its live VPP buffer is the physical PacketLease carrier. Fixed hot-path fields are stored inline as a common ownership header plus Adapter-private fields. VPP nodes and worker queues move the buffer index rather than copying packet bytes. This is a C/VPP ownership mechanism, not a Rust owner type. Rust does not run VPP graph nodes and does not reconstruct a Rust owner on VPP worker handoff. The fork's deprecated NFQUEUE plugin is not an implementation reference.
_Avoid_: Rust `LocalPacket` inside the VPP graph, Rust-native VPP worker handoff, independent lease table, second packet buffer, payload copy, per-packet heap allocation, treating the deprecated NFQUEUE plugin as production evidence

**Rust–VPP Compatibility Boundary**:
The coarse-grained non-unwinding C ABI through which Rust controls VPP lifecycle, configuration, policy snapshots, status, and diagnostics. Individual packet bytes, live VPP buffers, Adapter Completion, and worker handoff remain inside VPP-native Packet capture Adapters and never cross this boundary.
_Avoid_: per-packet Rust callback, Rust-owned platform packet I/O, Rust VPP nodes, Rust buffer return bridge, simultaneous Rust and VPP packet ownership

**VPP Buffer Return Boundary**:
The VPP-native ownership transition that returns a completed live buffer through its native chain, reference, metadata, callback, cache, and pool lifecycle after Adapter Completion. It remains inside the dataplane and creates no Rust packet owner, second pool, independently exhaustible return resource, or packet-byte copy.
_Avoid_: Rust buffer-return wrapper, fallible `try_return`, second reclamation pool, return retry, bypassing native free callbacks, packet-byte copy

**PacketLease Capacity Invariant**:
The fixed-pool conservation rule for Buffer-Resident PacketLease ownership. Every live VPP buffer checked out from the one preallocated pool implicitly carries its right to return; the pool may be empty at ingress allocation, but a valid checked-out buffer cannot make the pool expand, shrink, become negative, or reject its return for capacity. Every decided buffer, including policy `DROP`, remains live through native Adapter Completion and then returns through the VPP Buffer Return Boundary. Failure to obtain the initial ingress buffer is the only pool-capacity failure and occurs before policy processing.
_Avoid_: separate return credit, second packet buffer, independently bounded return capacity, ordinary return failure/retry/fallback, policy `DROP` local free, releasing a buffer before its Platform I/O Lane consumes it

**Completion Frame**:
A bounded VPP-native batch of original buffer indexes carrying terminal Runtime Dispositions from Flow owners to the originating Platform I/O Lane. It transfers ownership metadata, not packet bytes, so the origin lane can perform thread-affine platform completion and native buffer return.
_Avoid_: Rust packet bridge, second packet buffer, payload copy, per-packet heap object, policy re-entry, shared platform handle

**Event-Driven Adapter Completion**:
The completion scheduling rule under which a native Platform I/O Lane blocks only when no immediately runnable work remains and receives reliable, coalesced notification when new work requires attention. A notification is a reason to inspect work, not a packet count, ownership settlement or delivery acknowledgement.
_Avoid_: busy polling as idle behavior, periodic polling as a missed-wake repair, wake per packet, deliberate batching delay, treating a design decision or historical wake POC as device/release acceptance

**Packet Ownership Integrity Violation**:
A duplicate, invalid, misrouted, or stale-generation buffer ownership operation that makes the runtime unable to prove the fixed pool's ownership conservation. It is a fatal memory-integrity condition comparable in severity to detecting a possible double-free, use-after-free, or out-of-bounds access; it is not an Adapter failure or a recoverable buffer-return result. The affected dataplane runtime has no trustworthy continue path.
_Avoid_: retrying the return, dropping the index and continuing, reporting it as pool exhaustion, rewriting Policy Verdict or Adapter Completion

**Rust/VPP Control ABI Boundary**:
The non-unwinding coarse-grained compatibility boundary used for control, configuration, status, and immutable policy publication between Rust and C/VPP. Expected failures cross as explicit status values; packet bytes and live buffer ownership do not cross, and Rust panic or foreign-language exceptions never unwind through the ABI.
_Avoid_: per-packet FFI, `extern "C-unwind"`, panic as ordinary error handling, Rust-owned VPP buffer lifetime

**Completion Failure Accounting**:
The first-release bounded evidence for `FAILED_DEFINITE` and `OUTCOME_UNKNOWN` Adapter Completion, partitioned only by low-cardinality outcome, Adapter/channel, and stable operation-path reason. It increments counters and retains bounded first/last occurrence diagnostics so native errors, deterministic rejections, bridge, buffer, or configuration faults can be found and fixed. The failure reason is available to Runtime health, while exact health clear/latch behavior and detailed Product UI treatment are deferred beyond Functional Closure. The two non-success outcomes remain separate so uncertainty is never presented as proof of loss, while operation success is never presented as proof of later delivery. Accounting does not synchronously log every failed packet, retain packet payload, allocate per-packet failure history, or trigger automatic retry.
_Avoid_: retry mechanism, unbounded failure ledger, per-packet synchronous logging, packet payload retention, hiding a broken channel

**Transport Outcome**:
The post-policy forwarding result for traffic whose Runtime Disposition permits platform transport, notably VPN traffic handed to the VPN Userspace Flow Stack. `UNSUPPORTED` or `FAILED` remains distinct from policy `DROP` and Adapter Completion.
_Avoid_: policy verdict, runtime disposition, treating allow as proof of delivery

**VPN Flow Stack Packet Boundary**:
The packet-data handoff between the shared VPP graph/canonical FlowOwner and the VPN Userspace Flow Stack, with independent storage on each side of the accepted input/output copies. It is distinct from Adapter Completion and transport delivery: TUN-origin traffic enters the owner-local Flow Stack, while flow-stack-origin packets return through the shared graph.
_Avoid_: shared buffer lifetime, asynchronous borrowed input buffer, VPN Completion Boundary, HEV descriptor seam, treating Flow Stack acceptance as end-to-end delivery, direct Flow Stack-to-TUN return

**Platform I/O Lane**:
A VPP-native, event-driven Packet capture Adapter execution lane that exclusively operates its assigned platform fd or queue set for receive and Adapter Completion. A Root lane owns one NFQUEUE queue/socket; the initial VPN lane owns transferred TUN ingress and terminal TUN-completion authority. It materializes ingress into VPP-owned storage, submits work to the shared graph, regains terminal buffers through bounded Completion Frames, performs platform completion, and returns buffers through the native VPP lifecycle.
_Avoid_: Rust-owned packet lane, shared fd across concurrent owners, central NFQUEUE gather thread, busy polling, packet-byte return copy

**Root Completion Boundary**:
The ownership boundary at which the native origin NFQUEUE lane regains decided packets in Completion Frames and performs one NFQUEUE-defined terminal verdict operation for each using the original queue generation and packet ID. A reported successful terminal result is `SUCCEEDED`; a known rejection or failure is `FAILED_DEFINITE`; absence of a trustworthy terminal result is `OUTCOME_UNKNOWN`. This records only completion of the NFQUEUE operation, not a separate acknowledgement, later host/network delivery, or downstream traffic success. The lane then performs native VPP buffer return.
_Avoid_: end-to-end delivery claim, retrying an ambiguous netlink result, transport outcome owned by Sakamoto

**Lane-Owned NFQUEUE Completion**:
The Root threading rule that one native NFQUEUE Platform I/O Lane is the sole caller for receive and verdict operations on its netlink queue/socket. Flow owners never call a shared `nfq_q_handle`; they return terminal intents and original live VPP buffer indexes to the origin lane, which submits the original queue generation and packet IDs and then performs native buffer return. This completion routing is not owner distribution and never copies packet bytes.
_Avoid_: cross-worker `nfq_set_verdict`, `nfq_set_verdict_batch` for mixed or out-of-order decisions, shared socket mutex on the hot path, second completion buffer, wake per packet, freeing a buffer before its lane consumes completion

**NFQUEUE Verdict Datagram（判决数据报）**:
A Netlink datagram carrying one or more independently framed `NFQNL_MSG_VERDICT` messages, each retaining its original packet ID and verdict. The 2026-10-12 experimental C sender groups only already-ready work from one origin lane/generation with the same syscall flags in the existing bounded window. Scalar, sendmmsg and packed modes share that window; the experiment remains default OFF until qualified comparison establishes adoption. This differs from `sendmmsg`'s multiple datagrams and from `NFQNL_MSG_VERDICT_BATCH`'s same-verdict ID range. See the [Root verdict memo](docs/memos/ROOT_NFQUEUE_VERDICT_OPTIMIZATION_MEMO.md).
_Avoid_: rewriting the first child message length to the aggregate datagram length, waiting for future packets, mixed-verdict range completion, treating a full byte-count return as independent kernel confirmation of every message

**Infrastructure Fault**:
A bounded runtime, Adapter, completion, or transport failure fact that explains why packet execution could not follow its normal path. It may coexist with a Policy Verdict and must never be attributed to a policy rule.
_Avoid_: policy drop reason, synthetic rule match, generic final verdict

**Packet Processing Capacity Fault Policy**:
The cross-profile fail-open rule for bounded pre-policy processing exhaustion: no Policy Verdict is created, Root releases the packet through NFQUEUE, and VPN bypasses policy processing into its normal transport. A subsequent VPN transport-capacity failure is a separate failed Transport Outcome and may still lose the packet.
_Avoid_: policy allow, policy drop, unbounded buffering, claiming VPN delivery when transport failed

**Fail-Open Reserve**:
A startup-fixed, worker-local, bounded set of VPP-owned ingress buffers reserved for each active ingress lane so the Packet Processing Capacity Fault Policy remains executable during transient exhaustion of normal VPP ingress buffers without introducing an Adapter scratch-buffer copy or cross-worker contention. Its per-lane count is selected from the production capacity matrix using measured peak concurrent occupancy, burst duration, exhaustion, RSS, latency, and target-profile evidence; no POC count is part of this contract. Each reserve buffer follows the independently accepted Contiguous Parser Envelope, currently 9000-byte VPP buffer data in the first Android release. These buffers are withheld from the already allocated VPP pool rather than allocated as an additional pool. A reserve packet bypasses parser, flow, and policy work: Root uses its completion identity to submit `ACCEPT`, while VPN may continue only through the normal VPN Flow Stack Packet Boundary and its selected capacity-fault contract, never through a direct HEV bypass or alternate ownership channel. The reserve buffer is settled exactly once by the applicable platform or Flow Stack boundary. Reserve exhaustion never triggers dynamic growth or blocking; the packet is explicitly lost, bounded lane-level capacity-fault evidence is accumulated, and Adapter/runtime health is degraded. The reserve is a best-effort overload mechanism, not a guarantee of connectivity under memory exhaustion or transport failure.
_Avoid_: one shared contended reserve, whole-frame reservation, general-purpose packet pool, policy evaluation on reserve packets, unbounded emergency allocation, blocking for reserve capacity, claiming guaranteed fail-open delivery

**L4 Priority Level**:
The user-defined priority value retained in the unified effective rule ordering, with lower values preceding higher values. Explicit order and stable logical rule identity resolve ties across all applicable rule conditions.
_Avoid_: separate L4/protocol priority spaces, mask specificity as hidden priority, physical stage priority

**L4 WinnerRank**:
The compact ordering of an effective application rule set by priority, explicit order and stable logical rule identity. Pre-flow and post-flow programs preserve that same order.
_Avoid_: stage-local re-ranking, match specificity, persisted authoring priority

**L4 SubjectView**:
The compiled effective policy view selected by the platform's application subject identity. Its compatible pre-flow and post-flow programs preserve one logical ordering; other packet and network facts remain matching inputs rather than independent policy authorities.
_Avoid_: package-name partition, subject multiplied by Network/Direction/Protocol contexts, wildcard-rule replication across outer buckets

**L4PolicyMatcher**:
The deep Module Interface that compiles and evaluates the Packet/L4 Compiled Policy View while hiding priority contexts, mask partitions, hashes, and residual range checks. Its result carries rule identity, action, and source attribution; callers do not depend on pool indexes or hash layout.
_Avoid_: VPP ACL as the product policy schema, UI selecting a matcher, matcher-owned authoring rules

**Basic IPRULES**:
Historical term for policy using packet facts without CT-dependent conditions. In the current vocabulary this is expressed by L4 Traffic Rules within the unified effective rule set.
_Avoid_: independent policy priority space, necessarily early execution

**Stateful IPRULES**:
Historical term for policy using CT facts such as state and flow direction. The current model treats these as conditions in ordinary policy expressions.
_Avoid_: separate CT verdict stage, fixed priority over protocol conditions

**PacketFacts**:
Packet-local facts derived once by the shared VPP packet parser from the original L3 packet, then shared by packet policy and observation consumers. PacketFacts do not contain platform ingress facts, domain hints, Conntrack state, DPI identification results, or Adapter-specific transport handles.
_Avoid_: Host object, per-module parser state, Domain-IP Association facts, NFQUEUE-only facts

**Platform Packet Facts**:
Packet-local platform evidence, including available application identity, Linux interface index, NetworkContextId, Device Packet Direction, and VPN Packet Provenance, normalized at capture or restored for a reconstructed packet. Availability is explicit and reassembled datagrams use the offset-zero fragment's facts without filling its unknown fields from other fragments; queue, lane, file descriptor, completion identity, Runtime Profile, and speculative deployment domains are excluded and never select ExecutionOwner or FlowOwner.
_Avoid_: untyped packet hints, zero means unknown, first-arriving fragment as offset-zero fragment, cross-fragment fact merging, queue as policy fact, VPP sw_if_index as Linux ifindex, Runtime Profile as packet direction, provenance hidden in interface identity

**VPP Packet Validation Outcome**:
The pre-policy content-validity result produced by the shared VPP graph using the modified VPP fork's validation semantics. An invalid L3 envelope, including an invalid IP version, header shape, or declared length, is runtime-dropped with no Policy Verdict. A valid L3 packet for which deeper L4 facts are unavailable or unsupported is not invalidated merely for that reason: PacketFacts preserves the parser status and available facts, predicates requiring unavailable facts do not match, and the remaining evaluable stages continue.
_Avoid_: Adapter-side validation policy, fail-open invalid L3, policy-rule DROP, treating unsupported L4 as malformed L3, inventing ports or a synthetic flow

**Packet capture Adapter**:
The platform ingress and completion channel that transfers a received L3 packet into the shared VPP graph without interpreting its packet-policy meaning, supplies Platform Packet Facts, and later executes the resulting platform completion. Packet parsing, PacketFacts construction, flow ownership, and policy decisions belong to the shared VPP dataplane.
_Avoid_: policy engine, packet parser, PacketFacts builder, verdict pipeline

**Ingress Completion Identity**:
The Adapter-specific mandatory identity needed to form a PacketLease and later execute exactly one terminal platform completion, notably NFQUEUE queue instance/generation plus packet ID. An ingress event missing that identity is rejected at the Adapter boundary: it creates no PacketLease, does not enter VPP, and produces no Policy Verdict or fabricated Adapter Completion outcome. The Adapter records bounded `INGRESS_IDENTITY_MISSING` Infrastructure Fault evidence and exposes a health reason. Kernel queue fail-open or bypass may independently preserve traffic, but Sakamoto cannot claim that it submitted or proved `ACCEPT` for that packet.
_Avoid_: synthetic packet ID, guessing or scanning for an obligation, anonymous VPP injection, retry, claiming kernel acceptance without a terminal verdict operation

**Complete L3 Packet Ingress**:
The current local-endpoint requirement that Android Root/NFQUEUE, Android VPN/TUN, and Linux NFQUEUE transfer the complete received L3 packet into VPP so fragment, IPv6 extension, and future early-flow inspection semantics are established without capture truncation. Bounded-prefix NFQUEUE copy remains a later measured optimization and is not part of the closure contract.
_Avoid_: 512-byte correctness assumption, Adapter-side truncation baseline, treating original length as available packet bytes

**User-Space Single Materialization**:
The packet-ingress performance contract that, after the unavoidable kernel-to-user boundary, the complete L3 bytes are received directly into VPP-owned buffer data and processed in place rather than first landing in an Adapter scratch buffer and then being copied wholesale into VPP. TUN should read directly into a preallocated VPP buffer or chain, and NFQUEUE should receive the netlink datagram into VPP-owned ingress storage and project the contained L3 span without a second full-packet copy. Metadata normalization and small fixed-field copies are permitted. This is not a claim of absolute kernel zero-copy or of end-to-end transport zero-copy. A platform/API-specific full-copy fallback requires POC evidence that direct materialization is infeasible, measured cost, and a new explicit design decision; it must not appear silently as Adapter convenience code.
_Avoid_: shared full-packet scratch buffer, Adapter-to-VPP `memcpy`, absolute zero-copy marketing claim, rejecting VPP buffer chains, unmeasured fallback copy

**VPN Egress Copy Minimization**:
The performance goal of minimizing payload copies while preserving bounded independent ownership and exactly-once settlement, with the VPP-to-lwIP and lwIP-to-VPP copies accepted as the current baseline. This is neither an absolute zero-copy promise nor a claim that the entire protocol/kernel path performs only two memory movements; additional full-payload copies still need a named reason and measurement.
_Avoid_: absolute zero-copy contract, copy-free marketing claim, unmeasured copying, async borrowed pointer, unbounded buffer loan, ownership complexity pursued without measured benefit, treating every copy as an architecture violation

**VPP Packet Byte-Movement Contract**:
The contract that normal packet-domain processing and worker distribution transfer ownership and metadata without copying, cloning, or reserializing complete packet bytes. Protocol-required byte movement or content retention, including reassembly, requires a named, measured exception with explicit capacity/lifetime budgets and only the minimum necessary content; protocol identification alone grants no such exception.
_Avoid_: per-node packet clone, worker-to-worker payload copy, telemetry packet copy, implicit recognizer retention, unbounded payload history, using an exception to bypass User-Space Single Materialization

**Contiguous Parser Envelope**:
The first-release compatibility envelope inherited from the modified VPP `flow_dissector`: packet headers and the declared packet span presented to the parser must fit the contiguous current VPP buffer. Android Functional Closure inherits the fork's 9000-byte VPP buffer data size and initial default pool sizing rather than first shrinking buffers or adding chain-aware parsing; buffers are startup pool objects recycled according to concurrent occupancy, not allocated in proportion to cumulative traffic volume. The VPN Profile fixes the Android TUN MTU at 1500 bytes; the compatible packet envelope at the VPN Flow Stack Packet Boundary remains evidence-selected. The IPv6 minimum MTU of 1280 is only a future compatibility fallback triggered by device/path evidence, not the baseline; values below 1280 are outside the supported dual-stack profile. Buffer count or data-size tuning requires measured RSS, occupancy, and overload evidence after the functional path runs. The release does not pre-design Linux GSO/jumbo handling, choose `NFQA_CFG_F_GSO` policy, alter system/NIC offload configuration, add chain-aware parsing, or linearize full packets. If a packet nevertheless exceeds the envelope, existing length validation must prevent partial interpretation; it receives no Policy Verdict, Root completes `ACCEPT` under the local fail-open rule, and bounded generic `UNSUPPORTED_CONTIGUOUS_ENVELOPE` evidence is recorded. Linux GSO/jumbo support and possible operator mitigation such as disabling interface GSO require later real deployment evidence and a new decision.
_Avoid_: claiming the modified dissector is chain-aware, silent partial parsing, current-release GSO architecture, automatic host `ethtool` mutation, full-packet linearization, premature chain-parser complexity

**Packet Byte Mutation Authority**:
The explicit graph permission required to alter or synthesize packet bytes. Normal parser, policy, session, protocol-identification, distribution, and observation nodes are read-only and must pass the same unmodified L3 bytes onward. Root `ACCEPT` submits only the NFQUEUE verdict and never a replacement payload; VPN policy passes the unmodified packet to the VPN Flow Stack Packet Boundary. Only a named node whose network semantics require byte changes, such as fragment/TCP reassembly, an explicitly enabled future NAT, or packet synthesis, may receive mutation authority and own the resulting checksum, length, capacity, and evidence contract. Temporary edit-and-restore by an ordinary node is still mutation and is forbidden.
_Avoid_: implicit header edit, NFQUEUE replacement payload, mutate-then-restore parsing, policy-owned NAT, observation-side packet rewrite, treating writable memory as permission

**Packet capture Adapter Conformance Contract**:
The shared semantic acceptance contract for Android Root/NFQUEUE, Android VPN/TUN, and Linux NFQUEUE Adapters. They transfer the received L3 packet unchanged under User-Space Single Materialization, provide equivalent normalized Platform Packet Facts and original packet length, and preserve PacketLease exactly-once completion, fault handling, shutdown, and recovery around the same VPP packet runtime. Adapter-specific performance limits and documented platform constraints may differ, but packet parsing, policy semantics, Primary Software Distribution, and worker-owned state do not.
_Avoid_: separate Root/VPN policy behavior, queue- or fd-owned session state, declaring one Runtime Profile complete from pass-through alone

**Adapter Teardown Barrier**:
The bounded stop, pause, crash-cleanup, or Runtime Profile switch sequence for an active Packet capture Adapter. It first quiesces new ingress, then gives existing PacketLeases a fixed short drain deadline while completion and VPN transport remain available, and only afterward tears those channels down. Leases with an existing Policy Verdict complete that result. At the deadline, ordinary Root/NFQUEUE leases that have no Policy Verdict are accepted when their kernel identity can still be completed; ordinary VPN leases that can no longer be transported are released with explicit completion or Transport failure evidence. Previously classified non-fail-open runtime faults, including failed fragment reassembly and a repeated owner mismatch, retain their runtime-drop disposition. No recovery queue or replay crosses Adapter generations.
_Avoid_: closing completion before quiescing ingress, unbounded drain, new policy work after teardown, replay into a replacement runtime, changing an existing Policy Verdict, fail-opening fragment or repeated-owner faults

**VPN Transport Contract**:
The Android VPN Profile's post-policy forwarding capability. The first release requires production-proven IPv4/IPv6 TCP and UDP completion through the VPN Userspace Flow Stack. ICMP Echo is advertised only when the Sakamoto HEV Fork and device acceptance tests prove it; other IP protocols may still be matched, blocked, and observed by VPP but are not promised to forward after an allow verdict. Policy Verdict and Transport Outcome remain separate facts, so an unsupported or failed transport is never reported as a policy-rule drop. The product does not expand the stack merely to claim all-IP forwarding.
_Avoid_: claiming all-IP VPN forwarding, transport failure reported as firewall block, unverified capability, expanding the stack for unsupported protocols

**CtFacts**:
Conntrack-derived facts for the current packet and flow/session, such as `ct.state` and `ct.direction`, available only after the packet path enters L4 Conntrack. CtFacts are policy inputs, not an accepted-flow ledger.
_Avoid_: PacketFacts, packet cache, verdict history

**DpiFacts**:
Future flow/session-level protocol identification facts attached to the worker-owned FlowEntry or later Session state. DpiFacts require stable flow identity but do not require the Android L4 Product Release to implement full Conntrack, and they are not packet-local protocol guesses.
_Avoid_: IP protocol number, Traffic Windows protocol Top-K, standalone DPI cache

**Hot-path capability summary**:
A compiled hot-path summary of which policy or observation consumers are needed for a packet subject, such as Conntrack, future DPI, Traffic Windows, Domain-IP Association, or debug evidence. It is the shared gate input for stage and fact acquisition, not a per-module rule scan.
_Avoid_: scanning rules on every packet, enabling advanced facts globally

**family**:
The explicit IPRULES rule field declaring `ipv4` or `ipv6`; it is not inferred from `src` or `dst`.
_Avoid_: `family=any`, no-family IPv4 default

**matchKey**:
The canonical rule match identity used for duplicate-match warnings, explicit conflict checks, and apply-result mappings. The current form is `mk2`, which includes `family` and match dimensions but excludes action, priority, rule ids, and stats.
_Avoid_: treating `clientRuleId`, `ruleId`, or priority as part of the match identity

**clientRuleId**:
Historical caller-side correlation identifier from older authoring contracts. The current rule-version model uses a stable logical identity and a complete version identity without requiring a second daemon-assigned identity scheme.
_Avoid_: second authoritative rule identity, mandatory remapping layer

**ruleId**:
The complete identifier of a particular rule version, containing a stable logical-rule portion and a revision portion. A complete identifier cannot be rebound to different rule content; compiled indexes and Rank are separate execution details.
_Avoid_: array index, reusable version number, latest rule contents as historical contents

**Policy Binding Mode**:
The `enforce|observe` choice on a direct complete-Linux-UID binding to a rule or rule group. Rule-group internal references are structural and do not carry an observe/enforce choice.
_Avoid_: per-rule observe state, group-internal observe override

**Policy Binding Mode Conflict**:
A source-graph conflict where one complete Linux UID makes the same source rule applicable with both enforce and observe effective modes. Same-mode multi-path references to the same rule are not conflicts.
_Avoid_: automatic mode precedence, treating same-rule multi-path references as cycles

**Duplicate Match Warning**:
A non-blocking commit or preflight warning where one complete Linux UID would receive multiple distinct source rules with the same matchKey. It is surfaced clearly to the user but does not make the policy invalid, does not require a daemon/control-plane confirmation token, and does not alter the rule family's deterministic winner selection.
_Avoid_: commit failure, source graph conflict, hidden dedupe of distinct rules

**Rule execution mode**:
The effective packet-side mode of a rule occurrence, inherited from the complete-Linux-UID policy binding that made the rule applicable. Enforce applies the rule's declared action; observe records the same winner attribution but leaves the actual verdict allow.
_Avoid_: treating shadow evaluation as only an external debug session

**Rule hit counters**:
Packet-side counts attributed once to the final logical winning rule, with its version and effective mode. Cache reuse and compiler fragments do not multiply hits, and default ALLOW has no invented winner.
_Avoid_: candidate count, fragment hits, exported messages as packet hits

**wouldRuleId / wouldDrop**:
Legacy would-match fields from the old packet stream model. The refactored packet-side rule model should use `ruleId` plus effective rule execution mode instead of a parallel would-match attribution shape.
_Avoid_: new observe-mode attribution, compatibility-driven API design

**reasonId**:
Packet verdict attribution such as `IFACE_BLOCK`, `ALLOW_DEFAULT`, `IP_RULE_ALLOW`, or `IP_RULE_BLOCK`.
_Avoid_: treating reasonId as the actual verdict itself

**IFACE_BLOCK**:
A high-priority packet verdict caused by interface-kind mask policy, not by an IPRULES rule hit.
_Avoid_: IP rule block

**L4 Conntrack**:
The userspace connection state layer that provides flow identity, orig/reply direction, and `new/established/invalid` semantics for advanced policy and observation. It updates its own flow/session state once the packet path enters CT; complete Linux UID is packet/session attribution used by subject-scoped policy and capability gates, not the CT flow identity. CT is not a baseline dependency, Traffic Windows dependency, or verdict-gated accepted-flow ledger.
_Avoid_: packet cache, exact cache, accepted-flow ledger, Traffic Windows basic tier, ordinary-user default feature

**ct consumer**:
An active policy or observation consumer that makes a packet subject pay the L4 Conntrack acquisition cost, such as `ct.*` rules, `dpi.*` rules, full-flow telemetry, or gateway mode. CT consumers are subject/app-level gates, not per-rule cheap-precondition gates.
_Avoid_: unconditional per-packet CT, per-rule CT gate, ordinary Basic IPRULES

**CT acquisition gate**:
Eligibility for necessary flow/CT maintenance on the actual packet path. It does not override true pre-flow DROP or impose an additional application-wide observation requirement on automatic rule placement.
_Avoid_: observe dropped packets to reconstruct full CT history, global CT enable

**Unified CT entry**:
The single flow/session state record owned by L4 Conntrack for a given observed flow. Flow Telemetry counters, DPI state/results, debug/export state, and other flow-level attachments hang from this entry rather than creating separate per-consumer CT tables.
_Avoid_: DPI-specific CT table, telemetry CT table, duplicate flow tables

**Per-worker flow ownership**:
The target VPP runtime rule that one worker privately owns the mutable state of one bidirectional flow. Adapter-specific Initial Execution Placement is not ownership. Primary Software Distribution computes the final owner once on the ingress execution context and either continues locally or performs one Primary Handoff before owner-sensitive state. Downstream owner-local nodes use the current VPP worker directly and do not run a second owner calculation or corrective dispatch.
_Avoid_: shared authoritative flow table, queue id as owner, INPUT/OUTPUT thread as correctness

**Canonical Owner Key**:
The direction-independent key used to select an ExecutionOwner for every valid IPv4/IPv6 packet. All three explicit shapes contain key kind, IP family, terminal IP protocol, and the canonical address pair. `L4_PORTS` adds canonical typed ports for complete TCP/UDP; `ICMP_QUERY` adds a normalized Echo query class and identifier for supported ICMPv4/v6 request/reply pairs. Echo sequence is only a packet fact. Other legal protocols and valid L3 packets with unavailable transport identity use `L3`, without invented zero ports. Platform, deployment, direction, queue, interface, UID, Runtime Profile, provenance, CPU, and network-namespace facts never participate.
_Avoid_: treating every owner key as a five-tuple, zero-port synthetic flow, protocol-free address hash, CPU-aware packet hash, `flow_domain`

**OwnerAssignment**:
The one immutable result of canonicalizing shared PacketFacts and selecting an equally participating logical worker from the startup-fixed Worker Layout. It contains the typed key, canonical hash, ExecutionOwner and a source-side projection; downstream nodes consume the saved result without parsing, endpoint comparison, rehashing or corrective dispatch. Invalid L3 has no valid assignment and is runtime-dropped in its current execution context.
_Avoid_: platform-specific selectors, packet sequence as session identity, recomputing owner at each node

**ExecutionOwner**:
The VPP logical worker selected once from a Canonical Owner Key and the runtime-start-fixed Worker Layout. Every valid IPv4/IPv6 packet has an ExecutionOwner even when it is not eligible for a FlowEntry. The assignment remains stable for the active runtime generation, drives the sole Primary Handoff when the selected worker differs from Initial Execution Placement, and does not imply transport support or flow-state creation.
_Avoid_: arrival worker, VLIB thread index, Linux CPU ID, NFQUEUE lane, FlowEntry eligibility, overload spill target

**FlowOwner**:
The ExecutionOwner associated with a typed bidirectional session identity: complete TCP/UDP uses `L4_PORTS`, and supported ICMP Echo uses `ICMP_QUERY`. This identity can feed the later FlowEntry/tracker; an assignment does not itself create an entry or implement an ICMP tracker. L3-only fallback has an ExecutionOwner without synthetic flow state.
_Avoid_: ownerless ICMP/ESP/GRE execution, every packet creates flow state, separate FlowEntry hash-to-worker decision

**Canonical Flow Key**:
The typed direction-independent session identity supplied by OwnerAssignment: `L4_PORTS` for complete TCP/UDP or `ICMP_QUERY` for supported Echo query/reply traffic. Both explicitly retain family and terminal protocol; Echo identity includes its normalized query class and identifier, never sequence or fake transport ports. L3 fallback is not a FlowEntry key. Complete Linux UID, ApplicationSubjectId, NetworkContextId, Linux interface index, VPP interface index, queue, lane, Runtime Profile, VPN Packet Provenance, CPU, and network namespace never participate. Linux v1 runs only in the network namespace that owns its NFQUEUE Adapter; namespace isolation is a deployment boundary rather than a per-packet discriminator.
_Avoid_: UID-aware handoff, directional tuple, four-tuple hash that omits IP protocol, queue affinity as flow identity, network namespace discriminator, `flow_domain`

**Device Packet Direction**:
The packet-local `INPUT` or `OUTPUT` direction relative to the protected host/device, normalized by each Packet capture Adapter. It is used by stateless L4 direction predicates, platform activity, and interface/network context. It does not define flow orig/reply direction.
_Avoid_: Flow Direction, canonical endpoint order, client/server role, queue direction

**Flow Direction**:
The `ORIG` or `REPLY` direction relative to the first packet that creates a worker-owned FlowEntry or later Session. The creating packet is `ORIG`; packets with reversed endpoints are `REPLY`. This semantic is independent of Device Packet Direction and canonical endpoint sorting. A flow picked up midstream retains first-observed creation semantics rather than inferring or rewriting client/server roles. Protocol-identification direction uses this stable flow-relative orientation.
_Avoid_: INPUT means ORIG, OUTPUT means ORIG, lexical endpoint direction, client/server heuristic, direction rewrite after SYN inference

**Session Role Direction**:
The future full Session Manager's protocol-aware `C2S` or `S2C` role classification, following the inspected VPP fork's TCP SYN/SYN-ACK, configured UDP server-port, and ICMP request/reply evidence. It is distinct from first-observed Flow Direction and may remain unknown when role evidence is unavailable; adding or refining it never rewrites completed packet decisions.
_Avoid_: Flow Direction, Device Packet Direction, canonical endpoint order, assuming every first-observed packet is client-to-server

**Flow Origin Device Direction**:
The Device Packet Direction of the packet that created the FlowEntry, exported as `flowOriginDir`. Together with the current `packetDir` it explains whether an observed packet is on the flow's ORIG or REPLY side without collapsing the two direction concepts.
_Avoid_: alias for Flow Direction, current packet direction, canonical endpoint orientation

**Canonical Endpoint Orientation**:
The internal endpoint A/B order produced only to encode a Canonical Owner Key and select a worker consistently. L3 keys compare addresses; L4-ports keys compare address-and-port endpoints. It has no product, policy, orig/reply, client/server, or libprotoident direction meaning.
_Avoid_: packet direction, flow direction, protocol direction, user-visible source/destination role

**Worker Layout**:
The runtime-start-fixed VPP logical worker count, Canonical Owner Key hash/seed mapping, and bounded worker-private flow/session and cache capacities. All launched packet workers participate equally in owner selection. It remains immutable while packet processing is active.
_Avoid_: online worker reshard, policy apply changing flow ownership, queue topology as Worker Layout, CPU IDs in the owner hash, weighted software RETA

**Worker Placement**:
The startup-only mapping from ordered VPP logical workers to distinct online Linux CPU IDs. An experimental product setting may let the user choose contiguous or non-contiguous worker CPU IDs; the product validates and applies the selection but does not classify cores, recommend an optimal big/middle/little mix, weight packet distribution, or migrate workers while running. A change requires a clean VPP runtime restart and does not alter Canonical Owner Key semantics.
_Avoid_: CPU ID as owner identity, automatic heterogeneous-core optimization, live affinity migration, packet-hash weighting

**Initial Execution Placement**:
The Adapter-selected VPP execution context on which a native Platform I/O Lane first admits an ingress packet. Root maps independent NFQUEUE lanes across VPP ingress workers without a central fan-in; the initial VPN lane starts from one I/O owner. This placement never establishes Flow owner.
_Avoid_: queue ID as Flow owner, central NFQUEUE gather thread, VPN single-fd topology imposed on Root, policy semantics

**Primary Software Distribution**:
The normal in-graph owner selection performed on the packet's Initial Execution Placement using the Canonical Owner Key and fixed Worker Layout. If the ExecutionOwner is the current worker, processing continues locally with no enqueue; otherwise exactly one Primary Handoff moves the buffer index and side metadata to that owner before owner-sensitive state. Root and VPN share this OwnerSelector despite different ingress topology.
_Avoid_: queue ID as owner, kernel queue-balance as owner selection, central fan-in, packet-byte movement, second owner calculation, corrective dispatch

**Fragment Steering**:
The exceptional pre-policy path that co-locates all fragments of one IP datagram for bounded reassembly, then delivers the reconstructed packet to the ExecutionOwner selected by its Canonical Owner Key. Fragment identity is temporary reassembly state and never becomes FlowEntry identity. Protocol-required reassembly is an explicit bounded exception to the VPP Packet Byte-Movement Contract and has Packet Byte Mutation Authority; ordinary fragment steering and worker handoff still move buffer indexes rather than copying packet bytes. Following the current SAKAMOTO-229 contract, malformed/conflicting fragments terminate as runtime faults; timeout ends an incomplete datagram without a Policy Verdict. Pure resource exhaustion uses processing bypass when original data and a safe normal return path remain: complete NFQUEUE identity permits one NF_ACCEPT attempt per original. Otherwise record no-return/transport failure and release owned resources. An already-decided policy DROP remains DROP.
_Avoid_: treating non-initial fragments as if they contain ports, UID-based fragment dispatch, fragment-keyed FlowEntry, accepting malformed/conflicting packets, reporting resource exhaustion as a policy decision, claiming delivery from an ACCEPT attempt

**FlowRuntime**:
The owner-local authority coordinating FlowEntry lookup, creation, observation and closure, including its internal storage, protocol tracking, expiry and finalization responsibilities.
_Avoid_: platform-owned session table, shared mutable flow manager, external reference project names as product modules

**FlowEnd**:
The internal end-of-flow signal that lets consumers finish processing an unlinked FlowEntry before its storage becomes reusable. It is not an original network packet or an Adapter Completion obligation.
_Avoid_: immediate slot reuse on unlink, NFQ verdict, TUN output packet

**FlowEntry**:
The bounded owner-local flow instance carrying identity, direction, protocol facts and cumulative accounting for packets that reach flow processing. True pre-flow DROP does not query, create or update it; policy changes invalidate decisions without resetting its lifecycle or established facts.
_Avoid_: accepted-flow ledger, full TCP state machine, separate DPI flow table

**Flow Expiry**:
The point at which a FlowEntry's protocol deadline makes it logically expired, so a later lookup cannot reuse it as a still-valid flow. Owner-local finalization and resource release may follow with bounded delay; that cleanup delay does not extend the flow's logical lifetime.
_Avoid_: extending protocol timeout to accommodate cleanup, treating an expired entry as valid until a background sweep, equating logical expiry with immediate memory release

**ActivityAccumulator**:
Historical bounded coalescing evidence for traffic blocked before flow creation. The accepted Blocked Observation model defines its replacement lifecycle and attribution semantics.
_Avoid_: current record ABI, authoritative history, rule identity as observation identity

**DPI / L7 Policy**:
Policy using published flow-local application-protocol and supported domain facts within the unified rule expression model. Fact production does not create an independent verdict priority stage.
_Avoid_: independent flow table, arbitrary deep decoder coverage, automatic flow termination

**l4Status**:
The packet parser classification for known L4, legal other terminal protocol, fragment, or invalid/unavailable L4. For a valid L3 packet, unavailable or unsupported deeper facts cause predicates that require those facts to no-match while other evaluable policy stages continue; this status does not override a VPP validation node that has classified the packet itself as invalid.
_Avoid_: overloading `protocol=other` to mean every invalid or unavailable L4 case

**NFQUEUE ingress topology**:
The Packet capture Adapter's runtime-start-fixed set of NFQUEUE queues and native Platform I/O Lanes. Connection-stable kernel `queue-balance` distributes initial receive work without a central gather point, while each queue remains exclusively owned for receive and verdict by one origin lane. Queue identity selects only Initial Execution Placement; every valid IP packet still uses the Canonical Owner Key and Worker Layout to select its ExecutionOwner. Queue count and lane mapping are measured capacity choices that change only across runtime restart and queue-range reconstruction.
_Avoid_: direction inferred from lane identity, Rust packet lane, shared NFQUEUE handle, queue ID as Flow owner, queue-balance as a correctness guarantee, fixed POC queue count as product contract

**Adapter I/O Topology**:
The Packet capture Adapter-specific arrangement of VPP-native Platform I/O Lanes around the shared owner-worker graph. Android VPN/TUN begins with one event-driven I/O owner after Android transfers the required descriptors; Root/NFQUEUE uses measured parallel queue lanes. Both enter the same OwnerSelector and owner-worker graph, then route terminal work back to the platform-specific origin lane for completion.
_Avoid_: Rust per-packet bridge, busy polling, main-thread NFQUEUE fan-in, VPN lane count imposed on Root, queue identity as Flow owner, pretending all platform fds have identical batch semantics

**Origin Adapter Lane**:
The VPP-native Platform I/O Lane that admitted a packet and exclusively owns its platform completion authority, such as the original NFQUEUE queue generation, handle, and packet ID. Flow processing may occur on another worker, but terminal intent returns to this lane before completion.
_Avoid_: FlowOwner, shared completion handle, queue ID as canonical owner, cross-worker verdict

**Canonical Return**:
The bounded completion route from a remote ExecutionOwner back to the Origin Adapter Lane after policy/runtime processing. It carries the original live buffer identity and terminal intent without copying packet bytes and is Adapter completion routing rather than Primary Handoff.
_Avoid_: shared-TX, direct remote verdict, second packet buffer, another flow redistribution, unbounded retry

**NFQUEUE fail-open fault policy**:
The shared Android Root and Linux Host Firewall policy that recoverable NFQUEUE infrastructure or packet-processing faults preserve connectivity whenever an accept verdict can still be completed. Missing listeners use queue bypass; supported kernel queue delivery/overflow paths are configured fail-open; parser-execution and ordinary worker-capacity faults with a valid packet identity return accept and record bounded fault/health evidence. An ingress event without Ingress Completion Identity never enters VPP and cannot be actively recovered by Sakamoto, although kernel fail-open/bypass may independently release it. Content that the shared VPP graph has positively classified as an invalid L3 packet is instead runtime-dropped according to VPP Packet Validation Outcome. Fragment resource failures follow SAKAMOTO-229's original-data/identity/safe-return test; protocol faults, timeout and previously decided policy DROP retain their distinct dispositions.
_Avoid_: silent unobserved bypass, conflating parser execution failure with an invalid packet, fail-closed overload for recoverable capacity faults, fail-open invalid L3, injecting a packet without completion identity, accepting every fragment failure indiscriminately, claiming recovery of an unavailable packet ID, treating a policy-rule DROP as an infrastructure fault

### Multi-User Identity

**complete Linux UID**:
The full Android UID including userId high bits and appId low bits. Core daemon identity uses complete Linux UID.
_Avoid_: treating appId alone as a globally unique app identity

**UID attribution**:
The packet/session fact acquisition step that determines the complete Linux UID for a packet when the capture Adapter did not provide it directly. It is not TUN metadata and not CT flow identity; unknown attribution remains `uidKnown=false`.
_Avoid_: guessing VPN app UID, appId-only attribution, CT key identity

**appId**:
The per-package Android app id portion of a UID. Multiple Android users may have distinct complete UIDs for the same appId.
_Avoid_: using appId as the only storage or policy key

**userId**:
The Android user/profile identifier used with package name to identify a specific installed app instance.
_Avoid_: assuming package name alone is unambiguous

**app selector**:
The vNext `args.app` object, either `{uid}` or `{pkg,userId}`, used to select an app instance.
_Avoid_: legacy positional `<uid|str> USER <userId>` syntax as the current control-plane model

**selector ambiguity / selector not found**:
The vNext failure modes for app selection. Ambiguous package selectors return candidates; missing selectors report not found.
_Avoid_: silent fallback to user 0 or creating an app during read-only queries

### Observability

**Telemetry Plane**:
The bounded record export layer for persistent or queryable flow facts consumed outside the daemon.
_Avoid_: event system, Debug Stream, metrics

**Flow Telemetry**:
Normal cumulative observations of Flow instances, complemented by independent Blocked Observations for pre-flow drops. The records carry accounting, attribution and lifecycle facts for Rust consumption without end-to-end delivery guarantees.
_Avoid_: per-packet trace, mandatory old shared-memory ABI, DNS records in the current packet scope

**Flow Record**:
A telemetry record for flow begin, update, or end facts, including cumulative counters and final execution metadata.
_Avoid_: per-packet event

**Fact Records**:
Observation records for things that actually happened, such as flow lifecycle facts, DNS decisions, packet verdicts, counters, and final attribution.
_Avoid_: explain evidence, shadow evaluation, rule hit counters

**Explain Evidence**:
Diagnostic evidence that explains why a verdict happened, including evaluated stages, winners, skipped stages, and rule snapshots.
_Avoid_: fact records, shadow evaluation, ordinary history

**Shadow Evaluation**:
Dry-run policy evaluation that reports what a candidate or non-enforcing policy would have matched without changing the actual verdict.
_Avoid_: executed verdict, fact records, explain evidence

**Safe Policy Change Workflow**:
Policy modification with distinct saved and active outcomes and an available correction path. Detailed UI workflows, simulation and checkpoint-based rescue are not requirements of the current backend specification.
_Avoid_: mandatory Try/Diagnose/Rescue UI, automatic saved-config rollback, separate shadow engine

**DNS_DECISION record**:
A telemetry record for blocked DNS decisions and DomainPolicy attribution. It is separate from packet and flow records.
_Avoid_: DNS-to-IP join record

**L3_OBSERVATION**:
A telemetry-only `FLOW` observation for fragments or invalid/unavailable L4 packets; it is not a normal L4 lifecycle.
_Avoid_: pretending malformed or fragmentary traffic is a normal TCP/UDP/ICMP flow

**Telemetry consumer**:
The Local Product Backend component that opens runtime telemetry, reads bounded records, and owns persistence, queries, and aggregation. On Android it runs on the RuntimeService side under the ordinary application identity rather than in VPP or the Tauri UI process; Linux later reuses the same product-core consumer in its product process.
_Avoid_: daemon-side Top-K or history database, root-owned database writer, WebView telemetry consumer, UI-lifecycle data loss

**Product Store**:
An umbrella term for product persistence, not one physical database. Rule configuration is the VPP-owned source file; normal observation history and summaries belong to a separate Rust-owned store.
_Avoid_: single shared policy/history database, remote storage service, UI-owned schema

**Activity Store**:
The bounded Rust-owned normal observation store containing recent overview/attribution and longer-lived traffic aggregates. It is separate from rule configuration, excludes packet payloads and remains independent of frontend lifecycle.
_Avoid_: VPP-written analytics database, raw packet archive, complete permanent configuration archive

**Metrics**:
Pull-style low-cardinality counters and health/performance summaries.
_Avoid_: using metrics for Top-K, history, timeline, or high-cardinality destination analytics

**Traffic Windows**:
Predefined overall, application, per-application protocol and rule-effect views incrementally maintained by Rust from normal observations. Queries use maintained summaries and expose their temporal granularity and coverage gaps.
_Avoid_: VPP-owned historical windows, arbitrary analytics cube, full raw-record rescan per query

**Traffic Windows Top-K**:
Historical terminology for optional heavy-hitter detail. It does not add dimensions or an independent input pipeline to the four accepted normal views.
_Avoid_: current exact destination ledger, mandatory fifth normal view

**Diagnostic Focus**:
Historical name for session-scoped diagnostic targeting. Specific target selection and interaction modes remain deferred under the current debug design boundary.
_Avoid_: confirmed single-app UI, persistent normal-observation setting

**Debug Stream**:
A legacy / generic name for short-window debug evidence streams. In the refactored packet-side model, use Packet Diagnostics and Diagnostic Focus; the old DNS stream remains a frozen DNS-line capability until the Domain/DNS line is reopened.
_Avoid_: long-term telemetry, normal dashboard API, new packet diagnostics API name

**Packet Diagnostics**:
Detailed evidence serving one explicit debugging session, with temporary interpretation data and truthful attribution to actual execution when tracing. Concrete capture, simulation and UI modes are deferred; normal history does not become a debug archive.
_Avoid_: normal cumulative observations, long-term debug history, settled JSON or UI contract

**tracked**:
Legacy name for the old app-level Debug Stream gate. The refactored packet diagnostics model should use Diagnostic Focus instead.
_Avoid_: new configuration name, persistent diagnostics state, treating tracked as the general observability enable switch

**PerfMetrics**:
Latency and health instrumentation for diagnosing datapath cost. PerfMetrics has a low-disturbance basic tier for default health observation, an explicit detail tier for heavier diagnosis and measurement, and a developer/release profiling level for per-stage latency breakdown. Frontend policy controls whether detail runs briefly or remains enabled; developer tooling or CI controls profiling. The daemon provides bounded collection mechanisms. When enabled, its own collection work is part of the packet hot path and must remain bounded and aggressively minimized.
_Avoid_: always-on product dashboard metrics, treating diagnostic measurement overhead as free, exposing profiling breakdown as ordinary user detail, separate profiling command surface

**Datapath Performance Indicators**:
Observable measurements of packet path cost, such as per-packet datapath latency and NFQUEUE queue health. They describe runtime performance data; separate test and release gates decide when those measurements must be collected or enforced.
_Avoid_: unit test suite, release checklist, network RTT, always-on product dashboard KPI

**RDNS / rdns.enabled**:
Diagnostic-only reverse-DNS enrichment. It may help explain traffic, but it is not an enforcement dependency.
_Avoid_: making IPRULES enforcement depend on reverse DNS

### Product Delivery

**Capability-and-Evidence Equivalence**:
A recovery condition in which the current authority's behavior, state ownership, failure semantics, and resource closure are implemented by product-candidate code and supported by claim-matched Current-head Product Evidence. It does not require source, class, command, test-count, or historical implementation parity.
_Avoid_: source parity, test-count parity, historical PASS as current acceptance, requiring every evidence layer for every claim

**Current-head Product Evidence**:
Reproducible evidence produced directly by a current product-candidate revision and its identified artifacts, with an exact claim, environment, command, raw result, validity, claim boundary, and residue outcome. It remains current until a relevant implementation, artifact, contract, or seam changes; a runnable POC still does not become product evidence.
_Avoid_: latest-commit-only evidence, undocumented PASS, POC rerun as product acceptance, blanket invalidation after unrelated changes

**Product Evidence Stack**:
The claim-matched recovery model with three execution layers—Host Semantic, Product VPP Graph, and Android Device—and two cross-cutting obligations—Control/Lifecycle and Resource/Residue. The layers complement rather than substitute for one another, while each slice carries only the obligations relevant to its claim.
_Avoid_: five interchangeable test tiers, Host proof as Android proof, duplicating every semantic vector on-device, all-layers gate for every slice

**Controlled LAN Network Evidence**:
Deterministic real-Wi-Fi request/response evidence against a controlled LAN endpoint for IPv4/IPv6 and TCP/UDP, used as the blocking network oracle for Root and VPN recovery. Public IPv4 reachability is a later narrow smoke, while public IPv6 is recorded only when the environment provides it and does not replace or block the controlled dual-stack claim.
_Avoid_: device loopback as underlay proof, public service as deterministic oracle, public IPv6 as a recovery prerequisite, DNS standing in for UDP dataplane evidence, LAN IPv6 as a public-reachability claim

**Recovery Acceptance Card**:
The smallest per-slice statement of its exact capability claim, required Product Evidence Stack cells, decisive cases and oracle, and explicit non-claims. A slice is accepted only when every required cell has compatible Current-head Product Evidence marked PASS; FAIL blocks the claim, while INVALID and NOT RUN remain evidence gaps.
_Avoid_: long test plan, implicit done criteria, Host PASS overriding device FAIL, treating INVALID as PASS, mandatory full-stack evidence for every slice

**Mainline Recovery Slice**:
An architecture-level product-candidate capability increment used as the unit of recovery planning and native blocking. It may contain many small implementation steps and Device-native Micro-validations, remains in the mainline by default, and closes through one coherent Recovery Acceptance Card without turning every test cell or single-machine scheduling constraint into a separate slice.
_Avoid_: individual code step, individual protocol/family test cell, device scheduling edge as architecture blocking, disposable POC by default, false readiness, end-of-slice-only device testing

**Recovery Microstep**:
An ordered, single-claim implementation-and-evidence step inside one Mainline Recovery Slice, with a named seam, minimal input/output, decisive oracle, and explicit next unlock. It is recorded in the recovery specification but becomes a separate implementation ticket only when independently grabbable work or a real blocking edge justifies it.
_Avoid_: architecture slice, automatic Plane issue, unrecorded coding step, device test without a product claim, artificial blocker for single-device scheduling

**VPP-native Mainline Recovery Baseline**:
The capability-and-evidence level the product must regain from the last active pre-removal mainline, amended by current accepted decisions and bounded POC findings. Rejected routes, archive-only capabilities, historical PASS results, POC source shapes, and experimental constants do not enter it automatically.
_Avoid_: C++ source parity, archive feature restoration, direct POC import, treating a scoped POC result as product completion

**VPP Foundation Closure**:
The blocking recovery layer that proves the pinned VPP product runtime can start, carry real dual-stack traffic, stop, fail, and recover under both Root/NFQUEUE and VPN/TUN Runtime Profiles with fixed worker/core placement, bounded resources, and POC-level engineering guardrails. It precedes restoration of richer policy, flow, control, and observability capabilities and is not release certification.
_Avoid_: full product recovery, one-shot VPP startup smoke, release performance gate, feature-complete dataplane

**Device-native Micro-validation**:
A smallest device test that proves one observable product fact through real Android, VPP, TUN or NFQUEUE behavior as soon as that fact becomes runnable, without waiting for a whole Module or milestone. Ordinary unit tests merely executed on a phone do not qualify; Host and device evidence remain complementary.
_Avoid_: device-hosted unit test, end-of-module device batch, one final integration campaign, POC-only smoke

**Android Runtime Supervisor**:
The Java platform Module that is the sole authority for the active Runtime Profile and its Android/VPP lifecycle. It serializes start, profile switch, stop, and observation; owns permissions, foreground-service state, TUN and privileged resources, artifact launch, generation-safe readiness, and deterministic cleanup. Rust may request lifecycle changes, but neither Rust nor UI owns the resulting platform state.
_Avoid_: generic reconciliation framework, parallel active profiles, UI-owned lifecycle, PID-only readiness, per-packet Java bridge

**Rust Product Core**:
The Tauri-independent Rust Module that owns product intent, the single-writer Product Store, immutable policy revisions, stable product status and errors, and the one persistent serialized VAPI control session. Its recovery interface begins with minimal profile lifecycle commands and snapshots; packet bytes and Android resources never cross it.
_Avoid_: direct UI-to-VAPI, Android types in product policy, per-command reconnect, automatic replay after outcome-unknown mutation, per-packet Rust FFI

**Shared VPP Packet Runtime**:
The single VPP-native C product dataplane used by both Root/NFQUEUE and VPN/TUN Runtime Profiles. Profile adapters join one bounded worker-owned graph and retain origin-specific completion; control crosses only coarse versioned VAPI and lifecycle seams.
_Avoid_: C++ compatibility path, imported POC source shape, parallel dataplanes, shared mutable flow ownership, per-packet cross-language control

**VPN Flow Stack**:
The VPN-only, owner-local C/VPP transport Module that applies HEV/lwIP TCP and UDP semantics after shared VPP admission. It keeps transport PCB/socket state separate from VPP FlowEntry policy state, uses the Android Socket Broker only at underlay socket setup, and returns packets through VPP VPN completion rather than writing TUN directly.
_Avoid_: second dataplane, direct TUN write, per-packet protect/bind call, policy authority in the flow stack, unbounded reconnect

**Device Evidence Harness**:
The test-only automation Module that drives real product controls, artifacts, device traffic, and OS/VPP observations to produce Device-native Micro-validation evidence. It carries no runtime authority or product repair logic; Host tests support but do not replace its Root- and VPN-specific device claims.
_Avoid_: test-only product backdoor, mock acceptance, runtime logic in the harness, inferring one Runtime Profile from the other

**Android L4 Product Release**:
The first user-complete Android release: mutually exclusive Root/VPN Runtime Profiles, multi-user App-first Control, Wi-Fi/Mobile/VPN Network Gates, advanced per-app IPv4/IPv6 L4 Traffic Rules, bounded activity/statistics, health, recovery, Product UI, help, and release materials.
_Avoid_: VPP POC milestone, backend-only L4 completion, Linux release

**Android VPN Engineering Feasibility**:
The pre-implementation feasibility threshold for the non-root VPN Runtime Profile: the accepted architecture is correct, bounded, and lifecycle-convergent on its target environment. It is not release readiness or final capacity sizing.
_Avoid_: one-shot connectivity smoke, production readiness, release acceptance, final capacity sizing, product implementation completion

**Direct Egress Performance Acceptance**:
The two-level performance evidence required for HEV Direct Egress: a controlled prototype A/B against the existing HEV SOCKS5 path, followed by absolute Android release-budget evidence for the production artifact. The prototype requires Direct median throughput at least 90% of baseline, p95/p99 latency and CPU per byte or transaction at most 110% of baseline with a small absolute latency tolerance, steady-state RSS growth at most 8 MiB, and no increasing RSS, thread, or fd trend across repeated connections and restarts. Passing only the relative comparison or only the release budget is insufficient.
_Avoid_: HTTPS-connectivity-only acceptance, unpaired benchmark, prototype benchmark as release approval, SOCKS5 comparison as the sole product gate

**Direct Egress Feasibility Conclusion**:
The decision produced by the throwaway HEV Direct Egress prototype, expressed as `可进入正式实现`, `需先重构`, or `路线不可行`. These phrases describe evidence and next action; they are not implementation languages or release approval.
_Avoid_: `GO`, `NO-GO`, Go language implication, treating throwaway prototype code as production code

**Sakamoto HEV Fork**:
The project-maintained MIT-licensed fork of pinned HEV selected as the starting implementation of the VPN Userspace Flow Stack because it already integrates lwIP flow/session lifecycle and TCP/UDP socket bridging. It serves Sakamoto's requirements rather than preserving SOCKS5 as the subsystem's defining purpose. It does not routinely rebase or follow upstream; only a major bug fix or evidence-backed significant performance improvement may trigger review and selective migration into a new tested pinned commit. It has no plan or release obligation to contribute Sakamoto changes upstream.
_Avoid_: temporary downstream patch, scheduled rebase, automatic upstream tracking, update for version freshness, upstream contribution roadmap, waiting for upstream acceptance

**POC Evidence Harness**:
A throwaway scaffold that builds, runs, and seals evidence for one runnable question without becoming a product Module or implementation source.
_Avoid_: production seam, reference implementation, migration-ready code, treating PASS or Plane Done as higher-fidelity evidence

**Implementation Feasibility POC Campaign**:
A bounded pre-implementation research sequence used to decide whether an accepted architecture is viable on its target platform. It ends with an evidence-backed feasibility boundary, not a production or release decision.
_Avoid_: implementation phase, release validation, production hardening, open-ended research, repeating already accepted architecture proofs

**Evidence-Guided POC Roadmap**:
A revisable ordering of feasibility questions shaped by current evidence and gaps. Its objective and evidence standards remain stable while individual POCs may change.
_Avoid_: frozen experiment checklist, predetermined ticket sequence, silent scope drift, continuing an obsolete POC after its question is settled

**POC Evidence Batch**:
A group of complementary POCs interpreted together as one upper-level engineering question. It is a planning and execution unit, not a claim that any single cell proves the route.
_Avoid_: one-POC-one-meeting workflow, batch approval gate, unbounded experiment chain, ignoring a campaign-invalidating discovery, interpreting each partial result as the campaign conclusion

**Lightweight POC Protocol**:
The minimum evidence discipline that preserves a POC's freedom to explore: state its question and decisive counter-evidence before execution, record meaningful additions during it, and seal evidence and claim boundaries afterward.
_Avoid_: process as the POC outcome, freezing every test cell upfront, silent gate relaxation, discarding exploratory failures, documentation work that blocks useful investigation

**POC Evidence Conclusion**:
The vocabulary that separates an experiment cell result from its roadmap meaning. Each conclusion states in plain language what the evidence supports and what remains outside its claim.
_Avoid_: bare `GO/NO-GO`, treating one passing cell as campaign completion, turning a benchmark number into an architecture verdict, omitting non-claims

**Evidence-backed Architecture Baseline**:
The architecture direction supported by the strongest current bounded evidence and used as the default premise for subsequent POCs. It is stable but revisable: contradictory higher-fidelity evidence or a material new constraint may reopen it, while ordinary harness or implementation-seam defects do not.
_Avoid_: immutable frozen architecture, permanent decision, restarting architecture selection for every POC, treating every defect as an architecture reversal

**POC Finding Ledger**:
The evidence-linked record of both closed findings and open risks discovered during feasibility POCs, retained so formal implementation does not repeat known architecture, platform, ownership, lifecycle, or experiment-design failures. It is an engineering-knowledge source, not an open-work backlog or a transcript of incidental trial and error.
_Avoid_: bug backlog, unresolved-items-only list, experiment diary, recording every typo or transient command failure

**Evidence Gap Map**:
The claim-oriented map that distinguishes what model, Host, and Pixel evidence currently support from what remains unproven, invalidated, or outside scope. It links feasibility-critical gaps into future POC Evidence Batches without mislabelling an untested claim as an observed defect.
_Avoid_: POC Finding Ledger, speculative bug list, flat TODO backlog, treating Host and Pixel evidence as interchangeable, treating untested as false

**POC Correction**:
A throwaway change used to make a feasibility experiment faithfully exercise its registered question after a real defect is exposed. It is reference evidence for the invariant that formal implementation must preserve, not a production patch or implementation template.
_Avoid_: production fix, migration-ready code, reference implementation, copying the POC patch as the design

**Target-Device Anchored POC**:
A feasibility POC whose highest-fidelity target-device evidence anchors claims about that platform, while deterministic subclaims may come from Host or model evidence. It does not imply universal device compatibility.
_Avoid_: Host-only Android conclusion, requiring every deterministic vector to be duplicated on-device, Pixel evidence as universal OEM compatibility, emulator evidence as physical-device closure

**Full-device VPN POC**:
A VPN feasibility run in which normal device traffic exercises the target path. Narrower isolation is a diagnostic variant, not equivalent evidence.
_Avoid_: production deployment, protecting a personal daily-use device, narrow-loopback-only external-network conclusion, requiring one synthetic traffic app for every device cell

**Closure Evidence Matrix**:
The real-environment-first layered acceptance model for Android Functional Closure: exhaustive shared semantic vectors run at the Adapter-neutral VPP graph contract, each Root/VPN Adapter separately proves its platform ingress/completion/fault/teardown boundary, and both Runtime Profiles pass a representative Android end-to-end parity set. It preserves useful existing unit and integration fixtures, runs newly required device evidence on the available controlled target device with real installed applications and network paths whenever practical, and uses host or synthetic evidence only for boundaries that cannot be reproduced deterministically end to end without duplicating every shared combinatorial vector across both profiles.
_Avoid_: POC result list, identical exhaustive device suites per profile, Root-only closure, pass-through smoke as semantic acceptance

**Functional Closure Contract**:
The revisable working contract that freezes accepted product and architecture invariants while exposing implementation choices, capacities, thresholds, and other evidence-driven variables to adjustment as POCs, code, and controlled-device results arrive. A contradictory result pauses the affected gate and triggers an explicit contract or ADR update; it never authorizes silently weakening a test to preserve a pass.
_Avoid_: immutable final-release specification, historical POC checklist, implementation blueprint, silent gate relaxation

**Protocol Identification Release**:
The stage release that adds project-mapped base and supplemental application-protocol facts and protocol rules to the same worker-owned FlowEntry and existing Product UI. A published result is immediately actionable within this release's recognition capability; it is not a provisional hint awaiting scanner or protocol-decoder confirmation.
_Avoid_: full NGFW, stream reassembly release, separate DPI product, raw provider guess as published fact, candidate/decoded split, decoder confirmation requirement

**Supplemental Protocol Recognition**:
The protocol-identification rules that complement the base recognizer, using nDPI detection logic as the primary reference and selected reference-fork heuristics and useful protocol distinctions as supplements for personal endpoints. These are recognition rules, distinct from user firewall rules; a heuristic classification does not imply a completed handshake or cryptographic validation.
_Avoid_: upstream-library-only recognition, wholesale fork-rule compatibility, firewall rule priority, protocol label as proof of a valid session

**LpiRecognitionState**:
Bounded recognition state and the deduplicated sequence of published application-protocol results belonging to one owner-local FlowEntry. Available results participate immediately; later results do not erase earlier facts or retroactively rewrite completed packet decisions.
_Avoid_: latest-result-only policy, recognition order as priority, winning DROP terminates the flow

**LPI Recognition Budget**:
The bounded work and lifetime permitted for one recognition attempt. Exhaustion retains published facts while unavailable facts remain unavailable; it is not proof of a final Unknown result.
_Avoid_: unbounded retries, budget exhaustion means no protocol, validated upstream numeric defaults

**Recognize-then-enforce**:
Packet decisions use facts available by the current decision cutoff without holding original packets for future recognition. Later facts affect later decisions, while a proven early logical winner retains its precedence for its already-bound packet.
_Avoid_: automatic first-N-packets allow, lower-priority late-stage override, retroactive verdict change

**Packet Decision Cutoff**:
The Adapter completion boundary for facts affecting one packet. Packet-local parsing, synchronous application evidence, and protocol facts produced before completion may participate in the current verdict without constituting a hold; asynchronous attribution or identification received afterward can update worker-owned flow state but affects only later packets.
_Avoid_: waiting for future facts, next-packet-only rule for synchronous facts, retroactive enforcement, treating normal graph execution as packet caching

### Runtime State

**Authoring Policy Bundle**:
The complete source configuration of reusable rules, groups and application bindings managed by VPP. It is saved independently of the immutable Runtime Snapshot compiled from a particular saved version.
_Avoid_: frontend database, worker-mutable rule graph, stage-owned priority families

**Stale UID Binding**:
An Authoring Policy Bundle binding whose complete Linux UID is not currently present on the device. It is valid saved configuration, not a commit validation failure. It remains user configuration for control-plane display and cleanup, but does not contribute runtime rules or capability summaries while stale.
_Avoid_: automatic deletion, package-name identity, runtime subject

**Draft**:
Editing state while preparing a complete source configuration. A particular persisted-draft lifecycle or UI workflow is not fixed by the current rule backend specification.
_Avoid_: active Runtime Snapshot, mandatory independent persisted draft store

**Policy Commit / Committed Policy Revision**:
A fully saved source configuration version that can be compiled and applied. Saving does not establish that the version is active, and a compilation failure preserves it for user correction.
_Avoid_: successful publication, automatic rollback after compile rejection, required checkpoint

**Draft Commit**:
Historical name for committing an authoring draft. The current backend requires complete saving before compilation without freezing a separate draft-command or UI workflow.
_Avoid_: mandatory multi-step editor contract, worker publication

**Checkpoint / Policy Bundle Checkpoint**:
Historical name for a retained full source configuration from an earlier authoring design. The current specification permits explanation from retained configuration material but does not require a checkpoint product, fixed retention count or complete old-rule archive.
_Avoid_: Runtime Snapshot, guaranteed current restore feature, normal observation record

**Runtime Snapshot**:
The immutable execution state compiled from one identified saved configuration, including compatible programs, effective application views and attribution. A packet uses one protected snapshot throughout policy evaluation; the snapshot is not the persistent source configuration.
_Avoid_: editable source graph, persistent checkpoint, per-stage independent publication

**Policy Apply**:
Compilation of an identified saved configuration and publication of its complete Runtime Snapshot. Failure retains the saved edits and any existing active snapshot, with saved and applied outcomes reported separately.
_Avoid_: save equals active, half publication, resetting every flow, automatic saved-config rollback

**Policy Revision Re-evaluation**:
The lazy existing-flow behavior after Runtime Snapshot publication. On the next packet, a FlowEntry whose stored policy revision differs from the active revision retains reusable identity, counters, CT state, and protocol facts, but clears decision caches, winner attribution, and allow/drop fast-path state before evaluating the new snapshot. Facts are not reconstructed from missed historical packets.
_Avoid_: grandfathering verdicts until flow expiry, eager full-table scan, retaining cached verdicts across revisions, replaying early payload

**Checkpoint Restore**:
Historical authoring operation for selecting a retained source snapshot. Automatic last-known-good recovery and a dedicated checkpoint-restore workflow are not promises of the current initial rule-engine specification.
_Avoid_: startup error silently publishes empty policy, guaranteed configuration history

**RESETALL**:
The full reset pipeline that returns daemon memory state, observation state, configuration state, and persisted save tree to a clean baseline while the native daemon process remains under RuntimeService lifecycle ownership.
If an active runtime owner cannot return its state to the clean baseline, the RESETALL command fails and the failure is also reflected in Runtime health.
_Avoid_: daemon restart, daemon shutdown, process recycle, partial config reset, per-feature clear command, best-effort success

**Policy state**:
Source configuration and derived active execution state that determine packet-rule behavior. Saved configuration and active Runtime Snapshot are distinct identities rather than interchangeable copies.
_Avoid_: observation buffers, historical traffic summaries

**Observability session state**:
Runtime state for diagnostics sessions, telemetry consumers, frozen legacy streams, and record assembly. RESETALL or checkpoint restore may force clients to reopen sessions.
_Avoid_: treating it as durable policy

**Counters**:
In-memory metrics or stats used for health, attribution, or measurement. Unless a specific doc says otherwise, counters are resettable and not durable history.
_Avoid_: frontend timeline/history storage

**ip-leak / Domain-IP bridge**:
Legacy/backlog terminology for DNS-learned Domain-to-IP association and packet-side domain hints.
_Avoid_: treating legacy `BLOCKIPLEAKS`, `GETBLACKIPS`, or `MAXAGEIP` as current mainline APIs

**OpenSpec archive**:
Historical process material kept for reference only. It is not an active workflow or source of current constraints unless the user explicitly asks for archived context.
_Avoid_: active OpenSpec change, current spec source
