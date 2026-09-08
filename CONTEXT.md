# Sakamoto Snort

Sakamoto Snort is a local-endpoint firewall project for Android and Linux, providing DNS/domain policy, IP packet policy, and bounded observability. This glossary captures project-specific language used across the current docs so agents do not drift back to legacy or OpenSpec-era terminology.

## Language

### Architecture Surfaces

**vNext control plane**:
The current daemon control surface for policy mutation, configuration, metrics, streams, telemetry, and checkpoint commands.
_Avoid_: legacy control, `60606` as the current surface

**Control Plane**:
The configuration and debug surface for immediate daemon operations. It does not own long-term storage, high-cardinality analytics, or dashboard history.
_Avoid_: analytics backend, history store

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
The sole RuntimeService-supervised native dataplane instance for the active Runtime Profile. It owns the shared VPP graph, Worker Layout, live VPP buffers, and active VPP-native Packet I/O Adapter.
_Avoid_: bare Runtime, surrounding C++ daemon, HEV runtime, parallel Root/VPN dataplanes

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
The Direct Egress treatment of DNS as its original TCP or UDP traffic sent to the packet's original destination. It does not introduce a separate resolver, redirect DNS to a product-selected server, or bypass normal policy and transport accounting.
_Avoid_: built-in DNS proxy, silent resolver replacement, treating DNS as outside Direct Egress

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
A VPN Userspace Flow Stack TCP or UDP socket bound to the selected Android underlay and successfully excluded by Android `VpnService` from the active VPN before `connect()` or the first send, preventing its outer traffic from re-entering the TUN. Its underlay epoch is fixed at creation: new flows use the latest Network Context Snapshot, while an invalidated TCP underlay ends the transport flow so the application can reconnect rather than transparently migrating or reconnecting its byte stream. Any future UDP mapping rebuild across underlays requires explicit, tested semantics and never silently reuses the old socket. Protection or underlay-binding failure closes the socket with no unprotected fallback and remains an Infrastructure Fault and failed Transport Outcome without rewriting the Policy Verdict.
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
The on-device, cross-platform control and persistence layer that exposes product state to Product UI and adapts it to the packet runtime. On Android it is owned by the RuntimeService side and remains available while protection runs even if the Tauri Activity is absent; Linux later hosts the same product-core responsibilities in its native product process. It is shared product code, not a remote account, cloud API, or server.
_Avoid_: remote backend server, Compose-owned database, UI-process lifecycle owner, VPP-owned product database, UI calling VPP internals

**App-first Control**:
The product control model where network access, L4 rules, activity, and statistics remain organized around a platform application. Android preserves multi-user identity through complete Linux UID; Linux resolves its own application identity through the Application Identity Provider. It does not prescribe which screen opens first.
_Avoid_: rule-inventory-first control model, device-wide expert console, UID-only Linux application identity, treating launch destination as control ownership

**Progressive Control Disclosure**:
The single Product UI model where common app controls appear first and L4 rules, evidence, and diagnostics appear as the user drills into context. It does not divide users or policy into global simple and advanced modes.
_Avoid_: simple mode, expert mode, duplicated beginner and advanced UI

**Daemon lifecycle**:
Whether the native daemon process is running under the Android-side service owner. It is separate from daemon feature gates such as policy or observability switches.
_Avoid_: `block.enabled`, component gate, empty daemon mode

**Bounded Runtime Recovery**:
The Android RuntimeService policy for an unexpected active VPP runtime exit: clean profile-owned hooks, fds, sockets, and partial state, then attempt automatic recovery with bounded retries and backoff. Repeated failure within the configured recovery window stops further restart, releases Root/VPN resources, preserves diagnostics, and requires user intervention through the Visible Runtime Notification and product status. Exact thresholds are release-tested implementation constants, not ordinary-user settings.
_Avoid_: infinite crash loop, silent permanent stop after one fault, restarting without cleanup, UI Activity as restart owner

**Protection Pause**:
A user-requested clean stop of the active Android Runtime Profile. Pausing stops VPP and releases all profile-owned packet-capture resources: Root removes its NFQUEUE hooks and VPN closes its TUN and releases the system VPN slot. The selected profile, Authoring Policy Bundle, and last successfully applied policy state remain persisted for a later restart. Pause is not a live VPP pass-through mode and produces no packet Activity; observe-only behavior belongs to policy, not lifecycle.
_Avoid_: VPP kept alive while paused, pass-through pause, collecting Activity while paused, treating an unexpected runtime exit as a user pause

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

**DomainPolicy**:
Domain-level allow/block policy at app or device scope, using literal domains and references to reusable domain rules.
_Avoid_: conflating it with IPRULES or packet verdict policy

**DomainRules**:
Reusable domain, wildcard, or regex rules referenced by DomainPolicy payloads.
_Avoid_: treating every domain rule as a DomainList entry

**DomainLists**:
Managed allow/block domain-list imports or subscriptions with metadata and imported domains.
_Avoid_: BlockingList, `BLOCKLIST.*`

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
The optional association layer that records learned domain-to-IP relationships for enrichment, debug evidence, and features such as IP leak handling. Its data sources are separate from DomainPolicy and may include DNS observation paths that do not block or modify DNS requests.
_Avoid_: DomainPolicy itself, Basic IPRULES matcher, RDNS, Host cache

**Resolved-IP Policy**:
An optional packet enforcement capability that uses DNS-learned Domain-IP Association data to apply domain-derived policy to resolved IP traffic.
_Avoid_: ip-leak, IP link, Basic IPRULES, DomainPolicy itself

### IP And L4 Policy

**IPRULES**:
The per-app L3/L4 IP rule engine for IPv4 and IPv6 packet policy, per-rule stats, and packet attribution.
_Avoid_: IPv4 rules, firewall rules without the IPRULES scope

**NetworkContextId**:
The bounded platform-provided network category used by Network Gate: Android supplies Wi-Fi, Mobile, and VPN; Linux supplies Wired, Wi-Fi, Mobile, and VPN from reliable facts about the packet's actual interface, with unavailable classification remaining explicitly unknown. This category is separate from concrete interface matching and Runtime Profile, and the shared Product UI presents the platform's available categories.
_Avoid_: hard-coding Android columns into shared UI, unbounded user-created hot-path dimensions, ifindex as a persisted cross-reboot identity, Runtime Profile

**Network Context Snapshot**:
The event-driven platform facts used to associate a packet with a reliable NetworkContextId: Android VPN uses its bound underlying network, while Linux NFQUEUE uses the packet's actual ingress or egress interface. Concurrent networks retain their own classifications; the system default network does not replace a packet's actual network facts, and unavailable classification remains unknown.
_Avoid_: synchronous per-packet platform query, UI Activity state, VPN Runtime Profile as network context, guessing an unavailable context, treating every virtual interface as VPN

**Unknown Network Context**:
The explicit absence of a reliable NetworkContextId for the current packet. Network-specific Gate and L4 predicates no-match, while every rule that can be evaluated from the remaining facts continues normally; if no stage drops the packet, the normal default is allow.
_Avoid_: guessing Wi-Fi/Mobile/VPN, holding the packet for a platform query, skipping all policy, infrastructure bypass

**Network Gate**:
The per-ApplicationSubjectId and NetworkContextId access control exposed as the common app-level firewall action, with Android's Wi-Fi/Mobile/VPN categories and Linux's Wired/Wi-Fi/Mobile/VPN categories. It is a dedicated rule family inside the Authoring Policy Bundle: blocked returns `DROP` ahead of L4 rules, while open returns `PASS_NEXT` into applicable later policy.
_Avoid_: frontend-owned gate database, terminal allow on an open gate, L4 allow exception, Root/VPN mode selector, device-wide firewall mode

**L4 Traffic Rule**:
A per-app Basic IPRULES rule over IPv4/IPv6 source and destination CIDR, source and destination port or range, IP protocol, packet direction, and optional interface context. It uses packet-local facts and does not imply Stateful Conntrack.
_Avoid_: Network Gate, full CT rule, protocol-identification rule

**Protocol Rule**:
A later-stage compound policy rule that requires an exact Application Protocol Identity or Application Protocol Category and may also constrain application subject plus normalized, flow-stable ORIG/REPLY endpoint CIDRs, ports, and IP protocol retained by the FlowEntry. Protocol Policy chooses one current winner from every rule satisfied by the FlowEntry's currently accumulated supported stable facts using stage-local priority, explicit order, and stable rule ID; newly learned facts participate in the next current-winner selection rather than receiving an isolated verdict. Winner cache, candidate index, epoch, cursor, matched-set, full-scan, and incremental-update representations remain implementation and benchmark decisions.
_Avoid_: AppID-only rule, current-packet direction predicate, isolated verdict per newly recognized protocol, required incremental winner cache, `evaluatedResultCount`, generic MAAT clone, per-packet Protocol Policy replay, duplicating the early L4 matcher as a separate product rule, cross-stage allow override, MAAT dependency, fields from unimplemented decoders

**Policy Rule Family**:
A typed rule collection inside one Authoring Policy Bundle. Network Gate, L4 Traffic Rules, protocol-identification rules, and future metadata rules may share subject identity, revision, source attribution, and one apply transaction while retaining stage-owned predicates and priority spaces.
_Avoid_: universal rule AST, product-wide priority comparison, frontend-owned Gate/IP/DPI databases

**Enforcement Stage**:
A dataplane point with a bounded set of available facts and one stage-owned rule family, such as Network Gate, packet/L4, or Protocol Policy. A later stage may combine its newly available fact with facts retained from earlier stages; stage separation determines when a rule is evaluable and which priority space owns it, not that earlier facts become unavailable. Stages acquire expensive facts only when active consumers require them. An earlier `DROP` is terminal; `PASS_NEXT` continues to the next active stage.
_Avoid_: Product UI mode, global priority space, discarding earlier facts at a later stage, unconditional CT/DPI work

**Compiled Policy View**:
An immutable, stage-specific runtime projection produced from one Authoring Policy Bundle and published as part of one Runtime Snapshot. Gate, packet/L4, protocol-identification, and future metadata views may use different indexes and stage-owned ordering while preserving policy revision and source attribution.
_Avoid_: authoritative policy source, independently edited stage table, frontend policy database

**Stage Verdict**:
The result emitted by an enforcement stage. `DROP` terminates the packet path; `PASS_NEXT` continues to the next active stage. An allow rule at an early stage therefore means `PASS_NEXT`, not product-wide terminal allow.
_Avoid_: global `FinalAllow`, later rules reopening an earlier `DROP`, cache hits changing stage order

**Policy Verdict**:
The attributable product-policy result after the active enforcement stages have either produced a terminal `DROP` or all completed without one. It records why policy allowed or blocked traffic and remains independent of whether runtime or platform execution succeeded; if an earlier runtime fault prevents evaluation, no Policy Verdict exists and product evidence reports `NOT_EVALUATED`.
_Avoid_: NFQUEUE verdict send result, VPN forwarding result, infrastructure drop, Adapter completion

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
The target completion scheduling rule under which a native Platform I/O Lane may sleep when neither platform input nor Completion Frames are pending and receives at most one coalesced notification for newly pending work. The exact conditional-wake handshake remains unaccepted until a new artifact passes idle CPU and sleep-confirmed latency gates.
_Avoid_: busy polling, periodic completion polling, persistent wake mode, wake per packet, deliberate batching delay, treating the current wake POC patch as release-approved

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
The `stellar_acl`-style ordering band used only by the stateless L4 classifier. Lower numeric values are evaluated before higher values. Within one level, lower explicit rule order wins, followed by lower stable rule ID. Rules may be compiled into multiple mask/hash partitions, but partition traversal must not alter this precedence.
_Avoid_: comparing L4 priority with Protocol Policy priority, mask specificity as hidden priority, one lookup context per product stage

**L4 WinnerRank**:
A compact consecutive integer assigned by the L4 compiler to preserve `(priority ascending, explicit order ascending, stable rule ID ascending)` inside one compiled subject/view. Mask subtables may record `bestPossibleRank` and stop lookup when remaining tables cannot beat the current winner. WinnerRank is a runtime optimization, not persisted authoring priority and not a cross-stage rank.
_Avoid_: computing specificity on the packet path, exposing WinnerRank in the UI, comparing WinnerRank across enforcement stages

**L4 SubjectView**:
The compiled outer policy bucket selected once by the platform-optimized runtime subject key: complete Linux UID on Android or Runtime Subject Handle on Linux. It contains the subject's bounded NetworkContextId blocked-bit mask and separate IPv4/IPv6 L4 classifiers. Direction, concrete network/interface facts, protocol, CIDRs, and ports remain matcher dimensions inside those classifiers. A missing SubjectView contributes no Gate or L4 decision.
_Avoid_: package-name partition, subject multiplied by Network/Direction/Protocol contexts, wildcard-rule replication across outer buckets

**L4PolicyMatcher**:
The deep Module Interface that compiles and evaluates the Packet/L4 Compiled Policy View while hiding priority contexts, mask partitions, hashes, and residual range checks. Its result carries rule identity, action, and source attribution; callers do not depend on pool indexes or hash layout.
_Avoid_: VPP ACL as the product policy schema, UI selecting a matcher, matcher-owned authoring rules

**Basic IPRULES**:
IP packet rules that use packet facts without requiring L4 Conntrack state.
_Avoid_: stateful rules, `ct.*` rules

**Stateful IPRULES**:
Advanced IP packet rules that use L4 Conntrack state such as `ct.state` or `ct.direction`.
_Avoid_: ordinary IP rules, baseline packet policy

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
The in-graph rule that normal parsing, policy, observation, Primary Software Distribution, and owner handoff move only VPP buffer indexes/ownership and side metadata, never copy, clone, or reserialize complete packet bytes between workers or nodes. Explicit protocol-required consumers may perform bounded content movement only when their semantics require it, notably fragment or TCP stream reassembly. The inspected modified VPP `stellar_lpi` baseline is not such an exception: it inspects the current L4 payload in place and retains only small derived per-session features, identifiers, and counters rather than packet copies. Any later recognizer that demonstrably requires selected payload retention owns a named capacity/lifetime budget and measurement; recognition must retain only the minimum required content rather than treating this exception as permission to archive packets.
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
The caller-provided stable rule identity used to correlate an apply payload with committed rule mappings.
_Avoid_: treating it as the daemon-assigned `ruleId`

**ruleId**:
The daemon-assigned committed rule identity used in stats, packet attribution, and print output.
_Avoid_: assuming it is stable across every whole-policy apply unless the specific contract says so

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
Low-cost per-rule counters owned by packet-side rules. An active rule occurrence that wins the normal scan increments its own hit counter whether its effective mode is enforce or observe; record exports, when present, should use the same winner attribution fields rather than a separate observe-only model.
_Avoid_: separate shadow stats model, per-packet allocation, Debug Stream

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
The subject/app-level decision that eligible packets should enter L4 Conntrack before stateful or DPI-dependent facts are used. It keeps ordinary subjects off CT while avoiding per-rule packet-by-packet CT gating inside an advanced subject.
_Avoid_: global CT enable for all packets, single-rule prefilter deciding CT entry

**Unified CT entry**:
The single flow/session state record owned by L4 Conntrack for a given observed flow. Flow Telemetry counters, DPI state/results, debug/export state, and other flow-level attachments hang from this entry rather than creating separate per-consumer CT tables.
_Avoid_: DPI-specific CT table, telemetry CT table, duplicate flow tables

**Per-worker flow ownership**:
The target VPP runtime rule that one worker privately owns the mutable state of one bidirectional flow. Adapter-specific Initial Execution Placement is not ownership. Primary Software Distribution computes the final owner once on the ingress execution context and either continues locally or performs one Primary Handoff before owner-sensitive state. Downstream owner-local nodes use the current VPP worker directly and do not run a second owner calculation or corrective dispatch.
_Avoid_: shared authoritative flow table, queue id as owner, INPUT/OUTPUT thread as correctness

**Canonical Owner Key**:
The direction-independent key used to select an ExecutionOwner for every valid IPv4/IPv6 packet. Its L3 form contains key kind, IP family, terminal IP protocol, and the canonical address pair; its L4-ports form additionally contains the canonical port pair when typed transport ports are available. Unavailable ports are omitted rather than invented as zero-valued flow identity. Complete TCP/UDP packets use the L4-ports form, while other legal protocols and valid L3 packets with unavailable ports use the L3 form. Platform, deployment, direction, queue, interface, UID, Runtime Profile, provenance, CPU, and network-namespace facts never participate.
_Avoid_: treating every owner key as a five-tuple, zero-port synthetic flow, protocol-free address hash, CPU-aware packet hash, `flow_domain`

**ExecutionOwner**:
The VPP logical worker selected once from a Canonical Owner Key and the runtime-start-fixed Worker Layout. Every valid IPv4/IPv6 packet has an ExecutionOwner even when it is not eligible for a FlowEntry. The assignment remains stable for the active runtime generation, drives the sole Primary Handoff when the selected worker differs from Initial Execution Placement, and does not imply transport support or flow-state creation.
_Avoid_: arrival worker, VLIB thread index, Linux CPU ID, NFQUEUE lane, FlowEntry eligibility, overload spill target

**FlowOwner**:
The ExecutionOwner of a packet eligible for one bidirectional FlowEntry, currently a complete TCP/UDP packet using the L4-ports Canonical Owner Key. FlowOwner owns that entry and later protocol/session state; other legal protocols may have an ExecutionOwner without acquiring a FlowOwner or FlowEntry.
_Avoid_: ownerless ICMP/ESP/GRE execution, every packet creates flow state, separate FlowEntry hash-to-worker decision

**Canonical Flow Key**:
The direction-independent IPv4/IPv6 five-tuple that identifies one bidirectional FlowEntry: IP protocol plus the canonicalized source/destination address-and-port endpoint pair. It is the L4-ports form of the Canonical Owner Key for complete TCP/UDP traffic. Complete Linux UID, ApplicationSubjectId, NetworkContextId, Linux interface index, VPP interface index, queue, lane, Runtime Profile, VPN Packet Provenance, CPU, and network namespace never participate. Linux v1 runs only in the network namespace that owns its NFQUEUE Adapter; namespace isolation is a deployment boundary rather than a per-packet discriminator.
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
The exceptional pre-policy path that co-locates all fragments of one IP datagram for bounded reassembly, then delivers the reconstructed packet to the ExecutionOwner selected by its Canonical Owner Key. Fragment identity is temporary reassembly state and never becomes FlowEntry identity. Protocol-required reassembly is an explicit bounded exception to the VPP Packet Byte-Movement Contract and has Packet Byte Mutation Authority; ordinary fragment steering and worker handoff still move buffer indexes rather than copying packet bytes. Malformed, conflict, timeout, or capacity failure follows the inspected VPP reassembly behavior: runtime-drop every retained packet obligation with no Policy Verdict.
_Avoid_: treating non-initial fragments as if they contain ports, UID-based fragment dispatch, fragment-keyed FlowEntry, fail-open fragment bypass, reporting reassembly failure as policy drop

**FlowEntry**:
A bounded worker-owned record created only after early Network Gate/L4 policy returns `PASS_NEXT`. Its creating packet establishes Flow Direction `ORIG`, reversed endpoints are `REPLY`, and it records the creating packet's Device Packet Direction as `flowOriginDir`. It also holds flow identity, attribution, allowed-flow activity, the last evaluated policy revision, decision state, and optional later facts. On revision mismatch it preserves reusable flow facts but discards cached winner/verdict state and lazily re-evaluates on the next packet. The first product version's FlowEntry is not a full Stateful Conntrack promise. Packets dropped before creation have no Flow Direction.
_Avoid_: accepted-flow ledger, full TCP state machine, separate DPI flow table

**Flow Expiry**:
The point at which a FlowEntry's protocol deadline makes it logically expired, so a later lookup cannot reuse it as a still-valid flow. Owner-local finalization and resource release may follow with bounded delay; that cleanup delay does not extend the flow's logical lifetime.
_Avoid_: extending protocol timeout to accommodate cleanup, treating an expired entry as valid until a background sweep, equating logical expiry with immediate memory release

**ActivityAccumulator**:
A fixed-capacity, worker-private, loss-tolerant coalescing table for product Activity evidence when Network Gate or L4 policy drops before FlowEntry creation. It is keyed by bounded packet attribution such as complete UID, network/direction, five-tuple, winner rule reference, and policy revision, and stores first/last time plus packet/byte totals. Eviction may lose UI detail but never changes verdicts or exact app/rule counters.
_Avoid_: FlowEntry, policy cache, authoritative history, unbounded per-blocked-flow allocation, exact counter source

**DPI / L7 Policy**:
Future advanced policy based on flow/session protocol identification. It depends on stable per-worker flow identity; protocol-identification facts attach to the existing FlowEntry or later unified Session rather than requiring a separate DPI flow table or making full Conntrack a prerequisite for the Protocol Identification Release.
_Avoid_: packet-local DPI result, Traffic Windows protocol counters, replacing L3/L4 IPRULES

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
The shared Android Root and Linux Host Firewall policy that recoverable NFQUEUE infrastructure or packet-processing faults preserve connectivity whenever an accept verdict can still be completed. Missing listeners use queue bypass; supported kernel queue delivery/overflow paths are configured fail-open; parser-execution and ordinary worker-capacity faults with a valid packet identity return accept and record bounded fault/health evidence. An ingress event without Ingress Completion Identity never enters VPP and cannot be actively recovered by Sakamoto, although kernel fail-open/bypass may independently release it. Content that the shared VPP graph has positively classified as an invalid L3 packet is instead runtime-dropped according to VPP Packet Validation Outcome. Every packet retained by failed bounded fragment reassembly is also runtime-dropped with no Policy Verdict.
_Avoid_: silent unobserved bypass, conflating parser execution failure with an invalid packet, fail-closed overload for recoverable ordinary capacity faults, fail-open invalid L3, injecting a packet without completion identity, fail-open fragment failure, claiming recovery of an unavailable packet ID, treating a policy-rule DROP as an infrastructure fault

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
The consumer-driven telemetry mode that exports `FLOW` and `DNS_DECISION` records through a bounded shared-memory channel.
_Avoid_: always-on dashboard source, Debug Stream

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
The user-facing workflow for changing packet policy with a clear recovery path: observe-mode apply for trying a policy, Packet Diagnostics for explaining behavior, and component gates plus Checkpoint Restore for rescue. It is a frontend/product workflow over daemon primitives, not a separate daemon policy mode.
_Avoid_: standalone Try/Diagnose/Rescue daemon modules, global safety mode, global dry-run, shadow engine, diagnostics as a rescue prerequisite

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
The first-release Local Product Backend persistence implementation: one simple embedded store with one backend-side writer. Policy/configuration and bounded Activity use distinct tables and repository APIs because their durability semantics differ, but v1 does not pre-build separate database services, multiple physical stores, event sourcing, or an analytics pipeline. Physical isolation is introduced only when measured contention, capacity, or reliability evidence requires it.
_Avoid_: remote database, database microservice, speculative multi-store topology, event-sourced policy, UI-owned schema

**Activity Store**:
The bounded Activity portion of Product Store for product facts and derived queries. It continues ingest while the Android UI is closed, stores no packet payload, and applies age and storage-budget retention. Product UI only queries projections and keeps transient presentation caches. Exact embedded database engine, retention limits, and compaction schedule are implementation and release-testing choices.
_Avoid_: frontend history database, VPP writing SQLite, raw packet archive, unbounded history, one writer per UI client

**Metrics**:
Pull-style low-cardinality counters and health/performance summaries.
_Avoid_: using metrics for Top-K, history, timeline, or high-cardinality destination analytics

**Traffic Windows**:
Bounded relative-time traffic summaries for ordinary UI activity views. Traffic Windows have a basic always-on tier for low-cardinality app/device/window/direction counters and app ranking, and an optional detail tier for heavier Top-K summaries. Both tiers share the same device-scope configured windows. Per-app Traffic Windows are keyed by complete Linux UID, so the same appId in different Android users/profiles has separate counts. New windows only accumulate from the time they become active.
_Avoid_: separate Traffic Accounting concept, blocked bytes as usage, full history store, arbitrary time-range query, Flow Telemetry records, Debug Stream

**Traffic Windows Top-K**:
The optional detail tier inside Traffic Windows: bounded heavy-hitter summaries such as remote IP, protocol, and protocol-port leaders. Remote IP leaders may be approximate; small ordering differences near the tail are not audit-grade facts.
_Avoid_: exact destination ledger, unbounded per-destination map, full dimensional cube

**Diagnostic Focus**:
The single active, session-owned per-app or per-UID diagnostic focus gate that allows heavier packet/IPRULES explain, diagnostic streams, and focused diagnostic metrics for the selected subject.
_Avoid_: Traffic Windows, Flow Telemetry, ordinary observability, global debug mode, persistent app configuration

**Debug Stream**:
A legacy / generic name for short-window debug evidence streams. In the refactored packet-side model, use Packet Diagnostics and Diagnostic Focus; the old DNS stream remains a frozen DNS-line capability until the Domain/DNS line is reopened.
_Avoid_: long-term telemetry, normal dashboard API, new packet diagnostics API name

**Packet Diagnostics**:
The user-facing packet/IPRULES diagnostic mode opened by a diagnostics session. It is session-owned, targets one app or UID, emits JSON diagnostic events with full explain evidence, and is not part of normal telemetry records.
_Avoid_: Flow Telemetry, Traffic Windows, persistent app setting, developer internal trace

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
The next stage release that adds libprotoident application protocol facts and protocol rules to the same worker-owned FlowEntry and existing Product UI. A libprotoident result is final and immediately actionable within this release's recognition capability; it is not a provisional hint awaiting scanner or protocol-decoder confirmation.
_Avoid_: full NGFW, stream reassembly release, separate DPI product, candidate/decoded split, decoder confirmation requirement

**LpiRecognitionState**:
The bounded libprotoident lifecycle state attached to the worker-owned FlowEntry. It records `detecting`, `done`, or `exhausted` plus an ordered, duplicate-free sequence of exact final `ApplicationProtocolId` results and the payload-packet sequence where each first appeared. Tunnelling, NAT, STARTTLS, and other continue-recognition cases may append more than one final result; Protocol Policy incrementally maintains one winner over all rules satisfied by the current accumulated result set, and rebuilds that winner from retained results after a policy-revision or application-subject change. Only a current winning protocol `DROP` terminates the flow; the latest exact result is the default UI summary, while the full sequence remains Activity detail rather than rule precedence.
_Avoid_: first-result-only state, last-result-only history, treating an earlier result as provisional, isolated verdict per appended result, any-matched-deny-wins semantics, result discovery order as rule priority, decoder evidence fields in this release

**LPI Recognition Budget**:
The fixed internal upper bound on payload-bearing packets offered to libprotoident for one FlowEntry. Empty-payload packets do not consume it. The state becomes `done` when libprotoident stops normally and `exhausted` when the budget is consumed; neither state retries recognition for that flow. Only results mapped into the release's curated Application Protocol Catalog enter the result sequence; a terminal flow with no mapped result is product-level `unidentified`, while any non-empty sequence remains `identified` even if later continue-recognition exhausted its budget. The first default is benchmarked with the inspected fork's 20-payload-packet limit as a baseline and is not a first-release UI setting.
_Avoid_: unbounded per-flow detection, counting ACK-only packets, retry after exhaustion, user-facing expert tuning, treating 20 as validated without measurement

**Recognize-then-enforce**:
The Protocol Identification Release behavior where an early L4 allow returns `PASS_NEXT` and packets are never held waiting for recognition. A fact produced synchronously in the current VPP graph before Adapter completion may immediately drive Protocol Policy for that same packet; a fact arriving only after completion affects later packets. Earlier completed verdicts never change. A protocol rule cannot reopen a packet already dropped by Network Gate or L4 policy, so default-deny-and-allow-only-after-identification requires a future controlled-probe design and is outside the first two releases.
_Avoid_: pre-identification block, early-flow hold, intentionally delaying enforcement by one packet, strict first-packet enforcement, retroactive verdict change, later allow overriding an earlier deny

**Packet Decision Cutoff**:
The Adapter completion boundary for facts affecting one packet. Packet-local parsing, synchronous application evidence, and protocol facts produced before completion may participate in the current verdict without constituting a hold; asynchronous attribution or identification received afterward can update worker-owned flow state but affects only later packets.
_Avoid_: waiting for future facts, next-packet-only rule for synchronous facts, retroactive enforcement, treating normal graph execution as packet caching

### Runtime State

**Authoring Policy Bundle**:
The persisted control-plane policy source graph containing typed Policy Rule Families, reusable rule groups, bounded group nesting, and ApplicationSubjectId applicability bindings with binding mode. GateMatrix, L4RuleList, and later ProtocolRuleList share this bundle and its transaction history without becoming one universal rule type or priority space. Platform application metadata may be retained for display, but persisted policy identity is the tagged ApplicationSubjectId; Android Apply still compiles it to the optimized complete-Linux-UID `byUid` view. v1 rule-group nesting is capped at 3 group levels. The frontend edits this model through daemon commands; it is not a frontend-owned database and is not a compiled hot-path view.
_Avoid_: Runtime Snapshot, packet rule table, frontend-only state

**Stale UID Binding**:
An Authoring Policy Bundle binding whose complete Linux UID is not currently present on the device. It is valid saved configuration, not a commit validation failure. It remains user configuration for control-plane display and cleanup, but does not contribute runtime rules or capability summaries while stale.
_Avoid_: automatic deletion, package-name identity, runtime subject

**Draft**:
The editable Authoring Policy Bundle working state. It may contain uncommitted changes and is not an apply or restore source until committed.
_Avoid_: committed policy, runtime policy, checkpoint, hot-path snapshot

**Policy Commit / Committed Policy Revision**:
A persisted Authoring Policy Bundle revision produced from the draft after policy validation succeeds. It is the source for apply, but committing it never changes the datapath by itself; failed apply does not roll it back. It can be reset by restoring a checkpoint, including when it has not yet been applied.
_Avoid_: editable draft, checkpoint, runtime snapshot

**Draft Commit**:
The atomic operation that validates the draft and makes it the current committed policy revision. Failed commit leaves the draft edits available and leaves the committed policy unchanged.
_Avoid_: policy apply, checkpoint creation, runtime switch

**Checkpoint / Policy Bundle Checkpoint**:
One retained full Authoring Policy Bundle snapshot from a successful apply, including the source rules, rule groups, ApplicationSubjectId bindings, and per-rule apply status from that apply. A checkpoint may record both active and inactive rules, but it is not an editable draft, not an uncommitted policy revision, not a diff chain, and not the in-memory hot-path runtime view.
_Avoid_: Draft, uncommitted policy revision, frontend history database, Runtime Snapshot

**Runtime Snapshot**:
The in-memory datapath view compiled from the selected checkpoint, including all Compiled Policy Views, hot-path capability summaries, one policy revision, and source attribution needed to explain a winner. Packet execution reads this atomic snapshot, not the draft or checkpoint storage; stage-specific rule families are published as one runtime revision rather than separately applied policies. The concrete worker publication primitive remains an implementation decision.
_Avoid_: persisted checkpoint, editable policy draft, frontend rule group

**Policy Apply**:
The atomic operation that compiles and validates the current committed Authoring Policy Bundle off-path, publishes one complete Runtime Snapshot revision, then records success and its source checkpoint. Apply returns success only after publication. Failed apply leaves the committed policy unchanged, creates no checkpoint, and does not change the runtime snapshot; Apply never scans all FlowEntries or proactively terminates flows.
_Avoid_: draft commit, partial runtime switch, checkpoint restore

**Policy Revision Re-evaluation**:
The lazy existing-flow behavior after Runtime Snapshot publication. On the next packet, a FlowEntry whose stored policy revision differs from the active revision retains reusable identity, counters, CT state, and protocol facts, but clears decision caches, winner attribution, and allow/drop fast-path state before evaluating the new snapshot. Facts are not reconstructed from missed historical packets.
_Avoid_: grandfathering verdicts until flow expiry, eager full-table scan, retaining cached verdicts across revisions, replaying early payload

**Checkpoint Restore**:
The atomic operation that makes a selected checkpoint's Authoring Policy Bundle snapshot the current committed policy and runtime source. It is not a new apply, does not rewrite the checkpoint's apply-time status, and fails if the runtime snapshot cannot be rebuilt from that checkpoint. It requires no uncommitted draft changes; failed restore leaves the draft, committed policy, selected checkpoint, and runtime snapshot unchanged.
_Avoid_: draft save, partial rollback, best-effort restore, recomputed apply status

**RESETALL**:
The full reset pipeline that returns daemon memory state, observation state, configuration state, and persisted save tree to a clean baseline while the native daemon process remains under RuntimeService lifecycle ownership.
If an active runtime owner cannot return its state to the clean baseline, the RESETALL command fails and the failure is also reflected in Runtime health.
_Avoid_: daemon restart, daemon shutdown, process recycle, partial config reset, per-feature clear command, best-effort success

**Policy state**:
Verdict-affecting daemon state such as DomainPolicy, DomainLists, IPRULES, config gates, and checkpoint contents.
_Avoid_: mixing it with observational session buffers

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
