# Sakamoto Snort

Sakamoto Snort is an Android root daemon project for DNS/domain policy, IP packet policy, and bounded observability. This glossary captures project-specific language used across the current docs so agents do not drift back to legacy or OpenSpec-era terminology.

## Language

### Architecture Surfaces

**vNext control plane**:
The current daemon control surface for policy mutation, configuration, metrics, streams, telemetry, and checkpoint commands.
_Avoid_: legacy control, `60606` as the current surface

**Control Plane**:
The configuration and debug surface for immediate daemon operations. It does not own long-term storage, high-cardinality analytics, or dashboard history.
_Avoid_: analytics backend, history store

**Dataplane**:
The runtime packet and DNS execution path that produces verdicts and maintains only bounded hot-path state.
_Avoid_: storage layer, reporting backend

**RuntimeService**:
The Android-side owner of daemon startup, shutdown, artifact handoff, configuration sync, and post-start health checks.
_Avoid_: UI directly managing the native daemon

**Daemon lifecycle**:
Whether the native daemon process is running under the Android-side service owner. It is separate from daemon feature gates such as policy or observability switches.
_Avoid_: `block.enabled`, component gate, empty daemon mode

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

**Basic IPRULES**:
IP packet rules that use packet facts without requiring L4 Conntrack state.
_Avoid_: stateful rules, `ct.*` rules

**Stateful IPRULES**:
Advanced IP packet rules that use L4 Conntrack state such as `ct.state` or `ct.direction`.
_Avoid_: ordinary IP rules, baseline packet policy

**Hot-path capability summary**:
A compiled hot-path summary of which policy or observation consumers are needed for a packet subject, such as Conntrack, future DPI, Traffic Windows, Domain-IP Association, or debug evidence. The first read should be a 64-bit primary mask, with lazy secondary masks for richer CT/DPI/association pruning.
_Avoid_: scanning rules on every packet, enabling advanced facts globally

**family**:
The explicit IPRULES rule field declaring `ipv4` or `ipv6`; it is not inferred from `src` or `dst`.
_Avoid_: `family=any`, no-family IPv4 default

**matchKey**:
The canonical rule match identity used for conflict detection and apply-result mappings. The current form is `mk2`, which includes `family` and match dimensions but excludes action, priority, rule ids, and stats.
_Avoid_: treating `clientRuleId`, `ruleId`, or priority as part of the match identity

**clientRuleId**:
The caller-provided stable rule identity used to correlate an apply payload with committed rule mappings.
_Avoid_: treating it as the daemon-assigned `ruleId`

**ruleId**:
The daemon-assigned committed rule identity used in stats, packet attribution, and print output.
_Avoid_: assuming it is stable across every whole-policy apply unless the specific contract says so

**Rule execution mode**:
The per-rule state that decides whether a packet-side rule is disabled, actively enforced, or evaluated only for dry-run hit observation. Enforce and observe use the same winner attribution shape; observe differs by not applying the declared action to the actual verdict.
_Avoid_: treating shadow evaluation as only an external debug session

**Rule hit counters**:
Low-cost per-rule counters owned by packet-side rules. An enabled rule that wins the normal scan increments its own hit counter whether it is in enforce or observe mode; record exports, when present, should use the same winner attribution fields rather than a separate observe-only model.
_Avoid_: separate shadow stats model, per-packet allocation, Debug Stream

**wouldRuleId / wouldDrop**:
Legacy would-match fields from the old packet stream model. The refactored packet-side rule model should use `ruleId` plus rule execution mode instead of a parallel would-match attribution shape.
_Avoid_: new observe-mode attribution, compatibility-driven API design

**reasonId**:
Packet verdict attribution such as `IFACE_BLOCK`, `ALLOW_DEFAULT`, `IP_RULE_ALLOW`, or `IP_RULE_BLOCK`.
_Avoid_: treating reasonId as the actual verdict itself

**IFACE_BLOCK**:
A high-priority packet verdict caused by interface-kind mask policy, not by an IPRULES rule hit.
_Avoid_: IP rule block

**L4 Conntrack**:
The userspace connection state layer that provides flow identity, orig/reply direction, and `new/established/invalid` semantics for advanced policy and observation. It is a strategic datapath primitive for `ct.*` rules, full-flow observation, future DPI/L7 policy, and gateway mode; it is not a baseline or ordinary Traffic Windows dependency.
_Avoid_: packet cache, exact cache, baseline accounting, ordinary-user default feature

**ct consumer**:
An active rule or telemetry path that needs conntrack state for a UID and family.
_Avoid_: assuming conntrack is an unconditional per-packet cost

**l4Status**:
The packet parser classification for known L4, legal other terminal protocol, fragment, or invalid/unavailable L4.
_Avoid_: overloading `protocol=other` to mean every invalid or unavailable L4 case

**NFQUEUE topology**:
The daemon-start packet worker layout, currently defaulting to `split-in-out` with `shared-flow-pool` as an experimental mode.
_Avoid_: treating queue topology as a correctness guarantee

### Multi-User Identity

**complete Linux UID**:
The full Android UID including userId high bits and appId low bits. Core daemon identity uses complete Linux UID.
_Avoid_: treating appId alone as a globally unique app identity

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

**DNS_DECISION record**:
A telemetry record for blocked DNS decisions and DomainPolicy attribution. It is separate from packet and flow records.
_Avoid_: DNS-to-IP join record

**L3_OBSERVATION**:
A telemetry-only `FLOW` observation for fragments or invalid/unavailable L4 packets; it is not a normal L4 lifecycle.
_Avoid_: pretending malformed or fragmentary traffic is a normal TCP/UDP/ICMP flow

**Telemetry consumer**:
The external component, usually app-side, that opens telemetry, reads shared-memory records, and owns persistence, queries, and aggregation.
_Avoid_: daemon-side Top-K or history database

**Metrics**:
Pull-style low-cardinality counters and health/performance summaries.
_Avoid_: using metrics for Top-K, history, timeline, or high-cardinality destination analytics

**Baseline accounting**:
The always-on low-cardinality traffic accounting available while the dataplane is running, scoped to app/device packet totals and original IP packet bytes.
_Avoid_: copied-prefix length, L4 payload-only bytes, Flow Telemetry, Debug Stream, destination history, Top-K analytics

**Traffic Windows**:
Bounded relative-time traffic summaries for ordinary UI activity views, centered on accepted usage bytes/packets with blocked packet counts as separate policy-attempt counters. They are designed for ordinary-user long-lived enablement, not arbitrary absolute-time history, and new windows only accumulate from the time they become active.
_Avoid_: baseline accounting, blocked bytes as usage, full history store, arbitrary time-range query, Flow Telemetry records, Debug Stream

**Traffic Windows Top-K**:
The bounded heavy-hitter summaries inside Traffic Windows, such as remote IP, protocol, and protocol-port leaders. Remote IP leaders may be approximate with a bounded error; small ordering differences near the tail are not audit-grade facts.
_Avoid_: exact destination ledger, unbounded per-destination map, full dimensional cube

**Diagnostic Focus**:
The single active, session-owned per-app or per-UID diagnostic focus gate that allows heavier packet/DNS explain, diagnostic streams, and focused diagnostic metrics for the selected subject.
_Avoid_: baseline accounting, Traffic Windows, Flow Telemetry, ordinary observability, global debug mode, persistent app configuration

**Debug Stream**:
A vNext short-window evidence stream for DNS or packet investigation, normally gated by Diagnostic Focus.
_Avoid_: long-term telemetry, normal dashboard API

**Packet Diagnostics**:
The user-facing packet/IPRULES diagnostic mode opened by a diagnostics session. It is session-owned, targets one app or UID, emits JSON diagnostic events with full explain evidence, and is not part of normal telemetry records.
_Avoid_: Flow Telemetry, Traffic Windows, persistent app setting, developer internal trace

**tracked**:
Legacy name for the old app-level Debug Stream gate. The refactored packet diagnostics model should use Diagnostic Focus instead.
_Avoid_: new configuration name, persistent diagnostics state, treating tracked as the general observability enable switch

**PerfMetrics**:
Short-window latency and health instrumentation for diagnosing datapath cost.
_Avoid_: always-on product dashboard metrics

**RDNS / rdns.enabled**:
Diagnostic-only reverse-DNS enrichment. It may help explain traffic, but it is not an enforcement dependency.
_Avoid_: making IPRULES enforcement depend on reverse DNS

### Runtime State

**Policy Bundle Checkpoint**:
A fixed-slot daemon snapshot and restore primitive for verdict-affecting policy state.
_Avoid_: frontend history database, user-facing checkpoint metadata store

**RESETALL**:
The full reset pipeline that returns daemon memory state, observation state, and persisted save tree to a clean baseline.
_Avoid_: partial config reset, per-feature clear command

**Policy state**:
Verdict-affecting daemon state such as DomainPolicy, DomainLists, IPRULES, config gates, and checkpoint contents.
_Avoid_: mixing it with observational session buffers

**Observability session state**:
Runtime state for streams, telemetry consumers, suppressed notices, and record assembly. RESETALL or checkpoint restore may force clients to reopen sessions.
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
