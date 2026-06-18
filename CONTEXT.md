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

### IP And L4 Policy

**IPRULES**:
The per-app L3/L4 IP rule engine for IPv4 and IPv6 packet policy, per-rule stats, and packet attribution.
_Avoid_: IPv4 rules, firewall rules without the IPRULES scope

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

**wouldRuleId / wouldDrop**:
Shadow-evaluation fields that describe a rule that would have affected a packet without changing the actual verdict.
_Avoid_: interpreting would fields as the executed verdict

**reasonId**:
Packet verdict attribution such as `IFACE_BLOCK`, `ALLOW_DEFAULT`, `IP_RULE_ALLOW`, or `IP_RULE_BLOCK`.
_Avoid_: treating reasonId as the verdict itself

**IFACE_BLOCK**:
A high-priority packet verdict caused by interface-kind mask policy, not by an IPRULES rule hit.
_Avoid_: IP rule block

**L4 Conntrack**:
The userspace connection state layer that provides flow identity, orig/reply direction, and `new/established/invalid` semantics for IPRULES and telemetry.
_Avoid_: packet cache, exact cache

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

**Debug Stream**:
A vNext short-window evidence stream for DNS or packet investigation, normally gated by tracked app state.
_Avoid_: long-term telemetry, normal dashboard API

**tracked**:
An app-level gate for Debug Stream visibility and suppressed-event behavior. It does not gate Flow Telemetry records or DomainPolicy source metrics.
_Avoid_: treating tracked as the general observability enable switch

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
