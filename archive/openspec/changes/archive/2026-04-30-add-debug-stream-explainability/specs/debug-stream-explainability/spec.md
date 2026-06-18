## ADDED Requirements

### Requirement: Debug Stream explainability is tracked-gated and non-overlapping
The system MUST treat vNext `STREAM.START(type="dns")` and `STREAM.START(type="pkt")` as tracked Debug Stream surfaces for per-event explainability.

For apps whose tracked snapshot is false, the system MUST NOT construct or emit per-event DNS or packet explanations. It SHALL continue to report aggregate `notice="suppressed"` events using the existing stream notice mechanism.

Debug Stream explainability MUST NOT add Flow Telemetry records, Metrics names, DEV query surfaces, persistent storage, Top-K, timeline/history aggregation, Geo/ASN, or DNS-to-packet join behavior.

#### Scenario: Untracked app suppresses debug evidence
- **GIVEN** an app has `tracked=0`
- **WHEN** DNS or packet traffic for that app reaches a subscribed vNext stream
- **THEN** the daemon SHALL NOT emit a per-event `dns` or `pkt` explanation for that traffic
- **AND** the daemon SHALL preserve the existing suppressed notice behavior

#### Scenario: Debug Stream does not create telemetry or metrics outputs
- **WHEN** a tracked `dns` or `pkt` Debug Stream event is emitted
- **THEN** the daemon SHALL NOT create an additional Flow Telemetry record because of that stream event
- **AND** the daemon SHALL NOT update a Debug Stream specific Metrics counter

### Requirement: DNS explanations carry the ordered DomainPolicy chain
A tracked `dns` stream event MUST include an `explain` object with:
- `version=1`
- `kind="dns-policy"`
- `inputs` containing at least `blockEnabled`, `tracked`, `domainCustomEnabled`, `useCustomList`, `domain`, `domMask`, and `appMask`
- `final` containing at least `blocked`, `getips`, `policySource`, `scope`, and optional `ruleId`
- `stages[]` in the stable DomainPolicy order

The DNS stage order MUST be:
- `app.custom.allowList`
- `app.custom.blockList`
- `app.custom.allowRules`
- `app.custom.blockRules`
- `deviceWide.allow`
- `deviceWide.block`
- `maskFallback`

Each stage MUST include `enabled`, `evaluated`, `matched`, `outcome`, and `winner`. A skipped stage MUST include `skipReason`.

Matched DNS rule stages MUST include self-contained rule snapshots with at least `ruleId`, `type`, `pattern`, `scope`, and `action`. Matched DNS list stages MUST include self-contained list-entry snapshots with at least `type`, `pattern`, `scope`, and `action`; stable list identifiers or names SHALL be included only when already available and cheap to expose.

#### Scenario: DNS app rule winner is explainable
- **GIVEN** an app has `tracked=1` and `domain.custom.enabled=1`
- **AND** app scope DomainPolicy rules block a queried domain
- **WHEN** the daemon emits the tracked `dns` stream event
- **THEN** `event.explain.kind` SHALL equal `"dns-policy"`
- **AND** `event.explain.final.blocked` SHALL be true
- **AND** one stage SHALL have `name="app.custom.blockRules"`, `matched=true`, `winner=true`, include the winning `ruleId`, and include the winning rule snapshot

#### Scenario: DNS list-entry winner is self-contained
- **GIVEN** an app has `tracked=1` and a custom list entry blocks a queried domain
- **WHEN** the daemon emits the tracked `dns` stream event
- **THEN** the winning list stage SHALL include a list-entry snapshot with the matched pattern, scope, and action
- **AND** the client SHALL NOT need to query current list state to explain the decision

#### Scenario: DNS fallback winner is explainable
- **GIVEN** an app has `tracked=1`
- **AND** no app or device-wide custom list/rule stage matches the queried domain
- **WHEN** the daemon emits the tracked `dns` stream event
- **THEN** `event.explain.stages` SHALL include a `name="maskFallback"` stage
- **AND** that stage SHALL expose `domMask`, `appMask`, the effective mask comparison value, `matched`, `outcome`, and `winner`

### Requirement: Packet explanations carry the ordered verdict chain
A tracked `pkt` stream event MUST include an `explain` object with:
- `version=1`
- `kind="packet-verdict"`
- `inputs` containing at least `blockEnabled`, `iprulesEnabled`, `direction`, `ipVersion`, `protocol`, `l4Status`, `ifindex`, `ifaceKindBit`, and conntrack state/direction when evaluated
- `final` containing at least `accepted`, `reasonId`, optional `ruleId`, optional `wouldRuleId`, and optional `wouldDrop`
- `stages[]` in the stable packet verdict order

The packet stage order MUST be:
- `ifaceBlock`
- `iprules.enforce`
- `domainIpLeak`
- `iprules.would`

Each stage MUST include `enabled`, `evaluated`, `matched`, `outcome`, and `winner`. A skipped stage MUST include `skipReason`.

Matched IPRULES stages MUST include self-contained rule definition snapshots with at least `ruleId`, `clientRuleId`, `matchKey`, `action`, `enforce`, `log`, `family`, `dir`, `iface`, `ifindex`, `proto`, `ct`, `src`, `dst`, `sport`, `dport`, and `priority`.

#### Scenario: IPRULES enforce winner is explainable
- **GIVEN** an app has `tracked=1`
- **AND** a packet matches an enforcing IPRULES block rule
- **WHEN** the daemon emits the tracked `pkt` stream event
- **THEN** `event.explain.kind` SHALL equal `"packet-verdict"`
- **AND** `event.explain.final.accepted` SHALL be false
- **AND** one stage SHALL have `name="iprules.enforce"`, `matched=true`, `winner=true`, include the winning `ruleId`, and include the winning rule definition snapshot

#### Scenario: IFACE_BLOCK short-circuits lower stages
- **GIVEN** an app has `tracked=1`
- **AND** interface policy blocks a packet before IPRULES evaluation
- **WHEN** the daemon emits the tracked `pkt` stream event
- **THEN** the `ifaceBlock` stage SHALL have `matched=true` and `winner=true`
- **AND** the `ifaceBlock` stage SHALL expose the app interface mask, packet interface bit/kind, evaluated intersection, and short-circuit reason
- **AND** lower-priority stages that were not evaluated SHALL have `evaluated=false` and `skipReason="shortCircuited"`

#### Scenario: Would-match overlay is explainable
- **GIVEN** an app has `tracked=1`
- **AND** a packet is finally accepted but matches an IPRULES `action=block,enforce=0,log=1` rule
- **WHEN** the daemon emits the tracked `pkt` stream event
- **THEN** `event.explain.final.accepted` SHALL be true
- **AND** `event.explain.final.wouldDrop` SHALL be true
- **AND** the `iprules.would` stage SHALL include the matching `wouldRuleId` and its rule definition snapshot

### Requirement: Candidate evidence is bounded and stable
Debug Stream explanations MUST cap each stage's candidate snapshot list at `maxExplainCandidatesPerStage=64`.

Domain rule candidate arrays MUST be ordered by ascending `ruleId`. IPRULES candidate arrays MUST follow effective evaluation order: priority descending, then `ruleId` ascending.

When matching candidates exceed the cap, the stage MUST set `truncated=true`. The winning rule snapshot MUST remain present even when the candidate list is truncated.

#### Scenario: Candidate list is truncated explicitly
- **GIVEN** more than 64 rules match one explanation stage
- **WHEN** the daemon emits the tracked Debug Stream event
- **THEN** that stage SHALL include at most 64 candidate snapshots
- **AND** that stage SHALL set `truncated=true`
- **AND** the winning rule snapshot SHALL be present in the event

### Requirement: Debug Stream removes normal observability responsibilities
The system MUST define Debug Stream as a per-event evidence surface only. It MUST NOT act as the normal DNS/packet record API, history API, timeline API, analytics surface, Top-K source, or Metrics replacement.

Existing `STREAM.START` replay arguments for `dns` and `pkt` SHALL be treated only as bounded in-process debug prebuffer controls. They MUST NOT imply durable history, Flow Telemetry replay, or timeline reconstruction.

`notice="suppressed"` SHALL only explain why tracked-gated debug events were not emitted. `notice="dropped"` SHALL only report loss of queued debug evidence.

`activity` SHALL remain outside Debug Stream explainability and MUST NOT gain an `explain` object or new telemetry responsibilities in this change.

#### Scenario: Replay is debug prebuffer only
- **WHEN** a client starts `STREAM.START(type="dns")` or `STREAM.START(type="pkt")` with replay parameters
- **THEN** replayed events SHALL come only from the bounded in-process stream buffer
- **AND** the daemon SHALL NOT query Flow Telemetry, Metrics, or persistent history to satisfy the replay

#### Scenario: Activity is not a Debug Stream explainability surface
- **WHEN** a client starts `STREAM.START(type="activity")`
- **THEN** emitted `activity` events SHALL NOT include an `explain` object
- **AND** the daemon SHALL NOT add new debug evidence, telemetry aggregation, or history semantics to activity events
