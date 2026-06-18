## Context

vNext streams already provide bounded `dns`, `pkt`, and `activity` event delivery with replay, `started`, `suppressed`, and `dropped` notices. Flow Telemetry now owns normal high-cardinality facts through shared-memory `FLOW` and `DNS_DECISION` records, so vNext streams should not duplicate that role.

The remaining gap is debug explainability. A user investigating one tracked app needs to answer why a DNS request or packet verdict happened without stitching together stream fields, metrics snapshots, rule dumps, and manual policy reasoning. Existing stream events carry winner fields such as `policySource`, `ruleId`, `reasonId`, and `wouldRuleId`, but not the ordered policy chain, shadowed branches, skipped stages, full rule/list snapshots, or bounded candidate evidence.

The constraints are the existing hot-path boundaries: packet/DNS verdict code must not perform socket I/O, JSON formatting, disk/network I/O, unbounded scans, or long blocking locks. Detailed stream output is acceptable only behind `tracked=1`; untracked apps continue to produce only aggregate suppressed notices.

## Goals / Non-Goals

**Goals:**

- Reposition `STREAM.START(type=dns|pkt)` as Debug Stream output while keeping the command shape and stream state machine.
- Add structured `explain` objects to tracked DNS and packet events so a client can reconstruct the ordered decision chain from the event alone, without follow-up rule/list/control queries.
- Make explanations complete enough for policy debugging: winner, skipped stages, shadowed stages, matched rule/list definition snapshots, final verdict, and key inputs.
- Keep output bounded with explicit `truncated` markers.
- Preserve Flow Telemetry and Metrics boundaries: no records, Top-K, timeline/history, or long-term storage in this change.
- Re-scope legacy stream duties in this same change: replay is a bounded debug prebuffer, notices explain debug delivery/suppression, and `activity` is not part of Debug Stream explainability.
- Keep JSON serialization and socket writes out of DNS/packet hot paths.

**Non-Goals:**

- No new `STREAM.START(type=debug)` stream type.
- No expansion of `activity` stream behavior; it remains command-compatible but outside Debug Stream explainability.
- No new `METRICS.*`, `DEV.*`, Flow Telemetry ABI, or persistent schema.
- No DNS-to-packet join, domain-to-flow correlation, Geo/ASN, destination annotations, or consumer database work.
- No guarantee of lossless debug delivery; stream pending queues remain bounded and may drop events with notices.

## Decisions

1. **Existing `dns` and `pkt` streams become the Debug Stream contract.**

   The command surface remains `STREAM.START(type="dns"|"pkt"|"activity")`. `dns` and `pkt` events gain `explain`; `activity` remains command-compatible but is not a Debug Stream explainability surface and does not gain new fields or responsibilities. This avoids a fourth stream type and keeps client subscription routing simple: subscribe to the event family being debugged.

   Alternative considered: `STREAM.START(type="debug")` multiplexing DNS and packet events. Rejected because the existing per-type single-subscriber and replay model already fits DNS and packet event families, and a multiplexed stream would add ordering and filtering questions without improving the tracked-gated debug workflow.

2. **`tracked=1` is the cost and noise gate.**

   The daemon constructs per-event debug explanations only for apps whose tracked snapshot is true. `tracked=0` continues to skip per-event construction and accumulates suppressed traffic notices. This matches the intended workflow: users enable debug detail only for the app under investigation.

   This change does not introduce a separate `explain=1` argument. Once an app is tracked, the stream is the debug surface and should carry complete evidence.

3. **`explain.version=1` is the authoritative, self-contained evidence object.**

   Existing top-level event fields may remain as compatibility summaries, but clients should treat `explain` as the authoritative decision chain. The object is schema-versioned independently from the stream protocol and must include the rule/list/mask snapshots needed to explain the decision without issuing follow-up control queries.

   DNS `explain` contains:
   - `version=1`, `kind="dns-policy"`.
   - `inputs`: `blockEnabled`, `tracked`, `domainCustomEnabled`, `useCustomList`, `domMask`, `appMask`, and the normalized queried domain.
   - `final`: `blocked`, `getips`, `policySource`, `scope`, optional `ruleId`.
   - `stages[]`: ordered DomainPolicy stages with stable names, `enabled`, `evaluated`, `matched`, `outcome`, `winner`, optional `ruleIds`, `ruleSnapshots`, `listEntrySnapshots`, `truncated`, and `skipReason`.
   - DNS rule snapshots contain at least `ruleId`, `type`, `pattern`, `scope`, and `action`.
   - DNS list-entry snapshots contain at least `type`, `pattern`, `scope`, and `action`; stable `listId` or list names are included only when they already exist and are cheap to expose.
   - `maskFallback` includes the effective mask comparison inputs: `domMask`, `appMask`, the computed intersection/effective value used by the verdict, `outcome`, and `winner`.

   Packet `explain` contains:
   - `version=1`, `kind="packet-verdict"`.
   - `inputs`: `blockEnabled`, `iprulesEnabled`, packet family/direction/proto/L4 status/interface fields, and conntrack state/direction when evaluated.
   - `final`: `accepted`, `reasonId`, optional `ruleId`, optional `wouldRuleId`, optional `wouldDrop`.
   - `stages[]`: ordered packet stages with stable names, `enabled`, `evaluated`, `matched`, `outcome`, `winner`, optional `ruleIds`, `ruleSnapshots`, `truncated`, and `skipReason`.
   - IPRULES snapshots contain at least `ruleId`, `clientRuleId`, `matchKey`, `action`, `enforce`, `log`, `family`, `dir`, `iface`, `ifindex`, `proto`, `ct`, `src`, `dst`, `sport`, `dport`, and `priority`.
   - `ifaceBlock` includes app interface mask, packet interface bit/kind, the evaluated intersection, `outcome`, and the short-circuit reason when it wins.

4. **Stable stage names and ordering are part of the contract.**

   DNS stage order:
   - `app.custom.allowList`
   - `app.custom.blockList`
   - `app.custom.allowRules`
   - `app.custom.blockRules`
   - `deviceWide.allow`
   - `deviceWide.block`
   - `maskFallback`

   Packet stage order:
   - `ifaceBlock`
   - `iprules.enforce`
   - `domainIpLeak`
   - `iprules.would`

   A later stage can be `evaluated=false` with `skipReason="shortCircuited"` when an earlier winner ends the decision. A disabled feature uses `skipReason="disabled"`. Missing L4/conntrack prerequisites use specific skip reasons such as `l4Unavailable`, `fragment`, or `ctUnavailable`.

5. **Candidate evidence is self-contained but bounded.**

   Candidate arrays use stable order:
   - Domain rule stages: ascending `ruleId`.
   - IPRULES stages: effective evaluation order, priority descending then `ruleId` ascending.

   Each candidate snapshot array is capped at `maxExplainCandidatesPerStage=64`. Stages may also expose `ruleIds` as a compact compatibility index, but the snapshots are the authoritative evidence. If more candidates match, the stage sets `truncated=true` and may include `omittedCandidateCount` when cheaply known. The winning rule snapshot must be present even if candidates are truncated.

6. **Implementation uses debug snapshots, not JSON in hot paths.**

   `ControlVNextStreamManager::{DnsEvent,PktEvent}` should carry compact C++ snapshot structs. The stream writer converts them to JSON. Helpers should use RAII/standard containers, avoid raw owning pointers, and preserve const-correctness.

   DNS explain helpers may scan rule attribution snapshots only on tracked DNS events. Packet explain helpers may call new IPRULES debug evaluation APIs only on tracked packet events. The normal `IpRulesEngine::evaluate()` hot path remains unchanged for non-tracked and non-stream work.

7. **No overlap with Flow Telemetry or Metrics.**

   Debug Stream explains a single observed decision in detail. It must not emit durable flow records, aggregate counters, Top-K, timelines, or health metrics. Flow Telemetry remains responsible for normal business records; Metrics remains responsible for low-cardinality pull counters.

8. **Legacy stream responsibilities are cleaned up in this change.**

   The implementation and documentation must stop describing `dns`/`pkt` streams as normal observability history, timeline, or analytics surfaces. Existing `STREAM.START` replay arguments remain command-compatible, but their meaning is a bounded debug prebuffer for recent in-process evidence only, not a historical query API. `notice="suppressed"` exists only to explain why tracked-gated debug events were not emitted. `notice="dropped"` exists only to report loss of queued debug evidence. `activity` remains outside this Debug Stream contract and must not gain explain fields or replacement telemetry semantics here.

## Risks / Trade-offs

- [Risk] Debug events become large for broad rulesets. -> Mitigation: tracked-only construction, per-stage candidate caps, `truncated=true`, and existing stream drop notices.
- [Risk] IPRULES debug evaluation diverges from the real matcher. -> Mitigation: derive winner/candidate selection from the same compiled snapshot ordering used by `evaluate()` and add host tests comparing real verdict and explain winner.
- [Risk] DNS rule/list explanation adds cost to DNS verdicts. -> Mitigation: only construct explain for tracked apps and reuse existing lock-free rule attribution snapshots.
- [Risk] Existing clients expect current top-level stream fields. -> Mitigation: keep compatibility summaries where practical, stop treating them as authoritative debug evidence, and document `explain` as the new contract.
- [Risk] Replay may be mistaken for a history API. -> Mitigation: document replay as a bounded debug prebuffer only; `explain.version=1` and stream ring remains in-process only; RESETALL/STOP clears replay state as today.

## Migration Plan

- Implement as a stream event contract change inside one OpenSpec change: additive `explain` objects plus documentation/tests that remove normal telemetry/history responsibilities from Debug Stream.
- Update `docs/INTERFACE_SPECIFICATION.md` together with implementation.
- Keep command compatibility and the legacy stream state machine, but document replay and notices as debug-only delivery mechanics.
- Rollback is straightforward: omit `explain` construction/serialization while leaving existing summary fields and stream mechanics intact.
