---
status: accepted
date: 2026-07-20
---

# One policy bundle, stage-owned rule families

Sakamoto has one authoritative Authoring Policy Bundle and one transactional policy revision, but it does
not force Network Gate, L4, protocol-identification, or future decoded-metadata policy into one universal
rule schema or one product-wide priority space. Each enforcement stage owns the predicates, priority levels,
compiled representation, and cache behavior appropriate to the facts available at that stage.

The first two product stages are:

```text
Packet capture Adapter
  -> FlowSteering
       non-fragment: Primary Software Distribution -> final owner
       owner mismatch: one Corrective Handoff; second mismatch -> DROP
       fragment: fragment co-location -> bounded reassembly -> final owner handoff
  -> Network Gate table
  -> priority-tiered stateless L4 classifier
  -> worker-owned FlowEntry / session
  -> libprotoident protocol facts
  -> project-owned Protocol Policy matcher and enforcer
```

Network Gate, L4 rules, and later protocol rules remain separate rule families inside the same persisted
bundle. They share complete-Linux-UID subject identity, one apply transaction, policy revision, stable source
references, diagnostics, and product attribution. They do not share predicate syntax or compare priorities
across stages.

**2026-09-11 scope clarification (user decision):** the current UID-grouped, priority-ordered
bounded rule scan is retained for the present implementation phase. This phase requires correct static
ACL matching, precedence, publication and stage behavior; implementing the mask/hash layout below is
not a prerequisite for S229 or FlowRuntime work. ACL will receive a separate design review and refactor
later. Existing retained design discussions may inform that review; ADR-0008 still excludes the removed
C++ implementation from use as a source reference. The following mask/hash paragraphs describe the
previously discussed design direction, not the current implementation or a frozen future choice.

The previously discussed L4 classifier design groups rules by
explicit priority level, lower numeric priority is evaluated first, and each level uses mask shapes, masked
hash lookup, and residual port-range checks. Sakamoto requires
complete-Linux-UID and Android network context, immutable publication, deterministic same-level behavior,
and bounded worst-case probes. Physical mask or pool traversal order is not allowed to become an accidental
policy tie-break. L4 precedence is fixed as `priority ascending -> explicit order ascending -> stable rule ID
ascending`; match specificity is not an implicit precedence dimension.

For the packet path, the compiler converts that precedence key into a compact consecutive `WinnerRank` inside
each compiled L4 view. Physical layout may flatten priority levels and group rules by mask shape across levels
instead of literally rescanning one mask pool per priority context. Each mask subtable records its
`bestPossibleRank`; lookup stops when the current winner is already better than every remaining bound. Exact
and wildcard ports stay on the masked-hash path, while range rules use bounded residual candidate lists.

Complete Linux UID is the only outer policy partition for the first release, following the useful `byUid`
organization of the previous Snort classifier. One UID lookup returns a compiled SubjectView containing the
Wi-Fi/Mobile/VPN blocked-bit mask and separate IPv4 and IPv6 L4 classifiers. Direction, network/interface kind,
optional ifindex, protocol, CIDRs, and ports remain classifier dimensions rather than multiplying outer
contexts. A missing SubjectView means open Gate, no L4 match, and `PASS_NEXT` to the default/later policy.

FlowSteering is a deep Module in front of policy evaluation. Its Primary Software Distribution selects the
final owner only from a direction-independent Canonical Flow Key containing the complete IPv4/IPv6
five-tuple, groups ingress packets by target, and delivers them directly to that worker. Both directions of an
ordinary flow reaching the same worker is a correctness guarantee, not best-effort affinity. UID,
network/interface context, capture queue, and Runtime Profile do not participate.

The Worker Layout is frozen before traffic starts: worker count, key-to-worker mapping, and bounded
worker-private session/cache capacities do not change during the runtime. An Owner Guard runs before any
worker-private policy counter or flow/session mutation. A correctly distributed packet continues locally; a
mismatch permits one Corrective Handoff to the calculated owner, and a second mismatch drops the packet as a
runtime fault. Primary distribution and correction use the same Owner Selector and Worker Layout, and queue
congestion never authorizes placing the flow on a different worker.

For fragmented IP, FlowSteering hides the fork-inspired two-stage path: co-locate fragments on a bounded
reassembly worker, retain the final owner computed from the first fragment's complete five-tuple, reconstruct
one policy-ready packet, and hand it to that owner when the two workers differ. This explicit Fragment
Steering transition is not a distribution error and does not consume the one Corrective Handoff allowance.
Fragment identity is not a second FlowEntry key. **SAKAMOTO-229 clarification, synchronized 2026-09-11:**
malformed/conflicting fragments terminate as runtime faults; timeout ends an incomplete datagram without
producing a Policy Verdict. Pure reassembly resource exhaustion uses processing bypass when original data
and a safe normal return path remain, with one NF_ACCEPT attempt per complete NFQUEUE original identity.
If return is unavailable, record no-return/transport failure and release owned resources. Already-decided
policy DROP remains DROP. This replaces the earlier blanket capacity runtime-drop wording with the current
S229 acceptance contract; an ACCEPT attempt does not establish delivery.

Sakamoto's Canonical Flow Key includes IP protocol. The port-aware L4 classifier evaluates only after
successful reassembly and final-owner handoff so non-initial fragments cannot bypass port rules.

Network Gate or L4 `DROP` occurs before full flow/session allocation. The hot path updates exact per-app/per-rule packet and byte
counters, then may coalesce bounded product evidence into a worker-private, loss-tolerant
ActivityAccumulator. That accumulator has fixed capacity, carries no policy or protocol state, and may evict
detail without changing verdicts or exact counters. Only `PASS_NEXT` traffic may create a worker-owned
FlowEntry and receive libprotoident, Conntrack, or future stream attachments.

Protocol policy does not extend the L4 classifier with libprotoident fields. Libprotoident facts enter the
worker-owned flow/session path and are matched by a project-owned Protocol Policy module. For the Protocol
Identification Release, a libprotoident result is the final actionable recognition result at that product
capability level; there is no candidate/decoded split and no deeper decoder confirmation. Its rules,
application objects, compiled matcher, and enforcer do not depend on MAAT. Useful continue-recognition
behavior from the inspected fork may be referenced for tunnels or protocol transitions, but its qDPI,
AppSketch, decoder, and MAAT data models are not compatibility requirements.

The FlowEntry keeps a bounded ordered sequence of duplicate-free libprotoident results and their first-seen
payload-packet sequence. Continue-recognition may append several final results; every new result is evaluated
by Protocol Policy. A prior allow does not finalize protocol policy for the flow, while any drop remains
terminal. Product summary may derive the latest result without discarding the recognition sequence.

Libprotoident work is bounded by a fixed internal budget counted only on payload-bearing packets. Normal
detector completion produces `done`; budget completion produces `exhausted`; both are terminal for that flow.
The initial value is selected by measurement, using the inspected fork's 20-payload-packet cap only as a
baseline, and is not exposed as a first-release product setting.

Every stage returns a simple datapath outcome: `DROP` terminates processing and `PASS_NEXT` continues to the
next stage. Therefore a Network Gate or L4 drop cannot be reopened later. An L4 allow means pass to the next
active stage, not product-wide terminal allow. Recognize-then-enforce can consequently allow early packets and
drop later packets after protocol identification without a global three-state policy algebra.

Policy Apply validates and publishes a complete successor runtime revision transactionally so runtime tables
from different policy revisions are not mixed. The exact worker publication primitive and existing-flow cache
invalidation mechanism are implementation decisions and are not fixed by this ADR.

## Consequences

- The UI may present Network Gates, advanced L4 rules, and protocol rules as related app controls without
  pretending they are the same rule type.
- The Local Product Backend remains the sole policy authority; separate compiled stage tables do not create
  separate frontend databases or separately applied configurations.
- L4 priority is local to the L4 stage. Protocol Policy has its own stage-local precedence and does not
  compare priority with L4.
- L4 same-level precedence is explicit source order, then stable rule ID; the compiler reduces the complete
  key to an integer WinnerRank for lookup and pruning.
- Complete Linux UID is looked up once per packet; Network, direction, protocol, and other rule dimensions do
  not create a Cartesian product of outer contexts.
- Complete Linux UID is only a policy partition. It never changes worker selection or FlowEntry identity.
- Normal traffic reaches its flow owner through Primary Software Distribution; Corrective Handoff is a
  one-shot fault path whose sustained use marks the runtime unhealthy.
- Worker Layout is immutable during a runtime. Policy Apply cannot reshard existing or future flows.
- Fragment Steering is internal to FlowSteering; Gate/L4/FlowEntry callers do not expose fragment-worker or
  second-handoff mechanics in their Interfaces.
- Match-set containment is useful for shadow/redundancy diagnostics and UI auto-placement, but is not a
  hidden cross-rule specificity rank.
- Current implementation work retains one bounded static L4 matcher. Its later structural redesign may
  revisit the priority/mask/hash discussions; the 2026-09-11 scope decision defers that work
  without weakening matching correctness or introducing a parallel matcher now.
- Stateless L4 matching does not own Sakamoto FlowEntry lifecycle and does not enable VPP ACL session or
  `permit+reflect` behavior.
- Early Gate/L4 drops do not allocate FlowEntry; bounded ActivityAccumulator loss is an observability event,
  not a policy or counter correctness failure.
- Per-worker single-owner FlowEntry remains the attachment point for libprotoident, later Conntrack, and
  future stream state.
