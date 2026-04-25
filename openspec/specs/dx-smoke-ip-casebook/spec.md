# dx-smoke-ip-casebook Specification

## Purpose
Define the active vNext datapath smoke responsibility for the IP casebook, covering `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP` Case 1–8 through the existing `dx-smoke-datapath` and `tests/device/ip/run.sh --profile smoke` entrypoints.
## Requirements
### Requirement: dx-smoke-datapath covers IP casebook cases
`dx-smoke-datapath` MUST use the active vNext IP smoke profile to cover `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP` Case 1–8. The implementation MUST keep the existing public entrypoints unchanged: `dx-smoke-datapath` and `tests/device/ip/run.sh --profile smoke`.

The IP casebook smoke scope MUST exclude `## IP - Conntrack`; conntrack coverage MUST NOT be added to this change's smoke responsibility.

#### Scenario: Run active IP casebook smoke
- **WHEN** a developer runs `dx-smoke-datapath`
- **THEN** the datapath stage SHALL execute `tests/device/ip/run.sh --profile smoke`
- **AND** that smoke profile SHALL cover IP Case 1–8 through vNext control paths
- **AND** it SHALL NOT require a new `dx-smoke*` entrypoint or profile name

#### Scenario: Conntrack remains out of scope
- **WHEN** the IP casebook smoke is implemented for this change
- **THEN** it SHALL NOT add `## IP - Conntrack` assertions to the active smoke profile as part of this change

### Requirement: IPRULES surface smoke exposes stable output contracts
The IP casebook smoke MUST verify the vNext `IPRULES.PREFLIGHT`, `IPRULES.APPLY`, and `IPRULES.PRINT` surface without requiring real datapath traffic.

At minimum, the smoke MUST verify:
- `IPRULES.PREFLIGHT` returns `summary`, `limits`, `warnings`, and `violations`.
- `IPRULES.APPLY` returns committed rule mappings with numeric `ruleId` and string `matchKey`.
- `IPRULES.PRINT` returns rules in stable order with canonical CIDR output and a `stats` object containing packet and byte counters.

#### Scenario: IPRULES surface contracts are visible
- **WHEN** the IP smoke runs its surface case
- **THEN** `IPRULES.PREFLIGHT` SHALL expose the required report keys
- **AND** `IPRULES.APPLY` SHALL expose rule mapping fields
- **AND** `IPRULES.PRINT` SHALL expose canonical rules and runtime stats fields

### Requirement: Tier-1 verdict cases assert real connectivity and attribution
The IP casebook smoke MUST verify Tier‑1 allow, block, would-match, and IFACE_BLOCK behavior with real TCP traffic through the netns+veth topology.

For each verdict case:
- allow and would-match traffic MUST assert that TCP connectivity succeeds.
- block and IFACE_BLOCK traffic MUST assert that TCP connectivity fails.
- pkt stream assertions MUST filter by uid, peer IP, direction, port, reasonId, and rule attribution.
- reasons metrics MUST be reset before the trigger and then checked for the expected reason bucket.
- per-app traffic metrics MUST be reset before the trigger and then checked for the expected dimension bucket.
- per-rule stats MUST be checked where the verdict is caused by an IPRULES rule.

#### Scenario: Allow rule is a complete datapath closure
- **WHEN** a matching enforce allow rule is installed and Tier‑1 TCP traffic is triggered
- **THEN** the TCP connection SHALL succeed
- **AND** pkt stream SHALL report `IP_RULE_ALLOW` with the matching `ruleId`
- **AND** reasons, traffic, and per-rule hit packet counters SHALL increase in the allow buckets

#### Scenario: Block rule is a complete datapath closure
- **WHEN** a matching enforce block rule is installed and Tier‑1 TCP traffic is triggered
- **THEN** the TCP connection SHALL fail
- **AND** pkt stream SHALL report `IP_RULE_BLOCK` with the matching `ruleId`
- **AND** reasons, traffic, and per-rule hit packet counters SHALL increase in the block buckets

#### Scenario: Would-match preserves connectivity with attribution
- **WHEN** a matching `action=block,enforce=0,log=1` rule is installed and Tier‑1 TCP traffic is triggered
- **THEN** the TCP connection SHALL succeed
- **AND** pkt stream SHALL report actual verdict `ALLOW_DEFAULT`
- **AND** pkt stream SHALL include `wouldRuleId` and `wouldDrop`
- **AND** reasons, traffic, and per-rule would-hit packet counters SHALL reflect the would-match path

#### Scenario: IFACE_BLOCK wins without rule stats
- **WHEN** an app `block.ifaceKindMask` matches the Tier‑1 egress interface and Tier‑1 TCP traffic is triggered
- **THEN** the TCP connection SHALL fail
- **AND** pkt stream SHALL report `IFACE_BLOCK`
- **AND** pkt stream SHALL NOT include `ruleId` or `wouldRuleId`
- **AND** reasons and traffic block buckets SHALL increase
- **AND** lower-priority IPRULES stats SHALL NOT increase due to IFACE_BLOCK

### Requirement: Datapath gates are tested for correctness
The IP casebook smoke MUST verify the two datapath gates documented by the casebook:
- When `block.enabled=0`, packet datapath metrics and reasons MUST NOT grow from the test trigger, and pkt stream MUST NOT emit a matching packet event.
- When `iprules.enabled=0`, existing IPRULES rules MUST NOT affect verdict or rule stats, and matching traffic MUST fall back to `ALLOW_DEFAULT`.

Both gates MUST be restored after the case to avoid polluting later smoke cases.

#### Scenario: block.enabled disables datapath accounting
- **WHEN** `block.enabled` is set to `0` and Tier‑1 traffic is triggered
- **THEN** reasons metrics SHALL remain at zero for the trigger
- **AND** per-app traffic metrics SHALL remain at zero for the trigger
- **AND** pkt stream SHALL NOT emit a matching packet verdict event for the trigger

#### Scenario: iprules.enabled disables rule matching only
- **WHEN** a matching block rule exists and `iprules.enabled` is set to `0`
- **THEN** Tier‑1 TCP connectivity SHALL succeed
- **AND** pkt stream SHALL report `ALLOW_DEFAULT` without `ruleId` or `wouldRuleId`
- **AND** the matching rule's hit counters SHALL NOT increase
- **AND** traffic allow and `ALLOW_DEFAULT` reasons buckets SHALL increase

### Requirement: Payload bytes smoke uses deterministic Tier-1 traffic
The IP casebook smoke MUST include a payload-based Tier‑1 allow case that reads a fixed number of bytes from the TCP zero server and uses that trigger for stable byte counter assertions.

The payload case MUST:
- Assert the client reads exactly the requested payload byte count.
- Install allow rules sufficient to observe inbound payload and outbound handshake/ACK traffic.
- Assert per-app byte counters and reasons byte counters using thresholds compatible with NFQUEUE packet-length accounting.
- Assert per-rule `hitBytes` for the rule that observes the payload direction.

#### Scenario: Payload traffic drives byte counters
- **WHEN** the smoke reads a fixed payload of `N` bytes from the Tier‑1 TCP zero server under matching allow rules
- **THEN** the client-observed byte count SHALL equal `N`
- **AND** `traffic.rxb.allow` SHALL be greater than or equal to `N`
- **AND** `traffic.txp.allow` SHALL be greater than or equal to `1`
- **AND** `IP_RULE_ALLOW.bytes` SHALL be greater than or equal to `N`
- **AND** the inbound allow rule's `hitBytes` SHALL be greater than or equal to `N`

### Requirement: IP casebook documentation is kept aligned with smoke checks
After implementing the IP casebook smoke, the documentation MUST identify the active check ids that cover each `## IP` Case 1–8 and MUST remove or update obsolete gap notes for those cases.

The coverage matrix MUST also describe the new IP casebook coverage without claiming Conntrack coverage for this change.

Any Snort daemon/product behavior error found during validation or device testing MUST be recorded in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md` with enough context to reproduce and triage it. Errors caused by the test implementation itself MUST NOT be recorded in that file.

#### Scenario: Casebook points to implemented checks
- **WHEN** a developer reads `docs/testing/DEVICE_SMOKE_CASEBOOK.md` after this change
- **THEN** each `## IP` Case 1–8 SHALL list current smoke check ids or an explicit remaining caveat
- **AND** no completed IP case SHALL retain a stale “暂无 smoke” gap note

#### Scenario: Coverage matrix reflects IP-only scope
- **WHEN** a developer reads `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md` after this change
- **THEN** the matrix SHALL describe IP Case 1–8 coverage under `dx-smoke-datapath`
- **AND** it SHALL NOT describe `## IP - Conntrack` as completed by this change

#### Scenario: Product behavior errors are logged
- **WHEN** validation or device testing exposes a Snort daemon/product behavior error
- **THEN** `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md` SHALL record the command, environment, expected result, actual result, and relevant logs
- **AND** errors caused by the test implementation itself SHALL NOT be recorded in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`
