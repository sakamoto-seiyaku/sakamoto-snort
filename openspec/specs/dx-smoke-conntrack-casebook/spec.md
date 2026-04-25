# dx-smoke-conntrack-casebook Specification

## Purpose
Define the active vNext datapath smoke responsibility for the conntrack casebook, covering `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP - Conntrack` Case 1 through the existing `dx-smoke-datapath` and `tests/device/ip/run.sh --profile smoke` entrypoints.

## Requirements
### Requirement: dx-smoke-datapath covers conntrack casebook
`dx-smoke-datapath` MUST use the active vNext IP smoke profile to cover `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP - Conntrack` Case 1. The implementation MUST keep the existing public entrypoints unchanged: `dx-smoke-datapath` and `tests/device/ip/run.sh --profile smoke`.

The conntrack smoke scope MUST be limited to the Tier‑1 minimal CT state/direction closure. It MUST NOT add new `dx-smoke*` entrypoints, new profile names, perf/stress/longrun responsibilities, or stronger flow-state semantics as part of this change.

#### Scenario: Run active conntrack casebook smoke
- **WHEN** a developer runs `dx-smoke-datapath`
- **THEN** the datapath stage SHALL execute `tests/device/ip/run.sh --profile smoke`
- **AND** that smoke profile SHALL include the conntrack casebook case through vNext control paths
- **AND** it SHALL NOT require a new `dx-smoke*` entrypoint or profile name

#### Scenario: Conntrack case remains minimal
- **WHEN** the conntrack casebook smoke is implemented for this change
- **THEN** it SHALL cover the documented Tier‑1 CT Case 1 only
- **AND** it SHALL NOT add perf, matrix, stress, longrun, UDP, ICMP, or multi-flow CT coverage to the active smoke responsibility

### Requirement: Conntrack allow path verifies state direction and payload
The conntrack smoke MUST verify an allow path using real Tier‑1 TCP payload traffic. The allow rules MUST use non-`any` conntrack dimensions so the test proves conntrack gating is active.

At minimum, the allow phase MUST:
- Reset daemon state with `RESETALL` before establishing the conntrack baseline.
- Install an outbound allow rule for `ct.state=new` and `ct.direction=orig`.
- Install an inbound allow rule for `ct.state=established` and `ct.direction=reply`.
- Trigger a fixed TCP payload read of `N` bytes through the Tier‑1 netns+veth topology.
- Assert that the client reads exactly `N` bytes.
- Assert both allow rules report `stats.hitPackets>=1` through `IPRULES.PRINT`.

#### Scenario: Allow rules match new orig and established reply packets
- **WHEN** the conntrack smoke installs matching `new/orig` outbound and `established/reply` inbound allow rules
- **AND** Tier‑1 TCP payload traffic reads `N` bytes
- **THEN** the client-observed byte count SHALL equal `N`
- **AND** the `new/orig` allow rule SHALL report `hitPackets>=1`
- **AND** the `established/reply` allow rule SHALL report `hitPackets>=1`

### Requirement: Conntrack metrics prove create on accept
The conntrack smoke MUST use `METRICS.GET(name=conntrack)` to verify create-on-accept behavior for the allow phase. Because conntrack metrics are global and `METRICS.RESET(name=conntrack)` is not supported, the smoke MUST establish its baseline with `RESETALL`.

At minimum, the allow phase MUST assert:
- Before triggering traffic after `RESETALL`, `totalEntries==0` and `creates==0`.
- After accepted CT traffic, `creates>=1` and `totalEntries>=1`.

#### Scenario: Accepted conntrack traffic creates an entry
- **WHEN** the smoke has reset daemon state and reads `METRICS.GET(name=conntrack)`
- **THEN** `totalEntries` SHALL equal `0`
- **AND** `creates` SHALL equal `0`
- **WHEN** matching CT allow rules accept Tier‑1 TCP payload traffic
- **THEN** a subsequent `METRICS.GET(name=conntrack)` SHALL report `creates>=1`
- **AND** it SHALL report `totalEntries>=1`

### Requirement: Conntrack block path verifies no create and attribution
The conntrack smoke MUST verify an enforce block path for `ct.state=new` and `ct.direction=orig` using real Tier‑1 TCP traffic.

At minimum, the block phase MUST:
- Reset daemon state with `RESETALL` before installing the block rule.
- Install a matching outbound block rule for `ct.state=new` and `ct.direction=orig`.
- Trigger the same fixed TCP payload read path used by the allow phase.
- Assert the read returns `0` bytes or the connection fails in the scripted expected form.
- Assert `METRICS.GET(name=reasons)` reports `IP_RULE_BLOCK.packets>=1`.
- Assert the block rule reports `stats.hitPackets>=1` through `IPRULES.PRINT`.
- Assert `METRICS.GET(name=conntrack)` reports `creates==0` and `totalEntries==0` after the blocked trigger.

#### Scenario: New orig block rule drops traffic without creating conntrack entry
- **WHEN** the conntrack smoke installs a matching `new/orig` enforce block rule
- **AND** Tier‑1 TCP payload traffic is triggered
- **THEN** the client SHALL read `0` bytes or observe the expected connection failure
- **AND** `reasons.IP_RULE_BLOCK.packets` SHALL be greater than or equal to `1`
- **AND** the block rule SHALL report `hitPackets>=1`
- **AND** conntrack metrics SHALL report `creates==0`
- **AND** conntrack metrics SHALL report `totalEntries==0`

### Requirement: Conntrack smoke preserves explainable outcomes
The conntrack smoke MUST distinguish environmental precondition failures from product assertion failures. Missing root, missing Tier‑1 networking tools, unavailable vNext control transport, or lack of a network-capable app uid MUST be reported as `BLOCKED(77)` or existing IP-module `SKIP(10)` semantics. If preconditions are satisfied but CT verdicts, stats, reasons, or metrics violate the casebook expectations, the smoke MUST fail with a nonzero assertion error.

#### Scenario: Missing Tier-1 prerequisites are not reported as pass
- **WHEN** a developer runs the active smoke profile on a device without required Tier‑1 prerequisites
- **THEN** the conntrack smoke SHALL report `BLOCKED` or `SKIP`
- **AND** it SHALL NOT report the conntrack case as passed

#### Scenario: CT assertion mismatch fails the smoke
- **WHEN** Tier‑1 prerequisites and vNext control transport are available
- **AND** a conntrack verdict, rule stat, reason metric, or conntrack metric does not match the expected casebook value
- **THEN** the conntrack smoke SHALL fail the active smoke profile

### Requirement: Conntrack casebook documentation is kept aligned
After implementing the conntrack smoke, the documentation MUST identify the active check ids that cover `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP - Conntrack` Case 1 and MUST remove or update obsolete gap notes for that case.

The coverage matrix and roadmap MUST also describe the conntrack casebook coverage without claiming broader CT matrix, perf, stress, or longrun coverage. Any Snort daemon/product behavior error found during validation or device testing MUST be recorded in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md` with enough context to reproduce and triage it. Errors caused by the test implementation itself MUST NOT be recorded in that file.

#### Scenario: Casebook points to implemented conntrack checks
- **WHEN** a developer reads `docs/testing/DEVICE_SMOKE_CASEBOOK.md` after this change
- **THEN** `## IP - Conntrack` Case 1 SHALL list current smoke check ids or an explicit remaining caveat
- **AND** it SHALL NOT retain a stale “not in smoke profile” gap note once the active smoke profile covers the case

#### Scenario: Coverage matrix reflects minimal conntrack smoke scope
- **WHEN** a developer reads `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md` after this change
- **THEN** the matrix SHALL describe minimal conntrack casebook coverage under `dx-smoke-datapath`
- **AND** it SHALL NOT describe CT matrix, perf, stress, or longrun coverage as completed by this change

#### Scenario: Product behavior errors are logged
- **WHEN** validation or device testing exposes a Snort daemon/product behavior error
- **THEN** `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md` SHALL record the command, environment, expected result, actual result, and relevant logs
- **AND** errors caused by the test implementation itself SHALL NOT be recorded in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`
