# dx-smoke-other-casebook Specification

## Purpose
Define the optional real-device validation path for `DEVICE_SMOKE_CASEBOOK.md`
`## 其他` Case 1 and Case 2, covering `perfmetrics.enabled` semantics and
large control-plane limits sanity without changing the default `dx-smoke` chain.

## Requirements

### Requirement: Optional other casebook runner preserves default smoke boundaries
The project MUST provide an opt-in device validation path for `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1 and Case 2. This validation path MUST NOT be part of the default `dx-smoke` fail-fast chain and MUST NOT add new `dx-smoke*` CTest names.

The validation path MUST use vNext control APIs only. It MUST NOT call legacy text protocol commands as the active assertion path.

#### Scenario: Default dx-smoke does not run other casebook
- **WHEN** a developer runs `dx-smoke`
- **THEN** the default smoke chain SHALL remain `platform -> control -> datapath`
- **AND** it SHALL NOT execute the optional other casebook checks
- **AND** no new `dx-smoke*` entrypoint SHALL be required for this change

#### Scenario: Other casebook can be run explicitly
- **WHEN** a developer explicitly invokes the optional other casebook validation path
- **THEN** it SHALL run checks for `## 其他` Case 1 and Case 2 or report documented `BLOCKED/SKIP` preconditions
- **AND** every executed check SHALL use vNext control commands

### Requirement: perfmetrics.enabled case uses controlled Tier-1 traffic
The optional other casebook validation MUST cover `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1 using controlled Tier‑1 payload traffic rather than公网-dependent download traffic.

At minimum, the perfmetrics case MUST:
- Save the original `perfmetrics.enabled` value and restore it during cleanup.
- Set `perfmetrics.enabled=0`, reset perf metrics, trigger Tier‑1 payload traffic, and assert `nfq_total_us.samples==0`.
- Set `perfmetrics.enabled=1`, reset perf metrics, trigger Tier‑1 payload traffic, and assert `nfq_total_us.samples>=1`.
- Set `perfmetrics.enabled=1` again without resetting and assert `nfq_total_us.samples` does not decrease.
- Attempt `perfmetrics.enabled=2` and assert the request is rejected without changing the current valid value.

`dns_decision_us` growth MAY be checked only when the netd resolver hook is active and DNS traffic is explicitly triggered. DNS perf growth MUST NOT be a hard requirement for this case.

#### Scenario: Disabled perfmetrics stays zero under controlled traffic
- **WHEN** the validation sets `perfmetrics.enabled=0`
- **AND** resets `METRICS.GET(name=perf)` aggregates through the vNext metrics reset surface
- **AND** Tier‑1 payload traffic enters NFQUEUE
- **THEN** a subsequent `METRICS.GET(name=perf)` response SHALL report `result.perf.nfq_total_us.samples==0`

#### Scenario: Enabled perfmetrics collects nfq samples
- **WHEN** the validation sets `perfmetrics.enabled=1`
- **AND** resets perf aggregates
- **AND** Tier‑1 payload traffic enters NFQUEUE
- **THEN** a subsequent `METRICS.GET(name=perf)` response SHALL report `result.perf.nfq_total_us.samples>=1`

#### Scenario: Idempotent enable does not clear samples
- **WHEN** perfmetrics are enabled and `nfq_total_us.samples` is `N`
- **AND** the validation sets `perfmetrics.enabled=1` again without resetting metrics
- **THEN** a subsequent `METRICS.GET(name=perf)` response SHALL report `result.perf.nfq_total_us.samples>=N`

#### Scenario: Invalid perfmetrics value is rejected
- **WHEN** the validation sends `CONFIG.SET(scope=device,set={"perfmetrics.enabled":2})`
- **THEN** the command SHALL fail with an invalid-argument error
- **AND** the previously valid `perfmetrics.enabled` value SHALL remain effective

### Requirement: Domain import limits sanity is explainable and recoverable
The optional other casebook validation MUST cover the `DOMAINLISTS.IMPORT` portion of `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 2 as a limits/error/recovery sanity check.

At minimum, the domain import limits case MUST:
- Confirm vNext `HELLO` succeeds before the test and exposes request-size limits.
- Create or select a disabled test-only domain list so verdict behavior is not affected.
- Execute an under-limit import and verify it succeeds and updates `domainsCount`.
- Execute an over-limit import that stays within the transport assumptions of the test but exceeds command-level import limits.
- Assert the over-limit response is structured and explainable, including `INVALID_ARGUMENT` and `error.limits.maxImportDomains` / `error.limits.maxImportBytes`.
- Assert a subsequent `HELLO` still succeeds.

#### Scenario: Under-limit domain import succeeds
- **WHEN** the validation imports a bounded under-limit set of valid domains into a disabled test list
- **THEN** `DOMAINLISTS.IMPORT` SHALL succeed
- **AND** `DOMAINLISTS.GET` SHALL report the expected `domainsCount`

#### Scenario: Over-limit domain import reports limits
- **WHEN** the validation sends a `DOMAINLISTS.IMPORT` request that exceeds command-level import limits
- **THEN** the response SHALL fail with `INVALID_ARGUMENT`
- **AND** the error object SHALL include `limits.maxImportDomains`
- **AND** the error object SHALL include `limits.maxImportBytes`
- **AND** the error object SHALL include a chunking or size-reduction hint

#### Scenario: Daemon remains reachable after domain import failure
- **WHEN** an over-limit `DOMAINLISTS.IMPORT` request is rejected
- **THEN** a subsequent vNext `HELLO` SHALL succeed on a new or existing control connection

### Requirement: IPRULES scale limits sanity is explainable and recoverable
The optional other casebook validation MUST cover the `IPRULES.APPLY` portion of `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 2 as a preflight limits/error/recovery sanity check.

At minimum, the IPRULES limits case MUST:
- Use a test app uid and reset daemon state before mutating rules.
- Apply an under-limit ruleset large enough to trigger a recommended `rulesTotal` warning and assert `IPRULES.PREFLIGHT` exposes that warning.
- Attempt an over-hard-limit ruleset and assert `IPRULES.APPLY` fails with `INVALID_ARGUMENT` and structured `error.preflight.violations`.
- Assert the failed apply is all-or-nothing and a subsequent `HELLO` and `IPRULES.PREFLIGHT` still succeed.

#### Scenario: Under-limit large ruleset reports warning
- **WHEN** the validation applies an under-hard-limit ruleset whose active rule count exceeds the recommended `rulesTotal` threshold
- **THEN** `IPRULES.APPLY` SHALL succeed
- **AND** `IPRULES.PREFLIGHT` SHALL include a `rulesTotal` warning

#### Scenario: Over-hard-limit ruleset is rejected
- **WHEN** the validation attempts to apply a ruleset whose active rule count exceeds the hard `rulesTotal` limit
- **THEN** `IPRULES.APPLY` SHALL fail with `INVALID_ARGUMENT`
- **AND** the error SHALL include `preflight.violations`
- **AND** one violation SHALL identify `rulesTotal`

#### Scenario: Daemon remains reachable after IPRULES failure
- **WHEN** an over-hard-limit `IPRULES.APPLY` request is rejected
- **THEN** a subsequent vNext `HELLO` SHALL succeed
- **AND** a subsequent `IPRULES.PREFLIGHT` SHALL return a parseable report

### Requirement: Other casebook outcomes are explicit
The optional other casebook validation MUST distinguish environmental precondition failures from assertion failures. Missing ADB, missing root, unavailable vNext control transport, missing Tier‑1 networking prerequisites, missing test app uid, or resource limits that prevent constructing a trustworthy optional-scale check MUST be reported as `BLOCKED(77)` or the existing explicit `SKIP(10)` style. If preconditions are satisfied but a perfmetrics, limits, or recovery assertion fails, the validation MUST fail with a nonzero assertion error.

#### Scenario: Environment preconditions are not reported as pass
- **WHEN** the optional other casebook validation cannot establish required device, root, vNext, Tier‑1, uid, or resource prerequisites
- **THEN** it SHALL report `BLOCKED` or `SKIP`
- **AND** it SHALL NOT report the relevant case as passed

#### Scenario: Contract mismatch fails validation
- **WHEN** required preconditions are satisfied
- **AND** a perfmetrics, limits, all-or-nothing, or post-failure recovery assertion does not match the casebook expectation
- **THEN** the optional other casebook validation SHALL fail

### Requirement: Other casebook documentation is kept aligned
After implementing the optional other casebook validation, documentation MUST identify the active check ids that cover `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1 and Case 2. Documentation MUST clearly state that these checks are optional and not part of the default `dx-smoke` main chain.

The coverage matrix and roadmap MUST also describe the final coverage without claiming that this change adds new product capabilities, default smoke responsibilities, stress/perf/longrun coverage, or broader diagnostics semantics. Any Snort daemon/product behavior error found during validation or device testing MUST be recorded in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md` with enough context to reproduce and triage it. Errors caused by the test implementation itself MUST NOT be recorded in that file.

#### Scenario: Casebook points to implemented other checks
- **WHEN** a developer reads `docs/testing/DEVICE_SMOKE_CASEBOOK.md` after this change is implemented
- **THEN** `## 其他` Case 1 and Case 2 SHALL list current optional check ids or explicit remaining caveats
- **AND** the document SHALL NOT imply that the optional checks run in the default `dx-smoke` chain

#### Scenario: Coverage matrix reflects optional scope
- **WHEN** a developer reads `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md` after this change is implemented
- **THEN** the matrix SHALL describe the optional other casebook coverage
- **AND** it SHALL preserve the existing default smoke and diagnostics entrypoint boundaries

#### Scenario: Product behavior errors are logged
- **WHEN** validation or device testing exposes a Snort daemon/product behavior error
- **THEN** `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md` SHALL record the command, environment, expected result, actual result, and relevant logs
- **AND** errors caused by the test implementation itself SHALL NOT be recorded in `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`
