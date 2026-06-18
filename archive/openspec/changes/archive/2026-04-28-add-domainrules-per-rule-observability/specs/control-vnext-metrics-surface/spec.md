## MODIFIED Requirements

### Requirement: METRICS.GET supports v1 names and enforces selector constraints
`METRICS.GET.args.name` MUST be a string and MUST be one of:
- `perf`
- `reasons`
- `domainSources`
- `traffic`
- `conntrack`
- `domainRuleStats`

`METRICS.GET.args.app`:
- MUST be allowed only when `name="traffic"` or `name="domainSources"`.
- MUST follow vNext selector rules (`{uid}` OR `{pkg,userId}`).
- If the selector is not found or ambiguous, the daemon MUST return a structured selector error
  (`SELECTOR_NOT_FOUND` / `SELECTOR_AMBIGUOUS`) including `error.candidates[]` sorted by `uid`
  ascending.

#### Scenario: Unknown name is rejected
- **WHEN** client sends `{"id":2,"cmd":"METRICS.GET","args":{"name":"nope"}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`

#### Scenario: App selector is rejected for unsupported metric names
- **WHEN** client sends `{"id":3,"cmd":"METRICS.GET","args":{"name":"perf","app":{"uid":10123}}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`

#### Scenario: App selector is rejected for domainRuleStats
- **WHEN** client sends `{"id":30,"cmd":"METRICS.GET","args":{"name":"domainRuleStats","app":{"uid":10123}}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`

#### Scenario: Selector not-found returns candidates array
- **WHEN** client sends `{"id":4,"cmd":"METRICS.GET","args":{"name":"traffic","app":{"uid":999999}}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="SELECTOR_NOT_FOUND"`
- **AND** `error.candidates` SHALL be present as an array

### Requirement: METRICS.RESET clears supported metrics and rejects conntrack
`METRICS.RESET.args.name` MUST be a string and MUST be one of:
- `perf`
- `reasons`
- `domainSources`
- `traffic`
- `conntrack`
- `domainRuleStats`

Reset support (v1):
- MUST support reset: `perf` / `reasons` / `domainSources` / `traffic` / `domainRuleStats`
- MUST NOT support reset: `conntrack` (only `RESETALL` clears conntrack counters)

#### Scenario: Conntrack reset is rejected
- **WHEN** client sends `{"id":5,"cmd":"METRICS.RESET","args":{"name":"conntrack"}}`
- **THEN** daemon SHALL respond `ok=false` with `error.code="INVALID_ARGUMENT"`
