## MODIFIED Requirements

### Requirement: `IPRULES.PREFLIGHT` returns a stable preflight report
The daemon MUST implement `IPRULES.PREFLIGHT` as defined in:
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
- `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md` (schema §9.1)

The daemon MUST follow the vNext envelope/strict reject rules in
`docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`.

On success, the response MUST be `ok=true` and MUST include `result` with:
- `summary` (object; all fields u64)
- `byFamily` (object):
  - MUST include both `ipv4` and `ipv6` keys (objects)
  - each family object MUST mirror the `summary` field set (all fields u64)
- `limits` (object; `recommended` and `hard`, all fields u64)
- `warnings[]` and `violations[]` arrays (items `{metric:string,value:u64,limit:u64,message:string}`)

#### Scenario: `IPRULES.PREFLIGHT` returns required fields
- **WHEN** client sends `{"id":1,"cmd":"IPRULES.PREFLIGHT","args":{}}`
- **THEN** daemon responds with `{"id":1,"ok":true,"result":{...}}` containing `summary`, `byFamily`, `limits`, `warnings`, and `violations`

### Requirement: `IPRULES.PRINT` returns stable rules baseline for a target app
The daemon MUST implement `IPRULES.PRINT` as defined in:
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
- `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md` (schema §9.2/§9.4)

Selector requirements:
- The request MUST include `args.app` and MUST follow vNext selector rules (`{uid}` OR `{pkg,userId}`).
- Selector not-found/ambiguous MUST be a structured error (`SELECTOR_NOT_FOUND/SELECTOR_AMBIGUOUS`) and MUST include `error.candidates[]` sorted by `uid` ascending.

On success, the response MUST be `ok=true` and MUST include:
- `result.uid` (u32)
- `result.rules[]` (array) where each item MUST include the full `Rule` field set from the contract:
  - identity: `ruleId` (u32), `clientRuleId` (string), `matchKey` (string)
  - behavior: `action` (`"allow"|"block"`), `priority` (i32), `enabled/enforce/log` (0|1 numbers)
  - match: `family/dir/iface/ifindex/proto/ct/src/dst/sport/dport` (types/values per contract)
  - stats: `stats.{hitPackets,hitBytes,lastHitTsNs,wouldHitPackets,wouldHitBytes,lastWouldHitTsNs}` (u64)
- `result.rules[]` MUST be sorted by `ruleId` ascending.

#### Scenario: `IPRULES.PRINT` output is sorted by `ruleId`
- **WHEN** client sends `{"id":2,"cmd":"IPRULES.PRINT","args":{"app":{"uid":10123}}}`
- **THEN** daemon responds `ok=true` and `result.rules[]` is sorted by `ruleId` ascending

### Requirement: `IPRULES.APPLY` is atomic replace and returns mapping
The daemon MUST implement `IPRULES.APPLY` as defined in:
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
- `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md` (apply semantics + schema §9.3)

Request validation requirements:
- The request MUST include `args.app` and MUST follow vNext selector rules.
- The request MUST include `args.rules[]` and each rule item MUST include all required fields per the contract (including `family`).
- The daemon MUST reject apply payloads that carry forbidden fields (`ruleId`, `matchKey`, `stats`) with `ok=false` and `error.code="INVALID_ARGUMENT"`.
- The daemon MUST reject payloads with duplicate `clientRuleId` (within the same apply) with `ok=false` and `error.code="INVALID_ARGUMENT"`.

Apply semantics:
- The apply MUST be all-or-nothing (no partial apply).
- `clientRuleId` MUST be treated as the stable rule identity:
  - if a `clientRuleId` already exists in the current baseline, the daemon MUST reuse the existing `ruleId`
  - if a `clientRuleId` is new, the daemon MUST assign a new `ruleId` (monotonic; no reuse until `RESETALL`)
- On success, the daemon MUST respond `ok=true` and MUST return `result` with:
  - `result.uid` (u32)
  - `result.rules[]` mapping array containing `{clientRuleId,ruleId,matchKey}` for every committed rule (no omissions)

#### Scenario: `IPRULES.APPLY` returns mapping for committed rules
- **WHEN** client sends `IPRULES.APPLY` for a uid with one rule `{clientRuleId,...}`
- **THEN** daemon responds `ok=true` and `result.rules[]` contains an item with the same `clientRuleId` and assigned `ruleId` and computed `matchKey`

## REMOVED Requirements

### Requirement: `matchKey` is computed with mk1 canonicalization and conflicts are rejected
**Reason**: IPRULES rule model is upgraded to dual-stack, so `matchKey` MUST include `family` and becomes mk2.
**Migration**: Update daemon/clients/tests to compute/validate mk2 per `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md` §3 and reject duplicates by mk2.

## ADDED Requirements

### Requirement: `matchKey` is computed with mk2 canonicalization and conflicts are rejected
For each rule in an `IPRULES.APPLY`, the daemon MUST compute a `matchKey` string per mk2:
- exact mk2 format and field ordering (see `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md` §3)
- `family` MUST be included and MUST be one of `ipv4|ipv6`
- CIDR values MUST be canonicalized to network-address form (mask host bits to zero) for both IPv4 and IPv6
- `ifindex` MUST be canonicalized as decimal with `0` meaning any

Conflict detection:
- Within a single `IPRULES.APPLY` payload for a uid, duplicate `matchKey` MUST be rejected.
- On rejection, the daemon MUST respond with:
  - `ok=false`, `error.code="INVALID_ARGUMENT"`
  - `error.conflicts[]` items including `uid`, `matchKey`, and `rules[]` with minimal fields `{clientRuleId,action,priority,enabled,enforce,log}`
  - `error.truncated` boolean indicating whether `conflicts[]` was truncated

#### Scenario: Duplicate mk2 `matchKey` in apply payload is rejected with `conflicts[]`
- **WHEN** client sends `IPRULES.APPLY` containing two rules for the same uid that normalize to the same mk2 `matchKey`
- **THEN** daemon responds `ok=false` with `error.code="INVALID_ARGUMENT"` and includes `error.conflicts[]` describing the duplicated `matchKey`

