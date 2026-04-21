# control-vnext-domain-surface Specification

## Purpose
TBD - created by archiving change add-control-vnext-domain-surface. Update Purpose after archive.

## Requirements

### Requirement: `DOMAINRULES.GET` returns stable rules baseline
The daemon MUST implement `DOMAINRULES.GET` as defined in `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md` and MUST follow the vNext envelope/strict reject rules in `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`.

The response MUST be `ok=true` and MUST include:
- `result.rules[]` where each item has:
  - `ruleId` (u32)
  - `type` (`"domain"|"wildcard"|"regex"`)
  - `pattern` (string)
- `result.rules[]` sorted by `ruleId` ascending.

#### Scenario: `DOMAINRULES.GET` is sorted and stable
- **WHEN** client sends `{"id":1,"cmd":"DOMAINRULES.GET","args":{}}`
- **THEN** daemon responds `ok=true` and `result.rules[]` is sorted by `ruleId` ascending

### Requirement: `DOMAINRULES.APPLY` is atomic replace with ruleId upsert
The daemon MUST implement `DOMAINRULES.APPLY` as an atomic replace:
- The request MUST be all-or-nothing (no partial apply).
- `args.rules[]` MAY include `ruleId` for upsert/restore; missing `ruleId` means “new rule”.
- The daemon MUST reject:
  - duplicate `ruleId` in the payload
  - duplicate `(type,pattern)` in the payload
  - invalid regex compilation for `type="domain"|"regex"` (and wildcard-to-regex translation for `type="wildcard"`)
  - missing `ruleId` when `(type,pattern)` already exists in the current baseline (client must `GET` first and send `ruleId`)
- Referential integrity MUST be enforced:
  - The daemon MUST NOT remove any ruleId that is still referenced by any `DOMAINPOLICY` scope (device or any app).
  - On violation, the daemon MUST reject the entire apply with `error.code="INVALID_ARGUMENT"` and MUST include `error.conflicts[]` with the following minimal shape:
    - `{"ruleId":<u32>,"refs":[{"scope":"device"}|{"scope":"app","app":{"uid":<u32>}}]}`

On success:
- The daemon MUST respond `ok=true` and MUST return the final baseline in `result.rules[]` (including assigned `ruleId` values for newly created rules).
- `result.rules[]` MUST be sorted by `ruleId` ascending.

#### Scenario: New rules get assigned a `ruleId` and are echoed back
- **WHEN** client sends `DOMAINRULES.APPLY` with a rule missing `ruleId`
- **THEN** daemon responds `ok=true` and includes the assigned `ruleId` for that rule in `result.rules[]`

### Requirement: `DOMAINPOLICY.GET/APPLY` supports device/app scopes and ack-only apply
The daemon MUST implement:
- `DOMAINPOLICY.GET` returning `result.policy`:
  - `policy.allow.domains[]` (string)
  - `policy.allow.ruleIds[]` (u32)
  - `policy.block.domains[]` (string)
  - `policy.block.ruleIds[]` (u32)
- `DOMAINPOLICY.APPLY` as an atomic replace for the target scope, with an ack-only response (`{"id":...,"ok":true}`).

Validation requirements:
- `args.scope` MUST be `"device"` or `"app"` (and follow vNext scope/app selector rules).
- `policy.*.ruleIds[]` MUST reference existing `DOMAINRULES` baseline ruleIds; otherwise reject with `error.code="INVALID_ARGUMENT"`.
- `policy.*.domains[]` entries MUST pass minimal validation:
  - non-empty string, length `<= HOST_NAME_MAX`
  - no ASCII whitespace
  - no control chars (`< 0x20`) and no `\0`
- The daemon MUST NOT perform canonicalization (no trim/lowercase/strip trailing dot) for custom domains.

#### Scenario: `DOMAINPOLICY.APPLY` is ack-only
- **WHEN** client sends `{"id":2,"cmd":"DOMAINPOLICY.APPLY","args":{"scope":"device","policy":{"allow":{"domains":[],"ruleIds":[]},"block":{"domains":[],"ruleIds":[]}}}}`
- **THEN** daemon responds `{"id":2,"ok":true}` (no `result`)

### Requirement: `DOMAINLISTS.GET/APPLY` manages list config + subscription metadata
The daemon MUST implement:
- `DOMAINLISTS.GET` returning `result.lists[]` sorted by `listKind` then `listId` ascending.
- `DOMAINLISTS.APPLY` supporting `upsert[]` + `remove[]` with request-level atomicity.

`DOMAINLISTS.GET.result.lists[]` items MUST include:
- execution config: `listId` (GUID string), `listKind` (`"block"|"allow"`), `mask` (u8), `enabled` (0|1)
- subscription metadata fields (strings unless specified): `url`, `name`, `updatedAt`, `etag`, `outdated` (0|1), `domainsCount` (u32)

`DOMAINLISTS.APPLY` semantics:
- `upsert[]` items MUST include execution config fields (`listId/listKind/mask/enabled`).
- subscription metadata fields in `upsert[]` are patch semantics:
  - if a field is omitted, the daemon MUST preserve the stored value
  - if provided, the daemon MUST overwrite the stored value
- On new list creation, omitted subscription metadata fields MUST default to:
  - `url=""`, `name=""`, `updatedAt=""`, `etag=""`, `outdated=1`, `domainsCount=0`
- `remove[]` unknown `listId` MUST NOT fail the request; it MUST be echoed in `result.notFound[]`.
- `DOMAINLISTS.APPLY` response MUST include `result.removed[]` and `result.notFound[]`.

#### Scenario: Removing an unknown listId is reported as notFound
- **WHEN** client sends `DOMAINLISTS.APPLY` with `remove:["00000000-0000-0000-0000-000000000000"]`
- **THEN** daemon responds `ok=true` and includes that listId in `result.notFound[]`

### Requirement: `DOMAINLISTS.IMPORT` enforces limits and is all-or-nothing
The daemon MUST implement `DOMAINLISTS.IMPORT`:
- `args.listId` MUST exist (otherwise reject with `error.code="INVALID_ARGUMENT"` and a hint to create via `DOMAINLISTS.APPLY`).
- `args.listKind/mask` MUST match the stored metadata for `listId` (consistency check); mismatch MUST be rejected with `error.code="INVALID_ARGUMENT"`.
- `args.clear` semantics:
  - `clear=1`: replace the domain set for `listId`
  - `clear=0`: union-add domains not already present
- The operation MUST be atomic at request level (no partial import on any validation or persistence failure).
- Domain validation MUST match the minimal protection rules:
  - non-empty string, length `<= HOST_NAME_MAX`
  - no ASCII whitespace
  - no control chars (`< 0x20`) and no `\0`
  - no DNS syntax validation beyond the above
- The daemon MUST NOT perform canonicalization (no trim/lowercase/strip trailing dot) when importing domains.

Command-level limits:
- `maxImportDomains=1_000_000`
- `maxImportBytes=16MiB`
- `importBytes` MUST be computed as the sum of UTF-8 byte lengths of all `domains[]` strings.
- If either limit is exceeded (while the frame itself is within `maxRequestBytes`), the daemon MUST reject with:
  - `ok=false`, `error.code="INVALID_ARGUMENT"`
  - `error.limits={"maxImportDomains":1000000,"maxImportBytes":16777216}`

On success:
- The daemon MUST respond `ok=true` with `result.imported` (u32).
- The daemon MUST update only `domainsCount` in the list metadata for that `listId` (visible via `DOMAINLISTS.GET`).

#### Scenario: Oversized import is rejected with limits
- **WHEN** client sends `DOMAINLISTS.IMPORT` exceeding `maxImportDomains` or `maxImportBytes`
- **THEN** daemon responds `ok=false`, `error.code="INVALID_ARGUMENT"`, and includes `error.limits`

