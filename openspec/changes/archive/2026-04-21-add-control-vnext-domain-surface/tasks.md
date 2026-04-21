## 1. vNext Domain Handler Plumbing

- [x] 1.1 Add vNext domain command handler module and wire into `ControlVNextSession` dispatch order
- [x] 1.2 Ensure domain mutating commands run under exclusive `mutexListeners` lock (same discipline as `RESETALL/CONFIG.SET`)

## 2. `DOMAINRULES.*` Surface

- [x] 2.1 Implement `DOMAINRULES.GET` response shape (`ruleId/type/pattern`) + stable sort by `ruleId`
- [x] 2.2 Implement `DOMAINRULES.APPLY` request parsing + strict validation (unknown keys, duplicate ruleId, duplicate `(type,pattern)`)
- [x] 2.3 Implement regex/wildcard compile validation and reject invalid rules (`INVALID_ARGUMENT`)
- [x] 2.4 Implement ruleId upsert + allocation for missing ruleId and echo back final baseline (sorted by `ruleId`)
- [x] 2.5 Enforce referential integrity vs `DOMAINPOLICY` and return `INVALID_ARGUMENT` with `error.conflicts[]` on violations

## 3. `DOMAINPOLICY.*` Surface

- [x] 3.1 Implement `DOMAINPOLICY.GET` for `scope="device"` (shape: `policy.allow/block.{domains,ruleIds}`)
- [x] 3.2 Implement `DOMAINPOLICY.GET` for `scope="app"` using vNext app selector rules (`{uid}` or `{pkg,userId}`)
- [x] 3.3 Implement `DOMAINPOLICY.APPLY` as atomic replace for the target scope with ack-only response (`{"id":...,"ok":true}`)
- [x] 3.4 Validate `ruleIds[]` exist in `DOMAINRULES` baseline and domains[] follow minimal validation rules

## 4. `DOMAINLISTS.GET/APPLY` Surface

- [x] 4.1 Implement `DOMAINLISTS.GET` from persisted metadata (include subscription fields) and sort by `listKind` then `listId`
- [x] 4.2 Implement `DOMAINLISTS.APPLY` upsert/remove with request-level atomicity and subscription-field patch semantics
- [x] 4.3 Implement remove semantics: unknown listId does not fail, must appear in `result.notFound[]`
- [x] 4.4 Implement `listKind` switch semantics + mask-change restriction (reject changing kind+mask in one upsert)
- [x] 4.5 Ensure `enabled` toggles map to existing on-disk enabled/disabled list file forms

## 5. `DOMAINLISTS.IMPORT` (limits + atomicity + domainsCount)

- [x] 5.1 Validate list existence (`listId`) and metadata consistency (`listKind/mask` must match stored config)
- [x] 5.2 Enforce minimal domain validation and “no canonicalization” behavior
- [x] 5.3 Enforce `maxImportDomains=1_000_000` and `maxImportBytes=16MiB` and return structured `INVALID_ARGUMENT` with `error.limits`
- [x] 5.4 Implement request-level atomic import (temp-file strategy) for both `clear=1` (replace) and `clear=0` (union-add)
- [x] 5.5 On success, update only `domainsCount` in list metadata (do not implicitly change subscription fields)

## 6. Host P0 Unit Tests

- [x] 6.1 Add P0 tests for `DOMAINRULES.GET` sorting + shape
- [x] 6.2 Add P0 tests for `DOMAINRULES.APPLY` ruleId assignment + echo baseline sorting
- [x] 6.3 Add P0 tests for invalid regex/wildcard rejection
- [x] 6.4 Add P0 tests for rule referential-integrity rejection (`error.conflicts[]`)
- [x] 6.5 Add P0 tests for `DOMAINPOLICY.GET/APPLY` (ack-only, scope validation, selector errors)
- [x] 6.6 Add P0 tests for `DOMAINLISTS.GET/APPLY` sorting + patch/remove semantics
- [x] 6.7 Add P0 tests for `DOMAINLISTS.IMPORT` limits error shape and success updating `domainsCount`

## 7. Integration (P1)

- [x] 7.1 Extend `tests/integration/vnext-baseline.sh` (or add a sibling script) to cover Domain surface: apply → get/print → verify
- [x] 7.2 (Optional) Use `DEV.DNSQUERY` to provide a stable on-device verification of policy effects in the P1 flow

## 8. Device (P2, if needed)

- [x] 8.1 Add minimal `device-smoke` regression to ensure vNext domain commands work on real devices (shape + basic behavior)
