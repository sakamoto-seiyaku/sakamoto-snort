## 1. vNext IPRULES Handler Plumbing

- [x] 1.1 Add vNext iprules command handler module (`ControlVNextSessionCommandsIpRules.*`)
- [x] 1.2 Wire handler into `src/ControlVNextSession.cpp` dispatch order (after domain handler)
- [x] 1.3 Ensure `IPRULES.APPLY` runs under exclusive `mutexListeners` lock; `PREFLIGHT/PRINT` under shared lock

## 2. `IPRULES.PREFLIGHT` Surface

- [x] 2.1 Implement `IPRULES.PREFLIGHT` request parsing (empty args + strict reject unknown keys)
- [x] 2.2 Map `IpRulesEngine::PreflightReport` to vNext JSON shape (schema §9.1) with correct numeric types

## 3. `IPRULES.PRINT` Surface

- [x] 3.1 Implement `args.app` selector resolve (`{uid}` or `{pkg,userId}`) with structured not-found/ambiguous errors
- [x] 3.2 Implement `IPRULES.PRINT` response shape (schema §9.2/§9.4) and stable sort by `ruleId`
- [x] 3.3 Implement `matchKey` mk1 computation for PRINT (canonicalization + fixed field ordering)
- [x] 3.4 Ensure `src/dst` CIDR output uses network-address canonical form (mask host bits)
- [x] 3.5 Include per-rule `stats` snapshot fields (u64) and `ct` wrapper fields

## 4. Engine: `clientRuleId` + Atomic Replace Apply

- [x] 4.1 Extend rule state to persist `clientRuleId` (string) alongside existing rule fields
- [x] 4.2 Bump iprules save format version and implement backward-compatible restore strategy
- [x] 4.3 Implement atomic replace apply per-UID driven by `clientRuleId` identity:
  - reuse `ruleId` for existing `clientRuleId`
  - allocate new `ruleId` monotonically for new `clientRuleId`
- [x] 4.4 Implement stats retention rules for apply (preserve only when definition unchanged; otherwise reset)
- [x] 4.5 Ensure apply updates allocator state and rules epoch consistently and remains restart-stable

## 5. `IPRULES.APPLY` vNext Surface

- [x] 5.1 Implement `IPRULES.APPLY` schema validation (required fields; forbid `ruleId/matchKey/stats`; strict reject unknown keys)
- [x] 5.2 Enforce `clientRuleId` format + uniqueness within payload
- [x] 5.3 Compute `matchKey` mk1 per rule and reject duplicate `matchKey` with contract `error.conflicts[]` shape
- [x] 5.4 On success, return mapping `result.rules[]` as `{clientRuleId,ruleId,matchKey}` for all committed rules
- [x] 5.5 On preflight/limits failure, return `INVALID_ARGUMENT` with structured `error.preflight` report

## 6. Host P0 Unit Tests

- [x] 6.1 Add host test target `control_vnext_iprules_surface_tests` and wire into `tests/host/CMakeLists.txt`
- [x] 6.2 Add tests for `IPRULES.PREFLIGHT` response shape/types
- [x] 6.3 Add tests for `IPRULES.PRINT` sorting + required fields (`clientRuleId/matchKey/stats`)
- [x] 6.4 Add tests for `IPRULES.APPLY` forbidden fields rejection (`ruleId/matchKey/stats`)
- [x] 6.5 Add tests for duplicate `matchKey` rejection (`INVALID_ARGUMENT` + `error.conflicts[]` + `truncated`)
- [x] 6.6 Add tests for apply success mapping and `ruleId` reuse by `clientRuleId`
- [x] 6.7 Add tests for apply preflight failure including structured `error.preflight`

## 7. Integration (P1)

- [x] 7.1 Extend `tests/integration/vnext-baseline.sh` with vNext iprules flow: preflight → apply → print → verify
- [x] 7.2 Reuse/align rule expectations with existing `tests/integration/iprules.sh` to prevent semantic drift

## 8. Device (P2)

- [x] 8.1 Add a device-module profile that drives iprules via vNext control (using `sucre-snort-ctl` over forwarded 60607)
- [x] 8.2 Add a minimal smoke case verifying vNext apply→print works on real devices (shape + basic behavior)
