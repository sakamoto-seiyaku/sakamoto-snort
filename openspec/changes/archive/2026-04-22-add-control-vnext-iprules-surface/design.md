## Context

- Roadmap slice: `docs/IMPLEMENTATION_ROADMAP.md` → vNext control 平面切片 `add-control-vnext-iprules-surface`。
- Protocol truth:
  - wire/envelope/errors/strict reject/selector: `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
  - cmd directory: `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
  - IPRULES apply contract (schema + conflicts + matchKey + mapping): `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`
- Current code state (already implemented):
  - vNext session loop + codec: `src/ControlVNext.cpp`, `src/ControlVNextSession.cpp`, `src/ControlVNextCodec.*`
  - daemon base vNext commands: `src/ControlVNextSessionCommandsDaemon.cpp`
  - domain surface vNext commands: `src/ControlVNextSessionCommandsDomain.cpp`
  - IPRULES engine + legacy control surface (for behavior reference only): `src/IpRulesEngine.*`, `src/Control.cpp`

## Goals / Non-Goals

**Goals:**

- Implement vNext IPRULES surface commands in the daemon:
  - `IPRULES.PREFLIGHT` / `IPRULES.PRINT` / `IPRULES.APPLY`
- Enforce vNext strict reject + structured errors (stable shapes; no silent no-op).
- Enforce the apply contract invariants:
  - atomic replace (all-or-nothing) per target UID
  - `clientRuleId` validation, persistence, and echoing in PRINT and conflict errors
  - `matchKey` (mk1) canonicalization and conflict detection (duplicate matchKey reject)
  - success response mapping `clientRuleId -> ruleId -> matchKey`
  - preflight/limits failure returns structured `error.preflight`
- Provide stable output sorting suitable for snapshot tests (`rules[]` sorted by `ruleId` ascending).

**Non-Goals:**

- No changes to packet hot-path verdict semantics (IFACE_BLOCK priority, enforce vs would semantics, etc.).
- No new non-vNext legacy commands; legacy `IPRULES.ADD/UPDATE/ENABLE/REMOVE/PRINT/PREFLIGHT` remain for transition/reference.
- No metrics/stream vNext work (separate roadmap slices).
- No auth/permission model changes (v1 reserved error code remains reserved).

## Decisions

1) **Command handler structure**

- Add a dedicated vNext iprules command handler module (e.g. `ControlVNextSessionCommandsIpRules.*`) mirroring the existing daemon/domain handler style:
  - Input: `ControlVNext::RequestView` + limits
  - Output: `ResponsePlan { rapidjson::Document response, closeAfterWrite }`
- Dispatch order in `ControlVNextSession`:
  1. meta (`HELLO/QUIT`)
  2. daemon base handler
  3. domain surface handler
  4. iprules surface handler
  5. fallback `UNSUPPORTED_COMMAND`

2) **Locking / concurrency**

- Treat IPRULES mutating commands as control-plane mutations and run them under the same exclusive lock used by `RESETALL/CONFIG.SET`:
  - Exclusive: `IPRULES.APPLY`
  - Shared: `IPRULES.PREFLIGHT`, `IPRULES.PRINT`
- Rationale: match the “apply is atomic” contract under concurrent clients and keep behavior consistent with the already-shipped domain surface discipline.

3) **App selector**

- `IPRULES.PRINT/APPLY` MUST resolve the target app via vNext selector (`args.app`):
  - `{uid}` OR `{pkg,userId}`; not both
  - not-found/ambiguous MUST be structured errors (`SELECTOR_NOT_FOUND/SELECTOR_AMBIGUOUS + candidates[]`)
- Implementation preference: reuse the same selector resolver behavior as the domain handler (to avoid divergent error shapes and candidate sorting).

4) **Engine ownership: `clientRuleId` becomes the stable identity**

- Extend the rule persistence model so each rule has a stored `clientRuleId` (string):
  - Needed for stable `ruleId` reuse under apply and for vNext PRINT join.
  - `clientRuleId` format and uniqueness constraints follow `IPRULES_APPLY_CONTRACT.md`.
- RuleId allocation and stability under apply:
  - Existing `clientRuleId` MUST reuse its prior `ruleId`
  - New `clientRuleId` MUST allocate new `ruleId` from a monotonic allocator (no reuse until `RESETALL`)
  - Apply MUST update allocator state to remain monotonic across restart/restore

5) **Atomic replace apply with matchKey conflict detection**

- Add an engine-level “replace ruleset for uid” operation that:
  - validates the entire payload first
  - computes `matchKey` (mk1) for each rule
  - rejects duplicate `clientRuleId` and duplicate `matchKey` within the same apply payload
  - performs compilation/preflight checks prior to publishing
  - publishes new ruleset atomically (all-or-nothing)

6) **Canonicalization**

- `matchKey` MUST use the mk1 format and fixed field ordering from `IPRULES_APPLY_CONTRACT.md`.
- Implementation note: keep contract-level validators/canonicalizers in a single shared helper (`src/IpRulesContract.hpp`) and reuse it from both the vNext handler and the engine (avoid drift).
- CIDR canonicalization MUST use network-address form (mask host bits to zero) for:
  - `matchKey` `src/dst`
  - vNext `IPRULES.PRINT` `src/dst` string output
- Rationale: avoid “equivalent but different-looking” rules producing different matchKeys or unstable diff output.

7) **Apply result + error shaping**

- Success (`ok=true`) MUST return mapping:
  - `result.uid` (resolved uid)
  - `result.rules[]` with `{clientRuleId,ruleId,matchKey}` for every rule in the committed baseline (no omissions).
- Conflict failure (`ok=false`) MUST use:
  - `error.code="INVALID_ARGUMENT"`
  - `error.conflicts[]` + `error.truncated` exactly as contract
- Preflight/limits failure (`ok=false`) MUST use:
  - `error.code="INVALID_ARGUMENT"`
  - `error.preflight={summary,limits,warnings,violations}` (structured; types locked)

## Risks / Trade-offs

- [Persistence format bump] → Bump iprules save format version; restore must handle old versions safely (either synthesize `clientRuleId` or reject restore; prefer synthesize for robustness).
- [Large rulesets / response size] → vNext is single-frame; ensure limits (`maxResponseBytes`) are configured sanely and add tests to catch accidental blowups in PRINT/APPLY responses.
- [Strict reject breaks sloppy clients] → Provide actionable `error.message/hint` and keep `sucre-snort-ctl help` examples aligned with the contract docs.
- [JS integer safety] → `stats.lastHitTsNs` fields are u64 and may exceed JS safe integer; document that UI must treat them as best-effort and avoid exact arithmetic.
