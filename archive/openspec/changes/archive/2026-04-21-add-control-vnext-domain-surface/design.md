## Context

- Roadmap slice: `docs/IMPLEMENTATION_ROADMAP.md` → vNext control 平面切片 `add-control-vnext-domain-surface`。
- Protocol truth:
  - wire/envelope/errors/strict reject: `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
  - cmd/args/result contracts: `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
- Current code state (already implemented):
  - vNext server + session loop: `src/ControlVNext.cpp`, `src/ControlVNextSession.cpp`
  - daemon base commands (meta/inventory/config/reset): `src/ControlVNextSessionCommandsDaemon.cpp`
- Domain runtime state (legacy behavior; vNext must keep semantics unchanged):
  - rules library: `src/RulesManager.*` + `src/Rule.*`
  - per-scope custom domains/rules: `src/DomainManager.*` (device-wide) + `src/App.*` (per-UID)
  - domain lists storage + mask aggregation: `src/DomainList.*`
  - list metadata (url/name/etag/outdated/enabled/domainsCount): `src/BlockingListManager.*` + `src/BlockingList.*`
  - legacy command surface (for behavior reference only): `src/Control.cpp`

## Goals / Non-Goals

**Goals:**

- Implement vNext Domain surface commands in the daemon:
  - `DOMAINRULES.GET/APPLY`
  - `DOMAINPOLICY.GET/APPLY` (ack-only apply)
  - `DOMAINLISTS.GET/APPLY/IMPORT`
- Enforce vNext strict reject and structured errors (stable shapes; no silent no-op).
- Keep output shapes stable and sortable for tests/snapshots (per vNext docs).
- `DOMAINLISTS.IMPORT`:
  - enforce command-level limits (`maxImportDomains=1_000_000`, `maxImportBytes=16MiB`)
  - implement all-or-nothing semantics (no partial import on error)
  - update only `domainsCount` on success (do not implicitly modify subscription fields)

**Non-Goals:**

- No changes to domain matching / verdict semantics (custom allow/block precedence, wildcard/regex semantics, suffix matching, etc.).
- No new “fetch remote list” behavior (daemon remains non-HTTP; refresh stays client-driven).
- No auth/permission model (v1 reserved error code remains reserved).
- No vNext metrics/stream/IPRULES work (separate roadmap slices).

## Decisions

1) **Command handler structure**

- Add a dedicated vNext domain command handler (e.g., `ControlVNextSessionCommandsDomain.*`) that mirrors the existing daemon-base handler style:
  - Input: `ControlVNext::RequestView` + limits
  - Output: `ResponsePlan { rapidjson::Document response, closeAfterWrite }`
- Dispatch order in `ControlVNextSession`:
  1. meta (`HELLO/QUIT`)
  2. daemon base handler
  3. domain surface handler
  4. fallback `UNSUPPORTED_COMMAND`

2) **Locking / concurrency**

- Treat domain mutating commands as control-plane mutations and run them under the same exclusive lock used by `RESETALL/CONFIG.SET`:
  - Exclusive: `DOMAINRULES.APPLY`, `DOMAINPOLICY.APPLY`, `DOMAINLISTS.APPLY`, `DOMAINLISTS.IMPORT`
  - Shared: `DOMAINRULES.GET`, `DOMAINPOLICY.GET`, `DOMAINLISTS.GET`
- Rationale: keep “apply is atomic” promises deterministic under concurrent traffic and avoid races with save/reset paths.

3) **Stable sorting guarantees**

- `DOMAINRULES.GET/APPLY.result.rules[]`: sort by `ruleId` ascending.
- `DOMAINLISTS.GET.result.lists[]`: sort by `listKind` then `listId` ascending (string order).
- Rationale: simplifies snapshot tests and “backup/restore” workflows.

4) **`DOMAINLISTS.IMPORT` limits + error shape**

- Limits (command-level, distinct from framing max):
  - `maxImportDomains=1_000_000`
  - `maxImportBytes=16MiB` (computed as sum of UTF-8 byte lengths of `domains[]` entries)
- When limits are exceeded (and frame size is still within `maxRequestBytes`), return:
  - `ok=false`, `error.code="INVALID_ARGUMENT"`
  - `error.limits={maxImportDomains,maxImportBytes}`
  - a `hint` that client must chunk import
- Rationale: avoids silent truncation and lets CLI/UI implement deterministic chunking.

5) **Import metadata policy**

- On successful `DOMAINLISTS.IMPORT`, daemon updates only `domainsCount` in list metadata for that `listId`.
- The daemon MUST NOT implicitly change `outdated/updatedAt/etag/url/name` in response to import.
- Rationale: `DOMAINLISTS.IMPORT` is a data-plane operation (domain set content), while subscription fields are UI/refresh semantics owned by the client; chunked imports must not accidentally mark a list as “fully synced”.

6) **Atomic apply semantics**

- All `*.APPLY` and `DOMAINLISTS.IMPORT` operations are all-or-nothing at the request level:
  - Validate entire payload first.
  - Only publish new in-memory baselines after successful validation + persistence.
- Rationale: aligns with vNext “apply is atomic” contract and prevents half-updated state on partial failures.

## Risks / Trade-offs

- [Large imports are expensive] → Enforce limits + require client chunking; implement import atomicity via temp-file strategy to avoid partial writes.
- [Strict reject breaks sloppy clients] → Provide `hint` fields and keep `sucre-snort-ctl help` examples in sync with vNext docs.
- [RuleId upsert impacts persistence/invariants] → Add P0 tests that cover ruleId allocation, duplicate detection, and referential integrity checks against `DOMAINPOLICY`.

## Open Questions

- None (limits + metadata policy are fixed by this change proposal).

