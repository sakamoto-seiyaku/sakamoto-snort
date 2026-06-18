# Documentation Maintenance Map

Last updated: 2026-06-18

This file records how Matt skills and future agents should treat the documentation tree after the OpenSpec workflow moved to `archive/openspec/` and Plane `SNORT` became the active tracker.

## Classification Rules

- `authoritative-current`: safe default context for planning or implementation.
- `evidence-current`: current evidence or acceptance material, but not a tracker.
- `reference-only`: history, background, review output, or lineage material. Read only when relevant.
- `historical-archive`: archived records that must not define current workflow.

## Default Agent Context

Use these first:

- `CONTEXT.md`
- `docs/agents/`
- `docs/README.md`
- `docs/IMPLEMENTATION_ROADMAP.md`
- `docs/INTERFACE_SPECIFICATION.md`
- `docs/decisions/`

Use these by task:

- `docs/testing/README.md` and focused `docs/testing/**` files for test work.
- `docs/tooling/**` for build, deploy, NDK, VS Code, and native debug work.
- `tests/host/README.md`, `tests/integration/README.md`, or module-local test docs when changing tests.

Use these only as background:

- `docs/reviews/`
- `docs/reference/`
- `docs/archived/`
- `archive/openspec/`

## Work Tracking Policy

Plane project `SNORT` is the source of truth for open work.

- Parent cleanup item: `SNORT-1`
- Daemon SIGTERM/SIGKILL evidence: `SNORT-2`
- Large IPRULES ruleset apply failure: `SNORT-3`
- IPRULES hot-path measurement matrix: `SNORT-4`
- DNS/pkt stream field contract assertions: `SNORT-5`
- DNS-to-IP binding pkt stream domain smoke: `SNORT-6`
- pkt `tracked=0` suppressed notice smoke: `SNORT-7`
- NFQUEUE power/performance architecture follow-ups: `SNORT-8`
- Active docs refresh item: `SNORT-9`

Docs may link to these work items and keep evidence, but they must not keep their own `Open`, `TODO`, or unchecked bug ledgers.

## Folder Handling

| Path | Classification | Handling |
| --- | --- | --- |
| `docs/agents/` | `authoritative-current` | Matt skills / Plane / domain-doc workflow context. |
| `docs/decisions/` | `authoritative-current` | Active decision records after refresh; interface details still defer to `docs/INTERFACE_SPECIFICATION.md`. |
| `docs/testing/` | mixed | Active runbooks, casebooks, and evidence. Open work must link to Plane. |
| `docs/tooling/` | `authoritative-current` | Active build/debug workflow docs. |
| `docs/reviews/` | `reference-only` | Point-in-time audits. Accepted decisions must be promoted to `docs/decisions/` or Plane. |
| `docs/reference/` | `reference-only` | Background/lineage comparison. Do not treat old bugs or line numbers as current facts. |
| `docs/archived/` | `historical-archive` | History only. Files may keep historical wording; use folder/file banners to avoid current-authority confusion. |
| `docs/archived/DOMAIN_IP_FUSION/` | `historical-archive` | Historical vNext/fusion workspace. Current authority is roadmap + interface spec + decisions. |
| `archive/openspec/` | `historical-archive` | OpenSpec archive only. Do not create new root `openspec/` work unless explicitly asked. |

## Glossary Follow-Up

`CONTEXT.md` should keep absorbing stable terminology when docs or implementation work clarifies it:

- `clientRuleId`, `ruleId`, `wouldRuleId`, `wouldDrop`, and would/shadow evaluation semantics.
- Complete Linux UID, `appId`, `userId`, app selector, selector ambiguity, and selector not found.
- Policy state vs observability session state vs counters vs reset/session boundaries.
- Legacy/backlog terms: `ip-leak`, Domain-IP bridge, `BLOCKIPLEAKS`, `GETBLACKIPS`, `MAXAGEIP`.
- Diagnostic-only reverse DNS: `RDNS` / `rdns.enabled`.
