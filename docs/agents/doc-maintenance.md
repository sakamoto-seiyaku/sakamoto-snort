# Documentation maintenance

Updated: 2026-09-13. [Current mainline](../current/README.md) is the short default
entry; [the documentation map](../README.md) routes everything else.

## Authority and placement

| Class | Locations | Rule |
| --- | --- | --- |
| Current implementation | `docs/current/`, current source contracts | Keep short; link bounded evidence and state important limits |
| Accepted constraints | `docs/adr/`, current entries in `docs/decisions/README.md` | Read before architectural work; retain supersession history |
| Product intent | `docs/product/` | Desired outcomes, not proof of shipping or tested behavior |
| Dated evidence / runbooks | `docs/testing/`, `tests/evidence/` | Preserve scope, source identity, failures and measurement date |
| Active workflow | `docs/agents/`, `docs/tooling/`, `dev/README.md` | Commands must refer to existing current tools |
| Accumulated context | root `CONTEXT.md`, roadmap, Android/VPP handoff | Select relevant sections; do not append every run to default reading |
| Reference / history | `docs/reviews/`, `docs/reference/`, `docs/archived/`, archived tests | Not current authority or code to import |

## Editing and archiving

- Separate current facts, intended goals and old observations. Do not erase an old
  failure report because a later run passes; add a new dated record and route to it.
- Move only unambiguously superseded material. Keep stable redirect pages where
  existing links need them; archived content retains its original context and paths.
- Historical scripts are non-runnable records, not supported entrypoints. Do not
  wire them back into CMake, editor tasks or current device runners.
- Do not move Product sources, current collectors or hashed verifier dependencies
  as cosmetic cleanup. Their paths and bytes are part of acceptance provenance.
- Preserve unrelated uncommitted changes. Large overlapping documents may be
  reclassified through navigation without rewriting or staging the user's edits.
- Never delete all `build-output/` as a “cache cleanup”: it contains frozen source,
  artifacts, raw evidence and retained failed attempts as well as generated output.
- OpenSpec remains an explicitly requested historical source only.

## Work tracking

Plane project `SAKAMOTO` owns open work, priorities and acceptance decisions; use
[plane-ops](issue-tracker.md). Docs may retain completed records, reproducible
commands and ticket links, but not a competing TODO/unchecked backlog.

Old SNORT identifiers and point-in-time “unfinished” statements are historical;
do not copy them into new issues without checking current source and Plane state.
See the [organization record](../maintenance/2026-09-13_REPOSITORY_ORGANIZATION.md)
for the latest separation of current navigation and preserved material.
