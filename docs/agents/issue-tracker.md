# Issue tracker: Plane REST via plane-ops

Issues, PRDs, epics, and implementation tasks for this repo live in Plane. Use the global `plane-ops` skill for all tracker operations; do not use Plane MCP.

## Default project

Use the `plane-ops` skill defaults unless the user explicitly names a different Plane project. Non-sensitive Plane defaults live in `~/.agents/skills/plane-ops/defaults.json`; the API key lives in the system keyring.

The current default tracker identifier is `SNORT`, and the repo slug is `sakamoto-snort`.

## Conventions

- Use `plane-ops project list|resolve` only when validating project existence or resolving a user-named project.
- Use `plane-ops work-item list|get|create|update|move|comment|archive|bulk-archive` for work item operations.
- Use `plane-ops label list|create|resolve` for triage labels.
- Use `plane-ops state list|resolve` and `plane-ops work-item move` for workflow state transitions.
- Use `plane-ops type list|schema|resolve` only when the backend reports type support; this self-hosted Plane may return `supported: false`.
- If Codex sandbox blocks keyring or network access, rerun the same `plane-ops` command with sandbox escalation.

## When a skill says "publish to the issue tracker"

Create or update Plane work items through `plane-ops`. Do not create GitHub/GitLab issues, and do not use `.scratch/` as the primary issue tracker unless the user explicitly asks for a temporary local draft.

## Docs are not the tracker

Repository docs may keep reproduction steps, dated measurements, acceptance criteria, and links to Plane work items. They must not maintain open-work ledgers such as `Open`, `TODO`, unchecked bug lists, or backlog queues as the source of truth.

When a doc exposes unresolved work, create or update the corresponding Plane work item first, then rewrite the doc as evidence or an index that links to Plane.

## Historical workflow note

`archive/openspec/` is legacy archive material for this repo. Do not treat OpenSpec proposals, tasks, or specs as current process constraints unless the user explicitly asks to inspect archived context.
