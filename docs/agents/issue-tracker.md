# Issue tracker: Plane MCP

Issues, PRDs, epics, and implementation tasks for this repo live in Plane. Use the Plane MCP tools for all tracker operations.

## Default project

Use this project unless the user explicitly names a different Plane project:

| Field | Value |
| ----- | ----- |
| Plane identifier | `SNORT` |
| Plane project ID | `9939eb81-377d-43be-9611-8b2eb7cb0fab` |
| Plane display name | `Sakamoto Snort` |
| Repo slug | `sakamoto-snort` |

Plane rejected `sakamoto-snort` as a project display name because project names cannot contain special characters. The project display name is `Sakamoto Snort`; the repo slug remains `sakamoto-snort`.

## Conventions

- Use `list_projects` only when validating project existence or resolving a user-named project. For this repo's default work, use the pinned `SNORT` project above.
- Use `create_work_item`, `retrieve_work_item`, `retrieve_work_item_by_identifier`, `update_work_item`, and `list_work_items` for work item operations.
- Use `list_labels`, `create_label`, and `manage_work_item_label` for triage labels.
- Use `list_states` and `update_work_item` for Plane workflow state transitions.
- Use `create_work_item_comment` and `list_work_item_comments` for discussion/history.
- For epics, call `resolve_work_item_type(project_id, "Epic")`, then create a normal work item with that `type_id`.

## When a skill says "publish to the issue tracker"

Create or update Plane work items through the Plane MCP tools. Do not create GitHub/GitLab issues, and do not use `.scratch/` as the primary issue tracker unless the user explicitly asks for a temporary local draft.

## Docs are not the tracker

Repository docs may keep reproduction steps, dated measurements, acceptance criteria, and links to Plane work items. They must not maintain open-work ledgers such as `Open`, `TODO`, unchecked bug lists, or backlog queues as the source of truth.

When a doc exposes unresolved work, create or update the corresponding Plane work item first, then rewrite the doc as evidence or an index that links to Plane.

## Historical workflow note

`archive/openspec/` is legacy archive material for this repo. Do not treat OpenSpec proposals, tasks, or specs as current process constraints unless the user explicitly asks to inspect archived context.
