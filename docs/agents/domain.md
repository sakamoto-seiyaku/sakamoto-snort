# Domain Docs

This is a single-context repo.

## Before exploring, read these

- `docs/IMPLEMENTATION_ROADMAP.md` for current phase, implementation order, and boundaries.
- `docs/INTERFACE_SPECIFICATION.md` before control-plane, API, stream, telemetry, RuntimeService, or frontend-contract work.
- `docs/decisions/` for architectural and domain decisions.
- `docs/README.md` for the documentation map.
- `docs/agents/doc-maintenance.md` before reorganizing, archiving, or refreshing documentation.
- Focused docs under `docs/testing/`, `docs/reviews/`, `docs/reference/`, or `docs/tooling/` when relevant to the task.
- `CONTEXT.md` at the repo root if it exists.

If `CONTEXT.md` does not exist, proceed silently. Do not create it upfront; create or update it only when a documentation-oriented skill such as `grill-with-docs` resolves project vocabulary.

## Historical archive

`archive/openspec/` is historical archive material. Do not use it as a source of active workflow constraints. Only inspect it when the user explicitly asks for archived OpenSpec context.

`docs/archived/`, `docs/reviews/`, and `docs/reference/` are not default agent context. Treat them as evidence or background unless an active roadmap, interface, testing, tooling, or decision document explicitly points to them.

## Vocabulary and decisions

Use the project's existing domain language from the roadmap and decision docs. If a proposal contradicts `docs/decisions/`, surface the conflict explicitly instead of silently overriding prior decisions.
