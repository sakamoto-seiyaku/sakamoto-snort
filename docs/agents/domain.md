# Domain docs

This is a single-context repo. Start with the root [README](../../README.md) and
[current mainline](../current/README.md), then route by task:

- Architecture: read the [decision map](../decisions/README.md), relevant decision
  records and [accepted ADRs](../adr/) before changing boundaries. ADR-0006/0007/0008
  define the VPP-native C mainline and the removed-C++ boundary.
- Control plane / API / RuntimeService: use the [interface map](../INTERFACE_SPECIFICATION.md)
  and the actual typed contracts it links.
- Product scope / UI / content / release: read [product docs](../product/README.md)
  and their routed plan. Goals are not implementation evidence.
- Tests / builds: use [testing](../testing/README.md) or [tooling](../tooling/README.md).
- Documentation organization: read [maintenance rules](doc-maintenance.md).

[CONTEXT](../../CONTEXT.md), the [roadmap](../IMPLEMENTATION_ROADMAP.md) and the
[long Android/VPP handoff](../ANDROID_VPP_CURRENT_STATE_HANDOFF.md) are accumulated
context. Read relevant sections for vocabulary and lineage, not all of them by
default. Resolve phase conflicts against accepted current decisions, actual source
and dated evidence; surface genuine decision conflicts instead of silently overriding them.

`docs/reviews/`, `docs/reference/`, `docs/archived/` and `experiments/` are supporting
or historical material. POC source is not an implementation template. OpenSpec in
`archive/openspec/` is history only; inspect it only when explicitly requested.

Use existing domain terms. Do not infer a product promise from an internal
capability, POC or archived backend feature. Work state belongs to Plane.
