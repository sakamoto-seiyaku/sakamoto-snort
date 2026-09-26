# T19 independent review

Fixed point: `d7ddb68c1524b662c7217008134f7ed60dc46810`.
Initial implementation: `419a8722820c2ceafee43c4f66663d12ac958d3e`.
Two independent agents reviewed the committed diff against repository standards
and the live SAKAMOTO-270/251 specification. Neither edited the implementation or
operated Plane/devices. Pre-existing uncommitted design documents were excluded.

## Standards

Initial report, lightly shortened:

- **P2 — Documented contract breach:** `rule_import.rs` exported configuration
  before constructing the VPP outcome. With `saved_revision == 0`, its export
  error branch returned only `stage: reply`, an export error and revisions,
  discarding `result`, `save_error`, `compile_error` and `error_index`. This state
  is reachable when startup cannot load/create its source. A rejected recovery
  import or failed initial save therefore hid the actionable VPP failure. The
  T19 contract requires existing result/error indices to be retained.
- **P3 — Repeated Switches / Primitive Obsession, judgement call:** the supported
  syntax string set was repeated separately from entry parsing. Future additions
  could be accepted by one branch and remain unreachable through the other.
  Parse the syntax once into a small enum, including validation of empty lists.

Follow-up report:

> Both findings are resolved in the working tree. `rule_import_json` now
> preserves the complete VPP status envelope when export fails, returning
> `configuration: null` and `export_error`. The CLI reports unsuccessful export,
> and the contract documents this behavior. The new startup regression covers
> query, rejected recovery import, save failure and successful repair; verifier
> mutations check that missing errors and invented source are rejected.
> `ListSyntax` supplies one authoritative syntax definition. Serde rejects unknown
> syntax even for empty lists, and entry parsing uses exhaustive enum dispatch.
> No new actionable standards or baseline-smell findings in the follow-up diff.

The P2 failure was reproduced through the actual Product API in
`build-output/t19-20260926/linux-startup-red-b/`, with no valid saved source.
The first startup test attempt (`linux-startup-red/`) had an incorrect harness
readiness assumption and is retained separately. The follow-up review itself
was a source review; execution is documented in the acceptance record.

## Spec

Initial report:

> No confirmed Spec findings in committed diff `d7ddb68...419a872`. The
> implementation matches T19's declared scope: complete online imports, full rule
> identities and conditions, configuration-side normalization, explicit syntax
> rejection, metadata persistence, VPP-owned save/compile and canonical
> export/re-import. Reviewed evidence distinguishes actual Linux and Pixel
> Root/VPN QUIC acceptance from host tests. The unrerun TLS/TCP matrix and broader
> stress coverage are explicitly disclosed and assigned to T29.

Follow-up report:

> No confirmed Spec findings in the follow-up delta. The error-envelope fix
> restores the required distinction between unavailable saved source and VPP
> validation/save/compile outcomes: it preserves status fields, returns
> `configuration: null`, and exposes `export_error`. The CLI correctly fails
> unavailable exports. The enum preserves the same four declared syntaxes and
> rejection behavior. Added tests cover strict IDNA, metadata boundaries and
> startup repair without expanding product semantics. The new Linux verifier
> checks rejected recovery imports, save failure and successful repair; mutation
> checks reject missing error fields and fabricated source.

Initial findings: Standards 1 contract breach and 1 smell judgement; Spec 0.
After correction/recheck: Standards 0 unresolved; Spec 0 confirmed findings.

## Final execution review

The independent Spec reviewer rechecked final source-bound summaries: Linux
121 operations/781 packets; Pixel Root and VPN 117 operations/493 packets each.
Negative counts and the captured 200-echo metrics match the acceptance record.
No confirmed overstatement or acceptance gap was found. The original VPN HOLD
remains unresolved; later representative passes do not claim a cause or fix.

The independent Standards reviewer likewise found no remaining actionable
findings. Final host/platform records and capture metrics match the report;
both original review findings remain resolved.
