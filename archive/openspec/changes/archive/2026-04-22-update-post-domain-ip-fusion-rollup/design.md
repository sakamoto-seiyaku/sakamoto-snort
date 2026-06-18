# Design: Rollup verification + docs sync

## Scope
This change does not introduce new runtime behavior. It consolidates post-implementation work:
- manual/regression verification
- documentation sync (OpenSpec + project docs)

## Verification focus

### Blockmask chains
- Independent list lifecycle when domains overlap across listIds:
  - Create two different listIds with different single-bit `blockMask` values.
  - Write the same domain into both lists.
  - Disable/remove either listId and confirm the other listId still contributes its `blockMask`.
- `BLOCKMASK` normalization:
  - Setting an app mask containing bit `8` (reinforced) MUST imply bit `1` (standard).
- Legacy-only behavior:
  - If only `1/8` are used in lists, `domainMask` must not contain extra-chain bits (`2/4/16/32/64`).

### Multi-user support
- Single-user regression:
  - Run existing smoke tests and confirm behavior matches pre-multi-user semantics (aside from new fields).
- Multi-user regression:
  - Same package installed for multiple users produces multiple distinct full UIDs.
  - `USER <userId>` clause selects the correct instance for STR selectors.
  - Per-app knobs (`TRACK`, `CUSTOMLIST.*`, app custom lists/rules) operate on the selected `(package, userId)` instance.
- Robustness:
  - Transient read/parse failures of `package-restrictions.xml` must not trigger uninstall storms (keep old snapshot).

## Documentation sync focus
- Promote archived change deltas into `openspec/specs/` (already done by archiving).
- Replace any stale “single-user only” statements in project documentation with the current multi-user reality.
- Update generated spec stubs (e.g. `Purpose` sections created during archive) so specs are self-contained and readable.

