# Reference naming and POC organization — 2026-09-13

Scope: [SAKAMOTO-250](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/8e61d338-af8d-4a15-ae57-b9739a749337).
This follows the [S249 organization](2026-09-13_REPOSITORY_ORGANIZATION.md).
The user subsequently approved reconciling and committing the 23 document changes
that S249 had deliberately left untouched. No Product feature or module redesign
is part of this work.

## Reference naming closure

Commit `d4e5e6506a0b99bbe3237b57dea19d89643f6d04` handles those 23 worktree entries
(21 modified documents plus one old/new filename pair), a naming guide and checks.
Product/glossary/ADR text uses the project's own semantics; external observations
are not worded as an already implemented Sakamoto recognizer. Reference records
retain real external API/CLI/environment/source names while abstracting the local
checkout root. The neutral wrapper-inventory filename has an old-path redirect.

The [naming guide](../reference/NAMING_AND_PROVENANCE.md) records the distinction.
The naming commit passed **42/42** CTest; its separate report is
`build-output/s250-20260913/naming-host-tests.xml`.
S249's original preservation/diff-hash record remains a truthful earlier checkpoint,
not a claim that these documents must remain uncommitted forever.

## Experiment and tool disposition

The intake contained **528 tracked experiment files and 12 reference tools**.
The [experiment map](../../experiments/README.md) and
[catalog](../../experiments/catalog.json) classify all of them. With added
navigation/archive metadata, the current catalog covers **546 paths**:
533 experiment files and 13 reference-tool files. Each has a documented role.

- Historical VPP/NFQUEUE/TUN sources, Android shells, overlays, patches, clients,
  prototypes, scripts/tests, registrations and raw records remain at original
  paths. This protects source-bound recipes and evidence; they are not Product
  source templates or default acceptance commands.
- The original campaign README and POC status table are archived intact, with
  maintained navigation/redirects at their original paths.
- S245/S246 and S247 remain frozen, separately scoped characterization records;
  the earlier S200-isolated handcrafted bridge remains a historical non-HEV POC.
- The catalog explicitly retains the staging/SOCKS helper paths still referenced
  by older checks, without presenting those consumers as current Product gates.
- Two Host recognition probes, their old S61 aggregate and old S61 static contract
  depended on the C++ model removed by ADR-0008. Their obsolete bodies are removed;
  four tiny same-name guards now return `RETIRED` / exit 2 before side effects.
  No C++ test/model source archive or fallback is created. The preceding Git
  revision and dated documents retain historical provenance; do not restore the model.
- Nine remaining reference tools keep their bytes and explicit reference-only
  boundary. No external library build, inventory probe or corpus replay was run.
- Ignored source/build/APK/runtime/result/evidence/cache directories remain intact.
  Classification is complete for the tracked inventory; disk purging and a fresh
  execution audit of every historical recipe are not claimed.

All **528 original experiment files** match their intake Git blobs, following the
two documented README/status moves. The **nine retained reference tools** also
match: **537/537 preserved files**, zero content mismatches. A local per-file
origin/target/blob report is `build-output/s250-20260913/preservation.json`.

## Verification and unchanged Product identity

Final root CTest is **43/43 PASS**. This adds the naming and experiment-catalog
checks to S249's 41-test set; historical 35/40 and earlier 41/41 reports are not
rewritten. The catalog check covers complete path classification, rejection of
unregistered experiment directories, retained reference hashes, all four fail-closed
guards (normal and `--help` calls) and the Product source-path boundary. It does
not run a POC or certify every historical experiment's correctness.

Final XML: `build-output/s250-20260913/final-host-tests.xml`, SHA-256
`29c0e92d57db7dadd8edcc3f7319262372ec4dbf9103b9031874aaf7843aa6b7`.

The independent joint checker freshly re-evaluated retained raw evidence as
`PASS_WITH_EXPLICIT_LIMITS`. Its new `foundation-recheck.json` has SHA-256
`c30e50b88da0dfa53f4b6eb5cb42ce595c27eade52765700da6b8bb76db94862`, identical
to the untouched original. Product source closure remains
`ab278ba6c69555a0772277f17d9350bc73ced8312d061a663d52fe3b06b05b96`.
Product C/Rust/Java/VPP/HEV/build tools, current device collectors and independent
verifiers have no source diff from before S250. No device operation, 24-hour test,
release claim or Product behavior change is introduced by this organization.
