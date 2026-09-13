# Repository organization — 2026-09-13

Scope: [SAKAMOTO-249](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/45dff573-1927-427a-8e5c-8c1059597ede).
This is an organization/test-maintenance record, not new Product implementation
or a release gate. Open work belongs to Plane.

## Navigation and classification

- [Current mainline](../current/README.md) is the short default implementation
  entry. Root README, docs index and agent reading rules route by task.
- Product plans remain goals; dated acceptance remains evidence. The long
  CONTEXT/roadmap/Android-VPP handoff stays in place as accumulated context.
- The old interface table and three unambiguously superseded decision records
  are [archived intact](../archived/pre-vpp/README.md), with current navigation or
  redirects at their stable paths. Mixed principle/history documents remain
  in place and are classified in the [decision map](../decisions/README.md).
- [Test navigation](../../tests/README.md) and [tooling](../tooling/README.md)
  separate executable current checks, scoped collectors, evidence and history.

## Test/tool archive and cleanup

The [pre-VPP test/tool bundle](../../tests/archive/pre-vpp/README.md) mirrors
125 original repository-relative paths: DX/vNext integration, IP/diagnostics/
telemetry tooling, Neper dependency/license files and six dedicated dev helpers.
The [retired-contract bundle](../../tests/archive/retired-contracts/README.md)
contains four obsolete registered source-shape tests and their short S191 alias.
Archived file bytes are preserved; executable bits are removed.

The two Android lifecycle migration harnesses remain at their original paths;
one is still referenced by an older hardening check. Their retained status does
not make them current acceptance. Current numbered device collectors and all
independent verifier dependencies keep their original paths and bytes.

Four obsolete CTest registrations are replaced with current executed Android
Runtime contracts, policy bundle/teardown contracts and focused Root/VPN/network
source-wiring guards. The VPP artifact check accepts the existing configurable
Host-evidence option while retaining Android exclusion. A navigation check covers
active local links, current registered test paths and archive isolation. These
source checks are not substituted for real packet evidence or semantic C tests.

Fourteen physically empty old source directories under `src/main`, `src/control`,
`src/config`, `src/datapath`, `src/core` and `src/app` were removed with non-recursive
`rmdir`; no source files were deleted. Generic NDK/device/tombstone helpers stay.
Duplicate build-output ignore entries are consolidated and Python tool caches
ignored. Approximately 35 MB of ignored old local IP records/Neper outputs remain
untouched at their original paths; their ignore rules are retained at the root.

## Preservation and verification

The user's 23 pre-existing document changes remain unchanged and uncommitted.
Their binary diff SHA-256 at intake is
`a4194b14cf58c994469059d68798cb92b844cc2113a082f71af9d0c363e8b7c7`;
the renamed untracked reference document is preserved separately.

No Product C/Rust/Java/VPP/HEV/build-tool source is changed or moved. The Product
source closure stays `ab278ba6c69555a0772277f17d9350bc73ced8312d061a663d52fe3b06b05b96`.
Frozen APK/native artifacts, raw success/failure evidence and the original joint
reports are not overwritten. The [foundation report](../testing/2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md)
keeps its historical 35/40 CTest observation; this cleanup uses a replacement
41-test set and separate output under `build-output/s249-20260913/`.

Fresh CTest is **41/41 PASS**, including executed Java contracts and the existing
Rust/C semantic tests. The first sandboxed run was 40/41 because Unix-socket
creation was denied; its `host-tests-first.xml` is retained. The complete rerun
in a socket-permitting host environment is `host-tests.xml`. Focused platform
wiring checks include seven in-memory corruption witnesses; none edits Product
source. Active navigation checks pass separately and in CTest.

All 130 archived test/tool files and four archived documents match the original
Git blobs byte-for-byte; only script executable modes change. Original end-of-file
formatting is retained, including missing final newlines in upstream Neper files.
The protected user diff and untracked reference document hashes still match intake.

The independently regenerated `foundation-recheck.json` remains
`PASS_WITH_EXPLICIT_LIMITS`, with SHA-256
`c30e50b88da0dfa53f4b6eb5cb42ce595c27eade52765700da6b8bb76db94862`,
identical to the untouched original report. This rechecks retained evidence; it
does not collect new device observations or erase its release/24-hour/hardware limits.

Large RuntimeService/packet-graph decomposition is deliberately outside this
organization change. No 24-hour test or device operation is started here.

## Delivery identity

Organization/test implementation commit:
`2995c7dc89d9e4abc2c8ad12e9cb1880e3499291`.
The final complete 41-test run, including the new negative witnesses, is retained
as `build-output/s249-20260913/host-tests-final.xml`, SHA-256
`f04d2071ec3fc33ad504d577fe83f27db9622526b6ef62c4173699d09aa4ad22`.
Archive origin/destination/blob identities are retained locally in
`build-output/s249-20260913/organization-integrity.json`.
After the implementation commit, Git status contained exactly the same 23
pre-existing changes, with no staged user documents or Product source edits.
