# KISS private-module organization — 2026-09-13

This change reorganizes existing Java, Rust and VPP C implementation. It adds no
framework, crate, transport, packet path or public interface. Policy formats,
compatibility entry points, generation ownership and lifecycle behavior remain
unchanged. This is a scoped refactor regression, not a release or performance gate.

## Implementation

- Java: package-private `RuntimeEvidenceFormatter` owns the two S194 serializers
  and their shared pure text/readback helpers. `RuntimeService` retains state
  capture, generation selection, file I/O and lifecycle orchestration. Exact-output
  Host tests cover null values, unsigned revisions, text bounds, CR/LF normalization,
  field order, readback classification and trailing newlines. Commits: `ec1e824`,
  with the remaining reconciliation caller connected in `5d9f9b0` after APK compilation.
- Rust: private `ffi`, `policy` and `session` modules stay in the existing crate.
  The original crate-root interface is retained through types, direct conversions
  and explicit re-exports. `lib.rs` decreases from 5,361 to 963 lines; tests move
  with their implementation. Commit: `e1d742a`.
- VPP: the contiguous 2,027-line Host-only fixture block moves to
  `product_packet_graph_host_fixtures.inc`, included at the original conditional
  position in the same translation unit. The main graph decreases from 6,783 to
  4,757 lines. Production nodes, ownership, credits and reassembly are unchanged.
  Commit: `f8f0f51`.
- Source-location checks follow the moved implementation without removing their
  assertions. S194's device runner requires the current exact Root readiness tag,
  matching `ProductPacketAdapterContract`, instead of its obsolete `root-nfqueue`
  tag. This test-only correction is `5d26900`.

## Verification

Local evidence is under `build-output/kiss-refactor-20260913/`.

| Check | Result and retained evidence |
| --- | --- |
| Complete Host CTest | **43/43 PASS**, `host-tests-final-head.xml`; includes Java contracts, the new formatter tests, C semantics, Rust 18 unit tests and 8 session tests |
| Rust compatibility | 144 production function definitions unchanged after internal visibility/formatting normalization; 40 public declaration names and 16 C export symbols unchanged; release remains `panic=abort`; `structural-audit.json` |
| VPP source movement | Expanding the private include reproduces the original graph byte-for-byte; Host-on and default preprocessing each match before/after; `host-*.i`, `default-*.i` |
| Product builds | Fresh Host-evidence **OFF** artifact and Android APK both succeed; `linux-build-b/build.json`, `pixel-build-b/build.json` |
| Android Host exclusion | Real NDK/API31/arm64 CMake configuration with Host evidence ON is rejected by the existing Android prohibition; `android-host-on-probe/` |
| Linux Root | Independent S242 verifier **PASS**: partial startup rollback plus stop, restart, abnormal exit and recovery; `linux-root-verified.json` |
| Pixel Root | Independent S242 supervisor verifier **PASS**, generations 1450–1453; each phase captures 24 continuous TCP/UDP dual-stack clients; `pixel-root-verified.json` |
| Controlled Pixel VPN | Independent S243 verifier **PASS**, generations 1454–1461: stop, native crash, broker 0/1 loss and fresh-runtime recovery, with both owners and TCP/UDP4/6; `vpn-active-verified.json` |
| S194 pre-submit fault | **PASS**, generation 1464: definite not-sent failure, no fence/candidate, explicit retry on the same handle, publication and final cleanup; `s194-presubmit-c/summary.properties` |
| S194 callback omission | **PASS**, generations 1467–1468: durable unknown result, same-generation fencing with no second mutation, fresh-generation readback without replay, and final cleanup; `s194-unknown-b/summary.properties` |

The preprocessing comparison normalizes only `__FILE__`/`__LINE__` diagnostics;
these comparison flags are **not** used in the Product builds. Preprocessing is
not counted as a successful Host-only runtime build or fixture execution.

## Build identity

Both accepted build witnesses bind the same current Product source closure:

`7513dc7747f0b7f69386be9be444addbbb8887070a4cf49adce2402a3195fc50`

Installed debug APK SHA-256:

`02afb37f1be6f9a93b4d5f2fa09407150b5ebe5cfc311541b4174b153ea7da71`

The existing verified VPP stages are reused from
`build-output/s220-20260913/{host,android}-stage-b`; VPP and HEV pins are unchanged.
Product C/Rust/JNI and Java artifacts are rebuilt, and the device verifiers check
installed APK/native identities. Build witnesses retain the pre-commit source
snapshot and dirty diff; their file closure, not an old APK or a commit label
alone, binds this regression. The earlier
[foundation report](../testing/2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md) remains
frozen evidence for its own source closure.

## Limits and retained failed attempts

- **Host-evidence ON remains unbuildable on the current pin.** Its existing
  `product_packet_fragment_graph.inc` requires removed
  `ip4_full_reass_custom_*` / `ip6_full_reass_custom_*` interfaces. Compiling the
  original and reorganized translation units produces the same 12 errors,
  retained in `host-evidence-before-compile.log` and
  `host-evidence-after-compile.log`. Host-only dynamic fixture parity is therefore
  unverified. No old reassembly implementation or compatibility fallback is restored.
- The extra S189 source script still fails at its unchanged old
  `hints.network_context_id` assertion. Its Rust checks pass at their new locations;
  this separate historical assertion is not relaxed or represented as passing.
- The initial APK compile exposed a missed Java helper caller, corrected before
  both accepted builds. `pixel-build/` retains that failure. The first Linux run
  encountered an already-present CLI socket before launch; the uniquely named
  `kiss-linux-root-b/` run passes. `linux-root/` retains the failed attempt.
- `s194-presubmit/` retains the obsolete-readiness failure. The following
  `s194-presubmit-b/` reaches the intended fault but its retry revision 192 is below
  the inherited native revision 197 (UI revision 191), so the unchanged Product
  guard correctly rejects it. S194 is then run with a backed-up, temporarily
  isolated native policy store; generation state is never reset.
- `s194-unknown/` was interrupted after a source-path argument typo. Its durable
  unknown fence is resolved through normal fresh-generation readback at generation
  1466, not file deletion; `interrupted-unknown-recovery.properties` retains that
  recovery. The interrupted run is not accepted as a complete S194 scenario.

After both accepted S194 runs, the original native policy, UI product state and
transaction state are restored byte-for-byte (all three SHA-256 values match;
`policy-restored.txt`). The app is stopped at generation 1468, `mayBeActive=false`,
with no runtime error and the original Root selection. Generation state is not
rolled back. Test-generated policy files remain recoverable in the app-private
`files/kiss-refactor-policy-backup-20260913/` directory; no policy data is deleted.

No 24-hour expiry run, CPU/p99 comparison, cellular/physical-network expansion,
ordinary-user VPN launch or release qualification is claimed here.
