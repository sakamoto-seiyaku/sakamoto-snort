# SAKAMOTO-197 Legacy Reference Audit

Date: 2026-09-02  
Scope: S170 fourth-gap cleanup: legacy C++ identifiers, unreachable runtime
branches, and tests that still treated the removed implementation as current.

This audit does not restore, translate, import, or add a compatibility path for
the removed Snort C++ packet-domain implementation. The product path remains
VPP-native C, Rust control plane, and the Android Java supervisor.

## Disposition

The initial inventory found two active-code problems rather than one isolated
file:

1. `RuntimeService.java` contained a dead legacy launch/ownership branch and
   retained identifiers for `libsucre_snortd.so` and its hash assets.
2. `tests/android/runtime-contract-test.sh` compiled the old vpn-lite
   experiment and positively asserted removed daemon/C++ paths.

Both active problems are now cleaned up. The dead Product Core-adjacent
ownership/recovery helpers were removed as well; this prevents a deleted
`adoptRuntime` path from remaining in the Android compile graph.

## Source cleanup

`app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java`
now has one runtime start path: `startProductCoreRuntime()`. It stages and
launches `libvpp_runtime.so`, validates the Product Core plugin and manifest,
uses Product Core owner audits, and performs Product Core-only stop/cleanup.
The following retired elements were removed:

- `ROOT_BINARY`, `VPN_BINARY`, `MANIFEST_ASSET`, `HASH_ASSET`, and
  `DAEMON_HASH_ASSET`;
- the unreachable duplicate Root/VPN launch and adoption logic;
- generic PID/profile ownership helpers that no current caller used;
- the old `failWithCleanup`/automatic-recovery integration and its dead
  cleanup result type.

`RuntimeOwnershipReconciliation` remains only where the current Product Core
owner command result type and host-tested policy seam require it. It is not a
route back to the removed daemon.

`RuntimeArtifactIdentity.java` had no repository callers after the branch was
removed and was deleted rather than left as an unused compatibility type.

## Test cleanup

`tests/android/runtime-contract-test.sh` is now a small current-head entry
point that runs the VPP-native Android contracts (S172/S173/S192/S196). It no
longer compiles the vpn-lite experiment or asserts removed source paths.

The following tests were deleted because their only implementation under test
was removed or their source paths no longer exist:

- `tests/android/RuntimeContractTest.java`;
- `tests/android/s56-vpn-attribution-runtime-contract-test.sh`;
- `tests/android/s61-disabled-lpi-provider-device-contract-test.sh`;
- `tests/android/s69-vpn-tun-matrix-contract-test.sh`;
- `tests/device/s61-disabled-lpi-provider-matrix.sh`;
- `tests/device/vpn-tun-device-matrix.sh`.

Current S56 attribution, S176-S196 packet/lifecycle contracts, Product Core
host tests, and the Android contract seam remain in place. S57 and S179 static
contracts now assert `failProductCoreGeneration()` and
`reconcileProductCoreRuntime()` rather than dead method names.

## Documentation classification

Current product and handoff documents were corrected to describe the
VPP-native Product Core baseline and to point at the S195/S196 evidence. ADRs,
POC journals, old release dossiers, and old device matrices remain as
historical records where they explain decisions or preserve evidence; their
headers must state that they are not current acceptance gates.

The following older runners still contain historical daemon names or old
release-era assumptions and are intentionally not counted as current evidence:

- `tests/device/root-nfqueue-device-matrix.sh`;
- `tests/device/s54-upgrade-rollback-matrix.sh`;
- `tests/device/s55-product-vpn-transport-matrix.sh`;
- `tests/device/s69-product-vpn-runtime-matrix.sh`;
- `tests/device/s70-profile-lifecycle-matrix.sh`;
- `tests/device/s71-dual-profile-closure-gate.sh`;
- related S54/S55/S59/S70/S71 contract wrappers.

These are archive/retarget follow-up material, not a reason to reintroduce C++
or to run an obsolete gate. The current acceptance source is the latest
S195/S196 dossier and its current-head contracts.

## Verification

The cleanup pass was checked with:

- `bash tests/android/runtime-contract-test.sh`;
- `bash tests/android/s172-product-lifecycle-contract-test.sh`;
- `bash tests/android/s196-runtime-instance-teardown-contract-test.sh`;
- `bash tests/android/android-runtime-hardening-contract-test.sh`;
- `git diff --check`.

The current APK evidence remains `/tmp/s194-apk-output-current-fixed/
sakamoto-runtime-debug.apk`, containing `libvpp_runtime.so`,
`libproduct_core_plugin.so`, and `assets/product-stage.properties`, with no
`libsucre_snortd.so`. No new device acceptance run is implied by this static
cleanup; existing S195/S196 device evidence remains the authoritative runtime
record until a later code change requires a rerun.

## Result

The active C++/dead-branch hotspot is resolved, and obsolete tests no longer
participate in the current Android contract entry point. S197 should remain
In Progress until the Android product build and the full current static suite
are rerun from this tree; historical runners must stay clearly quarantined.
