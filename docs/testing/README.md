# Testing status

Status: **legacy test estate retired** (2026-08-26, ADR-0008).

The former Host gtest/CTest suite, NDK daemon build, and device/DX scripts
exercised the removed Snort C++ mainline. They are not runnable acceptance
paths for the current product and must not be used to claim C/VPP readiness.

Focused current VPP-native C evidence:

- [S229 bounded Product reassembly](2026-09-11_S229_INDEPENDENT_REASSEMBLY.md).
- [S221 owner-local FlowRuntime](2026-09-11_S221_FLOW_RUNTIME.md): shared typed storage,
  startup capacity, processing bypass, worker/collision and stop ledgers. Protocol trackers,
  automatic expiry and release latency/size budgets remain distinct claims.

The first current product acceptance path was the combined SAKAMOTO-171/172
Product Spine device run recorded in
[`SAKAMOTO_171_172_DEVICE_ACCEPTANCE.md`](SAKAMOTO_171_172_DEVICE_ACCEPTANCE.md).
It starts from a newly versioned debug APK installed through `./dev/adb`, then
uses the visible Activity, Java Supervisor, Rust Product Core, production VAPI
bridge, and product VPP plugin. Plane marks both tickets Done as of
2026-08-30; the document remains the local record of what counted for that
Product Spine closure.

The SAKAMOTO-176 through SAKAMOTO-196 recovery device paths are closed. Their
current-head acceptance baseline, artifact hashes, retained failures, and
evidence limits are recorded in
[`SAKAMOTO_195_RECOVERY_ACCEPTANCE_DOSSIER.md`](SAKAMOTO_195_RECOVERY_ACCEPTANCE_DOSSIER.md).
Later source review findings must be recorded as code-review gaps rather than
rewriting a completed device observation or calling S176 the current blocker.

SAKAMOTO-171's named `sakamoto-product-host-fixture-abi-test` target and Rust
socket fixture remain fast supporting tests for the fixed ABI, generated-VAPI
seam, and one serialized generation-bound session. Their PASS was not the
Product Spine acceptance result. The fixture is Host-test-only and must never
be linked into the Android product; an Android build without generated VAPI
inputs fails rather than falling back to it. Detailed Host results remain in
[`SAKAMOTO_171_HOST_EVIDENCE.md`](SAKAMOTO_171_HOST_EVIDENCE.md).

The remaining `experiments/vpp-nfq-poc/` materials and their OI1–OI5 findings
are bounded design evidence only. New packet-domain tests must be specified
alongside the VPP-native C module and validate the owner-local flow-stack
contract in ADR-0006 and ADR-0007 without importing the old C++ implementation.

The obsolete vpn-lite/C++ runtime contract and disabled-LPI/vpn-lite device
wrappers were deleted in SAKAMOTO-197. Older detailed test documents and
release-era device runners are retained as historical records where useful;
their commands and pass results have no current execution status.
