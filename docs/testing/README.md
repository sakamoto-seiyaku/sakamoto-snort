# Testing status

Status: **legacy test estate retired** (2026-08-26, ADR-0008).

The former Host gtest/CTest suite, NDK daemon build, and device/DX scripts
exercised the removed Snort C++ mainline. They are not runnable acceptance
paths for the current product and must not be used to claim C/VPP readiness.

SAKAMOTO-171 is an explicit Host-only pre-adapter exception. Its named
`sakamoto-product-host-fixture-abi-test` target and Rust socket fixture cover
only the fixed ABI, generated-VAPI seam, artifact/plugin identity, one
serialized generation-bound session, and residue. They intentionally cannot
test the ADR-0007 Flow Stack because this slice has no packet adapter, packet
graph, or Flow Stack implementation. Their PASS is therefore Host control
evidence only, not ADR-0006/ADR-0007 graph or Android/device evidence. The
fixture target name must never be mistaken for the production Product VPP
ABI; the production path is built separately against the pinned official VPP
checkout by `tools/product/build-host-artifact.sh`.

The remaining `experiments/vpp-nfq-poc/` materials and their OI1–OI5 findings
are bounded design evidence only. New packet-domain tests must be specified
alongside the new VPP-native C module and validate the owner-local flow-stack
contract in ADR-0006 and ADR-0007 without importing the old C++ implementation.

Older detailed test documents are retained as historical records where useful;
their commands and pass results have no current execution status.
