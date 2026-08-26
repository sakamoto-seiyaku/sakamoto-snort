# Testing status

Status: **legacy test estate retired** (2026-08-26, ADR-0008).

The Host gtest/CTest suite, NDK daemon build, and device/DX scripts described
by the former testing documentation exercised the removed Snort C++ mainline.
They are not runnable acceptance paths for the current product and must not be
used to claim C/VPP readiness.

The remaining `experiments/vpp-nfq-poc/` materials and their OI1–OI5 findings
are bounded design evidence only. New tests must be specified alongside the
new VPP-native C module; they must validate the owner-local flow-stack contract
in ADR-0006 and ADR-0007 without importing the old C++ implementation.

Older detailed test documents are retained as historical records where useful;
their commands and pass results have no current execution status.
