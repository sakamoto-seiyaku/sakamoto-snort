# VS Code + CMake Workspace Boundary

Status: **retired C++ workflow** (2026-08-26, ADR-0008).

The checked-in VS Code tasks no longer build, deploy, test, or debug the
removed Snort C++ daemon. The sole CMake task, `vpp-mainline-pending`, makes
the intentional product-state boundary explicit: a VPP-native C mainline has
not yet been implemented.

There are deliberately no checked-in LLDB launch configurations. Reintroduce
editor build or debug tasks only with the new C/VPP product module and its
documented runtime contract. Do not restore the former NDK, host-test, deploy,
or C++ compatibility tasks.

Historical configuration and source evidence live under `archive/`; they are
not executable workflow instructions.
