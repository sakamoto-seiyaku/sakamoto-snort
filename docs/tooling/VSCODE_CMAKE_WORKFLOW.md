# VS Code and CMake boundary

The checked-in editor configuration does not build or debug the removed C++
daemon. Its informational `vpp-mainline-pending` task is a legacy-named pointer
to the external VPP build, not a claim that Product Core is still unimplemented.

Use the [current tooling guide](README.md) for C Host/CTest and the separate
VPP-native artifact build. There is no checked-in Product LLDB launch contract.
Do not restore former NDK daemon, deploy or C++ compatibility targets.
