# Integration directory boundary

Current Product device acceptance starts at the [testing evidence map](../../docs/testing/README.md)
and its scoped collectors in [tests/device](../device/), not the former DX smoke suite.
Root CMake does not include an integration subdirectory or register legacy daemon tests.

The [archived integration bundle](../archive/pre-vpp/tests/integration/) preserves
the former DX/vNext scripts and README as historical records. Those commands
target removed APIs and are not supported execution paths.

`android-runtime-lifecycle.sh` and `android-runtime-incubator-lifecycle.sh` remain
at their original paths as migration harnesses; the latter is still referenced
by an older hardening check. Their retention does not make them current acceptance
or authorize invoking them against a device. Use the named current evidence matrix.
