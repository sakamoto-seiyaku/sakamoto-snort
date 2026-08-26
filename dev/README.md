# `dev/` helpers

The legacy Snort C++ daemon build, deploy, and native-debug helpers were
removed by ADR-0008 together with their source and NDK artifact. Do not restore
or invoke those workflows.

The only active Android device entry is [`./dev/adb`](./adb). It remains the
required wrapper for scoped C/VPP POC device operations. Standalone device test
utility builders may remain under `dev/`, but they are not a product daemon or
an implementation starting point.

The product runtime is intentionally unavailable until a VPP-native C mainline
and its RuntimeService contract are specified.
