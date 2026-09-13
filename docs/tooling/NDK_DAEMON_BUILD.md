# Retired NDK daemon build

ADR-0008 removed `sucre-snort-ndk`, `libsucre_snortd.so` and the former
`snort-build-ndk` target. Do not restore that C++ build or deployment workflow.

The VPP-native C Product runtime now exists. Use the [current tooling guide](README.md)
and [Android artifact build entry](../../app/android-runtime/scripts/build-debug-apk.sh).
POC adapter artifacts do not replace the product build.
