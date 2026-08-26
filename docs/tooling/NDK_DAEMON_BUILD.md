# Retired NDK daemon build

ADR-0008 removed the Android NDK C++ daemon build, `sucre-snort-ndk`, and the
APK artifact `libsucre_snortd.so`. The former `snort-build-ndk` target and its
deploy/debug workflow no longer exist.

This is deliberate: the next product runtime must be a newly specified
VPP-native C mainline. C/VPP POC scripts are scoped evidence tools and do not
replace that product build.
