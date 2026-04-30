# Archived Soong daemon material

This directory keeps historical Android source / Soong daemon files for audit
context only.

The active root daemon build is the Android NDK r29 path:

```bash
bash dev/dev-build-ndk.sh
cmake --build --preset dev-debug --target snort-build-ndk
```

Do not use the archived `Android.bp` or `sucre-snort.rc` as an active daemon
build, install, deploy, or debug workflow.
