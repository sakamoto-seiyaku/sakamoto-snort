## Why

The current daemon release artifact is produced inside the Android source tree through Soong and depends on platform-private native libraries. That blocks practical APK/AAB distribution because release builds must be reproducible from the app/repo build environment without Lineage or system_ext integration.

The runtime architecture investigation already concluded that the root daemon can become an NDK `minSdk=31` artifact without rewriting the NFQUEUE datapath. This change turns that investigation into an implementation track.

## What Changes

- Add an NDK r29 + CMake build path for the root daemon, producing an `arm64-v8a` dogfood executable at `build-output/sucre-snort-ndk`.
- Remove daemon runtime dependencies on Android platform-private `libbase` and `libcutils`.
- Keep NDK-public `liblog` and the Bionic system libraries as dynamic dependencies.
- Vendor fixed upstream netfilter library sources and statically link `libmnl`, `libnetfilter_queue`, and `libnfnetlink`.
- Stage the release daemon as an APK-native shaped artifact named `libsucre_snortd.so` under `arm64-v8a`, without building the frontend APK in this change.
- Extend vNext `HELLO` with daemon build/artifact metadata so the existing root deploy and future RuntimeService launch path can validate the running daemon.

## Capabilities

### New Capabilities

- `root-daemon-ndk-release`: Covers the NDK r29 daemon build, native artifact shape, private-library removal, third-party static dependencies, and device validation requirements.

### Modified Capabilities

- `control-vnext-daemon-base`: `HELLO` gains compatible daemon build and artifact metadata fields.

## Impact

- Affected build systems: repo CMake/dev scripts and daemon source lists.
- Affected daemon code: logging, settings property usage, init socket inheritance, vNext `HELLO`.
- Affected dependencies: removes `libbase`/`libcutils`, vendors netfilter sources, requires Android NDK `29.0.14206865`.
- Affected validation: NDK build inspection, existing adb/root dogfood deploy, `dx-smoke`, IP device profiles, and staged APK-native artifact inspection.
