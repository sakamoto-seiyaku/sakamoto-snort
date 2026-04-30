## ADDED Requirements

### Requirement: Daemon builds with Android NDK r29
The release daemon build MUST use Android NDK `29.0.14206865`, target `android-31`, compile as C++20, and produce an `arm64-v8a` executable artifact at `build-output/sucre-snort-ndk`.

The build entrypoint MUST treat NDK r29 as an external Android SDK dependency. The documented local default SDK root SHALL be `/home/js/.local/share/android-sdk`, which makes the documented local default NDK path `/home/js/.local/share/android-sdk/ndk/29.0.14206865`. The build entrypoint MUST also support CI and open-source developer environments by discovering the same NDK version from `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, `$ANDROID_SDK_ROOT/ndk/29.0.14206865`, or `$ANDROID_HOME/ndk/29.0.14206865`.

#### Scenario: NDK dogfood artifact is built
- **WHEN** the NDK daemon build entrypoint runs with NDK `29.0.14206865`
- **THEN** it SHALL produce `build-output/sucre-snort-ndk` as an ARM64 Android executable artifact

#### Scenario: Local default NDK path is discovered
- **WHEN** no explicit NDK environment variable is set and `/home/js/.local/share/android-sdk/ndk/29.0.14206865` exists
- **THEN** the NDK daemon build entrypoint SHALL use that NDK installation

#### Scenario: CI SDK-root NDK path is discovered
- **WHEN** GitHub Actions or another CI runner installs NDK `29.0.14206865` under `$ANDROID_SDK_ROOT/ndk/29.0.14206865`
- **THEN** the NDK daemon build entrypoint SHALL use that NDK installation without requiring a hard-coded `/home/js` path

#### Scenario: Missing r29 NDK fails clearly
- **WHEN** the NDK daemon build entrypoint cannot find NDK `29.0.14206865`
- **THEN** it SHALL fail before compilation with an actionable message naming the required NDK version, supported environment variables, and the documented local default path

### Requirement: Daemon release artifact does not depend on platform-private native libraries
The NDK-built daemon MUST NOT dynamically depend on Android platform-private `libbase.so` or `libcutils.so`. It MAY dynamically depend on NDK/public Android libraries such as `liblog.so`, `libc.so`, `libm.so`, and `libdl.so`.

#### Scenario: Dynamic dependency inspection rejects private libraries
- **WHEN** `readelf -d build-output/sucre-snort-ndk` is inspected after a successful NDK build
- **THEN** the NEEDED entries SHALL NOT include `libbase.so` or `libcutils.so`

#### Scenario: Logging remains available through logcat
- **WHEN** the NDK-built daemon emits INFO, WARNING, ERROR, or FATAL logs
- **THEN** the logs SHALL be written through NDK `liblog` with the same daemon log tag family used by the release artifact

### Requirement: Netfilter userspace libraries are vendored and statically linked
The NDK daemon build MUST use vendored upstream sources for `libmnl 1.0.5`, `libnetfilter_queue 1.0.5`, and `libnfnetlink 1.0.2`, build them as static libraries, and link them into the daemon artifact.

#### Scenario: Netfilter libraries are not loaded dynamically
- **WHEN** `readelf -d build-output/sucre-snort-ndk` is inspected after a successful NDK build
- **THEN** the NEEDED entries SHALL NOT include `libmnl.so`, `libnetfilter_queue.so`, or `libnfnetlink.so`

#### Scenario: Vendored source licenses are shipped
- **WHEN** the vendored netfilter sources are added to the repository
- **THEN** their source version, origin, and license/NOTICE information SHALL be present in the vendored dependency tree or release documentation

### Requirement: NDK dogfood artifact follows current real-device deploy flow
The NDK dogfood artifact MUST be runnable through the existing adb/root development flow by explicitly selecting `build-output/sucre-snort-ndk` as the daemon binary.

#### Scenario: Existing deploy script starts NDK daemon
- **WHEN** `dev/dev-deploy.sh --binary build-output/sucre-snort-ndk` runs on a rooted test device
- **THEN** the daemon SHALL start from `/data/local/tmp/sucre-snort-dev`, expose `@sucre-snort-control-vnext`, and answer vNext `HELLO`

#### Scenario: Existing smoke flow validates NDK daemon
- **WHEN** `dx-smoke` runs after deploying the NDK dogfood artifact
- **THEN** the platform, control, and datapath smoke checks SHALL pass without requiring Android source tree build output

### Requirement: Release daemon is staged as APK-native artifact
The NDK build MUST stage the release daemon as `build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so`. This change MUST NOT require a frontend Flutter/Gradle APK build or install validation.

#### Scenario: APK-native artifact is staged
- **WHEN** the NDK daemon build completes
- **THEN** `build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so` SHALL exist and identify as an ARM64 Android executable artifact

#### Scenario: RuntimeService launch contract is documented for follow-up
- **WHEN** frontend APK packaging is implemented in a later change
- **THEN** it SHOULD consume the staged `lib/arm64-v8a/libsucre_snortd.so` artifact and launch the installed `${applicationInfo.nativeLibraryDir}/libsucre_snortd.so` path through root

### Requirement: NDK validation does not require the Soong graph
The NDK daemon build and validation workflow MUST NOT require Lineage, Soong, `system_ext_specific`, Android source tree outputs, or `snort-build-regen-graph`.

#### Scenario: NDK build does not call Soong
- **WHEN** the NDK daemon build is invoked
- **THEN** it SHALL build through the NDK/CMake path and SHALL NOT call the Soong daemon target

#### Scenario: Android.bp graph rebuild is not part of NDK validation
- **WHEN** validating the NDK daemon migration
- **THEN** `snort-build-regen-graph` SHALL NOT be required unless a separate change modifies `Android.bp`
