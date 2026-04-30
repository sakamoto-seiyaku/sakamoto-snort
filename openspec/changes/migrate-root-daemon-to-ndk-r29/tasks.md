## 1. NDK Build Baseline

- [x] 1.1 Add an NDK r29 build entrypoint that requires Android NDK `29.0.14206865`, discovers it from `ANDROID_NDK_HOME` / `ANDROID_NDK_ROOT` / SDK-root side-by-side paths, documents `/home/js/.local/share/android-sdk/ndk/29.0.14206865` as the local default, and fails clearly when that version is missing.
- [x] 1.2 Add a CMake Android/arm64 daemon target using `android-31`, C++20, exceptions, pthreads, and the existing daemon source list.
- [x] 1.3 Generate `build-output/sucre-snort-ndk` from the NDK build path without requiring Lineage, Soong, or Android source tree outputs.
- [x] 1.4 Add a repo build target or script wrapper so developers and GitHub Actions can build the NDK daemon from the repository root using the same NDK discovery rules.

## 2. Private Android Library Removal

- [x] 2.1 Replace `<android-base/logging.h>` usage with a local stream-style logger wrapper backed by NDK `liblog`.
- [x] 2.2 Preserve `LOG(INFO/WARNING/ERROR/FATAL) << ...` call sites, with `LOG(FATAL)` logging and terminating the process.
- [x] 2.3 Remove `sucre-snort.first_start` system-property state and delete the `android-base/properties.h` dependency.
- [x] 2.4 Replace `android_get_control_socket()` calls with a local init-socket helper that supports inherited `ANDROID_SOCKET_<name>` fds and otherwise enters the existing fallback socket path.
- [x] 2.5 Verify host tests still compile with the new local compatibility headers or test stubs.

## 3. Vendored Netfilter Dependencies

- [x] 3.1 Import fixed upstream sources for `libmnl 1.0.5`, `libnetfilter_queue 1.0.5`, and `libnfnetlink 1.0.2`.
- [x] 3.2 Preserve source origin, version, license, and NOTICE information for the vendored netfilter dependencies.
- [x] 3.3 Add CMake static library targets for the three netfilter libraries using the minimal source lists needed by the daemon.
- [x] 3.4 Link the daemon against the vendored static libraries and remove dependence on Android-tree `external/lib*` libraries.

## 4. Daemon Metadata And APK Artifact Contract

- [x] 4.1 Extend vNext `HELLO` to return `daemonBuildId`, `artifactAbi`, and `capabilities` without changing existing HELLO fields.
- [x] 4.2 Add tests for the compatible HELLO extension and existing HELLO clients that read only the old fields.
- [x] 4.3 Produce or stage the release artifact as `libsucre_snortd.so` for `arm64-v8a`.
- [x] 4.4 Document the future frontend APK packaging handoff without requiring Flutter/Gradle build or APK install in this change.
- [x] 4.5 Document RuntimeService launch expectations for the follow-up frontend change: resolve `${applicationInfo.nativeLibraryDir}/libsucre_snortd.so`, launch it through root, and validate HELLO metadata.

## 5. Device Validation

- [x] 5.1 Inspect `build-output/sucre-snort-ndk` with `file` and `readelf -d`.
- [x] 5.2 Verify dynamic dependencies do not include `libbase.so`, `libcutils.so`, `libmnl.so`, `libnetfilter_queue.so`, or `libnfnetlink.so`.
- [x] 5.3 Run `dev/dev-deploy.sh --binary build-output/sucre-snort-ndk` on a rooted device and confirm daemon pid, sockets, and vNext HELLO.
- [x] 5.4 Run `dx-smoke` against the NDK daemon artifact.
- [x] 5.5 Run IP device smoke/matrix profiles and telemetry consumer validation against the NDK daemon artifact.
- [x] 5.6 Verify the staged APK-native `.so` artifact exists and is the same Android ARM64 executable payload validated by the rooted device tests.

## 6. Release Workflow Boundaries

- [x] 6.1 Defer frontend APK install validation and formal Soong daemon release-path removal to follow-up changes after this NDK artifact is proven.
- [x] 6.2 Keep or migrate helper/tool builds independently so no release task depends on Android source tree daemon output.
- [x] 6.3 Update docs and developer commands to point to the NDK daemon build and deployment flow.
- [x] 6.4 Route NDK daemon validation through `snort-build-ndk` / `dev/dev-build-ndk.sh`; keep `snort-build-regen-graph` only for separate legacy Soong / `Android.bp` graph changes.
