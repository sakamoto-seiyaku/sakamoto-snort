## Context

The runtime architecture investigation in `/home/js/Git/sucre/sakamoto/docs/ROADMAP/TMP_ROOT_DAEMON_RUNTIME_ARCHITECTURE.md` establishes the target shape: the Play-facing app owns a foreground RuntimeService, and the root daemon is delivered as an APK native artifact rather than as a system_ext binary built from Android platform source.

The current daemon build is a Soong `cc_binary` in `Android.bp`. It statically links netfilter libraries from the Android tree and dynamically links `libbase`, `libcutils`, `liblog`, `libc++`, `libc`, `libm`, and `libdl`. `libbase` and `libcutils` are the release blockers because they are platform-private native libraries. The data path itself already uses Linux/Bionic APIs and netfilter libraries that can be built from source with the NDK.

## Goals / Non-Goals

**Goals:**

- Build the daemon with Android NDK r29 (`29.0.14206865`), `minSdk=31`, `arm64-v8a`, and C++20.
- Produce a dogfood executable at `build-output/sucre-snort-ndk` that can run through the current adb/root deploy and device smoke flows.
- Remove daemon links to `libbase` and `libcutils` without changing control, DNS, or packet verdict semantics.
- Vendor and statically link upstream netfilter libraries needed by NFQUEUE.
- Stage the APK-native artifact shape for the future frontend RuntimeService.
- Add daemon build metadata to vNext `HELLO` for APK/runtime compatibility checks.

**Non-Goals:**

- No NFQUEUE datapath rewrite.
- No change to vNext command schemas other than compatible `HELLO` additions.
- No new runtime supervisor implementation in this backend change beyond the artifact and metadata contract.
- No multi-ABI release in the first version; first release is `arm64-v8a` only.
- No assets/raw executable copy path and no dynamic code download path.
- No frontend Flutter/Gradle APK build, APK install, or RuntimeService implementation in this change.
- No removal of the legacy Soong daemon build path in this change; that is a follow-up after APK/RuntimeService validation.

## Decisions

1. **Use NDK r29 as the only formal daemon release toolchain.**

   r29 is the currently confirmed stable target and supports the C++20 surface needed by the daemon, including `std::atomic_ref` through libc++. Older local NDKs, including r23/r26, are not accepted as proof for this migration.

   The NDK is treated as an external Android SDK dependency, not a repository artifact and not a project-specific absolute path. The default local Linux SDK root for this project is `/home/js/.local/share/android-sdk`, so the default local NDK path is `/home/js/.local/share/android-sdk/ndk/29.0.14206865`. Build tooling must still be CI-compatible by discovering the NDK from `ANDROID_NDK_HOME`, `ANDROID_NDK_ROOT`, or `$ANDROID_SDK_ROOT/ndk/29.0.14206865` / `$ANDROID_HOME/ndk/29.0.14206865`. GitHub Actions installs the same version into the runner SDK root with `sdkmanager` or an Android setup action.

2. **Create a dogfood binary before APK integration.**

   The first build output is `build-output/sucre-snort-ndk`. Existing `dev/dev-deploy.sh --binary` and `dx-smoke` already exercise the actual root daemon lifecycle, sockets, iptables hooks, NFQUEUE, control plane, and telemetry. This isolates build/dependency risk before adding RuntimeService packaging concerns.

3. **Remove private Android libraries with local compatibility shims.**

   `libbase` logging is replaced by a local stream-style logger wrapper that writes to NDK `liblog` and aborts on fatal logs. `first_start` property usage is removed because current code has no business call sites for `firstStart()`/`finishFirstStart()`. `android_get_control_socket()` is replaced by a local init-socket helper that reads inherited `ANDROID_SOCKET_<name>` fds when present and otherwise returns `-1`, preserving the existing fallback socket path for APK/root launch.

4. **Vendor upstream netfilter sources and statically link them.**

   NDK does not ship `libmnl`, `libnetfilter_queue`, or `libnfnetlink`. The change vendors fixed upstream source releases: `libmnl 1.0.5`, `libnetfilter_queue 1.0.5`, and `libnfnetlink 1.0.2`. They are built as static libraries through CMake and linked into the daemon, with license/NOTICE review captured in the implementation.

5. **Stage the APK-native artifact shape for release handoff.**

   The NDK build stages `build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so`.
   This proves the binary shape that the frontend APK can later consume. Actual Flutter/AGP
   packaging and install-time `nativeLibraryDir` verification are intentionally left to a
   separate frontend integration change.

6. **Make `HELLO` carry daemon identity.**

   RuntimeService needs a cheap compatibility gate after root launch. vNext `HELLO` keeps all existing fields and adds `daemonBuildId`, `artifactAbi`, and `capabilities`. Existing clients that ignore unknown fields remain compatible.

7. **Keep Soong as legacy until the frontend integration change.**

   The NDK path is now the release-candidate daemon path, and NDK validation must not call
   `snort-build-regen-graph`. Removing the legacy Soong daemon release surface is deferred until
   APK/RuntimeService packaging has passed on-device validation.

## Risks / Trade-offs

- [Risk] NDK r29 may expose compile failures hidden by the Android platform toolchain. -> Mitigation: first task is a compile spike with no behavior changes, then fix private API and C++20 issues locally.
- [Risk] Vendored netfilter sources may need Android-specific compile flags. -> Mitigation: start from the current Lineage source lists and upstream release tarballs, keep the static library build minimal, and validate with `readelf` plus device NFQUEUE smoke.
- [Risk] Static libc++ can conflict if the daemon later loads plugins or shared C++ libraries. -> Mitigation: the release artifact is a single executable-style native artifact; if future shared C++ components are introduced, revisit `c++_shared`.
- [Risk] APK native library extraction differs by AGP/minSdk defaults. -> Mitigation: defer AGP packaging to a frontend change after this backend NDK artifact is proven.
- [Risk] Removing Soong quickly removes a known build fallback. -> Mitigation: keep Soong legacy entrypoints until APK/RuntimeService validation has its own change.

## Migration Plan

1. Create the NDK build entrypoint and compile the daemon with r29, using `/home/js/.local/share/android-sdk/ndk/29.0.14206865` as the documented local default and environment-variable/SDK-root discovery for CI.
2. Replace `libbase`/`libcutils` usage and remove `first_start` property semantics.
3. Vendor and statically link the netfilter libraries.
4. Validate `build-output/sucre-snort-ndk` with `readelf`, `dev-deploy --binary`, `dx-smoke`, IP device profiles, and telemetry checks.
5. Stage the APK-native `.so` artifact and document the future RuntimeService launch metadata contract.
6. Keep formal Soong removal and frontend APK install validation as follow-up work.

## Open Questions

- The exact daemon build id source can be generated from git metadata, release version metadata, or a CMake-provided value; implementation must choose one stable string and expose it through `HELLO`.
- SELinux behavior for `@sucre-snort-control-vnext` under APK/root launch remains a device-matrix validation item.
