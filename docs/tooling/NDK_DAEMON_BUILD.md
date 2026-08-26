# NDK Daemon Build

The root daemon release path builds with Android NDK `29.0.14206865`,
`android-31`, C++20, and `arm64-v8a`.

## Local Setup

The documented local SDK root is:

```bash
/home/js/.local/share/android-sdk
```

The documented local NDK path is:

```bash
/home/js/.local/share/android-sdk/ndk/29.0.14206865
```

Validate or print the environment with:

```bash
bash dev/dev-setup-ndk.sh --check
eval "$(bash dev/dev-setup-ndk.sh --print-env)"
```

## Build

From the repository root:

```bash
bash dev/dev-build-ndk.sh
```

This produces:

```text
build-output/sucre-snort-ndk
build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so
```

Both paths contain the same ARM64 Android executable payload. The `.so` path is
an APK-native staging name for future packaging; it is not a separate shared
library build.

The repo-root CMake workflow also exposes:

```bash
cmake --build --preset dev-debug --target snort-build-ndk
```

The build script discovers NDK r29 from `ANDROID_NDK_HOME`,
`ANDROID_NDK_ROOT`, `$ANDROID_SDK_ROOT/ndk/29.0.14206865`,
`$ANDROID_HOME/ndk/29.0.14206865`, or the documented local default.

This NDK path is the active daemon build path and is independent of the legacy
Soong/Blueprint graph. The repo-root workflow no longer exposes a Soong daemon
build or graph-regeneration target.

## APK-Native Staging

This backend slice only stages the APK-native shaped daemon artifact:

```text
build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so
```

It does not build the Flutter APK. The Android VPN-lite POC now wires this
staged directory into a debug APK and verifies install behavior in SAKAMOTO-12.

## RuntimeService Launch Contract

The frontend APK packaging path should include the staged artifact at:

```text
lib/arm64-v8a/libsucre_snortd.so
```

RuntimeService should resolve:

```text
${applicationInfo.nativeLibraryDir}/libsucre_snortd.so
```

and launch that filesystem path through the root execution path. That APK
packaging integration slice must force native library extraction or legacy JNI library
packaging so `nativeLibraryDir` contains a real executable file.

After launch, RuntimeService should call vNext `HELLO` and validate:

```text
artifactAbi == "arm64-v8a"
daemonBuildId is non-empty
capabilities contains stable compatibility strings
```

SAKAMOTO-12 validated the contract on Pixel 6a / Android 16 / `arm64-v8a`:

```text
APK-native daemon SHA-256: fe2b15dc87d28404e4c6c912ecbc9dea658104b0666e604519b8113a22f00b57
HELLO artifactAbi: arm64-v8a
HELLO daemonBuildId: ndk-r29-7c897161e637
HELLO capabilities: snort10-base, nfqueue-pass-through
```

The debug POC requires an explicit KernelSU Superuser grant for the APK. Before
that grant, the app process cannot see `/system/bin/su` in its mount namespace;
the root launch path therefore fails before the daemon starts. The service writes
the root daemon PID to an app-private runtime file and uses that PID for TERM/KILL
cleanup because killing the Java `Process` wrapper alone is not reliable after
`su` executes the daemon. This is a debug POC result, not a release permission,
foreground-service, upgrade, or rollback contract.

Operational pitfall: `adb shell su` success only proves the shell package is
authorized. It does not prove `com.sakamoto.snort.androidruntime` can launch the
root runtime. Before accepting S70/S71 root-profile failures as dataplane
evidence, verify the KernelSU allowlist or Manager UI includes the Android
runtime package. If it does not, the expected product state is
`root_authorization_required`; grant KernelSU Superuser authorization to the APK
and rerun the lifecycle gate. The APK manifest declares KernelSU package
visibility so the app can surface the grant path, but that declaration is not a
grant.

## APK POC Build Identity

The APK build scripts package the already-staged
`build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so`; they do not rebuild
the daemon source. After changing daemon code, rebuild the NDK artifact first:

```bash
bash dev/dev-build-ndk.sh
bash experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh
```

SAKAMOTO-14 first produced an invalid run because the APK still contained the
pre-change artifact. The formal run was accepted only after the staged artifact
reported `hello_daemon_build_id=ndk-r29-f0c2da8f030e` and its hash was captured
alongside the APK hash.

## Device Validation

Dogfood the NDK daemon directly before APK RuntimeService integration:

```bash
bash dev/dev-deploy.sh
bash tests/integration/dx-smoke.sh --skip-deploy --cleanup-forward
bash tests/device/ip/run.sh --profile matrix --skip-deploy --cleanup-forward
```

`dx-smoke` covers platform, vNext control, datapath, and flow telemetry smoke.
The IP `matrix` profile covers the broader L3/L4 rule matrix against the same
NDK daemon process.
