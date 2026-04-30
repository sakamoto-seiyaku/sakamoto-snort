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

The repo-root CMake workflow also exposes:

```bash
cmake --build --preset dev-debug --target snort-build-ndk
```

The build script discovers NDK r29 from `ANDROID_NDK_HOME`,
`ANDROID_NDK_ROOT`, `$ANDROID_SDK_ROOT/ndk/29.0.14206865`,
`$ANDROID_HOME/ndk/29.0.14206865`, or the documented local default.

This NDK path is independent of the legacy Soong/Blueprint graph. Do not use
`snort-build-regen-graph` for NDK daemon validation; that target remains only
for separate legacy Soong changes such as `Android.bp` edits.

## APK-Native Staging

This backend change only stages the APK-native shaped daemon artifact:

```text
build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so
```

It does not build the Flutter APK. A later frontend integration change should
wire this staged directory into the Android packaging flow and verify install
behavior.

## RuntimeService Launch Contract

The future frontend APK packaging path should include the staged artifact at:

```text
lib/arm64-v8a/libsucre_snortd.so
```

RuntimeService should resolve:

```text
${applicationInfo.nativeLibraryDir}/libsucre_snortd.so
```

and launch that filesystem path through the root execution path. That later APK
packaging change must force native library extraction or legacy JNI library
packaging so `nativeLibraryDir` contains a real executable file.

After launch, RuntimeService should call vNext `HELLO` and validate:

```text
artifactAbi == "arm64-v8a"
daemonBuildId is non-empty
capabilities contains stable compatibility strings
```

## Device Validation

Dogfood the NDK daemon directly before APK RuntimeService integration:

```bash
bash dev/dev-deploy.sh --binary build-output/sucre-snort-ndk
bash tests/integration/dx-smoke.sh --skip-deploy --cleanup-forward
bash tests/device/ip/run.sh --profile matrix --skip-deploy --cleanup-forward
```

`dx-smoke` covers platform, vNext control, datapath, and flow telemetry smoke.
The IP `matrix` profile covers the broader L3/L4 rule matrix against the same
NDK daemon process.
