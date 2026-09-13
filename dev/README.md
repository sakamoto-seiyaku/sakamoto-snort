# `dev/` helpers

The legacy Snort C++ daemon build, deploy, and native-debug helpers were
removed by ADR-0008 together with their source and NDK artifact. Do not restore
or invoke those workflows.

The only active Android device entry is [`./dev/adb`](./adb). It is required
for Product and scoped POC device operations. Current builds and tests are routed
through the [tooling guide](../docs/tooling/README.md) and
[testing map](../docs/testing/README.md).

Generic NDK setup/environment, Android device selection and tombstone helpers
remain here. Former DX/IP/telemetry utility builders and the resolver mount helper
are [archived together with their tests](../tests/archive/pre-vpp/README.md).
They are not supported product commands or implementation starting points.

## KernelSU Superuser grant after reinstall

For root-mode device acceptance, a debug APK uninstall/reinstall can leave
KernelSU without a valid Superuser grant for the new app install/UID. If the app
reports `root_authorization_required`, first verify KernelSU before diagnosing
the product runtime.

Use only the repo-local wrapper:

```sh
./dev/adb -s <serial> shell input keyevent HOME
./dev/adb -s <serial> shell am start -n me.weishu.kernelsu/.ui.MainActivity
./dev/adb -s <serial> shell screencap -p /sdcard/ksu.png
./dev/adb -s <serial> shell uiautomator dump /sdcard/ksu.xml
./dev/adb -s <serial> pull /sdcard/ksu.png /tmp/
./dev/adb -s <serial> pull /sdcard/ksu.xml /tmp/
```

In KernelSU Manager, open `超级用户`, select the target app entry, and ensure
the `超级用户` switch is on. For this repo's Android runtime, the target package
is `com.sakamoto.snort.androidruntime` and the visible app name is usually
`Sakamoto Runtime`.

Do not edit KernelSU's database or allowlist files directly unless the user
explicitly authorizes that destructive/out-of-band recovery path.

The current VPP-native C runtime and its acceptance limits are summarized in
[current mainline](../docs/current/README.md). Device operations continue to use
`./dev/adb`; the removed C++ daemon helpers remain historical.
