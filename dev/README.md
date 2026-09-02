# `dev/` helpers

The legacy Snort C++ daemon build, deploy, and native-debug helpers were
removed by ADR-0008 together with their source and NDK artifact. Do not restore
or invoke those workflows.

The only active Android device entry is [`./dev/adb`](./adb). It remains the
required wrapper for scoped C/VPP POC device operations. Standalone device test
utility builders may remain under `dev/`, but they are not a product daemon or
an implementation starting point.

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

The VPP-native C Product runtime and its RuntimeService contract are available
through the S170 recovery baseline. Device operations for that runtime must
continue to use `./dev/adb`; the removed C++ daemon helpers remain historical.
