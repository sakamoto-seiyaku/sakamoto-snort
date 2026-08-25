# Snort VPN Lite

Minimal Android VPN-mode POC for `experiments/vpp-nfq-poc`.

Scope:

```text
Phase 1:
  Android VpnService full-route IPv4 VPN
  -> detach tun-fd
  -> JNI fd probe reads L3 packet headers

Phase 2:
  optionally package Android VPP runtime
  -> fork/exec VPP from VpnService native helper
  -> dup detached tun-fd to fd 3
  -> tun_poc count-only reads packets through VPP
```

Non-goals for this directory:

```text
No HEV startup.
No packet forwarding.
No product UI.
```

Build:

```sh
bash experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh
```

For an OI3/B1 build, select every runtime input explicitly rather than relying
on a previously populated stage:

```sh
VPP_RUNTIME_STAGE_DIR=/path/to/vpp-stage \
HEV_STAGE_DIR=/path/to/hev-owner-stage \
VPP_POC_PLUGIN=/path/to/hev_external_driver_poc_plugin.so \
bash experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh
```

`VPP_POC_PLUGIN` updates both
`hev_external_driver_poc_plugin.so` and
`libhev_external_driver_poc_plugin.so`. The build fails unless both packaged
members hash-match the selected input. Do not use an APK for evidence if the
HEV stage does not export the owner API required by OI3 or if source, plugin,
stage, APK-member, installed-APK, and device-runtime provenance cannot be
joined.

Install:

```sh
bash experiments/vpp-nfq-poc/android/vpn-lite/scripts/install-debug-apk.sh
```

Start VPP count-only mode from adb:

```sh
./dev/adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp
```

Emergency stop:

```sh
./dev/adb shell am force-stop com.sakamoto.snort.vpnlite
```

## OI3 lifecycle boundary (Android 16)

The OI3 service runs as a foreground service (`specialUse`) for bounded POC
cells; without that declaration Android 16 may reap an idle service and remove
the underlay callback while the native flow is still being diagnosed. OI3 also
registers a `ConnectivityManager.NetworkCallback` for the non-VPN underlay and
publishes an epoch/physical-handle snapshot through JNI to the owner thread.
The callback never mutates FlowStackOwner state directly.

When Wi-Fi is physically lost, Android 16 can remove the existing VPN Network
even though the service observes a replacement physical Network. The supported
POC recovery is therefore: owner-side invalidation of the old generation,
bounded VPN stop/start, then fresh traffic on the new VPN Network. This is not
a claim of seamless in-place Android VPN migration or automatic session
recreation.

## Android 16 LAN-fixture preflight

Android 16 Local Network Protection can be enabled for this package by the
`RESTRICT_LOCAL_NETWORK` compatibility test state. In that state, a WSL2/LAN
server can receive and reply while the reply is still dropped for the VpnLite
UID before the protected connector socket becomes readable. A successful shell
probe does not rule this out because the policy is per UID.
See Android's official
[Local network permission documentation](https://developer.android.com/privacy-and-security/local-network-permission)
for the Android 16 opt-in test behavior and temporary permission path.

Before interpreting a controlled LAN timeout as an OI3/HEV return failure:

1. Stop the VPN and prove the endpoint with both a shell control and a direct
   socket owned by `com.sakamoto.snort.vpnlite`.
2. Record the package UID, active underlay Network, runtime permission grants,
   and `RESTRICT_LOCAL_NETWORK` compat state.
3. Unless Local Network Protection is the subject of the cell, restore the POC
   package to the declared baseline and reboot when required for netd/BPF state
   to rebuild:

   ```sh
   ./dev/adb shell am compat disable RESTRICT_LOCAL_NETWORK com.sakamoto.snort.vpnlite
   ./dev/adb shell pm grant com.sakamoto.snort.vpnlite android.permission.NEARBY_WIFI_DEVICES
   ./dev/adb reboot
   ```

The temporary permission is a controlled Android 16 POC condition, not a
decision that the release product must request it. Full diagnosis and evidence
boundaries are in
[`S140_B1_RETURN_HOTSPOT_DIAGNOSIS.md`](../../S140_B1_RETURN_HOTSPOT_DIAGNOSIS.md).
