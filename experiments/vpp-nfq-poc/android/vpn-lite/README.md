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

Install:

```sh
bash experiments/vpp-nfq-poc/android/vpn-lite/scripts/install-debug-apk.sh
```

Start VPP count-only mode from adb:

```sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp
```

Emergency stop:

```sh
adb shell am force-stop com.sakamoto.snort.vpnlite
```
