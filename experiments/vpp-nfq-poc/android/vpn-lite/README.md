# Snort VPN Lite

Minimal Android VPN-mode POC for `experiments/vpp-nfq-poc`.

Scope:

```text
Phase 1 only:
  Android VpnService full-route IPv4 VPN
  -> detach tun-fd
  -> JNI fd probe reads L3 packet headers
```

Non-goals for this directory at Phase 1:

```text
No VPP startup.
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

Emergency stop:

```sh
adb shell am force-stop com.sakamoto.snort.vpnlite
```
