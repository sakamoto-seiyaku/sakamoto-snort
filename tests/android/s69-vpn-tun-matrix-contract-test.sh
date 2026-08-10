#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/vpn-tun-device-matrix.sh"
main_activity="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/MainActivity.java"
build_script="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh"

[[ -f "$matrix" ]] || {
  echo "missing S69 VPN/TUN device matrix: $matrix" >&2
  exit 1
}
[[ -f "$main_activity" ]] || {
  echo "missing vpn-lite MainActivity: $main_activity" >&2
  exit 1
}
[[ -f "$build_script" ]] || {
  echo "missing vpn-lite build script: $build_script" >&2
  exit 1
}

grep -q './dev/adb' "$matrix"
grep -q 'export ADB="${repo_root}/dev/adb"' "$matrix"
if grep -Eq '(^|[[:space:]])adb([[:space:]]|$)|adb\.exe' "$matrix"; then
  echo "S69 VPN/TUN matrix must use repo-local ./dev/adb, not raw adb" >&2
  exit 1
fi

for script in \
  android-run-vpp-direct-owner-poc.sh \
  android-run-vpn-owner-gate-poc.sh \
  android-run-vpp-owner-resolver-poc.sh \
  android-run-vpp-owner-resolver-udp-poc.sh \
  android-run-vpn-protect-poc.sh \
  android-run-vpp-hev-50-cycle-poc.sh
do
  grep -q "$script" "$matrix" || {
    echo "S69 VPN/TUN matrix does not reference expected POC script: $script" >&2
    exit 1
  }
done

grep -q 'vpp-hev-direct-owner-single-writer' "$matrix"
grep -q 'S69_LIFECYCLE_CYCLES:-3' "$matrix"
grep -q 'S69_VPP_STAGE_DIR' "$matrix"
grep -q 'android-vpp-direct-owner-stage' "$matrix"
grep -q 'UNAVAILABLE' "$matrix"
grep -q 'POC_ONLY' "$matrix"
grep -q 'PRODUCT_GAP' "$matrix"
grep -q 'not_claimed' "$matrix"
grep -q 'run.log' "$matrix"
grep -q 'RESULT_DIR' "$matrix"

for legacy_extra in \
  EXTRA_LEGACY_START \
  EXTRA_LEGACY_STOP \
  EXTRA_LEGACY_HTTP_PROBE \
  EXTRA_LEGACY_UDP_PROBE
do
  grep -q "$legacy_extra" "$main_activity" || {
    echo "vpn-lite MainActivity must bridge historical POC extra: $legacy_extra" >&2
    exit 1
  }
done

for service_action in \
  SnortVpnService.ACTION_START \
  SnortVpnService.ACTION_STOP \
  SnortVpnService.ACTION_HTTP_PROBE \
  SnortVpnService.ACTION_UDP_PROBE
do
  grep -q "$service_action" "$main_activity" || {
    echo "vpn-lite MainActivity must bridge POC extras to: $service_action" >&2
    exit 1
  }
done

grep -q 'startService(serviceIntent)' "$main_activity"
grep -q 'SnortVpnService.EXTRA_ALLOWED_PACKAGE' "$main_activity"
grep -q 'SnortVpnService.EXTRA_BLOCK_OWNER_UID' "$main_activity"
grep -q 'SnortVpnService.EXTRA_ENABLE_IPV6' "$main_activity"

grep -q 'vpn_fd_probe.c' "$build_script"
grep -q 'libvpnfdprobe.so' "$build_script"
grep -q 'aarch64-linux-android31-clang' "$build_script"
grep -q 'VPP_STAGE_DIR' "$build_script"
grep -q 'libvpppoc.so' "$build_script"
grep -q 'lib$so_name' "$build_script"
grep -q 'snort-vpn-lite-debug.apk' "$build_script"
grep -q 'HEV_STAGE_DIR' "$build_script"
grep -q 'libhev-socks5-tunnel.so' "$build_script"
grep -q 'vpp.strings' "$build_script"

if grep -Eq 'PRODUCT_GAP\.s69Done[[:space:]]+(complete|done|claimed)($|[[:space:]])' "$matrix"; then
  echo "S69 VPN/TUN matrix must not claim S69 closure" >&2
  exit 1
fi

echo "s69 vpn/tun matrix static contract: PASS"
