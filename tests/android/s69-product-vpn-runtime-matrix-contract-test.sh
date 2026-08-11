#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/s69-product-vpn-runtime-matrix.sh"

[[ -f "$matrix" ]] || {
  echo "missing S69 product VPN runtime matrix: $matrix" >&2
  exit 1
}

grep -q './dev/adb' "$matrix"
grep -q 'export ADB="${repo_root}/dev/adb"' "$matrix"
if grep -Eq '(^|[[:space:]])adb([[:space:]]|$)|adb\.exe' "$matrix"; then
  echo "S69 product VPN matrix must use repo-local ./dev/adb, not raw adb" >&2
  exit 1
fi

grep -q 'com.sakamoto.snort.androidruntime' "$matrix"
grep -q 'runtimeStart true --es runtimeProfile vpn' "$matrix"
grep -q 'adapterReadiness=vpn-tun-hev' "$matrix"
grep -q 'localabstract:${CONTROL_SOCKET}' "$matrix"
grep -q 'packet-adapter-vpn-tun-hev' "$matrix"
grep -q 'VPN_TUN.STATUS' "$matrix"
grep -q 'POLICY.STATUS' "$matrix"
grep -q 'vpn_tun_control_attach=ok adapter=vpn-tun-hev' "$matrix"
grep -q 'vpn_hev_transport=ok' "$matrix"
grep -q 'runtimeStop true' "$matrix"
grep -q 'S69_PRODUCT_RESTART_CYCLES:-2' "$matrix"
grep -q 'restart_cleanup_loop' "$matrix"
grep -q 'restart.result' "$matrix"
grep -q 'ip link show tun0' "$matrix"
grep -q 'dumpsys connectivity' "$matrix"
grep -q 'POC_ONLY.*false' "$matrix"
grep -q 's69Done.*not_claimed' "$matrix"

echo "s69 product vpn runtime matrix static contract: PASS"
