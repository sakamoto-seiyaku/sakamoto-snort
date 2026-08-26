#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/s61-disabled-lpi-provider-matrix.sh"

[[ -f "$matrix" ]] || {
  echo "missing S61 disabled LPI provider device matrix: $matrix" >&2
  exit 1
}

grep -q './dev/adb' "$matrix"
grep -q 'export ADB="${repo_root}/dev/adb"' "$matrix"
if grep -Eq '(^|[[:space:]])adb([[:space:]]|$)|adb\.exe' "$matrix"; then
  echo "S61 disabled provider matrix must use repo-local ./dev/adb, not raw adb" >&2
  exit 1
fi

grep -q 'source .*dev/dev-android-device-lib.sh' "$matrix"
grep -q 'device_preflight' "$matrix"
grep -q 'require_device_root' "$repo_root/dev/dev-android-device-lib.sh"
grep -q 'S61_APK_VARIANT' "$matrix"
grep -q 'S61_BUILD_APK' "$matrix"
grep -q 'S61_INSTALL_APK' "$matrix"
grep -q 'sha256sum' "$matrix"
grep -q 'ro.build.fingerprint' "$matrix"
grep -q 'ro.product.cpu.abilist' "$matrix"
grep -q 'buildFingerprint' "$matrix"
grep -q 'apk.sha256' "$matrix"
grep -q 'profiles=' "$matrix"

grep -q 'runtimeStart true --es runtimeProfile' "$matrix"
grep -q 'root-nfqueue' "$matrix"
grep -q 'vpn-tun-fd-compat' "$matrix"
grep -q 'NFQUEUE.STATUS' "$matrix"
grep -q 'VPN_TUN.STATUS' "$matrix"
grep -q 'localabstract:sucre-snort-control-vnext' "$repo_root/dev/dev-android-device-lib.sh"

grep -q 'debugDownload' "$matrix"
grep -q 'debugDownloadUrl' "$matrix"
grep -q 'debugDownloadTimeoutMillis' "$matrix"
grep -q 'debugDownloadMaxBytes' "$matrix"
grep -q 'download_succeeded' "$matrix"
grep -q 'download_failed' "$matrix"
grep -q 'payload-bearing HTTP/TCP' "$matrix"
grep -q 'download-probe.properties' "$matrix"
grep -q 'payloadBoundary=transport-payload-only' "$matrix"
grep -q 'downloadOutcome' "$matrix"
grep -q 'providerContract' "$matrix"
grep -q 'PASS_WITH_TRANSPORT_WARNING' "$matrix"
grep -q 'transportStatus' "$matrix"
grep -q 'TCP-connect fallback' "$matrix"

for field in \
  available \
  name \
  payloadBudgetPackets \
  mappedResultCapacity \
  packetsObserved \
  payloadEligiblePackets \
  terminalSkippedPackets \
  providerUnavailablePackets \
  flowSlotUnavailablePackets \
  providerContextUnavailablePackets \
  packetsSubmittedToProvider \
  providerNoResultPackets \
  providerFactPackets \
  detectorDonePackets \
  budgetExhaustedPackets
do
  grep -q "$field" "$matrix" || {
    echo "S61 matrix is missing LPI status field: $field" >&2
    exit 1
  }
done
grep -q 'payloadEligiblePackets.*providerUnavailablePackets' "$matrix"
grep -q 'mappedResultCapacity.*8' "$matrix"
grep -q 'payloadBudgetPackets.*20' "$matrix"
grep -q '"available": False' "$matrix"
grep -q '"name": "disabled"' "$matrix"
grep -q 'status-before.json' "$matrix"
grep -q 'status-after.json' "$matrix"
grep -q 'status-delta.properties' "$matrix"

python3 - "$matrix" <<'PY'
import sys

source = open(sys.argv[1], encoding="utf-8").read()
run_profile = source[source.index("run_profile()") :]
failed = run_profile.index("download_failed")
status_after = run_profile.index('status-after.json')
if failed >= status_after:
    raise SystemExit(
        "S61 failed download evidence must still collect status-after"
    )
download_window = run_profile[run_profile.index("local download_rc") : status_after]
if "return " in download_window:
    raise SystemExit(
        "S61 download outcome handling must not return before status-after"
    )
if "providerContract" not in run_profile:
    raise SystemExit("S61 matrix must record an independent providerContract PASS")
if "downloadOutcome" not in run_profile:
    raise SystemExit("S61 matrix must record downloadOutcome separately")
PY

grep -q 'source=android-installed-apk-debugDownload' "$matrix"
grep -q 'corpus=not_used' "$matrix"
grep -q 'provider=disabled' "$matrix"
grep -q 'providerSource=none' "$matrix"
grep -q 'realProviderEnabled=not_claimed' "$matrix"
grep -q 'ProtocolRule=out_of_scope' "$matrix"
grep -q 'protocolRuleEnforcement=not_claimed' "$matrix"
grep -q 'sourceImported=not_claimed' "$matrix"
grep -q 'corpusImported=not_claimed' "$matrix"

grep -q 'runtimeStop true' "$matrix"
grep -q 'pidof sucre-snortd' "$matrix"
grep -q 'iptables -S' "$matrix"
grep -q 'ip6tables -S' "$matrix"
grep -q 'ip link show tun0' "$matrix"
grep -q 'dumpsys connectivity' "$matrix"
grep -q 'remove_control_vnext_forward' "$matrix"
grep -q 'S61_CLEANUP_ON_EXIT' "$matrix"
grep -q 'app_file_rm' "$matrix"

grep -q 'SKIP' "$matrix"
grep -q 'BLOCKED' "$matrix"
grep -q 'FAIL' "$matrix"
grep -q 'return 77' "$matrix"
grep -q 'no signing/install bypass attempted' "$matrix"

grep -q 's61-disabled-lpi-provider-device' "$matrix"
grep -q 'Root/NFQUEUE' "$matrix"
grep -q 'VPN/TUN' "$matrix"

echo "s61 disabled LPI provider device matrix static contract: PASS"
