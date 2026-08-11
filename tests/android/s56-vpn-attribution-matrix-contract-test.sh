#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/s56-vpn-attribution-matrix.sh"

if [[ ! -f "$matrix" ]]; then
  echo "missing S56 VPN attribution matrix: $matrix" >&2
  exit 1
fi

if grep -Eq '(^|[^./[:alnum:]_-])adb([[:space:]]|$)' "$matrix"; then
  echo "S56 VPN attribution matrix must use repo-local ./dev/adb, not raw adb" >&2
  exit 1
fi

grep -q 'export ADB="${repo_root}/dev/adb"' "$matrix"
grep -q 'debugTrafficSourcePort' "$matrix"
grep -q 'VPN_TUN.ATTRIBUTION.APPLY' "$matrix"
grep -q 'vpn-tun-attribution-control' "$matrix"
grep -q 'uidUnknownFallbackPackets' "$matrix"
grep -q 'attributionResolutions' "$matrix"
grep -q 'noRecognitionHoldEvidence" "claimed' "$matrix"
grep -q 'first.noRecognitionHold" "claimed' "$matrix"
grep -q 'completedVerdictNotRetroactive" "claimed' "$matrix"
grep -q 'matrix.s56LateAttributionEvidence.*claimed' "$matrix"
grep -q 'multiUserIdentity" "not_claimed' "$matrix"

echo "s56 vpn attribution matrix static contract: PASS"
