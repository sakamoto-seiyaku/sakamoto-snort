#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/s56-vpn-multi-user-identity-matrix.sh"

if [[ ! -f "$matrix" ]]; then
  echo "missing S56 VPN multi-user identity matrix: $matrix" >&2
  exit 1
fi

if grep -Eq '(^|[^./[:alnum:]_-])adb([[:space:]]|$)' "$matrix"; then
  echo "S56 VPN multi-user identity matrix must use repo-local ./dev/adb, not raw adb" >&2
  exit 1
fi

grep -q 'export ADB="${repo_root}/dev/adb"' "$matrix"
grep -q 'product-catalog-device-evidence.sh' "$matrix"
grep -q -- '--create-test-profile' "$matrix"
grep -q 'test_profile.cleanup=REMOVED' "$matrix"
grep -q 'same_app_id' "$matrix"
grep -q 'package_uid.distinctFullUid" "PASS' "$matrix"
grep -q 'matrix.s56MultiUserIdentityEvidence" "claimed' "$matrix"

echo "s56 vpn multi-user identity static contract: PASS"
