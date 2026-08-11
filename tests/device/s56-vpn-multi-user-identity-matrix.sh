#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-56 product VPN multi-user identity evidence matrix.
#
# This is a bounded wrapper around the S50 product catalog device evidence:
# it creates a temporary managed profile, installs the existing product package
# for that profile, records per-user complete Linux UIDs, then verifies that
# the same package is represented by distinct Android UIDs rather than a lossy
# appId-only subject. The wrapped script removes the temporary profile during
# cleanup.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s56-vpn-multi-user-identity-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
CATALOG_EVIDENCE="${repo_root}/tests/device/product-catalog-device-evidence.sh"

mkdir -p "$RESULT_DIR"

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

value_for() {
  local key="$1"
  local file="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); found=1 } END { if (!found) exit 1 }' "$file"
}

same_app_id() {
  python3 - "$1" "$2" <<'PY'
import sys

left = int(sys.argv[1])
right = int(sys.argv[2])
offset = 100000
if left % offset != right % offset:
    raise SystemExit(1)
print(left % offset)
PY
}

section "matrix_contract"
kv "matrix" "SAKAMOTO-56-vpn-multi-user-identity"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "package" "$PACKAGE"
kv "temporaryManagedProfile" "claimed"
kv "fullAndroidUidSubject" "claimed"

section "product_catalog_multi_user_probe"
PACKAGE="$PACKAGE" bash "$CATALOG_EVIDENCE" --refresh-projection --create-test-profile \
  >"${RESULT_DIR}/product-catalog-device-evidence.log"
cat "${RESULT_DIR}/product-catalog-device-evidence.log"

grep -Fxq 'test_profile.create=PASS' "${RESULT_DIR}/product-catalog-device-evidence.log"
grep -Fxq 'test_profile.cleanup=REMOVED' "${RESULT_DIR}/product-catalog-device-evidence.log"
grep -Fxq 'multi_user_identity=PASS' "${RESULT_DIR}/product-catalog-device-evidence.log"

primary_uid="$(value_for "package_uid.user_0.target" "${RESULT_DIR}/product-catalog-device-evidence.log")"
profile_uid="$(awk -F= -v package="$PACKAGE" '
  $1 ~ /^package_uid\.user_[0-9]+\.target$/ && $1 != "package_uid.user_0.target" {
    print $2
    exit
  }
' "${RESULT_DIR}/product-catalog-device-evidence.log")"

[[ "$primary_uid" =~ ^[0-9]+$ ]]
[[ "$profile_uid" =~ ^[0-9]+$ ]]
[[ "$primary_uid" != "$profile_uid" ]]
app_id="$(same_app_id "$primary_uid" "$profile_uid")"

kv "package_uid.user_0.target" "$primary_uid"
kv "package_uid.profile.target" "$profile_uid"
kv "package_uid.sameAppId" "$app_id"
kv "package_uid.distinctFullUid" "PASS"
kv "multi_user_identity" "PASS"
kv "matrix.s56MultiUserIdentityEvidence" "claimed"
