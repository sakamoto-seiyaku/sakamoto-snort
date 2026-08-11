#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-59 final signed APK evidence suite.
#
# This is the ordered evidence runner for the Android L4 Product Release gate.
# It does not approve the release. It requires caller-provided final release
# signing inputs, builds the final signed APK once, then reruns the product
# evidence matrices against the same final-release artifact.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"

RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s59-final-release-evidence-suite}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
FINAL_APK="${FINAL_APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-release.apk}"
FINAL_BUILD_SCRIPT="${FINAL_BUILD_SCRIPT:-app/android-runtime/scripts/build-final-release-apk.sh}"
FINAL_APK_SHA256=""
S59_FINAL_RUN_S55="${S59_FINAL_RUN_S55:-1}"
S59_FINAL_RUN_S58="${S59_FINAL_RUN_S58:-1}"
S59_FINAL_RUN_BUDGET="${S59_FINAL_RUN_BUDGET:-1}"
S59_FINAL_RUN_S71="${S59_FINAL_RUN_S71:-1}"
S59_FINAL_EVIDENCE_COMPLETE=1

mkdir -p "$RESULT_DIR"
if [[ "${S59_FINAL_EVIDENCE_LOGGING:-0}" != "1" ]]; then
  export S59_FINAL_EVIDENCE_LOGGING=1
  exec > >(tee "${RESULT_DIR}/matrix.log") 2>&1
fi

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

run_logged() {
  local name="$1"
  shift
  local log="${RESULT_DIR}/${name}.log"
  section "$name"
  kv "${name}.log" "${log#${repo_root}/}"
  kv "${name}.command" "$*"
  set +e
  (cd "$repo_root" && "$@") >"$log" 2>&1
  local rc=$?
  set -e
  kv "${name}.rc" "$rc"
  if [[ "$rc" == "0" ]]; then
    kv "${name}.result" "PASS"
    return
  fi
  kv "${name}.result" "FAIL"
  tail -120 "$log" >&2 || true
  exit "$rc"
}

run_matrix() {
  local name="$1"
  shift
  run_logged "$name" env "$@"
}

assert_log_has() {
  local name="$1"
  local pattern="$2"
  local log="${RESULT_DIR}/${name}.log"
  grep -Eq "$pattern" "$log" || {
    echo "S59 final release suite missing expected evidence in ${log#${repo_root}/}: $pattern" >&2
    exit 1
  }
}

assert_log_has_literal() {
  local name="$1"
  local text="$2"
  local log="${RESULT_DIR}/${name}.log"
  grep -Fxq "$text" "$log" || {
    echo "S59 final release suite missing expected evidence in ${log#${repo_root}/}: $text" >&2
    exit 1
  }
}

section "matrix_contract"
kv "matrix" "SAKAMOTO-59-final-release-evidence-suite"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "apkVariant" "final-release"
kv "releaseStatus" "final_signed_release_apk_evidence_required"
kv "s59Done" "not_claimed"
kv "requiredSigningInput.ANDROID_RUNTIME_RELEASE_SIGNING_KEYSTORE" "${ANDROID_RUNTIME_RELEASE_SIGNING_KEYSTORE:+set}"
kv "requiredSigningInput.ANDROID_RUNTIME_RELEASE_SIGNING_ALIAS" "${ANDROID_RUNTIME_RELEASE_SIGNING_ALIAS:+set}"
kv "requiredSigningInput.ANDROID_RUNTIME_RELEASE_STORE_PASS_FILE" "${ANDROID_RUNTIME_RELEASE_STORE_PASS_FILE:+set}"
kv "optionalSigningInput.ANDROID_RUNTIME_RELEASE_KEY_PASS_FILE" "${ANDROID_RUNTIME_RELEASE_KEY_PASS_FILE:+set}"

run_logged build_final_release_apk bash "$FINAL_BUILD_SCRIPT"
[[ -f "$FINAL_APK" ]] || {
  echo "missing final release APK after build: $FINAL_APK" >&2
  exit 1
}
FINAL_APK_SHA256="$(sha256sum "$FINAL_APK" | awk '{print $1}')"
kv "apk" "${FINAL_APK#${repo_root}/}"
kv "apk.sha256" "$FINAL_APK_SHA256"

section "device_contract"
source "${repo_root}/dev/dev-android-device-lib.sh"
require_adb_device
kv "device" "$(adb_target_desc)"

if [[ "$S59_FINAL_RUN_S55" == "1" ]]; then
  run_matrix s55_product_vpn_transport \
    S55_APK_VARIANT=final-release \
    S55_BUILD_APK=0 \
    APK="$FINAL_APK" \
    RESULT_DIR="${RESULT_DIR}/s55-product-vpn-transport" \
    bash tests/device/s55-product-vpn-transport-matrix.sh
  assert_log_has s55_product_vpn_transport '^apkVariant=final-release$'
  assert_log_has_literal s55_product_vpn_transport "apk.sha256=$FINAL_APK_SHA256"
  assert_log_has s55_product_vpn_transport '^matrix[.]result=PASS$'
  assert_log_has s55_product_vpn_transport '^matrix[.]s55TransportEvidence=claimed$'
else
  kv "s55ProductVpnTransport.result" "SKIPPED"
  S59_FINAL_EVIDENCE_COMPLETE=0
fi

if [[ "$S59_FINAL_RUN_S58" == "1" ]]; then
  run_matrix s58_vpn_l4_product_workflow \
    S58_APK_VARIANT=final-release \
    S58_BUILD_APK=0 \
    APK="$FINAL_APK" \
    RESULT_DIR="${RESULT_DIR}/s58-vpn-l4-product-workflow" \
    bash tests/device/s58-vpn-l4-product-workflow-matrix.sh
  assert_log_has s58_vpn_l4_product_workflow '^apkVariant=final-release$'
  assert_log_has_literal s58_vpn_l4_product_workflow "apk.sha256=$FINAL_APK_SHA256"
  assert_log_has s58_vpn_l4_product_workflow '^matrix[.]result=PASS$'
  assert_log_has s58_vpn_l4_product_workflow '^matrix[.]s58VpnProductWorkflowEvidence=claimed$'
else
  kv "s58VpnL4ProductWorkflow.result" "SKIPPED"
  S59_FINAL_EVIDENCE_COMPLETE=0
fi

if [[ "$S59_FINAL_RUN_BUDGET" == "1" ]]; then
  run_matrix s59_release_budget_probe \
    S59_APK_VARIANT=final-release \
    S59_BUILD_APK=0 \
    APK="$FINAL_APK" \
    RESULT_DIR="${RESULT_DIR}/s59-release-budget-probe" \
    bash tests/device/s59-release-budget-probe.sh
  assert_log_has s59_release_budget_probe '^apkVariant=final-release$'
  assert_log_has_literal s59_release_budget_probe "apk.sha256=$FINAL_APK_SHA256"
  assert_log_has s59_release_budget_probe '^releaseStatus=final_signed_release_apk_evidence$'
  assert_log_has s59_release_budget_probe '^matrix[.]result=PASS$'
  assert_log_has s59_release_budget_probe '^matrix[.]s59ReleaseBudgetProbe=claimed_final_signed_release_budget$'
else
  kv "s59ReleaseBudgetProbe.result" "SKIPPED"
  S59_FINAL_EVIDENCE_COMPLETE=0
fi

if [[ "$S59_FINAL_RUN_S71" == "1" ]]; then
  run_matrix s71_dual_profile_closure_gate \
    S71_APK_VARIANT=final-release \
    ANDROID_RUNTIME_APK_VARIANT=final-release \
    S71_RUN_HOST=1 \
    S71_RUN_ROOT=1 \
    S71_RUN_VPN=1 \
    S71_RUN_LIFECYCLE=1 \
    S69_PRODUCT_BUILD_APK=0 \
    S70_BUILD_APK=0 \
    S71_EXPECTED_APK_SHA256="$FINAL_APK_SHA256" \
    APK="$FINAL_APK" \
    RESULT_DIR="${RESULT_DIR}/s71-dual-profile-closure-gate" \
    bash tests/device/s71-dual-profile-closure-gate.sh
  assert_log_has s71_dual_profile_closure_gate '^apkVariant=final-release$'
  assert_log_has_literal s71_dual_profile_closure_gate "apk.sha256=$FINAL_APK_SHA256"
  assert_log_has s71_dual_profile_closure_gate '^host_runtime_contract[.]result=PASS$'
  assert_log_has s71_dual_profile_closure_gate '^root[.]gate=PASS$'
  assert_log_has s71_dual_profile_closure_gate '^vpn[.]gate=PASS$'
  assert_log_has s71_dual_profile_closure_gate '^lifecycle[.]gate=PASS$'
  assert_log_has s71_dual_profile_closure_gate '^matrix[.]result=PASS$'
  assert_log_has s71_dual_profile_closure_gate '^matrix[.]s71Done=not_claimed$'
else
  kv "s71DualProfileClosureGate.result" "SKIPPED"
  S59_FINAL_EVIDENCE_COMPLETE=0
fi

section "matrix_result"
kv "matrix.result" "PASS"
if [[ "$S59_FINAL_EVIDENCE_COMPLETE" == "1" ]]; then
  kv "matrix.s59FinalReleaseEvidence" "claimed_final_signed_release_apk_evidence"
else
  kv "matrix.s59FinalReleaseEvidence" "partial_final_signed_release_apk_evidence"
fi
kv "s59Done" "not_claimed"
