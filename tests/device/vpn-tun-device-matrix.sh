#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-69 first-slice VPN/TUN evidence matrix.
#
# This is a source-owned, auditable wrapper around already-proven VPN/TUN/HEV
# POC harnesses.  It intentionally does not claim product RuntimeService
# integration, shared production Gate/L4 parity, or S69 closure.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
poc_dir="${repo_root}/experiments/vpp-nfq-poc"

# Force every nested POC script through the repo-local Android wrapper.
export ADB="${repo_root}/dev/adb"

source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s69-vpn-tun-device-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

S69_BUILD_APK="${S69_BUILD_APK:-1}"
S69_INSTALL_APK="${S69_INSTALL_APK:-1}"
S69_SKIP_IPV6="${S69_SKIP_IPV6:-0}"
S69_IPV6_REQUIRED="${S69_IPV6_REQUIRED:-0}"
S69_IPV6_HOST="${S69_IPV6_HOST:-2606:4700:4700::1111}"
S69_DIRECT_OWNER_HOSTS="${S69_DIRECT_OWNER_HOSTS:-142.251.13.94 1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222 93.184.216.34 151.101.1.69 13.107.42.14}"
S69_UDP_HOST="${S69_UDP_HOST:-8.8.8.8}"
S69_UDP_PORT="${S69_UDP_PORT:-53}"
S69_UDP_COUNT="${S69_UDP_COUNT:-4}"
S69_LIFECYCLE_CYCLES="${S69_LIFECYCLE_CYCLES:-3}"
S69_VPP_STAGE_DIR="${S69_VPP_STAGE_DIR:-${poc_dir}/work/android-vpp-direct-owner-stage}"
S69_CLEANUP_ON_EXIT="${S69_CLEANUP_ON_EXIT:-1}"
S69_DID_START_DEVICE=0
MATRIX_RC=0

usage() {
  cat <<EOF
Usage: $0 [--serial <serial>] [--result-dir <dir>] [--skip-ipv6] [--require-ipv6]

Runs the bounded SAKAMOTO-69 VPN/TUN first-slice evidence matrix.

Required sections:
  - direct-owner/single-writer TUN/HEV path
  - IPv4 TCP owner gate / UID attribution
  - UDP owner resolver
  - VpnService.protect() anti-loop
  - short VPP/HEV restart-cleanup loop

Optional-by-availability section:
  - IPv6 TCP owner resolver. Emits UNAVAILABLE unless the target has a usable
    IPv6 route, unless --require-ipv6 or S69_IPV6_REQUIRED=1 is set.

Environment:
  PACKAGE, RESULT_DIR, RESULTS_ROOT, RUN_ID
  S69_BUILD_APK, S69_INSTALL_APK
  S69_DIRECT_OWNER_HOSTS, S69_UDP_HOST, S69_UDP_PORT, S69_UDP_COUNT
  S69_LIFECYCLE_CYCLES, S69_SKIP_IPV6, S69_IPV6_REQUIRED, S69_IPV6_HOST
  S69_VPP_STAGE_DIR
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    --result-dir)
      RESULT_DIR="$2"
      shift 2
      ;;
    --skip-ipv6)
      S69_SKIP_IPV6=1
      shift
      ;;
    --require-ipv6)
      S69_IPV6_REQUIRED=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$RESULT_DIR"

kv() {
  printf '%s=%s\n' "$1" "$2"
}

section() {
  printf '\n## %s\n' "$1"
}

mark_required_failure() {
  local name="$1"
  local rc="$2"
  kv "${name}.result" "FAIL"
  kv "${name}.requiredFailure" "true"
  kv "${name}.failureRc" "$rc"
  MATRIX_RC=1
}

cleanup() {
  if [[ "$S69_CLEANUP_ON_EXIT" != "1" || "$S69_DID_START_DEVICE" != "1" ]]; then
    return
  fi
  adb_cmd shell am start -n "${PACKAGE}/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

run_poc_section() {
  local name="$1"
  local required="$2"
  local script="$3"
  shift 3
  local section_dir="${RESULT_DIR}/${name}"
  local run_log="${section_dir}/run.log"
  mkdir -p "$section_dir"

  section "$name"
  kv "${name}.required" "$required"
  kv "${name}.POC_ONLY" "true"
  kv "${name}.script" "${script#${repo_root}/}"
  kv "${name}.rawLog" "${run_log#${repo_root}/}"
  kv "${name}.resultDir" "${section_dir#${repo_root}/}"

  S69_DID_START_DEVICE=1
  set +e
  (
    cd "$repo_root"
    env "$@" bash "$script"
  ) >"$run_log" 2>&1
  local rc=$?
  set -e

  kv "${name}.rc" "$rc"
  if [[ "$rc" == "0" ]]; then
    kv "${name}.result" "PASS"
    return 0
  fi
  if [[ "$required" == "true" ]]; then
    mark_required_failure "$name" "$rc"
  else
    kv "${name}.result" "UNAVAILABLE"
    kv "${name}.unavailableRc" "$rc"
  fi
  return 0
}

run_build_hev_if_requested() {
  if [[ "$S69_BUILD_APK" != "1" ]]; then
    return 0
  fi
  run_poc_section \
    "build_hev" \
    "true" \
    "${poc_dir}/scripts/android-build-hev.sh"
}

prepare_vpn_lite_apk_if_requested() {
  if [[ "$S69_BUILD_APK" != "1" ]]; then
    return 0
  fi
  local name="prepare_vpn_lite_apk"
  local section_dir="${RESULT_DIR}/${name}"
  local run_log="${section_dir}/run.log"
  local build_script="${poc_dir}/android/vpn-lite/scripts/build-debug-apk.sh"
  local output_dir="${poc_dir}/android/vpn-lite/build/outputs"
  local current_apk="${output_dir}/sakamoto-runtime-debug.apk"
  local legacy_apk="${output_dir}/snort-vpn-lite-debug.apk"
  mkdir -p "$section_dir"

  section "$name"
  kv "${name}.required" "true"
  kv "${name}.POC_ONLY" "true"
  kv "${name}.script" "${build_script#${repo_root}/}"
  kv "${name}.rawLog" "${run_log#${repo_root}/}"
  kv "${name}.vppStageDir" "${S69_VPP_STAGE_DIR#${repo_root}/}"
  kv "${name}.currentApk" "${current_apk#${repo_root}/}"
  kv "${name}.legacyInstallAlias" "${legacy_apk#${repo_root}/}"

  set +e
  (
    set -euo pipefail
    cd "$repo_root"
    VPP_STAGE_DIR="$S69_VPP_STAGE_DIR" bash "$build_script"
    [[ -f "$current_apk" ]]
    cp "$current_apk" "$legacy_apk"
    sha256sum "$current_apk" "$legacy_apk"
  ) >"$run_log" 2>&1
  local rc=$?
  set -e

  kv "${name}.rc" "$rc"
  if [[ "$rc" == "0" ]]; then
    kv "${name}.result" "PASS"
  else
    mark_required_failure "$name" "$rc"
  fi
}

ipv6_route_available() {
  if [[ "$S69_SKIP_IPV6" == "1" ]]; then
    kv "ipv6_owner_resolver.result" "UNAVAILABLE"
    kv "ipv6_owner_resolver.reason" "skipped_by_S69_SKIP_IPV6"
    return 1
  fi

  local route_output=""
  section "ipv6_owner_resolver_precheck"
  kv "ipv6_owner_resolver.routeCheck.command" "./dev/adb shell ip -6 route get ${S69_IPV6_HOST}"
  set +e
  route_output="$(adb_cmd shell ip -6 route get "$S69_IPV6_HOST" 2>&1 | tr -d '\r')"
  local route_rc=$?
  set -e
  kv "ipv6_owner_resolver.routeCheck.rc" "$route_rc"
  kv "ipv6_owner_resolver.routeCheck.output" "$route_output"

  if [[ "$route_rc" != "0" || "$route_output" == *"unreachable"* \
        || "$route_output" == *"Network is unreachable"* \
        || "$route_output" != *" dev "* ]]; then
    kv "ipv6_owner_resolver.result" "UNAVAILABLE"
    kv "ipv6_owner_resolver.reason" "no_usable_ipv6_route_to_${S69_IPV6_HOST}"
    return 1
  fi
  return 0
}

section "matrix_contract"
kv "matrix" "SAKAMOTO-69-vpn-tun-first-slice"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "package" "$PACKAGE"
kv "POC_ONLY" "true"
kv "PRODUCT_GAP.productRuntimeServiceVpnAdapter" "not_claimed"
kv "PRODUCT_GAP.sharedGateL4PolicyParity" "not_claimed"
kv "PRODUCT_GAP.rootVpnClosureParity" "not_claimed"
kv "PRODUCT_GAP.s69Done" "not_claimed"
kv "PRODUCT_GAP.reason" "this matrix consolidates POC evidence only; production adapter/shared policy parity remains separate work"

run_build_hev_if_requested
prepare_vpn_lite_apk_if_requested

run_poc_section \
  "direct_owner_single_writer" \
  "true" \
  "${poc_dir}/scripts/android-run-vpp-direct-owner-poc.sh" \
  MODE="vpp-hev-direct-owner-single-writer" \
  HOSTS="$S69_DIRECT_OWNER_HOSTS" \
  UDP_HOST="$S69_UDP_HOST" \
  UDP_PORT="$S69_UDP_PORT" \
  UDP_COUNT="$S69_UDP_COUNT" \
  BUILD_APK="0" \
  INSTALL_APK="$S69_INSTALL_APK" \
  RESULT_DIR="${RESULT_DIR}/direct_owner_single_writer/upstream"

run_poc_section \
  "ipv4_tcp_owner_gate" \
  "true" \
  "${poc_dir}/scripts/android-run-vpn-owner-gate-poc.sh" \
  IP_FAMILY="inet4" \
  BUILD_APK="0" \
  INSTALL_APK="0" \
  LOG_DIR="${RESULT_DIR}/ipv4_tcp_owner_gate/upstream"

if ipv6_route_available; then
  run_poc_section \
    "ipv6_owner_resolver" \
    "$([[ "$S69_IPV6_REQUIRED" == "1" ]] && printf true || printf false)" \
    "${poc_dir}/scripts/android-run-vpp-owner-resolver-poc.sh" \
    HOST="$S69_IPV6_HOST" \
    PORT="80" \
    ENABLE_IPV6="1" \
    EXPECT_DROP="0" \
    BUILD_APK="0" \
    INSTALL_APK="0" \
    LOG_DIR="${RESULT_DIR}/ipv6_owner_resolver/upstream"
elif [[ "$S69_IPV6_REQUIRED" == "1" ]]; then
  mark_required_failure "ipv6_owner_resolver" 77
fi

run_poc_section \
  "udp_owner_resolver" \
  "true" \
  "${poc_dir}/scripts/android-run-vpp-owner-resolver-udp-poc.sh" \
  HOST="$S69_UDP_HOST" \
  PORT="$S69_UDP_PORT" \
  UDP_COUNT="$S69_UDP_COUNT" \
  BLOCK_OWNER_UID="package" \
  EXPECT_DROP="1" \
  BUILD_APK="0" \
  INSTALL_APK="0" \
  LOG_DIR="${RESULT_DIR}/udp_owner_resolver/upstream"

run_poc_section \
  "protect_anti_loop" \
  "true" \
  "${poc_dir}/scripts/android-run-vpn-protect-poc.sh" \
  BUILD="0" \
  INSTALL="0" \
  RESULT_DIR="${RESULT_DIR}/protect_anti_loop/upstream"

run_poc_section \
  "restart_cleanup_no_residue" \
  "true" \
  "${poc_dir}/scripts/android-run-vpp-hev-50-cycle-poc.sh" \
  CYCLES="$S69_LIFECYCLE_CYCLES" \
  BUILD="0" \
  INSTALL="0" \
  RESULT_DIR="${RESULT_DIR}/restart_cleanup_no_residue/upstream"

section "matrix_result"
kv "matrix.resultDir" "${RESULT_DIR#${repo_root}/}"
kv "matrix.requiredFailure" "$([[ "$MATRIX_RC" == "0" ]] && printf false || printf true)"
kv "matrix.result" "$([[ "$MATRIX_RC" == "0" ]] && printf PASS || printf FAIL)"
kv "matrix.POC_ONLY" "true"
kv "matrix.PRODUCT_GAP.s69Done" "not_claimed"

exit "$MATRIX_RC"
