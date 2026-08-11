#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-71 dual-profile closure gate.
#
# Aggregates the source-owned Root, product VPN, lifecycle, and host/VPP graph
# gates that together close the first Android Root+VPN minimal L4 slice.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s71-dual-profile-closure-gate}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
VNEXT_PORT="${VNEXT_PORT:-60607}"
SNORT_CTL="${SNORT_CTL:-${repo_root}/build-output/cmake/dev-debug/tests/host/sucre-snort-ctl}"
PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
S71_RUN_HOST="${S71_RUN_HOST:-1}"
S71_RUN_ROOT="${S71_RUN_ROOT:-1}"
S71_RUN_VPN="${S71_RUN_VPN:-1}"
S71_RUN_LIFECYCLE="${S71_RUN_LIFECYCLE:-1}"

mkdir -p "$RESULT_DIR"

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
  else
    kv "${name}.result" "FAIL"
    tail -120 "$log" >&2 || true
    exit "$rc"
  fi
}

assert_log_has() {
  local name="$1"
  local pattern="$2"
  local log="${RESULT_DIR}/${name}.log"
  grep -Eq "$pattern" "$log" || {
    echo "S71 missing expected evidence in ${log#${repo_root}/}: $pattern" >&2
    exit 1
  }
}

assert_log_lacks_result_failures() {
  local name="$1"
  local log="${RESULT_DIR}/${name}.log"
  if grep -Eq '(^|[[:space:]])[A-Za-z0-9_.-]+[.]result=(FAIL|BLOCKED|INVALID)($|[[:space:]])' "$log"; then
    echo "S71 observed failing result marker in ${log#${repo_root}/}" >&2
    grep -En '(^|[[:space:]])[A-Za-z0-9_.-]+[.]result=(FAIL|BLOCKED|INVALID)($|[[:space:]])' "$log" >&2 || true
    exit 1
  fi
}

assert_root_gate() {
  local name="root_nfqueue_matrix"
  assert_log_has "$name" '^ipv6_output[.]result=PASS$'
  assert_log_has "$name" '^input_ipv4[.]result=UID_UNAVAILABLE$'
  assert_log_has "$name" '^input_ipv4_unknown[.]result=PASS$'
  assert_log_has "$name" '^control_socket_timeout[.]result=PASS$'
  assert_log_has "$name" '^restart[.]helloResult=PASS$'
  assert_log_has "$name" '^restart[.]finalCleanup[.]result=PASS$'
  assert_log_has "$name" '^sigkill_fault[.]recovery[.]result=PASS$'
  assert_log_has "$name" '^sigkill_fault[.]finalCleanup[.]result=PASS$'
  assert_log_has "$name" '^final[.]noResidue[.]result=PASS$'
  assert_log_lacks_result_failures "$name"
  kv "root.gate" "PASS"
  kv "root.inputUidSeam" "UID_UNAVAILABLE_WITH_UNKNOWN_APPLICATION_PASS"
}

assert_vpn_gate() {
  local name="product_vpn_matrix"
  assert_log_has "$name" '^productRuntimeServiceVpnAdapter=claimed$'
  assert_log_has "$name" '^POC_ONLY=false$'
  assert_log_has "$name" '^start[.]result=PASS$'
  assert_log_has "$name" '^connectivity[.]vpnNetwork=PASS$'
  assert_log_has "$name" '^runtimeLog[.]vpnStartup=PASS$'
  assert_log_has "$name" '^control[.]VPN_TUN[.]STATUS=PASS$'
  assert_log_has "$name" '^control[.]POLICY[.]STATUS=PASS$'
  assert_log_has "$name" '^protect[.]result=PASS$'
  assert_log_has "$name" '^cleanup[.]result=PASS$'
  assert_log_has "$name" '^restart[.]result=PASS$'
  assert_log_has "$name" '^matrix[.]result=PASS$'
  assert_log_lacks_result_failures "$name"
  kv "vpn.gate" "PASS"
}

assert_lifecycle_gate() {
  local name="profile_lifecycle_matrix"
  assert_log_has "$name" '^productState[.]binding=PASS$'
  assert_log_has "$name" '^productState[.]policyBundleBaseline=RECORDED$'
  assert_log_has "$name" '^switch[.]rootToVpn=PASS$'
  assert_log_has "$name" '^activity[.]recreateKeepsRuntime=PASS$'
  assert_log_has "$name" '^appProcessDeath[.]result=PASS$'
  assert_log_has "$name" '^switch[.]vpnToRoot=PASS$'
  assert_log_has "$name" '^pause[.]bindingPreserved=PASS$'
  assert_log_has "$name" '^pause[.]policyPreserved=PASS$'
  assert_log_has "$name" '^pause[.]lastSuccessfulPolicyPreserved=PASS$'
  assert_log_has "$name" '^cleanupFault[.]result=PASS$'
  assert_log_has "$name" '^crash[.]result=PASS$'
  assert_log_has "$name" '^restartAfterCrash[.]result=PASS$'
  assert_log_has "$name" '^doze[.]result=PASS$'
  assert_log_has "$name" '^finalCleanup[.]result=PASS$'
  assert_log_has "$name" '^matrix[.]result=PASS$'
  assert_log_lacks_result_failures "$name"
  kv "lifecycle.gate" "PASS"
}

section "matrix_contract"
require_adb_device
kv "matrix" "SAKAMOTO-71-dual-profile-closure-gate"
kv "resultDir" "${RESULT_DIR#${repo_root}/}"
kv "adbWrapper" "./dev/adb"
kv "device" "$(adb_target_desc)"
kv "s71Done" "not_claimed"

if [[ "$S71_RUN_HOST" == "1" ]]; then
  run_logged host_runtime_contract bash tests/android/runtime-contract-test.sh
  run_logged host_vpp_graph_and_conformance cmake --build --preset dev-debug --target snort-host-tests
  run_logged root_daemon_build cmake --build --preset dev-debug --target snort-build-ndk
else
  kv "host.gate" "SKIPPED"
fi

if [[ "$S71_RUN_ROOT" == "1" ]]; then
  run_logged root_daemon_deploy env "CONTROL_FORWARD_PORT=${VNEXT_PORT}" bash dev/dev-deploy.sh --no-clear-log
  run_logged product_app_force_stop "$repo_root/dev/adb" shell am force-stop "$PACKAGE"
  run_logged root_nfqueue_matrix bash tests/device/root-nfqueue-device-matrix.sh --ctl "$SNORT_CTL"
  assert_root_gate
else
  kv "root.gate" "SKIPPED"
fi

if [[ "$S71_RUN_VPN" == "1" ]]; then
  run_logged product_vpn_matrix bash tests/device/s69-product-vpn-runtime-matrix.sh
  assert_vpn_gate
else
  kv "vpn.gate" "SKIPPED"
fi

if [[ "$S71_RUN_LIFECYCLE" == "1" ]]; then
  run_logged profile_lifecycle_matrix bash tests/device/s70-profile-lifecycle-matrix.sh
  assert_lifecycle_gate
else
  kv "lifecycle.gate" "SKIPPED"
fi

section "scope_deferral"
kv "deferred.completeAppCatalog" "true"
kv "deferred.completeProductUi" "true"
kv "deferred.checkpointImportExport" "true"
kv "deferred.linux" "true"
kv "deferred.protocolIdentification" "true"

section "matrix_result"
kv "matrix.result" "PASS"
kv "matrix.s71Done" "not_claimed"
