#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-61 provider-neutral Android device evidence.
#
# This is deliberately a disabled-provider slice. It proves that the
# production Root/NFQUEUE and VPN/TUN profiles expose the same bounded LPI
# status and account payload-bearing packets as provider-unavailable, without
# claiming a real provider, corpus replay, or ProtocolRule enforcement.

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

# All Android operations in this matrix go through the repository wrapper.
export ADB="${repo_root}/dev/adb"
source "${repo_root}/dev/dev-android-device-lib.sh"

PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s61-disabled-lpi-provider-matrix}"
RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
S61_APK_VARIANT="${S61_APK_VARIANT:-${ANDROID_RUNTIME_APK_VARIANT:-debug}}"
case "$S61_APK_VARIANT" in
  debug)
    APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-debug.apk}"
    S61_BUILD_SCRIPT="${S61_BUILD_SCRIPT:-app/android-runtime/scripts/build-debug-apk.sh}"
    ;;
  release-candidate)
    APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-release-candidate.apk}"
    S61_BUILD_SCRIPT="${S61_BUILD_SCRIPT:-app/android-runtime/scripts/build-release-candidate-apk.sh}"
    ;;
  final-release)
    APK="${APK:-${repo_root}/app/android-runtime/build/outputs/sakamoto-runtime-release.apk}"
    S61_BUILD_SCRIPT="${S61_BUILD_SCRIPT:-app/android-runtime/scripts/build-final-release-apk.sh}"
    ;;
  *)
    echo "FAIL: unsupported S61_APK_VARIANT: $S61_APK_VARIANT" >&2
    exit 1
    ;;
esac

S61_BUILD_APK="${S61_BUILD_APK:-1}"
S61_INSTALL_APK="${S61_INSTALL_APK:-1}"
S61_FORWARD_PORT="${S61_FORWARD_PORT:-60621}"
S61_DOWNLOAD_URL="${S61_DOWNLOAD_URL:-https://speed.cloudflare.com/__down?bytes=500000}"
S61_DOWNLOAD_TIMEOUT_MILLIS="${S61_DOWNLOAD_TIMEOUT_MILLIS:-20000}"
S61_DOWNLOAD_MAX_BYTES="${S61_DOWNLOAD_MAX_BYTES:-500000}"
S61_PROFILE_SET="${S61_PROFILE_SET:-root,vpn}"
S61_CLEANUP_ON_EXIT="${S61_CLEANUP_ON_EXIT:-1}"
S61_SKIP_DEVICE="${S61_SKIP_DEVICE:-0}"
S61_DOWNLOAD_RESULT_PATH="files/debug/download-probe.properties"
STATE_PATH="files/runtime-state/snapshot.properties"
SNORT_CTL="${SNORT_CTL:-}"
CURRENT_PROFILE=""
S61_TRANSPORT_WARNING=0

mkdir -p "$RESULT_DIR"

section() {
  printf '\n## %s\n' "$1"
}

kv() {
  printf '%s=%s\n' "$1" "$2"
}

usage() {
  cat <<EOF
Usage: $0 [--serial <serial>] [--ctl <path>] [--profile root|vpn]
          [--skip-build] [--skip-install] [--skip-device] [--result-dir <path>]

Runs the SAKAMOTO-61 disabled LPI provider device evidence slice for Root/NFQUEUE
and VPN/TUN. A production APK debugDownload produces a payload-bearing HTTP/TCP
flow; each profile must report payloadEligiblePackets == providerUnavailablePackets
with all provider submission/fact/terminal/context/slot counters unchanged.

Exit semantics:
  0  PASS or intentional SKIP
  1  FAIL: available runtime evidence contradicts the contract
  77 BLOCKED: device/root/tool/network/permission prerequisite unavailable
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      [[ $# -ge 2 ]] || { echo "FAIL: --serial needs a value" >&2; exit 1; }
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    --ctl)
      [[ $# -ge 2 ]] || { echo "FAIL: --ctl needs a value" >&2; exit 1; }
      SNORT_CTL="$2"
      shift 2
      ;;
    --profile)
      [[ $# -ge 2 ]] || { echo "FAIL: --profile needs a value" >&2; exit 1; }
      S61_PROFILE_SET="$2"
      shift 2
      ;;
    --skip-build)
      S61_BUILD_APK=0
      shift
      ;;
    --skip-install)
      S61_INSTALL_APK=0
      shift
      ;;
    --skip-device)
      S61_SKIP_DEVICE=1
      shift
      ;;
    --result-dir)
      [[ $# -ge 2 ]] || { echo "FAIL: --result-dir needs a value" >&2; exit 1; }
      RESULT_DIR="$2"
      mkdir -p "$RESULT_DIR"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "FAIL: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

write_boundary_properties() {
  local result="$1"
  local status="$2"
  {
    printf 'suite=s61-disabled-lpi-provider-device\n'
    printf 'status=%s\n' "$status"
    printf 'evidence=provider-neutral-device-runtime\n'
    printf 'source=android-installed-apk-debugDownload\n'
    printf 'corpus=not_used\n'
    printf 'provider=disabled\n'
    printf 'providerSource=none\n'
    printf 'providerAvailability=disabled\n'
    printf 'realProviderEnabled=not_claimed\n'
    printf 'ProtocolRule=out_of_scope\n'
    printf 'protocolRule=out_of_scope\n'
    printf 'protocolRuleEnforcement=not_claimed\n'
    printf 'payloadBoundary=transport-payload-only\n'
    printf 'referenceSource=not_used\n'
    printf 'referenceCorpus=not_used\n'
    printf 'sourceImported=not_claimed\n'
    printf 'corpusImported=not_claimed\n'
  } >"$result"
}

write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "NOT_RUN"

cleanup() {
  if [[ "${S61_CLEANUP_ON_EXIT}" != "1" ]]; then
    return 0
  fi
  if [[ -n "$CURRENT_PROFILE" ]]; then
    stop_profile "$CURRENT_PROFILE" >/dev/null 2>&1 || true
  fi
  remove_control_vnext_forward "$S61_FORWARD_PORT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

find_snort_ctl() {
  if [[ -n "$SNORT_CTL" ]]; then
    [[ -x "$SNORT_CTL" ]] || {
      echo "BLOCKED: SNORT_CTL is not executable: $SNORT_CTL" >&2
      return 77
    }
    printf '%s\n' "$SNORT_CTL"
    return 0
  fi
  local candidate
  local candidates=(
    "$repo_root/build-output/cmake/dev-debug/tests/host/sucre-snort-ctl"
    "$repo_root/build-output/cmake/dev-relwithdebinfo/tests/host/sucre-snort-ctl"
    "$repo_root/build-output/cmake/host-asan-clang/tests/host/sucre-snort-ctl"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "BLOCKED: missing sucre-snort-ctl; build dev-debug target or pass --ctl" >&2
  return 77
}

ctl() {
  local command="$1"
  local args="${2:-}"
  if [[ -n "$args" ]]; then
    "$SNORT_CTL" --tcp "127.0.0.1:${S61_FORWARD_PORT}" --compact "$command" "$args"
  else
    "$SNORT_CTL" --tcp "127.0.0.1:${S61_FORWARD_PORT}" --compact "$command"
  fi
}

app_file_path() {
  printf '/data/user/0/%s/%s\n' "$PACKAGE" "$1"
}

app_file_cat() {
  local relative_path="$1"
  adb_cmd shell run-as "$PACKAGE" cat "$relative_path" 2>/dev/null \
    || adb_su "cat $(shell_single_quote "$(app_file_path "$relative_path")") 2>/dev/null" \
    || true
}

app_file_rm() {
  local relative_path="$1"
  adb_cmd shell run-as "$PACKAGE" rm -f "$relative_path" >/dev/null 2>&1 \
    || adb_su "rm -f $(shell_single_quote "$(app_file_path "$relative_path")")" \
      >/dev/null 2>&1 \
    || true
}

read_snapshot() {
  app_file_cat "$STATE_PATH" | tr -d '\r' || true
}

snapshot_value() {
  local key="$1"
  local snapshot="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); found=1 }
    END { if (!found) exit 1 }' <<<"$snapshot"
}

wait_for_snapshot_field() {
  local key="$1"
  local expected="$2"
  local out_file="$3"
  local attempts="${4:-45}"
  local snapshot=""
  for _ in $(seq 1 "$attempts"); do
    snapshot="$(read_snapshot)"
    printf '%s\n' "$snapshot" >"$out_file"
    if grep -Fxq "${key}=${expected}" <<<"$snapshot"; then
      printf '%s\n' "$snapshot"
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_download_result() {
  local out_file="$1"
  local attempts="${2:-35}"
  local result=""
  for _ in $(seq 1 "$attempts"); do
    result="$(app_file_cat "$S61_DOWNLOAD_RESULT_PATH" | tr -d '\r' || true)"
    printf '%s\n' "$result" >"$out_file"
    if grep -Eq '^result=(download_succeeded|download_failed)$' <<<"$result"; then
      printf '%s\n' "$result"
      return 0
    fi
    sleep 1
  done
  return 1
}

json_ok() {
  python3 -c 'import json,sys
try:
    sys.exit(0 if json.load(sys.stdin).get("ok") is True else 1)
except Exception:
    sys.exit(1)'
}

verify_status_contract() {
  local profile="$1"
  local status_command="$2"
  local before_file="$3"
  local after_file="$4"
  local delta_file="$5"
  python3 - "$profile" "$status_command" "$before_file" "$after_file" "$delta_file" <<'PY'
import json
import sys

profile, command, before_path, after_path, delta_path = sys.argv[1:]
with open(before_path, encoding="utf-8") as handle:
    before = json.load(handle)
with open(after_path, encoding="utf-8") as handle:
    after = json.load(handle)
if before.get("ok") is not True or after.get("ok") is not True:
    print("status.result=FAIL")
    print("status.reason=control_status_not_ok")
    sys.exit(1)

def provider(doc):
    return doc["result"]["lpiProvider"]

expected = {
    "available": False,
    "name": "disabled",
    "payloadBudgetPackets": 20,
    "mappedResultCapacity": 8,
}
errors = []
for label, doc in (("before", before), ("after", after)):
    current = provider(doc)
    for key, value in expected.items():
        if current.get(key) != value:
            errors.append(f"{label}.{key}={current.get(key)!r},expected={value!r}")

counter_keys = [
    "packetsObserved",
    "payloadEligiblePackets",
    "terminalSkippedPackets",
    "providerUnavailablePackets",
    "flowSlotUnavailablePackets",
    "providerContextUnavailablePackets",
    "packetsSubmittedToProvider",
    "providerNoResultPackets",
    "providerFactPackets",
    "detectorDonePackets",
    "budgetExhaustedPackets",
]
before_provider = provider(before)
after_provider = provider(after)
delta = {
    key: int(after_provider.get(key, 0)) - int(before_provider.get(key, 0))
    for key in counter_keys
}
for key, value in delta.items():
    print(f"status.delta.{key}={value}")
print(f"status.profile={profile}")
print(f"status.command={command}")
print(f"status.payloadBudgetPackets={after_provider.get('payloadBudgetPackets')}")
print(f"status.mappedResultCapacity={after_provider.get('mappedResultCapacity')}")

if delta["payloadEligiblePackets"] <= 0:
    errors.append("payloadEligiblePackets must increase")
if delta["providerUnavailablePackets"] <= 0:
    errors.append("providerUnavailablePackets must increase")
if delta["payloadEligiblePackets"] != delta["providerUnavailablePackets"]:
    errors.append("payloadEligiblePackets/providerUnavailablePackets delta mismatch")
if delta["packetsObserved"] < delta["payloadEligiblePackets"]:
    errors.append("packetsObserved delta smaller than payloadEligiblePackets")
for key in [
    "terminalSkippedPackets",
    "flowSlotUnavailablePackets",
    "providerContextUnavailablePackets",
    "packetsSubmittedToProvider",
    "providerNoResultPackets",
    "providerFactPackets",
    "detectorDonePackets",
    "budgetExhaustedPackets",
]:
    if delta[key] != 0:
        errors.append(f"{key} delta must be zero, got {delta[key]}")

lines = []
if errors:
    print("providerContract=FAIL")
    print("status.result=FAIL")
    lines.append("providerContract=FAIL")
    lines.append("status.result=FAIL")
    for error in errors:
        print(f"status.error={error}")
        lines.append(f"status.error={error}")
else:
    print("providerContract=PASS")
    print("status.result=PASS")
    lines.append("providerContract=PASS")
    lines.append("status.result=PASS")
lines.extend(f"status.delta.{key}={value}" for key, value in delta.items())
lines.extend([f"status.profile={profile}", f"status.command={command}"])
with open(delta_path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
if errors:
    sys.exit(1)
PY
}

download_value() {
  local result_file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); found=1 }
    END { if (!found) exit 1 }' "$result_file"
}

assert_download_success() {
  local profile="$1"
  local result_file="$2"
  local result bytes url
  result="$(download_value "$result_file" result || true)"
  bytes="$(download_value "$result_file" bytes || true)"
  url="$(download_value "$result_file" url || true)"
  kv "$profile.download.result" "$result"
  kv "$profile.download.bytes" "$bytes"
  kv "$profile.download.url" "$url"
  if [[ "$result" == "download_failed" ]]; then
    # A failed HTTPS probe is a transport outcome only. The caller must still
    # collect status-after and evaluate the provider contract independently.
    kv "$profile.downloadOutcome" "FAIL"
    kv "$profile.transportStatus" "BLOCKED"
    kv "$profile.transportOutcome" "BLOCKED"
    kv "$profile.download.status" "BLOCKED"
    kv "$profile.download.reason" "external HTTP endpoint unavailable"
    return 77
  fi
  if [[ "$result" != "download_succeeded" || ! "$bytes" =~ ^[1-9][0-9]*$ ]]; then
    kv "$profile.downloadOutcome" "BLOCKED"
    kv "$profile.transportStatus" "BLOCKED"
    kv "$profile.transportOutcome" "BLOCKED"
    kv "$profile.download.status" "BLOCKED"
    kv "$profile.download.reason" "debugDownload did not produce a positive payload byte count"
    return 77
  fi
  kv "$profile.downloadOutcome" "PASS"
  kv "$profile.transportStatus" "PASS"
  kv "$profile.transportOutcome" "PASS"
  kv "$profile.download.status" "PASS"
  return 0
}

daemon_pids() {
  adb_su "pidof sucre-snortd libsucre_snortd.so sucre-snort-ndk 2>/dev/null || true" \
    | tr -d '\r'
}

assert_no_profile_residue() {
  local profile="$1"
  local profile_dir="$2"
  local pids hooks ip6hooks tun connectivity
  pids="$(daemon_pids || true)"
  hooks="$(adb_su "iptables -S 2>/dev/null | grep sucre-snort || true" | tr -d '\r')"
  ip6hooks="$(adb_su "ip6tables -S 2>/dev/null | grep sucre-snort || true" | tr -d '\r')"
  tun="$(adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r')"
  connectivity="$(adb_cmd shell dumpsys connectivity 2>/dev/null | tr -d '\r' || true)"
  {
    printf 'processCheck.command=./dev/adb shell su 0 sh -c pidof_sucre_snort\n'
    printf 'iptablesCheck.command=./dev/adb shell su 0 sh -c iptables_S_grep_sucre_snort\n'
    printf 'ip6tablesCheck.command=./dev/adb shell su 0 sh -c ip6tables_S_grep_sucre_snort\n'
    printf 'tunCheck.command=./dev/adb shell su 0 ip_link_show_tun0\n'
    printf 'connectivityCheck.command=./dev/adb shell dumpsys connectivity\n'
    printf 'processResidue=%s\n' "$pids"
    printf 'iptablesResidue=%s\n' "$hooks"
    printf 'ip6tablesResidue=%s\n' "$ip6hooks"
    printf 'tun0Residue=%s\n' "$tun"
    if [[ "$connectivity" == *"VPN:${PACKAGE}"* || "$connectivity" == *"InterfaceName: tun0"* ]]; then
      printf 'connectivityResidue=VPN_or_tun0_present\n'
    else
      printf 'connectivityResidue=\n'
    fi
  } >"${profile_dir}/residue.properties"

  if [[ -z "$pids" && -z "$hooks" && -z "$ip6hooks" \
    && "$tun" != *"tun0:"* && "$tun" != *"tun0@"* \
    && "$connectivity" != *"VPN:${PACKAGE}"* \
    && "$connectivity" != *"InterfaceName: tun0"* ]]; then
    kv "$profile.cleanup.residue" "PASS"
    return 0
  fi
  kv "$profile.cleanup.residue" "FAIL"
  return 1
}

stop_profile() {
  local profile="$1"
  local profile_dir="$RESULT_DIR/$profile"
  mkdir -p "$profile_dir"
  adb_cmd shell am start -n "$ACTIVITY" --ez runtimeStop true \
    >"${profile_dir}/runtime-stop.intent.log" 2>&1 || true
  if ! wait_for_snapshot_field state stopped \
      "${profile_dir}/runtime-snapshot.stopped" 30; then
    kv "$profile.cleanup.runtime" "FAIL"
    return 1
  fi
  kv "$profile.cleanup.runtime" "PASS"
  app_file_rm "$S61_DOWNLOAD_RESULT_PATH"
  remove_control_vnext_forward "$S61_FORWARD_PORT" >/dev/null 2>&1 || true
  assert_no_profile_residue "$profile" "$profile_dir"
}

start_profile() {
  local profile="$1"
  local adapter="$2"
  local profile_dir="$RESULT_DIR/$profile"
  mkdir -p "$profile_dir"
  CURRENT_PROFILE="$profile"
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez runtimeStart true --es runtimeProfile "$profile" \
    >"${profile_dir}/runtime-start.intent.log" 2>&1 || true
  local snapshot=""
  if ! snapshot="$(wait_for_snapshot_field state running \
      "${profile_dir}/runtime-snapshot.running" 45)"; then
    local failed_snapshot
    failed_snapshot="$(cat "${profile_dir}/runtime-snapshot.running" 2>/dev/null || true)"
    local error_code
    error_code="$(snapshot_value errorCode "$failed_snapshot" 2>/dev/null || true)"
    if [[ "$error_code" == "notification_permission_required" \
      || "$error_code" == "root_authorization_required" \
      || "$error_code" == "vpn_permission_required" \
      || "$error_code" == "vpn_prepare_required" ]]; then
      kv "$profile.start.result" "BLOCKED"
      kv "$profile.start.reason" "runtime permission or root authorization unavailable: ${error_code:-unknown}"
      return 77
    fi
    kv "$profile.start.result" "FAIL"
    kv "$profile.start.reason" "runtime did not reach running state"
    return 1
  fi
  printf '%s\n' "$snapshot" >"${profile_dir}/runtime-snapshot.running"
  local actual_profile actual_health actual_adapter
  actual_profile="$(snapshot_value profile "$snapshot")"
  actual_health="$(snapshot_value coreHealth "$snapshot")"
  actual_adapter="$(snapshot_value adapterReadiness "$snapshot")"
  kv "$profile.snapshot.profile" "$actual_profile"
  kv "$profile.snapshot.health" "$actual_health"
  kv "$profile.snapshot.adapterReadiness" "$actual_adapter"
  if [[ "$actual_profile" != "$profile" || "$actual_health" != "ok" \
    || "$actual_adapter" != "$adapter" ]]; then
    kv "$profile.start.result" "FAIL"
    kv "$profile.start.reason" "running snapshot did not prove expected profile/health/adapter"
    return 1
  fi
  kv "$profile.start.result" "PASS"
  return 0
}

run_profile() {
  local profile="$1"
  local status_command="$2"
  local adapter="$3"
  local profile_dir="$RESULT_DIR/$profile"
  mkdir -p "$profile_dir"

  section "${profile}_disabled_provider"
  kv "$profile.profile" "$profile"
  kv "$profile.statusCommand" "$status_command"
  kv "$profile.source" "android-installed-apk-debugDownload"
  kv "$profile.corpus" "not_used"
  kv "$profile.provider" "disabled"
  kv "$profile.ProtocolRule" "out_of_scope"
  if start_profile "$profile" "$adapter"; then
    :
  else
    local start_rc=$?
    return "$start_rc"
  fi

  if ! check_control_vnext_forward "$S61_FORWARD_PORT"; then
    setup_control_vnext_forward "$S61_FORWARD_PORT"
  fi
  local hello
  hello="$(ctl HELLO || true)"
  printf '%s\n' "$hello" >"${profile_dir}/hello.json"
  if ! printf '%s\n' "$hello" | json_ok; then
    kv "$profile.control.result" "BLOCKED"
    kv "$profile.control.reason" "HELLO failed through vNext forward"
    return 77
  fi
  kv "$profile.control.result" "PASS"

  app_file_rm "$S61_DOWNLOAD_RESULT_PATH"
  local before after
  before="$(ctl "$status_command" || true)"
  printf '%s\n' "$before" >"${profile_dir}/status-before.json"
  if ! printf '%s\n' "$before" | json_ok; then
    kv "$profile.status.before" "BLOCKED"
    kv "$profile.status.reason" "$status_command did not return ok"
    return 77
  fi
  kv "$profile.status.before" "PASS"

  kv "$profile.download.command" "./dev/adb shell am start -n $ACTIVITY --ez debugDownload true --es debugDownloadUrl $S61_DOWNLOAD_URL --ei debugDownloadTimeoutMillis $S61_DOWNLOAD_TIMEOUT_MILLIS --ei debugDownloadMaxBytes $S61_DOWNLOAD_MAX_BYTES"
  adb_cmd shell am start -n "$ACTIVITY" \
    --ez debugDownload true \
    --es debugDownloadUrl "$S61_DOWNLOAD_URL" \
    --ei debugDownloadTimeoutMillis "$S61_DOWNLOAD_TIMEOUT_MILLIS" \
    --ei debugDownloadMaxBytes "$S61_DOWNLOAD_MAX_BYTES" \
    >"${profile_dir}/download.intent.log" 2>&1 || true
  local download_rc=0
  if ! wait_for_download_result "${profile_dir}/download-probe.properties"; then
    # Keep the transport result separate from provider-neutral status. A
    # missing/failed download must not prevent status-after from being read.
    download_rc=77
    kv "$profile.downloadOutcome" "BLOCKED"
    kv "$profile.transportStatus" "BLOCKED"
    kv "$profile.transportOutcome" "BLOCKED"
    kv "$profile.download.status" "BLOCKED"
    kv "$profile.download.reason" "debugDownload did not publish a bounded result"
  else
    if assert_download_success "$profile" "${profile_dir}/download-probe.properties"; then
      :
    else
      download_rc=$?
    fi
  fi

  # Even download_failed (for example, HTTPS connection reset) must reach this
  # status-after query. The counter delta is the provider contract evidence;
  # the debugDownload result remains a distinct transport outcome.
  sleep 1
  after="$(ctl "$status_command" || true)"
  printf '%s\n' "$after" >"${profile_dir}/status-after.json"
  if ! printf '%s\n' "$after" | json_ok; then
    kv "$profile.providerContract" "BLOCKED"
    kv "$profile.status.after" "BLOCKED"
    kv "$profile.status.reason" "$status_command did not return ok after HTTP payload"
    return 77
  fi
  local provider_rc=0
  if verify_status_contract "$profile" "$status_command" \
      "${profile_dir}/status-before.json" "${profile_dir}/status-after.json" \
      "${profile_dir}/status-delta.properties"; then
    provider_rc=0
  else
    provider_rc=$?
  fi
  cat "${profile_dir}/status-delta.properties"

  local provider_contract profile_result
  if [[ "$provider_rc" -eq 0 ]]; then
    provider_contract="PASS"
    kv "$profile.providerContract" "PASS"
    kv "$profile.status.after" "PASS"
    if [[ "$download_rc" -eq 0 ]]; then
      profile_result="PASS"
      kv "$profile.result" "PASS"
    else
      # S59's TCP-connect fallback can provide separate transport evidence,
      # but it can never replace this payload-bearing provider contract.
      S61_TRANSPORT_WARNING=1
      profile_result="PASS_WITH_TRANSPORT_WARNING"
      kv "$profile.result" "$profile_result"
    fi
  else
    provider_contract="FAIL"
    kv "$profile.providerContract" "FAIL"
    kv "$profile.status.after" "FAIL"
    kv "$profile.status.result" "FAIL"
    profile_result="FAIL"
  fi
  local download_result download_outcome transport_status
  download_result="$(download_value "${profile_dir}/download-probe.properties" result 2>/dev/null || true)"
  if [[ "$download_rc" -eq 0 ]]; then
    download_outcome="PASS"
    transport_status="PASS"
  elif [[ "$download_result" == "download_failed" ]]; then
    download_outcome="FAIL"
    transport_status="BLOCKED"
  else
    download_outcome="BLOCKED"
    transport_status="BLOCKED"
  fi
  {
    printf 'profile=%s\n' "$profile"
    printf 'downloadOutcome=%s\n' "$download_outcome"
    printf 'transportStatus=%s\n' "$transport_status"
    printf 'transportOutcome=%s\n' "$transport_status"
    printf 'providerContract=%s\n' "$provider_contract"
    printf 'result=%s\n' "$profile_result"
  } >"${profile_dir}/contract.properties"
  if [[ "$provider_rc" -ne 0 ]]; then
    return 1
  fi
  return 0
}

section "preflight"
if [[ "$S61_SKIP_DEVICE" == "1" ]]; then
  write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "SKIP"
  kv "matrix.result" "SKIP"
  kv "matrix.reason" "intentional device skip requested"
  exit 0
fi

device_preflight || {
  write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "BLOCKED"
  kv "matrix.result" "BLOCKED"
  kv "matrix.reason" "device_preflight failed; one rooted Android target is required"
  exit 77
}
SNORT_CTL="$(find_snort_ctl)" || {
  write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "BLOCKED"
  kv "matrix.result" "BLOCKED"
  exit 77
}
export SNORT_CTL

if [[ "$S61_BUILD_APK" == "1" ]]; then
  kv "build.command" "bash $S61_BUILD_SCRIPT"
  if ! (cd "$repo_root" && bash "$S61_BUILD_SCRIPT") \
      >"$RESULT_DIR/build-apk.log" 2>&1; then
    write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "BLOCKED"
    kv "matrix.result" "BLOCKED"
    kv "matrix.reason" "APK build prerequisites or authorized build input unavailable"
    exit 77
  fi
  kv "build.result" "PASS"
fi
if [[ ! -f "$APK" ]]; then
  write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "BLOCKED"
  kv "matrix.result" "BLOCKED"
  kv "matrix.reason" "missing APK: $APK"
  exit 77
fi
if [[ "$S61_INSTALL_APK" == "1" ]]; then
  if ! adb_cmd install -r "$APK" >"$RESULT_DIR/install.log" 2>&1; then
    write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "BLOCKED"
    kv "matrix.result" "BLOCKED"
    kv "matrix.reason" "authorized APK install failed; no signing/install bypass attempted"
    exit 77
  fi
  kv "install.result" "PASS"
fi

fingerprint="$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r\n')"
abi="$(adb_cmd shell getprop ro.product.cpu.abilist | tr -d '\r\n')"
if [[ -z "$abi" ]]; then
  abi="$(adb_cmd shell getprop ro.product.cpu.abi | tr -d '\r\n')"
fi
device="$(adb_target_desc)"
apk_sha256="$(sha256sum "$APK" | awk '{print $1}')"
{
  printf 'matrix=s61-disabled-lpi-provider-device\n'
  printf 'device=%s\n' "$device"
  printf 'package=%s\n' "$PACKAGE"
  printf 'activity=%s\n' "$ACTIVITY"
  printf 'apk=%s\n' "${APK#${repo_root}/}"
  printf 'apk.sha256=%s\n' "$apk_sha256"
  printf 'buildFingerprint=%s\n' "$fingerprint"
  printf 'abi=%s\n' "$abi"
  printf 'adbWrapper=./dev/adb\n'
  printf 'source=android-installed-apk-debugDownload\n'
  printf 'corpus=not_used\n'
  printf 'provider=disabled\n'
  printf 'providerSource=none\n'
  printf 'realProviderEnabled=not_claimed\n'
  printf 'ProtocolRule=out_of_scope\n'
  printf 'protocolRule=out_of_scope\n'
  printf 'protocolRuleEnforcement=not_claimed\n'
  printf 'payloadBoundary=transport-payload-only\n'
  printf 'profiles=%s\n' "$S61_PROFILE_SET"
} >"$RESULT_DIR/device.properties"
kv "matrix" "s61-disabled-lpi-provider-device"
kv "device" "$device"
kv "package" "$PACKAGE"
kv "apk" "${APK#${repo_root}/}"
kv "apk.sha256" "$apk_sha256"
kv "buildFingerprint" "$fingerprint"
kv "abi" "$abi"
kv "source" "android-installed-apk-debugDownload"
kv "corpus" "not_used"
kv "provider" "disabled"
kv "ProtocolRule" "out_of_scope"

IFS=',' read -r -a profiles <<<"$S61_PROFILE_SET"
if [[ ${#profiles[@]} -eq 0 ]]; then
  write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "FAIL"
  kv "matrix.result" "FAIL"
  kv "matrix.reason" "no profiles selected"
  exit 1
fi
for profile in "${profiles[@]}"; do
  case "$profile" in
    root)
      run_profile root NFQUEUE.STATUS root-nfqueue || {
        rc=$?
        if [[ "$rc" -eq 77 ]]; then
          write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "BLOCKED"
          kv "matrix.result" "BLOCKED"
          exit 77
        fi
        write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "FAIL"
        kv "matrix.result" "FAIL"
        exit 1
      }
      ;;
    vpn)
      run_profile vpn VPN_TUN.STATUS vpn-tun-hev || {
        rc=$?
        if [[ "$rc" -eq 77 ]]; then
          write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "BLOCKED"
          kv "matrix.result" "BLOCKED"
          exit 77
        fi
        write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "FAIL"
        kv "matrix.result" "FAIL"
        exit 1
      }
      ;;
    *)
      write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "FAIL"
      kv "matrix.result" "FAIL"
      kv "matrix.reason" "unknown profile in S61_PROFILE_SET: $profile"
      exit 1
      ;;
  esac
  if ! stop_profile "$profile"; then
    write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "FAIL"
    kv "matrix.result" "FAIL"
    kv "matrix.reason" "runtime or adapter residue after $profile"
    exit 1
  fi
  CURRENT_PROFILE=""
done

matrix_status="PASS"
if [[ "$S61_TRANSPORT_WARNING" == "1" ]]; then
  matrix_status="PASS_WITH_TRANSPORT_WARNING"
fi
write_boundary_properties "$RESULT_DIR/s61-disabled-lpi-provider.properties" "$matrix_status"
{
  printf 'device=%s\n' "$device"
  printf 'apk.sha256=%s\n' "$apk_sha256"
  printf 'buildFingerprint=%s\n' "$fingerprint"
  printf 'abi=%s\n' "$abi"
  printf 'profiles=%s\n' "$S61_PROFILE_SET"
  printf 'matrix.result=%s\n' "$matrix_status"
} >>"$RESULT_DIR/s61-disabled-lpi-provider.properties"
kv "matrix.result" "$matrix_status"
exit 0
