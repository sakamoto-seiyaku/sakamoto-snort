#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-176 Root NFQUEUE IPv4 OUTPUT real-device acceptance entry point.
#
# PASS means the installed debug APK started the Product VPP Root profile,
# one app-UID IPv4 OUTPUT TCP probe reached a Controlled LAN endpoint through
# the product Root NFQUEUE adapter, and STOP removed the root hook residue.
# KernelSU authorization must be granted explicitly to this debug APK in
# KernelSU Manager first. ADB shell root is not evidence that the APK can start
# the Root Product VPP. Fixed-coordinate KSU clicks are not accepted evidence.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S176_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s176-root-nfqueue-output}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="${STATE_PATH:-files/runtime-state/snapshot.properties}"
readonly STATUS_PATH="${STATUS_PATH:-files/product-state/s176-root-nfqueue-output.properties}"
readonly CLEANUP_PATH="${CLEANUP_PATH:-files/product-state/s176-root-nfqueue-cleanup.properties}"
readonly PROBE_PATH="${PROBE_PATH:-files/debug/traffic-probe.properties}"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s176-root-nfqueue-output-product.sh --run --host <controlled-lan-ipv4> [--port 80]

Runs the SAKAMOTO-176 installed-debug-APK acceptance on the controlled Pixel 6a.

Required:
  --run                         prevents accidental device mutation
  --host / S176_CONTROLLED_LAN_HOST
                                IPv4 literal for a Controlled LAN TCP endpoint

Optional:
  --serial 28201JEGR0XPAJ       only this Pixel 6a is accepted
  --port / S176_CONTROLLED_LAN_PORT
                                Controlled LAN TCP port; default 80
  --timeout-ms / S176_PROBE_TIMEOUT_MILLIS
                                TCP connect timeout; default 3000
  S176_PROBE_COMMAND            override the built-in APK start/probe/stop flow

Before running, manually grant Superuser permission for this debug APK in
KernelSU Manager. Do not use fixed-coordinate UI clicks as evidence.

Required product evidence:
  product.adapter_available=1
  queue_id=176
  hook=OUTPUT
  origin_verdict_attempts>=1
  internal_settlements=origin_verdict_attempts
  buffer_returns=origin_verdict_attempts
  controlled_lan_response=matched
  productRootNfqueueResidueClean=true
  state=stopped
  mayBeActive=false
EOF
}

serial="$S176_SERIAL"
run=0
controlled_host="${S176_CONTROLLED_LAN_HOST:-}"
controlled_port="${S176_CONTROLLED_LAN_PORT:-80}"
probe_timeout_ms="${S176_PROBE_TIMEOUT_MILLIS:-3000}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      serial="${2:-}"
      shift 2
      ;;
    --run)
      run=1
      shift
      ;;
    --host)
      controlled_host="${2:-}"
      shift 2
      ;;
    --port)
      controlled_port="${2:-}"
      shift 2
      ;;
    --timeout-ms)
      probe_timeout_ms="${2:-}"
      shift 2
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

if [[ "$serial" != "$S176_SERIAL" ]]; then
  echo "SAKAMOTO-176 only accepts controlled Pixel 6a serial $S176_SERIAL; got $serial" >&2
  exit 2
fi

if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi

if ! [[ "$controlled_port" =~ ^[0-9]+$ ]] \
    || (( controlled_port < 1 || controlled_port > 65535 )); then
  echo "invalid Controlled LAN port: $controlled_port" >&2
  exit 2
fi

if ! [[ "$probe_timeout_ms" =~ ^[0-9]+$ ]] || (( probe_timeout_ms < 1 )); then
  echo "invalid probe timeout: $probe_timeout_ms" >&2
  exit 2
fi

if [[ -z "${S176_PROBE_COMMAND:-}" ]]; then
  if [[ -z "$controlled_host" ]]; then
    echo "missing --host or S176_CONTROLLED_LAN_HOST" >&2
    usage >&2
    exit 2
  fi
  if ! [[ "$controlled_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Controlled LAN host must be an IPv4 literal to avoid DNS side traffic: $controlled_host" >&2
    exit 2
  fi
fi

mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/runner.log") 2>&1

kv() {
  printf '%s=%s\n' "$1" "$2"
}

fail_closed() {
  printf 'SAKAMOTO-176-root-nfqueue-output=BLOCKED\n' >&2
  printf '%s\n' "$1" >&2
  exit 77
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null || true
}

require_exact() {
  local name="$1"
  local expected="$2"
  local evidence="$3"
  if ! grep -Fxq "${name}=${expected}" <<<"$evidence"; then
    printf 'missing or unequal evidence: %s=%s\n' "$name" "$expected" >&2
    return 1
  fi
}

field_value() {
  local name="$1"
  local evidence="$2"
  awk -F= -v key="$name" '$1 == key { print $2; exit }' <<<"$evidence"
}

positive_equal_packet_counters() {
  local evidence="$1"
  local verdicts
  local settlements
  local returns
  verdicts="$(field_value origin_verdict_attempts "$evidence")"
  settlements="$(field_value internal_settlements "$evidence")"
  returns="$(field_value buffer_returns "$evidence")"
  [[ "$verdicts" =~ ^[0-9]+$ ]] || return 1
  [[ "$settlements" =~ ^[0-9]+$ ]] || return 1
  [[ "$returns" =~ ^[0-9]+$ ]] || return 1
  (( verdicts >= 1 )) || return 1
  (( settlements == verdicts )) || return 1
  (( returns == verdicts )) || return 1
}

require_positive_equal_packet_counters() {
  local evidence="$1"
  if ! positive_equal_packet_counters "$evidence"; then
    printf 'missing or inconsistent Root NFQUEUE packet counters\n' >&2
    return 1
  fi
}

start_activity() {
  adb_target shell am start -n "$ACTIVITY" "$@" >/dev/null
}

clear_previous_evidence() {
  adb_target shell run-as "$PACKAGE" rm -f \
    "$STATE_PATH" "$STATUS_PATH" "$CLEANUP_PATH" "$PROBE_PATH" >/dev/null 2>&1 || true
}

grant_notification_permission_best_effort() {
  adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS >/dev/null 2>&1 || true
}

wait_for_root_running() {
  local snapshot=""
  local last_error=""
  local attempt
  for ((attempt = 1; attempt <= 90; attempt++)); do
    snapshot="$(app_file "$STATE_PATH" | tr -d '\r')"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.poll"
    if grep -Fxq "errorCode=root_authorization_required" <<<"$snapshot"; then
      fail_closed "KernelSU has not granted Superuser to $PACKAGE; grant it in KernelSU Manager, then rerun"
    fi
    if grep -Fxq "errorCode=notification_permission_required" <<<"$snapshot"; then
      fail_closed "Android notification permission is required before RuntimeService can start"
    fi
    if grep -Fxq "state=error" <<<"$snapshot"; then
      last_error="$snapshot"
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.error.properties"
    elif grep -Fxq "state=running" <<<"$snapshot" \
        && grep -Fxq "profile=root" <<<"$snapshot" \
        && grep -Fxq "coreHealth=ok" <<<"$snapshot" \
        && grep -Fxq "adapterReadiness=root-nfqueue" <<<"$snapshot" \
        && grep -Fxq "protectionRunning=true" <<<"$snapshot"; then
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.timeout.properties"
  if [[ -n "$last_error" ]]; then
    printf '%s\n' "$last_error" >"$RESULT_DIR/snapshot.last-error.properties"
  fi
  fail_closed "Product Root runtime did not publish root-nfqueue running state"
}

wait_for_probe_success() {
  local probe=""
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    probe="$(app_file "$PROBE_PATH" | tr -d '\r')"
    printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.poll"
    if grep -Fxq "result=tcp_connect_succeeded" <<<"$probe"; then
      printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.timeout.properties"
  fail_closed "Controlled LAN TCP probe did not succeed"
}

wait_for_product_status() {
  local status=""
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    status="$(app_file "$STATUS_PATH" | tr -d '\r')"
    printf '%s\n' "$status" >"$RESULT_DIR/product-status.poll"
    if grep -Fxq "product.adapter_available=1" <<<"$status" \
        && grep -Fxq "queue_id=176" <<<"$status" \
        && grep -Fxq "hook=OUTPUT" <<<"$status" \
        && positive_equal_packet_counters "$status" \
        && grep -Fxq "controlled_lan_response=matched" <<<"$status"; then
      printf '%s\n' "$status" >"$RESULT_DIR/product-status.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$status" >"$RESULT_DIR/product-status.timeout.properties"
  fail_closed "Product S176 status did not prove exactly one accepted Root NFQUEUE OUTPUT packet"
}

wait_for_cleanup() {
  local cleanup=""
  local snapshot=""
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    cleanup="$(app_file "$CLEANUP_PATH" | tr -d '\r')"
    snapshot="$(app_file "$STATE_PATH" | tr -d '\r')"
    printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.poll"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.stopped.poll"
    if grep -Fxq "productRootNfqueueResidueClean=true" <<<"$cleanup" \
        && grep -Fxq "state=stopped" <<<"$snapshot" \
        && grep -Fxq "mayBeActive=false" <<<"$snapshot" \
        && grep -Fxq "errorCode=" <<<"$snapshot"; then
      printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.properties"
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.stopped.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.timeout.properties"
  fail_closed "Product Root NFQUEUE hook residue did not clean after STOP"
}

run_builtin_probe() {
  clear_previous_evidence
  grant_notification_permission_best_effort

  start_activity --ez runtimeStart true --es runtimeProfile root
  wait_for_root_running

  start_activity --ez debugTraffic true \
    --es debugTrafficHost "$controlled_host" \
    --ei debugTrafficPort "$controlled_port" \
    --ei debugTrafficTimeoutMillis "$probe_timeout_ms"
  wait_for_probe_success
  wait_for_product_status

  start_activity --ez runtimeStop true
  wait_for_cleanup
}

run_custom_probe() {
  S176_DEVICE_SERIAL="$serial" \
    S176_RESULT_DIR="$RESULT_DIR" \
    S176_CONTROLLED_LAN_HOST="$controlled_host" \
    S176_CONTROLLED_LAN_PORT="$controlled_port" \
    bash -c "$S176_PROBE_COMMAND"
}

"$ADB" devices | tr -d '\r' | grep -Eq "^${serial}[[:space:]]+device$" \
  || fail_closed "controlled Pixel 6a is not connected through ./dev/adb"

adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"

kv test_id SAKAMOTO-176-root-nfqueue-output
kv device_serial "$serial"
kv package "$PACKAGE"
kv activity "$ACTIVITY"
kv controlled_lan_host "${controlled_host:-custom}"
kv controlled_lan_port "$controlled_port"

if [[ -n "${S176_PROBE_COMMAND:-}" ]]; then
  run_custom_probe
else
  run_builtin_probe
fi

status="$(app_file "$STATUS_PATH" | tr -d '\r')"
cleanup="$(app_file "$CLEANUP_PATH" | tr -d '\r')"
printf '%s\n' "$status" >"$RESULT_DIR/product-status.properties"
printf '%s\n' "$cleanup" >"$RESULT_DIR/cleanup-status.properties"

require_exact product.adapter_available 1 "$status"
require_exact queue_id 176 "$status"
require_exact hook OUTPUT "$status"
require_positive_equal_packet_counters "$status"
require_exact controlled_lan_response matched "$status"
require_exact productRootNfqueueResidueClean true "$cleanup"
snapshot="$(app_file "$STATE_PATH" | tr -d '\r')"
require_exact state stopped "$snapshot"
require_exact mayBeActive false "$snapshot"
require_exact errorCode "" "$snapshot"

printf 'SAKAMOTO-176-root-nfqueue-output=PASS\n'
