#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-177 Root NFQUEUE multi-lane real-device acceptance entry point.
#
# PASS means the installed debug APK starts one Root Product VPP generation with
# two ready NFQUEUE lanes, queue-balance drives real app-UID OUTPUT traffic
# to two controlled host-owned IPv4 destinations through both lanes, and the
# graph reports both owner-local and owner-remote completion before STOP
# removes platform hook residue.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S177_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s177-root-nfqueue-multilane}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="${STATE_PATH:-files/runtime-state/snapshot.properties}"
readonly STATUS_PATH="${STATUS_PATH:-files/product-state/s177-root-nfqueue-multilane.properties}"
readonly CLEANUP_PATH="${CLEANUP_PATH:-files/product-state/s176-root-nfqueue-cleanup.properties}"
readonly PROBE_PATH="${PROBE_PATH:-files/debug/traffic-probe.properties}"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s177-root-nfqueue-multilane-product.sh --run --host <controlled-lan-ipv4> [--port 80]

Runs SAKAMOTO-177 on the controlled Pixel 6a.

Required:
  --run
  --host / S177_CONTROLLED_LAN_HOST
        Primary controlled LAN IPv4 TCP endpoint.

Optional:
  --serial 28201JEGR0XPAJ
  --port / S177_CONTROLLED_LAN_PORT
  --timeout-ms / S177_PROBE_TIMEOUT_MILLIS
  --attempts / S177_PROBE_ATTEMPTS
  --address-host / S177_ADDRESS_DIVERSE_HOST
        Optional second controlled host-owned IPv4 destination.
  --address-via / S177_ADDRESS_DIVERSE_VIA
        Next hop for --address-host from the Pixel. Default: --host.
  --address-iface / S177_ADDRESS_DIVERSE_IFACE
        Pixel egress interface/table. Default: inferred from route to --host.

Before running, grant Superuser permission for this debug APK in KernelSU
Manager. ADB shell root is not APK root authorization evidence.

Required product evidence:
  product.adapter_available=1
  queue_id=176
  queue_last=177
  queue_range=176-177
  lane_count=2
  ready_lane_mask=3
  origin_verdict_attempts>=2
  internal_settlements=origin_verdict_attempts
  buffer_returns=origin_verdict_attempts
  lane0_verdict_attempts>=1
  lane1_verdict_attempts>=1
  origin_local_completions>=1
  origin_remote_completions>=1
  controlled_lan_response=matched
  productRootNfqueueResidueClean=true
  state=stopped
  mayBeActive=false
EOF
}

serial="$S177_SERIAL"
run=0
controlled_host="${S177_CONTROLLED_LAN_HOST:-}"
controlled_port="${S177_CONTROLLED_LAN_PORT:-80}"
probe_timeout_ms="${S177_PROBE_TIMEOUT_MILLIS:-3000}"
probe_attempts="${S177_PROBE_ATTEMPTS:-64}"
address_diverse_host="${S177_ADDRESS_DIVERSE_HOST:-}"
address_diverse_via="${S177_ADDRESS_DIVERSE_VIA:-}"
address_diverse_iface="${S177_ADDRESS_DIVERSE_IFACE:-}"
address_diverse_route_installed=0

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
    --attempts)
      probe_attempts="${2:-}"
      shift 2
      ;;
    --address-host)
      address_diverse_host="${2:-}"
      shift 2
      ;;
    --address-via)
      address_diverse_via="${2:-}"
      shift 2
      ;;
    --address-iface)
      address_diverse_iface="${2:-}"
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

if [[ "$serial" != "$S177_SERIAL" ]]; then
  echo "SAKAMOTO-177 only accepts controlled Pixel 6a serial $S177_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$controlled_host" ]]; then
  echo "missing --host or S177_CONTROLLED_LAN_HOST" >&2
  usage >&2
  exit 2
fi
if ! [[ "$controlled_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Controlled LAN host must be an IPv4 literal: $controlled_host" >&2
  exit 2
fi
if [[ -n "$address_diverse_host" && -z "$address_diverse_via" ]]; then
  address_diverse_via="$controlled_host"
fi
if [[ -n "$address_diverse_host" ]] \
    && ! [[ "$address_diverse_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Address-diverse host must be an IPv4 literal: $address_diverse_host" >&2
  exit 2
fi
if [[ -n "$address_diverse_host" ]] \
    && ! [[ "$address_diverse_via" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Address-diverse next hop must be an IPv4 literal: $address_diverse_via" >&2
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
if ! [[ "$probe_attempts" =~ ^[0-9]+$ ]] || (( probe_attempts < 2 )); then
  echo "invalid probe attempts: $probe_attempts" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/runner.log") 2>&1

fail_closed() {
  printf 'SAKAMOTO-177-root-nfqueue-multilane=BLOCKED\n' >&2
  printf '%s\n' "$1" >&2
  exit 77
}

kv() {
  printf '%s=%s\n' "$1" "$2"
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null || true
}

cleanup_address_diverse_route() {
  if [[ "$address_diverse_route_installed" == 1 && -n "$address_diverse_iface" ]]; then
    adb_target shell su -c "ip route del ${address_diverse_host}/32 table ${address_diverse_iface}" \
      >/dev/null 2>&1 || true
  fi
}

trap cleanup_address_diverse_route EXIT

field_value() {
  local name="$1"
  local evidence="$2"
  awk -F= -v key="$name" '$1 == key { print $2; exit }' <<<"$evidence"
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

require_ge() {
  local name="$1"
  local minimum="$2"
  local evidence="$3"
  local value
  value="$(field_value "$name" "$evidence")"
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  (( value >= minimum )) || return 1
}

positive_equal_packet_counters() {
  local evidence="$1"
  local verdicts settlements returns
  verdicts="$(field_value origin_verdict_attempts "$evidence")"
  settlements="$(field_value internal_settlements "$evidence")"
  returns="$(field_value buffer_returns "$evidence")"
  [[ "$verdicts" =~ ^[0-9]+$ ]] || return 1
  [[ "$settlements" =~ ^[0-9]+$ ]] || return 1
  [[ "$returns" =~ ^[0-9]+$ ]] || return 1
  (( verdicts >= 2 )) || return 1
  (( settlements == verdicts )) || return 1
  (( returns == verdicts )) || return 1
}

start_activity() {
  adb_target shell am start -n "$ACTIVITY" "$@" >/dev/null
}

infer_address_diverse_iface() {
  local route
  route="$(adb_target shell su -c "ip route get ${controlled_host}" | tr -d '\r')"
  awk '{
    for (field = 1; field <= NF; field++) {
      if ($field == "dev") {
        print $(field + 1)
        exit
      }
    }
  }' <<<"$route"
}

install_address_diverse_route() {
  if [[ -z "$address_diverse_host" ]]; then
    return 0
  fi
  if [[ "$address_diverse_host" == "$controlled_host" ]]; then
    fail_closed "address-diverse host must differ from the primary controlled LAN host"
  fi
  if [[ -z "$address_diverse_iface" ]]; then
    address_diverse_iface="$(infer_address_diverse_iface)"
  fi
  if [[ -z "$address_diverse_iface" ]]; then
    fail_closed "could not infer Pixel egress interface for address-diverse host"
  fi
  adb_target shell su -c \
    "ip route replace ${address_diverse_host}/32 via ${address_diverse_via} dev ${address_diverse_iface} table ${address_diverse_iface}"
  address_diverse_route_installed=1
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
  local attempt
  for ((attempt = 1; attempt <= 90; attempt++)); do
    snapshot="$(app_file "$STATE_PATH" | tr -d '\r')"
    printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.poll"
    if grep -Fxq "errorCode=root_authorization_required" <<<"$snapshot"; then
      fail_closed "KernelSU Superuser grant is missing for the installed debug APK"
    fi
    if grep -Fxq "state=running" <<<"$snapshot" \
        && grep -Fxq "profile=root" <<<"$snapshot" \
        && grep -Fxq "adapterReadiness=root-nfqueue" <<<"$snapshot"; then
      printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$snapshot" >"$RESULT_DIR/snapshot.running.timeout.properties"
  fail_closed "Product Root runtime did not publish root-nfqueue running state"
}

probe_once() {
  local host="$1"
  local source_port="$2"
  adb_target shell run-as "$PACKAGE" rm -f "$PROBE_PATH" >/dev/null 2>&1 || true
  start_activity --ez debugTraffic true \
    --es debugTrafficHost "$host" \
    --ei debugTrafficPort "$controlled_port" \
    --ei debugTrafficSourcePort "$source_port" \
    --ei debugTrafficTimeoutMillis "$probe_timeout_ms"
}

wait_for_probe_success() {
  local label="$1"
  local probe=""
  local attempt
  for ((attempt = 1; attempt <= 20; attempt++)); do
    probe="$(app_file "$PROBE_PATH" | tr -d '\r')"
    printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.poll"
    if grep -Fxq "result=tcp_connect_succeeded" <<<"$probe"; then
      printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.properties"
      return 0
    fi
    sleep 1
  done
  printf '%s\n' "$probe" >"$RESULT_DIR/traffic-probe.${label}.timeout.properties"
  fail_closed "Controlled LAN TCP probe did not succeed for ${label}"
}

probe_cycle_once() {
  local source_port="$1"
  probe_once "$controlled_host" "$source_port"
  wait_for_probe_success primary
  if [[ -n "$address_diverse_host" ]]; then
    probe_once "$address_diverse_host" "$((source_port + 1))"
    wait_for_probe_success address-diverse
  fi
}

s177_status_complete() {
  local status="$1"
  grep -Fxq "product.adapter_available=1" <<<"$status" \
    && grep -Fxq "queue_id=176" <<<"$status" \
    && grep -Fxq "queue_last=177" <<<"$status" \
    && grep -Fxq "queue_range=176-177" <<<"$status" \
    && grep -Fxq "lane_count=2" <<<"$status" \
    && grep -Fxq "ready_lane_mask=3" <<<"$status" \
    && grep -Fxq "hook=OUTPUT" <<<"$status" \
    && positive_equal_packet_counters "$status" \
    && require_ge lane0_verdict_attempts 1 "$status" \
    && require_ge lane1_verdict_attempts 1 "$status" \
    && require_ge origin_local_completions 1 "$status" \
    && require_ge origin_remote_completions 1 "$status" \
    && grep -Fxq "controlled_lan_response=matched" <<<"$status"
}

wait_for_status_complete() {
  local status=""
  local attempt
  for ((attempt = 1; attempt <= 15; attempt++)); do
    status="$(app_file "$STATUS_PATH" | tr -d '\r')"
    printf '%s\n' "$status" >"$RESULT_DIR/product-status.poll"
    if s177_status_complete "$status"; then
      printf '%s\n' "$status" >"$RESULT_DIR/product-status.properties"
      return 0
    fi
    sleep 1
  done
  return 1
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

"$ADB" devices | tr -d '\r' | grep -Eq "^${serial}[[:space:]]+device$" \
  || fail_closed "controlled Pixel 6a is not connected through ./dev/adb"

adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"

kv test_id SAKAMOTO-177-root-nfqueue-multilane
kv device_serial "$serial"
kv package "$PACKAGE"
kv activity "$ACTIVITY"
kv controlled_lan_host "$controlled_host"
kv controlled_lan_port "$controlled_port"
kv probe_attempts "$probe_attempts"
if [[ -n "$address_diverse_host" ]]; then
  kv address_diverse_host "$address_diverse_host"
  kv address_diverse_via "$address_diverse_via"
else
  kv address_diverse_host ""
  kv address_diverse_strategy "source-port-rotation"
fi

clear_previous_evidence
grant_notification_permission_best_effort
install_address_diverse_route
if [[ -n "$address_diverse_host" ]]; then
  kv address_diverse_iface "$address_diverse_iface"
fi

start_activity --ez runtimeStart true --es runtimeProfile root
wait_for_root_running

for ((attempt = 0; attempt < probe_attempts; attempt++)); do
  source_port=$((20000 + (attempt * 2)))
  kv probe_source_port "$source_port"
  probe_cycle_once "$source_port"
  if wait_for_status_complete; then
    break
  fi
done

status="$(app_file "$STATUS_PATH" | tr -d '\r')"
printf '%s\n' "$status" >"$RESULT_DIR/product-status.properties"
if ! s177_status_complete "$status"; then
  printf '%s\n' "$status" >"$RESULT_DIR/product-status.incomplete.properties"
  start_activity --ez runtimeStop true
  wait_for_cleanup || true
  fail_closed "Product S177 status did not cover two lanes and local/remote origin completion"
fi

start_activity --ez runtimeStop true
wait_for_cleanup

cleanup="$(app_file "$CLEANUP_PATH" | tr -d '\r')"
snapshot="$(app_file "$STATE_PATH" | tr -d '\r')"
require_exact product.adapter_available 1 "$status"
require_exact queue_id 176 "$status"
require_exact queue_last 177 "$status"
require_exact queue_range 176-177 "$status"
require_exact lane_count 2 "$status"
require_exact ready_lane_mask 3 "$status"
require_exact hook OUTPUT "$status"
positive_equal_packet_counters "$status"
require_ge lane0_verdict_attempts 1 "$status"
require_ge lane1_verdict_attempts 1 "$status"
require_ge origin_local_completions 1 "$status"
require_ge origin_remote_completions 1 "$status"
require_exact controlled_lan_response matched "$status"
require_exact productRootNfqueueResidueClean true "$cleanup"
require_exact state stopped "$snapshot"
require_exact mayBeActive false "$snapshot"
require_exact errorCode "" "$snapshot"

printf 'SAKAMOTO-177-root-nfqueue-multilane=PASS\n'
