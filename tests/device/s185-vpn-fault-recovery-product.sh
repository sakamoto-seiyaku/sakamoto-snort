#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-185 VPN fault/recovery/residue real-device acceptance.
#
# PASS means the installed debug APK fails closed for VPN authorization/TUN and
# protected Direct socket faults, handles revoke/crash/no-callback stop through
# the serialized RuntimeService cleanup path, then starts a fresh VPN generation
# and proves UDP4/TCP4/UDP6/TCP6 installed-app LAN traffic before final cleanup.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S185_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s185-vpn-fault-recovery}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly STATUS_PATH="files/product-state/s185-vpn-fault-recovery.properties"
readonly S180_STATUS_PATH="files/product-state/s180-vpn-udp4-direct-egress.properties"
readonly S181_STATUS_PATH="files/product-state/s181-vpn-tcp4-direct-egress.properties"
readonly S182_STATUS_PATH="files/product-state/s182-vpn-udp6-direct-egress.properties"
readonly S183_STATUS_PATH="files/product-state/s183-vpn-tcp6-direct-egress.properties"
readonly S184_STATUS_PATH="files/product-state/s184-vpn-network-epoch.properties"
readonly TCP_PROBE_PATH="files/debug/traffic-probe.properties"
readonly UDP_PROBE_PATH="files/debug/udp-traffic-probe.properties"
readonly RUNTIME_LOG_PATH="files/logs/runtime-service.log"
readonly VPN_PROFILE_PATH="files/profiles/vpn/vpp"
readonly VPN_NETWORK_WAIT_ATTEMPTS="${S185_VPN_NETWORK_WAIT_ATTEMPTS:-45}"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s185-vpn-fault-recovery-product.sh --run \
    --host4 <controlled-lan-ipv4> --host6 <controlled-lan-ipv6>

Required:
  --run
  --host4 / S185_CONTROLLED_LAN_HOST4
  --host6 / S185_CONTROLLED_LAN_HOST6

Optional:
  --serial 28201JEGR0XPAJ
  --base-port / S185_BASE_PORT       default 18190
  --timeout-ms / S185_TIMEOUT_MILLIS default 5000

Before running, Android must already have approved this app as a VPN service.
If the script reports vpn_authorization_required, approve the VPN dialog on the
controlled Pixel 6a and rerun. Packet evidence must come from the installed
debug app and controlled LAN peers.

Required final evidence:
  establish_null, protect_false, bind_failed fail closed
  close_tun records a native VPN infrastructure fault before cleanup
  revoke/native_crash/user force-stop recover through fresh generations
  installed_app_udp4_source true
  installed_app_tcp4_source true
  installed_app_udp6_source true
  installed_app_tcp6_source true
  flow_stack_admission_observed true
  final_residue_clean true
EOF
}

serial="$S185_SERIAL"
run=0
host4="${S185_CONTROLLED_LAN_HOST4:-}"
host6="${S185_CONTROLLED_LAN_HOST6:-}"
base_port="${S185_BASE_PORT:-18190}"
timeout_ms="${S185_TIMEOUT_MILLIS:-5000}"
app_uid=""

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
    --host4)
      host4="${2:-}"
      shift 2
      ;;
    --host6)
      host6="${2:-}"
      shift 2
      ;;
    --base-port)
      base_port="${2:-}"
      shift 2
      ;;
    --timeout-ms)
      timeout_ms="${2:-}"
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

if [[ "$serial" != "$S185_SERIAL" ]]; then
  echo "SAKAMOTO-185 only accepts controlled Pixel 6a serial $S185_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$host4" || -z "$host6" ]]; then
  echo "missing --host4/--host6 or S185_CONTROLLED_LAN_HOST4/6" >&2
  usage >&2
  exit 2
fi
if ! [[ "$host4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "controlled IPv4 host must be an IPv4 literal: $host4" >&2
  exit 2
fi
python3 - "$host6" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("controlled IPv6 host must be an IPv6 literal")
if address.version != 6:
    raise SystemExit("controlled IPv6 host must be an IPv6 literal")
if getattr(address, "ipv4_mapped", None) is not None:
    raise SystemExit("controlled IPv6 host must not be IPv4-mapped")
if address.is_loopback or address.is_unspecified or address.is_global:
    raise SystemExit("controlled IPv6 host must be reachable LAN, not loopback/public")
PY
if ! [[ "$base_port" =~ ^[0-9]+$ ]] \
    || (( base_port < 1024 || base_port > 65480 )); then
  echo "invalid base port: $base_port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 500 || timeout_ms > 30000 )); then
  echo "invalid timeout ms: $timeout_ms" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
: > "$summary"
server_pid=""

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

fail_closed() {
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-185 FAIL: $1" >&2
  exit 1
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

start_activity() {
  adb_target shell am start -W -f 0x10008000 -n "$ACTIVITY" "$@" \
    >> "$RESULT_DIR/am-start.log" 2>&1
}

# Headless control intents finish DebugControlActivity.  A following intent can
# otherwise race that finish and be acknowledged by am without reaching the
# service.  Force-stop the short-lived activity before fault injection so the
# next am start is a cold, explicit delivery.
cold_start_control_activity() {
  adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 2
}

installed_app_uid() {
  local output="$RESULT_DIR/package-list.txt"
  local dumpsys="$RESULT_DIR/package-dumpsys.txt"
  local uid=""
  adb_target shell cmd package list packages -U "$PACKAGE" > "$output" 2>/dev/null || true
  uid="$(tr -d '\r' < "$output" | awk -v package="package:${PACKAGE}" \
    '$1 == package { for (i = 1; i <= NF; i++) {
       if ($i ~ /^uid:/) { sub(/^uid:/, "", $i); print $i; exit }
     }}')"
  if [[ -z "$uid" ]]; then
    adb_target shell dumpsys package "$PACKAGE" > "$dumpsys" 2>/dev/null || true
    uid="$(tr -d '\r' < "$dumpsys" \
      | awk -F= '/userId=/{ gsub(/[^0-9].*/, "", $2); print $2; exit }')"
  fi
  if ! [[ "$uid" =~ ^[0-9]+$ ]] || (( uid <= 0 || uid >= 4294967295 )); then
    fail_closed "could not discover installed APK complete UID for $PACKAGE"
  fi
  printf '%s\n' "$uid"
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null | tr -d '\r' || true
}

property_value() {
  local key="$1"
  local file="$2"
  awk -F= -v wanted="$key" '
    $1 == wanted {
      value = substr($0, index($0, "=") + 1)
      sub(/\r$/, "", value)
      print value
      exit
    }' "$file"
}

require_property() {
  local key="$1"
  local expected="$2"
  local file="$3"
  grep -Fxq "${key}=${expected}" "$file" \
    || fail_closed "$key=$expected missing in $file"
}

require_positive_property() {
  local key="$1"
  local file="$2"
  local value
  value="$(property_value "$key" "$file")"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value <= 0 )); then
    fail_closed "$key is not positive in $file"
  fi
  kv "$key" "$value"
}

require_zero_property() {
  local key="$1"
  local file="$2"
  local value
  value="$(property_value "$key" "$file")"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value != 0 )); then
    fail_closed "$key is not zero in $file"
  fi
  kv "$key" "$value"
}

clear_app_files() {
  adb_target shell run-as "$PACKAGE" rm -f \
    "$STATE_PATH" "$STATUS_PATH" "$S180_STATUS_PATH" "$S181_STATUS_PATH" \
    "$S182_STATUS_PATH" "$S183_STATUS_PATH" "$S184_STATUS_PATH" \
    "$TCP_PROBE_PATH" "$UDP_PROBE_PATH" \
    >/dev/null 2>&1 || true
}

snapshot_to_file() {
  local label="$1"
  read_app_file "$STATE_PATH" > "$RESULT_DIR/snapshot.${label}.properties"
}

status_to_file() {
  local label="$1"
  read_app_file "$STATUS_PATH" > "$RESULT_DIR/s185-status.${label}.properties"
}

capture_runtime_log() {
  local label="$1"
  read_app_file "$RUNTIME_LOG_PATH" > "$RESULT_DIR/runtime-service.${label}.log"
}

wait_for_snapshot_state() {
  local label="$1"
  local expected_state="$2"
  local expected_error="${3:-}"
  local expected_may="${4:-}"
  local deadline=$((SECONDS + 45))
  while (( SECONDS < deadline )); do
    snapshot_to_file "${label}.poll"
    if grep -Fq "state=${expected_state}" "$RESULT_DIR/snapshot.${label}.poll.properties" \
        && grep -Fq "profile=vpn" "$RESULT_DIR/snapshot.${label}.poll.properties"; then
      if [[ -n "$expected_error" ]] \
          && ! grep -Fxq "errorCode=${expected_error}" \
            "$RESULT_DIR/snapshot.${label}.poll.properties"; then
        sleep 1
        continue
      fi
      if [[ -n "$expected_may" ]] \
          && ! grep -Fxq "mayBeActive=${expected_may}" \
            "$RESULT_DIR/snapshot.${label}.poll.properties"; then
        sleep 1
        continue
      fi
      cp "$RESULT_DIR/snapshot.${label}.poll.properties" \
        "$RESULT_DIR/snapshot.${label}.properties"
      return 0
    fi
    if grep -Fxq "errorCode=vpn_authorization_required" \
        "$RESULT_DIR/snapshot.${label}.poll.properties"; then
      fail_closed "VPN authorization is missing; approve the Android VPN dialog and rerun"
    fi
    if grep -Fxq "errorCode=notification_permission_required" \
        "$RESULT_DIR/snapshot.${label}.poll.properties"; then
      fail_closed "Android notification permission is required before RuntimeService can start"
    fi
    sleep 1
  done
  cp "$RESULT_DIR/snapshot.${label}.poll.properties" \
    "$RESULT_DIR/snapshot.${label}.timeout.properties" 2>/dev/null || true
  return 1
}

complete_vpn_running() {
  local label="$1"
  require_property adapterReadiness vpn-tun-hev-lwip \
    "$RESULT_DIR/snapshot.${label}.properties"
  require_property protectionRunning true "$RESULT_DIR/snapshot.${label}.properties"
  start_activity --ez debugRefresh true
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    status_to_file "$label"
    if grep -Fq "schema=s185-vpn-fault-recovery/v1" \
        "$RESULT_DIR/s185-status.${label}.properties" \
        && grep -Fq "stage=running" \
          "$RESULT_DIR/s185-status.${label}.properties"; then
      return 0
    fi
    sleep 1
  done
  fail_closed "$label did not publish S185 running status"
}

wait_for_vpn_running() {
  local label="$1"
  wait_for_snapshot_state "$label" running "" true \
    || fail_closed "$label did not reach running VPN state"
  complete_vpn_running "$label"
}

wait_for_vpn_error() {
  local label="$1"
  local expected_error="$2"
  wait_for_snapshot_state "$label" error "$expected_error" false \
    || fail_closed "$label did not publish errorCode=$expected_error"
  status_to_file "$label"
  require_property schema s185-vpn-fault-recovery/v1 \
    "$RESULT_DIR/s185-status.${label}.properties"
  require_property stage error "$RESULT_DIR/s185-status.${label}.properties"
  require_property errorCode "$expected_error" \
    "$RESULT_DIR/s185-status.${label}.properties"
}

wait_for_clean_stop() {
  local label="$1"
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    snapshot_to_file "${label}.poll"
    if grep -Fxq "state=stopped" "$RESULT_DIR/snapshot.${label}.poll.properties" \
        && grep -Fxq "profile=vpn" "$RESULT_DIR/snapshot.${label}.poll.properties" \
        && grep -Fxq "mayBeActive=false" "$RESULT_DIR/snapshot.${label}.poll.properties"; then
      cp "$RESULT_DIR/snapshot.${label}.poll.properties" \
        "$RESULT_DIR/snapshot.${label}.properties"
      return 0
    fi
    sleep 1
  done
  cp "$RESULT_DIR/snapshot.${label}.poll.properties" \
    "$RESULT_DIR/snapshot.${label}.timeout.properties" 2>/dev/null || true
  fail_closed "$label did not reach stopped/mayBeActive=false"
}

wait_for_vpn_inactive() {
  local label="$1"
  local deadline=$((SECONDS + 60))
  while (( SECONDS < deadline )); do
    snapshot_to_file "${label}.poll"
    if grep -Fxq "profile=vpn" "$RESULT_DIR/snapshot.${label}.poll.properties" \
        && grep -Fxq "mayBeActive=false" \
          "$RESULT_DIR/snapshot.${label}.poll.properties" \
        && { grep -Fxq "state=stopped" \
              "$RESULT_DIR/snapshot.${label}.poll.properties" \
          || grep -Fxq "state=error" \
              "$RESULT_DIR/snapshot.${label}.poll.properties"; }; then
      cp "$RESULT_DIR/snapshot.${label}.poll.properties" \
        "$RESULT_DIR/snapshot.${label}.properties"
      return 0
    fi
    sleep 1
  done
  cp "$RESULT_DIR/snapshot.${label}.poll.properties" \
    "$RESULT_DIR/snapshot.${label}.timeout.properties" 2>/dev/null || true
  fail_closed "$label did not settle to inactive VPN state"
}

preflight_stop_vpn() {
  adb_target shell am force-stop "$PACKAGE" >/dev/null
  sleep 2
  clear_app_files
  kv preflight_force_stopped true
  start_activity --es runtimeVpnFaultMode none --ez runtimeStop true
  local deadline=$((SECONDS + 15))
  local empty_polls=0
  while (( SECONDS < deadline )); do
    snapshot_to_file preflight.poll
    if [[ ! -s "$RESULT_DIR/snapshot.preflight.poll.properties" ]]; then
      empty_polls=$((empty_polls + 1))
      if (( empty_polls >= 3 )); then
        kv preflight_clean_start no_projection
        return 0
      fi
      sleep 1
      continue
    fi
    empty_polls=0
    if grep -Fxq "mayBeActive=false" \
          "$RESULT_DIR/snapshot.preflight.poll.properties" \
        && { grep -Fxq "state=stopped" \
              "$RESULT_DIR/snapshot.preflight.poll.properties" \
          || grep -Fxq "state=error" \
              "$RESULT_DIR/snapshot.preflight.poll.properties"; }; then
      cp "$RESULT_DIR/snapshot.preflight.poll.properties" \
        "$RESULT_DIR/snapshot.preflight.properties"
      kv preflight_clean_start \
        "$(property_value state "$RESULT_DIR/snapshot.preflight.properties")"
      return 0
    fi
    if grep -Fxq "state=error" "$RESULT_DIR/snapshot.preflight.poll.properties" \
        && grep -Fxq "mayBeActive=false" \
          "$RESULT_DIR/snapshot.preflight.poll.properties"; then
      cp "$RESULT_DIR/snapshot.preflight.poll.properties" \
        "$RESULT_DIR/snapshot.preflight.properties"
      kv preflight_clean_start inactive_error
      return 0
    fi
    sleep 1
  done
  cp "$RESULT_DIR/snapshot.preflight.poll.properties" \
    "$RESULT_DIR/snapshot.preflight.timeout.properties" 2>/dev/null || true
  fail_closed "preflight did not settle to no runtime, inactive error, or stopped/mayBeActive=false"
}

finish_server() {
  if [[ -n "$server_pid" ]]; then
    wait "$server_pid" || true
    server_pid=""
  fi
}

kill_server() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
    server_pid=""
  fi
}

cleanup() {
  kill_server
  adb_target shell am start -n "$ACTIVITY" --es runtimeVpnFaultMode none \
    --ez runtimeStop true >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_host_ready() {
  local ready_file="$1"
  local deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    [[ -f "$ready_file" ]] && return 0
    sleep 1
  done
  return 1
}

capture_vpn_connectivity() {
  local label="$1"
  adb_target shell dumpsys connectivity \
    > "$RESULT_DIR/connectivity.${label}.txt" 2>&1 || true
}

vpn_network_present() {
  local file="$1"
  python3 - "$file" "$PACKAGE" "$app_uid" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
package = sys.argv[2]
uid = sys.argv[3]
text = path.read_text(encoding="utf-8", errors="replace")

# Keep the package, tun0, transport, and owner checks in one NetworkAgentInfo
# block.  A global grep could combine another VPN's network with this app.
for block in re.split(r"(?=NetworkAgentInfo\{)", text):
    if f"VPN:{package}" not in block:
        continue
    if "InterfaceName: tun0" not in block:
        continue
    transports = re.search(r"Transports:\s*([A-Z0-9_|]+)", block)
    if transports is None or "VPN" not in transports.group(1).split("|"):
        continue
    if re.search(rf"\bOwnerUid:\s*{re.escape(uid)}\b", block) is None:
        continue
    handle = re.search(r"\bhandle\{([0-9]+)\}", block)
    print(f"networkHandle={handle.group(1) if handle else -1}")
    raise SystemExit(0)
raise SystemExit(1)
PY
}

wait_for_vpn_network() {
  local label="$1"
  local output="$RESULT_DIR/connectivity.${label}.txt"
  local attempts_dir="$RESULT_DIR/connectivity.${label}.attempts"
  local attempts_log="$RESULT_DIR/connectivity.${label}.attempts.tsv"
  local attempt
  local match
  mkdir -p "$attempts_dir"
  : > "$attempts_log"
  for ((attempt = 1; attempt <= VPN_NETWORK_WAIT_ATTEMPTS; attempt++)); do
    capture_vpn_connectivity "$label"
    cp "$output" \
      "$attempts_dir/attempt-$(printf '%03d' "$attempt").txt" 2>/dev/null || true
    if match="$(vpn_network_present "$output" 2>/dev/null)"; then
      printf '%s\t%s\tpresent\t%s\n' \
        "$attempt" "$(date +%s)" "$match" >> "$attempts_log"
      kv "${label}.vpn_network_present" true
      kv "${label}.vpn_network_attempt" "$attempt"
      kv "${label}.vpn_network_handle" "${match#networkHandle=}"
      return 0
    fi
    printf '%s\t%s\tabsent\n' "$attempt" "$(date +%s)" >> "$attempts_log"
    sleep 1
  done
  kv "${label}.vpn_network_present" false
  return 1
}

start_echo_server() {
  local proto="$1"
  local family="$2"
  local bind_host="$3"
  local listen_port="$4"
  local expected_nonce="$5"
  local ready_file="$6"
  local log_file="$7"
  python3 - "$proto" "$family" "$bind_host" "$listen_port" \
    "$expected_nonce" "$ready_file" "$log_file" <<'PY' >/dev/null 2>&1 &
import pathlib
import socket
import sys

proto, family, host = sys.argv[1], sys.argv[2], sys.argv[3]
port = int(sys.argv[4])
expected = sys.argv[5].encode()
ready = pathlib.Path(sys.argv[6])
log = pathlib.Path(sys.argv[7])
af = socket.AF_INET6 if family == "6" else socket.AF_INET

def emit(result, peer="", request_bytes=0, response_bytes=0, nonce=""):
    log.write_text(
        f"proto={proto}\nfamily=AF_INET{family}\nresult={result}\npeer={peer}\n"
        f"requestBytes={request_bytes}\nresponseBytes={response_bytes}\n"
        f"nonce={nonce}\n",
        encoding="utf-8",
    )

if proto == "udp":
    sock = socket.socket(af, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == "6":
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    sock.settimeout(30)
    ready.write_text("ready\n", encoding="utf-8")
    try:
        data, address = sock.recvfrom(2048)
        peer = f"{address[0]}:{address[1]}"
        nonce = data.decode(errors="replace")
        if data == expected:
            sock.sendto(data, address)
            emit("udp_echo_matched", peer, len(data), len(data), nonce)
        else:
            emit("udp_echo_mismatch", peer, len(data), 0, nonce)
    except Exception as error:
        emit(f"udp_echo_failed:{error.__class__.__name__}:{error}")
    finally:
        sock.close()
else:
    server = socket.socket(af, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == "6":
        server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    server.bind((host, port))
    server.listen(1)
    server.settimeout(30)
    ready.write_text("ready\n", encoding="utf-8")
    try:
        conn, address = server.accept()
        peer = f"{address[0]}:{address[1]}"
        with conn:
            conn.settimeout(10)
            data = conn.recv(4096)
            nonce = data.decode(errors="replace")
            if data == expected:
                conn.sendall(data)
                emit("tcp_echo_matched", peer, len(data), len(data), nonce)
            else:
                emit("tcp_echo_mismatch", peer, len(data), 0, nonce)
    except Exception as error:
        emit(f"tcp_echo_failed:{error.__class__.__name__}:{error}")
    finally:
        server.close()
PY
  server_pid="$!"
}

wait_probe_result() {
  local relative="$1"
  local expected_nonce="$2"
  local expected_result="$3"
  local out_file="$4"
  local deadline=$((SECONDS + 40))
  while (( SECONDS < deadline )); do
    read_app_file "$relative" > "$out_file"
    if grep -Fq "nonce=${expected_nonce}" "$out_file" \
        && grep -Fq "result=${expected_result}" "$out_file"; then
      return 0
    fi
    if grep -Fq "nonce=${expected_nonce}" "$out_file" \
        && grep -Fxq "bindResult=vpn_network_not_found" "$out_file"; then
      return 2
    fi
    sleep 1
  done
  return 1
}

require_app_probe() {
  local probe_file="$1"
  local label="$2"
  grep -Fq "bindToVpn=true" "$probe_file" \
    || fail_closed "$label app probe was not requested as VPN-bound"
  grep -Fq "bindResult=bound" "$probe_file" \
    || fail_closed "$label app probe did not bind to the active VPN Network"
  local uid
  uid="$(property_value uid "$probe_file")"
  if ! [[ "$uid" =~ ^[0-9]+$ ]] || [[ "$uid" == "2000" ]]; then
    fail_closed "$label did not run as installed app UID"
  fi
}

run_probe() {
  local label="$1"
  local proto="$2"
  local family="$3"
  local target_host="$4"
  local listen_port="$5"
  local nonce="s185-${label}-${RUN_ID}"
  local ready_file="$RESULT_DIR/${label}.server.ready"
  local log_file="$RESULT_DIR/${label}.server.properties"
  local probe_file="$RESULT_DIR/${label}.probe.properties"
  local bind_host="0.0.0.0"
  local probe_path="$TCP_PROBE_PATH"
  local expected="tcp_echo_matched"
  local probe_rc=1
  local probe_relaunches=0
  rm -f "$ready_file" "$log_file" "$probe_file"
  if [[ "$family" == 6 ]]; then
    bind_host="$target_host"
  fi
  if [[ "$proto" == udp ]]; then
    probe_path="$UDP_PROBE_PATH"
    expected="udp_echo_matched"
  fi
  server_pid=""
  while :; do
    if ! wait_for_vpn_network "${label}.before-probe"; then
      fail_closed "$label VPN NetworkAgent did not become visible within ${VPN_NETWORK_WAIT_ATTEMPTS}s"
    fi
    rm -f "$ready_file" "$log_file" "$probe_file"
    start_echo_server "$proto" "$family" "$bind_host" "$listen_port" "$nonce" \
      "$ready_file" "$log_file"
    wait_for_host_ready "$ready_file" || fail_closed "$label server did not become ready"
    if [[ "$proto" == udp ]]; then
      start_activity --ez debugUdpTraffic true --es debugUdpHost "$target_host" \
        --ei debugUdpPort "$listen_port" --es debugUdpNonce "$nonce" \
        --ez debugUdpExpectReply true --ei debugUdpTimeoutMillis "$timeout_ms" \
        --ez debugTrafficBindToVpn true
    else
      start_activity --ez debugTraffic true --es debugTrafficHost "$target_host" \
        --ei debugTrafficPort "$listen_port" --es debugTrafficNonce "$nonce" \
        --ei debugTrafficTimeoutMillis "$timeout_ms" --ez debugTrafficBindToVpn true
    fi
    if wait_probe_result "$probe_path" "$nonce" "$expected" "$probe_file"; then
      probe_rc=0
    else
      probe_rc=$?
    fi
    if (( probe_rc == 0 )); then
      break
    fi
    if (( probe_rc == 2 && probe_relaunches == 0 )); then
      probe_relaunches=1
      cp "$probe_file" "$RESULT_DIR/${label}.bind-retry-1.probe.properties" \
        2>/dev/null || true
      cp "$log_file" "$RESULT_DIR/${label}.bind-retry-1.server.properties" \
        2>/dev/null || true
      if [[ -n "$server_pid" ]]; then
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
        server_pid=""
      fi
      sleep 1
      kv "${label}.vpn_probe_relaunched" true
      continue
    fi
    fail_closed "$label installed app probe did not echo"
  done
  finish_server
  grep -Fq "result=${expected}" "$log_file" \
    || fail_closed "$label controlled LAN server did not observe nonce"
  require_app_probe "$probe_file" "$label"
}

start_vpn_clean() {
  local label="$1"
  local attempt
  for attempt in 1 2; do
    start_activity --es runtimeVpnFaultMode none --ez runtimeStart true --es runtimeProfile vpn
    if wait_for_snapshot_state "$label" running "" true; then
      complete_vpn_running "$label"
      return
    fi
    if grep -Fxq "mayBeActive=false" \
          "$RESULT_DIR/snapshot.${label}.timeout.properties"; then
      if grep -Fxq "errorCode=product_core_not_ready" \
            "$RESULT_DIR/snapshot.${label}.timeout.properties"; then
        kv "${label}_retry_after_product_core_not_ready" true
        wait_for_vpn_inactive "${label}.retry-settled"
        sleep 2
        continue
      fi
      if grep -Fxq "errorCode=vpn_underlay_unavailable" \
            "$RESULT_DIR/snapshot.${label}.timeout.properties"; then
        kv "${label}_retry_after_vpn_underlay_unavailable" true
        wait_for_vpn_inactive "${label}.retry-settled"
        sleep 2
        continue
      fi
    fi
    break
  done
  fail_closed "$label did not reach running VPN state"
}

stop_vpn_clean() {
  local label="$1"
  start_activity --es runtimeVpnFaultMode none --ez runtimeStop true
  wait_for_clean_stop "$label"
}

generation_from_snapshot() {
  local file="$1"
  property_value generation "$file"
}

run_start_fault_case() {
  local label="$1"
  local mode="$2"
  local expected_error="$3"
  cold_start_control_activity
  clear_app_files
  # uses --es runtimeVpnFaultMode establish_null
  # uses --es runtimeVpnFaultMode protect_false
  # uses --es runtimeVpnFaultMode bind_failed
  start_activity --es runtimeVpnFaultMode "$mode" --ez runtimeStart true \
    --es runtimeProfile vpn
  wait_for_vpn_error "$label" "$expected_error"
  kv "${mode}_fail_closed" true
}

run_recovery_start_stop() {
  local label="$1"
  start_vpn_clean "${label}.running"
  stop_vpn_clean "${label}.stopped"
  kv "${label}_recovered" true
}

run_close_tun_case() {
  local label="close-tun"
  start_vpn_clean "${label}.before"
  local before_generation
  before_generation="$(generation_from_snapshot "$RESULT_DIR/snapshot.${label}.before.properties")"
  # uses --es runtimeVpnFaultEvent close_tun
  start_activity --es runtimeVpnFaultEvent close_tun
  wait_for_vpn_error "$label" vpn_tun_abnormal_close
  require_property last_vpn_fault_event tun_abnormal_close \
    "$RESULT_DIR/s185-status.${label}.properties"
  require_property last_vpn_fault_tun_ready false \
    "$RESULT_DIR/s185-status.${label}.properties"
  require_positive_property last_vpn_fault_infrastructure_faults \
    "$RESULT_DIR/s185-status.${label}.properties"
  kv tun_abnormal_close_fail_closed true
  start_vpn_clean "${label}.recovered"
  local after_generation
  after_generation="$(generation_from_snapshot \
    "$RESULT_DIR/snapshot.${label}.recovered.properties")"
  if ! [[ "$before_generation" =~ ^[0-9]+$ && "$after_generation" =~ ^[0-9]+$ ]] \
      || (( after_generation <= before_generation )); then
    fail_closed "fresh generation did not advance after close_tun"
  fi
  kv close_tun_generation_before "$before_generation"
  kv close_tun_generation_after "$after_generation"
  stop_vpn_clean "${label}.recovered-stopped"
}

run_revoke_case() {
  local label="revoke"
  start_vpn_clean "${label}.before"
  # uses --es runtimeVpnFaultEvent revoke
  start_activity --es runtimeVpnFaultEvent revoke
  wait_for_vpn_error "$label" vpn_authorization_revoked
  kv revoke_fail_closed true
  start_vpn_clean "${label}.recovered-before-race"
  kv revoke_recovered_before_race true
  start_activity --es runtimeVpnFaultEvent revoke
  start_activity --ez runtimeStop true
  wait_for_vpn_inactive "${label}.race-settled"
  kv revoke_stop_start_race_settled true
  sleep 2
  start_vpn_clean "${label}.recovered"
  kv revoke_stop_start_race_recovered true
  stop_vpn_clean "${label}.recovered-stopped"
}

run_native_crash_case() {
  local label="native-crash"
  start_vpn_clean "${label}.before"
  # uses --es runtimeVpnFaultEvent native_crash
  start_activity --es runtimeVpnFaultEvent native_crash
  wait_for_vpn_error "$label" unexpected_exit
  kv native_crash_fail_closed true
  start_vpn_clean "${label}.recovered"
  kv native_crash_recovered true
  stop_vpn_clean "${label}.recovered-stopped"
}

run_force_stop_case() {
  local label="force-stop"
  start_vpn_clean "${label}.before"
  adb_target shell am force-stop "$PACKAGE" >/dev/null
  sleep 2
  start_vpn_clean "${label}.recovered"
  kv user_stop_no_callback_recovered true
}

require_final_status() {
  local file="$1"
  require_property schema s185-vpn-fault-recovery/v1 "$file"
  require_property stage running "$file"
  require_property product.adapter_available 1 "$file"
  require_property protectionRunning true "$file"
  require_positive_property vpn_tun_fd_attached "$file"
  require_positive_property vpn_direct_udp4_socket_attached "$file"
  require_positive_property vpn_direct_udp6_socket_attached "$file"
  require_positive_property vpn_direct_tcp4_socket_attached "$file"
  require_positive_property vpn_direct_tcp6_socket_attached "$file"
  require_positive_property vpn_tun_udp4_tun_origin_packets "$file"
  require_positive_property vpn_tun_udp6_tun_origin_packets "$file"
  require_positive_property vpn_tun_tcp4_tun_origin_packets "$file"
  require_positive_property vpn_tun_tcp6_tun_origin_packets "$file"
  require_positive_property vpn_flow_stack_admissions "$file"
  require_zero_property vpn_direct_udp4_transport_failed "$file"
  require_zero_property vpn_direct_udp6_transport_failed "$file"
  require_zero_property vpn_direct_tcp4_transport_failed "$file"
  require_zero_property vpn_direct_tcp6_transport_failed "$file"
  grep -Fq "policy_verdict_separate=policy_default_pass" "$file" \
    || fail_closed "policy verdict separation evidence missing"
  grep -Fq "transport_outcome_separate=direct_socket_counters" "$file" \
    || fail_closed "transport outcome separation evidence missing"
  grep -Fq "infrastructure_fault_separate=vpn_infrastructure_faults" "$file" \
    || fail_closed "infrastructure fault separation evidence missing"
}

kv acceptance SAKAMOTO-185-vpn-fault-recovery
kv serial "$serial"
kv package "$PACKAGE"
kv host4 "$host4"
kv host6 "$host6"
kv base_port "$base_port"
kv vpn_prepare_authorization_gate checked_by_start_path

"$ADB" devices | tr -d '\r' | grep -Eq "^${serial}[[:space:]]+device$" \
  || fail_closed "controlled Pixel 6a serial is not in adb devices"
adb_target shell getprop ro.product.model | tr -d '\r' > "$RESULT_DIR/device-model.txt"
grep -Fq "Pixel 6a" "$RESULT_DIR/device-model.txt" \
  || fail_closed "connected serial is not the controlled Pixel 6a"
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  >/dev/null 2>&1 || true
app_uid="$(installed_app_uid)"
kv installed_app_uid "$app_uid"

preflight_stop_vpn
cold_start_control_activity
kv preflight_cold_start_settled true
clear_app_files

run_start_fault_case establish-null establish_null vpn_establish_returned_null
run_start_fault_case protect-false protect_false vpn_direct_udp4_protect_failed
run_start_fault_case bind-failed bind_failed vpn_direct_udp4_bind_failed
run_recovery_start_stop after-start-faults
run_close_tun_case
run_revoke_case
run_native_crash_case
run_force_stop_case

run_probe udp4 udp 4 "$host4" "$base_port"
kv installed_app_udp4_source true
run_probe tcp4 tcp 4 "$host4" "$((base_port + 1))"
kv installed_app_tcp4_source true
run_probe udp6 udp 6 "$host6" "$((base_port + 2))"
kv installed_app_udp6_source true
run_probe tcp6 tcp 6 "$host6" "$((base_port + 3))"
kv installed_app_tcp6_source true
kv uid_not_shell true

start_activity --ez debugRefresh true
wait_for_vpn_running final
require_final_status "$RESULT_DIR/s185-status.final.properties"
kv flow_stack_admission_observed true
capture_runtime_log final

stop_vpn_clean final
if adb_target shell run-as "$PACKAGE" test ! -e "$VPN_PROFILE_PATH"; then
  kv final_residue_clean true
else
  fail_closed "VPN Product Core profile residue remains after final stop"
fi

kv result PASS
echo "SAKAMOTO-185 VPN fault recovery: PASS"
