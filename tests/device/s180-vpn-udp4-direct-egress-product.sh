#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-180-vpn-udp4-direct-egress real-device acceptance entry point.
#
# PASS means the installed debug APK starts the VPN Product Core on the
# controlled Pixel 6a, transfers the VpnService TUN fd and one protected
# Direct UDP4 socket fd to Product VPP, sends a VPN-bound UDP nonce through
# TUN -> VPP -> Direct UDP -> controlled LAN, receives the echo, reenters VPP
# with return provenance, writes the reply to TUN, and stops cleanly.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S180_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s180-vpn-udp4-direct-egress}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly STATUS_PATH="files/product-state/s180-vpn-udp4-direct-egress.properties"
readonly PROBE_PATH="files/debug/udp-traffic-probe.properties"

usage() {
  cat <<'EOF'
Usage:
  tests/device/s180-vpn-udp4-direct-egress-product.sh --run --host <controlled-lan-ipv4>

Required:
  --run
  --host / S180_CONTROLLED_LAN_HOST

Optional:
  --serial 28201JEGR0XPAJ
  --port / S180_UDP4_PORT             default 18180
  --timeout-ms / S180_TIMEOUT_MILLIS  default 5000

Before running, the debug APK must already be installed. If Android displays
the VPN authorization dialog, approve it on the Pixel 6a and rerun this
script; VpnService authorization is revocable and cannot be assumed.

Required final evidence:
  adapterReadiness=vpn-tun-hev-lwip
  shell_external_udp_source true
  uid=2000
  files/product-state/s180-vpn-udp4-direct-egress.properties
  vpn_tun_udp4_tun_origin_packets > 0
  vpn_direct_udp4_protect_succeeded > 0
  vpn_direct_udp4_bind_succeeded > 0
  vpn_flow_stack_return_provenance_packets > 0
  vpn_tun_write_completions > 0
  final_residue_clean true
EOF
}

serial="$S180_SERIAL"
run=0
controlled_host="${S180_CONTROLLED_LAN_HOST:-}"
port="${S180_UDP4_PORT:-18180}"
timeout_ms="${S180_TIMEOUT_MILLIS:-5000}"

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
      port="${2:-}"
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

if [[ "$serial" != "$S180_SERIAL" ]]; then
  echo "SAKAMOTO-180 only accepts controlled Pixel 6a serial $S180_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ -z "$controlled_host" ]]; then
  echo "missing --host or S180_CONTROLLED_LAN_HOST" >&2
  usage >&2
  exit 2
fi
if ! [[ "$controlled_host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "controlled host must be an IPv4 literal: $controlled_host" >&2
  exit 2
fi
if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1024 || port > 65535 )); then
  echo "invalid UDP4 port: $port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] || (( timeout_ms < 500 || timeout_ms > 30000 )); then
  echo "invalid timeout ms: $timeout_ms" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
: > "$summary"

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

fail_closed() {
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-180 FAIL: $1" >&2
  exit 1
}

adb_target() {
  "$ADB" -s "$serial" "$@"
}

start_activity() {
  adb_target shell am start -n "$ACTIVITY" "$@" >/dev/null
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null | tr -d '\r' || true
}

clear_app_files() {
  adb_target shell run-as "$PACKAGE" rm -f "$STATE_PATH" "$STATUS_PATH" "$PROBE_PATH" \
    >/dev/null 2>&1 || true
}

wait_app_property() {
  local relative="$1"
  local key="$2"
  local expected="$3"
  local out_file="$4"
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    read_app_file "$relative" > "$out_file"
    if grep -Fq "${key}=${expected}" "$out_file"; then
      return 0
    fi
    sleep 1
  done
  return 1
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

wait_for_host_ready() {
  local ready_file="$1"
  local deadline=$((SECONDS + 10))
  while (( SECONDS < deadline )); do
    if [[ -f "$ready_file" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_udp4_echo_server() {
  local bind_host="$1"
  local listen_port="$2"
  local expected_nonce="$3"
  local ready_file="$4"
  local log_file="$5"
  python3 - "$bind_host" "$listen_port" "$expected_nonce" "$ready_file" "$log_file" \
    <<'PY' >/dev/null 2>&1 &
import pathlib
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
expected = sys.argv[3].encode()
ready = pathlib.Path(sys.argv[4])
log = pathlib.Path(sys.argv[5])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((host, port))
sock.settimeout(30)
ready.write_text("ready\n", encoding="utf-8")
result = "udp_echo_unseen"
peer = ""
request_bytes = 0
response_bytes = 0
try:
    data, address = sock.recvfrom(2048)
    peer = f"{address[0]}:{address[1]}"
    request_bytes = len(data)
    if data == expected:
        sock.sendto(data, address)
        response_bytes = len(data)
        result = "udp_echo_matched"
    else:
        result = "udp_echo_mismatch"
except Exception as error:
    result = f"udp_echo_failed:{error.__class__.__name__}:{error}"
finally:
    sock.close()
    log.write_text(
        f"result={result}\npeer={peer}\nrequestBytes={request_bytes}\n"
        f"responseBytes={response_bytes}\n",
        encoding="utf-8",
    )
PY
  server_pid="$!"
}

shell_single_quote() {
  local value="$1"
  printf "'"
  printf "%s" "$value" | sed "s/'/'\\\\''/g"
  printf "'"
}

run_shell_udp4_echo_probe() {
  local host="$1"
  local listen_port="$2"
  local expected_nonce="$3"
  local timeout_millis="$4"
  local result_file="$5"
  local stdout_file="$RESULT_DIR/device-udp4-probe.stdout"
  local stderr_file="$RESULT_DIR/device-udp4-probe.stderr"
  local timeout_seconds=$(((timeout_millis + 999) / 1000))
  local quoted_nonce
  local remote_command
  local reply
  local result
  local message

  if (( timeout_seconds < 1 )); then
    timeout_seconds=1
  fi
  quoted_nonce="$(shell_single_quote "$expected_nonce")"
  remote_command="printf %s $quoted_nonce | toybox nc -4 -u -W $timeout_seconds -q 1 $host $listen_port"
  if adb_target shell "$remote_command" >"$stdout_file" 2>"$stderr_file"; then
    reply="$(tr -d '\r' <"$stdout_file")"
    if [[ "$reply" == "$expected_nonce" ]]; then
      result="udp_echo_matched"
      message="shell UID UDP echo matched through Product VPN Direct Egress"
    else
      result="udp_echo_mismatch"
      message="shell UID UDP echo mismatch or missing reply"
    fi
  else
    reply="$(tr -d '\r' <"$stdout_file" 2>/dev/null || true)"
    result="udp_echo_failed"
    message="shell UID UDP client failed"
  fi
  {
    printf 'host=%s\n' "$host"
    printf 'port=%s\n' "$listen_port"
    printf 'uid=2000\n'
    printf 'timeoutMillis=%s\n' "$timeout_millis"
    printf 'nonce=%s\n' "$expected_nonce"
    printf 'requestBytes=%s\n' "${#expected_nonce}"
    printf 'responseBytes=%s\n' "${#reply}"
    printf 'shell_external_udp_source=true\n'
    printf 'command=%s\n' "$remote_command"
    printf 'stdoutFile=%s\n' "$stdout_file"
    printf 'stderrFile=%s\n' "$stderr_file"
    printf 'result=%s\n' "$result"
    printf 'message=%s\n' "$message"
  } >"$result_file"
}

kv acceptance SAKAMOTO-180-vpn-udp4-direct-egress
kv serial "$serial"
kv package "$PACKAGE"
kv host "$controlled_host"
kv port "$port"

adb_target get-state >/dev/null || fail_closed "ADB device is not available"
adb_target shell getprop ro.product.model | tr -d '\r' > "$RESULT_DIR/device-model.txt"
if ! grep -Fq "Pixel 6a" "$RESULT_DIR/device-model.txt"; then
  fail_closed "connected serial is not the controlled Pixel 6a"
fi
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  >/dev/null 2>&1 || true

ready_file="$RESULT_DIR/s180.udp4.ready"
server_log="$RESULT_DIR/s180.udp4.server.log"
nonce="s180-${RUN_ID}"

clear_app_files
start_activity --ez runtimeStart true --es runtimeProfile vpn
wait_app_property "$STATE_PATH" adapterReadiness vpn-tun-hev-lwip \
  "$RESULT_DIR/state.running.properties" \
  || fail_closed "VPN Product Core did not publish adapterReadiness=vpn-tun-hev-lwip; approve any VPN dialog and rerun"

rm -f "$ready_file" "$server_log"
server_pid=""
start_udp4_echo_server "0.0.0.0" "$port" "$nonce" "$ready_file" "$server_log"
trap 'kill "$server_pid" >/dev/null 2>&1 || true' EXIT
wait_for_host_ready "$ready_file" || fail_closed "controlled LAN UDP4 server did not become ready"

run_shell_udp4_echo_probe "$controlled_host" "$port" "$nonce" "$timeout_ms" \
  "$RESULT_DIR/device-udp4-probe.properties"
grep -Fq "result=udp_echo_matched" "$RESULT_DIR/device-udp4-probe.properties" \
  || fail_closed "shell UID VPN-bound UDP4 probe did not echo through Product Core"

wait "$server_pid" || true
trap - EXIT
if ! grep -Fq "result=udp_echo_matched" "$server_log"; then
  fail_closed "controlled LAN server did not observe the UDP4 nonce"
fi

start_activity --ez debugRefresh true
wait_app_property "$STATUS_PATH" adapterReadiness vpn-tun-hev-lwip \
  "$RESULT_DIR/s180-status.properties" \
  || fail_closed "S180 status did not publish the VPN adapter state after UDP4 response"

grep -Fq "adapterReadiness=vpn-tun-hev-lwip" "$RESULT_DIR/s180-status.properties" \
  || fail_closed "S180 status missing adapter readiness"
grep -Fq "shell_external_udp_source=true" "$RESULT_DIR/device-udp4-probe.properties" \
  || fail_closed "S180 probe did not use shell UID as external VPN traffic source"
kv shell_external_udp_source true
kv uid 2000
require_positive_property vpn_tun_fd_attached "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_direct_udp4_socket_attached "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_direct_udp4_protect_succeeded "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_direct_udp4_bind_succeeded "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_tun_ingress_packets "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_tun_udp4_tun_origin_packets "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_flow_stack_admissions "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_direct_udp4_send_succeeded "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_flow_stack_return_packets "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_flow_stack_return_provenance_packets "$RESULT_DIR/s180-status.properties"
require_positive_property vpn_tun_write_completions "$RESULT_DIR/s180-status.properties"

start_activity --ez runtimeStop true
wait_app_property "$STATE_PATH" state stopped "$RESULT_DIR/state.stopped.properties" \
  || fail_closed "VPN Product Core did not stop cleanly"
if grep -Fq "mayBeActive=true" "$RESULT_DIR/state.stopped.properties"; then
  fail_closed "stopped state still reports mayBeActive=true"
fi
kv final_residue_clean true
kv result PASS
echo "SAKAMOTO-180 VPN UDP4 Direct Egress: PASS"
