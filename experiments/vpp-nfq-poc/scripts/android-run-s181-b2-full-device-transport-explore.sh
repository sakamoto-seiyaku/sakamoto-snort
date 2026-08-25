#!/usr/bin/env bash
set -euo pipefail

# S181 / B2 full-device transport-failure exploration.
#
# This runner uses the real AppA -> VpnService -> OI3 multi-owner full-device
# route with a WSL2/LAN fixture.  It intentionally does not use the S146/S179
# controlled negative cells.  The TCP closed-port cell is treated as the
# behavior actually observed through Android VPN/OI3: the local proxy can
# complete the TCP handshake, while the underlay destination remains silent
# from the app/native perspective until timeout.  Do not use this cell as a
# real ECONNREFUSED/RST claim unless a deterministic reset fixture is added.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_PACKAGE="${APP_PACKAGE:-com.sakamoto.snort.poc.appa}"
APP_COMPONENT="${APP_COMPONENT:-com.sakamoto.snort.poc.appa/com.sakamoto.snort.a2traffic.TrafficAdapterActivity}"
B1_ACTION="${B1_ACTION:-com.sakamoto.snort.a2traffic.B1_PROBE}"
VPN_MODE="${VPN_MODE:-vpp-oi3-multi}"
ENABLE_IPV6="${ENABLE_IPV6:-false}"
if [[ -z "${SOURCE_PORT_BASE:-}" ]]; then
  SOURCE_PORT_BASE="$((49000 + ($(date +%s) % 1000) * 10))"
fi
POSITIVE_SOURCE_PORT="${POSITIVE_SOURCE_PORT:-$((SOURCE_PORT_BASE + 1))}"
NO_REPLY_SOURCE_PORT="${NO_REPLY_SOURCE_PORT:-$((SOURCE_PORT_BASE + 2))}"
TCP_TIMEOUT_SOURCE_PORT="${TCP_TIMEOUT_SOURCE_PORT:-${REFUSED_SOURCE_PORT:-$((SOURCE_PORT_BASE + 3))}}"
POLICY_DROP_SOURCE_PORT="${POLICY_DROP_SOURCE_PORT:-$((SOURCE_PORT_BASE + 4))}"
UID_DROP_SOURCE_PORT="${UID_DROP_SOURCE_PORT:-$((SOURCE_PORT_BASE + 5))}"
B1_TIMEOUT_MS="${B1_TIMEOUT_MS:-2500}"
B1_PAYLOAD_HEX="${B1_PAYLOAD_HEX:-123401000001000000000000076578616d706c6503636f6d0000010001}"
FIXTURE_HOST="${FIXTURE_HOST:-}"
FIXTURE_BIND_HOST="${FIXTURE_BIND_HOST:-0.0.0.0}"
POSITIVE_PORT="${POSITIVE_PORT:-53541}"
NO_REPLY_PORT="${NO_REPLY_PORT:-53542}"
TCP_TIMEOUT_PORT="${TCP_TIMEOUT_PORT:-${REFUSED_PORT:-53543}}"
TCP_EXPECTED_FAILURE="${TCP_EXPECTED_FAILURE:-}"
POLICY_DROP_PORT="${POLICY_DROP_PORT:-53544}"
UID_DROP_PORT="${UID_DROP_PORT:-53545}"
INCLUDE_POLICY_DROP="${INCLUDE_POLICY_DROP:-false}"
INCLUDE_UID_DROP="${INCLUDE_UID_DROP:-false}"
INCLUDE_NO_REPLY="${INCLUDE_NO_REPLY:-true}"
INCLUDE_TCP_TIMEOUT="${INCLUDE_TCP_TIMEOUT:-true}"
STAGE_PREFIX="${STAGE_PREFIX:-S181}"
RUNNER_TITLE="${RUNNER_TITLE:-S181 B2 full-device transport-failure exploration}"
RUNNER_NAME="${RUNNER_NAME:-android-run-s181-b2-full-device-transport-explore.sh}"
RUNNER_SCHEMA="${RUNNER_SCHEMA:-s181-b2-full-device-transport-explore/v1}"
RUNNER_SCOPE="${RUNNER_SCOPE:-bounded_full_device_b2_transport_failure_exploration}"
RUNNER_CLAIM_BOUNDARY="${RUNNER_CLAIM_BOUNDARY:-}"
RUNNER_NON_CLAIM="${RUNNER_NON_CLAIM:-}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s181-b2-full-device-transport-explore-$(date +%Y%m%d)}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
APP_APK="${APP_APK:-$POC_DIR/android/a2-traffic-adapter/build/outputs/com-sakamoto-snort-poc-appa-debug.apk}"
WAIT_VPP_READY_ATTEMPTS="${WAIT_VPP_READY_ATTEMPTS:-120}"
WAIT_B1_RECORD_ATTEMPTS="${WAIT_B1_RECORD_ATTEMPTS:-80}"
WAIT_STOP_CLEANUP_ATTEMPTS="${WAIT_STOP_CLEANUP_ATTEMPTS:-28}"
POST_B1_NATIVE_SETTLE_SECONDS="${POST_B1_NATIVE_SETTLE_SECONDS:-5}"
REMOTE_LOG_TAIL_LINES="${REMOTE_LOG_TAIL_LINES:-2400}"
ADB_READ_RETRY_ATTEMPTS="${ADB_READ_RETRY_ATTEMPTS:-3}"
ADB_READ_RETRY_DELAY_SECONDS="${ADB_READ_RETRY_DELAY_SECONDS:-1}"
START_VPN_RETRY_ATTEMPTS="${START_VPN_RETRY_ATTEMPTS:-3}"
START_VPN_RETRY_DELAY_SECONDS="${START_VPN_RETRY_DELAY_SECONDS:-1}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/cells"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$(date +%s%N | tail -c 7)"
RUN_LOG="$RESULT_DIR/run-$RUN_ID.log"
CSV="$RESULT_DIR/cells-$RUN_ID.csv"
MANIFEST="$RESULT_DIR/run-$RUN_ID-manifest.json"
VALIDITY="$RESULT_DIR/run-validity-$RUN_ID.txt"
CELL_ROOT="$RESULT_DIR/cells/$RUN_ID"
FIXTURE_SCRIPT="$RESULT_DIR/s181_transport_fixture.py"
FIXTURE_LOG="$RESULT_DIR/fixture-$RUN_ID.log"
mkdir -p "$CELL_ROOT"

VPN_FILES="/data/user/0/$VPN_PACKAGE/files"
VPN_LOGS="$VPN_FILES/vpp/logs"
APP_FILES="/data/user/0/$APP_PACKAGE/files"
APP_B1_LOG="$APP_FILES/debug/b1-runtime.jsonl"
REMOTE_UID_CONTRACT_LOG="$VPN_FILES/logs/uid-attribution-contract.jsonl"
REMOTE_VPN_SESSION="$VPN_FILES/vpn-session-provenance.json"
REMOTE_VPP_START="$VPN_FILES/vpp/runtime/vpp-start-provenance.json"
REMOTE_CLI_LOG="$VPN_LOGS/vpp-cli.log"
REMOTE_STDOUT_LOG="$VPN_LOGS/vpp-stdout.log"
REMOTE_HEV_LOG="$VPN_LOGS/vpp-hev.log"
REMOTE_PROTECT_LOG="$VPN_LOGS/vpp-protect.log"
REMOTE_OI3_BROKER_LOG="$VPN_LOGS/vpp-oi3-broker.log"
REMOTE_OWNER_GATE_LOG="$VPN_LOGS/vpp-owner-gate.log"

FIXTURE_PID=""
exec > >(tee "$RUN_LOG") 2>&1

adb_read_once() {
  adb_su "$1" | tr -d '\r'
}

adb_read() {
  local command="$1" attempt rc output had_errexit=0
  for attempt in $(seq 1 "$ADB_READ_RETRY_ATTEMPTS"); do
    case $- in *e*) had_errexit=1 ;; *) had_errexit=0 ;; esac
    set +e
    output="$(adb_read_once "$command" 2>&1)"
    rc=$?
    if [[ "$had_errexit" == 1 ]]; then
      set -e
    fi
    if [[ "$rc" == 0 ]]; then
      printf '%s\n' "$output"
      return 0
    fi
    if [[ "$attempt" -lt "$ADB_READ_RETRY_ATTEMPTS" ]]; then
      echo "adb_read retry attempt=$attempt rc=$rc command=$command" >&2
      sleep "$ADB_READ_RETRY_DELAY_SECONDS"
    fi
  done
  printf '%s\n' "$output" >&2
  return "$rc"
}

wait_stop_cleanup_marker() {
  local marker=""
  for _ in $(seq 1 "$WAIT_STOP_CLEANUP_ATTEMPTS"); do
    marker="$(adb_read "for f in '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG'; do if [ -f \"\$f\" ]; then tail -n 120 \"\$f\" 2>/dev/null | grep -E 'oi3_cleanup result=' || true; fi; done | tail -n 1")"
    if [[ -n "$marker" ]]; then
      return 0
    fi
    if [[ -z "$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")" ]]; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

stop_vpn() {
  adb_cmd shell am start -W -n "$VPN_PACKAGE/.MainActivity" --ez stop true \
    >/dev/null 2>&1 || true
  wait_stop_cleanup_marker || true
  adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
  sleep 1
}

cleanup() {
  stop_vpn
  if [[ -n "$FIXTURE_PID" ]]; then
    kill "$FIXTURE_PID" >/dev/null 2>&1 || true
    wait "$FIXTURE_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

effective_claim_boundary() {
  if [[ -n "$RUNNER_CLAIM_BOUNDARY" ]]; then
    printf '%s\n' "$RUNNER_CLAIM_BOUNDARY"
  elif [[ "$INCLUDE_UID_DROP" == "true" ]]; then
    printf '%s\n' "WSL2-LAN-fixture-real-per-App-UID-drop-via-native-TUN-gate-before-OI3-multi-broker-socket"
  elif [[ "$INCLUDE_POLICY_DROP" == "true" ]]; then
    printf '%s\n' "WSL2-LAN-fixture-real-no-reply-tcp-timeout-and-policy-drop-exploration"
  else
    printf '%s\n' "WSL2-LAN-fixture-real-no-reply-and-tcp-timeout-exploration-not-policy-drop-closure"
  fi
}

effective_non_claim() {
  if [[ -n "$RUNNER_NON_CLAIM" ]]; then
    printf '%s\n' "$RUNNER_NON_CLAIM"
  elif [[ "$INCLUDE_UID_DROP" == "true" ]]; then
    printf '%s\n' "not VPP-internal UID policy, not lifecycle/cache convergence closure, not IPv6, not public internet, not long soak/performance"
  elif [[ "$INCLUDE_POLICY_DROP" == "true" ]]; then
    printf '%s\n' "not per-App UID drop, not IPv6, not public internet, not long soak/performance"
  else
    printf '%s\n' "not policy-drop closure, not IPv6, not public internet, not long soak/performance"
  fi
}

discover_fixture_host() {
  if [[ -n "$FIXTURE_HOST" ]]; then
    printf '%s\n' "$FIXTURE_HOST"
    return 0
  fi
  ip -4 route get 1.1.1.1 2>/dev/null \
    | sed -n 's/.* src \([0-9.][0-9.]*\).*/\1/p' | head -n 1
}

write_fixture_script() {
  cat >"$FIXTURE_SCRIPT" <<'PY'
#!/usr/bin/env python3
import json
import socket
import sys
import threading
import time

bind_host = sys.argv[1]
positive_port = int(sys.argv[2])
no_reply_port = int(sys.argv[3])
tcp_timeout_port = int(sys.argv[4])
policy_drop_port = int(sys.argv[5])
uid_drop_port = int(sys.argv[6])
include_policy_drop = sys.argv[7].lower() == "true"
include_uid_drop = sys.argv[8].lower() == "true"
log_path = sys.argv[9]

def log(event, **fields):
    fields["event"] = event
    fields["monotonic_ns"] = time.monotonic_ns()
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(fields, sort_keys=True) + "\n")
        handle.flush()

def question(query):
    if len(query) < 12:
        return b""
    offset = 12
    while offset < len(query):
        length = query[offset]
        offset += 1
        if length == 0:
            break
        offset += length
    return query[12:min(len(query), offset + 4)]

def full_response(query):
    qid = query[:2] if len(query) >= 2 else b"\x00\x00"
    q = question(query)
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"
    return qid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q + answer

def udp_positive_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, positive_port))
    log("positive_udp_ready", bind_host=bind_host, port=positive_port)
    while True:
        query, addr = sock.recvfrom(4096)
        log("positive_udp_query", peer=f"{addr[0]}:{addr[1]}",
            port=positive_port, length=len(query), query_id=query[:2].hex())
        response = full_response(query)
        sock.sendto(response, addr)
        log("positive_udp_response", peer=f"{addr[0]}:{addr[1]}",
            port=positive_port, length=len(response), query_id=query[:2].hex())

def udp_no_reply_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, no_reply_port))
    log("no_reply_udp_ready", bind_host=bind_host, port=no_reply_port)
    while True:
        query, addr = sock.recvfrom(4096)
        log("no_reply_udp_query", peer=f"{addr[0]}:{addr[1]}",
            port=no_reply_port, length=len(query), query_id=query[:2].hex())

def udp_policy_drop_observer_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, policy_drop_port))
    log("policy_drop_udp_ready", bind_host=bind_host, port=policy_drop_port)
    while True:
        query, addr = sock.recvfrom(4096)
        log("policy_drop_udp_query", peer=f"{addr[0]}:{addr[1]}",
            port=policy_drop_port, length=len(query), query_id=query[:2].hex())

def udp_uid_drop_observer_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, uid_drop_port))
    log("uid_drop_udp_ready", bind_host=bind_host, port=uid_drop_port)
    while True:
        query, addr = sock.recvfrom(4096)
        log("uid_drop_udp_query", peer=f"{addr[0]}:{addr[1]}",
            port=uid_drop_port, length=len(query), query_id=query[:2].hex())

def assert_tcp_timeout_port_is_unbound():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_host, tcp_timeout_port))
        log("tcp_timeout_port_unbound", bind_host=bind_host, port=tcp_timeout_port)
    finally:
        sock.close()

assert_tcp_timeout_port_is_unbound()
threading.Thread(target=udp_positive_loop, daemon=True).start()
threading.Thread(target=udp_no_reply_loop, daemon=True).start()
if include_policy_drop:
    threading.Thread(target=udp_policy_drop_observer_loop, daemon=True).start()
if include_uid_drop:
    threading.Thread(target=udp_uid_drop_observer_loop, daemon=True).start()
while True:
    time.sleep(3600)
PY
  chmod +x "$FIXTURE_SCRIPT"
}

wait_fixture_ready() {
  for _ in $(seq 1 80); do
    if grep -q '"event": "positive_udp_ready"' "$FIXTURE_LOG" 2>/dev/null \
        && grep -q '"event": "no_reply_udp_ready"' "$FIXTURE_LOG" 2>/dev/null \
        && grep -q '"event": "tcp_timeout_port_unbound"' "$FIXTURE_LOG" 2>/dev/null; then
      if [[ "$INCLUDE_POLICY_DROP" != "true" ]] \
          || grep -q '"event": "policy_drop_udp_ready"' "$FIXTURE_LOG" 2>/dev/null; then
        if [[ "$INCLUDE_UID_DROP" != "true" ]] \
            || grep -q '"event": "uid_drop_udp_ready"' "$FIXTURE_LOG" 2>/dev/null; then
          return 0
        fi
      fi
    fi
    sleep 0.25
  done
  return 1
}

package_uid() {
  local package="$1"
  adb_read "cmd package list packages -U 2>/dev/null | sed -n 's#^package:$package uid:\\([0-9][0-9]*\\).*#\\1#p' | head -n 1" \
    | tr -d '\n'
}

installed_apk_path() {
  local package="$1"
  adb_read "pm path '$package' | sed -n 's#^package:\\(.*\\)/base.apk\$#\\1/base.apk#p' | head -n 1" \
    | tr -d '\n'
}

apk_member_sha256() {
  local apk="$1" member="$2"
  unzip -p "$apk" "$member" | sha256sum | awk '{print $1}'
}

capture_remote_tail() {
  local remote_path="$1" local_path="$2"
  adb_read "if [ -f '$remote_path' ]; then tail -n '$REMOTE_LOG_TAIL_LINES' '$remote_path' 2>/dev/null; fi" \
    >"$local_path"
}

capture_remote_json() {
  local remote_path="$1" local_path="$2"
  adb_read "if [ -f '$remote_path' ]; then cat '$remote_path' 2>/dev/null; fi" \
    >"$local_path"
}

capture_cell_common() {
  local cell_dir="$1"
  capture_remote_json "$REMOTE_VPN_SESSION" "$cell_dir/vpn-session-provenance.json"
  capture_remote_json "$REMOTE_VPP_START" "$cell_dir/vpp-start-provenance.json"
  capture_remote_json "$APP_B1_LOG" "$cell_dir/app-b1-runtime.jsonl"
  capture_remote_json "$REMOTE_UID_CONTRACT_LOG" "$cell_dir/uid-attribution-contract.jsonl"
  capture_remote_tail "$REMOTE_CLI_LOG" "$cell_dir/vpp-cli.log"
  capture_remote_tail "$REMOTE_STDOUT_LOG" "$cell_dir/vpp-stdout.log"
  capture_remote_tail "$REMOTE_HEV_LOG" "$cell_dir/vpp-hev.log"
  capture_remote_tail "$REMOTE_PROTECT_LOG" "$cell_dir/vpp-protect.log"
  capture_remote_tail "$REMOTE_OI3_BROKER_LOG" "$cell_dir/vpp-oi3-broker.log"
  capture_remote_tail "$REMOTE_OWNER_GATE_LOG" "$cell_dir/vpp-owner-gate.log"
  {
    cat "$cell_dir/vpp-stdout.log" 2>/dev/null || true
    cat "$cell_dir/vpp-cli.log" 2>/dev/null || true
    cat "$cell_dir/vpp-oi3-broker.log" 2>/dev/null || true
    cat "$cell_dir/vpp-owner-gate.log" 2>/dev/null || true
  } >"$cell_dir/native-combined.log"
  adb_read 'dumpsys connectivity 2>/dev/null || true' >"$cell_dir/connectivity.txt"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I S139A2Traffic:I '*:S' \
    | tr -d '\r' >"$cell_dir/logcat.txt" || true
}

wait_vpp_ready() {
  local vpp_pid="" oi3_line=""
  for _ in $(seq 1 "$WAIT_VPP_READY_ATTEMPTS"); do
    vpp_pid="$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")"
    oi3_line="$(adb_read "for f in '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG'; do if [ -f \"\$f\" ]; then tail -n 80 \"\$f\" 2>/dev/null | grep -E 'oi4 multi enabled|oi3 multi enabled|show plugins' || true; fi; done | tail -n 12")"
    if [[ -n "$vpp_pid" && "$oi3_line" == *"owners=4"* ]]; then
      printf '%s\n' "$vpp_pid"
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_b1_record() {
  local stage="$1"
  for _ in $(seq 1 "$WAIT_B1_RECORD_ATTEMPTS"); do
    if adb_read "if [ -f '$APP_B1_LOG' ]; then tail -n 20 '$APP_B1_LOG' 2>/dev/null; fi" \
      | grep -Fq "\"stage_id\":\"$stage\""; then
      return 0
    fi
    sleep 1
  done
  return 1
}

write_run_provenance() {
  local vpn_uid="$1" app_uid="$2" vpn_installed app_installed
  vpn_installed="$(installed_apk_path "$VPN_PACKAGE")"
  app_installed="$(installed_apk_path "$APP_PACKAGE")"
  {
    printf 'package\tuid\thost_apk\thost_sha256\tinstalled_path\tinstalled_sha256\n'
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$VPN_PACKAGE" "$vpn_uid" "$APK" "$(sha256sum "$APK" | awk '{print $1}')" \
      "$vpn_installed" "$(adb_read "sha256sum '$vpn_installed' 2>/dev/null | awk '{print \$1}'")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$APP_PACKAGE" "$app_uid" "$APP_APK" "$(sha256sum "$APP_APK" | awk '{print $1}')" \
      "$app_installed" "$(adb_read "sha256sum '$app_installed' 2>/dev/null | awk '{print \$1}'")"
    printf 'vpn_member_plugin_sha256\t%s\n' \
      "$(apk_member_sha256 "$APK" "lib/arm64-v8a/libhev_external_driver_poc_plugin.so")"
    printf 'vpn_member_plugin_compat_sha256\t%s\n' \
      "$(apk_member_sha256 "$APK" "lib/arm64-v8a/hev_external_driver_poc_plugin.so")"
    printf 'vpn_member_hev_sha256\t%s\n' \
      "$(apk_member_sha256 "$APK" "lib/arm64-v8a/libhev-socks5-tunnel.so")"
  } >"$RESULT_DIR/apk-provenance.tsv"
  {
    echo "adb_serial=$(adb_target_desc)"
    echo "device_model=$(adb_read 'getprop ro.product.model')"
    echo "device_fingerprint=$(adb_read 'getprop ro.build.fingerprint')"
    echo "android_release=$(adb_read 'getprop ro.build.version.release')"
    echo "android_sdk=$(adb_read 'getprop ro.build.version.sdk')"
  } >"$RESULT_DIR/device-build.properties"
  {
    echo "run_id=$RUN_ID"
    echo "git_revision=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "runner=$RUNNER_NAME"
    echo "scope=$RUNNER_SCOPE"
    echo "vpn_mode=$VPN_MODE"
    echo "allowed_package=$APP_PACKAGE"
    echo "fixture_host=$FIXTURE_HOST"
    echo "positive_port=$POSITIVE_PORT"
    echo "no_reply_port=$NO_REPLY_PORT"
    echo "tcp_timeout_port=$TCP_TIMEOUT_PORT"
    echo "tcp_expected_failure=$TCP_EXPECTED_FAILURE"
    echo "policy_drop_port=$POLICY_DROP_PORT"
    echo "uid_drop_port=$UID_DROP_PORT"
    echo "include_policy_drop=$INCLUDE_POLICY_DROP"
    echo "include_uid_drop=$INCLUDE_UID_DROP"
    echo "include_no_reply=$INCLUDE_NO_REPLY"
    echo "include_tcp_timeout=$INCLUDE_TCP_TIMEOUT"
    echo "claim_boundary=$(effective_claim_boundary)"
  } >"$RESULT_DIR/source-provenance.properties"
}

start_vpn_for_cell() {
  local cell_dir="$1" expected_failure="${2:-}" block_ip4_dst="${3:-}" block_owner_uid="${4:-}"
  local args=(
    shell am start -W -n "$VPN_PACKAGE/.MainActivity"
    --ez start true --es mode "$VPN_MODE" --es allowedPackage "$APP_PACKAGE"
    --ez enableIpv6 "$ENABLE_IPV6"
  )
  if [[ -n "$expected_failure" ]]; then
    args+=(--es oi3ExpectedFailure "$expected_failure")
  fi
  if [[ -n "$block_ip4_dst" ]]; then
    args+=(--es blockIp4Dst "$block_ip4_dst")
  fi
  if [[ -n "$block_owner_uid" ]]; then
    args+=(--ei blockOwnerUid "$block_owner_uid")
  fi
  local attempt rc=1
  : >"$cell_dir/start.txt"
  for attempt in $(seq 1 "$START_VPN_RETRY_ATTEMPTS"); do
    set +e
    adb_cmd "${args[@]}" >"$cell_dir/start-attempt-$attempt.txt" 2>&1
    rc=$?
    set -e
    {
      echo "## attempt=$attempt rc=$rc"
      cat "$cell_dir/start-attempt-$attempt.txt"
    } >>"$cell_dir/start.txt"
    if [[ "$rc" == 0 ]]; then
      printf '%s\n' "$rc"
      return 0
    fi
    if [[ "$attempt" -lt "$START_VPN_RETRY_ATTEMPTS" ]]; then
      echo "start_vpn retry attempt=$attempt rc=$rc" >&2
      sleep "$START_VPN_RETRY_DELAY_SECONDS"
    fi
  done
  printf '%s\n' "$rc"
}

run_b1_intent() {
  local cell="$1" stage="$2" protocol="$3" dns="$4" source_port="$5" destination_port="$6" cell_dir="$7"
  local args=(
    shell am start -W -n "$APP_COMPONENT" -a "$B1_ACTION"
    --es b1StageId "$stage"
    --es b1Family ip4
    --es b1Protocol "$protocol"
    --ei b1SourcePort "$source_port"
    --es b1DestinationHost "$FIXTURE_HOST"
    --ei b1DestinationPort "$destination_port"
    --ei b1TimeoutMillis "$B1_TIMEOUT_MS"
    --ez b1Dns "$dns"
    --es b1PayloadHex "$B1_PAYLOAD_HEX"
    --es b1TcpWriteMode coalesced
  )
  set +e
  adb_cmd "${args[@]}" >"$cell_dir/b1-intent-$cell.txt" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "$rc"
}

run_cell() {
  local cell="$1" protocol="$2" dns="$3" source_port="$4" destination_port="$5" expected_failure="${6:-}" block_ip4_dst="${7:-}" block_owner_uid="${8:-}"
  local stage="$STAGE_PREFIX-$cell"
  local cell_dir="$CELL_ROOT/$cell"
  mkdir -p "$cell_dir"
  echo "cell=$cell stage=$stage protocol=$protocol dns=$dns source=$source_port destination=$FIXTURE_HOST:$destination_port expected_failure=$expected_failure block_ip4_dst=$block_ip4_dst block_owner_uid=$block_owner_uid"
  stop_vpn
  adb_cmd shell am force-stop "$APP_PACKAGE" >/dev/null 2>&1 || true
  adb_read "rm -f '$APP_B1_LOG' '$REMOTE_UID_CONTRACT_LOG' '$REMOTE_VPN_SESSION' '$REMOTE_VPP_START' '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG' '$REMOTE_OI3_BROKER_LOG' '$REMOTE_OWNER_GATE_LOG'"
  adb_read "ps -A -o USER,PID,PPID,RSS,NAME,ARGS 2>/dev/null || ps -A" >"$cell_dir/processes-before.txt"
  adb_cmd logcat -c >/dev/null 2>&1 || true
  local start_rc intent_rc vpp_pid residual_vpp tun0_text tun0_after
  start_rc="$(start_vpn_for_cell "$cell_dir" "$expected_failure" "$block_ip4_dst" "$block_owner_uid")"
  vpp_pid="$(wait_vpp_ready || true)"
  if [[ -z "$vpp_pid" ]]; then
    echo "cell=$cell INVALID: VPP/OI3 four-owner startup not proven" >&2
  fi
  sleep 1
  intent_rc="$(run_b1_intent "$cell" "$stage" "$protocol" "$dns" "$source_port" "$destination_port" "$cell_dir")"
  wait_b1_record "$stage" || echo "cell=$cell B1 record wait timed out" >&2
  sleep "$POST_B1_NATIVE_SETTLE_SECONDS"
  capture_cell_common "$cell_dir"
  stop_vpn
  residual_vpp="$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'" | tr -d '\n')"
  tun0_text="$(adb_read "ip link show tun0 2>/dev/null || true")"
  printf '%s\n' "$tun0_text" >"$cell_dir/tun0-after.txt"
  tun0_after=0
  if [[ "$tun0_text" == *"tun0:"* ]]; then
    tun0_after=1
  fi
  adb_read "ps -A -o USER,PID,PPID,RSS,NAME,ARGS 2>/dev/null || ps -A" >"$cell_dir/processes-after-stop.txt"
  {
    echo "cell=$cell"
    echo "stage=$stage"
    echo "protocol=$protocol"
    echo "dns=$dns"
    echo "source_port=$source_port"
    echo "destination_port=$destination_port"
    echo "expected_failure=$expected_failure"
    echo "block_ip4_dst=$block_ip4_dst"
    echo "block_owner_uid=$block_owner_uid"
    echo "start_rc=$start_rc"
    echo "intent_rc=$intent_rc"
    echo "residual_vpp=$residual_vpp"
    echo "tun0_after=$tun0_after"
  } >"$cell_dir/cell.properties"
}

summarize_all() {
  python3 - "$RUN_ID" "$CELL_ROOT" "$FIXTURE_LOG" "$CSV" "$MANIFEST" "$VALIDITY" \
    "$APK" "$APP_APK" "$VPN_PACKAGE" "$APP_PACKAGE" "$FIXTURE_HOST" \
    "$POSITIVE_PORT" "$NO_REPLY_PORT" "$TCP_TIMEOUT_PORT" \
    "$INCLUDE_POLICY_DROP" "$POLICY_DROP_PORT" \
    "$INCLUDE_UID_DROP" "$UID_DROP_PORT" \
    "$INCLUDE_NO_REPLY" "$INCLUDE_TCP_TIMEOUT" "$TCP_EXPECTED_FAILURE" \
    "$STAGE_PREFIX" "$RUNNER_SCHEMA" "$RUNNER_SCOPE" \
    "$(effective_claim_boundary)" "$(effective_non_claim)" <<'PY'
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

run_id = sys.argv[1]
cell_root = Path(sys.argv[2])
fixture_log = Path(sys.argv[3])
csv_path = Path(sys.argv[4])
manifest_path = Path(sys.argv[5])
validity_path = Path(sys.argv[6])
apk = Path(sys.argv[7])
app_apk = Path(sys.argv[8])
vpn_package = sys.argv[9]
app_package = sys.argv[10]
fixture_host = sys.argv[11]
positive_port = int(sys.argv[12])
no_reply_port = int(sys.argv[13])
tcp_timeout_port = int(sys.argv[14])
include_policy_drop = sys.argv[15].lower() == "true"
policy_drop_port = int(sys.argv[16])
include_uid_drop = sys.argv[17].lower() == "true"
uid_drop_port = int(sys.argv[18])
include_no_reply = sys.argv[19].lower() == "true"
include_tcp_timeout = sys.argv[20].lower() == "true"
tcp_expected_failure = sys.argv[21]
stage_prefix = sys.argv[22]
runner_schema = sys.argv[23]
runner_scope = sys.argv[24]
claim_boundary = sys.argv[25]
non_claim = sys.argv[26]

fixture_events = []
if fixture_log.exists():
    for line in fixture_log.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            fixture_events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

def read_props(path):
    out = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                out[k] = v
    return out

def last_app_record(cell_dir, stage):
    path = cell_dir / "app-b1-runtime.jsonl"
    records = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("stage_id") == stage:
                records.append(item)
    return records[-1] if records else {}

def native_stats(cell_dir):
    text = ""
    for name in ("native-combined.log", "vpp-stdout.log", "vpp-cli.log",
                 "vpp-oi3-broker.log", "vpp-owner-gate.log"):
        path = cell_dir / name
        if path.exists():
            text += "\n" + path.read_text(encoding="utf-8", errors="replace")
    cleanup = re.findall(r"oi3_cleanup result=([^ ]+) outcome=([^ ]+).*", text)
    cleanup_results = ",".join(item[0] for item in cleanup)
    cleanup_outcomes = ",".join(item[1] for item in cleanup)
    cleanup_last = cleanup[-1] if cleanup else ("", "")
    transport_failures = 0
    infrastructure_failures = 0
    direct_cleanup = 0
    output_cleanup = 0
    handshake_cleanup = 0
    rewritten_cleanup = 0
    for line in re.findall(r"oi3_cleanup result=.*", text):
        for key, target in [
            ("transport-failures", "transport_failures"),
            ("infrastructure-failures", "infrastructure_failures"),
            ("direct", "direct_cleanup"),
            ("output", "output_cleanup"),
            ("handshake", "handshake_cleanup"),
            ("rewritten", "rewritten_cleanup"),
        ]:
            match = re.search(key + r"=([0-9]+)", line)
            if match:
                value = int(match.group(1))
                if target == "transport_failures":
                    transport_failures = max(transport_failures, value)
                elif target == "infrastructure_failures":
                    infrastructure_failures = max(infrastructure_failures, value)
                elif target == "direct_cleanup":
                    direct_cleanup = max(direct_cleanup, value)
                elif target == "output_cleanup":
                    output_cleanup = max(output_cleanup, value)
                elif target == "handshake_cleanup":
                    handshake_cleanup = max(handshake_cleanup, value)
                elif target == "rewritten_cleanup":
                    rewritten_cleanup = max(rewritten_cleanup, value)
    return {
        "broker_success": len(re.findall(r"\boi3 broker-completion result=SUCCESS", text)),
        "tun_output": len(re.findall(r"\boi3 tun-output length=[1-9][0-9]* result=OK", text)),
        "direct_send": len(re.findall(r"\boi3 direct-send length=[1-9][0-9]*", text)),
        "cleanup_results": cleanup_results,
        "cleanup_outcomes": cleanup_outcomes,
        "cleanup_last_result": cleanup_last[0],
        "cleanup_last_outcome": cleanup_last[1],
        "cleanup_fail": int("result=FAIL" in text),
        "cleanup_passish": int(any(result.startswith("PASS") for result, _ in cleanup)),
        "ambient_timeout": int("oi3 ambient transport outcome=EXPECTED_TIMEOUT" in text),
        "policy_drop": int("oi4 multi-policy-drop result=DROP" in text),
        "gate_uid_drop": len(re.findall(r"\bgate drop packet=.*ownerUid=[0-9]+", text)),
        "gate_forward": len(re.findall(r"\bgate forward packet=", text)),
        "gate_started": int("gate start tun-fd=" in text),
        "transport_refusal": int("transport-refusal" in text or "connector-so-error" in text),
        # native-combined.log intentionally mirrors vpp-stdout.log.  These
        # are presence markers; exact-once is asserted by the owner cleanup
        # counters below, so counting both files creates a false duplicate.
        "transport_reset": int(re.search(
            r"\boi3 transport-event result=(?:READ_ERROR|WRITE_ERROR) "
            r"errno=104 .*reset-observed=1", text) is not None),
        "downstream_reset": int(re.search(
            r"\boi3 downstream-transport result=RST .*reset-observed=1", text)
            is not None),
        "transport_failures": transport_failures,
        "infrastructure_failures": infrastructure_failures,
        "direct_cleanup": direct_cleanup,
        "output_cleanup": output_cleanup,
        "handshake_cleanup": handshake_cleanup,
        "rewritten_cleanup": rewritten_cleanup,
    }

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

rows = []
cell_names = ["positive-udp-dns"]
if include_no_reply:
    cell_names.append("no-reply-udp-dns")
if include_tcp_timeout:
    cell_names.append("closed-tcp-timeout")
if include_policy_drop:
    cell_names.append("policy-drop-udp-dns")
if include_uid_drop:
    cell_names.append("uid-drop-udp-dns")
for cell in cell_names:
    cell_dir = cell_root / cell
    props = read_props(cell_dir / "cell.properties")
    stage = props.get("stage", f"{stage_prefix}-{cell}")
    record = last_app_record(cell_dir, stage)
    stats = native_stats(cell_dir)
    vpn_prov = int((cell_dir / "vpn-session-provenance.json").exists()
                   and (cell_dir / "vpn-session-provenance.json").stat().st_size > 0)
    vpp_prov = int((cell_dir / "vpp-start-provenance.json").exists()
                   and (cell_dir / "vpp-start-provenance.json").stat().st_size > 0)
    start_rc = int(props.get("start_rc", "99"))
    intent_rc = int(props.get("intent_rc", "99"))
    residual_vpp = props.get("residual_vpp", "")
    tun0_after = int(props.get("tun0_after", "1"))
    startup_valid = int(start_rc == 0 and intent_rc == 0 and vpn_prov and vpp_prov)
    residue_valid = int(residual_vpp == "" and tun0_after == 0)
    fixture_valid = 0
    app_valid = 0
    native_expected = 0
    native_observed = 0
    design_gap = ""
    if cell == "positive-udp-dns":
        fixture_valid = int(
            any(e.get("event") == "positive_udp_query" and e.get("port") == positive_port
                for e in fixture_events)
            and any(e.get("event") == "positive_udp_response" and e.get("port") == positive_port
                    for e in fixture_events)
        )
        app_valid = int(record.get("send_connect_outcome") == "udp_datagram_sent"
                        and record.get("return_outcome") == "dns_response_received"
                        and record.get("response_valid") is True)
        native_observed = int(stats["broker_success"] >= 1
                              and stats["tun_output"] >= 1
                              and stats["direct_send"] >= 1)
        native_expected = int(native_observed and stats["cleanup_fail"] == 0)
    elif cell == "no-reply-udp-dns":
        fixture_valid = int(
            any(e.get("event") == "no_reply_udp_query" and e.get("port") == no_reply_port
                for e in fixture_events)
        )
        app_valid = int(record.get("send_connect_outcome") == "udp_datagram_sent"
                        and record.get("return_outcome") == "dns_response_timeout"
                        and record.get("tuple_attempted") is True)
        native_observed = int(stats["broker_success"] >= 1
                              and stats["direct_send"] >= 1
                              and stats["transport_failures"] == 0
                              and stats["infrastructure_failures"] == 0)
        native_expected = int(native_observed and stats["cleanup_fail"] == 0
                              and ("EXPECTED_REAL_NO_REPLY"
                                   in stats["cleanup_outcomes"]))
        if app_valid and fixture_valid and native_observed and not native_expected:
            design_gap = "native-positive-cleanup-cannot-express-real-udp-no-reply"
    elif cell == "closed-tcp-timeout":
        fixture_valid = int(
            any(e.get("event") == "tcp_timeout_port_unbound" and e.get("port") == tcp_timeout_port
                for e in fixture_events)
        )
        if tcp_expected_failure == "real-reset":
            app_valid = int(record.get("protocol") == "tcp"
                            and record.get("dns") is True
                            and record.get("send_connect_outcome")
                            in ("tcp_connect_succeeded", "tcp_payload_sent")
                            and record.get("return_outcome") == "dns_response_reset"
                            and record.get("tuple_attempted") is True)
            native_observed = int(stats["broker_success"] >= 1
                                  and stats["direct_send"] >= 1
                                  and stats["output_cleanup"] >= 3
                                  and stats["handshake_cleanup"] >= 1
                                  and stats["rewritten_cleanup"] >= 3
                                  and stats["direct_cleanup"] >= 1
                                  and stats["transport_reset"] == 1
                                  and stats["downstream_reset"] == 1
                                  and stats["transport_failures"] == 1
                                  and stats["infrastructure_failures"] == 0)
            native_expected = int(
                native_observed and stats["cleanup_fail"] == 0
                and "EXPECTED_REAL_TRANSPORT_RESET"
                in stats["cleanup_outcomes"])
            if app_valid and fixture_valid and not native_observed:
                design_gap = "owner-reset-was-not-propagated-to-tun-client"
        else:
            app_valid = int(record.get("protocol") == "tcp"
                            and record.get("dns") is True
                            and record.get("send_connect_outcome") == "tcp_connect_succeeded"
                            and record.get("return_outcome") == "dns_response_timeout"
                            and record.get("tuple_attempted") is True)
            native_observed = int(stats["broker_success"] >= 1
                                  and stats["ambient_timeout"] >= 1
                                  and stats["output_cleanup"] >= 1
                                  and stats["handshake_cleanup"] >= 1
                                  and stats["rewritten_cleanup"] >= 1
                                  and stats["direct_cleanup"] == 0
                                  and stats["transport_failures"] == 0
                                  and stats["infrastructure_failures"] == 0)
            native_expected = int(native_observed and stats["cleanup_fail"] == 0
                                  and ("EXPECTED_TIMEOUT"
                                       in stats["cleanup_outcomes"]))
            if app_valid and fixture_valid and native_observed and not native_expected:
                design_gap = "native-cleanup-cannot-express-real-tcp-timeout-after-proxy-handshake"
    elif cell == "policy-drop-udp-dns":
        fixture_valid = int(
            any(e.get("event") == "policy_drop_udp_ready" and e.get("port") == policy_drop_port
                for e in fixture_events)
            and not any(e.get("event") == "policy_drop_udp_query"
                        and e.get("port") == policy_drop_port
                        for e in fixture_events)
        )
        app_valid = int(record.get("send_connect_outcome") == "udp_datagram_sent"
                        and record.get("return_outcome") == "dns_response_timeout"
                        and record.get("tuple_attempted") is True)
        native_observed = int(stats["policy_drop"] >= 1
                              and stats["broker_success"] == 0
                              and stats["direct_send"] == 0
                              and stats["tun_output"] == 0
                              and stats["transport_failures"] == 0
                              and stats["infrastructure_failures"] == 0)
        # The real multi-owner dispatcher drops before owner admission, so a
        # policy packet has no owner cleanup generation to classify.  The
        # session-level DROP marker is the authoritative terminal evidence;
        # retain the outcome token as a compatibility field for older logs.
        native_expected = int(native_observed and stats["cleanup_fail"] == 0
                              and (stats["policy_drop"] >= 1
                                   or "EXPECTED_REAL_POLICY_DROP"
                                   in stats["cleanup_outcomes"]))
        if app_valid and fixture_valid and native_observed and not native_expected:
            design_gap = "native-cleanup-cannot-express-real-policy-drop-no-transport"
    elif cell == "uid-drop-udp-dns":
        fixture_valid = int(
            any(e.get("event") == "uid_drop_udp_ready" and e.get("port") == uid_drop_port
                for e in fixture_events)
            and not any(e.get("event") == "uid_drop_udp_query"
                        and e.get("port") == uid_drop_port
                        for e in fixture_events)
        )
        app_valid = int(record.get("send_connect_outcome") == "udp_datagram_sent"
                        and record.get("return_outcome") == "dns_response_timeout"
                        and record.get("tuple_attempted") is True)
        native_observed = int(stats["gate_started"] == 1
                              and stats["gate_uid_drop"] >= 1
                              and stats["broker_success"] == 0
                              and stats["direct_send"] == 0
                              and stats["tun_output"] == 0
                              and stats["policy_drop"] == 0
                              and stats["transport_failures"] == 0
                              and stats["infrastructure_failures"] == 0)
        native_expected = int(native_observed and stats["cleanup_fail"] == 0)
        if app_valid and fixture_valid and not native_observed:
            design_gap = "native-tun-gate-did-not-enforce-app-uid-before-oi3-multi"
    if startup_valid and residue_valid and app_valid and fixture_valid and native_expected:
        verdict = "PASS"
    elif startup_valid and residue_valid and app_valid and fixture_valid and native_observed and design_gap:
        verdict = "DESIGN_GAP_NATIVE_EXPECTATION"
    else:
        verdict = "FAIL"
    rows.append({
        "cell": cell,
        "stage": stage,
        "startRc": start_rc,
        "intentRc": intent_rc,
        "vpnSessionProvenance": vpn_prov,
        "vppStartProvenance": vpp_prov,
        "appValid": app_valid,
        "fixtureValid": fixture_valid,
        "nativeObserved": native_observed,
        "nativeExpected": native_expected,
        "cleanupResults": stats["cleanup_results"],
        "cleanupOutcomes": stats["cleanup_outcomes"],
        "cleanupLastResult": stats["cleanup_last_result"],
        "cleanupLastOutcome": stats["cleanup_last_outcome"],
        "brokerSuccess": stats["broker_success"],
        "tunOutput": stats["tun_output"],
        "directSend": stats["direct_send"],
        "transportFailures": stats["transport_failures"],
        "downstreamReset": stats["downstream_reset"],
        "infrastructureFailures": stats["infrastructure_failures"],
        "outputCleanup": stats["output_cleanup"],
        "handshakeCleanup": stats["handshake_cleanup"],
        "directCleanup": stats["direct_cleanup"],
        "rewrittenCleanup": stats["rewritten_cleanup"],
        "ambientTimeout": stats["ambient_timeout"],
        "policyDrop": stats["policy_drop"],
        "gateStarted": stats["gate_started"],
        "gateUidDrop": stats["gate_uid_drop"],
        "gateForward": stats["gate_forward"],
        "sendConnectOutcome": record.get("send_connect_outcome", ""),
        "returnOutcome": record.get("return_outcome", ""),
        "error": record.get("error", ""),
        "residualVpp": residual_vpp,
        "tun0After": tun0_after,
        "designGap": design_gap,
        "verdict": verdict,
    })

with csv_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

fail_count = sum(1 for row in rows if row["verdict"] == "FAIL")
pass_count = sum(1 for row in rows if row["verdict"] == "PASS")
design_gap_count = sum(1 for row in rows if row["verdict"] == "DESIGN_GAP_NATIVE_EXPECTATION")
if fail_count:
    status = "FAIL"
elif design_gap_count:
    status = "DESIGN_GAP_NATIVE_EXPECTATION"
else:
    status = "PASS"

manifest = {
    "schema": runner_schema,
    "runId": run_id,
    "status": status,
    "scope": runner_scope,
    "claimBoundary": claim_boundary,
    "vpnPackage": vpn_package,
    "appPackage": app_package,
    "cellRoot": str(cell_root),
    "fixtureHost": fixture_host,
    "positivePort": positive_port,
    "noReplyPort": no_reply_port,
    "tcpTimeoutPort": tcp_timeout_port,
    "includePolicyDrop": include_policy_drop,
    "policyDropPort": policy_drop_port,
    "includeUidDrop": include_uid_drop,
    "uidDropPort": uid_drop_port,
    "cellsRecorded": len(rows),
    "passCount": pass_count,
    "designGapCount": design_gap_count,
    "failureCount": fail_count,
    "vpnApkSha256": sha(apk),
    "appApkSha256": sha(app_apk),
}
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")

lines = [
    f"status={status}",
    f"run_id={run_id}",
    f"scope={runner_scope}",
    f"claim_boundary={claim_boundary}",
    f"cells_recorded={len(rows)}",
    f"pass_count={pass_count}",
    f"design_gap_count={design_gap_count}",
    f"failure_count={fail_count}",
    f"non_claim={non_claim}",
]
for row in rows:
    lines.append(
        "cell={cell} verdict={verdict} appValid={appValid} fixtureValid={fixtureValid} "
        "nativeObserved={nativeObserved} nativeExpected={nativeExpected} "
        "cleanup={cleanupResults}/{cleanupOutcomes} app={sendConnectOutcome}/{returnOutcome} "
        "transportFailures={transportFailures} policyDrop={policyDrop} "
        "gateDrop={gateUidDrop} gateForward={gateForward} designGap={designGap} "
        "residualVpp={residualVpp} tun0={tun0After}".format(**row)
    )
validity_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

echo "# $RUNNER_TITLE"
echo "run_id=$RUN_ID"
echo "device=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE app_package=$APP_PACKAGE"

device_preflight
[[ -f "$APK" ]] || { echo "VPN APK not found: $APK" >&2; exit 1; }
[[ -f "$APP_APK" ]] || { echo "AppA APK not found: $APP_APK" >&2; exit 1; }
unzip -l "$APK" "lib/arm64-v8a/libhev_external_driver_poc_plugin.so" >/dev/null
unzip -l "$APK" "lib/arm64-v8a/hev_external_driver_poc_plugin.so" >/dev/null
unzip -l "$APK" "lib/arm64-v8a/libhev-socks5-tunnel.so" >/dev/null

FIXTURE_HOST="$(discover_fixture_host)"
[[ -n "$FIXTURE_HOST" ]] || { echo "FIXTURE_HOST unavailable; set it explicitly" >&2; exit 2; }
echo "fixture_host=$FIXTURE_HOST bind=$FIXTURE_BIND_HOST positive=$POSITIVE_PORT no_reply=$NO_REPLY_PORT tcp_timeout=$TCP_TIMEOUT_PORT policy_drop=$POLICY_DROP_PORT uid_drop=$UID_DROP_PORT include_policy_drop=$INCLUDE_POLICY_DROP include_uid_drop=$INCLUDE_UID_DROP"
write_fixture_script
: >"$FIXTURE_LOG"
python3 "$FIXTURE_SCRIPT" "$FIXTURE_BIND_HOST" "$POSITIVE_PORT" "$NO_REPLY_PORT" "$TCP_TIMEOUT_PORT" "$POLICY_DROP_PORT" "$UID_DROP_PORT" "$INCLUDE_POLICY_DROP" "$INCLUDE_UID_DROP" "$FIXTURE_LOG" &
FIXTURE_PID=$!
wait_fixture_ready || { echo "fixture did not become ready" >&2; exit 2; }

stop_vpn
adb_cmd install -r "$APK" >/dev/null
adb_cmd install -r "$APP_APK" >/dev/null
adb_cmd shell am compat disable RESTRICT_LOCAL_NETWORK "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell pm grant "$VPN_PACKAGE" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true
adb_cmd shell pm grant "$APP_PACKAGE" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true

vpn_uid="$(package_uid "$VPN_PACKAGE")"
app_uid="$(package_uid "$APP_PACKAGE")"
[[ -n "$vpn_uid" ]] || { echo "VPN package UID unavailable" >&2; exit 1; }
[[ -n "$app_uid" ]] || { echo "App package UID unavailable" >&2; exit 1; }
echo "vpn_uid=$vpn_uid app_uid=$app_uid"
write_run_provenance "$vpn_uid" "$app_uid"

run_cell "positive-udp-dns" "udp" "true" "$POSITIVE_SOURCE_PORT" "$POSITIVE_PORT"
if [[ "$INCLUDE_NO_REPLY" == "true" ]]; then
  run_cell "no-reply-udp-dns" "udp" "true" "$NO_REPLY_SOURCE_PORT" "$NO_REPLY_PORT" "real-no-reply"
fi
if [[ "$INCLUDE_TCP_TIMEOUT" == "true" ]]; then
  run_cell "closed-tcp-timeout" "tcp" "true" "$TCP_TIMEOUT_SOURCE_PORT" "$TCP_TIMEOUT_PORT" "$TCP_EXPECTED_FAILURE"
fi
if [[ "$INCLUDE_POLICY_DROP" == "true" ]]; then
  # The dispatcher target itself is the policy expectation.  Do not pass a
  # per-owner transport expectation: this seam intentionally never creates an
  # owner generation or cleanup marker for the dropped packet.
  run_cell "policy-drop-udp-dns" "udp" "true" "$POLICY_DROP_SOURCE_PORT" "$POLICY_DROP_PORT" "" "$FIXTURE_HOST"
fi
if [[ "$INCLUDE_UID_DROP" == "true" ]]; then
  # This POC uses the existing Android owner lookup at the native TUN gate,
  # then verifies that a real AppA UID block stops before the OI3 multi
  # broker/socket path.
  run_cell "uid-drop-udp-dns" "udp" "true" "$UID_DROP_SOURCE_PORT" "$UID_DROP_PORT" "" "" "$app_uid"
fi

summarize_all
cat "$VALIDITY"
if grep -q '^status=FAIL$' "$VALIDITY"; then
  exit 1
fi
