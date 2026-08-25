#!/usr/bin/env bash
set -euo pipefail

# S180 / B1 DNS UDP-to-TCP fallback proof.
#
# This runner starts a local IPv4 DNS fixture: UDP returns the same query with
# the DNS TC bit set, and TCP returns a valid answer for the same query ID.
# AppA must perform one B1 UDP probe with b1FallbackTcpOnTruncated=true and
# then retry the same query over TCP.  Independent UDP/TCP cells are not
# accepted as fallback evidence.

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
  SOURCE_PORT_BASE="$((47000 + ($(date +%s) % 1500) * 10))"
fi
UDP_SOURCE_PORT="${UDP_SOURCE_PORT:-$((SOURCE_PORT_BASE + 1))}"
TCP_SOURCE_PORT="${TCP_SOURCE_PORT:-$((SOURCE_PORT_BASE + 2))}"
B1_TIMEOUT_MS="${B1_TIMEOUT_MS:-5000}"
B1_PAYLOAD_HEX="${B1_PAYLOAD_HEX:-123401000001000000000000076578616d706c6503636f6d0000010001}"
FIXTURE_HOST="${FIXTURE_HOST:-}"
FIXTURE_BIND_HOST="${FIXTURE_BIND_HOST:-0.0.0.0}"
FIXTURE_PORT="${FIXTURE_PORT:-53535}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s180-b1-dns-fallback-$(date +%Y%m%d)}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
APP_APK="${APP_APK:-$POC_DIR/android/a2-traffic-adapter/build/outputs/com-sakamoto-snort-poc-appa-debug.apk}"
WAIT_VPP_READY_ATTEMPTS="${WAIT_VPP_READY_ATTEMPTS:-120}"
WAIT_B1_RECORD_ATTEMPTS="${WAIT_B1_RECORD_ATTEMPTS:-90}"
WAIT_STOP_CLEANUP_ATTEMPTS="${WAIT_STOP_CLEANUP_ATTEMPTS:-28}"
POST_B1_NATIVE_SETTLE_SECONDS="${POST_B1_NATIVE_SETTLE_SECONDS:-6}"
REMOTE_LOG_TAIL_LINES="${REMOTE_LOG_TAIL_LINES:-2400}"
ADB_READ_RETRY_ATTEMPTS="${ADB_READ_RETRY_ATTEMPTS:-3}"
ADB_READ_RETRY_DELAY_SECONDS="${ADB_READ_RETRY_DELAY_SECONDS:-1}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/cells"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$(date +%s%N | tail -c 7)"
RUN_LOG="$RESULT_DIR/run-$RUN_ID.log"
CSV="$RESULT_DIR/cells-$RUN_ID.csv"
MANIFEST="$RESULT_DIR/run-$RUN_ID-manifest.json"
VALIDITY="$RESULT_DIR/run-validity-$RUN_ID.txt"
CELL_ROOT="$RESULT_DIR/cells/$RUN_ID"
CELL_DIR="$CELL_ROOT/ip4-udp-tcp-fallback"
FIXTURE_SCRIPT="$RESULT_DIR/s180_dns_fixture.py"
FIXTURE_LOG="$RESULT_DIR/fixture-$RUN_ID.log"
mkdir -p "$CELL_DIR"

VPN_FILES="/data/user/0/$VPN_PACKAGE/files"
VPN_LOGS="$VPN_FILES/vpp/logs"
APP_FILES="/data/user/0/$APP_PACKAGE/files"
APP_B1_LOG="$APP_FILES/debug/b1-runtime.jsonl"
REMOTE_VPN_SESSION="$VPN_FILES/vpn-session-provenance.json"
REMOTE_VPP_START="$VPN_FILES/vpp/runtime/vpp-start-provenance.json"
REMOTE_CLI_LOG="$VPN_LOGS/vpp-cli.log"
REMOTE_STDOUT_LOG="$VPN_LOGS/vpp-stdout.log"
REMOTE_HEV_LOG="$VPN_LOGS/vpp-hev.log"
REMOTE_PROTECT_LOG="$VPN_LOGS/vpp-protect.log"
REMOTE_OI3_BROKER_LOG="$VPN_LOGS/vpp-oi3-broker.log"

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
import struct
import sys
import threading
import time

bind_host = sys.argv[1]
port = int(sys.argv[2])
log_path = sys.argv[3]

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

def truncated_response(query):
    qid = query[:2] if len(query) >= 2 else b"\x00\x00"
    qdcount = query[4:6] if len(query) >= 6 else b"\x00\x01"
    return qid + b"\x83\x80" + qdcount + b"\x00\x00\x00\x00\x00\x00" + question(query)

def full_response(query):
    qid = query[:2] if len(query) >= 2 else b"\x00\x00"
    q = question(query)
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"
    return qid + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q + answer

def udp_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, port))
    log("udp_ready", bind_host=bind_host, port=port)
    while True:
        query, addr = sock.recvfrom(4096)
        log("udp_query", peer=f"{addr[0]}:{addr[1]}", length=len(query),
            query_id=query[:2].hex())
        response = truncated_response(query)
        sock.sendto(response, addr)
        log("udp_truncated_response", peer=f"{addr[0]}:{addr[1]}",
            length=len(response), query_id=query[:2].hex())

def tcp_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, port))
    sock.listen(16)
    log("tcp_ready", bind_host=bind_host, port=port)
    while True:
        conn, addr = sock.accept()
        with conn:
            header = conn.recv(2)
            if len(header) < 2:
                log("tcp_short_header", peer=f"{addr[0]}:{addr[1]}")
                continue
            length = struct.unpack("!H", header)[0]
            query = b""
            while len(query) < length:
                chunk = conn.recv(length - len(query))
                if not chunk:
                    break
                query += chunk
            log("tcp_query", peer=f"{addr[0]}:{addr[1]}", length=len(query),
                query_id=query[:2].hex())
            response = full_response(query)
            conn.sendall(struct.pack("!H", len(response)) + response)
            log("tcp_full_response", peer=f"{addr[0]}:{addr[1]}",
                length=len(response), query_id=query[:2].hex())

threading.Thread(target=udp_loop, daemon=True).start()
threading.Thread(target=tcp_loop, daemon=True).start()
while True:
    time.sleep(3600)
PY
  chmod +x "$FIXTURE_SCRIPT"
}

wait_fixture_ready() {
  for _ in $(seq 1 80); do
    if grep -q '"event": "udp_ready"' "$FIXTURE_LOG" 2>/dev/null \
        && grep -q '"event": "tcp_ready"' "$FIXTURE_LOG" 2>/dev/null; then
      return 0
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
  capture_remote_json "$REMOTE_VPN_SESSION" "$CELL_DIR/vpn-session-provenance.json"
  capture_remote_json "$REMOTE_VPP_START" "$CELL_DIR/vpp-start-provenance.json"
  capture_remote_json "$APP_B1_LOG" "$CELL_DIR/app-b1-runtime.jsonl"
  capture_remote_tail "$REMOTE_CLI_LOG" "$CELL_DIR/vpp-cli.log"
  capture_remote_tail "$REMOTE_STDOUT_LOG" "$CELL_DIR/vpp-stdout.log"
  capture_remote_tail "$REMOTE_HEV_LOG" "$CELL_DIR/vpp-hev.log"
  capture_remote_tail "$REMOTE_PROTECT_LOG" "$CELL_DIR/vpp-protect.log"
  capture_remote_tail "$REMOTE_OI3_BROKER_LOG" "$CELL_DIR/vpp-oi3-broker.log"
  adb_read 'dumpsys connectivity 2>/dev/null || true' >"$CELL_DIR/connectivity.txt"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I S139A2Traffic:I '*:S' \
    | tr -d '\r' >"$CELL_DIR/logcat.txt" || true
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
    echo "runner=android-run-s180-b1-dns-fallback.sh"
    echo "scope=bounded_b1_dns_udp_to_tcp_fallback"
    echo "vpn_mode=$VPN_MODE"
    echo "allowed_package=$APP_PACKAGE"
    echo "fixture_host=$FIXTURE_HOST"
    echo "fixture_port=$FIXTURE_PORT"
    echo "claim_boundary=WSL2-LAN-fixture-forced-TC-fallback-not-public-resolver-coverage"
  } >"$RESULT_DIR/source-provenance.properties"
}

start_vpn_for_cell() {
  set +e
  adb_cmd shell am start -W -n "$VPN_PACKAGE/.MainActivity" \
    --ez start true --es mode "$VPN_MODE" --es allowedPackage "$APP_PACKAGE" \
    --ez enableIpv6 "$ENABLE_IPV6" >"$CELL_DIR/start.txt" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "$rc"
}

run_b1_fallback_intent() {
  local stage="$1"
  local args=(
    shell am start -W -n "$APP_COMPONENT" -a "$B1_ACTION"
    --es b1StageId "$stage"
    --es b1Family ip4
    --es b1Protocol udp
    --ei b1SourcePort "$UDP_SOURCE_PORT"
    --es b1DestinationHost "$FIXTURE_HOST"
    --ei b1DestinationPort "$FIXTURE_PORT"
    --ei b1TimeoutMillis "$B1_TIMEOUT_MS"
    --ez b1Dns true
    --es b1PayloadHex "$B1_PAYLOAD_HEX"
    --ez b1FallbackTcpOnTruncated true
    --ei b1FallbackTcpSourcePort "$TCP_SOURCE_PORT"
    --es b1TcpWriteMode coalesced
  )
  set +e
  adb_cmd "${args[@]}" >"$CELL_DIR/b1-intent.txt" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "$rc"
}

summarize_cell() {
  local stage="$1" start_rc="$2" intent_rc="$3" residual_vpp="$4" tun0_after="$5"
  python3 - "$stage" "$CELL_DIR" "$FIXTURE_LOG" "$CSV" "$start_rc" "$intent_rc" \
    "$residual_vpp" "$tun0_after" <<'PY'
import csv
import json
import re
import sys
from pathlib import Path

stage = sys.argv[1]
cell_dir = Path(sys.argv[2])
fixture_log = Path(sys.argv[3])
csv_path = Path(sys.argv[4])
start_rc = int(sys.argv[5])
intent_rc = int(sys.argv[6])
residual_vpp = sys.argv[7]
tun0_after = int(sys.argv[8])
records = []
jsonl = cell_dir / "app-b1-runtime.jsonl"
if jsonl.exists():
    for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("stage_id") == stage:
            records.append(item)
record = records[-1] if records else {}
fixture_events = []
if fixture_log.exists():
    for line in fixture_log.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            fixture_events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
udp_query = any(event.get("event") == "udp_query" for event in fixture_events)
udp_tc = any(event.get("event") == "udp_truncated_response" for event in fixture_events)
tcp_query = any(event.get("event") == "tcp_query" for event in fixture_events)
tcp_full = any(event.get("event") == "tcp_full_response" for event in fixture_events)
query_ids = {event.get("query_id") for event in fixture_events
             if event.get("event") in {"udp_query", "tcp_query"}}
same_query_id = len(query_ids - {None}) == 1
native_text = ""
for name in ("vpp-stdout.log", "vpp-cli.log", "vpp-oi3-broker.log"):
    path = cell_dir / name
    if path.exists():
        native_text += "\n" + path.read_text(encoding="utf-8", errors="replace")
broker_success = len(re.findall(r"\boi3 broker-completion result=SUCCESS", native_text))
tun_output = len(re.findall(r"\boi3 tun-output length=[1-9][0-9]* result=OK", native_text))
direct_send = len(re.findall(r"\boi3 direct-send length=[1-9][0-9]*", native_text))
cleanup_pass = len(re.findall(r"oi3_cleanup result=PASS", native_text))
cleanup_fail = len(re.findall(r"oi3_cleanup result=FAIL", native_text))
vpn_prov = int((cell_dir / "vpn-session-provenance.json").exists()
               and (cell_dir / "vpn-session-provenance.json").stat().st_size > 0)
vpp_prov = int((cell_dir / "vpp-start-provenance.json").exists()
               and (cell_dir / "vpp-start-provenance.json").stat().st_size > 0)
app_valid = int(
    bool(record)
    and record.get("schema") == "s139-b1-runtime/v1"
    and record.get("event") == "B1_TRAFFIC_RESULT"
    and record.get("family") == "ip4"
    and record.get("protocol") == "udp"
    and record.get("fallback_tcp_on_truncated") is True
    and record.get("fallback_attempted") is True
    and record.get("fallback_reason") == "udp_tc"
    and record.get("udp_truncated") is True
    and record.get("return_outcome") == "dns_tcp_fallback_response_received"
    and record.get("fallback_return_outcome") == "dns_response_received"
    and record.get("response_valid") is True
    and record.get("tcp_response_valid") is True
)
fixture_valid = int(udp_query and udp_tc and tcp_query and tcp_full and same_query_id)
native_valid = int(broker_success >= 2 and tun_output >= 2 and direct_send >= 2)
residue_valid = int(residual_vpp == "" and tun0_after == 0)
startup_valid = int(start_rc == 0 and intent_rc == 0 and vpn_prov == 1 and vpp_prov == 1)
valid = int(app_valid and fixture_valid and native_valid and residue_valid
            and startup_valid and cleanup_fail == 0)
if valid and cleanup_pass > 0:
    verdict = "PASS"
elif valid:
    verdict = "PASS_DATAPLANE_CLEANUP_MARKER_MISSING"
else:
    verdict = "FAIL"
row = {
    "cell": "ip4-udp-tcp-dns-fallback",
    "stage": stage,
    "startRc": start_rc,
    "intentRc": intent_rc,
    "vpnSessionProvenance": vpn_prov,
    "vppStartProvenance": vpp_prov,
    "appValid": app_valid,
    "fixtureValid": fixture_valid,
    "nativeValid": native_valid,
    "cleanupPass": cleanup_pass,
    "cleanupFail": cleanup_fail,
    "brokerSuccess": broker_success,
    "tunOutput": tun_output,
    "directSend": direct_send,
    "residualVpp": residual_vpp,
    "tun0After": tun0_after,
    "fallbackAttempted": record.get("fallback_attempted", ""),
    "fallbackReason": record.get("fallback_reason", ""),
    "returnOutcome": record.get("return_outcome", ""),
    "fallbackReturnOutcome": record.get("fallback_return_outcome", ""),
    "udpTruncated": record.get("udp_truncated", ""),
    "tcpResponseValid": record.get("tcp_response_valid", ""),
    "receivedLength": record.get("received_length", 0),
    "verdict": verdict,
}
writer = csv.DictWriter(csv_path.open("w", newline="", encoding="utf-8"),
                        fieldnames=list(row.keys()))
writer.writeheader()
writer.writerow(row)
PY
}

write_validity_and_manifest() {
  python3 - "$RUN_ID" "$CSV" "$MANIFEST" "$VALIDITY" "$APK" "$APP_APK" \
    "$VPN_PACKAGE" "$APP_PACKAGE" "$CELL_ROOT" "$FIXTURE_HOST" "$FIXTURE_PORT" <<'PY'
import csv
import hashlib
import json
import sys
from pathlib import Path

run_id, csv_path, manifest_path, validity_path, apk, app_apk = sys.argv[1:7]
vpn_package, app_package, cell_root, fixture_host, fixture_port = sys.argv[7:12]
rows = list(csv.DictReader(Path(csv_path).open(newline="", encoding="utf-8")))
fail_count = sum(1 for row in rows if row["verdict"] == "FAIL")
pass_count = sum(1 for row in rows if row["verdict"] == "PASS")
cleanup_gap_count = sum(1 for row in rows if row["verdict"] == "PASS_DATAPLANE_CLEANUP_MARKER_MISSING")
status = "PASS" if rows and fail_count == 0 and cleanup_gap_count == 0 else (
    "PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS" if rows and fail_count == 0 else "FAIL"
)
def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
manifest = {
    "schema": "s180-b1-dns-fallback/v1",
    "runId": run_id,
    "status": status,
    "scope": "bounded_b1_dns_udp_to_tcp_fallback",
    "claimBoundary": "WSL2 LAN fixture forced TC fallback; not public resolver coverage",
    "vpnPackage": vpn_package,
    "appPackage": app_package,
    "cellRoot": cell_root,
    "fixtureHost": fixture_host,
    "fixturePort": int(fixture_port),
    "cellsRecorded": len(rows),
    "passCount": pass_count,
    "cleanupMarkerGapCount": cleanup_gap_count,
    "failureCount": fail_count,
    "vpnApkSha256": sha(apk),
    "appApkSha256": sha(app_apk),
}
Path(manifest_path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
lines = [
    f"status={status}",
    f"run_id={run_id}",
    "scope=bounded_b1_dns_udp_to_tcp_fallback",
    "claim_boundary=WSL2 LAN fixture forced TC fallback; not public resolver coverage",
    f"cells_recorded={len(rows)}",
    f"pass_count={pass_count}",
    f"cleanup_marker_gap_count={cleanup_gap_count}",
    f"failure_count={fail_count}",
    "non_claim=not public resolver fallback, not IPv6 fallback, not long soak/performance",
]
for row in rows:
    lines.append(
        "cell={cell} verdict={verdict} appValid={appValid} fixtureValid={fixtureValid} "
        "nativeValid={nativeValid} fallback={fallbackAttempted}/{fallbackReason} "
        "return={returnOutcome} tcp={fallbackReturnOutcome} residualVpp={residualVpp} "
        "tun0={tun0After}".format(**row)
    )
Path(validity_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

echo "# S180 B1 DNS UDP-to-TCP fallback"
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
echo "fixture_host=$FIXTURE_HOST fixture_bind_host=$FIXTURE_BIND_HOST fixture_port=$FIXTURE_PORT"
write_fixture_script
: >"$FIXTURE_LOG"
python3 "$FIXTURE_SCRIPT" "$FIXTURE_BIND_HOST" "$FIXTURE_PORT" "$FIXTURE_LOG" &
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

stage="S180-ip4-udp-tcp-dns-fallback"
stop_vpn
adb_cmd shell am force-stop "$APP_PACKAGE" >/dev/null 2>&1 || true
adb_read "rm -f '$APP_B1_LOG' '$REMOTE_VPN_SESSION' '$REMOTE_VPP_START' '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG' '$REMOTE_OI3_BROKER_LOG'"
adb_read "ps -A -o USER,PID,PPID,RSS,NAME,ARGS 2>/dev/null || ps -A" >"$CELL_DIR/processes-before.txt"
adb_cmd logcat -c >/dev/null 2>&1 || true
start_rc="$(start_vpn_for_cell)"
vpp_pid="$(wait_vpp_ready || true)"
if [[ -z "$vpp_pid" ]]; then
  echo "cell=ip4-udp-tcp-dns-fallback INVALID: VPP/OI3 four-owner startup not proven" >&2
fi
sleep 1
intent_rc="$(run_b1_fallback_intent "$stage")"
wait_b1_record "$stage" || echo "cell=ip4-udp-tcp-dns-fallback B1 record wait timed out" >&2
sleep "$POST_B1_NATIVE_SETTLE_SECONDS"
capture_cell_common
stop_vpn
residual_vpp="$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'" | tr -d '\n')"
tun0_text="$(adb_read "ip link show tun0 2>/dev/null || true")"
printf '%s\n' "$tun0_text" >"$CELL_DIR/tun0-after.txt"
tun0_after=0
if [[ "$tun0_text" == *"tun0:"* ]]; then
  tun0_after=1
fi
adb_read "ps -A -o USER,PID,PPID,RSS,NAME,ARGS 2>/dev/null || ps -A" >"$CELL_DIR/processes-after-stop.txt"
summarize_cell "$stage" "$start_rc" "$intent_rc" "$residual_vpp" "$tun0_after"
write_validity_and_manifest
cat "$VALIDITY"
if grep -q '^status=FAIL$' "$VALIDITY"; then
  exit 1
fi
