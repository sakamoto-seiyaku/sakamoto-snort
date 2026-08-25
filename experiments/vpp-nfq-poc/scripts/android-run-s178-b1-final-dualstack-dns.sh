#!/usr/bin/env bash
set -euo pipefail

# S178 / B1 final-artifact dual-stack DNS probe.
#
# This runner replays the B1 AppA DNS cells against the current accepted
# VpnLite final artifact.  It is a bounded evidence collector: app-level DNS
# success, VPP startup/provenance, native direct/broker/TUN-output evidence,
# and zero residue are required for a dataplane-valid row.  The OI3 cleanup
# marker is reported separately because short B1/TCP flows can finish at the
# app while the native lifecycle marker is still timing-sensitive; rows with
# dataplane success but missing cleanup markers are not lifecycle PASS claims.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_PACKAGE="${APP_PACKAGE:-com.sakamoto.snort.poc.appa}"
APP_ACTIVITY="${APP_ACTIVITY:-com.sakamoto.snort.a2traffic.TrafficAdapterActivity}"
APP_COMPONENT="${APP_COMPONENT:-com.sakamoto.snort.poc.appa/com.sakamoto.snort.a2traffic.TrafficAdapterActivity}"
B1_ACTION="${B1_ACTION:-com.sakamoto.snort.a2traffic.B1_PROBE}"
VPN_MODE="${VPN_MODE:-vpp-oi3-multi}"
ENABLE_IPV6="${ENABLE_IPV6:-true}"
if [[ -z "${SOURCE_PORT_BASE:-}" ]]; then
  SOURCE_PORT_BASE="$((46000 + ($(date +%s) % 1500) * 10))"
fi
B1_TIMEOUT_MS="${B1_TIMEOUT_MS:-5000}"
B1_PAYLOAD_HEX="${B1_PAYLOAD_HEX:-123401000001000000000000076578616d706c6503636f6d0000010001}"
CELLS="${CELLS:-all}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s178-b1-final-dualstack-dns-$(date +%Y%m%d)}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
APP_APK="${APP_APK:-$POC_DIR/android/a2-traffic-adapter/build/outputs/com-sakamoto-snort-poc-appa-debug.apk}"
WAIT_VPP_READY_ATTEMPTS="${WAIT_VPP_READY_ATTEMPTS:-120}"
WAIT_B1_RECORD_ATTEMPTS="${WAIT_B1_RECORD_ATTEMPTS:-90}"
WAIT_STOP_CLEANUP_ATTEMPTS="${WAIT_STOP_CLEANUP_ATTEMPTS:-28}"
POST_B1_NATIVE_SETTLE_SECONDS="${POST_B1_NATIVE_SETTLE_SECONDS:-6}"
REMOTE_LOG_TAIL_LINES="${REMOTE_LOG_TAIL_LINES:-2000}"
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
mkdir -p "$CELL_ROOT"

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

count_matches() {
  local pattern="$1" file="$2" count
  count="$(grep -Ec "$pattern" "$file" 2>/dev/null || true)"
  printf '%s\n' "${count:-0}"
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
}
trap cleanup EXIT

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

require_apk_member() {
  local apk="$1" member="$2"
  unzip -l "$apk" "$member" >/dev/null
}

cell_enabled() {
  local cell="$1"
  [[ "$CELLS" == "all" || ",$CELLS," == *",$cell,"* ]]
}

safe_capture_remote_tail() {
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
  mkdir -p "$cell_dir"
  capture_remote_json "$REMOTE_VPN_SESSION" "$cell_dir/vpn-session-provenance.json"
  capture_remote_json "$REMOTE_VPP_START" "$cell_dir/vpp-start-provenance.json"
  capture_remote_json "$APP_B1_LOG" "$cell_dir/app-b1-runtime.jsonl"
  safe_capture_remote_tail "$REMOTE_CLI_LOG" "$cell_dir/vpp-cli.log"
  safe_capture_remote_tail "$REMOTE_STDOUT_LOG" "$cell_dir/vpp-stdout.log"
  safe_capture_remote_tail "$REMOTE_HEV_LOG" "$cell_dir/vpp-hev.log"
  safe_capture_remote_tail "$REMOTE_PROTECT_LOG" "$cell_dir/vpp-protect.log"
  safe_capture_remote_tail "$REMOTE_OI3_BROKER_LOG" "$cell_dir/vpp-oi3-broker.log"
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
    echo "runner=android-run-s178-b1-final-dualstack-dns.sh"
    echo "scope=bounded_final_artifact_b1_dualstack_dns"
    echo "vpn_mode=$VPN_MODE"
    echo "allowed_package=$APP_PACKAGE"
    echo "enable_ipv6=$ENABLE_IPV6"
    echo "direct_preflight=not-run-current-AppA-B1-helper-requires-active-VPN"
    echo "expected_hash_policy=current-artifact-by-default-no-static-historical-hashes"
  } >"$RESULT_DIR/source-provenance.properties"
  adb_read "cmd package list packages -U | grep -E '($VPN_PACKAGE|$APP_PACKAGE)' || true" \
    >"$RESULT_DIR/package-list-packages-U.txt"
}

start_vpn_for_cell() {
  local cell_dir="$1"
  set +e
  adb_cmd shell am start -W -n "$VPN_PACKAGE/.MainActivity" \
    --ez start true --es mode "$VPN_MODE" --es allowedPackage "$APP_PACKAGE" \
    --ez enableIpv6 "$ENABLE_IPV6" >"$cell_dir/start.txt" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "$rc"
}

run_b1_intent() {
  local stage="$1" family="$2" protocol="$3" source_port="$4" destination_host="$5" tcp_write_mode="$6" cell_dir="$7"
  local args=(
    shell am start -W -n "$APP_COMPONENT" -a "$B1_ACTION"
    --es b1StageId "$stage"
    --es b1Family "$family"
    --es b1Protocol "$protocol"
    --ei b1SourcePort "$source_port"
    --es b1DestinationHost "$destination_host"
    --ei b1DestinationPort 53
    --ei b1TimeoutMillis "$B1_TIMEOUT_MS"
    --ez b1Dns true
    --es b1PayloadHex "$B1_PAYLOAD_HEX"
  )
  if [[ "$protocol" == "tcp" ]]; then
    args+=(--es b1TcpWriteMode "$tcp_write_mode")
  fi
  set +e
  adb_cmd "${args[@]}" >"$cell_dir/b1-intent.txt" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "$rc"
}

summarize_cell() {
  local cell_id="$1" stage="$2" family="$3" protocol="$4" tcp_write_mode="$5"
  local source_port="$6" destination_host="$7" start_rc="$8" intent_rc="$9"
  local cell_dir="${10}" residual_vpp="${11}" tun0_after="${12}" rules_match="${13}"
  python3 - "$cell_id" "$stage" "$family" "$protocol" "$tcp_write_mode" \
    "$source_port" "$destination_host" "$start_rc" "$intent_rc" "$cell_dir" \
    "$residual_vpp" "$tun0_after" "$rules_match" <<'PY'
import csv
import json
import re
import sys
from pathlib import Path

cell_id, stage, family, protocol, tcp_write_mode = sys.argv[1:6]
source_port = int(sys.argv[6])
destination_host = sys.argv[7]
start_rc = int(sys.argv[8])
intent_rc = int(sys.argv[9])
cell_dir = Path(sys.argv[10])
residual_vpp = sys.argv[11]
tun0_after = int(sys.argv[12])
rules_match = int(sys.argv[13])
jsonl = cell_dir / "app-b1-runtime.jsonl"
records = []
if jsonl.exists():
    for line in jsonl.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("stage_id") == stage:
            records.append(record)
record = records[-1] if records else {}
cleanup_text = ""
for name in ("cleanup.log", "vpp-stdout.log", "vpp-cli.log"):
    path = cell_dir / name
    if path.exists():
        cleanup_text += "\n" + path.read_text(encoding="utf-8", errors="replace")
cleanup_pass = len(re.findall(r"oi3_cleanup result=PASS", cleanup_text))
cleanup_fail = len(re.findall(r"oi3_cleanup result=FAIL", cleanup_text))
vpn_prov = int((cell_dir / "vpn-session-provenance.json").stat().st_size > 0) if (cell_dir / "vpn-session-provenance.json").exists() else 0
vpp_prov = int((cell_dir / "vpp-start-provenance.json").stat().st_size > 0) if (cell_dir / "vpp-start-provenance.json").exists() else 0
native_direct = int(bool(re.search(r"\boi3 direct-send length=[1-9][0-9]*", cleanup_text))
                    and (protocol != "tcp" or bool(re.search(r"\boi3 direct-recv length=[1-9][0-9]*", cleanup_text))))
native_rewritten = int(bool(re.search(r"\boi3 tun-output length=[1-9][0-9]* result=OK", cleanup_text)))
native_broker = int(bool(re.search(r"\boi3 broker-completion result=SUCCESS", cleanup_text)))
native_underlay = int(bool(re.search(r"\bunderlay-available=1", cleanup_text)))
native_handshake = int(protocol != "tcp" or bool(re.search(r"\btcp-flags=0x02", cleanup_text)))
expected_send = "udp_datagram_sent" if protocol == "udp" else "tcp_payload_sent"
app_valid = int(
    bool(record)
    and record.get("schema") == "s139-b1-runtime/v1"
    and record.get("event") == "B1_TRAFFIC_RESULT"
    and record.get("app_package") == "com.sakamoto.snort.poc.appa"
    and record.get("family") == family
    and record.get("protocol") == protocol
    and int(record.get("source_port", -1)) == source_port
    and str(record.get("destination_host", "")) == destination_host
    and int(record.get("destination_port", -1)) == 53
    and record.get("bind_result") == "bound"
    and record.get("tuple_attempted") is True
    and record.get("send_connect_outcome") == expected_send
    and record.get("return_outcome") == "dns_response_received"
    and record.get("return_received") is True
    and record.get("response_valid") is True
    and int(record.get("payload_length", -1)) == 29
    and int(record.get("received_length", 0)) > 0
)
cleanup_valid = int(cleanup_pass > 0 and cleanup_fail == 0)
residue_valid = int(residual_vpp == "" and tun0_after == 0 and rules_match == 1)
startup_valid = int(start_rc == 0 and intent_rc == 0 and vpn_prov == 1 and vpp_prov == 1)
native_valid = int(native_direct and native_rewritten and native_broker and native_underlay and native_handshake)
valid = int(app_valid and native_valid and residue_valid and startup_valid and cleanup_fail == 0)
if valid and cleanup_valid:
    verdict = "PASS"
elif valid:
    verdict = "PASS_DATAPLANE_CLEANUP_MARKER_MISSING"
else:
    verdict = "FAIL"
row = [
    cell_id, stage, family, protocol, tcp_write_mode, source_port,
    destination_host, 53, start_rc, intent_rc, vpn_prov, vpp_prov,
    record.get("bind_result", ""), record.get("send_connect_outcome", ""),
    record.get("return_outcome", ""), record.get("return_received", ""),
    record.get("response_valid", ""), record.get("payload_length", 0),
    record.get("received_length", 0), record.get("error", ""),
    cleanup_pass, cleanup_fail, residual_vpp, tun0_after, rules_match,
    native_direct, native_rewritten, native_broker, native_underlay,
    native_handshake, app_valid, native_valid, valid, verdict,
]
writer = csv.writer(sys.stdout, lineterminator="\n")
writer.writerow(row)
PY
}

write_validity_and_manifest() {
  python3 - "$RUN_ID" "$CSV" "$MANIFEST" "$VALIDITY" "$APK" "$APP_APK" \
    "$VPN_PACKAGE" "$APP_PACKAGE" "$VPN_MODE" "$ENABLE_IPV6" "$CELL_ROOT" <<'PY'
import csv
import hashlib
import json
import sys
from pathlib import Path

run_id, csv_path, manifest_path, validity_path, apk, app_apk = sys.argv[1:7]
vpn_package, app_package, vpn_mode, enable_ipv6, cell_root = sys.argv[7:12]
csv_path = Path(csv_path)
rows = list(csv.DictReader(csv_path.open(newline="", encoding="utf-8")))
total = len(rows)
pass_count = sum(1 for row in rows if row["verdict"] == "PASS")
cleanup_gap_count = sum(1 for row in rows if row["verdict"] == "PASS_DATAPLANE_CLEANUP_MARKER_MISSING")
fail_count = sum(1 for row in rows if row["verdict"] == "FAIL")
app_valid_count = sum(1 for row in rows if row["appValid"] == "1")
native_valid_count = sum(1 for row in rows if row["nativeValid"] == "1")
status = "PASS" if total and pass_count == total else (
    "PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS" if total and fail_count == 0 and app_valid_count == total and native_valid_count == total else "FAIL"
)
def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
manifest = {
    "schema": "s178-b1-final-dualstack-dns/v1",
    "runId": run_id,
    "status": status,
    "scope": "bounded_final_artifact_b1_dualstack_dns",
    "vpnPackage": vpn_package,
    "appPackage": app_package,
    "vpnMode": vpn_mode,
    "enableIpv6": enable_ipv6 == "true",
    "cellRoot": cell_root,
    "cellsRecorded": total,
    "passCount": pass_count,
    "cleanupMarkerGapCount": cleanup_gap_count,
    "failureCount": fail_count,
    "appValidCount": app_valid_count,
    "nativeValidCount": native_valid_count,
    "vpnApkSha256": sha(apk),
    "appApkSha256": sha(app_apk),
}
Path(manifest_path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
lines = [
    f"status={status}",
    f"run_id={run_id}",
    f"scope=bounded_final_artifact_b1_dualstack_dns",
    f"cells_recorded={total}",
    f"pass_count={pass_count}",
    f"cleanup_marker_gap_count={cleanup_gap_count}",
    f"failure_count={fail_count}",
    f"app_valid_count={app_valid_count}",
    f"native_valid_count={native_valid_count}",
    "direct_preflight=not-run-current-AppA-B1-helper-requires-active-VPN; do not treat vpn_unavailable as endpoint failure",
    "non_claim=not a long soak, throughput, CPU, Doze, or full E2 campaign verdict",
    "pass_rule=full PASS requires app DNS response, native direct/broker/tun-output markers, zero residue, and cleanup marker",
    "dataplane_pass_rule=dataplane PASS allows cleanup marker gap if app/native dataplane proof and zero residue are present",
]
for row in rows:
    lines.append(
        "cell={cell} verdict={verdict} appValid={appValid} nativeValid={nativeValid} "
        "bind={bindResult} send={sendConnectOutcome} return={returnOutcome} "
        "responseValid={responseValid} cleanup={cleanupPass}/{cleanupFail} "
        "residualVpp={residualVpp} tun0={tun0After} rules={rulesMatch}".format(**row)
    )
Path(validity_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

echo "# S178 B1 final-artifact dual-stack DNS"
echo "run_id=$RUN_ID"
echo "device=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE app_package=$APP_PACKAGE vpn_mode=$VPN_MODE enable_ipv6=$ENABLE_IPV6"
echo "cells=$CELLS source_port_base=$SOURCE_PORT_BASE timeout_ms=$B1_TIMEOUT_MS"

device_preflight
[[ -f "$APK" ]] || { echo "VPN APK not found: $APK" >&2; exit 1; }
[[ -f "$APP_APK" ]] || { echo "AppA APK not found: $APP_APK" >&2; exit 1; }
require_apk_member "$APK" "lib/arm64-v8a/libhev_external_driver_poc_plugin.so"
require_apk_member "$APK" "lib/arm64-v8a/hev_external_driver_poc_plugin.so"
require_apk_member "$APK" "lib/arm64-v8a/libhev-socks5-tunnel.so"

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

printf 'cell,stage,family,protocol,tcpWriteMode,sourcePort,destinationHost,destinationPort,startRc,intentRc,vpnSessionProvenance,vppStartProvenance,bindResult,sendConnectOutcome,returnOutcome,returnReceived,responseValid,payloadLength,receivedLength,error,cleanupPass,cleanupFail,residualVpp,tun0After,rulesMatch,nativeDirect,nativeRewritten,nativeBroker,nativeUnderlay,nativeHandshake,appValid,nativeValid,valid,verdict\n' >"$CSV"

CELL_SPECS=(
  "ip4-udp-dns|ip4|udp|1.1.1.1|separate"
  "ip4-tcp-dns-separate|ip4|tcp|1.1.1.1|separate"
  "ip4-tcp-dns-coalesced|ip4|tcp|1.1.1.1|coalesced"
  "ip6-udp-dns|ip6|udp|2606:4700:4700::1111|separate"
  "ip6-tcp-dns-separate|ip6|tcp|2606:4700:4700::1111|separate"
  "ip6-tcp-dns-coalesced|ip6|tcp|2606:4700:4700::1111|coalesced"
)

selected=0
failures=0
for spec in "${CELL_SPECS[@]}"; do
  IFS='|' read -r cell_id family protocol destination_host tcp_write_mode <<<"$spec"
  cell_enabled "$cell_id" || continue
  selected=$((selected + 1))
  source_port=$((SOURCE_PORT_BASE + selected))
  stage="S178-$cell_id"
  cell_dir="$CELL_ROOT/$cell_id"
  mkdir -p "$cell_dir"
  echo "## cell=$cell_id stage=$stage family=$family protocol=$protocol source=$source_port destination=$destination_host:53 mode=$tcp_write_mode"
  stop_vpn
  adb_cmd shell am force-stop "$APP_PACKAGE" >/dev/null 2>&1 || true
  adb_read "rm -f '$APP_B1_LOG' '$REMOTE_VPN_SESSION' '$REMOTE_VPP_START' '$REMOTE_CLI_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_HEV_LOG' '$REMOTE_PROTECT_LOG' '$REMOTE_OI3_BROKER_LOG'"
  baseline_rules="$(adb_read 'ip rule show')"
  printf '%s\n' "$baseline_rules" >"$cell_dir/baseline-ip-rules.txt"
  adb_read "ps -A -o USER,PID,PPID,RSS,NAME,ARGS 2>/dev/null || ps -A" >"$cell_dir/processes-before.txt"
  adb_cmd logcat -c >/dev/null 2>&1 || true
  start_rc="$(start_vpn_for_cell "$cell_dir")"
  vpp_pid="$(wait_vpp_ready || true)"
  if [[ -z "$vpp_pid" ]]; then
    echo "cell=$cell_id INVALID: VPP/OI3 four-owner startup not proven" >&2
  fi
  sleep 1
  intent_rc="$(run_b1_intent "$stage" "$family" "$protocol" "$source_port" "$destination_host" "$tcp_write_mode" "$cell_dir")"
  wait_b1_record "$stage" || echo "cell=$cell_id B1 record wait timed out" >&2
  sleep "$POST_B1_NATIVE_SETTLE_SECONDS"
  capture_cell_common "$cell_dir"
  stop_vpn
  safe_capture_remote_tail "$REMOTE_STDOUT_LOG" "$cell_dir/cleanup-stdout.log"
  safe_capture_remote_tail "$REMOTE_CLI_LOG" "$cell_dir/cleanup-cli.log"
  {
    cat "$cell_dir/cleanup-stdout.log" 2>/dev/null || true
    cat "$cell_dir/cleanup-cli.log" 2>/dev/null || true
  } >"$cell_dir/cleanup.log"
  adb_read "ps -A -o USER,PID,PPID,RSS,NAME,ARGS 2>/dev/null || ps -A" >"$cell_dir/processes-after-stop.txt"
  after_rules="$(adb_read 'ip rule show')"
  printf '%s\n' "$after_rules" >"$cell_dir/after-ip-rules.txt"
  residual_vpp="$(adb_read "pidof vpp 2>/dev/null || true" | tr -d '\n')"
  tun0_after_output="$(adb_read 'ip link show tun0 2>/dev/null || true')"
  printf '%s\n' "$tun0_after_output" >"$cell_dir/tun0-after.txt"
  tun0_after=0
  [[ "$tun0_after_output" == *"tun0:"* ]] && tun0_after=1
  rules_match=0
  [[ "$baseline_rules" == "$after_rules" ]] && rules_match=1
  summarize_cell "$cell_id" "$stage" "$family" "$protocol" "$tcp_write_mode" \
    "$source_port" "$destination_host" "$start_rc" "$intent_rc" "$cell_dir" \
    "$residual_vpp" "$tun0_after" "$rules_match" >>"$CSV"
  verdict="$(tail -n 1 "$CSV" | awk -F, '{print $NF}')"
  echo "cell=$cell_id verdict=$verdict"
  if [[ "$verdict" == "FAIL" ]]; then
    failures=$((failures + 1))
    break
  fi
done

if [[ "$selected" == 0 ]]; then
  echo "No cells selected by CELLS=$CELLS" >&2
  exit 2
fi

write_validity_and_manifest
echo "results=$RESULT_DIR"
echo "csv=$CSV"
echo "manifest=$MANIFEST"
echo "validity=$VALIDITY"
echo "failures=$failures"

[[ "$failures" == 0 ]]
