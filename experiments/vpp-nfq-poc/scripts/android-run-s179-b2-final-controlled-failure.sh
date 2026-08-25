#!/usr/bin/env bash
set -euo pipefail

# S179 / B2 final-artifact controlled failure-semantics regression.
#
# This runner intentionally exercises the existing controlled full-TUN OI3
# negative cells on the current final VpnLite artifact.  It is not a complete
# external/default-route B2 proof.  The goal is to prove that the S146/S147
# refusal/no-reply/policy-drop outcome contract still holds after the later
# S176/S177/S178 artifact changes.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APK="${APK:-$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s179-b2-final-controlled-failure-$(date +%Y%m%d)}"
CELLS="${CELLS:-refused,no-reply,policy-drop}"
WAIT_APP_RECORD_ATTEMPTS="${WAIT_APP_RECORD_ATTEMPTS:-80}"
WAIT_NATIVE_OUTCOME_ATTEMPTS="${WAIT_NATIVE_OUTCOME_ATTEMPTS:-120}"
WAIT_STOP_SECONDS="${WAIT_STOP_SECONDS:-8}"
ADB_READ_RETRY_ATTEMPTS="${ADB_READ_RETRY_ATTEMPTS:-3}"
ADB_READ_RETRY_DELAY_SECONDS="${ADB_READ_RETRY_DELAY_SECONDS:-1}"
REMOTE_LOG_TAIL_LINES="${REMOTE_LOG_TAIL_LINES:-2400}"
VERIFIER="$SCRIPT_DIR/verify-s146-b2.py"

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
VPN_RECEIPTS="$VPN_FILES/logs"
VPN_VPP_LOGS="$VPN_FILES/vpp/logs"
REMOTE_VPN_SESSION="$VPN_RECEIPTS/vpn-session-provenance.json"
REMOTE_VPN_FAILURE="$VPN_RECEIPTS/vpn-session-provenance-failure.json"
REMOTE_VPP_START="$VPN_RECEIPTS/vpp-start-provenance.json"
REMOTE_APP_LOG="$VPN_RECEIPTS/vpp-oi3-controlled-app.log"
REMOTE_STDOUT_LOG="$VPN_VPP_LOGS/vpp-stdout.log"
REMOTE_CLI_LOG="$VPN_VPP_LOGS/vpp-cli.log"
REMOTE_VPP_LOG="$VPN_VPP_LOGS/vpp.log"
REMOTE_OI3_LOG="$VPN_VPP_LOGS/vpp-oi3-controlled.log"

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

stop_vpn() {
  adb_cmd shell am start -W -n "$VPN_PACKAGE/.MainActivity" --ez stop true \
    >/dev/null 2>&1 || true
  local deadline=$((SECONDS + WAIT_STOP_SECONDS))
  while (( SECONDS <= deadline )); do
    if [[ -z "$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'")" ]]; then
      break
    fi
    sleep 0.25
  done
  adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
  sleep 1
}

cleanup() {
  stop_vpn
}
trap cleanup EXIT

cell_enabled() {
  local cell="$1"
  [[ "$CELLS" == "all" || ",$CELLS," == *",$cell,"* ]]
}

mode_for_cell() {
  case "$1" in
    refused) echo "vpp-oi3-controlled-refused" ;;
    no-reply) echo "vpp-oi3-controlled-no-reply" ;;
    policy-drop) echo "vpp-oi3-controlled-policy-drop" ;;
    *) return 2 ;;
  esac
}

app_result_for_cell() {
  case "$1" in
    refused) echo "EXPECTED_TRANSPORT_FAILURE" ;;
    no-reply) echo "EXPECTED_NO_REPLY_TIMEOUT" ;;
    policy-drop) echo "EXPECTED_POLICY_DROP_NO_TRANSPORT" ;;
    *) return 2 ;;
  esac
}

native_outcome_for_cell() {
  case "$1" in
    refused) echo "EXPECTED_TRANSPORT_REFUSAL" ;;
    no-reply) echo "EXPECTED_TIMEOUT" ;;
    policy-drop) echo "EXPECTED_POLICY_DROP" ;;
    *) return 2 ;;
  esac
}

capture_remote_file() {
  local remote_path="$1" local_path="$2"
  adb_read "if [ -f '$remote_path' ]; then cat '$remote_path' 2>/dev/null; fi" \
    >"$local_path"
}

capture_remote_tail() {
  local remote_path="$1" local_path="$2"
  adb_read "if [ -f '$remote_path' ]; then tail -n '$REMOTE_LOG_TAIL_LINES' '$remote_path' 2>/dev/null; fi" \
    >"$local_path"
}

capture_cell_files() {
  local cell_dir="$1"
  capture_remote_file "$REMOTE_VPN_SESSION" "$cell_dir/vpn-session-provenance.json"
  capture_remote_file "$REMOTE_VPN_FAILURE" "$cell_dir/vpn-session-provenance-failure.json"
  capture_remote_file "$REMOTE_VPP_START" "$cell_dir/vpp-start-provenance.json"
  capture_remote_file "$REMOTE_APP_LOG" "$cell_dir/vpp-oi3-controlled-app.log"
  capture_remote_tail "$REMOTE_STDOUT_LOG" "$cell_dir/vpp-stdout.log"
  capture_remote_tail "$REMOTE_CLI_LOG" "$cell_dir/vpp-cli.log"
  capture_remote_tail "$REMOTE_VPP_LOG" "$cell_dir/vpp.log"
  capture_remote_tail "$REMOTE_OI3_LOG" "$cell_dir/vpp-oi3-controlled.log"
  {
    cat "$cell_dir/vpp-stdout.log" 2>/dev/null || true
    cat "$cell_dir/vpp-cli.log" 2>/dev/null || true
    cat "$cell_dir/vpp-oi3-controlled.log" 2>/dev/null || true
  } >"$cell_dir/native-combined.log"
  adb_read 'dumpsys connectivity 2>/dev/null || true' >"$cell_dir/connectivity.txt"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' \
    | tr -d '\r' >"$cell_dir/logcat.txt" || true
}

wait_app_record() {
  local cell="$1" expected_result="$2"
  for _ in $(seq 1 "$WAIT_APP_RECORD_ATTEMPTS"); do
    if adb_read "if [ -f '$REMOTE_APP_LOG' ]; then tail -n 20 '$REMOTE_APP_LOG' 2>/dev/null; fi" \
      | grep -Eq "\\bcell=$cell\\b.*\\bresult=$expected_result\\b"; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

wait_native_outcome() {
  local outcome="$1"
  for _ in $(seq 1 "$WAIT_NATIVE_OUTCOME_ATTEMPTS"); do
    if adb_read "for f in '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' '$REMOTE_OI3_LOG'; do if [ -f \"\$f\" ]; then tail -n 160 \"\$f\" 2>/dev/null; fi; done" \
      | grep -Eq "\\boi3_cleanup\\b.*\\bresult=PASS_EXPECTED_FAILURE\\b.*\\boutcome=$outcome\\b"; then
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

write_run_provenance() {
  local vpn_uid="$1" vpn_installed
  vpn_installed="$(installed_apk_path "$VPN_PACKAGE")"
  {
    printf 'package\tuid\thost_apk\thost_sha256\tinstalled_path\tinstalled_sha256\n'
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$VPN_PACKAGE" "$vpn_uid" "$APK" "$(sha256sum "$APK" | awk '{print $1}')" \
      "$vpn_installed" "$(adb_read "sha256sum '$vpn_installed' 2>/dev/null | awk '{print \$1}'")"
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
    echo "runner=android-run-s179-b2-final-controlled-failure.sh"
    echo "scope=bounded_final_artifact_controlled_b2_failure_semantics"
    echo "cells=$CELLS"
    echo "expected_hash_policy=current-artifact-by-default-no-static-historical-hashes"
    echo "claim_boundary=controlled-full-tun-regression-not-external-default-route-b2"
  } >"$RESULT_DIR/source-provenance.properties"
  adb_read "cmd package list packages -U | grep -E '($VPN_PACKAGE)' || true" \
    >"$RESULT_DIR/package-list-packages-U.txt"
}

start_cell() {
  local mode="$1" cell_dir="$2"
  set +e
  adb_cmd shell am start -W -n "$VPN_PACKAGE/.MainActivity" \
    --ez start true --es mode "$mode" --ez oi3AppInject true \
    --ez ownerCache false --ez enableIpv6 false >"$cell_dir/start.txt" 2>&1
  local rc=$?
  set -e
  printf '%s\n' "$rc"
}

summarize_cell() {
  local cell="$1" mode="$2" start_rc="$3" app_wait="$4" native_wait="$5"
  local verifier_rc="$6" cell_dir="$7" residual_vpp="$8" tun0_after="$9"
  python3 - "$cell" "$mode" "$start_rc" "$app_wait" "$native_wait" \
    "$verifier_rc" "$cell_dir" "$residual_vpp" "$tun0_after" <<'PY'
import csv
import re
import sys
from pathlib import Path

cell, mode = sys.argv[1:3]
start_rc = int(sys.argv[3])
app_wait = int(sys.argv[4])
native_wait = int(sys.argv[5])
verifier_rc = int(sys.argv[6])
cell_dir = Path(sys.argv[7])
residual_vpp = sys.argv[8]
tun0_after = int(sys.argv[9])
app_text = (cell_dir / "vpp-oi3-controlled-app.log").read_text(
    encoding="utf-8", errors="replace") if (cell_dir / "vpp-oi3-controlled-app.log").exists() else ""
native_text = (cell_dir / "native-combined.log").read_text(
    encoding="utf-8", errors="replace") if (cell_dir / "native-combined.log").exists() else ""
app_line = ""
for line in app_text.splitlines():
    if re.search(rf"\bcell={re.escape(cell)}\b", line):
        app_line = line
native_line = ""
for line in native_text.splitlines():
    if "oi3_cleanup" in line and "PASS_EXPECTED_FAILURE" in line:
        native_line = line
vpn_prov = int((cell_dir / "vpn-session-provenance.json").exists()
               and (cell_dir / "vpn-session-provenance.json").stat().st_size > 0)
vpp_prov = int((cell_dir / "vpp-start-provenance.json").exists()
               and (cell_dir / "vpp-start-provenance.json").stat().st_size > 0)
residue_valid = int(residual_vpp == "" and tun0_after == 0)
verdict = "PASS" if (
    start_rc == 0 and app_wait == 1 and native_wait == 1 and verifier_rc == 0
    and vpn_prov == 1 and vpp_prov == 1 and residue_valid == 1
) else "FAIL"
row = [
    cell, mode, start_rc, app_wait, native_wait, verifier_rc, vpn_prov,
    vpp_prov, residual_vpp, tun0_after, residue_valid, app_line, native_line,
    verdict,
]
csv.writer(sys.stdout, lineterminator="\n").writerow(row)
PY
}

write_validity_and_manifest() {
  python3 - "$RUN_ID" "$CSV" "$MANIFEST" "$VALIDITY" "$APK" "$VPN_PACKAGE" "$CELL_ROOT" <<'PY'
import csv
import hashlib
import json
import sys
from pathlib import Path

run_id, csv_path, manifest_path, validity_path, apk, vpn_package, cell_root = sys.argv[1:8]
rows = list(csv.DictReader(Path(csv_path).open(newline="", encoding="utf-8")))
pass_count = sum(1 for row in rows if row["verdict"] == "PASS")
fail_count = len(rows) - pass_count
def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
status = "PASS" if rows and fail_count == 0 else "FAIL"
manifest = {
    "schema": "s179-b2-final-controlled-failure/v1",
    "runId": run_id,
    "status": status,
    "scope": "bounded_final_artifact_controlled_b2_failure_semantics",
    "claimBoundary": "controlled full-TUN negative semantics regression; not external/default-route B2 closure",
    "vpnPackage": vpn_package,
    "cellRoot": cell_root,
    "cellsRecorded": len(rows),
    "passCount": pass_count,
    "failureCount": fail_count,
    "vpnApkSha256": sha(apk),
}
Path(manifest_path).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
lines = [
    f"status={status}",
    f"run_id={run_id}",
    "scope=bounded_final_artifact_controlled_b2_failure_semantics",
    "claim_boundary=controlled full-TUN negative semantics regression; not external/default-route B2 closure",
    f"cells_recorded={len(rows)}",
    f"pass_count={pass_count}",
    f"failure_count={fail_count}",
    "non_claim=not complete B2, not external/default-route failure coverage, not AppA policy matrix, not performance/soak",
]
for row in rows:
    lines.append(
        "cell={cell} verdict={verdict} appWait={appWait} nativeWait={nativeWait} "
        "verifierRc={verifierRc} residualVpp={residualVpp} tun0={tun0After}".format(**row)
    )
Path(validity_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

echo "# S179 B2 final-artifact controlled failure-semantics regression"
echo "run_id=$RUN_ID"
echo "device=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE cells=$CELLS"

device_preflight
[[ -f "$APK" ]] || { echo "VPN APK not found: $APK" >&2; exit 1; }
[[ -f "$VERIFIER" ]] || { echo "Verifier not found: $VERIFIER" >&2; exit 1; }
unzip -l "$APK" "lib/arm64-v8a/libhev_external_driver_poc_plugin.so" >/dev/null
unzip -l "$APK" "lib/arm64-v8a/hev_external_driver_poc_plugin.so" >/dev/null
unzip -l "$APK" "lib/arm64-v8a/libhev-socks5-tunnel.so" >/dev/null

stop_vpn
adb_cmd install -r "$APK" >/dev/null
adb_cmd shell am compat disable RESTRICT_LOCAL_NETWORK "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell pm grant "$VPN_PACKAGE" android.permission.NEARBY_WIFI_DEVICES >/dev/null 2>&1 || true

vpn_uid="$(package_uid "$VPN_PACKAGE")"
[[ -n "$vpn_uid" ]] || { echo "VPN package UID unavailable" >&2; exit 1; }
echo "vpn_uid=$vpn_uid"
write_run_provenance "$vpn_uid"

printf 'cell,mode,startRc,appWait,nativeWait,verifierRc,vpnSessionProvenance,vppStartProvenance,residualVpp,tun0After,residueValid,appLine,nativeLine,verdict\n' >"$CSV"

failures=0
for cell in refused no-reply policy-drop; do
  cell_enabled "$cell" || continue
  mode="$(mode_for_cell "$cell")"
  expected_app="$(app_result_for_cell "$cell")"
  expected_native="$(native_outcome_for_cell "$cell")"
  cell_dir="$CELL_ROOT/$cell"
  mkdir -p "$cell_dir"
  echo "## cell=$cell mode=$mode expected_app=$expected_app expected_native=$expected_native"
  stop_vpn
  adb_read "rm -f '$REMOTE_VPN_SESSION' '$REMOTE_VPN_FAILURE' '$REMOTE_VPP_START' '$REMOTE_APP_LOG' '$REMOTE_STDOUT_LOG' '$REMOTE_CLI_LOG' '$REMOTE_VPP_LOG' '$REMOTE_OI3_LOG'"
  adb_cmd logcat -c >/dev/null 2>&1 || true
  adb_read "ps -A -o USER,PID,PPID,RSS,NAME,ARGS 2>/dev/null || ps -A" >"$cell_dir/processes-before.txt"
  start_rc="$(start_cell "$mode" "$cell_dir")"
  app_wait=0
  native_wait=0
  if wait_app_record "$cell" "$expected_app"; then
    app_wait=1
  else
    echo "cell=$cell app expected record not observed" >&2
  fi
  if wait_native_outcome "$expected_native"; then
    native_wait=1
  else
    echo "cell=$cell native expected outcome not observed" >&2
  fi
  capture_cell_files "$cell_dir"
  set +e
  python3 "$VERIFIER" --cell "$cell" \
    --app-log "$cell_dir/vpp-oi3-controlled-app.log" \
    --native-log "$cell_dir/native-combined.log" \
    >"$cell_dir/verify-s146-b2.txt" 2>&1
  verifier_rc=$?
  set -e
  stop_vpn
  residual_vpp="$(adb_read "pidof vpp 2>/dev/null | awk '{print \$1}'" | tr -d '\n')"
  tun0_text="$(adb_read "ip link show tun0 2>/dev/null || true")"
  printf '%s\n' "$tun0_text" >"$cell_dir/tun0-after.txt"
  tun0_after=0
  if [[ "$tun0_text" == *"tun0:"* ]]; then
    tun0_after=1
  fi
  adb_read "ps -A -o USER,PID,PPID,RSS,NAME,ARGS 2>/dev/null || ps -A" >"$cell_dir/processes-after-stop.txt"
  summarize_cell "$cell" "$mode" "$start_rc" "$app_wait" "$native_wait" \
    "$verifier_rc" "$cell_dir" "$residual_vpp" "$tun0_after" >>"$CSV"
  verdict="$(tail -n 1 "$CSV" | awk -F, '{print $NF}')"
  echo "cell=$cell verifier_rc=$verifier_rc verdict=$verdict"
  if [[ "$verdict" != "PASS" ]]; then
    failures=$((failures + 1))
  fi
done

write_validity_and_manifest
cat "$VALIDITY"
if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
