#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: expose VPP/HEV lifecycle and resource residue over 50 cycles.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
CYCLES="${CYCLES:-50}"
HOST4="${HOST4:-142.251.13.94}"
PORT="${PORT:-80}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-50-cycle-poc}"
BUILD="${BUILD:-0}"
INSTALL="${INSTALL:-0}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-4-vpp-hev-50-cycle-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
CSV="$RESULT_DIR/cycles.csv"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SERVER_LOG="$REMOTE_ROOT/socks5.log"
SERVER_PID="$REMOTE_ROOT/socks5.pid"
APP_HTTP_LOG="files/logs/app-http-probe.log"
HEV_LOG="files/vpp/logs/vpp-hev.log"
PROTECT_LOG="files/vpp/logs/vpp-protect.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/rounds"
exec > >(tee "$RUN_LOG") 2>&1

app_cmd() {
  adb_cmd shell run-as "$PACKAGE" "$@"
}

app_read() {
  app_cmd cat "$1" 2>/dev/null | tr -d '\r' || true
}

stop_app() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 1
}

stop_server() {
  adb_cmd shell "if [ -f '$SERVER_PID' ]; then kill -TERM \$(cat '$SERVER_PID') 2>/dev/null || true; fi; rm -f '$SERVER_PID'" >/dev/null 2>&1 || true
}

cleanup() {
  stop_app
  stop_server
}
trap cleanup EXIT

process_snapshot() {
  adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS | tr -d '\r'
}

fd_count() {
  local pid="$1"
  if [[ -z "$pid" || "$pid" == "0" ]]; then
    printf '0\n'
    return
  fi
  app_cmd ls -1 "/proc/$pid/fd" 2>/dev/null | tr -d '\r' | wc -l
}

echo "# SAKAMOTO-4 VPP/HEV $CYCLES-cycle POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
echo "host=$HOST4:$PORT mode=vpp-hev-owner-resolver"

if [[ "$BUILD" == "1" ]]; then
  "$SCRIPT_DIR/android-build-hev.sh"
  "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
fi
if [[ "$INSTALL" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
fi

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
package_uid="$(awk -F'uid:' -v package="package:$PACKAGE" 'index($0, package) == 1 {print $2; exit}' <<<"$packages")"
[[ -n "$package_uid" ]]
miss_uid=$((package_uid + 100000))
echo "package_uid=$package_uid"

"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null
stop_app
stop_server
adb_cmd shell mkdir -p "$REMOTE_ROOT"
adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
adb_cmd shell chmod 755 "$REMOTE_SERVER"
adb_cmd shell "nohup '$REMOTE_SERVER' >'$SERVER_LOG' 2>&1 < /dev/null & echo \$! >'$SERVER_PID'"
sleep 1

baseline_rules="$(adb_cmd shell ip rule show | tr -d '\r')"
printf '%s\n' "$baseline_rules" >"$RESULT_DIR/baseline-ip-rules.txt"
printf '%s\n' 'round,start_rc,http_ok,app_pid,vpp_pid,hev_pid,app_rss_kb,vpp_rss_kb,hev_rss_kb,app_fd,vpp_fd,hev_fd,protect_ok,critical_errors,residual_processes,tun0_after,rules_match_baseline' >"$CSV"

failures=0
for round in $(seq 1 "$CYCLES"); do
  round_dir="$RESULT_DIR/rounds/$(printf '%02d' "$round")"
  mkdir -p "$round_dir"
  app_cmd rm -f "$APP_HTTP_LOG" "$HEV_LOG" "$PROTECT_LOG" >/dev/null 2>&1 || true
  adb_cmd logcat -c

  set +e
  start_output="$(adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true \
    --es mode vpp-hev-owner-resolver \
    --es allowedPackage "$PACKAGE" \
    --ei blockOwnerUid "$miss_uid" 2>&1)"
  start_rc=$?
  set -e
  printf '%s\n' "$start_output" >"$round_dir/start.txt"
  sleep 1

  active_ps="$(process_snapshot)"
  printf '%s\n' "$active_ps" >"$round_dir/active-processes.txt"
  app_pid="$(awk -v uid="$package_uid" -v pkg="$PACKAGE" '$1 == uid && $5 == pkg {if (!min || $2 < min) min=$2} END {print min+0}' <<<"$active_ps")"
  vpp_pid="$(awk -v uid="$package_uid" '$1 == uid && $5 == "vpp" {print $2; exit}' <<<"$active_ps")"
  hev_pid="$(awk -v uid="$package_uid" -v pkg="$PACKAGE" -v parent="$app_pid" '$1 == uid && $5 == pkg && $3 == parent {print $2; exit}' <<<"$active_ps")"
  app_rss="$(awk -v pid="$app_pid" '$2 == pid {print $4; exit}' <<<"$active_ps")"
  vpp_rss="$(awk -v pid="$vpp_pid" '$2 == pid {print $4; exit}' <<<"$active_ps")"
  hev_rss="$(awk -v pid="$hev_pid" '$2 == pid {print $4; exit}' <<<"$active_ps")"
  app_fd="$(fd_count "${app_pid:-0}")"
  vpp_fd="$(fd_count "${vpp_pid:-0}")"
  hev_fd="$(fd_count "${hev_pid:-0}")"

  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appHttpProbe true --es host "$HOST4" --ei port "$PORT" \
    --es path "/sakamoto-4-$round" >/dev/null
  sleep 2
  http_log="$(app_read "$APP_HTTP_LOG")"
  protect_log="$(app_read "$PROTECT_LOG")"
  printf '%s\n' "$http_log" >"$round_dir/http.log"
  printf '%s\n' "$protect_log" >"$round_dir/protect.log"
  http_ok=0
  protect_ok=0
  grep -Fq ' ok bytes=' <<<"$http_log" && http_ok=1
  grep -Fq 'protect fd=' <<<"$protect_log" && grep -Fq 'result=1' <<<"$protect_log" && protect_ok=1

  stop_app
  after_ps="$(process_snapshot)"
  printf '%s\n' "$after_ps" >"$round_dir/after-processes.txt"
  residual="$(awk -v uid="$package_uid" -v pkg="$PACKAGE" '$1 == uid && ($5 == pkg || $5 == "vpp") {count++} END {print count+0}' <<<"$after_ps")"
  tun0_after=0
  adb_cmd shell ip link show tun0 >/dev/null 2>&1 && tun0_after=1
  after_rules="$(adb_cmd shell ip rule show | tr -d '\r')"
  printf '%s\n' "$after_rules" >"$round_dir/after-ip-rules.txt"
  rules_match=0
  [[ "$after_rules" == "$baseline_rules" ]] && rules_match=1
  logcat_text="$(adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r')"
  printf '%s\n' "$logcat_text" >"$round_dir/logcat.txt"
  critical="$(grep -Eic 'fatal|segmentation|abort|nativeStartVppProbe.*rc=-|protect.*result=0|dlopen failed|dlsym failed' <<<"$logcat_text" || true)"

  printf '%s\n' "$round,$start_rc,$http_ok,${app_pid:-0},${vpp_pid:-0},${hev_pid:-0},${app_rss:-0},${vpp_rss:-0},${hev_rss:-0},${app_fd:-0},${vpp_fd:-0},${hev_fd:-0},$protect_ok,$critical,$residual,$tun0_after,$rules_match" >>"$CSV"

  if [[ "$start_rc" != "0" || "$http_ok" != "1" || "$protect_ok" != "1" ||
        -z "$vpp_pid" || -z "$hev_pid" || "$critical" != "0" ||
        "$residual" != "0" || "$tun0_after" != "0" || "$rules_match" != "1" ]]; then
    failures=$((failures + 1))
    echo "round=$round FAIL start=$start_rc http=$http_ok protect=$protect_ok residual=$residual tun0=$tun0_after rules=$rules_match critical=$critical"
  else
    echo "round=$round PASS rss=$app_rss/$vpp_rss/$hev_rss fd=$app_fd/$vpp_fd/$hev_fd"
  fi
done

adb_cmd shell cat "$SERVER_LOG" >"$RESULT_DIR/socks-server.log"

awk -F, 'NR == 2 {for (i=7;i<=12;i++) min[i]=max[i]=$i} NR > 1 {for (i=7;i<=12;i++) {sum[i]+=$i; if ($i<min[i]) min[i]=$i; if ($i>max[i]) max[i]=$i}} END {name[7]="app_rss_kb";name[8]="vpp_rss_kb";name[9]="hev_rss_kb";name[10]="app_fd";name[11]="vpp_fd";name[12]="hev_fd"; for(i=7;i<=12;i++) printf "%s min=%d avg=%.1f max=%d\n",name[i],min[i],sum[i]/(NR-1),max[i]}' "$CSV" >"$RESULT_DIR/resource-summary.txt"

# Add first/last and deltas with a second pass to keep the raw CSV authoritative.
awk -F, 'NR==2 {for(i=7;i<=12;i++) first[i]=$i} NR>1 {for(i=7;i<=12;i++) last[i]=$i} END {for(i=7;i<=12;i++) printf "column_%d first=%d last=%d delta=%d\n",i,first[i],last[i],last[i]-first[i]}' "$CSV" >>"$RESULT_DIR/resource-summary.txt"
cat "$RESULT_DIR/resource-summary.txt"
echo "failures=$failures cycles=$CYCLES"
[[ "$failures" == "0" ]]
echo "PASS: $CYCLES VPP/HEV start-stop cycles"
echo "result_dir=$RESULT_DIR"
