#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: sample Android idle behavior and traffic recovery after screen wake.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST4="${HOST4:-142.251.13.94}"
HOST6="${HOST6:-2606:4700:4700::1111}"
PORT="${PORT:-80}"
SAMPLES="${SAMPLES:-20}"
INTERVAL="${INTERVAL:-30}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-idle-wake-poc}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-6-idle-wake-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
CSV="$RESULT_DIR/samples.csv"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SERVER_LOG="$REMOTE_ROOT/socks5.log"
SERVER_PID="$REMOTE_ROOT/socks5.pid"
APP_HTTP_LOG="files/logs/app-http-probe.log"
HEV_LOG="files/vpp/logs/vpp-hev.log"
PROTECT_LOG="files/vpp/logs/vpp-protect.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/samples"
exec > >(tee "$RUN_LOG") 2>&1

screen_off=0

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
}

stop_server() {
  adb_cmd shell "if [ -f '$SERVER_PID' ]; then kill -TERM \$(cat '$SERVER_PID') 2>/dev/null || true; fi; rm -f '$SERVER_PID'" >/dev/null 2>&1 || true
}

start_server() {
  adb_cmd shell mkdir -p "$REMOTE_ROOT"
  adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
  adb_cmd shell chmod 755 "$REMOTE_SERVER"
  adb_cmd shell "nohup '$REMOTE_SERVER' >'$SERVER_LOG' 2>&1 < /dev/null & echo \$! >'$SERVER_PID'"
  sleep 1
}

process_snapshot() {
  adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS | tr -d '\r'
}

cpu_ticks() {
  local pid="$1"
  if [[ -z "$pid" || "$pid" == "0" ]]; then
    printf '0\n'
    return
  fi
  app_cmd cat "/proc/$pid/stat" 2>/dev/null | awk '{print $14 + $15}' | tail -n 1
}

probe() {
  local family="$1"
  local host="$2"
  local name="$3"
  app_cmd rm -f "$APP_HTTP_LOG" "$HEV_LOG" "$PROTECT_LOG" >/dev/null 2>&1 || true
  local started="$(date +%s)"
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appHttpProbe true --es host "$host" --ei port "$PORT" \
    --es path "/sakamoto-6-$name" >/dev/null
  sleep 6
  local finished="$(date +%s)"
  local http="$(app_read "$APP_HTTP_LOG")"
  local protect="$(app_read "$PROTECT_LOG")"
  printf '%s\n' "$http" >"$RESULT_DIR/$name-http.log"
  printf '%s\n' "$protect" >"$RESULT_DIR/$name-protect.log"
  echo "probe=$name family=$family elapsed_lower_bound_ms=$(( (finished - started) * 1000 ))"
  printf '%s\n' "$http"
}

sample() {
  local index="$1"
  local sample_name
  if [[ "$index" =~ ^[0-9]+$ ]]; then
    printf -v sample_name '%02d' "$index"
  else
    sample_name="$index"
  fi
  local dir="$RESULT_DIR/samples/$sample_name"
  mkdir -p "$dir"
  local ps
  ps="$(process_snapshot)"
  printf '%s\n' "$ps" >"$dir/processes.txt"

  local app_pid vpp_pid hev_pid
  app_pid="$(awk -v uid="$package_uid" -v pkg="$PACKAGE" '$1 == uid && $5 == pkg {if (!min || $2 < min) min=$2} END {print min+0}' <<<"$ps")"
  vpp_pid="$(awk -v uid="$package_uid" '$1 == uid && $5 == "vpp" {print $2; exit}' <<<"$ps")"
  hev_pid="$(awk -v uid="$package_uid" -v pkg="$PACKAGE" -v parent="$app_pid" '$1 == uid && $5 == pkg && $3 == parent {print $2; exit}' <<<"$ps")"
  local app_rss vpp_rss hev_rss
  app_rss="$(awk -v pid="$app_pid" '$2 == pid {print $4; exit}' <<<"$ps")"
  vpp_rss="$(awk -v pid="$vpp_pid" '$2 == pid {print $4; exit}' <<<"$ps")"
  hev_rss="$(awk -v pid="$hev_pid" '$2 == pid {print $4; exit}' <<<"$ps")"
  local app_cpu vpp_cpu hev_cpu
  app_cpu="$(cpu_ticks "$app_pid")"
  vpp_cpu="$(cpu_ticks "$vpp_pid")"
  hev_cpu="$(cpu_ticks "$hev_pid")"

  adb_cmd shell dumpsys power >"$dir/power.txt"
  adb_cmd shell dumpsys deviceidle >"$dir/deviceidle.txt"
  adb_cmd shell dumpsys batterystats --charged >"$dir/batterystats.txt"
  adb_cmd shell dumpsys battery >"$dir/battery.txt"
  adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' >"$dir/logcat.txt"
  local wakefulness
  wakefulness="$(rg -m1 'mWakefulness=|mInteractive=' "$dir/power.txt" | tr '\n' ' ' || true)"
  local device_idle
  device_idle="$(rg -m1 'mState=|mScreenOn=' "$dir/deviceidle.txt" | tr '\n' ' ' || true)"
  local alive=0
  [[ -n "$vpp_pid" && "$vpp_pid" != "0" && -n "$hev_pid" && "$hev_pid" != "0" ]] && alive=1

  printf '%s\n' "$index,$app_pid,$vpp_pid,$hev_pid,${app_cpu:-0},${vpp_cpu:-0},${hev_cpu:-0},${app_rss:-0},${vpp_rss:-0},${hev_rss:-0},$alive" >>"$CSV"
  echo "sample=$index alive=$alive cpu_ticks=$app_cpu/$vpp_cpu/$hev_cpu rss_kb=$app_rss/$vpp_rss/$hev_rss $wakefulness $device_idle"
}

wake_device() {
  if [[ "$screen_off" == "1" ]] && ! adb_cmd shell dumpsys power | rg -q 'mInteractive=true|mWakefulness=Awake'; then
    adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
    sleep 3
  fi
  screen_off=0
}

ensure_screen_on() {
  if ! adb_cmd shell dumpsys power | rg -q 'mInteractive=true|mWakefulness=Awake'; then
    adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
    sleep 3
  fi
}

cleanup() {
  wake_device
  stop_app
  stop_server
}
trap cleanup EXIT INT TERM

echo "# SAKAMOTO-6 Android idle/wake POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
echo "battery=$(adb_cmd shell dumpsys battery | rg 'level:|temperature:|AC powered|USB powered|Wi-Fi powered' | tr '\n' ' ')"
echo "wifi=$(adb_cmd shell cmd wifi status | rg -m1 'Wifi is|WifiInfo:' | tr '\n' ' ')"
echo "apk_sha256=$(sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk")"
echo "vpp_sha256=$(sha256sum "$POC_DIR/work/android-vpp-release-no-multiarch-no-ipsec-idle-stage/bin/vpp")"

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
package_uid="$(awk -F'uid:' -v package="package:$PACKAGE" 'index($0, package) == 1 {print $2; exit}' <<<"$packages")"
[[ -n "$package_uid" ]]
echo "package_uid=$package_uid"

printf '%s\n' 'sample,app_pid,vpp_pid,hev_pid,app_cpu_ticks,vpp_cpu_ticks,hev_cpu_ticks,app_rss_kb,vpp_rss_kb,hev_rss_kb,all_data_processes_alive' >"$CSV"
stop_app
stop_server
start_server
start_vpn() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true --ez enableIpv6 true \
    --es mode vpp-hev-owner-resolver --es allowedPackage "$PACKAGE" \
    --ei blockOwnerUid 112540 >/dev/null
  sleep 5
}
start_vpn
ensure_screen_on
probe ip4 "$HOST4" pre-sleep-ip4
probe ip6 "$HOST6" pre-sleep-ip6
ensure_screen_on
sample 0

echo "## screen off idle window seconds=$((SAMPLES * INTERVAL))"
ensure_screen_on
adb_cmd shell input keyevent 26
screen_off=1
sleep 5
for sample_index in $(seq 1 "$SAMPLES"); do
  sleep "$INTERVAL"
  sample "$sample_index"
done

echo "## wake and probe"
wake_device
sample wake
probe ip4 "$HOST4" post-wake-ip4
probe ip6 "$HOST6" post-wake-ip6
adb_cmd shell cat "$SERVER_LOG" >"$RESULT_DIR/socks-server.log"
adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS >"$RESULT_DIR/final-processes.txt"
adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' >"$RESULT_DIR/final-logcat.txt"

if ! grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/pre-sleep-ip4-http.log" ||
   ! grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/pre-sleep-ip6-http.log" ||
   ! grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/post-wake-ip4-http.log" ||
   ! grep -Fq 'HTTP/1.0 200 OK' "$RESULT_DIR/post-wake-ip6-http.log"; then
  echo "traffic probe failure" >&2
  exit 1
fi

alive_count="$(awk -F, 'NR > 1 && $11 == 1 {count++} END {print count+0}' "$CSV")"
expected_alive=$((SAMPLES + 2))
echo "alive_samples=$alive_count expected=$expected_alive"
[[ "$alive_count" == "$expected_alive" ]]
echo "PASS: $((SAMPLES * INTERVAL))-second screen-off idle window and IPv4/IPv6 wake recovery"
echo "result_dir=$RESULT_DIR"
