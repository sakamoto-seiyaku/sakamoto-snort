#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: measure sustained app-UID TCP/UDP load through Android VPP/HEV.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
HOST4="${HOST4:-142.251.13.94}"
TCP_PORT="${TCP_PORT:-80}"
UDP_HOST="${UDP_HOST:-8.8.8.8}"
UDP_PORT="${UDP_PORT:-53}"
ROUNDS="${ROUNDS:-3}"
DURATION_SECONDS="${DURATION_SECONDS:-300}"
WARMUP_SECONDS="${WARMUP_SECONDS:-15}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-15}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-30}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-throughput-risk-poc}"

RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-7-throughput-risk-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
SAMPLES_CSV="$RESULT_DIR/samples.csv"
ROUNDS_CSV="$RESULT_DIR/rounds.csv"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SERVER_LOG="$REMOTE_ROOT/socks5.log"
SERVER_PID="$REMOTE_ROOT/socks5.pid"
APP_HTTP_LOG="files/logs/app-http-probe.log"
APP_UDP_LOG="files/logs/app-udp-probe.log"
VPP_CLI_LOG="files/vpp/logs/vpp-cli.log"
HEV_LOG="files/vpp/logs/vpp-hev.log"
PROTECT_LOG="files/vpp/logs/vpp-protect.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR/samples" "$RESULT_DIR/rounds"
exec > >(tee "$RUN_LOG") 2>&1

battery_unplugged=0
screen_off=0
failures=0
package_uid=""
miss_uid=""

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
  adb_cmd shell "if [ -f '$SERVER_PID' ]; then kill -TERM \$(cat '$SERVER_PID') 2>/dev/null || true; fi; rm -f '$SERVER_PID'" \
    >/dev/null 2>&1 || true
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

cpu_processor() {
  local pid="$1"
  if [[ -z "$pid" || "$pid" == "0" ]]; then
    printf '%s\n' '-'
    return
  fi
  app_cmd cat "/proc/$pid/stat" 2>/dev/null | awk '{print $39}' | tail -n 1
}

cpu_allowed() {
  local pid="$1"
  if [[ -z "$pid" || "$pid" == "0" ]]; then
    printf '%s\n' '-'
    return
  fi
  app_cmd cat "/proc/$pid/status" 2>/dev/null | tr -d '\r' | awk '/Cpus_allowed_list:/ {print $2}' | tail -n 1
}

battery_value() {
  local key="$1"
  local battery="$2"
  awk -F: -v key="$key" '$1 ~ key {gsub(/[[:space:]]/, "", $2); print $2; exit}' <<<"$battery"
}

ensure_screen_on() {
  if ! adb_cmd shell dumpsys power | rg -q 'mInteractive=true|mWakefulness=Awake'; then
    adb_cmd shell input keyevent 224 >/dev/null 2>&1 || adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
    sleep 3
  fi
}

wake_device() {
  if [[ "$screen_off" == "1" ]]; then
    ensure_screen_on
    screen_off=0
  fi
}

capture_device_identity() {
  {
    echo "run_id=$RUN_ID"
    echo "adb_serial=$(resolve_adb_serial)"
    echo "device=$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
    echo "android=$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
    echo "build_fingerprint=$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r')"
    echo "abi=$(adb_cmd shell getprop ro.product.cpu.abilist | tr -d '\r')"
    echo "kernel=$(adb_cmd shell uname -a | tr -d '\r')"
    echo "apk_sha256=$(sha256sum "$POC_DIR/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk")"
    echo "vpp_sha256=$(sha256sum "$POC_DIR/work/android-vpp-release-no-multiarch-no-ipsec-idle-stage/bin/vpp")"
    echo "host4=$HOST4 tcp_port=$TCP_PORT udp_host=$UDP_HOST udp_port=$UDP_PORT"
    echo "rounds=$ROUNDS duration_seconds=$DURATION_SECONDS warmup_seconds=$WARMUP_SECONDS sample_interval=$SAMPLE_INTERVAL cooldown_seconds=$COOLDOWN_SECONDS"
    echo "## battery before unplug"
    adb_cmd shell dumpsys battery | tr -d '\r'
    echo "## wifi"
    adb_cmd shell cmd wifi status | tr -d '\r'
    echo "## interfaces"
    adb_cmd shell ip addr show | tr -d '\r'
    echo "## routes4"
    adb_cmd shell ip route show | tr -d '\r'
    echo "## routes6"
    adb_cmd shell ip -6 route show | tr -d '\r'
    echo "## cpuinfo"
    adb_cmd shell "cat /proc/cpuinfo" | tr -d '\r'
  } >"$RESULT_DIR/device-identity.txt"
  adb_cmd shell dumpsys thermalservice | tr -d '\r' >"$RESULT_DIR/thermal-before.txt"
}

sample_round() {
  local round="$1"
  local kind="$2"
  local index="$3"
  local elapsed="$4"
  local dir="$RESULT_DIR/samples/$(printf '%02d-%s-%03d' "$round" "$kind" "$index")"
  mkdir -p "$dir"

  local ps battery power idle thermal http udp cli logcat
  ps="$(process_snapshot)"
  battery="$(adb_cmd shell dumpsys battery | tr -d '\r')"
  power="$(adb_cmd shell dumpsys power | tr -d '\r')"
  idle="$(adb_cmd shell dumpsys deviceidle | tr -d '\r')"
  thermal="$(adb_cmd shell dumpsys thermalservice | tr -d '\r')"
  http="$(app_read "$APP_HTTP_LOG")"
  udp="$(app_read "$APP_UDP_LOG")"
  cli="$(app_read "$VPP_CLI_LOG")"
  logcat="$(adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r')"

  printf '%s\n' "$ps" >"$dir/processes.txt"
  printf '%s\n' "$battery" >"$dir/battery.txt"
  printf '%s\n' "$power" >"$dir/power.txt"
  printf '%s\n' "$idle" >"$dir/deviceidle.txt"
  printf '%s\n' "$thermal" >"$dir/thermalservice.txt"
  printf '%s\n' "$http" >"$dir/app-http-probe.log"
  printf '%s\n' "$udp" >"$dir/app-udp-probe.log"
  printf '%s\n' "$cli" >"$dir/vpp-cli.log"
  printf '%s\n' "$logcat" >"$dir/logcat.txt"

  local app_pid vpp_pid hev_pid
  app_pid="$(awk -v uid="$package_uid" -v pkg="$PACKAGE" '$1 == uid && $5 == pkg {if (!min || $2 < min) min=$2} END {print min+0}' <<<"$ps")"
  vpp_pid="$(awk -v uid="$package_uid" '$1 == uid && $5 == "vpp" {print $2; exit}' <<<"$ps")"
  hev_pid="$(awk -v uid="$package_uid" -v pkg="$PACKAGE" -v parent="$app_pid" '$1 == uid && $5 == pkg && $3 == parent {print $2; exit}' <<<"$ps")"

  local app_rss vpp_rss hev_rss app_ticks vpp_ticks hev_ticks
  app_rss="$(awk -v pid="$app_pid" '$2 == pid {print $4; exit}' <<<"$ps")"
  vpp_rss="$(awk -v pid="$vpp_pid" '$2 == pid {print $4; exit}' <<<"$ps")"
  hev_rss="$(awk -v pid="$hev_pid" '$2 == pid {print $4; exit}' <<<"$ps")"
  app_ticks="$(cpu_ticks "$app_pid")"
  vpp_ticks="$(cpu_ticks "$vpp_pid")"
  hev_ticks="$(cpu_ticks "$hev_pid")"

  local app_cpu vpp_cpu hev_cpu app_allowed vpp_allowed hev_allowed
  app_cpu="$(cpu_processor "$app_pid")"
  vpp_cpu="$(cpu_processor "$vpp_pid")"
  hev_cpu="$(cpu_processor "$hev_pid")"
  app_allowed="$(cpu_allowed "$app_pid")"
  vpp_allowed="$(cpu_allowed "$vpp_pid")"
  hev_allowed="$(cpu_allowed "$hev_pid")"

  local level temp usb alive
  level="$(battery_value 'level' "$battery")"
  temp="$(battery_value 'temperature' "$battery")"
  usb="$(battery_value 'USB powered' "$battery")"
  alive=0
  [[ -n "$vpp_pid" && "$vpp_pid" != "0" && -n "$hev_pid" && "$hev_pid" != "0" ]] && alive=1

  printf '%s\n' "round=$round kind=$kind index=$index elapsed_s=$elapsed alive=$alive"
  printf '%s\n' "pids=$app_pid/$vpp_pid/$hev_pid rss_kb=$app_rss/$vpp_rss/$hev_rss cpu_ticks=$app_ticks/$vpp_ticks/$hev_ticks"
  printf '%s\n' "processor=$app_cpu/$vpp_cpu/$hev_cpu allowed=$app_allowed/$vpp_allowed/$hev_allowed battery_level=$level battery_temp_tenths=$temp usb_powered=$usb"
  printf '%s\n' "$round,$kind,$index,$elapsed,$app_pid,$vpp_pid,$hev_pid,${app_ticks:-0},${vpp_ticks:-0},${hev_ticks:-0},${app_rss:-0},${vpp_rss:-0},${hev_rss:-0},$app_cpu,$vpp_cpu,$hev_cpu,$app_allowed,$vpp_allowed,$hev_allowed,${level:-0},${temp:-0},$usb,$alive" >>"$SAMPLES_CSV"
}

metric() {
  local key="$1"
  local text="$2"
  awk -v key="$key" '{for (i = 1; i <= NF; i++) {split($i, item, "="); if (item[1] == key) value = item[2]}} END {print value + 0}' <<<"$text"
}

stream_summary() {
  local kind="$1"
  local text="$2"
  local elapsed_ms requests successes errors bytes p50 p95 p99 packets
  elapsed_ms="$(metric elapsedMs "$text")"
  errors="$(metric errors "$text")"
  if [[ "$kind" == "tcp" ]]; then
    requests="$(metric requests "$text")"
    successes="$(metric successes "$text")"
    bytes="$(metric responseBytes "$text")"
    p50="$(metric latencyMsP50 "$text")"
    p95="$(metric latencyMsP95 "$text")"
    p99="$(metric latencyMsP99 "$text")"
    packets=0
  else
    requests=0
    successes=0
    bytes="$(metric bytes "$text")"
    packets="$(metric packets "$text")"
    p50=-1
    p95=-1
    p99=-1
  fi
  local bytes_per_second
  bytes_per_second="$(awk -v bytes="$bytes" -v elapsed="$elapsed_ms" 'BEGIN {if (elapsed > 0) printf "%.3f", bytes * 1000 / elapsed; else print "0"}')"
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$CURRENT_ROUND" "$kind" "$elapsed_ms" "$requests" "$successes" "$packets" "$errors" "$bytes" \
    "$bytes_per_second" "$p50" "$p95" "$p99" >>"$ROUNDS_CSV"
  printf '%s kind=%s elapsed_ms=%s requests=%s successes=%s packets=%s errors=%s bytes=%s bytes_per_second=%s p50_ms=%s p95_ms=%s p99_ms=%s\n' \
    "round=$CURRENT_ROUND" "$kind" "$elapsed_ms" "$requests" "$successes" "$packets" "$errors" "$bytes" "$bytes_per_second" "$p50" "$p95" "$p99"

  if [[ "$elapsed_ms" -lt $((DURATION_SECONDS * 1000 - 5000)) || "$errors" != "0" ]]; then
    failures=$((failures + 1))
    echo "round=$CURRENT_ROUND kind=$kind FAIL: duration/errors" >&2
  fi
  if [[ "$kind" == "tcp" && ( "$successes" == "0" || "$p95" == "-1" || "$p99" == "-1" ) ]]; then
    failures=$((failures + 1))
    echo "round=$CURRENT_ROUND kind=tcp FAIL: no successful latency samples" >&2
  fi
  if [[ "$kind" == "udp" && "$packets" == "0" ]]; then
    failures=$((failures + 1))
    echo "round=$CURRENT_ROUND kind=udp FAIL: no packets sent" >&2
  fi
}

start_vpn() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez start true --ez enableIpv6 true \
    --es mode vpp-hev-owner-resolver --es allowedPackage "$PACKAGE" \
    --ei blockOwnerUid "$miss_uid" >/dev/null
  sleep 5
}

run_round() {
  local round="$1"
  local kind="$2"
  local host port action log_path path
  if [[ "$kind" == "tcp" ]]; then
    host="$HOST4"
    port="$TCP_PORT"
    action="appHttpProbe"
    log_path="$APP_HTTP_LOG"
    path="/sakamoto-7-tcp-$round"
  else
    host="$UDP_HOST"
    port="$UDP_PORT"
    action="appUdpProbe"
    log_path="$APP_UDP_LOG"
    path="/"
  fi

  CURRENT_ROUND="$round"
  echo "## round=$round kind=$kind duration=${DURATION_SECONDS}s usb_powered=false screen_off=true"
  wake_device
  stop_app
  app_cmd rm -f "$APP_HTTP_LOG" "$APP_UDP_LOG" "$HEV_LOG" "$PROTECT_LOG" >/dev/null 2>&1 || true
  adb_cmd logcat -c
  start_vpn
  sleep "$WARMUP_SECONDS"

  if [[ "$kind" == "tcp" ]]; then
    adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
      --ez appHttpProbe true --es host "$host" --ei port "$port" \
      --es path "$path" --ei durationSeconds "$DURATION_SECONDS" >/dev/null
  else
    adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
      --ez appUdpProbe true --es host "$host" --ei port "$port" \
      --ei count 1 --ei durationSeconds "$DURATION_SECONDS" >/dev/null
  fi
  sleep 2
  if ! app_read "$log_path" | rg -q 'stream-start'; then
    echo "round=$round kind=$kind FAIL: stream did not start" >&2
    failures=$((failures + 1))
  fi

  ensure_screen_on
  adb_cmd shell input keyevent 26 >/dev/null 2>&1 || true
  screen_off=1
  local round_started="$SECONDS"
  local sample_index=0
  local timeout_at=$((SECONDS + DURATION_SECONDS + 45))
  while :; do
    sleep "$SAMPLE_INTERVAL"
    sample_index=$((sample_index + 1))
    sample_round "$round" "$kind" "$sample_index" "$((SECONDS - round_started))"
    if app_read "$log_path" | rg -q 'stream-done'; then
      break
    fi
    if (( SECONDS >= timeout_at )); then
      echo "round=$round kind=$kind FAIL: timeout waiting for stream-done" >&2
      failures=$((failures + 1))
      break
    fi
  done

  local final_log
  final_log="$(app_read "$log_path")"
  printf '%s\n' "$final_log" >"$RESULT_DIR/rounds/$(printf '%02d-%s.log' "$round" "$kind")"
  printf '%s\n' "$(app_read "$VPP_CLI_LOG")" >"$RESULT_DIR/rounds/$(printf '%02d-%s-vpp-cli.log' "$round" "$kind")"
  printf '%s\n' "$(app_read "$HEV_LOG")" >"$RESULT_DIR/rounds/$(printf '%02d-%s-hev.log' "$round" "$kind")"
  printf '%s\n' "$(adb_cmd logcat -d -s SnortVpnLite:I SnortVpnLiteNative:I '*:S' | tr -d '\r')" \
    >"$RESULT_DIR/rounds/$(printf '%02d-%s-logcat.txt' "$round" "$kind")"
  local done_line
  done_line="$(printf '%s\n' "$final_log" | rg 'stream-done' | tail -n 1 || true)"
  if [[ -z "$done_line" ]]; then
    failures=$((failures + 1))
  else
    stream_summary "$kind" "$done_line"
  fi

  wake_device
  stop_app
  if (( COOLDOWN_SECONDS > 0 )); then
    echo "cooldown_seconds=$COOLDOWN_SECONDS"
    sleep "$COOLDOWN_SECONDS"
  fi
}

cleanup() {
  wake_device || true
  stop_app || true
  stop_server || true
  if [[ "$battery_unplugged" == "1" ]]; then
    adb_cmd shell dumpsys battery reset >/dev/null 2>&1 || true
    echo "battery_reset=done"
  fi
}
trap cleanup EXIT INT TERM

echo "# SAKAMOTO-7 Android sustained throughput risk POC"
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
capture_device_identity

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
package_uid="$(awk -F'uid:' -v package="package:$PACKAGE" 'index($0, package) == 1 {print $2; exit}' <<<"$packages")"
[[ -n "$package_uid" ]]
miss_uid=$((package_uid + 100000))
echo "package_uid=$package_uid miss_uid=$miss_uid"

"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null
stop_app
stop_server
start_server

echo "## simulate USB power removal before Doze-sensitive measurement"
adb_cmd shell dumpsys battery unplug
battery_unplugged=1
battery_after_unplug="$(adb_cmd shell dumpsys battery | tr -d '\r')"
printf '%s\n' "$battery_after_unplug" >"$RESULT_DIR/battery-after-unplug.txt"
if ! grep -Eq 'USB powered: false|USB powered=false' <<<"$battery_after_unplug"; then
  echo "USB power simulation failed" >&2
  exit 1
fi

printf '%s\n' 'round,kind,elapsed_ms,requests,successes,packets,errors,bytes,bytes_per_second,p50_ms,p95_ms,p99_ms' >"$ROUNDS_CSV"
printf '%s\n' 'round,kind,index,elapsed_s,app_pid,vpp_pid,hev_pid,app_cpu_ticks,vpp_cpu_ticks,hev_cpu_ticks,app_rss_kb,vpp_rss_kb,hev_rss_kb,app_processor,vpp_processor,hev_processor,app_cpus_allowed,vpp_cpus_allowed,hev_cpus_allowed,battery_level,battery_temp_tenths,usb_powered,all_data_processes_alive' >"$SAMPLES_CSV"

for round in $(seq 1 "$ROUNDS"); do
  run_round "$round" tcp
  run_round "$round" udp
done

adb_cmd shell cat "$SERVER_LOG" >"$RESULT_DIR/socks-server.log"
adb_cmd shell ps -A -n -o USER,PID,PPID,RSS,NAME,ARGS >"$RESULT_DIR/final-processes.txt"
adb_cmd shell dumpsys battery >"$RESULT_DIR/battery-before-reset.txt"
adb_cmd shell dumpsys thermalservice >"$RESULT_DIR/thermal-after.txt"

alive_bad="$(awk -F, 'NR > 1 && $23 != 1 {count++} END {print count+0}' "$SAMPLES_CSV")"
echo "sample_rows=$(( $(wc -l <"$SAMPLES_CSV") - 1 )) alive_bad=$alive_bad failures=$failures"
cat "$ROUNDS_CSV"
if [[ "$alive_bad" != "0" ]]; then
  failures=$((failures + 1))
fi
if [[ "$failures" != "0" ]]; then
  echo "FAIL: SAKAMOTO-7 sustained throughput risk baseline failures=$failures" >&2
  echo "result_dir=$RESULT_DIR"
  exit 1
fi
echo "PASS: SAKAMOTO-7 sustained TCP/UDP risk baseline"
echo "result_dir=$RESULT_DIR"
