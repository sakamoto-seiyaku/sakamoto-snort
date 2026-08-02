#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: prove Android TUN fragment-owner metadata and bounded reassembly.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
MODE="${MODE:-vpp-fragment-owner}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc-fragment-owner}"
VPP_STAGE_DIR="${VPP_STAGE_DIR:-$POC_DIR/work/android-vpp-direct-owner-stage}"
ALLOWED_PACKAGE="${ALLOWED_PACKAGE:-$PACKAGE}"
FRAGMENT_PING_HOST="${FRAGMENT_PING_HOST:-1.1.1.1}"
FRAGMENT_PING_SIZE="${FRAGMENT_PING_SIZE:-4000}"
FRAGMENT_PING_COUNT="${FRAGMENT_PING_COUNT:-2}"
FRAGMENT_UDP_BYTES="${FRAGMENT_UDP_BYTES:-4000}"
HOSTS_TEXT="${HOSTS:-142.251.13.94 1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222 93.184.216.34}"
UDP_HOST="${UDP_HOST:-8.8.8.8}"
UDP_PORT="${UDP_PORT:-53}"
UDP_COUNT="${UDP_COUNT:-8}"
ENABLE_IPV6="${ENABLE_IPV6:-0}"
BUILD_APK="${BUILD_APK:-1}"
INSTALL_APK="${INSTALL_APK:-1}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-10}"
STOP_WAIT="${STOP_WAIT:-3}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/2026-07-20/sakamoto-41-fragment-owner-$(date +%Y%m%d-%H%M%S)}"
LOG="$RESULT_DIR/run.log"
SERVER_BIN="$POC_DIR/build/android-socks5-smoke-server"
REMOTE_SERVER="$REMOTE_ROOT/android-socks5-smoke-server"
SERVER_LOG="$REMOTE_ROOT/logs/android-socks5-smoke-server.log"
SERVER_PID="$REMOTE_ROOT/runtime/socks.pid"
APP_HTTP_LOG="/data/user/0/$PACKAGE/files/logs/app-http-probe.log"
APP_UDP_LOG="/data/user/0/$PACKAGE/files/logs/app-udp-probe.log"
APP_PING_LOG="/data/user/0/$PACKAGE/files/logs/app-ping-probe.log"
VPP_CLI_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-cli.log"
VPP_STDOUT_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-stdout.log"
HEV_LOG="/data/user/0/$PACKAGE/files/vpp/logs/vpp-hev.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
exec > >(tee "$LOG") 2>&1

cleanup() {
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  adb_su "if [ -f '$SERVER_PID' ]; then kill -TERM \$(cat '$SERVER_PID') 2>/dev/null || true; sleep 1; kill -9 \$(cat '$SERVER_PID') 2>/dev/null || true; fi; rm -f '$SERVER_PID'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "# Android TUN fragment-owner POC"
echo "adb_serial=$(adb_target_desc)"
echo "package=$PACKAGE"
echo "mode=$MODE"
echo "remote_root=$REMOTE_ROOT"
echo "vpp_stage_dir=$VPP_STAGE_DIR"
echo "hosts=$HOSTS_TEXT"
echo "udp=$UDP_HOST:$UDP_PORT count=$UDP_COUNT"
echo "enable_ipv6=$ENABLE_IPV6"
echo "allowed_package=$ALLOWED_PACKAGE"
echo "fragment_ping=$FRAGMENT_PING_HOST size=$FRAGMENT_PING_SIZE count=$FRAGMENT_PING_COUNT"
echo "fragment_udp_bytes=$FRAGMENT_UDP_BYTES"
echo "result_dir=$RESULT_DIR"

"$SCRIPT_DIR/android-build-socks5-smoke-server.sh" >/dev/null
if [[ "$BUILD_APK" == "1" ]]; then
  VPP_STAGE_DIR="$VPP_STAGE_DIR" "$POC_DIR/android/vpn-lite/scripts/build-debug-apk.sh"
fi
if [[ "$INSTALL_APK" == "1" ]]; then
  "$POC_DIR/android/vpn-lite/scripts/install-debug-apk.sh"
fi

adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
adb_su "mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; chmod 777 '$REMOTE_ROOT' '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; rm -f '$SERVER_LOG' '$SERVER_PID'"
adb_cmd push "$SERVER_BIN" "$REMOTE_SERVER" >/dev/null
adb_su "chmod 755 '$REMOTE_SERVER'; nohup '$REMOTE_SERVER' >'$SERVER_LOG' 2>&1 < /dev/null & echo \$! > '$SERVER_PID'"
sleep 1

adb_su "rm -f '$APP_HTTP_LOG' '$APP_UDP_LOG' '$APP_PING_LOG' '$VPP_CLI_LOG' '$VPP_STDOUT_LOG' '$HEV_LOG' /data/user/0/$PACKAGE/files/vpp/logs/vpp-shim.log"
before_count="$(adb_su "grep -c 'connect ' '$SERVER_LOG' 2>/dev/null || true" | tr -d '\r' | tail -n 1)"
before_count="${before_count:-0}"
echo "socks_connect_before=$before_count"

echo "## start vpp-hev-direct-owner"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez start true \
  --es mode "$MODE" \
  --es allowedPackage "$ALLOWED_PACKAGE" \
  --ez enableIpv6 "$ENABLE_IPV6"
sleep "$START_WAIT"

read -r -a hosts <<< "$HOSTS_TEXT"
echo "## launch bounded HTTP burst count=${#hosts[@]}"
index=0
for host in "${hosts[@]}"; do
  adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
    --ez appHttpProbe true \
    --es host "$host" \
    --ei port 80 \
    --es path "/sakamoto-33-direct-$index" >/dev/null
  index=$((index + 1))
  sleep 0.25
done

echo "## launch UDP burst"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez appUdpProbe true \
  --es host "$UDP_HOST" \
  --ei port "$UDP_PORT" \
  --ei count "$UDP_COUNT" \
  --ei payloadBytes 0 >/dev/null
echo "## launch app-owned large UDP payload to force TUN fragmentation"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez appUdpProbe true \
  --es host "$UDP_HOST" \
  --ei port "$UDP_PORT" \
  --ei count 2 \
  --ei payloadBytes "$FRAGMENT_UDP_BYTES" >/dev/null
echo "## launch app-owned large-payload ping"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" \
  --ez appPingProbe true \
  --es host "$FRAGMENT_PING_HOST" \
  --ei size "$FRAGMENT_PING_SIZE" \
  --ei count "$FRAGMENT_PING_COUNT" >/dev/null
sleep "$PROBE_WAIT"

echo "## launch large-payload ping to exercise kernel IPv4 fragmentation"
fragment_ping_log="$( { adb_cmd shell ping -c "$FRAGMENT_PING_COUNT" -s "$FRAGMENT_PING_SIZE" -W 5 "$FRAGMENT_PING_HOST" 2>&1 || true; } | tr -d '\r')"
printf '%s\n' "$fragment_ping_log"
printf '%s\n' "$fragment_ping_log" > "$RESULT_DIR/fragment-ping.log"

echo "## app HTTP log"
http_log="$(adb_su "cat '$APP_HTTP_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$http_log"
printf '%s\n' "$http_log" > "$RESULT_DIR/app-http-probe.log"

echo "## app UDP log"
udp_log="$(adb_su "cat '$APP_UDP_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$udp_log"
printf '%s\n' "$udp_log" > "$RESULT_DIR/app-udp-probe.log"

echo "## app ping log"
ping_log="$(adb_su "cat '$APP_PING_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$ping_log"
printf '%s\n' "$ping_log" > "$RESULT_DIR/app-ping-probe.log"

echo "## VPP CLI log"
vpp_cli="$(adb_su "cat '$VPP_CLI_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$vpp_cli"
printf '%s\n' "$vpp_cli" > "$RESULT_DIR/vpp-cli.log"

echo "## VPP stdout tail"
adb_su "tail -n 120 '$VPP_STDOUT_LOG' 2>/dev/null || true" | tr -d '\r' | tee "$RESULT_DIR/vpp-stdout-tail.log"

echo "## HEV log"
hev_log="$(adb_su "cat '$HEV_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$hev_log"
printf '%s\n' "$hev_log" > "$RESULT_DIR/hev.log"

echo "## SOCKS server log"
socks_log="$(adb_su "cat '$SERVER_LOG' 2>/dev/null || true" | tr -d '\r')"
printf '%s\n' "$socks_log"
printf '%s\n' "$socks_log" > "$RESULT_DIR/socks.log"
after_count="$(grep -c 'connect ' <<< "$socks_log" || true)"
echo "socks_connect_after=$after_count"

echo "## stop"
adb_cmd shell am start -n "$PACKAGE/.MainActivity" --ez stop true >/dev/null
sleep "$STOP_WAIT"

fail() {
  echo "NO-GO: $*" >&2
  exit 1
}

expected_mode='fragment-owner'
if [[ "$MODE" == "vpp-hev-direct-owner-fault" ]]; then
  expected_mode='direct-owner-fault'
elif [[ "$MODE" == "vpp-hev-direct-owner-return" ]]; then
  expected_mode='direct-owner-return'
elif [[ "$MODE" == "vpp-hev-direct-owner-single-writer" ]]; then
  expected_mode='direct-owner-single-writer'
fi
grep -q "mode $expected_mode" <<< "$vpp_cli" || fail "VPP did not enable $expected_mode mode"
if [[ "$MODE" == "vpp-hev-direct-owner-polling" ]]; then
  grep -q 'polling-thread main 1 shim 1' <<< "$vpp_cli" || \
    fail "VPP did not configure polling thread 1"
  grep -Eq 'thread-hits main last 1 t0 0 t1 [1-9][0-9]*' <<< "$vpp_cli" || \
    fail "TUN callback did not run on selected polling thread 1"
fi
if [[ "$MODE" == "vpp-hev-fragment-owner" || "$MODE" == "vpp-fragment-owner" ]]; then
  grep -Eq 'direct workers [2-9][0-9]* target-workers [2-9][0-9]* enqueued [1-9]' <<< "$vpp_cli" || \
    fail "fragment dispatch did not reach at least two workers"
  grep -Eq 'fragment packets [1-9][0-9]* bytes [1-9][0-9]* first [1-9][0-9]* nonfirst [1-9][0-9]* last [1-9][0-9]*' <<< "$vpp_cli" || \
    fail "large-payload workload did not produce observable fragments"
  grep -Eq 'fragment owner-guard pass [1-9][0-9]* mismatch 0 transitions [1-9][0-9]* reassembly-success [1-9][0-9]*' <<< "$vpp_cli" || \
    fail "fragment owner guard/reassembly transition was not proven"
elif [[ "$MODE" == "vpp-hev-direct-owner-fault" ]]; then
  grep -Eq 'direct owner-guard pass [1-9][0-9]* mismatch [1-9][0-9]* .*corrective-handoff [2-9][0-9]* corrective-drop 0 second-mismatch-drop [1-9][0-9]* fault-injected 2 single-completed 1' <<< "$vpp_cli" || \
    fail "Owner Guard fault injection did not prove single-correction and second-mismatch DROP"
else
  grep -Eq 'direct owner-guard pass [1-9][0-9]* mismatch 0' <<< "$vpp_cli" || \
    fail "Owner Guard did not prove a clean direct path"
fi
if [[ "$MODE" == "vpp-hev-direct-owner-fault" ]]; then
  grep -Eq 'reverse-projection-matches [1-9][0-9]* reverse-projection-mismatch 0 corrective-handoff [1-9][0-9]*' <<< "$vpp_cli" || \
    fail "canonical reverse-owner projection was not proven in fault mode"
else
  grep -Eq 'reverse-projection-matches [1-9][0-9]* reverse-projection-mismatch 0 corrective-handoff 0' <<< "$vpp_cli" || \
    fail "canonical reverse-owner projection was not proven"
fi
grep -Eq 'direct worker-hits t0 [1-9][0-9]* t1 [1-9][0-9]*' <<< "$vpp_cli" || \
	fail "both target worker counters did not advance"
if [[ "$MODE" == "vpp-hev-direct-owner-return" ]]; then
  grep -Eq 'shim-rx [1-9][0-9]* bytes [1-9][0-9]*' <<< "$vpp_cli" || \
    fail "transport-return lane did not receive packets on shim fd"
  grep -Eq 'direct return enqueued [1-9][0-9]* bytes [1-9][0-9]* congestion-drops 0 worker-packets [1-9][0-9]* bytes [1-9][0-9]* tx [1-9][0-9]* bytes [1-9][0-9]*' <<< "$vpp_cli" || \
    fail "transport-return packets did not traverse worker graph and complete to TUN"
fi
if [[ "$MODE" == "vpp-hev-direct-owner-single-writer" ]]; then
  grep -Eq 'shim-rx [1-9][0-9]* bytes [1-9][0-9]*' <<< "$vpp_cli" || \
    fail "single-writer completion lane did not receive transport-return packets"
  grep -Eq 'direct return enqueued [1-9][0-9]* bytes [1-9][0-9]* congestion-drops 0 worker-packets [1-9][0-9]* bytes [1-9][0-9]* tx [1-9][0-9]* bytes [1-9][0-9]*' <<< "$vpp_cli" || \
    fail "single-writer return packets did not reach the completion owner"
  grep -Eq 'completion target-thread 0 fq [0-9]+ enqueued [1-9][0-9]* bytes [1-9][0-9]* processed [1-9][0-9]* bytes [1-9][0-9]* eagain-drops 2 terminal-drops 2' <<< "$vpp_cli" || \
    fail "single-writer completion owner did not prove bounded EAGAIN terminal drops"
fi
if [[ "$MODE" != "vpp-fragment-owner" ]]; then
  grep -q 'HTTP/1.0 200 OK' <<< "$http_log" || fail "HTTP burst did not receive a response"
  grep -q "packets=$UDP_COUNT" <<< "$udp_log" || fail "UDP burst did not send expected packet count"
  (( after_count > before_count )) || fail "SOCKS server saw no forwarded flow"
fi
if grep -E 'free\(\): invalid size|Fatal signal|SIGABRT' <<< "$hev_log" >/dev/null; then
  fail "HEV emitted a fatal pattern"
fi

adb_cmd shell am force-stop "$PACKAGE" >/dev/null || true
sleep 1
leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
[[ -z "$leftovers" ]] || fail "VPP process remained after stop: $leftovers"

echo "GO: Android fragment-owner TUN workload passed"
