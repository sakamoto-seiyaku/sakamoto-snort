#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-123 real Pixel 6a cost-attribution runner.  It writes raw command
# output only; interpretation belongs in S123_COST_ATTRIBUTION_MEMO.md.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/s122-vpp}"
HEV_LIB="${HEV_LIB:-$REMOTE_ROOT/lib/libhev-socks5-tunnel.so}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s123/$(date +%Y%m%d-%H%M%S)-pixel6a-cost-matrix}"
TARGET_THREAD="${TARGET_THREAD:-1}"
LOW_COUNT="${LOW_COUNT:-10000}"
HIGH_COUNT="${HIGH_COUNT:-100000}"
WARMUP_COUNT="${WARMUP_COUNT:-10000}"
WARMUP_SECONDS="${WARMUP_SECONDS:-10}"
REPEATS="${REPEATS:-3}"
ARMS="${ARMS:-full prebuilt builder memcpy}"
PROTOCOLS="${PROTOCOLS:-udp tcp}"
PAYLOADS="${PAYLOADS:-33 512 1400}"
LOADS="${LOADS:-low high}"
BURSTS="${BURSTS:-1 32}"

export ADB="${ADB:-$REPO_ROOT/dev/adb}"
source "$REPO_ROOT/dev/dev-android-device-lib.sh"

mkdir -p "$RESULT_DIR"
device_preflight

vppctl() {
  local command="$1"
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $command" | tr -d '\r'
}

pid="$(adb_su "cat '$REMOTE_ROOT/runtime/vpp.pid'" | tr -d '\r\n')"
{
  echo "device=$(adb_target_desc)"
  echo "date=$(adb_su 'date -Ins' | tr -d '\r\n')"
  echo "product=$(adb_su 'getprop ro.product.device' | tr -d '\r\n')"
  echo "model=$(adb_su 'getprop ro.product.model' | tr -d '\r\n')"
  echo "build=$(adb_su 'getprop ro.build.fingerprint' | tr -d '\r\n')"
  echo "vpp_pid=$pid"
  echo "plugin_sha256=$(adb_su "sha256sum '$REMOTE_ROOT/plugins/hev_external_driver_poc_plugin.so'" | tr -d '\r')"
  echo "hev_sha256=$(adb_su "sha256sum '$HEV_LIB'" | tr -d '\r')"
  echo "threads=$(adb_su "cat /proc/$pid/status | grep '^Threads:'" | tr -d '\r')"
  echo "--- show threads ---"
  vppctl "show threads"
  echo "--- affinity ---"
  adb_su "for t in /proc/$pid/task/*; do tid=\${t##*/}; comm=\$(cat \"\$t/comm\" 2>/dev/null || true); allowed=\$(grep '^Cpus_allowed_list:' \"\$t/status\" 2>/dev/null | awk '{print \$2}'); cpu=\$(awk '{print \$39}' \"\$t/stat\" 2>/dev/null || true); printf '%s comm=%s cpu=%s allowed=%s\\n' \"\$tid\" \"\$comm\" \"\$cpu\" \"\$allowed\"; done" | tr -d '\r'
} >"$RESULT_DIR/device-metadata.raw"

wait_finished() {
  local raw="$1"
  local show=""
  for _ in $(seq 1 600); do
    sleep 1
    show="$(vppctl "show s122-packet-path-perf")"
    printf '%s\n' "$show" >>"$raw"
    if printf '%s\n' "$show" | grep -q 'finished 1 remaining 0' &&
       printf '%s\n' "$show" | grep -q 'active 0 pending 0'; then
      return 0
    fi
  done
  echo "timeout=1" >>"$raw"
  return 1
}

run_once() {
  local label="$1"
  local arm="$2"
  local protocol="$3"
  local payload="$4"
  local count="$5"
  local burst="$6"
  local raw="$RESULT_DIR/$label.raw"
  local command

  command="s122-packet-path-perf run arm $arm protocol $protocol target-thread $TARGET_THREAD payload $payload count $count burst $burst"
  if [[ "$arm" == "full" || "$arm" == "prebuilt" ]]; then
    command+=" lib $HEV_LIB"
  fi
  {
    echo "run=$label"
    echo "started=$(date -Ins)"
    echo "device=$(adb_target_desc)"
    echo "vpp_pid=$pid"
    echo "command=$command"
    vppctl "$command"
  } >"$raw"
  wait_finished "$raw"
  {
    echo "finished=$(date -Ins)"
    echo "--- vpp stdout tail ---"
    adb_su "tail -4 '$REMOTE_ROOT/logs/vpp-stdout.log'" | tr -d '\r'
  } >>"$raw"
}

warmup_cell() {
  local key="$1"
  local arm="$2"
  local protocol="$3"
  local payload="$4"
  local burst="$5"
  local started elapsed=0 round=0

  started="$(date +%s)"
  while (( elapsed < WARMUP_SECONDS )); do
    round=$((round + 1))
    run_once "$key-warmup-$round" "$arm" "$protocol" "$payload" "$WARMUP_COUNT" "$burst"
    elapsed=$(( $(date +%s) - started ))
  done
}

for arm in $ARMS; do
  for protocol in $PROTOCOLS; do
    for payload in $PAYLOADS; do
      for burst in $BURSTS; do
        key="${arm}-${protocol}-p${payload}-b${burst}"
        warmup_cell "$key" "$arm" "$protocol" "$payload" "$burst"
        for load in $LOADS; do
          count="$LOW_COUNT"
          [[ "$load" == high ]] && count="$HIGH_COUNT"
          for repeat in $(seq 1 "$REPEATS"); do
            run_once "$key-$load-r$repeat" "$arm" "$protocol" "$payload" "$count" "$burst"
          done
        done
      done
    done
  done
done

echo "results=$RESULT_DIR"
