#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-43: run the identical Android direct-owner workload while sampling
# the VPP process. The workload script remains the source of truth for the
# HTTP/UDP probes and datapath counters; this wrapper adds comparable process,
# context-switch, and thermal samples for each placement profile.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
PROFILE="${PROFILE:-main}"
if [[ "$PROFILE" == "polling" ]]; then
  MODE="${MODE:-vpp-hev-direct-owner-polling}"
else
  MODE="${MODE:-vpp-hev-direct-owner}"
fi
PACKAGE="${PACKAGE:-com.sakamoto.snort.vpnlite}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/2026-07-20/sakamoto-43-$PROFILE-$(date +%Y%m%d-%H%M%S)}"
WORKLOAD_RESULT_DIR="$RESULT_DIR/workload"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"
HOSTS="${HOSTS:-142.251.13.94 1.1.1.1 8.8.8.8}"
UDP_HOST="${UDP_HOST:-8.8.8.8}"
UDP_PORT="${UDP_PORT:-53}"
UDP_COUNT="${UDP_COUNT:-8}"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/run.log") 2>&1

echo "# SAKAMOTO-43 VPN profile measurement"
echo "profile=$PROFILE mode=$MODE"
echo "adb_serial=$(adb_target_desc) package=$PACKAGE"
echo "result_dir=$RESULT_DIR sample_interval=${SAMPLE_INTERVAL}s"

sample_once() {
  local label="$1"
  adb_su "label='$label'; pid=\$(pidof vpp 2>/dev/null | awk '{print \$1}'); ticks=0; ctx=0; threads=0; if [ -n \"\$pid\" ]; then for t in /proc/\$pid/task/*; do [ -d \"\$t\" ] || continue; threads=\$((threads+1)); ticks=\$((ticks+\$(awk '{print \$14+\$15}' \"\$t/stat\" 2>/dev/null || echo 0))); ctx=\$((ctx+\$(awk '/voluntary_ctxt_switches:/{v+=\$2} /nonvoluntary_ctxt_switches:/{v+=\$2} END{print v+0}' \"\$t/status\" 2>/dev/null || echo 0))); done; fi; temps=''; for z in /sys/class/thermal/thermal_zone*; do [ -r \"\$z/temp\" ] || continue; type=\$(cat \"\$z/type\" 2>/dev/null || echo '?'); value=\$(cat \"\$z/temp\" 2>/dev/null || echo '?'); temps=\"\$temps\$type:\$value,\"; done; printf '%s pid=%s threads=%s ticks=%s ctx_switches=%s thermal=%s\\n' \"\$label\" \"\${pid:-none}\" \"\$threads\" \"\$ticks\" \"\$ctx\" \"\$temps\"" | tr -d '\r'
}

device_preflight
printf 'sample\tpid\tthreads\tticks\tctx_switches\tthermal\n' > "$RESULT_DIR/metrics.tsv"

set +e
MODE="$MODE" PACKAGE="$PACKAGE" HOSTS="$HOSTS" UDP_HOST="$UDP_HOST" UDP_PORT="$UDP_PORT" UDP_COUNT="$UDP_COUNT" \
  BUILD_APK=0 INSTALL_APK=0 START_WAIT=6 PROBE_WAIT=8 STOP_WAIT=3 \
  RESULT_DIR="$WORKLOAD_RESULT_DIR" \
  "$SCRIPT_DIR/android-run-vpp-direct-owner-poc.sh" >"$RESULT_DIR/workload.log" 2>&1 &
workload_pid=$!
set -e

sample_index=0
while kill -0 "$workload_pid" 2>/dev/null; do
  sample_index=$((sample_index + 1))
  line="$(sample_once "sample-$sample_index")"
  echo "$line"
  # Keep a tabular copy while retaining the verbatim device line in run.log.
  pid="$(sed -n 's/.* pid=\([^ ]*\).*/\1/p' <<<"$line")"
  threads="$(sed -n 's/.* threads=\([^ ]*\).*/\1/p' <<<"$line")"
  ticks="$(sed -n 's/.* ticks=\([^ ]*\).*/\1/p' <<<"$line")"
  ctx="$(sed -n 's/.* ctx_switches=\([^ ]*\).*/\1/p' <<<"$line")"
  thermal="$(sed -n 's/.* thermal=//p' <<<"$line")"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$sample_index" "${pid:-none}" "${threads:-0}" "${ticks:-0}" "${ctx:-0}" "${thermal:-}" >> "$RESULT_DIR/metrics.tsv"
sleep "$SAMPLE_INTERVAL"
done
set +e
wait "$workload_pid"
workload_rc=$?
set -e

echo "workload_rc=$workload_rc"
echo "## workload tail"
tail -n 40 "$RESULT_DIR/workload.log" || true
echo "## metrics"
cat "$RESULT_DIR/metrics.tsv"
exit "$workload_rc"
