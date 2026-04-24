#!/bin/bash

set -euo pipefail

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../../.." && pwd)"

source "$IPMOD_DIR/lib_legacy.sh"

DO_BUILD=1
DO_DEPLOY=1
MODE="${MODE:-udp}" # udp|tcp
DURATION_S="${DURATION_S:-10}"
THREADS="${THREADS:-8}"
FLOWS="${FLOWS:-1024}"
BYTES="${BYTES:-64}"
DELAY_NS="${DELAY_NS:-0}"
PORT="${PORT:-20000}"
CONTROL_PORT="${CONTROL_PORT:-19999}"
PERFMETRICS="${PERFMETRICS:-1}"
IPRULES="${IPRULES:-0}"
CLIENT_UID="${CLIENT_UID:-$IPTEST_UID}"
NUM_PORTS="${NUM_PORTS:-1}" # tcp only
LOCAL_HOST_COUNT="${LOCAL_HOST_COUNT:-1}" # tcp only (bind per flow via -L)
LOCAL_HOST_BASE_OCTET="${LOCAL_HOST_BASE_OCTET:-101}"

show_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>     Target Android serial
  --adb <path>          adb binary path
  --skip-build          Reuse existing build-output/iptest-neper-*
  --skip-deploy         Reuse current sucre-snort daemon
  --mode <udp|tcp>      Workload (default: ${MODE})
  --seconds <n>         Test duration (default: ${DURATION_S})
  --threads <n>         Neper threads (default: ${THREADS})
  --flows <n>           Neper flows (default: ${FLOWS})
  --bytes <n>           UDP payload size OR TCP request/response size (default: ${BYTES})
  --delay-ns <n>        UDP per-send delay (ns) (default: ${DELAY_NS})
  --port <n>            Data port base (default: ${PORT})
  --control-port <n>    Control port (default: ${CONTROL_PORT})
  --uid <uid>           Client UID (default: ${CLIENT_UID})
  --num-ports <n>       TCP: number of server listen ports (default: ${NUM_PORTS})
  --local-host-count <n> TCP: client bind IP pool size (default: ${LOCAL_HOST_COUNT})
  --local-host-base-octet <n> TCP: extra host IPs start at x.x.x.<n> (default: ${LOCAL_HOST_BASE_OCTET})
  --perfmetrics <0|1>   Toggle PERFMETRICS during test (default: ${PERFMETRICS})
  --iprules <0|1>       Toggle IPRULES during test (default: ${IPRULES})
  -h, --help            Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      ADB_SERIAL="$2"
      export ADB_SERIAL
      shift 2
      ;;
    --adb)
      ADB="$2"
      export ADB
      shift 2
      ;;
    --skip-build)
      DO_BUILD=0
      shift
      ;;
    --skip-deploy)
      DO_DEPLOY=0
      shift
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --seconds)
      DURATION_S="$2"
      shift 2
      ;;
    --threads)
      THREADS="$2"
      shift 2
      ;;
    --flows)
      FLOWS="$2"
      shift 2
      ;;
    --bytes)
      BYTES="$2"
      shift 2
      ;;
    --delay-ns)
      DELAY_NS="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --control-port)
      CONTROL_PORT="$2"
      shift 2
      ;;
    --uid)
      CLIENT_UID="$2"
      shift 2
      ;;
    --num-ports)
      NUM_PORTS="$2"
      shift 2
      ;;
    --local-host-count)
      LOCAL_HOST_COUNT="$2"
      shift 2
      ;;
    --local-host-base-octet)
      LOCAL_HOST_BASE_OCTET="$2"
      shift 2
      ;;
    --perfmetrics)
      PERFMETRICS="$2"
      shift 2
      ;;
    --iprules)
      IPRULES="$2"
      shift 2
      ;;
    -h|--help)
      show_help
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      show_help >&2
      exit 1
      ;;
  esac
done

for v in DURATION_S THREADS FLOWS BYTES DELAY_NS PORT CONTROL_PORT PERFMETRICS IPRULES CLIENT_UID NUM_PORTS LOCAL_HOST_COUNT LOCAL_HOST_BASE_OCTET; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "$v must be a non-negative integer (got: ${!v})" >&2
    exit 1
  fi
done

if [[ "$MODE" != "udp" && "$MODE" != "tcp" ]]; then
  echo "MODE must be udp or tcp (got: $MODE)" >&2
  exit 1
fi

if [[ "$DURATION_S" -lt 1 || "$THREADS" -lt 1 || "$FLOWS" -lt 1 || "$BYTES" -lt 1 ]]; then
  echo "SECONDS/THREADS/FLOWS/BYTES must all be >= 1" >&2
  exit 1
fi

if [[ "$MODE" == "tcp" ]]; then
  if [[ "$NUM_PORTS" -lt 1 ]]; then
    echo "NUM_PORTS must be >= 1 (got: $NUM_PORTS)" >&2
    exit 1
  fi
  if [[ "$LOCAL_HOST_COUNT" -lt 1 ]]; then
    echo "LOCAL_HOST_COUNT must be >= 1 (got: $LOCAL_HOST_COUNT)" >&2
    exit 1
  fi
fi

if [[ "$IPRULES" -ne 0 && "$IPRULES" -ne 1 ]]; then
  echo "IPRULES must be 0 or 1 (got: $IPRULES)" >&2
  exit 1
fi

if [[ "$PERFMETRICS" -ne 0 && "$PERFMETRICS" -ne 1 ]]; then
  echo "PERFMETRICS must be 0 or 1 (got: $PERFMETRICS)" >&2
  exit 1
fi

if [[ $DO_BUILD -eq 1 ]]; then
  bash "$SNORT_ROOT/dev/dev-build-iptest-neper.sh"
fi

if [[ $DO_DEPLOY -eq 1 ]]; then
  deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
  if [[ -n "${ADB_SERIAL:-}" ]]; then
    deploy_cmd+=(--serial "$ADB_SERIAL")
  fi
  "${deploy_cmd[@]}"
fi

init_test_env

table=""
records_dir=""
cleanup() {
  if [[ -n "$table" ]]; then
    iptest_tier1_teardown "$table" || true
  fi
}
trap cleanup EXIT

if ! adb_su "command -v ip >/dev/null 2>&1"; then
  echo "SKIP: missing ip tool on device" >&2
  exit 10
fi

build_ip_pool() {
  local prefix="$1"
  local start_octet="$2"
  local count="$3"
  local -n out_ref="$4"

  out_ref=()
  local i
  for ((i = 0; i < count; i++)); do
    out_ref+=("${prefix}.$((start_octet + i))")
  done
}

csv_from_array() {
  local -n arr_ref="$1"
  local IFS=','
  printf '%s' "${arr_ref[*]}"
}

local_hosts_csv=""
if [[ "$MODE" == "tcp" && "$LOCAL_HOST_COUNT" -gt 1 ]]; then
  net_prefix="${IPTEST_HOST_IP%.*}"
  declare -a extra_host_ips=()
  build_ip_pool "$net_prefix" "$LOCAL_HOST_BASE_OCTET" "$((LOCAL_HOST_COUNT - 1))" extra_host_ips
  IPTEST_HOST_IP_POOL="$(csv_from_array extra_host_ips)"
  export IPTEST_HOST_IP_POOL
  declare -a all_hosts=("$IPTEST_HOST_IP" "${extra_host_ips[@]}")
  local_hosts_csv="$(csv_from_array all_hosts)"
else
  IPTEST_HOST_IP_POOL=""
fi

table="$(iptest_tier1_setup)"

ts="$(date -u +%Y%m%dT%H%M%SZ)"
records_dir="$IPMOD_DIR/records/neper-poc-${ts}_$(adb_target_desc)"
mkdir -p "$records_dir"

assert_ok "RESETALL" "RESETALL baseline"
assert_ok "BLOCK 1" "BLOCK=1"
assert_ok "PERFMETRICS ${PERFMETRICS}" "PERFMETRICS=${PERFMETRICS}"
assert_ok "IPRULES ${IPRULES}" "IPRULES=${IPRULES}"
assert_ok "METRICS.PERF.RESET" "METRICS.PERF.RESET"

iptest_stage_neper_binaries

adb_su "cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true" >"$records_dir/nfq_before.txt" || true

if [[ "$MODE" == "udp" ]]; then
  server_log="/data/local/tmp/iptest_neper_udp_srv.log"
  adb_su "rm -f \"$server_log\""
  adb_su "ip netns exec \"$IPTEST_NS\" \"$IPTEST_NEPER_UDP_STREAM_DEVICE_BIN\" --nolog -4 -P \"$PORT\" -C \"$CONTROL_PORT\" -T \"$THREADS\" -F \"$FLOWS\" -B \"$BYTES\" >\"$server_log\" 2>&1 &"
  sleep 0.2

  iptest_adb_as_uid "$CLIENT_UID" \
    "\"$IPTEST_NEPER_UDP_STREAM_DEVICE_BIN\" --nolog -4 -c -H \"$IPTEST_PEER_IP\" -P \"$PORT\" -C \"$CONTROL_PORT\" -T \"$THREADS\" -F \"$FLOWS\" -B \"$BYTES\" -D \"$DELAY_NS\" -l \"$DURATION_S\"" \
    >"$records_dir/client.txt"

  adb_su "cat \"$server_log\" 2>/dev/null || true" >"$records_dir/server.txt" || true
else
  server_log="/data/local/tmp/iptest_neper_tcp_srv.log"
  adb_su "rm -f \"$server_log\""
  adb_su "ip netns exec \"$IPTEST_NS\" \"$IPTEST_NEPER_TCP_CRR_DEVICE_BIN\" --nolog -4 -P \"$PORT\" -C \"$CONTROL_PORT\" -T \"$THREADS\" -F \"$FLOWS\" --num-ports \"$NUM_PORTS\" -Q \"$BYTES\" -R \"$BYTES\" >\"$server_log\" 2>&1 &"
  sleep 0.2

  tcp_client_cmd="\"$IPTEST_NEPER_TCP_CRR_DEVICE_BIN\" --nolog -4 -c -H \"$IPTEST_PEER_IP\" -P \"$PORT\" -C \"$CONTROL_PORT\" -T \"$THREADS\" -F \"$FLOWS\" --num-ports \"$NUM_PORTS\" -Q \"$BYTES\" -R \"$BYTES\" -l \"$DURATION_S\" --no-delay"
  if [[ -n "$local_hosts_csv" ]]; then
    tcp_client_cmd="${tcp_client_cmd} -L \"${local_hosts_csv}\""
  fi

  iptest_adb_as_uid "$CLIENT_UID" \
    "${tcp_client_cmd}" \
    >"$records_dir/client.txt"

  adb_su "cat \"$server_log\" 2>/dev/null || true" >"$records_dir/server.txt" || true
fi

adb_su "cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true" >"$records_dir/nfq_after.txt" || true

send_cmd "METRICS.PERF" >"$records_dir/metrics_perf.json"

python3 - <<'PY' "$records_dir"
import json
import sys
from pathlib import Path

records_dir = Path(sys.argv[1])
metrics = json.loads((records_dir / "metrics_perf.json").read_text())
perf_samples = int(metrics["perf"]["nfq_total_us"]["samples"])

def load_nfq(path: Path) -> dict[int, tuple[int, int, int]]:
    # man7 proc_pid_net(5):
    # <queue_num> <peer_portid> <queue_total> <copy_mode> <copy_range>
    # <queue_dropped> <user_dropped> <id_sequence> 1
    out: dict[int, tuple[int, int, int]] = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            qid = int(parts[0])
            seq = int(parts[7])
            qdrop = int(parts[5]) if len(parts) > 5 else 0
            udrop = int(parts[6]) if len(parts) > 6 else 0
        except ValueError:
            continue
        out[qid] = (seq, qdrop, udrop)
    return out

before = load_nfq(records_dir / "nfq_before.txt")
after = load_nfq(records_dir / "nfq_after.txt")

seq_total = 0
qdrop_total = 0
udrop_total = 0
top = []
for qid, (seq_after, qdrop_after, udrop_after) in after.items():
    seq_before, qdrop_before, udrop_before = before.get(qid, (seq_after, qdrop_after, udrop_after))

    seq_diff = max(0, seq_after - seq_before)
    qdrop_diff = max(0, qdrop_after - qdrop_before)
    udrop_diff = max(0, udrop_after - udrop_before)

    seq_total += seq_diff
    qdrop_total += qdrop_diff
    udrop_total += udrop_diff

    if seq_diff:
        top.append((seq_diff, qid))
top.sort(reverse=True)
top = top[:6]

ratio = (perf_samples / seq_total) if seq_total else 0.0
lines = [
    f"perf_samples={perf_samples}",
    f"nfq_seq_total={seq_total}",
    f"nfq_queue_dropped_total={qdrop_total}",
    f"nfq_user_dropped_total={udrop_total}",
    f"perf/seq_ratio={ratio:.6f}",
    "nfq_top=" + ",".join([f"q{qid}:{diff}" for diff, qid in top]) if top else "nfq_top=",
]

out = "\n".join(lines) + "\n"
(records_dir / "summary.txt").write_text(out)
sys.stdout.write(out)
PY

echo "OK records_dir=$records_dir"
