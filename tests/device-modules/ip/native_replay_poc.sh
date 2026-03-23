#!/bin/bash

set -euo pipefail

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"

source "$IPMOD_DIR/lib.sh"

DO_BUILD=1
DO_DEPLOY=1
DURATION_S="${DURATION_S:-10}"
THREADS="${THREADS:-112}"
TRACE_ENTRIES="${TRACE_ENTRIES:-16384}"
CONN_BYTES="${CONN_BYTES:-256}"
PORT_BASE="${PORT_BASE:-18080}"
PORT_COUNT="${PORT_COUNT:-16}"
SRC_PORT_BASE="${SRC_PORT_BASE:-20000}"
SRC_PORT_SPAN="${SRC_PORT_SPAN:-16384}"
HOST_COUNT="${HOST_COUNT:-8}"
PEER_COUNT="${PEER_COUNT:-16}"
HOST_BASE_OCTET="${HOST_BASE_OCTET:-101}"
PEER_BASE_OCTET="${PEER_BASE_OCTET:-2}"
TRACE_SHUFFLE="${TRACE_SHUFFLE:-1}"
TRACE_SEED="${TRACE_SEED:-1}"
IPTEST_REPLAY_SINGLE_IPRULES="${IPTEST_REPLAY_SINGLE_IPRULES:-1}"
IPTEST_REPLAY_TRAFFIC_RULES="${IPTEST_REPLAY_TRAFFIC_RULES:-0}"
TRACE_HOST_PATH=""

csv_from_array() {
  local -n arr_ref="$1"
  local IFS=','
  printf '%s' "${arr_ref[*]}"
}

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

show_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>         Target Android serial
  --adb <path>              adb binary path
  --skip-build              Reuse existing build-output/iptest-replay
  --skip-deploy             Reuse current sucre-snort daemon
  --seconds <n>             Replay duration (default: ${DURATION_S})
  --threads <n>             Replay threads (default: ${THREADS})
  --entries <n>             Trace entries (default: ${TRACE_ENTRIES})
  --conn-bytes <n>          Bytes per connection (default: ${CONN_BYTES})
  --port-base <n>           First destination port (default: ${PORT_BASE})
  --port-count <n>          Number of destination ports (default: ${PORT_COUNT})
  --trace-seed <n>          Trace shuffle seed (default: ${TRACE_SEED})
  --trace-host-path <path>  Explicit host trace path
  -h, --help                Show help

Environment:
  IPTEST_REPLAY_SINGLE_IPRULES  0|1, set IPRULES during replay (default: ${IPTEST_REPLAY_SINGLE_IPRULES})
  IPTEST_REPLAY_TRAFFIC_RULES   Mixed would-block rules for replay UID (default: ${IPTEST_REPLAY_TRAFFIC_RULES})
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
    --seconds)
      DURATION_S="$2"
      shift 2
      ;;
    --threads)
      THREADS="$2"
      shift 2
      ;;
    --entries)
      TRACE_ENTRIES="$2"
      shift 2
      ;;
    --conn-bytes)
      CONN_BYTES="$2"
      shift 2
      ;;
    --port-base)
      PORT_BASE="$2"
      shift 2
      ;;
    --port-count)
      PORT_COUNT="$2"
      shift 2
      ;;
    --trace-seed)
      TRACE_SEED="$2"
      shift 2
      ;;
    --trace-host-path)
      TRACE_HOST_PATH="$2"
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

for v in DURATION_S THREADS TRACE_ENTRIES CONN_BYTES PORT_BASE PORT_COUNT SRC_PORT_BASE SRC_PORT_SPAN HOST_COUNT PEER_COUNT HOST_BASE_OCTET PEER_BASE_OCTET TRACE_SHUFFLE TRACE_SEED IPTEST_REPLAY_SINGLE_IPRULES IPTEST_REPLAY_TRAFFIC_RULES; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "$v must be a non-negative integer (got: ${!v})" >&2
    exit 1
  fi
done

if [[ "$DURATION_S" -lt 1 || "$THREADS" -lt 1 || "$TRACE_ENTRIES" -lt 1 || "$CONN_BYTES" -lt 1 ||
      "$HOST_COUNT" -lt 1 || "$PEER_COUNT" -lt 1 ]]; then
  echo "DURATION_S/THREADS/TRACE_ENTRIES/CONN_BYTES/HOST_COUNT/PEER_COUNT must all be >= 1" >&2
  exit 1
fi

if [[ "$PORT_COUNT" -lt 1 ]]; then
  echo "PORT_COUNT must be >= 1" >&2
  exit 1
fi

if [[ "$TRACE_SHUFFLE" -ne 0 && "$TRACE_SHUFFLE" -ne 1 ]]; then
  echo "TRACE_SHUFFLE must be 0 or 1" >&2
  exit 1
fi

if [[ "$IPTEST_REPLAY_SINGLE_IPRULES" -ne 0 && "$IPTEST_REPLAY_SINGLE_IPRULES" -ne 1 ]]; then
  echo "IPTEST_REPLAY_SINGLE_IPRULES must be 0 or 1" >&2
  exit 1
fi

net_prefix="${IPTEST_HOST_IP%.*}"
declare -a host_ips=("$IPTEST_HOST_IP")
declare -a peer_ips=("$IPTEST_PEER_IP")

if [[ "$HOST_COUNT" -gt 1 ]]; then
  build_ip_pool "$net_prefix" "$HOST_BASE_OCTET" "$((HOST_COUNT - 1))" host_extra_ips
  host_ips+=("${host_extra_ips[@]}")
  IPTEST_HOST_IP_POOL="$(csv_from_array host_extra_ips)"
  export IPTEST_HOST_IP_POOL
else
  unset IPTEST_HOST_IP_POOL || true
fi

build_ip_pool "$net_prefix" "$PEER_BASE_OCTET" "$PEER_COUNT" peer_ips
if [[ "${peer_ips[0]}" != "$IPTEST_PEER_IP" ]]; then
  peer_ips[0]="$IPTEST_PEER_IP"
fi
if [[ "${#peer_ips[@]}" -gt 1 ]]; then
  peer_extra_ips=("${peer_ips[@]:1}")
  IPTEST_PEER_IP_POOL="$(csv_from_array peer_extra_ips)"
  export IPTEST_PEER_IP_POOL
else
  unset IPTEST_PEER_IP_POOL || true
fi

host_ips_csv="$(csv_from_array host_ips)"
peer_ips_csv="$(csv_from_array peer_ips)"

if [[ $DO_BUILD -eq 1 ]]; then
  bash "$SNORT_ROOT/dev/dev-build-iptest-replay.sh"
fi

if [[ $DO_DEPLOY -eq 1 ]]; then
  deploy_cmd=(bash "$SNORT_ROOT/dev/dev-deploy.sh")
  if [[ -n "${ADB_SERIAL:-}" ]]; then
    deploy_cmd+=(--serial "$ADB_SERIAL")
  fi
  "${deploy_cmd[@]}"
fi

init_test_env

if ! iptest_require_tier1_prereqs; then
  echo "SKIP: tier1 prereqs missing (need root + ip/netns/veth + nc)" >&2
  exit 10
fi

table=""
tmp_trace=""
tmp_result=""
cleanup() {
  if [[ -n "$tmp_trace" && -f "$tmp_trace" ]]; then
    rm -f "$tmp_trace"
  fi
  if [[ -n "$tmp_result" && -f "$tmp_result" ]]; then
    rm -f "$tmp_result"
  fi
  adb_su "rm -f \"$IPTEST_REPLAY_DEVICE_TRACE\" \"$IPTEST_REPLAY_DEVICE_BIN\" 2>/dev/null || true" >/dev/null 2>&1 || true
  if [[ -n "$table" ]]; then
    iptest_tier1_teardown "$table" || true
  fi
}
trap cleanup EXIT

table="$(iptest_tier1_setup)"
iptest_reset_baseline
assert_ok "PERFMETRICS 1" "PERFMETRICS enable"
assert_ok "IPRULES ${IPTEST_REPLAY_SINGLE_IPRULES}" "IPRULES=${IPTEST_REPLAY_SINGLE_IPRULES}"

iptest_stage_replay_binary

if [[ -z "$TRACE_HOST_PATH" ]]; then
  tmp_trace="$(mktemp /tmp/iptest-trace-poc.XXXXXX.bin)"
  TRACE_HOST_PATH="$tmp_trace"
fi

ports_csv=""
for ((i = 0; i < PORT_COUNT; i++)); do
  if [[ -n "$ports_csv" ]]; then
    ports_csv+=","
  fi
  ports_csv+="$((PORT_BASE + i))"
done

add_rule() {
  local uid="$1"
  local desc="$2"
  local kv="$3"
  local out

  out="$(send_cmd "IPRULES.ADD ${uid} ${kv}")"
  if [[ ! "$out" =~ ^[0-9]+$ ]]; then
    echo "failed to add rule: ${desc}" >&2
    echo "cmd=IPRULES.ADD ${uid} ${kv}" >&2
    echo "got=${out}" >&2
    exit 1
  fi
  printf '%s\n' "$out"
}

install_replay_mix_rules() {
  local rules_added=0
  local host_count="${#host_ips[@]}"
  local peer_count="${#peer_ips[@]}"
  local miss_prefix="${IPTEST_PEER_IP%.*}"
  local veth0_ifindex=""
  local i host_ip peer_ip port hit_prio miss_prio miss_peer_ip miss_host_ip miss_port kv
  local range_hit_hi range_hit_lo range_miss_hi

  veth0_ifindex="$(iptest_iface_ifindex "$IPTEST_VETH0" 2>/dev/null || true)"

  for ((i = 0; rules_added < IPTEST_REPLAY_TRAFFIC_RULES; i++)); do
    host_ip="${host_ips[$((i % host_count))]}"
    peer_ip="${peer_ips[$(((i / host_count) % peer_count))]}"
    port="$((PORT_BASE + ((i / (host_count * peer_count)) % PORT_COUNT)))"
    hit_prio=$((420 - (i % 160)))
    miss_prio=$((900 - (i % 280)))
    miss_peer_ip="${miss_prefix}.$((200 + (i % 40)))"
    miss_host_ip="${miss_prefix}.$((150 + (i % 40)))"
    miss_port="$((PORT_BASE + PORT_COUNT + (i % 32)))"

    range_hit_lo=$(( port > PORT_BASE ? port - 1 : port ))
    range_hit_hi=$((port + 2))
    range_miss_hi=$((miss_port + 2))

    case $((i % 12)) in
      0)
        kv="action=block log=1 enforce=0 priority=${miss_prio} dir=out proto=tcp src=${host_ip}/32 dst=${peer_ip}/32 dport=${range_hit_lo}-${range_hit_hi}"
        ;;
      1)
        kv="action=block log=1 enforce=0 priority=${miss_prio} dir=out proto=tcp dst=${peer_ip}/32 dport=${range_hit_lo}-${port}"
        ;;
      2)
        kv="action=block log=1 enforce=0 priority=${hit_prio} dir=out proto=tcp dst=${IPTEST_NET_CIDR} dport=${port}"
        ;;
      3)
        kv="action=block log=1 enforce=0 priority=${miss_prio} dir=out proto=tcp src=${host_ip}/32 dst=${peer_ip}/32 dport=${miss_port}-${range_miss_hi}"
        ;;
      4)
        kv="action=block log=1 enforce=0 priority=${miss_prio} dir=out proto=tcp dst=${miss_peer_ip}/32 dport=${port}"
        ;;
      5)
        kv="action=block log=1 enforce=0 priority=${miss_prio} dir=out proto=tcp src=${miss_host_ip}/32 dst=${peer_ip}/32 dport=${port}"
        ;;
      6)
        kv="action=block log=1 enforce=0 priority=${hit_prio} dir=out proto=tcp src=${host_ip}/32 dst=${peer_ip}/32 dport=${port}"
        ;;
      7)
        kv="action=block log=1 enforce=0 priority=${hit_prio} dir=out proto=tcp dst=${peer_ip}/32 dport=${port}"
        ;;
      8)
        kv="action=block log=1 enforce=0 priority=${hit_prio} dir=out proto=any dst=${peer_ip}/32 dport=${port}"
        ;;
      9)
        kv="action=block log=1 enforce=0 priority=${hit_prio} dir=any proto=tcp dst=${peer_ip}/32 dport=${port}"
        ;;
      10)
        kv="action=block log=1 enforce=0 priority=${miss_prio} dir=in proto=tcp dst=${peer_ip}/32 dport=${port}"
        ;;
      11)
        if [[ "$veth0_ifindex" =~ ^[0-9]+$ ]]; then
          kv="action=block log=1 enforce=0 priority=${hit_prio} dir=out proto=tcp ifindex=${veth0_ifindex} dst=${peer_ip}/32 dport=${port}"
        else
          kv="action=block log=1 enforce=0 priority=${miss_prio} dir=out proto=udp dst=${peer_ip}/32 dport=${port}"
        fi
        ;;
    esac

    add_rule "$IPTEST_UID" "ADD native replay mixed rule i=$i" "$kv" >/dev/null
    rules_added=$((rules_added + 1))
  done
}

if [[ "$IPTEST_REPLAY_TRAFFIC_RULES" -gt 0 ]]; then
  install_replay_mix_rules
fi

preflight_json="$(send_cmd "IPRULES.PREFLIGHT")"
assert_ok "METRICS.PERF.RESET" "METRICS.PERF.RESET"

trace_gen_cmd=(
  python3 "$IPMOD_DIR/tools/gen_trace.py"
  --output "$TRACE_HOST_PATH"
  --entries "$TRACE_ENTRIES"
  --host-ip "$IPTEST_HOST_IP"
  --peer-ip "$IPTEST_PEER_IP"
  --host-ips-csv "$host_ips_csv"
  --peer-ips-csv "$peer_ips_csv"
  --dst-port-base "$PORT_BASE"
  --dst-port-count "$PORT_COUNT"
  --dst-ports-csv "$ports_csv"
  --src-port-base "$SRC_PORT_BASE"
  --src-port-span "$SRC_PORT_SPAN"
  --seed "$TRACE_SEED"
  --conn-bytes "$CONN_BYTES"
)

if [[ "$TRACE_SHUFFLE" -eq 1 ]]; then
  trace_gen_cmd+=(--shuffle)
fi

"${trace_gen_cmd[@]}"

adb_push_file "$TRACE_HOST_PATH" "$IPTEST_REPLAY_DEVICE_TRACE" >/dev/null
adb_su "chmod 644 \"$IPTEST_REPLAY_DEVICE_TRACE\""

server_pids="$(iptest_tier1_start_tcp_zero_servers "$ports_csv" | tr -d '\r' || true)"
server_count="$(printf '%s\n' "$server_pids" | sed '/^$/d' | wc -l | tr -d '[:space:]')"
if [[ ! "$server_count" =~ ^[0-9]+$ || "$server_count" -lt "$PORT_COUNT" ]]; then
  echo "failed to start tier1 tcp zero servers: expected=$PORT_COUNT got=$server_count" >&2
  exit 1
fi

tmp_result="$(mktemp /tmp/iptest-replay-result.XXXXXX)"
(
  iptest_adb_as_uid "$IPTEST_UID" \
    "sleep 1; \"$IPTEST_REPLAY_DEVICE_BIN\" --trace \"$IPTEST_REPLAY_DEVICE_TRACE\" --seconds \"$DURATION_S\" --threads \"$THREADS\"" \
    | tr -d '\r' || true
) >"$tmp_result" &
result_pid=$!

sample="$(stream_sample "PKTSTREAM.START 0 0" "PKTSTREAM.STOP" 3)"

wait "$result_pid"
result_raw="$(cat "$tmp_result")"

result_json="$(printf '%s\n' "$result_raw" | awk '/^IPTEST_REPLAY_RESULT_JSON /{sub(/^IPTEST_REPLAY_RESULT_JSON /, ""); print; exit}')"
if [[ -z "$result_json" ]]; then
  echo "missing IPTEST_REPLAY_RESULT_JSON" >&2
  echo "$result_raw" >&2
  exit 1
fi

read -r bytes_actual connections_actual failures_actual <<<"$(python3 - "$result_json" <<'PY'
import json
import sys
r = json.loads(sys.argv[1])
print(r["bytes"], r["connections"], r["failures"])
PY
)"

if [[ "$bytes_actual" -le 0 || "$connections_actual" -le 0 ]]; then
  echo "native replay transferred no traffic: bytes=$bytes_actual connections=$connections_actual" >&2
  exit 1
fi

set +e
PKT_UID="$IPTEST_UID" SRC_IPS_CSV="$host_ips_csv" DST_IPS_CSV="$peer_ips_csv" DST_PORTS_CSV="$ports_csv" \
python3 -c '
import json
import os
import sys

uid = int(os.environ["PKT_UID"])
src_ips = {item for item in os.environ["SRC_IPS_CSV"].split(",") if item}
dst_ips = {item for item in os.environ["DST_IPS_CSV"].split(",") if item}
ports = {int(item) for item in os.environ["DST_PORTS_CSV"].split(",") if item}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    if obj.get("uid") != uid:
        continue
    if obj.get("direction") != "out":
        continue
    if obj.get("protocol") != "tcp":
        continue
    if obj.get("srcIp") not in src_ips or obj.get("dstIp") not in dst_ips:
        continue
    if int(obj.get("dstPort", -1)) not in ports:
        continue
    raise SystemExit(0)

raise SystemExit(2)
' <<<"$sample"
pktstream_rc=$?
set -e

if [[ $pktstream_rc -ne 0 ]]; then
  echo "PKTSTREAM did not capture the native replay flow" >&2
  exit 1
fi

perf_json="$(send_cmd "METRICS.PERF")"
samples="$(echo "$perf_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(int(d["perf"]["nfq_total_us"]["samples"]))')"
if [[ ! "$samples" =~ ^[0-9]+$ || "$samples" -le 0 ]]; then
  echo "METRICS.PERF has no nfq_total_us samples after native replay" >&2
  echo "$perf_json" >&2
  exit 1
fi

echo "TRACE_PATH=$TRACE_HOST_PATH"
echo "REPLAY_BYTES=$bytes_actual"
echo "REPLAY_CONNECTIONS=$connections_actual"
echo "REPLAY_FAILURES=$failures_actual"
echo "PERF_SAMPLES=$samples"
echo "TRACE_HOST_COUNT=${#host_ips[@]}"
echo "TRACE_PEER_COUNT=${#peer_ips[@]}"
echo "TRACE_PORT_COUNT=$PORT_COUNT"
echo "TRACE_SHUFFLE=$TRACE_SHUFFLE"
echo "TRACE_SEED=$TRACE_SEED"
echo "REPLAY_IPRULES=$IPTEST_REPLAY_SINGLE_IPRULES"
echo "REPLAY_TRAFFIC_RULES=$IPTEST_REPLAY_TRAFFIC_RULES"
echo "PKTSTREAM_MATCH=1"
echo "REPLAY_RESULT_JSON $result_json"
echo "PREFLIGHT_RESULT_JSON $(echo "$preflight_json" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), ensure_ascii=False, separators=(",", ":")))')"
echo "PERF_RESULT_JSON $(echo "$perf_json" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin), ensure_ascii=False, separators=(",", ":")))')"
