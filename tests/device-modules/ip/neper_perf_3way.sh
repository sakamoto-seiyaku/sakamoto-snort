#!/bin/bash

set -euo pipefail
umask 077

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"

source "$IPMOD_DIR/lib.sh"

DO_BUILD=0
DO_DEPLOY=0

SCENARIO_MODE="${SCENARIO_MODE:-all}" # all|off|2k|4k
DURATION_S="${DURATION_S:-30}"
WARMUP_S="${WARMUP_S:-0}"
COOLDOWN_S="${COOLDOWN_S:-0}"
THREADS="${THREADS:-8}"
FLOWS="${FLOWS:-1024}"
BYTES="${BYTES:-1}"
PORT="${PORT:-20000}"
CONTROL_PORT="${CONTROL_PORT:-19999}"
NUM_PORTS="${NUM_PORTS:-16}"
CLIENT_UID="${CLIENT_UID:-$IPTEST_UID}"
LOCAL_HOST_COUNT="${LOCAL_HOST_COUNT:-1}"
LOCAL_HOST_BASE_OCTET="${LOCAL_HOST_BASE_OCTET:-101}"

# Heavy ruleset sizes (traffic UID only).
RULES_2K="${RULES_2K:-2048}"
RULES_4K="${RULES_4K:-4096}"

# Keep PERFMETRICS off by default. We primarily use neper's own stats, and use
# nfnetlink_queue deltas as guardrails.
PERFMETRICS="${PERFMETRICS:-0}"

# neper/server tuning
LISTEN_BACKLOG="${LISTEN_BACKLOG:-4096}"

show_help() {
  cat <<EOF
Usage: $0 [options]

Options:
  --serial <serial>      Target Android serial
  --adb <path>           adb binary path
  --build                Build neper (dev/dev-build-iptest-neper.sh)
  --deploy               Deploy sucre-snort daemon (dev/dev-deploy.sh)
  --scenario <mode>      Run mode: all|off|2k|4k (default: ${SCENARIO_MODE})
  --seconds <n>          Per-scenario duration (default: ${DURATION_S})
  --warmup <n>           Warmup duration before measured scenarios (default: ${WARMUP_S})
  --cooldown <n>         Sleep between scenarios (default: ${COOLDOWN_S})
  --threads <n>          neper threads (default: ${THREADS})
  --flows <n>            neper flows (default: ${FLOWS})
  --bytes <n>            tcp_crr request/response bytes (default: ${BYTES})
  --num-ports <n>        tcp_crr num ports (default: ${NUM_PORTS})
  --local-host-count <n> Client bind IP pool size (default: ${LOCAL_HOST_COUNT})
  --local-host-base-octet <n> Extra host IPs start at x.x.x.<n> (default: ${LOCAL_HOST_BASE_OCTET})
  --uid <uid>            Client UID (default: ${CLIENT_UID})
  --perfmetrics <0|1>    Toggle PERFMETRICS during the run (default: ${PERFMETRICS})
  -h, --help             Show help

Scenarios (expected monotonic separation):
  1) iprules_off    IPRULES=0 (empty ruleset)
  2) iprules_2k     IPRULES=1 (traffic UID rules ~${RULES_2K})
  3) iprules_4k     IPRULES=1 (traffic UID rules ~${RULES_4K})
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
    --build)
      DO_BUILD=1
      shift
      ;;
    --deploy)
      DO_DEPLOY=1
      shift
      ;;
    --scenario)
      SCENARIO_MODE="$2"
      shift 2
      ;;
    --seconds)
      DURATION_S="$2"
      shift 2
      ;;
    --warmup)
      WARMUP_S="$2"
      shift 2
      ;;
    --cooldown)
      COOLDOWN_S="$2"
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
    --uid)
      CLIENT_UID="$2"
      shift 2
      ;;
    --perfmetrics)
      PERFMETRICS="$2"
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

for v in DURATION_S WARMUP_S COOLDOWN_S THREADS FLOWS BYTES PORT CONTROL_PORT NUM_PORTS CLIENT_UID LOCAL_HOST_COUNT LOCAL_HOST_BASE_OCTET RULES_2K RULES_4K PERFMETRICS LISTEN_BACKLOG; do
  if ! [[ "${!v}" =~ ^[0-9]+$ ]]; then
    echo "$v must be a non-negative integer (got: ${!v})" >&2
    exit 1
  fi
done

case "$SCENARIO_MODE" in
  all|off|2k|4k) ;;
  *)
    echo "SCENARIO_MODE must be one of: all|off|2k|4k (got: $SCENARIO_MODE)" >&2
    exit 1
    ;;
esac

if [[ "$DURATION_S" -lt 1 || "$THREADS" -lt 1 || "$FLOWS" -lt 1 || "$BYTES" -lt 1 || "$NUM_PORTS" -lt 1 ]]; then
  echo "SECONDS/THREADS/FLOWS/BYTES/NUM_PORTS must all be >= 1" >&2
  exit 1
fi
if [[ "$PORT" -lt 20000 ]]; then
  echo "PORT must be >= 20000 (ruleset miss-range assumes base port >=20000; got: $PORT)" >&2
  exit 1
fi
if [[ $((PORT + NUM_PORTS - 1)) -gt 65535 ]]; then
  echo "PORT + NUM_PORTS exceeds 65535 (port=$PORT num_ports=$NUM_PORTS)" >&2
  exit 1
fi
if [[ "$LOCAL_HOST_COUNT" -lt 1 ]]; then
  echo "LOCAL_HOST_COUNT must be >= 1 (got: $LOCAL_HOST_COUNT)" >&2
  exit 1
fi
if [[ "$LOCAL_HOST_BASE_OCTET" -lt 1 || "$LOCAL_HOST_BASE_OCTET" -gt 254 ]]; then
  echo "LOCAL_HOST_BASE_OCTET must be in [1,254] (got: $LOCAL_HOST_BASE_OCTET)" >&2
  exit 1
fi
if [[ "$LOCAL_HOST_COUNT" -gt 1 ]]; then
  last_octet=$((LOCAL_HOST_BASE_OCTET + LOCAL_HOST_COUNT - 2))
  if [[ "$last_octet" -gt 254 ]]; then
    echo "LOCAL_HOST_BASE_OCTET too large for LOCAL_HOST_COUNT=$LOCAL_HOST_COUNT (last_octet=$last_octet)" >&2
    exit 1
  fi
fi

if [[ "$PERFMETRICS" -ne 0 && "$PERFMETRICS" -ne 1 ]]; then
  echo "PERFMETRICS must be 0 or 1 (got: $PERFMETRICS)" >&2
  exit 1
fi

if [[ "$RULES_2K" -le 0 || "$RULES_4K" -le 0 || "$RULES_2K" -ge "$RULES_4K" ]]; then
  echo "RULES_2K and RULES_4K must be >0 and RULES_2K < RULES_4K" >&2
  exit 1
fi
if [[ $((RULES_2K % 64)) -ne 0 || $((RULES_4K % 64)) -ne 0 ]]; then
  echo "RULES_2K/RULES_4K must be multiples of 64 (range candidates hard limit per bucket)" >&2
  exit 1
fi
if [[ "$RULES_4K" -gt 4096 ]]; then
  echo "RULES_4K too large (max 4096 for this ruleset shape; got: $RULES_4K)" >&2
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

if ! iptest_require_tier1_prereqs; then
  echo "SKIP: tier1 prereqs missing (need root + ip/netns/veth + ping)" >&2
  exit 10
fi

iptest_stage_neper_binaries

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
if [[ "$LOCAL_HOST_COUNT" -gt 1 ]]; then
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

table=""
records_dir=""

cleanup() {
  if [[ -n "$table" ]]; then
    iptest_tier1_teardown "$table" || true
  fi
}
trap cleanup EXIT

table="$(iptest_tier1_setup)" || exit $?

ts="$(date -u +%Y%m%dT%H%M%SZ)"
records_dir="$IPMOD_DIR/records/neper-perf-3way-${ts}_$(adb_target_desc)"
mkdir -p "$records_dir"

log() {
  printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

snortctl_batch() {
  python3 "$IPMOD_DIR/tools/snortctl.py" --batch
}

snortctl_cmd() {
  python3 "$IPMOD_DIR/tools/snortctl.py" --cmd "$1"
}

capture_nfq() {
  adb_su "cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true"
}

nfq_delta_summary() {
  python3 - "$1" "$2" <<'PY'
import sys
from pathlib import Path

before_path = Path(sys.argv[1])
after_path = Path(sys.argv[2])

def load(path: Path) -> dict[int, tuple[int, int, int]]:
    out: dict[int, tuple[int, int, int]] = {}
    for line in path.read_text().splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            qid = int(parts[0])
            qdrop = int(parts[5])
            udrop = int(parts[6])
            seq = int(parts[7])
        except ValueError:
            continue
        out[qid] = (seq, qdrop, udrop)
    return out

before = load(before_path)
after = load(after_path)

seq_total = 0
qdrop_total = 0
udrop_total = 0
top = []
for qid, (seq_a, qd_a, ud_a) in after.items():
    seq_b, qd_b, ud_b = before.get(qid, (seq_a, qd_a, ud_a))
    seq_d = max(0, seq_a - seq_b)
    qd_d = max(0, qd_a - qd_b)
    ud_d = max(0, ud_a - ud_b)
    seq_total += seq_d
    qdrop_total += qd_d
    udrop_total += ud_d
    if seq_d:
        top.append((seq_d, qid))
top.sort(reverse=True)
top = top[:6]

print(f"nfq_seq_total={seq_total}")
print(f"nfq_queue_dropped_total={qdrop_total}")
print(f"nfq_user_dropped_total={udrop_total}")
print("nfq_top=" + ",".join([f"q{qid}:{diff}" for diff, qid in top]) if top else "nfq_top=")
PY
}

run_neper_tcp_crr() {
  local label="$1"
  local seconds="${2:-$DURATION_S}"
  local client_log="$records_dir/${label}_client.txt"
  local server_log="$records_dir/${label}_server.txt"
  local nfq_before="$records_dir/${label}_nfq_before.txt"
  local nfq_after="$records_dir/${label}_nfq_after.txt"
  local proc_before="$records_dir/${label}_snort_proc_before.txt"
  local proc_after="$records_dir/${label}_snort_proc_after.txt"

  iptest_capture_snort_proc_snapshot >"$proc_before" || true
  capture_nfq >"$nfq_before" || true

  adb_su "rm -f /data/local/tmp/iptest_neper_tcp_srv.log"
  adb_su "ip netns exec \"$IPTEST_NS\" \"$IPTEST_NEPER_TCP_CRR_DEVICE_BIN\" --nolog -4 -P \"$PORT\" -C \"$CONTROL_PORT\" -T \"$THREADS\" -F \"$FLOWS\" --num-ports \"$NUM_PORTS\" --listen-backlog \"$LISTEN_BACKLOG\" -Q \"$BYTES\" -R \"$BYTES\" >/data/local/tmp/iptest_neper_tcp_srv.log 2>&1 &"
  sleep 0.2

  local client_cmd="\"$IPTEST_NEPER_TCP_CRR_DEVICE_BIN\" --nolog -4 -c -H \"$IPTEST_PEER_IP\" -P \"$PORT\" -C \"$CONTROL_PORT\" -T \"$THREADS\" -F \"$FLOWS\" --num-ports \"$NUM_PORTS\" -Q \"$BYTES\" -R \"$BYTES\" -l \"$seconds\" --no-delay"
  if [[ -n "$local_hosts_csv" ]]; then
    client_cmd="${client_cmd} -L \"${local_hosts_csv}\""
  fi

  iptest_adb_as_uid "$CLIENT_UID" \
    "$client_cmd" \
    >"$client_log"

  adb_su "cat /data/local/tmp/iptest_neper_tcp_srv.log 2>/dev/null || true" >"$server_log" || true

  capture_nfq >"$nfq_after" || true
  iptest_capture_snort_proc_snapshot >"$proc_after" || true

  local summary="$records_dir/${label}_summary.txt"
  {
    echo "== neper =="
    tail -n 40 "$client_log" | sed -n '/num_transactions=/,$p'
    echo ""
    echo "== nfq delta =="
    nfq_delta_summary "$nfq_before" "$nfq_after"
    echo ""
    echo "== snort proc delta =="
    iptest_snort_proc_delta_summary "$proc_before" "$proc_after"
  } | tee "$summary"

  python3 - "$label" "$client_log" "$summary" "$seconds" "$THREADS" "$FLOWS" "$NUM_PORTS" "$BYTES" "$CLIENT_UID" "$LOCAL_HOST_COUNT" "$LOCAL_HOST_BASE_OCTET" >>"$records_dir/results.jsonl" <<'PY'
import json
import re
import sys
from pathlib import Path

label = sys.argv[1]
client_log = Path(sys.argv[2]).read_text()
summary_txt = Path(sys.argv[3]).read_text()
seconds = int(sys.argv[4])
threads = int(sys.argv[5])
flows = int(sys.argv[6])
num_ports = int(sys.argv[7])
bytes_rr = int(sys.argv[8])
uid = int(sys.argv[9])
local_host_count = int(sys.argv[10])
local_host_base_octet = int(sys.argv[11])

def find_float(name: str) -> float:
    m = re.search(rf"^{re.escape(name)}=([-+]?[0-9]*\.?[0-9]+)$", client_log, re.M)
    if not m:
        return 0.0
    return float(m.group(1))

def find_int(name: str) -> int:
    m = re.search(rf"^{re.escape(name)}=([0-9]+)$", client_log, re.M)
    if not m:
        return 0
    return int(m.group(1))

def find_kv_int(name: str) -> int:
    m = re.search(rf"^{re.escape(name)}=([-]?[0-9]+)$", summary_txt, re.M)
    if not m:
        return 0
    return int(m.group(1))

seq_total = find_kv_int("nfq_seq_total")
snort_cpu_ticks = find_kv_int("snort_cpu_ticks_delta")
snort_clk_tck = find_kv_int("snort_clk_tck")
snort_cpu_ms_delta = (snort_cpu_ticks / snort_clk_tck * 1000.0) if snort_clk_tck else 0.0

num_transactions = find_int("num_transactions")
snort_cpu_ticks_per_txn = (snort_cpu_ticks / num_transactions) if num_transactions else 0.0
snort_cpu_ms_per_txn = (snort_cpu_ms_delta / num_transactions) if num_transactions else 0.0

row = {
    "scenario": label,
    "knobs": {
        "seconds": seconds,
        "threads": threads,
        "flows": flows,
    "num_ports": num_ports,
    "bytes": bytes_rr,
    "uid": uid,
    "local_host_count": local_host_count,
    "local_host_base_octet": local_host_base_octet,
  },
    "neper": {
        "throughput_tps": find_float("throughput"),
        "num_transactions": num_transactions,
        "latency_mean_s": find_float("latency_mean"),
        "latency_max_s": find_float("latency_max"),
    },
    "nfq": {
        "seq_total": seq_total,
        "queue_dropped_total": find_kv_int("nfq_queue_dropped_total"),
        "user_dropped_total": find_kv_int("nfq_user_dropped_total"),
    },
    "snort_proc": {
        "pid": find_kv_int("snort_pid"),
        "clk_tck": snort_clk_tck,
        "utime_ticks_delta": find_kv_int("snort_utime_ticks_delta"),
        "stime_ticks_delta": find_kv_int("snort_stime_ticks_delta"),
        "cpu_ticks_delta": snort_cpu_ticks,
        "cpu_ms_delta": snort_cpu_ms_delta,
        "cpu_ticks_per_txn": snort_cpu_ticks_per_txn,
        "cpu_ms_per_txn": snort_cpu_ms_per_txn,
        "vm_rss_kb_before": find_kv_int("snort_vm_rss_kb_before"),
        "vm_rss_kb_after": find_kv_int("snort_vm_rss_kb_after"),
        "vm_rss_kb_delta": find_kv_int("snort_vm_rss_kb_delta"),
    },
}
print(json.dumps(row, ensure_ascii=False, separators=(",", ":")))
PY
}

install_heavy_rules() {
  local label="$1" # tag for records
  local subtable_start="$2"
  local subtable_count="$3"

  local target_rules=$((subtable_count * 64))
  log "install rules: label=$label uid=$CLIENT_UID start=$subtable_start count=$subtable_count target_rules=$target_rules"

  local out
  out="$(snortctl_cmd "IPRULES.PREFLIGHT")"
  echo "$out" >"$records_dir/${label}_preflight_before.json"

  # Strategy:
  # - We stay within hard constraints:
  #   - maxSubtablesPerUid <= 64
  #   - maxRangeRulesPerBucket <= 64
  # - Create S subtables (S=32 for 2k, S=64 for 4k), each with exactly 64 range candidates.
  # - Ensure that the winner is always the LAST rule (priority low) so each bucket scans all 64.
  python3 - "$CLIENT_UID" "$subtable_start" "$subtable_count" "$IPTEST_HOST_IP" "$IPTEST_PEER_IP" <<'PY' \
    | snortctl_batch \
    | python3 /dev/fd/3 "$target_rules" 3<<'PY2'
import ipaddress
import sys

uid = int(sys.argv[1])
subtable_start = int(sys.argv[2])
subtable_count = int(sys.argv[3])
host_ip = int(ipaddress.IPv4Address(sys.argv[4]))
peer_ip = int(ipaddress.IPv4Address(sys.argv[5]))

def mask(prefix: int) -> int:
    if prefix == 0:
        return 0
    return (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF

def cidr(ip_int: int, prefix: int) -> str:
    net = ip_int & mask(prefix)
    return f"{ipaddress.IPv4Address(net)}/{prefix}"

# Prefixes are chosen to ensure host/peer share the same masked value (<= 30 is OK for .1/.2).
prefixes = [0, 1, 2, 4, 8, 12, 16, 24]

# Subtables (srcPrefix,dstPrefix) grid.
subtables = [(sp, dp) for sp in prefixes for dp in prefixes]  # 64

subtables = subtables[subtable_start : subtable_start + subtable_count]
if len(subtables) != subtable_count:
    raise SystemExit("subtable slice out of range")

per_subtable = 64
total = len(subtables) * per_subtable
if total != subtable_count * per_subtable:
    raise SystemExit("internal mismatch")

miss_prio = 1000
hit_prio = 0

# All miss rules use a port range that never matches our traffic ports (base port >= 20000).
miss_dport = "1-19999"
hit_dport = "0-65535"

for sp, dp in subtables:
    # Use the same base to ensure host/peer resolve to the same masked values
    # for the chosen prefixes (so rules apply to both IN and OUT directions).
    src = cidr(host_ip, sp)
    dst = cidr(host_ip, dp)

    # 63 miss rules (range) + 1 hit rule (range), all would-block (enforce=0).
    for _ in range(per_subtable - 1):
        print(
            f"IPRULES.ADD {uid} action=block log=1 enforce=0 priority={miss_prio} "
            f"dir=any proto=tcp src={src} dst={dst} dport={miss_dport}"
        )
    print(
        f"IPRULES.ADD {uid} action=block log=1 enforce=0 priority={hit_prio} "
        f"dir=any proto=tcp src={src} dst={dst} dport={hit_dport}"
    )
PY
import sys

target = int(sys.argv[1])
count = 0
for line in sys.stdin:
    s = line.strip()
    if not s:
        continue
    if not s.isdigit():
        sys.stderr.write(f"unexpected response: {s[:200]}\n")
        raise SystemExit(1)
    count += 1
if count != target:
    sys.stderr.write(f"rule add count mismatch: got={count} expected={target}\n")
    raise SystemExit(1)
PY2

  out="$(snortctl_cmd "IPRULES.PREFLIGHT")"
  echo "$out" >"$records_dir/${label}_preflight_after.json"
  echo "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("summary",{}), ensure_ascii=False))' \
    | tee "$records_dir/${label}_preflight_after.summary.txt"
}

log "RESETALL + baseline toggles"
assert_ok "RESETALL" "RESETALL baseline"
assert_ok "BLOCK 1" "BLOCK=1"
assert_ok "PERFMETRICS ${PERFMETRICS}" "PERFMETRICS=${PERFMETRICS}"
assert_ok "METRICS.PERF.RESET" "METRICS.PERF.RESET"

if [[ "$WARMUP_S" -gt 0 ]]; then
  log "warmup: iprules_off duration=${WARMUP_S}s"
  assert_ok "IPRULES 0" "IPRULES=0 (warmup)"
  run_neper_tcp_crr "warmup_off" "$WARMUP_S"
  if [[ "$COOLDOWN_S" -gt 0 ]]; then
    log "cooldown: ${COOLDOWN_S}s"
    sleep "$COOLDOWN_S"
  fi
fi

subtables_2k=$((RULES_2K / 64))
subtables_4k=$((RULES_4K / 64))

if [[ "$SCENARIO_MODE" == "all" || "$SCENARIO_MODE" == "off" ]]; then
  log "scenario: iprules_off (empty ruleset)"
  assert_ok "IPRULES 0" "IPRULES=0 (off)"
  run_neper_tcp_crr "iprules_off" "$DURATION_S"
  if [[ "$COOLDOWN_S" -gt 0 && "$SCENARIO_MODE" == "all" ]]; then
    log "cooldown: ${COOLDOWN_S}s"
    sleep "$COOLDOWN_S"
  fi
fi

if [[ "$SCENARIO_MODE" == "all" || "$SCENARIO_MODE" == "2k" || "$SCENARIO_MODE" == "4k" ]]; then
  assert_ok "IPRULES 1" "IPRULES=1 (on)"
fi

if [[ "$SCENARIO_MODE" == "all" || "$SCENARIO_MODE" == "2k" ]]; then
  log "scenario: iprules_2k"
  install_heavy_rules "iprules_2k" 0 "$subtables_2k"
  run_neper_tcp_crr "iprules_2k" "$DURATION_S"
  if [[ "$COOLDOWN_S" -gt 0 && "$SCENARIO_MODE" == "all" ]]; then
    log "cooldown: ${COOLDOWN_S}s"
    sleep "$COOLDOWN_S"
  fi
fi

if [[ "$SCENARIO_MODE" == "all" ]]; then
  log "scenario: iprules_4k"
  install_heavy_rules "iprules_4k" "$subtables_2k" "$((subtables_4k - subtables_2k))"
  run_neper_tcp_crr "iprules_4k" "$DURATION_S"
elif [[ "$SCENARIO_MODE" == "4k" ]]; then
  log "scenario: iprules_4k"
  install_heavy_rules "iprules_4k" 0 "$subtables_4k"
  run_neper_tcp_crr "iprules_4k" "$DURATION_S"
fi

log "done: records_dir=$records_dir"
echo "OK records_dir=$records_dir"
