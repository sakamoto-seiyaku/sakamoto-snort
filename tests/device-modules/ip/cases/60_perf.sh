#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "ip perf (tier1)"

IPTEST_PERF_PORT="${IPTEST_PERF_PORT:-18080}"
IPTEST_PERF_BYTES="${IPTEST_PERF_BYTES:-20000000}"
IPTEST_PERF_SECONDS="${IPTEST_PERF_SECONDS:-0}"
IPTEST_PERF_CHUNK_BYTES="${IPTEST_PERF_CHUNK_BYTES:-2000000}"
IPTEST_PERF_LOAD_MODE="${IPTEST_PERF_LOAD_MODE:-stream}" # stream|chunk|mix
IPTEST_PERF_SINGLE_IPRULES="${IPTEST_PERF_SINGLE_IPRULES:-1}" # 0|1 when compare=0
IPTEST_PERF_MIX_WORKERS="${IPTEST_PERF_MIX_WORKERS:-16}"
IPTEST_PERF_MIX_CONN_BYTES="${IPTEST_PERF_MIX_CONN_BYTES:-8192}"
IPTEST_PERF_MIX_HOST_COUNT="${IPTEST_PERF_MIX_HOST_COUNT:-4}"
IPTEST_PERF_MIX_PEER_COUNT="${IPTEST_PERF_MIX_PEER_COUNT:-16}"
IPTEST_PERF_MIX_PORT_COUNT="${IPTEST_PERF_MIX_PORT_COUNT:-8}"
IPTEST_PERF_MIX_HOST_BASE_OCTET="${IPTEST_PERF_MIX_HOST_BASE_OCTET:-101}"
IPTEST_PERF_MIX_PEER_BASE_OCTET="${IPTEST_PERF_MIX_PEER_BASE_OCTET:-2}"
IPTEST_PERF_MIX_PORT_BASE="${IPTEST_PERF_MIX_PORT_BASE:-18080}"

IPTEST_PERF_TRAFFIC_RULES="${IPTEST_PERF_TRAFFIC_RULES:-2000}"
IPTEST_PERF_BG_TOTAL="${IPTEST_PERF_BG_TOTAL:-0}"
IPTEST_PERF_BG_UIDS="${IPTEST_PERF_BG_UIDS:-$IPTEST_PERF_BG_TOTAL}"
IPTEST_PERF_BG_UID_BASE="${IPTEST_PERF_BG_UID_BASE:-10000}"
IPTEST_PERF_COMPARE="${IPTEST_PERF_COMPARE:-0}"

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

declare -a perf_host_ips=("$IPTEST_HOST_IP")
declare -a perf_peer_ips=("$IPTEST_PEER_IP")
declare -a perf_ports=("$IPTEST_PERF_PORT")

if [[ "$IPTEST_PERF_LOAD_MODE" == "mix" ]]; then
  if [[ "$IPTEST_PERF_MIX_WORKERS" -lt 1 || "$IPTEST_PERF_MIX_CONN_BYTES" -lt 1 ||
        "$IPTEST_PERF_MIX_HOST_COUNT" -lt 1 || "$IPTEST_PERF_MIX_PEER_COUNT" -lt 1 ||
        "$IPTEST_PERF_MIX_PORT_COUNT" -lt 1 ]]; then
    echo "SKIP: mix perf knobs must all be >= 1"
    exit 10
  fi

  net_prefix="${IPTEST_HOST_IP%.*}"
  perf_host_ips=("$IPTEST_HOST_IP")
  if [[ "$IPTEST_PERF_MIX_HOST_COUNT" -gt 1 ]]; then
    build_ip_pool "$net_prefix" "$IPTEST_PERF_MIX_HOST_BASE_OCTET" \
      "$((IPTEST_PERF_MIX_HOST_COUNT - 1))" perf_host_extra_ips
    perf_host_ips+=("${perf_host_extra_ips[@]}")
    IPTEST_HOST_IP_POOL="$(csv_from_array perf_host_extra_ips)"
    export IPTEST_HOST_IP_POOL
  else
    unset IPTEST_HOST_IP_POOL || true
  fi

  build_ip_pool "$net_prefix" "$IPTEST_PERF_MIX_PEER_BASE_OCTET" \
    "$IPTEST_PERF_MIX_PEER_COUNT" perf_peer_ips
  if [[ "${perf_peer_ips[0]}" != "$IPTEST_PEER_IP" ]]; then
    perf_peer_ips[0]="$IPTEST_PEER_IP"
  fi
  if [[ "${#perf_peer_ips[@]}" -gt 1 ]]; then
    perf_peer_extra_ips=("${perf_peer_ips[@]:1}")
    IPTEST_PEER_IP_POOL="$(csv_from_array perf_peer_extra_ips)"
    export IPTEST_PEER_IP_POOL
  else
    unset IPTEST_PEER_IP_POOL || true
  fi

  perf_ports=()
  for ((i = 0; i < IPTEST_PERF_MIX_PORT_COUNT; i++)); do
    perf_ports+=("$((IPTEST_PERF_MIX_PORT_BASE + i))")
  done
  IPTEST_PERF_PORT="${perf_ports[0]}"
fi

mix_host_ips_csv="$(csv_from_array perf_host_ips)"
mix_peer_ips_csv="$(csv_from_array perf_peer_ips)"
mix_ports_csv="$(csv_from_array perf_ports)"

if ! init_test_env; then
  exit 2
fi

if ! iptest_require_tier1_prereqs; then
  echo "SKIP: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)"
  exit 10
fi

table=""
cleanup() {
  if [[ -n "$table" ]]; then
    iptest_tier1_teardown "$table" || true
  fi
}
trap cleanup EXIT

table="$(iptest_tier1_setup)" || exit $?

iptest_reset_baseline

assert_ok "PERFMETRICS 1" "PERFMETRICS enable"
assert_ok "METRICS.PERF.RESET" "METRICS.PERF.RESET"

if [[ "$IPTEST_PERF_LOAD_MODE" == "mix" ]]; then
  server_pids="$(iptest_tier1_start_tcp_zero_servers "$mix_ports_csv" | tr -d '\r' || true)"
  server_count="$(printf '%s\n' "$server_pids" | sed '/^$/d' | wc -l | tr -d '[:space:]')"
  if [[ ! "$server_count" =~ ^[0-9]+$ || "$server_count" -lt "${#perf_ports[@]}" ]]; then
    log_fail "start tier1 tcp mix servers"
    echo "server_pids=$server_pids"
    exit 3
  fi
  log_info "tier1 tcp mix servers ports=$mix_ports_csv pids=$(printf '%s' "$server_pids" | tr '\n' ',')"
else
  server_pid="$(iptest_tier1_start_tcp_zero_server "$IPTEST_PERF_PORT" | tr -d '\r\n' || true)"
  if [[ ! "$server_pid" =~ ^[0-9]+$ ]]; then
    log_fail "start tier1 tcp server"
    echo "server_pid=$server_pid"
    exit 3
  fi
  log_info "tier1 tcp server pid=$server_pid port=$IPTEST_PERF_PORT"
fi

# Ruleset: traffic UID gets N rules (baseline default: 2K).
log_info "install rules: trafficUid=$IPTEST_UID trafficRules=$IPTEST_PERF_TRAFFIC_RULES backgroundTotal=$IPTEST_PERF_BG_TOTAL"

total_rules=$((IPTEST_PERF_TRAFFIC_RULES + IPTEST_PERF_BG_TOTAL))
if [[ "$total_rules" -gt 5000 ]]; then
  echo "SKIP: total active rules exceed hard limit (total=$total_rules > 5000)"
  exit 10
fi

if [[ "$IPTEST_PERF_TRAFFIC_RULES" -lt 0 ]]; then
  echo "SKIP: IPTEST_PERF_TRAFFIC_RULES must be >= 0 (got $IPTEST_PERF_TRAFFIC_RULES)"
  exit 10
fi

add_rule() {
  local uid="$1"
  local desc="$2"
  local kv="$3"

  local out
  out="$(send_cmd "IPRULES.ADD ${uid} ${kv}")"
  if [[ ! "$out" =~ ^[0-9]+$ ]]; then
    log_fail "$desc"
    echo "cmd=IPRULES.ADD ${uid} ${kv}"
    echo "got: $out"
    exit 4
  fi
  printf '%s\n' "$out"
  return 0
}

veth0_ifindex="$(iptest_iface_ifindex "$IPTEST_VETH0" 2>/dev/null || true)"
if [[ "$veth0_ifindex" =~ ^[0-9]+$ ]]; then
  log_info "veth0 ifindex=$veth0_ifindex"
else
  veth0_ifindex=""
  log_info "veth0 ifindex unavailable; skip ifindex-specific rules"
fi

rules_added=0

install_single_flow_rules() {
  if [[ "$IPTEST_PERF_TRAFFIC_RULES" -le 0 ]]; then
    log_info "traffic rules disabled: running empty-ruleset baseline"
    return 0
  fi

  rid_hit="$(add_rule "$IPTEST_UID" "ADD traffic hit rule" "action=allow priority=1000 dir=out proto=tcp dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}")"
  rules_added=$((rules_added + 1))

  declare -a hot_kv=(
    "action=allow priority=1000 dir=any proto=tcp dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
    "action=allow priority=1000 dir=out proto=any dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
    "action=allow priority=1000 dir=out proto=tcp dst=${IPTEST_NET_CIDR} dport=${IPTEST_PERF_PORT}"
    "action=allow priority=1000 dir=out proto=tcp dst=any dport=${IPTEST_PERF_PORT}"
    "action=allow priority=1000 dir=out proto=tcp dst=${IPTEST_PEER_IP}/32 dport=any"
    "action=allow priority=1000 dir=out proto=tcp src=${IPTEST_HOST_IP}/32 dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
  )
  if [[ -n "$veth0_ifindex" ]]; then
    hot_kv+=("action=allow priority=1000 dir=out proto=tcp ifindex=${veth0_ifindex} dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}")
  fi

  for kv in "${hot_kv[@]}"; do
    if [[ "$rules_added" -ge "$IPTEST_PERF_TRAFFIC_RULES" ]]; then
      break
    fi
    add_rule "$IPTEST_UID" "ADD hot traffic rule" "$kv" >/dev/null
    rules_added=$((rules_added + 1))
  done

  if [[ "$rules_added" -lt "$IPTEST_PERF_TRAFFIC_RULES" ]]; then
    log_info "adding deterministic filler rules (added=$rules_added target=$IPTEST_PERF_TRAFFIC_RULES)..."
  fi

  for ((i = 0; rules_added < IPTEST_PERF_TRAFFIC_RULES; i++)); do
    o3=$(( (i / 254) % 254 + 1 ))
    o4=$(( i % 254 + 1 ))
    dst32="10.${o3}.${o4}.1/32"
    dst24="10.${o3}.${o4}.0/24"
    prio=$((900 - (i % 800)))
    case $((i % 8)) in
      0) kv="action=allow priority=${prio} dir=out proto=tcp dst=${dst32} dport=${IPTEST_PERF_PORT}" ;;
      1) kv="action=allow priority=${prio} dir=out proto=udp dst=${dst32} dport=${IPTEST_PERF_PORT}" ;;
      2) kv="action=allow priority=${prio} dir=in proto=tcp dst=${dst32} dport=${IPTEST_PERF_PORT}" ;;
      3) kv="action=allow priority=${prio} dir=out proto=tcp dst=${dst24} dport=${IPTEST_PERF_PORT}" ;;
      4)
        dport_miss=$(( (IPTEST_PERF_PORT + 1) % 65536 ))
        kv="action=allow priority=${prio} dir=out proto=tcp dst=${IPTEST_PEER_IP}/32 dport=${dport_miss}"
        ;;
      5) kv="action=allow priority=${prio} dir=out proto=any dst=${dst32} dport=${IPTEST_PERF_PORT}" ;;
      6)
        if [[ -n "$veth0_ifindex" ]]; then
          kv="action=allow priority=${prio} dir=out proto=tcp ifindex=$((veth0_ifindex + 1)) dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
        else
          kv="action=allow priority=${prio} dir=out proto=tcp dst=${dst32} dport=${IPTEST_PERF_PORT}"
        fi
        ;;
      7) kv="action=allow priority=${prio} dir=out proto=tcp sport=12345 dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}" ;;
    esac

    out="$(add_rule "$IPTEST_UID" "ADD filler traffic rule i=$i" "$kv")"
    if [[ ! "$out" =~ ^[0-9]+$ ]]; then
      log_fail "ADD filler traffic rule i=$i"
      echo "got: $out"
      exit 5
    fi
    rules_added=$((rules_added + 1))
    if [[ $(( rules_added % 200 )) -eq 0 ]]; then
      log_info "added ${rules_added}/${IPTEST_PERF_TRAFFIC_RULES} traffic rules..."
    fi
  done
}

install_mix_rules() {
  if [[ "$IPTEST_PERF_TRAFFIC_RULES" -le 0 ]]; then
    log_info "traffic rules disabled: running empty-ruleset baseline"
    return 0
  fi

  log_info "adding mixed replay rules (hostIps=${#perf_host_ips[@]} peerIps=${#perf_peer_ips[@]} ports=${#perf_ports[@]})..."

  local host_count="${#perf_host_ips[@]}"
  local peer_count="${#perf_peer_ips[@]}"
  local port_count="${#perf_ports[@]}"
  local miss_prefix="${IPTEST_PEER_IP%.*}"
  local i host_ip peer_ip port hit_prio miss_prio miss_peer_ip miss_host_ip miss_port kv out
  local range_hit_hi range_hit_lo range_miss_hi

  for ((i = 0; rules_added < IPTEST_PERF_TRAFFIC_RULES; i++)); do
    host_ip="${perf_host_ips[$((i % host_count))]}"
    peer_ip="${perf_peer_ips[$(((i / host_count) % peer_count))]}"
    port="${perf_ports[$(((i / (host_count * peer_count)) % port_count))]}"
    hit_prio=$((420 - (i % 160)))
    miss_prio=$((900 - (i % 280)))
    miss_peer_ip="${miss_prefix}.$((200 + (i % 40)))"
    miss_host_ip="${miss_prefix}.$((150 + (i % 40)))"
    miss_port="$((IPTEST_PERF_MIX_PORT_BASE + IPTEST_PERF_MIX_PORT_COUNT + (i % 32)))"

    range_hit_lo=$(( port > IPTEST_PERF_MIX_PORT_BASE ? port - 1 : port ))
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
        if [[ -n "$veth0_ifindex" ]]; then
          kv="action=block log=1 enforce=0 priority=${hit_prio} dir=out proto=tcp ifindex=${veth0_ifindex} dst=${peer_ip}/32 dport=${port}"
        else
          kv="action=block log=1 enforce=0 priority=${miss_prio} dir=out proto=udp dst=${peer_ip}/32 dport=${port}"
        fi
        ;;
    esac

    out="$(add_rule "$IPTEST_UID" "ADD mixed traffic rule i=$i" "$kv")"
    if [[ ! "$out" =~ ^[0-9]+$ ]]; then
      log_fail "ADD mixed traffic rule i=$i"
      echo "got: $out"
      exit 5
    fi
    rules_added=$((rules_added + 1))
    if [[ $(( rules_added % 200 )) -eq 0 ]]; then
      log_info "added ${rules_added}/${IPTEST_PERF_TRAFFIC_RULES} mixed traffic rules..."
    fi
  done
}

if [[ "$IPTEST_PERF_LOAD_MODE" == "mix" ]]; then
  install_mix_rules
else
  install_single_flow_rules
fi

if [[ "$IPTEST_PERF_BG_TOTAL" -gt 0 ]]; then
  log_info "adding background rules..."
  bg_uids="$IPTEST_PERF_BG_UIDS"
  if [[ "$bg_uids" -gt "$IPTEST_PERF_BG_TOTAL" ]]; then
    bg_uids="$IPTEST_PERF_BG_TOTAL"
  fi
  if [[ "$bg_uids" -lt 1 ]]; then
    bg_uids=1
  fi

  for ((j = 0; j < IPTEST_PERF_BG_TOTAL; j++)); do
    uid=$((IPTEST_PERF_BG_UID_BASE + (j % bg_uids)))
    o3=$(( (j / 254) % 254 + 1 ))
    o4=$(( j % 254 + 1 ))
    dst="10.${o3}.${o4}.2/32"
    out="$(send_cmd "IPRULES.ADD ${uid} action=allow priority=1 dir=out proto=tcp dst=${dst} dport=${IPTEST_PERF_PORT}")"
    if [[ ! "$out" =~ ^[0-9]+$ ]]; then
      log_fail "ADD background rule j=$j uid=$uid"
      echo "got: $out"
      exit 7
    fi
    if [[ $(( (j + 1) % 500 )) -eq 0 ]]; then
      log_info "added $((j + 1))/${IPTEST_PERF_BG_TOTAL} background rules..."
    fi
  done
fi

log_info "preflight summary:"
preflight="$(send_cmd "IPRULES.PREFLIGHT")"
echo "$preflight" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get("summary",{}), ensure_ascii=False))'

run_phase() {
  local tag="$1"
  local iprules="$2"

  assert_ok "IPRULES ${iprules}" "IPRULES=${iprules} (${tag})"
  assert_ok "METRICS.PERF.RESET" "METRICS.PERF.RESET (${tag})"

  local bytes_actual=0
  local connections_actual=0

  if [[ "$IPTEST_PERF_SECONDS" -gt 0 ]]; then
    if [[ "$IPTEST_PERF_LOAD_MODE" == "stream" ]]; then
      log_info "tier1 tcp load duration=${IPTEST_PERF_SECONDS}s mode=single-stream (${tag})"
      bytes_actual="$(iptest_tier1_tcp_stream_count_bytes "$IPTEST_PERF_PORT" "$IPTEST_PERF_SECONDS" "$IPTEST_UID" | tr -d '\r\n' || true)"
      if [[ ! "$bytes_actual" =~ ^[0-9]+$ ]]; then
        bytes_actual=0
      fi
    elif [[ "$IPTEST_PERF_LOAD_MODE" == "mix" ]]; then
      log_info "tier1 tcp load duration=${IPTEST_PERF_SECONDS}s mode=mixed-churn workers=${IPTEST_PERF_MIX_WORKERS} connBytes=${IPTEST_PERF_MIX_CONN_BYTES} hostIps=${#perf_host_ips[@]} peerIps=${#perf_peer_ips[@]} ports=${#perf_ports[@]} (${tag})"
      mix_result="$(iptest_tier1_tcp_mix_count_bytes "$IPTEST_PERF_SECONDS" "$IPTEST_UID" "$IPTEST_PERF_MIX_CONN_BYTES" "$IPTEST_PERF_MIX_WORKERS" "$mix_host_ips_csv" "$mix_peer_ips_csv" "$mix_ports_csv" | tr -d '\r' || true)"
      bytes_actual="$(printf '%s\n' "$mix_result" | awk 'NF>=1{print $1}' | tail -n 1)"
      connections_actual="$(printf '%s\n' "$mix_result" | awk 'NF>=2{print $2}' | tail -n 1)"
      if [[ ! "$bytes_actual" =~ ^[0-9]+$ ]]; then
        bytes_actual=0
      fi
      if [[ ! "$connections_actual" =~ ^[0-9]+$ ]]; then
        connections_actual=0
      fi
    else
      log_info "tier1 tcp load duration=${IPTEST_PERF_SECONDS}s mode=chunk chunk=${IPTEST_PERF_CHUNK_BYTES} (${tag})"
      local start end now n i
      start="$(date +%s)"
      end=$((start + IPTEST_PERF_SECONDS))
      i=0
      while :; do
        now="$(date +%s)"
        if [[ "$now" -ge "$end" ]]; then
          break
        fi
        n="$(iptest_tier1_tcp_count_bytes "$IPTEST_PERF_PORT" "$IPTEST_PERF_CHUNK_BYTES" "$IPTEST_UID" | tr -d '\r\n' || true)"
        if [[ "$n" =~ ^[0-9]+$ ]]; then
          bytes_actual=$((bytes_actual + n))
        fi
        i=$((i + 1))
        if [[ $((i % 10)) -eq 0 ]]; then
          log_info "load progress: elapsed=$((now - start))s bytes=${bytes_actual} iters=${i} (${tag})"
        fi
      done
    fi
  else
    log_info "tier1 tcp read bytes=${IPTEST_PERF_BYTES} (${tag})"
    bytes_actual="$(iptest_tier1_tcp_count_bytes "$IPTEST_PERF_PORT" "$IPTEST_PERF_BYTES" "$IPTEST_UID" | tr -d '\r\n' || true)"
    if [[ "$bytes_actual" =~ ^[0-9]+$ ]]; then
      bytes_actual="$bytes_actual"
    else
      bytes_actual=0
    fi
  fi

  if [[ "$bytes_actual" -le 0 ]]; then
    log_fail "traffic must transfer some bytes (${tag})"
    echo "bytes_actual=$bytes_actual"
    exit 6
  fi

  perf_json="$(send_cmd "METRICS.PERF")"
  samples="$(echo "$perf_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(int(d["perf"]["nfq_total_us"]["samples"]))')"
  if [[ ! "$samples" =~ ^[0-9]+$ || "$samples" -le 0 ]]; then
    log_fail "METRICS.PERF must have samples after traffic (${tag})"
    echo "$perf_json"
    exit 6
  fi

  log_info "traffic bytes_actual=${bytes_actual} (${tag})"
  if [[ "$connections_actual" -gt 0 ]]; then
    log_info "traffic connections_actual=${connections_actual} (${tag})"
  fi
  log_info "METRICS.PERF (${tag}):"
  echo "$perf_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d, ensure_ascii=False))'

  PERF_JSON="$perf_json" python3 - "$tag" "$iprules" "$bytes_actual" "$connections_actual" "$preflight" <<'PY'
import json
import os
import sys

tag = sys.argv[1]
iprules = int(sys.argv[2])
bytes_actual = int(sys.argv[3])
connections_actual = int(sys.argv[4])
preflight = json.loads(sys.argv[5])
perf = json.loads(os.environ["PERF_JSON"])["perf"]["nfq_total_us"]

result = {
    "tag": tag,
    "iprules": iprules,
    "bytes": bytes_actual,
    "connections": connections_actual,
    "samples": int(perf["samples"]),
    "latency_us": {
        "min": int(perf["min"]),
        "avg": int(perf["avg"]),
        "p50": int(perf["p50"]),
        "p95": int(perf["p95"]),
        "p99": int(perf["p99"]),
        "max": int(perf["max"]),
    },
    "preflight": preflight.get("summary", {}),
}
print("PERF_RESULT_JSON " + json.dumps(result, ensure_ascii=False, separators=(",", ":")))
PY

  # JSON summary line for log parsing.
  echo "PERF_PHASE_SUMMARY tag=${tag} iprules=${iprules} bytes=${bytes_actual} connections=${connections_actual} samples=${samples}"
  return 0
}

if [[ "$IPTEST_PERF_COMPARE" -eq 1 ]]; then
  log_info "perf compare enabled: iprules=1 vs iprules=0"
  run_phase "iprules_on" 1
  run_phase "iprules_off" 0
  assert_ok "IPRULES 1" "restore IPRULES=1"
  log_pass "perf compare ok"
else
  if [[ "$IPTEST_PERF_SINGLE_IPRULES" != "0" && "$IPTEST_PERF_SINGLE_IPRULES" != "1" ]]; then
    echo "SKIP: IPTEST_PERF_SINGLE_IPRULES must be 0 or 1 (got $IPTEST_PERF_SINGLE_IPRULES)"
    exit 10
  fi
  run_phase "single" "$IPTEST_PERF_SINGLE_IPRULES"
  log_pass "perf ok"
fi
exit 0
