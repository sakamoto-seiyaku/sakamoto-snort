#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$CASE_DIR/../lib.sh"

log_section "ip perf (tier1; vNext-only)"

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
IPTEST_PERF_ENABLE_CT="${IPTEST_PERF_ENABLE_CT:-0}" # 0|1: add a ct consumer rule to force conntrack work

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

is_json() {
  printf '%s\n' "$1" | python3 -c 'import sys,json; json.load(sys.stdin)' >/dev/null 2>&1
}

vnext_rpc_ok() {
  local cmd="$1"
  local args_json="${2:-}"

  set +e
  local out rc
  if [[ -n "$args_json" ]]; then
    out="$(vnext_ctl_cmd "$cmd" "$args_json" 2>/dev/null)"
  else
    out="$(vnext_ctl_cmd "$cmd" 2>/dev/null)"
  fi
  rc=$?
  set -e

  if ! is_json "$out"; then
    echo "BLOCKED: vNext $cmd transport failed (rc=$rc)" >&2
    return 77
  fi
  if [[ $rc -ne 0 ]]; then
    log_fail "vNext $cmd returns ok"
    printf '%s\n' "$out" | head -n 3 | sed 's/^/    /'
    return 1
  fi
  printf '%s\n' "$out"
  return 0
}

enable_perfmetrics() {
  vnext_rpc_ok CONFIG.SET '{"scope":"device","set":{"perfmetrics.enabled":1}}' >/dev/null
}

reset_perf_metrics() {
  vnext_rpc_ok METRICS.RESET '{"name":"perf"}' >/dev/null
}

get_perf_metrics() {
  vnext_rpc_ok METRICS.GET '{"name":"perf"}'
}

set_iprules_enabled() {
  local enabled="$1" # 0|1
  vnext_rpc_ok CONFIG.SET "{\"scope\":\"device\",\"set\":{\"block.enabled\":1,\"iprules.enabled\":${enabled}}}" >/dev/null
}

apply_rules_for_uid() {
  local uid="$1"
  local rules_json="$2" # JSON array
  vnext_rpc_ok IPRULES.APPLY "{\"app\":{\"uid\":${uid}},\"rules\":${rules_json}}" >/dev/null
}

generate_traffic_rules_json() {
  local count="$1"

  IPTEST_PEER_IP="$IPTEST_PEER_IP" \
    IPTEST_HOST_IP="$IPTEST_HOST_IP" \
    IPTEST_NET_CIDR="$IPTEST_NET_CIDR" \
    IPTEST_PERF_PORT="$IPTEST_PERF_PORT" \
    IPTEST_PERF_TRAFFIC_RULES="$count" \
    IPTEST_PERF_ENABLE_CT="$IPTEST_PERF_ENABLE_CT" \
    python3 - <<'PY'
import json
import os

peer = os.environ["IPTEST_PEER_IP"]
host = os.environ["IPTEST_HOST_IP"]
net = os.environ["IPTEST_NET_CIDR"]
port = int(os.environ["IPTEST_PERF_PORT"])
n = int(os.environ["IPTEST_PERF_TRAFFIC_RULES"])
enable_ct = int(os.environ.get("IPTEST_PERF_ENABLE_CT", "0"))


def rule(
    client_id: str,
    *,
    action: str,
    priority: int,
    enabled: int = 1,
    enforce: int = 0,
    log: int = 1,
    dir: str = "out",
    iface: str = "any",
    ifindex: int = 0,
    proto: str = "tcp",
    ct_state: str = "any",
    ct_dir: str = "any",
    src: str = "any",
    dst: str = "any",
    sport: str = "any",
    dport: str = "any",
):
    return {
        "clientRuleId": client_id,
        "action": action,
        "priority": priority,
        "enabled": enabled,
        "enforce": enforce,
        "log": log,
        "dir": dir,
        "iface": iface,
        "ifindex": ifindex,
        "proto": proto,
        "ct": {"state": ct_state, "direction": ct_dir},
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
    }


rules: list[dict] = []

if enable_ct == 1 and n > 0:
    # A ct consumer rule forces conntrack work on the datapath (even if it never matches).
    rules.append(
        rule(
            "perf:ct-consumer",
            action="allow",
            priority=1,
            enabled=1,
            enforce=0,
            log=0,
            dir="any",
            proto="tcp",
            ct_state="invalid",
            ct_dir="any",
            src="any",
            dst="any",
            sport="any",
            dport="any",
        )
    )

if n > 0:
    # One deterministic hot rule that matches the actual workload.
    rules.append(
        rule(
            "perf:hit",
            action="allow",
            priority=1000,
            enabled=1,
            enforce=1,
            log=0,
            dir="out",
            proto="tcp",
            ct_state="any",
            ct_dir="any",
            src=f"{host}/32",
            dst=f"{peer}/32",
            sport="any",
            dport=str(port),
        )
    )

idx = 0
while len(rules) < n:
    i = idx
    idx += 1
    o3 = (i // 254) % 254 + 1
    o4 = i % 254 + 1

    dst32 = f"10.{o3}.{o4}.1/32"
    dst24 = f"10.{o3}.{o4}.0/24"
    prio = 900 - (i % 800)

    mod = i % 8
    if mod == 0:
        rules.append(rule(f"perf:r{i}", action="block", priority=prio, proto="tcp", dst=dst32, dport=str(port)))
    elif mod == 1:
        rules.append(rule(f"perf:r{i}", action="block", priority=prio, proto="udp", dst=dst32, dport=str(port)))
    elif mod == 2:
        rules.append(rule(f"perf:r{i}", action="block", priority=prio, dir="any", proto="tcp", dst=dst32, dport=str(port)))
    elif mod == 3:
        rules.append(rule(f"perf:r{i}", action="block", priority=prio, proto="tcp", dst=dst24, dport=str(port)))
    elif mod == 4:
        # Keep matchKeys unique: derive a per-rule miss port from i.
        miss = 1024 + ((port + i) % 64511)  # 1024..65534
        if miss == port:
            miss = 1024 + ((miss + 1) % 64511)
        rules.append(rule(f"perf:r{i}", action="block", priority=prio, proto="tcp", dst=f"{peer}/32", dport=str(miss)))
    elif mod == 5:
        rules.append(rule(f"perf:r{i}", action="block", priority=prio, proto="any", dst=dst32, dport=str(port)))
    elif mod == 6:
        # Keep matchKeys unique: use src=dst32 as a stable per-rule differentiator.
        rules.append(rule(f"perf:r{i}", action="block", priority=prio, proto="tcp", src=dst32, dst=net, dport=str(port)))
    elif mod == 7:
        # Keep matchKeys unique: derive per-rule source port from i.
        sport = str(20000 + i)
        rules.append(rule(f"perf:r{i}", action="block", priority=prio, proto="tcp", sport=sport, dst=f"{peer}/32", dport=str(port)))

print(json.dumps(rules, ensure_ascii=False, separators=(",", ":")))
PY
}

generate_background_rules_json() {
  local uid="$1"
  local count="$2"
  local seed="$3"

  IPTEST_PERF_PORT="$IPTEST_PERF_PORT" BG_UID="$uid" BG_COUNT="$count" BG_SEED="$seed" python3 - <<'PY'
import json
import os

port = int(os.environ["IPTEST_PERF_PORT"])
uid = int(os.environ["BG_UID"])
n = int(os.environ["BG_COUNT"])
seed = int(os.environ["BG_SEED"])

rules = []
for i in range(n):
    j = seed + i
    o3 = (j // 254) % 254 + 1
    o4 = j % 254 + 1
    dst = f"10.{o3}.{o4}.2/32"
    rules.append(
        {
            "clientRuleId": f"bg:{uid}:{i}",
            "action": "allow",
            "priority": 1,
            "enabled": 1,
            "enforce": 1,
            "log": 0,
            "dir": "out",
            "iface": "any",
            "ifindex": 0,
            "proto": "tcp",
            "ct": {"state": "any", "direction": "any"},
            "src": "any",
            "dst": dst,
            "sport": "any",
            "dport": str(port),
        }
    )

print(json.dumps(rules, ensure_ascii=False, separators=(",", ":")))
PY
}

run_phase() {
  local tag="$1"
  local iprules="$2" # 0|1
  local preflight_summary_json="$3"

  set_iprules_enabled "$iprules" || return $?
  reset_perf_metrics || return $?

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
    if [[ ! "$bytes_actual" =~ ^[0-9]+$ ]]; then
      bytes_actual=0
    fi
  fi

  if [[ "$bytes_actual" -le 0 ]]; then
    echo "SKIP: tier1 tcp traffic unavailable (tag=${tag} uid=$IPTEST_UID bytes_actual=$bytes_actual); try setting IPTEST_APP_UID to a network-capable app uid"
    return 10
  fi

  perf_json="$(get_perf_metrics)" || return $?
  samples="$(vnext_json_get "$perf_json" "result.perf.nfq_total_us.samples" | tr -d '\r\n' || true)"
  if [[ ! "$samples" =~ ^[0-9]+$ || "$samples" -le 0 ]]; then
    log_fail "METRICS.GET(perf) must have samples after traffic (${tag})"
    echo "$perf_json" | head -c 500 || true
    return 6
  fi

  log_info "traffic bytes_actual=${bytes_actual} (${tag})"
  if [[ "$connections_actual" -gt 0 ]]; then
    log_info "traffic connections_actual=${connections_actual} (${tag})"
  fi
  log_info "METRICS.GET(perf) (${tag}):"
  echo "$perf_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps(d, ensure_ascii=False))'

  PERF_JSON="$perf_json" PREFLIGHT_SUMMARY="$preflight_summary_json" python3 - "$tag" "$iprules" "$bytes_actual" "$connections_actual" <<'PY'
import json
import os
import sys

tag = sys.argv[1]
iprules = int(sys.argv[2])
bytes_actual = int(sys.argv[3])
connections_actual = int(sys.argv[4])

preflight = json.loads(os.environ["PREFLIGHT_SUMMARY"])
perf = json.loads(os.environ["PERF_JSON"])["result"]["perf"]["nfq_total_us"]

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
    "preflight": preflight,
}
print("PERF_RESULT_JSON " + json.dumps(result, ensure_ascii=False, separators=(",", ":")))
PY

  echo "PERF_PHASE_SUMMARY tag=${tag} iprules=${iprules} bytes=${bytes_actual} connections=${connections_actual} samples=${samples}"
  return 0
}

main() {
  if ! vnext_preflight; then
    exit 77
  fi

  if ! iptest_require_tier1_prereqs; then
    echo "SKIP: tier1 prereqs missing (need root + ip/netns/veth + ping + nc)"
    exit 10
  fi

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

  table=""
  cleanup() {
    if [[ -n "$table" ]]; then
      iptest_tier1_teardown "$table" || true
    fi
  }
  trap cleanup EXIT

  table="$(iptest_tier1_setup)" || exit $?

  iptest_reset_baseline

  enable_perfmetrics || exit $?
  reset_perf_metrics || exit $?

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

  log_info "install rules via IPRULES.APPLY: trafficUid=$IPTEST_UID trafficRules=$IPTEST_PERF_TRAFFIC_RULES backgroundTotal=$IPTEST_PERF_BG_TOTAL"

  total_rules=$((IPTEST_PERF_TRAFFIC_RULES + IPTEST_PERF_BG_TOTAL))
  if [[ "$total_rules" -gt 5000 ]]; then
    echo "SKIP: total active rules exceed hard limit (total=$total_rules > 5000)"
    exit 10
  fi
  if [[ "$IPTEST_PERF_TRAFFIC_RULES" -lt 0 ]]; then
    echo "SKIP: IPTEST_PERF_TRAFFIC_RULES must be >= 0 (got $IPTEST_PERF_TRAFFIC_RULES)"
    exit 10
  fi

  traffic_rules_json="$(generate_traffic_rules_json "$IPTEST_PERF_TRAFFIC_RULES")"
  apply_rules_for_uid "$IPTEST_UID" "$traffic_rules_json" || exit $?

  if [[ "$IPTEST_PERF_BG_TOTAL" -gt 0 ]]; then
    log_info "adding background rules..."
    bg_uids="$IPTEST_PERF_BG_UIDS"
    if [[ "$bg_uids" -gt "$IPTEST_PERF_BG_TOTAL" ]]; then
      bg_uids="$IPTEST_PERF_BG_TOTAL"
    fi
    if [[ "$bg_uids" -lt 1 ]]; then
      bg_uids=1
    fi

    declare -A bg_counts=()
    for ((j = 0; j < IPTEST_PERF_BG_TOTAL; j++)); do
      uid=$((IPTEST_PERF_BG_UID_BASE + (j % bg_uids)))
      bg_counts["$uid"]=$(( ${bg_counts["$uid"]:-0} + 1 ))
    done

    seed=0
    for uid in "${!bg_counts[@]}"; do
      n="${bg_counts["$uid"]}"
      rules_json="$(generate_background_rules_json "$uid" "$n" "$seed")"
      seed=$((seed + n))
      apply_rules_for_uid "$uid" "$rules_json" || exit $?
    done
  fi

  preflight="$(vnext_rpc_ok IPRULES.PREFLIGHT)" || exit $?
  preflight_summary="$(printf '%s\n' "$preflight" | python3 -c 'import json,sys; j=json.load(sys.stdin); print(json.dumps(j.get("result",{}).get("summary",{}), ensure_ascii=False, separators=(",",":")))' 2>/dev/null || echo '{}')"
  log_info "preflight summary: $preflight_summary"

  if [[ "$IPTEST_PERF_COMPARE" -eq 1 ]]; then
    log_info "perf compare enabled: iprules=1 vs iprules=0"
    run_phase "iprules_on" 1 "$preflight_summary"
    run_phase "iprules_off" 0 "$preflight_summary"
    set_iprules_enabled 1 || exit $?
    log_pass "perf compare ok"
  else
    if [[ "$IPTEST_PERF_SINGLE_IPRULES" != "0" && "$IPTEST_PERF_SINGLE_IPRULES" != "1" ]]; then
      echo "SKIP: IPTEST_PERF_SINGLE_IPRULES must be 0 or 1 (got $IPTEST_PERF_SINGLE_IPRULES)"
      exit 10
    fi
    run_phase "single" "$IPTEST_PERF_SINGLE_IPRULES" "$preflight_summary"
    log_pass "perf ok"
  fi

  exit 0
}

main "$@"
