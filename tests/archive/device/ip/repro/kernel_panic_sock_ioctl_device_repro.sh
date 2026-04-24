#!/system/bin/sh

# Device-side reproducer for kernel panic observed in docs/testing/ip/BUG_kernel_panic_sock_ioctl.md
# Goal: run the same perf duration workflow on-device and persist step markers to /data/local/tmp.

set -e

umask 022

LOG_DIR="${LOG_DIR:-/data/local/tmp/iptest_panic_repro}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/run_${RUN_ID}.log}"
STEP_FILE="${STEP_FILE:-$LOG_DIR/last_step.txt}"

REPRO_MODE="${REPRO_MODE:-full}" # full|net_only
SKIP_RULES="${SKIP_RULES:-0}"

SNORT_SOCKET="${SNORT_SOCKET:-/dev/socket/sucre-snort-control}"
SNORT_BIN="${SNORT_BIN:-/data/local/tmp/sucre-snort-dev}"
SNORT_PROC_NAME="${SNORT_PROC_NAME:-sucre-snort-dev}"
STOP_SNORT="${STOP_SNORT:-0}"

IPTEST_NS="${IPTEST_NS:-iptest_ns}"
IPTEST_VETH0="${IPTEST_VETH0:-iptest_veth0}"
IPTEST_VETH1="${IPTEST_VETH1:-iptest_veth1}"

IPTEST_NET_CIDR="${IPTEST_NET_CIDR:-10.200.1.0/24}"
IPTEST_HOST_IP="${IPTEST_HOST_IP:-10.200.1.1}"
IPTEST_PEER_IP="${IPTEST_PEER_IP:-10.200.1.2}"

IPTEST_UID="${IPTEST_UID:-2000}"

IPTEST_PERF_PORT="${IPTEST_PERF_PORT:-18080}"
SERVER_MODE="${SERVER_MODE:-sh_cat_zero}" # sh_cat_zero|cat_zero
IPTEST_PERF_SECONDS="${IPTEST_PERF_SECONDS:-180}"
IPTEST_PERF_CHUNK_BYTES="${IPTEST_PERF_CHUNK_BYTES:-2000000}"
IPTEST_PERF_COMPARE="${IPTEST_PERF_COMPARE:-1}"

IPTEST_PERF_TRAFFIC_RULES="${IPTEST_PERF_TRAFFIC_RULES:-2000}"
IPTEST_PERF_BG_TOTAL="${IPTEST_PERF_BG_TOTAL:-2000}"
IPTEST_PERF_BG_UIDS="${IPTEST_PERF_BG_UIDS:-200}"
IPTEST_PERF_BG_UID_BASE="${IPTEST_PERF_BG_UID_BASE:-10000}"

LOAD_WRAPPER="${LOAD_WRAPPER:-su_sh}"        # su_sh|sh|direct
LOAD_MODE="${LOAD_MODE:-head_wc}"            # head_wc|head_only|head1_only|connect_q0|timeout_raw_read|sleep_only
LOAD_HEAD_BYTES="${LOAD_HEAD_BYTES:-$IPTEST_PERF_CHUNK_BYTES}"
LOAD_TIMEOUT_SECONDS="${LOAD_TIMEOUT_SECONDS:-1}" # for timeout_raw_read
LOAD_MAX_ITERS="${LOAD_MAX_ITERS:-0}"             # 0 means no limit (time only)
LOG_SYNC_EVERY="${LOG_SYNC_EVERY:-1}"             # 1 means sync every iter marker write

mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR/latest.log" "$LOG_DIR/latest_step.txt" 2>/dev/null || true
ln -s "$LOG_FILE" "$LOG_DIR/latest.log" 2>/dev/null || true
ln -s "$STEP_FILE" "$LOG_DIR/latest_step.txt" 2>/dev/null || true

exec >>"$LOG_FILE" 2>&1

step_n=0
log() {
  # shellcheck disable=SC2039
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

mark_step() {
  step_n=$((step_n + 1))
  echo "STEP ${step_n}: $*" >"$STEP_FILE"
  sync
  log "===== STEP ${step_n}: $* ====="
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "FATAL: missing command: $1"
    exit 2
  fi
}

send_cmd() {
  cmd="$1"
  # Send a single command per connection.
  # Note: the control server itself appends a trailing NUL on responses; we
  # do not need to send a NUL terminator here as long as we send exactly one
  # command and close stdin (netcat will shutdown write side on EOF).
  printf '%s' "$cmd" | nc -U -W 2 "$SNORT_SOCKET" | tr -d '\000'
}

send_cmd_expect_ok() {
  cmd="$1"
  out="$(send_cmd "$cmd")"
  log "CMD: $cmd"
  log "OUT: $out"
  if [ "$out" != "OK" ]; then
    log "FATAL: expected OK, got: $out"
    exit 3
  fi
}

start_daemon_if_needed() {
  if [ -S "$SNORT_SOCKET" ]; then
    return 0
  fi

mark_step "daemon socket missing; start daemon"

if [ ! -x "$SNORT_BIN" ]; then
    log "FATAL: snort binary not found/executable: $SNORT_BIN"
    exit 4
  fi

  # Start daemon and wait for socket to appear.
  "$SNORT_BIN" >>/data/local/tmp/sucre-snort-dev.log 2>&1 &
  daemon_pid=$!
  log "daemon pid=$daemon_pid"

  i=0
  while [ $i -lt 30 ]; do
    if [ -S "$SNORT_SOCKET" ]; then
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done

  log "FATAL: daemon socket still missing after start"
  exit 5
}

stop_snort_if_requested() {
  if [ "$STOP_SNORT" -ne 1 ] 2>/dev/null; then
    return 0
  fi
  mark_step "stop snort requested"
  if command -v pidof >/dev/null 2>&1; then
    pids="$(pidof "$SNORT_PROC_NAME" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      log "killing $SNORT_PROC_NAME pids=$pids"
      kill -9 $pids 2>/dev/null || true
      sleep 1
    fi
  fi
  rm -f "$SNORT_SOCKET" 2>/dev/null || true
}

teardown() {
  # Best-effort cleanup.
  if ip netns list 2>/dev/null | grep -q "^${IPTEST_NS}\$"; then
    pids="$(ip netns pids "$IPTEST_NS" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
      kill -9 $pids 2>/dev/null || true
    fi
  fi
  ip route del "$IPTEST_NET_CIDR" dev "$IPTEST_VETH0" table "$client_table" >/dev/null 2>&1 || true
  ip link del "$IPTEST_VETH0" >/dev/null 2>&1 || true
  ip netns del "$IPTEST_NS" >/dev/null 2>&1 || true
}

mark_step "start"
log "run_id=$RUN_ID"
log "id=$(id)"
log "uname=$(uname -a)"
log "fingerprint=$(getprop ro.build.fingerprint 2>/dev/null || true)"
log "kernel_version=$(cat /proc/version 2>/dev/null || true)"

mark_step "prereq check"
need_cmd ip
need_cmd nc
need_cmd cat
need_cmd ping
need_cmd timeout
need_cmd head
need_cmd wc

stop_snort_if_requested

if [ "$REPRO_MODE" = "full" ]; then
  start_daemon_if_needed
fi

mark_step "control HELLO"
if [ "$REPRO_MODE" = "full" ]; then
  out="$(send_cmd "HELLO" || true)"
  log "HELLO: $out"
else
  log "HELLO: (skipped, REPRO_MODE=$REPRO_MODE)"
fi

mark_step "detect route table for uid=$IPTEST_UID"
client_table="$(ip route get "$IPTEST_PEER_IP" uid "$IPTEST_UID" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="table") {print $(i+1); exit}}')"
if [ -z "$client_table" ]; then
  client_table="main"
fi
log "client_table=$client_table"

mark_step "tier1 netns+veth setup"
teardown || true

ip netns add "$IPTEST_NS"
ip link add "$IPTEST_VETH0" type veth peer name "$IPTEST_VETH1"
ip link set "$IPTEST_VETH1" netns "$IPTEST_NS"
ip addr add "${IPTEST_HOST_IP}/24" dev "$IPTEST_VETH0"
ip link set "$IPTEST_VETH0" up
ip -n "$IPTEST_NS" addr add "${IPTEST_PEER_IP}/24" dev "$IPTEST_VETH1"
ip -n "$IPTEST_NS" link set "$IPTEST_VETH1" up
ip -n "$IPTEST_NS" link set lo up
ip route add "$IPTEST_NET_CIDR" dev "$IPTEST_VETH0" table "$client_table" 2>/dev/null || true

mark_step "verify uid route injection"
verify="$(ip route get "$IPTEST_PEER_IP" uid "$IPTEST_UID" 2>/dev/null || true)"
log "route_get: $verify"
echo "$verify" | grep -q "dev $IPTEST_VETH0" || {
  log "FATAL: route injection not effective (expect dev=$IPTEST_VETH0)"
  exit 6
}

trap teardown EXIT

mark_step "baseline reset"
if [ "$REPRO_MODE" = "full" ]; then
  send_cmd_expect_ok "RESETALL"
  send_cmd_expect_ok "BLOCK 1"
  send_cmd_expect_ok "BLOCKIPLEAKS 0"
  send_cmd_expect_ok "IPRULES 1"
  send_cmd_expect_ok "BLOCKIFACE ${IPTEST_UID} 0"
  send_cmd_expect_ok "PERFMETRICS 1"
  send_cmd_expect_ok "METRICS.PERF.RESET"
else
  log "baseline reset: (skipped, REPRO_MODE=$REPRO_MODE)"
fi

mark_step "start tier1 tcp zero server (mode=$SERVER_MODE)"
case "$SERVER_MODE" in
  sh_cat_zero)
    server_cmd="nc -p \"$IPTEST_PERF_PORT\" -L sh -c \"cat /dev/zero\""
    ;;
  cat_zero)
    server_cmd="nc -p \"$IPTEST_PERF_PORT\" -L cat /dev/zero"
    ;;
  *)
    log "FATAL: unsupported SERVER_MODE=$SERVER_MODE"
    exit 9
    ;;
esac
log "server_cmd=$server_cmd"
server_pid="$(ip netns exec "$IPTEST_NS" sh -c "$server_cmd >/dev/null 2>&1 & echo \$!")"
log "server_pid=$server_pid port=$IPTEST_PERF_PORT mode=$SERVER_MODE"

mark_step "read veth0 ifindex"
veth0_ifindex="$(ip link show dev "$IPTEST_VETH0" 2>/dev/null | awk -F':' 'NR==1{gsub(/ /,"",$1); print $1}')"
log "veth0_ifindex=$veth0_ifindex"

mark_step "install traffic rules (N=$IPTEST_PERF_TRAFFIC_RULES)"
if [ "$REPRO_MODE" = "full" ] && [ "$SKIP_RULES" -ne 1 ] 2>/dev/null; then
  rules_added=0

  rid_hit="$(send_cmd "IPRULES.ADD ${IPTEST_UID} action=allow priority=1000 dir=out proto=tcp dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}")"
  log "rid_hit=$rid_hit"
  rules_added=$((rules_added + 1))

  add_rule() {
    uid="$1"
    kv="$2"
    send_cmd "IPRULES.ADD ${uid} ${kv}"
  }

	  # Deterministic "hot" rules (mirror tests/device/ip/cases/60_perf.sh)
	  hot_kv_1="action=allow priority=1000 dir=any proto=tcp dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
  hot_kv_2="action=allow priority=1000 dir=out proto=any dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
  hot_kv_3="action=allow priority=1000 dir=out proto=tcp dst=${IPTEST_NET_CIDR} dport=${IPTEST_PERF_PORT}"
  hot_kv_4="action=allow priority=1000 dir=out proto=tcp dst=any dport=${IPTEST_PERF_PORT}"
  hot_kv_5="action=allow priority=1000 dir=out proto=tcp dst=${IPTEST_PEER_IP}/32 dport=any"
  hot_kv_6="action=allow priority=1000 dir=out proto=tcp src=${IPTEST_HOST_IP}/32 dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
  hot_kv_7="action=allow priority=1000 dir=out proto=tcp ifindex=${veth0_ifindex} dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"

  for kv in "$hot_kv_1" "$hot_kv_2" "$hot_kv_3" "$hot_kv_4" "$hot_kv_5" "$hot_kv_6"; do
    if [ "$rules_added" -ge "$IPTEST_PERF_TRAFFIC_RULES" ]; then
      break
    fi
    out="$(add_rule "$IPTEST_UID" "$kv")"
    log "rule[hot] rid=$out kv=$kv"
    rules_added=$((rules_added + 1))
  done

  if [ -n "$veth0_ifindex" ] && [ "$rules_added" -lt "$IPTEST_PERF_TRAFFIC_RULES" ]; then
    out="$(add_rule "$IPTEST_UID" "$hot_kv_7")"
    log "rule[hot] rid=$out kv=$hot_kv_7"
    rules_added=$((rules_added + 1))
  fi

  i=0
  while [ "$rules_added" -lt "$IPTEST_PERF_TRAFFIC_RULES" ]; do
    o3=$(( (i / 254) % 254 + 1 ))
    o4=$(( i % 254 + 1 ))
    dst32="10.${o3}.${o4}.1/32"
    dst24="10.${o3}.${o4}.0/24"
    prio=$((900 - (i % 800)))
    mod=$((i % 8))

    if [ "$mod" -eq 0 ]; then
      kv="action=allow priority=${prio} dir=out proto=tcp dst=${dst32} dport=${IPTEST_PERF_PORT}"
    elif [ "$mod" -eq 1 ]; then
      kv="action=allow priority=${prio} dir=out proto=udp dst=${dst32} dport=${IPTEST_PERF_PORT}"
    elif [ "$mod" -eq 2 ]; then
      kv="action=allow priority=${prio} dir=in proto=tcp dst=${dst32} dport=${IPTEST_PERF_PORT}"
    elif [ "$mod" -eq 3 ]; then
      kv="action=allow priority=${prio} dir=out proto=tcp dst=${dst24} dport=${IPTEST_PERF_PORT}"
    elif [ "$mod" -eq 4 ]; then
      dport_miss=$(( (IPTEST_PERF_PORT + 1) % 65536 ))
      kv="action=allow priority=${prio} dir=out proto=tcp dst=${IPTEST_PEER_IP}/32 dport=${dport_miss}"
    elif [ "$mod" -eq 5 ]; then
      kv="action=allow priority=${prio} dir=out proto=any dst=${dst32} dport=${IPTEST_PERF_PORT}"
    elif [ "$mod" -eq 6 ]; then
      if [ -n "$veth0_ifindex" ]; then
        kv="action=allow priority=${prio} dir=out proto=tcp ifindex=$((veth0_ifindex + 1)) dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
      else
        kv="action=allow priority=${prio} dir=out proto=tcp dst=${dst32} dport=${IPTEST_PERF_PORT}"
      fi
    else
      kv="action=allow priority=${prio} dir=out proto=tcp sport=12345 dst=${IPTEST_PEER_IP}/32 dport=${IPTEST_PERF_PORT}"
    fi

    out="$(add_rule "$IPTEST_UID" "$kv")"
    rules_added=$((rules_added + 1))
    if [ $((rules_added % 200)) -eq 0 ]; then
      log "traffic rules progress: added=${rules_added}/${IPTEST_PERF_TRAFFIC_RULES} last_rid=$out"
      sync
    fi
    i=$((i + 1))
  done
else
  log "traffic rules: (skipped, REPRO_MODE=$REPRO_MODE SKIP_RULES=$SKIP_RULES)"
fi

mark_step "install background rules (N=$IPTEST_PERF_BG_TOTAL, uids=$IPTEST_PERF_BG_UIDS)"
if [ "$REPRO_MODE" = "full" ] && [ "$SKIP_RULES" -ne 1 ] 2>/dev/null; then
  j=0
  while [ "$j" -lt "$IPTEST_PERF_BG_TOTAL" ]; do
    uid=$((IPTEST_PERF_BG_UID_BASE + (j % IPTEST_PERF_BG_UIDS)))
    o3=$(( (j / 254) % 254 + 1 ))
    o4=$(( j % 254 + 1 ))
    dst="10.${o3}.${o4}.2/32"
    out="$(send_cmd "IPRULES.ADD ${uid} action=allow priority=1 dir=out proto=tcp dst=${dst} dport=${IPTEST_PERF_PORT}")"
    j=$((j + 1))
    if [ $((j % 500)) -eq 0 ]; then
      log "background rules progress: added=${j}/${IPTEST_PERF_BG_TOTAL} last_rid=$out"
      sync
    fi
  done
else
  log "background rules: (skipped, REPRO_MODE=$REPRO_MODE SKIP_RULES=$SKIP_RULES)"
fi

mark_step "preflight summary"
if [ "$REPRO_MODE" = "full" ] && [ "$SKIP_RULES" -ne 1 ] 2>/dev/null; then
  preflight="$(send_cmd "IPRULES.PREFLIGHT")"
  log "PREFLIGHT: $preflight"
else
  log "PREFLIGHT: (skipped, REPRO_MODE=$REPRO_MODE SKIP_RULES=$SKIP_RULES)"
fi

write_iter_marker() {
  iter="$1"
  phase="$2"
  bytes="$3"
  rc="$4"

  echo "iter=${iter} phase=${phase} mode=${LOAD_MODE} wrapper=${LOAD_WRAPPER} bytes=${bytes} rc=${rc}" >"$LOG_DIR/last_iter.txt"
  echo "wrapper=${LOAD_WRAPPER}" >"$LOG_DIR/last_cmd.txt"
  echo "mode=${LOAD_MODE}" >>"$LOG_DIR/last_cmd.txt"
  echo "cmd=${load_cmd}" >>"$LOG_DIR/last_cmd.txt"
  if [ "$LOG_SYNC_EVERY" -eq 1 ] 2>/dev/null; then
    sync
  fi
}

run_wrapped_load_cmd() {
  cmd="$1"
  case "$LOAD_WRAPPER" in
    su_sh)
      su "$IPTEST_UID" sh -c "$cmd"
      ;;
    sh)
      sh -c "$cmd"
      ;;
    direct)
      case "$LOAD_MODE" in
        connect_q0)
          nc -n -w 5 -q 0 "$IPTEST_PEER_IP" "$IPTEST_PERF_PORT" </dev/null
          ;;
        timeout_raw_read)
          timeout "$LOAD_TIMEOUT_SECONDS" nc -n -w 5 "$IPTEST_PEER_IP" "$IPTEST_PERF_PORT" >/dev/null 2>&1
          ;;
        sleep_only)
          sleep "$LOAD_TIMEOUT_SECONDS"
          ;;
        *)
          log "FATAL: LOAD_WRAPPER=direct only supports LOAD_MODE=connect_q0|timeout_raw_read|sleep_only"
          exit 7
          ;;
      esac
      ;;
    *)
      log "FATAL: unsupported LOAD_WRAPPER=$LOAD_WRAPPER"
      exit 7
      ;;
  esac
}

run_phase() {
  tag="$1"
  iprules="$2"

  mark_step "phase ${tag}: set IPRULES=${iprules} + METRICS.PERF.RESET"
  if [ "$REPRO_MODE" = "full" ]; then
    send_cmd_expect_ok "IPRULES ${iprules}"
    send_cmd_expect_ok "METRICS.PERF.RESET"
  else
    log "IPRULES/METRICS reset: (skipped, REPRO_MODE=$REPRO_MODE)"
  fi

  mark_step "phase ${tag}: duration load start (seconds=$IPTEST_PERF_SECONDS chunk=$IPTEST_PERF_CHUNK_BYTES)"
  start="$(date +%s)"
  end=$((start + IPTEST_PERF_SECONDS))
  bytes_actual=0
  iter=0

  log "load config: mode=$LOAD_MODE wrapper=$LOAD_WRAPPER head_bytes=$LOAD_HEAD_BYTES timeout_seconds=$LOAD_TIMEOUT_SECONDS max_iters=$LOAD_MAX_ITERS"

  while :; do
    now="$(date +%s)"
    if [ "$now" -ge "$end" ]; then
      break
    fi
    if [ "$LOAD_MAX_ITERS" -gt 0 ] 2>/dev/null && [ "$iter" -ge "$LOAD_MAX_ITERS" ]; then
      break
    fi

    iter=$((iter + 1))

    case "$LOAD_MODE" in
      sleep_only)
        load_cmd="sleep \"$LOAD_TIMEOUT_SECONDS\""
        n="0"
        ;;
      connect_q0)
        # Connect and immediately quit after EOF on stdin. No read.
        load_cmd="nc -n -w 5 -q 0 \"$IPTEST_PEER_IP\" \"$IPTEST_PERF_PORT\" </dev/null >/dev/null 2>&1 || true"
        n="0"
        ;;
      head_only)
        load_cmd="nc -n -w 5 \"$IPTEST_PEER_IP\" \"$IPTEST_PERF_PORT\" | head -c \"$LOAD_HEAD_BYTES\" >/dev/null 2>&1 || true"
        n="$LOAD_HEAD_BYTES"
        ;;
      head1_only)
        load_cmd="nc -n -w 5 \"$IPTEST_PEER_IP\" \"$IPTEST_PERF_PORT\" | head -c 1 >/dev/null 2>&1 || true"
        n="1"
        ;;
      timeout_raw_read)
        load_cmd="timeout \"$LOAD_TIMEOUT_SECONDS\" nc -n -w 5 \"$IPTEST_PEER_IP\" \"$IPTEST_PERF_PORT\" </dev/null >/dev/null 2>&1 || true"
        n="0"
        ;;
      head_wc)
        # Mirror original host-side pipeline:
        #   su <uid> sh -c 'nc -n -w 5 <peer> <port> | head -c <bytes> | wc -c'
        load_cmd="nc -n -w 5 \"$IPTEST_PEER_IP\" \"$IPTEST_PERF_PORT\" | head -c \"$LOAD_HEAD_BYTES\" | wc -c 2>/dev/null || true"
        n=""
        ;;
      *)
        log "FATAL: unsupported LOAD_MODE=$LOAD_MODE"
        exit 8
        ;;
    esac

    # Persist marker *before* running, so a crash inside the command leaves the iter visible.
    write_iter_marker "$iter" "$tag" "-" "-"

    if [ "$LOAD_MODE" = "head_wc" ]; then
      out="$(run_wrapped_load_cmd "$load_cmd" | tr -d '\r\n' || true)"
      rc=$?
      n="$out"
    else
      run_wrapped_load_cmd "$load_cmd" >/dev/null 2>&1 || true
      rc=$?
    fi

    write_iter_marker "$iter" "$tag" "$n" "$rc"

    case "$n" in
      ''|*[!0-9]*)
        n=0
        ;;
    esac
    bytes_actual=$((bytes_actual + n))

    if [ $((iter % 10)) -eq 0 ]; then
      log "LOAD ${tag}: elapsed=$((now - start))s iter=${iter} bytes=${bytes_actual}"
      echo "LOAD ${tag}: iter=${iter} bytes=${bytes_actual}" >"$LOG_DIR/last_load.txt"
      sync
    fi
  done

  mark_step "phase ${tag}: collect METRICS.PERF"
  if [ "$REPRO_MODE" = "full" ]; then
    perf="$(send_cmd "METRICS.PERF")"
    log "METRICS.PERF: $perf"
  else
    log "METRICS.PERF: (skipped, REPRO_MODE=$REPRO_MODE)"
  fi
  log "PHASE_DONE ${tag}: bytes=${bytes_actual} iter=${iter}"
  sync
}

if [ "$IPTEST_PERF_COMPARE" -eq 1 ] 2>/dev/null; then
  mark_step "perf compare enabled: iprules=1 then iprules=0"
  run_phase "iprules_on" 1
  run_phase "iprules_off" 0
  if [ "$REPRO_MODE" = "full" ]; then
    send_cmd_expect_ok "IPRULES 1"
  fi
else
  mark_step "perf single phase"
  run_phase "single" 1
fi

mark_step "done"
log "DONE"
exit 0
