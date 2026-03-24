#!/bin/bash

set -euo pipefail

IPMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$IPMOD_DIR/../../.." && pwd)"

source "$SNORT_ROOT/tests/integration/lib.sh"

# Device-modules do their own per-case aggregation in the runner. Avoid
# integration lib's global counters (which are not set -e safe).
log_pass() { echo -e "${GREEN}✓${NC} $1"; }
log_fail() { echo -e "${RED}✗${NC} $1"; }
log_skip() { echo -e "${YELLOW}⊘${NC} $1"; }

# -----------------------------------------------------------------------------
# Common expectations (device-module friendly)
# -----------------------------------------------------------------------------

expect_ok() {
  local cmd="$1"
  local desc="$2"
  local result status

  set +e
  result="$(send_cmd "$cmd")"
  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_fail "$desc"
    echo "    cmd: $cmd"
    echo "    got: $result"
    return 1
  fi

  if [[ "$result" == "OK" ]]; then
    log_pass "$desc"
    return 0
  fi

  log_fail "$desc"
  echo "    cmd: $cmd"
  echo "    got: $result"
  return 1
}

expect_nok() {
  local cmd="$1"
  local desc="$2"
  local result status

  set +e
  result="$(send_cmd "$cmd")"
  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_fail "$desc"
    echo "    cmd: $cmd"
    echo "    got: $result"
    return 1
  fi

  if [[ "$result" == "NOK" ]]; then
    log_pass "$desc"
    return 0
  fi

  log_fail "$desc"
  echo "    cmd: $cmd"
  echo "    got: $result"
  return 1
}

expect_uint() {
  local cmd="$1"
  local desc="$2"
  local result status

  set +e
  result="$(send_cmd "$cmd")"
  status=$?
  set -e

  if [[ $status -ne 0 ]]; then
    log_fail "$desc" >&2
    echo "    cmd: $cmd" >&2
    echo "    got: $result" >&2
    return 1
  fi

  if [[ "$result" =~ ^[0-9]+$ ]]; then
    log_pass "$desc (value=$result)" >&2
    echo "$result"
    return 0
  fi

  log_fail "$desc" >&2
  echo "    cmd: $cmd" >&2
  echo "    got: $result" >&2
  return 1
}

IPTEST_NS="${IPTEST_NS:-iptest_ns}"
IPTEST_VETH0="${IPTEST_VETH0:-iptest_veth0}"
IPTEST_VETH1="${IPTEST_VETH1:-iptest_veth1}"

IPTEST_NET_CIDR="${IPTEST_NET_CIDR:-10.200.1.0/24}"
IPTEST_HOST_IP="${IPTEST_HOST_IP:-10.200.1.1}"
IPTEST_PEER_IP="${IPTEST_PEER_IP:-10.200.1.2}"
IPTEST_HOST_IP_POOL="${IPTEST_HOST_IP_POOL:-}" # optional CSV of extra host-side IPs
IPTEST_PEER_IP_POOL="${IPTEST_PEER_IP_POOL:-}" # optional CSV of extra peer-side IPs

IPTEST_UID="${IPTEST_UID:-2000}" # default: shell (stable)
IPTEST_REPLAY_HOST_BIN="${IPTEST_REPLAY_HOST_BIN:-$SNORT_ROOT/build-output/iptest-replay}"
IPTEST_REPLAY_DEVICE_BIN="${IPTEST_REPLAY_DEVICE_BIN:-/data/local/tmp/iptest-replay}"
IPTEST_REPLAY_DEVICE_TRACE="${IPTEST_REPLAY_DEVICE_TRACE:-/data/local/tmp/iptest-trace.bin}"

IPTEST_NEPER_TCP_CRR_HOST_BIN="${IPTEST_NEPER_TCP_CRR_HOST_BIN:-$SNORT_ROOT/build-output/iptest-neper-tcp_crr}"
IPTEST_NEPER_UDP_STREAM_HOST_BIN="${IPTEST_NEPER_UDP_STREAM_HOST_BIN:-$SNORT_ROOT/build-output/iptest-neper-udp_stream}"
IPTEST_NEPER_TCP_CRR_DEVICE_BIN="${IPTEST_NEPER_TCP_CRR_DEVICE_BIN:-/data/local/tmp/iptest-neper-tcp_crr}"
IPTEST_NEPER_UDP_STREAM_DEVICE_BIN="${IPTEST_NEPER_UDP_STREAM_DEVICE_BIN:-/data/local/tmp/iptest-neper-udp_stream}"

iptest_adb_shell() {
  local command="$1"
  local quoted
  quoted="$(shell_single_quote "$command")"
  adb_cmd shell "sh -c $quoted"
}

iptest_adb_as_uid() {
  local uid="$1"
  local command="$2"
  local quoted
  quoted="$(shell_single_quote "$command")"
  adb_cmd shell "su $uid sh -c $quoted"
}

iptest_stage_replay_binary() {
  if [[ ! -f "$IPTEST_REPLAY_HOST_BIN" ]]; then
    echo "missing host replay binary: $IPTEST_REPLAY_HOST_BIN" >&2
    return 1
  fi
  adb_push_file "$IPTEST_REPLAY_HOST_BIN" "$IPTEST_REPLAY_DEVICE_BIN" >/dev/null
  adb_su "chmod 755 \"$IPTEST_REPLAY_DEVICE_BIN\""
}

iptest_stage_neper_binaries() {
  local missing=0

  if [[ ! -f "$IPTEST_NEPER_TCP_CRR_HOST_BIN" ]]; then
    echo "missing host neper tcp_crr binary: $IPTEST_NEPER_TCP_CRR_HOST_BIN" >&2
    missing=1
  fi
  if [[ ! -f "$IPTEST_NEPER_UDP_STREAM_HOST_BIN" ]]; then
    echo "missing host neper udp_stream binary: $IPTEST_NEPER_UDP_STREAM_HOST_BIN" >&2
    missing=1
  fi
  [[ $missing -eq 0 ]] || return 1

  adb_push_file "$IPTEST_NEPER_TCP_CRR_HOST_BIN" "$IPTEST_NEPER_TCP_CRR_DEVICE_BIN" >/dev/null
  adb_push_file "$IPTEST_NEPER_UDP_STREAM_HOST_BIN" "$IPTEST_NEPER_UDP_STREAM_DEVICE_BIN" >/dev/null
  adb_su "chmod 755 \"$IPTEST_NEPER_TCP_CRR_DEVICE_BIN\" \"$IPTEST_NEPER_UDP_STREAM_DEVICE_BIN\""
}

iptest_snort_pid() {
  local pid

  pid="$(adb_su 'pidof sucre-snort-dev 2>/dev/null | awk "{print \$1}" || true' | tr -d '\r\n')"
  if [[ -z "$pid" ]]; then
    pid="$(adb_su 'pidof sucre-snort 2>/dev/null | awk "{print \$1}" || true' | tr -d '\r\n')"
  fi

  if [[ -z "$pid" ]]; then
    return 1
  fi

  printf '%s\n' "$pid"
  return 0
}

iptest_capture_snort_proc_snapshot() {
  adb_su "$(cat <<'SH'
set -e

pid="$(pidof sucre-snort-dev 2>/dev/null | awk "{print \$1}" || true)"
if [ -z "${pid}" ]; then
  pid="$(pidof sucre-snort 2>/dev/null | awk "{print \$1}" || true)"
fi

echo timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
if [ -z "${pid}" ]; then
  echo snort_pid=0
  exit 0
fi

echo snort_pid="${pid}"
readlink "/proc/${pid}/exe" 2>/dev/null | awk '{print "snort_exe=" $0}' || true
tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null | awk '{print "snort_cmdline=" $0}' || true
awk '{print "snort_utime_ticks=" $14 "\n" "snort_stime_ticks=" $15 "\n" "snort_rss_pages=" $24}' "/proc/${pid}/stat" 2>/dev/null || true
grep '^VmRSS:' "/proc/${pid}/status" 2>/dev/null | awk '{print "snort_vm_rss_kb=" $2}' || true
grep '^VmSize:' "/proc/${pid}/status" 2>/dev/null | awk '{print "snort_vm_size_kb=" $2}' || true
getconf CLK_TCK 2>/dev/null | awk '{print "snort_clk_tck=" $1}' || true
SH
)"
}

iptest_snort_proc_delta_summary() {
  local before_path="$1"
  local after_path="$2"
  python3 - "$before_path" "$after_path" <<'PY'
import sys
from pathlib import Path

before_path = Path(sys.argv[1])
after_path = Path(sys.argv[2])


def load(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except FileNotFoundError:
        return out
    for line in lines:
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def as_int(d: dict[str, str], key: str) -> int:
    val = d.get(key, "")
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0


before = load(before_path)
after = load(after_path)

pid = as_int(after, "snort_pid") or as_int(before, "snort_pid")
clk_tck = as_int(after, "snort_clk_tck") or as_int(before, "snort_clk_tck")

ut_b = as_int(before, "snort_utime_ticks")
st_b = as_int(before, "snort_stime_ticks")
ut_a = as_int(after, "snort_utime_ticks")
st_a = as_int(after, "snort_stime_ticks")

vmrss_b = as_int(before, "snort_vm_rss_kb")
vmrss_a = as_int(after, "snort_vm_rss_kb")

ut_d = max(0, ut_a - ut_b)
st_d = max(0, st_a - st_b)
cpu_d = ut_d + st_d
vmrss_d = vmrss_a - vmrss_b

print(f"snort_pid={pid}")
print(f"snort_clk_tck={clk_tck}")
print(f"snort_utime_ticks_delta={ut_d}")
print(f"snort_stime_ticks_delta={st_d}")
print(f"snort_cpu_ticks_delta={cpu_d}")
print(f"snort_vm_rss_kb_before={vmrss_b}")
print(f"snort_vm_rss_kb_after={vmrss_a}")
print(f"snort_vm_rss_kb_delta={vmrss_d}")
PY
}

iptest_reset_baseline() {
  assert_ok "RESETALL" "RESETALL baseline"
  assert_ok "BLOCK 1" "BLOCK=1"
  assert_ok "BLOCKIPLEAKS 0" "BLOCKIPLEAKS=0"
  assert_ok "IPRULES 1" "IPRULES=1"
  assert_ok "BLOCKIFACE ${IPTEST_UID} 0" "BLOCKIFACE cleared for uid=$IPTEST_UID"
}

iptest_require_tier1_prereqs() {
  adb_su "command -v ip >/dev/null 2>&1" || return 1
  adb_su "ip netns list >/dev/null 2>&1" || return 1
  adb_su "ip link add \"$IPTEST_VETH0\" type veth peer name \"$IPTEST_VETH1\" >/dev/null 2>&1 && ip link del \"$IPTEST_VETH0\" >/dev/null 2>&1" ||
    return 1
  adb_cmd shell "command -v nc >/dev/null 2>&1 || command -v netcat >/dev/null 2>&1" >/dev/null 2>&1 || return 1
  adb_cmd shell "command -v ping >/dev/null 2>&1" >/dev/null 2>&1 || return 1
  return 0
}

iptest_detect_client_table() {
  # Output: table name/id or "main"
  local out table
  out="$(adb_cmd shell "ip route get \"$IPTEST_PEER_IP\" uid \"$IPTEST_UID\" 2>/dev/null" | tr -d '\r')"
  table="$(echo "$out" | awk '{for (i=1;i<=NF;i++) if ($i=="table") {print $(i+1); exit}}')"
  if [[ -n "$table" ]]; then
    printf '%s\n' "$table"
    return 0
  fi
  printf '%s\n' "main"
  return 0
}

iptest_tier1_teardown() {
  local table="${1:-}"
  if [[ -z "$table" ]]; then
    table="$(iptest_detect_client_table)"
  fi

  # Kill any processes still living in the namespace (best-effort).
  adb_su "pids=\"\$(ip netns pids \"$IPTEST_NS\" 2>/dev/null || true)\"; if [ -n \"\$pids\" ]; then kill -9 \$pids 2>/dev/null || true; fi"
  adb_su "ip route del \"$IPTEST_NET_CIDR\" dev \"$IPTEST_VETH0\" table \"$table\" >/dev/null 2>&1 || true"
  adb_su "ip link del \"$IPTEST_VETH0\" >/dev/null 2>&1 || true"
  adb_su "ip netns del \"$IPTEST_NS\" >/dev/null 2>&1 || true"
}

iptest_tier1_setup() {
  local table
  table="$(iptest_detect_client_table)"

  # Best-effort cleanup in case a previous run crashed.
  iptest_tier1_teardown "$table"

  local host_extra_cmd=""
  local peer_extra_cmd=""
  local ip

  if [[ -n "${IPTEST_HOST_IP_POOL:-}" ]]; then
    IFS=',' read -r -a _host_pool <<< "$IPTEST_HOST_IP_POOL"
    for ip in "${_host_pool[@]}"; do
      [[ -n "$ip" ]] || continue
      host_extra_cmd="${host_extra_cmd}
ip addr add \"${ip}\"/24 dev \"$IPTEST_VETH0\""
    done
  fi

  if [[ -n "${IPTEST_PEER_IP_POOL:-}" ]]; then
    IFS=',' read -r -a _peer_pool <<< "$IPTEST_PEER_IP_POOL"
    for ip in "${_peer_pool[@]}"; do
      [[ -n "$ip" ]] || continue
      peer_extra_cmd="${peer_extra_cmd}
ip -n \"$IPTEST_NS\" addr add \"${ip}\"/24 dev \"$IPTEST_VETH1\""
    done
  fi

  adb_su "set -e
ip netns add \"$IPTEST_NS\"
ip link add \"$IPTEST_VETH0\" type veth peer name \"$IPTEST_VETH1\"
ip link set \"$IPTEST_VETH1\" netns \"$IPTEST_NS\"
ip addr add \"$IPTEST_HOST_IP\"/24 dev \"$IPTEST_VETH0\"
${host_extra_cmd}
ip link set \"$IPTEST_VETH0\" up
ip -n \"$IPTEST_NS\" addr add \"$IPTEST_PEER_IP\"/24 dev \"$IPTEST_VETH1\"
${peer_extra_cmd}
ip -n \"$IPTEST_NS\" link set \"$IPTEST_VETH1\" up
ip -n \"$IPTEST_NS\" link set lo up
ip route add \"$IPTEST_NET_CIDR\" dev \"$IPTEST_VETH0\" table \"$table\" 2>/dev/null || true
"

  # Verify policy routing for the client UID.
  local verify
  verify="$(adb_cmd shell "ip route get \"$IPTEST_PEER_IP\" uid \"$IPTEST_UID\" 2>/dev/null" | tr -d '\r')"
  echo "$verify" | grep -q "dev $IPTEST_VETH0" || {
    echo "SKIP: tier1 route injection not effective for uid=$IPTEST_UID (need dev=$IPTEST_VETH0): $verify" >&2
    iptest_tier1_teardown "$table"
    return 10
  }

  printf '%s\n' "$table"
  return 0
}

iptest_tier1_ping_once() {
  iptest_adb_shell "ping -c 1 -W 1 \"$IPTEST_PEER_IP\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

iptest_iface_ifindex() {
  local iface="$1"
  local out idx

  out="$(adb_su "ip link show dev \"$iface\" 2>/dev/null" | tr -d '\r' || true)"
  idx="$(echo "$out" | awk -F':' 'NR==1{gsub(/ /,"",$1); print $1}')"
  if [[ ! "$idx" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  printf '%s\n' "$idx"
  return 0
}

iptest_tier1_start_tcp_zero_server() {
  local port="$1"
  # Start a simple endless sender in the netns. Use Toybox netcat's -L mode to
  # keep the listener alive and spawn a child process per connection.
  # Note: Toybox netcat disallows combining -l with -L ("No 'L' with 'l'").
  # Avoid spawning /system/bin/sh on a socket stdio (Pixel 6a kernel panic in sock_ioctl).
  adb_su "ip netns exec \"$IPTEST_NS\" sh -c 'nc -p \"$port\" -L cat /dev/zero >/dev/null 2>&1 & echo \$!'"
}

iptest_tier1_start_tcp_zero_servers() {
  local ports_csv="$1"
  local ports_shell
  ports_shell="$(printf '%s' "$ports_csv" | tr ',' ' ')"
  adb_su "ip netns exec \"$IPTEST_NS\" sh -c '
set -e
for port in ${ports_shell}; do
  nc -p \"\$port\" -L cat /dev/zero >/dev/null 2>&1 &
  echo \$!
done
'"
}


iptest_tier1_tcp_read_bytes() {
  local port="$1"
  local bytes="$2"
  local uid="${3:-$IPTEST_UID}"

  iptest_adb_as_uid "$uid" "nc -n -w 5 \"$IPTEST_PEER_IP\" \"$port\" | head -c \"$bytes\" >/dev/null 2>&1 || true" >/dev/null 2>&1
}

iptest_tier1_tcp_count_bytes() {
  local port="$1"
  local bytes="$2"
  local uid="${3:-$IPTEST_UID}"

  iptest_adb_as_uid "$uid" "nc -n -w 5 \"$IPTEST_PEER_IP\" \"$port\" | head -c \"$bytes\" | wc -c 2>/dev/null || true"
}

iptest_tier1_tcp_stream_count_bytes() {
  local port="$1"
  local seconds="$2"
  local uid="${3:-$IPTEST_UID}"

  iptest_adb_as_uid "$uid" "timeout \"$seconds\" nc -n -w 5 \"$IPTEST_PEER_IP\" \"$port\" | wc -c 2>/dev/null || true"
}

iptest_tier1_tcp_mix_count_bytes() {
  local seconds="$1"
  local uid="$2"
  local conn_bytes="$3"
  local workers="$4"
  local host_ips_csv="$5"
  local peer_ips_csv="$6"
  local ports_csv="$7"

  local -a host_ips peer_ips ports
  local i
  IFS=',' read -r -a host_ips <<< "$host_ips_csv"
  IFS=',' read -r -a peer_ips <<< "$peer_ips_csv"
  IFS=',' read -r -a ports <<< "$ports_csv"

  if [[ "${#host_ips[@]}" -lt 1 || "${#peer_ips[@]}" -lt 1 || "${#ports[@]}" -lt 1 ]]; then
    return 1
  fi

  local host_case=""
  local peer_case=""
  local port_case=""
  for i in "${!host_ips[@]}"; do
    host_case="${host_case}    ${i}) echo '${host_ips[$i]}' ;;\n"
  done
  for i in "${!peer_ips[@]}"; do
    peer_case="${peer_case}    ${i}) echo '${peer_ips[$i]}' ;;\n"
  done
  for i in "${!ports[@]}"; do
    port_case="${port_case}    ${i}) echo '${ports[$i]}' ;;\n"
  done

  local device_script
  device_script=$(cat <<EOF
set -eu
tmp="/data/local/tmp/iptest_mix_\$\$"
rm -rf "\$tmp"
mkdir -p "\$tmp"

pick_host_ip() {
  case "\$1" in
$(printf '%b' "$host_case")    *) echo '${host_ips[0]}' ;;
  esac
}

pick_peer_ip() {
  case "\$1" in
$(printf '%b' "$peer_case")    *) echo '${peer_ips[0]}' ;;
  esac
}

pick_port() {
  case "\$1" in
$(printf '%b' "$port_case")    *) echo '${ports[0]}' ;;
  esac
}

worker() {
  wid="\$1"
  end=\$(( \$(date +%s) + ${seconds} ))
  total=0
  conns=0
  i=0
  while [ "\$(date +%s)" -lt "\$end" ]; do
    host_idx=\$(( (wid + i) % ${#host_ips[@]} ))
    peer_idx=\$(( (wid * 3 + i) % ${#peer_ips[@]} ))
    port_idx=\$(( (wid * 5 + i) % ${#ports[@]} ))
    host_ip="\$(pick_host_ip "\$host_idx")"
    peer_ip="\$(pick_peer_ip "\$peer_idx")"
    port="\$(pick_port "\$port_idx")"
    n="\$(nc -n -s "\$host_ip" -w 5 "\$peer_ip" "\$port" | head -c "${conn_bytes}" | wc -c 2>/dev/null | tr -d '[:space:]' || true)"
    case "\$n" in
      ''|*[!0-9]*) n=0 ;;
    esac
    total=\$((total + n))
    conns=\$((conns + 1))
    i=\$((i + 1))
  done
  printf '%s %s\n' "\$total" "\$conns" > "\$tmp/\$wid"
}

w=0
while [ "\$w" -lt "${workers}" ]; do
  worker "\$w" &
  w=\$((w + 1))
done
wait

bytes=0
conns=0
for f in "\$tmp"/*; do
  [ -f "\$f" ] || continue
  set -- \$(cat "\$f")
  bytes=\$((bytes + \${1:-0}))
  conns=\$((conns + \${2:-0}))
done

rm -rf "\$tmp"
printf '%s %s\n' "\$bytes" "\$conns"
EOF
)

  iptest_adb_as_uid "$uid" "$device_script"
}
