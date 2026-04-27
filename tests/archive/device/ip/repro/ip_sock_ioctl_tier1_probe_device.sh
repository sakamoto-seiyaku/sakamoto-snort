#!/system/bin/sh

# Device-side probe for Pixel/Android kernel panic in sock_ioctl triggered by `ip`.
# Purpose: pinpoint which `ip` subcommand sequence (Tier-1 prereqs / netns+veth / IPv6 route get)
# causes the reboot by writing step markers to a persistent directory.

set -e

umask 022

LOG_DIR="${LOG_DIR:-/data/local/tmp/iptest_sock_ioctl_probe}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/run_${RUN_ID}.log}"
STEP_FILE="${STEP_FILE:-$LOG_DIR/last_step.txt}"
CMD_FILE="${CMD_FILE:-$LOG_DIR/last_cmd.txt}"

PROBE_ITERS="${PROBE_ITERS:-1}"
PROBE_IPV6="${PROBE_IPV6:-1}" # 1 enables `ip -6` and IPv6 route injection/get

IPTEST_NS="${IPTEST_NS:-iptest_ns}"
IPTEST_VETH0="${IPTEST_VETH0:-iptest_veth0}"
IPTEST_VETH1="${IPTEST_VETH1:-iptest_veth1}"

IPTEST_NET_CIDR="${IPTEST_NET_CIDR:-10.200.1.0/24}"
IPTEST_HOST_IP="${IPTEST_HOST_IP:-10.200.1.1}"
IPTEST_PEER_IP="${IPTEST_PEER_IP:-10.200.1.2}"

IPTEST_NET6_CIDR="${IPTEST_NET6_CIDR:-fd00:200:1::/64}"
IPTEST_HOST_IP6="${IPTEST_HOST_IP6:-fd00:200:1::1}"
IPTEST_PEER_IP6="${IPTEST_PEER_IP6:-fd00:200:1::2}"

IPTEST_UID="${IPTEST_UID:-2000}" # shell uid

mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR/latest.log" "$LOG_DIR/latest_step.txt" "$LOG_DIR/latest_cmd.txt" 2>/dev/null || true
ln -s "$LOG_FILE" "$LOG_DIR/latest.log" 2>/dev/null || true
ln -s "$STEP_FILE" "$LOG_DIR/latest_step.txt" 2>/dev/null || true
ln -s "$CMD_FILE" "$LOG_DIR/latest_cmd.txt" 2>/dev/null || true

exec >>"$LOG_FILE" 2>&1

step_n=0
log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

mark_step() {
  step_n=$((step_n + 1))
  echo "STEP ${step_n}: $*" >"$STEP_FILE"
  sync
  log "===== STEP ${step_n}: $* ====="
}

mark_cmd() {
  echo "$*" >"$CMD_FILE"
  sync
  log "CMD: $*"
}

run_probe_cmd() {
  desc="$1"
  shift
  mark_step "$desc"
  mark_cmd "$*"
  set +e
  "$@"
  rc=$?
  set -e
  log "rc=$rc"
  return 0
}

cleanup() {
  set +e
  # Best-effort cleanup in case we get part-way through.
  ip route del "$IPTEST_NET_CIDR" dev "$IPTEST_VETH0" table "$client_table" >/dev/null 2>&1 || true
  ip -6 route del "$IPTEST_NET6_CIDR" dev "$IPTEST_VETH0" table "$client_table" >/dev/null 2>&1 || true
  ip link del "$IPTEST_VETH0" >/dev/null 2>&1 || true
  ip netns del "$IPTEST_NS" >/dev/null 2>&1 || true
}

log "run_id=$RUN_ID"
log "id=$(id)"
log "uname=$(uname -a)"
log "fingerprint=$(getprop ro.build.fingerprint 2>/dev/null || true)"
log "kernel_version=$(cat /proc/version 2>/dev/null || true)"

mark_step "detect route table for uid=$IPTEST_UID"
client_table="$(ip route get "$IPTEST_PEER_IP" uid "$IPTEST_UID" 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="table") {print $(i+1); exit}}')"
if [ -z "$client_table" ]; then
  client_table="main"
fi
log "client_table=$client_table"

trap cleanup EXIT

iter=1
while [ "$iter" -le "$PROBE_ITERS" ]; do
  log "=== iter=$iter/$PROBE_ITERS ==="

  run_probe_cmd "prereq: ip -V" ip -V

  if [ "$PROBE_IPV6" -eq 1 ] 2>/dev/null; then
    run_probe_cmd "prereq: ip -6 addr show" ip -6 addr show
    run_probe_cmd "prereq: ip -6 route show" ip -6 route show
  fi

  run_probe_cmd "prereq: ip netns list" ip netns list

  run_probe_cmd "prereq: veth add/del (no netns)" sh -c "ip link add \"$IPTEST_VETH0\" type veth peer name \"$IPTEST_VETH1\" && ip link del \"$IPTEST_VETH0\""

  mark_step "tier1: netns+veth setup"
  cleanup || true

  run_probe_cmd "tier1: ip netns add" ip netns add "$IPTEST_NS"
  run_probe_cmd "tier1: ip link add veth" ip link add "$IPTEST_VETH0" type veth peer name "$IPTEST_VETH1"
  run_probe_cmd "tier1: ip link set veth1 netns" ip link set "$IPTEST_VETH1" netns "$IPTEST_NS"
  run_probe_cmd "tier1: ip addr add v4 host" ip addr add "${IPTEST_HOST_IP}/24" dev "$IPTEST_VETH0"
  run_probe_cmd "tier1: ip link set veth0 up" ip link set "$IPTEST_VETH0" up
  run_probe_cmd "tier1: ip -n ns addr add v4 peer" ip -n "$IPTEST_NS" addr add "${IPTEST_PEER_IP}/24" dev "$IPTEST_VETH1"
  run_probe_cmd "tier1: ip -n ns link set veth1 up" ip -n "$IPTEST_NS" link set "$IPTEST_VETH1" up
  run_probe_cmd "tier1: ip -n ns link set lo up" ip -n "$IPTEST_NS" link set lo up
  run_probe_cmd "tier1: ip route add v4 net via veth0 (uid table)" sh -c "ip route add \"$IPTEST_NET_CIDR\" dev \"$IPTEST_VETH0\" table \"$client_table\" 2>/dev/null || true"
  run_probe_cmd "tier1: ip route get v4 peer uid=$IPTEST_UID" ip route get "$IPTEST_PEER_IP" uid "$IPTEST_UID"

  if [ "$PROBE_IPV6" -eq 1 ] 2>/dev/null; then
    run_probe_cmd "tier1: ip addr add v6 host" ip addr add "${IPTEST_HOST_IP6}/64" dev "$IPTEST_VETH0"
    run_probe_cmd "tier1: ip -n ns addr add v6 peer" ip -n "$IPTEST_NS" addr add "${IPTEST_PEER_IP6}/64" dev "$IPTEST_VETH1"
    run_probe_cmd "tier1: ip -6 route add v6 net via veth0 (uid table)" sh -c "ip -6 route add \"$IPTEST_NET6_CIDR\" dev \"$IPTEST_VETH0\" table \"$client_table\" 2>/dev/null || true"
    run_probe_cmd "tier1: ip -6 route get v6 peer uid=$IPTEST_UID" ip -6 route get "$IPTEST_PEER_IP6" uid "$IPTEST_UID"
  fi

  mark_step "iter cleanup"
  cleanup || true

  iter=$((iter + 1))
done

mark_step "done"
log "OK: finished without reboot (iters=$PROBE_ITERS ipv6=$PROBE_IPV6)"

