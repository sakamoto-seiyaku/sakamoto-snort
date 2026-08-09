#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-76 disposable four-lane topology.  The parent namespace owns one
# veth endpoint and the peer namespace drives INPUT/OUTPUT traffic for both
# families, so the same live VPP buffer can take local and remote-worker paths.

QUEUE_BASE="${QUEUE_BASE:-42}"
HOST_IF="${S76_HOST_IF:-nfq76-host}"
PEER_IF="${S76_PEER_IF:-nfq76-peer}"
HOST4="${S76_HOST4:-10.201.76.1}"
PEER4="${S76_PEER4:-10.201.76.2}"
HOST6="${S76_HOST6:-fd00:201:76::1}"
PEER6="${S76_PEER6:-fd00:201:76::2}"
STATE_DIR="${S76_NETNS_STATE:-/tmp/sakamoto-nfqueue-s76-state}"
PID_FILE="$STATE_DIR/peer.pid"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "S76 network setup needs root/CAP_NET_ADMIN inside the disposable namespace" >&2
    exit 1
  fi
}

peer_pid() {
  if [ -s "$PID_FILE" ]; then
    tr -d '[:space:]' <"$PID_FILE"
  fi
}

delete_rules() {
  while iptables -D OUTPUT -o "$HOST_IF" -p icmp -d "$PEER4" \
      -j NFQUEUE --queue-num "$QUEUE_BASE" >/dev/null 2>&1; do :; done
  while iptables -D INPUT -i "$HOST_IF" -p icmp -d "$HOST4" \
      -j NFQUEUE --queue-num "$((QUEUE_BASE + 1))" >/dev/null 2>&1; do :; done
  while ip6tables -D OUTPUT -o "$HOST_IF" -p ipv6-icmp -d "$PEER6" \
      -j NFQUEUE --queue-num "$((QUEUE_BASE + 2))" >/dev/null 2>&1; do :; done
  while ip6tables -D INPUT -i "$HOST_IF" -p ipv6-icmp -d "$HOST6" \
      -j NFQUEUE --queue-num "$((QUEUE_BASE + 3))" >/dev/null 2>&1; do :; done
}

down() {
  delete_rules || true
  local pid
  pid="$(peer_pid || true)"
  if [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
  ip link del "$HOST_IF" >/dev/null 2>&1 || true
  rm -f "$PID_FILE"
  rmdir "$STATE_DIR" >/dev/null 2>&1 || true
}

up() {
  down
  mkdir -p "$STATE_DIR"
  ip link add "$HOST_IF" type veth peer name "$PEER_IF"
  unshare -n --fork sleep 300 &
  local pid="$!"
  for _ in $(seq 1 50); do
    [ -d "/proc/$pid/ns/net" ] && break
    sleep 0.01
  done
  ip link set "$PEER_IF" netns "$pid"
  printf '%s\n' "$pid" >"$PID_FILE"

  ip addr add "$HOST4/24" dev "$HOST_IF"
  ip -6 addr add "$HOST6/64" dev "$HOST_IF" nodad
  ip link set "$HOST_IF" up
  nsenter -t "$pid" -n ip link set lo up
  nsenter -t "$pid" -n ip addr add "$PEER4/24" dev "$PEER_IF"
  nsenter -t "$pid" -n ip -6 addr add "$PEER6/64" dev "$PEER_IF" nodad
  nsenter -t "$pid" -n ip link set "$PEER_IF" up

  iptables -I OUTPUT 1 -o "$HOST_IF" -p icmp -d "$PEER4" \
    -j NFQUEUE --queue-num "$QUEUE_BASE"
  iptables -I INPUT 1 -i "$HOST_IF" -p icmp -d "$HOST4" \
    -j NFQUEUE --queue-num "$((QUEUE_BASE + 1))"
  ip6tables -I OUTPUT 1 -o "$HOST_IF" -p ipv6-icmp -d "$PEER6" \
    -j NFQUEUE --queue-num "$((QUEUE_BASE + 2))"
  ip6tables -I INPUT 1 -i "$HOST_IF" -p ipv6-icmp -d "$HOST6" \
    -j NFQUEUE --queue-num "$((QUEUE_BASE + 3))"

  echo "S76 topology: host $HOST4/$HOST6 on $HOST_IF; peer $PEER4/$PEER6 in netns pid $pid"
  echo "S76 queues: ip4 OUTPUT=$QUEUE_BASE INPUT=$((QUEUE_BASE + 1)) ip6 OUTPUT=$((QUEUE_BASE + 2)) INPUT=$((QUEUE_BASE + 3))"
}

need_root
case "${1:-}" in
  up) up ;;
  down) down ;;
  peer-pid) peer_pid ;;
  *) echo "usage: $0 up|down|peer-pid" >&2; exit 2 ;;
esac
