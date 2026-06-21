#!/usr/bin/env bash
set -euo pipefail

QUEUE_NUM="${QUEUE_NUM:-42}"
HOST_IF="${HOST_IF:-nfq-host}"
PEER_NS="${PEER_NS:-nfq-peer}"
PEER_IF="${PEER_IF:-nfq-peer0}"
HOST_IP="${HOST_IP:-10.200.42.1}"
PEER_IP="${PEER_IP:-10.200.42.2}"
CIDR="${CIDR:-24}"

rule_args=(-o "$HOST_IF" -p icmp -d "$PEER_IP" -j NFQUEUE --queue-num "$QUEUE_NUM")

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root inside the container." >&2
    exit 1
  fi
}

delete_rule() {
  while iptables -D OUTPUT "${rule_args[@]}" >/dev/null 2>&1; do
    true
  done
}

down() {
  delete_rule
  ip link del "$HOST_IF" >/dev/null 2>&1 || true
  ip netns del "$PEER_NS" >/dev/null 2>&1 || true
}

up() {
  down

  ip netns add "$PEER_NS"
  ip link add "$HOST_IF" type veth peer name "$PEER_IF"
  ip link set "$PEER_IF" netns "$PEER_NS"

  ip addr add "$HOST_IP/$CIDR" dev "$HOST_IF"
  ip link set "$HOST_IF" up

  ip -n "$PEER_NS" addr add "$PEER_IP/$CIDR" dev "$PEER_IF"
  ip -n "$PEER_NS" link set "$PEER_IF" up
  ip -n "$PEER_NS" link set lo up

  iptables -I OUTPUT 1 "${rule_args[@]}"

  echo "Created $HOST_IF $HOST_IP/$CIDR -> $PEER_NS:$PEER_IF $PEER_IP/$CIDR"
  echo "Queued ICMP OUTPUT packets to $PEER_IP on NFQUEUE $QUEUE_NUM"
}

need_root

case "${1:-}" in
  up)
    up
    ;;
  down)
    down
    ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
