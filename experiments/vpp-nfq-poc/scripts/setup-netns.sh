#!/usr/bin/env bash
set -euo pipefail

QUEUE_NUM="${QUEUE_NUM:-42}"
IP_FAMILY="${IP_FAMILY:-inet}"
HOST_IF="${HOST_IF:-nfq-host}"
PEER_NS="${PEER_NS:-nfq-peer}"
PEER_IF="${PEER_IF:-nfq-peer0}"

case "$IP_FAMILY" in
  inet|ip4|ipv4)
    IP_FAMILY="inet"
    HOST_IP="${HOST_IP:-10.200.42.1}"
    PEER_IP="${PEER_IP:-10.200.42.2}"
    CIDR="${CIDR:-24}"
    addr_args=(addr add "$HOST_IP/$CIDR" dev "$HOST_IF")
    peer_addr_args=(-n "$PEER_NS" addr add "$PEER_IP/$CIDR" dev "$PEER_IF")
    firewall_bin=iptables
    rule_args=(-o "$HOST_IF" -p icmp -d "$PEER_IP" -j NFQUEUE --queue-num "$QUEUE_NUM")
    ;;
  inet6|ip6|ipv6)
    IP_FAMILY="inet6"
    HOST_IP="${HOST_IP:-fd00:42::1}"
    PEER_IP="${PEER_IP:-fd00:42::2}"
    CIDR="${CIDR:-64}"
    addr_args=(-6 addr add "$HOST_IP/$CIDR" dev "$HOST_IF" nodad)
    peer_addr_args=(-n "$PEER_NS" -6 addr add "$PEER_IP/$CIDR" dev "$PEER_IF" nodad)
    firewall_bin=ip6tables
    rule_args=(-o "$HOST_IF" -p ipv6-icmp -d "$PEER_IP" -j NFQUEUE --queue-num "$QUEUE_NUM")
    ;;
  *)
    echo "unknown IP_FAMILY=$IP_FAMILY; use inet or inet6" >&2
    exit 2
    ;;
esac

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script needs root inside the container." >&2
    exit 1
  fi
}

delete_rule() {
  while "$firewall_bin" -D OUTPUT "${rule_args[@]}" >/dev/null 2>&1; do
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

  ip "${addr_args[@]}"
  ip link set "$HOST_IF" up

  ip "${peer_addr_args[@]}"
  ip -n "$PEER_NS" link set "$PEER_IF" up
  ip -n "$PEER_NS" link set lo up

  "$firewall_bin" -I OUTPUT 1 "${rule_args[@]}"

  echo "Created $HOST_IF $HOST_IP/$CIDR -> $PEER_NS:$PEER_IF $PEER_IP/$CIDR"
  echo "Queued $IP_FAMILY ICMP OUTPUT packets to $PEER_IP on NFQUEUE $QUEUE_NUM"
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
