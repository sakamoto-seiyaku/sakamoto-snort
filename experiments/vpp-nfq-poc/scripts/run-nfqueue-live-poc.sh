#!/usr/bin/env bash
set -euo pipefail

# One-command SAKAMOTO-73 Linux/netns tracer bullet. It builds nothing and
# starts only the dedicated VPP install produced by build-nfqueue-live-poc.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_WORK_ROOT/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0}"
VPP_BIN="${VPP_BIN:-$VPP_INSTALL_DIR/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$VPP_INSTALL_DIR/bin/vppctl}"
VPP_CONFIG="${VPP_CONFIG:-$POC_DIR/configs/nfqueue-live-poc-startup.conf}"
RUNTIME_ROOT="${S73_RUNTIME_ROOT:-/tmp/sakamoto-vpp-nfqueue-s73}"
EVIDENCE_DIR="${S73_EVIDENCE_DIR:-/tmp/sakamoto-s73-evidence}"
QUEUE_NUM="${QUEUE_NUM:-42}"
IP_FAMILY="${IP_FAMILY:-inet}"
S73_LOCAL_DUMMY="${S73_LOCAL_DUMMY:-0}"
S73_REGULAR_MEMFD="${S73_REGULAR_MEMFD:-0}"
case "$IP_FAMILY" in
  inet|ip4|ipv4)
    IP_FAMILY="inet"
    VPP_FAMILY="ip4"
    PEER_IP="${PEER_IP:-10.200.42.2}"
    PING_ARGS=()
    ;;
  inet6|ip6|ipv6)
    IP_FAMILY="inet6"
    VPP_FAMILY="ip6"
    PEER_IP="${PEER_IP:-fd00:42::2}"
    PING_ARGS=(-6)
    ;;
  *)
    echo "unknown IP_FAMILY=$IP_FAMILY; use inet or inet6" >&2
    exit 2
    ;;
esac
FAULT_ARGS=()
if [ "${INJECT_STALE:-0}" = "1" ]; then FAULT_ARGS+=(inject-stale); fi
if [ "${INJECT_DUPLICATE:-0}" = "1" ]; then FAULT_ARGS+=(inject-duplicate); fi

if [ "$(id -u)" -ne 0 ]; then
  echo "S73 netns smoke needs root/CAP_NET_ADMIN" >&2
  exit 1
fi
for binary in "$VPP_BIN" "$VPPCTL_BIN"; do
  if [ ! -x "$binary" ]; then
    echo "missing executable: $binary (run build-nfqueue-live-poc.sh first)" >&2
    exit 1
  fi
done
if [ ! -f "$VPP_INSTALL_DIR/s73-provenance.properties" ]; then
  echo "missing S73 provenance: $VPP_INSTALL_DIR/s73-provenance.properties" >&2
  exit 1
fi

mkdir -p "$RUNTIME_ROOT/plugins" "$EVIDENCE_DIR"
cp "$VPP_INSTALL_DIR/lib/vpp_plugins/nfqueue_live_poc_plugin.so" \
  "$RUNTIME_ROOT/plugins/nfqueue_live_poc_plugin.so"
rm -f "$RUNTIME_ROOT/cli.sock" "$RUNTIME_ROOT/vpp.log" \
  "$EVIDENCE_DIR/run.log" "$EVIDENCE_DIR/show-before-disable.txt" \
  "$EVIDENCE_DIR/show-after-disable.txt"

vpp_pid=""
cleanup() {
  if [ -S "$RUNTIME_ROOT/cli.sock" ]; then
    "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc disable \
      >/dev/null 2>&1 || true
  fi
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || true
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
  S73_LOCAL_DUMMY="$S73_LOCAL_DUMMY" IP_FAMILY="$IP_FAMILY" \
    PEER_IP="$PEER_IP" QUEUE_NUM="$QUEUE_NUM" \
    "$SCRIPT_DIR/setup-netns.sh" down \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

S73_LOCAL_DUMMY="$S73_LOCAL_DUMMY" IP_FAMILY="$IP_FAMILY" \
  PEER_IP="$PEER_IP" QUEUE_NUM="$QUEUE_NUM" \
  "$SCRIPT_DIR/setup-netns.sh" up
SAKAMOTO_S73_REGULAR_MEMFD="$S73_REGULAR_MEMFD" \
  "$VPP_BIN" -c "$VPP_CONFIG" >"$RUNTIME_ROOT/vpp.stdout.log" 2>&1 &
vpp_pid="$!"
for _ in $(seq 1 100); do
  [ -S "$RUNTIME_ROOT/cli.sock" ] && break
  if ! kill -0 "$vpp_pid" >/dev/null 2>&1; then
    cat "$RUNTIME_ROOT/vpp.stdout.log" >&2 || true
    exit 1
  fi
  sleep 0.1
done
[ -S "$RUNTIME_ROOT/cli.sock" ] || {
  cat "$RUNTIME_ROOT/vpp.stdout.log" >&2 || true
  exit 1
}

{
  echo "# SAKAMOTO-73 runtime evidence"
  echo "command=$0"
  echo "vpp=$VPP_BIN"
  echo "provenance=$VPP_INSTALL_DIR/s73-provenance.properties"
  echo "regular-memfd-fallback=$S73_REGULAR_MEMFD (throwaway opt-in only)"
  echo "workers=1 (origin main thread 0 -> owner worker 1)"
  echo "enable=nfqueue-live-poc enable queue $QUEUE_NUM family $VPP_FAMILY ${FAULT_ARGS[*]}"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc enable \
    queue "$QUEUE_NUM" family "$VPP_FAMILY" "${FAULT_ARGS[@]}"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc
  echo "inject=ping ${PING_ARGS[*]} -I nfq-host -c 1 -W 1 $PEER_IP"
  set +e
  ping "${PING_ARGS[@]}" -I nfq-host -c 1 -W 1 "$PEER_IP"
  ping_rc="$?"
  set -e
  echo "ping_rc=$ping_rc"
  sleep 0.2
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc
} 2>&1 | tee "$EVIDENCE_DIR/run.log"

"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc \
  >"$EVIDENCE_DIR/show-before-disable.txt"
"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc disable
"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc \
  >"$EVIDENCE_DIR/show-after-disable.txt"
cat "$EVIDENCE_DIR/show-before-disable.txt"
cat "$EVIDENCE_DIR/show-after-disable.txt"

show="$EVIDENCE_DIR/show-before-disable.txt"
require_stat() {
  local key="$1" minimum="$2" value
  value="$(awk -v key="$key" '{for (i=1;i<=NF;i++) if ($i==key) {print $(i+1); exit}}' "$show" | tr -d '\r')"
  if [ -z "$value" ] || [ "$value" -lt "$minimum" ]; then
    echo "S73 acceptance failure: $key=$value expected >= $minimum" >&2
    exit 1
  fi
}
require_zero() {
  local key="$1" value
  value="$(awk -v key="$key" '{for (i=1;i<=NF;i++) if ($i==key) {print $(i+1); exit}}' "$show" | tr -d '\r')"
  if [ "${value:-missing}" != 0 ]; then
    echo "S73 acceptance failure: $key=$value expected 0" >&2
    exit 1
  fi
}
require_stat datagrams 1
require_stat callbacks 1
require_stat handoffs 1
require_stat owner-mismatches 1
require_stat verdict-attempts 1
require_stat native-buffer-returns 1
require_stat uid-known 1
require_zero send-failures
require_zero ingress-alloc-failures
require_zero packet-copies
require_zero scratch-rx-buffers
require_zero full-packet-memcpy
require_zero per-packet-heap-objects
require_zero outstanding-obligations
require_zero payload-span-failures
echo "S73 runtime acceptance: PASS"
echo "raw evidence: $EVIDENCE_DIR/run.log $EVIDENCE_DIR/show-before-disable.txt $EVIDENCE_DIR/show-after-disable.txt"
