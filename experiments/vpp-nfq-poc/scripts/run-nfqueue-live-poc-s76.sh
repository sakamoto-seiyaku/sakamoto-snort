#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-76 runtime conformance: one VPP process, four native NFQUEUE
# lanes, and two real workers.  Worker placement is derived from inline
# identity; no payload bytes cross the frame queue.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_WORK_ROOT/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0}"
VPP_BIN="${VPP_BIN:-$VPP_INSTALL_DIR/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$VPP_INSTALL_DIR/bin/vppctl}"
VPP_CONFIG="${VPP_CONFIG:-$POC_DIR/configs/nfqueue-live-poc-s76-startup.conf}"
RUNTIME_ROOT="${S76_RUNTIME_ROOT:-/tmp/sakamoto-vpp-nfqueue-s76}"
EVIDENCE_DIR="${S76_EVIDENCE_DIR:-/tmp/sakamoto-s76-evidence}"
QUEUE_BASE="${QUEUE_BASE:-42}"
S76_REGULAR_MEMFD="${S76_REGULAR_MEMFD:-0}"
S76_NETNS_STATE="${S76_NETNS_STATE:-/tmp/sakamoto-nfqueue-s76-state}"
HOST4="${S76_HOST4:-10.201.76.1}"
PEER4="${S76_PEER4:-10.201.76.2}"
HOST6="${S76_HOST6:-fd00:201:76::1}"
PEER6="${S76_PEER6:-fd00:201:76::2}"
OWNER_MODE="${S76_OWNER_MODE:-mixed}"
STRESS_MODE="${S76_STRESS:-0}"
STRESS_COUNT="${S76_STRESS_COUNT:-64}"
if [ "$STRESS_MODE" = 1 ]; then
  PING_COUNT="$STRESS_COUNT"
  PING_INTERVAL="${S76_STRESS_INTERVAL:-0.001}"
else
  PING_COUNT=8
  PING_INTERVAL=0.2
fi

case "$OWNER_MODE" in
  local) OWNER_ARG=owner-local ;;
  remote) OWNER_ARG=owner-remote ;;
  mixed) OWNER_ARG=owner-mixed ;;
  *) echo "S76_OWNER_MODE must be local, remote, or mixed" >&2; exit 2 ;;
esac
FAULT_ARGS=()
[ "${INJECT_STALE:-0}" = 1 ] && FAULT_ARGS+=(inject-stale)
[ "${INJECT_DUPLICATE:-0}" = 1 ] && FAULT_ARGS+=(inject-duplicate)
[ "${INJECT_COMPLETION_OVERFLOW:-0}" = 1 ] && FAULT_ARGS+=(inject-completion-overflow)
[ "${INJECT_MISSING_PACKET_ID:-0}" = 1 ] && FAULT_ARGS+=(inject-missing-packet-id)
[ "${INJECT_MISSING_GENERATION:-0}" = 1 ] && FAULT_ARGS+=(inject-missing-generation)
[ "${INJECT_UID_UNKNOWN:-0}" = 1 ] && FAULT_ARGS+=(inject-uid-unknown)
[ "${INJECT_OWNER_QUEUE_FULL:-0}" = 1 ] && FAULT_ARGS+=(inject-owner-queue-full)
[ "${INJECT_COMPLETION_CREDIT_EXHAUSTION:-0}" = 1 ] && \
  FAULT_ARGS+=(inject-completion-credit-exhaustion)

if [ "$(id -u)" -ne 0 ]; then
  echo "S76 netns smoke needs root/CAP_NET_ADMIN (run with rtk unshare -Urn)" >&2
  exit 1
fi
for binary in "$VPP_BIN" "$VPPCTL_BIN"; do
  [ -x "$binary" ] || {
    echo "missing executable: $binary (run build-nfqueue-live-poc.sh first)" >&2
    exit 1
  }
done
[ -f "$VPP_INSTALL_DIR/s73-provenance.properties" ] || {
  echo "missing pinned VPP provenance: $VPP_INSTALL_DIR/s73-provenance.properties" >&2
  exit 1
}

mkdir -p "$RUNTIME_ROOT/plugins" "$EVIDENCE_DIR"
cp "$VPP_INSTALL_DIR/lib/vpp_plugins/nfqueue_live_poc_plugin.so" \
  "$RUNTIME_ROOT/plugins/nfqueue_live_poc_plugin.so"
rm -f "$RUNTIME_ROOT/cli.sock" "$RUNTIME_ROOT/vpp.log" \
  "$RUNTIME_ROOT/vpp.stdout.log" "$EVIDENCE_DIR/run.log" \
  "$EVIDENCE_DIR/show-before-disable.txt" "$EVIDENCE_DIR/show-after-disable.txt"

vpp_pid=""
cleanup() {
  local status="$?" cleanup_error=0
  if [ -S "$RUNTIME_ROOT/cli.sock" ] &&
     ! "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc disable \
       >"$EVIDENCE_DIR/cleanup-disable.log" 2>&1; then
    echo "S76 cleanup: disable failed; see $EVIDENCE_DIR/cleanup-disable.log" >&2
    cleanup_error=1
  fi
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || cleanup_error=1
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
  if ! QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$S76_NETNS_STATE" \
      S76_HOST4="$HOST4" S76_PEER4="$PEER4" S76_HOST6="$HOST6" S76_PEER6="$PEER6" \
      "$SCRIPT_DIR/setup-netns-s76.sh" down >"$EVIDENCE_DIR/cleanup-netns.log" 2>&1; then
    echo "S76 cleanup: network teardown failed; see $EVIDENCE_DIR/cleanup-netns.log" >&2
    cleanup_error=1
  fi
  if [ "$cleanup_error" -ne 0 ] && [ "$status" -eq 0 ]; then status=1; fi
  return "$status"
}
trap cleanup EXIT

QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$S76_NETNS_STATE" \
  S76_HOST4="$HOST4" S76_PEER4="$PEER4" S76_HOST6="$HOST6" S76_PEER6="$PEER6" \
  "$SCRIPT_DIR/setup-netns-s76.sh" up
SAKAMOTO_S73_REGULAR_MEMFD="$S76_REGULAR_MEMFD" \
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
peer_pid="$(QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$S76_NETNS_STATE" \
  "$SCRIPT_DIR/setup-netns-s76.sh" peer-pid)"

{
  echo "# SAKAMOTO-76 two-worker live-buffer runtime evidence"
  echo "command=$0"
  echo "vpp=$VPP_BIN"
  echo "provenance=$VPP_INSTALL_DIR/s73-provenance.properties"
  echo "workers=2 (origin main thread 0; worker threads 1 and 2)"
  echo "owner-mode=$OWNER_MODE"
  echo "enable=nfqueue-live-poc enable-dual queue-base $QUEUE_BASE two-workers $OWNER_ARG ${FAULT_ARGS[*]}"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc enable-dual \
    queue-base "$QUEUE_BASE" two-workers "$OWNER_ARG" "${FAULT_ARGS[@]}"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc
  echo "inject=concurrent IPv4/IPv6 peer pings for INPUT and OUTPUT count=$PING_COUNT interval=$PING_INTERVAL stress=$STRESS_MODE"
  set +e
  nsenter -t "$peer_pid" -n ping -c "$PING_COUNT" -i "$PING_INTERVAL" -W 1 "$HOST4" >"$EVIDENCE_DIR/ping-ip4.log" 2>&1 &
  p4="$!"
  nsenter -t "$peer_pid" -n ping -6 -c "$PING_COUNT" -i "$PING_INTERVAL" -W 1 "$HOST6" >"$EVIDENCE_DIR/ping-ip6.log" 2>&1 &
  p6="$!"
  wait "$p4"; ping4_rc="$?"
  wait "$p6"; ping6_rc="$?"
  set -e
  echo "ping4_rc=$ping4_rc ping6_rc=$ping6_rc peer_pid=$peer_pid"
  sleep 0.3
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc
} 2>&1 | tee "$EVIDENCE_DIR/run.log"

"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc >"$EVIDENCE_DIR/show-before-disable.txt"
"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc disable
"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc >"$EVIDENCE_DIR/show-after-disable.txt"
cat "$EVIDENCE_DIR/show-before-disable.txt"
cat "$EVIDENCE_DIR/show-after-disable.txt"

show="$EVIDENCE_DIR/show-before-disable.txt"
value_for() {
  local key="$1"
  awk -v key="$key" '{for (i = 1; i <= NF; i++) if ($i == key) { print $(i + 1); exit }}' "$show" | tr -d '\r'
}
require_at_least() {
  local key="$1" minimum="$2" value
  value="$(value_for "$key")"
  if [ -z "$value" ] || [ "$value" -lt "$minimum" ]; then
    echo "S76 acceptance failure: $key=$value expected >= $minimum" >&2
    exit 1
  fi
}
require_exact() {
  local key="$1" expected="$2" value
  value="$(value_for "$key")"
  if [ "${value:-missing}" != "$expected" ]; then
    echo "S76 acceptance failure: $key=$value expected $expected" >&2
    exit 1
  fi
}

require_exact workers 2
require_at_least datagrams 8
require_at_least callbacks 8
require_at_least live-buffer-receives 8
require_at_least inline-metadata-writes 1
require_at_least payload-pointer-projections 1
require_at_least handoffs 1
require_at_least verdict-attempts 1
require_at_least native-buffer-returns 1
require_exact policy-verdicts 0
require_exact adapter-policy-parser-attempts 0
require_exact send-failures 0
require_exact packet-copies 0
require_exact scratch-rx-buffers 0
require_exact full-packet-memcpy 0
require_exact per-packet-heap-objects 0
require_exact outstanding-obligations 0
require_exact residue-obligations 0
require_exact completion-credits-held 0
require_exact residue-completion-credits 0
require_exact origin-return-overflow 0
credits_acquired="$(value_for completion-credit-acquired)"
credits_released="$(value_for completion-credit-released)"
if [ "${credits_acquired:-missing}" != "${credits_released:-different}" ]; then
  echo "S76 acceptance failure: credit acquired=$credits_acquired released=$credits_released" >&2
  exit 1
fi
require_exact identity-proof-failures 0
case "$OWNER_MODE" in
  mixed)
    require_at_least owner-local-obligations 1
    require_at_least owner-remote-obligations 1
    require_at_least owner-remote-handoffs 1
    require_at_least identity-proof-checks 1
    require_at_least identity-proof-matches 1
    ;;
  local)
    require_at_least owner-local-obligations 1
    require_exact owner-remote-obligations 0
    require_exact owner-remote-handoffs 0
    ;;
  remote)
    require_at_least owner-remote-obligations 1
    require_at_least owner-remote-handoffs 1
    require_at_least identity-proof-checks 1
    require_at_least identity-proof-matches 1
    ;;
esac
if [ "${INJECT_OWNER_QUEUE_FULL:-0}" = 1 ]; then
  require_at_least owner-queue-full 1
  require_at_least owner-terminal-intents 1
fi
if [ "${INJECT_COMPLETION_CREDIT_EXHAUSTION:-0}" = 1 ]; then
  require_at_least completion-credit-exhausted 1
fi
if [ "${INJECT_UID_UNKNOWN:-0}" = 1 ]; then
  require_at_least uid-unknown-fast-path 1
fi
if [ "${INJECT_MISSING_PACKET_ID:-0}" = 1 ]; then
  require_at_least missing-packet-id 1
fi
if [ "${INJECT_MISSING_GENERATION:-0}" = 1 ]; then
  require_at_least missing-queue-generation 1
fi
if [ "$STRESS_MODE" = 1 ]; then
  obligations="$(value_for ledger-message-obligations)"
  verdicts="$(value_for verdict-attempts)"
  returns="$(value_for native-buffer-returns)"
  proof_checks="$(value_for identity-proof-checks)"
  proof_matches="$(value_for identity-proof-matches)"
  remote_obligations="$(value_for owner-remote-obligations)"
  remote_handoffs="$(value_for owner-remote-handoffs)"
  if [ -z "$obligations" ] || [ "$obligations" -le 0 ] ||
     [ "$obligations" != "$verdicts" ] || [ "$obligations" != "$returns" ]; then
    echo "S76 stress acceptance failure: obligations=$obligations verdicts=$verdicts returns=$returns" >&2
    exit 1
  fi
  if [ "$proof_checks" != "$proof_matches" ] ||
     [ "$(value_for identity-proof-failures)" != 0 ] ||
     [ "$remote_obligations" != "$remote_handoffs" ]; then
    echo "S76 stress acceptance failure: proof=$proof_checks/$proof_matches failures=$(value_for identity-proof-failures) remote=$remote_obligations/$remote_handoffs" >&2
    exit 1
  fi
  echo "S76 stress ledger: obligations=$obligations verdicts=$verdicts native-returns=$returns credits=$(value_for completion-credit-acquired)/$(value_for completion-credit-released) proof=$proof_checks/$proof_matches remote=$remote_obligations/$remote_handoffs residues=$(value_for residue-obligations)/$(value_for residue-completion-credits)"
fi
echo "S76 runtime acceptance: PASS"
echo "raw evidence: $EVIDENCE_DIR/run.log $EVIDENCE_DIR/show-before-disable.txt $EVIDENCE_DIR/show-after-disable.txt"
