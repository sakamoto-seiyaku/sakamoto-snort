#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-75 runtime conformance. One VPP process opens four independent
# native NFQUEUE lanes (IPv4/IPv6 x INPUT/OUTPUT); one disposable kernel
# topology then sends both families through both directions concurrently.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_WORK_ROOT/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0}"
VPP_BIN="${VPP_BIN:-$VPP_INSTALL_DIR/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$VPP_INSTALL_DIR/bin/vppctl}"
VPP_CONFIG="${VPP_CONFIG:-$POC_DIR/configs/nfqueue-live-poc-s75-startup.conf}"
RUNTIME_ROOT="${S75_RUNTIME_ROOT:-/tmp/sakamoto-vpp-nfqueue-s75}"
EVIDENCE_DIR="${S75_EVIDENCE_DIR:-/tmp/sakamoto-s75-evidence}"
QUEUE_BASE="${QUEUE_BASE:-42}"
S75_REGULAR_MEMFD="${S75_REGULAR_MEMFD:-0}"
S75_NETNS_STATE="${S75_NETNS_STATE:-/tmp/sakamoto-nfqueue-s75-state}"
HOST4="${S75_HOST4:-10.201.75.1}"
PEER4="${S75_PEER4:-10.201.75.2}"
HOST6="${S75_HOST6:-fd00:201:75::1}"
PEER6="${S75_PEER6:-fd00:201:75::2}"

FAULT_ARGS=()
[ "${INJECT_STALE:-0}" = 1 ] && FAULT_ARGS+=(inject-stale)
[ "${INJECT_DUPLICATE:-0}" = 1 ] && FAULT_ARGS+=(inject-duplicate)
[ "${INJECT_COMPLETION_OVERFLOW:-0}" = 1 ] && FAULT_ARGS+=(inject-completion-overflow)
[ "${INJECT_MISSING_PACKET_ID:-0}" = 1 ] && FAULT_ARGS+=(inject-missing-packet-id)
[ "${INJECT_MISSING_GENERATION:-0}" = 1 ] && FAULT_ARGS+=(inject-missing-generation)
[ "${INJECT_UID_UNKNOWN:-0}" = 1 ] && FAULT_ARGS+=(inject-uid-unknown)

if [ "$(id -u)" -ne 0 ]; then
  echo "S75 netns smoke needs root/CAP_NET_ADMIN (run with rtk unshare -Urn)" >&2
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
    echo "S75 cleanup: disable failed; see $EVIDENCE_DIR/cleanup-disable.log" >&2
    cleanup_error=1
  fi
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || cleanup_error=1
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
  if ! QUEUE_BASE="$QUEUE_BASE" S75_NETNS_STATE="$S75_NETNS_STATE" \
      S75_HOST4="$HOST4" S75_PEER4="$PEER4" S75_HOST6="$HOST6" S75_PEER6="$PEER6" \
      "$SCRIPT_DIR/setup-netns-s75.sh" down >"$EVIDENCE_DIR/cleanup-netns.log" 2>&1; then
    echo "S75 cleanup: network teardown failed; see $EVIDENCE_DIR/cleanup-netns.log" >&2
    cleanup_error=1
  fi
  if [ "$cleanup_error" -ne 0 ] && [ "$status" -eq 0 ]; then status=1; fi
  return "$status"
}
trap cleanup EXIT

QUEUE_BASE="$QUEUE_BASE" S75_NETNS_STATE="$S75_NETNS_STATE" \
  S75_HOST4="$HOST4" S75_PEER4="$PEER4" S75_HOST6="$HOST6" S75_PEER6="$PEER6" \
  "$SCRIPT_DIR/setup-netns-s75.sh" up
SAKAMOTO_S73_REGULAR_MEMFD="$S75_REGULAR_MEMFD" \
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
peer_pid="$(QUEUE_BASE="$QUEUE_BASE" S75_NETNS_STATE="$S75_NETNS_STATE" \
  "$SCRIPT_DIR/setup-netns-s75.sh" peer-pid)"

{
  echo "# SAKAMOTO-75 dual-stack INPUT/OUTPUT runtime evidence"
  echo "command=$0"
  echo "vpp=$VPP_BIN"
  echo "provenance=$VPP_INSTALL_DIR/s73-provenance.properties"
  echo "regular-memfd-fallback=$S75_REGULAR_MEMFD (throwaway opt-in only)"
  echo "workers=1 (origin main thread 0 -> owner worker 1)"
  echo "enable=nfqueue-live-poc enable-dual queue-base $QUEUE_BASE ${FAULT_ARGS[*]}"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc enable-dual \
    queue-base "$QUEUE_BASE" "${FAULT_ARGS[@]}"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc
  echo "inject=concurrent IPv4/IPv6 peer pings for INPUT and OUTPUT"
  set +e
  nsenter -t "$peer_pid" -n ping -c 4 -W 1 "$HOST4" >"$EVIDENCE_DIR/ping-ip4.log" 2>&1 &
  p4="$!"
  nsenter -t "$peer_pid" -n ping -6 -c 4 -W 1 "$HOST6" >"$EVIDENCE_DIR/ping-ip6.log" 2>&1 &
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
    echo "S75 acceptance failure: $key=$value expected >= $minimum" >&2
    exit 1
  fi
}
require_exact() {
  local key="$1" expected="$2" value
  value="$(value_for "$key")"
  if [ "${value:-missing}" != "$expected" ]; then
    echo "S75 acceptance failure: $key=$value expected $expected" >&2
    exit 1
  fi
}

require_at_least datagrams 4
require_at_least callbacks 4
require_at_least live-buffer-receives 4
require_at_least inline-metadata-writes 1
require_at_least payload-pointer-projections 1
require_at_least original-length 1
require_at_least captured-length 1
require_at_least packet-id 1
require_at_least queue-generation 1
# NFQA_UID is optional in the kernel netlink message.  A conforming run may
# therefore take either the known-UID path or the explicit uidKnown=false
# fast path; neither path is allowed to wait, read a cache, or replay.
uid_known="$(value_for uid-known-packets)"
uid_unknown="$(value_for uid-unknown-fast-path)"
if [ "${uid_known:-0}" -lt 1 ] && [ "${uid_unknown:-0}" -lt 1 ]; then
  echo "S75 acceptance failure: neither uid-known-packets nor uid-unknown-fast-path was observed" >&2
  exit 1
fi
require_exact uid-waits 0
require_exact uid-cache-reads 0
require_exact uid-replays 0
require_at_least handoffs 1
require_at_least verdict-attempts 1
require_at_least native-buffer-returns 1
for lane in 0 1 2 3; do
  if ! grep -Eq "^lane $lane .*datagrams [1-9][0-9]* .*callbacks [1-9][0-9]*" "$show"; then
    echo "S75 acceptance failure: lane $lane did not receive a callback" >&2
    exit 1
  fi
done
require_exact policy-verdicts 0
require_exact adapter-policy-parser-attempts 0
require_exact send-failures 0
require_exact packet-copies 0
require_exact scratch-rx-buffers 0
require_exact full-packet-memcpy 0
require_exact per-packet-heap-objects 0
require_exact outstanding-obligations 0
require_exact residue-obligations 0
require_exact origin-return-overflow 0
if [ "${INJECT_UID_UNKNOWN:-0}" = 1 ]; then
  require_at_least uid-unknown-fast-path 1
fi
if [ "${INJECT_MISSING_PACKET_ID:-0}" = 1 ]; then require_at_least missing-packet-id 1; fi
if [ "${INJECT_MISSING_GENERATION:-0}" = 1 ]; then require_at_least missing-queue-generation 1; fi
echo "S75 runtime acceptance: PASS"
echo "raw evidence: $EVIDENCE_DIR/run.log $EVIDENCE_DIR/show-before-disable.txt $EVIDENCE_DIR/show-after-disable.txt"
