#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-78 live reserve path.  One VPP process owns four native NFQUEUE
# lanes.  The positive-capacity scenarios fill a startup-fixed normal ledger,
# observe its live VPP-buffer peak, and then exercise the lane-local reserve;
# the direct scenario remains a zero-capacity fault control.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FAULT="${S78_FAULT:-reserve-exhaustion}"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_WORK_ROOT/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0}"
VPP_BIN="${VPP_BIN:-$VPP_INSTALL_DIR/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$VPP_INSTALL_DIR/bin/vppctl}"
CONFIG_TEMPLATE="${S78_CONFIG_TEMPLATE:-$POC_DIR/configs/nfqueue-live-poc-s78-startup.conf}"
RUNTIME_ROOT="${S78_RUNTIME_ROOT:-/tmp/sakamoto-vpp-nfqueue-s78}"
EVIDENCE_DIR="${S78_EVIDENCE_DIR:-/tmp/sakamoto-s78-evidence}"
QUEUE_BASE="${S78_QUEUE_BASE:-42}"
NETNS_STATE="${S78_NETNS_STATE:-/tmp/sakamoto-nfqueue-s78-state}"
HOST_IF="${S78_HOST_IF:-nfq78-host}"
PEER_IF="${S78_PEER_IF:-nfq78-peer}"
HOST4="${S78_HOST4:-10.201.78.1}"
PEER4="${S78_PEER4:-10.201.78.2}"
HOST6="${S78_HOST6:-fd00:201:78::1}"
PEER6="${S78_PEER6:-fd00:201:78::2}"
NORMAL_CAPACITY="${S78_NORMAL_CAPACITY:-0}"
RESERVE_CAPACITY="${S78_RESERVE_CAPACITY:-2}"
PING_COUNT="${S78_PING_COUNT:-4}"
STRESS="${S78_STRESS:-0}"
FORCE_NORMAL_EXHAUSTION=0
EXPECT_POSITIVE_NORMAL=0
ARM_NORMAL_CAPACITY_AFTER_FILL=0

case "$FAULT" in
  reserve-exhaustion)
    : "${S78_NORMAL_CAPACITY:=1}"
    : "${S78_RESERVE_CAPACITY:=2}"
    : "${S78_PING_COUNT:=16}"
    : "${S78_STRESS:=0}"
    EXPECT_LOSS=1
    EXPECT_POSITIVE_NORMAL=1
    ARM_NORMAL_CAPACITY_AFTER_FILL=1
    ;;
  reserve-direct)
    : "${S78_NORMAL_CAPACITY:=0}"
    : "${S78_RESERVE_CAPACITY:=8}"
    : "${S78_PING_COUNT:=1}"
    : "${S78_STRESS:=0}"
    EXPECT_LOSS=0
    FORCE_NORMAL_EXHAUSTION=1
    ;;
  reserve-stress)
    : "${S78_NORMAL_CAPACITY:=0}"
    : "${S78_RESERVE_CAPACITY:=2}"
    : "${S78_STRESS:=1}"
    : "${S78_STRESS_COUNT:=64}"
    : "${S78_PING_COUNT:=64}"
    EXPECT_LOSS=1
    FORCE_NORMAL_EXHAUSTION=1
    ;;
  *)
    echo "S78_FAULT must be reserve-exhaustion, reserve-direct, or reserve-stress" >&2
    exit 2
    ;;
esac

# Re-read case-selected values after applying scenario defaults above.
NORMAL_CAPACITY="${S78_NORMAL_CAPACITY}"
RESERVE_CAPACITY="${S78_RESERVE_CAPACITY}"
PING_COUNT="${S78_PING_COUNT}"
STRESS="${S78_STRESS}"

if [ "$(id -u)" -ne 0 ]; then
  echo "S78 netns smoke needs root/CAP_NET_ADMIN (run with rtk unshare -Urn)" >&2
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
sed "s#__S78_RUNTIME_ROOT__#$RUNTIME_ROOT#g" "$CONFIG_TEMPLATE" >"$EVIDENCE_DIR/startup.conf"
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
    echo "S78 cleanup: disable failed; see $EVIDENCE_DIR/cleanup-disable.log" >&2
    cleanup_error=1
  fi
  if [ -n "$vpp_pid" ] && kill -0 "$vpp_pid" >/dev/null 2>&1; then
    kill -TERM "$vpp_pid" >/dev/null 2>&1 || cleanup_error=1
    wait "$vpp_pid" >/dev/null 2>&1 || true
  fi
  if ! QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$NETNS_STATE" \
      S76_HOST_IF="$HOST_IF" S76_PEER_IF="$PEER_IF" \
      S76_HOST4="$HOST4" S76_PEER4="$PEER4" S76_HOST6="$HOST6" S76_PEER6="$PEER6" \
      "$SCRIPT_DIR/setup-netns-s76.sh" down \
      >"$EVIDENCE_DIR/cleanup-netns.log" 2>&1; then
    echo "S78 cleanup: network teardown failed; see $EVIDENCE_DIR/cleanup-netns.log" >&2
    cleanup_error=1
  fi
  if [ "$cleanup_error" -ne 0 ] && [ "$status" -eq 0 ]; then status=1; fi
  return "$status"
}
trap cleanup EXIT

QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$NETNS_STATE" \
  S76_HOST_IF="$HOST_IF" S76_PEER_IF="$PEER_IF" \
  S76_HOST4="$HOST4" S76_PEER4="$PEER4" S76_HOST6="$HOST6" S76_PEER6="$PEER6" \
  "$SCRIPT_DIR/setup-netns-s76.sh" up
SAKAMOTO_S73_REGULAR_MEMFD="${S78_REGULAR_MEMFD:-1}" \
  "$VPP_BIN" -c "$EVIDENCE_DIR/startup.conf" >"$RUNTIME_ROOT/vpp.stdout.log" 2>&1 &
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
peer_pid="$(QUEUE_BASE="$QUEUE_BASE" S76_NETNS_STATE="$NETNS_STATE" \
  "$SCRIPT_DIR/setup-netns-s76.sh" peer-pid)"

enable_args=(queue-base "$QUEUE_BASE" two-workers owner-mixed \
  normal-capacity "$NORMAL_CAPACITY" reserve-capacity "$RESERVE_CAPACITY")
if [ "$FORCE_NORMAL_EXHAUSTION" -eq 1 ]; then
  enable_args+=(inject-normal-capacity-exhaustion)
fi
if [ "$ARM_NORMAL_CAPACITY_AFTER_FILL" -eq 1 ]; then
  enable_args+=(arm-normal-capacity-exhaustion-after-fill)
fi
if [ "$STRESS" = 1 ]; then
  PING_COUNT="${S78_STRESS_COUNT:-64}"
fi

{
  echo "# SAKAMOTO-78 startup-fixed lane-local reserve runtime evidence"
  echo "command=$0"
  echo "vpp=$VPP_BIN"
  echo "provenance=$VPP_INSTALL_DIR/s73-provenance.properties"
  echo "pluginSha256=$(sha256sum "$RUNTIME_ROOT/plugins/nfqueue_live_poc_plugin.so" | awk '{print $1}')"
  echo "workers=2 (origin main thread 0; worker threads 1 and 2)"
  echo "enable=nfqueue-live-poc enable-dual ${enable_args[*]}"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc enable-dual \
    "${enable_args[@]}"
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc
  echo "inject=concurrent IPv4/IPv6 peer pings for INPUT and OUTPUT count=$PING_COUNT stress=$STRESS"
  set +e
  nsenter -t "$peer_pid" -n ping -c "$PING_COUNT" -i 0.001 -W 1 "$HOST4" \
    >"$EVIDENCE_DIR/ping-ip4.log" 2>&1 &
  p4="$!"
  nsenter -t "$peer_pid" -n ping -6 -c "$PING_COUNT" -i 0.001 -W 1 "$HOST6" \
    >"$EVIDENCE_DIR/ping-ip6.log" 2>&1 &
  p6="$!"
  wait "$p4"; ping4_rc="$?"
  wait "$p6"; ping6_rc="$?"
  set -e
  echo "ping4_rc=$ping4_rc ping6_rc=$ping6_rc peer_pid=$peer_pid"
  sleep 0.3
  "$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc
} 2>&1 | tee "$EVIDENCE_DIR/run.log"

"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc \
  >"$EVIDENCE_DIR/show-before-disable.txt"
"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" nfqueue-live-poc disable
"$VPPCTL_BIN" -s "$RUNTIME_ROOT/cli.sock" show nfqueue-live-poc \
  >"$EVIDENCE_DIR/show-after-disable.txt"

show="$EVIDENCE_DIR/show-before-disable.txt"
value_for() {
  local key="$1"
  awk -v key="$key" '{for (i = 1; i <= NF; i++) if ($i == key) { print $(i + 1); exit }}' "$show" | tr -d '\r'
}
require_at_least() {
  local key="$1" minimum="$2" value
  value="$(value_for "$key")"
  if [ -z "$value" ] || [ "$value" -lt "$minimum" ]; then
    echo "S78 acceptance failure: $key=$value expected >= $minimum" >&2
    exit 1
  fi
}
require_exact() {
  local key="$1" expected="$2" value
  value="$(value_for "$key")"
  if [ "${value:-missing}" != "$expected" ]; then
    echo "S78 acceptance failure: $key=$value expected $expected" >&2
    exit 1
  fi
}

require_exact reserve-enabled 1
require_exact reserve-capacity "$RESERVE_CAPACITY"
require_exact normal-capacity "$NORMAL_CAPACITY"
require_at_least reserve-startup-reservations $((4 * RESERVE_CAPACITY))
require_at_least normal-capacity-exhaustions 1
if [ "$EXPECT_POSITIVE_NORMAL" -eq 1 ]; then
  require_at_least normal-peak-occupancy 1
  require_exact normal-capacity-arm-after-fill 1
fi
require_at_least reserve-direct-obligations 1
require_at_least reserve-direct-completions 1
require_at_least reserve-direct-native-returns 1
if [ "$EXPECT_LOSS" -eq 1 ]; then
  require_at_least reserve-exhaustions 1
  require_at_least reserve-losses 1
  require_at_least reserve-degraded-health 1
else
  require_exact reserve-losses 0
  require_exact reserve-loss-materializations 0
fi
require_exact reserve-startup-failures 0
require_exact reserve-receive-faults 0
require_exact reserve-envelope-bytes 9000
require_exact reserve-parser-attempts 0
require_exact reserve-flow-enters 0
require_exact reserve-policy-verdicts 0
require_exact reserve-delivery-success-claims 0
require_exact reserve-copy-count 0
require_exact dynamic-reserve-growth 0
require_exact cross-lane-reserve-borrows 0
require_exact reserve-blocking-waits 0
require_exact outstanding-obligations 0
require_exact residue-obligations 0
require_exact reserve-outstanding 0
require_exact packet-copies 0
require_exact scratch-rx-buffers 0
require_exact full-packet-memcpy 0
require_exact per-packet-heap-objects 0
direct="$(value_for reserve-direct-obligations)"
completions="$(value_for reserve-direct-completions)"
returns="$(value_for reserve-direct-native-returns)"
if [ "$direct" != "$completions" ] || [ "$direct" != "$returns" ]; then
  echo "S78 acceptance failure: direct=$direct completions=$completions returns=$returns" >&2
  exit 1
fi
loss_materializations="$(value_for reserve-loss-materializations)"
losses="$(value_for reserve-losses)"
loss_unmaterialized="$(value_for reserve-loss-unmaterialized)"
loss_drops="$(value_for reserve-loss-native-drops)"
loss_failed="$(value_for reserve-loss-failed-definite)"
loss_unknown="$(value_for reserve-loss-unknown)"
if [ $((loss_drops + loss_failed + loss_unknown)) -gt "$loss_materializations" ] || \
   [ $((loss_materializations + loss_unmaterialized)) -ne "$losses" ]; then
  echo "S78 acceptance failure: loss outcomes do not partition materialized/unmaterialized losses" >&2
  exit 1
fi
if [ "$FAULT" = reserve-stress ]; then
  require_at_least datagrams 4
fi
echo "S78 runtime acceptance: PASS"
echo "raw evidence: $EVIDENCE_DIR/run.log $EVIDENCE_DIR/show-before-disable.txt $EVIDENCE_DIR/show-after-disable.txt"
