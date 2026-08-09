#!/usr/bin/env bash
set -euo pipefail

# S77 reuses the proven S76 real VPP/netns driver, changing only resource
# names, completion fault mode, and the acceptance ledger.  The plugin and
# pinned source build remain the S73--S76 live-buffer artifact lineage.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="${S77_EVIDENCE_DIR:-/tmp/sakamoto-s77-evidence}"
RUNTIME_ROOT="${S77_RUNTIME_ROOT:-/tmp/sakamoto-vpp-nfqueue-s77}"
NETNS_STATE="${S77_NETNS_STATE:-/tmp/sakamoto-nfqueue-s77-state}"
CONFIG_TEMPLATE="${S77_CONFIG_TEMPLATE:-$POC_DIR/configs/nfqueue-live-poc-s77-startup.conf}"
FAULT="${S77_FAULT:-normal}"
OWNER_MODE="${S77_OWNER_MODE:-remote}"

case "$OWNER_MODE" in
  local|remote|mixed) ;;
  *) echo "S77_OWNER_MODE must be local, remote, or mixed" >&2; exit 2 ;;
esac
case "$FAULT" in
  normal)
    export INJECT_STALE=1 INJECT_DUPLICATE=1
    unset INJECT_VERDICT_FAILED_DEFINITE INJECT_VERDICT_OUTCOME_UNKNOWN
    ;;
  failed-definite)
    unset INJECT_STALE INJECT_DUPLICATE INJECT_VERDICT_OUTCOME_UNKNOWN
    export INJECT_VERDICT_FAILED_DEFINITE=1
    ;;
  outcome-unknown)
    unset INJECT_STALE INJECT_DUPLICATE INJECT_VERDICT_FAILED_DEFINITE
    export INJECT_VERDICT_OUTCOME_UNKNOWN=1
    ;;
  *) echo "S77_FAULT must be normal, failed-definite, or outcome-unknown" >&2; exit 2 ;;
esac

mkdir -p "$EVIDENCE_DIR"
GENERATED_CONFIG="$EVIDENCE_DIR/startup.conf"
sed "s#__S77_RUNTIME_ROOT__#$RUNTIME_ROOT#g" "$CONFIG_TEMPLATE" >"$GENERATED_CONFIG"
set +e
S76_EVIDENCE_DIR="$EVIDENCE_DIR" \
S76_RUNTIME_ROOT="$RUNTIME_ROOT" \
S76_NETNS_STATE="$NETNS_STATE" \
S76_HOST_IF="${S77_HOST_IF:-nfq77-host}" \
S76_PEER_IF="${S77_PEER_IF:-nfq77-peer}" \
S76_HOST4="${S77_HOST4:-10.201.77.1}" \
S76_PEER4="${S77_PEER4:-10.201.77.2}" \
S76_HOST6="${S77_HOST6:-fd00:201:77::1}" \
S76_PEER6="${S77_PEER6:-fd00:201:77::2}" \
S76_OWNER_MODE="$OWNER_MODE" \
S76_REGULAR_MEMFD="${S77_REGULAR_MEMFD:-0}" \
S76_PING_COUNT="${S77_PING_COUNT:-$([ "$FAULT" = normal ] && echo 8 || echo 1)}" \
VPP_CONFIG="${VPP_CONFIG:-$GENERATED_CONFIG}" \
"$SCRIPT_DIR/run-nfqueue-live-poc-s76.sh"
runner_rc="$?"
set -e
if [ "$runner_rc" -ne 0 ]; then
  echo "S77 underlying live-buffer driver failed (rc=$runner_rc)" >&2
  exit "$runner_rc"
fi

show="$EVIDENCE_DIR/show-before-disable.txt"
value_for() {
  local key="$1"
  awk -v key="$key" '{for (i = 1; i <= NF; i++) if ($i == key) { print $(i + 1); exit }}' "$show" | tr -d '\r'
}
require_at_least() {
  local key="$1" minimum="$2" value
  value="$(value_for "$key")"
  if [ -z "$value" ] || [ "$value" -lt "$minimum" ]; then
    echo "S77 acceptance failure: $key=$value expected >= $minimum" >&2
    exit 1
  fi
}
require_exact() {
  local key="$1" expected="$2" value
  value="$(value_for "$key")"
  if [ "${value:-missing}" != "$expected" ]; then
    echo "S77 acceptance failure: $key=$value expected $expected" >&2
    exit 1
  fi
}

require_at_least physical-verdict-attempts 1
require_at_least native-buffer-returns 1
require_exact outstanding-obligations 0
require_exact residue-obligations 0
require_exact completion-debt 0
require_exact retry-attempts 0
require_exact worker-reentries 0
require_exact policy-re-evaluations 0
require_exact replacement-payloads 0
require_exact terminal-intent-rewrites 0
require_exact policy-verdict-rewrites 0
require_exact verdict-identity-mismatches 0
require_exact packet-copies 0
require_exact scratch-rx-buffers 0
require_exact full-packet-memcpy 0
require_exact per-packet-heap-objects 0

attempts="$(value_for physical-verdict-attempts)"
native_calls="$(value_for native-verdict-calls)"
definite_rejections="$(value_for verdict-definite-rejections)"
ambiguous_results="$(value_for verdict-ambiguous-results)"
if [ -z "$attempts" ] || [ -z "$native_calls" ] || \
   [ -z "$definite_rejections" ] || [ -z "$ambiguous_results" ] || \
   [ "$attempts" -ne $((native_calls + definite_rejections + ambiguous_results)) ]; then
  echo "S77 acceptance failure: operation evidence does not partition physical attempts (attempts=$attempts native=$native_calls definite=$definite_rejections ambiguous=$ambiguous_results)" >&2
  exit 1
fi

if [ "$FAULT" = normal ]; then
  require_at_least completion-outcome-succeeded 1
  require_exact completion-outcome-failed-definite 0
  require_exact completion-outcome-unknown 0
  require_exact verdict-ambiguous-results 0
  require_at_least duplicate-attempts 1
  require_at_least stale-generation-completions 1
elif [ "$FAULT" = failed-definite ]; then
  require_at_least completion-outcome-failed-definite 1
  require_exact completion-outcome-unknown 0
  require_exact verdict-ambiguous-results 0
  require_at_least verdict-fault-injections 1
else
  require_at_least completion-outcome-unknown 1
  require_exact completion-outcome-failed-definite 0
  require_at_least verdict-ambiguous-results 1
  require_exact verdict-definite-rejections 0
  require_exact send-failures 0
  require_at_least verdict-fault-injections 1
fi

attempt_generation="$(value_for last-verdict-generation)"
packet_generation="$(value_for queue-generation)"
attempt_packet="$(value_for last-verdict-packet-id)"
packet_id="$(value_for packet-id)"
if [ "$attempt_generation" != "$packet_generation" ] || [ "$attempt_packet" != "$packet_id" ]; then
  echo "S77 acceptance failure: completion identity $attempt_generation/$attempt_packet != $packet_generation/$packet_id" >&2
  exit 1
fi

echo "S77 runtime acceptance: PASS"
echo "raw evidence: $EVIDENCE_DIR/run.log $EVIDENCE_DIR/show-before-disable.txt $EVIDENCE_DIR/show-after-disable.txt"
