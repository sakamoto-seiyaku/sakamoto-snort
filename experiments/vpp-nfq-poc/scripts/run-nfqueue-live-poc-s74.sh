#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-74 acceptance wrapper around the established live Linux/netns
# runner. The runner supplies the real kernel NFQUEUE ingress and VPP native
# return; this wrapper checks the measured envelope and per-message ledger.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVIDENCE_DIR="${S73_EVIDENCE_DIR:-/tmp/sakamoto-s74-evidence}"

S73_EVIDENCE_DIR="$EVIDENCE_DIR" \
  "$SCRIPT_DIR/run-nfqueue-live-poc.sh"

show="$EVIDENCE_DIR/show-before-disable.txt"
if [ ! -s "$show" ]; then
  echo "S74 acceptance failure: missing runtime show file $show" >&2
  exit 1
fi

value_for() {
  local key="$1"
  awk -v key="$key" '{for (i = 1; i <= NF; i++) if ($i == key) {
    print $(i + 1)
    exit
  }}' "$show" | tr -d '\r'
}

require_at_least() {
  local key="$1" minimum="$2" value
  value="$(value_for "$key")"
  if [ -z "$value" ] || [ "$value" -lt "$minimum" ]; then
    echo "S74 acceptance failure: $key=$value expected >= $minimum" >&2
    exit 1
  fi
}

require_exact() {
  local key="$1" expected="$2" value
  value="$(value_for "$key")"
  if [ "${value:-missing}" != "$expected" ]; then
    echo "S74 acceptance failure: $key=$value expected $expected" >&2
    exit 1
  fi
}

require_at_least datagrams 1
require_at_least callbacks 1
require_at_least envelope-messages 1
require_at_least valid-messages 1
require_at_least recoverable-messages 1
require_at_least envelope-boundary-passes 1
require_at_least live-buffer-receives 1
require_at_least ledger-message-obligations 1
require_at_least verdict-attempts 1
require_at_least native-buffer-returns 1
require_exact buffer-data-size 9000
require_exact multiple-message-datagrams 0
require_exact envelope-recovery-attempts 0
require_exact recoveries 0
require_exact envelope-payload-offset 60
require_exact usable-l3-envelope 84
require_exact oversize-rejects 0
require_exact malformed-rejects 0
require_exact message-rejections 0
require_exact copy-count 0
require_exact residue-obligations 0
require_exact packet-copies 0
require_exact full-packet-memcpy 0
require_exact per-packet-heap-objects 0
require_exact outstanding-obligations 0

echo "S74 runtime acceptance: PASS"
echo "raw evidence: $EVIDENCE_DIR/run.log $EVIDENCE_DIR/show-before-disable.txt $EVIDENCE_DIR/show-after-disable.txt"
