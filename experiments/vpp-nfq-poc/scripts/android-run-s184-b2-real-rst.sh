#!/usr/bin/env bash
set -euo pipefail

# S184 / B2 real LAN TCP reset exploration.
#
# S181's unbound LAN port is a valid closed-port timeout fixture but did not
# produce a stable native ECONNREFUSED/RST signal. This wrapper keeps the
# S181 full-device harness and replaces only that fixture after its unbound
# precondition has been recorded. It intentionally does not change the
# product artifact or synthesize a refusal in the verifier.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RESULT_DIR="${RESULT_DIR:-$POC_DIR/evidence/s184-b2-real-rst-$(date +%Y%m%d)}"
TCP_RST_PORT="${TCP_RST_PORT:-53546}"
RST_LOG="$RESULT_DIR/tcp-rst-fixture.log"
WRAPPER_LOG="$RESULT_DIR/s184-wrapper.log"
S181_PID=""
RST_PID=""

mkdir -p "$RESULT_DIR"

cleanup() {
  if [[ -n "$RST_PID" ]]; then
    kill "$RST_PID" >/dev/null 2>&1 || true
    wait "$RST_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$S181_PID" ]]; then
    kill "$S181_PID" >/dev/null 2>&1 || true
    wait "$S181_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

(
  export RESULT_DIR
  export TCP_TIMEOUT_PORT="$TCP_RST_PORT"
  export TCP_EXPECTED_FAILURE="real-reset"
  export INCLUDE_NO_REPLY="false"
  export INCLUDE_TCP_TIMEOUT="true"
  export INCLUDE_POLICY_DROP="false"
  export INCLUDE_UID_DROP="false"
  export STAGE_PREFIX="S184"
  export RUNNER_TITLE="S184 B2 real LAN TCP RST exploration"
  export RUNNER_NAME="android-run-s184-b2-real-rst.sh"
  export RUNNER_SCHEMA="s184-b2-real-rst/v1"
  export RUNNER_SCOPE="bounded_full_device_b2_real_lan_tcp_rst"
  export RUNNER_CLAIM_BOUNDARY="WSL2-LAN-fixture-real-AppA-TCP-RST-after-SYN-through-VpnService-OI3-multi"
  export RUNNER_NON_CLAIM="not deterministic pre-connect ECONNREFUSED, not bind/protect failure, not infrastructure failure, not public internet, not production timeout constants"
  exec "$SCRIPT_DIR/android-run-s181-b2-full-device-transport-explore.sh"
) >"$WRAPPER_LOG" 2>&1 &
S181_PID=$!

fixture_log=""
for _ in $(seq 1 240); do
  for candidate in "$RESULT_DIR"/fixture-*.log; do
    if [[ -f "$candidate" ]]; then
      fixture_log="$candidate"
      break
    fi
  done
  if [[ -n "$fixture_log" ]] \
      && grep -Fq "\"event\": \"tcp_timeout_port_unbound\"" "$fixture_log"; then
    break
  fi
  if ! kill -0 "$S181_PID" >/dev/null 2>&1; then
    echo "S181 runner exited before the unbound TCP precondition" >&2
    exit 2
  fi
  sleep 0.25
done

if [[ -z "$fixture_log" ]] \
    || ! grep -Fq "\"event\": \"tcp_timeout_port_unbound\"" "$fixture_log"; then
  echo "timed out waiting for S181 tcp_timeout_port_unbound" >&2
  exit 2
fi

rm -f "$RST_LOG"
python3 "$SCRIPT_DIR/s184-rst-fixture.py" 0.0.0.0 "$TCP_RST_PORT" "$RST_LOG" &
RST_PID=$!

for _ in $(seq 1 40); do
  if [[ -f "$RST_LOG" ]] \
      && grep -Fq '"event": "tcp_rst_ready"' "$RST_LOG"; then
    break
  fi
  if ! kill -0 "$RST_PID" >/dev/null 2>&1; then
    echo "RST fixture exited before readiness" >&2
    exit 2
  fi
  sleep 0.25
done

if [[ ! -f "$RST_LOG" ]] \
    || ! grep -Fq '"event": "tcp_rst_ready"' "$RST_LOG"; then
  echo "timed out waiting for RST fixture readiness" >&2
  exit 2
fi

set +e
wait "$S181_PID"
runner_rc=$?
set -e

{
  echo "runner_rc=$runner_rc"
  echo "fixture_log=$fixture_log"
  echo "rst_fixture_log=$RST_LOG"
  echo "tcp_rst_port=$TCP_RST_PORT"
  if grep -Fq '"event": "tcp_rst_connection"' "$RST_LOG"; then
    echo "rst_connection_observed=true"
  else
    echo "rst_connection_observed=false"
  fi
  if grep -Fq '"event": "tcp_rst_sent"' "$RST_LOG"; then
    echo "rst_sent=true"
  else
    echo "rst_sent=false"
  fi
} >"$RESULT_DIR/s184-wrapper-result.txt"

# A passing native/app verdict is not sufficient unless this exact controlled
# fixture both accepted the registered connection and performed the RST close.
# Do not let an unrelated ambient reset satisfy the cell.
if [[ "$runner_rc" -eq 0 ]] \
    && { ! grep -Fq '"event": "tcp_rst_connection"' "$RST_LOG" \
         || ! grep -Fq '"event": "tcp_rst_sent"' "$RST_LOG"; }; then
  echo "S184 runner passed without the registered fixture RST evidence" >&2
  exit 1
fi

# Preserve the underlying S181-derived verdict. A non-zero result is meaningful
# evidence, not a wrapper failure hidden by `|| true`.
exit "$runner_rc"
