#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-175 public-seam RED for bounded handoff rejection in the installed
# Product VPP graph. The Host-only fixture injects capacity outcomes; packet
# ownership and settlement still execute in the real VLIB nodes.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host-s174}"
runtime_dir="${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime-s175-congestion-$$}"
evidence_dir="${SAKAMOTO_S175_CONGESTION_EVIDENCE_DIR:-/tmp/sakamoto-s175-product-vpp-congestion-$$}"
launcher="$repo_root/tools/product/run-host-vpp.sh"
stopper="$repo_root/tools/product/stop-host-vpp.sh"
residue="$repo_root/tools/product/host-residue-check.sh"
fixture_id=s175-handoff-congestion-v1
graph_source="$repo_root/src/product/vpp/product_packet_graph.c"
vpp_pid=

mkdir -p -- "$evidence_dir"

fail() {
  echo "SAKAMOTO-175 Product VPP congestion contract: FAIL: $*" >&2
  exit 1
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "$vpp_pid" ]] && kill -0 "$vpp_pid" 2>/dev/null; then
    PRODUCT_ARTIFACT_DIR="$artifact_root" \
      PRODUCT_RUNTIME_DIR="$runtime_dir" \
      "$stopper" >"$evidence_dir/stop.trace" 2>&1
    wait "$vpp_pid" 2>/dev/null
  fi
  PRODUCT_ARTIFACT_DIR="$artifact_root" \
    PRODUCT_RUNTIME_DIR="$runtime_dir" \
    "$residue" >"$evidence_dir/final-residue.trace" 2>&1
  local residue_status=$?
  set -e
  if [[ "$status" -eq 0 && "$residue_status" -ne 0 ]]; then
    cat "$evidence_dir/final-residue.trace" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

grep -Fq 'vlib_buffer_enqueue_to_thread_retained (' "$graph_source" ||
  fail "Product handoff does not use the nonblocking retained VPP API"

[[ -x "$artifact_root/bin/vpp" &&
   -f "$artifact_root/lib/vpp_plugins/product_core_plugin.so" ]] ||
  fail "missing installed Host Product VPP artifact"

PRODUCT_ARTIFACT_DIR="$artifact_root" \
  PRODUCT_RUNTIME_DIR="$runtime_dir" \
  "$residue" >"$evidence_dir/initial-residue.trace"

PRODUCT_ARTIFACT_DIR="$artifact_root" \
PRODUCT_RUNTIME_DIR="$runtime_dir" \
PRODUCT_GENERATION=175 \
PRODUCT_WORKER_COUNT=2 \
  "$launcher" >"$evidence_dir/vpp.trace" 2>&1 &
vpp_pid=$!

for _ in {1..200}; do
  [[ -S "$runtime_dir/cli.sock" ]] && break
  if ! kill -0 "$vpp_pid" 2>/dev/null; then
    cat "$evidence_dir/vpp.trace" >&2
    fail "installed Product VPP exited before its CLI became ready"
  fi
  sleep 0.05
done
[[ -S "$runtime_dir/cli.sock" ]] || fail "Product VPP CLI did not become ready"

cli() {
  local command="$1"
  python3 - "$runtime_dir/cli.sock" "$command" <<'PY'
import re
import socket
import sys

path, command = sys.argv[1:]
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
# A worker that waits for queue space fails this test at the public seam.
client.settimeout(2.0)
client.connect(path)

def receive_prompt():
    data = bytearray()
    while b"vpp# " not in data:
        chunk = client.recv(65536)
        if not chunk:
            raise RuntimeError("Product VPP CLI closed before prompt")
        data.extend(chunk)
        if len(data) > 1024 * 1024:
            raise RuntimeError("Product VPP CLI response exceeded 1 MiB")
    return bytes(data)

receive_prompt()
client.sendall(command.encode("utf-8") + b"\n")
response = receive_prompt()
client.close()
text = response.decode("utf-8", "replace")
text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text).replace("\r", "")
if "vpp# " in text:
    text = text.rsplit("vpp# ", 1)[0]
lines = text.splitlines()
if lines and lines[0].strip() == command:
    lines.pop(0)
print("\n".join(lines).strip())
PY
}

require_line() {
  local output="$1"
  local expected="$2"
  printf '%s\n' "$output" | grep -Fqx -- "$expected" ||
    fail "missing congestion evidence: $expected"
}

field() {
  local output="$1"
  local name="$2"
  printf '%s\n' "$output" |
    awk -F= -v name="$name" '$1 == name { print substr($0, index($0, "=") + 1); exit }'
}

require_rejected_vector() {
  local output="$1"
  local vector="$2"
  local stage="$3"
  local fault="$4"
  local reason="$5"
  local prefix="vector.$vector"

  require_line "$output" "$prefix.handoff_stage=$stage"
  require_line "$output" "$prefix.injected_fault=$fault"
  require_line "$output" "$prefix.runtime_drop_reason=$reason"
  require_line "$output" "$prefix.terminal_intent=drop-runtime"
  require_line "$output" "$prefix.terminal_intents=1"
  require_line "$output" "$prefix.ledger_settlements=1"
  require_line "$output" "$prefix.buffer_returns=1"

  local ingress reject terminal ingress_digest terminal_digest
  ingress="$(field "$output" "$prefix.ingress_buffer_index")"
  reject="$(field "$output" "$prefix.reject_buffer_index")"
  terminal="$(field "$output" "$prefix.terminal_buffer_index")"
  ingress_digest="$(field "$output" "$prefix.ingress_digest")"
  terminal_digest="$(field "$output" "$prefix.terminal_digest")"
  [[ "$ingress" =~ ^[0-9]+$ && "$ingress" == "$reject" &&
     "$reject" == "$terminal" ]] ||
    fail "$vector did not retain its one live buffer through rejection"
  [[ "$ingress_digest" =~ ^[[:xdigit:]]{64}$ &&
     "$ingress_digest" == "$terminal_digest" ]] ||
    fail "$vector bytes changed or became inaccessible after rejection"
}

configure_output="$(cli 'product packet-graph configure workers 2 fixture s174-valid-dual-stack-v1')"
require_line "$configure_output" "graph.configure=ok"
enable_output="$(cli 'product packet-graph enable')"
require_line "$enable_output" "graph.enable=ok"

fixture_output="$(cli "product packet-graph run-congestion-fixture $fixture_id")"
printf '%s\n' "$fixture_output" | tee "$evidence_dir/congestion-fixture.trace"
require_line "$fixture_output" "fixture.id=$fixture_id"
require_line "$fixture_output" "fixture.vector_count=2"
require_rejected_vector "$fixture_output" primary-credit-exhausted primary \
  credit-exhausted primary-handoff-congestion
require_rejected_vector "$fixture_output" corrective-queue-full corrective \
  queue-full corrective-handoff-congestion

status_output="$(cli 'show product packet-graph')"
printf '%s\n' "$status_output" | tee "$evidence_dir/status.trace"
for expected in \
  graph.congestion_rejections=2 \
  graph.runtime_drop_settlements=2 \
  graph.terminal_intents=2 \
  graph.ledger_settlements=2 \
  graph.buffer_returns=2 \
  graph.duplicate_terminals=0 \
  graph.duplicate_settlements=0 \
  graph.lost_buffers=0; do
  require_line "$status_output" "$expected"
done

disable_output="$(cli 'product packet-graph disable')"
printf '%s\n' "$disable_output" | tee "$evidence_dir/disable.trace"
require_line "$disable_output" "graph.disable=ok"
require_line "$disable_output" "graph.buffer_debt=0"
require_line "$disable_output" "graph.handoff_credit_debt=0"
require_line "$disable_output" "graph.obligation_debt=0"

echo "SAKAMOTO-175 Product VPP congestion contract: PASS"
echo "evidence=$evidence_dir"
