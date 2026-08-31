#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-175 public-seam RED for graph lifecycle. The Host-only fixture
# drives real enable/disable transitions while fragment and handoff ownership
# is outstanding; the installed graph remains responsible for draining and
# rejecting stale-generation work.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host-s175-patched}"
runtime_dir="${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime-s175-lifecycle-$$}"
evidence_dir="${SAKAMOTO_S175_LIFECYCLE_EVIDENCE_DIR:-/tmp/sakamoto-s175-product-vpp-lifecycle-$$}"
launcher="$repo_root/tools/product/run-host-vpp.sh"
stopper="$repo_root/tools/product/stop-host-vpp.sh"
residue="$repo_root/tools/product/host-residue-check.sh"
host_graph_source="$repo_root/src/product/vpp/product_packet_graph_host_evidence.c"
fixture_id=s175-bounded-drain-generation-v1
vpp_pid=

mkdir -p -- "$evidence_dir"

fail() {
  echo "SAKAMOTO-175 Product VPP lifecycle contract: FAIL: $*" >&2
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

grep -Fq 'product packet-graph run-lifecycle-fixture' "$host_graph_source" ||
  fail "installed Host graph does not expose the lifecycle fixture seam"

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
# A lifecycle transition that exceeds this public bound is not a bounded drain.
client.settimeout(3.0)
client.connect(path)

def receive_prompt():
    data = bytearray()
    while b"vpp# " not in data:
        chunk = client.recv(65536)
        if not chunk:
            raise RuntimeError("Product VPP CLI closed before prompt")
        data.extend(chunk)
        if len(data) > 2 * 1024 * 1024:
            raise RuntimeError("Product VPP CLI response exceeded 2 MiB")
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
    fail "missing lifecycle evidence: $expected"
}

field() {
  local output="$1"
  local name="$2"
  printf '%s\n' "$output" |
    awk -F= -v name="$name" '$1 == name { print substr($0, index($0, "=") + 1); exit }'
}

configure_output="$(cli 'product packet-graph configure workers 2 fixture s174-valid-dual-stack-v1')"
require_line "$configure_output" "graph.configure=ok"

fixture_output="$(cli "product packet-graph run-lifecycle-fixture $fixture_id")"
printf '%s\n' "$fixture_output" | tee "$evidence_dir/lifecycle-fixture.trace"

for expected in \
  "fixture.id=$fixture_id" \
  fixture.disable.admission_quiesced=1 \
  fixture.drain.fragment_outstanding=1 \
  fixture.drain.handoff_outstanding=1 \
  fixture.drain.input_obligations=2 \
  fixture.drain.terminal_intents=2 \
  fixture.drain.ledger_settlements=2 \
  fixture.drain.buffer_returns=2 \
  fixture.drain.outstanding_obligations=0 \
  fixture.generation.stale_completion_after_reenable=1 \
  fixture.generation.stale_timeout_after_reenable=1 \
  fixture.generation.stale_events_rejected=2 \
  fixture.generation.cross_generation_admissions=0 \
  fixture.generation.late_verdicts=0 \
  fixture.repeat.enable_disable_cycles=3 \
  fixture.fragment_contexts=0 \
  fixture.ingress_fqm_occupancy=0 \
  fixture.owner_fqm_occupancy=0 \
  fixture.fragment_context_debt=0 \
  fixture.handoff_credit_debt=0 \
  fixture.obligation_debt=0 \
  fixture.buffer_debt=0 \
  fixture.duplicate_settlements=0 \
  fixture.lost_buffers=0; do
  require_line "$fixture_output" "$expected"
done

drain_ms="$(field "$fixture_output" fixture.drain.elapsed_ms)"
[[ "$drain_ms" =~ ^[0-9]+$ && "$drain_ms" -le 2000 ]] ||
  fail "disable drain exceeded the 2000 ms Host fixture bound"

status_output="$(cli 'show product packet-graph')"
printf '%s\n' "$status_output" | tee "$evidence_dir/final-status.trace"
for expected in \
  graph.enabled=0 \
  graph.fragment_context_debt=0 \
  graph.handoff_credit_debt=0 \
  graph.obligation_debt=0 \
  graph.buffer_debt=0; do
  require_line "$status_output" "$expected"
done

echo "SAKAMOTO-175 Product VPP lifecycle contract: PASS"
echo "evidence=$evidence_dir"
