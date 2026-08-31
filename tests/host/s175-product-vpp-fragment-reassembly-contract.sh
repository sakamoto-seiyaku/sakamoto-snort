#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-175 public-seam RED for Product Fragment Steering through the
# pinned VPP IPv4/IPv6 full-reassembly custom nodes. The Host-only fixture
# supplies deterministic fragments; ownership, reassembly, final-owner
# transition, and terminal settlement remain in the installed VLIB graph.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host-s175-patched}"
runtime_dir="${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime-s175-fragment-$$}"
evidence_dir="${SAKAMOTO_S175_FRAGMENT_EVIDENCE_DIR:-/tmp/sakamoto-s175-product-vpp-fragment-$$}"
launcher="$repo_root/tools/product/run-host-vpp.sh"
stopper="$repo_root/tools/product/stop-host-vpp.sh"
residue="$repo_root/tools/product/host-residue-check.sh"
fixture_id=s175-official-full-reassembly-v1
vpp_pid=

mkdir -p -- "$evidence_dir"

fail() {
  echo "SAKAMOTO-175 Product VPP fragment contract: FAIL: $*" >&2
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
client.settimeout(10.0)
client.connect(path)

def receive_prompt():
    data = bytearray()
    while b"vpp# " not in data:
        chunk = client.recv(65536)
        if not chunk:
            raise RuntimeError("Product VPP CLI closed before prompt")
        data.extend(chunk)
        if len(data) > 4 * 1024 * 1024:
            raise RuntimeError("Product VPP CLI response exceeded 4 MiB")
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
    fail "missing fragment evidence: $expected"
}

field() {
  local output="$1"
  local name="$2"
  printf '%s\n' "$output" |
    awk -F= -v name="$name" '$1 == name { print substr($0, index($0, "=") + 1); exit }'
}

require_settled() {
  local output="$1"
  local vector="$2"
  local obligations="$3"
  local prefix="vector.$vector"

  require_line "$output" "$prefix.input_obligations=$obligations"
  require_line "$output" "$prefix.terminal_intents=$obligations"
  require_line "$output" "$prefix.ledger_settlements=$obligations"
  require_line "$output" "$prefix.buffer_returns=$obligations"
  require_line "$output" "$prefix.outstanding_obligations=0"
  require_line "$output" "$prefix.duplicate_settlements=0"
  require_line "$output" "$prefix.lost_buffers=0"
}

require_success() {
  local output="$1"
  local vector="$2"
  local family="$3"
  local obligations="$4"
  local arrival_order="${5:-}"
  local prefix="vector.$vector"
  local fragment_worker initial_owner final_owner survivor final_buffer

  require_line "$output" "$prefix.family=$family"
  require_line "$output" "$prefix.reassembly_engine=${family}-full-reassembly-custom"
  require_line "$output" "$prefix.fragment_worker_count=1"
  if [[ -n "$arrival_order" ]]; then
    require_line "$output" "$prefix.arrival_order=$arrival_order"
  fi
  require_line "$output" "$prefix.runtime_disposition=policy-ready"
  require_line "$output" "$prefix.reassembled_packets=1"
  require_line "$output" "$prefix.final_owner_transitions=1"
  require_line "$output" "$prefix.corrective_handoffs=0"
  require_settled "$output" "$vector" "$obligations"

  fragment_worker="$(field "$output" "$prefix.fragment_worker")"
  initial_owner="$(field "$output" "$prefix.initial_fragment_final_owner")"
  final_owner="$(field "$output" "$prefix.final_owner")"
  survivor="$(field "$output" "$prefix.reassembly_survivor_buffer_index")"
  final_buffer="$(field "$output" "$prefix.final_owner_buffer_index")"
  [[ "$fragment_worker" =~ ^[0-9]+$ && "$final_owner" =~ ^[0-9]+$ &&
     "$fragment_worker" != "$final_owner" ]] ||
    fail "$vector did not execute a distinct reassembly-to-final-owner transition"
  [[ "$initial_owner" == "$final_owner" ]] ||
    fail "$vector did not retain the initial fragment's final owner"
  [[ "$survivor" =~ ^[0-9]+$ && "$survivor" == "$final_buffer" ]] ||
    fail "$vector did not transfer the official reassembly survivor by buffer identity"
}

require_failure() {
  local output="$1"
  local vector="$2"
  local family="$3"
  local obligations="$4"
  local reason="$5"
  local prefix="vector.$vector"

  require_line "$output" "$prefix.family=$family"
  require_line "$output" "$prefix.reassembly_engine=${family}-full-reassembly-custom"
  require_line "$output" "$prefix.fragment_worker_count=1"
  require_line "$output" "$prefix.runtime_disposition=drop-runtime"
  require_line "$output" "$prefix.runtime_drop_reason=$reason"
  require_line "$output" "$prefix.policy_verdicts=0"
  require_line "$output" "$prefix.policy_ready_packets=0"
  require_line "$output" "$prefix.reassembled_packets=0"
  require_line "$output" "$prefix.final_owner_transitions=0"
  require_line "$output" "$prefix.corrective_handoffs=0"
  require_settled "$output" "$vector" "$obligations"
}

configure_output="$(cli "product packet-graph configure workers 2 fixture $fixture_id")"
require_line "$configure_output" "graph.configure=ok"
enable_output="$(cli 'product packet-graph enable')"
require_line "$enable_output" "graph.enable=ok"

fixture_output="$(cli "product packet-graph run-fragment-fixture $fixture_id")"
printf '%s\n' "$fixture_output" | tee "$evidence_dir/fragment-fixture.trace"
require_line "$fixture_output" "fixture.id=$fixture_id"
require_line "$fixture_output" "fixture.vector_count=12"
require_line "$fixture_output" "fixture.official_ip4_full_reassembly=1"
require_line "$fixture_output" "fixture.official_ip6_full_reassembly=1"

require_success "$fixture_output" ip4-out-of-order ip4 3 out-of-order
require_success "$fixture_output" ip6-out-of-order ip6 3 out-of-order

for family in ip4 ip6; do
  require_success "$fixture_output" "$family-exact-duplicate" "$family" 4
  require_line "$fixture_output" "vector.$family-exact-duplicate.exact_duplicates=1"

  require_failure "$fixture_output" "$family-same-range-byte-conflict" \
    "$family" 2 fragment-conflict
  require_line "$fixture_output" \
    "vector.$family-same-range-byte-conflict.conflict_kind=same-range-different-byte"

  require_failure "$fixture_output" "$family-partial-overlap" \
    "$family" 2 fragment-conflict
  require_line "$fixture_output" \
    "vector.$family-partial-overlap.conflict_kind=partial-overlap"

  require_failure "$fixture_output" "$family-timeout" \
    "$family" 2 fragment-timeout
  require_failure "$fixture_output" "$family-capacity" \
    "$family" 4 fragment-capacity
done

for expected in \
  fixture.fragment_context_debt=0 \
  fixture.obligation_debt=0 \
  fixture.buffer_debt=0 \
  fixture.duplicate_settlements=0 \
  fixture.lost_buffers=0; do
  require_line "$fixture_output" "$expected"
done

disable_output="$(cli 'product packet-graph disable')"
printf '%s\n' "$disable_output" | tee "$evidence_dir/disable.trace"
require_line "$disable_output" "graph.disable=ok"
require_line "$disable_output" "graph.buffer_debt=0"
require_line "$disable_output" "graph.handoff_credit_debt=0"
require_line "$disable_output" "graph.obligation_debt=0"

echo "SAKAMOTO-175 Product VPP fragment contract: PASS"
echo "evidence=$evidence_dir"
