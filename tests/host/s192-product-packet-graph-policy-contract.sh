#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
graph_source="$repo_root/src/product/vpp/product_packet_graph.c"
graph_header="$repo_root/src/product/vpp/product_packet_graph.h"
host_source="$repo_root/src/product/vpp/product_packet_graph_host_evidence.c"

fail() {
  echo "SAKAMOTO-192 Product packet graph policy contract: FAIL: $*" >&2
  exit 1
}

[[ -f "$graph_source" && -f "$graph_header" && -f "$host_source" ]] ||
  fail "graph policy sources are missing"

# Keep this contract on the VPP-native graph seam.  Policy evaluation must not
# acquire an ABI, Rust/JNI, historical Snort, or alternate classifier input.
for forbidden in 'product_core.api' 'POLICY.EVALUATE' 'sucre-snort' \
  'SnortConfig' 'nfq_q_handle' 'jni.h' 'extern "C"'; do
  if grep -Fq "$forbidden" "$graph_source" "$graph_header" "$host_source"; then
    fail "forbidden dependency or historical policy path: $forbidden"
  fi
done

grep -q 'product_packet_graph_policy_stage' "$graph_header"
grep -q 'PRODUCT_PACKET_GRAPH_POLICY_STAGE_GATE' "$graph_header"
grep -q 'PRODUCT_PACKET_GRAPH_POLICY_STAGE_L4' "$graph_header"
grep -q 'PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT' "$graph_header"
grep -q 'PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP' "$graph_header"
grep -q 'product_packet_graph_set_policy_hints' "$graph_header"
grep -q 'product_packet_graph_get_policy_hints' "$graph_header"
grep -q 'product_l4_policy_view_t' "$graph_source"
grep -q 'product_l4_policy_evaluate' "$graph_source"
grep -q 'product_packet_graph_publish_policy_bundle' "$graph_header"
grep -q 'product_packet_graph_apply_policy_bundle' "$graph_header"
grep -q 'l4_policy_banks\[2\]' "$graph_source"
grep -q 'l4_policy_active_bank' "$graph_source"
grep -q 'l4_policy_bank_readers\[2\]' "$graph_source"
grep -q 'l4_policy_view_active' "$graph_source"
grep -q 'bundle->generation' "$graph_source"
grep -q 'bundle->revision' "$graph_source"
grep -q 'bundle->snapshot_hash' "$graph_source"

grep -q 'product-packet-owner-guard.*' "$graph_source" ||
  fail "owner guard node is missing"
grep -q 'PRODUCT_OWNER_GUARD_NEXT_POLICY' "$graph_source"
grep -q '\[PRODUCT_OWNER_GUARD_NEXT_POLICY\] = "product-packet-policy"' \
  "$graph_source"
grep -q '\.name = "product-packet-policy"' "$graph_source"
grep -q '\[PRODUCT_POLICY_NEXT_TERMINAL\] = "product-packet-terminal"' \
  "$graph_source"

stage_definition_count="$(grep -c '^product_packet_graph_policy_stage (' "$graph_source")"
[[ "$stage_definition_count" == 1 ]] ||
  fail "shared policy stage must have exactly one definition"
stage_call_count="$(grep -c 'product_packet_graph_policy_stage (&lease' "$graph_source")"
[[ "$stage_call_count" == 2 ]] ||
  fail "node and external paths must call the same policy stage"

policy_body="$(awk '
  /^product_packet_graph_policy_stage \(/ { in_stage = 1 }
  in_stage { print }
  in_stage && /^}/ { exit }
' "$graph_source")"
gate_line="$(printf '%s\n' "$policy_body" | grep -n \
  'product_packet_graph_policy_gate_drop' | head -n1 | cut -d: -f1)"
view_select_line="$(printf '%s\n' "$policy_body" | grep -n \
  'product_packet_graph_l4_policy_view_active' | head -n1 | cut -d: -f1)"
view_eval_line="$(printf '%s\n' "$policy_body" | grep -n \
  'product_packet_graph_l4_view_evaluate' | head -n1 | cut -d: -f1)"
legacy_label_line="$(printf '%s\n' "$policy_body" | grep -n \
  '^scalar_l4_evaluation:' | head -n1 | cut -d: -f1)"
legacy_eval_line="$(printf '%s\n' "$policy_body" | grep -n \
  'product_packet_graph_l4_match' | head -n1 | cut -d: -f1)"
[[ -n "$gate_line" && -n "$view_select_line" && -n "$view_eval_line" &&
   -n "$legacy_label_line" && -n "$legacy_eval_line" &&
   "$gate_line" -lt "$view_select_line" &&
   "$view_select_line" -lt "$view_eval_line" &&
   "$view_eval_line" -lt "$legacy_label_line" &&
   "$legacy_label_line" -lt "$legacy_eval_line" ]] ||
  fail "Gate must precede the shared L4 stage"
printf '%s\n' "$policy_body" | grep -q 'PRODUCT_PACKET_INTENT_DROP_RUNTIME' ||
  fail "policy stage does not own terminal DROP"
printf '%s\n' "$policy_body" | grep -q 'PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT' ||
  fail "policy stage has no PASS_NEXT outcome"
printf '%s\n' "$policy_body" | grep -q 'terminal_preserved' ||
  fail "policy stage can reopen a prior terminal intent"
printf '%s\n' "$policy_body" | grep -q \
  'product_packet_graph_l4_policy_view_active' ||
  fail "policy stage does not select the typed L4 view"
printf '%s\n' "$policy_body" | grep -q \
  'product_packet_graph_l4_view_evaluate' ||
  fail "policy stage does not call the shared typed matcher seam"
projection_body="$(awk '
  /^product_packet_graph_l4_packet_projection \(/ { in_projection = 1 }
  in_projection { print }
  in_projection && /^}/ { exit }
' "$graph_source")"
printf '%s\n' "$projection_body" | grep -q 'ports_available' ||
  fail "typed projection does not carry predicate-only L4 availability"
printf '%s\n' "$projection_body" | grep -q 'source_address + 12' ||
  fail "typed IPv4 source projection does not move PacketFacts tail bytes"
printf '%s\n' "$projection_body" | grep -q 'destination_address + 12' ||
  fail "typed IPv4 destination projection does not move PacketFacts tail bytes"
printf '%s\n' "$projection_body" | grep -q \
  'product_packet_graph_l4_direction_from_hints' ||
  fail "typed projection does not normalize Device Packet Direction centrally"
grep -q 'profile_id.*normalized Device Packet Direction' "$graph_header" ||
  fail "graph header does not define profile_id direction semantics"
grep -q 'interface_id.*adapter interface/provenance' "$graph_header" ||
  fail "graph header does not preserve interface provenance semantics"
grep -q 'profile_id.*adapter-normalized device direction' "$graph_source" ||
  fail "graph projection does not document profile_id as direction input"
if grep -Fq 'PRODUCT_VPN_PACKET_ORIGIN_TUN' "$graph_source" "$graph_header"; then
  fail "graph owns VPN provenance instead of consuming normalized hints"
fi
if printf '%s\n' "$projection_body" | grep -Eq \
    'interface_id[^\n]*direction|direction[^\n]*interface_id'; then
  fail "graph projection derives policy direction from interface provenance"
fi

bundle_fixture_body="$(awk '
  /^product_packet_graph_policy_fixture_cli \(/ { in_fixture = 1 }
  in_fixture { print }
  in_fixture && /^}/ { exit }
' "$graph_source")"
printf '%s\n' "$bundle_fixture_body" |
  grep -q 'product_packet_graph_publish_policy_bundle' ||
  fail "host policy fixture does not publish a typed bundle"
if printf '%s\n' "$bundle_fixture_body" |
  grep -Eq 'product_packet_graph_publish_(gate|l4)_policy'; then
  fail "host policy fixture still exercises only the legacy scalar publisher"
fi

# Completion belongs to the external submitter/adapter seam, never to policy
# evaluation or the host fixture node.
callback_count="$(grep -c 'graph->external_completion (' "$graph_source")"
[[ "$callback_count" == 1 ]] ||
  fail "external completion must have one graph call site"
if printf '%s\n' "$policy_body" | grep -q 'external_completion'; then
  fail "policy stage must not complete an adapter obligation"
fi
terminal_body="$(awk '
  /^VLIB_NODE_FN \(product_packet_terminal_node\)/ { in_terminal = 1 }
  in_terminal { print }
  in_terminal && /^}/ { exit }
' "$graph_source")"
if printf '%s\n' "$terminal_body" | grep -q 'external_completion'; then
  fail "terminal node must not complete an adapter obligation"
fi
external_body="$(awk '
  /^product_packet_graph_submit_external \(/ { in_submit = 1 }
  in_submit { print }
  in_submit && /^}/ { exit }
' "$graph_source")"
if printf '%s\n' "$external_body" | grep -Eq \
    'product_packet_graph_(policy_gate_drop|l4_policy_active|l4_match)'; then
  fail "external path retains a private policy evaluator"
fi
grep -q 'product_packet_graph_policy_stage' "$graph_source"
grep -q 'vnet_buffer_get_opaque' "$graph_source"
grep -q 'PRODUCT_POLICY_HINTS_MAGIC' "$graph_source"
grep -q 'product_packet_graph_ipv4_scalar_value' "$graph_source"
for offset in 12 13 14 15; do
  grep -q "address\\[$offset\\]" "$graph_source" ||
    fail "scalar IPv4 policy projection omits PacketFacts address[$offset]"
done

for script in "$host_source"; do
  [[ -f "$script" ]] || fail "missing host evidence source"
done
bash -n "$BASH_SOURCE"

artifact_root="${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host}"
runtime_dir="${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime-s192-$$}"
evidence_dir="${SAKAMOTO_S192_EVIDENCE_DIR:-/tmp/sakamoto-s192-product-packet-graph-$$}"
launcher="$repo_root/tools/product/run-host-vpp.sh"
stopper="$repo_root/tools/product/stop-host-vpp.sh"
vpp_pid=
mkdir -p -- "$evidence_dir"

# Source checks remain useful without a locally built VPP artifact.  CI or an
# acceptance run can set SAKAMOTO_S192_REQUIRE_RUNTIME=1 to require live VPP.
if [[ ! -x "$artifact_root/bin/vpp" ||
      ! -f "$artifact_root/lib/vpp_plugins/product_core_plugin.so" ]]; then
  if [[ "${SAKAMOTO_S192_REQUIRE_RUNTIME:-0}" == 1 ]]; then
    fail "missing Host VPP artifact; run tools/product/build-host-artifact.sh"
  fi
  echo "sakamoto S192 Product graph policy source contract: PASS"
  echo "runtime=SKIPPED (Host VPP artifact not present)"
  exit 0
fi

cleanup() {
  local status=$?
  set +e
  if [[ -n "$vpp_pid" ]] && kill -0 "$vpp_pid" 2>/dev/null; then
    PRODUCT_ARTIFACT_DIR="$artifact_root" \
      PRODUCT_RUNTIME_DIR="$runtime_dir" \
      "$stopper" >"$evidence_dir/stop.trace" 2>&1
    wait "$vpp_pid" 2>/dev/null
  fi
  set -e
  exit "$status"
}
trap cleanup EXIT

PRODUCT_ARTIFACT_DIR="$artifact_root" \
PRODUCT_RUNTIME_DIR="$runtime_dir" \
PRODUCT_GENERATION=192 PRODUCT_WORKER_COUNT=2 \
  "$launcher" >"$evidence_dir/vpp.trace" 2>&1 &
vpp_pid=$!
for _ in {1..200}; do
  [[ -S "$runtime_dir/cli.sock" ]] && break
  if ! kill -0 "$vpp_pid" 2>/dev/null; then
    cat "$evidence_dir/vpp.trace" >&2
    fail "Host VPP exited before its CLI socket became ready"
  fi
  sleep 0.05
done
[[ -S "$runtime_dir/cli.sock" ]] || fail "Host VPP CLI socket did not become ready"

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

def prompt():
    data = bytearray()
    while b"vpp# " not in data:
        chunk = client.recv(65536)
        if not chunk:
            raise RuntimeError("Host VPP CLI closed before prompt")
        data.extend(chunk)
        if len(data) > 4 * 1024 * 1024:
            raise RuntimeError("Host VPP CLI response exceeded 4 MiB")
    return bytes(data)

prompt()
client.sendall(command.encode("utf-8") + b"\n")
response = prompt()
client.close()
text = response.decode("utf-8", "replace")
text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text).replace("\r", "")
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
    fail "missing runtime evidence: $expected"
}

field() {
  local output="$1"
  local name="$2"
  printf '%s\n' "$output" |
    awk -F= -v name="$name" '$1 == name { print substr($0, index($0, "=") + 1); exit }'
}

count_line() {
  local output="$1"
  local line="$2"
  local expected="$3"
  local actual
  actual="$(printf '%s\n' "$output" | grep -Fc -- "$line" || true)"
  [[ "$actual" == "$expected" ]] ||
    fail "expected $expected lines matching $line, got $actual"
}

run_case() {
  local case_name="$1"
  local configure_output enable_output setup_output fixture_output status_output
  local runtime_output
  configure_output="$(cli 'product packet-graph configure workers 2 fixture s174-valid-dual-stack-v1')"
  require_line "$configure_output" 'graph.configure=ok'
  enable_output="$(cli 'product packet-graph enable')"
  require_line "$enable_output" 'graph.enable=ok'
  setup_output="$(cli "product packet-graph run-policy-fixture $case_name")"
  require_line "$setup_output" "policy.fixture=$case_name"
  fixture_output="$(cli 'product packet-graph run-fixture s174-valid-dual-stack-v1')"
  require_line "$fixture_output" 'fixture.vector_count=8'
  status_output="$(cli 'show product packet-graph')"
  require_line "$status_output" 'graph.policy_stage_evaluations=8'
  require_line "$status_output" 'graph.policy_vectors=8'
  require_line "$status_output" 'graph.terminal_intents=8'
  require_line "$status_output" 'graph.ledger_settlements=8'
  require_line "$status_output" 'graph.buffer_returns=8'
  [[ "$(field "$status_output" graph.policy_last_drop_completion_attempts)" == 1 ||
     "$case_name" != gate-drop && "$case_name" != l4-drop ]] ||
    fail "$case_name policy drop did not retain one completion attempt"

  case "$case_name" in
    gate-drop)
      count_line "$fixture_output" 'terminal_intent=drop-runtime' 8
      require_line "$status_output" 'graph.policy_gate_evaluations=8'
      require_line "$status_output" 'graph.policy_l4_evaluations=0'
      require_line "$status_output" 'graph.policy_stage_pass_next=0'
      require_line "$status_output" 'graph.policy_stage_drops=8'
      require_line "$status_output" 'graph.policy_drop_records=8'
      require_line "$status_output" 'graph.l4_policy_view_active=1'
      require_line "$status_output" 'graph.l4_policy_view_rule_count=0'
      require_line "$status_output" 'graph.l4_policy_view_match_records=0'
      ;;
    l4-drop)
      count_line "$fixture_output" 'terminal_intent=drop-runtime' 1
      count_line "$fixture_output" 'terminal_intent=pass-adapter' 7
      require_line "$status_output" 'graph.policy_gate_evaluations=0'
      require_line "$status_output" 'graph.policy_l4_evaluations=8'
      require_line "$status_output" 'graph.policy_stage_pass_next=7'
      require_line "$status_output" 'graph.policy_stage_drops=1'
      require_line "$status_output" 'graph.policy_drop_records=1'
      require_line "$status_output" 'graph.l4_match_records=1'
      require_line "$status_output" 'graph.l4_policy_view_active=1'
      require_line "$status_output" 'graph.l4_policy_view_rule_count=1'
      require_line "$status_output" 'graph.l4_policy_view_match_records=1'
      require_line "$status_output" 'graph.l4_policy_view_no_match_records=7'
      require_line "$status_output" 'graph.l4_policy_view_last_winner_rank=1'
      require_line "$status_output" 'graph.l4_policy_view_last_rule_id=192002'
      ;;
    l4-allow)
      count_line "$fixture_output" 'terminal_intent=drop-runtime' 0
      count_line "$fixture_output" 'terminal_intent=pass-adapter' 8
      require_line "$status_output" 'graph.policy_gate_evaluations=0'
      require_line "$status_output" 'graph.policy_l4_evaluations=8'
      require_line "$status_output" 'graph.policy_stage_pass_next=8'
      require_line "$status_output" 'graph.policy_stage_drops=0'
      require_line "$status_output" 'graph.policy_drop_records=0'
      require_line "$status_output" 'graph.l4_match_records=1'
      require_line "$status_output" 'graph.l4_policy_view_active=1'
      require_line "$status_output" 'graph.l4_policy_view_rule_count=1'
      require_line "$status_output" 'graph.l4_policy_view_match_records=1'
      require_line "$status_output" 'graph.l4_policy_view_no_match_records=7'
      require_line "$status_output" 'graph.l4_policy_view_last_winner_rank=1'
      require_line "$status_output" 'graph.l4_policy_view_last_rule_id=192002'
      ;;
    l4-no-match)
      count_line "$fixture_output" 'terminal_intent=drop-runtime' 0
      count_line "$fixture_output" 'terminal_intent=pass-adapter' 8
      require_line "$status_output" 'graph.policy_gate_evaluations=0'
      require_line "$status_output" 'graph.policy_l4_evaluations=8'
      require_line "$status_output" 'graph.policy_stage_pass_next=8'
      require_line "$status_output" 'graph.policy_stage_drops=0'
      require_line "$status_output" 'graph.policy_drop_records=0'
      require_line "$status_output" 'graph.l4_match_records=0'
      require_line "$status_output" 'graph.l4_policy_view_active=1'
      require_line "$status_output" 'graph.l4_policy_view_rule_count=1'
      require_line "$status_output" 'graph.l4_policy_view_match_records=0'
      require_line "$status_output" 'graph.l4_policy_view_no_match_records=8'
      ;;
    empty)
      count_line "$fixture_output" 'terminal_intent=drop-runtime' 0
      count_line "$fixture_output" 'terminal_intent=pass-adapter' 8
      require_line "$status_output" 'graph.policy_gate_evaluations=0'
      require_line "$status_output" 'graph.policy_l4_evaluations=8'
      require_line "$status_output" 'graph.policy_stage_pass_next=8'
      require_line "$status_output" 'graph.policy_stage_drops=0'
      require_line "$status_output" 'graph.policy_drop_records=0'
      require_line "$status_output" 'graph.l4_policy_view_active=1'
      require_line "$status_output" 'graph.l4_policy_view_rule_count=0'
      require_line "$status_output" 'graph.l4_policy_view_match_records=0'
      require_line "$status_output" 'graph.l4_policy_view_no_match_records=8'
      require_line "$status_output" 'graph.l4_policy_view_last_no_match_reason=6'
      ;;
    l4-matrix)
      count_line "$fixture_output" 'terminal_intent=drop-runtime' 1
      count_line "$fixture_output" 'terminal_intent=pass-adapter' 7
      require_line "$status_output" 'graph.policy_gate_evaluations=0'
      require_line "$status_output" 'graph.policy_l4_evaluations=8'
      require_line "$status_output" 'graph.policy_stage_pass_next=7'
      require_line "$status_output" 'graph.policy_stage_drops=1'
      require_line "$status_output" 'graph.policy_drop_records=1'
      require_line "$status_output" 'graph.l4_match_records=4'
      require_line "$status_output" 'graph.l4_policy_view_active=1'
      require_line "$status_output" 'graph.l4_policy_view_rule_count=5'
      require_line "$status_output" 'graph.l4_policy_view_match_records=4'
      require_line "$status_output" 'graph.l4_policy_view_no_match_records=4'
      require_line "$status_output" 'graph.l4_policy_view_last_winner_rank=4'
      require_line "$status_output" 'graph.l4_policy_view_last_candidate_count=5'
      require_line "$status_output" 'graph.l4_policy_view_last_rule_id=192204'
      ;;
    clear)
      count_line "$fixture_output" 'terminal_intent=drop-runtime' 0
      count_line "$fixture_output" 'terminal_intent=pass-adapter' 8
      require_line "$status_output" 'graph.policy_gate_evaluations=0'
      require_line "$status_output" 'graph.policy_l4_evaluations=0'
      require_line "$status_output" 'graph.policy_stage_pass_next=8'
      require_line "$status_output" 'graph.policy_stage_drops=0'
      require_line "$status_output" 'graph.policy_drop_records=0'
      require_line "$status_output" 'graph.l4_policy_view_active=0'
      ;;
    *) fail "unknown policy case $case_name" ;;
  esac
  runtime_output="$(cli 'show runtime')"
  printf '%s\n' "$runtime_output" |
    awk '$1 == "product-packet-policy" && $3 + 0 > 0 && $4 + 0 > 0 { found = 1 }
         END { exit found ? 0 : 1 }' ||
    fail "product-packet-policy has no real runtime calls/vectors"
  require_line "$(cli 'product packet-graph disable')" 'graph.disable=ok'
}

for case_name in gate-drop l4-drop l4-allow l4-no-match empty l4-matrix clear; do
  run_case "$case_name"
done

echo "sakamoto S192 Product graph policy runtime contract: PASS"
echo "evidence=$evidence_dir"
