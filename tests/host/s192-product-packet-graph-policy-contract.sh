#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
graph_source="$repo_root/src/product/vpp/product_packet_graph.c"
graph_header="$repo_root/src/product/vpp/product_packet_graph.h"
host_source="$repo_root/src/product/vpp/product_packet_graph_host_evidence.c"
fixture_source="$repo_root/src/product/vpp/product_packet_graph_host_fixtures.inc"
abi_header="$repo_root/src/product/include/sakamoto_product_abi.h"
api_source="$repo_root/src/product/vpp/product_core.api"
plugin_source="$repo_root/src/product/vpp/product_core_plugin.c"
vapi_source="$repo_root/src/product/native/sakamoto_product_vapi.c"
rust_source="$repo_root/crates/product-core/src/lib.rs"
jni_source="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
java_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
java_service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"

fail() {
  echo "SAKAMOTO-192 Product packet graph policy contract: FAIL: $*" >&2
  exit 1
}

[[ -f "$graph_source" && -f "$graph_header" && -f "$host_source" && -f "$fixture_source" &&
   -f "$abi_header" && -f "$api_source" && -f "$plugin_source" &&
   -f "$vapi_source" && -f "$rust_source" && -f "$jni_source" &&
   -f "$java_status" && -f "$java_service" ]] ||
  fail "graph policy sources are missing"

# Keep this contract on the VPP-native graph seam.  Policy evaluation must not
# acquire an ABI, Rust/JNI, historical Snort, or alternate classifier input.
for forbidden in 'product_core.api' 'POLICY.EVALUATE' 'sucre-snort' \
  'SnortConfig' 'nfq_q_handle' 'jni.h' 'extern "C"'; do
  if grep -Fq "$forbidden" "$graph_source" "$graph_header" "$host_source" "$fixture_source"; then
    fail "forbidden dependency or historical policy path: $forbidden"
  fi
done

grep -q 'product_packet_graph_policy_stage' "$graph_header"
grep -q 'PRODUCT_PACKET_GRAPH_POLICY_STAGE_GATE' "$graph_header"
grep -q 'PRODUCT_PACKET_GRAPH_POLICY_STAGE_L4' "$graph_header"
grep -q 'PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT' "$graph_header"
grep -q 'PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP' "$graph_header"
grep -q 'product_packet_graph_set_platform_facts' "$graph_header"
grep -q 'product_packet_graph_get_platform_facts' "$graph_header"
grep -q 'product_l4_policy_view_t' "$graph_source"
grep -q 'product_l4_policy_evaluate' "$graph_source"
grep -q 'PRODUCT_PACKET_GRAPH_L4_WINNER_RULE' "$graph_source"
grep -q 'evaluation->winner = PRODUCT_PACKET_GRAPH_L4_WINNER_RULE' \
  "$graph_source"
grep -q 'PRODUCT_PACKET_GRAPH_L4_WINNER_RULE);' "$graph_source"
grep -q 'product_packet_graph_publish_policy_bundle' "$graph_header"
grep -q 'product_packet_graph_apply_policy_bundle' "$graph_header"
grep -q 'l4_policy_banks\[2\]' "$graph_source"
grep -q 'l4_policy_active_bank' "$graph_source"
grep -q 'l4_policy_bank_readers\[2\]' "$graph_source"
grep -q 'l4_policy_view_active' "$graph_source"
grep -q 'bundle->generation' "$graph_source"
grep -q 'bundle->revision' "$graph_source"
grep -q 'bundle->snapshot_hash' "$graph_source"
grep -q 'bundle->l4_rule_count == 1' "$graph_source"
grep -q 'status->view_rule_count != 1' "$graph_source"
grep -q 'PRODUCT_PACKET_GRAPH_GATE_TABLE_MAX_ENTRIES' "$graph_header"
grep -q 'product_packet_graph_gate_table_t' "$graph_header"
grep -q 'gate_entries' "$graph_header"
grep -q 'gate_entry_count' "$graph_header"
grep -q 'gate_table_last_match_rule_id' "$graph_source"
grep -q 'gate_table_last_winner_rank' "$graph_source"
grep -q 'gate_table_last_no_match_reason' "$graph_source"
grep -q 'gate_table_last_candidate_count' "$graph_source"
grep -q 'gate_table_last_probes' "$graph_source"
grep -q 'active_entry_count' "$graph_source"
grep -q '#include "product_flow_entry.h"' "$graph_source" ||
  fail "graph does not consume the bounded FlowEntry seam"
grep -q 'flow_pools\[PRODUCT_GRAPH_WORKERS\]' "$graph_source" ||
  fail "graph does not own one fixed FlowEntry pool per worker"
for flow_symbol in product_flow_runtime_create \
  product_flow_policy_identity_t product_flow_entry_observe \
  product_flow_entry_set_decision product_flow_runtime_flush \
  product_packet_graph_flow_status; do
  grep -q "$flow_symbol" "$graph_source" "$graph_header" ||
    fail "graph FlowEntry integration omits $flow_symbol"
done
for flow_status in flow_allocation_count flow_reuse_count \
  flow_early_drop_count flow_capacity_rejection_count \
  flow_revision_invalidation_count flow_revision_mismatch_count \
  flow_flush_count; do
  grep -q "$flow_status" "$graph_source" "$graph_header" "$fixture_source" ||
    fail "graph FlowEntry status omits $flow_status"
done
for flow_fixture_token in lazy_revision_ok flow_revision_invalidation_count \
  flow_active_entries flow_early_drop_count; do
  grep -q "$flow_fixture_token" "$fixture_source" ||
    fail "Host graph fixture omits FlowEntry evidence: $flow_fixture_token"
done
grep -q 'flow_active_snapshot_hash' "$graph_source" "$graph_header" ||
  fail "graph FlowEntry cache is not bound to a publication snapshot hash"
if grep -Fq 'gate_claim_count > 1' "$plugin_source"; then
  fail "typed GateTable handler still rejects multiple enabled Gate entries"
fi
# The retired Gate authoring API is not a Product source writer.
# S216 replaces numeric unknown sentinels and the mixed hints overlay.
grep -q 'metadata.obligation.queue_generation != generation' "$graph_source" ||
  fail "platform facts lack full generation validation"
grep -q 'PRODUCT_PLATFORM_UID_KNOWN' "$graph_source"
grep -q 'PRODUCT_PLATFORM_IFINDEX_KNOWN' "$graph_source"
grep -q 'PRODUCT_PLATFORM_CONTEXT_KNOWN' "$graph_source"

grep -q 'product-packet-owner-guard.*' "$graph_source" ||
  fail "owner guard node is missing"
grep -q 'PRODUCT_OWNER_GUARD_NEXT_POLICY' "$graph_source"
grep -q '\[PRODUCT_OWNER_GUARD_NEXT_POLICY\] = "product-packet-policy"' \
  "$graph_source"
grep -q '\.name = "product-packet-policy"' "$graph_source"
grep -q '\[PRODUCT_POLICY_NEXT_CONSUMER\] = "product-flow-consumer"' \
  "$graph_source"
grep -q '\[PRODUCT_CONSUMER_NEXT_TERMINAL\] = "product-packet-terminal"' \
  "$graph_source"
grep -q '\[PRODUCT_CONSUMER_NEXT_VPN_EGRESS\] = "product-vpn-egress"' \
  "$graph_source"

stage_definition_count="$(grep -c '^product_packet_graph_policy_stage (' "$graph_source")"
[[ "$stage_definition_count" == 1 ]] ||
  fail "shared policy stage must have exactly one definition"
node_stage_call_count="$(awk '
  /^VLIB_NODE_FN \(product_packet_policy_node\)/ { in_node = 1 }
  in_node { print }
  in_node && /^}/ { exit }
' "$graph_source" | grep -c 'product_packet_graph_policy_on_owner (' || true)"
external_stage_call_count="$(awk '
  /^product_packet_graph_submit_external \(/ { in_submit = 1 }
  in_submit { print }
  in_submit && /^}/ { exit }
' "$graph_source" | grep -c 'product_packet_graph_policy_on_owner (' || true)"
# Product and Host evidence have separate preprocessor branches at this seam.
[[ ( "$node_stage_call_count" == 1 || "$node_stage_call_count" == 2 )
   && "$external_stage_call_count" == 0 ]] ||
  fail "policy belongs to the real node; external submit must only schedule it"

policy_body="$(awk '
  /^product_packet_graph_policy_stage_snapshot \(/ { in_stage = 1 }
  in_stage { print }
  in_stage && /^}/ { exit }
' "$graph_source")"
if printf '%s\n' "$policy_body" | grep -q 'product_packet_graph_policy_gate_drop'; then
  fail "retired Gate precedence remains in the packet path"
fi
printf '%s\n' "$policy_body" | grep -q 'PRODUCT_PACKET_INTENT_DROP_RUNTIME' ||
  fail "policy stage does not own terminal DROP"
printf '%s\n' "$policy_body" | grep -q 'PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT' ||
  fail "policy stage has no PASS_NEXT outcome"
printf '%s\n' "$policy_body" | grep -q 'terminal_preserved' ||
  fail "policy stage can reopen a prior terminal intent"
printf '%s\n' "$policy_body" | grep -q \
  'product_packet_graph_l4_view_evaluate' ||
  fail "policy stage does not call the shared typed matcher seam"
# S209 binds once instead of retrying independent Gate/L4 acquisitions.
for identity in generation revision snapshot_hash; do
  printf '%s\n' "$policy_body" | grep -q "evaluation->$identity = snapshot->identity.$identity" ||
    fail "policy stage does not consume the acquired $identity"
done
python3 - "$graph_source" <<'PY_SNAPSHOT'
from pathlib import Path
import sys
s=Path(sys.argv[1]).read_text()
body=s.split('static product_packet_result_t\nproduct_packet_graph_policy_on_owner (',1)[1].split('\nint\nproduct_packet_graph_submit_external',1)[0]
assert body.index('product_policy_snapshot_acquire') < body.index('product_packet_graph_flow_observe') < body.index('product_packet_graph_policy_stage_snapshot') < body.rindex('product_packet_graph_flow_observe') < body.index('product_policy_snapshot_release')
assert 'if (post_flow)' in body
assert 'early.evaluation == PRODUCT_L4_POLICY_EVALUATION_NO_MATCH' in body
assert 'result == PRODUCT_PACKET_OK && !post_flow' in body
assert 'PRODUCT_L4_POLICY_POSITION_PRE' in body and 'PRODUCT_L4_POLICY_POSITION_POST' in body
assert 'lease->terminal_intent == PRODUCT_PACKET_INTENT_NONE' in body
assert 'product_flow_entry_publish_revision' not in s
assert 'product_packet_graph_l4_match (' not in s
assert 'product_packet_graph_policy_gate_drop' not in s
assert 'gate_table;' not in s
PY_SNAPSHOT
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
  'product_packet_graph_l4_direction_from_platform' ||
  fail "typed projection does not normalize Device Packet Direction centrally"
grep -q 'platform->direction' "$graph_source" ||
  fail "graph does not consume typed device direction"
if printf '%s\n' "$projection_body" | grep -Eq 'queue_id|origin_lane|packet_id|profile_id'; then
  fail "policy projection interprets adapter completion ownership"
fi

bundle_fixture_body="$(awk '
  /^product_packet_graph_policy_fixture_cli \(/ { in_fixture = 1 }
  in_fixture { print }
  in_fixture && /^}/ { exit }
' "$fixture_source")"
printf '%s\n' "$bundle_fixture_body" |
  grep -q 'product_packet_graph_publish_policy_bundle' ||
  fail "host policy fixture does not publish a typed bundle"
if printf '%s\n' "$bundle_fixture_body" |
  grep -Eq 'product_packet_graph_publish_(gate|l4)_policy'; then
  fail "host policy fixture still exercises only the legacy scalar publisher"
fi

# Completion belongs to the external submitter/adapter seam, never to policy
# evaluation or the host fixture node.
completion_body="$(awk '
  /^VLIB_NODE_FN \(product_packet_origin_completion_node\)/ { in_completion = 1 }
  in_completion { print }
  in_completion && /^}/ { exit }
' "$graph_source")"
for endpoint in product_root_nfqueue_complete_from_graph product_vpn_tun_complete_from_graph; do
  callback_count="$(grep -Ec "$endpoint[[:space:]]*\\(" "$graph_source" || true)"
  [[ "$callback_count" == 1 ]] ||
    fail "typed adapter endpoint must have one graph call site: $endpoint"
  printf '%s\n' "$completion_body" | grep -Fq "$endpoint" ||
    fail "adapter completion must run only at Origin: $endpoint"
done
printf '%s\n' "$completion_body" | grep -Fq 'switch (completion.obligation.kind)' ||
  fail "immutable adapter obligation must select completion endpoint"
if grep -q 'graph->external_completion' "$graph_source"; then
  fail "mutable global callback must not redirect typed adapter completion"
fi
if printf '%s\n' "$policy_body" | grep -Eq 'external_completion|complete_from_graph'; then
  fail "policy stage must not complete an adapter obligation"
fi
terminal_body="$(awk '
  /^VLIB_NODE_FN \(product_packet_terminal_node\)/ { in_terminal = 1 }
  in_terminal { print }
  in_terminal && /^}/ { exit }
' "$graph_source")"
if printf '%s\n' "$terminal_body" | grep -Eq 'external_completion|complete_from_graph'; then
  fail "terminal must publish Completion Frame, not call the adapter"
fi
grep -q 'VLIB_NODE_FN (product_packet_origin_completion_node)' "$graph_source"
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
grep -q 'product_buffer_platform_metadata_t' "$graph_source"
grep -q 'metadata.obligation.queue_generation' "$graph_source"
grep -q 'product_packet_graph_l4_packet_projection' "$graph_source"
for status_field in \
  'typed_match_policy_key' 'typed_match_probe_key' \
  'last_evaluation_probe_key'; do
  grep -Fq "$status_field" "$graph_header" ||
    fail "graph status omits evidence key: $status_field"
done
for status_field in \
  'policy_l4_typed_match_policy_key' 'policy_l4_typed_match_probe_key' \
  'policy_l4_last_evaluation_probe_key'; do
  for source in "$abi_header" "$api_source" "$plugin_source" "$vapi_source" \
    "$rust_source" "$jni_source"; do
    grep -Fq "$status_field" "$source" ||
      fail "status key is not wired through $(basename "$source"): $status_field"
  done
done
grep -Fq 'STATUS_ASSOCIATION_VALUE_COUNT = 3' "$jni_source" ||
  fail "JNI status wire count does not reserve the three evidence keys"
for java_field in policyL4TypedMatchPolicyKey policyL4TypedMatchProbeKey \
  policyL4LastEvaluationProbeKey; do
  grep -Fq "$java_field" "$java_status" ||
    fail "Java status key is missing: $java_field"
done
# A later background/no-match packet may legitimately advance the global
# evaluation key after a target UDP match.  The writer therefore requires both
# bounded keys to be present, exact target rule/tuple identity (including
# ports), and a per-probe or first-probe fenced counter transition rather than
# incorrectly requiring the target to remain the last global evaluation.
grep -Fq 'status.policyL4TypedMatchProbeKey == 0L' "$java_service" ||
  fail "S192 writer does not require a nonzero typed match key"
grep -Fq 'status.policyL4LastEvaluationProbeKey == 0L' "$java_service" ||
  fail "S192 writer does not require a nonzero evaluation key"
grep -Fq 's192ProbePortsMatch' "$java_service" ||
  fail "S192 writer does not exact-compare target ports"
grep -Fq 'counters.probeEpochFallbackCandidate' "$java_service" ||
  fail "S192 writer does not fence epoch fallback to a new probe"
for association_symbol in \
  'l4_typed_match_policy_key' 'l4_typed_match_probe_key' \
  'l4_typed_match_subject_key' 'PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_PROBE' \
  'PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_SUBJECT' \
  'PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_UNRELATED'; do
  grep -q "$association_symbol" "$graph_source" ||
    fail "graph lacks bounded typed-match evidence association: $association_symbol"
done
grep -q 'product_packet_graph_policy_association_fixture_cli' "$fixture_source" ||
  fail "host graph lacks typed-match evidence association fixture"
grep -q 'run-policy-association-fixture' "$host_source" ||
  fail "host evidence source does not expose association fixture command"
grep -q 'product_packet_graph_gate_table_fixture_cli' "$fixture_source" ||
  fail "host graph lacks bounded GateTable fixture"
grep -q 'run-gate-table-fixture' "$host_source" ||
  fail "host evidence source does not expose GateTable fixture command"
for gate_vector in drop_ok range_ok ipv6_ok address_ok ifindex_ok \
  unavailable_ok unknown_uid_ok wildcard_ok unknown_context_ok; do
  grep -q "$gate_vector" "$fixture_source" ||
    fail "GateTable fixture omits vector: $gate_vector"
done
grep -q 'gate_table_last_match_action' "$graph_source"
grep -q 'PRODUCT_L4_POLICY_IFINDEX_ANY' "$repo_root/src/product/vpp/product_rule_config.c"
# The shared typed projection above replaces the former scalar address reader.


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

require_flow_common() {
  local output="$1"
  require_line "$output" 'graph.flow_worker_count=2'
  require_line "$output" 'graph.flow_max_entries_per_worker=1024'
  [[ "$(field "$output" graph.flow_active_generation)" == \
     "$(field "$output" graph.generation)" ]] ||
    fail "FlowEntry status is not tied to the active graph generation"
  require_line "$output" 'graph.flow_wrong_owner_count=0'
  require_line "$output" 'graph.flow_capacity_rejection_count=0'
}

require_flow_cleared() {
  local output="$1"
  local flush_count
  require_line "$output" 'graph.flow_active_entries=0'
  require_line "$output" 'graph.flow_active_revision=0'
  require_line "$output" 'graph.flow_active_snapshot_hash=0'
  flush_count="$(field "$output" graph.flow_flush_count)"
  [[ "$flush_count" =~ ^[0-9]+$ && "$flush_count" -gt 0 ]] ||
    fail "FlowEntry pools were not flushed at the lifecycle boundary"
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
  require_flow_common "$status_output"
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
      require_line "$status_output" 'graph.flow_active_entries=0'
      require_line "$status_output" 'graph.flow_allocation_count=0'
      require_line "$status_output" 'graph.flow_reuse_count=0'
      require_line "$status_output" 'graph.flow_early_drop_count=8'
      require_line "$status_output" 'graph.flow_revision_invalidation_count=0'
      require_line "$status_output" 'graph.flow_revision_mismatch_count=0'
      require_line "$status_output" 'graph.flow_unavailable_count=0'
      require_line "$status_output" 'graph.flow_pass_next_count=0'
      require_line "$status_output" 'graph.flow_drop_count=8'
      require_line "$status_output" 'graph.flow_flush_count=0'
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
      require_line "$status_output" 'graph.flow_active_entries=4'
      require_line "$status_output" 'graph.flow_allocation_count=4'
      require_line "$status_output" 'graph.flow_reuse_count=3'
      require_line "$status_output" 'graph.flow_early_drop_count=1'
      require_line "$status_output" 'graph.flow_revision_invalidation_count=0'
      require_line "$status_output" 'graph.flow_revision_mismatch_count=0'
      require_line "$status_output" 'graph.flow_unavailable_count=0'
      require_line "$status_output" 'graph.flow_pass_next_count=7'
      require_line "$status_output" 'graph.flow_drop_count=1'
      require_line "$status_output" 'graph.flow_flush_count=0'
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
      require_line "$status_output" 'graph.flow_active_entries=4'
      require_line "$status_output" 'graph.flow_allocation_count=4'
      require_line "$status_output" 'graph.flow_reuse_count=4'
      require_line "$status_output" 'graph.flow_early_drop_count=0'
      require_line "$status_output" 'graph.flow_revision_invalidation_count=0'
      require_line "$status_output" 'graph.flow_revision_mismatch_count=0'
      require_line "$status_output" 'graph.flow_unavailable_count=0'
      require_line "$status_output" 'graph.flow_pass_next_count=8'
      require_line "$status_output" 'graph.flow_drop_count=0'
      require_line "$status_output" 'graph.flow_flush_count=0'
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
      require_line "$status_output" 'graph.flow_active_entries=4'
      require_line "$status_output" 'graph.flow_allocation_count=4'
      require_line "$status_output" 'graph.flow_reuse_count=4'
      require_line "$status_output" 'graph.flow_early_drop_count=0'
      require_line "$status_output" 'graph.flow_revision_invalidation_count=0'
      require_line "$status_output" 'graph.flow_revision_mismatch_count=0'
      require_line "$status_output" 'graph.flow_unavailable_count=0'
      require_line "$status_output" 'graph.flow_pass_next_count=8'
      require_line "$status_output" 'graph.flow_drop_count=0'
      require_line "$status_output" 'graph.flow_flush_count=0'
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
      require_line "$status_output" 'graph.flow_active_entries=4'
      require_line "$status_output" 'graph.flow_allocation_count=4'
      require_line "$status_output" 'graph.flow_reuse_count=4'
      require_line "$status_output" 'graph.flow_early_drop_count=0'
      require_line "$status_output" 'graph.flow_revision_invalidation_count=0'
      require_line "$status_output" 'graph.flow_revision_mismatch_count=0'
      require_line "$status_output" 'graph.flow_unavailable_count=0'
      require_line "$status_output" 'graph.flow_pass_next_count=8'
      require_line "$status_output" 'graph.flow_drop_count=0'
      require_line "$status_output" 'graph.flow_flush_count=0'
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
      require_line "$status_output" 'graph.flow_active_entries=4'
      require_line "$status_output" 'graph.flow_allocation_count=4'
      require_line "$status_output" 'graph.flow_reuse_count=3'
      require_line "$status_output" 'graph.flow_early_drop_count=1'
      require_line "$status_output" 'graph.flow_revision_invalidation_count=0'
      require_line "$status_output" 'graph.flow_revision_mismatch_count=0'
      require_line "$status_output" 'graph.flow_unavailable_count=0'
      require_line "$status_output" 'graph.flow_pass_next_count=7'
      require_line "$status_output" 'graph.flow_drop_count=1'
      require_line "$status_output" 'graph.flow_flush_count=0'
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
      require_line "$status_output" 'graph.flow_active_entries=0'
      require_line "$status_output" 'graph.flow_active_revision=0'
      require_line "$status_output" 'graph.flow_active_snapshot_hash=0'
      require_line "$status_output" 'graph.flow_allocation_count=0'
      require_line "$status_output" 'graph.flow_reuse_count=0'
      require_line "$status_output" 'graph.flow_early_drop_count=0'
      require_line "$status_output" 'graph.flow_revision_mismatch_count=8'
      require_line "$status_output" 'graph.flow_unavailable_count=0'
      require_line "$status_output" 'graph.flow_pass_next_count=0'
      require_line "$status_output" 'graph.flow_drop_count=0'
      require_line "$status_output" 'graph.flow_flush_count=1'
      ;;
    *) fail "unknown policy case $case_name" ;;
  esac
  runtime_output="$(cli 'show runtime')"
  printf '%s\n' "$runtime_output" |
    awk '$1 == "product-packet-policy" && $3 + 0 > 0 && $4 + 0 > 0 { found = 1 }
         END { exit found ? 0 : 1 }' ||
    fail "product-packet-policy has no real runtime calls/vectors"
  local disable_output post_disable_status
  disable_output="$(cli 'product packet-graph disable')"
  require_line "$disable_output" 'graph.disable=ok'
  post_disable_status="$(cli 'show product packet-graph')"
  require_flow_cleared "$post_disable_status"
}

run_association_case() {
  local configure_output enable_output setup_output association_output status_output
  local post_disable_status
  configure_output="$(cli 'product packet-graph configure workers 2 fixture s174-valid-dual-stack-v1')"
  require_line "$configure_output" 'graph.configure=ok'
  enable_output="$(cli 'product packet-graph enable')"
  require_line "$enable_output" 'graph.enable=ok'
  setup_output="$(cli 'product packet-graph run-policy-fixture l4-drop')"
  require_line "$setup_output" 'policy.fixture=l4-drop'
  association_output="$(cli 'product packet-graph run-policy-association-fixture')"
  require_line "$association_output" 'association.fixture=s192-typed-match-v1'
  require_line "$association_output" 'association.drop_terminal=drop-runtime'
  require_line "$association_output" 'association.drop_completion_attempts=1'
  require_line "$association_output" 'association.l4_last_match_winner=2'
  require_line "$association_output" 'association.policy_last_drop_winner=2'
  require_line "$association_output" 'association.last_match_winner_rank=1'
  require_line "$association_output" 'association.evaluation_winner=2'
  require_line "$association_output" 'association.winner_kind_valid=1'
  require_line "$association_output" 'association.unrelated_preserved=1'
  require_line "$association_output" 'association.same_probe_preserved=1'
  require_line "$association_output" 'association.wrong_port_visible=1'
  require_line "$association_output" 'association.match_records=1'
  require_line "$association_output" 'association.no_match_records=3'
  require_line "$association_output" 'association.last_match_rule_id=192002'
  require_line "$association_output" 'association.last_no_match_reason=7'
  for key in association.typed_match_policy_key \
    association.typed_match_probe_key association.last_evaluation_probe_key; do
    value="$(field "$association_output" "$key")"
    [[ "$value" =~ ^[0-9]+$ && "$value" != 0 ]] ||
      fail "missing nonzero runtime evidence: $key"
  done
  require_line "$association_output" 'association.wrong_port_probe_key_distinct=1'
  status_output="$(cli 'show product packet-graph')"
  require_line "$status_output" 'graph.policy_drop_records=1'
  require_line "$status_output" 'graph.l4_policy_view_match_records=1'
  require_line "$status_output" 'graph.l4_policy_view_no_match_records=3'
  require_line "$status_output" 'graph.l4_policy_view_last_no_match_reason=7'
  require_flow_common "$status_output"
  require_line "$status_output" 'graph.flow_active_entries=3'
  require_line "$status_output" 'graph.flow_allocation_count=3'
  require_line "$status_output" 'graph.flow_reuse_count=0'
  require_line "$status_output" 'graph.flow_early_drop_count=1'
  require_line "$status_output" 'graph.flow_revision_invalidation_count=0'
  require_line "$status_output" 'graph.flow_revision_mismatch_count=0'
  require_line "$status_output" 'graph.flow_unavailable_count=0'
  require_line "$status_output" 'graph.flow_pass_next_count=3'
  require_line "$status_output" 'graph.flow_drop_count=1'
  require_line "$status_output" 'graph.flow_flush_count=0'
  require_line "$(cli 'product packet-graph disable')" 'graph.disable=ok'
  post_disable_status="$(cli 'show product packet-graph')"
  require_flow_cleared "$post_disable_status"
}

run_gate_table_case() {
  local configure_output enable_output gate_table_output status_output
  local post_disable_status
  configure_output="$(cli 'product packet-graph configure workers 2 fixture s174-valid-dual-stack-v1')"
  require_line "$configure_output" 'graph.configure=ok'
  enable_output="$(cli 'product packet-graph enable')"
  require_line "$enable_output" 'graph.enable=ok'
  gate_table_output="$(cli 'product packet-graph run-gate-table-fixture')"
  require_line "$gate_table_output" 'gate-table.fixture=s192-gate-table-v1'
  require_line "$gate_table_output" 'gate-table.active_entry_count=6'
  require_line "$gate_table_output" 'gate-table.max_probes=6'
  require_line "$gate_table_output" 'gate-table.scalar_rule_id=0'
  require_line "$gate_table_output" 'gate-table.drop_rule_id=192301'
  require_line "$gate_table_output" 'gate-table.drop_winner_rank=1'
  require_line "$gate_table_output" 'gate-table.drop_candidate_count=3'
  require_line "$gate_table_output" 'gate-table.range_rule_id=192305'
  require_line "$gate_table_output" 'gate-table.ipv6_rule_id=192303'
  require_line "$gate_table_output" 'gate-table.wildcard_rule_id=192306'
  require_line "$gate_table_output" 'gate-table.wildcard_winner_rank=6'
  require_line "$gate_table_output" 'gate-table.address_no_match_reason=8'
  require_line "$gate_table_output" 'gate-table.ifindex_no_match_reason=1'
  require_line "$gate_table_output" 'gate-table.unavailable_no_match_reason=9'
  require_line "$gate_table_output" 'gate-table.unknown_uid_no_match_reason=2'
  require_line "$gate_table_output" 'gate-table.unknown_context_no_match_reason=3'
  require_line "$gate_table_output" 'gate-table.drop_terminal=1'
  require_line "$gate_table_output" 'gate-table.open_pass_next=1'
  require_line "$gate_table_output" 'gate-table.scalar_identity_empty=1'
  require_line "$gate_table_output" 'gate-table.lazy_revision=19207'
  require_line "$gate_table_output" 'gate-table.lazy_revision_ok=1'
  require_line "$gate_table_output" 'gate-table.flow_active_entries=4'
  require_line "$gate_table_output" 'gate-table.flow_allocation_count=4'
  require_line "$gate_table_output" 'gate-table.flow_reuse_count=4'
  require_line "$gate_table_output" 'gate-table.flow_early_drop_count=1'
  require_line "$gate_table_output" \
    'gate-table.flow_revision_invalidation_count=1'
  status_output="$(cli 'show product packet-graph')"
  [[ "$(field "$status_output" graph.gate_table_active_generation)" == \
     "$(field "$status_output" graph.generation)" ]] ||
    fail "GateTable status is not tied to the active graph generation"
  require_line "$status_output" 'graph.gate_table_active_revision=19207'
  require_line "$status_output" 'graph.gate_table_active_entry_count=6'
  require_line "$status_output" 'graph.gate_table_max_probes=6'
  require_line "$status_output" 'graph.gate_table_last_match_rule_id=192305'
  require_line "$status_output" 'graph.gate_table_last_winner_rank=5'
  require_line "$status_output" 'graph.gate_table_last_probes=6'
  require_line "$status_output" 'graph.gate_table_last_candidate_count=1'
  require_line "$status_output" 'graph.gate_table_last_no_match_reason=0'
  require_line "$status_output" 'graph.l4_policy_view_rule_count=0'
  require_flow_common "$status_output"
  require_line "$status_output" 'graph.flow_active_entries=4'
  require_line "$status_output" 'graph.flow_allocation_count=4'
  require_line "$status_output" 'graph.flow_reuse_count=4'
  require_line "$status_output" 'graph.flow_early_drop_count=1'
  require_line "$status_output" 'graph.flow_revision_invalidation_count=1'
  require_line "$status_output" 'graph.flow_revision_mismatch_count=0'
  require_line "$status_output" 'graph.flow_unavailable_count=1'
  require_line "$status_output" 'graph.flow_pass_next_count=8'
  require_line "$status_output" 'graph.flow_drop_count=1'
  require_line "$status_output" 'graph.flow_flush_count=0'
  require_line "$(cli 'product packet-graph disable')" 'graph.disable=ok'
  post_disable_status="$(cli 'show product packet-graph')"
  require_flow_cleared "$post_disable_status"
}

for case_name in gate-drop l4-drop l4-allow l4-no-match empty l4-matrix clear; do
  run_case "$case_name"
done
run_gate_table_case
run_association_case

echo "sakamoto S192 Product graph policy runtime contract: PASS"
echo "evidence=$evidence_dir"
