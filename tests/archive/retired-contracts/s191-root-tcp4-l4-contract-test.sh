#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
backend="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlBackend.java"
manifest="$repo_root/app/android-runtime/src/main/AndroidManifest.xml"
native_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
ffi="$repo_root/src/product/include/sakamoto_product_core_ffi.h"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
rust_core="$repo_root/crates/product-core/src/lib.rs"
vapi="$repo_root/src/product/native/sakamoto_product_vapi.c"
api="$repo_root/src/product/vpp/product_core.api"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
packet_h="$repo_root/src/product/vpp/product_packet.h"
graph="$repo_root/src/product/vpp/product_packet_graph.c"
graph_h="$repo_root/src/product/vpp/product_packet_graph.h"
device_runner="$repo_root/tests/device/s191-root-tcp4-l4-product.sh"

for file in "$service" "$activity" "$backend" "$manifest" "$native_status" "$jni" "$ffi" "$abi" "$rust_core" \
  "$vapi" "$api" "$plugin" "$packet_h" "$graph" "$graph_h" "$device_runner"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'product-state/s191-root-tcp4-l4.properties' "$service"
grep -Fq 'android:name=".DebugControlActivity"' "$manifest"
grep -Fq 'android:exported="true"' "$manifest"
grep -Fq 'android:name=".RuntimeService"' "$manifest"
grep -Fq 'android:exported="false"' "$manifest"
grep -Fq 'private void requestDebugL4Rule' "$activity"
grep -Fq 'backend.setL4Rule(this, rule)' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_SUBJECT' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_FAMILY' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_SOURCE_CIDR' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_DESTINATION_CIDR' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_SOURCE_PORT_FIRST' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_SOURCE_PORT_LAST' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_DESTINATION_PORT_FIRST' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_DESTINATION_PORT_LAST' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_IP_PROTOCOL' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_DIRECTION' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_NETWORK_CONTEXT' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_ACTION' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_PRIORITY' "$activity"
grep -Fq 'EXTRA_DEBUG_SET_L4_RULE_ORDER' "$activity"
grep -Fq 'new Intent(context, RuntimeService.class)' "$backend"
grep -Fq 'ACTION_PRODUCT_SET_L4_RULE' "$backend"
grep -Fq 'context.startService(intent)' "$backend"
grep -Fq 'parseRootL4PolicyFacts' "$service"
grep -Fq 'session.applyL4PolicyRevision(' "$service"
grep -Fq 'validateRootL4PolicySnapshot' "$service"
grep -Fq 'writeS191RootL4Status(status, currentRootL4PolicyFacts(),' "$service"
grep -Fq 'PRODUCT_POLICY_WINNER_L4 = 2' "$service"
grep -Fq 'PRODUCT_L4_DIRECTION_OUTPUT = 3' "$service"
grep -Fq 'PRODUCT_DEVICE_DIRECTION_OUTPUT = 3' "$service"
grep -Fq 'policyL4MatchRecords' "$service"
grep -Fq 'policy_l4_no_match_records=' "$service"
grep -Fq 'gate_before_l4=true' "$service"
grep -Fq 'root_adapter_completion_separate=true' "$service"
grep -Fq 'adapter_completion_separate=true' "$service"
grep -Fq 'rust_product_store=" + policyStoreEvidencePath(status,' "$service"
grep -Fq 'ui_policy_authority=false' "$service"
grep -Fq 'vpp_policy_authority=false' "$service"

grep -Fq 'private static final int STATUS_VALUE_COUNT = 135' "$native_status"
grep -Fq 'nativeApplyL4Policy' "$native_status"
grep -Fq 'nativeApplyL4PolicyRevision' "$native_status"
grep -Fq 'public synchronized Status applyL4PolicyRevision' "$native_status"
grep -Fq 'direction == 1 || direction == 3' "$native_status"
grep -Fq 'public final long policyL4ActiveRevision' "$native_status"
grep -Fq 'public final long policyL4NoMatchRecords' "$native_status"
grep -Fq 'public final int policyL4LastEvaluationVerdict' "$native_status"

grep -Fq 'STATUS_VALUE_COUNT = 135' "$jni"
grep -Fq 'nativeApplyL4Policy' "$jni"
grep -Fq 'nativeApplyL4PolicyRevision' "$jni"
grep -Fq 'sakamoto_product_core_apply_l4_policy' "$jni"
grep -Fq 'direction == 1 || direction == 3' "$jni"
grep -Fq 'policy_l4_active_revision' "$jni"
grep -Fq 'policy_l4_last_evaluation_verdict' "$jni"

grep -Fq 'sakamoto_product_core_apply_l4_policy' "$ffi"
grep -Fq 'sakamoto_product_core_apply_l4_policy_revision' "$ffi"
grep -Fq 'l4_subject_uid' "$abi"
grep -Fq 'l4_source_address[16]' "$abi"
grep -Fq 'policy_l4_match_records' "$abi"
grep -Fq 'sizeof(sakamoto_product_policy_snapshot_t) == 264U' "$abi"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"

grep -Fq 'L4_POLICY_STORE_FILE: &str = "l4-intent.properties"' "$rust_core"
grep -Fq 'sakamoto-l4-policy-intent/v1' "$rust_core"
grep -Fq 'struct StatelessL4PolicySnapshot' "$rust_core"
grep -Fq 'RuntimePolicySnapshot::StatelessL4' "$rust_core"
grep -Fq 'publish_l4_snapshot_revision' "$rust_core"
grep -Fq 'apply_l4_policy_revision' "$rust_core"
grep -Fq 'sakamoto_product_core_apply_l4_policy_revision' "$rust_core"
grep -Fq 'parse_ipv4_cidr' "$rust_core"

grep -Fq 'message->payload.l4_subject_uid = snapshot->l4_subject_uid' "$vapi"
grep -Fq 'call->status->policy_l4_match_records = reply->policy_l4_match_records' "$vapi"
grep -Fq 'u32 l4_subject_uid' "$api"
grep -Fq 'u64 policy_l4_match_records' "$api"
grep -Fq 'u8 l4_source_address[16]' "$api"

grep -Fq 'product_core_ipv4_from_snapshot_address' "$plugin"
grep -Fq 'int valid_l4' "$plugin"
grep -Fq 'product_packet_graph_publish_l4_policy (&parsed_l4)' "$plugin"
grep -Fq 'product_packet_graph_clear_gate_policy (requested_revision,' "$plugin"

grep -Fq 'PRODUCT_PACKET_DROP_POLICY_L4' "$packet_h"
grep -Fq 'PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT UINT8_C (3)' "$graph_h"
grep -Fq 'product_packet_graph_l4_policy_t' "$graph_h"
grep -Fq 'product_packet_graph_publish_l4_policy' "$graph_h"
grep -Fq 'product_packet_graph_l4_status' "$graph_h"
grep -Fq 'product_packet_graph_l4_match' "$graph"
grep -Fq 'product_packet_graph_record_l4_no_match' "$graph"
grep -Fq 'PRODUCT_PACKET_DROP_POLICY_L4' "$graph"
grep -Fq 'PRODUCT_PACKET_GRAPH_L4_WINNER_RULE' "$graph"

grep -Fq 'SAKAMOTO-191 Root IPv4 TCP stateless L4' "$device_runner"
grep -Fq 'readonly ACTIVITY="${PACKAGE}/.DebugControlActivity"' "$device_runner"
grep -Fq 'start_activity' "$device_runner"
if grep -Fq 'am startservice' "$device_runner"; then
  echo "S191 runner must route L4 mutations through DebugControlActivity" >&2
  exit 1
fi
grep -Fq 'debugSetL4RuleSubject "$subject"' "$device_runner"
grep -Fq 'debugSetL4RuleFamily ipv4' "$device_runner"
grep -Fq 'debugSetL4RuleIpProtocol 6' "$device_runner"
grep -Fq 'debugSetL4RuleDirection output' "$device_runner"
grep -Fq 'debugSetL4RuleNetworkContext wifi' "$device_runner"
grep -Fq 'debugSetL4RuleAction "$action"' "$device_runner"
grep -Fq 'apply_l4_rule drop "$subject"' "$device_runner"
grep -Fq 'apply_l4_rule allow "$subject"' "$device_runner"
grep -Fq 'capture_s191_status l4_drop_apply l4_apply' "$device_runner"
grep -Fq 'capture_s191_status l4_allow_apply l4_apply' "$device_runner"
grep -Fq 'actual_stage not in ("running", "l4_apply")' "$device_runner"
grep -Fq 'l4_direction_code", "3"' "$device_runner"
grep -Fq 'policy_l4_direction_code", "3"' "$device_runner"
grep -Fq 'policy_l4_match_records' "$device_runner"
grep -Fq 'policy_l4_no_match_records' "$device_runner"
grep -Fq 'policy_drop_recorded' "$device_runner"
grep -Fq 'policy_drop_records' "$device_runner"
grep -Fq 'adapter_completion_separate' "$device_runner"
grep -Fq 'no_match_pass_next' "$device_runner"
grep -Fq 'need("policy_l4_last_evaluation_result", "2")' "$device_runner"
grep -Fq 'need("policy_l4_last_evaluation_verdict", "1")' "$device_runner"
if grep -Fq 'need("policy_l4_last_evaluation_device_direction_code", "3")' \
    "$device_runner"; then
  echo "S191 no-match must not require the last bidirectional evaluation direction" >&2
  exit 1
fi

python3 - "$service" "$graph" "$plugin" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
graph = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
plugin = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")


def body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError("unclosed body for " + signature)


apply = body(service, "private LocalProductBackend.PolicyApplyResult applyCommittedProductPolicy(")
for token in (
    "l4Rules.length() != 1",
    "activeProfile != RuntimeProfile.ROOT",
    "rules != null && rules.length() != 0",
    "parseRootL4PolicyFacts(",
    "session.applyL4PolicyRevision(",
    "validateRootL4PolicySnapshot(status, compiledRevision)",
    "writeS191RootL4Status(status, l4,",
):
    if token not in apply:
        raise AssertionError("S191 apply path missing " + token)

start_product = body(service, "private void startProductCoreRuntime(")
hook_install = start_product.index("installProductRootNfqueueHook()")
profile_prepare = start_product.index("prepareProductCoreProfile(profileRoot, nativeDir, owner)")
if hook_install > profile_prepare:
    raise AssertionError(
        "Root hook retry cleanup must not run after Product Core profile preparation")

matcher = body(graph, "product_packet_graph_l4_match (")
for token in (
    "lease->hints.uid != matched->subject_uid",
    "lease->hints.network_context_id != matched->network_context_id",
    "lease->facts.ip_family != PRODUCT_PACKET_GRAPH_L4_FAMILY_IPV4",
    "lease->facts.protocol != PRODUCT_PACKET_GRAPH_L4_PROTOCOL_TCP",
    "lease->facts.l4_status != PRODUCT_PACKET_L4_COMPLETE",
    "product_packet_graph_l4_direction_matches",
    "product_packet_graph_ipv4_prefix_matches",
    "lease->facts.destination_port > matched->destination_port_last",
):
    if token not in matcher:
        raise AssertionError("S191 matcher missing " + token)

no_match_recorder = body(graph, "product_packet_graph_record_l4_no_match")
for token in (
    "l4_policy_direction",
    "product_packet_graph_l4_direction_matches",
    "PRODUCT_PACKET_GRAPH_L4_EVALUATION_NO_MATCH",
    "PRODUCT_POLICY_VERDICT_PASS_NEXT",
):
    if token not in no_match_recorder:
        raise AssertionError("S191 no-match recorder missing " + token)

handler = body(plugin, "vl_api_product_core_policy_apply_t_handler")
for token in (
    "int valid_l4",
    "gate_subject_uid == 0",
    "l4_ip_family == PRODUCT_PACKET_GRAPH_L4_FAMILY_IPV4",
    "l4_ip_protocol == PRODUCT_PACKET_GRAPH_L4_PROTOCOL_TCP",
    "parsed_l4.source_address =",
    "parsed_l4.destination_address =",
    "product_packet_graph_clear_gate_policy",
    "product_packet_graph_publish_l4_policy",
):
    if token not in handler:
        raise AssertionError("S191 plugin apply missing " + token)
PY

echo "sakamoto-191 Root TCP4 L4 contract: PASS"
