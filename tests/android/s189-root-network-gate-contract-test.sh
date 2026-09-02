#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
backend="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/LocalProductBackend.java"
transactions="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPolicyTransactions.java"
native_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
compiler="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AuthoringPolicyCompiler.java"
ffi="$repo_root/src/product/include/sakamoto_product_core_ffi.h"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
rust_core="$repo_root/crates/product-core/src/lib.rs"
vapi="$repo_root/src/product/native/sakamoto_product_vapi.c"
fixture="$repo_root/src/product/native/sakamoto_product_host_fixture_abi.c"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
graph="$repo_root/src/product/vpp/product_packet_graph.c"
graph_h="$repo_root/src/product/vpp/product_packet_graph.h"
packet_h="$repo_root/src/product/vpp/product_packet.h"
api="$repo_root/src/product/vpp/product_core.api"
root_adapter="$repo_root/src/product/vpp/product_root_nfqueue_adapter.c"
device_runner="$repo_root/tests/device/s189-root-network-gate-product.sh"

for file in "$service" "$backend" "$transactions" "$native_status" "$jni" \
  "$compiler" "$ffi" "$abi" "$rust_core" "$vapi" "$fixture" "$plugin" \
  "$graph" "$graph_h" "$packet_h" "$api" "$root_adapter" "$device_runner"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'product-state/s189-root-network-gate.properties' "$service"
grep -Fq 'String gateStage = preservedNetworkGateEvidenceStage(status)' "$service"
grep -Fq 'rememberNetworkGateEvidenceStage(status, gateStage)' "$service"
grep -Fq 'lastNetworkGateEvidenceGeneration' "$service"
grep -Fq 'lastNetworkGateEvidenceRevision' "$service"
grep -Fq 'lastNetworkGateEvidenceProfile' "$service"
grep -Fq 'writeS189RootNetworkGateStatus(status, gateStage, "", "")' "$service"
grep -Fq 'policyStoreEvidencePath(status,' "$service"
grep -Fq 'ACTION_PRODUCT_SET_NETWORK_GATE.equals(action)' "$service"
grep -Fq 'setProductNetworkGate(' "$service"
grep -Fq 'applyCommittedProductPolicy(' "$service"
grep -Fq 'long compiledRevision = payload.optLong("revision", -1L)' "$service"
grep -Fq 'subject.optBoolean("uidKnown", false)' "$service"
grep -Fq 'session.applyNetworkGatePolicyRevision(' "$service"
grep -Fq 'validateNetworkGatePolicySnapshot(status, compiledRevision' "$service"
grep -Fq 'repostStartAfterDestroy(intent, action)' "$service"
grep -Fq 'runtime_start=reposted_after_destroy action=' "$service"
grep -Fq 'PRODUCT_ROOT_NFQUEUE_HOOK_INSTALL_ATTEMPTS = 3' "$service"
grep -Fq 'product_root_nfqueue_hook_install=failed attempt=' "$service"
grep -Fq 'productRootNfqueueResidueClean(RuntimeProfile.ROOT)' "$service"
grep -Fq 'policy_drop_recorded=' "$service"
grep -Fq 'physical_nfqueue_completion=' "$service"
grep -Fq 'policy_last_drop_verdict=' "$service"
grep -Fq 'policy_last_drop_winner=' "$service"
grep -Fq 'policy_last_drop_device_direction", "OUTPUT"' "$device_runner"
grep -Fq 'expected_policy_last_drop_device_direction", "3"' "$device_runner"
grep -Fq 'debugSetNetworkGateSubject' "$device_runner"
grep -Fq 'debugSetNetworkGateContext wifi' "$device_runner"
grep -Fq 'S189_ADB_COMMAND_TIMEOUT_SECONDS' "$device_runner"
grep -Fq 'timeout "$S189_ADB_COMMAND_TIMEOUT_SECONDS" "$ADB" "$@"' "$device_runner"
grep -Fq 'start_activity --es debugSetNetworkGateSubject "$subject"' "$device_runner"
grep -Fq 'read_device_model "$RESULT_DIR/device-model.txt"' "$device_runner"
grep -Fq 'could not read controlled Pixel 6a model from ADB' "$device_runner"
grep -Fq -- '--ez debugSetNetworkGateBlocked true' "$device_runner"
grep -Fq -- '--ez debugSetNetworkGateBlocked false' "$device_runner"
grep -Fq 'capture_s189_status gate_blocked gate_blocked "$app_uid" 1 true 0 false' "$device_runner"
grep -Fq 'capture_s189_status gate_drop - "$app_uid" 1 true $((block_revision - 1)) true' "$device_runner"
grep -Fq 'capture_s189_status gate_open gate_open "$app_uid" 1 false "$block_revision" false' "$device_runner"
grep -Fq 'adb_target shell input keyevent HOME' "$device_runner"
grep -Fq 'capture_s189_status activity_reconnect - "$app_uid" 1 false $((open_revision - 1)) false' "$device_runner"
grep -Fq 'kv activity_reconnect_same_revision true' "$device_runner"
grep -Fq 'capture_s189_status restart_after_open - "$app_uid" 1 false $((open_revision - 1)) false' "$device_runner"
grep -Fq 'kv restart_after_open_same_revision true' "$device_runner"
grep -Fq 'run_app_tcp_probe_with_server restart_after_open' "$device_runner"
grep -Fq 'kv restart_after_open_traffic tcp_echo_matched' "$device_runner"
grep -Fq 'kv final_residue_clean true' "$device_runner"
grep -Fq 'tcp_echo_matched' "$device_runner"
grep -Fq 'tcp_connect_failed' "$device_runner"

grep -Fq 'withNetworkGate(subjectId, context, blocked)' "$backend"
grep -Fq 'applyPolicyTransaction(subjectId, nextBundle)' "$backend"
grep -Fq 'CommitValidationContext.of(nextState, catalog)' "$backend"
grep -Fq 'AuthoringPolicyCompiler.compilePolicyBundle(committed)' "$transactions"
grep -Fq 'subject.networkGateRules.add(rule)' "$compiler"
grep -Fq 'rule.optBoolean("blocked", true)' "$service"
grep -Fq '\"reasonId\"' "$compiler"
grep -Fq '\"ruleId\"' "$compiler"

grep -Fq 'private static final int STATUS_VALUE_COUNT = 136' "$native_status"
grep -Fq 'nativeApplyNetworkGatePolicy' "$native_status"
grep -Fq 'nativeApplyNetworkGatePolicyRevision' "$native_status"
grep -Fq 'public synchronized Status applyNetworkGatePolicyRevision' "$native_status"
grep -Fq 'nativeReconcilePolicy' "$native_status"
grep -Fq 'public final int policyGateSubjectUid' "$native_status"
grep -Fq 'public final long policyDropRecords' "$native_status"
grep -Fq 'public final int policyLastDropVerdict' "$native_status"
grep -Fq 'STATUS_VALUE_COUNT = 136' "$jni"
grep -Fq 'sakamoto_product_core_apply_network_gate_policy' "$jni"
grep -Fq 'sakamoto_product_core_apply_network_gate_policy_revision' "$jni"
grep -Fq 'sakamoto_product_core_reconcile_policy' "$jni"

grep -Fq 'sakamoto_product_core_apply_network_gate_policy' "$ffi"
grep -Fq 'sakamoto_product_core_apply_network_gate_policy_revision' "$ffi"
grep -Fq 'sakamoto_product_core_apply_empty_policy_revision' "$ffi"
grep -Fq 'sakamoto_product_core_reconcile_policy' "$ffi"
grep -Fq 'gate_subject_uid' "$abi"
grep -Fq 'policy_last_drop_winner' "$abi"
grep -Fq 'sizeof(sakamoto_product_policy_snapshot_t) == 264U' "$abi"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"

grep -Fq 'NETWORK_GATE_POLICY_STORE_FILE: &str = "network-gate-intent.properties"' "$rust_core"
grep -Fq 'sakamoto-network-gate-policy-intent/v1' "$rust_core"
grep -Fq 'struct NetworkGatePolicySnapshot' "$rust_core"
grep -Fq 'RuntimePolicySnapshot::NetworkGate' "$rust_core"
grep -Fq 'current_snapshot' "$rust_core"
grep -Fq 'publish_next_network_gate_snapshot' "$rust_core"
grep -Fq 'publish_network_gate_snapshot_revision' "$rust_core"
grep -Fq 'publish_empty_snapshot_revision' "$rust_core"
grep -Fq 'remove_network_gate_intent' "$rust_core"
grep -Fq 'apply_network_gate_policy' "$rust_core"
grep -Fq 'apply_network_gate_policy_revision' "$rust_core"
grep -Fq 'apply_empty_policy_revision' "$rust_core"
grep -Fq 'sakamoto_product_core_apply_network_gate_policy_revision' "$rust_core"
grep -Fq 'sakamoto_product_core_apply_empty_policy_revision' "$rust_core"
grep -Fq 'assert!(!store.network_gate_state_file().exists())' "$rust_core"
grep -Fq 'reconcile_policy' "$rust_core"
grep -Fq 'network_gate_policy_snapshot_ffi_carries_one_gate_claim_when_blocked' "$rust_core"

grep -Fq 'message->payload.gate_subject_uid = snapshot->gate_subject_uid' "$vapi"
grep -Fq 'call->status->policy_last_drop_winner = reply->policy_last_drop_winner' "$vapi"
grep -Fq 'one Root Network Gate policy snapshot, or one Root IPv4 TCP L4 policy snapshot is supported' "$fixture"

grep -Fq 'gate_subject_uid' "$api"
grep -Fq 'policy_last_drop_verdict' "$api"
grep -Fq 'product_packet_graph_publish_gate_policy' "$plugin"
grep -Fq 'product_packet_graph_clear_gate_policy' "$plugin"
grep -Fq 'valid_gate_block' "$plugin"
grep -Fq 'valid_gate_open' "$plugin"
grep -Fq 'product_packet_graph_gate_status (&gate_status)' "$plugin"

grep -Fq 'PRODUCT_PACKET_DROP_POLICY_GATE' "$packet_h"
grep -Fq 'product_packet_graph_gate_policy_t' "$graph_h"
grep -Fq 'product_packet_graph_publish_gate_policy' "$graph"
grep -Fq 'product_packet_graph_record_policy_drop' "$graph"
grep -Fq 'PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE' "$graph"
grep -Fq 'PRODUCT_POLICY_VERDICT_DROP' "$graph"
grep -Fq 'hints.network_context_id = PRODUCT_ROOT_NFQUEUE_NETWORK_CONTEXT_WIFI' "$root_adapter"
grep -Fq 'hints.profile_id = packet.hook' "$root_adapter"

python3 - "$service" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")


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
    "compiledRevision",
    "subjects.length() == 0",
    "session.applyEmptyPolicyRevision(",
    "subjects.length() != 1",
    "!subject.optBoolean(\"uidKnown\", false)",
    "rules == null || rules.length() == 0",
    "rules.length() != 1",
    "rule.optInt(\"networkContext\", -1)",
    "rule.optBoolean(\"blocked\", true)",
    "rule.optLong(\"ruleId\", -1L)",
    "rule.optInt(\"reasonId\", -1)",
    "session.applyNetworkGatePolicyRevision(",
    "validateNetworkGatePolicySnapshot(status, compiledRevision",
    "String gateStage = networkGateEvidenceStage(status)",
    "rememberNetworkGateEvidenceStage(status, gateStage)",
    "writeS189RootNetworkGateStatus(status, gateStage, \"\", \"\")",
    "String gateStage = blocked ? \"gate_blocked\" : \"gate_open\"",
):
    if token not in apply:
        raise AssertionError("S189 apply path missing " + token)

validator = body(service, "private String validateNetworkGatePolicySnapshot(")
for token in (
    "expectedRevision",
    "status.policyGeneration != generation",
    "!status.policyGenerationMatch",
    "status.policyRequestedRevision != status.policyActiveRevision",
    "status.policyActiveRevision != expectedRevision",
    "status.policySnapshotEmpty",
    "!status.policyDefaultPass",
    "status.policyL4RuleCount != 0",
    "status.policyGateClaimCount != (status.policyGateBlocked ? 1 : 0)",
    "status.policyGateSubjectUid != expectedSubjectUid",
    "status.policyGateNetworkContext != expectedNetworkContext",
    "status.policyGateBlocked != expectedBlocked",
    "status.policyGateRuleId != expectedRuleId",
    "status.policyGateReasonId != expectedReasonId",
    "status.policyWorker0Revision != status.policyActiveRevision",
    "status.policyMixedRevision",
    "!status.policyArtifactMatch",
):
    if token not in validator:
        raise AssertionError("S189 validator missing " + token)

preserved = body(service, "private String preservedNetworkGateEvidenceStage(")
for token in (
    "lastNetworkGateEvidenceProfile != activeProfile",
    "lastNetworkGateEvidenceGeneration != generation",
    "status.policyGeneration != lastNetworkGateEvidenceGeneration",
    "status.policyRequestedRevision != lastNetworkGateEvidenceRevision",
    "status.policyActiveRevision != lastNetworkGateEvidenceRevision",
    "clearNetworkGateEvidenceStage()",
    'return "running"',
):
    if token not in preserved:
        raise AssertionError("S189 stage preservation missing " + token)

writer = body(service, "private void writeS189RootNetworkGateStatus(")
for token in (
    "schema=s189-root-network-gate/v1",
    "gate_snapshot=",
    "gate_subject_uid=",
    "gate_network_context=",
    "gate_blocked=",
    "gate_rule_id=",
    "gate_reason_id=",
    "worker_revision_match=",
    "submission_status_code=",
    "operation_status_code=",
    "artifact_match=",
    "policy_drop_records=",
    "policy_last_drop_revision=",
    "policy_last_drop_rule_id=",
    "policy_last_drop_completion_attempts=",
    "policy_last_drop_uid=",
    "policy_last_drop_network_context=",
    "policy_last_drop_reason_id=",
    "policy_last_drop_verdict=",
    "policy_last_drop_winner=",
    "policy_last_drop_uid_known=",
    "policy_last_drop_device_direction=",
    "expected_policy_last_drop_verdict=",
    "expected_policy_last_drop_winner=",
    "expected_policy_last_drop_device_direction=",
    "policy_drop_recorded=",
    "root_nfqueue_verdict_attempts=",
    "root_nfqueue_verdict_succeeded=",
    "physical_nfqueue_completion=",
    "rust_product_store=",
    "rust_product_store_single_writer=true",
    "ui_policy_authority=false",
    "vpp_policy_authority=false",
):
    if token not in writer:
        raise AssertionError("S189 evidence missing " + token)
PY

echo "sakamoto-189 Root Network Gate contract: PASS"
