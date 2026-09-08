#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
native_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
ffi="$repo_root/src/product/include/sakamoto_product_core_ffi.h"
rust_core="$repo_root/crates/product-core/src/lib.rs"
vapi="$repo_root/src/product/native/sakamoto_product_vapi.c"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
graph="$repo_root/src/product/vpp/product_packet_graph.c"
root_adapter="$repo_root/src/product/vpp/product_root_nfqueue_adapter.c"
device_runner="$repo_root/tests/device/s189-root-network-gate-product.sh"

for file in "$service" "$native_status" "$jni" "$ffi" "$rust_core" \
  "$vapi" "$plugin" "$graph" "$root_adapter" "$device_runner"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'String gateStage = preservedNetworkGateEvidenceStage(status)' "$service"
grep -Fq 'rememberNetworkGateEvidenceStage(status, gateStage)' "$service"
grep -Fq 'lastNetworkGateEvidenceGeneration' "$service"
grep -Fq 'lastNetworkGateEvidenceRevision' "$service"
grep -Fq 'lastNetworkGateEvidenceProfile' "$service"

grep -Fq 'private static final int STATUS_VALUE_COUNT = 135' "$native_status"
grep -Fq 'STATUS_VALUE_COUNT = 135' "$jni"
grep -Fq 'nativeApplyNetworkGatePolicy' "$native_status"
grep -Fq 'nativeApplyNetworkGatePolicyRevision' "$native_status"
grep -Fq 'nativeReconcilePolicy' "$native_status"
grep -Fq 'applyNetworkGatePolicyRevision(' "$native_status"
grep -Fq 'sakamoto_product_core_apply_network_gate_policy' "$ffi"
grep -Fq 'sakamoto_product_core_apply_network_gate_policy_revision' "$ffi"
grep -Fq 'sakamoto_product_core_apply_empty_policy_revision' "$ffi"
grep -Fq 'sakamoto_product_core_reconcile_policy' "$ffi"
grep -Fq 'sakamoto_product_core_apply_network_gate_policy' "$jni"
grep -Fq 'sakamoto_product_core_apply_network_gate_policy_revision' "$jni"
grep -Fq 'sakamoto_product_core_apply_empty_policy_revision' "$jni"
grep -Fq 'sakamoto_product_core_reconcile_policy' "$jni"

for token in \
  'policyGateSubjectUid' \
  'policyGateNetworkContext' \
  'policyGateBlocked' \
  'policyGateReasonId' \
  'policyGateRuleId' \
  'policyDropRecords' \
  'policyLastDropRevision' \
  'policyLastDropRuleId' \
  'policyLastDropCompletionAttempts' \
  'policyLastDropUid' \
  'policyLastDropNetworkContext' \
  'policyLastDropReasonId' \
  'policyLastDropVerdict' \
  'policyLastDropWinner' \
  'policyLastDropUidKnown' \
  'policyLastDropDeviceDirection'; do
  grep -Fq "$token" "$native_status"
done

for token in \
  'S189_ROOT_NETWORK_GATE_STATUS' \
  'product-state/s189-root-network-gate.properties' \
  'schema=s189-root-network-gate/v1' \
  'session.applyNetworkGatePolicyRevision' \
  'session.applyEmptyPolicyRevision' \
  'session.applyEmptyPolicy(getFilesDir().getAbsolutePath())' \
  'rules == null || rules.length() == 0' \
  'validateNetworkGatePolicySnapshot' \
  'writeS189RootNetworkGateStatus' \
  'PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE' \
  'PRODUCT_POLICY_VERDICT_DROP' \
  'PRODUCT_DEVICE_DIRECTION_OUTPUT' \
  'physical_nfqueue_completion=' \
  'policy_drop_recorded='; do
  grep -Fq "$token" "$service"
done

python3 - "$service" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")

def body(signature):
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

apply = body("private LocalProductBackend.PolicyApplyResult applyCommittedProductPolicy(")
for token in (
        "subject.optBoolean(\"uidKnown\", false)",
        "subject.optInt(\"linuxUid\", -1)",
        "rules == null || rules.length() == 0",
        "session.applyEmptyPolicyRevision(",
        "session.applyEmptyPolicy(getFilesDir().getAbsolutePath())",
        "session.applyNetworkGatePolicyRevision(getFilesDir().getAbsolutePath()",
        "validateEmptyPolicySnapshot(status)",
        "validateNetworkGatePolicySnapshot(status, compiledRevision",
        "String gateStage = networkGateEvidenceStage(status)",
        "rememberNetworkGateEvidenceStage(status, gateStage)",
        "writeS189RootNetworkGateStatus(status, gateStage, \"\", \"\")",
        "writeS190VpnNetworkGateStatus(status, gateStage, \"\", \"\")",
        "String gateStage = blocked ? \"gate_blocked\" : \"gate_open\"",
        "writeS189RootNetworkGateStatus(status, gateStage, \"\", \"\""):
    if token not in apply:
        raise AssertionError("S189 apply path missing " + token)

preserved = body("private String preservedNetworkGateEvidenceStage(")
for token in (
        "lastNetworkGateEvidenceProfile != activeProfile",
        "lastNetworkGateEvidenceGeneration != generation",
        "status.policyGeneration != lastNetworkGateEvidenceGeneration",
        "status.policyRequestedRevision != lastNetworkGateEvidenceRevision",
        "status.policyActiveRevision != lastNetworkGateEvidenceRevision",
        "clearNetworkGateEvidenceStage()",
        'return "running"'):
    if token not in preserved:
        raise AssertionError("S189 stage preservation missing " + token)

reconcile = body("private RuntimeControlNative.Status reconcileProductEmptyPolicy(")
for token in (
        "session.reconcilePolicy(",
        "validateRuntimePolicySnapshot(status)",
        "writeS189RootNetworkGateStatus(status, stage"):
    if token not in reconcile:
        raise AssertionError("S189 reconcile path missing " + token)

writer = body("private void writeS189RootNetworkGateStatus(")
for token in (
        "gate_snapshot=",
        "gate_subject_uid=",
        "gate_network_context=",
        "gate_blocked=",
        "gate_rule_id=",
        "gate_reason_id=",
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
        "rootNfqueueHookName(status.policyLastDropDeviceDirection)",
        "policy_last_drop_device_direction_code=",
        "policy_drop_recorded=",
        "physical_nfqueue_completion="):
    if token not in writer:
        raise AssertionError("S189 evidence missing " + token)
PY

for token in \
  'clear_product_policy_files()' \
  'files/product-state/product.properties' \
  'files/product-transactions/transactions.properties' \
  'files/product-policy/policy-bundle.properties' \
  'files/product-policy/l4-intent.properties'; do
  grep -Fq "$token" "$device_runner"
done

for token in \
  'NetworkGatePolicySnapshot' \
  'NETWORK_GATE_POLICY_STORE_FILE: &str = "network-gate-intent.properties"' \
  'publish_next_network_gate_snapshot' \
  'publish_network_gate_snapshot_revision' \
  'publish_empty_snapshot_revision' \
  'apply_network_gate_policy' \
  'apply_network_gate_policy_revision' \
  'apply_empty_policy_revision' \
  'reconcile_policy' \
  'sakamoto_product_core_apply_network_gate_policy' \
  'sakamoto_product_core_apply_network_gate_policy_revision' \
  'sakamoto_product_core_apply_empty_policy_revision' \
  'sakamoto_product_core_reconcile_policy'; do
  grep -Fq "$token" "$rust_core"
done

for token in \
  'gate_claim_count = ntohl (mp->gate_claim_count)' \
  'valid_gate_block' \
  'valid_gate_open' \
  'product_packet_graph_publish_gate_policy' \
  'product_packet_graph_clear_gate_policy' \
  'product_packet_graph_gate_status'; do
  grep -Fq "$token" "$plugin"
done

for token in \
  'product_packet_graph_publish_gate_policy' \
  'product_packet_graph_clear_gate_policy' \
  'product_packet_graph_record_policy_drop' \
  'PRODUCT_PACKET_DROP_POLICY_GATE' \
  'PRODUCT_POLICY_VERDICT_DROP' \
  'PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE' \
  'policy_last_drop_completion_attempts' \
  'policy_last_drop_device_direction'; do
  grep -Fq "$token" "$graph"
done

grep -Fq 'hints.network_context_id = PRODUCT_ROOT_NFQUEUE_NETWORK_CONTEXT_WIFI' "$root_adapter"
grep -Fq 'hints.profile_id = packet.hook' "$root_adapter"

grep -Fq 'SAKAMOTO-189-root-network-gate' "$device_runner"
grep -Fq 'dev/adb' "$device_runner"
grep -Fq 'export ADB="${repo_root}/dev/adb"' "$device_runner"
if grep -Eq '(^|[[:space:]])adb([[:space:]]|$)|adb\.exe' "$device_runner"; then
  echo "S189 runner must use repo-local ./dev/adb, not raw adb" >&2
  exit 1
fi
for token in \
  'readonly S189_SERIAL="28201JEGR0XPAJ"' \
  'debugSetNetworkGateSubject' \
  'debugSetNetworkGateContext' \
  'debugSetNetworkGateBlocked' \
  'debugTraffic' \
  'tcp_echo_matched' \
  'tcp_connect_failed' \
  'run_app_tcp_probe_with_server blocked "$blocked_nonce" tcp_connect_failed' \
  'policy_drop_recorded' \
  'physical_nfqueue_completion' \
  'policy_last_drop_device_direction", "OUTPUT"' \
  'expected_policy_last_drop_device_direction", "3"' \
  'expected_policy_last_drop_winner", "1"' \
  'expected_policy_last_drop_verdict", "2"' \
  'activity_reconnect_same_revision' \
  'kv gate_open true' \
  'restart_after_open'; do
  grep -Fq "$token" "$device_runner"
done
if grep -Fq 'POLICY.EVALUATE' "$device_runner"; then
  echo "S189 runner must not use POLICY.EVALUATE as acceptance evidence" >&2
  exit 1
fi

echo "s189 root network gate product contract: PASS"
