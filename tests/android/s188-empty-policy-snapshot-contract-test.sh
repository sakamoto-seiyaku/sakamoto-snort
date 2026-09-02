#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
protocol="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java"
request="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlRequest.java"
backend="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlBackend.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
native_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
ffi="$repo_root/src/product/include/sakamoto_product_core_ffi.h"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
rust_core="$repo_root/crates/product-core/src/lib.rs"
vapi="$repo_root/src/product/native/sakamoto_product_vapi.c"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
api="$repo_root/src/product/vpp/product_core.api"
device_runner="$repo_root/tests/device/s188-empty-policy-snapshot-product.sh"

for file in "$service" "$protocol" "$request" "$backend" "$activity" "$native_status" \
  "$jni" "$ffi" "$abi" "$rust_core" "$vapi" "$plugin" "$api" "$device_runner"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'ACTION_PRODUCT_APPLY_EMPTY_POLICY' "$protocol"
grep -Fq 'product_apply_empty_policy' "$protocol"
grep -Fq 'PRODUCT_APPLY_EMPTY_POLICY' "$request"
grep -Fq 'applyEmptyPolicy(Context context)' "$backend"
grep -Fq 'debugApplyEmptyPolicy' "$activity"
grep -Fq 'backend.applyEmptyPolicy(this)' "$activity"
grep -Fq 'ACTION_PRODUCT_APPLY_EMPTY_POLICY.equals(action)' "$service"
grep -Fq 'enqueueLifecycle(this::applyProductEmptyPolicy)' "$service"
grep -Fq 'reconcileProductEmptyPolicy(session, "startup_reconcile")' "$service"
grep -Fq 'session.reconcilePolicy(' "$service"
grep -Fq 'status.policyActiveRevision <= 0L' "$service"
grep -Fq 'session.applyEmptyPolicy(getFilesDir().getAbsolutePath())' "$service"
grep -Fq 'validateRuntimePolicySnapshot(status)' "$service"
grep -Fq 'S188_EMPTY_POLICY_SNAPSHOT_STATUS' "$service"
grep -Fq 'product-state/s188-empty-policy-snapshot.properties' "$service"
grep -Fq 'schema=s188-empty-policy-snapshot/v1' "$service"
grep -Fq 'rust_product_store=product-policy/empty-intent.properties' "$service"
grep -Fq 'rust_product_store_single_writer=true' "$service"
grep -Fq 'ui_policy_authority=false' "$service"
grep -Fq 'vpp_policy_authority=false' "$service"
grep -Fq 'traffic_behavior_changed=false' "$service"

python3 - "$service" "$activity" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
activity = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")


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


reconcile = body(service, "private RuntimeControlNative.Status reconcileProductEmptyPolicy(")
for token in (
        "session.reconcilePolicy(",
        "getFilesDir().getAbsolutePath()",
        "status.policyActiveRevision <= 0L",
        "session.applyEmptyPolicy(getFilesDir().getAbsolutePath())",
        "stage = stage + \"_fresh_apply\"",
        "validateRuntimePolicySnapshot(status)",
        "writeS188EmptyPolicySnapshotStatus(status, stage, \"\", \"\")"):
    if token not in reconcile:
        raise AssertionError("S188 reconcile missing " + token)

apply = body(service, "private void applyProductEmptyPolicy(")
for token in (
        "session.applyEmptyPolicy(getFilesDir().getAbsolutePath())",
        "validateEmptyPolicySnapshot(status)",
        "publishProductCoreRunning(status, ProductCoreLifecycle.UNKNOWN_PID)",
        "writeS188EmptyPolicySnapshotStatus(status, \"applied\", \"\", \"\")"):
    if token not in apply:
        raise AssertionError("S188 explicit apply missing " + token)

validator = body(service, "private String validateEmptyPolicySnapshot(")
for token in (
        "status.policyGeneration != generation",
        "!status.policyGenerationMatch",
        "status.policyRequestedRevision <= 0L",
        "status.policyRequestedRevision != status.policyActiveRevision",
        "status.policySnapshotHash == 0L",
        "!status.policySnapshotEmpty",
        "!status.policyDefaultPass",
        "status.policyGateClaimCount != 0",
        "status.policyL4RuleCount != 0",
        "status.policyWorker0Revision != status.policyActiveRevision",
        "status.policyWorker1Revision != status.policyActiveRevision",
        "status.policyMixedRevision",
        "!status.policyArtifactMatch"):
    if token not in validator:
        raise AssertionError("S188 validation missing " + token)

writer = body(service, "private void writeS188EmptyPolicySnapshotStatus(")
for token in (
        "requested_revision=",
        "active_revision=",
        "revision_match=",
        "policy_generation=",
        "generation_match=",
        "policy_snapshot_hash=",
        "policy_snapshot_identity=",
        "policy_snapshot_empty=",
        "policy_default_pass=",
        "empty_default_pass=",
        "gate_claim_count=",
        "l4_rule_count=",
        "no_gate_l4_claim=",
        "worker0_revision=",
        "worker1_revision=",
        "worker_revision_match=",
        "submission_status_code=",
        "operation_status_code=",
        "artifact_match="):
    if token not in writer:
        raise AssertionError("S188 evidence missing " + token)

interactive = body(activity, "private boolean hasInteractiveDebugExtras(")
if "EXTRA_DEBUG_APPLY_EMPTY_POLICY" in interactive:
    raise AssertionError("S188 debug apply must stay headless for device automation")
PY

grep -Fq 'private static final int STATUS_VALUE_COUNT = 136' "$native_status"
grep -Fq 'STATUS_VALUE_COUNT = 136' "$jni"
for token in \
  'nativeApplyEmptyPolicy' \
  'nativeReconcileEmptyPolicy' \
  'public final long policyRequestedRevision' \
  'public final long policyActiveRevision' \
  'public final long policyGeneration' \
  'public final long policySnapshotHash' \
  'public final boolean policySnapshotEmpty' \
  'public final boolean policyDefaultPass' \
  'public final int policyGateClaimCount' \
  'public final int policyL4RuleCount' \
  'public final boolean policyMixedRevision' \
  'public final boolean policyArtifactMatch' \
  'public final boolean policyGenerationMatch' \
  'public final String policySnapshotIdentity'; do
  grep -Fq "$token" "$native_status"
done

grep -Fq 'sakamoto_product_core_apply_empty_policy' "$ffi"
grep -Fq 'sakamoto_product_core_reconcile_empty_policy' "$ffi"
grep -Fq 'sakamoto_product_session_apply_policy' "$abi"
grep -Fq 'sizeof(sakamoto_product_policy_snapshot_t) == 264U' "$abi"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"

for token in \
  'EMPTY_POLICY_STORE_DIR: &str = "product-policy"' \
  'EMPTY_POLICY_STORE_FILE: &str = "empty-intent.properties"' \
  'ProductPolicyStore' \
  'current_empty_snapshot' \
  'publish_next_empty_snapshot' \
  'apply_empty_policy' \
  'reconcile_empty_policy' \
  'sakamoto_product_core_apply_empty_policy' \
  'sakamoto_product_core_reconcile_empty_policy' \
  'fnv1a64' \
  'assert_eq!(size_of::<ProductPolicySnapshot>(), 264)' \
  'assert_eq!(size_of::<ProductStatus>(), 1304)'; do
  grep -Fq "$token" "$rust_core"
done

for token in \
  'product_core_policy_apply' \
  'policy_requested_revision' \
  'policy_active_revision' \
  'policy_generation' \
  'policy_snapshot_hash' \
  'policy_worker0_revision' \
  'policy_worker1_revision' \
  'policy_snapshot_empty' \
  'policy_default_pass' \
  'policy_gate_claim_count' \
  'policy_l4_rule_count' \
  'policy_last_apply_status_code' \
  'policy_snapshot_identity[96]'; do
  grep -Fq "$token" "$api"
done

for token in \
  'vapi_product_core_policy_apply' \
  'apply_policy_snapshot' \
  'policy_apply_reply' \
  'query_status (session, status)'; do
  grep -Fq "$token" "$vapi"
done

for token in \
  'vl_api_product_core_policy_apply_t_handler' \
  'requested_revision == 0' \
  'policy_generation_match = 0' \
  'policy_active_revision = requested_revision' \
  'policy_worker0_revision = requested_revision' \
  'policy_worker1_revision = requested_revision' \
  'valid_empty = snapshot_empty && default_pass && gate_claim_count == 0' \
  'policy_snapshot_empty = snapshot_empty' \
  'policy_default_pass = default_pass' \
  'policy_gate_claim_count = gate_claim_count' \
  'policy_l4_rule_count = l4_rule_count' \
  'policy_mixed_revision = 0' \
  'policy_artifact_match = 1' \
  'product_packet_graph_clear_gate_policy'; do
  grep -Fq "$token" "$plugin"
done

for token in \
  'SAKAMOTO-188-empty-policy-snapshot' \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'debugApplyEmptyPolicy' \
  'files/product-state/s188-empty-policy-snapshot.properties' \
  'files/product-policy/empty-intent.properties' \
  '.s188-device-run.lock' \
  'clear_app_file "$STATE_PATH"' \
  'clear_app_file "$STATUS_PATH"' \
  'clear_authoring_policy_files' \
  'assert_authoring_policy_files_cleared' \
  'files/product-policy/policy-bundle.properties' \
  'files/product-policy/network-gate-intent.properties' \
  'files/product-policy/l4-intent.properties' \
  'files/product-transactions/transactions.properties' \
  'preflight_authoring_policy_cleared' \
  'current_runtime_generation' \
  'validate_runtime_state_file' \
  'generation <= min_generation' \
  'need("adapterReadiness", expected_adapter)' \
  'capture_s188_status root_apply root $((root_start_revision + 1)) "$root_start_generation"' \
  'capture_s188_status root_restart root "$root_apply_revision" "$root_restart_generation"' \
  'capture_s188_status vpn_reconcile vpn "$root_apply_revision" "$vpn_generation"' \
  'root-nfqueue' \
  'vpn-tun-hev-lwip' \
  'root_restart_same_revision' \
  'root_restart_same_snapshot_hash' \
  'root_restart_same_snapshot_identity' \
  'root_vpn_same_revision' \
  'rust_product_store_single_writer' \
  'no_gate_l4_claim' \
  'traffic_behavior_changed' \
  'policy_snapshot_identity' \
  'policy_snapshot_hash' \
  'runtimeStart true --es runtimeProfile "$profile"' \
  'am force-stop "$PACKAGE"'; do
  grep -Fq "$token" "$device_runner"
done

if grep -Eq 'sakamoto-app|adb[.]exe|tun-poc|vpnlite|toybox nc|build-release-candidate|build-final-release|rm -rf' "$device_runner"; then
  echo "S188 runner uses a release/retired/historical path" >&2
  exit 1
fi

echo "sakamoto-188 empty policy snapshot contract: PASS"
