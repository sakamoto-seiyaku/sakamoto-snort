#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
product_dir="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime"
runtime_contract="$repo_root/tests/android/android-runtime-contract-test.sh"
debug_activity="$product_dir/DebugControlActivity.java"

for model in RuntimeSummary AppSummary AppDetail RuleDraft RuleView ActivityItem HealthIssue CapabilitySet; do
  source_file="$product_dir/${model}.java"
  test -f "$source_file"
  grep -q "public final class ${model}" "$source_file"
  grep -q "${model}[.]java" "$runtime_contract"
done

grep -q 'CapabilitySet.androidL4' "$product_dir/CapabilitySet.java"
grep -q 'HealthIssue.CATEGORY_PERMISSION' "$repo_root/tests/android/AndroidRuntimeContractTest.java"
grep -q 'HealthIssue.CATEGORY_TRANSPORT_FAILURE' "$repo_root/tests/android/AndroidRuntimeContractTest.java"
grep -q 'HealthIssue.CATEGORY_APPLY_FAILURE' "$repo_root/tests/android/AndroidRuntimeContractTest.java"
grep -q 'AppDetail.STATE_NORMAL' "$repo_root/tests/android/AndroidRuntimeContractTest.java"

grep -q 'bounded_activity_accumulator' "$product_dir/ActivityItem.java"
grep -q 'flow_entry' "$product_dir/ActivityItem.java"
grep -q 'policyRevision' "$product_dir/ActivityItem.java"
grep -q 'devicePacketDirection' "$product_dir/ActivityItem.java"
grep -q 'flowDirection' "$product_dir/ActivityItem.java"
grep -q 'winner' "$product_dir/ActivityItem.java"
grep -q 'RuleDraft.fromActivityL4RuleDraft' "$product_dir/RuleDraft.java"
grep -q 'ActivityL4RuleDraft.fromTcpPolicyDropActivity' "$debug_activity"
grep -q 'formatPolicyDropActivity' "$debug_activity"
grep -q 'formatAllowedFlowActivity' "$debug_activity"
grep -q 'private final BoundedActivityStore activityStore' "$product_dir/LocalProductBackend.java"
grep -q 'new BoundedActivityStore(BoundedActivityStore.DEFAULT_CAPACITY)' "$product_dir/LocalProductBackend.java"
grep -q 'void ingestActivity(ActivityItem item)' "$product_dir/LocalProductBackend.java"
grep -q 'AppDetail appDetail' "$product_dir/LocalProductBackend.java"
grep -q 'refreshProductActivityProjection' "$product_dir/LocalProductBackend.java"
grep -q 'ProductActivityProjectionStore.write' "$product_dir/LocalProductBackend.java"
grep -q 'ProductActivityProjectionStore.read' "$debug_activity"
grep -q 'product-activity-projection' "$product_dir/ProductActivityProjectionStore.java"
grep -q 'app-detail.properties' "$product_dir/ProductActivityProjectionStore.java"
grep -q 'output.getFD().sync()' "$product_dir/ProductActivityProjectionStore.java"
grep -q 'ProductActivityProjectionStore.java' "$runtime_contract"
grep -q 'activityItemsFor' "$product_dir/BoundedActivityStore.java"
grep -q 'LocalProductBackend' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'ProductNativeActivityIngestor.java' "$runtime_contract"
grep -q 'native_policy_drop_activity' "$product_dir/ProductNativeActivityIngestor.java"
grep -q 'NativeAllowedFlowRecord' "$product_dir/ProductNativeActivityIngestor.java"
grep -q 'lastProtocolRecognitionState' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'flow_entry_lpi_recognition' "$product_dir/ActivityItem.java"
grep -q 'ActivityItem.protocolRecognition' "$product_dir/ProductNativeActivityIngestor.java"
grep -q 'allowedFlowActivity' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'NFQUEUE.STATUS' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'VPN_TUN.STATUS' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'ingestLatestNativeActivity' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'productBackend.ingestActivity(item)' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'productBackend.ingestActivity(allowed)' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'refreshProductActivityProjection("query"' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'refreshProductActivityProjection("network_gate"' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
grep -q 'refreshProductActivityProjection("l4_rule"' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
! grep -q 'LocalProductBackend' "$debug_activity"

for source_file in \
  "$product_dir/RuntimeSummary.java" \
  "$product_dir/AppSummary.java" \
  "$product_dir/AppDetail.java" \
  "$product_dir/RuleDraft.java" \
  "$product_dir/RuleView.java" \
  "$product_dir/ActivityItem.java" \
  "$product_dir/HealthIssue.java" \
  "$product_dir/CapabilitySet.java"; do
  ! grep -Eq 'PacketLease|VAPI|vapi|NFQUEUE|nfqueue|buffer index|worker lane|daemon artifact|generated_vapi' "$source_file"
done

echo "s58 app-first activity ui contract: PASS"
