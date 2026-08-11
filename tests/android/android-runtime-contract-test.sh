#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

javac -source 8 -target 8 -d "$out_dir" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlRequest.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlOrdering.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeRecoveryPolicy.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeProfile.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeProfileInitializationPlan.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/BoundedText.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPacketAdapterContract.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationSubjectId.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationProtocolCatalog.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationCatalogEntry.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationCatalogProvider.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ActivityL4RuleDraft.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProtocolRecognitionSequence.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProtocolRecognitionProjection.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCatalogFormatter.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCatalogProjectionStore.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductActivityProjectionStore.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductNativeActivityIngestor.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPolicyTransactions.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPolicyTransactionStore.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/CapabilitySet.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/HealthIssue.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeSummary.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AppSummary.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AppDetail.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ReleaseDiagnosticsExport.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuleDraft.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuleView.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ActivityItem.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AuthoringPolicyBundle.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AuthoringPolicyCompiler.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductStateSnapshot.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductStateStore.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductStore.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/BoundedActivityStore.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/LocalProductBackend.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeSnapshot.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeOwnershipReconciliation.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeStateStore.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/VppHealthHandshake.java" \
  "$repo_root/tests/android/AndroidRuntimeContractTest.java"
java -cp "$out_dir" AndroidRuntimeContractTest

echo "android runtime contract seam: PASS"
