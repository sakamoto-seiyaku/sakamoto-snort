#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

javac -source 8 -target 8 -d "$out_dir" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlRequest.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlOrdering.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeProfile.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/BoundedText.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationSubjectId.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationCatalogEntry.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationCatalogProvider.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AuthoringPolicyBundle.java" \
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
