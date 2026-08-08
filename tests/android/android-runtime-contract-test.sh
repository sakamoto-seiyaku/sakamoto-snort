#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rtk rm -rf "$out_dir"' EXIT

rtk javac -source 8 -target 8 -d "$out_dir" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlRequest.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeProfile.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/BoundedText.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeSnapshot.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeOwnershipReconciliation.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeStateStore.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/VppHealthHandshake.java" \
  "$repo_root/tests/android/AndroidRuntimeContractTest.java"
rtk java -cp "$out_dir" AndroidRuntimeContractTest

echo "android runtime contract seam: PASS"
