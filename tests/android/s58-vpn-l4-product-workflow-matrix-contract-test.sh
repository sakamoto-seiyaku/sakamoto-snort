#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/s58-vpn-l4-product-workflow-matrix.sh"
debug_activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"

if [[ ! -f "$matrix" ]]; then
  echo "missing S58 VPN L4 product workflow matrix: $matrix" >&2
  exit 1
fi

if grep -Eq '(^|[^./[:alnum:]_-])adb([[:space:]]|$)' "$matrix"; then
  echo "S58 VPN L4 product workflow matrix must use repo-local ./dev/adb, not raw adb" >&2
  exit 1
fi

grep -q 'export ADB="${repo_root}/dev/adb"' "$matrix"
grep -q 'SAKAMOTO-58-vpn-l4-product-workflow' "$matrix"
grep -q 'S58_APK_VARIANT' "$matrix"
grep -q 'ANDROID_RUNTIME_APK_VARIANT' "$matrix"
grep -q 'build-release-candidate-apk.sh' "$matrix"
grep -q 'sakamoto-runtime-release-candidate.apk' "$matrix"
grep -q 'app_file_cat' "$matrix"
grep -q 'app_file_rm' "$matrix"
grep -q 'adb_su' "$matrix"
grep -q 'debugSetL4RuleSubject' "$matrix"
grep -q 'debugSetL4RuleDestinationCidr' "$matrix"
grep -q 'debugSetL4RuleAction' "$matrix"
grep -q 'debugTrafficSourcePort' "$matrix"
grep -q 'VPN_TUN.ATTRIBUTION.APPLY' "$matrix"
grep -q 'debugL4PrefillFromActivity' "$matrix"
grep -q 'policyDropActivity' "$matrix"
grep -q 'allowedFlowActivity' "$matrix"
grep -q 'drop.activityPrefill" "PASS' "$matrix"
grep -q 'open.restoreAllowedFlowEntry" "PASS' "$matrix"
grep -q 'first.noRecognitionHold" "claimed' "$matrix"
grep -q 'matrix.s58VpnProductWorkflowEvidence" "claimed' "$matrix"

grep -q 'ActivityL4RuleDraft.fromTcpPolicyDropActivity' "$debug_activity"
grep -q 'formatAllowedFlowActivity' "$debug_activity"
grep -q 'debugPacketStatusCommand(profile)' "$debug_activity"

echo "s58 vpn l4 product workflow matrix static contract: PASS"
