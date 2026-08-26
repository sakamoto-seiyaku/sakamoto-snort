#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
closure_contract="$repo_root/docs/decisions/ANDROID_FUNCTIONAL_CLOSURE_CONTRACT.md"
current_state="$repo_root/docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md"
roadmap="$repo_root/docs/IMPLEMENTATION_ROADMAP.md"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
recovery_policy="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeRecoveryPolicy.java"
runtime_contract="$repo_root/tests/android/AndroidRuntimeContractTest.java"
manifest="$repo_root/app/android-runtime/src/main/AndroidManifest.xml"

grep -q 'SAKAMOTO-54 Root permission revocation boundary' "$closure_contract"
grep -q 'Start/recovery authorization unavailable' "$closure_contract"
grep -q 'root_authorization_required' "$closure_contract"
grep -q 'RuntimeRecoveryPolicy.recoverable("root_authorization_required") == false' "$closure_contract"
grep -q 'KernelSU live revocation' "$closure_contract"
grep -q 'KernelSU platform boundary' "$closure_contract"
grep -q 'does not require destructive live allowlist mutation' "$closure_contract" || \
  grep -q '不再要求破坏性 live allowlist mutation 真机脚本' "$closure_contract"
grep -q 'fresh manual recovery' "$closure_contract"

grep -q 'root permission denied' "$current_state"
grep -q 'KernelSU live revocation' "$current_state"
grep -q '已知平台边界' "$current_state"
grep -q 'SAKAMOTO-24 RuntimeService root permission denial' "$roadmap"
grep -q 'SAKAMOTO-27 live KernelSU permission revocation' "$roadmap"

grep -q 'root_authorization_required' "$service"
grep -q '<queries>' "$manifest"
grep -q 'android:name="me.weishu.kernelsu"' "$manifest"
grep -q 'public boolean recoverable(String code)' "$recovery_policy"
grep -q 'runtime_start_failed' "$recovery_policy"
grep -q 'recoverable("root_authorization_required")' "$runtime_contract"
grep -q 'permission failures are surfaced to the user instead of auto-restarted' "$runtime_contract"

echo "s54 root permission boundary static contract: PASS"
