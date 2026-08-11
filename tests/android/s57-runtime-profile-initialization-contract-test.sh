#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
product_plan="$repo_root/docs/product/ANDROID_L4_PRODUCT_PLAN.md"
plan_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeProfileInitializationPlan.java"
runtime_contract="$repo_root/tests/android/AndroidRuntimeContractTest.java"
runtime_contract_script="$repo_root/tests/android/runtime-contract-test.sh"
device_matrix="$repo_root/tests/device/s70-profile-lifecycle-matrix.sh"

grep -q 'Runtime Profile Initialization' "$product_plan"
grep -q '推荐 Root，否则推荐 VPN' "$product_plan"
grep -q '请求并验证 Visible Runtime Notification' "$product_plan"
grep -q '启动并验证对应 Adapter、双栈 packet runtime 与 Runtime health' "$product_plan"
grep -q '切换 Profile 必须先停止当前 runtime' "$product_plan"
grep -q '切换过程保留同一 Authoring Policy Bundle' "$product_plan"

grep -q 'RuntimeProfileInitializationPlan' "$plan_source"
grep -q 'PROFILE_CONFIRMATION' "$plan_source"
grep -q 'VISIBLE_NOTIFICATION' "$plan_source"
grep -q 'PROFILE_AUTHORIZATION' "$plan_source"
grep -q 'RUNTIME_READINESS' "$plan_source"
grep -q 'shouldAutoAuthorize = false' "$plan_source"
grep -q 'shouldAutoStart = false' "$plan_source"
grep -q 'shouldAutoSwitchProfile = false' "$plan_source"
grep -q 'Authoring Policy Bundle' "$plan_source"
grep -q 'IPv4/IPv6 packet runtime' "$plan_source"

grep -q 'runtimeProfileInitializationPlanIsExplicitAndRecoverable' "$runtime_contract"
grep -q 'Root capability is recommended when present' "$runtime_contract"
grep -q 'VPN is recommended when Root capability is unavailable' "$runtime_contract"
grep -q 'visible notification is a gate before profile authorization and launch' "$runtime_contract"
grep -q 'initialization plan never grants permissions, starts, or switches runtime' "$runtime_contract"

grep -q 'start_profile root' "$device_matrix"
grep -q 'start_profile vpn' "$device_matrix"
grep -q 'switch_root_to_vpn' "$device_matrix"
grep -q 'switch_vpn_to_root' "$device_matrix"
grep -q 'assert_policy_bundle_preserved' "$device_matrix"
grep -q 'pause.lastSuccessfulPolicyPreserved' "$device_matrix"
grep -q 's57-runtime-profile-initialization-contract-test.sh' "$runtime_contract_script"

echo "s57 runtime profile initialization static contract: PASS"
