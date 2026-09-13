#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
vapi="$repo_root/src/product/native/sakamoto_product_vapi.c"
ffi="$repo_root/src/product/include/sakamoto_product_core_ffi.h"
core="$repo_root/crates/product-core/src/lib.rs"
rust_ffi="$repo_root/crates/product-core/src/ffi.rs"
session="$repo_root/crates/product-core/src/session.rs"
lifecycle="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCoreLifecycle.java"
native="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
protocol="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java"
backend="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlBackend.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
formatter="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeEvidenceFormatter.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
device_runner="$repo_root/tests/device/s194-product-mutation-product.sh"

fail() {
  echo "s194 Android mutation contract: $*" >&2
  exit 1
}

grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN UINT32_C(14)' "$abi" \
  || fail "ABI unknown tag is not present"
grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_MUTATION_FENCED UINT32_C(15)' "$abi" \
  || fail "ABI fence tag is not present"
grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_OMIT_CALLBACK UINT32_C(1)' "$abi" \
  || fail "ABI callback-omission fault tag is not present"
grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT UINT32_C(2)' "$abi" \
  || fail "ABI pre-submit fault tag is not present"
grep -Fq 'sakamoto_product_session_set_policy_mutation_fault' "$abi" \
  || fail "ABI fault arming entry point is not present"
grep -Fq 'sakamoto_product_session_set_policy_mutation_fault' "$vapi" \
  || fail "VAPI fault arming entry point is not present"
grep -Fq 'debug policy bundle apply was not submitted' "$vapi" \
  || fail "VAPI pre-submit fault does not expose a definite not-submitted detail"
grep -Fq 'sakamoto_product_core_set_policy_mutation_fault' "$ffi" \
  || fail "Rust C facade fault entry point is not present"
grep -Fq 'sakamoto_product_core_set_policy_mutation_fault' "$rust_ffi" \
  || fail "Rust fault entry point is not present"
grep -Fq 'Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeSetPolicyMutationFault' "$jni" \
  || fail "JNI fault entry point is not present"
grep -Fq 'case 14:' "$lifecycle" \
  || fail "Android does not project outcome unknown"
grep -Fq 'product_policy_outcome_unknown' "$lifecycle" \
  || fail "Android unknown projection is unstable"
grep -Fq 'case 15:' "$lifecycle" \
  || fail "Android does not project mutation fenced"
grep -Fq 'product_policy_mutation_fenced' "$lifecycle" \
  || fail "Android fence projection is unstable"

grep -Fq 'public synchronized Status applyPolicyBundle' "$native" \
  || fail "bundle mutation is not serialized"
grep -Fq 'public synchronized Status reconcilePolicy' "$native" \
  || fail "reconcile is not serialized"
grep -Fq 'fresh-generation active-state readback' "$native" \
  || fail "reconcile documentation does not state readback-only recovery"
grep -Fq 'session.applyPolicyBundle' "$service" \
  || fail "RuntimeService is not using the typed Product Core apply"
grep -Fq 'setPolicyMutationFaultMode' "$native" \
  || fail "Java native session has no typed fault seam"
grep -Fq 'bundle_callback_omission' "$native" \
  || fail "Java callback-omission mode is not bound"
grep -Fq 'bundle_pre_submit_not_sent' "$native" \
  || fail "Java pre-submit mode is not bound"
grep -Fq 'EXTRA_POLICY_MUTATION_FAULT_MODE' "$protocol" \
  || fail "control protocol has no typed fault extra"
grep -Fq 'setPolicyMutationFaultMode' "$backend" \
  || fail "control backend has no typed fault action"
grep -Fq 'EXTRA_RUNTIME_POLICY_MUTATION_FAULT_MODE' "$activity" \
  || fail "DebugControlActivity has no typed fault action"
grep -Fq 'ApplicationInfo.FLAG_DEBUGGABLE' "$service" \
  || fail "typed fault seam is not debug-only"
grep -Fq 'writeS194ProductMutationStatus' "$service" \
  || fail "RuntimeService has no S194 mutation evidence"
grep -Fq 'RuntimeEvidenceFormatter.productMutation(' "$service" \
  || fail "RuntimeService does not use the S194 formatter"
grep -Fq 'RuntimeEvidenceFormatter.policyMutationFault(' "$service" \
  || fail "RuntimeService does not use the S194 fault formatter"
grep -Fq 'reconcile_no_replay' "$formatter" \
  || fail "RuntimeService does not publish no-replay evidence"
grep -Fq 'reconciliationReadbackOnly' "$service" \
  || fail "RuntimeService does not preserve fresh reconcile resolution state"
grep -Fq 'RuntimeEvidenceFormatter.isUnknownPolicyMutationReadbackDetail(reconciliationDetail)' "$service" \
  || fail "RuntimeService does not use the shared readback classification"
grep -Fq 'appendLog(reconciliationDetail)' "$service" \
  || fail "RuntimeService does not log fresh reconcile resolution"
grep -Fq 'isUnknownPolicyMutationReadbackDetail(errorMessage)' "$formatter" \
  || fail "S194 status bridge drops preserved readback-only resolution detail"

test -x "$device_runner" || fail "S194 device runner is missing or not executable"
bash -n "$device_runner" || fail "S194 device runner has shell syntax errors"
runner_help="$(bash "$device_runner" --help)"
grep -Fq 'bundle_pre_submit_not_sent' <<<"$runner_help" \
  || fail "S194 runner does not expose pre-submit fault mode"
grep -Fq 'bundle_callback_omission' <<<"$runner_help" \
  || fail "S194 runner does not expose callback-omission fault mode"
for marker in candidate fence blocked reconcile no-replay; do
  grep -Fiq "$marker" "$device_runner" \
    || fail "S194 runner does not record $marker evidence"
done
grep -Fq 'runtimePolicyMutationFaultMode' "$device_runner" \
  || fail "S194 runner does not drive the Activity fault extra"
grep -Fq 'debugSetL4RuleSubject' "$device_runner" \
  || fail "S194 runner does not exercise typed L4 mutation"

# The fence is owned by Rust Product Core.  Android must not add a retry or a
# second bundle submission after the native unknown result.
grep -Fq 'PolicyMutationFenced' "$core" \
  || fail "Rust fence state is absent from the Android-visible core"
grep -Fq 'without issuing another VAPI mutation' "$session" \
  || fail "fresh-generation reconcile is not explicitly readback-only"
grep -Fq 'store.clear_mutation_fence()' "$session" \
  || fail "fence lifecycle has no clear operation"

echo "s194 Android mutation contract: PASS"
