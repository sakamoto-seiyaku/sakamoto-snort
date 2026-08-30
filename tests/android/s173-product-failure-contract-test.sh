#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
lifecycle="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCoreLifecycle.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
java_native="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
rust="$repo_root/crates/product-core/src/lib.rs"

test -f "$service"
test -f "$lifecycle"
test -f "$jni"
test -f "$java_native"
test -f "$abi"
test -f "$rust"

# A non-zero native status is already a typed result. The supervisor must
# expose that result at the visible Product Core failure seam instead of
# replacing it with a generic readiness timeout.
grep -Fq 'ProductCoreLifecycle.failureCode(status)' "$service"
grep -Fq 'ProductCoreLifecycle.isRetryableConnectionFailure(validation)' "$service"
grep -Fq 'session.closeAndGetStatus()' "$service"
grep -Fq 'public static String failureCode(' "$lifecycle"
grep -Fq 'product_core_allocation_failed' "$lifecycle"
grep -Fq 'product_core_connect_failed' "$lifecycle"
grep -Fq 'product_core_api_unavailable' "$lifecycle"
grep -Fq 'product_core_query_failed' "$lifecycle"
grep -Fq 'SAKAMOTO_PRODUCT_DISCONNECT_FAILED UINT32_C(11)' "$abi"
grep -Fq 'DisconnectFailed' "$rust"

# Readiness must compare against the installed artifact identity supplied by
# RuntimeService; the old self-expected overload could accept a reply's own
# artifact/API strings and create a false PASS.
if grep -Fq 'isReady(long generation, String expectedVppRevision' "$lifecycle"; then
  echo "Product Core readiness still exposes a self-expected overload" >&2
  exit 1
fi

# JNI returns the ABI function's code as part of the same status value; a
# bridge mismatch must not silently become a successful/unknown Java status.
grep -Fq 'status.status_code = code;' "$jni"

# Session shutdown retains the native disconnect result for the supervisor;
# AutoCloseable.close() itself remains source-compatible with existing callers.
grep -Fq 'closeAndGetStatus' "$java_native"
grep -Fq 'disconnectCode' "$java_native"

echo "s173 product failure code contract: PASS"
