#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
rust_source="$repo_root/crates/product-core/src/ffi.rs"
ffi_header="$repo_root/src/product/include/sakamoto_product_core_ffi.h"
jni_source="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
java_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"

test -f "$rust_source"
test -f "$ffi_header"
test -f "$jni_source"
test -f "$java_source"
test -x "$build_script"

# Product Core owns the only opaque session.  The C facade must not expose the
# generated VAPI session type or make JNI call the C transport ABI directly.
for symbol in \
  sakamoto_product_core_connect \
  sakamoto_product_core_query \
  sakamoto_product_core_disconnect \
  sakamoto_product_core_destroy; do
  grep -Fq "$symbol" "$ffi_header"
  grep -Fq "$symbol" "$rust_source"
done
grep -Fq 'catch_unwind' "$rust_source"
grep -Fq 'ProductCore::connect' "$rust_source"
grep -Fq 'core.query' "$rust_source"
if grep -Fq 'sakamoto_product_session_' "$jni_source"; then
  echo "JNI bridge bypasses the Rust Product Core facade" >&2
  exit 1
fi

# JNI keeps one Rust-owned session across queries and carries the generation
# on every operation.  The fixed status fields are returned as a single Java
# value rather than the retired show_version tuple.
for symbol in \
  nativeConnect \
  nativeQuery \
  nativeDisconnect \
  nativeDestroy; do
  grep -Fq "$symbol" "$jni_source"
  grep -Fq "$symbol" "$java_source"
done
grep -Fq 'connect(String apiSocket, long generation)' "$java_source"
grep -Fq 'query()' "$java_source"
grep -Fq 'long generation' "$java_source"
for field in \
  'code' \
  'generation' \
  'coreReady' \
  'adapterAvailable' \
  'protectionRunning' \
  'pluginLoaded' \
  'vapiHandleLive' \
  'generationLive' \
  'artifactId' \
  'apiIdentity' \
  'vppRevision' \
  'errorDetail' \
  'rootNfqueueQueueId' \
  'rootNfqueueQueueLast' \
  'rootNfqueueLaneCount' \
  'rootNfqueueReadyLaneMask' \
  'rootNfqueueGeneration' \
  'rootNfqueueVerdictAttempts' \
  'rootNfqueueInternalSettlements' \
  'rootNfqueueBufferReturns' \
  'rootNfqueueOriginLocalCompletions' \
  'rootNfqueueOriginRemoteCompletions' \
  'rootNfqueueLane0VerdictAttempts' \
  'rootNfqueueLane1VerdictAttempts' \
  'rootNfqueueInputPackets' \
  'rootNfqueueOutputPackets' \
  'rootNfqueueIpv4Packets' \
  'rootNfqueueIpv6Packets' \
  'rootNfqueueTcpPackets' \
  'rootNfqueueUdpPackets' \
  'rootNfqueueUidKnownPackets' \
  'rootNfqueueUidUnknownPackets' \
  'rootNfqueueLastIpFamily' \
  'rootNfqueueLastProtocol' \
  'rootNfqueueLastHook' \
  'rootNfqueueLastUidKnown' \
  'rootNfqueueLastUid' \
  'rootNfqueueLastQueueId' \
  'rootNfqueueLastPacketId' \
  'rootNfqueueVerdictSucceeded' \
  'rootNfqueueVerdictFailedDefinite' \
  'rootNfqueueVerdictOutcomeUnknown' \
  'rootNfqueueIngressIdentityMissing' \
  'rootNfqueueGraphSubmitFailOpens' \
  'rootNfqueueNonOwnerBypasses' \
  'rootNfqueueDuplicateCompletionDrops' \
  'rootNfqueueStaleCompletionDrops'; do
  grep -Fq "$field" "$java_source"
done
if grep -Fq 'show_version' "$jni_source" || grep -Fq 'show_version' "$java_source"; then
  echo "retired show_version control path remains in the product bridge" >&2
  exit 1
fi

# The bridge is a packaged JNI shared object whose direct dependency is the
# Rust Product Core library.  The APK must carry it beside its dependency.
grep -Fq 'sakamoto_product_core_jni.c' "$build_script"
grep -Fq 'libsakamoto_runtime_control.so' "$build_script"
grep -Fq 'libsakamoto_product_core.so' "$build_script"
grep -Fq 'NEEDED' "$build_script"
grep -Fq 'sakamoto_runtime_control.so' "$build_script"

echo "sakamoto-172 Rust Product Core JNI contract: PASS"
