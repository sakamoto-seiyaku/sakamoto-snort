#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
stage="${SAKAMOTO_S173_VPP_STAGE_DIR:-/tmp/sakamoto-172-product-stage}"
source_manifest="$repo_root/src/product/vpp/product-vpp-artifact.properties"
product_manifest="$stage/product-stage.properties"
vpp="$stage/lib/arm64-v8a/libvpp_runtime.so"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
lifecycle="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCoreLifecycle.java"

test -f "$source_manifest"
test -f "$product_manifest"
test -f "$vpp"

source_value() { sed -n "s/^$1=//p" "$source_manifest"; }
manifest_value() { sed -n "s/^$1=//p" "$product_manifest"; }
artifact_id="$(source_value artifact.id)"
api_identity="$(source_value product.api.identity)"
abi_version="$(source_value product.abi.version)"
api_version="$(source_value product.api.version)"
test "$(manifest_value artifactId)" = "$artifact_id"
test "$(manifest_value apiIdentity)" = "$api_identity"
test "$(manifest_value abiVersion)" = "$abi_version"
test "$(manifest_value apiVersion)" = "$api_version"
expected_hash="$(manifest_value vppBinarySha256)"
[[ "$expected_hash" =~ ^[[:xdigit:]]{64}$ ]]
actual_hash="$(sha256sum "$vpp" | awk '{print $1}')"
test "$actual_hash" = "$expected_hash"

# Build-tree VAPI output is not a device acceptance result; identity is
# checked at the public lifecycle seam and against the installed executable.
grep -Fq 'public static String validate(' "$lifecycle"
grep -Fq 'ProductCoreLifecycle.validate(generation, productArtifactId' "$service"
grep -Fq 'product_artifact_hash_mismatch' "$service"
grep -Fq 'product_abi_mismatch' "$service"
grep -Fq 'productCoreConnectFailureCode' "$service"
grep -Fq 'ProductCoreLifecycle.isIdentityFailure(validation)' "$service"

echo "s173 product identity contract: PASS"
