#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
spine_contract="$repo_root/tests/android/s172-product-spine-contract-test.sh"

test -x "$build_script"
test -x "$spine_contract"

# This entry point is kept for the older runtime aggregate suite.  The Android
# Product Core APK artifact boundary now lives at the SAKAMOTO-172 two-step
# seam: build-debug-apk.sh --stage-only publishes an owned product stage, and
# build-debug-apk.sh --apk-only packages exactly that stage.  The previous
# VPP_RUNTIME_STAGE_DIR/default-build path is intentionally no longer a product
# APK assembly path.
grep -Fq -- '--stage-only' "$build_script"
grep -Fq -- '--apk-only' "$build_script"
grep -Fq 'SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR' "$build_script"
grep -Fq 'Android product APK assembly is not enabled' "$build_script"

product_stage="${SAKAMOTO_S172_PRODUCT_STAGE_DIR:-${SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR:-}}"
if [[ -z "$product_stage" ]]; then
  echo "android runtime core artifact contract seam: SKIP (set SAKAMOTO_S172_PRODUCT_STAGE_DIR to run APK spine)"
  exit 0
fi

SAKAMOTO_S172_PRODUCT_STAGE_DIR="$product_stage" \
  bash "$spine_contract"

echo "android runtime core artifact contract seam: PASS"
