#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf -- "$out_dir"' EXIT

cc -std=c11 -Wall -Wextra -Werror \
  -I"$repo_root/src/product/include" \
  "$repo_root/tests/host/s192_product_policy_bundle_test.c" \
  -o "$out_dir/s192-product-policy-bundle-test"
"$out_dir/s192-product-policy-bundle-test"

rust="$repo_root/crates/product-core/src/lib.rs"
grep -Fq 'fn validate_policy_bundle' "$rust"
grep -Fq 'policy-bundle.properties' "$rust"
grep -Fq 'fs::rename(temporary, &target)' "$rust"
grep -Fq 'status.generation == expected_generation' "$rust"
grep -Fq 'status.policy_generation == expected_generation' "$rust"
grep -Fq 'status.policy_generation_match' "$rust"
grep -Fq 'status.policy_last_apply_status_code == 0' "$rust"
grep -Fq 'status.policy_artifact_match' "$rust"
grep -Fq 'status.artifact_id == fence.artifact_id' "$rust"
grep -Fq 'status.api_identity == fence.api_identity' "$rust"
grep -Fq 'status.code == ErrorCode::Ok' "$rust"

echo "s192 Product Host policy bundle contract: PASS"
