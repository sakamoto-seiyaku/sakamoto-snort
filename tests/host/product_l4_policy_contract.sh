#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-product-l4-policy.XXXXXX")"
cleanup() {
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT

header="$repo_root/src/product/vpp/product_l4_policy.h"
source="$repo_root/src/product/vpp/product_l4_policy.c"
test_source="$repo_root/tests/host/product_l4_policy_test.c"

[[ -f "$header" && -f "$source" && -f "$test_source" ]] || {
  echo "SAKAMOTO-192 L4 policy contract: missing standalone module source" >&2
  exit 1
}

# The Host contract must remain independent of VPP/Android/Rust and must not
# accidentally restore the removed Snort C++ or NDK implementation boundary.
for forbidden in '<vlib/' 'jni.h' 'jni/' 'product_core.api' 'extern "C"' \
  'sucre-snort' 'SnortConfig' 'nfq_q_handle'; do
  if grep -Fq "$forbidden" "$header" "$source" "$test_source"; then
    echo "SAKAMOTO-192 L4 policy contract: forbidden dependency $forbidden" >&2
    exit 1
  fi
done

for variant in baseline root-batch; do
  experiment_flags=()
  if [[ "$variant" == root-batch ]]; then
    experiment_flags=(-DSAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT=1)
  fi
  cc -std=c11 -Wall -Wextra -Werror -pedantic "${experiment_flags[@]}" \
    -I"$repo_root/src/product/vpp" \
    "$source" "$test_source" -o "$fixture_root/product-l4-policy-$variant-test"
  "$fixture_root/product-l4-policy-$variant-test"
done
echo "sakamoto S192 standalone stateless L4 policy contract: PASS"
