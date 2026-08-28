#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
helpers="$repo_root/tools/product/path-helpers.sh"
source "$helpers"
product_prepare_build_output
suffix="$$"
runtime_root="$repo_root/build-output/product-vpp-runtime-path-contract-$suffix"
runtime_link="$repo_root/build-output/product-vpp-runtime-path-link-$suffix"
cleanup() {
  rm -rf -- "$runtime_root" "$runtime_link"
}
trap cleanup EXIT
mkdir -p "$runtime_root"

set +e
product_validate_runtime_root "$repo_root/../unsafe-runtime" >/dev/null 2>&1
unsafe_status=$?
product_validate_runtime_root "$repo_root/build-output/product-vpp-runtime unsafe-$suffix" \
  >/dev/null 2>&1
space_status=$?
product_validate_owned_child "$runtime_root" ../escape >/dev/null 2>&1
escape_status=$?
set -e
if [[ "$unsafe_status" -ne 2 || "$space_status" -ne 2 || "$escape_status" -ne 2 ]]; then
  echo "unsafe product path was accepted" >&2
  exit 1
fi

ln -s "$runtime_root" "$runtime_link"
set +e
product_validate_runtime_root "$runtime_link" >/dev/null 2>&1
link_status=$?
set -e
if [[ "$link_status" -ne 2 ]]; then
  echo "symlinked product runtime path was accepted" >&2
  exit 1
fi

echo "sakamoto product path contract: PASS"
