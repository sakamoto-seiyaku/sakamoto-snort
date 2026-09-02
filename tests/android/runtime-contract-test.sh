#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# Compatibility entry point for older host/device aggregators. The former
# script compiled the removed vpn-lite experiment and positively asserted the
# retired C++ daemon. Current-head coverage belongs to the VPP-native Android
# contracts below; stage/pinned-source and device acceptance gates run from
# their S172-S196 entry points.
contracts=(
  android-runtime-contract-test.sh
  s192-policy-bundle-contract-test.sh
  s173-product-failure-contract-test.sh
  s173-product-owner-contract-test.sh
  s196-runtime-instance-teardown-contract-test.sh
)

for contract in "${contracts[@]}"; do
  bash "$repo_root/tests/android/$contract"
done

echo "current Android runtime contract suite: PASS"
