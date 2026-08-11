#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/s51-root-network-gate-product-matrix.sh"

[[ -f "$matrix" ]] || {
  echo "missing S51 root network gate matrix: $matrix" >&2
  exit 1
}

grep -q 'SAKAMOTO-51-root-network-gate-product-matrix' "$matrix"
grep -q './dev/adb' "$matrix"
grep -q 'export ADB="$SNORT_ROOT/dev/adb"' "$matrix"
if grep -Eq '(^|[[:space:]])adb([[:space:]]|$)|adb\.exe' "$matrix"; then
  echo "S51 root network gate matrix must use repo-local ./dev/adb, not raw adb" >&2
  exit 1
fi

grep -q 'localabstract:sucre-snort-control-vnext' "$matrix"
grep -q 'POLICY.APPLY' "$matrix"
grep -q 'POLICY.EVALUATE' "$matrix"
grep -q 'NFQUEUE.STATUS' "$matrix"
grep -q 'policyDropActivity' "$matrix"
grep -q 'lastRuleId' "$matrix"
grep -q 'lastRevision' "$matrix"
grep -q 'context_compile_matrix' "$matrix"
grep -q 'wifi:1' "$matrix"
grep -q 'mobile:2' "$matrix"
grep -q 'vpn:3' "$matrix"
grep -q 'unknown_subject' "$matrix"
grep -q 'block_real_traffic' "$matrix"
grep -q 'tcp_connect_failed' "$matrix"
grep -q 'apply_failure_preserves_snapshot' "$matrix"
grep -q 'policy_apply_duplicate_context' "$matrix"
grep -q 'open_restore' "$matrix"
grep -q 'tcp_connect_succeeded' "$matrix"
grep -q 'matrix.s51Done.*not_claimed' "$matrix"

echo "s51 root network gate product matrix static contract: PASS"
