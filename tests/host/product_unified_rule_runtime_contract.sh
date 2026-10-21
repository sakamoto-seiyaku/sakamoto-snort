#!/usr/bin/env bash
set -euo pipefail

# Current installed Product RuleConfig seam. A Host VPP without a Root/VPN
# Adapter can save a source but cannot publish an active packet snapshot;
# executable policy tests cover that publication and its decisions separately.
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
: "${PRODUCT_ARTIFACT_DIR:?set PRODUCT_ARTIFACT_DIR to the exact Host Product artifact}"
artifact_root="$(realpath -e -- "$PRODUCT_ARTIFACT_DIR")"
core="$artifact_root/bin/sakamoto-product-core-host"
launcher="$repo_root/tools/product/run-host-vpp.sh"
stopper="$repo_root/tools/product/stop-host-vpp.sh"
residue="$repo_root/tools/product/host-residue-check.sh"
evidence_base="${SAKAMOTO_RULE_RUNTIME_EVIDENCE_DIR:-/tmp}"
mkdir -p -- "$evidence_base"
case_root="$(mktemp -d "$evidence_base/sakamoto-rule-runtime.XXXXXX")"
mkdir -- "$case_root/config"
export LD_LIBRARY_PATH="$artifact_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
vpp_pid=
runtime_dir=
run=

fail() { echo "Product unified rule runtime contract: FAIL: $*" >&2; exit 1; }
require() { grep -Fxq -- "$2" "$1" || fail "missing $2 in $1"; }

stop() {
  [[ -n "$vpp_pid" ]] || return 0
  PRODUCT_ARTIFACT_DIR="$artifact_root" PRODUCT_RUNTIME_DIR="$runtime_dir" \
    "$stopper" >"$case_root/stop-$run.trace" 2>&1 || fail "stop failed"
  wait "$vpp_pid" || true
  vpp_pid=
  PRODUCT_ARTIFACT_DIR="$artifact_root" PRODUCT_RUNTIME_DIR="$runtime_dir" \
    "$residue" >"$case_root/residue-$run.trace" 2>&1 || fail "residue remained"
}
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$vpp_pid" ]]; then
    PRODUCT_ARTIFACT_DIR="$artifact_root" PRODUCT_RUNTIME_DIR="$runtime_dir" \
      "$stopper" >"$case_root/cleanup-$run.trace" 2>&1 || status=1
    wait "$vpp_pid" 2>/dev/null || true
    PRODUCT_ARTIFACT_DIR="$artifact_root" PRODUCT_RUNTIME_DIR="$runtime_dir" \
      "$residue" >"$case_root/cleanup-residue-$run.trace" 2>&1 || status=1
  fi
  exit "$status"
}
trap cleanup EXIT

[[ -x "$core" && -f "$artifact_root/product-vpp-artifact.properties" ]] ||
  fail "exact installed Product artifact is missing"
sha256sum "$artifact_root/product-vpp-artifact.properties" \
  "$artifact_root/lib/vpp_plugins/product_core_plugin.so" "$core" \
  >"$case_root/artifact.sha256"

start() {
  run="$1"
  runtime_dir="$repo_root/build-output/product-vpp-runtime-s305-rule-$run-$$"
  printf '%s=%s\n' "$run" "$runtime_dir" >>"$case_root/runtime-paths.trace"
  PRODUCT_ARTIFACT_DIR="$artifact_root" PRODUCT_RUNTIME_DIR="$runtime_dir" \
    PRODUCT_RULE_CONFIG_DIR="$case_root/config" PRODUCT_GENERATION="$2" \
    PRODUCT_WORKER_COUNT=2 "$launcher" >"$case_root/vpp-$run.trace" 2>&1 &
  vpp_pid=$!
  for _ in {1..200}; do
    [[ -S "$runtime_dir/api.sock" ]] && break
    if ! kill -0 "$vpp_pid" 2>/dev/null; then
      cat "$case_root/vpp-$run.trace" >&2
      fail "installed VPP exited before API readiness"
    fi
    sleep 0.05
  done
  [[ -S "$runtime_dir/api.sock" ]] || fail "API socket did not become ready"
}

start first 305001
"$core" rule-query "$runtime_dir/api.sock" 305001 >"$case_root/initial-query.trace"
require "$case_root/initial-query.trace" 'config.result=0'
require "$case_root/initial-query.trace" 'config.count=0'
initial_revision="$(awk -F= '$1 == "config.saved_revision" { print $2 }' "$case_root/initial-query.trace")"
[[ "$initial_revision" =~ ^[0-9]+$ ]] || fail "initial saved revision is missing"
initial_active="$(awk -F= '$1 == "config.active_revision" { print $2 }' "$case_root/initial-query.trace")"
[[ "$initial_active" =~ ^[0-9]+$ ]] || fail "initial active revision is missing"
next_revision="$((initial_revision + 1))"

if "$core" rule-replace "$runtime_dir/api.sock" 305001 "$initial_revision" 10001 \
     10.0.0.1 10.0.0.2 32000 53 drop >"$case_root/apply.trace"; then
  fail "bare Host VPP claimed an active packet policy without an Adapter"
fi
require "$case_root/apply.trace" 'config.result=6'
require "$case_root/apply.trace" "config.saved_revision=$next_revision"
require "$case_root/apply.trace" "config.active_revision=$initial_active"
require "$case_root/apply.trace" 'config.count=1'
require "$case_root/apply.trace" 'config.active_count=0'
require "$case_root/apply.trace" 'config.rule.0.uid=10001'
require "$case_root/apply.trace" 'config.rule.0.action=2'
require "$case_root/apply.trace" 'config.save_error=0'
require "$case_root/apply.trace" 'config.compile_error=6'

if "$core" rule-replace "$runtime_dir/api.sock" 305001 "$initial_revision" 10001 \
     10.0.0.1 10.0.0.2 32000 53 allow >"$case_root/stale-apply.trace" 2>&1; then
  fail "stale expected saved revision was accepted"
fi
"$core" rule-query "$runtime_dir/api.sock" 305001 >"$case_root/after-stale-query.trace"
require "$case_root/after-stale-query.trace" "config.saved_revision=$next_revision"
require "$case_root/after-stale-query.trace" "config.active_revision=$initial_active"
require "$case_root/after-stale-query.trace" 'config.rule.0.action=2'
stop

[[ -s "$case_root/config/rules.conf" ]] || fail "VPP did not save its source"
sha256sum "$case_root/config/rules.conf" >"$case_root/saved-source.sha256"
start second 305002
"$core" rule-query "$runtime_dir/api.sock" 305002 >"$case_root/restarted-query.trace"
require "$case_root/restarted-query.trace" 'config.result=0'
require "$case_root/restarted-query.trace" "config.saved_revision=$next_revision"
require "$case_root/restarted-query.trace" "config.active_revision=$initial_active"
require "$case_root/restarted-query.trace" 'config.count=1'
require "$case_root/restarted-query.trace" 'config.active_count=0'
require "$case_root/restarted-query.trace" 'config.rule.0.uid=10001'
require "$case_root/restarted-query.trace" 'config.rule.0.action=2'
sha256sum -c "$case_root/saved-source.sha256" >"$case_root/restart-source-check.trace"
stop

echo "Product unified rule runtime contract: PASS"
echo "evidence=$case_root"
