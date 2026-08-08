#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
harness="$repo_root/tests/integration/android-runtime-incubator-lifecycle.sh"
stage_script="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/scripts/stage-vpp-runtime.sh"

# A verifier failure is evidence of an unknown owner, never an empty owner
# list. Signal paths must re-run the complete verifier before each signal.
grep -q 'signal_verified_owner' "$harness"
if grep -Eq 'verified_owner_snapshot \|\| true|all_vpp_process_snapshot \|\| true|owner_output=.*\|\| true' "$harness"; then
  echo "owner verifier failures are being converted into zero-owner success" >&2
  exit 1
fi
grep -q 'signal_verified_owner .*TERM' "$harness"
grep -q 'signal_verified_owner .*KILL' "$harness"
grep -q 'OWNER_SCRIPT_OK=1' "$harness"

# A retained marker is not provenance. The stage boundary must rebuild from a
# pinned git archive, record the archive digest, then bind the final overlay
# tree digest.
grep -q 'baseArchiveSha256' "$stage_script"
grep -q 'archive --format=tar' "$stage_script"
grep -q 'apply-vpp-android-overlay.sh' "$stage_script"
grep -q 'sourceTreeSha256' "$stage_script"

echo "android runtime hardening contract: PASS"
