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
preinstall_line="$(grep -n 'cleanup_verified_vpp_owners preinstall$' "$harness" | head -n 1 | cut -d: -f1)"
install_line="$(grep -n 'adb_cmd install -r' "$harness" | head -n 1 | cut -d: -f1)"
[[ "$preinstall_line" =~ ^[0-9]+$ && "$install_line" =~ ^[0-9]+$ \
    && "$preinstall_line" -lt "$install_line" ]] \
  || { echo "APK replacement occurs before old-path owner cleanup" >&2; exit 1; }
grep -q 'preinstallRuntimePath=' "$harness"
grep -q 'packaged VPP remains after preinstall clear' "$harness"
grep -q 'env_raw_file=' "$harness"
if grep -Eq 'env_raw=\\\$\\\(runcon .*environ' "$harness"; then
  echo "owner verifier stores NUL-delimited /proc environ in command substitution" >&2
  exit 1
fi
grep -q 'trap .*cleanup_remote_temp' "$harness"
grep -q 'sakamoto-67-vpp-owner-ps.\*' "$harness"

# The Windows adb bridge can hang independently of the device. Every
# lifecycle command, including force-stop, must therefore run through one
# bounded timeout wrapper rather than invoking the bridge directly.
grep -q 'adb_timeout_seconds=' "$harness"
grep -q 'timeout --foreground --signal=TERM --kill-after=5s' "$harness"
grep -q 'adb_cmd() { adb_exec -s' "$harness"
grep -q 'adb_cmd shell am force-stop' "$harness"
if grep -Eq '"\$adb" -s' "$harness"; then
  echo "lifecycle harness invokes adb directly outside the bounded wrapper" >&2
  exit 1
fi

# A retained marker is not provenance. The stage boundary must rebuild from a
# pinned git archive, record the archive digest, then bind the final overlay
# tree digest.
grep -q 'baseArchiveSha256' "$stage_script"
grep -q 'archive --format=tar' "$stage_script"
grep -q 'apply-vpp-android-overlay.sh' "$stage_script"
grep -q 'sourceTreeSha256' "$stage_script"

echo "android runtime hardening contract: PASS"
