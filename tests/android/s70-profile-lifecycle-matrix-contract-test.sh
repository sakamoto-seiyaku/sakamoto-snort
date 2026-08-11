#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/s70-profile-lifecycle-matrix.sh"

[[ -f "$matrix" ]]
grep -q 'SAKAMOTO-70-profile-lifecycle' "$matrix"
grep -q './dev/adb' "$matrix"
grep -q 'runtimeStart true --es runtimeProfile "$profile"' "$matrix"
grep -q 'start_profile root' "$matrix"
grep -q 'start_profile vpn' "$matrix"
grep -q 'switch_root_to_vpn' "$matrix"
grep -q 'switch_vpn_to_root' "$matrix"
grep -q 'activity_recreate_does_not_stop_runtime' "$matrix"
grep -q 'pause_cleanup' "$matrix"
grep -q 'runtimeCleanupFault true' "$matrix"
grep -q 'errorCode=cleanup_failed' "$matrix"
grep -q 'reason.userPause' "$matrix"
grep -q 'assert_no_tun0_residue' "$matrix"
grep -q 'assert_no_connectivity_residue' "$matrix"
grep -q 'assert_no_native_residue' "$matrix"
grep -q 'matrix.s70Done' "$matrix"

echo "s70 profile lifecycle matrix static contract: PASS"
