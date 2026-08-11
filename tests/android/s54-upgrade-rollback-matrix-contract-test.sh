#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/tests/device/s54-upgrade-rollback-matrix.sh"

[[ -f "$matrix" ]]
grep -q 'SAKAMOTO-54-upgrade-rollback' "$matrix"
grep -q './dev/adb' "$matrix"
grep -q 'APK_VERSION_CODE' "$matrix"
grep -q 'APK_VERSION_NAME' "$matrix"
grep -q 'install -r -d "$OLD_APK"' "$matrix"
grep -q 'install -r "$NEW_APK"' "$matrix"
grep -q 'runtimeStart true --es runtimeProfile root' "$matrix"
grep -q 'pid_alive "$pid"' "$matrix"
grep -q 'assert_no_native_residue' "$matrix"
grep -q 'upgrade.noResidue' "$matrix"
grep -q 'rollback.noResidue' "$matrix"
grep -q 'matrix.result' "$matrix"

echo "s54 upgrade rollback matrix static contract: PASS"
