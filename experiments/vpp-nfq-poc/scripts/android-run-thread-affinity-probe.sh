#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
OUT_DIR="${OUT_DIR:-$POC_DIR/build}"
OUT="$OUT_DIR/android-thread-affinity-probe"
REMOTE="${REMOTE:-/data/local/tmp/sakamoto-thread-affinity-probe}"
WORKERS="${WORKERS:-4}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-thread-affinity-probe.log"

source "$REPO_ROOT/dev/dev-ndk-env.sh"

NDK_ROOT="$(snort_ndk_require)"
CLANG="${ANDROID_CLANG:-$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${SNORT_ANDROID_API}-clang}"

mkdir -p "$OUT_DIR" "$LOG_DIR"

{
  echo "# Android thread affinity probe"
  echo "ndk_root=$NDK_ROOT"
  echo "android_api=$SNORT_ANDROID_API"
  echo "clang=$CLANG"
  echo "out=$OUT"
  echo "remote=$REMOTE"
  echo "workers=$WORKERS"
  echo

  "$CLANG" -O2 -Wall -Wextra -Werror \
    -o "$OUT" \
    "$SCRIPT_DIR/android-thread-affinity-probe.c"

  file "$OUT"
  ls -lh "$OUT"

  if [ -z "${ADB:-}" ] && [ -x "$HOME/.local/android/platform-tools/adb" ]; then
    export ADB="$HOME/.local/android/platform-tools/adb"
  fi
  source "$REPO_ROOT/dev/dev-android-device-lib.sh"

  device_preflight
  adb_cmd push "$OUT" "$REMOTE" >/dev/null
  adb_cmd shell "chmod 755 '$REMOTE'"

  echo
  echo "## shell user"
  adb_cmd shell "'$REMOTE' '$WORKERS'" 2>&1 | tr -d '\r'

  echo
  echo "## root user"
  adb_su "'$REMOTE' '$WORKERS'" 2>&1 | tr -d '\r'
} 2>&1 | tee "$LOG"

echo "log: $LOG"
