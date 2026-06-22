#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NDK_ROOT="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
CLANG="${ANDROID_CLANG:-$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang}"
OUT_DIR="${OUT_DIR:-$POC_DIR/build}"
OUT="$OUT_DIR/android-socks5-smoke-server"

if [ ! -x "$CLANG" ]; then
  echo "Android clang not found or not executable: $CLANG" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
"$CLANG" -O2 -Wall -Wextra -Werror \
  -o "$OUT" \
  "$SCRIPT_DIR/android-socks5-smoke-server.c"

echo "# Android SOCKS5 smoke server"
file "$OUT"
ls -lh "$OUT"
