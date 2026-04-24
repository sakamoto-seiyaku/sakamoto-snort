#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/.."

export PATH="$HOME/bin:$PATH"

LINEAGE_ROOT="${LINEAGE_ROOT:-$HOME/android/lineage}"
OUTPUT_PATH="${DEV_DX_NETD_INJECT_OUTPUT_PATH:-$SNORT_ROOT/build-output/dx-netd-inject}"
SRC_PATH="${DEV_DX_NETD_INJECT_SOURCE_PATH:-$SNORT_ROOT/tests/device/dx/native/dx_netd_inject.cpp}"

if [[ ! -f "$SRC_PATH" ]]; then
  echo "❌ source not found: $SRC_PATH" >&2
  exit 1
fi

if [[ ! -d "$LINEAGE_ROOT" ]]; then
  echo "❌ 未找到 LINEAGE_ROOT: $LINEAGE_ROOT" >&2
  echo "   你可以设置环境变量 LINEAGE_ROOT=/path/to/lineage" >&2
  exit 1
fi

find_manual_ndk_root() {
  find "$LINEAGE_ROOT/out-kernel" \
    -path '*/prebuilts/ndk-r23/toolchains/llvm/prebuilt/linux-x86_64' \
    -type d 2>/dev/null | head -n 1
}

find_manual_clangxx() {
  local ndk_root="$1"
  find "$ndk_root/bin" \
    -maxdepth 1 \
    -name 'aarch64-linux-android*-clang++' \
    -type f 2>/dev/null | sort -V | tail -n 1
}

echo "=== DX netd injector build ==="
echo "LINEAGE_ROOT: $LINEAGE_ROOT"
echo "Source: $SRC_PATH"
echo "Output: $OUTPUT_PATH"
echo ""

ndk_root="$(find_manual_ndk_root)"
if [[ -z "$ndk_root" ]]; then
  echo "❌ 未找到 kernel NDK toolchain（out-kernel prebuilts）" >&2
  echo "   期望路径形如: $LINEAGE_ROOT/out-kernel/**/prebuilts/ndk-r23/toolchains/llvm/prebuilt/linux-x86_64" >&2
  exit 1
fi

clangxx="$(find_manual_clangxx "$ndk_root")"
if [[ -z "$clangxx" ]]; then
  echo "❌ 未找到 aarch64-linux-android*-clang++ in: $ndk_root/bin" >&2
  exit 1
fi

echo "Using toolchain:"
echo "  NDK root: $ndk_root"
echo "  CXX: $clangxx"
echo ""

tmp_output="$(mktemp "${OUTPUT_PATH}.XXXXXX")"
if ! "$clangxx" \
  -std=c++20 \
  -Wall \
  -Wextra \
  -Werror \
  -O2 \
  -g \
  -static-libstdc++ \
  "$SRC_PATH" \
  -o "$tmp_output"; then
  rm -f "$tmp_output"
  echo "❌ build failed" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
mv "$tmp_output" "$OUTPUT_PATH"
chmod 755 "$OUTPUT_PATH"

echo "✅ build complete"
ls -lh "$OUTPUT_PATH"

