#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/.."

export PATH="$HOME/bin:$PATH"

source "$SCRIPT_DIR/dev-ndk-env.sh"

OUTPUT_PATH="${DEV_TELEMETRY_CONSUMER_OUTPUT_PATH:-$SNORT_ROOT/build-output/sucre-snort-telemetry-consumer}"
SRC_PATH="${DEV_TELEMETRY_CONSUMER_SOURCE_PATH:-$SNORT_ROOT/tests/device/telemetry/native/telemetry_consumer.cpp}"

if [[ ! -f "$SRC_PATH" ]]; then
  echo "❌ source not found: $SRC_PATH" >&2
  exit 1
fi

echo "=== Telemetry consumer build ==="
echo "Source: $SRC_PATH"
echo "Output: $OUTPUT_PATH"
echo ""

ndk_root="$(snort_ndk_require)"
clangxx="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android${SNORT_ANDROID_API}-clang++"
if [[ ! -x "$clangxx" ]]; then
  echo "❌ 未找到 NDK clang++: $clangxx" >&2
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
  -fPIE \
  -pie \
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
