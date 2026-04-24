#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/.."

export PATH="$HOME/bin:$PATH"

LINEAGE_ROOT="${LINEAGE_ROOT:-$HOME/android/lineage}"
LUNCH_TARGET="${DEV_LUNCH_TARGET:-lineage_bluejay-bp2a-userdebug}"
LUNCH_PRODUCT="${DEV_LUNCH_PRODUCT:-${LUNCH_TARGET%%-*}}"
TARGET_DEVICE="${DEV_TARGET_DEVICE:-${LUNCH_PRODUCT#lineage_}}"
REMOTE_SNORT_PATH="system/sucre-snort"
BUILD_SOURCE_PATH="${DEV_REPLAY_BINARY_PATH:-out/target/product/${TARGET_DEVICE}/system_ext/bin/iptest-replay}"
OUTPUT_PATH="${DEV_REPLAY_OUTPUT_PATH:-$SNORT_ROOT/build-output/iptest-replay}"
REPLAY_SRC_PATH="${DEV_REPLAY_SOURCE_PATH:-$SNORT_ROOT/tests/device/ip/native/iptest_replay.cpp}"

if [[ ! -d "$LINEAGE_ROOT" ]]; then
    echo "❌ 未找到 LINEAGE_ROOT: $LINEAGE_ROOT" >&2
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

try_manual_build() {
    local ndk_root clangxx tmp_output

    [[ -f "$REPLAY_SRC_PATH" ]] || return 1

    ndk_root="$(find_manual_ndk_root)"
    [[ -n "$ndk_root" ]] || return 1

    clangxx="$(find_manual_clangxx "$ndk_root")"
    [[ -n "$clangxx" ]] || return 1

    echo "[fast-path] Using kernel NDK toolchain:"
    echo "  NDK root: $ndk_root"
    echo "  CXX: $clangxx"

    tmp_output="$(mktemp "${OUTPUT_PATH}.XXXXXX")"
    if ! "$clangxx" \
        -std=c++20 \
        -Wall \
        -Wextra \
        -Werror \
        -O2 \
        -g \
        -pthread \
        -static-libstdc++ \
        "$REPLAY_SRC_PATH" \
        -o "$tmp_output"; then
        rm -f "$tmp_output"
        return 1
    fi

    mkdir -p "$(dirname "$OUTPUT_PATH")"
    mv "$tmp_output" "$OUTPUT_PATH"
    chmod 755 "$OUTPUT_PATH"

    echo ""
    echo "✅ Manual NDK build complete"
    echo "Output: $OUTPUT_PATH"
    ls -lh "$OUTPUT_PATH"
    return 0
}

echo "=== IP Test Replay Build ==="
echo "LINEAGE_ROOT: $LINEAGE_ROOT"
echo "Lunch target: $LUNCH_TARGET"
echo "Target device: $TARGET_DEVICE"
echo ""

if try_manual_build; then
    exit 0
fi

echo "[fast-path] Manual NDK build unavailable, falling back to Soong."

cd "$LINEAGE_ROOT"

if [[ -L "$REMOTE_SNORT_PATH" ]]; then
    rm "$REMOTE_SNORT_PATH"
elif [[ -d "$REMOTE_SNORT_PATH" ]]; then
    rm -rf "$REMOTE_SNORT_PATH"
fi

echo "[1/4] Syncing source tree..."
rsync -a --delete "$SNORT_ROOT/" "$REMOTE_SNORT_PATH"

echo "[2/4] Loading build env..."
set +u
source build/envsetup.sh
lunch "$LUNCH_TARGET"
set -u

echo "[3/4] Building iptest-replay..."
START_TS="$(date +%s)"
m iptest-replay
END_TS="$(date +%s)"

if [[ ! -f "$BUILD_SOURCE_PATH" ]]; then
    echo "❌ 构建完成但未找到产物: $BUILD_SOURCE_PATH" >&2
    exit 1
fi

echo "[4/4] Copying output..."
mkdir -p "$(dirname "$OUTPUT_PATH")"
cp "$BUILD_SOURCE_PATH" "$OUTPUT_PATH"

echo ""
echo "✅ Build complete"
echo "Time: $((END_TS - START_TS))s"
echo "Output: $OUTPUT_PATH"
ls -lh "$OUTPUT_PATH"
