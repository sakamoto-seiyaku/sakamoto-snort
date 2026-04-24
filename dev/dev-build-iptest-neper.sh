#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/.."

export PATH="$HOME/bin:$PATH"

LINEAGE_ROOT="${LINEAGE_ROOT:-$HOME/android/lineage}"
NEPER_SRC_DIR="${DEV_NEPER_SOURCE_DIR:-$SNORT_ROOT/tests/device/ip/third_party/neper}"
OUT_DIR="${DEV_NEPER_OUTPUT_DIR:-$SNORT_ROOT/build-output}"
OUT_TCP_CRR="${DEV_NEPER_TCP_CRR_OUT:-$OUT_DIR/iptest-neper-tcp_crr}"
OUT_UDP_STREAM="${DEV_NEPER_UDP_STREAM_OUT:-$OUT_DIR/iptest-neper-udp_stream}"

find_manual_ndk_root() {
    find "$LINEAGE_ROOT/out-kernel" \
        -path '*/prebuilts/ndk-r23/toolchains/llvm/prebuilt/linux-x86_64' \
        -type d 2>/dev/null | head -n 1
}

echo "=== IP Test Neper Build ==="
echo "LINEAGE_ROOT: $LINEAGE_ROOT"
echo "neper src: $NEPER_SRC_DIR"
echo ""

if [[ ! -d "$LINEAGE_ROOT" ]]; then
    echo "❌ 未找到 LINEAGE_ROOT: $LINEAGE_ROOT" >&2
    exit 1
fi

if [[ ! -f "$NEPER_SRC_DIR/Makefile" ]]; then
    echo "❌ 未找到 neper 源码目录: $NEPER_SRC_DIR" >&2
    exit 1
fi

ndk_root="$(find_manual_ndk_root)"
if [[ -z "$ndk_root" ]]; then
    echo "❌ 未找到 kernel NDK toolchain (ndk-r23)" >&2
    exit 1
fi

cc="$ndk_root/bin/aarch64-linux-android31-clang"
if [[ ! -x "$cc" ]]; then
    echo "❌ 未找到 clang: $cc" >&2
    exit 1
fi

echo "Using kernel NDK toolchain:"
echo "  NDK root: $ndk_root"
echo "  CC: $cc"
echo ""

mkdir -p "$OUT_DIR"

make_args=(
    -C "$NEPER_SRC_DIR"
    tcp_crr
    udp_stream
    "CC=$cc"
    "CFLAGS=-std=c99 -Wall -O3 -g -D_GNU_SOURCE -DNO_LIBNUMA -fPIE -pthread"
    "LDFLAGS=-pie -pthread"
    "ext-libs=-lm"
)

echo "[1/2] Building tcp_crr + udp_stream..."
make "${make_args[@]}"

echo "[2/2] Copying outputs..."
tmp_tcp="$(mktemp "${OUT_TCP_CRR}.XXXXXX")"
tmp_udp="$(mktemp "${OUT_UDP_STREAM}.XXXXXX")"
cp "$NEPER_SRC_DIR/tcp_crr" "$tmp_tcp"
cp "$NEPER_SRC_DIR/udp_stream" "$tmp_udp"

chmod 755 "$tmp_tcp" "$tmp_udp"
mv "$tmp_tcp" "$OUT_TCP_CRR"
mv "$tmp_udp" "$OUT_UDP_STREAM"

echo ""
echo "✅ Build complete"
echo "tcp_crr: $OUT_TCP_CRR"
echo "udp_stream: $OUT_UDP_STREAM"
ls -lh "$OUT_TCP_CRR" "$OUT_UDP_STREAM"
