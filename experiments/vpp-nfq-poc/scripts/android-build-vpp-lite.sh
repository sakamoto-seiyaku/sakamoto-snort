#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
VPP_SRC_DIR="${VPP_SRC_DIR:-$VPP_DIR/src}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-trim-nfqueue}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-build-vpp-lite.log"

source "$REPO_ROOT/dev/dev-ndk-env.sh"

if [ ! -f "$BUILD_DIR/build.ninja" ]; then
  echo "Android VPP build dir is not configured: $BUILD_DIR" >&2
  exit 1
fi

NDK_ROOT="$(snort_ndk_require)"
ANDROID_API="${SNORT_ANDROID_API:-31}"
TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64"
CC="$TOOLCHAIN/bin/aarch64-linux-android${ANDROID_API}-clang"
LIB_DIR="$BUILD_DIR/lib/aarch64-linux-android"
OUT="$BUILD_DIR/bin/vpp_lite"

mkdir -p "$LOG_DIR" "$BUILD_DIR/bin"

{
  echo "# Android VPP lite build"
  echo "vpp_src=$VPP_SRC_DIR"
  echo "build_dir=$BUILD_DIR"
  echo "out=$OUT"
  echo "android_api=$ANDROID_API"
  echo

  "$CC" \
    -g -DANDROID -fdata-sections -ffunction-sections -funwind-tables \
    -fstack-protector-strong -no-canonical-prefixes -D_FORTIFY_SOURCE=2 \
    -Wformat -Werror=format-security -fPIE -Wno-address-of-packed-member \
    -march=armv8-a+crc -pthread \
    -I"$VPP_SRC_DIR" \
    -I"$BUILD_DIR/CMakeFiles" \
    -I"$BUILD_DIR/CMakeFiles/vpp" \
    "$POC_DIR/minimal-runtime/vpp_lite_main.c" \
    "$VPP_SRC_DIR/vpp/app/version.c" \
    -L"$LIB_DIR" \
    -Wl,--build-id=sha1 \
    -Wl,--no-undefined-version \
    -Wl,--fatal-warnings \
    -Wl,--no-undefined \
    -Wl,--export-dynamic \
    "$LIB_DIR/libvlibmemory.so" \
    "$LIB_DIR/libvlibapi.so" \
    "$LIB_DIR/libvlib.so" \
    "$LIB_DIR/libsvm.so" \
    "$LIB_DIR/libvppinfra.so" \
    -ldl -lm -pthread -latomic \
    -o "$OUT"

  readelf -d "$OUT" | grep NEEDED || true
  ls -lh "$OUT"
} 2>&1 | tee "$LOG"
