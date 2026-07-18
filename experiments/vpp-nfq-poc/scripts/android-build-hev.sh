#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
HEV_DIR="${HEV_DIR:-$VPP_WORK_ROOT/hev-socks5-tunnel}"
NDK_ROOT="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
NDK_BUILD="${NDK_BUILD:-$NDK_ROOT/ndk-build}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/hev-android-build}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-hev-stage}"
APP_ABI="${APP_ABI:-arm64-v8a}"
APP_PLATFORM="${APP_PLATFORM:-android-31}"

if [ ! -f "$HEV_DIR/Android.mk" ]; then
  "$SCRIPT_DIR/fetch-hev.sh"
fi

PROTECT_PATCH="$POC_DIR/patches/hev-android-socket-protect.patch"
if git -C "$HEV_DIR" apply --reverse --check "$PROTECT_PATCH" >/dev/null 2>&1; then
  : # already applied
else
  git -C "$HEV_DIR" apply --check "$PROTECT_PATCH"
  git -C "$HEV_DIR" apply "$PROTECT_PATCH"
fi

if [ ! -x "$NDK_BUILD" ]; then
  echo "ndk-build not found or not executable: $NDK_BUILD" >&2
  exit 1
fi

rm -rf "$BUILD_DIR" "$STAGE_DIR"
mkdir -p "$BUILD_DIR" "$STAGE_DIR/lib/$APP_ABI"

"$NDK_BUILD" \
  NDK_PROJECT_PATH="$HEV_DIR" \
  APP_BUILD_SCRIPT="$HEV_DIR/Android.mk" \
  NDK_OUT="$BUILD_DIR/obj" \
  NDK_LIBS_OUT="$BUILD_DIR/libs" \
  APP_ABI="$APP_ABI" \
  APP_PLATFORM="$APP_PLATFORM" \
  -j"$(nproc)"

cp "$BUILD_DIR/libs/$APP_ABI/libhev-socks5-tunnel.so" "$STAGE_DIR/lib/$APP_ABI/"

echo "# Android HEV build"
echo "hev_dir=$HEV_DIR"
echo "build_dir=$BUILD_DIR"
echo "stage_dir=$STAGE_DIR"
ls -lh "$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so"
