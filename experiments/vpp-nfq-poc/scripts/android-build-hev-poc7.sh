#!/usr/bin/env bash
set -euo pipefail

# Build the exact owner-context HEV fixture used by S125.  The generic HEV
# build script intentionally remains separate because its default checkout is
# the ordinary tunnel tree and does not contain the S118 owner seam.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
HEV_DIR="${HEV_DIR:-/tmp/hev-3911f79}"
NDK_ROOT="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
NDK_BUILD="${NDK_BUILD:-$NDK_ROOT/ndk-build}"
BUILD_DIR="${BUILD_DIR:-$POC_DIR/work/hev-poc7-android-build}"
STAGE_DIR="${STAGE_DIR:-$POC_DIR/work/android-hev-poc7-stage}"
APP_ABI="${APP_ABI:-arm64-v8a}"
APP_PLATFORM="${APP_PLATFORM:-android-31}"
PATCH_FILE="$POC_DIR/patches/hev-poc7-tcp-copy-timing.patch"

for path in "$HEV_DIR/Android.mk" "$HEV_DIR/src/include/lwip/owner_context.h" \
            "$HEV_DIR/src/hev-flow-stack-owner-context.c" "$PATCH_FILE"; do
  [[ -f "$path" ]] || { echo "missing POC-7 HEV input: $path" >&2; exit 1; }
done
[[ -x "$NDK_BUILD" ]] || { echo "ndk-build not found: $NDK_BUILD" >&2; exit 1; }

if ! grep -q 'flow_stack_owner_tcp_copy_metrics' \
    "$HEV_DIR/src/hev-flow-stack-owner-context.c"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$PATCH_FILE"
fi
grep -q 'flow_stack_owner_tcp_copy_metrics' \
  "$HEV_DIR/src/hev-flow-stack-owner-context.c" || {
  echo "POC-7 TCP copy seam was not applied" >&2
  exit 1
}

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

cp "$BUILD_DIR/libs/$APP_ABI/libhev-socks5-tunnel.so" \
  "$STAGE_DIR/lib/$APP_ABI/"
sha256sum "$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so" \
  >"$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so.sha256"
echo "hev_dir=$HEV_DIR"
echo "stage_dir=$STAGE_DIR"
echo "tcp_copy_symbol=$(nm -D "$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so" \
  | awk '$3 == "flow_stack_owner_tcp_copy_metrics" { print "present"; found=1 } END { if (!found) print "missing" }')"
ls -lh "$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so"
