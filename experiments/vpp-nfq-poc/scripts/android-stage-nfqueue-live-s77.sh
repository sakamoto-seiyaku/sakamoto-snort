#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-77 Android stage: the live-buffer plugin is built as a native
# Android VPP plugin and staged beside the minimum VPP runtime.  This keeps
# the S77 artifact separate from the historical nfqueue_poc stage helper.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-s77-android-build}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-s77-live-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-s77}"
NDK_ROOT="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
STRIP_BIN="${STRIP_BIN:-$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip}"
STRIP="${STRIP:-1}"

BIN_SRC="$BUILD_DIR/bin/vpp"
VPPCTL_SRC="$BUILD_DIR/bin/vppctl"
LIB_SRC="$BUILD_DIR/lib/aarch64-linux-android"
PLUGIN_SRC="$LIB_SRC/vpp_plugins/nfqueue_live_poc_plugin.so"

libs=(
  libvnet.so
  libvlibmemory.so
  libvlibapi.so
  libvlib.so
  libsvm.so
  libvppinfra.so
  libvapiclient.so
  libvlibmemoryclient.so
)

for binary in "$BIN_SRC" "$VPPCTL_SRC"; do
  [ -x "$binary" ] || { echo "Missing Android artifact: $binary" >&2; exit 1; }
done
[ -f "$PLUGIN_SRC" ] || { echo "Missing Android plugin: $PLUGIN_SRC" >&2; exit 1; }

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/bin" "$STAGE_DIR/lib" "$STAGE_DIR/plugins" "$STAGE_DIR/runtime"
cp "$BIN_SRC" "$STAGE_DIR/bin/vpp"
cp "$VPPCTL_SRC" "$STAGE_DIR/bin/vppctl"
for lib in "${libs[@]}"; do
  [ -f "$LIB_SRC/$lib" ] || { echo "Missing Android library: $LIB_SRC/$lib" >&2; exit 1; }
  cp "$LIB_SRC/$lib" "$STAGE_DIR/lib/$lib"
done
cp "$PLUGIN_SRC" "$STAGE_DIR/plugins/nfqueue_live_poc_plugin.so"

cat >"$STAGE_DIR/runtime/startup.conf" <<EOF
unix {
  nodaemon
  nobanner
  runtime-dir $REMOTE_ROOT/runtime
  log $REMOTE_ROOT/logs/vpp.log
  cli-listen $REMOTE_ROOT/runtime/cli.sock
  cli-no-pager
}

api-segment {
  prefix sakamoto-nfqueue-s77
}

statseg {
  socket-name $REMOTE_ROOT/runtime/statseg.sock
}

buffers {
  page-size default
}

cpu {
  main-core 0
  corelist-workers 1-2
}

plugins {
  path $REMOTE_ROOT/plugins
  plugin default { disable }
  plugin nfqueue_live_poc_plugin.so { enable }
}
EOF

if [ "$STRIP" = 1 ]; then
  "$STRIP_BIN" --strip-unneeded "$STAGE_DIR/bin"/* "$STAGE_DIR/lib"/*.so
  "$STRIP_BIN" --strip-unneeded "$STAGE_DIR/plugins/nfqueue_live_poc_plugin.so"
fi

echo "# SAKAMOTO-77 Android live-buffer stage"
echo "stage_dir=$STAGE_DIR"
echo "remote_root=$REMOTE_ROOT"
echo "plugin_sha256=$(sha256sum "$STAGE_DIR/plugins/nfqueue_live_poc_plugin.so" | awk '{print $1}')"
find "$STAGE_DIR" -maxdepth 2 -type f -print | sort
