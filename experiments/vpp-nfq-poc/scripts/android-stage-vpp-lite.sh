#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-trim-nfqueue}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-vpp-lite-stage}"
NDK_ROOT="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
STRIP_BIN="${STRIP_BIN:-$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip}"
STRIP="${STRIP:-1}"
ENABLE_PLUGINS_SECTION="${ENABLE_PLUGINS_SECTION:-1}"
ENABLE_NFQUEUE_PLUGIN="${ENABLE_NFQUEUE_PLUGIN:-1}"

BIN_SRC="$BUILD_DIR/bin/vpp_lite"
VPPCTL_SRC="$BUILD_DIR/bin/vppctl"
LIB_SRC="$BUILD_DIR/lib/aarch64-linux-android"
PLUGIN_SRC="$LIB_SRC/vpp_plugins/nfqueue_poc_plugin.so"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"

libs=(
  libvlibmemory.so
  libvlibapi.so
  libvlib.so
  libsvm.so
  libvppinfra.so
)

if [ ! -x "$BIN_SRC" ]; then
  echo "Missing Android vpp_lite binary: $BIN_SRC" >&2
  echo "Run: make android-vpp-build-lite" >&2
  exit 1
fi

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/bin" "$STAGE_DIR/lib" "$STAGE_DIR/plugins" "$STAGE_DIR/runtime"

cp "$BIN_SRC" "$STAGE_DIR/bin/vpp"
if [ -x "$VPPCTL_SRC" ]; then
  cp "$VPPCTL_SRC" "$STAGE_DIR/bin/vppctl"
fi
for lib in "${libs[@]}"; do
  cp "$LIB_SRC/$lib" "$STAGE_DIR/lib/$lib"
done
if [ -f "$PLUGIN_SRC" ]; then
  cp "$PLUGIN_SRC" "$STAGE_DIR/plugins/nfqueue_poc_plugin.so"
fi

cat >"$STAGE_DIR/runtime/startup.conf" <<EOF
unix {
  nodaemon
  nobanner
  full-coredump
  runtime-dir $REMOTE_ROOT/runtime
  log $REMOTE_ROOT/logs/vpp.log
  cli-listen $REMOTE_ROOT/runtime/cli.sock
}

buffers {
  page-size default
}
EOF

if [ "$ENABLE_PLUGINS_SECTION" = "1" ]; then
  cat >>"$STAGE_DIR/runtime/startup.conf" <<EOF
plugins {
  path $REMOTE_ROOT/plugins
  plugin default { disable }
EOF

  if [ "$ENABLE_NFQUEUE_PLUGIN" = "1" ] &&
    [ -f "$STAGE_DIR/plugins/nfqueue_poc_plugin.so" ]; then
    cat >>"$STAGE_DIR/runtime/startup.conf" <<EOF
  plugin nfqueue_poc_plugin.so { enable }
EOF
  fi

  cat >>"$STAGE_DIR/runtime/startup.conf" <<EOF
}
EOF
fi

if [ "$STRIP" = "1" ]; then
  "$STRIP_BIN" --strip-unneeded "$STAGE_DIR/bin"/* "$STAGE_DIR"/lib/*.so
  if [ -f "$STAGE_DIR/plugins/nfqueue_poc_plugin.so" ]; then
    "$STRIP_BIN" --strip-unneeded "$STAGE_DIR/plugins/nfqueue_poc_plugin.so"
  fi
fi

echo "# Android VPP lite stage"
echo "stage_dir=$STAGE_DIR"
find "$STAGE_DIR" -maxdepth 2 -type f -print | sort
du -sh "$STAGE_DIR"
