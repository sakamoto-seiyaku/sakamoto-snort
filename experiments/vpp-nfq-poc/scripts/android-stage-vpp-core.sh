#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-configure-probe}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-vpp-core-stage}"
NDK_ROOT="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
STRIP_BIN="${STRIP_BIN:-$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip}"
STRIP="${STRIP:-1}"

BIN_SRC="$BUILD_DIR/bin/vpp"
VPPCTL_SRC="$BUILD_DIR/bin/vppctl"
LIB_SRC="$BUILD_DIR/lib/aarch64-linux-android"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
plugins=(
  nfqueue_poc_plugin.so
  tun_poc_plugin.so
)

libs=(
  libvnet.so
  libvlibmemory.so
  libvlibapi.so
  libvlib.so
  libsvm.so
  libvppinfra.so
)

if [ ! -x "$BIN_SRC" ]; then
  echo "Missing Android vpp binary: $BIN_SRC" >&2
  echo "Run: make android-vpp-build-probe" >&2
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
for plugin in "${plugins[@]}"; do
  if [ -f "$LIB_SRC/vpp_plugins/$plugin" ]; then
    cp "$LIB_SRC/vpp_plugins/$plugin" "$STAGE_DIR/plugins/$plugin"
  fi
done

cat >"$STAGE_DIR/runtime/startup.conf" <<EOF
unix {
  nodaemon
  nobanner
  full-coredump
  runtime-dir $REMOTE_ROOT/runtime
  poll-sleep-usec 1000
  log $REMOTE_ROOT/logs/vpp.log
  cli-listen $REMOTE_ROOT/runtime/cli.sock
}

api-segment {
  prefix vpp-nfq-poc
}

statseg {
  socket-name $REMOTE_ROOT/runtime/statseg.sock
}

buffers {
  page-size default
}

plugins {
  path $REMOTE_ROOT/plugins
  plugin default { disable }
EOF

for plugin in "${plugins[@]}"; do
  if [ -f "$STAGE_DIR/plugins/$plugin" ]; then
    cat >>"$STAGE_DIR/runtime/startup.conf" <<EOF
  plugin $plugin { enable }
EOF
  fi
done

cat >>"$STAGE_DIR/runtime/startup.conf" <<EOF
}
EOF

if [ "$STRIP" = "1" ]; then
  "$STRIP_BIN" --strip-unneeded "$STAGE_DIR/bin"/* "$STAGE_DIR"/lib/*.so
  for plugin in "$STAGE_DIR"/plugins/*.so; do
    [ -f "$plugin" ] || continue
    "$STRIP_BIN" --strip-unneeded "$plugin"
  done
fi

echo "# Android VPP core stage"
echo "stage_dir=$STAGE_DIR"
find "$STAGE_DIR" -maxdepth 2 -type f -print | sort
du -sh "$STAGE_DIR"
