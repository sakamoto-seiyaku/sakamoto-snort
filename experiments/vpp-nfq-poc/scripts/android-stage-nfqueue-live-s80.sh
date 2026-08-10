#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-80 Android stage.  This is the source-owned artifact boundary for
# the live-buffer NFQUEUE runner; the runner never reconstructs a stage from
# an unpinned collection of files on the device.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-s77-android-build}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-s80-live-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-s80}"
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
  [ -x "$binary" ] || {
    echo "Missing Android artifact: $binary" >&2
    exit 1
  }
done
[ -f "$PLUGIN_SRC" ] || {
  echo "Missing Android plugin: $PLUGIN_SRC" >&2
  exit 1
}
[ -x "$STRIP_BIN" ] || {
  echo "Missing Android strip tool: $STRIP_BIN" >&2
  exit 1
}

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR/bin" "$STAGE_DIR/lib" "$STAGE_DIR/plugins" \
  "$STAGE_DIR/runtime"
cp "$BIN_SRC" "$STAGE_DIR/bin/vpp"
cp "$VPPCTL_SRC" "$STAGE_DIR/bin/vppctl"
for lib in "${libs[@]}"; do
  [ -f "$LIB_SRC/$lib" ] || {
    echo "Missing Android library: $LIB_SRC/$lib" >&2
    exit 1
  }
  cp "$LIB_SRC/$lib" "$STAGE_DIR/lib/$lib"
done
cp "$PLUGIN_SRC" "$STAGE_DIR/plugins/nfqueue_live_poc_plugin.so"

cat >"$STAGE_DIR/runtime/startup.conf" <<EOF
unix {
  nodaemon
  nobanner
  full-coredump
  runtime-dir $REMOTE_ROOT/runtime
  poll-sleep-usec 1000
  log $REMOTE_ROOT/logs/vpp.log
  cli-listen $REMOTE_ROOT/runtime/cli.sock
  cli-no-pager
}

api-segment {
  prefix sakamoto-vpp-nfqueue-s80
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

if grep -Eq 'handoff_perf_poc|frame-queue-wakeup' \
    "$STAGE_DIR/runtime/startup.conf"; then
  echo "Rejected conditional-wake startup configuration found in $STAGE_DIR/runtime/startup.conf" >&2
  exit 1
fi

if [ "$STRIP" = 1 ]; then
  "$STRIP_BIN" --strip-unneeded "$STAGE_DIR/bin"/* "$STAGE_DIR/lib"/*.so
  "$STRIP_BIN" --strip-unneeded "$STAGE_DIR/plugins/nfqueue_live_poc_plugin.so"
fi

repo_revision="unknown"
if git -C "$REPO_ROOT" rev-parse HEAD >/dev/null 2>&1; then
  repo_revision="$(git -C "$REPO_ROOT" rev-parse HEAD)"
fi
vpp_revision="unknown"
if git -C "$VPP_DIR" rev-parse HEAD >/dev/null 2>&1; then
  vpp_revision="$(git -C "$VPP_DIR" rev-parse HEAD)"
fi
source_status="absent"
if rg -n --hidden --glob '!*.o' --glob '!*.so' \
    'wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE|0003-vlib-frame-queue-wakeup-epoch-state' \
    "$VPP_DIR" >/dev/null 2>&1; then
  source_status="present"
fi

{
  echo "ticket=SAKAMOTO-80"
  echo "repoRevision=$repo_revision"
  echo "vppSourceRevision=$vpp_revision"
  echo "vppSourceTree=$VPP_DIR"
  echo "ndkRoot=$NDK_ROOT"
  echo "ndkVersion=$(basename "$NDK_ROOT")"
  echo "androidAbi=arm64-v8a"
  echo "androidApi=${SNORT_ANDROID_API:-31}"
  echo "remoteRoot=$REMOTE_ROOT"
  echo "conditionalWakeResearchSource=$source_status"
  echo "conditionalWakeRuntime=disabled"
  echo "vppSha256=$(sha256sum "$STAGE_DIR/bin/vpp" | awk '{print $1}')"
  echo "vppctlSha256=$(sha256sum "$STAGE_DIR/bin/vppctl" | awk '{print $1}')"
  echo "pluginSha256=$(sha256sum "$STAGE_DIR/plugins/nfqueue_live_poc_plugin.so" | awk '{print $1}')"
  echo "startupSha256=$(sha256sum "$STAGE_DIR/runtime/startup.conf" | awk '{print $1}')"
} >"$STAGE_DIR/runtime/source-provenance.properties"

echo "# SAKAMOTO-80 Android live-buffer stage"
echo "stage_dir=$STAGE_DIR"
echo "remote_root=$REMOTE_ROOT"
cat "$STAGE_DIR/runtime/source-provenance.properties"
find "$STAGE_DIR" -maxdepth 2 -type f -print | sort
