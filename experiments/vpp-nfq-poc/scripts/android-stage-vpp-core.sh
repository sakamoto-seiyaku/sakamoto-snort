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
VPP_SOURCE_REVISION="${VPP_SOURCE_REVISION:-unknown}"
VPP_SOURCE_ORIGIN="${VPP_SOURCE_ORIGIN:-$VPP_DIR}"
VPP_SOURCE_STATUS="${VPP_SOURCE_STATUS:-unknown}"
VPP_MAIN_CORE="${VPP_MAIN_CORE:-}"
VPP_WORKER_CORES="${VPP_WORKER_CORES:-}"

BIN_SRC="$BUILD_DIR/bin/vpp"
VPPCTL_SRC="$BUILD_DIR/bin/vppctl"
LIB_SRC="$BUILD_DIR/lib/aarch64-linux-android"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc}"
plugins=()
if [ -n "${VPP_PLUGINS:-}" ]; then
  IFS=';' read -r -a plugins <<<"$VPP_PLUGINS"
fi

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

EOF

if [ -n "$VPP_WORKER_CORES" ]; then
  cat >>"$STAGE_DIR/runtime/startup.conf" <<EOF
cpu {
  ${VPP_MAIN_CORE:+main-core $VPP_MAIN_CORE}
  corelist-workers $VPP_WORKER_CORES
}

EOF
fi

cat >>"$STAGE_DIR/runtime/startup.conf" <<EOF

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

for artifact in "$STAGE_DIR/bin/vpp" "$STAGE_DIR/bin/vppctl"; do
  [ -f "$artifact" ] || { echo "Missing staged VPP artifact: $artifact" >&2; exit 1; }
  if strings "$artifact" | grep -Eq 'wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE'; then
    echo "Rejected P6 conditional-wake symbols found in staged binary: $artifact" >&2
    exit 1
  fi
done

conditional_wake_pattern='wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE|0003-vlib-frame-queue-wakeup-epoch-state'
rg_conditional_wake=(rg -n --hidden --glob '!*.o' --glob '!*.so')
source_status="absent"
if [ "${#plugins[@]}" -gt 0 ] && [ -d "$VPP_DIR/src/plugins" ]; then
  # VPP_PLUGINS defines the staged runtime plugin closure.  Historical
  # experiments may leave rejected P6 symbols in unrelated plugin source; those
  # sources are not copied into this stage and must not block an OI3-only APK.
  if "${rg_conditional_wake[@]}" --glob '!**/plugins/**' \
      "$conditional_wake_pattern" "$VPP_DIR/src" >/dev/null 2>&1; then
    source_status="present"
  else
    for plugin in "${plugins[@]}"; do
      plugin_dir_name="${plugin%.so}"
      plugin_dir_name="${plugin_dir_name#lib}"
      plugin_dir_name="${plugin_dir_name%_plugin}"
      plugin_dir="$VPP_DIR/src/plugins/$plugin_dir_name"
      if [ -d "$plugin_dir" ] &&
          "${rg_conditional_wake[@]}" "$conditional_wake_pattern" \
            "$plugin_dir" >/dev/null 2>&1; then
        source_status="present"
        break
      fi
    done
  fi
else
  if "${rg_conditional_wake[@]}" "$conditional_wake_pattern" \
      "$VPP_DIR" >/dev/null 2>&1; then
    source_status="present"
  fi
fi
[ "$source_status" = "absent" ] || {
  echo "Rejected P6 conditional-wake source is present in $VPP_DIR" >&2
  exit 1
}
{
  echo "sourceRevision=$VPP_SOURCE_REVISION"
  echo "sourceOrigin=$VPP_SOURCE_ORIGIN"
  echo "sourceTree=$VPP_DIR"
  echo "sourceStatus=$VPP_SOURCE_STATUS"
  echo "conditionalWakeSource=absent"
  echo "conditionalWakeBinary=absent"
  echo "vppSha256=$(sha256sum "$STAGE_DIR/bin/vpp" | awk '{print $1}')"
  echo "vppctlSha256=$(sha256sum "$STAGE_DIR/bin/vppctl" | awk '{print $1}')"
} >"$STAGE_DIR/runtime/source-provenance.properties"

echo "# Android VPP core stage"
echo "stage_dir=$STAGE_DIR"
find "$STAGE_DIR" -maxdepth 2 -type f -print | sort
du -sh "$STAGE_DIR"
