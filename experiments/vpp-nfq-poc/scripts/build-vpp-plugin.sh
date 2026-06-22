#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-tun_poc_plugin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
VPP_BUILD_DIR="${VPP_BUILD_DIR:-$VPP_DIR/build-root/build-vpp-native/vpp}"
VPP_INSTALL_DIR="${VPP_INSTALL_DIR:-$VPP_DIR/build-root/install-vpp-native/vpp}"
JOBS="${JOBS:-$(nproc)}"

plugin_so="${TARGET%.so}.so"

if [ ! -f "$VPP_BUILD_DIR/build.ninja" ]; then
  echo "VPP build tree is not configured: $VPP_BUILD_DIR" >&2
  echo "Run make build-vpp once before building individual plugin targets." >&2
  exit 1
fi

cmake --build "$VPP_BUILD_DIR" --target "$TARGET" -j "$JOBS"

built_so="$(find "$VPP_BUILD_DIR/lib" -path "*/vpp_plugins/$plugin_so" -print -quit)"
if [ -z "$built_so" ]; then
  echo "built plugin not found: $plugin_so under $VPP_BUILD_DIR/lib" >&2
  exit 1
fi

install_plugin_dir="$(find "$VPP_INSTALL_DIR/lib" -path "*/vpp_plugins" -type d -print -quit)"
if [ -z "$install_plugin_dir" ]; then
  echo "install plugin directory not found under $VPP_INSTALL_DIR/lib" >&2
  exit 1
fi

cp "$built_so" "$install_plugin_dir/$plugin_so"
echo "Installed $plugin_so to $install_plugin_dir"
