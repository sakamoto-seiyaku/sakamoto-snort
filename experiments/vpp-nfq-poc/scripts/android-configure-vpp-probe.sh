#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp}"
VPP_SRC_DIR="${VPP_SRC_DIR:-$VPP_DIR/src}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-configure-probe}"
SAKAMOTO_NETFILTER_ROOT="${SAKAMOTO_NETFILTER_ROOT:-$REPO_ROOT/third_party/netfilter}"
VPP_PLUGINS="${VPP_PLUGINS:-}"
VPP_EXCLUDED_PLUGINS="${VPP_EXCLUDED_PLUGINS:-}"
VPP_CMAKE_BUILD_TYPE="${VPP_CMAKE_BUILD_TYPE:-}"
VPP_USE_LTO="${VPP_USE_LTO:-}"
VPP_EXTRA_CMAKE_ARGS="${VPP_EXTRA_CMAKE_ARGS:-}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/android-vpp-configure-probe.log"

source "$REPO_ROOT/dev/dev-ndk-env.sh"

if [ ! -f "$VPP_SRC_DIR/CMakeLists.txt" ]; then
  echo "VPP source CMakeLists.txt not found: $VPP_SRC_DIR/CMakeLists.txt" >&2
  exit 1
fi

NDK_ROOT="$(snort_ndk_require)"
ANDROID_API="${SNORT_ANDROID_API:-31}"
VLIB_PROCESS_LOG2_STACK_SIZE="${VLIB_PROCESS_LOG2_STACK_SIZE:-18}"

mkdir -p "$LOG_DIR"
rm -rf "$BUILD_DIR"

{
  echo "# Android VPP configure probe"
  echo "vpp_src=$VPP_SRC_DIR"
  echo "build_dir=$BUILD_DIR"
  echo "ndk_root=$NDK_ROOT"
  echo "android_abi=arm64-v8a"
  echo "android_api=$ANDROID_API"
  echo "vlib_process_log2_stack_size=$VLIB_PROCESS_LOG2_STACK_SIZE"
  echo "sakamoto_netfilter_root=$SAKAMOTO_NETFILTER_ROOT"
  echo "vpp_plugins=$VPP_PLUGINS"
  echo "vpp_excluded_plugins=$VPP_EXCLUDED_PLUGINS"
  echo "vpp_cmake_build_type=$VPP_CMAKE_BUILD_TYPE"
  echo "vpp_use_lto=$VPP_USE_LTO"
  echo "vpp_extra_cmake_args=$VPP_EXTRA_CMAKE_ARGS"
  echo

  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0=safe.directory
  export GIT_CONFIG_VALUE_0="$VPP_DIR"

  cmake_args=(
    -S "$VPP_SRC_DIR" \
    -B "$BUILD_DIR" \
    -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM="android-$ANDROID_API" \
    -DANDROID_STL=c++_static \
    -DVLIB_PROCESS_LOG2_STACK_SIZE="$VLIB_PROCESS_LOG2_STACK_SIZE" \
    -DSAKAMOTO_NETFILTER_ROOT="$SAKAMOTO_NETFILTER_ROOT" \
    -DVPP_HOST_TOOLS_ONLY=OFF
  )
  if [ -n "$VPP_PLUGINS" ]; then
    cmake_args+=(-DVPP_PLUGINS="$VPP_PLUGINS")
  fi
  if [ -n "$VPP_EXCLUDED_PLUGINS" ]; then
    cmake_args+=(-DVPP_EXCLUDED_PLUGINS="$VPP_EXCLUDED_PLUGINS")
  fi
  if [ -n "$VPP_CMAKE_BUILD_TYPE" ]; then
    cmake_args+=(-DCMAKE_BUILD_TYPE="$VPP_CMAKE_BUILD_TYPE")
  fi
  if [ -n "$VPP_USE_LTO" ]; then
    cmake_args+=(-DVPP_USE_LTO="$VPP_USE_LTO")
  fi
  if [ -n "$VPP_EXTRA_CMAKE_ARGS" ]; then
    read -r -a extra_cmake_args <<<"$VPP_EXTRA_CMAKE_ARGS"
    cmake_args+=("${extra_cmake_args[@]}")
  fi

  set +e
  cmake "${cmake_args[@]}"
  rc=$?
  set -e

  echo
  echo "cmake_rc=$rc"
  exit "$rc"
} 2>&1 | tee "$LOG"
