#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

source "$SCRIPT_DIR/dev-ndk-env.sh"

BUILD_DIR="$SNORT_ROOT/build-output/cmake/ndk-arm64"
BUILD_TYPE="${SNORT_NDK_BUILD_TYPE:-RelWithDebInfo}"
CLEAN=0
CONFIGURE_ONLY=0

show_help() {
    cat <<EOF
Usage: $0 [--clean] [--configure-only] [--build-dir <path>]

Builds the sucre-snort root daemon with Android NDK $SNORT_NDK_VERSION.

Output:
  build-output/sucre-snort-ndk
  build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so

Options:
  --clean            Remove the NDK CMake build directory before configuring.
  --configure-only   Configure the NDK CMake build without compiling.
  --build-dir <path> Override the CMake build directory.
  -h, --help         Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean)
            CLEAN=1
            shift
            ;;
        --configure-only)
            CONFIGURE_ONLY=1
            shift
            ;;
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            show_help >&2
            exit 1
            ;;
    esac
done

if ! command -v cmake >/dev/null 2>&1; then
    echo "cmake was not found on PATH" >&2
    exit 1
fi

NDK_ROOT="$(snort_ndk_require)"

if [[ "$CLEAN" -eq 1 ]]; then
    rm -rf "$BUILD_DIR"
    rm -f "$SNORT_ROOT/build-output/sucre-snort-ndk"
fi

cmake \
    -S "$SNORT_ROOT" \
    -B "$BUILD_DIR" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-$SNORT_ANDROID_API \
    -DANDROID_STL=c++_static \
    -DSNORT_ENABLE_NDK_DAEMON=ON \
    -DSNORT_ENABLE_DELEGATED_BUILD_TARGETS=OFF \
    -DSNORT_ENABLE_HOST_TESTS=OFF \
    -DSNORT_ENABLE_DEVICE_TESTS=OFF

if [[ "$CONFIGURE_ONLY" -eq 0 ]]; then
    cmake --build "$BUILD_DIR" --target sucre-snort-ndk-apk-lib
    echo "NDK daemon artifact: $SNORT_ROOT/build-output/sucre-snort-ndk"
    echo "APK native artifact: $SNORT_ROOT/build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so"
fi
