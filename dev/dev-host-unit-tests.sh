#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${HOST_TEST_BUILD_DIR:-$SNORT_ROOT/build-output/host-tests}"
BUILD_TYPE="${HOST_TEST_BUILD_TYPE:-Debug}"

echo "=== Sucre-Snort Host-side GTest ==="
echo "Repo root:  $SNORT_ROOT"
echo "Build dir:  $BUILD_DIR"
echo "Build type: $BUILD_TYPE"
echo ""

echo "[1/3] Configuring CMake project..."
cmake -S "$SNORT_ROOT/tests/host" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

echo "[2/3] Building host-side gtest target..."
cmake --build "$BUILD_DIR" -j"$(nproc)"

echo "[3/3] Running host-side unit tests..."
(
    cd "$BUILD_DIR"
    ctest --output-on-failure
)

echo ""
echo "✅ Host-side gtest passed"
