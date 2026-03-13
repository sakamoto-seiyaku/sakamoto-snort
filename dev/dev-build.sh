#!/bin/bash

set -e

# Derive script location for relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/.."

CLEAN=0
FORCE_GRAPH_REGEN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --clean|-c)
            CLEAN=1
            shift
            ;;
        --regen-graph|--full-graph)
            FORCE_GRAPH_REGEN=1
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

echo "=== Sucre-Snort Development Build ==="
echo ""

# Add repo to PATH
export PATH="$HOME/bin:$PATH"

cd ~/android/lineage

# Binary paths
PACKAGE_BINARY_PATH="out/target/product/bluejay/system_ext/bin/sucre-snort"
INTERMEDIATE_BINARY_PATH="out/soong/.intermediates/system/sucre-snort/sucre-snort/android_arm64_armv8-2a_cortex-a55/sucre-snort"
COMBINED_NINJA_PATH="out/combined-lineage_bluejay.ninja"
SOONG_NINJA_PATH="out/soong/build.lineage_bluejay.ninja"
OUTPUT_PATH="$SNORT_ROOT/build-output/sucre-snort"
BUILD_SOURCE_PATH="$PACKAGE_BINARY_PATH"
BUILD_MODE_DESC="full graph regeneration (m sucre-snort)"
USE_DIRECT_NINJA=0
DIRECT_NINJA_JOBS="${DEV_BUILD_JOBS:-4}"

# Optional clean
if [[ $CLEAN -eq 1 ]]; then
    echo "[Optional] Cleaning build artifacts..."
    rm -rf out/soong/.intermediates/*sucre-snort* 2>/dev/null || true
    rm -f "$PACKAGE_BINARY_PATH" 2>/dev/null || true
    rm -f "$INTERMEDIATE_BINARY_PATH" 2>/dev/null || true
    echo "Clean complete"
    echo ""
fi

echo "[0/6] Syncing source code..."
LINEAGE_SNORT_PATH="system/sucre-snort"
SOURCE_SNORT_PATH="$SNORT_ROOT"

# Remove old symlink or directory completely
if [ -L "$LINEAGE_SNORT_PATH" ]; then
    echo "Removing symlink: $LINEAGE_SNORT_PATH"
    rm "$LINEAGE_SNORT_PATH"
elif [ -d "$LINEAGE_SNORT_PATH" ]; then
    echo "Removing old directory: $LINEAGE_SNORT_PATH"
    rm -rf "$LINEAGE_SNORT_PATH"
fi

# Sync source code (preserving timestamps for incremental build)
# Using rsync -a to preserve file timestamps prevents unnecessary recompilation
# cp -r would update all timestamps causing 30min+ full rebuild
echo "Syncing source from: $SOURCE_SNORT_PATH"
rsync -a --delete "$SOURCE_SNORT_PATH/" "$LINEAGE_SNORT_PATH"
echo "✓ Source synced"
echo ""

if [[ $FORCE_GRAPH_REGEN -eq 0 && $CLEAN -eq 0 && -f "$COMBINED_NINJA_PATH" && -f "$SOONG_NINJA_PATH" ]]; then
    USE_DIRECT_NINJA=1
    BUILD_SOURCE_PATH="$INTERMEDIATE_BINARY_PATH"
    BUILD_MODE_DESC="direct ninja reuse (${DIRECT_NINJA_JOBS} jobs, no Soong regen)"
fi

if [[ $USE_DIRECT_NINJA -eq 1 ]]; then
    echo "[1/6] Reusing existing ninja graph..."
    echo "Build mode: $BUILD_MODE_DESC"
else
    echo "[1/6] Loading build environment..."
    source build/envsetup.sh

    echo "[2/6] Configuring lunch target..."
    lunch lineage_bluejay-bp2a-userdebug
fi

# Record timestamp before build
echo "[3/6] Checking existing binary..."
if [[ -f "$BUILD_SOURCE_PATH" ]]; then
    OLD_TIME=$(stat -c %Y "$BUILD_SOURCE_PATH" 2>/dev/null || echo 0)
    OLD_SIZE=$(stat -c %s "$BUILD_SOURCE_PATH" 2>/dev/null || echo 0)
    echo "Existing binary: $(date -d @$OLD_TIME '+%Y-%m-%d %H:%M:%S'), size: $OLD_SIZE bytes"
else
    OLD_TIME=0
    OLD_SIZE=0
    echo "No existing binary found (first build)"
fi
echo ""

echo "[4/6] Building sucre-snort (incremental)..."
START=$(date +%s)
if [[ $USE_DIRECT_NINJA -eq 1 ]]; then
    prebuilts/build-tools/linux-x86/bin/ninja -f "$COMBINED_NINJA_PATH" -j "$DIRECT_NINJA_JOBS" "$INTERMEDIATE_BINARY_PATH"
else
    m sucre-snort
fi
END=$(date +%s)

# Verify binary was updated
if [[ -f "$BUILD_SOURCE_PATH" ]]; then
    NEW_TIME=$(stat -c %Y "$BUILD_SOURCE_PATH")
    NEW_SIZE=$(stat -c %s "$BUILD_SOURCE_PATH")

    if [[ "$NEW_TIME" -le "$OLD_TIME" ]]; then
        echo ""
        echo "⚠️  WARNING: Binary timestamp not updated!"
        echo "   This means no source files were modified, using cached version."
        echo "   If you expect changes, run: bash dev-build.sh --clean"
        if [[ $USE_DIRECT_NINJA -eq 1 ]]; then
            echo "   If Android.bp changed, run: bash dev-build.sh --regen-graph"
        fi
    else
        echo ""
        echo "✓ Binary updated: $(date -d @$NEW_TIME '+%Y-%m-%d %H:%M:%S')"
        echo "  Size change: $OLD_SIZE → $NEW_SIZE bytes"
    fi
else
    echo ""
    echo "❌ ERROR: Binary not found after build!"
    exit 1
fi
echo ""

echo "[5/6] Extracting binary..."
mkdir -p "$(dirname "$OUTPUT_PATH")"
cp "$BUILD_SOURCE_PATH" "$OUTPUT_PATH"

echo ""
echo "=== Build Complete ==="
echo "Time: $((END - START))s"
echo "Output: $OUTPUT_PATH"
ls -lh "$OUTPUT_PATH"
echo ""
echo "Next: bash dev-deploy.sh"
