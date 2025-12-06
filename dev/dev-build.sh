#!/bin/bash

set -e

# Derive script location for relative paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNORT_ROOT="$SCRIPT_DIR/.."

echo "=== Sucre-Snort Development Build ==="
echo ""

# Add repo to PATH
export PATH="$HOME/bin:$PATH"

cd ~/android/lineage

# Binary paths
BINARY_PATH="out/target/product/bluejay/system_ext/bin/sucre-snort"
OUTPUT_PATH="$SNORT_ROOT/build-output/sucre-snort"

# Optional clean
if [ "$1" = "--clean" ] || [ "$1" = "-c" ]; then
    echo "[Optional] Cleaning build artifacts..."
    rm -rf out/soong/.intermediates/*sucre-snort* 2>/dev/null || true
    rm -f "$BINARY_PATH" 2>/dev/null || true
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

echo "[1/6] Loading build environment..."
source build/envsetup.sh

echo "[2/6] Configuring lunch target..."
lunch lineage_bluejay-bp2a-userdebug

# Record timestamp before build
echo "[3/6] Checking existing binary..."
if [ -f "$BINARY_PATH" ]; then
    OLD_TIME=$(stat -c %Y "$BINARY_PATH" 2>/dev/null || echo 0)
    OLD_SIZE=$(stat -c %s "$BINARY_PATH" 2>/dev/null || echo 0)
    echo "Existing binary: $(date -d @$OLD_TIME '+%Y-%m-%d %H:%M:%S'), size: $OLD_SIZE bytes"
else
    OLD_TIME=0
    OLD_SIZE=0
    echo "No existing binary found (first build)"
fi
echo ""

echo "[4/6] Building sucre-snort (incremental)..."
START=$(date +%s)
m sucre-snort
END=$(date +%s)

# Verify binary was updated
if [ -f "$BINARY_PATH" ]; then
    NEW_TIME=$(stat -c %Y "$BINARY_PATH")
    NEW_SIZE=$(stat -c %s "$BINARY_PATH")
    
    if [ "$NEW_TIME" -le "$OLD_TIME" ]; then
        echo ""
        echo "⚠️  WARNING: Binary timestamp not updated!"
        echo "   This means no source files were modified, using cached version."
        echo "   If you expect changes, run: bash dev-build.sh --clean"
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
cp "$BINARY_PATH" "$OUTPUT_PATH"

echo ""
echo "=== Build Complete ==="
echo "Time: $((END - START))s"
echo "Output: $OUTPUT_PATH"
ls -lh "$OUTPUT_PATH"
echo ""
echo "Next: bash dev-deploy.sh"
