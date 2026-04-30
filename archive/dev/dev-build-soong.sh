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

LINEAGE_ROOT="${LINEAGE_ROOT:-$HOME/android/lineage}"
LUNCH_TARGET="${DEV_LUNCH_TARGET:-lineage_bluejay-bp2a-userdebug}"
LUNCH_PRODUCT="${DEV_LUNCH_PRODUCT:-${LUNCH_TARGET%%-*}}"
TARGET_DEVICE="${DEV_TARGET_DEVICE:-${LUNCH_PRODUCT#lineage_}}"
PACKAGE_BINARY_PATH="${DEV_PACKAGE_BINARY_PATH:-out/target/product/${TARGET_DEVICE}/system_ext/bin/sucre-snort}"
DIRECT_NINJA_TARGET="${DEV_DIRECT_NINJA_TARGET:-$PACKAGE_BINARY_PATH}"
COMBINED_NINJA_PATH="${DEV_COMBINED_NINJA_PATH:-out/combined-${LUNCH_PRODUCT}.ninja}"
SOONG_NINJA_PATH="${DEV_SOONG_NINJA_PATH:-out/soong/build.${LUNCH_PRODUCT}.ninja}"
OUTPUT_PATH="${DEV_BUILD_OUTPUT_PATH:-$SNORT_ROOT/build-output/sucre-snort}"
DEBUG_OUTPUT_PATH="${DEV_BUILD_DEBUG_OUTPUT_PATH:-$SNORT_ROOT/build-output/sucre-snort.debug}"
NOCACHE_OUTPUT_NAME="sucre-snort-iprules-nocache"
OUTPUT_PATH_NOCACHE="$SNORT_ROOT/build-output/${NOCACHE_OUTPUT_NAME}"
DEBUG_OUTPUT_PATH_NOCACHE="$SNORT_ROOT/build-output/${NOCACHE_OUTPUT_NAME}.debug"
BUILD_SOURCE_PATH="$PACKAGE_BINARY_PATH"
BUILD_MODE_DESC="full graph regeneration (m sucre-snort)"
USE_DIRECT_NINJA=0
DIRECT_NINJA_JOBS="${DEV_BUILD_JOBS:-4}"

if [[ ! -d "$LINEAGE_ROOT" ]]; then
    echo "❌ 未找到 LINEAGE_ROOT: $LINEAGE_ROOT" >&2
    exit 1
fi

binary_build_id() {
    local binary_path="$1"

    [[ -f "$binary_path" ]] || return 1
    readelf -n "$binary_path" 2>/dev/null | awk '/Build ID:/ { print $3; exit }'
}

binary_has_debug_info() {
    local binary_path="$1"

    [[ -f "$binary_path" ]] || return 1
    readelf -S "$binary_path" 2>/dev/null | grep -q '\.debug_info'
}

find_matching_unstripped_binary() {
    local stripped_binary="$1"
    local expected_build_id=""
    local binary_name=""
    local candidate=""

    expected_build_id="$(binary_build_id "$stripped_binary" 2>/dev/null || true)"
    [[ -n "$expected_build_id" ]] || return 1

    binary_name="$(basename "$stripped_binary")"
    while IFS= read -r candidate; do
        if [[ "$(binary_build_id "$candidate" 2>/dev/null || true)" == "$expected_build_id" ]] \
            && binary_has_debug_info "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done < <(find out/soong/.intermediates/system -path "*/unstripped/$binary_name" -type f 2>/dev/null | sort)

    return 1
}

cd "$LINEAGE_ROOT"

# Optional clean
if [[ $CLEAN -eq 1 ]]; then
    echo "[Optional] Cleaning build artifacts..."
    rm -rf out/soong/.intermediates/*sucre-snort* 2>/dev/null || true
    rm -f "$PACKAGE_BINARY_PATH" 2>/dev/null || true
    rm -f "$DIRECT_NINJA_TARGET" 2>/dev/null || true
    rm -f "$OUTPUT_PATH" "$DEBUG_OUTPUT_PATH" "$OUTPUT_PATH_NOCACHE" "$DEBUG_OUTPUT_PATH_NOCACHE" 2>/dev/null || true
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
    BUILD_SOURCE_PATH="$PACKAGE_BINARY_PATH"
    BUILD_MODE_DESC="direct ninja reuse (${DIRECT_NINJA_JOBS} jobs, no Soong regen)"
fi

if [[ $USE_DIRECT_NINJA -eq 1 ]]; then
    echo "[1/6] Reusing existing ninja graph..."
    echo "Build mode: $BUILD_MODE_DESC"
else
    echo "[1/6] Loading build environment..."
    source build/envsetup.sh

    echo "[2/6] Configuring lunch target..."
    lunch "$LUNCH_TARGET"
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
echo "LINEAGE_ROOT: $LINEAGE_ROOT"
echo "Lunch target: $LUNCH_TARGET"
echo "Target device: $TARGET_DEVICE"
START=$(date +%s)
if [[ $USE_DIRECT_NINJA -eq 1 ]]; then
    prebuilts/build-tools/linux-x86/bin/ninja -f "$COMBINED_NINJA_PATH" -j "$DIRECT_NINJA_JOBS" "$DIRECT_NINJA_TARGET"
else
    m -j "$DIRECT_NINJA_JOBS" sucre-snort
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
        echo "   If you expect changes, run: bash dev/dev-build.sh --clean"
        if [[ $USE_DIRECT_NINJA -eq 1 ]]; then
            echo "   If Android.bp changed, run: bash dev/dev-build.sh --regen-graph"
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

echo "[5/6] Building cache-off diagnostic variant (iprules decision cache disabled)..."
ENGINE_CPP_PATH="$LINEAGE_SNORT_PATH/src/IpRulesEngine.cpp"
ENGINE_CPP_BACKUP="$(mktemp "${TMPDIR:-/tmp}/IpRulesEngine.cpp.XXXXXX")"
cp "$ENGINE_CPP_PATH" "$ENGINE_CPP_BACKUP"

restore_engine_cpp() {
    if [[ -n "${ENGINE_CPP_BACKUP:-}" && -f "$ENGINE_CPP_BACKUP" ]]; then
        cp "$ENGINE_CPP_BACKUP" "$ENGINE_CPP_PATH"
        rm -f "$ENGINE_CPP_BACKUP"
    fi
}
trap restore_engine_cpp EXIT

if ! grep -q "^#define SUCRE_SNORT_IPRULES_DECISION_CACHE 1$" "$ENGINE_CPP_PATH"; then
    echo "❌ Unexpected decision-cache toggle line in: $ENGINE_CPP_PATH" >&2
    echo "Expected an exact line: #define SUCRE_SNORT_IPRULES_DECISION_CACHE 1" >&2
    exit 1
fi
sed -i 's/^#define SUCRE_SNORT_IPRULES_DECISION_CACHE 1$/#define SUCRE_SNORT_IPRULES_DECISION_CACHE 0/' "$ENGINE_CPP_PATH"

if [[ $USE_DIRECT_NINJA -eq 1 ]]; then
    prebuilts/build-tools/linux-x86/bin/ninja -f "$COMBINED_NINJA_PATH" -j "$DIRECT_NINJA_JOBS" "$DIRECT_NINJA_TARGET"
else
    m -j "$DIRECT_NINJA_JOBS" sucre-snort
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
cp "$BUILD_SOURCE_PATH" "$OUTPUT_PATH_NOCACHE"
DEBUG_SOURCE_PATH_NOCACHE="$(find_matching_unstripped_binary "$BUILD_SOURCE_PATH" || true)"
if [[ -n "$DEBUG_SOURCE_PATH_NOCACHE" ]]; then
    cp "$DEBUG_SOURCE_PATH_NOCACHE" "$DEBUG_OUTPUT_PATH_NOCACHE"
else
    rm -f "$DEBUG_OUTPUT_PATH_NOCACHE" 2>/dev/null || true
fi

echo ""
echo "[6/6] Restoring cache-on source and rebuilding default..."
restore_engine_cpp
trap - EXIT

if [[ $USE_DIRECT_NINJA -eq 1 ]]; then
    prebuilts/build-tools/linux-x86/bin/ninja -f "$COMBINED_NINJA_PATH" -j "$DIRECT_NINJA_JOBS" "$DIRECT_NINJA_TARGET"
else
    m -j "$DIRECT_NINJA_JOBS" sucre-snort
fi

cp "$BUILD_SOURCE_PATH" "$OUTPUT_PATH"
DEBUG_SOURCE_PATH="$(find_matching_unstripped_binary "$BUILD_SOURCE_PATH" || true)"
if [[ -n "$DEBUG_SOURCE_PATH" ]]; then
    cp "$DEBUG_SOURCE_PATH" "$DEBUG_OUTPUT_PATH"
else
    rm -f "$DEBUG_OUTPUT_PATH" 2>/dev/null || true
fi
END=$(date +%s)

echo ""
echo "=== Build Complete ==="
echo "Time: $((END - START))s"
echo "Output: $OUTPUT_PATH"
ls -lh "$OUTPUT_PATH"
echo "Output (nocache): $OUTPUT_PATH_NOCACHE"
ls -lh "$OUTPUT_PATH_NOCACHE"
if [[ -f "$DEBUG_OUTPUT_PATH" ]]; then
    echo "Debug symbols: $DEBUG_OUTPUT_PATH"
    ls -lh "$DEBUG_OUTPUT_PATH"
else
    echo "⚠️  未找到匹配 Build ID 的 unstripped 产物，未生成 $DEBUG_OUTPUT_PATH"
fi
if [[ -f "$DEBUG_OUTPUT_PATH_NOCACHE" ]]; then
    echo "Debug symbols (nocache): $DEBUG_OUTPUT_PATH_NOCACHE"
    ls -lh "$DEBUG_OUTPUT_PATH_NOCACHE"
else
    echo "⚠️  未找到匹配 Build ID 的 unstripped 产物，未生成 $DEBUG_OUTPUT_PATH_NOCACHE"
fi
echo ""
echo "Next: bash dev/dev-deploy.sh"
