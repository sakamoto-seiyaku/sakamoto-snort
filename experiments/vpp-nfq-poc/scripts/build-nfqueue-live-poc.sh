#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-73 source-owned build. This never edits the historical work/vpp
# checkout: it clones the pinned revision into a dedicated throwaway tree,
# applies the 9000-byte provenance patch, overlays only nfqueue_live_poc, then
# emits a self-contained VPP install tree for the smoke command.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VPP_REPO="${VPP_REPO:-https://github.com/FDio/vpp.git}"
VPP_REVISION="${VPP_REVISION:-9258530f3804a152578ce11cc7c8a1e9eab88ed0}"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
VPP_DIR="${VPP_DIR:-$VPP_WORK_ROOT/vpp-s73-clean-$VPP_REVISION}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-s73-build-$VPP_REVISION}"
INSTALL_DIR="${INSTALL_DIR:-$VPP_WORK_ROOT/vpp-s73-install-$VPP_REVISION}"
NETFILTER_ROOT="${SAKAMOTO_NETFILTER_ROOT:-$REPO_ROOT/third_party/netfilter}"
JOBS="${JOBS:-$(nproc)}"
PATCH_FILE="$POC_DIR/overlay/patches/0001-s73-vpp-buffer-9000.patch"
REGULAR_MEMFD_PATCH_FILE="$POC_DIR/overlay/patches/0002-s73-opt-in-regular-memfd-fallback.patch"
OVERLAY_DIR="$POC_DIR/overlay/src/plugins/nfqueue_live_poc"
PYTHON_BIN="${PYTHON_BIN:-python3}"

mkdir -p "$VPP_WORK_ROOT"

if ! "$PYTHON_BIN" -c 'import ply' >/dev/null 2>&1; then
  PLY_VENV="$VPP_WORK_ROOT/s73-python-venv"
  if [ ! -x "$PLY_VENV/bin/python3" ]; then
    "$PYTHON_BIN" -m venv "$PLY_VENV"
    "$PLY_VENV/bin/python3" -m pip install --disable-pip-version-check --quiet ply
  fi
  PYTHON_BIN="$PLY_VENV/bin/python3"
fi

if [ ! -d "$VPP_DIR/.git" ]; then
  git clone --filter=blob:none "$VPP_REPO" "$VPP_DIR"
fi
git -C "$VPP_DIR" fetch --depth 1 origin "$VPP_REVISION" >/dev/null 2>&1 || true
git -C "$VPP_DIR" checkout --detach "$VPP_REVISION"
git -C "$VPP_DIR" reset --hard "$VPP_REVISION" >/dev/null
git -C "$VPP_DIR" clean -fd >/dev/null
if [ -n "$(git -C "$VPP_DIR" status --short)" ]; then
  echo "source tree is not clean before S73 overlay: $VPP_DIR" >&2
  exit 1
fi

if ! (cd "$VPP_DIR" && patch --batch --forward --fuzz=0 -p1 < "$PATCH_FILE"); then
  echo "S73 9000-byte patch does not apply to pinned VPP source" >&2
  exit 1
fi
if ! (cd "$VPP_DIR" && patch --batch --forward --fuzz=0 -p1 < "$REGULAR_MEMFD_PATCH_FILE"); then
  echo "S73 regular-memfd fallback patch does not apply to pinned VPP source" >&2
  exit 1
fi

rm -rf "$VPP_DIR/src/plugins/nfqueue_live_poc"
cp -R --no-preserve=ownership,timestamps "$OVERLAY_DIR" \
  "$VPP_DIR/src/plugins/nfqueue_live_poc"

if [ ! -f "$NETFILTER_ROOT/libnetfilter_queue/include/libnetfilter_queue/libnetfilter_queue.h" ]; then
  echo "checked-in netfilter source is missing: $NETFILTER_ROOT" >&2
  exit 1
fi

rm -rf "$BUILD_DIR" "$INSTALL_DIR"
cmake -S "$VPP_DIR/src" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DPython3_EXECUTABLE="$PYTHON_BIN" \
  -DVPP_MARCH_VARIANT_HSW=OFF \
  -DVPP_MARCH_VARIANT_SKX=OFF \
  -DVPP_MARCH_VARIANT_ICL=OFF \
  -DVPP_PLUGINS=nfqueue_live_poc \
  -DSAKAMOTO_NETFILTER_ROOT="$NETFILTER_ROOT"
# VPP's generated install manifest covers the core support tools in addition
# to the runtime binary.  Drive the install target so its `all` prerequisite
# builds every manifest input before installation (a direct `cmake --install`
# would fail on unbuilt support libraries such as svmdb/vlibmemoryclient).
cmake --build "$BUILD_DIR" --target install -j "$JOBS"

plugin="$(find "$BUILD_DIR" -path '*/vpp_plugins/nfqueue_live_poc_plugin.so' -print -quit)"
if [ -z "$plugin" ]; then
  echo "nfqueue_live_poc_plugin.so was not produced" >&2
  exit 1
fi
plugin_dir="$INSTALL_DIR/lib/vpp_plugins"
mkdir -p "$plugin_dir"
cp "$plugin" "$plugin_dir/nfqueue_live_poc_plugin.so"

revision="$(git -C "$VPP_DIR" rev-parse HEAD)"
patch_sha="$(sha256sum "$PATCH_FILE" | awk '{print $1}')"
regular_memfd_patch_sha="$(sha256sum "$REGULAR_MEMFD_PATCH_FILE" | awk '{print $1}')"
source_sha="$(sha256sum "$VPP_DIR/src/vlib/buffer.h" | awk '{print $1}')"
mkdir -p "$INSTALL_DIR"
{
  echo "ticket=SAKAMOTO-73"
  echo "sourceRevision=$revision"
  echo "sourceRepository=$VPP_REPO"
  echo "bufferDataSize=9000"
  echo "provenancePatch=$PATCH_FILE"
  echo "provenancePatchSha256=$patch_sha"
  echo "regularMemfdFallbackPatch=$REGULAR_MEMFD_PATCH_FILE"
  echo "regularMemfdFallbackPatchSha256=$regular_memfd_patch_sha"
  echo "patchedBufferHeaderSha256=$source_sha"
  echo "plugin=nfqueue_live_poc_plugin.so"
  echo "pluginSha256=$(sha256sum "$plugin_dir/nfqueue_live_poc_plugin.so" | awk '{print $1}')"
  echo "buildDirectory=$BUILD_DIR"
  echo "installDirectory=$INSTALL_DIR"
} | tee "$INSTALL_DIR/s73-provenance.properties"

echo "S73 VPP source: $VPP_DIR"
echo "S73 VPP install: $INSTALL_DIR"
