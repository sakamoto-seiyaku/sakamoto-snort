#!/usr/bin/env bash
set -euo pipefail

# Build the one official VPP-native product plugin against a prebuilt pinned
# VPP installation, then build the Rust Product Core with the generated VAPI
# C transport. This script deliberately does not build or copy a POC or the
# retired C++ daemon.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/tools/product/path-helpers.sh"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
expected_revision="$(tr -d '[:space:]' < "$pin_file")"
vpp_source_raw="${VPP_SOURCE_DIR:-}"
vpp_prefix_raw="${VPP_INSTALL_PREFIX:-}"
product_prepare_build_output || exit 2
artifact_root="$(product_validate_artifact_root \
  "${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host}")" || exit 2
artifact_marker="$artifact_root/.sakamoto-product-artifact"

usage() {
  echo "usage: VPP_SOURCE_DIR=/path/to/pinned/vpp [VPP_INSTALL_PREFIX=/path/to/vpp-prefix] $0" >&2
  echo "       set BUILD_VPP_RUNTIME=1 to let the pinned checkout build its own runtime" >&2
}

if [[ -z "$vpp_source_raw" || ( -z "$vpp_prefix_raw" && "${BUILD_VPP_RUNTIME:-0}" != 1 ) ]]; then
  usage
  exit 2
fi
vpp_source="$(product_canonical_existing "$vpp_source_raw")" || exit 2
if [[ ! -d "$vpp_source" || ! -e "$vpp_source/.git" ]]; then
  echo "VPP_SOURCE_DIR must be a git checkout so the source revision is auditable" >&2
  exit 2
fi
actual_revision="$(git -C "$vpp_source" rev-parse HEAD)"
if [[ "$actual_revision" != "$expected_revision" ]]; then
  echo "VPP revision mismatch: expected $expected_revision, got $actual_revision" >&2
  exit 2
fi
if ! git -C "$vpp_source" diff --quiet --exit-code ||
   ! git -C "$vpp_source" diff --cached --quiet --exit-code ||
   [[ -n "$(git -C "$vpp_source" status --porcelain)" ]]; then
  echo "VPP_SOURCE_DIR has uncommitted changes; reproducible product artifacts require a clean checkout" >&2
  exit 2
fi

if [[ "${BUILD_VPP_RUNTIME:-0}" == 1 ]]; then
  # This is the pinned VPP project's own release build. It is opt-in because
  # dependency installation and a full VPP compile are environment concerns;
  # the exact source revision and clean-worktree checks above remain mandatory.
  make -C "$vpp_source" build-release
  vpp_prefix_raw="${vpp_prefix_raw:-$vpp_source/build-root/install-vpp-native/vpp}"
fi
if [[ -z "$vpp_prefix_raw" ]]; then
  echo "VPP_INSTALL_PREFIX is required (or set BUILD_VPP_RUNTIME=1)" >&2
  exit 2
fi
vpp_prefix="$(product_validate_host_vpp_install_prefix \
  "$vpp_source" "$vpp_prefix_raw")" || exit 2

vpp_bin="$(product_canonical_existing \
  "${VPP_BIN:-$vpp_prefix/bin/vpp}")" || exit 2
expected_vpp_bin="$(product_canonical_existing "$vpp_prefix/bin/vpp")" || exit 2
if [[ "$vpp_bin" != "$expected_vpp_bin" || ! -x "$vpp_bin" ]]; then
  echo "VPP_BIN must be the executable from VPP_INSTALL_PREFIX" >&2
  exit 2
fi
product_require_within "$vpp_prefix" "$vpp_bin" || exit 2
vpp_include="$(product_canonical_existing \
  "${VPP_INCLUDE_DIR:-$vpp_prefix/include}")" || exit 2
expected_vpp_include="$(product_canonical_existing "$vpp_prefix/include")" || exit 2
if [[ "$vpp_include" != "$expected_vpp_include" || ! -d "$vpp_include" ]]; then
  echo "VPP_INCLUDE_DIR must be the include tree from VPP_INSTALL_PREFIX" >&2
  exit 2
fi
product_require_within "$vpp_prefix" "$vpp_include" || exit 2
vpp_lib="$(product_resolve_vpp_library_dir \
  "$vpp_prefix" "${VPP_LIBRARY_DIR:-}")" || exit 2
vpp_apigen="$(product_canonical_existing \
  "${VPP_APIGEN:-$vpp_source/src/tools/vppapigen/vppapigen}")" || exit 2
vpp_vapi_gen="$(product_canonical_existing \
  "${VPP_VAPI_C_GEN:-$vpp_source/src/vpp-api/vapi/vapi_c_gen.py}")" || exit 2
vpp_vapi_cpp_gen="$(product_canonical_existing \
  "${VPP_VAPI_CPP_GEN:-$vpp_source/src/vpp-api/vapi/vapi_cpp_gen.py}")" || exit 2
product_require_within "$vpp_source" "$vpp_apigen" || exit 2
product_require_within "$vpp_source" "$vpp_vapi_gen" || exit 2
product_require_within "$vpp_source" "$vpp_vapi_cpp_gen" || exit 2
if [[ ! -f "$vpp_lib/libvapiclient.so" && ! -f "$vpp_lib/libvapiclient.so.0" ]]; then
  echo "missing pinned VPP libvapiclient; build the official VPP runtime first" >&2
  exit 2
fi

if [[ -e "$artifact_root" ]]; then
  if [[ ! -d "$artifact_root" || ! -f "$artifact_marker" ||
        -L "$artifact_marker" ||
        "$(tr -d '\r\n' < "$artifact_marker")" != \
          "sakamoto-product-artifact-root-v1" ]]; then
    echo "refusing to clean an unvalidated product artifact root: $artifact_root" >&2
    exit 2
  fi
  rm -rf -- "$artifact_root"
fi
mkdir -p "$artifact_root"
printf '%s\n' 'sakamoto-product-artifact-root-v1' > "$artifact_marker"
mkdir -p "$artifact_root/bin" "$artifact_root/lib"
install -m 0755 "$vpp_bin" "$artifact_root/bin/vpp"
mapfile -t vpp_library_names < <(
  find "$vpp_lib" -mindepth 1 -maxdepth 1 \
    \( -type f -o -type l \) -name 'lib*.so*' -printf '%f\n' | sort)
if [[ "${#vpp_library_names[@]}" -eq 0 ]]; then
  echo "the pinned VPP install contains no shared runtime libraries" >&2
  exit 2
fi
libraries_manifest="$artifact_root/vpp-libraries.sha256"
: > "$libraries_manifest"
for library_name in "${vpp_library_names[@]}"; do
  if [[ ! "$library_name" =~ ^lib[A-Za-z0-9._+-]+$ ]]; then
    echo "unsafe VPP library name: $library_name" >&2
    exit 2
  fi
  core_library="$vpp_lib/$library_name"
  resolved_library="$(realpath -e -- "$core_library")" || exit 2
  product_require_within "$vpp_prefix" "$resolved_library" || exit 2
  cp -a -- "$core_library" "$artifact_root/lib/$library_name"
  printf '%s  %s\n' "$(sha256sum -- "$core_library" | awk '{print $1}')" \
    "$library_name" >> "$libraries_manifest"
done
plugin_build="$artifact_root/plugin-build"
cmake -S "$repo_root/src/product/vpp" -B "$plugin_build" -G Ninja \
  -DVPP_SOURCE_DIR="$vpp_source" \
  -DVPP_INCLUDE_DIR="$vpp_include" \
  -DVPP_APIGEN="$vpp_apigen" \
  -DVPP_VAPI_C_GEN="$vpp_vapi_gen" \
  -DVPP_VAPI_CPP_GEN="$vpp_vapi_cpp_gen" \
  -DCMAKE_INSTALL_PREFIX="$artifact_root" \
  -DCMAKE_INSTALL_LIBDIR=lib
cmake --build "$plugin_build" --target install

plugin_dir="$artifact_root/lib/vpp_plugins"
plugin="$plugin_dir/product_core_plugin.so"
if [[ -L "$plugin_dir" || -L "$plugin" || ! -f "$plugin" ]]; then
  echo "product VPP plugin was not produced at $plugin" >&2
  exit 1
fi
mapfile -t plugin_entries < <(find "$plugin_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [[ "${#plugin_entries[@]}" -ne 1 ||
      "${plugin_entries[0]:-}" != product_core_plugin.so ||
      ! -f "$plugin_dir/product_core_plugin.so" ]]; then
  echo "product artifact must contain exactly one allowlisted plugin" >&2
  printf 'found: %s\n' "${plugin_entries[@]}" >&2
  exit 1
fi
generated_api="$plugin_build/product_core.api.json"
if [[ -L "$generated_api" || ! -f "$generated_api" ]]; then
  echo "official VPP API generator did not produce product_core.api.json" >&2
  exit 1
fi
manifest_api_crc="$(awk -F= '$1 == "product.api.crc" { print $2; exit }' \
  "$repo_root/src/product/vpp/product-vpp-artifact.properties")"
if [[ ! "$manifest_api_crc" =~ ^[[:xdigit:]]{8}$ ]]; then
  echo "product.api.crc in product-vpp-artifact.properties is invalid" >&2
  exit 1
fi
if ! grep -Eiq '"vl_api_version"[[:space:]]*:[[:space:]]*"0x?'"$manifest_api_crc"'"' \
  "$generated_api"; then
  echo "generated product API CRC does not match product-vpp-artifact.properties" >&2
  exit 1
fi
generated_api_install="$artifact_root/share/vpp/api/plugins/product_core.api.json"
mkdir -p "$(dirname "$generated_api_install")"
install -m 0644 "$generated_api" "$generated_api_install"
generated_vapi_dir="$plugin_build/CMakeFiles/vpp-api/vapi"
if [[ ! -d "$generated_vapi_dir" ]]; then
  echo "official VPP CMake did not leave generated VAPI headers for Rust" >&2
  exit 1
fi

export SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR="$vpp_include"
export SAKAMOTO_PRODUCT_VAPI_LIBRARY_DIR="$vpp_lib"
export SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR="$generated_vapi_dir"
export SAKAMOTO_PRODUCT_VAPI_REQUIRED=1
cargo build --release -p sakamoto-product-core
install -m 0755 "$repo_root/target/release/sakamoto-product-core-host" \
  "$artifact_root/bin/sakamoto-product-core-host"

cp "$repo_root/src/product/vpp/product-vpp-artifact.properties" \
  "$artifact_root/product-vpp-artifact.properties"
{
  echo "source.revision=$actual_revision"
  echo "vpp.binary.sha256=$(sha256sum "$vpp_bin" | awk '{print $1}')"
  echo "product.plugin.sha256=$(sha256sum "$plugin" | awk '{print $1}')"
  echo "generated.api.path=share/vpp/api/plugins/product_core.api.json"
  echo "generated.api.sha256=$(sha256sum "$generated_api_install" | awk '{print $1}')"
  echo "vpp.libraries.sha256=vpp-libraries.sha256"
  echo "rust.core.sha256=$(sha256sum "$artifact_root/bin/sakamoto-product-core-host" | awk '{print $1}')"
  echo "rust.core.profile=release"
  echo "rust.core.artifact=target/release/sakamoto-product-core-host"
} >> "$artifact_root/product-vpp-artifact.properties"

echo "artifact=$artifact_root"
echo "vpp=$vpp_bin"
echo "plugin=$plugin"
echo "allowlist=product_core_plugin.so"
