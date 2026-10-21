#!/usr/bin/env bash
set -euo pipefail

# Build the one official VPP-native product plugin against a verified Product
# Host VPP stage, then build the Rust Product Core with the generated VAPI C
# transport. This script deliberately does not build or copy a POC or the
# retired C++ daemon.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/tools/product/path-helpers.sh"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
source_manifest="$repo_root/src/product/vpp/product-vpp-artifact.properties"
expected_revision="$(tr -d '[:space:]' < "$pin_file")"
stage_raw="${VPP_HOST_STAGE_DIR:-}"
host_evidence="${SAKAMOTO_PRODUCT_HOST_EVIDENCE:-OFF}"
root_batch_experiment="${SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT:-ON}"
root_verdict_batch_experiment="${SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT:-$root_batch_experiment}"
root_verdict_sender_default=sendmmsg
if [[ "$root_verdict_batch_experiment" == ON ]]; then root_verdict_sender_default=packed; fi
root_verdict_batch_mode="${SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE:-$root_verdict_sender_default}"
policy_qualification_counters="${SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS:-$root_batch_experiment}"
if [[ "$root_batch_experiment" != ON && "$root_batch_experiment" != OFF ]]; then
  echo "SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT must be ON or OFF" >&2
  exit 2
fi
if [[ "$policy_qualification_counters" != ON && "$policy_qualification_counters" != OFF ]]; then
  echo "SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS must be ON or OFF" >&2
  exit 2
fi
if [[ "$root_verdict_batch_experiment" != ON && "$root_verdict_batch_experiment" != OFF ]]; then
  echo "SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT must be ON or OFF" >&2
  exit 2
fi
if [[ "$root_verdict_batch_experiment" == ON && "$root_batch_experiment" != ON ]]; then
  echo "Root verdict batching requires SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT=ON" >&2
  exit 2
fi
case "$root_verdict_batch_mode" in
  scalar|sendmmsg|packed) ;;
  *) echo "SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE must be scalar, sendmmsg or packed" >&2; exit 2 ;;
esac
if [[ "$root_verdict_batch_experiment" != ON && "$root_verdict_batch_mode" != sendmmsg ]]; then
  echo "Selecting a Root verdict sender requires SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT=ON" >&2
  exit 2
fi
if [[ "$root_batch_experiment" == ON ]]; then policy_qualification_counters=ON; fi
if [[ "$host_evidence" != ON && "$host_evidence" != OFF ]]; then
  echo "SAKAMOTO_PRODUCT_HOST_EVIDENCE must be ON or OFF" >&2
  exit 2
fi
if [[ "$host_evidence" == ON ]]; then
  echo "Legacy Host-only evidence is unavailable on the current VPP pin (removed reassembly interfaces)." >&2
  echo "Use SAKAMOTO_PRODUCT_HOST_EVIDENCE=OFF for the Product mainline." >&2
  exit 2
fi
product_prepare_build_output || exit 2
artifact_root="$(product_validate_artifact_root \
  "${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host}")" || exit 2
artifact_marker="$artifact_root/.sakamoto-product-artifact"

usage() {
  echo "usage: VPP_HOST_STAGE_DIR=/path/to/verified/host-stage $0" >&2
}

manifest_value() {
  local manifest="$1"
  local key="$2"
  sed -n "s/^${key}=//p" "$manifest"
}

runtime_closure() {
  local prefix="$1"
  (
    cd "$prefix"
    while IFS= read -r path; do
      if [[ -L "$path" ]]; then
        printf 'link %s %s\n' "$path" "$(readlink -- "$path")"
      else
        printf 'file %s %s\n' "$path" \
          "$(sha256sum -- "$path" | awk '{print $1}')"
      fi
    done < <(find . -type f -o -type l | LC_ALL=C sort)
  ) | sha256sum | awk '{print $1}'
}

if [[ -z "$stage_raw" ]]; then
  usage
  echo "VPP_HOST_STAGE_DIR is required" >&2
  exit 2
fi
stage_dir="$(product_canonical_existing "$stage_raw")" || exit 2
stage_marker="$stage_dir/.sakamoto-product-vpp-stage"
stage_manifest="$stage_dir/host-vpp-stage.properties"
if [[ ! -d "$stage_dir" || -L "$stage_dir" || ! -f "$stage_marker"
      || -L "$stage_marker"
      || "$(tr -d '\r\n' < "$stage_marker")" != \
           sakamoto-product-vpp-stage-v1
      || ! -f "$stage_manifest" || -L "$stage_manifest" ]]; then
  echo "Host VPP stage marker is missing or invalid" >&2
  exit 2
fi
expected_core_count="$(manifest_value "$source_manifest" vpp.core.patch.count)"
expected_core_sha256="$(manifest_value "$source_manifest" vpp.core.patch.sha256)"
if [[ "$(manifest_value "$stage_manifest" vpp.base.revision)" != \
      "$expected_revision" ]]; then
  echo "Host VPP stage base revision mismatch" >&2
  exit 2
fi
if [[ "$(manifest_value "$stage_manifest" vpp.stage.profile)" != host ]]; then
  echo "Host VPP stage profile mismatch" >&2
  exit 2
fi
if [[ "$(manifest_value "$stage_manifest" vpp.core.patch.count)" != \
        "$expected_core_count"
      || "$(manifest_value "$stage_manifest" vpp.core.patch.sha256)" != \
           "$expected_core_sha256" ]]; then
  echo "Host VPP stage core patch identity mismatch" >&2
  exit 2
fi
runtime_closure_sha256="$(
  manifest_value "$stage_manifest" vpp.runtime.closure.sha256
)"
source_closure_sha256="$(
  manifest_value "$stage_manifest" vpp.source.closure.sha256
)"
if [[ ! "$runtime_closure_sha256" =~ ^[[:xdigit:]]{64}$
      || ! "$source_closure_sha256" =~ ^[[:xdigit:]]{64}$ ]]; then
  echo "Host VPP stage closure identity is invalid" >&2
  exit 2
fi

vpp_source="$stage_dir/source"
vpp_prefix="$vpp_source/build-root/install-vpp-native/vpp"
if [[ ! -d "$vpp_source" || ! -e "$vpp_source/.git" ]]; then
  echo "Host VPP stage patched source is missing" >&2
  exit 2
fi
actual_revision="$(git -C "$vpp_source" rev-parse HEAD)"
if [[ "$actual_revision" != "$expected_revision" ]]; then
  echo "Host VPP stage patched source revision mismatch" >&2
  exit 2
fi
source_tree_sha256="$(
  git -C "$vpp_source" diff --binary HEAD | sha256sum | awk '{print $1}'
)"
if [[ "$source_tree_sha256" != \
      "$(manifest_value "$stage_manifest" vpp.source.tree.sha256)" ]]; then
  echo "Host VPP stage patched source tree mismatch" >&2
  exit 2
fi
vpp_prefix="$(product_validate_host_vpp_install_prefix \
  "$vpp_source" "$vpp_prefix")" || exit 2
if [[ "$(runtime_closure "$vpp_prefix")" != "$runtime_closure_sha256" ]]; then
  echo "Host VPP stage runtime closure mismatch" >&2
  exit 2
fi

vpp_bin="$(product_canonical_existing "$vpp_prefix/bin/vpp")" || exit 2
expected_vpp_bin="$(product_canonical_existing "$vpp_prefix/bin/vpp")" || exit 2
if [[ "$vpp_bin" != "$expected_vpp_bin" || ! -x "$vpp_bin" ]]; then
  echo "Host VPP stage executable is invalid" >&2
  exit 2
fi
product_require_within "$vpp_prefix" "$vpp_bin" || exit 2
vpp_include="$(product_canonical_existing "$vpp_prefix/include")" || exit 2
expected_vpp_include="$(product_canonical_existing "$vpp_prefix/include")" || exit 2
if [[ "$vpp_include" != "$expected_vpp_include" || ! -d "$vpp_include" ]]; then
  echo "Host VPP stage include tree is invalid" >&2
  exit 2
fi
product_require_within "$vpp_prefix" "$vpp_include" || exit 2
vpp_lib="$(product_resolve_vpp_library_dir \
  "$vpp_prefix" "")" || exit 2
vpp_apigen="$(product_canonical_existing \
  "$vpp_source/src/tools/vppapigen/vppapigen")" || exit 2
vpp_vapi_gen="$(product_canonical_existing \
  "$vpp_source/src/vpp-api/vapi/vapi_c_gen.py")" || exit 2
vpp_vapi_cpp_gen="$(product_canonical_existing \
  "$vpp_source/src/vpp-api/vapi/vapi_cpp_gen.py")" || exit 2
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
  -DSAKAMOTO_PRODUCT_VPP_SOURCE_TREE_SHA256="$source_tree_sha256" \
  -DSAKAMOTO_PRODUCT_HOST_EVIDENCE="$host_evidence" \
  -DSAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT="$root_batch_experiment" \
  -DSAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT="$root_verdict_batch_experiment" \
  -DSAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE="$root_verdict_batch_mode" \
  -DSAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS="$policy_qualification_counters" \
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
  echo "vpp.stage.profile=host"
  echo "product.host.evidence=$host_evidence"
  echo "experiment.root.batch=$root_batch_experiment"
  echo "experiment.root.verdict.batch=$root_verdict_batch_experiment"
  echo "experiment.root.verdict.mode=$root_verdict_batch_mode"
  echo "experiment.policy.qualification=$policy_qualification_counters"
  echo "quic.crypto=mbedtls-3.6.7-aes-gcm-sha256-static-c"
  echo "domain.matcher=valkey-rax-05a9c29c62538519d870d6512978f80ac58a758f-vpp-fallible"
  echo "quic.version=1"
  echo "vpp.runtime.closure.sha256=$runtime_closure_sha256"
  echo "vpp.source.closure.sha256=$source_closure_sha256"
  echo "vpp.source.tree.sha256=$source_tree_sha256"
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
