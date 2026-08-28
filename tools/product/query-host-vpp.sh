#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/tools/product/path-helpers.sh"
product_prepare_build_output || exit 2
artifact_root="$(product_validate_artifact_root \
  "${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host}")" || exit 2
runtime_dir="$(product_validate_runtime_root \
  "${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime}")" || exit 2
core_bin="$artifact_root/bin/sakamoto-product-core-host"
if [[ -n "${PRODUCT_CORE_BIN:-}" &&
      "$(product_canonical_for_write "$PRODUCT_CORE_BIN")" != "$core_bin" ]]; then
  echo "PRODUCT_CORE_BIN must resolve to the verified artifact binary" >&2
  exit 2
fi
socket="$(product_validate_owned_child "$runtime_dir" api.sock)" || exit 2
generation_file="$(product_validate_owned_child "$runtime_dir" generation)" || exit 2
manifest="$artifact_root/product-vpp-artifact.properties"
artifact_marker="$artifact_root/.sakamoto-product-artifact"
source_manifest="$repo_root/src/product/vpp/product-vpp-artifact.properties"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"

manifest_value() {
  local manifest_file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
    "$manifest_file"
}

if [[ ! -x "$core_bin" || -L "$core_bin" || ! -S "$socket" ||
      ! -f "$generation_file" || ! -f "$manifest" || -L "$manifest" ]]; then
  echo "Host Product Core query requires a running artifact generation" >&2
  exit 2
fi
if [[ ! -f "$artifact_marker" || -L "$artifact_marker" ||
      "$(tr -d '\r\n' < "$artifact_marker")" != \
        "sakamoto-product-artifact-root-v1" ]]; then
  echo "artifact root is not marked as a validated product build" >&2
  exit 2
fi
if [[ ! -f "$source_manifest" || ! -f "$pin_file" ]]; then
  echo "source Product VPP identity manifest is missing" >&2
  exit 2
fi
for key in \
  artifact.id vpp.source.url vpp.revision product.abi.version \
  product.api.version product.api.crc product.api.identity product.plugin \
  product.plugin.allowlist product.adapter.available product.protection.running \
  control.transport control.sessions.per.generation control.buffers; do
  expected_value="$(manifest_value "$source_manifest" "$key")"
  actual_value="$(manifest_value "$manifest" "$key")"
  if [[ -z "$expected_value" || "$actual_value" != "$expected_value" ]]; then
    echo "artifact manifest identity mismatch for $key" >&2
    exit 2
  fi
done
expected_revision="$(tr -d '[:space:]' < "$pin_file")"
if [[ "$(manifest_value "$manifest" vpp.revision)" != "$expected_revision" ||
      "$(manifest_value "$manifest" source.revision)" != "$expected_revision" ]]; then
  echo "artifact VPP revision provenance is missing or mismatched" >&2
  exit 2
fi
plugin="$artifact_root/lib/vpp_plugins/product_core_plugin.so"
plugin_hash="$(manifest_value "$manifest" product.plugin.sha256)"
plugin_dir="$artifact_root/lib/vpp_plugins"
mapfile -t plugin_entries < <(find "$plugin_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [[ -L "$plugin_dir" || "${#plugin_entries[@]}" -ne 1 ||
      "${plugin_entries[0]:-}" != product_core_plugin.so ||
      -L "$plugin" || ! -f "$plugin" || ! "$plugin_hash" =~ ^[[:xdigit:]]{64}$ ||
      "$(sha256sum "$plugin" | awk '{print $1}')" != "$plugin_hash" ]]; then
  echo "product plugin identity/hash does not match the artifact manifest" >&2
  exit 2
fi
generated_api_relative="$(manifest_value "$manifest" generated.api.path)"
if [[ "$generated_api_relative" != share/vpp/api/plugins/product_core.api.json ]]; then
  echo "generated product API path is not the pinned artifact path" >&2
  exit 2
fi
generated_api="$artifact_root/$generated_api_relative"
generated_api_hash="$(manifest_value "$manifest" generated.api.sha256)"
if [[ ! -f "$generated_api" || -L "$generated_api" ||
      ! "$generated_api_hash" =~ ^[[:xdigit:]]{64}$ ||
      "$(sha256sum "$generated_api" | awk '{print $1}')" != "$generated_api_hash" ]]; then
  echo "generated product API hash does not match the artifact manifest" >&2
  exit 2
fi
api_crc="$(manifest_value "$manifest" product.api.crc)"
if [[ ! "$api_crc" =~ ^[[:xdigit:]]{8}$ ]]; then
  echo "artifact product.api.crc is invalid" >&2
  exit 2
fi
if ! grep -Eiq '"vl_api_version"[[:space:]]*:[[:space:]]*"0x?'"$api_crc"'"' \
  "$generated_api"; then
  echo "generated product API CRC does not match the artifact manifest" >&2
  exit 2
fi
libraries_manifest_name="$(manifest_value "$manifest" vpp.libraries.sha256)"
if [[ "$libraries_manifest_name" != vpp-libraries.sha256 ]]; then
  echo "artifact VPP library provenance manifest is missing" >&2
  exit 2
fi
libraries_manifest="$artifact_root/$libraries_manifest_name"
if [[ ! -f "$libraries_manifest" ]]; then
  echo "artifact VPP library provenance file is missing" >&2
  exit 2
fi
expected_library_names=()
while IFS= read -r library_line; do
  if [[ ! "$library_line" =~ ^([[:xdigit:]]{64})[[:space:]][[:space:]](lib[A-Za-z0-9._+-]+)$ ]]; then
    echo "artifact VPP library provenance has an unsafe entry" >&2
    exit 2
  fi
  expected_library_names+=("${BASH_REMATCH[2]}")
  resolved_library="$(realpath -e -- "$artifact_root/lib/${BASH_REMATCH[2]}")" || exit 2
  product_require_within "$artifact_root" "$resolved_library" || exit 2
done < "$libraries_manifest"
mapfile -t actual_library_names < <(
  find "$artifact_root/lib" -mindepth 1 -maxdepth 1 \
    \( -type f -o -type l \) -name 'lib*.so*' -printf '%f\n' | sort)
if [[ "${#expected_library_names[@]}" -eq 0 ||
      "${expected_library_names[*]:-}" != "${actual_library_names[*]:-}" ]]; then
  echo "artifact VPP library set differs from its provenance manifest" >&2
  exit 2
fi
if ! (cd "$artifact_root/lib" && sha256sum -c "$libraries_manifest" >/dev/null); then
  echo "artifact VPP library hash verification failed" >&2
  exit 2
fi
rust_hash="$(awk -F= '$1 == "rust.core.sha256" { print substr($0, index($0, "=") + 1); exit }' "$manifest")"
if [[ ! "$rust_hash" =~ ^[[:xdigit:]]{64}$ ||
      "$(sha256sum "$core_bin" | awk '{print $1}')" != "$rust_hash" ]]; then
  echo "Rust Product Core hash does not match the artifact manifest" >&2
  exit 2
fi
generation="$(tr -d '[:space:]' < "$generation_file")"
if [[ ! "$generation" =~ ^[1-9][0-9]*$ ]]; then
  echo "invalid active generation marker" >&2
  exit 2
fi
export LD_LIBRARY_PATH="$artifact_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
if ! query_output="$("$core_bin" query "$socket" "$generation" 2>&1)"; then
  printf '%s\n' "$query_output" >&2
  exit 1
fi
printf '%s\n' "$query_output"

# The operational query identity check compares every reported field with the
# artifact manifest; a core hash alone cannot prove the plugin/API identity.
expect_output() {
  local key="$1"
  local expected="$2"
  local actual
  actual="$(printf '%s\n' "$query_output" | awk -F= -v key="$key" \
    '$1 == key { print substr($0, index($0, "=") + 1); exit }')"
  if [[ "$actual" != "$expected" ]]; then
    echo "VPP status identity mismatch for $key: got '$actual', expected '$expected'" >&2
    exit 1
  fi
}

artifact_id="$(manifest_value "$manifest" artifact.id)"
api_identity="$(manifest_value "$manifest" product.api.identity)"
abi_version="$(manifest_value "$manifest" product.abi.version)"
api_version="$(manifest_value "$manifest" product.api.version)"
adapter_available="$(manifest_value "$manifest" product.adapter.available)"
protection_running="$(manifest_value "$manifest" product.protection.running)"
for label in connect query; do
  expect_output "$label.code_value" 0
  expect_output "$label.abi_version" "$abi_version"
  expect_output "$label.api_version" "$api_version"
  expect_output "$label.generation" "$generation"
  expect_output "$label.core_ready" true
  expect_output "$label.adapter_available" "$adapter_available"
  expect_output "$label.protection_running" "$protection_running"
  expect_output "$label.plugin_loaded" true
  expect_output "$label.vapi_handle_live" true
  expect_output "$label.generation_live" true
  expect_output "$label.artifact_id" "$artifact_id"
  expect_output "$label.api_identity" "$api_identity"
  expect_output "$label.vpp_revision" "$expected_revision"
done
