#!/usr/bin/env bash
set -euo pipefail

# Launch only the real pinned VPP binary and the single product plugin. The
# caller supplies the already verified artifact produced by
# build-host-artifact.sh; this script never substitutes a fixture runtime.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_root/tools/product/path-helpers.sh"
product_prepare_build_output || exit 2
artifact_root="$(product_validate_artifact_root \
  "${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host}")" || exit 2
runtime_dir="$(product_validate_runtime_root \
  "${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime}")" || exit 2
vpp_bin="$artifact_root/bin/vpp"
plugin_dir="$artifact_root/lib/vpp_plugins"
core_bin="$artifact_root/bin/sakamoto-product-core-host"
generation="${PRODUCT_GENERATION:-1}"
manifest="$artifact_root/product-vpp-artifact.properties"
artifact_marker="$artifact_root/.sakamoto-product-artifact"
source_manifest="$repo_root/src/product/vpp/product-vpp-artifact.properties"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"

if [[ -n "${VPP_BIN:-}" &&
      "$(product_canonical_for_write "$VPP_BIN")" != "$vpp_bin" ]]; then
  echo "VPP_BIN must resolve to the executable inside the verified artifact" >&2
  exit 2
fi
if [[ -n "${PRODUCT_PLUGIN_DIR:-}" &&
      "$(product_canonical_for_write "$PRODUCT_PLUGIN_DIR")" != "$plugin_dir" ]]; then
  echo "PRODUCT_PLUGIN_DIR must resolve to the verified artifact plugin directory" >&2
  exit 2
fi

manifest_value() {
  local manifest_file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, index($0, "=") + 1); exit }' \
    "$manifest_file"
}

if [[ ! -f "$manifest" || -L "$manifest" || ! -f "$source_manifest" ||
      ! -f "$pin_file" ]]; then
  echo "verified Product VPP artifact manifest is missing" >&2
  exit 2
fi
if [[ ! -f "$artifact_marker" || -L "$artifact_marker" ||
      "$(tr -d '\r\n' < "$artifact_marker")" != \
        "sakamoto-product-artifact-root-v1" ]]; then
  echo "artifact root is not marked as a validated product build" >&2
  exit 2
fi
expected_revision="$(tr -d '[:space:]' < "$pin_file")"
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
if [[ "$(manifest_value "$manifest" vpp.revision)" != "$expected_revision" ]]; then
  echo "artifact VPP revision does not match the pinned revision" >&2
  exit 2
fi
if [[ "$(manifest_value "$manifest" source.revision)" != "$expected_revision" ]]; then
  echo "artifact source revision provenance is missing or mismatched" >&2
  exit 2
fi
if [[ "$(manifest_value "$manifest" product.plugin)" != product_core_plugin.so ||
      "$(manifest_value "$manifest" product.plugin.allowlist)" != product_core_plugin.so ]]; then
  echo "artifact plugin identity is not the product_core_plugin allowlist" >&2
  exit 2
fi

if [[ -z "$vpp_bin" || -L "$vpp_bin" || ! -x "$vpp_bin" ]]; then
  echo "VPP_BIN must name the verified pinned official VPP executable" >&2
  exit 2
fi
if [[ -L "$core_bin" || ! -x "$core_bin" ]]; then
  echo "artifact is missing the Rust Product Core Host binary" >&2
  exit 2
fi
if [[ -L "$plugin_dir" || ! -d "$plugin_dir" ||
      -L "$plugin_dir/product_core_plugin.so" ||
      ! -f "$plugin_dir/product_core_plugin.so" ]]; then
  echo "product plugin directory is missing product_core_plugin.so" >&2
  exit 2
fi
mapfile -t plugin_entries < <(find "$plugin_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [[ "${#plugin_entries[@]}" -ne 1 ||
      "${plugin_entries[0]:-}" != product_core_plugin.so ||
      ! -f "$plugin_dir/product_core_plugin.so" ]]; then
  echo "plugin allowlist violation; expected exactly product_core_plugin.so" >&2
  exit 2
fi
vpp_hash="$(manifest_value "$manifest" vpp.binary.sha256)"
plugin_hash="$(manifest_value "$manifest" product.plugin.sha256)"
if [[ ! "$vpp_hash" =~ ^[[:xdigit:]]{64}$ ||
      "$(sha256sum "$vpp_bin" | awk '{print $1}')" != "$vpp_hash" ]]; then
  echo "VPP executable hash does not match the artifact manifest" >&2
  exit 2
fi
if [[ ! "$plugin_hash" =~ ^[[:xdigit:]]{64}$ ||
      "$(sha256sum "$plugin_dir/product_core_plugin.so" | awk '{print $1}')" != "$plugin_hash" ]]; then
  echo "product plugin hash does not match the artifact manifest" >&2
  exit 2
fi
rust_hash="$(manifest_value "$manifest" rust.core.sha256)"
if [[ ! "$rust_hash" =~ ^[[:xdigit:]]{64}$ ||
      "$(sha256sum "$core_bin" | awk '{print $1}')" != "$rust_hash" ]]; then
  echo "Rust Product Core hash does not match the artifact manifest" >&2
  exit 2
fi
generated_api="$artifact_root/share/vpp/api/plugins/product_core.api.json"
generated_api_hash="$(manifest_value "$manifest" generated.api.sha256)"
if [[ ! -f "$generated_api" || -L "$generated_api" ||
      ! "$generated_api_hash" =~ ^[[:xdigit:]]{64}$ ||
      "$(sha256sum "$generated_api" | awk '{print $1}')" != "$generated_api_hash" ]]; then
  echo "generated product API hash does not match the artifact manifest" >&2
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
if [[ "${expected_library_names[*]:-}" != "${actual_library_names[*]:-}" ||
      "${#expected_library_names[@]}" -eq 0 ]]; then
  echo "artifact VPP library set differs from its provenance manifest" >&2
  exit 2
fi
if ! (cd "$artifact_root/lib" && sha256sum -c "$libraries_manifest" >/dev/null); then
  echo "artifact VPP library hash verification failed" >&2
  exit 2
fi
if [[ ! "$generation" =~ ^[1-9][0-9]*$ ]]; then
  echo "PRODUCT_GENERATION must be a positive decimal integer" >&2
  exit 2
fi

mkdir -p "$runtime_dir"
if find "$runtime_dir" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "runtime directory is not empty; clean residue before starting a new generation" >&2
  exit 2
fi
config="$(product_validate_owned_child "$runtime_dir" startup.conf)" || exit 2
api_socket="$(product_validate_owned_child "$runtime_dir" api.sock)" || exit 2
cli_socket="$(product_validate_owned_child "$runtime_dir" cli.sock)" || exit 2
owner_pid="$(product_validate_owned_child "$runtime_dir" owner.pid)" || exit 2
generation_marker="$(product_validate_owned_child "$runtime_dir" generation)" || exit 2
printf '%s\n' "$$" > "$owner_pid"
printf '%s\n' "$generation" > "$generation_marker"
cat > "$config" <<EOF
unix {
  nodaemon
  runtime-dir $runtime_dir
  cli-listen $cli_socket
}
socksvr {
  socket-name $api_socket
}
plugins {
  plugin default { disable }
  plugin product_core_plugin.so { enable }
}
EOF

export SAKAMOTO_PRODUCT_GENERATION="$generation"
export LD_LIBRARY_PATH="$artifact_root/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$vpp_bin" plugin_path "$plugin_dir" -c "$config"
