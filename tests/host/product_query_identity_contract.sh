#!/usr/bin/env bash
set -euo pipefail

# This is an operational contract test for query-host-vpp.sh. The executable
# below is deliberately a status-output stub; it does not claim to be VPP or a
# production ABI. The test proves that the launcher compares runtime identity
# fields with the installed artifact manifest, including a negative mismatch.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
query_script="$repo_root/tools/product/query-host-vpp.sh"
suffix="$$"
artifact_root="$repo_root/build-output/product-vpp-host-query-contract-$suffix"
runtime_dir="$repo_root/build-output/product-vpp-runtime-query-contract-$suffix"
cleanup() {
  rm -rf -- "$artifact_root" "$runtime_dir"
}
trap cleanup EXIT

mkdir -p "$artifact_root/bin" "$artifact_root/lib/vpp_plugins" \
  "$artifact_root/share/vpp/api/plugins" "$runtime_dir"
printf '%s\n' 'sakamoto-product-artifact-root-v1' \
  > "$artifact_root/.sakamoto-product-artifact"
printf '%s\n' 'fixture-plugin' \
  > "$artifact_root/lib/vpp_plugins/product_core_plugin.so"
printf '%s\n' 'fixture-library' > "$artifact_root/lib/libfixture.so"

source_manifest="$repo_root/src/product/vpp/product-vpp-artifact.properties"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
artifact_id="$(awk -F= '$1 == "artifact.id" { print $2; exit }' "$source_manifest")"
api_identity="$(awk -F= '$1 == "product.api.identity" { print $2; exit }' "$source_manifest")"
abi_version="$(awk -F= '$1 == "product.abi.version" { print $2; exit }' "$source_manifest")"
api_version="$(awk -F= '$1 == "product.api.version" { print $2; exit }' "$source_manifest")"
api_crc="$(awk -F= '$1 == "product.api.crc" { print $2; exit }' "$source_manifest")"
revision="$(tr -d '[:space:]' < "$pin_file")"
printf '%s\n' "{\"vl_api_version\":\"0x$api_crc\",\"generated\":\"product_core.api\"}" \
  > "$artifact_root/share/vpp/api/plugins/product_core.api.json"
plugin_hash="$(sha256sum "$artifact_root/lib/vpp_plugins/product_core_plugin.so" | awk '{print $1}')"
generated_api_hash="$(sha256sum "$artifact_root/share/vpp/api/plugins/product_core.api.json" | awk '{print $1}')"
library_hash="$(sha256sum "$artifact_root/lib/libfixture.so" | awk '{print $1}')"

status_file="$runtime_dir/status.txt"
cat > "$status_file" <<EOF
connect.code_value=0
connect.abi_version=$abi_version
connect.api_version=$api_version
connect.generation=77
connect.core_ready=true
connect.adapter_available=false
connect.protection_running=false
connect.plugin_loaded=true
connect.vapi_handle_live=true
connect.generation_live=true
connect.artifact_id=$artifact_id
connect.api_identity=$api_identity
connect.vpp_revision=$revision
query.code_value=0
query.abi_version=$abi_version
query.api_version=$api_version
query.generation=77
query.core_ready=true
query.adapter_available=false
query.protection_running=false
query.plugin_loaded=true
query.vapi_handle_live=true
query.generation_live=true
query.artifact_id=$artifact_id
query.api_identity=$api_identity
query.vpp_revision=$revision
EOF
cat > "$artifact_root/bin/sakamoto-product-core-host" <<'EOF'
#!/usr/bin/env bash
cat "$FAKE_PRODUCT_STATUS_FILE"
EOF
chmod +x "$artifact_root/bin/sakamoto-product-core-host"
rust_hash="$(sha256sum "$artifact_root/bin/sakamoto-product-core-host" | awk '{print $1}')"
{
  cat "$source_manifest"
  echo "source.revision=$revision"
  echo "product.plugin.sha256=$plugin_hash"
  echo "generated.api.path=share/vpp/api/plugins/product_core.api.json"
  echo "generated.api.sha256=$generated_api_hash"
  echo "vpp.libraries.sha256=vpp-libraries.sha256"
  echo "rust.core.sha256=$rust_hash"
  echo "rust.core.profile=release"
  echo "rust.core.artifact=fixture-only"
} > "$artifact_root/product-vpp-artifact.properties"
printf '%s  %s\n' "$library_hash" libfixture.so > "$artifact_root/vpp-libraries.sha256"
printf '%s\n' 77 > "$runtime_dir/generation"

if python3 - "$runtime_dir/api.sock" <<'PY'
import socket
import sys

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    server.bind(sys.argv[1])
except PermissionError:
    sys.exit(77)
server.close()
PY
then
  :
else
  socket_status=$?
  if [[ "$socket_status" -eq 77 ]]; then
    echo "sakamoto product query identity contract: SKIP (AF_UNIX unavailable)"
    exit 0
  fi
  exit "$socket_status"
fi

positive_output="$(
  PRODUCT_ARTIFACT_DIR="$artifact_root" \
  PRODUCT_RUNTIME_DIR="$runtime_dir" \
  FAKE_PRODUCT_STATUS_FILE="$status_file" \
  "$query_script"
)"
printf '%s\n' "$positive_output" | grep -Fqx "query.artifact_id=$artifact_id"
printf '%s\n' "$positive_output" | grep -Fqx "query.api_identity=$api_identity"
printf '%s\n' "$positive_output" | grep -Fqx "query.vpp_revision=$revision"

bad_status="$runtime_dir/status-bad.txt"
sed 's/^query.api_identity=.*/query.api_identity=wrong-identity/' \
  "$status_file" > "$bad_status"
if PRODUCT_ARTIFACT_DIR="$artifact_root" \
  PRODUCT_RUNTIME_DIR="$runtime_dir" \
  FAKE_PRODUCT_STATUS_FILE="$bad_status" \
  "$query_script" >/dev/null 2>&1; then
  echo "query launcher accepted a mismatched API identity" >&2
  exit 1
fi

echo "sakamoto product query identity contract: PASS"
