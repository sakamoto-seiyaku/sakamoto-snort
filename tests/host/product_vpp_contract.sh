#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bash "$repo_root/tests/host/s192-policy-bundle-contract.sh"
plugin_cmake="$repo_root/src/product/vpp/CMakeLists.txt"
plugin_source="$repo_root/src/product/vpp/product_core_plugin.c"
packet_source="$repo_root/src/product/vpp/product_packet.c"
packet_header="$repo_root/src/product/vpp/product_packet.h"
graph_source="$repo_root/src/product/vpp/product_packet_graph.c"
host_graph_source="$repo_root/src/product/vpp/product_packet_graph_host_evidence.c"
host_fixtures="$repo_root/src/product/vpp/product_packet_graph_host_fixtures.inc"
manifest="$repo_root/src/product/vpp/product-vpp-artifact.properties"
launcher="$repo_root/tools/product/run-host-vpp.sh"
builder="$repo_root/tools/product/build-host-artifact.sh"
residue="$repo_root/tools/product/host-residue-check.sh"
path_helpers="$repo_root/tools/product/path-helpers.sh"
identity_template="$repo_root/src/product/vpp/product_core_identity.h.in"
query="$repo_root/tools/product/query-host-vpp.sh"
evidence="$repo_root/docs/testing/SAKAMOTO_171_HOST_EVIDENCE.md"
testing_docs="$repo_root/docs/testing/README.md"

grep -q '^add_vpp_plugin(product_core$' "$plugin_cmake"
grep -Eq '^[[:space:]]+product_packet\.c$' "$plugin_cmake"
grep -q 'SAKAMOTO_PRODUCT_HOST_EVIDENCE' "$plugin_cmake"
grep -q 'product_packet_graph_host_evidence.c' "$plugin_cmake"
grep -q 'Android/default Product source closure contains Host evidence' "$plugin_cmake"
# Product builds default OFF; the retained legacy Host branch is unavailable.
grep -Fq 'host_evidence="${SAKAMOTO_PRODUCT_HOST_EVIDENCE:-OFF}"' "$builder"
grep -Fq -- '-DSAKAMOTO_PRODUCT_HOST_EVIDENCE="$host_evidence"' "$builder"
grep -Fq 'SAKAMOTO_PRODUCT_HOST_EVIDENCE must be ON or OFF' "$builder"
grep -Fq '"Build the Host-only installed Product graph evidence seam" OFF)' "$plugin_cmake"
grep -Fq 'SAKAMOTO_PRODUCT_HOST_EVIDENCE is forbidden for Android Product builds' "$plugin_cmake"
grep -Fq 'Legacy Host-only evidence is unavailable on the current VPP pin' "$plugin_cmake"
# ON must fail with guidance before stage/artifact validation or cleanup.
if rejected="$(SAKAMOTO_PRODUCT_HOST_EVIDENCE=ON VPP_HOST_STAGE_DIR= \
    PRODUCT_ARTIFACT_DIR=/not-a-product-artifact bash "$builder" 2>&1)"; then
  echo "legacy Host evidence unexpectedly accepted" >&2
  exit 1
fi
grep -Fq 'Legacy Host-only evidence is unavailable on the current VPP pin' <<<"$rejected"
grep -Fq 'SAKAMOTO_PRODUCT_HOST_EVIDENCE=OFF' <<<"$rejected"
grep -Eq '^[[:space:]]+product_core\.api$' "$plugin_cmake"
grep -q '^product.plugin.allowlist=product_core_plugin.so$' "$manifest"
grep -q '^control.transport=generated-vapi-c-blocking$' "$manifest"
grep -q '^vpp.revision=' "$manifest"
grep -q '^product.api.identity=' "$manifest"
grep -q 'source.revision' "$launcher"
grep -Fq '  path $plugin_dir' "$launcher"
grep -Fq 'exec "$vpp_bin" -c "$config"' "$launcher"
grep -q 'PRODUCT_WORKER_COUNT' "$launcher"
grep -q 'cpu { workers $worker_count }' "$launcher"
grep -q 'cli-no-pager' "$launcher"
grep -q 'poll-sleep-usec 0' "$launcher"
if grep -Fq 'exec "$vpp_bin" plugin_path' "$launcher"; then
  echo "launcher passes ignored positional plugin config alongside -c" >&2
  exit 1
fi
grep -q 'plugin default { disable }' "$launcher"
grep -q 'plugin product_core_plugin.so { enable }' "$launcher"
grep -q 'product-vpp-artifact.properties' "$launcher"
grep -q 'vpp.binary.sha256' "$launcher"
grep -q 'product.plugin.sha256' "$launcher"
grep -q 'generated.api.sha256' "$launcher"
grep -q 'rust.core.sha256' "$launcher"
grep -q 'readlink -f "/proc/' "$residue"
grep -q 'owner.pid' "$residue"
grep -q 'api.sock' "$residue"
if grep -q 'pgrep' "$residue"; then
  echo "residue checker must not scan unrelated processes" >&2
  exit 1
fi
grep -q 'stopped_generation=' "$repo_root/tools/product/stop-host-vpp.sh"
grep -q 'rust.core.sha256' "$repo_root/tools/product/query-host-vpp.sh"
grep -q 'product.api.identity' "$query"
grep -q 'artifact_id' "$query"
grep -q 'vpp_revision' "$query"
grep -q 'generation_live' "$query"
grep -q 'query.*identity' "$query"
grep -q 'vl_api_version' "$query"
grep -q 'VPP_HOST_STAGE_DIR is required' "$builder"
grep -q 'sakamoto-product-vpp-stage-v1' "$builder"
grep -q 'vpp.core.patch.sha256' "$builder"
grep -q 'vpp.runtime.closure.sha256' "$builder"
grep -q 'git -C "${VPP_SOURCE_DIR}" rev-parse HEAD' "$plugin_cmake"
grep -q 'git -C "${VPP_SOURCE_DIR}" status --porcelain' "$plugin_cmake"
grep -q 'SAKAMOTO_PRODUCT_VAPI_REQUIRED=1' "$builder"
grep -q 'vapi_cpp_gen.py' "$builder"
grep -q '^vpp_vapi_cpp_gen="$(product_canonical_existing' "$builder"
grep -q 'product_require_within "$vpp_source" "$vpp_vapi_cpp_gen"' "$builder"
grep -q -- '-DVPP_VAPI_CPP_GEN="$vpp_vapi_cpp_gen"' "$builder"
grep -q 'generated_api_install' "$builder"
grep -q 'vpp.libraries.sha256' "$builder"
grep -q 'vl_api_version' "$builder"
grep -q 'artifact_marker' "$builder"
grep -q 'realpath -e' "$builder"
grep -q 'VLIB_PLUGIN_REGISTER' "$plugin_source"
grep -q 'VLIB_INIT_FUNCTION' "$plugin_source"
test -f "$packet_source"
test -f "$packet_header"
test -f "$graph_source"
test -f "$host_graph_source"
test -f "$host_fixtures"
# Fixtures retain the original conditional and translation-unit visibility.
# They must not become an unconditional include or a separate compiled source.
python3 - "$graph_source" "$host_graph_source" "$host_fixtures" "$plugin_cmake" <<'PY'
from pathlib import Path
import sys

graph, wrapper, fixtures, cmake = (Path(p).read_text() for p in sys.argv[1:])
include = '#include "product_packet_graph_host_fixtures.inc"'
assert graph.count(include) == 1, 'Host fixture include must occur exactly once'
assert '#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE\n' + include + '\n#endif' in graph
assert '#define SAKAMOTO_PRODUCT_HOST_EVIDENCE 1' in wrapper
assert '#include "product_packet_graph.c"' in wrapper
assert 'product_packet_graph_host_fixtures.inc' not in cmake
for definition in ('product_ipv4_fixture (', 'product_packet_graph_policy_fixture_cli (',
                   'product_packet_graph_disable_cli ('):
    assert '\n' + definition in fixtures, 'missing Host definition: ' + definition
    assert '\n' + definition not in graph, 'Host definition still in main graph: ' + definition
PY
if grep -Eq 's174-valid-dual-stack-v1|product packet-graph run-fixture' \
    "$graph_source"; then
  echo "Android-default Product graph source contains the Host evidence seam" >&2
  exit 1
fi
grep -q 's174-valid-dual-stack-v1' "$host_graph_source"
grep -q 'run-fixture' "$host_graph_source"
grep -q 'product_packet_admit' "$packet_source"
grep -q 'product_packet_admit' "$packet_header"
grep -q 'sakamoto_product_host_fixture_abi' "$repo_root/CMakeLists.txt"
grep -q 'sakamoto-product-host-fixture-abi-test' "$repo_root/CMakeLists.txt"
grep -q 'sakamoto-s174-product-packet-kernel-contract' \
  "$repo_root/CMakeLists.txt"
grep -q 'sakamoto_product_host_fixture_abi' "$repo_root/crates/product-core/build.rs"
grep -q 'sakamoto_product_status.h' "$repo_root/src/product/native/sakamoto_product_host_fixture_abi.c"
grep -q 'sakamoto_product_status.h' "$repo_root/src/product/native/sakamoto_product_vapi.c"
grep -q 'SAKAMOTO_PRODUCT_VPP_REVISION' "$plugin_cmake"
grep -q 'SAKAMOTO_PRODUCT_VPP_REVISION' "$plugin_source"
grep -q 'clib_memset (rmp->artifact_id' "$plugin_source"
grep -q 'vl_api_product_core_status_reply_t \*rmp' "$plugin_source"
grep -q 'reply == NULL' "$repo_root/src/product/native/sakamoto_product_vapi.c"
grep -q 'SAKAMOTO_PRODUCT_QUERY_FAILED' "$repo_root/src/product/native/sakamoto_product_vapi.c"
grep -q 'bool callback_called' "$repo_root/src/product/native/sakamoto_product_vapi.c"
grep -q 'call->callback_called = true' "$repo_root/src/product/native/sakamoto_product_vapi.c"
grep -q '!call.callback_called' "$repo_root/src/product/native/sakamoto_product_vapi.c"
grep -q 'sakamoto-product-host-query-identity-contract' "$repo_root/CMakeLists.txt"
grep -q 'sakamoto-product-host-residue-contract' "$repo_root/CMakeLists.txt"
grep -q 'sakamoto-product-vapi-callback-contract' "$repo_root/CMakeLists.txt"
grep -q 'sakamoto-product-host-vapi-build-contract' "$repo_root/CMakeLists.txt"
grep -q 'sakamoto-product-plugin-init-contract' "$repo_root/CMakeLists.txt"
grep -q 'sakamoto-product-path-contract' "$repo_root/CMakeLists.txt"
grep -q 'mismatched API identity' "$repo_root/tests/host/product_query_identity_contract.sh"
grep -q 'generation_marker=present' "$repo_root/tests/host/product_residue_contract.sh"
grep -q 'callback was not invoked' "$repo_root/tests/host/product_vapi_callback_contract.sh"
grep -q 'message-id setup failure was not fail-closed' \
  "$repo_root/tests/host/product_plugin_init_contract.sh"
grep -q 'one_connection_is_reused_for_two_serialized_queries' \
  "$repo_root/crates/product-core/tests/session_lifecycle.rs"
if [[ "$(grep -c 'assert_eq!(request(&mut stream), (OP_QUERY' \
        "$repo_root/crates/product-core/tests/session_lifecycle.rs")" -lt 2 ]]; then
  echo "lifecycle test must observe two query requests" >&2
  exit 1
fi
grep -q 'configure_file' "$plugin_cmake"
grep -q 'product_core_identity.h.in' "$plugin_cmake"
grep -q 'product_core_identity.h' "$plugin_source"
grep -q 'SAKAMOTO_PRODUCT_ARTIFACT_ID' "$plugin_source"
grep -q 'SAKAMOTO_PRODUCT_API_IDENTITY' "$plugin_source"
if grep -q 'product_core.api/1.0.0@1b103f1d' "$plugin_source"; then
  echo "plugin identity must come from the artifact manifest" >&2
  exit 1
fi
test -f "$identity_template"
# The testing overview may describe either the Host-only supporting seam or
# the combined installed-product acceptance path. The detailed evidence file
# below remains the stable assertion for the pre-adapter/Flow Stack boundary.
grep -Eq 'Host-only pre-adapter|Product Spine acceptance' "$testing_docs"
grep -Eq 'ADR-0007 Flow Stack|installed through' "$testing_docs"
grep -q 'pre-adapter' "$evidence"
grep -q 'does not prove.*Flow Stack' "$evidence"
grep -q 'path-helpers.sh' "$launcher"
grep -q 'canonical' "$path_helpers"
grep -q 'realpath -m' "$path_helpers"
grep -q 'product_prepare_build_output' "$launcher"
grep -q 'product_prepare_build_output' "$path_helpers"
grep -q 'product_resolve_vpp_library_dir' "$builder"
grep -q '^product_resolve_vpp_library_dir()' "$path_helpers"
grep -q 'product_validate_host_vpp_install_prefix' "$builder"
grep -q '^product_validate_host_vpp_install_prefix()' "$path_helpers"

for script in \
  "$repo_root/tools/product/build-host-artifact.sh" \
  "$repo_root/tools/product/run-host-vpp.sh" \
  "$repo_root/tools/product/query-host-vpp.sh" \
  "$repo_root/tools/product/stop-host-vpp.sh" \
  "$repo_root/tools/product/host-residue-check.sh" \
  "$path_helpers"; do
  bash -n "$script"
done
for test_script in \
  "$repo_root/tests/host/product_query_identity_contract.sh" \
  "$repo_root/tests/host/product_residue_contract.sh" \
  "$repo_root/tests/host/product_vapi_callback_contract.sh" \
  "$repo_root/tests/host/product_host_vapi_build_contract.sh" \
  "$repo_root/tests/host/product_plugin_init_contract.sh" \
  "$repo_root/tests/host/product_path_contract.sh"; do
  bash -n "$test_script"
done

echo "sakamoto product VPP build/allowlist contract: PASS"
