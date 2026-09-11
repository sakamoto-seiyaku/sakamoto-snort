#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-product-flow-entry.XXXXXX")"
cleanup() {
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT

header="$repo_root/src/product/vpp/product_flow_entry.h"
source="$repo_root/src/product/vpp/product_flow_entry.c"
test_source="$repo_root/tests/host/product_flow_entry_test.c"
root_cmake="$repo_root/CMakeLists.txt"
vpp_cmake="$repo_root/src/product/vpp/CMakeLists.txt"

for file in "$header" "$source" "$test_source" "$root_cmake" "$vpp_cmake"; do
  [[ -f "$file" ]] || {
    echo "S193 FlowEntry contract: missing $file" >&2
    exit 1
  }
done

# This module is a worker-local C seam, not a second runtime or a platform
# bridge.  A source-level guard keeps the ownership boundary reviewable.
for forbidden in '<vlib/' 'jni.h' 'jni/' 'pthread' 'realloc (' \
  '#include <new>' 'operator new' 'operator delete' 'conntrack' \
  'Conntrack' 'sucre-snort' 'SnortConfig' \
  'product_core.api'; do
  if grep -Fq "$forbidden" "$header" "$source" "$test_source"; then
    echo "S193 FlowEntry contract: forbidden dependency $forbidden" >&2
    exit 1
  fi
done

for token in \
  'product_flow_runtime_create' \
  'PRODUCT_FLOW_ENTRY_ADDRESS_BYTES UINT32_C (16)' \
  'PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT' \
  'PRODUCT_FLOW_ENTRY_VERDICT_DROP' \
  'PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG' \
  'PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY' \
  'product_flow_entry_observe' \
  'product_flow_entry_set_decision' \
  'product_flow_runtime_flush' \
  'product_flow_policy_identity_t' \
  'policy_generation' \
  'revision_invalidation_count' \
  'capacity_rejection_count'; do
  grep -Fq "$token" "$header" "$source"
done

python3 - "$source" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
observe_start = source.index("product_flow_entry_observe (")
observe = source[observe_start:source.index("product_flow_entry_set_decision (", observe_start)]
drop = observe.index("stage_verdict == PRODUCT_FLOW_ENTRY_VERDICT_DROP")
find = observe.index("slot = find_entry")
if drop > find:
    raise AssertionError("early DROP must precede FlowEntry lookup")
for allocation in ('malloc (', 'calloc (', 'free (', 'realloc ('):
    assert allocation not in observe, 'no packet-side allocation: ' + allocation
assert 'pool->free_head' in observe
assert 'pool->buckets' in source
assert 'PRODUCT_FLOW_ENTRY_MAX_ENTRIES' not in source
if "product_flow_entry_publish_revision" in source or "active_policy_revision" in source:
    raise AssertionError("FlowEntry must have no publisher-side epoch mutation API")
for identity in ("policy_generation == policy->generation", "policy_revision == policy->revision", "policy_snapshot_hash == policy->snapshot_hash"):
    assert identity in source, identity

PY

cc -std=c11 -Wall -Wextra -Werror -pedantic \
  -I"$repo_root/src/product/vpp" \
  "$repo_root/src/product/vpp/product_packet.c" "$source" "$test_source" -o "$fixture_root/product-flow-entry-test"

"$fixture_root/product-flow-entry-test"

grep -Fq 'sakamoto_product_flow_entry STATIC' "$root_cmake"
grep -Fq 'tests/host/product_flow_entry_test.c' "$root_cmake"
grep -Fq 'sakamoto-product-flow-entry-test' "$root_cmake"
grep -Fq 'sakamoto-product-flow-entry-contract' "$root_cmake"
grep -Fq 'product_flow_entry.c' "$vpp_cmake"

echo "sakamoto S221 owner-local FlowRuntime contract: PASS"

python3 - "$repo_root" <<'PY_OWNER'
import re,sys
from pathlib import Path
root=Path(sys.argv[1]);source=(root/'src/product/vpp/product_flow_entry.c').read_text()
assert not re.search(r'product_flow_entry_owner_for_packet|observe_on_owner|endpoint_compare|hash_bytes',source)
assert 'key_equal (&entry->key, &assignment->key)' in source
for field in ('a->kind != b->kind', 'a->ip_family != b->ip_family', 'a->protocol != b->protocol', 'a->query_class == b->query_class', 'a->transport.query.identifier == b->transport.query.identifier', 'a->transport.ports.a == b->transport.ports.a', 'a->transport.ports.b == b->transport.ports.b'):
    assert field in source, field
text=(root/'src/product/vpp/product_packet_graph.c').read_text()
flow=text.split('static void\nproduct_packet_graph_flow_observe (',1)[1].split('typedef struct',1)[0]
assert 'vlib_get_worker_index (vm->thread_index)' in flow and 'flow_pools[worker]' in flow
assert 'product_packet_graph_policy_writer_lock' not in flow and 'product_owner_assign (' not in flow
assert 'flow_pools[lease' not in flow and 'flow_pools[owner' not in flow
print('S208 current-worker mutation and no second selector audit: PASS')
PY_OWNER
