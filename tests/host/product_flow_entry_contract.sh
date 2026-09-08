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
for forbidden in '<vlib/' 'jni.h' 'jni/' 'pthread' 'malloc' 'calloc' 'realloc' \
  'free (' '#include <new>' 'operator new' 'operator delete' 'conntrack' \
  'Conntrack' 'sucre-snort' 'SnortConfig' \
  'product_core.api'; do
  if grep -Fq "$forbidden" "$header" "$source" "$test_source"; then
    echo "S193 FlowEntry contract: forbidden dependency $forbidden" >&2
    exit 1
  fi
done

for token in \
  'PRODUCT_FLOW_ENTRY_MAX_ENTRIES UINT32_C (64)' \
  'PRODUCT_FLOW_ENTRY_ADDRESS_BYTES UINT32_C (16)' \
  'PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT' \
  'PRODUCT_FLOW_ENTRY_VERDICT_DROP' \
  'PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG' \
  'PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY' \
  'product_flow_entry_publish_revision' \
  'product_flow_entry_observe' \
  'product_flow_entry_set_decision' \
  'product_flow_entry_pool_flush' \
  'active_policy_revision' \
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
find = observe.index("entry = find_entry")
if drop > find:
    raise AssertionError("early DROP must precede FlowEntry lookup")
publish_start = source.index("product_flow_entry_publish_revision (")
publish = source[publish_start:source.index("product_flow_entry_observe (", publish_start)]
if "for (" in publish or "entries[" in publish:
    raise AssertionError("revision publication must not scan or rewrite entries")
if "policy_revision < pool->active_policy_revision" not in publish:
    raise AssertionError("revision publication must reject non-successor revisions")
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

echo "sakamoto S208 owner-local FlowEntry contract: PASS"

python3 - "$repo_root" <<'PY_OWNER'
import re,sys
from pathlib import Path
root=Path(sys.argv[1]);source=(root/'src/product/vpp/product_flow_entry.c').read_text()
assert not re.search(r'product_flow_entry_owner_for_packet|observe_on_owner|endpoint_compare|hash_bytes',source)
assert 'memcmp (&entry->key, &assignment->key, sizeof (entry->key))' in source
text=(root/'src/product/vpp/product_packet_graph.c').read_text()
flow=text.split('static void\nproduct_packet_graph_flow_observe (',1)[1].split('typedef struct',1)[0]
assert 'vlib_get_worker_index (vm->thread_index)' in flow and 'flow_pools[worker]' in flow
assert 'product_packet_graph_policy_publish_lock' not in flow and 'product_owner_assign (' not in flow
assert 'flow_pools[lease' not in flow and 'flow_pools[owner' not in flow
print('S208 current-worker mutation and no second selector audit: PASS')
PY_OWNER
