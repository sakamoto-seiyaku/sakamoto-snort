#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d /tmp/sakamoto-s207-owner.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
cc -std=c11 -Wall -Wextra -Werror -pedantic \
  -I"$repo_root/src/product/vpp" \
  "$repo_root/src/product/vpp/product_packet.c" \
  "$repo_root/tests/host/s207_owner_assignment_test.c" \
  -o "$work_dir/owner-test"
"$work_dir/owner-test"

python3 - "$repo_root" <<'PY_AUDIT'
import re, sys
from pathlib import Path
root=Path(sys.argv[1])
for directory in ('src/product','crates/product-core','app/android-runtime/src/main'):
    for p in (root/directory).rglob('*'):
        if p.is_file() and p.suffix in ('.c','.h','.api','.rs','.java'):
            text=p.read_text()
            assert not re.search(r'flow_domain|FLOW_DOMAIN|FlowDomain',text),p
packet=(root/'src/product/vpp/product_packet.c').read_text()
assert len(re.findall(r'^product_owner_assign \(',packet,re.M))==1
admit=packet[packet.index('product_packet_admit ('):packet.index('product_packet_owner_guard (')]
assert admit.count('product_owner_assign (')==1
restore=(root/'src/product/vpp/product_packet_graph.c').read_text().split('product_lease_from_metadata (',1)[1].split('invalid_span:',1)[0]
assert not re.search(r'\b(?:product_owner_assign|endpoint_compare|hash_bytes|memcmp)\s*\(',restore)
print('S207 single assignment interface and removed-domain audit: PASS')
PY_AUDIT
