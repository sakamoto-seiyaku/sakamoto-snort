#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
python3 - "$repo_root" <<'CHECK'
from pathlib import Path
import sys
root = Path(sys.argv[1]) / "src/product/vpp"
graph = (root / "product_packet_graph.c").read_text()
header = (root / "product_packet_graph.h").read_text()
nfq = (root / "product_root_nfqueue_adapter.c").read_text()
tun = (root / "product_vpn_tun_adapter.c").read_text()

def body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            return source[start:index + 1]
    raise AssertionError("unclosed function: " + signature)

submit = body(graph, "product_packet_graph_submit_external (")
assert "Returns 1 when native frame scheduling accepts buffer ownership" in header
assert "Completion runs later" in header
assert submit.count("return 0;") == 1
assert submit.index("return 0;") < submit.index("product_buffer_platform_metadata_t")
assert submit.index("lifecycle_obligations, 1") < submit.index("vlib_put_frame_to_node") < submit.index("return 1;")
for forbidden in ("vlib_buffer_free", "product_owner_assign", "expected_owner", "external_result", "product_packet_graph_policy_on_owner"):
    assert forbidden not in submit, forbidden
for source in (graph, header, nfq, tun):
    assert "external_completion" not in source
assert "product_packet_graph_external_result_t" not in header

origin = body(graph, "VLIB_NODE_FN (product_packet_origin_completion_node)")
assert "switch (completion.obligation.kind)" in origin
assert origin.count("vlib_buffer_free (vm, &bi, 1)") == 1
for endpoint in ("product_root_nfqueue_complete_from_graph", "product_vpn_tun_complete_from_graph"):
    assert origin.count(endpoint + " (vm, bi, &completion)") == 1
    assert origin.index(endpoint) < origin.index("vlib_buffer_free")
for forbidden in ("product_packet_parse", "product_owner_assign", "product_packet_graph_policy_on_owner"):
    assert forbidden not in origin, forbidden
for source, endpoint in ((nfq, "product_root_nfqueue_complete_from_graph"), (tun, "product_vpn_tun_complete_from_graph")):
    complete = body(source, endpoint + " (")
    assert "void *opaque" not in complete
    assert complete.index("queue_generation") < complete.index("pending->active = 0")
    assert "vlib_buffer_free" not in complete
    assert "product_packet_graph_submit_external" in source
print("native asynchronous ingress and immutable adapter completion ownership: PASS")
CHECK
