#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
graph="$repo_root/src/product/vpp/product_packet_graph.c"
header="$repo_root/src/product/vpp/product_packet_graph.h"
root_adapter="$repo_root/src/product/vpp/product_root_nfqueue_adapter.c"
vpn_adapter="$repo_root/src/product/vpp/product_vpn_udp4_adapter.c"

python3 - "$graph" "$header" "$root_adapter" "$vpn_adapter" <<'PY'
from pathlib import Path
import sys

graph = Path(sys.argv[1]).read_text(encoding="utf-8")
header = Path(sys.argv[2]).read_text(encoding="utf-8")
root = Path(sys.argv[3]).read_text(encoding="utf-8")
vpn = Path(sys.argv[4]).read_text(encoding="utf-8")


def body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unclosed function: {signature}")


submit = body(graph, "product_packet_graph_submit_external (")

if "Returns 1 only after the graph has consumed and returned the buffer" not in header:
    raise AssertionError("external submit ownership contract is undocumented")

adopt = submit.find("buffer = vlib_get_buffer")
release = submit.find("vlib_buffer_free (")
ownership_return = submit.rfind("return 1;")
if adopt < 0 or release < adopt or ownership_return < release:
    raise AssertionError("external submit does not retain ownership through one buffer return")

rejects = []
offset = 0
while True:
    index = submit.find("return 0;", offset)
    if index < 0:
        break
    rejects.append(index)
    offset = index + 1
if len(rejects) != 1 or rejects[0] > adopt:
    raise AssertionError("external submit rejects after adopting the caller buffer")

if "return completed;" in submit:
    raise AssertionError("completion state is still exposed as buffer ownership")

if "if (completed && graph->external_completion" in submit:
    raise AssertionError("an adopted internal-failure path can skip Adapter completion")
for token in (
        "if (!completed)",
        "PRODUCT_PACKET_INTENT_PASS_ADAPTER",
        "lease.settled = 1"):
    if token not in submit:
        raise AssertionError(f"adopted internal failure is not terminalized: {token}")

callback = submit.find("graph->external_completion (")
if callback < 0 or callback > release:
    raise AssertionError("external callback must observe the live buffer before release")

for source, name in ((root, "Root"), (vpn, "VPN")):
    if "product_packet_graph_submit_external" not in source:
        raise AssertionError(f"{name} adapter does not use shared external graph ingress")

print("external graph ownership contract: PASS")
PY
