#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-174 public-seam contract for the real pinned Product VPP Graph.
# This runner never substitutes a fixture runtime: the fixture ID is only a
# coarse command instructing the installed product plugin to inject known L3
# vectors into its normal graph.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${PRODUCT_ARTIFACT_DIR:-$repo_root/build-output/product-vpp-host}"
runtime_dir="${PRODUCT_RUNTIME_DIR:-$repo_root/build-output/product-vpp-runtime-s174-$$}"
evidence_dir="${SAKAMOTO_S174_EVIDENCE_DIR:-/tmp/sakamoto-s174-product-vpp-graph-$$}"
launcher="$repo_root/tools/product/run-host-vpp.sh"
query="$repo_root/tools/product/query-host-vpp.sh"
stopper="$repo_root/tools/product/stop-host-vpp.sh"
residue="$repo_root/tools/product/host-residue-check.sh"
fixture_id=s174-valid-dual-stack-v1
generation=174
vpp_pid=
graph_source="$repo_root/src/product/vpp/product_packet_graph.c"
host_graph_source="$repo_root/src/product/vpp/product_packet_graph_host_evidence.c"

mkdir -p -- "$evidence_dir"

fail() {
  echo "SAKAMOTO-174 Product VPP Graph contract: FAIL: $*" >&2
  exit 1
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "$vpp_pid" ]] && kill -0 "$vpp_pid" 2>/dev/null; then
    PRODUCT_ARTIFACT_DIR="$artifact_root" \
      PRODUCT_RUNTIME_DIR="$runtime_dir" \
      "$stopper" >"$evidence_dir/stop.trace" 2>&1
    wait "$vpp_pid" 2>/dev/null
  fi
  PRODUCT_ARTIFACT_DIR="$artifact_root" \
    PRODUCT_RUNTIME_DIR="$runtime_dir" \
    "$residue" >"$evidence_dir/final-residue.trace" 2>&1
  local residue_status=$?
  set -e
  if [[ "$status" -eq 0 && "$residue_status" -ne 0 ]]; then
    cat "$evidence_dir/final-residue.trace" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

[[ -x "$artifact_root/bin/vpp" &&
   -x "$artifact_root/bin/sakamoto-product-core-host" &&
   -f "$artifact_root/lib/vpp_plugins/product_core_plugin.so" &&
   -f "$artifact_root/share/vpp/api/plugins/product_core.api.json" &&
   -f "$artifact_root/product-vpp-artifact.properties" ]] ||
  fail "missing formal Host artifact; run tools/product/build-host-artifact.sh first"

if grep -q 'vlib_thread_wakeup' "$graph_source" "$host_graph_source"; then
  fail "Product graph must rely on stock VPP scheduling, not an explicit wake path"
fi

if grep -Eq 'graph\.(pre_guard_private_mutations|local_enqueues|packet_copies|packet_clones|packet_reserializations|double_returns)=' \
    "$graph_source" "$host_graph_source"; then
  fail "zero-only graph counters are not admissible evidence"
fi

# The dynamic evidence below proves one unchanged live buffer identity. Keep a
# separate source-level guard against adding a hidden second packet allocation,
# clone, payload append, per-packet heap, or serializer inside the ordinary
# admit -> owner guard -> policy -> terminal node region.
ordinary_nodes="$(awk '
    /^VLIB_NODE_FN \(product_packet_admit_node\)/ { in_nodes = 1 }
    /^VLIB_REGISTER_NODE \(product_packet_terminal_node\)/ { after_terminal = 1 }
    after_terminal && /^};/ { in_nodes = 0 }
    in_nodes && /^#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE/ {
      in_host_evidence = 1
      next
    }
    in_nodes && in_host_evidence && /^#endif/ {
      in_host_evidence = 0
      next
    }
    in_nodes && !in_host_evidence { print }
  ' "$graph_source")"

# Close the helper-function bypass as well: after Host evidence is removed,
# the Android graph may expose live packet bytes only at the two Product
# ingress seams: the original VLIB admit parser and the S176 external Root
# NFQUEUE submitter. Its ten memcpy operations are the fixed-width opaque2
# metadata codec; raw packet memcpy/memmove and byte-index side stores have no
# place in this translation unit.
android_graph="$(awk '
    /^#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE/ {
      host_depth = 1
      next
    }
    host_depth && /^#if/ {
      host_depth++
      next
    }
    host_depth && /^#endif/ {
      host_depth--
      next
    }
    !host_depth { print }
  ' "$graph_source")"
# S192's typed L4 projection adds four fixed-width address copies from the
# already parsed PacketFacts into the matcher view.  They are not packet
# side-copies; retain an exact count so new copies still fail closed.
if [[ "$(printf '%s\n' "$android_graph" | grep -c 'vlib_buffer_get_current')" -ne 2 ]] ||
   [[ "$(printf '%s\n' "$android_graph" | grep -c 'clib_memcpy_fast')" -ne 14 ]] ||
   printf '%s\n' "$android_graph" | grep -Eq \
     '(^|[^[:alnum:]_])(memcpy|memmove)[[:space:]]*\(|(buffer|packet)->(data|opaque)[^;]*\\[[^]]+\\][[:space:]]*='; then
  fail "Android Product graph source closure contains a packet side-copy seam"
fi
if printf '%s\n' "$ordinary_nodes" | grep -Eq \
    'vlib_buffer_(copy|clone|add_data)|clib_mem_(alloc|realloc)|(^|[^[:alnum:]_])(malloc|calloc|realloc|pool_get|pool_get_zero|hash_create|mhash_init|serialize_)[[:space:]]*\('; then
  fail "ordinary Product packet nodes allocate, clone, copy, or reserialize packet state"
fi
if [[ "$(printf '%s\n' "$ordinary_nodes" | grep -c 'vlib_buffer_get_current')" -ne 1 ]] ||
   printf '%s\n' "$ordinary_nodes" | grep -Eq \
     '(memcpy|memmove|clib_memcpy|copy|clone|serialize|side[_-]?copy)'; then
  fail "ordinary Product nodes expose packet bytes outside the one parser ingress"
fi

# Mutation-sensitivity check: the structural rule must reject both a normal
# memcpy side copy and a custom byte loop, not merely a short API denylist.
for mutation in \
  'memcpy(side_copy, vlib_buffer_get_current(buffer), buffer->current_length);' \
  'for (i = 0; i < packet_length; i++) shadow[i] = ingress.data[i];'; do
  mutated_graph="$(printf '%s\n%s\n' "$android_graph" "$mutation")"
  if [[ "$(printf '%s\n' "$mutated_graph" | grep -c 'vlib_buffer_get_current')" -eq 1 ]] &&
     [[ "$(printf '%s\n' "$mutated_graph" | grep -c 'clib_memcpy_fast')" -eq 10 ]] &&
     ! printf '%s\n' "$mutated_graph" | grep -Eq \
       '(^|[^[:alnum:]_])(memcpy|memmove)[[:space:]]*\(|[[:alnum:]_>.-]+\[[^]]+\][[:space:]]*='; then
    fail "ordinary-node structural guard is insensitive to a packet side copy"
  fi
done

PRODUCT_ARTIFACT_DIR="$artifact_root" \
  PRODUCT_RUNTIME_DIR="$runtime_dir" \
  "$residue" >"$evidence_dir/initial-residue.trace"

PRODUCT_ARTIFACT_DIR="$artifact_root" \
PRODUCT_RUNTIME_DIR="$runtime_dir" \
PRODUCT_GENERATION="$generation" \
PRODUCT_WORKER_COUNT=2 \
  "$launcher" >"$evidence_dir/vpp.trace" 2>&1 &
vpp_pid=$!

for _ in {1..200}; do
  [[ -S "$runtime_dir/api.sock" && -S "$runtime_dir/cli.sock" ]] && break
  if ! kill -0 "$vpp_pid" 2>/dev/null; then
    cat "$evidence_dir/vpp.trace" >&2
    fail "pinned Product VPP exited before its control sockets became ready"
  fi
  sleep 0.05
done
[[ -S "$runtime_dir/api.sock" && -S "$runtime_dir/cli.sock" ]] ||
  fail "pinned Product VPP control sockets did not become ready"

PRODUCT_ARTIFACT_DIR="$artifact_root" \
  PRODUCT_RUNTIME_DIR="$runtime_dir" \
  "$query" | tee "$evidence_dir/artifact-api-identity.trace"

# Speak directly to the CLI socket owned by this exact artifact generation.
# No host-installed vppctl (which may belong to another revision) is used.
cli() {
  local command="$1"
  python3 - "$runtime_dir/cli.sock" "$command" <<'PY'
import re
import socket
import sys

path, command = sys.argv[1:]
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
# The Product graph itself has a bounded five-second completion timeout.
# Leave enough room to receive that fail-closed diagnostic instead of
# reporting a less useful client-side timeout first.
client.settimeout(10.0)
client.connect(path)

def receive_prompt():
    data = bytearray()
    while b"vpp# " not in data:
        chunk = client.recv(65536)
        if not chunk:
            raise RuntimeError("Product VPP CLI closed before prompt")
        data.extend(chunk)
        if len(data) > 4 * 1024 * 1024:
            raise RuntimeError("Product VPP CLI response exceeded 4 MiB")
    return bytes(data)

receive_prompt()
client.sendall(command.encode("utf-8") + b"\n")
response = receive_prompt()
client.close()

text = response.decode("utf-8", "replace")
text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
text = text.replace("\r", "")
if "vpp# " in text:
    text = text.rsplit("vpp# ", 1)[0]
lines = text.splitlines()
if lines and lines[0].strip() == command:
    lines.pop(0)
print("\n".join(lines).strip())
PY
}

require_line() {
  local output="$1"
  local expected="$2"
  printf '%s\n' "$output" | grep -Fqx -- "$expected" ||
    fail "missing graph evidence: $expected"
}

field() {
  local output="$1"
  local name="$2"
  printf '%s\n' "$output" |
    awk -F= -v name="$name" '$1 == name { print substr($0, index($0, "=") + 1); exit }'
}

require_pair_identity() {
  local output="$1"
  local pair="$2"
  local forward="vector.$pair-forward"
  local reverse="vector.$pair-reverse"
  local forward_key reverse_key forward_owner reverse_owner
  local forward_arrival reverse_arrival forward_placement reverse_placement
  local forward_enqueues reverse_enqueues
  local forward_admit forward_guard reverse_admit reverse_guard
  forward_key="$(field "$output" "$forward.canonical_key")"
  reverse_key="$(field "$output" "$reverse.canonical_key")"
  forward_owner="$(field "$output" "$forward.expected_owner")"
  reverse_owner="$(field "$output" "$reverse.expected_owner")"
  [[ -n "$forward_key" && "$forward_key" == "$reverse_key" ]] ||
    fail "$pair forward/reverse canonical keys differ"
  [[ "$forward_owner" =~ ^[01]$ && "$forward_owner" == "$reverse_owner" ]] ||
    fail "$pair forward/reverse owners differ or are outside the fixed layout"
  forward_arrival="$(field "$output" "$forward.arrival_worker")"
  reverse_arrival="$(field "$output" "$reverse.arrival_worker")"
  [[ ( "$forward_arrival" == 0 && "$reverse_arrival" == 1 ) ||
     ( "$forward_arrival" == 1 && "$reverse_arrival" == 0 ) ]] ||
    fail "$pair fixture did not explicitly use arrival workers 0 and 1"
  forward_placement="$(field "$output" "$forward.placement")"
  reverse_placement="$(field "$output" "$reverse.placement")"
  forward_enqueues="$(field "$output" "$forward.primary_enqueues")"
  reverse_enqueues="$(field "$output" "$reverse.primary_enqueues")"
  [[ ( "$forward_placement" == local && "$forward_enqueues" == 0 &&
       "$reverse_placement" == remote && "$reverse_enqueues" == 1 ) ||
     ( "$forward_placement" == remote && "$forward_enqueues" == 1 &&
       "$reverse_placement" == local && "$reverse_enqueues" == 0 ) ]] ||
    fail "$pair must contain one local/zero-enqueue and one remote/one-enqueue path"
  forward_admit="$(field "$output" "$forward.actual_admit_thread")"
  forward_guard="$(field "$output" "$forward.actual_guard_thread")"
  reverse_admit="$(field "$output" "$reverse.actual_admit_thread")"
  reverse_guard="$(field "$output" "$reverse.actual_guard_thread")"
  [[ "$forward_admit" == "$((forward_arrival + 1))" &&
     "$reverse_admit" == "$((reverse_arrival + 1))" ]] ||
    fail "$pair was not admitted on its real arrival worker"
  [[ "$forward_guard" == "$((forward_owner + 1))" &&
     "$reverse_guard" == "$((reverse_owner + 1))" ]] ||
    fail "$pair owner guard did not run on the selected owner worker"
  if [[ "$forward_placement" == local ]]; then
    [[ "$forward_admit" == "$forward_guard" &&
       "$reverse_admit" != "$reverse_guard" ]] ||
      fail "$pair local/remote worker transitions are not real"
  else
    [[ "$forward_admit" != "$forward_guard" &&
       "$reverse_admit" == "$reverse_guard" ]] ||
      fail "$pair remote/local worker transitions are not real"
  fi
}

require_vector() {
  local output="$1"
  local vector="$2"
  local family="$3"
  local protocol="$4"
  local obligation="$5"
  local source_address="$6"
  local destination_address="$7"
  local source_port="$8"
  local destination_port="$9"
  shift 9
  local l3_header_length="$1"
  local l4_header_length="$2"
  local packet_length="$3"
  local prefix="vector.$vector"
  require_line "$output" "$prefix.family=$family"
  require_line "$output" "$prefix.protocol=$protocol"
  require_line "$output" "$prefix.l3_status=complete"
  require_line "$output" "$prefix.l4_status=complete"
  require_line "$output" "$prefix.terminal_intents=1"
  require_line "$output" "$prefix.terminal_intent=pass-adapter"
  require_line "$output" "$prefix.ledger_settlements=1"
  require_line "$output" "$prefix.buffer_returns=1"
  require_line "$output" "$prefix.origin_obligation_id=$obligation"
  require_line "$output" "$prefix.source_address=$source_address"
  require_line "$output" "$prefix.destination_address=$destination_address"
  require_line "$output" "$prefix.source_port=$source_port"
  require_line "$output" "$prefix.destination_port=$destination_port"
  require_line "$output" "$prefix.l3_header_length=$l3_header_length"
  require_line "$output" "$prefix.l4_header_length=$l4_header_length"
  require_line "$output" "$prefix.packet_length=$packet_length"

  local ingress_index terminal_index ingress_digest terminal_digest
  local ingress_current_data terminal_current_data ingress_length terminal_length
  ingress_index="$(field "$output" "$prefix.ingress_buffer_index")"
  terminal_index="$(field "$output" "$prefix.terminal_buffer_index")"
  ingress_digest="$(field "$output" "$prefix.ingress_digest")"
  terminal_digest="$(field "$output" "$prefix.terminal_digest")"
  ingress_current_data="$(field "$output" "$prefix.ingress_current_data")"
  terminal_current_data="$(field "$output" "$prefix.terminal_current_data")"
  ingress_length="$(field "$output" "$prefix.ingress_length")"
  terminal_length="$(field "$output" "$prefix.terminal_length")"
  [[ "$ingress_index" =~ ^[0-9]+$ && "$ingress_index" == "$terminal_index" ]] ||
    fail "$vector did not retain one live VPP buffer index"
  [[ "$ingress_digest" =~ ^[[:xdigit:]]{64}$ && "$ingress_digest" == "$terminal_digest" ]] ||
    fail "$vector packet bytes changed between ingress and terminal"
  [[ "$ingress_current_data" =~ ^[0-9]+$ && "$ingress_current_data" == "$terminal_current_data" ]] ||
    fail "$vector current_data changed during the ordinary graph"
  [[ "$ingress_length" =~ ^[1-9][0-9]*$ && "$ingress_length" == "$terminal_length" ]] ||
    fail "$vector packet length changed during the ordinary graph"
}

require_graph_trace() {
  local trace_file="$1"
  local fixture_file="$2"
  python3 - "$trace_file" "$fixture_file" <<'PY'
import re
import sys

trace_path, fixture_path = sys.argv[1:]
pattern = re.compile(
    r"product-packet-trace node=(admit|owner-guard|policy|terminal) "
    r"buffer_index=([0-9]+) obligation=([0-9]+) thread=([0-9]+)(?: |$)"
)
by_obligation = {}
with open(trace_path, encoding="utf-8", errors="replace") as stream:
    for line in stream:
        match = pattern.search(line)
        if not match:
            continue
        node, buffer_index, obligation, thread = match.groups()
        by_obligation.setdefault(obligation, []).append(
            (node, buffer_index, int(thread))
        )

expected_obligations = {str(value) for value in range(174001, 174009)}
if set(by_obligation) != expected_obligations:
    raise SystemExit(
        "trace obligations differ: "
        f"expected={sorted(expected_obligations)!r} "
        f"actual={sorted(by_obligation)!r}"
    )

fixture = {}
with open(fixture_path, encoding="utf-8", errors="replace") as stream:
    for line in stream:
        if not line.startswith("vector.") or "=" not in line:
            continue
        key, value = line.rstrip("\n").split("=", 1)
        fixture[key] = value

buffer_indices = set()
for obligation, observations in by_obligation.items():
    nodes = [node for node, _, _ in observations]
    indices = {index for _, index, _ in observations}
    if len(nodes) != 4 or set(nodes) != {"admit", "owner-guard", "policy", "terminal"}:
        raise SystemExit(
            f"obligation {obligation} graph stages were {nodes!r}"
        )
    if len(indices) != 1:
        raise SystemExit(
            f"obligation {obligation} changed buffer index: {sorted(indices)!r}"
        )
    buffer_indices.update(indices)
    prefix = next(
        key.removesuffix(".origin_obligation_id")
        for key, value in fixture.items()
        if key.endswith(".origin_obligation_id") and value == obligation
    )
    expected_admit = int(fixture[f"{prefix}.actual_admit_thread"])
    expected_guard = int(fixture[f"{prefix}.actual_guard_thread"])
    observed = {node: thread for node, _, thread in observations}
    if observed["admit"] != expected_admit:
        raise SystemExit(
            f"obligation {obligation} admit thread mismatch: {observed!r}"
        )
    if (observed["owner-guard"] != expected_guard or
            observed["policy"] != expected_guard or
            observed["terminal"] != expected_guard):
        raise SystemExit(
            f"obligation {obligation} owner/terminal thread mismatch: {observed!r}"
        )

if len(buffer_indices) != 8:
    raise SystemExit(f"fixture reused live buffer indices: {sorted(buffer_indices)!r}")
PY
}

require_runtime_activity() {
  local runtime_file="$1"
  local node="$2"
  awk -v node="$node" '
    $1 == node && $3 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ &&
      $3 + 0 > 0 && $4 + 0 > 0 { found = 1 }
    END { exit found ? 0 : 1 }
  ' "$runtime_file" || fail "$node has no real VLIB runtime calls/vectors"
}

run_cycle() {
  local cycle="$1"
  local configure_output enable_output fixture_output status_output disable_output
  local trace_output runtime_output
  configure_output="$(cli "product packet-graph configure workers 2 fixture $fixture_id")"
  printf '%s\n' "$configure_output" | tee "$evidence_dir/cycle-$cycle-configure.trace"
  require_line "$configure_output" "graph.configure=ok"
  require_line "$configure_output" "graph.workers=2"
  require_line "$configure_output" "graph.fixture=$fixture_id"

  enable_output="$(cli 'product packet-graph enable')"
  printf '%s\n' "$enable_output" | tee "$evidence_dir/cycle-$cycle-enable.trace"
  require_line "$enable_output" "graph.enable=ok"

  cli 'clear trace' >"$evidence_dir/cycle-$cycle-clear-trace.trace"
  cli 'trace add product-packet-test-ingress 16' \
    >"$evidence_dir/cycle-$cycle-trace-add.trace"

  fixture_output="$(cli "product packet-graph run-fixture $fixture_id")"
  printf '%s\n' "$fixture_output" | tee "$evidence_dir/cycle-$cycle-fixture.trace"
  require_line "$fixture_output" "fixture.id=$fixture_id"
  require_line "$fixture_output" "fixture.workers=2"
  require_line "$fixture_output" "fixture.vector_count=8"
  # The fixture explicitly chooses each vector's arrival worker to exercise
  # four owner-local and four remote-primary paths. Forward/reverse direction
  # itself never defines placement and remains absent from owner selection.
  require_vector "$fixture_output" ipv4-tcp-forward 4 6 174001 \
    0000000000000000000000000a000001 0000000000000000000000000a000002 \
    12345 443 20 20 40
  require_vector "$fixture_output" ipv4-tcp-reverse 4 6 174002 \
    0000000000000000000000000a000002 0000000000000000000000000a000001 \
    443 12345 20 20 40
  require_vector "$fixture_output" ipv4-udp-forward 4 17 174003 \
    000000000000000000000000c0000201 000000000000000000000000c6336402 \
    5353 53 20 8 28
  require_vector "$fixture_output" ipv4-udp-reverse 4 17 174004 \
    000000000000000000000000c6336402 000000000000000000000000c0000201 \
    53 5353 20 8 28
  require_vector "$fixture_output" ipv6-tcp-forward 6 6 174005 \
    20010db8000000000000000000000001 20010db8000000000000000000000002 \
    2222 8443 40 20 60
  require_vector "$fixture_output" ipv6-tcp-reverse 6 6 174006 \
    20010db8000000000000000000000002 20010db8000000000000000000000001 \
    8443 2222 40 20 60
  require_vector "$fixture_output" ipv6-udp-forward 6 17 174007 \
    20010db8000000000000000000000001 20010db8000000000000000000000002 \
    60000 443 40 8 48
  require_vector "$fixture_output" ipv6-udp-reverse 6 17 174008 \
    20010db8000000000000000000000002 20010db8000000000000000000000001 \
    443 60000 40 8 48
  require_pair_identity "$fixture_output" ipv4-tcp
  require_pair_identity "$fixture_output" ipv4-udp
  require_pair_identity "$fixture_output" ipv6-tcp
  require_pair_identity "$fixture_output" ipv6-udp

  trace_output="$(cli 'show trace')"
  printf '%s\n' "$trace_output" | tee "$evidence_dir/cycle-$cycle-vlib-trace.trace"
  require_graph_trace "$evidence_dir/cycle-$cycle-vlib-trace.trace" \
    "$evidence_dir/cycle-$cycle-fixture.trace"

  runtime_output="$(cli 'show runtime')"
  printf '%s\n' "$runtime_output" | tee "$evidence_dir/cycle-$cycle-vlib-runtime.trace"
  require_runtime_activity "$evidence_dir/cycle-$cycle-vlib-runtime.trace" \
    product-packet-admit
  require_runtime_activity "$evidence_dir/cycle-$cycle-vlib-runtime.trace" \
    product-packet-owner-guard
  require_runtime_activity "$evidence_dir/cycle-$cycle-vlib-runtime.trace" \
    product-packet-policy
  require_runtime_activity "$evidence_dir/cycle-$cycle-vlib-runtime.trace" \
    product-packet-terminal

  status_output="$(cli 'show product packet-graph')"
  printf '%s\n' "$status_output" | tee "$evidence_dir/cycle-$cycle-status.trace"
  for expected in \
    graph.workers=2 \
    graph.admitted=8 \
    graph.local_packets=4 \
    graph.remote_packets=4 \
    graph.primary_enqueues=4 \
    graph.primary_enqueue_max_per_packet=1 \
    graph.policy_stage_evaluations=8 \
    graph.policy_stage_pass_next=8 \
    graph.policy_stage_drops=0 \
    graph.terminal_intents=8 \
    graph.ledger_settlements=8 \
    graph.buffer_returns=8 \
    graph.duplicate_terminals=0 \
    graph.duplicate_settlements=0 \
    graph.lost_buffers=0 \
    graph.ingress_fq_node=product-packet-test-ingress \
    graph.ingress_fq_enqueued_frames=2 \
    graph.ingress_fq_dequeued_frames=2 \
    graph.owner_guard_fq_node=product-packet-owner-guard \
    graph.owner_guard_fq_enqueued_frames=4 \
    graph.owner_guard_fq_dequeued_frames=4; do
    require_line "$status_output" "$expected"
  done
  local ingress_fq owner_fq
  ingress_fq="$(field "$status_output" graph.ingress_frame_queue)"
  owner_fq="$(field "$status_output" graph.owner_guard_frame_queue)"
  [[ "$ingress_fq" =~ ^[0-9]+$ && "$owner_fq" =~ ^[0-9]+$ &&
     "$ingress_fq" != "$owner_fq" ]] ||
    fail "ingress and Primary Distribution must use two distinct real FQMs"

  disable_output="$(cli 'product packet-graph disable')"
  printf '%s\n' "$disable_output" | tee "$evidence_dir/cycle-$cycle-disable.trace"
  require_line "$disable_output" "graph.disable=ok"
  require_line "$disable_output" "graph.buffer_debt=0"
  require_line "$disable_output" "graph.handoff_credit_debt=0"
  require_line "$disable_output" "graph.obligation_debt=0"
}

run_cycle 1
run_cycle 2

PRODUCT_ARTIFACT_DIR="$artifact_root" \
  PRODUCT_RUNTIME_DIR="$runtime_dir" \
  "$query" >"$evidence_dir/final-artifact-api-identity.trace"

echo "SAKAMOTO-174 Product VPP Graph contract: PASS"
echo "evidence=$evidence_dir"
