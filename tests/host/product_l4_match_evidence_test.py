#!/usr/bin/env python3
"""Check actual match recording against an independent byte-serialized hash oracle.

Compile the Product projection, hashing, match/no-match recording and association
functions verbatim. Only the graph's scalar storage and atomic primitives are
provided by the harness. Count work at the actual match-recording call site.
"""
import argparse
import os
from pathlib import Path
import random
import re
import resource
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = ROOT / "src/product/vpp"
parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, default=PRODUCT / "product_packet_graph.c")
parser.add_argument("--output", type=Path)
args = parser.parse_args()
source = args.source.read_text()


def function(name):
    match = re.search(r"(?m)^" + re.escape(name) + r"\s*\(", source)
    assert match, name
    start = source.rfind("\n", 0, match.start() - 1) + 1
    opening = source.index("{", match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


hash_begin = source.index("#define PRODUCT_PACKET_GRAPH_L4_EVIDENCE_FNV_OFFSET")
hash_end = source.index("static product_l4_policy_status_t\nproduct_packet_graph_l4_view_evaluate", hash_begin)
functions = "".join(function(n) for n in (
    "product_packet_graph_l4_direction_from_platform",
    "product_packet_graph_l4_packet_projection")) + source[hash_begin:hash_end]
functions += "".join(function(n) for n in (
    "product_packet_graph_record_l4_view_match",
    "product_packet_graph_record_l4_view_no_match"))
fields = sorted(set(re.findall(r"graph->(\w+)", functions)))
end = source.index("} product_packet_graph_main_t;")
declaration = source[source.rfind("typedef struct", 0, end):end]
storage = []
for field in fields:
    match = re.search(r"\b(u32|u64)\s+" + field + r"\s*;", declaration)
    assert match, field
    storage.append(match[0])
for name, index in (("product_packet_graph_l4_packet_projection", 0),
                    ("product_packet_graph_l4_match_policy_key", 1),
                    ("product_packet_graph_l4_evidence_hash_byte", 2)):
    pattern = r"(?m)(^" + name + r"\s*\([^{}]*\)\s*\{)"
    functions, count = re.subn(pattern, r"\1\n  work[" + str(index) + "]++;", functions)
    assert count == 1, name

prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "product_packet.h"
#include "product_l4_policy.h"
typedef uint8_t u8; typedef uint16_t u16;
typedef uint32_t u32; typedef uint64_t u64;
static u64 work[3];
static const void *stores[128]; static unsigned store_count;
#define clib_memset memset
#define clib_memcpy_fast memcpy
#define static_always_inline static inline __attribute__((always_inline))
#define clib_atomic_store_rel_n(p,n) do { \
  assert(store_count < 128); stores[store_count++] = (p); \
  __atomic_store_n((p),(n),__ATOMIC_RELEASE); } while (0)
#define clib_atomic_load_acq_n(p) __atomic_load_n((p),__ATOMIC_ACQUIRE)
#define clib_atomic_fetch_add_relax(p,n) __atomic_fetch_add((p),(n),__ATOMIC_RELAXED)
#define PRODUCT_POLICY_VERDICT_PASS_NEXT 1
#define PRODUCT_POLICY_VERDICT_ALLOW 1
#define PRODUCT_POLICY_VERDICT_DROP 2
#define PRODUCT_PACKET_GRAPH_L4_WINNER_RULE 2
#define PRODUCT_PACKET_GRAPH_L4_EVALUATION_MATCH 1
#define PRODUCT_PACKET_GRAPH_L4_EVALUATION_NO_MATCH 2
enum { PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_NONE,
       PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_PROBE,
       PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_SUBJECT,
       PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_UNRELATED };
'''
prefix += "typedef struct {\n" + "\n".join(storage) + "\n} product_packet_graph_main_t;\n"
suffix = r'''
int main(int argc, char **argv) {
  assert(argc == 2); FILE *file = fopen(argv[1], "rb"); assert(file);
  unsigned cases = 0; u64 observed[3] = {0};
  struct { u64 v[24]; u8 addresses[32]; } input;
  while (fread(&input, sizeof(input), 1, file) == 1) {
    u64 *v = input.v; product_packet_lease_t lease = {0};
    product_packet_graph_main_t graph = {0};
    product_l4_policy_match_result_t match = {0};
    lease.platform.uid = v[3]; lease.platform.network_context_id = v[4];
    lease.platform.linux_ifindex = v[5]; lease.facts.ip_family = v[6];
    lease.facts.protocol = v[7]; lease.facts.destination_port = v[8];
    lease.facts.source_port = v[9]; lease.platform.direction = v[10];
    lease.platform.availability = v[11]; lease.facts.l4_status = v[12];
    lease.terminal_count = v[20];
    memcpy(lease.facts.source_address, input.addresses, 16);
    memcpy(lease.facts.destination_address, input.addresses + 16, 16);
    match.actual_action = v[13]; match.action = v[14]; match.rule_id = v[15];
    match.reason_id = v[16]; match.winner_rank = v[17]; match.probes = v[18];
    match.candidate_count = v[19];
    memset(work, 0, sizeof(work)); store_count = 0;
    product_packet_graph_record_l4_view_match(&graph, &lease, v[0], v[1], v[2], &match);
    memcpy(observed, work, sizeof(observed));
    assert(graph.l4_typed_match_policy_key == v[21]);
    assert(graph.l4_typed_match_probe_key == v[22]);
    assert(graph.l4_typed_match_subject_key == v[23]);
    assert(graph.l4_last_evaluation_probe_key == v[22]);
    assert(graph.l4_policy_view_match_records == 1 && graph.l4_match_records == 1);
    assert(graph.l4_last_match_rule_id == v[15] && graph.l4_last_match_reason_id == v[16]);
    assert(graph.l4_last_match_uid == v[3] && graph.l4_last_match_network_context == v[4]);
    assert(graph.l4_last_match_winner == 2 && graph.l4_policy_view_last_winner_rank == v[17]);
    assert(graph.l4_policy_view_last_probes == v[18] && graph.l4_policy_view_last_candidate_count == v[19]);
    assert(graph.l4_last_evaluation_result == 1);
    assert(graph.l4_last_evaluation_verdict == (v[13] == 2 ? 2 : 1));
    assert(graph.policy_drop_records == (v[13] == 2));
    if (v[13] == 2) {
      assert(graph.policy_last_drop_rule_id == v[15]);
      assert(graph.policy_last_drop_completion_attempts == v[20]);
    }
    assert(store_count >= 3);
    assert(stores[store_count-3] == &graph.l4_typed_match_probe_key);
    assert(stores[store_count-2] == &graph.l4_typed_match_subject_key);
    assert(stores[store_count-1] == &graph.l4_typed_match_policy_key);
    assert(product_packet_graph_l4_match_association(&graph, &lease, v[0], v[1], v[2]) == 1);
    product_packet_lease_t changed = lease; changed.facts.source_port ^= 1;
    assert(product_packet_graph_l4_match_association(&graph, &changed, v[0], v[1], v[2]) == 1);
    changed = lease; changed.facts.destination_port ^= 1;
    assert(product_packet_graph_l4_match_association(&graph, &changed, v[0], v[1], v[2]) == 2);
    assert(product_packet_graph_l4_match_association(&graph, &lease, v[0]^1, v[1], v[2]) == 0);
    changed = lease; changed.platform.uid ^= 1;
    assert(product_packet_graph_l4_match_association(&graph, &changed, v[0], v[1], v[2]) == 3);
    match.no_match_reason = PRODUCT_L4_POLICY_NO_MATCH_NO_RULE;
    match.candidate_count = 1; store_count = 0;
    product_packet_graph_record_l4_view_no_match(&graph, v[0], v[1], v[2], 1, &match, &changed);
    assert(graph.l4_last_evaluation_result == 1 && graph.l4_no_match_records == 1);
    assert(graph.l4_typed_match_probe_key == v[22] && graph.l4_last_match_rule_id == v[15]);
    store_count = 0;
    product_packet_graph_record_l4_view_no_match(&graph, v[0], v[1], v[2], 1, &match, &lease);
    assert(graph.l4_last_evaluation_result == 1 && graph.l4_no_match_records == 2);
    changed = lease; changed.facts.destination_port ^= 1; store_count = 0;
    product_packet_graph_record_l4_view_no_match(&graph, v[0], v[1], v[2], 1, &match, &changed);
    assert(graph.l4_last_evaluation_result == ((v[11]&1) ? 2 : 1));
    assert(graph.l4_last_match_rule_id == v[15] && graph.l4_typed_match_probe_key == v[22]);
    memset(work, 0, sizeof(work)); store_count = 0;
    product_packet_graph_record_l4_view_match(0, &lease, v[0], v[1], v[2], &match);
    product_packet_graph_record_l4_view_match(&graph, 0, v[0], v[1], v[2], &match);
    product_packet_graph_record_l4_view_match(&graph, &lease, v[0], v[1], v[2], 0);
    assert(!work[0] && !work[1] && !work[2] && !store_count);
    cases++;
  }
  assert(feof(file) && cases); fclose(file);
  printf("Semantic equivalence PASS: %u cases; match work projection=%llu policy=%llu hash_bytes=%llu\n",
    cases, (unsigned long long)observed[0], (unsigned long long)observed[1], (unsigned long long)observed[2]);
  fflush(stdout);
  assert(observed[0] == 1 && observed[1] == 1 && observed[2] == 102);
  puts("PASS: actual match/no-match keys, associations, publication order and bounded work");
}
'''
if "product_packet_graph_l4_match_evidence_suffix" in source:
    suffix = suffix.replace('  puts("PASS:', '''
  product_l4_policy_packet_t zero_packet = {0};
  assert(product_packet_graph_l4_match_evidence_suffix(&zero_packet, 0) == 1);
  puts("PASS:''')


def hash_bytes(data):
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value or 1


def serialized_keys(values, addresses):
    policy = hash_bytes(struct.pack(">QQQ", *values[:3]))
    family, protocol, direction, availability = values[6], values[7], values[10], values[11]
    if family == 4:
        addresses = addresses[12:16] + bytes(12) + addresses[28:32] + bytes(12)
    elif family != 6:
        addresses = bytes(32)
    known_direction = direction in (1, 3)
    prefix = struct.pack(">QBB", policy, family, protocol) + addresses
    tail = struct.pack(">IIIBBBBB", *values[3:6], direction if known_direction else 0,
                       bool(availability & 1), bool(availability & 4),
                       bool(availability & 2), known_direction)
    return policy, hash_bytes(prefix + struct.pack(">H", values[8]) + tail), hash_bytes(prefix + tail)


rng = random.Random(0x210)
cases = []
for index in range(4864):
    values = [rng.getrandbits(64) for _ in range(3)] + [rng.getrandbits(32) for _ in range(3)]
    values += [rng.choice((0, 4, 6, 255)), rng.choice((1, 6, 17, 58, 255)),
               rng.getrandbits(16), rng.getrandbits(16), rng.choice((0, 1, 3, 4)), rng.randrange(8),
               rng.randrange(5), rng.choice((0, 1, 2)), rng.choice((1, 2)),
               rng.getrandbits(64), rng.getrandbits(32), rng.randrange(1, 129),
               rng.randrange(129), rng.randrange(129), rng.randrange(2)]
    if index < 768:
        # Cross unknown/known fields, families, direction and boundary values.
        values[:6] = ([0] * 6) if index % 2 == 0 else [2**64-1]*3 + [2**32-1]*3
        values[6] = (4, 6)[index % 2]
        values[8] = (0, 1, 65535)[index // 2 % 3]
        values[10] = (0, 1, 3, 4)[index // 6 % 4]
        values[11] = index // 24 % 8
    addresses = rng.randbytes(32)
    values += serialized_keys(values, addresses)
    cases.append(struct.pack("<24Q32s", *values, addresses))

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix="product-l4-match-evidence-") as directory:
    out = args.output or Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cases.bin").write_bytes(b"".join(cases))
    (out / "test.c").write_text(prefix + functions + suffix)
    binary = out / "test"
    subprocess.run(["cc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie",
                    "-I", str(PRODUCT),
                    str(out / "test.c"), "-o", str(binary)], check=True)
    # These Product functions use only caller-owned scalar and stack storage.
    # Disable LSan's process tracing, which is unavailable in managed sandboxes.
    environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:handle_segv=0:abort_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1")
    subprocess.run([str(binary), str(out / "cases.bin")], env=environment, check=True, timeout=15)
