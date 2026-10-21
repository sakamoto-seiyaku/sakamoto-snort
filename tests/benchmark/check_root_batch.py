#!/usr/bin/env python3
"""Offline Root qualification checks; never device performance evidence."""
import base64
import json
import math
from pathlib import Path
import re
import struct
import tempfile

import root_batch as collector

MANIFEST = {"uid": 12632, "peer_host": "192.168.4.5", "peer_port": 40720,
            "rules_count": 1, "rules_revision": 9, "applicable_rule_versions": [65537]}
LAYOUT = ("0 vpp_main 100 other (0) 0 0 0\n"
          "1 vpp_wk_0 workers 101 other (0) 1 1 0\n"
          "2 vpp_wk_1 workers 102 other (0) 2 2 0\n")


def diagnostic(step=0, enabled=False):
    lines = [LAYOUT, "batch.enabled=" + str(int(enabled)),
             f"batch.qualification=1 scope={collector.SCOPE} policy_qualified_succeeded={100 + step * 80} policy_qualified_matched_allow_succeeded={100 + step * 80} policy_qualified_matched_drop_succeeded=0 cpu_ns={1000000000 + step * 2000000000}",
             "capacity.status credits=32 primary_slots=64 completion_slots=128",
             "primary.status generation=1846 published=10",
             "completion.status generation=1846 pending=0",
             "policy.snapshot generation=1846 revision=9 snapshot_hash=55 sequence=2 publications=1",
             "policy.plan generation=1846 revision=9 hash=55 direct=1 factorized=0 residual=0",
             "rule.budget saved=9 active=9 compile_error=0"]
    for lane in range(4):
        lines += [f"root.receive generation=1846 lane={lane} family=4 queue={176 + lane} flags=2 maxlen=1024 allocated=20 datagrams={100 + step * 100} ingress_accepts=1 reserve_accepts=0 reserve_losses=0 identity_losses=0",
                  f"root.lane generation=1846 lane={lane} family=4 family_lane={lane % 2} worker={lane % 2} thread={lane % 2 + 1} queue={176 + lane} captured={100 + step * 100} submitted={100 + step * 100} verdicts={100 + step * 100} succeeded={100 + step * 100} failed=0 duplicate=0"]
    for worker in range(2):
        lines += [f"flow.runtime worker={worker} generation=1846 capacity=1024 allocated_bytes=65536 entry_bytes=64 capacity_misses=0",
                  f"policy.worker worker={worker} generation=1846 revision=9 snapshot_hash=55"]
    lines += [f"flow.entry worker=0 slot=0 incarnation=1 protocol=17 uid=12632 rule=65537 revision=9 policy_generation=1846 decision=1 key_a=000000000000000000000000c0a80405 key_b=000000000000000000000000c0a80402 port_a=40720 port_b=42000 packets={10 + step * 90}"]
    if enabled:
        fields = ("admit_frames", "admit_vectors", "prepare_windows", "prepared_packets", "primary_calls",
                  "primary_publications", "primary_vectors", "primary_failed", "policy_claims",
                  "policy_packets", "policy_hold_ns", "completion_calls", "completion_publications",
                  "completion_vectors", "retry_windows", "origin_frames", "origin_vectors")
        lines += ["batch.thread=" + str(thread) + " " + " ".join(f"{key}={10 + step * 10}" for key in fields)
                  + " policy_hold_max_ns=100" for thread in range(3)]
    return "\n".join(lines) + "\n"


def reject(call, message):
    try:
        call()
    except (RuntimeError, ValueError) as error:
        assert message in str(error), (message, str(error))
    else:
        raise AssertionError("invalid evidence accepted: " + message)


before, after = diagnostic(), diagnostic(1)
validate = lambda final: collector.validate_window(MANIFEST, "udp-fixed", "off", "1846", before, final)
qualified = validate(after)
assert qualified["policy_qualified_succeeded"] == 80
assert qualified["vpp_process_cpu_ns_delta"] == 2000000000
assert qualified["vpp_process_cpu_seconds"] == 2
assert qualified["root_lane_deltas"]["succeeded"] == 400
assert qualified["unqualified_succeeded"] == 320
assert qualified["applicable_flows"][0]["uid"] == "12632"
assert qualified["policy_qualified_matched_allow_succeeded"] == 80
assert qualified["policy_qualified_matched_drop_succeeded"] == 0
assert qualified["batch_ratios"] == {}
candidate = collector.validate_window(MANIFEST, "udp-fixed", "on", "1846", diagnostic(enabled=True), diagnostic(1, enabled=True))
assert candidate["batch_totals"]["admit_frames"] == 30
assert candidate["batch_ratios"]["primary_vectors_per_publication"] == 1
reject(lambda: validate(before), "no positive")
reject(lambda: validate(after.replace("policy_qualified_succeeded=180", "policy_qualified_succeeded=0")
                       .replace("policy_qualified_matched_allow_succeeded=180", "policy_qualified_matched_allow_succeeded=0")), "no positive")
reject(lambda: validate(after.replace("cpu_ns=3000000000", "cpu_ns=1000000000")), "did not advance")
reject(lambda: validate(after.replace("cpu_ns=3000000000", "cpu_ns=0")), "did not advance")
reject(lambda: validate(after.replace(" cpu_ns=3000000000", "")), "missing same-barrier")
reject(lambda: validate(after.replace("batch.qualification=1", "batch.qualification=0")), "OFF")
reject(lambda: validate(after.replace(collector.SCOPE, "endpoint_receipt")), "scope")
reject(lambda: validate(after.replace("batch.enabled=0", "batch.enabled=1")), "backend")
reject(lambda: validate(after.replace("generation=1846", "generation=1847")), "generation")
reject(lambda: validate(after.replace("active=9", "active=10")), "revision")
reject(lambda: validate(after.replace("direct=1", "direct=0")), "empty")
reject(lambda: validate(after.replace("uid=12632", "uid=2000")), "FlowEntry")
# A Flow row is its last packet's decision, which may be a reverse NoMatch.
# The immutable packet completion must independently prove matching ALLOWs.
assert validate(after.replace("rule=65537", "rule=0"))["policy_qualified_succeeded"] == 80
reject(lambda: validate(after.replace("policy_qualified_matched_allow_succeeded=180", "policy_qualified_matched_allow_succeeded=100")), "no positive matched")
reject(lambda: validate(after.replace(" policy_qualified_matched_allow_succeeded=180", "")), "missing matched")
reject(lambda: validate(after.replace("policy_qualified_matched_allow_succeeded=180", "policy_qualified_matched_allow_succeeded=170")), "lack complete matching")
reject(lambda: validate(after.replace("policy_qualified_matched_allow_succeeded=180", "policy_qualified_matched_allow_succeeded=181")), "exceed qualified")
reject(lambda: validate(after.replace("policy_qualified_matched_allow_succeeded=180", "policy_qualified_matched_allow_succeeded=179").replace("policy_qualified_matched_drop_succeeded=0", "policy_qualified_matched_drop_succeeded=1")), "Drop settlements")
reject(lambda: validate(after.replace("packets=100\n", "packets=10\n")), "FlowEntry")
reject(lambda: validate(after.replace("capacity=1024", "capacity=2048")), "resource")
reject(lambda: validate(after.replace("publications=1", "publications=2")), "republished")
reject(lambda: collector.batch(diagnostic(enabled=True).replace("batch.thread=2", "batch.thread=3"), "on"), "W2")

# An increased allocator footprint is observable, not increased packet capacity.
larger = after.replace("allocated_bytes=65536", "allocated_bytes=122888").replace("entry_bytes=64", "entry_bytes=120")
memory = validate(larger)
assert memory["resource_identity"] == qualified["resource_identity"]
assert memory["memory_footprint_before"]["flow_allocated_bytes_total"] == 131072
assert memory["memory_footprint_after"]["flow_allocated_bytes_total"] == 245776
assert collector.resource_identity(before.replace("credits=32", "credits=32 generation=1846 in_use=10")) == collector.resource_identity(
    after.replace("credits=32", "credits=32 generation=1847 in_use=20"))
frozen_resources = {**MANIFEST, "resource_identity": collector.resource_identity(before)}
assert collector.validate_window(frozen_resources, "udp-fixed", "on", "1847",
    diagnostic(enabled=True).replace("generation=1846", "generation=1847").replace("allocated_bytes=65536", "allocated_bytes=122888"),
    diagnostic(1, enabled=True).replace("generation=1846", "generation=1847").replace("allocated_bytes=65536", "allocated_bytes=122888"))["resource_identity"] == frozen_resources["resource_identity"]
reject(lambda: validate(after.replace("credits=32", "credits=64")), "resource")
reject(lambda: validate(after.replace("primary_slots=64", "primary_slots=128")), "resource")
reject(lambda: validate(after.replace("completion_slots=128", "completion_slots=256")), "resource")
reject(lambda: validate(after.replace("maxlen=1024", "maxlen=2048")), "resource")
reject(lambda: validate(after.replace("flags=2", "flags=3")), "resource")
reject(lambda: validate(after.replace("allocated=20", "allocated=21")), "resource")

# Ended TCP flows may have left the active table. Their real create/end
# counters and immutable matched-success completions must both advance.
churn_before = before + "\nflow.protocol worker=0 protocol=tcp creates=10 closed=8\n"
churn_after = after + "\nflow.protocol worker=0 protocol=tcp creates=30 closed=28\n"
churn = collector.validate_window(MANIFEST, "tcp-new", "off", "1846", churn_before, churn_after)
assert churn["tcp_churn_flow_creates"] == churn["tcp_churn_flow_closed"] == 20
assert not churn["applicable_flows"]
reject(lambda: collector.validate_window(MANIFEST, "tcp-new", "off", "1846", churn_before,
       churn_after.replace("creates=30", "creates=10")), "Flow creates")
reject(lambda: collector.validate_window(MANIFEST, "tcp-new", "off", "1846", churn_before,
       churn_after.replace("closed=28", "closed=8")), "create/end")

# Host control may use a forwarded port; policy/Flow evidence still uses traffic.
loopback = {**MANIFEST, "peer_host": "127.0.0.1", "peer_port": 41320,
            "peer_control_host": "127.0.0.1", "peer_control_port": 41420, "transport": "loopback"}
saved_query = collector.quick.peer_query
collector.quick.peer_query = lambda host, port, case_id, operation: (host, port, case_id, operation)
try:
    assert collector.query_peer(MANIFEST, 2, "R") == ("192.168.4.5", 40720, 2, "R")
    assert collector.query_peer(loopback, 3) == ("127.0.0.1", 41420, 3, "Q")
    host_only = {**MANIFEST, "peer_control_host": "127.0.0.1"}
    assert collector.query_peer(host_only, 4) == ("127.0.0.1", 40720, 4, "Q")
finally:
    collector.quick.peer_query = saved_query
loop_before = before.replace("c0a80405", "7f000001").replace("port_a=40720", "port_a=41320")
loop_after = after.replace("c0a80405", "7f000001").replace("port_a=40720", "port_a=41320")
assert collector.validate_window(loopback, "udp-fixed", "off", "1846", loop_before, loop_after)["policy_qualified_succeeded"] == 80
reject(lambda: collector.validate_window(loopback, "udp-fixed", "off", "1846", loop_before,
    loop_after.replace("port_a=41320", "port_a=41420")), "FlowEntry")

client = {"start_monotonic_ns": 1000000000, "end_monotonic_ns": 11000000000}
layout = collector.thread_layout(before)


def sample(ns, ticks, tids=(100, 101, 102)):
    return {"monotonic_ns": ns, "clock_ticks": 100, "page_size": 4096, "pid": 100,
            "threads": [{"tid": tid, "utime": ticks, "stime": 0, "rss_pages": 10, "last_cpu": i}
                        for i, tid in enumerate(tids)]}


cpu_rows = [sample(900000000, 0), sample(1100000000, 10), sample(10900000000, 110), sample(11100000000, 99999)]
raw = "\n".join(json.dumps(row) for row in cpu_rows)
cpu = collector.cpu_summary(raw, client, layout)
assert cpu["cpu_seconds"] == 3
assert math.isclose(cpu["coverage_fraction"], .98)
assert cpu["sample_count"] == 2
assert cpu["sample_start_monotonic_ns"] == 1100000000
reject(lambda: collector.cpu_summary(json.dumps(cpu_rows[1]), client, layout), "insufficient")
changed = [cpu_rows[1], sample(10900000000, 110, tids=(100, 101, 999))]
reject(lambda: collector.cpu_summary("\n".join(json.dumps(row) for row in changed), client, layout), "identity")
short = [cpu_rows[1], sample(3100000000, 20)]
reject(lambda: collector.cpu_summary("\n".join(json.dumps(row) for row in short), client, layout), "90%")

# Source parsing proves identities only; VPP supplies actual applicable winners.
payload = b"SKRULE06" + struct.pack("<QIIQ", 9, 1, 1, 65537) + struct.pack("<Q", 65537) + bytes(172)
source_manifest = {**MANIFEST, "rules_path": "/frozen/rules.conf",
                   "rules_sha256": collector.hashlib.sha256(payload).hexdigest()}


class SourceDevice:
    def root(self, command, **kwargs):
        assert command == "base64 /frozen/rules.conf"
        return base64.b64encode(payload).decode()


with tempfile.TemporaryDirectory() as directory:
    output = Path(directory)
    identity = collector.rule_source(SourceDevice(), source_manifest, output, "good")
    assert identity == {"revision": 9, "count": 1, "versions": [65537]}
    reject(lambda: collector.rule_source(SourceDevice(), {**source_manifest, "rules_count": 0}, output, "zero"), "count/revision")
    reject(lambda: collector.rule_source(SourceDevice(), {**source_manifest, "rules_revision": 10}, output, "revision"), "count/revision")
    reject(lambda: collector.rule_source(SourceDevice(), {**source_manifest, "applicable_rule_versions": [65538]}, output, "wrong"), "absent")
    # Check the current C wire layout, including the second row's identity.
    encoder = (collector.quick.ROOT / "src/product/vpp/product_rule_config.c").read_text()
    fields = re.findall(r"F\((\w+)\)", encoder.split("#define RULE_FIELDS(F)", 1)[1].split("static size_t encode", 1)[0])
    assert len(fields) == 16
    stride = 2 * 8 + len(fields) * 4 + 2 * 16 + 4 + 64
    assert stride == 180
    payload = (b"SKRULE06" + struct.pack("<QIIQQ", 9, 2, 2, 65537, 131073)
               + struct.pack("<QQ", 65537, 0) + bytes(stride - 16)
               + struct.pack("<QQ", 131073, 0) + bytes(stride - 16))
    two = {**source_manifest, "rules_count": 2, "applicable_rule_versions": [65537, 131073],
           "rules_sha256": collector.hashlib.sha256(payload).hexdigest()}
    assert collector.rule_source(SourceDevice(), two, output, "two")["versions"] == [65537, 131073]


class StopDevice:
    native = "s242 event=stop_native_zero generation=1846 " + " ".join(key + "=0" for key in collector.ZERO_FIELDS)
    residue = "productRootNfqueueResidueClean=true\n"
    queues = ""
    hooks = "*mangle\nCOMMIT\n"

    def action(self, *args, **kwargs):
        assert args == ("--ez", "runtimeStop", "true")
        return "ordinary stop requested\n"

    def wait_state(self, state, **kwargs):
        assert state == "stopped"
        return {"state": "stopped", "mayBeActive": "false"}

    def wait_process_gone(self, name, **kwargs):
        assert name == "libvpp_runtime.so"

    def command(self, *args, **kwargs):
        return self.native if "tail" in args else self.residue

    def root(self, command, **kwargs):
        return self.queues if "nfnetlink_queue" in command else self.hooks


with tempfile.TemporaryDirectory() as directory:
    output = Path(directory)
    target = StopDevice()
    assert collector.stop_audit(target, output, "1846")["native_zero"]
    target.native = target.native.replace("pending=0", "pending=1")
    reject(lambda: collector.stop_audit(target, output, "1846", "pending-"), "independent")
    audit = json.loads((output / "pending-stop-audit.json").read_text())
    assert not audit["native_zero"] and audit["capture_residue_clean"]
    target.native = StopDevice.native
    target.residue = "productRootNfqueueResidueClean=false\n"
    reject(lambda: collector.stop_audit(target, output, "1846", "residue-"), "independent")
    audit = json.loads((output / "residue-stop-audit.json").read_text())
    assert audit["native_zero"] and not audit["capture_residue_clean"]
    target.residue = StopDevice.residue
    target.queues = "176 0 0 2 4096 0 0 1 1\n"
    reject(lambda: collector.stop_audit(target, output, "1846", "queue-"), "independent")
    target.queues = "42 0 0 2 4096 0 0 1 1\n"
    assert collector.stop_audit(target, output, "1846", "unrelated-")["product_queues_absent"]

print("Root batch qualification / CPU-window regression checks: PASS")
