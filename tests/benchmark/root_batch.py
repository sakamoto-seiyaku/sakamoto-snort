#!/usr/bin/env python3
"""One ordinary Root cell: frozen applicable rules, VPP CPU / qualified SUCCEEDED.

Reuse a pixel_quick prepare manifest, adding rules_count, rules_revision and
applicable_rule_versions. This collector never edits rules or installs artifacts.
--inspect reads current identity/diagnostics without starting or stopping runtime.
Optional peer_control_host/peer_control_port route host queries separately from
the device traffic peer_host/peer_port (for example an adb-forwarded local peer).
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import time

import pixel_quick as quick

COMMANDS = ["show threads", "show product batch", "show product primary",
            "show product completion", "show product root receive",
            "show product root lanes", "show product flows",
            "show product policy-index", "show product rule-budget"]
SCOPE = "root_ordinary_subject_l4_succeeded"
ZERO_FIELDS = ("ready_mask", "graph_enabled", "graph_accepting", "pending",
               "buffers", "obligations", "handoffs", "completion_frames")


def save(output, name, value):
    (output / name).write_text(value if isinstance(value, str)
                               else json.dumps(value, indent=2) + "\n")
    return value


def query_peer(manifest, case_id, operation="Q"):
    return quick.peer_query(manifest.get("peer_control_host", manifest["peer_host"]),
                            manifest.get("peer_control_port", manifest["peer_port"]),
                            case_id, operation)


def marker_rows(raw, marker):
    """The identifier in batch.thread=1 is part of the row, not a prefix."""
    return [dict(re.findall(r"([\w.]+)=([^\s]+)", line[line.index(marker):]))
            for line in raw.splitlines() if marker in line]


def one_row(raw, prefix):
    values = quick.rows(raw, prefix)
    if len(values) != 1:
        raise RuntimeError("missing or ambiguous diagnostic: " + prefix)
    return values[0]


def batch(raw, expected):
    enabled, qualification = marker_rows(raw, "batch.enabled="), marker_rows(raw, "batch.qualification=")
    if len(enabled) != 1 or enabled[0]["batch.enabled"] != str(int(expected == "on")):
        raise RuntimeError("batch backend differs from --expect-batch")
    if (len(qualification) != 1 or qualification[0]["batch.qualification"] != "1"
            or qualification[0].get("scope") != SCOPE):
        raise RuntimeError("Policy-Qualified SUCCEEDED instrumentation is OFF or has the wrong scope")
    counter = int(qualification[0]["policy_qualified_succeeded"])
    if "cpu_ns" not in qualification[0]:
        raise RuntimeError("missing same-barrier VPP process CPU counter")
    cpu_ns = int(qualification[0]["cpu_ns"])
    matched_fields = ("policy_qualified_matched_allow_succeeded",
                      "policy_qualified_matched_drop_succeeded")
    if any(key not in qualification[0] for key in matched_fields):
        raise RuntimeError("missing matched verdict success counters")
    matched_allow, matched_drop = (int(qualification[0][key]) for key in matched_fields)
    if min(counter, cpu_ns, matched_allow, matched_drop) < 0:
        raise RuntimeError("negative qualified packet or VPP process CPU counter")
    if matched_allow + matched_drop > counter:
        raise RuntimeError("matched successful verdicts exceed qualified packets")
    threads = marker_rows(raw, "batch.thread=")
    if expected == "on" and sorted(int(row["batch.thread"]) for row in threads) != [0, 1, 2]:
        raise RuntimeError("candidate lacks main + W2 batch counters")
    return {"config": enabled[0], "qualified_succeeded": counter, "cpu_ns": cpu_ns,
            "matched_allow_succeeded": matched_allow, "matched_drop_succeeded": matched_drop,
            "threads": threads}


def thread_layout(raw):
    values = []
    for line in raw.splitlines():
        match = re.match(r"\s*(\d+)\s+(vpp_\S+)\s+(?:workers\s+)?(\d+)\s+\S+\s+\(\d+\)\s+(\d+)", line)
        if match:
            values.append(dict(id=int(match[1]), name=match[2], tid=int(match[3]), lcore=int(match[4])))
    if sorted(value["id"] for value in values) != [0, 1, 2]:
        raise RuntimeError("ordinary Root requires VPP main + W2")
    return values


def resource_identity(raw):
    """Freeze capacity and placement, independently of memory cost/occupancy."""
    fields = {"root.receive ": ("lane", "family", "queue", "flags", "maxlen", "allocated"),
              "root.lane ": ("lane", "family", "family_lane", "worker", "thread", "queue"),
              "flow.runtime ": ("worker", "capacity")}
    result = {prefix.strip(): sorted([{key: row[key] for key in keys}
                                      for row in quick.rows(raw, prefix)], key=lambda row: json.dumps(row, sort_keys=True))
              for prefix, keys in fields.items()}
    capacity = one_row(raw, "capacity.status ")
    result["capacity.status"] = {key: capacity[key]
                                 for key in ("credits", "primary_slots", "completion_slots")}
    result["threads"] = [{key: row[key] for key in ("id", "name", "lcore")}
                         for row in thread_layout(raw)]
    if len(result["flow.runtime"]) != 2 or not result["root.receive"] or not result["root.lane"]:
        raise RuntimeError("incomplete Root resource identity")
    return result


def memory_footprint(raw):
    """Observe allocator cost without turning it into an A/B capacity gate."""
    flows = sorted([{key: int(row[key]) for key in ("worker", "allocated_bytes", "entry_bytes")}
                    for row in quick.rows(raw, "flow.runtime ")], key=lambda row: row["worker"])
    return {"flow_workers": flows,
            "flow_allocated_bytes_total": sum(row["allocated_bytes"] for row in flows)}


def rule_source(device, manifest, output, label, strict=True):
    encoded = device.root("base64 " + shlex.quote(manifest["rules_path"]), cleanup=True)
    payload = base64.b64decode("".join(encoded.split()), validate=True)
    (output / (label + "-rules.conf")).write_bytes(payload)
    if hashlib.sha256(payload).hexdigest() != manifest["rules_sha256"]:
        raise RuntimeError("frozen rule-source SHA-256 changed")
    # Decode identities only. VPP remains the sole compiler/evaluator.
    if len(payload) < 24 or payload[:8] not in (b"SKRULE02", b"SKRULE03", b"SKRULE04", b"SKRULE05", b"SKRULE06"):
        raise RuntimeError("unsupported or truncated rule-source identity header")
    revision, count, retained = struct.unpack_from("<QII", payload, 8)
    # product_rule_config.c encode()/RULE_FIELDS: two u64 identities, sixteen
    # u32 fields, two 16-byte addresses; SKRULE04+ adds u32 length + 64 bytes.
    stride = 2 * 8 + 16 * 4 + 2 * 16 + (4 + 64 if payload[:8] >= b"SKRULE04" else 0)
    if len(payload) < 24 + retained * 8 + count * stride:
        raise RuntimeError("truncated rule-source identities")
    versions = [struct.unpack_from("<Q", payload, 24 + retained * 8 + i * stride)[0]
                for i in range(count)]
    identity = {"revision": revision, "count": count, "versions": versions}
    save(output, label + "-rule-identity.json", identity)
    if (strict and count <= 0
            or "rules_count" in manifest and count != manifest["rules_count"]
            or "rules_revision" in manifest and revision != manifest["rules_revision"]):
        raise RuntimeError("nonempty frozen rule count/revision mismatch")
    if not set(manifest.get("applicable_rule_versions", [])).issubset(versions):
        raise RuntimeError("selected applicable rule versions are absent from the frozen source")
    return identity


def matching_flows(raw, manifest, case):
    peer_key = "0" * 24 + socket.inet_aton(manifest["peer_host"]).hex()
    protocol = 17 if case.startswith("udp-") else 6
    last_port = manifest["peer_port"] + (63 if protocol == 17 else 0)
    return [row for row in quick.rows(raw, "flow.entry ")
            if int(row.get("uid", -1)) == manifest["uid"]
            and int(row.get("protocol", 0)) == protocol
            and int(row.get("revision", 0)) == manifest["rules_revision"]
            and row.get("decision") == "1"
            and any(row.get("key_" + side) == peer_key
                    and manifest["peer_port"] <= int(row.get("port_" + side, 0)) <= last_port
                    for side in ("a", "b"))]


def sum_delta(before, after, prefix, field):
    value = sum(int(row.get(field, 0)) for row in quick.rows(after, prefix)) - sum(
        int(row.get(field, 0)) for row in quick.rows(before, prefix))
    if value < 0:
        raise RuntimeError("diagnostic counter moved backwards: " + prefix + field)
    return value


def validate_window(manifest, case, expected, generation, before, after):
    old, new = batch(before, expected), batch(after, expected)
    if old["config"] != new["config"] or thread_layout(before) != thread_layout(after):
        raise RuntimeError("batch configuration or VPP thread identity changed")
    identity = resource_identity(before)
    if resource_identity(after) != identity or (manifest.get("resource_identity") is not None
                                                and manifest["resource_identity"] != identity):
        raise RuntimeError("Root resource identity changed or differs from manifest")
    for raw in (before, after):
        for prefix in ("root.receive ", "root.lane ", "primary.status ", "completion.status ",
                       "flow.runtime ", "policy.snapshot ", "policy.worker "):
            values = quick.rows(raw, prefix)
            if not values or any(row.get("generation") != str(generation) for row in values):
                raise RuntimeError("capture/policy generation changed or is missing: " + prefix)
        budget = one_row(raw, "rule.budget ")
        if (budget.get("saved") != str(manifest["rules_revision"])
                or budget.get("active") != str(manifest["rules_revision"])
                or budget.get("compile_error") != "0"):
            raise RuntimeError("frozen rule revision is not active")
        snapshot = one_row(raw, "policy.snapshot ")
        if snapshot.get("revision") != str(manifest["rules_revision"]):
            raise RuntimeError("policy snapshot revision mismatch")
        plan = one_row(raw, "policy.plan ")
        if sum(int(plan[key]) for key in ("direct", "factorized", "residual")) <= 0:
            raise RuntimeError("active effective rule plan is empty")
    frozen = lambda raw: {key: one_row(raw, "policy.snapshot ")[key]
                         for key in ("generation", "revision", "snapshot_hash", "sequence", "publications")}
    if frozen(before) != frozen(after):
        raise RuntimeError("policy was republished during the cell")
    q = new["qualified_succeeded"] - old["qualified_succeeded"]
    if q <= 0:
        raise RuntimeError("no positive Policy-Qualified SUCCEEDED delta")
    matched_allow = new["matched_allow_succeeded"] - old["matched_allow_succeeded"]
    matched_drop = new["matched_drop_succeeded"] - old["matched_drop_succeeded"]
    if matched_allow <= 0:
        raise RuntimeError("no positive matched Allow SUCCEEDED delta")
    if matched_drop != 0:
        raise RuntimeError("Allow workload has changed or nonzero matched Drop settlements")
    if matched_allow != q:
        raise RuntimeError("Allow workload qualified packets lack complete matching winners")
    process_cpu_ns = new["cpu_ns"] - old["cpu_ns"]
    if process_cpu_ns <= 0:
        raise RuntimeError("same-barrier VPP process CPU counter did not advance")
    quick.validate_capture_window("root", {"case": case, "bytes": 1}, before, after)
    flow_key = lambda row: tuple(row.get(key) for key in ("worker", "slot", "incarnation"))
    prior = {flow_key(row): int(row["packets"]) for row in matching_flows(before, manifest, case)}
    applicable = [row for row in matching_flows(after, manifest, case)
                  if row.get("policy_generation") == str(generation)
                  and int(row["packets"]) > prior.get(flow_key(row), 0)]
    flow_creates = flow_closed = None
    if case == "tcp-new":
        def protocol_count(raw, field):
            return sum(int(row[field]) for row in quick.rows(raw, "flow.protocol ")
                       if row.get("protocol") == "tcp")
        flow_creates = protocol_count(after, "creates") - protocol_count(before, "creates")
        flow_closed = protocol_count(after, "closed") - protocol_count(before, "closed")
        if flow_creates <= 0 or flow_closed <= 0:
            raise RuntimeError("TCP churn lacks actual Flow create/end progress")
    elif not applicable:
        raise RuntimeError("load has no progressing app-UID/peer/protocol FlowEntry")
    lane_delta = {key: sum_delta(before, after, "root.lane ", key)
                  for key in ("captured", "submitted", "verdicts", "succeeded", "failed", "duplicate")}
    if lane_delta["succeeded"] < q:
        raise RuntimeError("qualified delta exceeds successful Root verdicts")
    receive_delta = {key: sum_delta(before, after, "root.receive ", key)
                     for key in ("datagrams", "ingress_accepts", "reserve_accepts", "reserve_losses", "identity_losses")}
    thread_deltas = []
    for a, b in zip(old["threads"], new["threads"]):
        delta = {key: int(b[key]) - int(a[key]) for key in b if key != "batch.thread"
                 and key != "policy_hold_max_ns"}
        if a["batch.thread"] != b["batch.thread"] or any(value < 0 for value in delta.values()):
            raise RuntimeError("batch thread identity/counters changed")
        thread_deltas.append({"thread": int(b["batch.thread"]), **delta,
                              "policy_hold_max_ns_after": int(b["policy_hold_max_ns"])})
    totals = {key: sum(row[key] for row in thread_deltas) for key in thread_deltas[0]
              if key not in ("thread", "policy_hold_max_ns_after")} if thread_deltas else {}
    ratios = {name: totals[vectors] / totals[publications] if totals.get(publications) else None
              for name, vectors, publications in (
                  ("admit_vectors_per_frame", "admit_vectors", "admit_frames"),
                  ("prepared_packets_per_window", "prepared_packets", "prepare_windows"),
                  ("primary_vectors_per_publication", "primary_vectors", "primary_publications"),
                  ("policy_packets_per_claim", "policy_packets", "policy_claims"),
                  ("completion_vectors_per_publication", "completion_vectors", "completion_publications"),
                  ("origin_vectors_per_frame", "origin_vectors", "origin_frames"))} if totals else {}
    return {"policy_qualified_succeeded": q, "qualification_scope": SCOPE,
            "policy_qualified_matched_allow_succeeded": matched_allow,
            "policy_qualified_matched_drop_succeeded": matched_drop,
            "vpp_process_cpu_ns_delta": process_cpu_ns,
            "vpp_process_cpu_seconds": process_cpu_ns / 1e9,
            "qualified_boundary_counters": {
                "before": {"policy_qualified_succeeded": old["qualified_succeeded"],
                           "matched_allow_succeeded": old["matched_allow_succeeded"],
                           "matched_drop_succeeded": old["matched_drop_succeeded"], "cpu_ns": old["cpu_ns"]},
                "after": {"policy_qualified_succeeded": new["qualified_succeeded"],
                          "matched_allow_succeeded": new["matched_allow_succeeded"],
                          "matched_drop_succeeded": new["matched_drop_succeeded"], "cpu_ns": new["cpu_ns"]}},
            "unqualified_succeeded": lane_delta["succeeded"] - q,
            "qualified_fraction_of_succeeded": q / lane_delta["succeeded"],
            "applicable_flows": applicable, "resource_identity": identity,
            "tcp_churn_flow_creates": flow_creates, "tcp_churn_flow_closed": flow_closed,
            "memory_footprint_before": memory_footprint(before),
            "memory_footprint_after": memory_footprint(after),
            "root_lane_deltas": lane_delta, "root_receive_deltas": receive_delta,
            "flow_capacity_misses": sum_delta(before, after, "flow.runtime ", "capacity_misses"),
            "batch_thread_deltas": thread_deltas, "batch_totals": totals, "batch_ratios": ratios}


def cpu_summary(raw, client, layout):
    samples = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    selected = [row for row in samples if client["start_monotonic_ns"] <= row["monotonic_ns"] <= client["end_monotonic_ns"]]
    if len(selected) < 2:
        raise RuntimeError("insufficient VPP CPU samples inside actual client start/end")
    expected = {row["tid"] for row in layout}
    first = selected[0]
    for row in selected:
        if (row["pid"] != first["pid"] or row["clock_ticks"] != first["clock_ticks"]
                or {thread["tid"] for thread in row["threads"]} != expected):
            raise RuntimeError("VPP process/thread CPU sample identity changed")
    summary = quick.monitor_summary(raw, client)
    seconds = (client["end_monotonic_ns"] - client["start_monotonic_ns"]) / 1e9
    summary["coverage_fraction"] = summary["sample_coverage_seconds"] / seconds
    summary["sample_start_monotonic_ns"] = selected[0]["monotonic_ns"]
    summary["sample_end_monotonic_ns"] = selected[-1]["monotonic_ns"]
    summary["estimated_full_client_cpu_seconds"] = summary["cpu_seconds"] / summary["coverage_fraction"]
    if summary["coverage_fraction"] < .90 or summary["cpu_seconds"] <= 0:
        raise RuntimeError("VPP CPU coverage is below 90% or CPU did not advance")
    if any(row["cpu_seconds"] < 0 for row in summary["threads"]):
        raise RuntimeError("VPP CPU counter moved backwards")
    return summary


def stop_audit(device, output, generation, label=""):
    """Ordinary stop, then independent native-zero and capture-residue evidence."""
    save(output, label + "stop.txt", device.action("--ez", "runtimeStop", "true", cleanup=True))
    stopped = save(output, label + "stopped.json", device.wait_state("stopped", cleanup=True))
    device.wait_process_gone("libvpp_runtime.so", cleanup=True)
    tail = save(output, label + "native-stop.txt", device.command("shell", "run-as", quick.PACKAGE,
                "tail", "-n", "12", "files/product-state/s242-last-stop.log", cleanup=True))
    residue = save(output, label + "root-residue.properties", device.command("shell", "run-as", quick.PACKAGE,
                   "cat", "files/product-state/s176-root-nfqueue-cleanup.properties", cleanup=True))
    queues = save(output, label + "kernel-queues-after.txt", device.root("cat /proc/net/netfilter/nfnetlink_queue", cleanup=True))
    hooks = save(output, label + "kernel-hooks-after.txt", device.root("iptables-save -t mangle; ip6tables-save -t mangle", cleanup=True))
    audit = quick.rows(tail, "s242 event=stop_native_zero ")
    native_zero = len(audit) == 1 and audit[0].get("generation") == str(generation) and all(audit[0].get(key) == "0" for key in ZERO_FIELDS)
    clean = quick.properties(residue).get("productRootNfqueueResidueClean") == "true"
    product_queues = [line for line in queues.splitlines() if line.split() and line.split()[0].isdigit()
                      and 176 <= int(line.split()[0]) <= 179]
    audit_result = {"runtime": stopped, "native_zero": native_zero, "capture_residue_clean": clean,
                    "product_hooks_absent": "SAKAMOTO_PRODUCT_S17" not in hooks.upper(),
                    "product_queues_absent": not product_queues}
    save(output, label + "stop-audit.json", audit_result)
    if not all(audit_result[key] for key in ("native_zero", "capture_residue_clean", "product_hooks_absent", "product_queues_absent")):
        raise RuntimeError("ordinary stop failed independent native_zero/capture-residue audit")
    return audit_result


def manifest_check(manifest, strict=True):
    for key in ("serial", "uid", "apk", "apk_sha256", "rules_path", "rules_sha256",
                "source_sha256",
                "android_binary", "android_sha256", "remote", "peer_host", "peer_port"):
        if key not in manifest:
            raise RuntimeError("missing frozen manifest field: " + key)
    if not strict:
        return
    if (not isinstance(manifest.get("rules_count"), int) or manifest["rules_count"] <= 0
            or not isinstance(manifest.get("rules_revision"), int) or manifest["rules_revision"] <= 0
            or not manifest.get("applicable_rule_versions")
            or any(not isinstance(version, int) or version <= 0 for version in manifest["applicable_rule_versions"])):
        raise RuntimeError("manifest requires nonempty rules and positive applicable rule identities")


def run(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    result = {"schema": 1, "status": "INCOMPLETE", "errors": [], "case": args.case,
              "profile": "root", "expect_batch": args.expect_batch, "started_utc_ns": time.time_ns(),
              "runner_sha256": quick.digest(__file__), "measurement": None}
    device = None
    active, monitor_pid, generation = False, None, None
    try:
        manifest = result["manifest"] = json.loads(args.manifest.read_text())
        manifest_check(manifest, strict=not args.inspect)
        burst_size = manifest.get("udp_burst_size", 1)
        if (not isinstance(burst_size, int) or not 1 <= burst_size <= 16 * manifest.get("threads", 4)
                or burst_size > 1 and (args.case != "udp-fixed" or not manifest.get("offered_rate"))):
            raise RuntimeError("UDP burst requires a frozen paced UDP workload and a bounded burst size")
        result["peer_identity"] = {"transport": manifest.get("transport", "unspecified"),
                                   "traffic_host": manifest["peer_host"], "traffic_port": manifest["peer_port"],
                                   "control_host": manifest.get("peer_control_host", manifest["peer_host"]),
                                   "control_port": manifest.get("peer_control_port", manifest["peer_port"])}
        cell_ms = args.cell_ms or manifest.get("cell_ms", 10000)
        if not 3000 <= cell_ms <= 60000:
            raise RuntimeError("cell_ms must be 3000..60000 for sufficient CPU coverage")
        if args.cell_ms is not None and manifest.get("cell_ms", cell_ms) != cell_ms:
            raise RuntimeError("--cell-ms differs from the frozen manifest")
        result["cell_ms"] = cell_ms
        device = quick.Device(manifest["serial"], output)
        helper = manifest["remote"] + "/socket-load"
        device.helper = helper
        save(output, "initial-runtime.json", device.state())
        actual_uid = device.command("shell", "run-as", quick.PACKAGE, "id", "-u").strip()
        model = device.command("shell", "getprop", "ro.product.model").strip()
        if actual_uid != str(manifest["uid"]) or model != "Pixel 6a":
            raise RuntimeError("prepared app UID or Pixel 6a device identity mismatch")
        if quick.digest(quick.SOURCE) != manifest["source_sha256"] or quick.digest(manifest["android_binary"]) != manifest["android_sha256"]:
            raise RuntimeError("prepared helper source/artifact changed")
        actual = save(output, "installed-identity.txt", device.root("sha256sum " + shlex.join([manifest["apk"], manifest["rules_path"], helper])))
        if [line.split()[0] for line in actual.splitlines()] != [manifest["apk_sha256"], manifest["rules_sha256"], manifest["android_sha256"]]:
            raise RuntimeError("APK, rule source or installed helper identity mismatch")
        result["rule_identity"] = rule_source(device, manifest, output, "before", strict=not args.inspect)
        if args.inspect:
            state = device.state()
            if state.get("state") == "running" and state.get("profile") == "root":
                diagnostic = save(output, "inspect-cli.txt", device.cli("root", COMMANDS))
                result["resource_identity"] = resource_identity(diagnostic)
                result["memory_footprint"] = memory_footprint(diagnostic)
                result["batch"] = batch(diagnostic, args.expect_batch)
            result["status"] = "INSPECTED"
        else:
            state = device.state()
            if state.get("state") != "stopped" or state.get("mayBeActive") != "false":
                raise RuntimeError("Root batch cell requires initially stopped runtime")
            case_id = manifest.get("case_id", 0)
            peer_before = query_peer(manifest, case_id, "R")
            save(output, "peer-before.json", peer_before)
            active = True
            save(output, "start.txt", device.action("--ez", "runtimeStart", "true", "--es", "runtimeProfile", "root"))
            running = save(output, "running.json", device.wait_state("running", "root"))
            generation = result["generation"] = running["generation"]
            pids = device.command("shell", "pidof", "libvpp_runtime.so").strip().split()
            if len(pids) != 1 or not pids[0].isdigit():
                raise RuntimeError("ambiguous VPP PID")
            pid = result["vpp_pid"] = int(pids[0])
            startup = save(output, "startup.conf", device.command("shell", "run-as", quick.PACKAGE, "cat", "files/profiles/root/vpp/startup.conf"))
            result["startup_sha256"] = hashlib.sha256(startup.encode()).hexdigest()
            save(output, "owner.properties", device.command("shell", "run-as", quick.PACKAGE, "cat", "files/profiles/root/vpp/owner.properties"))
            # Warm the actual workload and UID; warm counters are excluded by the before CLI.
            def client_command(duration, identity):
                argv = [helper, "client", manifest["peer_host"], str(manifest["peer_port"]), str(identity), args.case,
                        str(duration), str(manifest.get("threads", 4)), str(manifest.get("flows_per_thread", 16))]
                if manifest.get("offered_rate") or (args.case == "udp-fixed" and manifest.get("udp_fixed_source_port_base")):
                    argv += [str(manifest.get("udp_fixed_source_port_base", 0) if args.case == "udp-fixed" else 0),
                             str(manifest.get("udp_fixed_source_port_stride", 1))]
                if manifest.get("offered_rate"):
                    argv += [str(manifest["offered_rate"])]
                    if "udp_burst_size" in manifest:
                        argv += [str(burst_size)]
                return ["shell", "su", str(manifest["uid"]), "-c", shlex.quote(shlex.join(argv))]
            warmup_ms = manifest.get("warmup_ms", 2000)
            if not isinstance(warmup_ms, int) or not 100 <= warmup_ms <= 10000:
                raise RuntimeError("warmup_ms must be frozen within 100..10000")
            query_peer(manifest, 14, "R")
            warm = save(output, "warm.json", device.command(*client_command(warmup_ms, 14), timeout=warmup_ms / 1000 + 3))
            if json.loads(warm).get("uid") != manifest["uid"] or not json.loads(warm).get("bytes"):
                raise RuntimeError("actual app-UID workload warmup failed")
            query_peer(manifest, case_id, "R")
            before_start = time.monotonic_ns()
            before = save(output, "before-cli.txt", device.cli("root", COMMANDS))
            before_end = time.monotonic_ns()
            batch(before, args.expect_batch)
            layout = thread_layout(before)
            remote_cpu = manifest["remote"] + "/root-batch-" + hashlib.sha256(str(output).encode()).hexdigest()[:12] + "-cpu.jsonl"
            monitor = shlex.join([helper, "monitor", str(pid), str(min(cell_ms + 1500, 61000))]) + " > " + shlex.quote(remote_cpu) + " 2>&1 < /dev/null & echo monitor=$!"
            monitor_text = save(output, "sampler.txt", device.root(monitor))
            monitor_pid = quick.properties(monitor_text).get("monitor")
            if not monitor_pid or not monitor_pid.isdigit():
                raise RuntimeError("invalid owned CPU monitor PID")
            value = save(output, "client.json", device.command(*client_command(cell_ms, case_id), timeout=cell_ms / 1000 + 3))
            client = json.loads(value)
            if (client["uid"] != manifest["uid"] or client["case"] != args.case
                    or client["requested_ms"] != cell_ms
                    or client["end_monotonic_ns"] - client["start_monotonic_ns"] < cell_ms * 1000000):
                raise RuntimeError("client UID/case/full measurement duration mismatch")
            if manifest.get("offered_rate"):
                offered = manifest["offered_rate"]
                if client.get("offered_rate") != offered:
                    raise RuntimeError("client differs from the frozen offered rate")
                if "udp_burst_size" in manifest and client.get("burst_size") != burst_size:
                    raise RuntimeError("client differs from the frozen UDP burst size")
                units = client["packets"] if args.case == "udp-fixed" else client["attempts"]
                actual_rate = units * 1e9 / (client["end_monotonic_ns"] - client["start_monotonic_ns"])
                if not .95 * offered <= actual_rate <= 1.05 * offered:
                    raise RuntimeError("actual offered rate differs from frozen target by more than 5 percent")
            if args.case == "tcp-new" and client["completed"] <= 0:
                raise RuntimeError("TCP churn has no completed connections")
            after_begin = time.monotonic_ns()
            after = save(output, "after-cli.txt", device.cli("root", COMMANDS))
            after_end = time.monotonic_ns()
            final_running = save(output, "after-runtime.json", device.state())
            if any(final_running.get(key) != running.get(key) for key in ("state", "profile", "generation", "protectionRunning")):
                raise RuntimeError("ordinary Root generation/protection changed during cell")
            if device.command("shell", "pidof", "libvpp_runtime.so").strip() != str(pid):
                raise RuntimeError("VPP process changed during cell")
            startup_after = device.command("shell", "run-as", quick.PACKAGE, "cat", "files/profiles/root/vpp/startup.conf")
            if startup_after != startup:
                raise RuntimeError("VPP startup configuration changed during cell")
            peer = save(output, "peer.json", query_peer(manifest, case_id))
            cpu_raw = save(output, "cpu.jsonl", device.root("cat " + shlex.quote(remote_cpu)))
            cpu = cpu_summary(cpu_raw, client, layout)
            qualified = validate_window(manifest, args.case, args.expect_batch, generation, before, after)
            base_score = quick.score(client, peer, cpu, after, before)
            q = qualified["policy_qualified_succeeded"]
            process_cpu = qualified["vpp_process_cpu_seconds"]
            result["measurement"] = {"client": client, "peer": peer, "cpu": cpu, **qualified,
                 "diagnostic_host_bounds_ns": {"before_start": before_start, "before_end": before_end,
                                               "after_start": after_begin, "after_end": after_end},
                 "score": {**base_score, "policy_throughput_qualified": True,
                           "qualification": SCOPE, "policy_qualified_succeeded": q,
                           "vpp_cpu_seconds": process_cpu,
                           "vpp_cpu_seconds_per_policy_qualified_succeeded": process_cpu / q,
                           "sampled_client_vpp_cpu_seconds": cpu["cpu_seconds"],
                           "primary_cpu_window": "CLOCK_PROCESS_CPUTIME_ID and Q share before/after batch CLI barriers; diagnostic overhead included",
                           "sampler_cpu_window": "only monitor samples inside actual client start/end; independent observation and coverage",
                           "throughput_latency_window": "actual client start/end",
                           "qualification_window": "before/after batch CLI barriers; includes diagnostic boundary gaps"}}
            save(output, "result.json", result)
            result["stop_audit"] = stop_audit(device, output, generation)
            active = False
            result["status"] = "COMPLETE"
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        if device is not None and monitor_pid:
            try:
                device.root("kill -TERM " + monitor_pid + " 2>/dev/null || true", cleanup=True)
            except Exception as error:
                result["errors"].append("monitor cleanup: " + str(error))
        if active and device is not None:
            try:
                if generation is not None:
                    result["cleanup_stop_audit"] = stop_audit(device, output, generation, label="cleanup-")
                else:
                    save(output, "stop.txt", device.action("--ez", "runtimeStop", "true", cleanup=True))
                    save(output, "stopped.json", device.wait_state("stopped", cleanup=True))
                    device.wait_process_gone("libvpp_runtime.so", cleanup=True)
            except Exception as error:
                result["errors"].append("ordinary stop cleanup: " + str(error))
        if device is not None and "manifest" in result and (output / "before-rules.conf").exists():
            try:
                rule_source(device, result["manifest"], output, "after", strict=not args.inspect)
                result["rules_unchanged"] = True
            except Exception as error:
                result["rules_unchanged"] = False
                result["errors"].append("final rule identity: " + str(error))
        if device is not None and not args.inspect and generation is not None:
            try:
                final = result["final_runtime"] = save(output, "final-runtime.json", device.state(cleanup=True))
                processes = save(output, "final-processes.txt", device.command("shell", "pidof", "libvpp_runtime.so", check=False, cleanup=True))
                if final.get("state") != "stopped" or final.get("mayBeActive") != "false" or processes.strip():
                    raise RuntimeError("final ordinary Root state/process audit failed")
            except Exception as error:
                result["errors"].append("final runtime audit: " + str(error))
        result["elapsed_seconds"] = time.monotonic() - started
        if result["errors"]:
            result["status"] = "INCOMPLETE"
        save(output, "result.json", result)
        print(json.dumps({key: result[key] for key in ("status", "elapsed_seconds", "errors")}, indent=2))
    return 0 if result["status"] in ("COMPLETE", "INSPECTED") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("root",), default="root")
    parser.add_argument("--case", choices=("udp-fixed", "tcp-fixed", "tcp-new"), default="udp-fixed")
    parser.add_argument("--expect-batch", choices=("off", "on"), required=True)
    parser.add_argument("--cell-ms", type=int)
    parser.add_argument("--inspect", "--snapshot", dest="inspect", action="store_true")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
