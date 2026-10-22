#!/usr/bin/env python3
"""Verify raw S307 campaigns and expose measured denominators and limits."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

import pixel_quick as quick
from s304_summary import counter_delta, evidence_path


ROOT = Path(__file__).resolve().parents[2]


def read(path):
    return json.loads(path.read_text())


def verify_cpu_summary(raw, client, recorded):
    # Historical rows predate interval metadata. Recompute their original full
    # schema exactly; when either interval endpoint is supplied, require both
    # endpoints and all original CPU evidence to match the raw samples.
    cpu = quick.monitor_summary(raw, client, include_interval=any(
        key in recorded for key in ('begin_monotonic_ns', 'end_monotonic_ns')))
    assert cpu == recorded
    return cpu


def summarize(path, snapshots, runners, *, allow_profile=False):
    campaign = read(path / "campaign.json")
    assert campaign["status"] == "COMPLETE" and not campaign["errors"]
    assert campaign["runner_sha256"] in runners
    if "plan_sha256" in campaign:
        assert quick.digest(path / "plan.json") == campaign["plan_sha256"]
    assert campaign["restored_apk_sha256"] == "cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110"
    assert campaign["final_runtime"]["state"] == "stopped" and not campaign["final_vpp_pid"]
    identities = {}
    for identity in path.glob("install*/identity.json"):
        value = read(identity)
        apk = evidence_path(value["apk"], ROOT)
        assert quick.digest(apk) == value["apk_sha256"]
        with zipfile.ZipFile(apk) as archive:
            native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                      for name in archive.namelist()
                      if name.startswith("lib/arm64-v8a/") and name.endswith(".so")}
        assert native == value["native_sha256"]
        identities[value["apk_sha256"]] = value
    result_rows = []
    for run in campaign["runs"]:
        assert run["status"] == "COMPLETE" and run["returncode"] == 0
        result_path = path / ("run-" + run["label"]) / "result.json"
        result = read(result_path)
        manifest = result["manifest"]
        assert result["status"] == "COMPLETE" and not result["errors"]
        assert result["runner_sha256"] == manifest["collector_sha256"]
        assert result["runner_sha256"] in snapshots
        assert manifest["apk_sha256"] in identities
        for key in ("android", "host"):
            assert quick.digest(evidence_path(manifest[key + "_binary"], ROOT)) == manifest[key + "_sha256"]
        assert quick.digest(quick.SOURCE) == manifest["source_sha256"]
        assert manifest["client_cpu_mask"] == "10" and manifest["tun_io_cpu_id"] == 3
        assert allow_profile or not manifest["profiling"]
        assert result["rules_unchanged"] and not result["final_processes"]
        assert result["final_runtime"]["state"] == "stopped"
        assert len(result["cases"]) == 1
        case = result["cases"][0]
        client, peer = case["client"], case["peer"]
        cell = result_path.parent / ("vpn-" + case["case"])
        before, after = ((cell / (name + "-cli.txt")).read_text() for name in ("before", "after"))
        owners = manifest["worker_cpu_ids"]
        quick.validate_vpn_window(case["generation"], client, before, after, len(owners))
        quick.validate_vpn_stop((cell / "native-stop.txt").read_text(), case["generation"], len(owners))
        quick.validate_vpn_layout(case["worker_layout"], owners, 3, before)
        credits = manifest["primary_handoff_credits"]
        assert credits == run["credits"] and credits in (32, 48)
        for text in (before, after):
            status = quick.rows(text, "capacity.status ")
            assert len(status) == 1 and status[0] == dict(credits=str(credits), primary_slots="64", completion_slots="128")
            if "vpn_capture_batch_size" in manifest:
                assert quick.rows(text, "tun.capture_batch ")[0]["limit"] == str(manifest["vpn_capture_batch_size"])
        cpu = verify_cpu_summary((cell / "cpu.jsonl").read_text(), client, case["cpu"])
        score = quick.score(client, peer, cpu, after, before)
        assert score == case["score"]
        elapsed = (client["end_monotonic_ns"] - client["start_monotonic_ns"]) / 1e9
        faults = {key: counter_delta(before, after, prefix, field) for key, prefix, field in (
            ("credit", "primary.rejection ", "credit"), ("enqueue", "primary.rejection ", "enqueue"),
            ("alloc_failures", "tun.capture_capacity ", "alloc_failures"),
            ("read_pauses", "tun.capture_capacity ", "read_pauses"),
            ("read_resumes", "tun.capture_capacity ", "read_resumes"),
            ("write_failed", "tun.flow_stack ", "write_failed"),
            ("return_no_credit", "tun.return_detail ", "no_credit"),
            ("return_no_stamp", "tun.return_detail ", "no_stamp"),
            ("return_no_buffer", "tun.return_detail ", "no_buffer"))}
        assert all(value >= 0 for value in faults.values())
        pool = re.search(r"^default-numa-\S+\s+\d+\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)", after, re.M)
        assert pool and tuple(map(int, pool.groups())) == (10496, 10240, 2048)
        # The prefix includes the first key, unlike rows()'s ordinary prefixes.
        batch = [dict(word.split("=", 1) for word in line.split() if "=" in word)
                 for line in after.splitlines() if line.startswith("batch.thread=")]
        batch_before = [dict(word.split("=", 1) for word in line.split() if "=" in word)
                        for line in before.splitlines() if line.startswith("batch.thread=")]
        io = next((row for row in batch if row["batch.thread"] == str(len(owners) + 1)), None)
        old_io = next((row for row in batch_before if row["batch.thread"] == str(len(owners) + 1)), None)
        io_delta = ({key: int(io[key]) - int(old_io[key]) for key in
                     ("admit_frames", "admit_vectors", "primary_calls", "primary_publications", "primary_vectors")}
                    if io and old_io else None)
        holds = []
        for owner, (old, new) in enumerate(zip(quick.rows(before, "s306.owner="), quick.rows(after, "s306.owner="))):
            values = {key: int(new[key]) - int(old[key]) for key in new
                      if key not in ("hold_max_ns", "peak_credit_used")}
            values.update(lifetime_hold_max_ns=int(new["hold_max_ns"]),
                          lifetime_peak_credit_used=int(new["peak_credit_used"]), owner=owner)
            values["mean_hold_ns"] = values["hold_total_ns"] / values["hold_count"] if values["hold_count"] else None
            holds.append(values)
        mechanism = run.get("mechanism", path.name.startswith("s307-timing"))
        if mechanism:
            assert len(holds) == len(owners)
            assert all(value["hold_count"] > 0 and value["stamp_misses"] == 0 for value in holds)
        row = dict(label=run["label"], mechanism=mechanism,
                   apk_sha256=manifest["apk_sha256"], plugin_sha256=identities[manifest["apk_sha256"]]["native_sha256"]["libproduct_core_plugin.so"],
                   collector_sha256=manifest["collector_sha256"], generation=case["generation"],
                   case=case["case"], credits=credits, capture_batch=manifest.get("vpn_capture_batch_size"),
                   owners=owners, offered_rate=manifest.get("udp_offered_rate"),
                   elapsed_seconds=elapsed, delivered_mbps=score["delivered_mbps"],
                   loss=score["udp_loss_packets"], sent=client["packets"], received=peer["udp_received_packets"],
                   offered=client["offered_packets"], pacing_missed=client["pacing_missed"],
                   probe_requests=client["probe_requests"], latency_samples=client["latency_samples"],
                   timeouts=client["timeouts"], cancelled=client["cancelled_at_deadline"], errors=client["errors"],
                   p99_upper_us=client["p99_upper_us"], cpu=cpu,
                   cpu_seconds_estimated_window=score["vpp_cpu_seconds_estimated_window"],
                   cpu_seconds_per_delivered_gib=score["cpu_seconds_per_delivered_gib"],
                   allocated_buffer_stride_bytes=10496 * 2048, pool_data_bytes=10240 * 2048,
                   faults=faults, io_batch_delta=io_delta, hold_delta=holds,
                   raw_result=str(result_path))
        if allow_profile:
            row.update(profiling=manifest["profiling"],
                       profile_mode=run.get("profile", "none"),
                       cost_eligible=not manifest["profiling"] and not mechanism)
        if case["case"] == "udp-fixed":
            assert manifest["udp_fixed_source_port_base"] == 25000 and manifest["udp_burst_size"] == 1
            assert client["probe_requests"] == client["latency_samples"] + client["timeouts"] + client["cancelled_at_deadline"] + client["errors"] - client["udp_send_errors"]
            row["cpu_microseconds_per_received_packet"] = score["vpp_cpu_seconds_estimated_window"] * 1e6 / peer["udp_received_packets"]
        result_rows.append(row)
    return dict(campaign=str(path), rows=result_rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaigns", type=Path, nargs="+")
    parser.add_argument("--snapshots", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshots = {quick.digest(path) for path in args.snapshots.glob("*-pixel_quick.py")}
    snapshots.add(quick.digest(quick.__file__))
    runners = {quick.digest(path) for path in args.snapshots.glob("*-s307_vpn_tuning.py")}
    runners.update(quick.digest(ROOT / "tests/benchmark" / name) for name in
                   ("s307_vpn_tuning.py", "s306_vpn_credit.py"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(schema="s307-summary/v1", status="VERIFIED_RAW",
        scope="Pixel ordinary VPN descriptive windows; no adoption threshold; instrumented CPU excluded from cost comparisons",
        cohorts=[summarize(path, snapshots, runners) for path in args.campaigns]), indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
