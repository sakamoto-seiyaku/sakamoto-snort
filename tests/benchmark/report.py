#!/usr/bin/env python3
"""Offline Pixel run comparisons and exact-window simpleperf flamegraphs."""
import argparse
import collections
import html
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
SDK = Path("/home/js/.local/share/android-sdk/ndk/29.0.14206865/simpleperf")
spec = importlib.util.spec_from_file_location("pixel_quick", HERE / "pixel_quick.py")
quick = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quick)


def collect(args):
    started = time.monotonic()
    run = json.loads(args.run.read_text())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    device = quick.Device(run["manifest"]["serial"], output)
    sys.path.insert(0, str(args.sdk))
    from simpleperf_report_lib import ReportLib
    index = []
    for case in run["cases"]:
        remote = case.get("perf_remote")
        if not remote:
            continue
        name = case["profile"] + "-" + case["case"]
        record = output / (name + ".perf.data")
        record.touch()  # dev/adb needs an existing local destination for WSL path conversion
        device.command("pull", remote, record, timeout=30)
        lib = ReportLib()
        try:
            lib.SetRecordFile(str(record))
            if args.symfs:
                lib.SetSymfs(str(args.symfs.resolve()))
            metadata = lib.MetaInfo()
            if "Pixel 6a" not in metadata.get("product_props", ""):
                raise RuntimeError("perf metadata is not Pixel 6a: " + str(metadata))
            begin, end = case["client"]["start_monotonic_ns"], case["client"]["end_monotonic_ns"]
            samples, outside, unknown, first, last = 0, 0, 0, None, None
            hotspots = collections.Counter()
            while (sample := lib.GetNextSample()) is not None:
                if sample.pid != case["vpp_pid"] or not begin <= sample.time < end:
                    outside += 1
                    continue
                symbol = lib.GetSymbolOfCurrentSample()
                samples += 1
                first = sample.time if first is None else min(first, sample.time)
                last = sample.time if last is None else max(last, sample.time)
                unknown += symbol.symbol_name in ("unknown", "[unknown]") or "[+" in symbol.symbol_name
                hotspots[(symbol.dso_name, symbol.symbol_name)] += 1
        finally:
            lib.Close()
        filter_path = output / (name + ".filter")
        filter_path.write_text(f"CLOCK monotonic\nGLOBAL_BEGIN {begin}\nGLOBAL_END {end}\n")
        if not samples:
            raise RuntimeError("no VPP samples inside the actual workload: " + name)
        report_path = output / (name + "-flamegraph.html")
        command = [sys.executable, str(args.sdk / "inferno/inferno.py"), "--skip_collection", "--no_browser",
                   "--record_file", str(record), "--include-pid", str(case["vpp_pid"]),
                   "--filter-file", str(filter_path), "--report_path", str(report_path), "--title", name]
        if args.symfs:
            command += ["--symfs", str(args.symfs.resolve())]
        subprocess.run(command, check=True, cwd=output)
        data = {"case": name, "record_sha256": quick.digest(record), "metadata": metadata,
                "samples": samples, "outside_workload_samples": outside, "unknown_leaf_samples": unknown,
                "first_sample_offset_seconds": (first - begin) / 1e9,
                "last_sample_offset_seconds": (last - begin) / 1e9,
                "top_self": [{"dso": dso, "symbol": symbol, "samples": count}
                             for (dso, symbol), count in hotspots.most_common(30)],
                "flamegraph": report_path.name}
        (output / (name + "-hotspots.json")).write_text(json.dumps(data, indent=2) + "\n")
        index.append(data)
    if not index:
        raise RuntimeError("this run has no profiling artifacts")
    (output / "index.json").write_text(json.dumps({"offline_elapsed_seconds": time.monotonic() - started,
                                                  "run": str(args.run), "cases": index}, indent=2) + "\n")
    print(output / "index.json")


def compare(args):
    runs = [json.loads(path.read_text()) for path in args.runs]
    labels = args.labels or [f'B{i}' for i in range(len(runs))]
    if len(labels) != len(runs) or len(set(labels)) != len(labels):
        raise RuntimeError('comparison labels must be unique and match the runs')
    fixed = ("serial", "model", "uid", "rules_sha256", "source_sha256", "android_sha256",
             "cell_ms", "threads", "flows_per_thread", "profiling", "peer_host", "peer_port")
    for path, run in zip(args.runs, runs):
        if run["status"] != "COMPLETE" or len(run["cases"]) != 8 or run["elapsed_seconds"] > 120:
            raise RuntimeError("a comparison requires complete eight-cell runs within 120 seconds")
        for case in run['cases']:
            cell = path.parent / (case['profile'] + '-' + case['case'])
            quick.validate_capture_window(case['profile'], case['client'],
                                          (cell / 'before-cli.txt').read_text(),
                                          (cell / 'after-cli.txt').read_text())
        for key in fixed:
            if run["manifest"][key] != runs[0]["manifest"][key]:
                raise RuntimeError("benchmark parameter differs: " + key)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rows, comparison = [], []
    for index, case in enumerate(runs[0]["cases"]):
        key = (case["profile"], case["case"])
        base = case["score"]
        for version, run in enumerate(runs):
            current = run["cases"][index]
            if (current["profile"], current["case"]) != key:
                raise RuntimeError("case order changed")
            layout = lambda c: [(t["id"], t["name"], t["lcore"]) for t in c["worker_layout"]]
            if layout(current) != layout(case) or current["score"]["flow_capacity"] != case["score"]["flow_capacity"]:
                raise RuntimeError("worker layout or flow capacity changed")
            score = current["score"]
            primary = "completed_cps" if case["case"] == "tcp-new" else "input_unique_udp_tuples_per_second" if case["case"] == "udp-new" else "delivered_pps" if case["case"] == "udp-fixed" else "delivered_mbps"
            previous, value = base.get(primary), score.get(primary)
            delta = (value / previous - 1) * 100 if previous and value is not None else None
            record = {"version": labels[version], "profile": key[0], "case": key[1], "metric": primary,
                      "value": value, "change_from_b0_percent": delta, "score": score,
                      "apk_sha256": run["manifest"]["apk_sha256"]}
            comparison.append(record)
            def fmt(v):
                return "—" if v is None else f"{v:.2f}"
            rows.append("<tr>" + "".join("<td>" + html.escape(str(v)) + "</td>" for v in (
                labels[version], *key, primary, fmt(value), fmt(delta), fmt(score.get("p99_upper_us")),
                score["latency_samples"], score["flow_creates"], score["flow_capacity_misses"],
                current["client"]["errors"], current["client"]["timeouts"], fmt(score["vpp_cpu_seconds"]))) + "</tr>")
    headings = ("Version", "Profile", "Case", "Metric", "Value", "Δ B0 %", "p99 upper µs", "Samples", "Flow creates", "Capacity misses", "Errors", "Timeouts", "VPP CPU s")
    document = """<!doctype html><meta charset=utf-8><title>Pixel 6a quick baseline</title>
<style>body{font:15px system-ui;margin:28px;color:#17202b}table{border-collapse:collapse;width:100%}td,th{padding:9px;border-bottom:1px solid #ddd;text-align:right}th{background:#eee;position:sticky;top:0}td:nth-child(-n+4){text-align:left}</style>
<h1>Pixel 6a · Root + VPN · TCP + UDP</h1><p>Actual endpoint delivery and new-tuple pressure. Capacity misses and bypass remain explicit. These quick runs describe trends; they do not establish thermal steady state or full policy-path throughput.</p><table><thead><tr>"""
    document += "".join("<th>" + html.escape(h) + "</th>" for h in headings) + "</tr></thead><tbody>" + "\n".join(rows) + "</tbody></table>"
    (output / "index.html").write_text(document)
    (output / "comparison.json").write_text(json.dumps(comparison, indent=2) + "\n")
    print(output / "index.html")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    graph = sub.add_parser("collect")
    graph.add_argument("--run", type=Path, required=True)
    graph.add_argument("--output", type=Path, required=True)
    graph.add_argument("--sdk", type=Path, default=SDK)
    graph.add_argument("--symfs", type=Path)
    table = sub.add_parser("compare")
    table.add_argument("--runs", type=Path, nargs="+", required=True)
    table.add_argument("--labels", nargs='+', help='Explicit names for corrective/intermediate versions')
    table.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "collect":
        collect(args)
    else:
        compare(args)


if __name__ == "__main__":
    main()
