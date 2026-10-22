#!/usr/bin/env python3
"""Overlay bounded S306 credit-reject timestamps with an off-CPU perf record."""

import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(path, prefix):
    return [{key: int(value) for key, value in re.findall(r"(\w+)=([0-9]+)", line)}
            for line in path.read_text().splitlines() if line.startswith(prefix)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--record", type=Path, required=True)
    parser.add_argument("--symfs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, default=Path(
        "/home/js/.local/share/android-sdk/ndk/29.0.14206865/simpleperf"))
    args = parser.parse_args()
    run = json.loads(args.run.read_text())
    if run["status"] != "COMPLETE" or len(run["cases"]) != 1:
        raise ValueError("one complete Product window required")
    case = run["cases"][0]
    cell = args.run.parent / "vpn-udp-fixed"
    rejects = records(cell / "after-cli.txt", "s306.reject ")
    start = case["client"]["start_monotonic_ns"]
    end = case["client"]["end_monotonic_ns"]
    rejects = [row for row in rejects if start <= row["at_ns"] < end]
    sys.path.insert(0, str(args.sdk))
    from simpleperf_report_lib import ReportLib

    lib = ReportLib()
    lib.SetRecordFile(str(args.record))
    lib.SetSymfs(str(args.symfs))
    metadata = lib.MetaInfo()
    if metadata.get("trace_offcpu") != "true":
        raise ValueError("record has no off-CPU tracing")
    record_stats = {key: int(value) for key, value in
                    (part.split("=", 1) for part in metadata["record_stat"].split(","))}
    lib.SetTraceOffCpuMode("off-cpu")
    intervals = {}
    while (sample := lib.GetNextSample()) is not None:
        if sample.pid != case["vpp_pid"] or not sample.thread_comm.startswith("vpp_wk_"):
            continue
        if sample.time + sample.period <= start or sample.time >= end:
            continue
        raw = lib.GetTracingDataOfCurrentSample()
        chain = lib.GetCallChainOfCurrentSample()
        names = [lib.GetSymbolOfCurrentSample().symbol_name]
        names.extend(chain.entries[i].symbol.symbol_name for i in range(chain.nr))
        reason = ("epoll" if "do_epoll_wait" in names else
                  "preempted" if "preempt_schedule" in names else "other")
        intervals.setdefault(sample.tid, []).append(dict(
            start_ns=sample.time, end_ns=sample.time + sample.period,
            prev_state=int(raw["prev_state"]), reason=reason))
    lib.Close()
    by_tid = {}
    for tid, rows in intervals.items():
        rows.sort(key=lambda x: x["start_ns"])
        by_tid[tid] = [row["start_ns"] for row in rows]
    # show threads and /proc affinity retained by the collector identify the
    # logical owner position. vpp_wk_0/1 are thread indices 1/2 in N=2 VPN.
    names = {int(row["name"][-1]): row["tid"]
             for row in case["worker_layout"]
             if row["name"] in ("vpp_wk_0", "vpp_wk_1")}
    if names.keys() != {0, 1}:
        raise ValueError("cannot establish both owner TIDs")
    for row in rejects:
        tid = names[row["owner"]]
        starts = by_tid.get(tid, [])
        index = bisect_right(starts, row["at_ns"]) - 1
        interval = intervals[tid][index] if index >= 0 else None
        row["owner_tid"] = tid
        row["owner_offcpu"] = bool(interval and row["at_ns"] < interval["end_ns"])
        row["offcpu_reason"] = interval["reason"] if row["owner_offcpu"] else "on_cpu_or_unrecorded"
        row["offcpu_prev_state"] = interval["prev_state"] if row["owner_offcpu"] else None
        row["offcpu_interval_ns"] = interval["end_ns"] - interval["start_ns"] if row["owner_offcpu"] else None
    report = dict(schema="s306-sched-overlap/v1", run=str(args.run),
                  run_sha256=digest(args.run), record=str(args.record),
                  record_sha256=digest(args.record),
                  record_stats=record_stats, owner_tids=names,
                  load_window_ns=[start, end], rejects=rejects)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(rejects=len(rejects), owner_tids=names,
                          offcpu=sum(row["owner_offcpu"] for row in rejects),
                          reasons={reason: sum(row["offcpu_reason"] == reason for row in rejects)
                                   for reason in sorted({row["offcpu_reason"] for row in rejects})},
                          record_stats=record_stats), indent=2))


if __name__ == "__main__":
    main()
