#!/usr/bin/env python3
"""Verify S308 raw campaigns while keeping profiled rows out of cost comparisons."""

import argparse
import json
from pathlib import Path

import s307_summary as summary


def mechanism_counters(row):
    """Retain count deltas independently of CPU and lifetime-only maxima."""
    result_path = Path(row["raw_result"])
    result = summary.read(result_path)
    case, = result["cases"]
    cell = result_path.parent / ("vpn-" + case["case"])
    before, after = ((cell / (name + "-cli.txt")).read_text()
                     for name in ("before", "after"))
    counters = {}
    for prefix, fields in (
        ("tun.capture_io ", ("callbacks", "budget_exits", "callback_ns")),
        ("tun.capture_capacity ", ("alloc_attempts",)),
        ("tun.capture_batch ", ("calls", "packets")),
        ("tun.flow_stack ", ("return_packets", "write_attempts", "write_succeeded")),
        ("primary.status ", ("published", "received", "rejected", "returns")),
    ):
        counters[prefix.strip()] = {field: summary.counter_delta(before, after, prefix, field)
                                   for field in fields}
    def batch(text):
        return {int(values["batch.thread"]): values for line in text.splitlines()
                if line.startswith("batch.thread=")
                for values in [dict(word.split("=", 1) for word in line.split() if "=" in word)]}
    old, new = batch(before), batch(after)
    if old.keys() != new.keys():
        raise ValueError("batch thread layout changed inside a window")
    fields = ("admit_frames", "admit_vectors", "primary_calls", "primary_publications",
              "primary_vectors", "completion_calls", "completion_publications", "completion_vectors",
              "retry_windows", "origin_frames", "origin_vectors")
    counters["batch_threads"] = {thread: {field: int(values[field]) - int(old[thread][field])
                                         for field in fields} for thread, values in new.items()}
    counters["limits"] = ["Counts are not CPU attribution.",
                          "callback_ns is accumulated callback wall time, not thread CPU."]
    return counters


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaigns", type=Path, nargs="+")
    parser.add_argument("--snapshots", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    collectors = {summary.quick.digest(p) for p in args.snapshots.glob("*-pixel_quick.py")}
    runners = {summary.quick.digest(p) for p in args.snapshots.glob("*-s307_vpn_tuning.py")}
    if not collectors or not runners:
        raise ValueError("retained collector and campaign runner snapshots required")
    cohorts = [summary.summarize(path, collectors, runners, allow_profile=True)
               for path in args.campaigns]
    for cohort in cohorts:
        for row in cohort["rows"]:
            row["mechanism_counters"] = mechanism_counters(row)
    result = dict(schema="s308-summary/v1", status="VERIFIED_RAW", cohorts=cohorts,
                  scope="Descriptive Pixel windows; only cost_eligible rows are unprofiled cost evidence.",
                  limits=["Profiled rows measure mechanisms and probe perturbation, not candidate cost.",
                          "CPU window estimates extrapolate sampled scheduler accounting coverage.",
                          "No idle subtraction or adoption threshold is applied."])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
