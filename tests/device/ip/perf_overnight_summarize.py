#!/usr/bin/env python3

import argparse
import json
import statistics as stats
from collections import defaultdict
from pathlib import Path


METRIC_EXTRACTORS = {
    "rate_mib_s": lambda row: float(row["rate_mib_s"]),
    "conn_per_s": lambda row: float(row["conn_per_s"]),
    "samples_per_s": lambda row: float(row["samples_per_s"]),
    "lat_avg_us": lambda row: float(row["latency_us"]["avg"]),
    "lat_p50_us": lambda row: float(row["latency_us"]["p50"]),
    "lat_p95_us": lambda row: float(row["latency_us"]["p95"]),
    "lat_p99_us": lambda row: float(row["latency_us"]["p99"]),
    "lat_max_us": lambda row: float(row["latency_us"]["max"]),
}


def summarize(values):
    mean = sum(values) / len(values)
    stdev = stats.stdev(values) if len(values) > 1 else 0.0
    cv_pct = (stdev / mean * 100.0) if mean else None
    return {
        "mean": mean,
        "min": min(values),
        "max": max(values),
        "stdev": stdev,
        "cv_pct": cv_pct,
    }


def load_rows(path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def group_rows(rows):
    groups = defaultdict(list)
    for row in rows:
        key = (row["scenario"], int(row["duration_s"]))
        groups[key].append(row)
    return groups


def build_group_summary(rows):
    metric_stats = {}
    for name, extractor in METRIC_EXTRACTORS.items():
        metric_stats[name] = summarize([extractor(row) for row in rows])
    preflight = rows[-1].get("preflight", {})
    return {
        "count": len(rows),
        "rulesTotal": int(preflight.get("rulesTotal", 0)),
        "rangeRulesTotal": int(preflight.get("rangeRulesTotal", 0)),
        "subtablesTotal": int(preflight.get("subtablesTotal", 0)),
        "maxRangeRulesPerBucket": int(preflight.get("maxRangeRulesPerBucket", 0)),
        "metrics": metric_stats,
    }


def build_summary(rows):
    groups = group_rows(rows)
    grouped = []
    for scenario, duration_s in sorted(groups.keys(), key=lambda item: (item[1], item[0])):
        grouped.append(
            {
                "scenario": scenario,
                "duration_s": duration_s,
                **build_group_summary(groups[(scenario, duration_s)]),
            }
        )
    return {
        "total_runs": len(rows),
        "groups": grouped,
    }


def format_summary_text(summary):
    lines = []
    lines.append(f"total_runs={summary['total_runs']}")
    for group in summary["groups"]:
        lines.append("")
        lines.append(
            f"{group['scenario']} duration={group['duration_s']}s "
            f"n={group['count']} rulesTotal={group['rulesTotal']} "
            f"rangeRulesTotal={group['rangeRulesTotal']}"
        )
        for metric_name in (
            "rate_mib_s",
            "conn_per_s",
            "samples_per_s",
            "lat_avg_us",
            "lat_p95_us",
            "lat_p99_us",
        ):
            metric = group["metrics"][metric_name]
            cv = "n/a" if metric["cv_pct"] is None else f"{metric['cv_pct']:.2f}%"
            lines.append(
                f"  {metric_name}: mean={metric['mean']:.4f} "
                f"min={metric['min']:.4f} max={metric['max']:.4f} "
                f"stdev={metric['stdev']:.4f} cv={cv}"
            )
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Summarize overnight IP perf JSONL results.")
    parser.add_argument("--results", required=True, help="Path to results.jsonl")
    parser.add_argument("--summary-json", required=True, help="Path to summary JSON output")
    parser.add_argument("--summary-text", help="Optional text summary output")
    args = parser.parse_args()

    results_path = Path(args.results)
    summary_json_path = Path(args.summary_json)
    rows = load_rows(results_path)
    summary = build_summary(rows)

    summary_json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    if args.summary_text:
        Path(args.summary_text).write_text(format_summary_text(summary))


if __name__ == "__main__":
    main()
