#!/usr/bin/env python3

import argparse
import json
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCENARIOS = ("iprules_off", "iprules_2k", "iprules_4k")


@dataclass(frozen=True)
class Run:
    path: Path
    rows: Dict[str, Dict[str, Any]]


def _results_path(p: Path) -> Path:
    if p.is_dir():
        return p / "results.jsonl"
    return p


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def _pct(a: float, b: float) -> Optional[float]:
    if b == 0:
        return None
    return (a - b) / b * 100.0


def _fmt_pct(x: Optional[float]) -> str:
    if x is None:
        return "n/a"
    return f"{x:+.2f}%"


def _mean_stdev(vals: List[float]) -> Tuple[float, float]:
    if not vals:
        return 0.0, 0.0
    if len(vals) == 1:
        return vals[0], 0.0
    return statistics.mean(vals), statistics.stdev(vals)


def _extract_knobs(row: Dict[str, Any]) -> Dict[str, Any]:
    knobs = row.get("knobs")
    return knobs if isinstance(knobs, dict) else {}


def _extract_tps(row: Dict[str, Any]) -> float:
    neper = row.get("neper")
    if not isinstance(neper, dict):
        return 0.0
    val = neper.get("throughput_tps")
    if val is None:
        val = neper.get("throughput")
    try:
        return float(val)
    except (TypeError, ValueError):
        return 0.0


def _metric_kind(row: Dict[str, Any]) -> str:
    neper = row.get("neper")
    if not isinstance(neper, dict):
        return "throughput"
    if neper.get("throughput_tps") is not None:
        return "throughput_tps"
    return "throughput"


def _extract_drops(row: Dict[str, Any]) -> Tuple[int, int]:
    nfq = row.get("nfq")
    if not isinstance(nfq, dict):
        return 0, 0
    qd = nfq.get("queue_dropped_total", 0)
    ud = nfq.get("user_dropped_total", 0)
    try:
        return int(qd), int(ud)
    except (TypeError, ValueError):
        return 0, 0


def _print_knobs_summary(runs: List[Run]) -> None:
    # Best-effort: show whether knobs appear stable across runs.
    knobs_by_run: List[Dict[str, Any]] = []
    for r in runs:
        for s in SCENARIOS:
            row = r.rows.get(s)
            if row:
                knobs_by_run.append(_extract_knobs(row))
                break

    if not knobs_by_run:
        print("knobs: (none)")
        return

    keys = sorted({k for d in knobs_by_run for k in d.keys()})
    stable: Dict[str, Any] = {}
    unstable: List[str] = []
    for k in keys:
        vals = []
        for d in knobs_by_run:
            vals.append(d.get(k))
        uniq = {json.dumps(v, sort_keys=True, ensure_ascii=True) for v in vals}
        if len(uniq) == 1:
            stable[k] = vals[0]
        else:
            unstable.append(k)

    if stable:
        stable_str = " ".join([f"{k}={stable[k]}" for k in sorted(stable.keys())])
        print(f"knobs(stable): {stable_str}")
    else:
        print("knobs(stable): (none)")

    if unstable:
        print("knobs(unstable): " + ", ".join(unstable))


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Summarize neper_perf_3way records (mean/CV + monotonicity)")
    p.add_argument(
        "paths",
        nargs="+",
        help="records dirs (neper-perf-3way-*) or results.jsonl files",
    )
    p.add_argument(
        "--include-warmup",
        action="store_true",
        help="Include warmup_off in per-scenario stats",
    )
    args = p.parse_args(argv)

    inputs = [Path(x) for x in args.paths]
    runs: List[Run] = []
    for ip in inputs:
        rp = _results_path(ip)
        if not rp.exists():
            print(f"missing results.jsonl: {rp}", file=sys.stderr)
            return 2
        try:
            rows = _load_jsonl(rp)
        except Exception as e:
            print(f"failed to read {rp}: {e}", file=sys.stderr)
            return 2
        by_scenario: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            scenario = row.get("scenario")
            if not isinstance(scenario, str):
                continue
            by_scenario[scenario] = row
        runs.append(Run(path=rp.parent, rows=by_scenario))

    if not runs:
        print("no runs", file=sys.stderr)
        return 2

    scenarios: Tuple[str, ...] = SCENARIOS + (("warmup_off",) if args.include_warmup else ())

    print(f"runs={len(runs)}")
    _print_knobs_summary(runs)

    metric_kind = "throughput"
    all_tps: Dict[str, List[float]] = {s: [] for s in scenarios}
    any_drops = 0
    for r in runs:
        for s in scenarios:
            row = r.rows.get(s)
            if not row:
                continue
            if metric_kind == "throughput" and _metric_kind(row) == "throughput_tps":
                metric_kind = "throughput_tps"
            qd, ud = _extract_drops(row)
            if qd or ud:
                any_drops += 1
            all_tps[s].append(_extract_tps(row))

    print("")
    if metric_kind == "throughput_tps":
        print("throughput_tps (higher is better; txns/s):")
    else:
        print("throughput (higher is better; unit depends on runner, often bits/s for udp_stream):")
    for s in scenarios:
        vals = all_tps[s]
        mean, stdev = _mean_stdev(vals)
        cv = (stdev / mean * 100.0) if mean else 0.0
        if vals:
            print(f"- {s}: n={len(vals)} mean={mean:.2f} stdev={stdev:.2f} cv={cv:.2f}% min={min(vals):.2f} max={max(vals):.2f}")
        else:
            print(f"- {s}: n=0")

    if any_drops:
        print("")
        print(f"guardrail: drop_detected_in_rows={any_drops} (queue_dropped_total/user_dropped_total)")

    off_mean, _ = _mean_stdev(all_tps.get("iprules_off", []))
    k2_mean, _ = _mean_stdev(all_tps.get("iprules_2k", []))
    k4_mean, _ = _mean_stdev(all_tps.get("iprules_4k", []))

    print("")
    print("delta(mean):")
    print(f"- 2k_vs_off: {_fmt_pct(_pct(k2_mean, off_mean))}")
    print(f"- 4k_vs_off: {_fmt_pct(_pct(k4_mean, off_mean))}")
    print(f"- 4k_vs_2k:  {_fmt_pct(_pct(k4_mean, k2_mean))}")

    # Monotonicity per-run (only when the run has all three scenarios).
    mono = 0
    eligible = 0
    for r in runs:
        if not all(r.rows.get(s) for s in SCENARIOS):
            continue
        eligible += 1
        off = _extract_tps(r.rows["iprules_off"])
        k2 = _extract_tps(r.rows["iprules_2k"])
        k4 = _extract_tps(r.rows["iprules_4k"])
        if off > k2 > k4:
            mono += 1
    print("")
    print(f"monotonic_off_gt_2k_gt_4k: {mono}/{eligible}" if eligible else "monotonic_off_gt_2k_gt_4k: n/a")

    # Monotonicity by sample index. This works for both:
    # - 3-way runs (lists are aligned by run order), and
    # - scenario-matrix runs (independent jobs per scenario).
    off_vals = all_tps.get("iprules_off", [])
    k2_vals = all_tps.get("iprules_2k", [])
    k4_vals = all_tps.get("iprules_4k", [])
    paired = min(len(off_vals), len(k2_vals), len(k4_vals))
    if paired:
        by_index = sum(1 for i in range(paired) if off_vals[i] > k2_vals[i] > k4_vals[i])
        print(f"monotonic_off_gt_2k_gt_4k_by_index: {by_index}/{paired}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
