#!/usr/bin/env python3
"""PROTOTYPE: Android A/B/C VPP wake latency and stopped-generator idle CPU test."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shlex
import statistics
import subprocess
import time

REPO = Path(__file__).resolve().parents[3]
POC = REPO / "experiments/vpp-nfq-poc"
ADB = REPO / "dev/adb"
PATCHED = Path(os.environ.get("P5_PATCHED_BUILD", POC / "work/vpp-android-configure-probe"))
UNPATCHED = Path(os.environ.get("P5_UNPATCHED_BUILD", "/tmp/sakamoto-p5-unpatched-build"))
RUN_ID = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
RESULT = Path(os.environ.get("RESULT_DIR", POC / "results" / dt.date.today().isoformat() / f"vpp-wake-idle-p5-{RUN_ID}"))
PROFILE = os.environ.get("PROFILE", "smoke")
PHASE = os.environ.get("PHASE", "all")
ARM_FILTER = os.environ.get("ARM_FILTER", "A B C").split()
EXPECT_WAKE_DIAGNOSTICS = os.environ.get("EXPECT_WAKE_DIAGNOSTICS", "1") == "1"
REQUIRE_PERFORMANCE_GO = os.environ.get(
    "REQUIRE_PERFORMANCE_GO", "1" if PROFILE == "full" else "0"
) == "1"
SEED = int(os.environ.get("SEED", "20260802"))

if PROFILE == "full":
    IDLE_WARMUP, IDLE_SECONDS, BLOCKS = 60.0, 600.0, 3
    LATENCY_SECONDS, LATENCY_REPS, MIN_SAMPLES = 320.0, 3, 300
elif PROFILE == "pilot":
    IDLE_WARMUP, IDLE_SECONDS, BLOCKS = 10.0, 60.0, 3
    LATENCY_SECONDS, LATENCY_REPS, MIN_SAMPLES = 65.0, 3, 60
else:
    IDLE_WARMUP, IDLE_SECONDS, BLOCKS = 2.0, 10.0, 1
    LATENCY_SECONDS, LATENCY_REPS, MIN_SAMPLES = 12.0, 1, 8

IDLE_WARMUP = float(os.environ.get("IDLE_WARMUP", IDLE_WARMUP))
IDLE_SECONDS = float(os.environ.get("IDLE_SECONDS", IDLE_SECONDS))
BLOCKS = int(os.environ.get("BLOCKS", BLOCKS))
LATENCY_SECONDS = float(os.environ.get("LATENCY_SECONDS", LATENCY_SECONDS))
LATENCY_REPS = int(os.environ.get("LATENCY_REPS", LATENCY_REPS))
MIN_SAMPLES = int(os.environ.get("MIN_SAMPLES", MIN_SAMPLES))

ARMS = {
    "A": {"label": "exact-unpatched", "build": UNPATCHED, "wake_mode": 0},
    "B": {"label": "patched-off", "build": PATCHED, "wake_mode": 0},
    "C": {"label": "patched-conditional", "build": PATCHED, "wake_mode": 2},
}
LIBS = ("libsvm.so", "libvlib.so", "libvlibapi.so", "libvlibmemory.so", "libvnet.so", "libvppinfra.so")
REMOTE_BASE = "/data/local/tmp/vpp-p5"

COUNTERS_RE = re.compile(
    r"generated (?P<generated>\d+).*?ingress-enqueued (?P<ingress>\d+) "
    r"ingress-drops (?P<ingress_drops>\d+) alloc-errors (?P<alloc_errors>\d+) "
    r"terminal (?P<terminal>\d+).*?reclaimed (?P<reclaimed>\d+) "
    r"reclaim-overflows (?P<reclaim_overflows>\d+) clock-anomalies (?P<clock_anomalies>\d+) "
    r"credit-stalls (?P<credit_stalls>\d+) outstanding-packets (?P<outstanding>\d+)", re.S)
CYCLES_RE = re.compile(
    r"samples (?P<samples>\d+) latency-min (?P<latency_min>\d+) latency-mean (?P<latency_mean>[0-9.]+) "
    r"latency-p50-upper (?P<p50>\d+) latency-p95-upper (?P<p95>\d+) "
    r"latency-p99-upper (?P<p99>\d+) latency-max (?P<latency_max>\d+)")
WAKE_RE = re.compile(
    r"wake-diagnostics calls (?P<wake_calls>\d+) sleeps-seen (?P<sleeps_seen>\d+) "
    r"pending-claims (?P<pending_claims>\d+) writes (?P<writes>\d+) "
    r"write-errors (?P<write_errors>\d+).*?fq-full-waits (?P<fq_full_waits>\d+)", re.S)
SLEEP_RE = re.compile(r"sleep-proof sampled-remote-enqueues (?P<sampled_remote>\d+) target-sleeping (?P<target_sleeping>\d+)")
EXACT_RE = re.compile(r"exact-latency samples (?P<exact_samples>\d+) overflows (?P<exact_overflows>\d+) "
                      r"p50 (?P<exact_p50>\d+) p95 (?P<exact_p95>\d+) p99 (?P<exact_p99>\d+)")
EXACT_SLEEP_RE = re.compile(
    r"exact-sleep-latency samples (?P<exact_sleep_samples>\d+) "
    r"overflows (?P<exact_sleep_overflows>\d+) p50 (?P<exact_sleep_p50>\d+) "
    r"p95 (?P<exact_sleep_p95>\d+) p99 (?P<exact_sleep_p99>\d+)")


def run(args: list[str], check: bool = True, timeout: float = 180) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"rc={result.returncode}: {shlex.join(args)}\n{result.stdout}\n{result.stderr}")
    return result


def quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def su(command: str, check: bool = True, timeout: float = 180) -> str:
    result = run([str(ADB), "shell", f"su 0 sh -c {quote(command)}"], check, timeout)
    return (result.stdout + result.stderr).replace("\r", "")


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact(arm: str, relative: str) -> Path:
    return Path(ARMS[arm]["build"]) / relative


def remote_root(arm: str) -> str:
    return f"{REMOTE_BASE}/{'unpatched' if arm == 'A' else 'patched'}"


def ctl(arm: str, command: str, check: bool = True) -> str:
    root = remote_root(arm)
    return su(f"LD_LIBRARY_PATH={root}/lib {root}/bin/vppctl -s {root}/runtime/cli.sock {command}", check)


def stage_one(arm: str) -> None:
    root = remote_root(arm)
    build = Path(ARMS[arm]["build"])
    plugin = build / "lib/aarch64-linux-android/vpp_plugins/handoff_perf_poc_plugin.so"
    paths = [build / "bin/vpp", build / "bin/vppctl", plugin]
    paths += [build / "lib/aarch64-linux-android" / name for name in LIBS]
    missing = [str(path) for path in paths if not path.exists()]
    if missing:
        raise RuntimeError(f"missing artifacts for {arm}: {missing}")
    su(f"mkdir -p {root}/bin {root}/lib {root}/plugins {root}/runtime {root}/logs; "
       f"chmod 777 {root}/bin {root}/lib {root}/plugins {root}/runtime {root}/logs")
    run([str(ADB), "push", str(paths[0]), f"{root}/bin/vpp"], timeout=600)
    run([str(ADB), "push", str(paths[1]), f"{root}/bin/vppctl"], timeout=600)
    run([str(ADB), "push", str(plugin), f"{root}/plugins/handoff_perf_poc_plugin.so"], timeout=600)
    for path in paths[3:]:
        run([str(ADB), "push", str(path), f"{root}/lib/{path.name}"], timeout=1200)
    su(f"chmod 755 {root}/bin/vpp {root}/bin/vppctl")


def stage() -> None:
    stage_one("A")
    stage_one("B")


def write_config(arm: str, case_dir: Path) -> Path:
    root = remote_root(arm)
    config = case_dir / "startup.conf"
    config.write_text(f"""unix {{
  nodaemon
  nobanner
  runtime-dir {root}/runtime
  log {root}/logs/vpp.log
  cli-listen {root}/runtime/cli.sock
}}
cpu {{ main-core 0 corelist-workers 1 }}
api-segment {{ prefix vpp-p5-{arm.lower()} }}
statseg {{ socket-name {root}/runtime/statseg.sock }}
buffers {{ page-size default }}
plugins {{
  path {root}/plugins
  plugin default {{ disable }}
  plugin handoff_perf_poc_plugin.so {{ enable }}
}}
""")
    return config


def stop_vpp(arm: str) -> None:
    root = remote_root(arm)
    su(f"if [ -f {root}/runtime/vpp.pid ]; then p=$(cat {root}/runtime/vpp.pid); kill -TERM $p 2>/dev/null || true; for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 $p 2>/dev/null || break; sleep .1; done; kill -0 $p 2>/dev/null && kill -KILL $p 2>/dev/null || true; fi; rm -f {root}/runtime/cli.sock {root}/runtime/vpp.pid", False)


def start_vpp(arm: str, case_dir: Path) -> None:
    root = remote_root(arm)
    stop_vpp(arm)
    config = write_config(arm, case_dir)
    run([str(ADB), "push", str(config), f"{root}/runtime/startup.conf"])
    su(f"cd {root}; LD_LIBRARY_PATH={root}/lib nohup {root}/bin/vpp -c {root}/runtime/startup.conf >{root}/logs/stdout.log 2>&1 </dev/null & echo $! >{root}/runtime/vpp.pid")
    for _ in range(100):
        time.sleep(.1)
        probe = ctl(arm, "show version", False)
        if "vpp v" in probe.lower():
            break
    else:
        log = su(f"cat {root}/logs/stdout.log; cat {root}/logs/vpp.log", False)
        raise RuntimeError(f"VPP startup timeout for {arm}:\n{log}")
    (case_dir / "threads.txt").write_text(ctl(arm, "show threads"))
    if arm != "A":
        expected = f"handoff-perf wake mode {ARMS[arm]['wake_mode']}"
        result = ctl(arm, f"handoff-perf wake-mode {ARMS[arm]['wake_mode']}")
        if expected not in result:
            raise RuntimeError(f"failed to set wake mode: {result}")


def process_sample(arm: str) -> dict[str, object]:
    root = remote_root(arm)
    pid = int(su(f"cat {root}/runtime/vpp.pid").strip())
    tids = su(f"for t in /proc/{pid}/task/*; do echo ${{t##*/}}; done").split()
    tasks: dict[str, dict[str, int | str]] = {}
    battery: dict[str, int | str] = {}
    for tid in tids:
        raw = su(f"cat /proc/{pid}/task/{tid}/stat; cat /proc/{pid}/task/{tid}/schedstat; "
                 f"cat /proc/{pid}/task/{tid}/comm; cat /proc/{pid}/task/{tid}/status")
        lines = raw.splitlines()
        stat = lines[0].split()
        sched = lines[1].split()
        name = lines[2]
        status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                  for line in lines[3:] if ":" in line}
        tasks[tid] = {"name": name, "ticks": int(stat[13]) + int(stat[14]), "cpu": int(stat[38]),
                      "runtime_ns": int(sched[0]), "wait_ns": int(sched[1]), "slices": int(sched[2]),
                      "voluntary": int(status["voluntary_ctxt_switches"]),
                      "involuntary": int(status["nonvoluntary_ctxt_switches"])}
    for line in su("for f in status capacity current_now voltage_now charge_counter temp; do "
                   "p=/sys/class/power_supply/battery/$f; [ -r $p ] && echo \"$f $(cat $p)\"; done").splitlines():
        key, value = line.split(None, 1)
        battery[key] = int(value) if value.lstrip("-").isdigit() else value
    if len(tasks) != 2:
        raise RuntimeError(f"expected main+one worker, got {tasks}")
    return {"monotonic_ns": time.monotonic_ns(), "tasks": tasks, "battery": battery}


def sample_delta(before: dict[str, object], after: dict[str, object]) -> dict[str, object]:
    before_tasks = before["tasks"]
    after_tasks = after["tasks"]
    rows = []
    for tid, start in before_tasks.items():
        if tid not in after_tasks or after_tasks[tid]["name"] != start["name"]:
            raise RuntimeError("VPP task identity changed during measurement")
        end = after_tasks[tid]
        row = {"tid": int(tid), "name": start["name"]}
        for key in ("ticks", "runtime_ns", "wait_ns", "slices", "voluntary", "involuntary"):
            row[key] = int(end[key]) - int(start[key])
            if row[key] < 0:
                raise RuntimeError(f"negative {key} delta")
        rows.append(row)
    elapsed_ns = int(after["monotonic_ns"]) - int(before["monotonic_ns"])
    return {"elapsed_ns": elapsed_ns, "tasks": rows,
            "total_runtime_ns": sum(row["runtime_ns"] for row in rows),
            "total_contexts": sum(row["voluntary"] + row["involuntary"] for row in rows)}


def parse_show(text: str) -> dict[str, int | float]:
    result: dict[str, int | float] = {}
    for regex in (COUNTERS_RE, CYCLES_RE, WAKE_RE, SLEEP_RE, EXACT_RE, EXACT_SLEEP_RE):
        match = regex.search(text)
        if match:
            for key, value in match.groupdict().items():
                result[key] = float(value) if "." in value else int(value)
    return result


def idle_case(block: int, arm: str, index: int) -> dict[str, object]:
    case_dir = RESULT / "idle" / f"{index:02d}-block{block}-{arm}-{ARMS[arm]['label']}"
    case_dir.mkdir(parents=True)
    start_vpp(arm, case_dir)
    try:
        time.sleep(IDLE_WARMUP)
        show_before = ctl(arm, "show handoff-perf")
        before = process_sample(arm)
        time.sleep(IDLE_SECONDS)
        after = process_sample(arm)
        show_after = ctl(arm, "show handoff-perf")
        delta = sample_delta(before, after)
        wake_before, wake_after = parse_show(show_before), parse_show(show_after)
        wake_delta = {key: int(wake_after.get(key, 0)) - int(wake_before.get(key, 0))
                      for key in ("wake_calls", "writes", "write_errors", "fq_full_waits")}
        graph_tasks = [row for row in delta["tasks"] if row["name"] == "vpp_main" or str(row["name"]).startswith("vpp_wk_")]
        no_datapath = all(int(wake_after.get(key, -1)) == 0
                          for key in ("generated", "ingress", "terminal", "outstanding"))
        valid = (len(graph_tasks) == 2 and no_datapath and wake_delta["write_errors"] == 0
                 and wake_delta["fq_full_waits"] == 0)
        payload = {"phase": "idle", "block": block, "order_index": index, "arm": arm,
                   "label": ARMS[arm]["label"], "wake_mode": ARMS[arm]["wake_mode"],
                   "valid": valid, "wake_delta": wake_delta, **delta,
                   "datapath_after": {key: wake_after.get(key) for key in
                                      ("generated", "ingress", "terminal", "outstanding")},
                   "cpu_single_core_percent": delta["total_runtime_ns"] / delta["elapsed_ns"] * 100,
                   "battery_before": before["battery"], "battery_after": after["battery"]}
        (case_dir / "before.json").write_text(json.dumps(before, indent=2) + "\n")
        (case_dir / "after.json").write_text(json.dumps(after, indent=2) + "\n")
        (case_dir / "show-before.txt").write_text(show_before)
        (case_dir / "show-after.txt").write_text(show_after)
        (case_dir / "result.json").write_text(json.dumps(payload, indent=2) + "\n")
        return payload
    finally:
        stop_vpp(arm)


def latency_case(repetition: int, arm: str, index: int) -> dict[str, object]:
    case_dir = RESULT / "latency" / f"{index:02d}-rep{repetition}-{arm}-{ARMS[arm]['label']}"
    case_dir.mkdir(parents=True)
    start_vpp(arm, case_dir)
    try:
        command = ("handoff-perf start mode handoff-one distribution hot burst 1 packet-size 64 "
                   f"sample-rate 1 seed {SEED} tokens 1 rate 1 wake-workers {ARMS[arm]['wake_mode']}")
        started = ctl(arm, command)
        if "handoff-perf started" not in started:
            raise RuntimeError(started)
        time.sleep(2.2)
        ctl(arm, "handoff-perf stop")
        warmup_show = ""
        for _ in range(200):
            warmup_show = ctl(arm, "show handoff-perf")
            if parse_show(warmup_show).get("outstanding") == 0:
                break
            time.sleep(.01)
        resumed = ctl(arm, "handoff-perf resume")
        if "handoff-perf resumed with counters reset" not in resumed:
            raise RuntimeError(resumed)
        time.sleep(LATENCY_SECONDS)
        ctl(arm, "handoff-perf stop")
        parsed: dict[str, int | float] = {}
        show = ""
        for _ in range(200):
            show = ctl(arm, "show handoff-perf")
            parsed = parse_show(show)
            if parsed.get("outstanding") == 0:
                break
            time.sleep(.01)
        clock = ctl(arm, "show clock")
        errors = []
        generated = int(parsed.get("generated", -1))
        for key in ("ingress", "terminal", "reclaimed", "samples", "sampled_remote",
                    "exact_samples"):
            if int(parsed.get(key, -2)) != generated:
                errors.append(f"{key}!={generated}")
        if generated < MIN_SAMPLES:
            errors.append(f"samples<{MIN_SAMPLES}")
        for key in ("ingress_drops", "alloc_errors", "reclaim_overflows", "clock_anomalies",
                    "outstanding", "write_errors", "fq_full_waits"):
            if int(parsed.get(key, -1)) != 0:
                errors.append(f"{key}={parsed.get(key)}")
        if int(parsed.get("exact_overflows", -1)) != 0:
            errors.append(f"exact_overflows={parsed.get('exact_overflows')}")
        if int(parsed.get("target_sleeping", -1)) < MIN_SAMPLES:
            errors.append(f"sleep-confirmed<{MIN_SAMPLES}")
        if int(parsed.get("exact_sleep_samples", -2)) != int(parsed.get("target_sleeping", -1)):
            errors.append("sleep-latency-ledger")
        if int(parsed.get("exact_sleep_overflows", -1)) != 0:
            errors.append(f"exact_sleep_overflows={parsed.get('exact_sleep_overflows')}")
        if (arm == "C" and EXPECT_WAKE_DIAGNOSTICS
                and (int(parsed.get("sleeps_seen", 0)) == 0 or int(parsed.get("writes", 0)) == 0)):
            errors.append("conditional-wake-not-observed")
        ctl(arm, "handoff-perf cleanup")
        payload = {"phase": "latency", "repetition": repetition, "order_index": index,
                   "arm": arm, "label": ARMS[arm]["label"], "wake_mode": ARMS[arm]["wake_mode"],
                   "valid": not errors, "errors": errors, **parsed}
        (case_dir / "start.txt").write_text(started)
        (case_dir / "warmup-show.txt").write_text(warmup_show)
        (case_dir / "resume.txt").write_text(resumed)
        (case_dir / "show.txt").write_text(show)
        (case_dir / "clock.txt").write_text(clock)
        (case_dir / "result.json").write_text(json.dumps(payload, indent=2) + "\n")
        return payload
    finally:
        stop_vpp(arm)


def ci_upper(values: list[float]) -> float:
    if len(values) < 2:
        return math.inf
    one_sided_t95 = {2: 6.314, 3: 2.920, 4: 2.353, 5: 2.132}.get(len(values), 1.645)
    return statistics.fmean(values) + one_sided_t95 * statistics.stdev(values) / math.sqrt(len(values))


def summarize(rows: list[dict[str, object]]) -> dict[str, object]:
    idle = [row for row in rows if row["phase"] == "idle"]
    latency = [row for row in rows if row["phase"] == "latency"]
    summary: dict[str, object] = {"all_cases_valid": all(bool(row["valid"]) for row in rows)}
    if idle:
        by_block = {block: {row["arm"]: row for row in idle if row["block"] == block}
                    for block in sorted({int(row["block"]) for row in idle})}
        cb = [float(pair["C"]["cpu_single_core_percent"]) - float(pair["B"]["cpu_single_core_percent"])
              for pair in by_block.values() if "B" in pair and "C" in pair]
        ba = [float(pair["B"]["cpu_single_core_percent"]) - float(pair["A"]["cpu_single_core_percent"])
              for pair in by_block.values() if "A" in pair and "B" in pair]
        ca = [float(pair["C"]["cpu_single_core_percent"]) - float(pair["A"]["cpu_single_core_percent"])
              for pair in by_block.values() if "A" in pair and "C" in pair]
        wake_excess = [{key: int(pair["C"]["wake_delta"][key]) - int(pair["B"]["wake_delta"][key])
                        for key in ("wake_calls", "writes")}
                       for pair in by_block.values() if "B" in pair and "C" in pair]
        summary["idle"] = {"C_minus_B_cpu_pp": cb, "C_minus_B_95pct_one_sided_upper_pp": ci_upper(cb),
                           "B_minus_A_cpu_pp": ba, "B_minus_A_95pct_one_sided_upper_pp": ci_upper(ba),
                           "C_minus_B_wake_counts": wake_excess,
                           "C_minus_A_cpu_pp": ca,
                           "C_minus_A_95pct_one_sided_upper_pp": ci_upper(ca),
                           "go": ((len(cb) >= 3 and ci_upper(cb) <= .05
                                   and all(item["wake_calls"] <= 1 and item["writes"] <= 1
                                           for item in wake_excess))
                                  or (not cb and len(ca) >= 3 and ci_upper(ca) <= .05))
                                 and all(bool(row["valid"]) for row in idle)}
    if latency:
        valid_b = [row for row in latency if row["arm"] == "B" and row["valid"]]
        valid_c = [row for row in latency if row["arm"] == "C" and row["valid"]]
        b_p99 = statistics.median(float(row["exact_sleep_p99"]) for row in valid_b) if valid_b else math.inf
        c_p99 = statistics.median(float(row["exact_sleep_p99"]) for row in valid_c) if valid_c else math.inf
        b_p50 = statistics.median(float(row["exact_sleep_p50"]) for row in valid_b) if valid_b else math.inf
        c_p50 = statistics.median(float(row["exact_sleep_p50"]) for row in valid_c) if valid_c else math.inf
        summary["latency"] = {"B_median_exact_p99_cycles": b_p99, "C_median_exact_p99_cycles": c_p99,
                              "p99_improvement_fraction": 1 - c_p99 / b_p99 if math.isfinite(b_p99) else None,
                              "B_median_exact_p50_cycles": b_p50, "C_median_exact_p50_cycles": c_p50,
                              "go": len(valid_b) == LATENCY_REPS and len(valid_c) == LATENCY_REPS
                                    and c_p99 <= .8 * b_p99 and c_p50 <= 1.1 * b_p50}
    summary["power"] = {"status": "INCONCLUSIVE", "reason": "no calibrated external power meter; battery sysfs retained as proxy only"}
    return summary


def manifest() -> dict[str, object]:
    idle_orders = ([['A', 'C'], ['C', 'A']] if ARM_FILTER == ['A', 'C'] else
                   [['A', 'B', 'C'], ['C', 'A', 'B'], ['B', 'C', 'A']])
    result: dict[str, object] = {"prototype": True, "run_id": RUN_ID, "profile": PROFILE,
        "phase": PHASE, "seed": SEED, "idle_warmup_seconds": IDLE_WARMUP,
        "arm_filter": ARM_FILTER, "expect_wake_diagnostics": EXPECT_WAKE_DIAGNOSTICS,
        "require_performance_go": REQUIRE_PERFORMANCE_GO,
        "idle_seconds": IDLE_SECONDS, "blocks": BLOCKS, "latency_seconds": LATENCY_SECONDS,
        "latency_repetitions": LATENCY_REPS, "minimum_latency_samples": MIN_SAMPLES,
        "idle_orders": idle_orders,
        "power_claim": "INCONCLUSIVE without external meter", "artifacts": {}}
    for arm in ("A", "B"):
        build = Path(ARMS[arm]["build"])
        files = [build / "bin/vpp", build / "bin/vppctl",
                 build / "lib/aarch64-linux-android/vpp_plugins/handoff_perf_poc_plugin.so"]
        files += [build / "lib/aarch64-linux-android" / name for name in LIBS]
        result["artifacts"][arm] = {str(path): digest(path) for path in files}
    patched_source = POC / "work/vpp/src/vlib"
    unpatched_source = Path("/tmp/sakamoto-p5-unpatched-20260802/src/vlib")
    source_names = ("main.h", "threads.h", "file.c", "buffer_funcs.c")
    result["source_artifacts"] = {
        "patched": {str(patched_source / name): digest(patched_source / name) for name in source_names},
        "unpatched": {str(unpatched_source / name): digest(unpatched_source / name) for name in source_names},
        "patched_build_cache": digest(PATCHED / "CMakeCache.txt"),
        "vlib_wake_diagnostics": 0,
    }
    return result


def main() -> int:
    if PHASE not in ("idle", "latency", "all"):
        raise RuntimeError("PHASE must be idle, latency, or all")
    RESULT.mkdir(parents=True, exist_ok=False)
    (RESULT / "manifest.json").write_text(json.dumps(manifest(), indent=2) + "\n")
    stage()
    rows: list[dict[str, object]] = []
    try:
        if PHASE in ("idle", "all"):
            if ARM_FILTER == ["A", "C"]:
                orders = [["A", "C"], ["C", "A"]]
            else:
                orders = [["A", "B", "C"], ["C", "A", "B"], ["B", "C", "A"]]
            for block in range(BLOCKS):
                for arm in orders[block % len(orders)]:
                    rows.append(idle_case(block, arm, len(rows)))
                    (RESULT / "raw.json").write_text(json.dumps(rows, indent=2) + "\n")
        if PHASE in ("latency", "all"):
            cases = [(rep, arm) for rep in range(LATENCY_REPS) for arm in ("B", "C")]
            random.Random(SEED).shuffle(cases)
            for repetition, arm in cases:
                rows.append(latency_case(repetition, arm, len(rows)))
                (RESULT / "raw.json").write_text(json.dumps(rows, indent=2) + "\n")
    finally:
        stop_vpp("A")
        stop_vpp("B")
    summary = summarize(rows)
    (RESULT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"result": str(RESULT), "summary": summary}, indent=2))
    gates_pass = bool(summary["all_cases_valid"])
    if REQUIRE_PERFORMANCE_GO and PHASE in ("idle", "all"):
        gates_pass = gates_pass and bool(summary["idle"]["go"])
    if REQUIRE_PERFORMANCE_GO and PHASE in ("latency", "all"):
        gates_pass = gates_pass and bool(summary["latency"]["go"])
    return 0 if gates_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
