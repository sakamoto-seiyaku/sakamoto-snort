#!/usr/bin/env python3
"""P6d formal Pixel 6a idle/latency runner.

The default action is ``--plan``.  Device mutation and the roughly six-hour formal run
require an explicit ``--execute``.  Protocol constants are intentionally not
CLI-tunable: changing one creates a different experiment.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import statistics
import subprocess
import time
from typing import Callable

REPO = Path(__file__).resolve().parents[3]
POC = REPO / "experiments/vpp-nfq-poc"
ADB = REPO / "dev/adb"
PATCHED = Path(os.environ.get("P6_PATCHED_BUILD", POC / "work/vpp-android-configure-probe"))
UNPATCHED = Path(os.environ.get("P6_UNPATCHED_BUILD", "/tmp/sakamoto-p5-unpatched-build"))
PATCHED_SOURCE = Path(os.environ.get("P6_PATCHED_SOURCE", POC / "work/vpp/src/vlib"))
UNPATCHED_SOURCE = Path(os.environ.get("P6_UNPATCHED_SOURCE", "/tmp/sakamoto-p5-unpatched-20260802/src/vlib"))
CANONICAL_PLUGIN_SOURCE = POC / "overlay/src/plugins/handoff_perf_poc/handoff_perf_poc.c"
RUNNER_SOURCE = Path(__file__).resolve()
RUN_ID = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
DEFAULT_RESULT = POC / "results" / dt.date.today().isoformat() / f"vpp-wake-idle-p6-{RUN_ID}"

SEED = 0x5A4B20260802
IDLE_ORDERS = ("AC", "CA", "CA", "AC", "CA", "AC", "AC", "CA")
LATENCY_ORDERS = ("BC", "CB", "BC", "CB", "CB", "BC", "CB", "BC")
IDLE_WARMUP_SECONDS = 60.0
IDLE_SAMPLE_SECONDS = 600.0
LATENCY_WARMUP_EVENTS = 20
LATENCY_MEASURED_EVENTS = 600
LATENCY_TOTAL_EVENTS = LATENCY_WARMUP_EVENTS + LATENCY_MEASURED_EVENTS
LATENCY_RATE_PPS = 1
LATENCY_REQUIRE_SLEEPING = True
REQUIRE_SLEEPING_CLI = "require-sleeping"
LATENCY_ARM_TIMEOUT_SECONDS = 660.0
METRIC_INTERVAL_SECONDS = 5.0
MAX_MISSING_FRACTION = 0.01
T95_DF7 = 1.894578605
IDLE_UPPER_GATE_PP = 0.05
P99_LOWER_GATE = 0.20
P50_UPPER_GATE = 0.10

ARMS = {
    "A": {"label": "exact-unpatched", "build": UNPATCHED, "wake_mode": 0},
    "B": {"label": "p6-patched-persistent-control", "build": PATCHED, "wake_mode": 3},
    "C": {"label": "p6-patched-conditional", "build": PATCHED, "wake_mode": 2},
}
LIBS = ("libsvm.so", "libvlib.so", "libvlibapi.so", "libvlibmemory.so", "libvnet.so", "libvppinfra.so")
REMOTE_BASE = "/data/local/tmp/vpp-p6"

CONFIG_RE = re.compile(
    r"running (?P<running>\d+).*?tokens-live (?P<tokens_live>\d+) "
    r"tokens-available (?P<tokens_available>\d+) wake-workers (?P<reported_wake_mode>\d+)"
    r"(?: require-sleeping (?P<reported_require_sleeping>\d+))?", re.S)
COUNTERS_RE = re.compile(
    r"generated (?P<generated>\d+).*?ingress-enqueued (?P<ingress>\d+) "
    r"ingress-drops (?P<ingress_drops>\d+) alloc-errors (?P<alloc_errors>\d+) "
    r"terminal (?P<terminal>\d+).*?return-drops (?P<return_drops>\d+) reclaimed (?P<reclaimed>\d+) "
    r"reclaim-overflows (?P<reclaim_overflows>\d+) clock-anomalies (?P<clock_anomalies>\d+) "
    r"credit-stalls (?P<credit_stalls>\d+) outstanding-packets (?P<outstanding>\d+)", re.S)
RATE_RE = re.compile(
    r"rate-scheduler scheduled-packets (?P<scheduled_packets>\d+) "
    r"backlog-packets (?P<backlog_packets>\d+(?:\.\d+)?)")
CYCLES_RE = re.compile(
    r"samples (?P<samples>\d+) latency-min (?P<latency_min>\d+) latency-mean (?P<latency_mean>[0-9.]+) "
    r"latency-p50-upper (?P<p50>\d+) latency-p95-upper (?P<p95>\d+) "
    r"latency-p99-upper (?P<p99>\d+) latency-max (?P<latency_max>\d+)")
WAKE_RE = re.compile(
    r"wake-diagnostics calls (?P<wake_calls>\d+) sleeps-seen (?P<sleeps_seen>\d+) "
    r"pending-claims (?P<pending_claims>\d+) writes (?P<writes>\d+) "
    r"write-errors (?P<write_errors>\d+).*?fq-full-waits (?P<fq_full_waits>\d+)", re.S)
WAKE_STATE_RE = re.compile(
    r"wake-state epoch-max (?P<epoch_max>\d+) faults (?P<wake_faults>\d+) fault-code (?P<wake_fault_code>\d+) "
    r"awake (?P<awake>\d+) preparing (?P<preparing>\d+) sleeping (?P<sleeping>\d+) "
    r"notified (?P<notified>\d+) draining (?P<draining>\d+) notifying (?P<notifying>\d+)")
SLEEP_RE = re.compile(
    r"sleep-proof sampled-remote-enqueues (?P<sampled_remote>\d+) "
    r"target-sleeping (?P<target_sleeping>\d+)"
    r"(?: sleep-wait-retries (?P<sleep_wait_retries>\d+))?")
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


def json_text(value: object, *, default: Callable[[object], object] | None = None) -> str:
    return json.dumps(value, indent=2, allow_nan=False, default=default) + "\n"


def write_json(path: Path, value: object, *, default: Callable[[object], object] | None = None) -> None:
    path.write_text(json_text(value, default=default))


def remote_root(arm: str) -> str:
    return f"{REMOTE_BASE}/{'unpatched' if arm == 'A' else 'patched'}"


def ctl(arm: str, command: str, check: bool = True) -> str:
    root = remote_root(arm)
    return su(f"LD_LIBRARY_PATH={root}/lib {root}/bin/vppctl -s {root}/runtime/cli.sock {command}", check)


def parse_show(text: str) -> dict[str, int | float]:
    parsed: dict[str, int | float] = {}
    for regex in (CONFIG_RE, COUNTERS_RE, RATE_RE, CYCLES_RE, WAKE_RE, WAKE_STATE_RE, SLEEP_RE,
                  EXACT_RE, EXACT_SLEEP_RE):
        match = regex.search(text)
        if match:
            for key, value in match.groupdict().items():
                if value is not None:
                    parsed[key] = float(value) if "." in value else int(value)
    return parsed


def device_identity() -> dict[str, str]:
    values = su("getprop ro.product.model; getprop ro.build.version.release; getprop ro.build.version.sdk").splitlines()
    if len(values) != 3:
        raise RuntimeError(f"could not read device identity: {values}")
    identity = {"model": values[0].strip(), "android_release": values[1].strip(), "api": values[2].strip()}
    if identity != {"model": "Pixel 6a", "android_release": "16", "api": "36"}:
        raise RuntimeError(f"P6d requires Pixel 6a Android 16/API36, got {identity}")
    return identity


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
    destinations = [f"{root}/bin/vpp", f"{root}/bin/vppctl", f"{root}/plugins/handoff_perf_poc_plugin.so"]
    for path, destination in zip(paths[:3], destinations):
        run([str(ADB), "push", str(path), destination], timeout=600)
    for path in paths[3:]:
        run([str(ADB), "push", str(path), f"{root}/lib/{path.name}"], timeout=1200)
    su(f"chmod 755 {root}/bin/vpp {root}/bin/vppctl")


def stage() -> None:
    stage_one("A")
    stage_one("B")  # B and C deliberately share this staged binary.


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
api-segment {{ prefix vpp-p6-{arm.lower()} }}
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
    su(f"if [ -f {root}/runtime/vpp.pid ]; then p=$(cat {root}/runtime/vpp.pid); "
       "kill -TERM $p 2>/dev/null || true; for i in 1 2 3 4 5 6 7 8 9 10; do "
       "kill -0 $p 2>/dev/null || break; sleep .1; done; kill -0 $p 2>/dev/null && "
       f"kill -KILL $p 2>/dev/null || true; fi; rm -f {root}/runtime/cli.sock {root}/runtime/vpp.pid", False)


def start_vpp(arm: str, case_dir: Path) -> None:
    root = remote_root(arm)
    stop_vpp(arm)
    config = write_config(arm, case_dir)
    run([str(ADB), "push", str(config), f"{root}/runtime/startup.conf"])
    su(f"cd {root}; LD_LIBRARY_PATH={root}/lib nohup {root}/bin/vpp -c {root}/runtime/startup.conf "
       f">{root}/logs/stdout.log 2>&1 </dev/null & echo $! >{root}/runtime/vpp.pid")
    for _ in range(100):
        time.sleep(.1)
        if "vpp v" in ctl(arm, "show version", False).lower():
            break
    else:
        raise RuntimeError(f"VPP startup timeout for {arm}:\n{su(f'cat {root}/logs/stdout.log', False)}")
    threads = ctl(arm, "show threads")
    (case_dir / "threads.txt").write_text(threads)
    if arm != "A":
        expected = f"handoff-perf wake mode {ARMS[arm]['wake_mode']}"
        result = ctl(arm, f"handoff-perf wake-mode {ARMS[arm]['wake_mode']}")
        if expected not in result:
            raise RuntimeError(f"failed to set wake mode: {result}")


def raw_environment(arm: str) -> str:
    root = remote_root(arm)
    return su(
        f"p=$(cat {root}/runtime/vpp.pid); echo __ONLINE__; cat /sys/devices/system/cpu/online; "
        "echo __CPUFREQ__; for d in /sys/devices/system/cpu/cpufreq/policy*; do "
        "[ -d $d ] || continue; echo POLICY=${d##*/}; for f in affected_cpus scaling_governor scaling_min_freq "
        "scaling_max_freq scaling_cur_freq cpuinfo_min_freq cpuinfo_max_freq; do [ -r $d/$f ] && echo $f=$(cat $d/$f); done; "
        "[ -r $d/stats/time_in_state ] && { echo TIME_IN_STATE; cat $d/stats/time_in_state; }; done; "
        "echo __THERMAL_SYSFS__; for f in /sys/class/thermal/thermal_zone*/temp "
        "/sys/class/thermal/cooling_device*/cur_state; do [ -r $f ] && echo $f=$(cat $f); done; "
        "echo __THERMAL_SERVICE__; dumpsys thermalservice; echo __TASKS__; "
        "for t in /proc/$p/task/*; do tid=${t##*/}; echo TID=$tid; cat $t/comm; cat $t/stat; cat $t/schedstat; "
        "grep -E '^(Cpus_allowed_list|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):' $t/status; done; "
        "echo __PROCESS__; cat /proc/$p/stat; echo CLK_TCK=$(getconf CLK_TCK)")


def parse_environment(raw: str, captured_ns: int | None = None) -> dict[str, object]:
    captured_ns = time.monotonic_ns() if captured_ns is None else captured_ns
    online_match = re.search(r"__ONLINE__\n([^\n]+)", raw)
    process_match = re.search(r"__PROCESS__\n([^\n]+)\nCLK_TCK=(\d+)", raw)
    if not online_match or not process_match:
        raise RuntimeError("incomplete environment sample")
    tasks: list[dict[str, object]] = []
    task_area = raw.split("__TASKS__\n", 1)[1].split("__PROCESS__\n", 1)[0]
    for chunk in task_area.split("TID=")[1:]:
        lines = chunk.strip().splitlines()
        tid, name, stat_line, sched_line = int(lines[0]), lines[1], lines[2], lines[3]
        stat, sched = stat_line.split(), sched_line.split()
        status = {line.split(":", 1)[0]: line.split(":", 1)[1].strip() for line in lines[4:] if ":" in line}
        tasks.append({"tid": tid, "name": name, "cpu": int(stat[38]),
                      "ticks": int(stat[13]) + int(stat[14]), "runtime_ns": int(sched[0]),
                      "wait_ns": int(sched[1]), "slices": int(sched[2]),
                      "cpus_allowed": status.get("Cpus_allowed_list", ""),
                      "voluntary": int(status.get("voluntary_ctxt_switches", -1)),
                      "involuntary": int(status.get("nonvoluntary_ctxt_switches", -1))})
    process_stat = process_match.group(1).split()
    freq_area = raw.split("__CPUFREQ__\n", 1)[1].split("__THERMAL_SYSFS__\n", 1)[0]
    stable_freq = re.findall(r"(POLICY=policy\d+|scaling_governor=\S+|scaling_min_freq=\d+|scaling_max_freq=\d+)", freq_area)
    policy_count = len(re.findall(r"^POLICY=", freq_area, re.M))
    freq_config_complete = policy_count > 0 and all(
        len(re.findall(rf"^{field}=", freq_area, re.M)) == policy_count
        for field in ("scaling_governor", "scaling_min_freq", "scaling_max_freq"))
    thermal_area = raw.split("__THERMAL_SERVICE__\n", 1)[1].split("__TASKS__\n", 1)[0]
    global_thermal = re.search(r"^Thermal Status:\s*(\d+)$", thermal_area, re.M)
    thermal_statuses = [int(value) for value in re.findall(
        r"mStatus\s*=\s*(\d+)", thermal_area)]
    cpu_cooling_states = {
        name: int(value) for value, name in re.findall(
            r"CoolingDevice\{mValue=(\d+),[^}]*mName=(thermal-cpufreq-[^},]+)", thermal_area)
    }
    graph = [task for task in tasks if task["name"] == "vpp_main" or str(task["name"]).startswith("vpp_wk_")]
    return {"monotonic_ns": captured_ns, "online": online_match.group(1).strip(),
            "tasks": tasks, "graph_tasks": graph,
            "process_ticks": int(process_stat[13]) + int(process_stat[14]),
            "clk_tck": int(process_match.group(2)), "stable_freq": stable_freq,
            "freq_config_complete": freq_config_complete,
            "cpufreq_residency_available": "TIME_IN_STATE" in freq_area,
            "thermal_global_status": int(global_thermal.group(1)) if global_thermal else None,
            "thermal_statuses": thermal_statuses, "cpu_cooling_states": cpu_cooling_states,
            "thermal_throttled": (global_thermal is not None and int(global_thermal.group(1)) != 0)
            or any(cpu_cooling_states.values()),
            "raw": raw}


def environment_sample(arm: str) -> dict[str, object]:
    raw = raw_environment(arm)
    return parse_environment(raw, time.monotonic_ns())


def cpu_list(value: str) -> set[int]:
    result: set[int] = set()
    for part in value.split(","):
        bounds = part.split("-", 1)
        first, last = int(bounds[0]), int(bounds[-1])
        result.update(range(first, last + 1))
    return result


def environment_errors(samples: list[dict[str, object]], missing: int, expected_intervals: int) -> list[str]:
    errors: list[str] = []
    if missing / expected_intervals > MAX_MISSING_FRACTION:
        errors.append(f"missing-metric-intervals={missing}/{expected_intervals}")
    if not samples:
        return errors + ["no-environment-samples"]
    baseline_freq = samples[0]["stable_freq"]
    baseline_tids = {int(t["tid"]): str(t["name"]) for t in samples[0]["graph_tasks"]}
    if len(baseline_tids) != 2 or sorted(baseline_tids.values()) != ["vpp_main", "vpp_wk_0"]:
        errors.append(f"unexpected-graph-tasks={baseline_tids}")
    if not baseline_freq or not samples[0]["freq_config_complete"]:
        errors.append("cpufreq-config-unavailable")
    if not samples[0]["cpufreq_residency_available"]:
        errors.append("cpufreq-residency-unavailable")
    if samples[0]["thermal_global_status"] is None or not samples[0]["cpu_cooling_states"]:
        errors.append("thermal-status-unavailable")
    for index, sample in enumerate(samples):
        if not {0, 1}.issubset(cpu_list(str(sample["online"]))):
            errors.append(f"cpu-offline@{index}={sample['online']}")
        if sample["stable_freq"] != baseline_freq:
            errors.append(f"cpufreq-config-changed@{index}")
        if not sample["freq_config_complete"] or not sample["cpufreq_residency_available"]:
            errors.append(f"cpufreq-evidence-missing@{index}")
        if sample["thermal_global_status"] is None or not sample["cpu_cooling_states"]:
            errors.append(f"thermal-status-missing@{index}")
        if sample["thermal_throttled"]:
            errors.append(f"thermal-throttled@{index}")
        graph = {int(t["tid"]): t for t in sample["graph_tasks"]}
        if {tid: str(task["name"]) for tid, task in graph.items()} != baseline_tids:
            errors.append(f"graph-task-identity@{index}")
            continue
        for task in graph.values():
            target = 0 if task["name"] == "vpp_main" else 1
            if task["cpu"] != target or task["cpus_allowed"] != str(target):
                errors.append(f"migration@{index}:{task['name']} cpu={task['cpu']} allowed={task['cpus_allowed']}")
            if int(task["voluntary"]) < 0 or int(task["involuntary"]) < 0:
                errors.append(f"context-evidence-missing@{index}:{task['name']}")
    return errors


def collect_window(arm: str, seconds: float, baseline: dict[str, object], checkpoint: Path
                   ) -> tuple[list[dict[str, object]], int, int]:
    deadline = time.monotonic() + seconds
    # Boundary samples are taken by the caller.  Keep the final internal sample
    # one interval before the boundary so environment collection cannot lengthen
    # the arm's CLOCK_MONOTONIC estimator window.
    expected = max(1, math.floor(seconds / METRIC_INTERVAL_SECONDS) - 1)
    samples: list[dict[str, object]] = []
    missing = 0
    last_error: str | None = None

    def save_checkpoint() -> None:
        write_json(checkpoint, {"expected_intervals": expected, "missing": missing,
                                "last_error": last_error, "samples": samples})

    for interval in range(expected):
        target = deadline - seconds + (interval + 1) * METRIC_INTERVAL_SECONDS
        time.sleep(max(0.0, target - time.monotonic()))
        try:
            samples.append(environment_sample(arm))
            save_checkpoint()
            errors = environment_errors([baseline, *samples], missing, expected)
            if errors:
                raise RuntimeError("environment-invalid:" + ";".join(errors))
        except (RuntimeError, subprocess.SubprocessError) as error:
            if isinstance(error, RuntimeError) and str(error).startswith("environment-invalid:"):
                last_error = str(error)
                save_checkpoint()
                raise
            missing += 1
            last_error = f"{type(error).__name__}:{error}"
            save_checkpoint()
            if missing / expected > MAX_MISSING_FRACTION:
                raise RuntimeError(
                    f"missing-metric-intervals={missing}/{expected};last={type(error).__name__}:{error}")
    time.sleep(max(0.0, deadline - time.monotonic()))
    return samples, missing, expected


def process_cpu_percent(before: dict[str, object], after: dict[str, object]) -> float:
    if before["clk_tck"] != after["clk_tck"]:
        raise RuntimeError("CLK_TCK changed")
    ticks = int(after["process_ticks"]) - int(before["process_ticks"])
    elapsed = (int(after["monotonic_ns"]) - int(before["monotonic_ns"])) / 1e9
    if ticks < 0 or elapsed <= 0:
        raise RuntimeError("invalid process CPU delta")
    return 100.0 * (ticks / int(before["clk_tck"])) / elapsed


def save_environment(case_dir: Path, name: str, sample: dict[str, object]) -> None:
    raw = str(sample["raw"])
    (case_dir / f"{name}.txt").write_text(raw)
    structured = {key: value for key, value in sample.items() if key != "raw"}
    write_json(case_dir / f"{name}.json", structured)


def idle_case(block: int, arm: str, order_index: int, result_dir: Path) -> dict[str, object]:
    case_dir = result_dir / "idle" / f"{order_index:02d}-block{block + 1}-{arm}-{ARMS[arm]['label']}"
    case_dir.mkdir(parents=True)
    start_vpp(arm, case_dir)
    try:
        warm_baseline = environment_sample(arm)
        save_environment(case_dir, "warmup-environment-baseline", warm_baseline)
        warm_samples, warm_missing, warm_expected = collect_window(
            arm, IDLE_WARMUP_SECONDS, warm_baseline, case_dir / "warmup-environment-intervals.json")
        show_before = ctl(arm, "show handoff-perf")
        before = environment_sample(arm)
        save_environment(case_dir, "environment-before", before)
        boundary_errors = environment_errors([warm_baseline, *warm_samples, before], warm_missing, warm_expected)
        if boundary_errors:
            raise RuntimeError("warmup-boundary-invalid:" + ";".join(boundary_errors))
        interval_samples, missing, expected = collect_window(
            arm, IDLE_SAMPLE_SECONDS, before, case_dir / "sample-environment-intervals.json")
        after = environment_sample(arm)
        save_environment(case_dir, "environment-after", after)
        show_after = ctl(arm, "show handoff-perf")
        parsed_before, parsed_after = parse_show(show_before), parse_show(show_after)
        errors = environment_errors([warm_baseline, *warm_samples, before, *interval_samples, after],
                                    warm_missing + missing, warm_expected + expected)
        for key in ("generated", "ingress", "terminal", "reclaimed", "outstanding"):
            if int(parsed_after.get(key, -1)) != 0:
                errors.append(f"idle-{key}={parsed_after.get(key)}")
        for key in ("write_errors", "fq_full_waits", "wake_faults", "notifying"):
            if int(parsed_after.get(key, 0)) != 0:
                errors.append(f"idle-{key}={parsed_after.get(key)}")
        payload = {"phase": "idle", "block": block + 1, "order_index": order_index, "arm": arm,
                   "label": ARMS[arm]["label"], "wake_mode": ARMS[arm]["wake_mode"],
                   "valid": not errors, "errors": errors,
                   "cpu_single_core_percent": process_cpu_percent(before, after),
                   "process_ticks_delta": int(after["process_ticks"]) - int(before["process_ticks"]),
                   "elapsed_monotonic_ns": int(after["monotonic_ns"]) - int(before["monotonic_ns"]),
                   "warmup_metric_intervals": warm_expected, "warmup_missing": warm_missing,
                   "sample_metric_intervals": expected, "sample_missing": missing,
                   "before_counters": parsed_before, "after_counters": parsed_after}
        write_json(case_dir / "environment-intervals.json", interval_samples)
        (case_dir / "show-before.txt").write_text(show_before)
        (case_dir / "show-after.txt").write_text(show_after)
        write_json(case_dir / "result.json", payload)
        return payload
    finally:
        stop_vpp(arm)


def settle(arm: str, deadline: float) -> tuple[str, dict[str, int | float]]:
    show, parsed = "", {}
    while time.monotonic() < deadline:
        show = ctl(arm, "show handoff-perf")
        parsed = parse_show(show)
        if int(parsed.get("outstanding", -1)) == 0:
            return show, parsed
        time.sleep(.01)
    raise TimeoutError("latency arm did not settle before 660-second deadline")


def run_rate_segment(arm: str, events: int, command: str | None, deadline: float,
                     baseline: dict[str, object], checkpoint: Path
                     ) -> tuple[str, dict[str, int | float], list[dict[str, object]], int, int]:
    response = ctl(arm, command) if command else ctl(arm, "handoff-perf resume")
    expected = "handoff-perf started" if command else "handoff-perf resumed with counters reset"
    if expected not in response:
        raise RuntimeError(response)
    # The rate scheduler grants its first whole packet after one second.  A
    # quarter-second guard stops after the requested whole credit but before the
    # next one; the exact generated count below remains the acceptance rule.
    segment_seconds = events / LATENCY_RATE_PPS + 0.25
    samples, missing, expected = collect_window(arm, segment_seconds, baseline, checkpoint)
    if time.monotonic() >= deadline:
        raise TimeoutError("latency arm exceeded 660-second deadline")
    ctl(arm, "handoff-perf stop")
    show, parsed = settle(arm, deadline)
    return show, parsed, samples, missing, expected


def latency_ledger_errors(parsed: dict[str, int | float], expected: int, arm: str,
                          measured: bool) -> list[str]:
    errors: list[str] = []
    if arm not in ("B", "C"):
        errors.append(f"unsupported-latency-arm={arm}")
        expected_wake_mode = -1
    else:
        expected_wake_mode = int(ARMS[arm]["wake_mode"])
    for key in ("generated", "ingress", "terminal", "reclaimed", "samples", "sampled_remote", "exact_samples"):
        if int(parsed.get(key, -1)) != expected:
            errors.append(f"{key}={parsed.get(key)} expected={expected}")
    for key in ("ingress_drops", "alloc_errors", "return_drops", "reclaim_overflows", "clock_anomalies",
                "credit_stalls", "outstanding", "write_errors", "fq_full_waits", "wake_faults",
                "wake_fault_code", "notifying", "exact_overflows", "exact_sleep_overflows"):
        if int(parsed.get(key, -1)) != 0:
            errors.append(f"{key}={parsed.get(key)}")
    if int(parsed.get("target_sleeping", -1)) != expected:
        errors.append(f"target_sleeping={parsed.get('target_sleeping')} expected={expected}")
    if int(parsed.get("exact_sleep_samples", -1)) != expected:
        errors.append(f"exact_sleep_samples={parsed.get('exact_sleep_samples')} expected={expected}")
    if int(parsed.get("scheduled_packets", -1)) != expected:
        errors.append(f"scheduled_packets={parsed.get('scheduled_packets')} expected={expected}")
    if float(parsed.get("backlog_packets", math.nan)) != 0.0:
        errors.append(f"backlog_packets={parsed.get('backlog_packets')} expected=0.0")
    if int(parsed.get("reported_wake_mode", -1)) != expected_wake_mode:
        errors.append(f"wake_mode={parsed.get('reported_wake_mode')} expected={expected_wake_mode}")
    if int(parsed.get("reported_require_sleeping", -1)) != 1:
        errors.append(f"require_sleeping={parsed.get('reported_require_sleeping')} expected=1")
    if "sleep_wait_retries" not in parsed:
        errors.append("sleep_wait_retries=missing")
    if measured and expected != LATENCY_MEASURED_EVENTS:
        errors.append("internal-measured-count")
    return errors


def latency_start_command(arm: str) -> str:
    if arm not in ("B", "C"):
        raise ValueError(f"latency require-sleeping is only supported for patched B/C arms, got {arm}")
    return ("handoff-perf start mode handoff-one distribution hot burst 1 packet-size 64 "
            f"sample-rate 1 seed {SEED} tokens 1 rate {LATENCY_RATE_PPS} "
            f"wake-workers {ARMS[arm]['wake_mode']} {REQUIRE_SLEEPING_CLI}")


def latency_case(block: int, arm: str, order_index: int, result_dir: Path) -> dict[str, object]:
    case_dir = result_dir / "latency" / f"{order_index:02d}-block{block + 1}-{arm}-{ARMS[arm]['label']}"
    case_dir.mkdir(parents=True)
    start_vpp(arm, case_dir)
    deadline = time.monotonic() + LATENCY_ARM_TIMEOUT_SECONDS
    try:
        before = environment_sample(arm)
        save_environment(case_dir, "environment-before", before)
        command = latency_start_command(arm)
        warm_show, warm, warm_samples, warm_missing, warm_expected = run_rate_segment(
            arm, LATENCY_WARMUP_EVENTS, command, deadline, before,
            case_dir / "warmup-environment-intervals.json")
        warm_errors = latency_ledger_errors(warm, LATENCY_WARMUP_EVENTS, arm, measured=False)
        warm_errors += environment_errors([before, *warm_samples], warm_missing, warm_expected)
        (case_dir / "warmup-show.txt").write_text(warm_show)
        write_json(case_dir / "warmup-environment-samples.json", warm_samples)
        if warm_errors:
            failure = {"phase": "latency-warmup", "block": block + 1, "arm": arm,
                       "valid": False, "errors": warm_errors, "warmup": warm,
                       "measured_started": False}
            write_json(case_dir / "warmup-failure.json", failure)
            raise RuntimeError("warmup-invalid:" + ";".join(warm_errors))
        measured_show, measured, measured_samples, measured_missing, measured_expected = run_rate_segment(
            arm, LATENCY_MEASURED_EVENTS, None, deadline, before,
            case_dir / "measured-environment-intervals.json")
        measured_errors = latency_ledger_errors(measured, LATENCY_MEASURED_EVENTS, arm, measured=True)
        after = environment_sample(arm)
        save_environment(case_dir, "environment-after", after)
        environment = environment_errors([before, *warm_samples, *measured_samples, after],
                                         warm_missing + measured_missing,
                                         warm_expected + measured_expected)
        cleanup = ctl(arm, "handoff-perf cleanup")
        if "handoff-perf token pool cleaned" not in cleanup:
            measured_errors.append("cleanup-failed")
        cleanup_show = ctl(arm, "show handoff-perf")
        cleanup_state = parse_show(cleanup_show)
        for key in ("running", "tokens_live", "tokens_available", "outstanding", "wake_faults",
                    "wake_fault_code", "notifying"):
            if int(cleanup_state.get(key, -1)) != 0:
                measured_errors.append(f"cleanup-{key}={cleanup_state.get(key)}")
        elapsed = LATENCY_ARM_TIMEOUT_SECONDS - (deadline - time.monotonic())
        errors = warm_errors + measured_errors + environment
        if elapsed > LATENCY_ARM_TIMEOUT_SECONDS:
            errors.append(f"arm-timeout={elapsed}")
        payload = {"phase": "latency", "block": block + 1, "order_index": order_index,
                   "arm": arm, "label": ARMS[arm]["label"], "wake_mode": ARMS[arm]["wake_mode"],
                   "valid": not errors, "errors": errors, "seed": SEED, "rate_pps": LATENCY_RATE_PPS,
                   "warmup_events": LATENCY_WARMUP_EVENTS, "measured_events": LATENCY_MEASURED_EVENTS,
                   "total_events": int(warm.get("generated", -1)) + int(measured.get("generated", -1)),
                   "overall_seconds": elapsed, "warmup": warm, "measured": measured,
                   "cleanup_state": cleanup_state,
                   "metric_intervals": warm_expected + measured_expected,
                   "metric_intervals_missing": warm_missing + measured_missing,
                   "require_sleeping": LATENCY_REQUIRE_SLEEPING,
                   "sleep_wait_retries": measured.get("sleep_wait_retries"),
                   "exact_sleep_p50": measured.get("exact_sleep_p50"),
                   "exact_sleep_p99": measured.get("exact_sleep_p99")}
        write_json(case_dir / "environment-intervals.json", [*warm_samples, *measured_samples])
        (case_dir / "measured-show.txt").write_text(measured_show)
        (case_dir / "cleanup.txt").write_text(cleanup)
        (case_dir / "cleanup-show.txt").write_text(cleanup_show)
        write_json(case_dir / "result.json", payload)
        return payload
    finally:
        stop_vpp(arm)


def one_sided_bounds(values: list[float]) -> tuple[float | None, float | None, float | None]:
    if len(values) != 8:
        return None, None, None
    mean = statistics.fmean(values)
    margin = T95_DF7 * statistics.stdev(values) / math.sqrt(8)
    return mean, mean - margin, mean + margin


def summarize(rows: list[dict[str, object]]) -> dict[str, object]:
    idle = [row for row in rows if row.get("phase") == "idle"]
    latency = [row for row in rows if row.get("phase") == "latency"]
    summary_errors: list[str] = []
    summary: dict[str, object] = {
        "all_cases_valid": len(rows) > 0 and all(bool(row.get("valid", False)) for row in rows),
        "errors": summary_errors,
    }
    for row in rows:
        if not bool(row.get("valid", False)):
            reasons = row.get("errors", ["invalid-row"])
            summary_errors.append(
                f"row-{row.get('phase', 'unknown')}-block-{row.get('block', '?')}-{row.get('arm', '?')}:"
                f"{reasons}")

    def finite_metric(row: dict[str, object], key: str) -> float | None:
        if not bool(row.get("valid", False)):
            return None
        try:
            value = float(row[key])
        except (KeyError, TypeError, ValueError, OverflowError):
            return None
        return value if math.isfinite(value) else None

    if idle:
        differences: list[float] = []
        for block in range(1, 9):
            a_row = next((row for row in idle if row.get("block") == block and row.get("arm") == "A"), {})
            c_row = next((row for row in idle if row.get("block") == block and row.get("arm") == "C"), {})
            a = finite_metric(a_row, "cpu_single_core_percent")
            c = finite_metric(c_row, "cpu_single_core_percent")
            if a is None or c is None:
                summary_errors.append(f"idle-block-{block}:missing-valid-finite-A/C-cpu-metric")
                continue
            differences.append(c - a)
        mean, lower, upper = one_sided_bounds(differences)
        summary["idle"] = {"C_minus_A_cpu_pp": differences, "mean_pp": mean,
                           "one_sided_95_lower_pp": lower, "one_sided_95_upper_pp": upper,
                           "errors": [error for error in summary_errors if error.startswith("idle-")],
                           "t_df7": T95_DF7, "go": len(differences) == 8 and upper is not None
                           and upper <= IDLE_UPPER_GATE_PP
                           and all(bool(row.get("valid", False)) for row in idle)}
    if latency:
        p99_improvements: list[float] = []
        p50_regressions: list[float] = []
        for block in range(1, 9):
            b_row = next((row for row in latency if row.get("block") == block and row.get("arm") == "B"), {})
            c_row = next((row for row in latency if row.get("block") == block and row.get("arm") == "C"), {})
            b99 = finite_metric(b_row, "exact_sleep_p99")
            c99 = finite_metric(c_row, "exact_sleep_p99")
            b50 = finite_metric(b_row, "exact_sleep_p50")
            c50 = finite_metric(c_row, "exact_sleep_p50")
            if None in (b99, c99, b50, c50):
                summary_errors.append(f"latency-block-{block}:missing-valid-finite-B/C-quantile")
                continue
            assert b99 is not None and c99 is not None and b50 is not None and c50 is not None
            if b99 <= 0 or b50 <= 0:
                summary_errors.append(f"latency-block-{block}:nonpositive-B-denominator-p99={b99}-p50={b50}")
                continue
            p99_improvements.append((b99 - c99) / b99)
            p50_regressions.append((c50 - b50) / b50)
        p99_mean, p99_lower, p99_upper = one_sided_bounds(p99_improvements)
        p50_mean, p50_lower, p50_upper = one_sided_bounds(p50_regressions)
        summary["latency"] = {"paired_p99_improvement": p99_improvements, "p99_mean": p99_mean,
                              "p99_one_sided_95_lower": p99_lower, "p99_one_sided_95_upper": p99_upper,
                              "paired_p50_regression": p50_regressions, "p50_mean": p50_mean,
                              "p50_one_sided_95_lower": p50_lower, "p50_one_sided_95_upper": p50_upper,
                              "errors": [error for error in summary_errors if error.startswith("latency-")],
                              "t_df7": T95_DF7, "go": len(p99_improvements) == 8
                              and p99_lower is not None and p50_upper is not None
                              and p99_lower >= P99_LOWER_GATE and p50_upper <= P50_UPPER_GATE
                              and all(bool(row.get("valid", False)) for row in latency)}
    if summary_errors:
        summary["all_cases_valid"] = False
    summary["power"] = {"status": "INCONCLUSIVE", "reason": "no calibrated external power meter"}
    return summary


def artifact_manifest() -> dict[str, object]:
    artifacts: dict[str, object] = {}
    for arm in ("A", "B"):
        build = Path(ARMS[arm]["build"])
        files = [build / "bin/vpp", build / "bin/vppctl",
                 build / "lib/aarch64-linux-android/vpp_plugins/handoff_perf_poc_plugin.so"]
        files += [build / "lib/aarch64-linux-android" / name for name in LIBS]
        artifacts[arm] = {str(path): digest(path) for path in files}
    source_names = ("main.h", "threads.h", "file.c", "buffer_funcs.c")
    return {"binaries": artifacts,
            "sources": {"patched": {str(PATCHED_SOURCE / name): digest(PATCHED_SOURCE / name) for name in source_names},
                        "unpatched": {str(UNPATCHED_SOURCE / name): digest(UNPATCHED_SOURCE / name) for name in source_names}},
            "measurement_harness": {
                "require_sleeping": LATENCY_REQUIRE_SLEEPING,
                "canonical_plugin_source": str(CANONICAL_PLUGIN_SOURCE),
                "canonical_plugin_sha256": digest(CANONICAL_PLUGIN_SOURCE),
                "runner_source": str(RUNNER_SOURCE),
                "runner_sha256": digest(RUNNER_SOURCE)},
            "patched_build_cache": digest(PATCHED / "CMakeCache.txt"), "vlib_wake_diagnostics": 0}


def staged_paths(arm: str) -> list[tuple[Path, str]]:
    build = Path(ARMS[arm]["build"])
    root = remote_root(arm)
    local = [build / "bin/vpp", build / "bin/vppctl",
             build / "lib/aarch64-linux-android/vpp_plugins/handoff_perf_poc_plugin.so"]
    local += [build / "lib/aarch64-linux-android" / name for name in LIBS]
    remote = [f"{root}/bin/vpp", f"{root}/bin/vppctl", f"{root}/plugins/handoff_perf_poc_plugin.so"]
    remote += [f"{root}/lib/{name}" for name in LIBS]
    return list(zip(local, remote))


def preflight(result_dir: Path) -> int:
    result_dir.mkdir(parents=True, exist_ok=False)
    identity = device_identity()
    stage()
    rows: list[dict[str, object]] = []
    try:
        for arm in ("A", "B", "C"):
            case_dir = result_dir / f"{arm}-{ARMS[arm]['label']}"
            case_dir.mkdir()
            start_vpp(arm, case_dir)
            try:
                sample = environment_sample(arm)
                show = ctl(arm, "show handoff-perf")
                parsed = parse_show(show)
                errors = environment_errors([sample], 0, 1)
                for key in ("generated", "ingress", "terminal", "reclaimed", "outstanding",
                            "write_errors", "fq_full_waits", "wake_faults", "notifying"):
                    if int(parsed.get(key, 0)) != 0:
                        errors.append(f"preflight-{key}={parsed.get(key)}")
                if arm != "A" and int(parsed.get("reported_wake_mode", -1)) != int(ARMS[arm]["wake_mode"]):
                    errors.append(f"wake-mode={parsed.get('reported_wake_mode')} expected={ARMS[arm]['wake_mode']}")
                if "generated " not in show:
                    errors.append("handoff-perf-plugin-unavailable")
                remote_hashes: dict[str, str] = {}
                for local, remote in staged_paths(arm):
                    observed = su(f"sha256sum {remote}").split()[0]
                    remote_hashes[remote] = observed
                    if observed != digest(local):
                        errors.append(f"remote-hash-mismatch={remote}")
                payload = {"arm": arm, "label": ARMS[arm]["label"],
                           "configured_wake_mode": None if arm == "A" else ARMS[arm]["wake_mode"],
                           "valid": not errors, "errors": errors, "remote_hashes": remote_hashes,
                           "counters": parsed}
                save_environment(case_dir, "environment", sample)
                (case_dir / "show.txt").write_text(show)
                write_json(case_dir / "result.json", payload)
                rows.append(payload)
            finally:
                stop_vpp(arm)
    finally:
        stop_vpp("A")
        stop_vpp("B")
    summary = {"preflight": True, "device": identity, "timed_arms_started": 0,
               "all_cases_valid": len(rows) == 3 and all(bool(row["valid"]) for row in rows), "cases": rows}
    write_json(result_dir / "summary.json", summary)
    print(json_text({"result": str(result_dir), "summary": summary}), end="")
    return 0 if summary["all_cases_valid"] else 1


def protocol_plan() -> dict[str, object]:
    return {"protocol": "P6d", "default_action": "plan-only", "seed_hex": hex(SEED),
            "device": {"model": "Pixel 6a", "android": "16", "api": 36, "adb": str(ADB)},
            "idle": {"orders": IDLE_ORDERS, "pairs": 8, "warmup_seconds": IDLE_WARMUP_SECONDS,
                     "sample_seconds": IDLE_SAMPLE_SECONDS, "arms": {"A": ARMS["A"], "C": ARMS["C"]},
                     "estimator": "100 * delta process CPU time / delta CLOCK_MONOTONIC",
                     "one_sided_t95_df7": T95_DF7, "upper_gate_pp": IDLE_UPPER_GATE_PP},
            "latency": {"orders": LATENCY_ORDERS, "pairs": 8, "rate_pps": LATENCY_RATE_PPS,
                        "events_per_arm": LATENCY_TOTAL_EVENTS, "warmup_events": LATENCY_WARMUP_EVENTS,
                        "measured_events": LATENCY_MEASURED_EVENTS, "timeout_seconds": LATENCY_ARM_TIMEOUT_SECONDS,
                        "arms": {"B": ARMS["B"], "C": ARMS["C"]},
                        "require_sleeping": LATENCY_REQUIRE_SLEEPING,
                        "sleep_wait_retries": "diagnostic only; zero is valid",
                        "p99_lower_gate": P99_LOWER_GATE, "p50_upper_gate": P50_UPPER_GATE},
            "fixed_arm_count": 32, "fixed_arm_time_upper_seconds": 32 * 660,
            "fixed_arm_time_upper": "5h52m plus staging and settlement",
            "restart_rule": "any invalid arm invalidates the campaign; preserve it and restart from block 1"}


def self_test() -> None:
    assert IDLE_ORDERS == ("AC", "CA", "CA", "AC", "CA", "AC", "AC", "CA")
    assert LATENCY_ORDERS == ("BC", "CB", "BC", "CB", "CB", "BC", "CB", "BC")
    assert SEED == 0x5A4B20260802 and LATENCY_TOTAL_EVENTS == 620 and T95_DF7 == 1.894578605
    assert ARMS["A"]["wake_mode"] == 0  # informational only; A never receives a wake-mode CLI.
    assert ARMS["B"]["build"] == ARMS["C"]["build"] == PATCHED
    assert (ARMS["B"]["wake_mode"], ARMS["C"]["wake_mode"]) == (3, 2)
    assert len(IDLE_ORDERS) * 2 + len(LATENCY_ORDERS) * 2 == 32
    assert 32 * 660 == 21120
    for arm in ("B", "C"):
        command = latency_start_command(arm)
        assert command.endswith(f"wake-workers {ARMS[arm]['wake_mode']} {REQUIRE_SLEEPING_CLI}")
        assert command.count(REQUIRE_SLEEPING_CLI) == 1
    try:
        latency_start_command("A")
    except ValueError:
        pass
    else:
        raise AssertionError("exact-unpatched A must not receive require-sleeping")
    mean, lower, upper = one_sided_bounds([0.01] * 8)
    assert abs(mean - 0.01) < 1e-12 and abs(lower - 0.01) < 1e-12 and abs(upper - 0.01) < 1e-12
    sample = ("running 0 mode handoff-one distribution hot burst 1 packet-size 64 sample-rate 1 "
              "offered-pps 1 workers 1 tokens-live 0 tokens-available 0 wake-workers 2 require-sleeping 1\n"
              "generated 600 bytes 1 local 0 ingress-enqueued 600 ingress-drops 0 alloc-errors 0 "
              "terminal 600 bytes 1 return-enqueued 0 return-drops 0 reclaimed 600 reclaim-overflows 0 "
              "clock-anomalies 0 credit-stalls 0 outstanding-packets 0\n"
              "rate-scheduler scheduled-packets 600 backlog-packets 0.00 timer-wakes 600 "
              "missed-wakes 0 wake-requests 600 tick-usec 100\n"
              "samples 600 latency-min 1 latency-mean 2.0 latency-p50-upper 2 latency-p95-upper 3 latency-p99-upper 4 latency-max 5\n"
              "wake-diagnostics calls 1 sleeps-seen 1 pending-claims 0 writes 1 write-errors 0 fq-full-waits 0\n"
              "wake-state epoch-max 1 faults 0 fault-code 0 awake 2 preparing 0 sleeping 0 notified 0 draining 0 notifying 0\n"
              "sleep-proof sampled-remote-enqueues 600 target-sleeping 600 sleep-wait-retries 0\n"
              "exact-latency samples 600 overflows 0 p50 2 p95 3 p99 4\n"
              "exact-sleep-latency samples 600 overflows 0 p50 2 p95 3 p99 4")
    assert not latency_ledger_errors(parse_show(sample), 600, "C", measured=True)
    b_sample = sample.replace("wake-workers 2", "wake-workers 3")
    assert not latency_ledger_errors(parse_show(b_sample), 600, "B", measured=True)
    assert parse_show(sample)["sleep_wait_retries"] == 0
    retried = sample.replace("sleep-wait-retries 0", "sleep-wait-retries 7")
    assert parse_show(retried)["sleep_wait_retries"] == 7
    assert not latency_ledger_errors(parse_show(retried), 600, "C", measured=True)
    assert any("wake_mode=" in error
               for error in latency_ledger_errors(parse_show(sample), 600, "B", measured=True))
    no_config = sample.split("\n", 1)[1]
    assert any("wake_mode=None" in error
               for error in latency_ledger_errors(parse_show(no_config), 600, "C", measured=True))
    assert any("scheduled_packets=" in error for error in latency_ledger_errors(
        parse_show(sample.replace("scheduled-packets 600", "scheduled-packets 599")),
        600, "C", measured=True))
    assert any("backlog_packets=" in error for error in latency_ledger_errors(
        parse_show(sample.replace("backlog-packets 0.00", "backlog-packets 1.00")),
        600, "C", measured=True))
    assert any("unsupported-latency-arm=A" in error
               for error in latency_ledger_errors(parse_show(sample), 600, "A", measured=True))
    legacy_sleep = parse_show("sleep-proof sampled-remote-enqueues 12 target-sleeping 11")
    assert legacy_sleep == {"sampled_remote": 12, "target_sleeping": 11}
    partial_idle = summarize([
        {"phase": "idle", "block": 1, "arm": "A", "valid": True,
         "cpu_single_core_percent": 0.1},
        {"phase": "idle", "block": 1, "arm": "C", "valid": False,
         "errors": ["exception"]},
    ])
    assert not partial_idle["all_cases_valid"] and not partial_idle["idle"]["go"]
    assert partial_idle["idle"]["errors"]
    json.dumps(partial_idle, allow_nan=False)
    zero_denominators = summarize([
        {"phase": "latency", "block": 1, "arm": "B", "valid": True,
         "exact_sleep_p50": 0, "exact_sleep_p99": 0},
        {"phase": "latency", "block": 1, "arm": "C", "valid": True,
         "exact_sleep_p50": 1, "exact_sleep_p99": 1},
    ])
    assert not zero_denominators["latency"]["go"]
    assert any("nonpositive-B-denominator" in error for error in zero_denominators["errors"])
    json.dumps(zero_denominators, allow_nan=False)
    invalid_none = summarize([
        {"phase": "latency", "block": 1, "arm": "B", "valid": True,
         "exact_sleep_p50": 10, "exact_sleep_p99": 20},
        {"phase": "latency", "block": 1, "arm": "C", "valid": False,
         "exact_sleep_p50": None, "exact_sleep_p99": None},
    ])
    assert not invalid_none["latency"]["go"] and not invalid_none["latency"]["paired_p99_improvement"]
    json.dumps(invalid_none, allow_nan=False)
    base_environment = {
        "online": "0-7", "stable_freq": ["POLICY=policy0", "scaling_governor=schedutil",
                                             "scaling_min_freq=300000", "scaling_max_freq=1800000"],
        "freq_config_complete": True, "cpufreq_residency_available": True,
        "thermal_global_status": 0, "cpu_cooling_states": {"cpu0": 0}, "thermal_throttled": False,
        "graph_tasks": [
            {"tid": 1, "name": "vpp_main", "cpu": 0, "cpus_allowed": "0",
             "voluntary": 0, "involuntary": 0},
            {"tid": 2, "name": "vpp_wk_0", "cpu": 1, "cpus_allowed": "1",
             "voluntary": 0, "involuntary": 0},
        ],
    }
    changed_environment = {**base_environment, "stable_freq": [*base_environment["stable_freq"],
                                                                  "scaling_max_freq=1900000"]}
    cross_boundary = environment_errors([base_environment, changed_environment], 0, 100)
    assert "cpufreq-config-changed@1" in cross_boundary


def execute(phase: str, result_dir: Path) -> int:
    result_dir.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, object]] = []
    aborted = False

    def record(case_phase: str, block: int, arm: str, operation: Callable[[], dict[str, object]]) -> bool:
        try:
            row = operation()
        except Exception as error:
            row = {"phase": case_phase, "block": block + 1, "arm": arm, "valid": False,
                   "errors": [f"exception:{type(error).__name__}:{error}"]}
            failure = result_dir / f"failure-{case_phase}-block{block + 1}-{arm}.json"
            write_json(failure, row)
        rows.append(row)
        write_json(result_dir / "raw.json", rows)
        return bool(row["valid"])

    try:
        identity = device_identity()
        manifest = {**protocol_plan(), "run_id": RUN_ID, "phase": phase, "device_observed": identity,
                    "artifacts": artifact_manifest()}
        write_json(result_dir / "manifest.json", manifest, default=str)
        stage()
        if phase in ("idle", "all"):
            for block, order in enumerate(IDLE_ORDERS):
                for arm in order:
                    if not record("idle", block, arm,
                                  lambda block=block, arm=arm: idle_case(block, arm, len(rows), result_dir)):
                        aborted = True
                        break
                if aborted:
                    break
        if phase in ("latency", "all") and not aborted:
            for block, order in enumerate(LATENCY_ORDERS):
                for arm in order:
                    if not record("latency", block, arm,
                                  lambda block=block, arm=arm: latency_case(block, arm, len(rows), result_dir)):
                        aborted = True
                        break
                if aborted:
                    break
    except Exception as error:
        rows.append({"phase": "setup", "block": 0, "arm": "setup", "valid": False,
                     "errors": [f"exception:{type(error).__name__}:{error}"]})
        write_json(result_dir / "setup-failure.json", rows[-1])
    finally:
        for arm in ("A", "B"):
            try:
                stop_vpp(arm)
            except Exception as error:
                rows.append({"phase": "teardown", "block": 0, "arm": arm, "valid": False,
                             "errors": [f"exception:{type(error).__name__}:{error}"]})
        write_json(result_dir / "raw.json", rows)
    summary = summarize(rows)
    write_json(result_dir / "summary.json", summary)
    print(json_text({"result": str(result_dir), "summary": summary}), end="")
    required = [name for name in ("idle", "latency") if phase in (name, "all")]
    return 0 if summary["all_cases_valid"] and all(
        bool(summary.get(name, {}).get("go")) for name in required) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--execute", action="store_true", help="explicitly run the fixed formal device protocol")
    action.add_argument("--preflight", action="store_true", help="stage and run untimed A/B/C device controls only")
    action.add_argument("--self-test", action="store_true", help="run device-free protocol/parser checks")
    action.add_argument("--plan", action="store_true", help="print the frozen protocol (default)")
    parser.add_argument("--phase", choices=("idle", "latency", "all"), default="all")
    parser.add_argument("--result-dir", type=Path, default=DEFAULT_RESULT)
    args = parser.parse_args()
    result_dir = args.result_dir.resolve()
    if args.self_test:
        self_test()
        print("P6d runner self-test: PASS")
        return 0
    if args.preflight:
        return preflight(result_dir)
    if not args.execute:
        print(json_text(protocol_plan(), default=str), end="")
        return 0
    return execute(args.phase, result_dir)


if __name__ == "__main__":
    raise SystemExit(main())
