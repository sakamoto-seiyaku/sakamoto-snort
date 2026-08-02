#!/usr/bin/env python3
"""PROTOTYPE: reproducible VLIB frame-queue handoff benchmark harness."""

from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import statistics
import subprocess
import time


POC_DIR = Path(__file__).resolve().parent.parent
VPP_DIR = Path(os.environ.get("VPP_DIR", POC_DIR / "work/vpp"))
INSTALL_DIR = Path(
    os.environ.get(
        "VPP_INSTALL_DIR",
        VPP_DIR / "build-root/install-vpp-native/vpp",
    )
)
VPP_BIN = Path(os.environ.get("VPP_BIN", INSTALL_DIR / "bin/vpp"))
VPPCTL_BIN = Path(os.environ.get("VPPCTL_BIN", INSTALL_DIR / "bin/vppctl"))
PLUGIN = next(INSTALL_DIR.glob("lib/*/vpp_plugins/handoff_perf_poc_plugin.so"), None)
RUN_ID = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
RESULT_DIR = Path(
    os.environ.get(
        "RESULT_DIR",
        POC_DIR / "results" / dt.date.today().isoformat() / f"handoff-perf-{RUN_ID}",
    )
)
PROFILE = os.environ.get("PROFILE", "smoke")
DURATION = float(os.environ.get("DURATION", "1" if PROFILE == "smoke" else "3"))
WARMUP = float(os.environ.get("WARMUP", "0.5"))
REPETITIONS = int(os.environ.get("REPETITIONS", "1" if PROFILE == "smoke" else "3"))
SAMPLE_RATE = int(os.environ.get("SAMPLE_RATE", "64" if PROFILE == "smoke" else "128"))
TOKENS = int(os.environ.get("TOKENS", "8192"))
SEED = int(os.environ.get("SEED", "20260802"))
CASE_FILTER = os.environ.get("CASE_FILTER", "")
WAKE_WORKERS = int(os.environ.get("WAKE_WORKERS", "0"))


COUNTERS_RE = re.compile(
    r"generated (?P<generated>\d+) bytes (?P<generated_bytes>\d+) "
    r"local (?P<local>\d+) ingress-enqueued (?P<ingress_enqueued>\d+) "
    r"ingress-drops (?P<ingress_drops>\d+) alloc-errors (?P<alloc_errors>\d+) "
    r"terminal (?P<terminal>\d+) bytes (?P<terminal_bytes>\d+) "
    r"return-enqueued (?P<return_enqueued>\d+) return-drops (?P<return_drops>\d+) "
    r"reclaimed (?P<reclaimed>\d+) reclaim-overflows (?P<reclaim_overflows>\d+) "
    r"clock-anomalies (?P<clock_anomalies>\d+) credit-stalls (?P<credit_stalls>\d+) "
    r"outstanding-packets (?P<outstanding>\d+)"
)
CONFIG_RE = re.compile(r"measurement-seconds (?P<measurement_seconds>[0-9.]+)")
CYCLES_RE = re.compile(
    r"cycles producer-total (?P<producer_cycles>\d+) producer-batches (?P<producer_batches>\d+) "
    r"producer-per-packet (?P<producer_per_packet>[0-9.]+) "
    r"primary-enqueue-total (?P<primary_cycles>\d+) primary-enqueue-calls (?P<primary_calls>\d+) "
    r"primary-enqueue-per-packet (?P<primary_per_packet>[0-9.]+) "
    r"return-enqueue-total (?P<return_cycles>\d+) samples (?P<samples>\d+) "
    r"latency-min (?P<latency_min>\d+) latency-mean (?P<latency_mean>[0-9.]+) "
    r"latency-p50-upper (?P<p50>\d+) latency-p95-upper (?P<p95>\d+) "
    r"latency-p99-upper (?P<p99>\d+) latency-max (?P<latency_max>\d+)"
)
THREAD_RE = re.compile(
    r"thread (?P<thread>\d+) worker-packets (?P<worker_packets>\d+) "
    r"terminal (?P<terminal>\d+) return-enqueued (?P<return_enqueued>\d+) "
    r"return-drops (?P<return_drops>\d+) latency-samples (?P<latency_samples>\d+)"
)
SCHEDULER_RE = re.compile(
    r"rate-scheduler scheduled-packets (?P<scheduled_packets>\d+) "
    r"backlog-packets (?P<backlog_packets>[0-9.]+) timer-wakes (?P<timer_wakes>\d+) "
    r"missed-wakes (?P<missed_wakes>\d+) wake-requests (?P<wake_requests>\d+) "
    r"tick-usec (?P<tick_usec>[0-9.]+)"
)
WAKE_DIAGNOSTICS_RE = re.compile(
    r"wake-diagnostics calls (?P<wake_calls>\d+) sleeps-seen (?P<wake_sleeps_seen>\d+) "
    r"pending-claims (?P<wake_pending_claims>\d+) writes (?P<wake_writes>\d+) "
    r"write-errors (?P<wake_write_errors>\d+) sleep-attempts (?P<sleep_attempts>\d+) "
    r"frame-queue-rechecks (?P<sleep_frame_queue_rechecks>\d+) "
    r"epoll-wakeups (?P<sleep_epoll_wakeups>\d+) "
    r"epoll-timeouts (?P<sleep_epoll_timeouts>\d+) sleep-cycles (?P<sleep_cycles>\d+) "
    r"sleep-max-cycles (?P<sleep_max_cycles>\d+) fq-full-waits (?P<fq_full_waits>\d+) "
    r"fq-full-wait-cycles (?P<fq_full_wait_cycles>\d+) "
    r"fq-full-wait-max-cycles (?P<fq_full_wait_max_cycles>\d+)"
)


def run_text(args: list[str], *, check: bool = True) -> str:
    return subprocess.run(
        args,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def wait_cli(process: subprocess.Popen[object], socket: Path, log: Path) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"VPP exited early:\n{log.read_text(errors='replace')}")
        if socket.exists():
            probe = subprocess.run(
                [str(VPPCTL_BIN), "-s", str(socket), "show", "version"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if probe.returncode == 0:
                return
        time.sleep(0.1)
    raise RuntimeError("timed out waiting for VPP CLI")


def vppctl(socket: Path, *command: str) -> str:
    return run_text([str(VPPCTL_BIN), "-s", str(socket), *command])


def make_cases() -> list[dict[str, int | str]]:
    if PROFILE == "smoke":
        return [
            {"workers": 2, "mode": mode, "distribution": "uniform", "burst": 64, "packet": 64, "rate": 100_000}
            for mode in ("local", "handoff-one", "handoff-return", "mixed-local-fastpath", "always-enqueue")
        ]

    if PROFILE == "ceiling":
        worker_count = int(os.environ.get("WORKERS", "2"))
        base = [
            {"workers": worker_count, "mode": "local", "distribution": "hot", "burst": 64, "packet": 64, "rate": 0}
        ]
        for mode in ("handoff-one", "handoff-return"):
            for distribution in ("hot", "uniform"):
                base.append({"workers": worker_count, "mode": mode, "distribution": distribution, "burst": 64, "packet": 64, "rate": 0})
        return base

    workers = [int(value) for value in os.environ.get("WORKERS", "2 4").split()]
    bursts = [int(value) for value in os.environ.get("BURSTS", "1 8 32 64 128 256").split()]
    packets = [int(value) for value in os.environ.get("PACKETS", "64").split()]
    rates = [int(value) for value in os.environ.get("RATES", "0").split()]
    cases: list[dict[str, int | str]] = []
    for worker_count in workers:
        for burst in bursts:
            for packet in packets:
                for rate in rates:
                    cases.append({"workers": worker_count, "mode": "local", "distribution": "hot", "burst": burst, "packet": packet, "rate": rate})
                    for mode in ("handoff-one", "handoff-return"):
                        for distribution in ("hot", "uniform"):
                            cases.append({"workers": worker_count, "mode": mode, "distribution": distribution, "burst": burst, "packet": packet, "rate": rate})
                    for mode in ("mixed-local-fastpath", "always-enqueue"):
                        cases.append({"workers": worker_count, "mode": mode, "distribution": "uniform", "burst": burst, "packet": packet, "rate": rate})
    return cases


def write_manifest(cases: list[dict[str, int | str]]) -> None:
    assert PLUGIN is not None
    manifest = {
        "prototype": True,
        "question": "incremental cost of zero, one, and two VLIB frame-queue transfers",
        "run_id": RUN_ID,
        "profile": PROFILE,
        "duration_seconds": DURATION,
        "warmup_seconds": WARMUP,
        "repetitions": REPETITIONS,
        "seed": SEED,
        "tokens": TOKENS,
        "sample_rate": SAMPLE_RATE,
        "case_filter": CASE_FILTER,
        "wake_workers": WAKE_WORKERS,
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "vpp_bin": str(VPP_BIN),
        "vpp_sha256": sha256(VPP_BIN),
        "plugin": str(PLUGIN),
        "plugin_sha256": sha256(PLUGIN),
        "source_sha256": sha256(POC_DIR / "overlay/src/plugins/handoff_perf_poc/handoff_perf_poc.c"),
        "uname": run_text(["uname", "-a"]).strip(),
        "lscpu": run_text(["lscpu"]),
        "git_status": run_text(["git", "-C", str(POC_DIR.parent.parent), "status", "--short"]),
        "sleep_profile": "no poll-sleep-usec; current fork adaptive unix-input path",
        "cases": len(cases),
    }
    (RESULT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def physical_core_cpus() -> list[int]:
    selected: dict[tuple[int, int], int] = {}
    for cpu_dir in sorted(Path("/sys/devices/system/cpu").glob("cpu[0-9]*"), key=lambda path: int(path.name[3:])):
        cpu = int(cpu_dir.name[3:])
        online_path = cpu_dir / "online"
        if online_path.exists() and online_path.read_text().strip() != "1":
            continue
        topology = cpu_dir / "topology"
        package = int((topology / "physical_package_id").read_text())
        core = int((topology / "core_id").read_text())
        selected.setdefault((package, core), cpu)
    return list(selected.values())


def write_startup(worker_count: int, case_dir: Path) -> tuple[Path, Path, Path, list[int]]:
    short_id = hashlib.sha256(case_dir.name.encode()).hexdigest()[:10]
    runtime = Path("/tmp") / f"hp-{RUN_ID[-6:]}-{short_id}"
    shutil.rmtree(runtime, ignore_errors=True)
    runtime.mkdir(parents=True)
    cli = runtime / "cli.sock"
    config = case_dir / "startup.conf"
    physical_cpus = physical_core_cpus()
    if len(physical_cpus) < worker_count + 1:
        raise RuntimeError(f"need {worker_count + 1} physical cores, found {len(physical_cpus)}")
    main_core = physical_cpus[0]
    worker_cores = physical_cpus[1 : worker_count + 1]
    worker_corelist = ",".join(str(cpu) for cpu in worker_cores)
    buffers_per_numa = max(32768, TOKENS * 2)
    config.write_text(
        f"""unix {{
  nodaemon
  nobanner
  runtime-dir {runtime}
  log {case_dir / 'vpp.log'}
  cli-listen {cli}
  cli-no-pager
}}

cpu {{
  main-core {main_core}
  corelist-workers {worker_corelist}
}}

api-segment {{ prefix hp-{RUN_ID[-6:]}-{short_id} }}
statseg {{ socket-name {runtime / 'statseg.sock'} }}
buffers {{
  buffers-per-numa {buffers_per_numa}
  page-size default
}}
plugins {{
  path {PLUGIN.parent if PLUGIN else ''}
  plugin default {{ disable }}
  plugin handoff_perf_poc_plugin.so {{ enable }}
}}
"""
    )
    return config, runtime, cli, [main_core, *worker_cores]


def verify_thread_placement(show_threads: str, expected_cpus: list[int]) -> None:
    actual: list[tuple[int, int]] = []
    for line in show_threads.splitlines()[1:]:
        match = re.search(r"\s(\d+)\s+(\d+)\s+(\d+)\s*$", line)
        if match:
            actual.append((int(match.group(1)), int(match.group(2))))
    if [cpu for cpu, _ in actual] != expected_cpus:
        raise RuntimeError(f"thread lcores {actual} do not match expected CPUs {expected_cpus}")
    if len({core for _, core in actual}) != len(actual):
        raise RuntimeError(f"VPP threads share physical cores: {actual}")


def read_task_cpu(pid: int) -> dict[int, dict[str, int | str]]:
    tasks: dict[int, dict[str, int | str]] = {}
    for task_dir in sorted((Path("/proc") / str(pid) / "task").glob("[0-9]*")):
        tid = int(task_dir.name)
        stat = (task_dir / "stat").read_text()
        comm_end = stat.rfind(")")
        comm = stat[stat.find("(") + 1 : comm_end]
        fields = stat[comm_end + 2 :].split()
        status = (task_dir / "status").read_text()
        voluntary = re.search(r"^voluntary_ctxt_switches:\s+(\d+)$", status, re.MULTILINE)
        involuntary = re.search(r"^nonvoluntary_ctxt_switches:\s+(\d+)$", status, re.MULTILINE)
        tasks[tid] = {
            "name": comm,
            "ticks": int(fields[11]) + int(fields[12]),
            "context_switches": int(voluntary.group(1)) + int(involuntary.group(1)),
        }
    return tasks


def task_cpu_delta(
    before: dict[int, dict[str, int | str]], after: dict[int, dict[str, int | str]]
) -> dict[int, dict[str, int | str]]:
    delta: dict[int, dict[str, int | str]] = {}
    for tid in sorted(before.keys() & after.keys()):
        delta[tid] = {
            "name": str(after[tid]["name"]),
            "ticks": int(after[tid]["ticks"]) - int(before[tid]["ticks"]),
            "context_switches": int(after[tid]["context_switches"])
            - int(before[tid]["context_switches"]),
        }
    return delta


def parse_show(show: str) -> tuple[dict[str, int | float], dict[int, dict[str, int]]]:
    config = CONFIG_RE.search(show)
    counters = COUNTERS_RE.search(show)
    cycles = CYCLES_RE.search(show)
    scheduler = SCHEDULER_RE.search(show)
    wake_diagnostics = WAKE_DIAGNOSTICS_RE.search(show)
    if (
        config is None
        or counters is None
        or cycles is None
        or scheduler is None
        or wake_diagnostics is None
    ):
        raise RuntimeError(f"could not parse benchmark output:\n{show}")
    parsed: dict[str, int | float] = {key: int(value) for key, value in counters.groupdict().items()}
    parsed["measurement_seconds"] = float(config.group("measurement_seconds"))
    for key, value in cycles.groupdict().items():
        parsed[key] = float(value) if "." in value else int(value)
    for key, value in scheduler.groupdict().items():
        parsed[key] = float(value) if "." in value else int(value)
    for key, value in wake_diagnostics.groupdict().items():
        parsed[key] = int(value)
    threads = {
        int(match.group("thread")): {
            key: int(value)
            for key, value in match.groupdict().items()
            if key != "thread"
        }
        for match in THREAD_RE.finditer(show)
    }
    return parsed, threads


def require_cli(output: str, marker: str | None = None) -> str:
    lowered = output.lower()
    if "%error" in lowered or "unknown input" in lowered or "failed" in lowered:
        raise RuntimeError(f"VPP CLI command failed: {output.strip()}")
    if marker is not None and marker not in output:
        raise RuntimeError(f"VPP CLI response missing {marker!r}: {output.strip()}")
    return output


def distribution_errors(
    case: dict[str, int | str], generated: int, local: int,
    threads: dict[int, dict[str, int]],
) -> list[str]:
    mode = str(case["mode"])
    distribution = str(case["distribution"])
    workers = int(case["workers"])
    expected_local = (generated + 1) // 2
    expected_remote = generated // 2
    worker_packets = {thread: values["worker_packets"] for thread, values in threads.items()}
    errors: list[str] = []

    if mode == "local":
        expected = {0: 0}
    elif mode in ("handoff-one", "handoff-return"):
        expected = {0: 0}
        if distribution == "hot":
            expected[1] = generated
        else:
            for thread in range(1, workers + 1):
                expected[thread] = generated // workers + int(thread <= generated % workers)
    elif mode == "mixed-local-fastpath":
        expected = {0: 0}
        if distribution == "hot":
            expected[1] = expected_remote
        else:
            for thread in range(1, workers + 1):
                expected[thread] = expected_remote // workers + int(thread <= expected_remote % workers)
    else:
        expected = {0: expected_local}
        if distribution == "hot":
            expected[1] = expected_remote
        else:
            for thread in range(1, workers + 1):
                expected[thread] = expected_remote // workers + int(thread <= expected_remote % workers)

    if mode == "local":
        expected_terminal = {0: generated}
    elif mode == "handoff-return":
        expected_terminal = {0: generated}
    elif mode == "handoff-one":
        expected_terminal = {thread: count for thread, count in expected.items() if thread != 0}
    else:
        expected_terminal = {**expected, 0: expected_local}

    for thread in range(0, workers + 1):
        if worker_packets.get(thread, 0) != expected.get(thread, 0):
            errors.append(
                f"thread {thread} worker-packets={worker_packets.get(thread, 0)} "
                f"expected={expected.get(thread, 0)}"
            )
        terminal = threads.get(thread, {}).get("terminal", 0)
        if terminal != expected_terminal.get(thread, 0):
            errors.append(
                f"thread {thread} terminal={terminal} expected={expected_terminal.get(thread, 0)}"
            )
    if mode in ("local", "mixed-local-fastpath") and local != (
        generated if mode == "local" else expected_local
    ):
        errors.append(f"local={local} violates {mode} invariant")
    if mode not in ("local", "mixed-local-fastpath") and local != 0:
        errors.append(f"local={local} must be zero for {mode}")
    return errors


def expected_sample_threads(case: dict[str, int | str]) -> set[int]:
    mode = str(case["mode"])
    if mode in ("local", "handoff-return"):
        return {0}
    remote = {1} if case["distribution"] == "hot" else set(range(1, int(case["workers"]) + 1))
    if mode in ("mixed-local-fastpath", "always-enqueue"):
        remote.add(0)
    return remote


def write_aggregates(rows: list[dict[str, int | float | str]]) -> None:
    key_names = ("workers", "mode", "distribution", "burst", "packet", "rate", "wake_workers")
    groups: dict[tuple[object, ...], list[dict[str, int | float | str]]] = {}
    for row in rows:
        key = tuple(row[name] for name in key_names)
        groups.setdefault(key, []).append(row)
    aggregates: list[dict[str, int | float | str]] = []
    for key, members in sorted(groups.items(), key=lambda item: str(item[0])):
        terminal_pps = [float(member["terminal_pps"]) for member in members]
        mean_pps = statistics.fmean(terminal_pps)
        aggregates.append(
            {
                **dict(zip(key_names, key)),
                "runs": len(members),
                "valid_runs": sum(int(member["valid"]) for member in members),
                "median_terminal_pps": statistics.median(terminal_pps),
                "mean_terminal_pps": mean_pps,
                "cv_terminal_pps": statistics.pstdev(terminal_pps) / mean_pps if mean_pps else 0.0,
                "median_producer_cycles_per_packet": statistics.median(
                    float(member["producer_per_packet"]) for member in members
                ),
                "median_primary_cycles_per_packet": statistics.median(
                    float(member["primary_per_packet"]) for member in members
                ),
                "median_return_cycles_per_packet": statistics.median(
                    float(member["return_cycles_per_packet"]) for member in members
                ),
                "median_cpu_utilization_cores": statistics.median(
                    float(member["cpu_utilization_cores"]) for member in members
                ),
                "median_cpu_seconds_per_packet": statistics.median(
                    float(member["cpu_seconds_per_packet"]) for member in members
                ),
                "median_credit_stalls_per_batch": statistics.median(
                    int(member["credit_stalls"]) / max(int(member["producer_batches"]), 1)
                    for member in members
                ),
                "median_scheduler_missed_wake_ratio": statistics.median(
                    int(member["missed_wakes"])
                    / max(int(member["timer_wakes"]) + int(member["missed_wakes"]), 1)
                    for member in members
                ),
                "median_wake_writes_per_packet": statistics.median(
                    int(member["wake_writes"]) / max(int(member["generated"]), 1)
                    for member in members
                ),
                "median_sleep_timeouts": statistics.median(
                    int(member["sleep_epoll_timeouts"]) for member in members
                ),
                "median_fq_full_waits": statistics.median(
                    int(member["fq_full_waits"]) for member in members
                ),
                "median_fq_full_wait_cycles_per_packet": statistics.median(
                    int(member["fq_full_wait_cycles"]) / max(int(member["generated"]), 1)
                    for member in members
                ),
                "median_fq_full_wait_max_cycles": statistics.median(
                    int(member["fq_full_wait_max_cycles"]) for member in members
                ),
                "median_latency_p99_upper": statistics.median(float(member["p99"]) for member in members),
            }
        )
    with (RESULT_DIR / "aggregated.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(aggregates[0]))
        writer.writeheader()
        writer.writerows(aggregates)


def run_case(case: dict[str, int | str], repetition: int, index: int) -> dict[str, int | float | str]:
    case_name = f"{index:04d}-w{case['workers']}-{case['mode']}-{case['distribution']}-b{case['burst']}-p{case['packet']}-r{case['rate']}-rep{repetition}"
    case_dir = RESULT_DIR / "cases" / case_name
    case_dir.mkdir(parents=True)
    config, runtime, cli, expected_cpus = write_startup(int(case["workers"]), case_dir)
    stdout_path = case_dir / "vpp-stdout.log"
    with stdout_path.open("w") as stdout:
        process = subprocess.Popen([str(VPP_BIN), "-c", str(config)], stdout=stdout, stderr=subprocess.STDOUT)
    try:
        wait_cli(process, cli, stdout_path)
        show_threads = vppctl(cli, "show", "threads")
        (case_dir / "threads.txt").write_text(show_threads)
        verify_thread_placement(show_threads, expected_cpus)
        (case_dir / "clock.txt").write_text(vppctl(cli, "show", "clock"))
        command = (
            "handoff-perf", "start", "mode", str(case["mode"]),
            "distribution", str(case["distribution"]), "burst", str(case["burst"]),
            "packet-size", str(case["packet"]), "sample-rate", str(SAMPLE_RATE),
            "seed", str(SEED), "tokens", str(TOKENS), "rate", str(case["rate"]),
            "wake-workers", str(WAKE_WORKERS),
        )
        warmup_start = require_cli(vppctl(cli, *command), "handoff-perf started")
        (case_dir / "warmup-start.txt").write_text(warmup_start)
        time.sleep(WARMUP)
        warmup_stop = require_cli(vppctl(cli, "handoff-perf", "stop"), "handoff-perf stopped")
        (case_dir / "warmup-stop.txt").write_text(warmup_stop)
        warm_parsed: dict[str, int | float] = {}
        for _ in range(100):
            warm = vppctl(cli, "show", "handoff-perf")
            warm_parsed, _ = parse_show(warm)
            if warm_parsed["outstanding"] == 0:
                break
            time.sleep(0.01)
        (case_dir / "warmup-show.txt").write_text(warm)
        if warm_parsed["outstanding"] != 0:
            raise RuntimeError("warmup did not drain")
        require_cli(vppctl(cli, "clear", "runtime"))
        resume = require_cli(
            vppctl(cli, "handoff-perf", "resume"),
            "handoff-perf resumed with counters reset",
        )
        (case_dir / "measurement-resume.txt").write_text(resume)
        cpu_before = read_task_cpu(process.pid)
        cpu_started = time.monotonic()
        time.sleep(DURATION)
        cpu_after = read_task_cpu(process.pid)
        cpu_elapsed = time.monotonic() - cpu_started
        cpu_delta = task_cpu_delta(cpu_before, cpu_after)
        (case_dir / "cpu-before.json").write_text(json.dumps(cpu_before, indent=2) + "\n")
        (case_dir / "cpu-after.json").write_text(json.dumps(cpu_after, indent=2) + "\n")
        (case_dir / "cpu-delta.json").write_text(json.dumps(cpu_delta, indent=2) + "\n")
        stop = require_cli(vppctl(cli, "handoff-perf", "stop"), "handoff-perf stopped")
        (case_dir / "measurement-stop.txt").write_text(stop)
        show = ""
        parsed: dict[str, int | float] = {}
        threads: dict[int, dict[str, int]] = {}
        for _ in range(200):
            show = vppctl(cli, "show", "handoff-perf")
            parsed, threads = parse_show(show)
            if parsed["outstanding"] == 0:
                break
            time.sleep(0.01)
        (case_dir / "show.txt").write_text(show)
        (case_dir / "show-runtime.txt").write_text(vppctl(cli, "show", "runtime"))

        generated = int(parsed["generated"])
        terminal = int(parsed["terminal"])
        ingress_drops = int(parsed["ingress_drops"])
        return_drops = int(parsed["return_drops"])
        elapsed = float(parsed["measurement_seconds"])
        if elapsed <= 0:
            raise RuntimeError(f"non-positive plugin measurement interval: {elapsed}")
        errors = distribution_errors(case, generated, int(parsed["local"]), threads)
        measured_vpp_threads = [
            values
            for values in cpu_delta.values()
            if values["name"] == "vpp_main" or str(values["name"]).startswith("vpp_wk_")
        ]
        if len(measured_vpp_threads) != int(case["workers"]) + 1:
            errors.append(
                f"CPU delta captured {len(measured_vpp_threads)} VPP graph threads, "
                f"expected {int(case['workers']) + 1}"
            )
        if any(int(values["ticks"]) < 0 for values in cpu_delta.values()):
            errors.append("negative per-task CPU tick delta")
        if int(parsed["wake_write_errors"]) != 0:
            errors.append(f"eventfd write errors={parsed['wake_write_errors']}")
        mode = str(case["mode"])
        expected_ingress = 0 if mode == "local" else (
            generated // 2 if mode == "mixed-local-fastpath" else generated
        )
        if int(parsed["ingress_enqueued"]) != expected_ingress:
            errors.append(
                f"ingress-enqueued={parsed['ingress_enqueued']} expected={expected_ingress}"
            )
        expected_return = generated if mode == "handoff-return" else 0
        if int(parsed["return_enqueued"]) != expected_return:
            errors.append(
                f"return-enqueued={parsed['return_enqueued']} expected={expected_return}"
            )
        rate = int(case["rate"])
        if rate != 0 and elapsed > 0:
            relative_rate_error = abs(generated / elapsed - rate) / rate
            if relative_rate_error > 0.05:
                errors.append(f"offered rate error {relative_rate_error:.3%} exceeds 5%")
            scheduler_balance = int(parsed["scheduled_packets"]) - generated
            if abs(scheduler_balance - float(parsed["backlog_packets"])) > 1.5:
                errors.append(
                    f"scheduler balance={scheduler_balance} backlog={parsed['backlog_packets']}"
                )
        lifecycle_valid = (
            int(parsed["outstanding"]) == 0
            and int(parsed["alloc_errors"]) == 0
            and int(parsed["reclaim_overflows"]) == 0
            and int(parsed["clock_anomalies"]) == 0
            and ingress_drops == 0
            and return_drops == 0
            and generated == terminal
            and int(parsed["reclaimed"]) == terminal
            and int(parsed["generated_bytes"]) == generated * int(case["packet"])
            and int(parsed["terminal_bytes"]) == terminal * int(case["packet"])
        )
        minimum_samples = 10 if PROFILE == "smoke" else 100
        sample_threads = expected_sample_threads(case)
        latency_errors = [
            f"thread {thread} has {threads.get(thread, {}).get('latency_samples', 0)} samples"
            for thread in sorted(sample_threads)
            if threads.get(thread, {}).get("latency_samples", 0) < minimum_samples
        ]
        cleanup = require_cli(
            vppctl(cli, "handoff-perf", "cleanup"), "handoff-perf token pool cleaned"
        )
        (case_dir / "cleanup.txt").write_text(cleanup)
        valid = lifecycle_valid and not errors and not latency_errors
        latency_valid = not latency_errors
        cpu_ticks = sum(int(values["ticks"]) for values in cpu_delta.values())
        cpu_seconds = cpu_ticks / os.sysconf("SC_CLK_TCK")
        row: dict[str, int | float | str] = {
            **case,
            "repetition": repetition,
            "wake_workers": WAKE_WORKERS,
            "elapsed_seconds": elapsed,
            "generated_pps": generated / elapsed,
            "terminal_pps": terminal / elapsed,
            "valid": int(valid),
            "latency_valid": int(latency_valid),
            "validation_errors": "; ".join(errors),
            "latency_errors": "; ".join(latency_errors),
            "thread_stats": json.dumps(threads, sort_keys=True),
            "cpu_placement": ",".join(str(cpu) for cpu in expected_cpus),
            "cpu_interval_seconds": cpu_elapsed,
            "cpu_seconds": cpu_seconds,
            "cpu_utilization_cores": cpu_seconds / cpu_elapsed,
            "cpu_seconds_per_packet": cpu_seconds / generated if generated else 0.0,
            "cpu_task_delta": json.dumps(cpu_delta, sort_keys=True),
            "return_cycles_per_packet": (
                int(parsed["return_cycles"]) / int(parsed["return_enqueued"])
                if int(parsed["return_enqueued"])
                else 0.0
            ),
            "lossless": int(lifecycle_valid),
            **parsed,
            "case_dir": str(case_dir.relative_to(RESULT_DIR)),
        }
        if not valid or not latency_valid:
            with (RESULT_DIR / "invalid-runs.md").open("a") as stream:
                stream.write(
                    f"- `{case_name}`: data gate failed: "
                    f"{'; '.join(errors + latency_errors) or 'lifecycle failure'}; "
                    f"see `{row['case_dir']}`.\n"
                )
        return row
    except Exception as error:
        (case_dir / "error.txt").write_text(f"{type(error).__name__}: {error}\n")
        with (RESULT_DIR / "invalid-runs.md").open("a") as stream:
            stream.write(f"- `{case_name}`: harness exception `{type(error).__name__}: {error}`.\n")
        raise
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        shutil.rmtree(runtime, ignore_errors=True)


def main() -> int:
    if WAKE_WORKERS not in (0, 1, 2, 3):
        raise RuntimeError("WAKE_WORKERS must be 0, 1, 2, or 3")
    if PLUGIN is None or not VPP_BIN.exists() or not VPPCTL_BIN.exists():
        raise RuntimeError("VPP/plugin artifacts missing; build handoff_perf_poc_plugin first")
    RESULT_DIR.mkdir(parents=True, exist_ok=False)
    (RESULT_DIR / "invalid-runs.md").write_text("# Invalid or inconclusive runs\n\n")
    base_cases = make_cases()
    if CASE_FILTER:
        case_pattern = re.compile(CASE_FILTER)
        base_cases = [
            case
            for case in base_cases
            if case_pattern.search(f"{case['mode']}/{case['distribution']}")
        ]
        if not base_cases:
            raise RuntimeError(f"CASE_FILTER {CASE_FILTER!r} matched no cases")
    cases = [
        {**case, "_repetition": repetition}
        for repetition in range(1, REPETITIONS + 1)
        for case in base_cases
    ]
    random.Random(SEED).shuffle(cases)
    write_manifest(cases)
    rows = []
    for index, case in enumerate(cases, 1):
        repetition = int(case.pop("_repetition"))
        print(f"[{index}/{len(cases)}] {case}", flush=True)
        rows.append(run_case(case, repetition, index))
    with (RESULT_DIR / "raw.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    write_aggregates(rows)
    valid = sum(int(row["valid"]) for row in rows)
    latency_valid = sum(int(row["latency_valid"]) for row in rows)
    (RESULT_DIR / "summary.md").write_text(
        "# VLIB handoff performance POC\n\n"
        f"- Profile: `{PROFILE}`\n"
        f"- Valid runs: `{valid}/{len(rows)}`\n"
        f"- Latency path coverage: `{latency_valid}/{len(rows)}`\n"
        "- Packet sizes are logical VPP buffer lengths; the fixed policy touch is two header bytes.\n"
        "- This host/WSL run is relative evidence only.\n"
    )
    print(f"results={RESULT_DIR} valid={valid}/{len(rows)}")
    return 0 if valid == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
