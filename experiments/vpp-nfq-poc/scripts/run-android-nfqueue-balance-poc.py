#!/usr/bin/env python3
"""Run the throwaway Android NFQUEUE queue-balance P2a/P2b matrix."""

from __future__ import annotations

import csv
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


REPO = Path(__file__).resolve().parents[3]
POC = REPO / "experiments" / "vpp-nfq-poc"
ADB = REPO / "dev" / "adb"
REMOTE = os.environ.get("REMOTE_ROOT", "/data/local/tmp/vpp-nfqb-poc")
QUEUE_BASE = int(os.environ.get("QUEUE_BASE", "60"))
QUEUE_MAXLEN = int(os.environ.get("QUEUE_MAXLEN", "4096"))
OWNERS = int(os.environ.get("OWNERS", "2"))
POLLING = os.environ.get("POLLING", "main")
HASH_SEED = 0x1234
HASH_VERSION = 1
EXPECTED_GOLDEN_HASH = 6363941064820286797
PROFILE = os.environ.get("PROFILE", "pilot")
REPETITIONS = int(os.environ.get("REPETITIONS", "3" if PROFILE == "matrix" else "1"))
FLOWS = int(os.environ.get("FLOWS", "256"))
HOT_SECONDS = float(os.environ.get("HOT_SECONDS", "2"))
SOURCE_PORT = int(os.environ.get("SOURCE_PORT", "19000"))
RUN_LIFECYCLE = os.environ.get("RUN_LIFECYCLE", "1") == "1"
RUN_ID = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
RESULT_DIR = Path(
    os.environ.get(
        "RESULT_DIR",
        str(POC / "results" / dt.date.today().isoformat() / f"nfqueue-balance-{PROFILE}-{RUN_ID}"),
    )
)
STARTUP_CONFIG = Path(
    os.environ.get(
        "STARTUP_CONFIG",
        str(POC / "configs" / "android-nfqueue-balance-workers-startup.conf"),
    )
)

TOP_RE = re.compile(
    r"nfqb enabled (?P<enabled>\d+) topology (?P<topology>\S+) queue (?P<queue>\d+) "
    r"lanes (?P<lanes>\d+) owners (?P<owners>\d+) packets (?P<packets>\d+) "
    r"marked (?P<marked>\d+) verdict-debt (?P<verdict_debt>\d+) "
    r"missing-id (?P<missing_id>\d+) missing-marker (?P<missing_marker>\d+)"
)
FLOW_RE = re.compile(
    r"nfqb flows (?P<flows>\d+) table-full (?P<table_full>\d+) "
    r"migration-flows (?P<migration_flows>\d+) migration-packets (?P<migration_packets>\d+) "
    r"migration-owner-mismatches (?P<migration_owner_mismatches>\d+) "
    r"duplicates (?P<duplicates>\d+) reorders (?P<reorders>\d+) gaps (?P<gaps>\d+)"
)
PROJECTION_RE = re.compile(
    r"nfqb projection local-packets (?P<local_packets>\d+) handoff-packets (?P<handoff_packets>\d+) "
    r"local-flows (?P<local_flows>\d+) handoff-flows (?P<handoff_flows>\d+)"
)
GOLDEN_RE = re.compile(
    r"nfqb golden version (?P<golden_version>\d+) seed (?P<golden_seed>\d+) "
    r"hash (?P<golden_hash>\d+) reverse-hash (?P<golden_reverse_hash>\d+)"
)
LANE_RE = re.compile(
    r"nfqb lane (?P<lane>\d+) queue (?P<queue>\d+) packets (?P<packets>\d+) "
    r"marked (?P<marked>\d+) flows (?P<flows>\d+) callbacks (?P<callbacks>\d+) "
    r"recv-calls (?P<recv_calls>\d+) recv-bytes (?P<recv_bytes>\d+) eagain (?P<eagain>\d+) "
    r"eintr (?P<eintr>\d+) enobufs (?P<enobufs>\d+) recv-errors (?P<recv_errors>\d+) "
    r"drain-yields (?P<drain_yields>\d+) handle-errors (?P<handle_errors>\d+) "
    r"verdict-calls (?P<verdict_calls>\d+) "
    r"verdict-errors (?P<verdict_errors>\d+) verdict-eagain (?P<verdict_eagain>\d+) "
    r"verdict-enobufs (?P<verdict_enobufs>\d+) thread (?P<thread>\d+) "
    r"expected-thread (?P<expected_thread>\d+) thread-mismatches (?P<thread_mismatches>\d+) "
    r"tid (?P<tid>\d+) cpu (?P<cpu>-?\d+) first-tid (?P<first_tid>\d+) "
    r"first-cpu (?P<first_cpu>-?\d+) tid-changes (?P<tid_changes>\d+) "
    r"cpu-changes (?P<cpu_changes>\d+)"
)
SENDER_RE = re.compile(
    r"pattern=(?P<pattern>\S+) flows=(?P<flows>\d+) requested=(?P<requested>\d+) "
    r"sent=(?P<sent>\d+) errors=(?P<errors>\d+) rate-target=(?P<rate>\d+) "
    r"epoch=(?P<epoch>\d+) elapsed-ns=(?P<elapsed_ns>\d+) achieved-pps=(?P<achieved_pps>[0-9.]+)"
)


def run(args: list[str], *, check: bool = True, timeout: float | None = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, check=False, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed rc={result.returncode}: {shlex.join(args)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def shell_quote(command: str) -> str:
    return "'" + command.replace("'", "'\"'\"'") + "'"


def adb_su(command: str, *, check: bool = True, timeout: float | None = 120) -> str:
    result = run([str(ADB), "shell", f"su 0 sh -c {shell_quote(command)}"], check=check, timeout=timeout)
    return (result.stdout + result.stderr).replace("\r", "")


def adb_su_popen(command: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [str(ADB), "shell", f"su 0 sh -c {shell_quote(command)}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def ctl(command: str, *, check: bool = True) -> str:
    return adb_su(
        f"LD_LIBRARY_PATH={REMOTE}/lib {REMOTE}/bin/vppctl "
        f"-s {REMOTE}/runtime/cli.sock {command}",
        check=check,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def production_golden() -> str:
    output = POC / "build" / "flow-steering-golden"
    output.parent.mkdir(parents=True, exist_ok=True)
    run(
        [
            os.environ.get("CXX", "g++"),
            "-std=c++20",
            "-O2",
            "-I",
            str(REPO / "src" / "core" / "flow"),
            str(POC / "clients" / "flow_steering_golden.cpp"),
            str(REPO / "src" / "core" / "flow" / "FlowSteering.cpp"),
            "-o",
            str(output),
        ],
        timeout=120,
    )
    oracle = run([str(output)]).stdout.strip()
    expected = f"production-golden version={HASH_VERSION} seed={HASH_SEED} hash={EXPECTED_GOLDEN_HASH} exact=1 reverse=1"
    if oracle != expected:
        raise RuntimeError(f"production golden oracle mismatch: {oracle!r}")
    return oracle


def remove_rule(lanes: int) -> None:
    target = (
        f"--queue-num {QUEUE_BASE}"
        if lanes == 1
        else f"--queue-balance {QUEUE_BASE}:{QUEUE_BASE + lanes - 1}"
    )
    command = (
        "/system/bin/iptables -w -D OUTPUT -p udp -d 127.0.0.0/8 "
        f"--dport 20000:24095 -j NFQUEUE {target} --queue-bypass"
    )
    adb_su(f"while {command} 2>/dev/null; do :; done", check=False)


def remove_all_rules() -> None:
    for lanes in (1, 2, 4):
        remove_rule(lanes)


def add_rule(lanes: int) -> None:
    target = (
        f"--queue-num {QUEUE_BASE}"
        if lanes == 1
        else f"--queue-balance {QUEUE_BASE}:{QUEUE_BASE + lanes - 1}"
    )
    adb_su(
        "/system/bin/iptables -w -I OUTPUT 1 -p udp -d 127.0.0.0/8 "
        f"--dport 20000:24095 -j NFQUEUE {target} --queue-bypass"
    )


def proc_nfqueue() -> str:
    return adb_su("cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true", check=False)


def wait_owned_queues_empty(timeout: float = 2.0) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        last = proc_nfqueue()
        owned = parse_proc(last, 4)
        if all(values["queue_total"] == 0 for values in owned.values()):
            return True, last
        time.sleep(0.02)
    return False, last


def parse_proc(text: str, lanes: int) -> dict[int, dict[str, int]]:
    parsed: dict[int, dict[str, int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].isdigit():
            continue
        queue = int(fields[0])
        if QUEUE_BASE <= queue < QUEUE_BASE + lanes:
            parsed[queue] = {
                "queue_total": int(fields[2]),
                "queue_dropped": int(fields[5]),
                "user_dropped": int(fields[6]),
                "id_sequence": int(fields[7]),
            }
    return parsed


def sample_threads() -> str:
    return adb_su(
        f"pid=$(cat {REMOTE}/runtime/vpp.pid 2>/dev/null || true); "
        "if [ -n \"$pid\" ]; then for t in /proc/$pid/task/*; do "
        "tid=${t##*/}; comm=$(cat $t/comm 2>/dev/null || true); "
        "ticks=$(awk '{print $14+$15}' $t/stat 2>/dev/null || echo 0); "
        "ctx=$(awk '/voluntary_ctxt_switches:/{v+=$2} /nonvoluntary_ctxt_switches:/{v+=$2} "
        "END{print v+0}' $t/status 2>/dev/null || echo 0); "
        "printf '%s comm=%s ticks=%s ctx=%s\\n' $tid $comm $ticks $ctx; done; fi",
        check=False,
    )


def sample_device_state() -> str:
    return adb_su(
        "for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq; do "
        "[ -r $f ] && printf '%s=%s\\n' $f $(cat $f); done; "
        "for f in /sys/class/thermal/thermal_zone*/temp; do "
        "[ -r $f ] && printf '%s=%s\\n' $f $(cat $f); done",
        check=False,
    )


def parse_thread_totals(text: str) -> tuple[int, int]:
    ticks = 0
    contexts = 0
    for line in text.splitlines():
        tick_match = re.search(r"\bticks=(\d+)", line)
        ctx_match = re.search(r"\bctx=(\d+)", line)
        if tick_match:
            ticks += int(tick_match.group(1))
        if ctx_match:
            contexts += int(ctx_match.group(1))
    return ticks, contexts


def parse_thread_rows(text: str) -> dict[int, dict[str, int | str]]:
    rows: dict[int, dict[str, int | str]] = {}
    for line in text.splitlines():
        match = re.match(r"^(?P<tid>\d+) comm=(?P<comm>\S+) ticks=(?P<ticks>\d+) ctx=(?P<ctx>\d+)", line)
        if match:
            values = match.groupdict()
            rows[int(values["tid"])] = {
                "comm": values["comm"],
                "ticks": int(values["ticks"]),
                "ctx": int(values["ctx"]),
            }
    return rows


def parse_vpp_threads(text: str) -> dict[int, dict[str, int | str]]:
    rows: dict[int, dict[str, int | str]] = {}
    for line in text.splitlines():
        match = re.match(
            r"^(?P<index>\d+)\s+(?P<name>\S+)\s+"
            r"(?:(?P<type>[A-Za-z_]\S*)\s+)?(?P<tid>\d+)\s+\S+\s+\([^)]*\)\s+"
            r"(?P<lcore>\d+)",
            line,
        )
        if not match:
            continue
        values = match.groupdict()
        rows[int(values["index"])] = {
            "name": values["name"],
            "type": values["type"] or "main",
            "tid": int(values["tid"]),
            "lcore": int(values["lcore"]),
        }
    return rows


def parse_show(text: str) -> tuple[dict[str, int | str], list[dict[str, int]]]:
    top = TOP_RE.search(text)
    flows = FLOW_RE.search(text)
    projection = PROJECTION_RE.search(text)
    golden = GOLDEN_RE.search(text)
    if not top or not flows or not projection or not golden:
        raise ValueError(f"could not parse plugin output:\n{text}")
    summary: dict[str, int | str] = {key: int(value) if value.isdigit() else value for key, value in top.groupdict().items()}
    summary.update({key: int(value) for key, value in flows.groupdict().items()})
    summary.update({key: int(value) for key, value in projection.groupdict().items()})
    summary.update({key: int(value) for key, value in golden.groupdict().items()})
    lanes = [{key: int(value) for key, value in match.groupdict().items()} for match in LANE_RE.finditer(text)]
    return summary, lanes


def canonical_hash(src: bytes, dst: bytes, src_port: int, dst_port: int, protocol: int) -> int:
    left = (src, src_port)
    right = (dst, dst_port)
    if left > right:
        left, right = right, left
    left_address = left[0] + bytes(12)
    right_address = right[0] + bytes(12)
    key = (
        bytes((protocol, 0))
        + left_address
        + bytes((0,))
        + right_address
        + left[1].to_bytes(2, "big")
        + right[1].to_bytes(2, "big")
    )
    value = 14695981039346656037 ^ HASH_SEED
    for octet in key:
        value ^= octet
        value = (value * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


def skew(values: list[int]) -> tuple[float, float, float]:
    if not values or sum(values) == 0:
        return 0.0, 0.0, 0.0
    mean = statistics.fmean(values)
    cv = statistics.pstdev(values) / mean if mean else 0.0
    minimum = min(values)
    ratio = max(values) / minimum if minimum else math.inf
    jain = sum(values) ** 2 / (len(values) * sum(value * value for value in values))
    return cv, ratio, jain


def case_matrix() -> list[dict[str, int | str]]:
    def add_polling(case: dict[str, int | str]) -> list[dict[str, int | str]]:
        if POLLING != "paired":
            return [{**case, "polling": POLLING}]
        repetition = int(case["repetition"])
        order = ("main", "workers") if repetition % 2 == 0 else ("workers", "main")
        return [{**case, "polling": polling} for polling in order]

    if PROFILE == "pilot":
        rates = [int(value) for value in os.environ.get("RATES", "5000 10000 20000 40000").split()]
        return [
            variant
            for repetition in range(REPETITIONS)
            for lanes in (1, 2, 4)
            for rate in rates
            for variant in add_polling(
                {
                    "lanes": lanes,
                    "pattern": "address-diverse",
                    "temperature": "hot",
                    "rate": rate,
                    "repetition": repetition,
                }
            )
        ]
    if PROFILE != "matrix":
        raise ValueError("PROFILE must be pilot or matrix")
    rate = int(os.environ["RATE"])
    cases: list[dict[str, int | str]] = []
    for repetition in range(REPETITIONS):
        for temperature in ("cold", "hot"):
            cases.extend(
                add_polling(
                    {"lanes": 1, "pattern": "address-diverse", "temperature": temperature, "rate": rate, "repetition": repetition}
                )
            )
        for lanes in (2, 4):
            for pattern in ("port-only", "address-diverse", "elephant-mice"):
                for temperature in ("cold", "hot"):
                    cases.extend(
                        add_polling(
                            {"lanes": lanes, "pattern": pattern, "temperature": temperature, "rate": rate, "repetition": repetition}
                        )
                    )
    return cases


def run_case(index: int, case: dict[str, int | str]) -> dict[str, int | float | str]:
    lanes = int(case["lanes"])
    pattern = str(case["pattern"])
    temperature = str(case["temperature"])
    rate = int(case["rate"])
    repetition = int(case.get("repetition", 0))
    polling = str(case["polling"])
    packets = FLOWS if temperature == "cold" else max(FLOWS, int(rate * HOT_SECONDS))
    epoch = 100000 + repetition * 100000 + lanes * 10000 + rate
    case_name = f"{index:03d}-q{lanes}-{pattern}-{temperature}-r{rate}-{polling}-rep{repetition}"
    case_dir = RESULT_DIR / "cases" / case_name
    case_dir.mkdir(parents=True)

    remove_all_rules()
    wait_owned_queues_empty()
    ctl("nfqueue-balance-poc stop", check=False)
    ctl(
        f"nfqueue-balance-poc start queue {QUEUE_BASE} lanes {lanes} owners {OWNERS} "
        f"queue-maxlen {QUEUE_MAXLEN} polling {polling}"
    )
    add_rule(lanes)
    before_threads = sample_threads()
    before_device_state = sample_device_state()
    samples = [proc_nfqueue()]
    sender_command = f"{REMOTE}/bin/nfqb-sender {pattern} {FLOWS} {packets} {rate} {epoch} {SOURCE_PORT}"
    sender = adb_su_popen(sender_command)
    while sender.poll() is None:
        samples.append(proc_nfqueue())
        time.sleep(0.05)
    sender_output, _ = sender.communicate(timeout=10)
    sender_output = sender_output.replace("\r", "")
    samples.append(proc_nfqueue())
    time.sleep(0.25)
    samples.append(proc_nfqueue())
    after_threads = sample_threads()
    after_device_state = sample_device_state()
    show = ctl("show nfqueue-balance-poc")
    show_threads = ctl("show threads")

    (case_dir / "sender.txt").write_text(sender_output)
    (case_dir / "show.txt").write_text(show)
    (case_dir / "show-threads.txt").write_text(show_threads)
    (case_dir / "nfnetlink_queue_samples.txt").write_text(
        "\n".join(f"## sample {number}\n{sample.rstrip()}" for number, sample in enumerate(samples)) + "\n"
    )
    (case_dir / "threads-before.txt").write_text(before_threads)
    (case_dir / "threads-after.txt").write_text(after_threads)
    (case_dir / "device-state-before.txt").write_text(before_device_state)
    (case_dir / "device-state-after.txt").write_text(after_device_state)

    sender_match = SENDER_RE.search(sender_output)
    if not sender_match:
        raise ValueError(f"could not parse sender output:\n{sender_output}")
    sender_data = {key: int(value) if key not in ("pattern", "achieved_pps") else value for key, value in sender_match.groupdict().items()}
    summary, lane_rows = parse_show(show)
    proc_rows = [parse_proc(sample, lanes) for sample in samples]
    queue_total_max = max((values["queue_total"] for row in proc_rows for values in row.values()), default=0)
    queue_dropped_max = max((values["queue_dropped"] for row in proc_rows for values in row.values()), default=0)
    user_dropped_max = max((values["user_dropped"] for row in proc_rows for values in row.values()), default=0)
    packet_values = [row["marked"] for row in lane_rows]
    flow_values = [row["flows"] for row in lane_rows]
    packet_cv, packet_ratio, packet_jain = skew(packet_values)
    flow_cv, flow_ratio, flow_jain = skew(flow_values)
    ticks_before, contexts_before = parse_thread_totals(before_threads)
    ticks_after, contexts_after = parse_thread_totals(after_threads)
    sent = int(sender_data["sent"])
    achieved_pps = float(sender_data["achieved_pps"])

    reasons: list[str] = []
    expected_topology = "worker-callback" if polling == "workers" else "main-callback"
    expected_hash = canonical_hash(bytes((192, 0, 2, 1)), bytes((198, 51, 100, 2)), 12345, 443, 17)
    vpp_threads = parse_vpp_threads(show_threads)
    before_thread_rows = parse_thread_rows(before_threads)
    after_thread_rows = parse_thread_rows(after_threads)
    thread_deltas = {
        tid: {
            "ticks": max(0, int(values["ticks"]) - int(before_thread_rows.get(tid, {}).get("ticks", 0))),
            "ctx": max(0, int(values["ctx"]) - int(before_thread_rows.get(tid, {}).get("ctx", 0))),
        }
        for tid, values in after_thread_rows.items()
    }
    if sender.returncode != 0 or int(sender_data["errors"]) != 0 or sent != packets:
        reasons.append("sender-accounting")
    if summary["topology"] != expected_topology:
        reasons.append("topology-mismatch")
    if len(lane_rows) != lanes:
        reasons.append("lane-count-mismatch")
    if (
        int(summary["golden_version"]) != HASH_VERSION
        or int(summary["golden_seed"]) != HASH_SEED
        or expected_hash != EXPECTED_GOLDEN_HASH
        or int(summary["golden_hash"]) != EXPECTED_GOLDEN_HASH
        or int(summary["golden_reverse_hash"]) != expected_hash
    ):
        reasons.append("golden-hash-mismatch")
    if int(summary["marked"]) != sent or int(summary["packets"]) != sent:
        reasons.append("sent-seen-mismatch")
    for key in ("verdict_debt", "missing_id", "missing_marker", "table_full", "migration_flows", "migration_packets", "migration_owner_mismatches", "duplicates", "reorders", "gaps"):
        if int(summary[key]) != 0:
            reasons.append(key)
    if sum(
        row["recv_errors"]
        + row["handle_errors"]
        + row["enobufs"]
        + row["verdict_errors"]
        + row["thread_mismatches"]
        for row in lane_rows
    ) != 0:
        reasons.append("userspace-errors")
    for lane in lane_rows:
        expected_thread = 0 if polling == "main" else 1 + (lane["lane"] % OWNERS)
        if lane["expected_thread"] != expected_thread:
            reasons.append("declared-thread-mismatch")
        if lane["packets"]:
            vpp_thread = vpp_threads.get(expected_thread)
            if (
                lane["thread"] != expected_thread
                or lane["tid"] == 0
                or lane["cpu"] < 0
                or lane["first_tid"] != lane["tid"]
                or lane["first_cpu"] != lane["cpu"]
                or lane["tid_changes"] != 0
                or lane["cpu_changes"] != 0
                or vpp_thread is None
                or lane["tid"] != int(vpp_thread["tid"])
                or lane["cpu"] != int(vpp_thread["lcore"])
            ):
                reasons.append("callback-thread-proof")
    if queue_dropped_max or user_dropped_max:
        reasons.append("kernel-drops")
    if temperature == "hot" and achieved_pps < rate * 0.90:
        reasons.append("rate-miss")
    if queue_total_max > QUEUE_MAXLEN // 10:
        reasons.append("backlog-over-10pct")

    remove_all_rules()
    queues_idle, final_queue_sample = wait_owned_queues_empty()
    (case_dir / "nfnetlink_queue_final.txt").write_text(final_queue_sample)
    if not queues_idle:
        reasons.append("queue-not-drained")
    ctl("nfqueue-balance-poc stop", check=False)
    row: dict[str, int | float | str] = {
        "case": case_name,
        "profile": PROFILE,
        "polling": polling,
        "lanes": lanes,
        "pattern": pattern,
        "temperature": temperature,
        "rate": rate,
        "repetition": repetition,
        "flows": FLOWS,
        "requested": packets,
        "sent": sent,
        "achieved_pps": achieved_pps,
        "marked": int(summary["marked"]),
        "flow_count": int(summary["flows"]),
        "packet_cv": packet_cv,
        "packet_max_min": packet_ratio,
        "packet_jain": packet_jain,
        "flow_cv": flow_cv,
        "flow_max_min": flow_ratio,
        "flow_jain": flow_jain,
        "projected_handoff_packet_ratio": int(summary["handoff_packets"]) / sent if sent else 0.0,
        "projected_handoff_flow_ratio": int(summary["handoff_flows"]) / int(summary["flows"]) if int(summary["flows"]) else 0.0,
        "recv_calls": sum(item["recv_calls"] for item in lane_rows),
        "callbacks": sum(item["callbacks"] for item in lane_rows),
        "callback_tids": ";".join(str(item["tid"]) for item in lane_rows),
        "callback_cpus": ";".join(str(item["cpu"]) for item in lane_rows),
        "queue_total_max": queue_total_max,
        "queue_dropped_max": queue_dropped_max,
        "user_dropped_max": user_dropped_max,
        "vpp_ticks_delta": max(0, ticks_after - ticks_before),
        "vpp_contexts_delta": max(0, contexts_after - contexts_before),
        "valid": int(not reasons),
        "invalid_reasons": ",".join(reasons),
    }
    (case_dir / "parsed.json").write_text(
        json.dumps(
            {
                "row": row,
                "summary": summary,
                "lanes": lane_rows,
                "vpp_threads": vpp_threads,
                "thread_deltas": thread_deltas,
            },
            indent=2,
        )
        + "\n"
    )
    return row


def start_vpp() -> None:
    run([str(ADB), "push", str(STARTUP_CONFIG), "/data/local/tmp/vpp-nfqb-startup.conf"])
    adb_su(
        f"cp /data/local/tmp/vpp-nfqb-startup.conf {REMOTE}/runtime/startup.conf; "
        f"chmod 644 {REMOTE}/runtime/startup.conf"
    )
    adb_su(
        f"if [ -f {REMOTE}/runtime/vpp.pid ]; then "
        f"old=$(cat {REMOTE}/runtime/vpp.pid); kill -TERM $old 2>/dev/null || true; "
        "for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 $old 2>/dev/null || break; sleep 0.1; done; "
        "kill -0 $old 2>/dev/null && kill -KILL $old 2>/dev/null || true; fi; "
        f"rm -f {REMOTE}/runtime/cli.sock {REMOTE}/runtime/statseg.sock {REMOTE}/logs/stdout.log; "
        f"cd {REMOTE}; export LD_LIBRARY_PATH={REMOTE}/lib; "
        f"nohup {REMOTE}/bin/vpp plugin_path {REMOTE}/plugins -c {REMOTE}/runtime/startup.conf "
        f">{REMOTE}/logs/stdout.log 2>&1 </dev/null & echo $! >{REMOTE}/runtime/vpp.pid"
    )
    for _ in range(30):
        time.sleep(0.2)
        try:
            ctl("show version")
            return
        except RuntimeError:
            pass
    raise RuntimeError("VPP did not become ready")


def lifecycle_probe() -> dict[str, object]:
    cycles: list[dict[str, int | float | str]] = []
    remove_all_rules()
    wait_owned_queues_empty()
    ctl("nfqueue-balance-poc stop", check=False)
    for index in range(10):
        polling = "main" if index % 2 == 0 else "workers"
        ctl(
            f"nfqueue-balance-poc start queue {QUEUE_BASE} lanes 4 owners {OWNERS} "
            f"queue-maxlen {QUEUE_MAXLEN} polling {polling}"
        )
        active_queues = len(parse_proc(proc_nfqueue(), 4))
        started_files = ctl("show files").count("nfqueue-balance-poc")
        started = time.monotonic()
        ctl("nfqueue-balance-poc stop")
        stop_ms = (time.monotonic() - started) * 1000.0
        remaining_queues = len(parse_proc(proc_nfqueue(), 4))
        remaining_files = ctl("show files").count("nfqueue-balance-poc")
        ctl("show version")
        cycle = {
            "cycle": index,
            "polling": polling,
            "active_queues": active_queues,
            "started_files": started_files,
            "stop_ms": stop_ms,
            "remaining_queues": remaining_queues,
            "remaining_files": remaining_files,
        }
        cycles.append(cycle)
        if active_queues != 4 or started_files != 4 or remaining_queues or remaining_files or stop_ms > 2000:
            raise RuntimeError(f"lifecycle cycle failed: {cycle}")

    ctl(
        f"nfqueue-balance-poc start queue {QUEUE_BASE} lanes 4 owners {OWNERS} "
        f"queue-maxlen {QUEUE_MAXLEN} polling workers"
    )
    add_rule(4)
    sender = adb_su_popen(
        f"{REMOTE}/bin/nfqb-sender address-diverse 64 100000 20000 999999 {SOURCE_PORT}"
    )
    time.sleep(0.2)
    started = time.monotonic()
    ctl("nfqueue-balance-poc stop")
    stress_stop_ms = (time.monotonic() - started) * 1000.0
    remove_all_rules()
    sender_output, _ = sender.communicate(timeout=15)
    remaining_queues = len(parse_proc(proc_nfqueue(), 4))
    remaining_files = ctl("show files").count("nfqueue-balance-poc")
    ctl("show version")
    stress = {
        "stop_ms": stress_stop_ms,
        "sender_returncode": sender.returncode,
        "remaining_queues": remaining_queues,
        "remaining_files": remaining_files,
        "sender_output": sender_output.replace("\r", "").strip(),
    }
    if stress_stop_ms > 2000 or remaining_queues or remaining_files or sender.returncode != 0:
        raise RuntimeError(f"active-traffic lifecycle failed: {stress}")
    return {"cycles": cycles, "active_traffic_stop": stress}


def cleanup() -> None:
    remove_all_rules()
    wait_owned_queues_empty()
    ctl("nfqueue-balance-poc stop", check=False)
    adb_su(
        f"if [ -f {REMOTE}/runtime/vpp.pid ]; then old=$(cat {REMOTE}/runtime/vpp.pid); "
        "kill -TERM $old 2>/dev/null || true; for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 $old 2>/dev/null || break; sleep 0.1; done; "
        "kill -0 $old 2>/dev/null && kill -KILL $old 2>/dev/null || true; fi; "
        f"rm -f {REMOTE}/runtime/vpp.pid {REMOTE}/runtime/cli.sock {REMOTE}/runtime/statseg.sock",
        check=False,
    )


def main() -> int:
    if POLLING not in ("main", "workers", "paired"):
        raise ValueError("POLLING must be main, workers, or paired")
    RESULT_DIR.mkdir(parents=True, exist_ok=False)
    golden_oracle = production_golden()
    (RESULT_DIR / "invalid-runs.md").write_text("# Invalid or inconclusive runs\n\n")
    cases = case_matrix()
    manifest = {
        "prototype": True,
        "profile": PROFILE,
        "polling": POLLING,
        "run_id": RUN_ID,
        "device_model": adb_su("getprop ro.product.model").strip(),
        "android_release": adb_su("getprop ro.build.version.release").strip(),
        "android_sdk": adb_su("getprop ro.build.version.sdk").strip(),
        "kernel": adb_su("uname -a").strip(),
        "iptables": adb_su("/system/bin/iptables --version").strip(),
        "system_nfqueue_baseline": proc_nfqueue(),
        "queue_base": QUEUE_BASE,
        "queue_maxlen": QUEUE_MAXLEN,
        "owners": OWNERS,
        "flows": FLOWS,
        "hot_seconds": HOT_SECONDS,
        "source_port": SOURCE_PORT,
        "run_lifecycle": RUN_LIFECYCLE,
        "startup_config": str(STARTUP_CONFIG),
        "startup_config_sha256": sha256(STARTUP_CONFIG),
        "production_golden_oracle": golden_oracle,
        "cases": cases,
        "local_artifacts": {
            "vpp": sha256(POC / "work" / "android-nfqb-stage" / "bin" / "vpp"),
            "libvlib": sha256(POC / "work" / "android-nfqb-stage" / "lib" / "libvlib.so"),
            "plugin": sha256(POC / "work" / "android-nfqb-stage" / "plugins" / "nfqueue_poc_plugin.so"),
            "sender": sha256(POC / "build" / "android-nfqueue-balance-sender"),
        },
        "source_artifacts": {
            "nfqueue_balance_poc": sha256(
                POC / "overlay" / "src" / "plugins" / "nfqueue_poc" / "nfqueue_balance_poc.c"
            ),
            "runner": sha256(POC / "scripts" / "run-android-nfqueue-balance-poc.py"),
            "sender_source": sha256(POC / "clients" / "android_nfqueue_balance_sender.c"),
            "startup_config": sha256(STARTUP_CONFIG),
            "flow_steering": sha256(REPO / "src" / "core" / "flow" / "FlowSteering.cpp"),
            "wakeup_patch": sha256(
                POC / "overlay" / "patches" / "0001-vlib-frame-queue-wakeup-handshake.patch"
            ),
        },
    }
    (RESULT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    rows: list[dict[str, int | float | str]] = []
    start_vpp()
    (RESULT_DIR / "show-threads.txt").write_text(ctl("show threads"))
    try:
        if RUN_LIFECYCLE:
            lifecycle = lifecycle_probe()
            (RESULT_DIR / "lifecycle.json").write_text(json.dumps(lifecycle, indent=2) + "\n")
        for index, case in enumerate(cases, 1):
            print(f"[{index}/{len(cases)}] {case}", flush=True)
            try:
                row = run_case(index, case)
            except Exception as error:
                row = {"case": f"{index:03d}", "valid": 0, "invalid_reasons": f"exception:{error}"}
                remove_all_rules()
                wait_owned_queues_empty()
                ctl("nfqueue-balance-poc stop", check=False)
            rows.append(row)
            if not int(row["valid"]):
                with (RESULT_DIR / "invalid-runs.md").open("a") as stream:
                    stream.write(f"- `{row['case']}`: {row['invalid_reasons']}\n")
    finally:
        cleanup()

    fieldnames = sorted({key for row in rows for key in row})
    with (RESULT_DIR / "raw.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    valid = sum(int(row["valid"]) for row in rows)
    (RESULT_DIR / "summary.md").write_text(
        "# Android NFQUEUE balance P2a/P2b\n\n"
        f"- Profile: `{PROFILE}`\n"
        f"- Polling: `{POLLING}`\n"
        f"- Valid: `{valid}/{len(rows)}`\n"
        f"- Topology schedule: `{POLLING}`; paired mode alternates main/workers within each repetition and reverses first order between repetitions.\n"
        "- This measures kernel distribution and canonical-owner mismatch; it does not yet execute corrective VLIB handoff.\n"
    )
    print(f"results={RESULT_DIR} valid={valid}/{len(rows)}")
    return 0 if valid == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
