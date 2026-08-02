#!/usr/bin/env python3
"""PROTOTYPE: P3 canonical-owner handoff with origin-lane NFQ verdict."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import random
import shlex
import subprocess
import time

REPO = Path(__file__).resolve().parents[3]
POC = REPO / "experiments" / "vpp-nfq-poc"
ADB = REPO / "dev" / "adb"
REMOTE = "/data/local/tmp/vpp-nfqb-poc"
QUEUE = 70
SOURCE_PORT = 19000
RUN_ID = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
RESULT = Path(os.environ.get("RESULT_DIR", POC / "results" / dt.date.today().isoformat() / f"nfqueue-handoff-p3-{RUN_ID}"))
CONFIG = POC / "configs" / "android-nfqueue-balance-workers-startup.conf"
BUILD = POC / "work" / "vpp-android-configure-probe"
PLUGIN = BUILD / "lib" / "aarch64-linux-android" / "vpp_plugins" / "nfqueue_poc_plugin.so"
SENDER = Path(os.environ.get("P3_SENDER", "/tmp/android_nfqueue_balance_sender"))

LANE_RE = re.compile(
    r"p3 lane (?P<lane>\d+) queue (?P<queue>\d+) seen (?P<seen>\d+) local (?P<local>\d+) "
    r"remote (?P<remote>\d+) overload (?P<overload>\d+) owner-done (?P<owner_done>\d+) "
    r"completion-done (?P<completion_done>\d+) verdict-attempts (?P<verdict_attempts>\d+) "
    r"verdict-success (?P<verdict_success>\d+) verdict-errors (?P<verdict_errors>\d+) free (?P<free>\d+) "
    r"stale-generation (?P<stale_generation>\d+) duplicate-terminal (?P<duplicate_terminal>\d+).*?"
    r"thread-mismatches (?P<thread_mismatches>\d+) qh-mismatches (?P<qh_mismatches>\d+) "
    r"verdict-thread-mismatches (?P<verdict_thread_mismatches>\d+) wake-attempts (?P<wake_attempts>\d+) "
    r"wake-writes (?P<wake_writes>\d+) wake-errors (?P<wake_errors>\d+) shared-try (?P<shared_try>\d+) "
    r"shared-hit (?P<shared_hit>\d+) shared-miss (?P<shared_miss>\d+) shared-fallback (?P<shared_fallback>\d+) "
    r"lane-gate-defer (?P<lane_gate_defer>\d+)"
)
OWNER_RE = re.compile(
    r"p3 owner (?P<owner>\d+) processed (?P<processed>\d+) completion-push-errors (?P<completion_push_errors>\d+) "
    r"wake-attempts (?P<wake_attempts>\d+) wake-writes (?P<wake_writes>\d+) wake-errors (?P<wake_errors>\d+) "
    r"thread-mismatches (?P<thread_mismatches>\d+)"
)
TOP_RE = re.compile(r"p3 enabled 1 accepting (?P<accepting>\d+)(?: mode (?P<mode>\S+))? pool (?P<pool>\d+) outstanding (?P<outstanding>\d+).*?injected-stale (?P<injected_stale>\d+) injected-duplicate (?P<injected_duplicate>\d+)")
ORACLE_RE = re.compile(r"p3 oracle lane0-owner0 (?P<l0o0>\d+) lane0-owner1 (?P<l0o1>\d+) lane1-owner0 (?P<l1o0>\d+) lane1-owner1 (?P<l1o1>\d+)")
SENDER_RE = re.compile(r"requested=(?P<requested>\d+) sent=(?P<sent>\d+) errors=(?P<errors>\d+).*?elapsed-ns=(?P<elapsed_ns>\d+) achieved-pps=(?P<achieved_pps>[0-9.]+)")


def run(args: list[str], check: bool = True, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"rc={result.returncode}: {shlex.join(args)}\n{result.stdout}\n{result.stderr}")
    return result


def quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def su(command: str, check: bool = True, timeout: float = 120) -> str:
    result = run([str(ADB), "shell", f"su 0 sh -c {quote(command)}"], check, timeout)
    return (result.stdout + result.stderr).replace("\r", "")


def popen_su(command: str) -> subprocess.Popen[str]:
    return subprocess.Popen([str(ADB), "shell", f"su 0 sh -c {quote(command)}"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def ctl(command: str, check: bool = True) -> str:
    return su(f"LD_LIBRARY_PATH={REMOTE}/lib {REMOTE}/bin/vppctl -s {REMOTE}/runtime/cli.sock {command}", check)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def remove_rules() -> None:
    command = f"/system/bin/iptables -w -D OUTPUT -p udp -d 127.0.0.0/8 --dport 20000:24095 -j NFQUEUE --queue-balance {QUEUE}:{QUEUE + 1} --queue-bypass"
    su(f"while {command} 2>/dev/null; do :; done", False)


def add_rule() -> None:
    su(f"/system/bin/iptables -w -I OUTPUT 1 -p udp -d 127.0.0.0/8 --dport 20000:24095 -j NFQUEUE --queue-balance {QUEUE}:{QUEUE + 1} --queue-bypass")


def nfq_sample() -> str:
    return su("cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true", False)


def thread_sample() -> dict[str, int]:
    text = su(f"pid=$(cat {REMOTE}/runtime/vpp.pid); for t in /proc/$pid/task/*; do awk '{{ticks+=$14+$15}} END{{print ticks+0}}' $t/stat; awk '/voluntary_ctxt_switches:|nonvoluntary_ctxt_switches:/{{ctx+=$2}} END{{print ctx+0}}' $t/status; done")
    values = [int(value) for value in text.split()]
    return {"ticks": sum(values[0::2]), "contexts": sum(values[1::2])}


def device_state() -> str:
    return su("for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq /sys/class/thermal/thermal_zone*/temp; do [ -r $f ] && echo $f=$(cat $f); done", False)


def owned_rows(text: str) -> list[list[int]]:
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].isdigit() and QUEUE <= int(fields[0]) <= QUEUE + 1:
            rows.append([int(value) for value in fields[:8]])
    return rows


def parse_show(text: str) -> dict[str, object]:
    lanes = [{k: int(v) for k, v in m.groupdict().items()} for m in LANE_RE.finditer(text)]
    owners = [{k: int(v) for k, v in m.groupdict().items()} for m in OWNER_RE.finditer(text)]
    top = TOP_RE.search(text)
    oracle = ORACLE_RE.search(text)
    if len(lanes) != 2 or len(owners) != 2 or not top or not oracle:
        raise RuntimeError(f"unparseable P3 output:\n{text}")
    top_values = {k: (v if k == "mode" else int(v)) for k, v in top.groupdict().items() if v is not None}
    return {"lanes": lanes, "owners": owners, "top": top_values, "oracle": {k: int(v) for k, v in oracle.groupdict().items()}}


def wait_drained(timeout: float = 3) -> tuple[str, dict[str, object]]:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        last = ctl("show nfqueue-handoff-poc")
        parsed = parse_show(last)
        if int(parsed["top"]["outstanding"]) == 0:
            return last, parsed
        time.sleep(.02)
    raise RuntimeError(f"P3 did not drain:\n{last}")


def validate(parsed: dict[str, object], sent: int, pool: int, kind: str, mode: str, samples: list[str]) -> list[str]:
    lanes = parsed["lanes"]
    owners = parsed["owners"]
    top = parsed["top"]
    reasons: list[str] = []
    if sum(x["seen"] for x in lanes) != sent: reasons.append("sent-seen")
    if any(x["seen"] != x["local"] + x["remote"] + x["overload"] for x in lanes): reasons.append("lane-ledger")
    if sum(x["remote"] for x in lanes) != sum(x["processed"] for x in owners): reasons.append("owner-ledger")
    if any(x["remote"] != x["owner_done"] or x["remote"] != x["completion_done"] for x in lanes): reasons.append("completion-ledger")
    if sum(x["verdict_attempts"] for x in lanes) != sent or sum(x["verdict_success"] for x in lanes) != sent: reasons.append("verdict-ledger")
    zero_fields = ("verdict_errors", "thread_mismatches", "qh_mismatches", "verdict_thread_mismatches", "wake_errors")
    if any(x[field] for x in lanes for field in zero_fields): reasons.append("lane-errors")
    if any(x[field] for x in owners for field in ("completion_push_errors", "wake_errors", "thread_mismatches")): reasons.append("owner-errors")
    if int(top["outstanding"]) or any(x["free"] != pool for x in lanes): reasons.append("pool-debt")
    drops = [row for sample in samples for row in owned_rows(sample) if row[5] or row[6]]
    if drops: reasons.append("kernel-drops")
    if kind == "normal":
        if [parsed["oracle"][key] for key in ("l0o0", "l0o1", "l1o0", "l1o1")] != [0, 224, 1, 226]: reasons.append("oracle-route")
        quarter = sent // 4
        expected = [sent // 2, 0, 0, sent // 2] if mode == "queue-local" else [quarter, quarter, quarter, quarter]
        if [lanes[0]["local"], lanes[0]["remote"], lanes[1]["remote"], lanes[1]["local"]] != expected: reasons.append("four-path-count")
        if mode == "canonical-shared-trylock":
            if sum(x["shared_try"] for x in lanes) != sent // 2: reasons.append("shared-try-ledger")
            if sum(x["shared_hit"] + x["shared_miss"] for x in lanes) != sent // 2: reasons.append("shared-result-ledger")
            if sum(x["shared_miss"] for x in lanes) != sum(x["shared_fallback"] for x in lanes): reasons.append("shared-fallback-ledger")
        if sum(x["stale_generation"] + x["duplicate_terminal"] for x in lanes): reasons.append("unexpected-fault")
    elif kind == "overload":
        if sum(x["overload"] for x in lanes) == 0: reasons.append("overload-not-triggered")
    elif kind == "fault":
        if sum(x["stale_generation"] for x in lanes) != 1 or sum(x["duplicate_terminal"] for x in lanes) != 1: reasons.append("fault-count")
        if int(top["injected_stale"]) != 1 or int(top["injected_duplicate"]) != 1: reasons.append("fault-not-injected")
    elif kind == "remote":
        if mode == "queue-local" and (sum(x["local"] for x in lanes) != sent or sum(x["remote"] for x in lanes)): reasons.append("remote-local-ledger")
        if mode != "queue-local" and (sum(x["remote"] for x in lanes) != sent or sum(x["local"] for x in lanes)): reasons.append("all-remote-ledger")
        if mode == "canonical-shared-trylock" and sum(x["shared_try"] for x in lanes) != sent: reasons.append("shared-try-ledger")
    return reasons


def run_case(index: int, kind: str, repetition: int, rate: int, pool: int, packets: int, mode: str = "canonical-return") -> dict[str, object]:
    case_dir = RESULT / "cases" / f"{index:03d}-{mode}-{kind}-r{rate}-rep{repetition}"
    case_dir.mkdir(parents=True)
    remove_rules(); ctl("nfqueue-handoff-poc stop", False)
    flags = " inject stale inject duplicate" if kind == "fault" else ""
    ctl(f"nfqueue-handoff-poc start queue {QUEUE} pool {pool} mode {mode}{flags}")
    add_rule()
    pattern = "p4-all-remote" if kind == "remote" else ("p3-oracle-four" if kind in ("normal", "fault") else "address-diverse")
    flows = 2 if pattern == "p4-all-remote" else (4 if pattern == "p3-oracle-four" else 256)
    samples = [nfq_sample()]
    before_threads = thread_sample()
    before_state = device_state()
    sender = popen_su(f"{REMOTE}/bin/nfqb-sender {pattern} {flows} {packets} {rate} {300000 + index} {SOURCE_PORT}")
    while sender.poll() is None:
        samples.append(nfq_sample()); time.sleep(.04)
    sender_text, _ = sender.communicate(timeout=10); sender_text = sender_text.replace("\r", "")
    samples.append(nfq_sample())
    after_threads = thread_sample()
    after_state = device_state()
    remove_rules()
    show, parsed = wait_drained()
    sender_match = SENDER_RE.search(sender_text)
    reasons = [] if sender_match else ["sender-parse"]
    sent = int(sender_match.group("sent")) if sender_match else 0
    if sender.returncode or not sender_match or int(sender_match.group("errors")) or sent != packets: reasons.append("sender-accounting")
    if sender_match and float(sender_match.group("achieved_pps")) < rate * .9: reasons.append("rate-miss")
    if max((row[2] for sample in samples for row in owned_rows(sample)), default=0) > 409: reasons.append("backlog-over-10pct")
    reasons += validate(parsed, sent, pool, kind, mode, samples)
    stop = ctl("nfqueue-handoff-poc stop", False)
    if "error" in stop.lower(): reasons.append("stop-error")
    (case_dir / "sender.txt").write_text(sender_text)
    (case_dir / "show.txt").write_text(show)
    (case_dir / "nfqueue.txt").write_text("\n---\n".join(samples))
    (case_dir / "device-state-before.txt").write_text(before_state)
    (case_dir / "device-state-after.txt").write_text(after_state)
    (case_dir / "parsed.json").write_text(json.dumps(parsed, indent=2) + "\n")
    elapsed_ns = int(sender_match.group("elapsed_ns")) if sender_match else 0
    return {"case": case_dir.name, "kind": kind, "mode": mode, "rate": rate, "pool": pool, "packets": packets, "sent": sent, "elapsed_ns": elapsed_ns, "achieved_pps": float(sender_match.group("achieved_pps")) if sender_match else 0, "vpp_ticks": after_threads["ticks"] - before_threads["ticks"], "vpp_contexts": after_threads["contexts"] - before_threads["contexts"], "valid": not reasons, "reasons": reasons}


def lifecycle() -> dict[str, object]:
    remove_rules(); ctl("nfqueue-handoff-poc stop", False); ctl("nfqueue-balance-poc stop", False)
    baseline_files = ctl("show files").count("nfqueue-handoff-poc")
    ctl(f"nfqueue-balance-poc start queue {QUEUE + 1} lanes 1 owners 2 polling workers")
    failed = ctl(f"nfqueue-handoff-poc start queue {QUEUE} pool 32", False)
    files_after_failure = ctl("show files").count("nfqueue-handoff-poc")
    ctl("nfqueue-balance-poc stop")
    ctl(f"nfqueue-handoff-poc start queue {QUEUE} pool 32"); ctl("nfqueue-handoff-poc stop")
    if "p3 start" not in failed or files_after_failure != baseline_files:
        raise RuntimeError(f"partial-start cleanup failed: {failed!r}, files={files_after_failure}")
    cycles = []
    for n in range(int(os.environ.get("P3_LIFECYCLE_CYCLES", "10"))):
        ctl(f"nfqueue-handoff-poc start queue {QUEUE} pool 32")
        active_files = ctl("show files").count("nfqueue-handoff-poc")
        started = time.monotonic(); ctl("nfqueue-handoff-poc stop"); elapsed = (time.monotonic() - started) * 1000
        remaining_files = ctl("show files").count("nfqueue-handoff-poc")
        if active_files != 6 or remaining_files or elapsed > 2000: raise RuntimeError("lifecycle residue")
        cycles.append({"cycle": n, "active_files": active_files, "remaining_files": remaining_files, "stop_ms": elapsed})
    ctl(f"nfqueue-handoff-poc start queue {QUEUE} pool 32"); add_rule()
    sender = popen_su(f"{REMOTE}/bin/nfqb-sender address-diverse 256 10000 5000 399999 {SOURCE_PORT}")
    time.sleep(.2); remove_rules(); show, parsed = wait_drained(); ctl("nfqueue-handoff-poc stop")
    sender_text, _ = sender.communicate(timeout=10)
    if sender.returncode or int(parsed["top"]["outstanding"]): raise RuntimeError("active drain failed")
    return {"partial_start": {"error": failed.strip(), "files_after_failure": files_after_failure}, "cycles": cycles, "active_drain": {"show": show, "sender": sender_text.replace("\r", "").strip()}}


def start_vpp() -> None:
    run([str(ADB), "push", str(PLUGIN), f"{REMOTE}/plugins/nfqueue_poc_plugin.so"])
    run([str(ADB), "push", str(SENDER), f"{REMOTE}/bin/nfqb-sender"])
    run([str(ADB), "push", str(CONFIG), "/data/local/tmp/p3-startup.conf"])
    su(f"chmod 755 {REMOTE}/bin/nfqb-sender; cp /data/local/tmp/p3-startup.conf {REMOTE}/runtime/startup.conf; if [ -f {REMOTE}/runtime/vpp.pid ]; then old=$(cat {REMOTE}/runtime/vpp.pid); kill -TERM $old 2>/dev/null || true; for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 $old 2>/dev/null || break; sleep .1; done; kill -0 $old 2>/dev/null && kill -KILL $old 2>/dev/null || true; fi; rm -f {REMOTE}/runtime/cli.sock; cd {REMOTE}; LD_LIBRARY_PATH={REMOTE}/lib nohup {REMOTE}/bin/vpp plugin_path {REMOTE}/plugins -c {REMOTE}/runtime/startup.conf >{REMOTE}/logs/stdout.log 2>&1 </dev/null & echo $! >{REMOTE}/runtime/vpp.pid")
    for _ in range(30):
        time.sleep(.2)
        try:
            ctl("show version")
            return
        except RuntimeError:
            pass
    raise RuntimeError("VPP startup timeout")


def cleanup() -> None:
    remove_rules(); ctl("nfqueue-handoff-poc stop", False); ctl("nfqueue-balance-poc stop", False)
    su(f"if [ -f {REMOTE}/runtime/vpp.pid ]; then kill -TERM $(cat {REMOTE}/runtime/vpp.pid) 2>/dev/null || true; fi", False)


def main() -> int:
    RESULT.mkdir(parents=True)
    (RESULT / "invalid-runs.md").write_text("# Invalid or inconclusive runs\n\n")
    manifest = {"prototype": True, "device": su("getprop ro.product.model").strip(), "android": su("getprop ro.build.version.release").strip(), "sdk": su("getprop ro.build.version.sdk").strip(), "kernel": su("uname -a").strip(), "queue": [70, 71], "source_port": SOURCE_PORT, "oracle_flows": [0, 224, 1, 226], "sha256": {"plugin": digest(PLUGIN), "p3_source": digest(POC / "overlay/src/plugins/nfqueue_poc/nfqueue_handoff_poc.c"), "runner": digest(Path(__file__)), "sender": digest(SENDER), "sender_source": digest(POC / "clients/android_nfqueue_balance_sender.c"), "config": digest(CONFIG)}}
    (RESULT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    rows = []
    start_vpp()
    try:
        life = lifecycle(); (RESULT / "lifecycle.json").write_text(json.dumps(life, indent=2) + "\n")
        if os.environ.get("P3_ONLY_LIFECYCLE") == "1":
            print(f"results={RESULT} lifecycle-only=1")
            return 0
        if os.environ.get("P3_PROFILE") == "p4-correctness":
            cases = [("normal", rep, rate, 32, 512, mode) for rate in (1000, 5000) for rep in range(3) for mode in ("queue-local", "canonical-return", "canonical-shared-trylock")]
        elif os.environ.get("P3_PROFILE") == "p4-performance":
            repetitions = int(os.environ.get("P4_REPETITIONS", "5"))
            seconds = int(os.environ.get("P4_SECONDS", "10"))
            rates = [int(value) for value in os.environ.get("P4_RATES", "5000 10000").split()]
            pool = int(os.environ.get("P4_POOL", "32"))
            modes = os.environ.get("P4_MODES", "queue-local canonical-return canonical-shared-trylock").split()
            cases = [("normal", rep, rate, pool, rate * seconds, mode) for rate in rates for rep in range(repetitions) for mode in modes]
            cases += [("remote", rep, 5000, pool, 5000 * seconds, mode) for rep in range(repetitions) for mode in modes]
            random.Random(20260802).shuffle(cases)
        else:
            cases = [("normal", rep, rate, 32, 512) for rate in (1000, 5000) for rep in range(3)] + [("overload", 0, 5000, 1, 5000), ("fault", 0, 1000, 32, 512)]
        for index, case in enumerate(cases, 1):
            print(f"[{index}/{len(cases)}] {case}", flush=True)
            row = run_case(index, *case); rows.append(row)
            if not row["valid"]:
                with (RESULT / "invalid-runs.md").open("a") as stream: stream.write(f"- `{row['case']}`: {','.join(row['reasons'])}\n")
    finally:
        cleanup()
    (RESULT / "raw.json").write_text(json.dumps(rows, indent=2) + "\n")
    valid = sum(bool(row["valid"]) for row in rows)
    (RESULT / "summary.md").write_text(f"# NFQUEUE canonical-owner return P3\n\n- Valid: `{valid}/{len(rows)}`\n- Lifecycle and partial-start cleanup: `lifecycle.json`\n")
    print(f"results={RESULT} valid={valid}/{len(rows)}")
    return 0 if valid == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
