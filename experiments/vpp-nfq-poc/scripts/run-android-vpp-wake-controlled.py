#!/usr/bin/env python3
"""Run the frozen P6 protocol behind a fail-closed Android environment guard.

This wrapper deliberately owns only environmental control.  It does not alter the
formal runner or any protocol constant.  A normal invocation performs a 30-minute
soak, the runner's untimed preflight, a post-preflight readiness check, and then the
frozen formal run.  Every mutation is enclosed by restoration of package-manager
and dexopt state.
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
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any
from unittest import mock


REPO = Path(__file__).resolve().parents[3]
ADB = REPO / "dev/adb"
RUNNER = Path(__file__).with_name("run-android-vpp-wake-idle-poc.py")
VENDING = "com.android.vending"
REMOTE_VPP_ROOTS = ("/data/local/tmp/vpp-p6/unpatched", "/data/local/tmp/vpp-p6/patched")

SOAK_SECONDS = 30 * 60
SOAK_INTERVAL_SECONDS = 5 * 60
CPU_SAMPLE_SECONDS = 5
SKIN_MAX_C = 37.0
SKIN_TREND_TOLERANCE_C = 0.1
AGGREGATE_IDLE_REFERENCE_PERCENT = 790.0
PROCESS_CPU_OBSERVATION_REFERENCE_PERCENT = 5.0
MANAGED_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)

RESTORE_COMMANDS = {
    0: f"pm default-state --user 0 {VENDING}",
    1: f"pm enable --user 0 {VENDING}",
    2: f"pm disable --user 0 {VENDING}",
    3: f"pm disable-user --user 0 {VENDING}",
    4: f"pm disable-until-used --user 0 {VENDING}",
}


class GuardError(RuntimeError):
    """A fail-closed environmental-control error."""


class ShutdownRequested(GuardError):
    def __init__(self, signum: int):
        super().__init__(f"received signal {signal.Signals(signum).name}")
        self.signum = signum


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def json_text(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"


def write_json(path: Path, value: object) -> None:
    path.write_text(json_text(value), encoding="utf-8")


def quote(value: str) -> str:
    return shlex.quote(value)


class EnvironmentGuard:
    def __init__(self, result_dir: Path, preflight_only: bool):
        self.result_dir = result_dir
        self.audit_dir = result_dir / "environmental-control"
        self.preflight_dir = result_dir.parent / f"{result_dir.name}-preflight"
        self.preflight_only = preflight_only
        self.original_vending_state: int | None = None
        self.baseline_cpufreq: list[str] | None = None
        self.child: subprocess.Popen[str] | None = None
        self.child_pgid: int | None = None
        self.child_leader_starttime: int | None = None
        self.events: list[dict[str, Any]] = []
        self.exit_status: int | None = None
        self.restoring = False
        self.vending_touched = False
        self.dexopt_touched = False
        self.restore_plan_persisted = False

    def command(self, args: list[str], *, check: bool = True,
                timeout: float = 180) -> dict[str, Any]:
        started = utc_now()
        try:
            result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            def partial(value: str | bytes | None) -> str:
                if value is None:
                    return ""
                if isinstance(value, bytes):
                    value = value.decode(errors="replace")
                return value.replace("\r", "")

            record = {"timestamp_utc": started, "argv": args,
                      "timeout": timeout, "timeout_seconds": timeout, "timed_out": True,
                      "returncode": None, "stdout": partial(error.stdout),
                      "stderr": partial(error.stderr)}
            self.events.append(record)
            raise GuardError(
                f"command timed out after {timeout}s: {shlex.join(args)}\n"
                f"{record['stdout']}{record['stderr']}") from error
        record = {"timestamp_utc": started, "argv": args, "returncode": result.returncode,
                  "timed_out": False,
                  "stdout": result.stdout.replace("\r", ""),
                  "stderr": result.stderr.replace("\r", "")}
        self.events.append(record)
        if check and result.returncode:
            raise GuardError(
                f"command failed rc={result.returncode}: {shlex.join(args)}\n"
                f"{record['stdout']}{record['stderr']}")
        return record

    def su(self, command: str, *, check: bool = True,
           timeout: float = 180) -> dict[str, Any]:
        return self.command(
            [str(ADB), "shell", f"su 0 sh -c {quote(command)}"],
            check=check, timeout=timeout)

    def output(self, command: str, *, check: bool = True,
               timeout: float = 180) -> str:
        record = self.su(command, check=check, timeout=timeout)
        return str(record["stdout"]) + str(record["stderr"])

    def flush_events(self, name: str, start: int) -> None:
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        try:
            write_json(self.audit_dir / name, {
                "written_utc": utc_now(), "commands": self.events[start:]})
            self.write_manifest()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)

    def write_manifest(self) -> None:
        files: dict[str, dict[str, Any]] = {}
        if self.audit_dir.exists():
            for path in sorted(self.audit_dir.iterdir()):
                if not path.is_file() or path.name == "sha256-manifest.json":
                    continue
                payload = path.read_bytes()
                files[path.name] = {"sha256": hashlib.sha256(payload).hexdigest(),
                                    "bytes": len(payload)}
        controller = Path(__file__).resolve()
        controller_payload = controller.read_bytes()
        manifest = {
            "generated_utc": utc_now(),
            "controller_source": {
                "path": str(controller),
                "sha256": hashlib.sha256(controller_payload).hexdigest(),
                "bytes": len(controller_payload),
            },
            "files": files,
        }
        write_json(self.audit_dir / "sha256-manifest.json", manifest)

    def vending_state(self) -> int:
        text = self.output(f"dumpsys package {VENDING}")
        state = self.parse_vending_state(text)
        if state is None:
            raise GuardError(f"could not parse Vending enabled state: {text!r}")
        if state not in RESTORE_COMMANDS:
            raise GuardError(f"unknown Vending enabled state {state}; refusing mutation")
        return state

    def vending_uid(self) -> int:
        text = self.output(f"dumpsys package {VENDING}")
        uid = self.parse_vending_uid(text)
        if uid is None:
            raise GuardError(f"could not parse Vending package UID: {text!r}")
        return uid

    @staticmethod
    def parse_vending_state(text: str) -> int | None:
        package = re.search(
            rf"(?ms)^  Package \[{re.escape(VENDING)}\].*?(?=^  Package \[|\Z)", text)
        if not package:
            return None
        user = re.search(r"(?m)^    User 0:.*\benabled=([0-9]+)\b", package.group(0))
        return int(user.group(1)) if user else None

    @staticmethod
    def parse_vending_uid(text: str) -> int | None:
        package = re.search(
            rf"(?ms)^  Package \[{re.escape(VENDING)}\].*?(?=^  Package \[|\Z)", text)
        if not package:
            return None
        # Android package dumps use either userId= or appId= for the package's
        # user-0 Linux identity, depending on platform release/build.
        uid = re.search(r"(?m)^    (?:userId|appId)=([0-9]+)\s*$", package.group(0))
        return int(uid.group(1)) if uid else None

    def cpufreq_vector(self) -> list[str]:
        text = self.output(
            "for d in /sys/devices/system/cpu/cpufreq/policy*; do "
            "[ -d \"$d\" ] || continue; echo POLICY=${d##*/}; "
            "for f in affected_cpus scaling_governor scaling_min_freq scaling_max_freq; do "
            "[ -r \"$d/$f\" ] || exit 41; echo $f=$(cat \"$d/$f\"); done; done")
        vector = [line.strip() for line in text.splitlines() if re.match(
            r"^(POLICY=|affected_cpus=|scaling_governor=|scaling_min_freq=|scaling_max_freq=)",
            line.strip())]
        policies = sum(line.startswith("POLICY=") for line in vector)
        if not policies or len(vector) != policies * 5:
            raise GuardError(f"incomplete cpufreq vector: {vector}")
        return vector

    def full_audit(self, phase: str) -> None:
        start = len(self.events)
        commands = {
            "timestamp_device": "date -Ins; getprop ro.product.model; getprop ro.build.fingerprint; getprop ro.build.version.release; getprop ro.build.version.sdk",
            "vending_package": f"dumpsys package {VENDING}",
            "disabled_packages_user0": "pm list packages -d --user 0",
            "processes": "for n in com.android.vending dex2oat dex2oat32 dex2oat64 vpp; do echo PIDOF=$n; pidof $n || true; done; top -b -n 1 -o PID,CPU,ARGS 2>&1 || top -b -n 1",
            "package_help_bg_dexopt": "cmd package help; echo __BG_DEXOPT__; cmd package bg-dexopt-job --help 2>&1 || true; dumpsys package dexopt 2>&1 || true",
            "thermalservice": "dumpsys thermalservice",
            "cpufreq_residency": "for d in /sys/devices/system/cpu/cpufreq/policy*; do [ -d \"$d\" ] || continue; echo POLICY=${d##*/}; for f in affected_cpus scaling_governor scaling_min_freq scaling_max_freq scaling_cur_freq cpuinfo_min_freq cpuinfo_max_freq; do [ -r \"$d/$f\" ] && echo $f=$(cat \"$d/$f\"); done; [ -r \"$d/stats/time_in_state\" ] && { echo TIME_IN_STATE; cat \"$d/stats/time_in_state\"; }; done",
            "screen": "dumpsys power; echo __DISPLAY__; dumpsys display",
        }
        for label, command in commands.items():
            record = self.su(command, check=False, timeout=300)
            record["label"] = label
        state: int | str
        try:
            state = self.vending_state()
        except Exception as error:
            state = f"ERROR:{type(error).__name__}:{error}"
            self.flush_events(f"{phase}.json", start)
            raise
        self.events.append({"timestamp_utc": utc_now(), "label": "vending_enabled_state_user0",
                            "state": state})
        self.flush_events(f"{phase}.json", start)

    def device_processes(self) -> list[dict[str, Any]]:
        text = self.output("ps -A -ww -o PID,UID,NAME,ARGS")
        return self.parse_device_processes(text)

    @staticmethod
    def parse_device_processes(text: str) -> list[dict[str, Any]]:
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines or lines[0].split() != ["PID", "UID", "NAME", "ARGS"]:
            raise GuardError("unexpected toybox ps header")
        processes: list[dict[str, Any]] = []
        seen: set[int] = set()
        for line in lines[1:]:
            fields = line.strip().split(None, 3)
            if len(fields) != 4 or not fields[0].isdigit() or not fields[1].isdigit():
                raise GuardError(f"unparseable toybox ps row: {line!r}")
            pid = int(fields[0])
            if pid in seen:
                raise GuardError(f"duplicate PID in toybox ps: {pid}")
            seen.add(pid)
            processes.append({"pid": pid, "uid": int(fields[1]),
                              "comm": fields[2], "cmdline": fields[3]})
        if not processes or 1 not in seen:
            raise GuardError("toybox ps snapshot is empty or missing PID 1")
        return processes

    def vpp_processes(self) -> list[dict[str, Any]]:
        return [process for process in self.device_processes()
                if any(root in str(process["cmdline"]) for root in REMOTE_VPP_ROOTS)]

    def assert_no_vpp(self) -> None:
        offenders = self.vpp_processes()
        if offenders:
            raise GuardError(f"stale P6 VPP processes remain: {offenders}")

    def assert_quiet_packages(self) -> None:
        if self.vending_state() != 3:
            raise GuardError("Vending is not in disabled-user state for user 0")
        vending_uid = self.vending_uid()
        offenders: list[dict[str, Any]] = []
        for process in self.device_processes():
            command = str(process["cmdline"]).strip()
            comm = str(process["comm"]).strip()
            vending_process = (int(process["uid"]) == vending_uid
                               or command == VENDING or command.startswith(f"{VENDING}:"))
            dex_process = any(name in (comm, command.split(" ", 1)[0])
                              for name in ("dex2oat", "dex2oat32", "dex2oat64"))
            if vending_process or dex_process:
                offenders.append(process)
        if offenders:
            raise GuardError(f"Vending/dex2oat processes remain: {offenders}")

    def screen_off(self) -> None:
        self.su("input keyevent 223")
        text = self.output("dumpsys power; dumpsys display")
        off = (re.search(r"Display Power:\s*state=OFF", text, re.I) is not None
               or re.search(r"mScreenOn=false", text, re.I) is not None
               or re.search(r"mScreenState=OFF", text, re.I) is not None)
        if not off:
            raise GuardError("screen-off verification failed")

    def apply_controls(self) -> None:
        start = len(self.events)
        try:
            # Mark a control as touched before invoking it: a transport error can
            # occur after Android has already applied the command.
            self.vending_touched = True
            self.su(f"pm disable-user --user 0 {VENDING}")
            self.su(f"am force-stop --user 0 {VENDING}")
            self.dexopt_touched = True
            self.su("cmd package bg-dexopt-job --cancel")
            self.su("cmd package bg-dexopt-job --disable")
            self.screen_off()
            self.assert_quiet_packages()
        finally:
            self.flush_events("applied.json", start)

    @staticmethod
    def parse_thermal(text: str) -> tuple[int, dict[str, int], float]:
        status_match = re.search(r"(?m)^Thermal Status:\s*([0-9]+)\s*$", text)
        if not status_match:
            raise GuardError("thermal global status unavailable")
        temperatures_match = re.search(
            r"(?ms)^Current temperatures from HAL:\s*\n(.*?)"
            r"(?=^[^\s].*:\s*$|\Z)", text)
        cooling_match = re.search(
            r"(?ms)^Current cooling devices from HAL:\s*\n(.*?)"
            r"(?=^[^\s].*:\s*$|\Z)", text)
        if not temperatures_match or not cooling_match:
            raise GuardError("current HAL thermal sections unavailable")
        temperatures_text = temperatures_match.group(1)
        cooling_text = cooling_match.group(1)
        cooling = {name: int(value) for value, name in re.findall(
            r"CoolingDevice\{mValue=([0-9]+),[^}]*mName=([^,}]+)", cooling_text)
                   if name.startswith("thermal-cpufreq-")}
        if not cooling:
            raise GuardError("CPU thermal cooling-device states unavailable")
        skin_matches = re.findall(
            r"Temperature\{mValue=([0-9]+(?:\.[0-9]+)?),[^}]*mName=VIRTUAL-SKIN(?:-[^,}]*)?",
            temperatures_text, re.I)
        if not skin_matches:
            raise GuardError("VIRTUAL-SKIN temperature unavailable")
        return int(status_match.group(1)), cooling, max(float(value) for value in skin_matches)

    @staticmethod
    def parse_proc_stat(text: str) -> dict[int, tuple[int, int]]:
        result: dict[int, tuple[int, int]] = {}
        for line in text.splitlines():
            match = re.match(r"cpu([0-9]+)\s+(.+)$", line)
            if not match:
                continue
            values = [int(value) for value in match.group(2).split()]
            if len(values) < 5:
                continue
            result[int(match.group(1))] = (sum(values), values[3] + values[4])
        return result

    @staticmethod
    def parse_process_stats(text: str) -> dict[int, tuple[int, str, int]]:
        """Parse concatenated proc stat rows as ticks, comm, and start-time."""
        result: dict[int, tuple[int, str, int]] = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            first_space = line.find(" ")
            close = line.rfind(") ")
            if first_space <= 0 or close <= first_space + 1:
                raise GuardError(f"unparseable /proc stat row: {line!r}")
            pid_text = line[:first_space]
            if not pid_text.isdigit() or line[first_space + 1] != "(":
                raise GuardError(f"unparseable /proc stat identity: {line!r}")
            pid = int(pid_text)
            comm = line[first_space + 2:close]
            rest = line[close + 2:].split()
            # After removing `pid (comm) `, rest[0] is field 3 (state), so
            # utime/stime fields 14/15 are indices 11/12.
            if len(rest) < 20 or len(rest[0]) != 1:
                raise GuardError(f"incomplete /proc stat row for pid {pid}")
            try:
                ticks = int(rest[11]) + int(rest[12])
                starttime = int(rest[19])  # field 22
            except ValueError as error:
                raise GuardError(f"invalid process counters for pid {pid}") from error
            if pid in result:
                raise GuardError(f"duplicate /proc stat PID: {pid}")
            result[pid] = (ticks, comm, starttime)
        if not result or 1 not in result:
            raise GuardError("process stat snapshot is empty or missing PID 1")
        return result

    @classmethod
    def parse_cpu_snapshot(cls, text: str) -> tuple[
            dict[int, tuple[int, int]], dict[int, tuple[int, str, int]],
            dict[int, dict[str, Any]], int]:
        marker_names = {"__PROC_STAT__", "__PROCESS_STATS__", "__PS__", "__CLK_TCK__"}
        sections: dict[str, list[str]] = {}
        current: str | None = None
        for line in text.splitlines():
            if line in marker_names:
                if line in sections:
                    raise GuardError(f"duplicate CPU snapshot section: {line}")
                sections[line] = []
                current = line
            elif current is None:
                if line.strip():
                    raise GuardError(f"CPU snapshot data precedes section marker: {line!r}")
            else:
                sections[current].append(line)
        if set(sections) != marker_names:
            raise GuardError(
                f"incomplete batched CPU snapshot sections: {sorted(sections)}")
        proc_text = "\n".join(sections["__PROC_STAT__"])
        process_text = "\n".join(sections["__PROCESS_STATS__"])
        ps_text = "\n".join(sections["__PS__"])
        hz_text = "\n".join(sections["__CLK_TCK__"])
        hz_lines = [line.strip() for line in hz_text.splitlines() if line.strip()]
        if len(hz_lines) != 1 or not hz_lines[0].isdigit():
            raise GuardError(f"invalid CLK_TCK evidence: {hz_lines}")
        ps = {int(process["pid"]): process
              for process in cls.parse_device_processes(ps_text)}
        return cls.parse_proc_stat(proc_text), cls.parse_process_stats(process_text), ps, int(hz_lines[0])

    def cpu_window(self) -> dict[str, Any]:
        process_sections = (
            "echo __PROCESS_STATS__; "
            "cat /proc/[0-9]*/stat 2>/dev/null; echo __PS__; "
            "ps -A -ww -o PID,UID,NAME,ARGS; echo __CLK_TCK__; getconf CLK_TCK")
        before_command = process_sections + "; echo __PROC_STAT__; cat /proc/stat"
        after_command = "echo __PROC_STAT__; cat /proc/stat; " + process_sections
        before_text = self.output(before_command)
        before_mono = time.monotonic()
        time.sleep(CPU_SAMPLE_SECONDS)
        after_mono = time.monotonic()
        after_text = self.output(after_command)
        elapsed = after_mono - before_mono
        before_cpu, before_process, before_ps, before_hz = self.parse_cpu_snapshot(before_text)
        after_cpu, after_process, after_ps, after_hz = self.parse_cpu_snapshot(after_text)
        common_cpus = sorted(set(before_cpu) & set(after_cpu))
        if len(common_cpus) != 8:
            raise GuardError(f"expected eight CPU accounting rows, got {common_cpus}")
        idle_fractions: dict[str, float] = {}
        for cpu in common_cpus:
            total_delta = after_cpu[cpu][0] - before_cpu[cpu][0]
            idle_delta = after_cpu[cpu][1] - before_cpu[cpu][1]
            if total_delta <= 0 or not (0 <= idle_delta <= total_delta):
                raise GuardError(f"invalid /proc/stat delta for cpu{cpu}")
            idle_fractions[str(cpu)] = 100.0 * idle_delta / total_delta
        if before_hz != after_hz:
            raise GuardError(f"CLK_TCK changed: {before_hz}->{after_hz}")
        hz = before_hz
        busy: list[dict[str, Any]] = []
        churn_observations: list[dict[str, Any]] = []

        def classify(pid: int, ticks: int, process: dict[str, Any] | None,
                     reason: str, identity: dict[str, Any]) -> None:
            if ticks < 0:
                raise GuardError(f"process ticks decreased for pid {pid}: {ticks}")
            percent = 100.0 * ticks / hz / elapsed
            if percent <= PROCESS_CPU_OBSERVATION_REFERENCE_PERCENT:
                return
            if process is None:
                busy.append({
                    "pid": pid,
                    "ticks": ticks,
                    "single_core_percent": percent,
                    "reason": reason,
                    "identity": identity,
                    "metadata_missing": True,
                    "observation_unquantifiable": True,
                    "qualification_gate": False,
                    "reference_percent": PROCESS_CPU_OBSERVATION_REFERENCE_PERCENT,
                    "status": "over-reference-metadata-missing",
                })
                return
            cmdline = str(process["cmdline"])
            if any(root in cmdline for root in REMOTE_VPP_ROOTS):
                return
            busy.append({"pid": pid, "uid": int(process["uid"]),
                         "comm": str(process["comm"]), "cmdline": cmdline,
                         "single_core_percent": percent, "reason": reason,
                         "identity": identity, "qualification_gate": False,
                         "reference_percent": PROCESS_CPU_OBSERVATION_REFERENCE_PERCENT,
                         "metadata_missing": False,
                         "observation_unquantifiable": False,
                         "status": "over-reference-observation"})

        for pid in sorted(set(before_process) & set(after_process)):
            before_ticks, before_comm, before_starttime = before_process[pid]
            after_ticks, after_comm, after_starttime = after_process[pid]
            # starttime is the stable Linux process-identity token. Kernel worker
            # comm values may legitimately change with their current workqueue.
            if before_starttime != after_starttime:
                raise GuardError(
                    f"process identity changed for common pid {pid}: "
                    f"starttime {before_starttime}->{after_starttime}")
            if (before_comm != after_comm
                    and not (before_comm.startswith("kworker/")
                             and after_comm.startswith("kworker/"))):
                raise GuardError(
                    f"process comm changed for stable pid {pid}: "
                    f"{before_comm!r}->{after_comm!r}")
            delta = after_ticks - before_ticks
            classify(pid, delta, after_ps.get(pid), "common-pid-tick-delta",
                     {"starttime": after_starttime, "stat_comm": after_comm})
        for pid in sorted(set(after_process) - set(before_process)):
            ticks, comm, starttime = after_process[pid]
            classify(pid, ticks, after_ps.get(pid), "after-only-total-ticks-upper-bound",
                     {"starttime": starttime, "stat_comm": comm})
        for pid in sorted(set(before_process) - set(after_process)):
            ticks, comm, starttime = before_process[pid]
            if ticks < 0:
                raise GuardError(f"process ticks decreased for pid {pid}: {ticks}")
            lifetime_upper_percent = 100.0 * ticks / hz / elapsed
            if lifetime_upper_percent <= PROCESS_CPU_OBSERVATION_REFERENCE_PERCENT:
                continue
            process = before_ps.get(pid)
            churn_observations.append({
                "pid": pid,
                "comm": str(process["comm"]) if process is not None else None,
                "stat_comm": comm,
                "starttime": starttime,
                "identity": {"starttime": starttime, "stat_comm": comm},
                "lifetime_ticks": ticks,
                "lifetime_ticks_as_window_upper_bound_percent": lifetime_upper_percent,
                "window_percent": None,
                "covered_by": "aggregate-idle-observation",
                "observation_unquantifiable": True,
                "qualification_gate": False,
                "reference_percent": PROCESS_CPU_OBSERVATION_REFERENCE_PERCENT,
                "reason": ("before-only-kworker-lifetime-unquantifiable"
                           if comm.startswith("kworker/")
                           else "before-only-user-lifetime-unquantifiable"),
            })
        aggregate_idle = sum(idle_fractions.values())
        aggregate_observation = {
            "qualification_gate": False,
            "reference_percent": AGGREGATE_IDLE_REFERENCE_PERCENT,
            "observed_percent": aggregate_idle,
            "status": ("at-or-above-reference" if aggregate_idle
                       >= AGGREGATE_IDLE_REFERENCE_PERCENT else "below-reference"),
        }
        unquantifiable_count = (sum(bool(item.get("observation_unquantifiable")) for item in busy)
                                + sum(bool(item.get("observation_unquantifiable"))
                                      for item in churn_observations))
        total_observations = len(busy) + len(churn_observations)
        process_observation = {
            "qualification_gate": False,
            "reference_percent": PROCESS_CPU_OBSERVATION_REFERENCE_PERCENT,
            "status": ("unquantifiable-observations-present" if unquantifiable_count
                       else "observations-over-reference-present" if total_observations
                       else "no-observations-over-reference"),
            "observation_count": total_observations,
            "busy_observation_count": len(busy),
            "churn_observation_count": len(churn_observations),
            "unquantifiable_observation_count": unquantifiable_count,
            "observations": busy,
            "churn_observations": churn_observations,
        }
        return {"sample_seconds": elapsed,
                "sample_seconds_semantics": (
                    "CLOCK_MONOTONIC host wait between endpoint commands; process ticks span "
                    "the wider before-to-after process-stat interval, so "
                    "single-core percentages are conservative"),
                "aggregate_window_semantics": (
                    "before /proc/stat is the final before section and after /proc/stat is the "
                    "first after section, excluding guard endpoint collection overhead"),
                "per_cpu_idle_percent": idle_fractions,
                "aggregate_idle_percent_of_800": aggregate_idle,
                "aggregate_idle_observation": aggregate_observation,
                "non_test_processes_over_5_percent": busy,
                "process_cpu_observation": process_observation,
                "process_churn_observations": churn_observations}

    def readiness_snapshot(self, label: str) -> dict[str, Any]:
        start = len(self.events)
        try:
            self.screen_off()
            self.assert_quiet_packages()
            self.assert_no_vpp()
            thermal_text = self.output("dumpsys thermalservice")
            thermal_status, cooling, skin_c = self.parse_thermal(thermal_text)
            cpufreq = self.cpufreq_vector()
            cpu = self.cpu_window()
            errors: list[str] = []
            if thermal_status != 0:
                errors.append(f"thermal-global={thermal_status}")
            active_cooling = {name: value for name, value in cooling.items() if value != 0}
            if active_cooling:
                errors.append(f"cpu-cooling-active={active_cooling}")
            if skin_c > SKIN_MAX_C:
                errors.append(f"VIRTUAL-SKIN={skin_c:.3f}>{SKIN_MAX_C:.1f}")
            if cpufreq != self.baseline_cpufreq:
                errors.append("cpufreq-vector-differs-from-before-audit")
            snapshot = {"timestamp_utc": utc_now(), "label": label,
                        "thermal_global_status": thermal_status,
                        "cooling_devices": cooling, "virtual_skin_c": skin_c,
                        "cpufreq_vector": cpufreq, "cpu": cpu, "errors": errors,
                        "valid": not errors}
            self.events.append({"timestamp_utc": utc_now(), "label": f"readiness:{label}",
                                "snapshot": snapshot})
            return snapshot
        except BaseException as error:
            self.events.append({"timestamp_utc": utc_now(),
                                "label": f"readiness-failure:{label}",
                                "error": f"{type(error).__name__}:{error}"})
            raise
        finally:
            self.flush_events(f"readiness-{label}.json", start)

    @staticmethod
    def require_final_trend(points: list[dict[str, Any]]) -> dict[str, Any]:
        """Return a JSON-safe, fail-closed assessment of the final four points."""
        final = points[-4:]
        all_points_valid = len(final) == 4 and all(
            bool(point.get("valid", False)) for point in final)
        temperatures: list[float | None] = []
        for point in final:
            try:
                value = float(point.get("virtual_skin_c"))
            except (TypeError, ValueError, OverflowError):
                value = math.nan
            temperatures.append(value if math.isfinite(value) else None)
        all_finite = len(temperatures) == 4 and all(
            temperature is not None for temperature in temperatures)
        all_at_or_below = all_finite and all(
            temperature is not None and temperature <= SKIN_MAX_C
            for temperature in temperatures)
        adjacent: list[float | None] = []
        for earlier, later in zip(temperatures, temperatures[1:]):
            adjacent.append(None if earlier is None or later is None else later - earlier)
        deltas_finite = len(adjacent) == 3 and all(delta is not None for delta in adjacent)
        max_rise = max(delta for delta in adjacent if delta is not None) if deltas_finite else None
        first = temperatures[0] if all_finite else None
        last = temperatures[-1] if all_finite else None
        early_mean = ((temperatures[0] + temperatures[1]) / 2
                      if all_finite and temperatures[0] is not None
                      and temperatures[1] is not None else None)
        late_mean = ((temperatures[2] + temperatures[3]) / 2
                     if all_finite and temperatures[2] is not None
                     and temperatures[3] is not None else None)
        net_delta = last - first if first is not None and last is not None else None
        half_mean_delta = (late_mean - early_mean
                           if early_mean is not None and late_mean is not None else None)
        epsilon = 1e-12
        net_ok = (net_delta is not None
                  and net_delta <= SKIN_TREND_TOLERANCE_C + epsilon)
        half_mean_ok = (half_mean_delta is not None
                        and half_mean_delta <= SKIN_TREND_TOLERANCE_C + epsilon)
        trend_status = ("unavailable" if net_delta is None or half_mean_delta is None
                        else "within-reference" if net_ok and half_mean_ok
                        else "above-reference")
        checks = {
            "exactly_four_points": len(final) == 4,
            "all_points_valid": all_points_valid,
            "all_temperatures_finite": all_finite,
            "all_at_or_below_37c": all_at_or_below,
        }
        errors: list[str] = []
        if not checks["exactly_four_points"]:
            errors.append(f"final-point-count={len(final)} expected=4")
        if not all_points_valid:
            invalid = [f"{point.get('label', '?')}:{point.get('errors', [])}"
                       for point in final if not bool(point.get("valid", False))]
            errors.append(f"invalid-final-points={invalid}")
        if not all_finite:
            errors.append("non-finite-final-temperature")
        if all_finite and not all_at_or_below:
            errors.append(f"final-temperature-above-{SKIN_MAX_C:.1f}c")
        return {
            "trend_rule_id": "final4-hard-thermal-with-trend-observation-v1",
            "final_four_virtual_skin_c": temperatures,
            "adjacent_deltas": adjacent,
            "adjacent_deltas_c": adjacent,
            "net_delta": net_delta,
            "net_delta_c": net_delta,
            "max_adjacent_rise": max_rise,
            "max_adjacent_rise_c": max_rise,
            "adjacent_observation": {
                "observation_only": True,
                "adjacent_deltas_c": adjacent,
                "max_adjacent_rise_c": max_rise,
            },
            "thermal_trend_observation": {
                "qualification_gate": False,
                "reference_c": SKIN_TREND_TOLERANCE_C,
                "status": trend_status,
                "first_c": first,
                "last_c": last,
                "early_mean_c": early_mean,
                "late_mean_c": late_mean,
                "adjacent_deltas_c": adjacent,
                "max_adjacent_rise_c": max_rise,
                "net_delta_c": net_delta,
                "half_mean_delta_c": half_mean_delta,
                "net_within_reference": net_ok,
                "half_mean_within_reference": half_mean_ok,
            },
            "first": first,
            "first_c": first,
            "last": last,
            "last_c": last,
            "early_mean": early_mean,
            "early_mean_c": early_mean,
            "late_mean": late_mean,
            "late_mean_c": late_mean,
            "half_mean_delta": half_mean_delta,
            "half_mean_delta_c": half_mean_delta,
            "tolerance": SKIN_TREND_TOLERANCE_C,
            "tolerance_c": SKIN_TREND_TOLERANCE_C,
            "all_points_valid": all_points_valid,
            "all_at_or_below_37c": all_at_or_below,
            "checks": checks,
            "valid": all(checks.values()),
            "errors": errors,
        }

    def write_soak_summary(self, points: list[dict[str, Any]],
                           assessment: dict[str, Any]) -> dict[str, Any]:
        summary = {
            "started_utc": points[0].get("timestamp_utc") if points else None,
            "finished_utc": points[-1].get("timestamp_utc") if points else None,
            "points": points,
            **assessment,
        }
        write_json(self.audit_dir / "soak-summary.json", summary)
        self.write_manifest()
        return summary

    def soak(self) -> list[dict[str, Any]]:
        points: list[dict[str, Any]] = []
        deadline = time.monotonic() + SOAK_SECONDS
        index = 0
        while True:
            points.append(self.readiness_snapshot(f"soak-{index:02d}"))
            if time.monotonic() >= deadline:
                break
            index += 1
            target = deadline - SOAK_SECONDS + index * SOAK_INTERVAL_SECONDS
            time.sleep(max(0.0, target - time.monotonic()))
        assessment = self.require_final_trend(points)
        self.write_soak_summary(points, assessment)
        if not assessment["valid"]:
            raise GuardError("readiness gate failed: " + "; ".join(assessment["errors"]))
        return points

    def run_child(self, args: list[str], label: str) -> int:
        start = len(self.events)
        self.events.append({"timestamp_utc": utc_now(), "label": f"child-start:{label}",
                            "argv": args})
        child: subprocess.Popen[str] | None = None
        try:
            old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
            try:
                child = subprocess.Popen(args, text=True, start_new_session=True)
                self.child = child
                # start_new_session makes the child both session and group leader.
                self.child_pgid = child.pid
                try:
                    observed_pgid, starttime = self.host_process_identity(child.pid)
                except BaseException:
                    # Popen still owns an unreaped, start_new_session leader here.
                    # Clean that exact leader/session without relying on the missing
                    # /proc start-time token, then propagate the identity failure.
                    self.stop_unidentified_child(child)
                    raise
                if observed_pgid != child.pid:
                    raise GuardError(
                        f"child {child.pid} did not become its expected process-group leader")
                self.child_leader_starttime = starttime
                write_json(self.audit_dir / f"child-{label}-control.json", {
                    "timestamp_utc": utc_now(), "argv": args, "leader_pid": child.pid,
                    "pgid": self.child_pgid,
                    "leader_starttime_ticks": self.child_leader_starttime,
                })
                self.write_manifest()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            return child.wait()
        finally:
            try:
                # The leader may exit before descendants.  Always drain and verify
                # the recorded process group before forgetting its identity.
                self.stop_child()
            finally:
                self.events.append({"timestamp_utc": utc_now(), "label": f"child-exit:{label}",
                                    "returncode": child.poll() if child is not None else None})
                self.flush_events(f"child-{label}.json", start)

    def stop_unidentified_child(self, child: subprocess.Popen[str]) -> None:
        """Clean a just-created session whose /proc identity capture failed."""
        pgid = child.pid
        if self.child is not child or self.child_pgid != pgid:
            raise GuardError("unidentified child cleanup lost its exact Popen leader")
        if child.poll() is None:
            try:
                if os.getpgid(child.pid) != pgid or os.getsid(child.pid) != child.pid:
                    raise GuardError(
                        f"child {child.pid} is not its expected session/group leader")
                os.killpg(pgid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            # The unreaped leader still owns this PID, so the group number cannot
            # have been reused by an unrelated session.
            os.killpg(pgid, signal.SIGKILL)
            child.wait(timeout=10)

        # The leader can leave descendants behind.  Its original group cannot be
        # reused while any such member exists; signal exact, revalidated members.
        deadline = time.monotonic() + 10
        members = self.host_group_members(pgid)
        while members and time.monotonic() < deadline:
            for pid, starttime in members.items():
                try:
                    if self.host_process_identity(pid) == (pgid, starttime):
                        os.kill(pid, signal.SIGKILL)
                except (FileNotFoundError, ProcessLookupError):
                    pass
            time.sleep(.05)
            members = self.host_group_members(pgid)
        if members:
            raise GuardError(
                f"unidentified child process group {pgid} survived cleanup: {members}")
        child.wait(timeout=1)
        self.child = None
        self.child_pgid = None
        self.child_leader_starttime = None

    @staticmethod
    def host_process_identity(pid: int) -> tuple[int, int]:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        rest = text[text.rfind(")") + 2:].split()
        if len(rest) < 20:
            raise GuardError(f"incomplete host /proc stat for pid {pid}")
        return int(rest[2]), int(rest[19])  # process group, start-time ticks

    @classmethod
    def host_group_members(cls, pgid: int) -> dict[int, int]:
        members: dict[int, int] = {}
        for path in Path("/proc").iterdir():
            if not path.name.isdigit():
                continue
            pid = int(path.name)
            try:
                observed_pgid, starttime = cls.host_process_identity(pid)
            except (FileNotFoundError, ProcessLookupError, PermissionError, GuardError):
                continue
            if observed_pgid == pgid:
                members[pid] = starttime
        return members

    def child_group_members(self) -> dict[int, int]:
        pgid = self.child_pgid
        leader_starttime = self.child_leader_starttime
        if pgid is None or leader_starttime is None:
            return {}
        members = self.host_group_members(pgid)
        observed_leader = members.get(pgid)
        if observed_leader is not None and observed_leader != leader_starttime:
            # The original group is gone and Linux reused its numeric PGID.  Treat
            # that unrelated group as out of scope and, critically, do not signal it.
            self.events.append({"timestamp_utc": utc_now(), "label": "child-pgid-reused",
                                "pgid": pgid, "expected_leader_starttime": leader_starttime,
                                "observed_leader_starttime": observed_leader})
            return {}
        return members

    def stop_child(self) -> None:
        if self.child_pgid is None:
            return
        pgid = self.child_pgid
        deadline = time.monotonic() + 15
        members = self.child_group_members()
        while members and time.monotonic() < deadline:
            self.signal_child_members(members, signal.SIGTERM)
            time.sleep(.1)
            members = self.child_group_members()
        members = self.child_group_members()
        if members:
            deadline = time.monotonic() + 10
            while members and time.monotonic() < deadline:
                self.signal_child_members(members, signal.SIGKILL)
                time.sleep(.05)
                members = self.child_group_members()
        remaining = self.child_group_members()
        if remaining:
            raise GuardError(f"child process group {pgid} survived cleanup: {remaining}")
        if self.child is not None:
            try:
                self.child.wait(timeout=1)
            except subprocess.TimeoutExpired as error:
                raise GuardError(f"child leader {self.child.pid} was not reaped") from error
        self.child = None
        self.child_pgid = None
        self.child_leader_starttime = None

    def signal_child_members(self, members: dict[int, int], signum: int) -> None:
        """Signal exact process identities, never a potentially reused numeric PGID."""
        if self.child_pgid is None:
            return
        for pid, expected_starttime in members.items():
            try:
                observed_pgid, observed_starttime = self.host_process_identity(pid)
                if (observed_pgid, observed_starttime) != (
                        self.child_pgid, expected_starttime):
                    continue
                os.kill(pid, signum)
            except (FileNotFoundError, ProcessLookupError):
                continue

    def stop_vpp(self) -> None:
        for root in REMOTE_VPP_ROOTS:
            self.su(
                f"if [ -f {root}/runtime/vpp.pid ]; then p=$(cat {root}/runtime/vpp.pid); "
                "case \"$p\" in ''|*[!0-9]*) p=;; esac; "
                "cmd=; [ -n \"$p\" ] && cmd=$(tr '\\000' ' ' </proc/$p/cmdline 2>/dev/null || true); "
                f"case \"$cmd\" in *{root}*) kill -TERM $p 2>/dev/null || true; "
                "i=0; while kill -0 $p 2>/dev/null && [ $i -lt 20 ]; do sleep .1; i=$(($i+1)); done; "
                "kill -KILL $p 2>/dev/null || true;; esac; fi; "
                f"rm -f {root}/runtime/cli.sock {root}/runtime/vpp.pid",
                check=False)
        for _ in range(2):
            offenders = self.vpp_processes()
            if not offenders:
                break
            pids = " ".join(str(process["pid"]) for process in offenders)
            patterns = "|".join(f"*{root}*" for root in REMOTE_VPP_ROOTS)
            self.su(
                f"for p in {pids}; do cmd=$(tr '\\000' ' ' </proc/$p/cmdline 2>/dev/null || true); "
                f"case \"$cmd\" in {patterns}) kill -TERM $p 2>/dev/null || true;; esac; done; "
                "sleep .5; "
                f"for p in {pids}; do cmd=$(tr '\\000' ' ' </proc/$p/cmdline 2>/dev/null || true); "
                f"case \"$cmd\" in {patterns}) kill -KILL $p 2>/dev/null || true;; esac; done",
                check=False)
        self.assert_no_vpp()

    def persist_restore_plan(self) -> None:
        if self.original_vending_state is None:
            raise GuardError("cannot persist restore plan without exact Vending state")
        write_json(self.audit_dir / "restore-plan.json", {
            "written_utc": utc_now(),
            "must_exist_before_first_mutation": True,
            "vending": {"package": VENDING, "user": 0,
                        "original_enabled_state": self.original_vending_state,
                        "restore_command": RESTORE_COMMANDS[self.original_vending_state]},
            "bg_dexopt_restore_command": "cmd package bg-dexopt-job --enable",
            "vpp_roots_to_stop": list(REMOTE_VPP_ROOTS),
            "controller_source_sha256": hashlib.sha256(
                Path(__file__).resolve().read_bytes()).hexdigest(),
        })
        self.write_manifest()
        self.restore_plan_persisted = True

    def run_preflight(self) -> dict[str, Any]:
        if self.preflight_dir.exists():
            raise GuardError(f"preflight result directory already exists: {self.preflight_dir}")
        before = self.readiness_snapshot("preflight-before")
        if not before["valid"]:
            raise GuardError(f"preflight-before readiness failed: {before['errors']}")
        rc = self.run_child(
            [sys.executable, str(RUNNER), "--preflight", "--result-dir", str(self.preflight_dir)],
            "preflight")
        if rc != 0:
            raise GuardError(f"P6 runner preflight failed with rc={rc}")
        after = self.readiness_snapshot("preflight-after-00")
        if not after["valid"]:
            raise GuardError(f"post-preflight readiness failed: {after['errors']}")
        before_skin = float(before["virtual_skin_c"])
        after_skin = float(after["virtual_skin_c"])
        delta = after_skin - before_skin
        thermal_observation = {
            "qualification_gate": False,
            "reference_c": SKIN_TREND_TOLERANCE_C,
            "before_c": before_skin,
            "after_c": after_skin,
            "delta_c": delta,
            "status": ("within-reference" if delta <= SKIN_TREND_TOLERANCE_C + 1e-12
                       else "above-reference"),
        }
        assessment = {"preflight": True, "hard_readiness_valid": True,
                      "thermal_delta_observation": thermal_observation,
                      "before": before, "after": after}
        write_json(self.audit_dir / "preflight-assessment.json", assessment)
        self.write_manifest()
        after = {**after, "preflight_thermal_delta_observation": thermal_observation}
        return after

    def run(self) -> int:
        if not ADB.is_file() or not os.access(ADB, os.X_OK):
            raise GuardError(f"repo-local adb is missing or not executable: {ADB}")
        if not RUNNER.is_file():
            raise GuardError(f"frozen runner missing: {RUNNER}")
        self.result_dir.mkdir(parents=True, exist_ok=False)
        self.audit_dir.mkdir()
        try:
            self.original_vending_state = self.vending_state()
            self.persist_restore_plan()
            self.full_audit("before")
            baseline_start = len(self.events)
            try:
                self.stop_vpp()
                self.assert_no_vpp()
                self.baseline_cpufreq = self.cpufreq_vector()
            finally:
                self.flush_events("pre-soak-vpp-control.json", baseline_start)
            self.apply_controls()
            self.soak()
            self.run_preflight()
            if self.preflight_only:
                self.exit_status = 0
                return 0
            rc = self.run_child(
                [sys.executable, str(RUNNER), "--execute", "--phase", "all",
                 "--result-dir", str(self.result_dir / "formal")], "formal")
            self.exit_status = rc
            return rc
        finally:
            self.restore()

    def restore(self) -> None:
        self.restoring = True
        start = len(self.events)
        errors: list[str] = []
        try:
            self.stop_child()
        except Exception as error:
            errors.append(f"stop-child:{type(error).__name__}:{error}")
        if self.restore_plan_persisted:
            try:
                self.stop_vpp()
            except Exception as error:
                errors.append(f"stop-vpp:{type(error).__name__}:{error}")
        if self.dexopt_touched:
            try:
                self.su("cmd package bg-dexopt-job --enable")
            except Exception as error:
                errors.append(f"bg-dexopt-enable:{type(error).__name__}:{error}")
        if self.vending_touched:
            if self.original_vending_state is None:
                errors.append("original-vending-state-unavailable")
            else:
                try:
                    self.su(RESTORE_COMMANDS[self.original_vending_state])
                    observed = self.vending_state()
                    if observed != self.original_vending_state:
                        errors.append(
                            f"vending-state-mismatch expected={self.original_vending_state} observed={observed}")
                except Exception as error:
                    errors.append(f"vending-restore:{type(error).__name__}:{error}")
        try:
            self.full_audit("restore-audit")
        except Exception as error:
            errors.append(f"restore-audit:{type(error).__name__}:{error}")
        self.events.append({"timestamp_utc": utc_now(), "label": "restore-result",
                            "original_vending_state": self.original_vending_state,
                            "vending_touched": self.vending_touched,
                            "dexopt_touched": self.dexopt_touched,
                            "restore_plan_persisted": self.restore_plan_persisted,
                            "errors": errors, "valid": not errors})
        self.flush_events("restore.json", start)
        if errors and sys.exc_info()[0] is None:
            raise GuardError("restoration failed: " + "; ".join(errors))


def self_test() -> None:
    assert REPO / "dev/adb" == ADB
    assert set(RESTORE_COMMANDS) == {0, 1, 2, 3, 4}
    proc = "cpu  10 0 5 80 5 0 0 0\ncpu0 5 0 2 40 3 0 0 0\ncpu7 5 0 3 40 2 0 0 0\n"
    parsed = EnvironmentGuard.parse_proc_stat(proc)
    assert parsed == {0: (50, 43), 7: (50, 42)}
    processes = (
        "1 (init) S 0 1 1 0 0 0 0 0 0 0 3 1 0 0 20 0 1 0 100\n"
        "12 (thing with spaces (and) parens) R 1 2 3 4 5 6 7 8 9 10 40 2 0 0 20 0 1 0 12345\n"
        "13 (simple) S 1 2 3 4 5 6 7 8 9 10 7 8 0 0 20 0 1 0 23456\n")
    assert EnvironmentGuard.parse_process_stats(processes) == {
        1: (4, "init", 100),
        12: (42, "thing with spaces (and) parens", 12345),
        13: (15, "simple", 23456)}
    thermal = ("Thermal Status: 0\n"
               "Cached temperatures:\n"
               "\tTemperature{mValue=41.5, mType=3, mName=VIRTUAL-SKIN, mStatus=0}\n"
               "Current temperatures from HAL:\n"
               "\tTemperature{mValue=36.5, mType=3, mName=VIRTUAL-SKIN, mStatus=0}\n"
               "Current cooling devices from HAL:\n"
               "\tCoolingDevice{mValue=0, mType=2, mName=thermal-cpufreq-0}\n"
               "Temperature static thresholds from HAL:\n")
    assert EnvironmentGuard.parse_thermal(thermal) == (
        0, {"thermal-cpufreq-0": 0}, 36.5)
    packages = ("  Package [com.android.vending] (current):\n"
                "    appId=10123\n"
                "    versionName=52\n"
                "    User 0: installed=true enabled=1 stopped=true\n"
                "  Package [com.android.vending] (disabled-system):\n"
                "    versionName=46\n"
                "    User 0: installed=true enabled=0 stopped=false\n")
    assert EnvironmentGuard.parse_vending_state(packages) == 1
    assert EnvironmentGuard.parse_vending_uid(packages) == 10123
    assert EnvironmentGuard.parse_vending_uid(
        packages.replace("appId=10123", "userId=10123")) == 10123
    device_processes = (
        "  PID   UID NAME       ARGS\n"
        "    1     0 init       /system/bin/init\n"
        "   12 10123 process    com.android.vending:background --long argument\n"
        "   13     0 dex2oat64  dex2oat64 --zip-fd=4\n")
    assert EnvironmentGuard.parse_device_processes(device_processes) == [
        {"pid": 1, "uid": 0, "comm": "init", "cmdline": "/system/bin/init"},
        {"pid": 12, "uid": 10123, "comm": "process",
         "cmdline": "com.android.vending:background --long argument"},
        {"pid": 13, "uid": 0, "comm": "dex2oat64",
         "cmdline": "dex2oat64 --zip-fd=4"},
    ]
    before_cpu_snapshot = (
        "__PROCESS_STATS__\n" + processes + "__PS__\n" + device_processes
        + "__CLK_TCK__\n100\n__PROC_STAT__\n" + proc)
    after_cpu_snapshot = (
        "__PROC_STAT__\n" + proc + "__PROCESS_STATS__\n" + processes
        + "__PS__\n" + device_processes + "__CLK_TCK__\n100\n")
    for cpu_snapshot in (before_cpu_snapshot, after_cpu_snapshot):
        snapshot_cpu, snapshot_processes, snapshot_ps, snapshot_hz = (
            EnvironmentGuard.parse_cpu_snapshot(cpu_snapshot))
        assert snapshot_cpu == parsed and snapshot_processes[12][0] == 42
        assert snapshot_ps[12]["cmdline"].startswith(VENDING) and snapshot_hz == 100
    for parser, empty in (
            (EnvironmentGuard.parse_device_processes, "PID UID NAME ARGS\n"),
            (EnvironmentGuard.parse_process_stats, "")):
        try:
            parser(empty)
        except GuardError:
            pass
        else:
            raise AssertionError("empty process snapshot must fail closed")
    for parser, missing_init in (
            (EnvironmentGuard.parse_device_processes,
             "PID UID NAME ARGS\n12 1000 app /system/bin/app\n"),
            (EnvironmentGuard.parse_process_stats, processes.split("\n", 1)[1])):
        try:
            parser(missing_init)
        except GuardError:
            pass
        else:
            raise AssertionError("process snapshot missing PID 1 must fail closed")

    def synthetic_stat(pid: int, comm: str, ticks: int, starttime: int) -> str:
        return (f"{pid} ({comm}) S 0 1 1 0 0 0 0 0 0 0 {ticks} 0 "
                f"0 0 20 0 1 0 {starttime}\n")

    before_cpu_lines = "".join(
        f"cpu{cpu} 100 0 0 900 0 0 0 0\n" for cpu in range(8))
    after_cpu_lines = "".join(
        f"cpu{cpu} 100 0 0 1900 0 0 0 0\n" for cpu in range(8))
    before_only_stats = (synthetic_stat(1, "init", 100, 1)
                         + synthetic_stat(40, "kworker/u16:7-events", 30, 40))
    after_only_stats = synthetic_stat(1, "init", 100, 1) + synthetic_stat(30, "vpp", 30, 30)
    before_only_ps = (
        "PID UID NAME ARGS\n1 0 init /system/bin/init\n"
        "40 0 kworker/u16:7-events [kworker/u16:7-events]\n")
    after_only_ps = (
        "PID UID NAME ARGS\n1 0 init /system/bin/init\n"
        "30 1000 vpp /system/bin/not-a-p6-root\n")
    synthetic_before = (
        "__PROCESS_STATS__\n" + before_only_stats + "__PS__\n" + before_only_ps
        + "__CLK_TCK__\n100\n__PROC_STAT__\n" + before_cpu_lines)
    synthetic_after = (
        "__PROC_STAT__\n" + after_cpu_lines + "__PROCESS_STATS__\n" + after_only_stats
        + "__PS__\n" + after_only_ps + "__CLK_TCK__\n100\n")
    cpu_guard = EnvironmentGuard(Path("/device-free"), preflight_only=True)
    with (mock.patch.object(cpu_guard, "output", side_effect=[synthetic_before, synthetic_after]),
          mock.patch.object(time, "sleep"),
          mock.patch.object(time, "monotonic", side_effect=[0.0, 5.0])):
        synthetic_result = cpu_guard.cpu_window()
    reasons = {entry["reason"] for entry in synthetic_result["non_test_processes_over_5_percent"]}
    assert reasons == {"after-only-total-ticks-upper-bound"}
    assert synthetic_result["process_churn_observations"] == [{
        "pid": 40,
        "comm": "kworker/u16:7-events",
        "stat_comm": "kworker/u16:7-events",
        "starttime": 40,
        "identity": {"starttime": 40, "stat_comm": "kworker/u16:7-events"},
        "lifetime_ticks": 30,
        "lifetime_ticks_as_window_upper_bound_percent": 6.0,
        "window_percent": None,
        "covered_by": "aggregate-idle-observation",
        "observation_unquantifiable": True,
        "qualification_gate": False,
        "reference_percent": 5.0,
        "reason": "before-only-kworker-lifetime-unquantifiable",
    }]
    assert synthetic_result["aggregate_idle_observation"] == {
        "qualification_gate": False, "reference_percent": 790.0,
        "observed_percent": 800.0, "status": "at-or-above-reference"}
    assert synthetic_result["process_cpu_observation"]["qualification_gate"] is False
    assert synthetic_result["process_cpu_observation"]["status"] == (
        "unquantifiable-observations-present")
    assert synthetic_result["process_cpu_observation"]["observation_count"] == 2
    assert not any(root in entry["cmdline"] for root in REMOTE_VPP_ROOTS
                   for entry in synthetic_result["non_test_processes_over_5_percent"])
    invalid_before = synthetic_before.replace(
        "(kworker/u16:7-events)", "(ordinary-churn)").replace(
            "kworker/u16:7-events [kworker/u16:7-events]",
            "ordinary-churn /system/bin/ordinary-churn")
    with (mock.patch.object(cpu_guard, "output", side_effect=[invalid_before, synthetic_after]),
          mock.patch.object(time, "sleep"),
          mock.patch.object(time, "monotonic", side_effect=[0.0, 5.0])):
        ordinary_churn_result = cpu_guard.cpu_window()
    ordinary_observation = ordinary_churn_result["process_churn_observations"][0]
    assert ordinary_observation["reason"] == "before-only-user-lifetime-unquantifiable"
    assert ordinary_observation["observation_unquantifiable"] is True
    assert ordinary_observation["qualification_gate"] is False

    metadata_missing_after = synthetic_after.replace(
        "30 1000 vpp /system/bin/not-a-p6-root\n", "")
    with (mock.patch.object(cpu_guard, "output",
                            side_effect=[synthetic_before, metadata_missing_after]),
          mock.patch.object(time, "sleep"),
          mock.patch.object(time, "monotonic", side_effect=[0.0, 5.0])):
        metadata_missing_result = cpu_guard.cpu_window()
    missing = metadata_missing_result["non_test_processes_over_5_percent"][0]
    assert missing == {
        "pid": 30, "ticks": 30, "single_core_percent": 6.0,
        "reason": "after-only-total-ticks-upper-bound",
        "identity": {"starttime": 30, "stat_comm": "vpp"},
        "metadata_missing": True, "observation_unquantifiable": True,
        "qualification_gate": False, "reference_percent": 5.0,
        "status": "over-reference-metadata-missing",
    }
    assert metadata_missing_result["process_cpu_observation"]["status"] == (
        "unquantifiable-observations-present")

    def cpu_payload(aggregate: float, include_busy: bool) -> dict[str, Any]:
        payload = json.loads(json.dumps(synthetic_result))
        payload["aggregate_idle_percent_of_800"] = aggregate
        payload["aggregate_idle_observation"]["observed_percent"] = aggregate
        payload["aggregate_idle_observation"]["status"] = (
            "at-or-above-reference" if aggregate >= 790 else "below-reference")
        if not include_busy:
            payload["non_test_processes_over_5_percent"] = []
            payload["process_cpu_observation"]["observations"] = []
            payload["process_cpu_observation"]["busy_observation_count"] = 0
            payload["process_cpu_observation"]["observation_count"] = len(
                payload["process_churn_observations"])
            payload["process_cpu_observation"]["status"] = (
                "unquantifiable-observations-present")
        return payload

    for aggregate, include_busy in ((789.0, False), (800.0, True), (789.0, True)):
        readiness_guard = EnvironmentGuard(Path("/device-free-readiness"), preflight_only=True)
        readiness_guard.baseline_cpufreq = ["stable"]
        with (mock.patch.object(readiness_guard, "screen_off"),
              mock.patch.object(readiness_guard, "assert_quiet_packages"),
              mock.patch.object(readiness_guard, "assert_no_vpp"),
              mock.patch.object(readiness_guard, "output", return_value=thermal),
              mock.patch.object(readiness_guard, "cpufreq_vector", return_value=["stable"]),
              mock.patch.object(readiness_guard, "cpu_window",
                                return_value=cpu_payload(aggregate, include_busy)),
              mock.patch.object(readiness_guard, "flush_events")):
            readiness = readiness_guard.readiness_snapshot("cpu-observation-test")
        assert readiness["valid"] and not readiness["errors"]
        assert readiness["cpu"]["aggregate_idle_observation"]["qualification_gate"] is False
        assert readiness["cpu"]["process_cpu_observation"]["qualification_gate"] is False
    with tempfile.TemporaryDirectory(prefix="p6-guard-missing-ps-test-") as temporary:
        readiness_guard = EnvironmentGuard(Path(temporary) / "result", preflight_only=True)
        readiness_guard.audit_dir.mkdir(parents=True)
        readiness_guard.baseline_cpufreq = ["stable"]
        with (mock.patch.object(readiness_guard, "screen_off"),
              mock.patch.object(readiness_guard, "assert_quiet_packages"),
              mock.patch.object(readiness_guard, "assert_no_vpp"),
              mock.patch.object(readiness_guard, "output", return_value=thermal),
              mock.patch.object(readiness_guard, "cpufreq_vector", return_value=["stable"]),
              mock.patch.object(readiness_guard, "cpu_window",
                                return_value=metadata_missing_result)):
            readiness = readiness_guard.readiness_snapshot("metadata-missing")
        assert readiness["valid"] and not readiness["errors"]
        persisted = json.loads(
            (readiness_guard.audit_dir / "readiness-metadata-missing.json").read_text())
        persisted_snapshot = persisted["commands"][-1]["snapshot"]
        assert persisted_snapshot["valid"]
        assert persisted_snapshot["cpu"]["process_cpu_observation"]["status"] == (
            "unquantifiable-observations-present")
        manifest = json.loads(
            (readiness_guard.audit_dir / "sha256-manifest.json").read_text())
        assert "readiness-metadata-missing.json" in manifest["files"]
    for hard_thermal, expected_error in (
            (thermal.replace("Thermal Status: 0", "Thermal Status: 1"), "thermal-global=1"),
            (thermal.replace("CoolingDevice{mValue=0", "CoolingDevice{mValue=1"),
             "cpu-cooling-active="),
            (thermal.replace("mValue=36.5", "mValue=37.1"), "VIRTUAL-SKIN=37.100>37.0")):
        hard_guard = EnvironmentGuard(Path("/device-free-hard-thermal"), preflight_only=True)
        hard_guard.baseline_cpufreq = ["stable"]
        with (mock.patch.object(hard_guard, "screen_off"),
              mock.patch.object(hard_guard, "assert_quiet_packages"),
              mock.patch.object(hard_guard, "assert_no_vpp"),
              mock.patch.object(hard_guard, "output", return_value=hard_thermal),
              mock.patch.object(hard_guard, "cpufreq_vector", return_value=["stable"]),
              mock.patch.object(hard_guard, "cpu_window", return_value=synthetic_result),
              mock.patch.object(hard_guard, "flush_events")):
            hard_readiness = hard_guard.readiness_snapshot("hard-thermal-test")
        assert not hard_readiness["valid"]
        assert any(error.startswith(expected_error) for error in hard_readiness["errors"])
    with tempfile.TemporaryDirectory(prefix="p6-guard-preflight-rise-test-") as temporary:
        preflight_guard = EnvironmentGuard(Path(temporary) / "result", preflight_only=True)
        preflight_guard.audit_dir.mkdir(parents=True)
        preflight_before = {"valid": True, "errors": [], "virtual_skin_c": 35.0}
        preflight_after = {"valid": True, "errors": [], "virtual_skin_c": 35.3}
        with (mock.patch.object(preflight_guard, "readiness_snapshot",
                                side_effect=[preflight_before, preflight_after]) as readiness_mock,
              mock.patch.object(preflight_guard, "run_child", return_value=0),
              mock.patch.object(time, "sleep") as sleep_mock):
            preflight_result = preflight_guard.run_preflight()
        assert readiness_mock.call_count == 2
        sleep_mock.assert_not_called()
        observation = preflight_result["preflight_thermal_delta_observation"]
        assert observation["qualification_gate"] is False
        assert observation["status"] == "above-reference"
        assessment = json.loads(
            (preflight_guard.audit_dir / "preflight-assessment.json").read_text())
        assert assessment["hard_readiness_valid"]
        assert abs(assessment["thermal_delta_observation"]["delta_c"] - 0.3) < 1e-12
        manifest = json.loads(
            (preflight_guard.audit_dir / "sha256-manifest.json").read_text())
        assert "preflight-assessment.json" in manifest["files"]
    current_pgid, current_starttime = EnvironmentGuard.host_process_identity(os.getpid())
    assert current_pgid == os.getpgrp() and current_starttime > 0
    with tempfile.TemporaryDirectory(prefix="p6-guard-timeout-test-") as temporary:
        timeout_guard = EnvironmentGuard(Path(temporary) / "result", preflight_only=True)
        timeout_guard.audit_dir.mkdir(parents=True)
        timeout = subprocess.TimeoutExpired(
            [str(ADB), "shell", "test"], 7, output=b"partial\r\n", stderr="error\r\n")
        with mock.patch.object(subprocess, "run", side_effect=timeout):
            try:
                timeout_guard.apply_controls()
            except GuardError as error:
                assert "timed out" in str(error)
            else:
                raise AssertionError("command timeout must fail closed")
        applied = json.loads((timeout_guard.audit_dir / "applied.json").read_text())
        timeout_event = applied["commands"][0]
        assert timeout_event["timed_out"] is True
        assert timeout_event["returncode"] is None
        assert timeout_event["timeout"] == 180
        assert timeout_event["timeout_seconds"] == 180
        assert timeout_event["stdout"] == "partial\n"
        assert timeout_event["stderr"] == "error\n"
        manifest = json.loads(
            (timeout_guard.audit_dir / "sha256-manifest.json").read_text())
        assert "applied.json" in manifest["files"]
    with tempfile.TemporaryDirectory(prefix="p6-guard-identity-test-") as temporary:
        identity_guard = EnvironmentGuard(Path(temporary) / "result", preflight_only=True)
        identity_guard.audit_dir.mkdir(parents=True)
        real_identity = EnvironmentGuard.host_process_identity
        injected = {"done": False, "pid": None}

        def fail_first_identity(pid: int) -> tuple[int, int]:
            if not injected["done"]:
                injected["done"] = True
                injected["pid"] = pid
                raise GuardError("injected-host-process-identity-failure")
            return real_identity(pid)

        with mock.patch.object(
                EnvironmentGuard, "host_process_identity", side_effect=fail_first_identity):
            try:
                identity_guard.run_child(["/bin/sh", "-c", "sleep 60"], "identity-test")
            except GuardError as error:
                assert "injected-host-process-identity-failure" in str(error)
            else:
                raise AssertionError("identity capture failure must propagate")
        assert injected["pid"] is not None
        assert not Path(f"/proc/{injected['pid']}").exists()
        assert identity_guard.child is None and identity_guard.child_pgid is None
        identity_audit = json.loads(
            (identity_guard.audit_dir / "child-identity-test.json").read_text())
        assert identity_audit["commands"][-1]["returncode"] is not None
    # Device-free lifecycle check: the shell leader exits normally while a member
    # remains in its process group; run_child must terminate and verify that member.
    with tempfile.TemporaryDirectory(prefix="p6-guard-self-test-") as temporary:
        test_guard = EnvironmentGuard(Path(temporary) / "result", preflight_only=True)
        test_guard.audit_dir.mkdir(parents=True)
        assert test_guard.run_child(
            ["/bin/sh", "-c", "sleep 60 & exit 0"], "self-test") == 0
        assert test_guard.child is None and test_guard.child_pgid is None
    def thermal_points(values: tuple[float, float, float, float],
                       invalid_index: int | None = None) -> list[dict[str, Any]]:
        return [{"label": str(index), "timestamp_utc": f"t{index}",
                 "valid": index != invalid_index,
                 "errors": ["injected-invalid"] if index == invalid_index else [],
                 "virtual_skin_c": value}
                for index, value in enumerate(values)]

    controlled_12 = EnvironmentGuard.require_final_trend(
        thermal_points((29.611002, 29.577553, 29.54075, 29.585352)))
    assert controlled_12["valid"]
    assert abs(controlled_12["adjacent_deltas_c"][-1] - 0.044602) < 1e-12
    assert controlled_12["net_delta_c"] < 0
    controlled_15 = EnvironmentGuard.require_final_trend(
        thermal_points((29.921251, 30.100101, 30.03795, 29.89235)))
    assert controlled_15["valid"]
    assert abs(controlled_15["max_adjacent_rise_c"] - 0.17885) < 1e-12
    assert controlled_15["adjacent_observation"]["observation_only"] is True
    assert controlled_15["trend_rule_id"] == (
        "final4-hard-thermal-with-trend-observation-v1")
    controlled_18 = EnvironmentGuard.require_final_trend(
        thermal_points((33.675602, 33.729103, 33.780003, 33.8669)))
    assert controlled_18["valid"]
    assert controlled_18["thermal_trend_observation"]["status"] == "above-reference"
    assert abs(controlled_18["net_delta_c"] - 0.191298) < 1e-12
    assert abs(controlled_18["half_mean_delta_c"] - 0.121099) < 1e-12
    net_observation = EnvironmentGuard.require_final_trend(
        thermal_points((36.0, 36.04, 36.08, 36.12)))
    assert net_observation["valid"]
    assert net_observation["thermal_trend_observation"]["status"] == "above-reference"
    half_mean_observation = EnvironmentGuard.require_final_trend(
        thermal_points((36.0, 35.8, 36.1, 36.05)))
    assert half_mean_observation["valid"]
    assert half_mean_observation["thermal_trend_observation"]["status"] == "above-reference"
    adjacent_spike_observation = EnvironmentGuard.require_final_trend(
        thermal_points((36.5, 36.0, 36.3, 36.1)))
    assert adjacent_spike_observation["valid"]
    assert adjacent_spike_observation["max_adjacent_rise_c"] > 0.2
    assert adjacent_spike_observation["net_delta_c"] < 0
    assert adjacent_spike_observation["half_mean_delta_c"] < 0
    boundary = EnvironmentGuard.require_final_trend(
        thermal_points((36.0, 36.0, 36.1, 36.1)))
    assert boundary["valid"] and boundary["tolerance_c"] == 0.1
    assert abs(boundary["net_delta_c"] - 0.1) < 1e-12
    assert abs(boundary["half_mean_delta_c"] - 0.1) < 1e-12
    invalid = EnvironmentGuard.require_final_trend(
        thermal_points((36.0, 36.0, 36.0, 36.0), invalid_index=2))
    assert not invalid["valid"] and not invalid["all_points_valid"]
    for nonfinite in (math.nan, math.inf, -math.inf):
        assessment = EnvironmentGuard.require_final_trend(
            thermal_points((36.0, 36.0, 36.0, nonfinite)))
        assert not assessment["valid"]
        assert assessment["final_four_virtual_skin_c"][-1] is None
        json.dumps(assessment, allow_nan=False)
    above_limit = EnvironmentGuard.require_final_trend(
        thermal_points((36.0, 36.0, 36.0, 37.0001)))
    assert not above_limit["valid"] and not above_limit["all_at_or_below_37c"]
    with tempfile.TemporaryDirectory(prefix="p6-guard-trend-test-") as temporary:
        trend_guard = EnvironmentGuard(Path(temporary) / "result", preflight_only=True)
        trend_guard.audit_dir.mkdir(parents=True)
        written = trend_guard.write_soak_summary(
            thermal_points((36.0, 36.0, 36.0, 36.0), invalid_index=2), invalid)
        assert not written["valid"] and written["errors"]
        persisted = json.loads((trend_guard.audit_dir / "soak-summary.json").read_text())
        for key in ("trend_rule_id", "final_four_virtual_skin_c", "adjacent_deltas",
                    "adjacent_deltas_c", "max_adjacent_rise", "max_adjacent_rise_c",
                    "adjacent_observation", "first", "last", "early_mean", "late_mean",
                    "net_delta", "half_mean_delta", "tolerance", "all_points_valid",
                    "all_at_or_below_37c", "thermal_trend_observation", "checks",
                    "valid", "errors"):
            assert key in persisted
        manifest = json.loads(
            (trend_guard.audit_dir / "sha256-manifest.json").read_text())
        assert "soak-summary.json" in manifest["files"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-dir", type=Path, help="new wrapper result directory")
    parser.add_argument("--preflight-only", action="store_true",
                        help="stop after controls, soak, and untimed preflight")
    parser.add_argument("--self-test", action="store_true", help="run device-free parser checks")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("P6 environment guard self-test: PASS")
        return 0
    if args.result_dir is None:
        parser.error("--result-dir is required unless --self-test is used")
    guard = EnvironmentGuard(args.result_dir.resolve(), args.preflight_only)
    shutdown: dict[str, int | None] = {"signum": None}

    def handle_signal(signum: int, _frame: object) -> None:
        if guard.restoring or shutdown["signum"] is not None:
            return
        shutdown["signum"] = signum
        raise ShutdownRequested(signum)

    previous = {sig: signal.getsignal(sig) for sig in MANAGED_SIGNALS}
    for sig in MANAGED_SIGNALS:
        signal.signal(sig, handle_signal)
    try:
        return guard.run()
    except ShutdownRequested as error:
        print(f"P6 environment guard interrupted: {error}", file=sys.stderr)
        return 128 + error.signum
    except Exception as error:
        print(f"P6 environment guard failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    finally:
        # Restoration happens inside guard.run().  Restore host handlers only after it
        # has completed so a second termination request cannot bypass device cleanup.
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
