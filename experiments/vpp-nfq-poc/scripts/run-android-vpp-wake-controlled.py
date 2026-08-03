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
COOLING_INTERVAL_SECONDS = 5 * 60
MAX_COOLING_SECONDS = 2 * 60 * 60
SKIN_MAX_C = 37.0
AGGREGATE_IDLE_MIN_PERCENT = 790.0
PROCESS_CPU_MAX_PERCENT = 5.0
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
        uid = re.search(r"(?m)^    userId=([0-9]+)\s*$", package.group(0))
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
        text = self.output(
            "for p in /proc/[0-9]*; do [ -r \"$p/status\" ] || continue; "
            "pid=${p##*/}; uid=$(awk '/^Uid:/{print $2; exit}' \"$p/status\" 2>/dev/null); "
            "comm=$(cat \"$p/comm\" 2>/dev/null | tr '\\t\\n' '  '); "
            "cmd=$(tr '\\000\\t\\n' '   ' <\"$p/cmdline\" 2>/dev/null); "
            "printf 'PID=%s\\tUID=%s\\tCOMM=%s\\tCMD=%s\\n' \"$pid\" \"$uid\" \"$comm\" \"$cmd\"; done")
        return self.parse_device_processes(text)

    @staticmethod
    def parse_device_processes(text: str) -> list[dict[str, Any]]:
        processes: list[dict[str, Any]] = []
        for line in text.splitlines():
            match = re.match(
                r"PID=([0-9]+)\tUID=([0-9]+)\tCOMM=([^\t]*)\tCMD=(.*)", line)
            if match:
                processes.append({"pid": int(match.group(1)), "uid": int(match.group(2)),
                                  "comm": match.group(3), "cmdline": match.group(4)})
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
        cooling = {name: int(value) for value, name in re.findall(
            r"CoolingDevice\{mValue=([0-9]+),[^}]*mName=([^,}]+)", text)
                   if name.startswith("thermal-cpufreq-")}
        if not cooling:
            raise GuardError("CPU thermal cooling-device states unavailable")
        skin_matches = re.findall(
            r"Temperature\{mValue=([0-9]+(?:\.[0-9]+)?),[^}]*mName=VIRTUAL-SKIN(?:-[^,}]*)?",
            text, re.I)
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
    def parse_process_stats(text: str) -> dict[int, tuple[int, str, str]]:
        result: dict[int, tuple[int, str, str]] = {}
        for line in text.splitlines():
            match = re.match(r"PID=([0-9]+)\tTICKS=([0-9]+)\tCOMM=([^\t]*)\tCMD=(.*)", line)
            if match:
                result[int(match.group(1))] = (
                    int(match.group(2)), match.group(3), match.group(4))
        return result

    def cpu_window(self) -> dict[str, Any]:
        proc_command = (
            "cat /proc/stat; echo __PROCESSES__; hz=$(getconf CLK_TCK); echo CLK_TCK=$hz; "
            "for p in /proc/[0-9]*; do [ -r \"$p/stat\" ] || continue; "
            "pid=${p##*/}; s=$(cat \"$p/stat\" 2>/dev/null) || continue; "
            "rest=${s#*) }; set -- $rest; ticks=$(($12+$13)); "
            "comm=$(cat \"$p/comm\" 2>/dev/null | tr '\\t\\n' '  '); "
            "cmd=$(tr '\\000\\t\\n' '   ' <\"$p/cmdline\" 2>/dev/null); "
            "printf 'PID=%s\\tTICKS=%s\\tCOMM=%s\\tCMD=%s\\n' \"$pid\" \"$ticks\" \"$comm\" \"$cmd\"; done")
        before_text = self.output(proc_command)
        before_mono = time.monotonic()
        time.sleep(CPU_SAMPLE_SECONDS)
        after_text = self.output(proc_command)
        elapsed = time.monotonic() - before_mono
        before_cpu = self.parse_proc_stat(before_text.split("__PROCESSES__", 1)[0])
        after_cpu = self.parse_proc_stat(after_text.split("__PROCESSES__", 1)[0])
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
        hz_match = re.search(r"CLK_TCK=([0-9]+)", before_text)
        if not hz_match:
            raise GuardError("CLK_TCK unavailable")
        hz = int(hz_match.group(1))
        before_process = self.parse_process_stats(before_text)
        after_process = self.parse_process_stats(after_text)
        busy: list[dict[str, Any]] = []
        for pid in sorted(set(before_process) & set(after_process)):
            delta = after_process[pid][0] - before_process[pid][0]
            percent = 100.0 * delta / hz / elapsed
            comm, cmdline = after_process[pid][1:]
            is_test = ("/data/local/tmp/vpp-p6/" in cmdline
                       or comm == "vpp" or comm.startswith("vpp_"))
            if percent > PROCESS_CPU_MAX_PERCENT and not is_test:
                busy.append({"pid": pid, "comm": comm, "cmdline": cmdline,
                             "single_core_percent": percent})
        return {"sample_seconds": elapsed, "per_cpu_idle_percent": idle_fractions,
                "aggregate_idle_percent_of_800": sum(idle_fractions.values()),
                "non_test_processes_over_5_percent": busy}

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
            if cpu["aggregate_idle_percent_of_800"] < AGGREGATE_IDLE_MIN_PERCENT:
                errors.append(f"aggregate-idle={cpu['aggregate_idle_percent_of_800']:.3f}<790")
            if cpu["non_test_processes_over_5_percent"]:
                errors.append("non-test-process-over-5-percent")
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
    def require_final_trend(points: list[dict[str, Any]]) -> None:
        if len(points) < 4:
            raise GuardError("fewer than four readiness points in final 15-minute window")
        final = points[-4:]
        errors = [f"{point['label']}:{point['errors']}" for point in final if not point["valid"]]
        temperatures = [float(point["virtual_skin_c"]) for point in final]
        if any(later > earlier for earlier, later in zip(temperatures, temperatures[1:])):
            errors.append(f"VIRTUAL-SKIN final trend is rising: {temperatures}")
        if errors:
            raise GuardError("readiness gate failed: " + "; ".join(errors))

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
        self.require_final_trend(points)
        write_json(self.audit_dir / "soak-summary.json", {
            "started_utc": points[0]["timestamp_utc"],
            "finished_utc": points[-1]["timestamp_utc"], "points": points,
            "final_four_virtual_skin_c": [point["virtual_skin_c"] for point in points[-4:]],
            "valid": True})
        self.write_manifest()
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
        if float(after["virtual_skin_c"]) > float(before["virtual_skin_c"]):
            cooling_deadline = time.monotonic() + MAX_COOLING_SECONDS
            previous = after
            index = 1
            while True:
                if time.monotonic() >= cooling_deadline:
                    raise GuardError("post-preflight cooling did not reach a flat/falling <=37C point")
                time.sleep(COOLING_INTERVAL_SECONDS)
                current = self.readiness_snapshot(f"preflight-after-{index:02d}")
                if current["valid"] and float(current["virtual_skin_c"]) <= float(previous["virtual_skin_c"]):
                    after = current
                    break
                previous = current
                index += 1
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
    processes = "PID=12\tTICKS=99\tCOMM=thing\tCMD=/system/bin/thing --x\n"
    assert EnvironmentGuard.parse_process_stats(processes) == {
        12: (99, "thing", "/system/bin/thing --x")}
    thermal = ("Thermal Status: 0\n"
               "CoolingDevice{mValue=0, mType=2, mName=thermal-cpufreq-0}\n"
               "Temperature{mValue=36.5, mType=3, mName=VIRTUAL-SKIN, mStatus=0}\n")
    assert EnvironmentGuard.parse_thermal(thermal) == (
        0, {"thermal-cpufreq-0": 0}, 36.5)
    packages = ("  Package [com.android.vending] (current):\n"
                "    userId=10123\n"
                "    versionName=52\n"
                "    User 0: installed=true enabled=1 stopped=true\n"
                "  Package [com.android.vending] (disabled-system):\n"
                "    versionName=46\n"
                "    User 0: installed=true enabled=0 stopped=false\n")
    assert EnvironmentGuard.parse_vending_state(packages) == 1
    assert EnvironmentGuard.parse_vending_uid(packages) == 10123
    device_processes = (
        "PID=12\tUID=10123\tCOMM=process\tCMD=com.android.vending:background\n"
        "PID=13\tUID=0\tCOMM=dex2oat64\tCMD=dex2oat64 --zip-fd=4\n")
    assert EnvironmentGuard.parse_device_processes(device_processes) == [
        {"pid": 12, "uid": 10123, "comm": "process",
         "cmdline": "com.android.vending:background"},
        {"pid": 13, "uid": 0, "comm": "dex2oat64",
         "cmdline": "dex2oat64 --zip-fd=4"},
    ]
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
    good = [{"label": str(index), "valid": True, "errors": [], "virtual_skin_c": value}
            for index, value in enumerate((37.0, 36.9, 36.9, 36.8))]
    EnvironmentGuard.require_final_trend(good)
    try:
        EnvironmentGuard.require_final_trend([
            *good[:3], {"label": "3", "valid": True, "errors": [], "virtual_skin_c": 37.0}])
    except GuardError:
        pass
    else:
        raise AssertionError("rising final thermal point must fail")


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
