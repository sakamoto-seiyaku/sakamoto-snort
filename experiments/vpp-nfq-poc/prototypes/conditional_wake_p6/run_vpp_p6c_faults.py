#!/usr/bin/env python3
"""Drive isolated build-tree VPP P6c runtime correctness campaigns.

This is a correctness/fault driver, not a performance benchmark. Every case
gets a fresh VPP process and evidence directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

DEFAULT_SEED = 0x5A4B20260802
CLI_TIMEOUT = 5.0
START_TIMEOUT = 10.0
TERMINAL_TIMEOUT = 10.0
SETTLE_TIMEOUT = 10.0
POLL_SECONDS = 0.20


class CampaignFailure(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def key_values(line: str, *, skip_first: bool) -> dict[str, int | float | str]:
    result: dict[str, int | float | str] = {}
    tokens = line.split()
    index = 1 if skip_first else 0
    while index + 1 < len(tokens):
        key, raw = tokens[index], tokens[index + 1]
        if key == "available":
            index += 1
            continue
        if re.fullmatch(r"[a-z][a-z0-9-]*", key):
            try:
                value: int | float | str = int(raw, 0)
            except ValueError:
                try:
                    value = float(raw)
                except ValueError:
                    value = raw
            result[key] = value
            index += 2
        else:
            index += 1
    return result


def parse_show(output: str) -> dict[str, dict[str, int | float | str]]:
    prefixes = {
        "running ": "config",
        "generated ": "ledger",
        "wake-diagnostics ": "wake_diagnostics",
        "wake-state ": "wake_state",
        "wake-injection ": "wake_injection",
    }
    parsed: dict[str, dict[str, int | float | str]] = {}
    for line in output.splitlines():
        stripped = line.strip()
        for prefix, name in prefixes.items():
            if stripped.startswith(prefix):
                parsed[name] = key_values(
                    stripped,
                    skip_first=name in {"wake_diagnostics", "wake_state", "wake_injection"},
                )
                break
    missing = {"config", "ledger", "wake_diagnostics", "wake_state"} - parsed.keys()
    if missing:
        raise CampaignFailure(f"show handoff-perf missing sections: {sorted(missing)}")
    return parsed


def integer(section: dict[str, int | float | str], key: str) -> int:
    value = section.get(key)
    if not isinstance(value, int):
        raise CampaignFailure(f"missing/non-integer counter {key}: {value!r}")
    return value


@dataclass(frozen=True)
class BuildArtifacts:
    build_dir: Path
    vpp: Path
    vppctl: Path
    plugin: Path
    plugin_dir: Path
    library_dir: Path

    @classmethod
    def discover(cls, build_dir: Path) -> "BuildArtifacts":
        root = build_dir.resolve()
        vpp = root / "bin" / "vpp"
        vppctl = root / "bin" / "vppctl"
        plugins = sorted(root.glob("lib/*/vpp_plugins/handoff_perf_poc_plugin.so"))
        if not vpp.is_file() or not os.access(vpp, os.X_OK):
            raise CampaignFailure(f"missing executable: {vpp}")
        if not vppctl.is_file() or not os.access(vppctl, os.X_OK):
            raise CampaignFailure(f"missing executable: {vppctl}")
        if len(plugins) != 1:
            raise CampaignFailure(f"expected one handoff plugin, found {len(plugins)}: {plugins}")
        plugin = plugins[0]
        return cls(root, vpp, vppctl, plugin, plugin.parent, plugin.parent.parent)


class VppCase:
    def __init__(self, name: str, case_dir: Path, artifacts: BuildArtifacts, seed: int):
        self.name = name
        self.case_dir = case_dir
        self.artifacts = artifacts
        self.seed = seed
        self.runtime = case_dir / "runtime"
        self.cli_socket = self.runtime / "cli.sock"
        self.startup = case_dir / "startup.conf"
        self.stdout_path = case_dir / "stdout.log"
        self.vpp_log = case_dir / "vpp.log"
        self.transcript: list[dict[str, object]] = []
        self.command_index = 0
        self.process: subprocess.Popen[str] | None = None
        self.stdout_stream: Any = None
        self.started_at = 0.0
        self.exit_reason = "not-started"

    def write_startup(self) -> None:
        self.runtime.mkdir()
        api_prefix = re.sub(r"[^a-zA-Z0-9-]", "-", f"p6c-{self.name}")
        self.startup.write_text(
            f"""unix {{
  nodaemon
  nobanner
  runtime-dir {self.runtime}
  log {self.vpp_log}
  cli-listen {self.cli_socket}
}}
cpu {{ main-core 0 corelist-workers 1 }}
api-segment {{ prefix {api_prefix} }}
statseg {{ socket-name {self.runtime / 'statseg.sock'} }}
buffers {{ page-size default }}
plugins {{
  path {self.artifacts.plugin_dir}
  plugin default {{ disable }}
  plugin handoff_perf_poc_plugin.so {{ enable }}
}}
""",
            encoding="utf-8",
        )

    def manifest(self) -> dict[str, object]:
        files = (self.artifacts.vpp, self.artifacts.vppctl, self.artifacts.plugin, self.startup,
                 Path(__file__).resolve())
        return {
            "case": self.name,
            "seed": f"0x{self.seed:x}",
            "files": {str(path): {"size": path.stat().st_size, "sha256": sha256(path)}
                      for path in files},
        }

    def start(self) -> None:
        self.write_startup()
        atomic_json(self.case_dir / "manifest.json", self.manifest())
        environment = os.environ.copy()
        old_path = environment.get("LD_LIBRARY_PATH", "")
        environment["LD_LIBRARY_PATH"] = str(self.artifacts.library_dir) + (
            f":{old_path}" if old_path else ""
        )
        self.stdout_stream = self.stdout_path.open("w", encoding="utf-8")
        self.started_at = time.monotonic()
        self.process = subprocess.Popen(
            [str(self.artifacts.vpp), "-c", str(self.startup)],
            cwd=self.artifacts.build_dir,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.stdout_stream,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + START_TIMEOUT
        last_error = "CLI socket not ready"
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise CampaignFailure(f"VPP exited during startup rc={self.process.returncode}")
            if self.cli_socket.exists():
                try:
                    self.cli("show version", label="startup-show-version")
                    self.cli("show plugins", label="startup-show-plugins")
                    return
                except CampaignFailure as error:
                    last_error = str(error)
            time.sleep(POLL_SECONDS)
        raise CampaignFailure(f"VPP startup timeout: {last_error}")

    def cli(self, command: str, *, label: str | None = None, allow_dead: bool = False) -> str:
        if self.process is None:
            raise CampaignFailure("VPP is not started")
        if self.process.poll() is not None and not allow_dead:
            raise CampaignFailure(f"VPP exited rc={self.process.returncode} before CLI: {command}")
        self.command_index += 1
        slug = re.sub(r"[^a-z0-9]+", "-", (label or command).lower()).strip("-")[:80]
        output_path = self.case_dir / f"cli-{self.command_index:03d}-{slug}.txt"
        started = time.monotonic()
        try:
            completed = subprocess.run(
                [str(self.artifacts.vppctl), "-s", str(self.cli_socket), *shlex.split(command)],
                cwd=self.artifacts.build_dir,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=CLI_TIMEOUT,
                check=False,
            )
            output = completed.stdout.replace("\r", "")
        except subprocess.TimeoutExpired as error:
            output = (error.stdout or "") if isinstance(error.stdout, str) else ""
            output += f"\nTIMEOUT after {CLI_TIMEOUT}s\n"
            output_path.write_text(output, encoding="utf-8")
            raise CampaignFailure(f"CLI timeout: {command}") from error
        output_path.write_text(output, encoding="utf-8")
        record = {
            "index": self.command_index,
            "command": command,
            "returncode": completed.returncode,
            "duration_seconds": time.monotonic() - started,
            "output": output_path.name,
        }
        self.transcript.append(record)
        atomic_json(self.case_dir / "cli-transcript.json", self.transcript)
        if completed.returncode != 0 or "%Error" in output:
            raise CampaignFailure(
                f"CLI failed rc={completed.returncode} command={command!r}: {output.strip()}"
            )
        return output

    def show(self, label: str) -> dict[str, dict[str, int | float | str]]:
        return parse_show(self.cli("show handoff-perf", label=label))

    def wait_until(self, description: str, timeout: float,
                   predicate: Callable[[dict[str, dict[str, int | float | str]]], bool]) \
            -> dict[str, dict[str, int | float | str]]:
        deadline = time.monotonic() + timeout
        last: dict[str, dict[str, int | float | str]] | None = None
        while time.monotonic() < deadline:
            if self.process is None or self.process.poll() is not None:
                code = None if self.process is None else self.process.returncode
                raise CampaignFailure(f"VPP exited rc={code} while waiting for {description}")
            last = self.show(f"poll-{description}")
            if predicate(last):
                return last
            time.sleep(POLL_SECONDS)
        raise CampaignFailure(f"timeout waiting for {description}; last={last}")

    def wait_exit(self, timeout: float) -> tuple[int, float]:
        if self.process is None:
            raise CampaignFailure("VPP not started")
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise CampaignFailure(f"VPP did not exit within {timeout}s") from error
        self.exit_reason = "self-exit"
        return code, time.monotonic() - self.started_at

    def terminate(self) -> int | None:
        if self.process is None:
            return None
        if self.process.poll() is None:
            self.exit_reason = "term"
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.exit_reason = "kill"
                self.process.kill()
                self.process.wait(timeout=2.0)
        return self.process.returncode

    def close(self) -> None:
        if self.stdout_stream is not None:
            self.stdout_stream.flush()
            self.stdout_stream.close()
            self.stdout_stream = None


def start_command(seed: int, *, burst: int = 1, rate: int = 1) -> str:
    return (
        "handoff-perf start mode handoff-one distribution hot "
        f"burst {burst} packet-size 64 sample-rate 1 seed {seed} "
        f"tokens 64 rate {rate} wake-workers 2"
    )


def assert_zero_fault(parsed: dict[str, dict[str, int | float | str]]) -> None:
    state = parsed["wake_state"]
    if integer(state, "faults") != 0 or integer(state, "fault-code") != 0:
        raise CampaignFailure(f"wake fault present: {state}")
    residue_keys = ("preparing", "sleeping", "notified", "draining", "notifying")
    residue = {key: integer(state, key) for key in residue_keys if integer(state, key) != 0}
    if residue:
        raise CampaignFailure(f"wake-state residue: {residue}")


def assert_closed_ledger(parsed: dict[str, dict[str, int | float | str]], *, positive: bool) -> None:
    ledger = parsed["ledger"]
    generated = integer(ledger, "generated")
    values = {
        "generated": generated,
        "ingress-enqueued": integer(ledger, "ingress-enqueued"),
        "terminal": integer(ledger, "terminal"),
        "reclaimed": integer(ledger, "reclaimed"),
    }
    if len(set(values.values())) != 1 or (positive and generated <= 0):
        raise CampaignFailure(f"ledger not closed: {values}")
    zero_keys = ("ingress-drops", "alloc-errors", "return-drops", "reclaim-overflows",
                 "clock-anomalies", "outstanding-packets")
    nonzero = {key: integer(ledger, key) for key in zero_keys if integer(ledger, key) != 0}
    if nonzero:
        raise CampaignFailure(f"ledger errors/debt/residue: {nonzero}")
    config = parsed["config"]
    if integer(config, "tokens-live") != 0 or integer(config, "tokens-available") != 0:
        raise CampaignFailure(f"token residue after cleanup: {config}")


def assert_wake_mapping(parsed: dict[str, dict[str, int | float | str]]) -> None:
    wake = parsed["wake_diagnostics"]
    writes = integer(wake, "writes")
    sleeps = integer(wake, "sleeps-seen")
    claims = integer(wake, "pending-claims")
    if writes > sleeps or writes > claims:
        raise CampaignFailure(f"notification mapping invalid: writes={writes} sleeps={sleeps} claims={claims}")
    if integer(wake, "write-errors") != 0:
        raise CampaignFailure(f"unexpected write errors: {wake}")


def stop_settle_cleanup(case: VppCase) -> dict[str, dict[str, int | float | str]]:
    case.cli("handoff-perf stop", label="stop")
    case.wait_until(
        "outstanding-zero", SETTLE_TIMEOUT,
        lambda value: integer(value["ledger"], "outstanding-packets") == 0,
    )
    case.cli("handoff-perf cleanup", label="cleanup")
    return case.show("final-after-cleanup")


def configure_fault(case: VppCase, outcome: str, count: int) -> None:
    case.cli(f"handoff-perf wake-fault thread 1 {outcome} count {count}",
             label=f"configure-{outcome}-{count}")
    configured = case.show("show-after-fault-config")
    injection = configured.get("wake_injection", {})
    expected_outcomes = {"success": 1, "eintr": 2, "eagain": 3, "ebadf": 4,
                         "einval": 5, "short": 6}
    if integer(injection, "thread") != 1 or integer(injection, "outcome") != expected_outcomes[outcome] \
            or integer(injection, "remaining") != count:
        raise CampaignFailure(f"fault plan mismatch: {injection}")


def run_recoverable(case: VppCase, outcome: str, count: int) -> dict[str, object]:
    configure_fault(case, outcome, count)
    case.cli(start_command(case.seed), label="start")
    deadline = time.monotonic() + SETTLE_TIMEOUT
    observed: dict[str, dict[str, int | float | str]] | None = None
    while time.monotonic() < deadline:
        # A CLI show takes the worker barrier, and VPP deliberately avoids
        # sleeping for 0.5 s after a barrier release. Leave a longer quiet
        # window before each observation so the 1 pps publish can encounter a
        # genuinely SLEEPING target and consume the configured plan.
        time.sleep(1.2)
        observed = case.show("poll-plan-consumed-and-packet")
        if (integer(observed.get("wake_injection", {}), "remaining") == 0
                and integer(observed["ledger"], "generated") >= 1):
            break
    else:
        raise CampaignFailure(
            f"timeout waiting for plan-consumed-and-packet; last={observed}"
        )
    final = stop_settle_cleanup(case)
    assert_zero_fault(final)
    assert_closed_ledger(final, positive=True)
    assert_wake_mapping(final)
    wake = final["wake_diagnostics"]
    if outcome == "success" and integer(wake, "writes") < 1:
        raise CampaignFailure("success injection produced no notification write")
    if outcome == "eintr":
        minimum = 1 if count == 1 else 2
        if integer(final["wake_state"], "write-retries") < minimum or integer(wake, "writes") < 1:
            raise CampaignFailure(f"EINTR retry evidence too small: {final}")
    if outcome == "eagain" and integer(final["wake_state"], "write-eagain") < 1:
        raise CampaignFailure("EAGAIN injection was not observed")
    return {"final": final}


def run_terminal(case: VppCase, outcome: str, count: int) -> dict[str, object]:
    configure_fault(case, outcome, count)
    case.cli(start_command(case.seed), label="start")
    code, duration = case.wait_exit(TERMINAL_TIMEOUT)
    if code != 86:
        raise CampaignFailure(f"terminal fault exited rc={code}, expected 86")
    return {
        "exit_code": code,
        "exit_seconds": duration,
        "bounded_teardown_note": (
            "Process exit 86 is bounded teardown/destruction evidence. Claim retirement and stable "
            "fault are established jointly by the bounded model/static mapping; no post-exit zero "
            "counter claim is made."
        ),
    }


def run_coalescing(case: VppCase) -> dict[str, object]:
    case.cli(start_command(case.seed, burst=64, rate=64), label="start")
    time.sleep(3.0)
    final = stop_settle_cleanup(case)
    assert_zero_fault(final)
    assert_closed_ledger(final, positive=True)
    assert_wake_mapping(final)
    wake = final["wake_diagnostics"]
    writes = integer(wake, "writes")
    generated = integer(final["ledger"], "generated")
    if writes <= 0 or writes >= generated:
        raise CampaignFailure(f"burst did not coalesce: writes={writes} generated={generated}")
    return {"trigger_seconds": 3.0, "final": final}


def run_sustained_awake(case: VppCase) -> dict[str, object]:
    case.cli(start_command(case.seed, burst=64, rate=100000), label="warmup-start")
    time.sleep(1.0)
    case.cli("handoff-perf stop", label="warmup-stop")
    case.wait_until("warmup-outstanding-zero", SETTLE_TIMEOUT,
                    lambda value: integer(value["ledger"], "outstanding-packets") == 0)
    case.cli("handoff-perf resume", label="measured-resume")
    time.sleep(1.0)
    final = stop_settle_cleanup(case)
    assert_zero_fault(final)
    assert_closed_ledger(final, positive=True)
    assert_wake_mapping(final)
    return {"warmup_seconds": 1.0, "trigger_seconds": 1.0, "final": final}


def run_barrier_spurious(case: VppCase) -> dict[str, object]:
    observations = []
    for mode in (2, 3, 2, 0):
        case.cli(f"handoff-perf wake-mode {mode}", label=f"wake-mode-{mode}")
        parsed = case.show(f"show-after-mode-{mode}")
        assert_zero_fault(parsed)
        assert_closed_ledger(parsed, positive=False)
        observations.append({"mode": mode, "show": parsed})
    return {"observations": observations}


CASE_SPECS: tuple[tuple[str, Callable[[VppCase], dict[str, object]]], ...] = (
    ("recover-success-1", lambda case: run_recoverable(case, "success", 1)),
    ("recover-eintr-1", lambda case: run_recoverable(case, "eintr", 1)),
    ("recover-eintr-2", lambda case: run_recoverable(case, "eintr", 2)),
    ("recover-eagain-1", lambda case: run_recoverable(case, "eagain", 1)),
    ("terminal-eintr-3", lambda case: run_terminal(case, "eintr", 3)),
    ("terminal-ebadf-1", lambda case: run_terminal(case, "ebadf", 1)),
    ("terminal-einval-1", lambda case: run_terminal(case, "einval", 1)),
    ("terminal-short-1", lambda case: run_terminal(case, "short", 1)),
    ("burst-coalescing", run_coalescing),
    ("sustained-awake", run_sustained_awake),
    ("spurious-barrier-no-work", run_barrier_spurious),
)


def run_case(name: str, function: Callable[[VppCase], dict[str, object]], root: Path,
             artifacts: BuildArtifacts, seed: int) -> dict[str, object]:
    case_dir = root / name
    case_dir.mkdir()
    case = VppCase(name, case_dir, artifacts, seed)
    started = time.monotonic()
    result: dict[str, object] = {"name": name, "status": "FAIL", "seed": f"0x{seed:x}"}
    try:
        case.start()
        evidence = function(case)
        if case.process is not None and case.process.poll() is None:
            code = case.terminate()
            if code != 0:
                raise CampaignFailure(f"VPP TERM exit rc={code}, expected 0")
        result.update(status="PASS", evidence=evidence)
    except Exception as error:  # Preserve every case's evidence and continue the campaign.
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        exit_code = case.terminate()
        case.close()
        result.update(
            duration_seconds=time.monotonic() - started,
            process_exit_code=exit_code,
            process_exit_reason=case.exit_reason,
            stdout=case.stdout_path.name,
            vpp_log=case.vpp_log.name,
            startup=case.startup.name,
            cli_transcript="cli-transcript.json",
            manifest="manifest.json",
        )
        atomic_json(case_dir / "case.json", result)
    return result


def summary_markdown(summary: dict[str, object]) -> str:
    lines = ["# P6c VPP runtime correctness campaign", "", "This is correctness-path evidence, not performance data.", "",
             "| Case | Status | Exit | Duration (s) |", "|---|---:|---:|---:|"]
    for case in summary["cases"]:  # type: ignore[index]
        assert isinstance(case, dict)
        lines.append(f"| {case['name']} | {case['status']} | {case.get('process_exit_code')} | "
                     f"{float(case['duration_seconds']):.3f} |")
    lines.extend(["", f"Overall: **{summary['status']}**", ""])
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--result-dir", required=True, type=Path)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=DEFAULT_SEED)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.result_dir.exists():
        print(f"result directory must not exist: {args.result_dir}", file=sys.stderr)
        return 2
    try:
        artifacts = BuildArtifacts.discover(args.build_dir)
    except CampaignFailure as error:
        print(error, file=sys.stderr)
        return 2
    args.result_dir.mkdir(parents=True)
    results = []
    for name, function in CASE_SPECS:
        print(f"P6c runtime {name}: RUN", flush=True)
        result = run_case(name, function, args.result_dir, artifacts, args.seed)
        results.append(result)
        print(f"P6c runtime {name}: {result['status']}", flush=True)
    passed = all(result["status"] == "PASS" for result in results)
    summary = {
        "schema": "p6c-vpp-runtime-v1",
        "status": "PASS" if passed else "FAIL",
        "correctness_only": True,
        "seed": f"0x{args.seed:x}",
        "build_dir": str(artifacts.build_dir),
        "result_dir": str(args.result_dir.resolve()),
        "cases": results,
    }
    atomic_json(args.result_dir / "summary.json", summary)
    (args.result_dir / "summary.md").write_text(summary_markdown(summary), encoding="utf-8")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
