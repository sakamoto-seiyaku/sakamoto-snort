#!/usr/bin/env python3
"""Parse S125/POC-7 raw cells and produce validity/attribution summaries.

The parser is deliberately conservative: correctness, timing attribution,
resource evidence, and simpleperf evidence are reported separately.  Missing
evidence never becomes a zero and never silently turns into a copy decision.
"""

import argparse
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path


REQUIRED_REPEATS = 3


NUMBER = re.compile(r"^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$")


def scalar(value):
    if value in ("true", "false"):
        return value == "true"
    if NUMBER.match(value):
        return float(value) if any(c in value for c in ".eE") else int(value)
    return value


def kv_line(line):
    parts = line.strip().split()
    out = {}
    start = 1
    if len(parts) > 1 and NUMBER.match(parts[1]):
        out["__id"] = int(float(parts[1]))
        start = 2
    for token in parts[start:]:
        if "=" in token:
            key, value = token.split("=", 1)
            out[key] = scalar(value)
    for i in range(start, len(parts) - 1, 2):
        key, value = parts[i], parts[i + 1]
        if "=" in key:
            continue
        out[key] = scalar(value)
    return out


def read_text(path):
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def parse_cli_status(path):
    samples = []
    errors = []
    current = None
    previous_mono = None
    for raw in read_text(path).splitlines():
        marker = re.match(r"# cli_monotonic_ns=(\d+)", raw)
        if marker:
            mono = int(marker.group(1))
            if previous_mono is not None and mono <= previous_mono:
                errors.append("cli-monotonic-not-increasing")
            previous_mono = mono
            if current and "stage" in current:
                samples.append(current)
            current = {"mono": mono, "owners": {}}
            continue
        if current is None:
            continue
        if raw.startswith("s124-vpn-tun-stage "):
            current["stage"] = kv_line(raw)
        elif raw.startswith("s124-vpn-tun-output "):
            current["output"] = kv_line(raw)
        elif raw.startswith("s124-vpn-tun-memcpy "):
            current["memcpy"] = kv_line(raw)
        elif raw.startswith("s124-owner "):
            values = kv_line(raw)
            owner = str(values.pop("__id", len(current["owners"])))
            current["owners"].setdefault(owner, {})["owner"] = values
        elif raw.startswith("s124-owner-perf "):
            values = kv_line(raw)
            owner = str(values.pop("__id", len(current["owners"])))
            current["owners"].setdefault(owner, {})["perf"] = values
        elif raw.startswith("s124-owner-runtime "):
            values = kv_line(raw)
            owner = str(values.pop("__id", len(current["owners"])))
            current["owners"].setdefault(owner, {})["runtime"] = values
        elif raw.startswith("s124-owner-lwip "):
            values = kv_line(raw)
            owner = str(values.pop("__id", len(current["owners"])))
            current["owners"].setdefault(owner, {})["lwip"] = values
    if current and "stage" in current:
        samples.append(current)
    if not samples:
        errors.append("no-cli-samples")
    return samples, sorted(set(errors))


def parse_cli(path):
    """Compatibility wrapper used by the golden test and ad-hoc probes."""
    return parse_cli_status(path)[0]


def parse_app(path):
    result = {"done": None, "fail": None, "phase": {}, "flows": [], "runId": None}
    for raw in read_text(path).splitlines():
        if re.search(r"\bphase\b", raw):
            for key in ("setup-start-nanos", "setup-end-nanos",
                        "warmup-start-nanos", "steady-start-nanos",
                        "steady-end-nanos", "drain-end-nanos"):
                match = re.search(r"%s=(\d+)" % re.escape(key), raw)
                if match:
                    result["phase"][key] = int(match.group(1))
        run_match = re.search(r"\bstart .*\brunId=(\d+)", raw)
        if run_match:
            result["runId"] = int(run_match.group(1))
            result["phase"] = {}
            result["flows"] = []
            result["done"] = None
            result["fail"] = None
        if " flow=" in " " + raw:
            flow = kv_line("x " + raw.split(" flow=", 1)[1])
            if "__id" in flow:
                flow["flow"] = flow.pop("__id")
            if (result["runId"] is None
                    or flow.get("runId") == result["runId"]):
                result["flows"].append(flow)
        if " done " in " " + raw:
            done = kv_line("x " + raw.split(" done ", 1)[1])
            if (result["runId"] is None
                    or done.get("runId") == result["runId"]):
                result["done"] = done
                for source, target in (("setupStartNanos", "setup-start-nanos"),
                                       ("setupEndNanos", "setup-end-nanos"),
                                       ("teardownStartNanos", "teardown-start-nanos"),
                                       ("teardownEndNanos", "teardown-end-nanos")):
                    if source in result["done"]:
                        result["phase"][target] = result["done"][source]
        if " fail " in " " + raw:
            fail = kv_line("x " + raw.split(" fail ", 1)[1])
            if (result["runId"] is None
                    or fail.get("runId") == result["runId"]):
                result["fail"] = raw
    return result


def parse_proc_stat(line):
    # /proc/stat has a parenthesized comm field that can contain spaces.
    close = line.rfind(")")
    if close < 0:
        return None
    fields = line[close + 1:].split()
    if len(fields) < 15:
        return None
    try:
        # fields[11]/fields[12] are proc stat fields 14/15 (utime/stime).
        return int(fields[11]) + int(fields[12])
    except ValueError:
        return None


def parse_resource(path):
    text = read_text(path)
    result = {"present": bool(text), "phase": None, "thermalTemps": []}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("phase="):
            result["phase"] = line.split("=", 1)[1]
        elif line.startswith("VmRSS:"):
            key = "appVmRssKb" if section == "--- app status ---" else "vppVmRssKb"
            result[key] = int(line.split()[1])
        elif line.startswith("VmHWM:"):
            key = "appVmHwmKb" if section == "--- app status ---" else "vppVmHwmKb"
            result[key] = int(line.split()[1])
        elif line.startswith("vpp_pid="):
            result["vppPid"] = line.split("=", 1)[1].split()[0]
        elif line.startswith("--- "):
            section = line
        elif section == "--- vpp stat ---" and line:
            ticks = parse_proc_stat(line)
            if ticks is not None:
                result["vppCpuTicks"] = ticks
        elif section == "--- app stat ---" and line:
            ticks = parse_proc_stat(line)
            if ticks is not None:
                result["appCpuTicks"] = ticks
        elif section in ("--- vpp status ---", "--- app status ---"):
            match = re.match(r"(voluntary_ctxt_switches|nonvoluntary_ctxt_switches):\s+(\d+)", line)
            if match:
                prefix = "app" if section == "--- app status ---" else "vpp"
                result[prefix + match.group(1).replace("_ctxt_switches", "CtxtSwitches")] = int(match.group(2))
        elif section == "--- thermal ---" and line:
            for value in re.findall(r"=(\d+)\b", line):
                result["thermalTemps"].append(int(value))
        elif line.startswith("--- thermal ---"):
            section = "--- thermal ---"
    if result["thermalTemps"]:
        result["thermalMaxMillic"] = max(result["thermalTemps"])
    result["threadCount"] = len(re.findall(r"^\d+ comm=", text, re.MULTILINE))
    result["threadSamples"] = [
        {key: scalar(value) for key, value in re.findall(r"(comm|cpu|allowed|voluntary|nonvoluntary)=([^ ]*)", line)}
        for line in text.splitlines() if re.match(r"^\d+ comm=", line)
    ]
    result["ready"] = all(key in result for key in
                           ("vppCpuTicks", "vppVmRssKb", "vppVmHwmKb",
                            "appVmRssKb", "appVmHwmKb", "appCpuTicks",
                            "thermalMaxMillic"))
    return result


def values_in_window(samples, section, field, start, end):
    values = []
    for sample in samples:
        if not (start <= sample["mono"] <= end):
            continue
        value = sample.get(section, {}).get(field)
        if isinstance(value, (int, float)):
            values.append(value)
    return values


def latest_value_in_window(samples, section, field, start, end):
    """Return the latest numeric snapshot value in a CLI window.

    Unlike cumulative counters, diagnostic fields such as the last rejected
    packet's length/version/protocol must not be delta'ed.  Keeping this
    separate also makes it explicit that the value is evidence about the
    packet, not a throughput metric.
    """
    values = values_in_window(samples, section, field, start, end)
    return values[-1] if values else None


def owner_values(samples, section, field, start, end):
    values = []
    for sample in samples:
        if not (start <= sample["mono"] <= end):
            continue
        total = 0
        found = False
        for owner in sample.get("owners", {}).values():
            value = owner.get(section, {}).get(field)
            if isinstance(value, (int, float)):
                total += value
                found = True
        if found:
            values.append(total)
    return values


def latest_owner_sections(samples, sections, start, end):
    """Return the latest per-owner identity snapshots in the steady window."""
    for sample in reversed(samples):
        if not (start <= sample["mono"] <= end):
            continue
        result = {section: [] for section in sections}
        for owner_id, owner in sample.get("owners", {}).items():
            for section in sections:
                if section in owner:
                    result[section].append({"owner": owner_id,
                                            **owner[section]})
        if any(result.values()):
            return result
    return {section: [] for section in sections}


def delta(values):
    if len(values) < 2:
        return None
    if any(right < left for left, right in zip(values, values[1:])):
        return None
    return values[-1] - values[0]


def cumulative_field_delta(samples, section, field, start, end):
    """Delta a cumulative CLI field while retaining the pre-window baseline.

    A monitor snapshot can land after a phase boundary and already include
    packets processed just before that snapshot.  Taking first-in-window as
    the baseline silently loses those packets (notably TCP SYN/SYN-ACK during
    setup).  Use the last sample before the window as the baseline instead.
    """
    if start is None or end is None or end < start:
        return None
    before = []
    after = []
    for sample in samples:
        value = sample.get(section, {}).get(field)
        if not isinstance(value, (int, float)):
            continue
        if sample["mono"] < start:
            before.append(value)
        elif sample["mono"] <= end:
            after.append(value)
    if not after:
        return None
    # If the monitor did not emit a sample before the phase boundary, the
    # first in-window snapshot is the only defensible baseline.  Falling back
    # to zero would charge setup/warmup traffic to the cell (and breaks the
    # small golden fixture); the gate window still starts at setup-start so a
    # normal run has a pre-boundary sample for packets completed just before
    # that edge.
    baseline = before[-1] if before else after[0]
    if after[-1] < baseline:
        return None
    return after[-1] - baseline


def cumulative_owner_delta(samples, section, field, start, end):
    """Cumulative delta for a field summed across owner snapshots."""
    if start is None or end is None or end < start:
        return None
    before = []
    after = []
    for sample in samples:
        total = 0
        found = False
        for owner in sample.get("owners", {}).values():
            value = owner.get(section, {}).get(field)
            if isinstance(value, (int, float)):
                total += value
                found = True
        if not found:
            continue
        if sample["mono"] < start:
            before.append(total)
        elif sample["mono"] <= end:
            after.append(total)
    if not after:
        return None
    baseline = before[-1] if before else after[0]
    if after[-1] < baseline:
        return None
    return after[-1] - baseline


def cumulative_owner_deltas(samples, section, field, start, end):
    """Return cumulative deltas per owner, preserving worker distribution."""
    if start is None or end is None or end < start:
        return None
    before = {}
    first_after = {}
    last_after = {}
    for sample in samples:
        if sample["mono"] < start:
            target = before
        elif sample["mono"] <= end:
            target = last_after
        else:
            continue
        for owner_id, owner in sample.get("owners", {}).items():
            value = owner.get(section, {}).get(field)
            if isinstance(value, (int, float)):
                if target is last_after and owner_id not in first_after:
                    first_after[owner_id] = value
                target[owner_id] = value
    if not last_after:
        return None
    result = {}
    for owner_id in set(before) | set(last_after):
        baseline = before.get(owner_id, first_after.get(owner_id, 0))
        value = last_after.get(owner_id, baseline)
        if value < baseline:
            return None
        result[owner_id] = value - baseline
    return result


def parse_simpleperf(cell):
    path = cell / "simpleperf.report"
    text = read_text(path)
    percentages = []
    copy_percent = 0.0
    copy_lines = []
    copy_terms = ("memcpy", "memmove", "clib_memcpy_fast", "tcp_write_copy",
                  "lwip_owner_tcp_copy")
    for raw in text.splitlines():
        match = re.match(r"\s*([0-9]+(?:\.[0-9]+)?)%\s+(.+)$", raw)
        if not match:
            continue
        percent = float(match.group(1))
        symbol = match.group(2)
        percentages.append(percent)
        if any(term in symbol.lower() for term in copy_terms):
            copy_percent += percent
            copy_lines.append({"percent": percent, "symbol": symbol})
    return {"present": bool(text), "copyPercent": copy_percent,
            "copyLines": copy_lines, "samplePercentTotal": sum(percentages)}


def bool_value(value):
    return value is True or value == "true" or value == 1


def parse_cell(cell):
    cell = Path(cell)
    try:
        manifest = json.loads(read_text(cell / "manifest.json"))
    except (json.JSONDecodeError, OSError):
        manifest = {}
    is_v2 = manifest.get("schema", "").endswith("/v2")
    app = parse_app(cell / "app.log")
    samples, cli_errors = parse_cli_status(cell / "vpp-show.raw")
    cli_text = read_text(cell / "vpp-show.raw")
    # ``show plugins`` proves the selected .so was discovered, while the
    # registered S124 status line proves its CLI/runtime constructor actually
    # loaded.  Either missing means the cell never exercised POC-7.
    plugin_registration_evidence = (
        "hev_external_driver_poc_plugin.so" in cli_text
        and "s124-vpn-tun-stage " in cli_text
    )
    phase = app["phase"]
    start = phase.get("steady-start-nanos")
    end = phase.get("steady-end-nanos")
    gate_start = phase.get("setup-start-nanos", start)
    gate_end = phase.get("drain-end-nanos", end)
    reasons = []
    if app["fail"]:
        reasons.append("app-fail")
    if not app["done"]:
        reasons.append("missing-app-done")
    if start is None or end is None or end <= start:
        reasons.append("missing-or-invalid-phase")
    if is_v2:
        phase_keys = ("setup-start-nanos", "setup-end-nanos",
                      "warmup-start-nanos", "steady-start-nanos",
                      "steady-end-nanos", "drain-end-nanos",
                      "teardown-start-nanos", "teardown-end-nanos")
        phase_values = [phase.get(key) for key in phase_keys]
        if any(value is None for value in phase_values):
            reasons.append("missing-setup-teardown-phase")
        elif any(right < left for left, right in zip(phase_values, phase_values[1:])):
            reasons.append("phase-order-invalid")
        if app.get("runId") is None:
            reasons.append("missing-run-id")
    if "cli-monotonic-not-increasing" in cli_errors:
        reasons.append("cli-monotonic-not-increasing")
    if is_v2 and not plugin_registration_evidence:
        reasons.append("plugin-registration-missing")
    window = [s for s in samples if start is not None and end is not None
              and start <= s["mono"] <= end]
    gate_window = [s for s in samples
                   if gate_start is not None and gate_end is not None
                   and gate_start <= s["mono"] <= gate_end]
    if len(window) < 2:
        reasons.append("insufficient-steady-samples")
    if cli_errors and cli_errors != ["no-cli-samples"]:
        reasons.extend(error for error in cli_errors if error not in reasons)

    done = app["done"] or {}
    shape_ok = (done.get("mismatches", 1) == 0
                and done.get("unexpected", 1) == 0
                and done.get("reordered", 1) == 0
                and done.get("fatalFlows", 0) == 0
                and not bool_value(done.get("executorTimeout", False)))
    expect_echo = bool(manifest.get("expectEcho", True))
    if is_v2:
        expected_flows = manifest.get("flows")
        flow_records = app.get("flows", [])
        if not isinstance(expected_flows, int) or len(flow_records) != expected_flows:
            reasons.append("flow-record-count-mismatch")
        else:
            expected_port_base = 41000 if manifest.get("protocol") == "tcp" else 40000
            observed_tcp_ports = []
            for index, flow in enumerate(flow_records):
                if manifest.get("protocol") == "tcp":
                    local_port = flow.get("localPort", 0)
                    local_port_ok = isinstance(local_port, (int, float)) \
                        and 1024 <= local_port <= 65535
                    observed_tcp_ports.append(local_port)
                else:
                    local_port_ok = flow.get("localPort") == expected_port_base + index
                if (flow.get("flow") != index
                        or not local_port_ok
                        or flow.get("runId") != app.get("runId")
                        or flow.get("sent", 0) <= 0
                        or (manifest.get("load") == "closed"
                            and flow.get("errors", 1) != 0)
                        or flow.get("mismatches", 1) != 0
                        or flow.get("unexpected", 1) != 0
                        or flow.get("reordered", 1) != 0
                        or bool_value(flow.get("fatal", False))):
                    reasons.append("flow-correctness-failure")
                    if flow.get("runId") != app.get("runId"):
                        reasons.append("flow-run-id-mismatch")
                if expect_echo and manifest.get("load") == "closed":
                    if flow.get("sent", 0) != flow.get("received", -1):
                        reasons.append("flow-closed-correctness-failure")
            if (manifest.get("protocol") == "tcp"
                    and len(set(observed_tcp_ports)) != len(observed_tcp_ports)):
                reasons.append("tcp-local-port-duplicate")
        if done and flow_records:
            if any(done.get(key, 0) != sum(flow.get(key, 0)
                                          for flow in flow_records)
                   for key in ("sent", "received", "errors", "mismatches",
                               "unexpected", "late", "reordered")):
                reasons.append("app-counter-disagreement")
    if done and expect_echo:
        if manifest.get("load") == "closed":
            if not (done.get("sent", 0) == done.get("received", -1)
                    and done.get("errors", 1) == 0 and shape_ok):
                reasons.append("closed-correctness-failure")
        else:
            if not (done.get("sent", 0) > 0
                    and done.get("received", -1) <= done.get("sent", 0)
                    and shape_ok):
                reasons.append("saturating-correctness-failure")
            if manifest.get("arm") == "full" and done.get("received", 0) <= 0:
                reasons.append("no-echo-capacity-signal")
    elif done and not expect_echo:
        if not (done.get("sent", 0) > 0 and done.get("errors", 1) == 0
                and shape_ok):
            reasons.append("ingress-control-failure")

    validity_text = read_text(cell / "validity.raw")
    for marker, reason in (("probe_timeout", "probe-timeout"),
                           ("simpleperf_timeout", "simpleperf-timeout"),
                           ("poc7_registration_missing", "plugin-registration-missing"),
                           ("raw_missing", "raw-missing"),
                           ("parser_failed", "parser-failed")):
        if marker in validity_text:
            reasons.append(reason)

    stage_timer_fields = ("tun-read-ns", "buffer-alloc-ns", "ingress-copy-ns",
                          "parse-ns", "enqueue-ns")
    stage_counter_fields = (
        "tun-read-calls", "tun-read-bytes", "tun-read-eagain", "tun-read-errors",
        "buffer-alloc-calls", "buffer-alloc-errors", "ingress-copy-bytes",
        "parse-packets", "parse-errors", "foreign-packets", "foreign-bytes",
        "tcp-input-checksum-checks", "tcp-input-checksum-errors",
        "udp-input-checksum-checks", "udp-input-checksum-errors",
        "tcp-output-checksum-checks", "tcp-output-checksum-errors",
        "udp-output-checksum-checks", "udp-output-checksum-errors",
        "tcp-input-syn-packets", "tcp-input-syn-ack-packets",
        "tcp-input-ack-packets", "tcp-input-data-packets",
        "tcp-output-syn-packets", "tcp-output-syn-ack-packets",
        "tcp-output-ack-packets", "tcp-output-data-packets",
        "enqueue-calls", "enqueue-packets", "enqueue-drops")
    stage_fields = stage_timer_fields + stage_counter_fields
    stage = {}
    for field in stage_fields:
        value = cumulative_field_delta(samples, "stage", field, start, end)
        if value is not None:
            stage[field] = value
    # Parse-error diagnostics are deliberately optional for backwards
    # compatibility with pre-diagnostic raw cells.  They are nevertheless
    # surfaced whenever present so an invalid cell can identify the packet
    # that caused the gate failure instead of merely reporting a counter.
    parse_error_bytes = cumulative_field_delta(samples, "stage",
                                               "parse-error-bytes", start, end)
    if parse_error_bytes is not None:
        stage["parse-error-bytes"] = parse_error_bytes
    for field in ("parse-error-last-len", "parse-error-last-version",
                  "parse-error-last-proto", "foreign-last-len",
                  "foreign-last-version", "foreign-last-proto",
                  "tcp-input-last-len", "tcp-input-last-src-port",
                  "tcp-input-last-dst-port", "tcp-input-last-flags",
                  "tcp-input-last-src-ip", "tcp-input-last-dst-ip",
                  "tcp-input-last-seq", "tcp-input-last-ack",
                  "tcp-input-last-ip-checksum", "tcp-input-last-tcp-checksum",
                  "tcp-output-last-len", "tcp-output-last-src-port",
                  "tcp-output-last-dst-port", "tcp-output-last-flags",
                  "tcp-output-last-src-ip", "tcp-output-last-dst-ip",
                  "tcp-output-last-seq", "tcp-output-last-ack",
                  "tcp-output-last-ip-checksum",
                  "tcp-output-last-tcp-checksum"):
        value = latest_value_in_window(samples, "stage", field,
                                       start or 0, end or 0)
        if value is not None:
            stage[field] = value
    if is_v2 and any(field not in stage for field in stage_fields):
        reasons.append("stage-evidence-missing")
    if is_v2 and any(field not in stage for field in stage_counter_fields):
        reasons.append("stage-counter-missing")

    output_fields = ("callback-calls", "pbuf-bytes", "write-calls", "write-bytes",
                     "partial-writes", "eagain", "eintr", "other-errors",
                     "output-copy-bytes")
    output = {}
    for field in output_fields:
        value = cumulative_field_delta(samples, "output", field, start, end)
        if value is not None:
            output[field] = value
    if is_v2 and manifest.get("expectEcho", True) \
            and any(field not in output for field in output_fields):
        reasons.append("output-evidence-missing")
    queue_wait = cumulative_owner_delta(samples, "owner", "queue-wait-ns",
                                        start, end)
    dequeue_to_submit = cumulative_owner_delta(samples, "owner",
                                               "dequeue-to-submit-ns",
                                               start, end)
    submit_total = cumulative_owner_delta(samples, "owner", "submit-total-ns",
                                          start, end)
    udp_echo_stack = cumulative_owner_delta(samples, "owner", "udp-echo-stack-ns",
                                            start, end)
    tcp_echo_stack = cumulative_owner_delta(samples, "owner", "tcp-echo-stack-ns",
                                            start, end)
    submit_copy = cumulative_owner_delta(samples, "perf", "submit-copy-ns",
                                         start, end)
    submit_copy_bytes = cumulative_owner_delta(samples, "perf", "submit-copy-bytes",
                                               start, end)
    udp_copy = cumulative_owner_delta(samples, "perf", "udp-copy-ns",
                                      start, end)
    udp_copy_bytes = cumulative_owner_delta(samples, "perf", "udp-copy-bytes",
                                            start, end)
    tcp_copy_ns = cumulative_owner_delta(samples, "perf", "tcp-copy-ns",
                                         start, end)
    tcp_copy_bytes = cumulative_owner_delta(samples, "perf", "tcp-copy-bytes",
                                            start, end)
    tcp_write_copy_bytes = cumulative_owner_delta(samples, "perf",
                                                  "tcp-write-bytes",
                                                  start, end)
    memcpy_ns = cumulative_field_delta(samples, "memcpy", "ns", start, end)
    memcpy_bytes = cumulative_field_delta(samples, "memcpy", "bytes", start, end)
    memcpy_packets = cumulative_field_delta(samples, "memcpy", "packets", start, end)
    memcpy_errors = cumulative_field_delta(samples, "memcpy", "errors", start, end)
    owner_packets = cumulative_owner_delta(samples, "owner", "packets",
                                           start, end)
    owner_bytes = cumulative_owner_delta(samples, "owner", "bytes",
                                         start, end)
    owner_packet_deltas = cumulative_owner_deltas(samples, "owner", "packets",
                                                  start, end)
    active_owner_ids = sorted(owner_id for owner_id, packets
                              in (owner_packet_deltas or {}).items()
                              if packets > 0)
    if is_v2 and (queue_wait is None or submit_total is None):
        reasons.append("owner-path-evidence-missing")
    # A one-flow cell is intentionally allowed to land on one worker.  Once
    # the registered multi-flow cells are used, however, workers=2 must show
    # both owner-local packet counters moving; otherwise the result is only a
    # duplicated workers=1 run with no multi-worker evidence.
    if (is_v2 and manifest.get("workers", 1) > 1
            and manifest.get("flows", 0) >= 8
            and len(active_owner_ids) < manifest.get("workers")):
        reasons.append("worker-distribution-incomplete")
    metric_flags = values_in_window(samples, "stage", "tcp-copy-metric",
                                    start or 0, end or 0)
    tcp_copy_metric = bool(metric_flags and any(metric_flags))
    identity = latest_owner_sections(samples, ("runtime", "lwip"),
                                     start or 0, end or 0)
    identity_ready = bool(identity["runtime"] and identity["lwip"])
    credit_rejects = sum(item.get("credit-rejects", 0)
                         for item in identity["runtime"])
    if is_v2 \
            and manifest.get("arm") == "full" \
            and manifest.get("observe") == "full" and not identity_ready:
        reasons.append("owner-identity-missing")
    if credit_rejects > 0:
        reasons.append("owner-credit-rejects")
    stage_complete = all(field in stage for field in stage_timer_fields)
    path_ready = (stage_complete and queue_wait is not None
                  and submit_total is not None)
    ingress_total = (sum(stage[field] for field in stage_timer_fields)
                     if stage_complete
                     else None)
    observed_copy_udp = None
    observed_copy_tcp = None
    if is_v2 and manifest.get("arm") == "full" \
            and manifest.get("observe") == "full" \
            and manifest.get("protocol") == "udp":
        if submit_copy is None or udp_copy is None:
            reasons.append("udp-copy-metric-missing")
        else:
            observed_copy_udp = stage.get("ingress-copy-ns", 0) \
                + submit_copy + udp_copy
    elif not is_v2 or manifest.get("protocol") == "udp":
        if submit_copy is not None and udp_copy is not None:
            observed_copy_udp = stage.get("ingress-copy-ns", 0) \
                + submit_copy + udp_copy
    if is_v2 and manifest.get("arm") == "full" \
            and manifest.get("observe") == "full" \
            and manifest.get("protocol") == "tcp":
        if submit_copy is None or tcp_copy_ns is None or tcp_copy_bytes is None \
                or tcp_write_copy_bytes is None:
            reasons.append("tcp-copy-metric-missing")
        else:
            observed_copy_tcp = stage.get("ingress-copy-ns", 0) \
                + submit_copy + tcp_copy_ns
    elif not is_v2 or manifest.get("protocol") == "tcp":
        if submit_copy is not None and tcp_copy_ns is not None:
            observed_copy_tcp = stage.get("ingress-copy-ns", 0) \
                + submit_copy + tcp_copy_ns
    observed_path = (ingress_total + queue_wait + submit_total
                     if ingress_total is not None and path_ready else None)
    owner_residual = None
    if submit_total is not None:
        nested = (udp_echo_stack if manifest.get("protocol") == "udp"
                  else tcp_echo_stack)
        if nested is not None:
            owner_residual = submit_total - nested
    if owner_residual is not None and owner_residual < 0:
        reasons.append("negative-owner-residual")
    resource = {name: parse_resource(cell / name)
                for name in ("resource-before.raw", "resource-steady.raw",
                             "resource-after.raw")}
    resource_ready = all(value["ready"] for value in resource.values())
    if is_v2 and not resource_ready:
        reasons.append("resource-evidence-missing")
    thermal_limit_text = read_text(cell / "thermal-limit.millic").strip()
    thermal_limit = scalar(thermal_limit_text) if thermal_limit_text else 65000
    if not isinstance(thermal_limit, (int, float)):
        reasons.append("thermal-limit-invalid")
        thermal_limit = 65000
    thermal_max = max((value.get("thermalMaxMillic", 0) for value in resource.values()),
                      default=0)
    if is_v2 and not thermal_limit_text:
        reasons.append("thermal-limit-missing")
    if thermal_limit is not None and thermal_max > thermal_limit:
        reasons.append("thermal-limit-exceeded")
    simpleperf = parse_simpleperf(cell)
    if manifest.get("simpleperfExpected"):
        if not simpleperf["present"] or simpleperf["samplePercentTotal"] <= 0:
            reasons.append("simpleperf-evidence-missing")

    # HEV submit/UDP perf counters are cumulative for every packet, while the
    # VPP stage timers are observe-filtered.  Only observe=full puts those
    # nested intervals on the same packet set.  off/sample64 remain valid
    # throughput/overhead controls, but must not enter copy attribution.
    attribution_ready = (path_ready and len(window) >= 2
                         and manifest.get("observe") == "full")
    timing_ready = attribution_ready
    if is_v2 and manifest.get("protocol") == "udp" \
            and manifest.get("arm") == "full" \
            and manifest.get("observe") == "full":
        timing_ready = timing_ready and submit_copy is not None \
            and udp_copy is not None
    if manifest.get("protocol") == "tcp" and manifest.get("arm") == "full":
        timing_ready = timing_ready and tcp_copy_metric and tcp_copy_ns is not None \
            and tcp_copy_bytes is not None and tcp_write_copy_bytes is not None
        if not tcp_copy_metric:
            reasons.append("tcp-copy-metric-missing")
    if is_v2 and stage_complete:
        if stage.get("parse-packets", 0) <= 0:
            reasons.append("no-ingress-packets")
        if stage.get("parse-errors", 0) != 0:
            reasons.append("ingress-parse-errors")
        if stage.get("foreign-packets", 0) > 0:
            # Foreign TUN input is an explicit, bounded exclusion from this
            # IPv4 target path.  It is retained in the summary; only malformed
            # target input (parse-errors) invalidates the cell.
            if any(field not in stage for field in
                   ("foreign-last-len", "foreign-last-version",
                    "foreign-last-proto")):
                reasons.append("foreign-diagnostic-missing")
        if stage.get("buffer-alloc-errors", 0) != 0:
            reasons.append("buffer-allocation-errors")
        # Queue drops are a correctness failure for closed cells and for the
        # fire-and-count controls: those cells must measure a lossless path.
        # Saturating echo arms intentionally expose capacity loss, so retain
        # the drop count in the summary instead of invalidating the cell; app
        # loss rate and output counters remain visible for interpretation.
        if (stage.get("enqueue-drops", 0) != 0
                and (manifest.get("load") == "closed"
                     or not manifest.get("expectEcho", True))):
            reasons.append("enqueue-drops")
        if stage.get("parse-packets", 0) < stage.get("enqueue-packets", 0):
            reasons.append("enqueue-exceeds-parse")
        # ``observe=off`` is an intentional overhead control: it disables
        # per-packet stage timing/copy attribution, so its ingress-copy byte
        # counter is expected to remain zero.  Sampled/full cells must still
        # prove that the measured packet set contains a real TUN->VPP copy.
        if (manifest.get("observe") != "off"
                and stage.get("ingress-copy-bytes", 0) <= 0):
            reasons.append("no-ingress-copy-bytes")
        checksum_error_fields = (
            "tcp-input-checksum-errors", "udp-input-checksum-errors",
            "tcp-output-checksum-errors", "udp-output-checksum-errors")
        gate_checksum = {
            field: cumulative_field_delta(samples, "stage", field,
                                          gate_start, gate_end)
            for field in checksum_error_fields
        }
        if any(gate_checksum.get(field, 0) not in (None, 0)
               for field in checksum_error_fields):
            reasons.append("l4-checksum-errors")
        if (manifest.get("arm") == "full"
                and manifest.get("protocol") == "tcp"):
            tcp_gate_fields = (
                "tcp-input-syn-packets", "tcp-output-syn-ack-packets",
                "tcp-input-ack-packets", "tcp-input-data-packets",
                "tcp-output-data-packets")
            gate_tcp = {
                field: cumulative_field_delta(samples, "stage", field,
                                              gate_start, gate_end)
                for field in tcp_gate_fields
            }
            if any(gate_tcp.get(field) is None for field in tcp_gate_fields):
                reasons.append("tcp-handshake-evidence-missing")
            elif any(gate_tcp.get(field, 0) <= 0 for field in tcp_gate_fields):
                reasons.append("tcp-handshake-packet-gate-failed")
        else:
            gate_tcp = {}
    else:
        gate_checksum = {}
        gate_tcp = {}

    tcp_handshake = {
        "appReady": bool_value(done.get("tcpHandshakeReady", False))
        if manifest.get("protocol") == "tcp" else None,
        "connectedFlows": done.get("tcpConnectedFlows"),
        "firstEchoFlows": done.get("tcpFirstEchoFlows"),
        "inputSynPackets": gate_tcp.get("tcp-input-syn-packets"),
        "outputSynAckPackets": gate_tcp.get("tcp-output-syn-ack-packets"),
        "inputAckPackets": gate_tcp.get("tcp-input-ack-packets"),
        "inputDataPackets": gate_tcp.get("tcp-input-data-packets"),
        "outputDataPackets": gate_tcp.get("tcp-output-data-packets"),
        "inputChecksumErrors": gate_checksum.get("tcp-input-checksum-errors"),
        "outputChecksumErrors": gate_checksum.get("tcp-output-checksum-errors"),
    }
    if (is_v2 and manifest.get("arm") == "full"
            and manifest.get("protocol") == "tcp"):
        expected_flows = manifest.get("flows")
        if not bool_value(done.get("tcpHandshakeReady", False)):
            reasons.append("tcp-handshake-app-failed")
        if (expected_flows is not None
                and done.get("tcpConnectedFlows") != expected_flows):
            reasons.append("tcp-connected-flow-count-mismatch")
        if (expected_flows is not None
                and done.get("tcpFirstEchoFlows") != expected_flows):
            reasons.append("tcp-first-echo-flow-count-mismatch")
    if is_v2 and manifest.get("expectEcho", True) and output:
        if any(output.get(field, 0) != 0
               for field in ("partial-writes", "eagain", "eintr", "other-errors")):
            reasons.append("output-write-errors")
        if output.get("write-bytes", 0) < output.get("pbuf-bytes", 0):
            reasons.append("output-write-byte-shortfall")
        if output.get("output-copy-bytes", 0) != 0:
            reasons.append("unexpected-output-copy")
    if is_v2 and manifest.get("arm") == "full" \
            and manifest.get("observe") == "full":
        if manifest.get("protocol") == "udp" and udp_copy_bytes is not None \
                and udp_copy_bytes <= 0:
            reasons.append("no-udp-copy-bytes")
        if manifest.get("protocol") == "tcp":
            if tcp_copy_bytes is not None and tcp_copy_bytes <= 0:
                reasons.append("no-tcp-copy-bytes")
            if tcp_write_copy_bytes is not None and tcp_write_copy_bytes <= 0:
                reasons.append("no-tcp-write-copy-bytes")
            if tcp_write_copy_bytes is not None and tcp_copy_bytes is not None \
                    and tcp_copy_bytes > tcp_write_copy_bytes:
                reasons.append("tcp-copy-byte-accounting-invalid")
            if tcp_write_copy_bytes is not None and tcp_write_copy_bytes > 0 \
                    and tcp_copy_bytes is not None \
                    and tcp_write_copy_bytes < tcp_copy_bytes:
                reasons.append("tcp-write-copy-byte-accounting-invalid")
    resource_delta = {}
    before = resource["resource-before.raw"]
    after = resource["resource-after.raw"]
    for name in ("vppCpuTicks", "appCpuTicks", "vppVmRssKb", "appVmRssKb",
                 "vppvoluntaryCtxtSwitches", "vppnonvoluntaryCtxtSwitches",
                 "appvoluntaryCtxtSwitches", "appnonvoluntaryCtxtSwitches"):
        if before.get(name) is not None and after.get(name) is not None:
            resource_delta[name] = after[name] - before[name]
            if resource_delta[name] < 0 and (name.endswith("CpuTicks")
                                             or name.endswith("CtxtSwitches")):
                reasons.append("resource-counter-decreased")
    thermal_values = [value.get("thermalMaxMillic") for value in resource.values()
                      if value.get("thermalMaxMillic") is not None]
    if thermal_values:
        resource_delta["thermalMaxMillic"] = max(thermal_values)

    sent_count = done.get("sent", 0) if done else 0
    loss_rate = ((sent_count - done.get("received", 0)) / sent_count
                 if done and sent_count > 0 else None)
    summary = {
        "schema": "s125-poc7-summary/v2",
        "label": manifest.get("label"),
        "config": {key: manifest.get(key) for key in
                    ("arm", "workers", "protocol", "flows", "payloadBytes",
                     "burst", "load", "observe", "expectEcho",
                     "reconnectEvery", "repeat",
                     "fireAndCountPacingNsPerPacket")},
        "valid": not reasons,
        "timingReady": timing_ready,
        "attributionReady": attribution_ready,
        "reasons": sorted(set(reasons)),
        "reason": "ok" if not reasons else sorted(set(reasons))[0],
        "steadySamples": len(window),
        "cliSamples": len(samples),
        "pluginRegistrationEvidence": plugin_registration_evidence,
        "app": app,
        "resource": resource,
        "resourceReady": resource_ready,
        "thermalLimitMillic": thermal_limit,
        "thermalMaxMillic": thermal_max,
        "resourceDelta": resource_delta,
        "ownerIdentity": identity,
        "ownerIdentityReady": identity_ready,
        "ownerCreditRejects": credit_rejects,
        "simpleperf": simpleperf,
        "lossRate": loss_rate,
        "stageDelta": stage,
        "gateStageDelta": {**gate_checksum, **gate_tcp},
        "stageComplete": stage_complete,
        "outputDelta": output,
        "queueWaitNs": queue_wait,
        "dequeueToSubmitNs": dequeue_to_submit,
        "submitTotalNs": submit_total,
        "ownerPackets": owner_packets,
        "ownerBytes": owner_bytes,
        "ownerPacketDeltas": owner_packet_deltas,
        "activeOwnerIds": active_owner_ids,
        "activeOwnerCount": len(active_owner_ids),
        "udpEchoStackNs": udp_echo_stack,
        "tcpEchoStackNs": tcp_echo_stack,
        "ownerResidualNs": owner_residual,
        "submitCopyNs": submit_copy,
        "udpCopyNs": udp_copy,
        "tcpCopyNs": tcp_copy_ns,
        "tcpCopyBytes": tcp_copy_bytes,
        "tcpCopyMetric": tcp_copy_metric,
        "tcpWriteCopyBytes": tcp_write_copy_bytes,
        "submitCopyBytes": submit_copy_bytes,
        "udpCopyBytes": udp_copy_bytes,
        "tcpWriteCalls": cumulative_owner_delta(samples, "perf",
                                                 "tcp-write-calls", start, end),
        "ingressCopyBytes": stage.get("ingress-copy-bytes"),
        "parsePackets": stage.get("parse-packets"),
        "enqueuePackets": stage.get("enqueue-packets"),
        "enqueueDrops": stage.get("enqueue-drops"),
        "foreignPackets": stage.get("foreign-packets"),
        "foreignBytes": stage.get("foreign-bytes"),
        "tcpHandshake": tcp_handshake,
        "wireBytesPerPacket": (
            stage.get("ingress-copy-bytes") / stage.get("parse-packets")
            if stage.get("parse-packets") else None),
        "submitCopyBytesPerPacket": (
            submit_copy_bytes / owner_packets
            if submit_copy_bytes is not None and owner_packets else None),
        "udpCopyBytesPerPacket": (
            udp_copy_bytes / owner_packets
            if udp_copy_bytes is not None and owner_packets else None),
        "tcpCopyBytesPerPacket": (
            tcp_copy_bytes / owner_packets
            if tcp_copy_bytes is not None and owner_packets else None),
        "tcpWriteCopyBytesPerPacket": (
            tcp_write_copy_bytes / owner_packets
            if tcp_write_copy_bytes is not None and owner_packets else None),
        "memcpyCalNs": memcpy_ns,
        "memcpyCalBytes": memcpy_bytes,
        "memcpyCalPackets": memcpy_packets,
        "memcpyCalErrors": memcpy_errors,
        "ingressTotalNs": ingress_total,
        "observedPathNs": observed_path,
        "observedCopyNsUdp": observed_copy_udp if attribution_ready else None,
        "observedCopyNsTcp": observed_copy_tcp if attribution_ready else None,
        "copyShareUdp": (observed_copy_udp / observed_path
                          if observed_copy_udp is not None and observed_path
                          and attribution_ready else None),
        "copyShareTcp": (observed_copy_tcp / observed_path
                          if observed_copy_tcp is not None and observed_path
                          and attribution_ready and tcp_copy_metric
                          else None),
    }
    return summary


def median(values):
    values = [value for value in values if isinstance(value, (int, float))]
    return statistics.median(values) if values else None


def percentile(values, probability):
    values = sorted(value for value in values
                    if isinstance(value, (int, float)))
    if not values:
        return None
    index = max(0, min(len(values) - 1,
                       math.ceil(probability * len(values)) - 1))
    return values[index]


def base_key(summary):
    config = summary.get("config", {})
    return tuple(config.get(key) for key in
                 ("arm", "workers", "protocol", "flows", "payloadBytes",
                  "burst", "load", "reconnectEvery"))


def copy_bytes_per_packet(summary):
    config = summary.get("config", {})
    if config.get("protocol") == "udp":
        return summary.get("udpCopyBytesPerPacket")
    return summary.get("tcpWriteCopyBytesPerPacket")


def slope_evidence(summaries):
    """Check that measured payload-copy bytes grow with payload size.

    The comparison is within the same protocol/worker/flow/burst/load/reconnect
    tuple, so it does not mistake topology or offered-load changes for a payload
    slope.  It intentionally uses conservative bounds: the large-payload cell
    must be at least 1.5x the small-payload cell and must account for at least a
    quarter of the configured payload.  Missing pairs are evidence gaps, not a
    passing zero slope.
    """
    groups = defaultdict(list)
    for summary in summaries:
        config = summary.get("config", {})
        # The TCP handshake gate is an intentional one-shot closed cell
        # (repeat=0).  It proves packet-path correctness but is not a payload
        # calibration point; including it would manufacture a missing-p1400
        # slope row beside the registered saturating pair.
        if (config.get("protocol") == "tcp"
                and config.get("repeat") == 0):
            continue
        if not (summary.get("valid") and summary.get("timingReady")
                and config.get("arm") == "full"
                and config.get("observe") == "full"):
            continue
        key = tuple(config.get(name) for name in
                    ("protocol", "workers", "flows", "burst", "load",
                     "reconnectEvery"))
        groups[key].append(summary)
    rows = []
    for key, values in sorted(groups.items(), key=lambda item: str(item[0])):
        by_payload = defaultdict(list)
        for value in values:
            metric = copy_bytes_per_packet(value)
            payload = value.get("config", {}).get("payloadBytes")
            if payload in (33, 1400) and isinstance(metric, (int, float)):
                by_payload[payload].append(metric)
        small = median(by_payload.get(33, []))
        large = median(by_payload.get(1400, []))
        row = {"key": key, "smallPayloadBytes": 33,
               "largePayloadBytes": 1400,
               "smallCopyBytesPerPacket": small,
               "largeCopyBytesPerPacket": large}
        if small is None or large is None:
            row["pass"] = False
            row["reason"] = "missing-payload-pair"
        else:
            row["ratio"] = large / small if small > 0 else None
            row["largePayloadFraction"] = large / 1400.0
            row["pass"] = (small > 0 and large >= small * 1.5
                           and large >= 1400.0 * 0.25)
            row["reason"] = "ok" if row["pass"] else "payload-slope-inconsistent"
        rows.append(row)
    protocols = {row["key"][0] for row in rows}
    required = {"udp", "tcp"}
    slope_pass = bool(rows) and required.issubset(protocols) and all(
        row.get("pass", False) for row in rows)
    return rows, slope_pass


def aggregate(summaries):
    groups = defaultdict(list)
    for summary in summaries:
        groups[base_key(summary)].append(summary)
    group_rows = []
    for key, values in sorted(groups.items(), key=lambda item: str(item[0])):
        valid_values = [value for value in values if value["valid"]]
        group_rows.append({
            "key": key,
            "cells": len(values),
            "validCells": sum(1 for value in values if value["valid"]),
            "timingReadyCells": sum(1 for value in values
                                     if value["timingReady"]),
            "copyShareUdpMedian": median(value["copyShareUdp"]
                                         for value in valid_values),
            "copyShareTcpMedian": median(value["copyShareTcp"]
                                         for value in valid_values),
            "simpleperfCopyPercentMedian": median(
                value["simpleperf"].get("copyPercent")
                for value in valid_values),
            "sentPpsMilliMedian": median(
                value["app"]["done"].get("sentPpsMilli")
                if value["app"].get("done") else None
                for value in valid_values),
            "goodputBytesPerSecMedian": median(
                value["app"]["done"].get("goodputBytesPerSec")
                if value["app"].get("done") else None
                for value in valid_values),
        })

    control_rows = []
    by_control = defaultdict(list)
    for summary in summaries:
        config = summary.get("config", {})
        control_key = tuple(config.get(key) for key in
                            ("workers", "protocol", "flows", "payloadBytes",
                             "burst", "load", "reconnectEvery", "observe"))
        by_control[control_key].append(summary)
    for key, values in sorted(by_control.items(), key=lambda item: str(item[0])):
        by_arm = defaultdict(list)
        for value in values:
            if value["valid"]:
                by_arm[value["config"].get("arm")].append(value)
        row = {"key": key}
        for arm in ("full", "udp-reflect", "ingress-only", "memcpy-cal"):
            if arm in by_arm:
                row[arm] = {
                    "validCells": len(by_arm[arm]),
                    "sentPpsMilliMedian": median(
                        value["app"]["done"].get("sentPpsMilli")
                        if value["app"].get("done") else None
                        for value in by_arm[arm]),
                    "goodputBytesPerSecMedian": median(
                        value["app"]["done"].get("goodputBytesPerSec")
                        if value["app"].get("done") else None
                        for value in by_arm[arm]),
                    "observedPathNsMedian": median(
                        value.get("observedPathNs") for value in by_arm[arm]),
                    "memcpyCalNsMedian": median(
                        value.get("memcpyCalNs") for value in by_arm[arm]),
                }
        if "memcpy-cal" in row and "ingress-only" in row:
            memcpy_path = row["memcpy-cal"].get("observedPathNsMedian")
            ingress_path = row["ingress-only"].get("observedPathNsMedian")
            row["memcpyMinusIngressPathNs"] = (
                memcpy_path - ingress_path
                if memcpy_path is not None and ingress_path is not None else None)
        if "full" in row and "udp-reflect" in row:
            full_path = row["full"].get("observedPathNsMedian")
            reflect_path = row["udp-reflect"].get("observedPathNsMedian")
            row["fullMinusReflectPathNs"] = (
                full_path - reflect_path
                if full_path is not None and reflect_path is not None else None)
        control_rows.append(row)

    instrumentation_rows = []
    by_instrumentation = defaultdict(list)
    for summary in summaries:
        config = summary.get("config", {})
        key = tuple(config.get(name) for name in
                    ("arm", "workers", "protocol", "flows", "payloadBytes",
                     "burst", "load", "reconnectEvery"))
        by_instrumentation[key].append(summary)
    for key, values in sorted(by_instrumentation.items(),
                              key=lambda item: str(item[0])):
        by_observe = defaultdict(list)
        for value in values:
            if value["valid"]:
                by_observe[value["config"].get("observe")].append(value)
        def overhead_metric(value):
            done = value["app"].get("done") or {}
            # Fire-and-count controls have no receive goodput by design; use
            # offered send rate there. Echo arms use receive goodput.
            if value["config"].get("expectEcho") is False:
                return done.get("sentPpsMilli")
            return done.get("goodputBytesPerSec")

        off = median(overhead_metric(value)
                     for value in by_observe.get("off", []))
        sampled = median(overhead_metric(value)
                          for value in by_observe.get("sample64", []))
        full = median(overhead_metric(value)
                      for value in by_observe.get("full", []))
        relative = (abs(sampled - off) / off
                    if off not in (None, 0) and sampled is not None else None)
        full_relative = (abs(full - sampled) / sampled
                         if sampled not in (None, 0) and full is not None else None)
        instrumentation_rows.append({
            "key": key,
            "offValidCells": len(by_observe.get("off", [])),
            "sample64ValidCells": len(by_observe.get("sample64", [])),
            "fullValidCells": len(by_observe.get("full", [])),
            "offMetricMedian": off,
            "sample64MetricMedian": sampled,
            "fullMetricMedian": full,
            "metric": ("sentPpsMilli" if any(
                value["config"].get("expectEcho") is False for value in values)
                       else "goodputBytesPerSec"),
            "relativeDelta": relative,
            "fullVsSample64RelativeDelta": full_relative,
            "pass": relative is not None and relative <= 0.03,
            "fullVsSample64Pass": (full_relative is not None
                                    and full_relative <= 0.03),
        })

    timing = [value for value in summaries
              if value["valid"] and value["timingReady"]]
    udp_shares = [value["copyShareUdp"] for value in timing
                  if value["config"].get("arm") == "full"
                  and value["config"].get("protocol") == "udp"
                  and value["copyShareUdp"] is not None]
    tcp_shares = [value["copyShareTcp"] for value in timing
                  if value["config"].get("arm") == "full"
                  and value["config"].get("protocol") == "tcp"
                  and value["copyShareTcp"] is not None]
    expected_perf = [value for value in summaries
                     if value["config"].get("arm") == "full"
                     and value["config"].get("protocol") in ("udp", "tcp")
                     and value["config"].get("flows") == 32
                     and value["config"].get("payloadBytes") == 1400
                     and value["config"].get("burst") == 32
                     and value["config"].get("load") == "saturating"
                     and value["config"].get("observe") == "full"]
    all_expected_perf_present = bool(expected_perf) and all(
        value["valid"] and value["simpleperf"]["present"]
        for value in expected_perf)
    expected_perf_groups = defaultdict(list)
    for value in expected_perf:
        config = value["config"]
        key = tuple(config.get(name) for name in
                    ("protocol", "workers", "flows", "payloadBytes",
                     "burst", "load", "observe"))
        expected_perf_groups[key].append(value)
    all_expected_perf_repeats = (
        bool(expected_perf_groups)
        and all(sum(1 for value in values if value["valid"]
                    and value["simpleperf"]["present"]) >= REQUIRED_REPEATS
                for values in expected_perf_groups.values()))
    all_expected_perf_present = all_expected_perf_present and all_expected_perf_repeats
    required_instrumentation_keys = {
        (arm, workers, "udp", 1, payload, burst, "saturating", 0)
        for arm in ("full", "udp-reflect", "ingress-only", "memcpy-cal")
        for workers in (1, 2)
        for payload in (33, 1400)
        for burst in (1, 32)
    }
    instrumentation_by_key = {
        tuple(row["key"]): row for row in instrumentation_rows
    }
    instrumentation_ok = all(
        key in instrumentation_by_key
        and instrumentation_by_key[key]["relativeDelta"] is not None
        and instrumentation_by_key[key]["pass"]
        and instrumentation_by_key[key].get("offValidCells", 0) >= REQUIRED_REPEATS
        and instrumentation_by_key[key].get("sample64ValidCells", 0) >= REQUIRED_REPEATS
        and instrumentation_by_key[key].get("fullValidCells", 0) >= REQUIRED_REPEATS
        and instrumentation_by_key[key].get("fullVsSample64Pass", False)
        for key in required_instrumentation_keys)
    # Require a matched full-observation UDP control tuple, not merely one
    # valid cell for each arm somewhere in the run.  These are the registered
    # Tier-0 keys; without them full-vs-control path deltas are not evidence.
    required_control_keys = {
        (workers, "udp", 1, payload, burst, "saturating", 0, "full")
        for workers in (1, 2)
        for payload in (33, 1400)
        for burst in (1, 32)
    }
    matched_control_keys = {
        tuple(row["key"]): row for row in control_rows
        if all(arm in row for arm in ("full", "udp-reflect",
                                      "ingress-only", "memcpy-cal"))
    }
    controls_ok = all(
        key in matched_control_keys
        and all(matched_control_keys[key][arm].get("validCells", 0)
                >= REQUIRED_REPEATS
                for arm in ("full", "udp-reflect", "ingress-only", "memcpy-cal"))
        and matched_control_keys[key].get("fullMinusReflectPathNs") is not None
        and matched_control_keys[key].get("memcpyMinusIngressPathNs") is not None
        and matched_control_keys[key].get("fullMinusReflectPathNs") >= 0
        and matched_control_keys[key].get("memcpyMinusIngressPathNs") >= 0
        for key in required_control_keys)
    control_deltas_ok = all(
        key in matched_control_keys
        and matched_control_keys[key].get("fullMinusReflectPathNs") is not None
        and matched_control_keys[key].get("memcpyMinusIngressPathNs") is not None
        and matched_control_keys[key].get("fullMinusReflectPathNs") >= 0
        and matched_control_keys[key].get("memcpyMinusIngressPathNs") >= 0
        for key in required_control_keys)
    tcp_calibration_key = ("full", 1, "tcp", 1, 33, 1, "saturating", 0)
    tcp_calibration = instrumentation_by_key.get(tcp_calibration_key, {})
    tcp_instrumentation_ok = (
        tcp_calibration.get("offValidCells", 0) >= REQUIRED_REPEATS
        and tcp_calibration.get("sample64ValidCells", 0) >= REQUIRED_REPEATS
        and tcp_calibration.get("fullValidCells", 0) >= REQUIRED_REPEATS
        and tcp_calibration.get("relativeDelta") is not None
        and tcp_calibration.get("pass", False)
        and tcp_calibration.get("fullVsSample64Pass", False))
    slope_rows, slope_ok = slope_evidence(summaries)
    tcp_gate_cells = [value for value in summaries
                      if value.get("config", {}).get("repeat") == 0
                      and value.get("config", {}).get("arm") == "full"
                      and value.get("config", {}).get("protocol") == "tcp"]
    tcp_handshake_gate_pass = bool(tcp_gate_cells) and all(
        value.get("valid") and value.get("tcpHandshake", {}).get("appReady")
        and value.get("tcpHandshake", {}).get("inputSynPackets", 0) > 0
        and value.get("tcpHandshake", {}).get("outputSynAckPackets", 0) > 0
        and value.get("tcpHandshake", {}).get("inputAckPackets", 0) > 0
        and value.get("tcpHandshake", {}).get("inputDataPackets", 0) > 0
        and value.get("tcpHandshake", {}).get("outputDataPackets", 0) > 0
        for value in tcp_gate_cells)
    decision = "INCONCLUSIVE"
    decision_reason = ("tcp-handshake-gate-not-passed"
                       if not tcp_handshake_gate_pass
                       else "missing-valid-timing-control-or-instrumentation-evidence")
    if (timing and udp_shares and tcp_shares and expected_perf
            and all_expected_perf_present and instrumentation_ok and controls_ok
            and control_deltas_ok and tcp_instrumentation_ok and slope_ok
            and tcp_handshake_gate_pass):
        udp_upper = percentile(udp_shares, 0.95)
        tcp_copy_upper = percentile(tcp_shares, 0.95)
        perf_values = [value["simpleperf"].get("copyPercent")
                       for value in expected_perf]
        perf_upper = percentile(perf_values, 0.95)
        udp_lower = percentile(udp_shares, 0.05)
        tcp_copy_lower = percentile(tcp_shares, 0.05)
        perf_lower = percentile(perf_values, 0.05)
        if udp_upper < 0.05 and tcp_copy_upper < 0.05 and perf_upper < 10.0:
            decision = "DEFER"
            decision_reason = "copy-share-and-samples-below-defer-threshold"
        elif (udp_lower >= 0.15 or tcp_copy_lower >= 0.15
              or perf_lower >= 20.0):
            decision = "MUST_INVEST"
            decision_reason = "copy-share-or-samples-over-must-invest-threshold"
        elif udp_upper >= 0.05 or tcp_copy_upper >= 0.05 or perf_upper >= 10.0:
            decision = "TARGETED"
            decision_reason = "copy-signal-in-targeted-band"

    return {
        "schema": "s125-poc7-run-summary/v2",
        "requiredRepeats": REQUIRED_REPEATS,
        "cellCount": len(summaries),
        "validCellCount": sum(1 for value in summaries if value["valid"]),
        "timingReadyCellCount": sum(1 for value in summaries
                                     if value["timingReady"]),
        "groups": group_rows,
        "controls": control_rows,
        "instrumentation": instrumentation_rows,
        "instrumentationPass": instrumentation_ok,
        "tcpInstrumentationPass": tcp_instrumentation_ok,
        "instrumentationCoverage": sum(
            1 for key in required_instrumentation_keys
            if key in instrumentation_by_key
            and instrumentation_by_key[key]["relativeDelta"] is not None),
        "controlsPass": controls_ok,
        "controlDeltasPass": control_deltas_ok,
        "payloadSlopePass": slope_ok,
        "tcpHandshakeGatePass": tcp_handshake_gate_pass,
        "tcpHandshakeGateCellCount": len(tcp_gate_cells),
        "payloadSlope": slope_rows,
        "matchedControlCount": sum(1 for key in required_control_keys
                                    if key in matched_control_keys),
        "decision": decision,
        "decisionReason": decision_reason,
        "decisionEvidence": {
            "controlsPass": controls_ok,
            "controlDeltasPass": control_deltas_ok,
            "payloadSlopePass": slope_ok,
            "tcpHandshakeGatePass": tcp_handshake_gate_pass,
            "tcpHandshakeGateCellCount": len(tcp_gate_cells),
            "udpCopyShareP05": percentile(udp_shares, 0.05),
            "udpCopyShareP95": percentile(udp_shares, 0.95),
            "tcpCopyShareP05": percentile(tcp_shares, 0.05),
            "tcpCopyShareP95": percentile(tcp_shares, 0.95),
            "simpleperfCopyPercentP05": percentile(
                [value["simpleperf"].get("copyPercent")
                 for value in expected_perf], 0.05),
            "simpleperfCopyPercentP95": percentile(
                [value["simpleperf"].get("copyPercent")
                 for value in expected_perf], 0.95),
            "payloadSlope": slope_rows,
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("cells", nargs="+", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    summaries = [parse_cell(cell) for cell in args.cells]
    payload = summaries[0] if len(summaries) == 1 else {
        "schema": "s125-poc7-run-summary/v2",
        "cells": summaries,
        "run": aggregate(summaries),
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
