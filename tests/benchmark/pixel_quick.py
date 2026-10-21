#!/usr/bin/env python3
"""Prepare once, then measure a frozen Pixel workload suite within 120 seconds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import socket
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "com.sakamoto.snort.androidruntime"
SERIAL = "28201JEGR0XPAJ"
CASES = ("tcp-fixed", "udp-fixed", "tcp-new", "udp-new")
SOURCE = Path(__file__).with_name("socket_load.c")
VPN_SUITE = "ordinary-vpn-v1"
VPN_FRESH_SUITE = "ordinary-vpn-fresh-v1"
VPN_TCP_SUITE = "ordinary-vpn-tcp-fixed-v1"
VPN_SUITES = (VPN_SUITE, VPN_FRESH_SUITE, VPN_TCP_SUITE)
NDK_CLANG = Path("/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def properties(text):
    return dict(line.split("=", 1) for line in text.splitlines()
                if "=" in line and not line.startswith("#"))


def peer_query(host, port, case_id, operation="Q"):
    with socket.create_connection((host, port), timeout=1) as connection:
        connection.sendall(struct.pack("!IIIIQ", 0x53424e31, case_id, ord(operation), 24, 0))
        return json.loads(connection.makefile("rb").readline(4096))


class Device:
    def __init__(self, serial, output, deadline=None, control_timeout=5):
        self.prefix = [str(ROOT / "dev/adb"), "-s", serial]
        self.output, self.deadline = output, deadline
        self.control_timeout = control_timeout
        self.helper = None

    def command(self, *args, timeout=None, check=True, cleanup=False):
        started = time.monotonic()
        timeout = self.control_timeout if timeout is None else timeout
        if self.deadline is not None and not cleanup:
            timeout = min(timeout, self.deadline - started)
            if timeout <= 0:
                raise TimeoutError("global 120-second deadline")
        try:
            completed = subprocess.run(self.prefix + list(map(str, args)),
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, errors="replace", timeout=timeout)
        except subprocess.TimeoutExpired:
            with (self.output / "operations.jsonl").open("a") as log:
                log.write(json.dumps({"started_monotonic": started,
                                      "elapsed_seconds": time.monotonic() - started,
                                      "args": list(map(str, args)), "timeout_seconds": timeout,
                                      "error": "TimeoutExpired"}) + "\n")
            raise
        value = completed.stdout.replace("\r", "")
        with (self.output / "operations.jsonl").open("a") as log:
            log.write(json.dumps({"started_monotonic": started,
                                  "elapsed_seconds": time.monotonic() - started,
                                  "args": list(map(str, args)), "returncode": completed.returncode}) + "\n")
        if check and completed.returncode:
            raise RuntimeError(value)
        return value

    def root(self, command, **kwargs):
        return self.command("shell", "su", "-c", shlex.quote(command), **kwargs)

    def state(self, **kwargs):
        return properties(self.command("shell", "run-as", PACKAGE, "cat",
                                       "files/runtime-state/snapshot.properties", **kwargs))

    def action(self, *args, **kwargs):
        return self.command("shell", "am", "start", "-n",
                            PACKAGE + "/.DebugControlActivity", *args, **kwargs)

    def wait_state(self, wanted, profile=None, cleanup=False):
        end = time.monotonic() + (8 if cleanup or wanted == "stopped" else 5)
        if self.deadline is not None and not cleanup:
            end = min(end, self.deadline)
        last = None
        while time.monotonic() < end:
            last = self.state(cleanup=cleanup)
            if last.get("state") == wanted and (profile is None or last.get("profile") == profile):
                if wanted == "running" and last.get("protectionRunning") != "true":
                    raise RuntimeError("ordinary Product profile is not protecting: " + str(last))
                if wanted == "stopped" and last.get("mayBeActive") != "false":
                    raise RuntimeError("stop still may be active: " + str(last))
                return last
            if last.get("errorCode") == "root_authorization_required":
                raise RuntimeError("Verify the installed app's Superuser grant in KernelSU Manager")
            if last.get("state") == "error" and wanted == "running":
                raise RuntimeError("runtime start error: " + str(last))
            time.sleep(.05)
        raise TimeoutError("runtime " + wanted + " deadline: " + str(last))

    def wait_process_gone(self, name, timeout=2, cleanup=False):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if not self.command("shell", "pidof", name, check=False, cleanup=cleanup).strip():
                return
            time.sleep(.05)
        raise TimeoutError("process did not exit: " + name)

    def cli(self, profile, commands):
        path = "/data/data/" + PACKAGE + "/files/profiles/" + profile + "/vpp/runtime/cli.sock"
        if self.helper:
            value = self.root(shlex.join([self.helper, "cli", path, *commands]), timeout=4)
            if "\nBENCHCLI_DONE\n" not in value:
                raise RuntimeError("incomplete native CLI response")
            return value
        process = subprocess.Popen(self.prefix + ["shell", "-T", "su", "-c",
                                                 shlex.quote("exec toybox nc -U -w 4 " + path)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        data, sent = b"", False
        marker = "BENCH_DONE_" + str(time.monotonic_ns())
        end = min(time.monotonic() + 4, self.deadline or float("inf"))
        try:
            while time.monotonic() < end:
                if not sent and b"vpp# " in data:
                    process.stdin.write(("\nset terminal pager off\n" + "\n".join(commands)
                                         + "\necho " + marker + "\n").encode())
                    process.stdin.flush()
                    sent = True
                if not selector.select(.05):
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                data += chunk
                if b"\n" + marker.encode() + b"\n" in data.replace(b"\r", b""):
                    process.stdin.write(b"quit\n")
                    process.stdin.flush()
                    remainder, _ = process.communicate(timeout=1)
                    if process.returncode:
                        raise RuntimeError("CLI transport exited unsuccessfully")
                    return (data + remainder).decode(errors="replace").replace("\r", "")
            raise TimeoutError("incomplete CLI response: " + data[-1000:].decode(errors="replace"))
        finally:
            selector.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=1)

    def retain_vpn_log(self, destination):
        """Hold the log inode across RuntimeService's normal profile deletion.

        The reader blocks on a FIFO until native exit; it can be started before
        load to preserve fatal evidence without polling during the samples.
        """
        log = "/data/data/" + PACKAGE + "/files/profiles/vpn/vpp/logs/vpp-stdout.log"
        q = shlex.quote
        gate = destination + ".gate"
        script = ("exec 3< " + q(log) + " || exit 1; mkfifo " + q(gate)
                  + " || exit 2; touch " + q(destination + ".ready")
                  + "; IFS= read -r trigger < " + q(gate) + " || exit 3; "
                  + "cat <&3 > " + q(destination) + " && touch " + q(destination + ".done")
                  + "; rm -f " + q(gate))
        value = self.root("timeout 120 sh -c " + q(script)
                          + " >/dev/null 2>&1 </dev/null & echo reader=$!")
        if not properties(value).get("reader", "").isdigit():
            raise RuntimeError("native log reader did not start")
        self.root("n=0; while [ ! -f " + q(destination + ".ready")
                  + " ] && [ $n -lt 50 ]; do sleep .02; n=$((n+1)); done; test -f "
                  + q(destination + ".ready"), timeout=2)

    def read_retained_vpn_log(self, destination, cleanup=False):
        q = shlex.quote
        return self.root("if [ ! -f " + q(destination + ".done")
                         + " ]; then timeout 1 sh -c "
                         + q("echo copy > " + q(destination + ".gate")) + "; fi"
                         + "; n=0; while [ ! -f " + q(destination + ".done")
                         + " ] && [ $n -lt 50 ]; do sleep .02; n=$((n+1)); done; "
                         + "test -f " + q(destination + ".done") + " && cat "
                         + q(destination), timeout=3, cleanup=cleanup)


def prepare(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    native, host = output / "socket-load-arm64", output / "socket-load-host"
    flags = ["-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-pthread"]
    for compiler, binary in ((str(args.clang), native), ("cc", host)):
        subprocess.run([compiler, *flags, str(SOURCE), "-o", str(binary)], check=True)
    device = Device(args.serial, output)
    initial = device.state()
    if initial.get("state") != "stopped" or initial.get("mayBeActive") != "false":
        raise RuntimeError("prepare requires the initial runtime to be stopped")
    uid = device.command("shell", "run-as", PACKAGE, "id", "-u").strip()
    if not uid.isdigit():
        raise RuntimeError("invalid app UID")
    apk = device.command("shell", "pm", "path", PACKAGE).strip().removeprefix("package:")
    if not apk.startswith("/data/app/") or not apk.endswith("/base.apk"):
        raise RuntimeError("ambiguous installed APK path")
    identity = device.command("shell", "getprop", "ro.product.model").strip()
    if identity != "Pixel 6a":
        raise RuntimeError("main benchmark requires a Pixel 6a, got " + identity)
    remote = "/data/local/tmp/sakamoto-benchmark-" + digest(native)[:12]
    device.command("shell", "mkdir", "-p", remote)
    device.command("push", native, remote + "/socket-load")
    device.command("shell", "chmod", "755", remote + "/socket-load")
    installed = device.command("shell", "sha256sum", remote + "/socket-load").split()[0]
    if installed != digest(native):
        raise RuntimeError("helper upload identity mismatch")
    source = "/data/user/0/" + PACKAGE + "/files/rule-configuration/rules.conf"
    hashes = device.root("sha256sum " + shlex.quote(apk) + " " + source).splitlines()
    manifest = {"schema": 1, "serial": args.serial, "model": identity, "uid": int(uid),
                "apk": apk, "apk_sha256": hashes[0].split()[0],
                "rules_path": source, "rules_sha256": hashes[1].split()[0],
                "source_sha256": digest(SOURCE), "android_binary": str(native),
                "android_sha256": installed, "host_binary": str(host),
                "host_sha256": digest(host), "remote": remote,
                "peer_host": args.peer, "peer_port": args.port,
                "cell_ms": args.cell_ms, "threads": 4, "flows_per_thread": 16,
                "profiling": not args.no_profile, "prepared_utc_ns": time.time_ns()}
    if args.suite in VPN_SUITES:
        manifest.update(suite=args.suite, profiles=["vpn"],
                        cases=["tcp-fixed"] if args.suite == VPN_TCP_SUITE else list(CASES),
                        collector_sha256=digest(__file__),
                        native_stop_evidence="retained-open-log-inode")
        if args.suite in (VPN_FRESH_SUITE, VPN_TCP_SUITE):
            manifest['fresh_lifetime_each_case'] = True
        if args.suite == VPN_TCP_SUITE:
            manifest['control_timeout_seconds'] = 15
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "device-before.json").write_text(json.dumps(initial, indent=2) + "\n")
    print(json.dumps({"prepared": str(output / "manifest.json"),
                      "peer_command": [str(host), "server", args.bind, str(args.port)]}, indent=2))


def rows(raw, prefix):
    result = []
    for line in raw.splitlines():
        at = line.find(prefix)
        if at < 0:
            continue
        result.append(dict(word.split("=", 1) for word in line[at:].split()[1:] if "=" in word))
    return result


def validate_capture_window(profile, client, before, after):
    """Endpoint success alone cannot establish an active Product packet path."""
    active = any(client.get(key, 0) for key in
                 ('bytes', 'packets', 'completed', 'input_unique_udp_tuples'))
    if not active:
        return
    if profile == 'root':
        old, new = rows(before, 'root.receive '), rows(after, 'root.receive ')
        identity = lambda values: sorted((v['generation'], v['lane']) for v in values)
        if not old or not new or identity(old) != identity(new):
            raise RuntimeError('Root capture generation changed or diagnostics are missing')
        if sum(int(v['datagrams']) for v in new) <= sum(int(v['datagrams']) for v in old):
            raise RuntimeError('Root capture made no progress despite endpoint traffic')
    if client['case'] in ('tcp-new', 'udp-new'):
        protocol = 'tcp' if client['case'] == 'tcp-new' else 'udp'
        creates = lambda text: sum(int(v['creates']) for v in rows(text, 'flow.protocol ')
                                  if v.get('protocol') == protocol)
        if creates(after) <= creates(before):
            raise RuntimeError('New-connection window has no VPP Flow creates')


def monitor_summary(raw, client):
    samples = [json.loads(line) for line in raw.splitlines() if line.startswith("{")]
    samples = [s for s in samples if client["start_monotonic_ns"] <= s["monotonic_ns"] <= client["end_monotonic_ns"]]
    if len(samples) < 2:
        raise RuntimeError("insufficient simultaneous VPP CPU samples")
    first, last = samples[0], samples[-1]
    start_threads = {t["tid"]: t for t in first["threads"]}
    values = []
    coverage = (last["monotonic_ns"] - first["monotonic_ns"]) / 1e9
    for t in last["threads"]:
        before = start_threads.get(t["tid"])
        if before:
            cpu = (t["utime"] + t["stime"] - before["utime"] - before["stime"]) / first["clock_ticks"]
            values.append({"tid": t["tid"], "cpu_seconds": cpu,
                           "cpu_percent_one_core": cpu / coverage * 100,
                           "last_cpu": t["last_cpu"]})
    return {"sample_coverage_seconds": coverage, "sample_count": len(samples),
            "cpu_seconds": sum(t["cpu_seconds"] for t in values), "threads": values,
            "rss_peak_bytes": max(t["rss_pages"] * s["page_size"] for s in samples for t in s["threads"])}


def validate_vpn_window(generation, client, before, after):
    for raw in (before, after):
        tun = rows(raw, "tun.status ")
        stack = rows(raw, "flow_stack.status ")
        if (len(tun) != 1 or tun[0].get("generation") != str(generation)
                or tun[0].get("enabled") != "1" or tun[0].get("attached") != "1"
                or len(stack) != 2 or {v.get("owner") for v in stack} != {"0", "1"}
                or any(v.get("generation") != str(generation) or v.get("ready") != "1"
                       for v in stack)):
            raise RuntimeError("VPN capture/owner generation or readiness changed")
    if any(client.get(k, 0) for k in ("bytes", "packets", "completed", "input_unique_udp_tuples")):
        if int(rows(after, "tun.status ")[0]["captured"]) <= int(rows(before, "tun.status ")[0]["captured"]):
            raise RuntimeError("VPN capture made no progress despite endpoint traffic")
    validate_capture_window("vpn", client, before, after)


def validate_vpn_stop(raw, generation):
    owners = rows(raw, "s237 event=owner_stopped ")
    stop = rows(raw, "s213 event=stop ")
    if (len(owners) != 2 or {v.get("owner") for v in owners} != {"0", "1"}
            or any(v.get("generation") != str(generation)
                   or any(v.get(k) != "0" for k in ("sessions", "inputs", "pbufs", "buffers", "obligations", "frames"))
                   or v.get("timer_fd") != "-1" or v.get("broker_fd") != "-1"
                   or v.get("sockets_created") != v.get("sockets_closed") for v in owners)
            or len(stop) != 1 or stop[0].get("generation") != str(generation)
            or any(stop[0].get(k) != "0" for k in ("pending", "buffers", "frames", "obligations"))
            or stop[0].get("tun_fd") != "-1"):
        raise RuntimeError("VPN native stop audit does not settle this generation")


def score(client, peer, cpu, diagnostic, before):
    seconds = (client["end_monotonic_ns"] - client["start_monotonic_ns"]) / 1e9
    case = client["case"]
    # UDP send() success is offered load; peer receipt is its delivered measure.
    delivered = client["bytes"] if case.startswith("tcp") else peer["udp_received_bytes"]
    protocols = rows(diagnostic, "flow.protocol ")
    roots = rows(diagnostic, "root.receive ")
    misses = sum(int(v.get("capacity_misses", 0)) for v in rows(diagnostic, "flow.runtime ")) - sum(int(v.get("capacity_misses", 0)) for v in rows(before, "flow.runtime "))
    protocol = "tcp" if case.startswith("tcp") else "udp"
    creates = sum(int(v.get("creates", 0)) for v in protocols if v.get("protocol") == protocol) - sum(int(v.get("creates", 0)) for v in rows(before, "flow.protocol ") if v.get("protocol") == protocol)
    root_fields = ("ingress_accepts", "reserve_accepts", "reserve_losses", "identity_losses")
    root_delta = {key: sum(int(v.get(key, 0)) for v in roots) - sum(int(v.get(key, 0)) for v in rows(before, "root.receive ")) for key in root_fields}
    estimated_cpu = cpu["cpu_seconds"] * seconds / cpu["sample_coverage_seconds"]
    return {"elapsed_seconds": seconds, "delivered_mbps": delivered * 8 / seconds / 1e6,
            "delivered_pps": peer["udp_received_packets"] / seconds if case.startswith("udp") else None,
            "completed_cps": client["completed"] / seconds if case == "tcp-new" else None,
            "input_unique_udp_tuples_per_second": client["input_unique_udp_tuples"] / seconds if case == "udp-new" else None,
            "udp_loss_packets": client["packets"] - peer["udp_received_packets"] + peer["udp_duplicates"] if case.startswith("udp") else None,
            "udp_duplicate_packets": peer["udp_duplicates"] if case.startswith("udp") else None,
            "flow_occupancy_before": [int(v["entries"]) for v in rows(before, "flow.pool ")],
            "flow_occupancy_after": [int(v["entries"]) for v in rows(diagnostic, "flow.pool ")],
            "flow_capacity": [int(v["capacity"]) for v in rows(diagnostic, "flow.runtime ")],
            "flow_creates": creates, "flow_capacity_misses": misses,
            "p99_upper_us": client["p99_upper_us"], "latency_samples": client["latency_samples"],
            "vpp_cpu_seconds": cpu["cpu_seconds"], "root_receive_rows": roots,
            "vpp_cpu_seconds_estimated_window": estimated_cpu,
            "root_unadmitted_accepts": root_delta["ingress_accepts"], "root_receive_deltas": root_delta,
            "cpu_seconds_per_delivered_gib": estimated_cpu / (delivered / 2**30) if delivered else None,
            "sparse_latency_samples": client["latency_samples"] < 100,
            "policy_throughput_qualified": False,
            "qualification": "endpoint delivery; consult admission, capacity and adapter counters for graph coverage"}


def run(args):
    entry = time.monotonic()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads(args.manifest.read_text())
    suite = manifest.get("suite", "root-vpn-v1")
    if suite not in ("root-vpn-v1", *VPN_SUITES):
        raise RuntimeError("unknown benchmark suite")
    vpn_only = suite in VPN_SUITES
    client_cpu_mask = manifest.get("client_cpu_mask")
    if client_cpu_mask is not None:
        if not vpn_only or not isinstance(client_cpu_mask, str) or not re.fullmatch(r"[0-9a-fA-F]+", client_cpu_mask) or not int(client_cpu_mask, 16):
            raise ValueError("client_cpu_mask requires a nonzero hex mask and VPN suite")
    primary_credits = manifest.get("primary_handoff_credits")
    if primary_credits is not None and (not vpn_only or type(primary_credits) is not int or primary_credits not in (32, 48)):
        raise ValueError("primary_handoff_credits requires VPN suite and 32 or 48")
    tcp_source_port = manifest.get("tcp_fixed_source_port_base")
    if tcp_source_port is not None:
        last_port = tcp_source_port + manifest['threads'] * (manifest['flows_per_thread'] + 1) - 1 if type(tcp_source_port) is int else 65536
        if suite != VPN_TCP_SUITE or type(tcp_source_port) is not int or tcp_source_port < 1024 or last_port > 65535:
            raise ValueError("tcp_fixed_source_port_base requires a valid fixed TCP port range")
    worker_cpus = manifest.get("worker_cpu_ids")
    if worker_cpus is not None and (suite != VPN_TCP_SUITE or not isinstance(worker_cpus, list)
            or len(worker_cpus) != 2 or any(type(cpu) is not int or cpu < 1 or cpu > 1023 for cpu in worker_cpus)
            or worker_cpus[0] == worker_cpus[1]):
        raise ValueError("worker_cpu_ids requires two distinct non-main CPUs and the TCP VPN suite")
    callgraph = manifest.get("profiler_callgraph", "dwarf")
    mmap_pages = manifest.get("profiler_mmap_pages")
    if callgraph not in ("dwarf", "fp"):
        raise ValueError("profiler_callgraph must be dwarf or fp")
    if mmap_pages is not None and (type(mmap_pages) is not int or mmap_pages not in (1024, 4096)):
        raise ValueError("profiler_mmap_pages must be 1024 or 4096")
    fresh_each_case = suite in (VPN_FRESH_SUITE, VPN_TCP_SUITE)
    if fresh_each_case and manifest.get('fresh_lifetime_each_case') is not True:
        raise RuntimeError("fresh VPN suite must freeze independent lifetimes")
    profiles = ("vpn",) if vpn_only else ("root", "vpn")
    cases = ("tcp-fixed",) if suite == VPN_TCP_SUITE else CASES
    if vpn_only and (manifest.get("profiles") != ["vpn"] or manifest.get("cases") != list(cases)):
        raise RuntimeError("VPN suite must freeze its exact workload list")
    result = {"schema": 1, "status": "INCOMPLETE", "manifest": manifest,
              "runner_sha256": digest(__file__), "cases": [], "errors": [],
              "started_utc_ns": time.time_ns(), "deadline_seconds": 120}
    control_timeout = manifest.get('control_timeout_seconds', 5)
    if control_timeout not in (5, 15) or (control_timeout != 5 and suite != VPN_TCP_SUITE):
        raise RuntimeError('control timeout is outside the frozen suite contract')
    device = Device(manifest["serial"], output, entry + 120, control_timeout)
    active = False
    initial = None
    sampler_pids = {}
    retained_log = None
    helper = manifest["remote"] + "/socket-load"
    device.helper = helper
    run_remote = manifest["remote"] + "/run-" + hashlib.sha256(str(output).encode()).hexdigest()[:12]
    try:
        if vpn_only and manifest.get("collector_sha256") != digest(__file__):
            raise RuntimeError("VPN collector changed; prepare a new frozen manifest")
        if digest(SOURCE) != manifest["source_sha256"] or digest(manifest["android_binary"]) != manifest["android_sha256"]:
            raise RuntimeError("prepared helper source/artifact changed; prepare a new version")
        initial = device.state()
        if initial.get("state") != "stopped" or initial.get("mayBeActive") != "false":
            raise RuntimeError("benchmark requires a stopped runtime")
        actual = device.root("sha256sum " + shlex.join([manifest["apk"], manifest["rules_path"], helper])).splitlines()
        expected = [manifest["apk_sha256"], manifest["rules_sha256"], manifest["android_sha256"]]
        if [line.split()[0] for line in actual] != expected:
            raise RuntimeError("APK, rule source or installed helper differs from prepared manifest")
        (output / "network-before.txt").write_text(device.command("shell", "ip", "-4", "addr"))
        peer_query(manifest["peer_host"], manifest["peer_port"], 0)
        device.root("mkdir " + shlex.quote(run_remote))
        for profile in profiles:
            for case in cases:
                # Never shorten a cell or omit a profile to claim a successful deadline.
                if entry + 120 - time.monotonic() < manifest["cell_ms"] / 1000 + 5:
                    raise TimeoutError("not enough global budget for a complete next cell and cleanup")
                case_id = len(result["cases"])
                cell = output / (profile + "-" + case)
                cell.mkdir()
                started = time.monotonic()
                fresh_lifetime = fresh_each_case or case in ("tcp-fixed", "udp-new")
                if fresh_lifetime:
                    active = True  # ambiguous start failure still requires normal stop
                    start_args = ["--ez", "runtimeStart", "true", "--es", "runtimeProfile", profile]
                    if worker_cpus is not None:
                        start_args.extend(["--es", "runtimeWorkerCpuIds", ",".join(map(str, worker_cpus))])
                    (cell / "start.txt").write_text(device.action(*start_args))
                    running = device.wait_state("running", profile)
                    pid_text = device.command("shell", "pidof", "libvpp_runtime.so").strip().split()
                    if len(pid_text) != 1:
                        raise RuntimeError("VPP PID is ambiguous")
                    pid = int(pid_text[0])
                else:
                    current = device.state()
                    if current.get("state") != "running" or current.get("profile") != profile or current.get("generation") != running["generation"]:
                        raise RuntimeError("runtime changed between fixed-flow workloads")
                (cell / "runtime.json").write_text(json.dumps(running, indent=2) + "\n")
                if suite == VPN_TCP_SUITE:
                    retained_log = run_remote + "/" + case + "-native.log"
                    device.retain_vpn_log(retained_log)
                if primary_credits is not None:
                    configured = device.cli(profile, [f"product capacity credits {primary_credits} primary-slots 64 completion-slots 128"])
                    (cell / "capacity-configured.txt").write_text(configured)
                    if not any(row.get("generation") == running["generation"] and row.get("credits") == str(primary_credits)
                               for row in rows(configured, "capacity.configured ")):
                        raise RuntimeError("diagnostic capacity requires an active empty graph; no retry")
                client_prefix = ["shell", "su", str(manifest["uid"]), "-c"] if profile == "root" else ["shell"]
                # Warm only existing tracing and the actual LAN path. Its flows and time are explicit.
                warm = [helper, "client", manifest["peer_host"], str(manifest["peer_port"]), "14", "tcp-fixed", "250", "2", "8"]
                warm_command = [*client_prefix, shlex.quote(shlex.join(warm))] if profile == "root" else [*client_prefix, *warm]
                if fresh_lifetime:
                    warm_value = device.command(*warm_command, timeout=2)
                    (cell / "warm.json").write_text(warm_value)
                    warm_result = json.loads(warm_value)
                    if not warm_result.get("bytes"):
                        raise RuntimeError("phone cannot deliver warmup data from the selected LAN peer")
                commands = ["show product primary", "show product completion", "show product root receive", "show product root lanes", "show product tun", "show product flows", "show buffers"]
                if vpn_only:
                    commands.append("show product flow-stack")
                if suite == VPN_TCP_SUITE:
                    commands.append("show runtime")
                    commands.append("show physmem")
                    (cell / "startup.conf").write_text(device.command(
                        "shell", "run-as", PACKAGE, "cat", "files/profiles/vpn/vpp/startup.conf"))
                    (cell / "interface-links.txt").write_text(device.root(
                        "ip -details link show"))
                diagnostic = device.cli(profile, ["show threads", *commands])
                (cell / "before-cli.txt").write_text(diagnostic)
                if suite == VPN_TCP_SUITE and manifest.get("minimum_native_buffers"):
                    available_pool = sum(int(line.split()[5]) for line in diagnostic.splitlines()
                                         if line.startswith("default-numa-"))
                    if available_pool < manifest["minimum_native_buffers"]:
                        raise RuntimeError("native buffer pool below frozen minimum: " + str(available_pool))
                    expected_count = manifest.get("expected_native_buffer_count")
                    if expected_count is not None and available_pool != expected_count:
                        raise RuntimeError("native buffer pool differs from frozen capacity: " + str(available_pool))
                    expected_data = manifest.get("expected_native_buffer_data_bytes")
                    if expected_data is not None and any(
                            int(line.split()[4]) != expected_data for line in diagnostic.splitlines()
                            if line.startswith("default-numa-")):
                        raise RuntimeError("native buffer data size differs from frozen profile")
                layout = []
                for line in diagnostic.splitlines():
                    match = re.match(r"\s*(\d+)\s+(vpp_\S+)\s+(?:workers\s+)?(\d+)\s+\S+\s+\(\d+\)\s+(\d+)", line)
                    if match:
                        layout.append({"id": int(match[1]), "name": match[2], "tid": int(match[3]), "lcore": int(match[4])})
                if len(layout) != 3:
                    raise RuntimeError("expected the current VPP main + two-worker layout")
                if worker_cpus is not None:
                    for index, cpu in enumerate(worker_cpus):
                        worker = next(row for row in layout if row["name"] == f"vpp_wk_{index}")
                        status = device.root(f"cat /proc/{pid}/task/{worker['tid']}/status")
                        (cell / f"worker-{index}-affinity.txt").write_text(status)
                        allowed = re.search(r"^Cpus_allowed_list:\s*(\S+)$", status, re.M)
                        if worker["lcore"] != cpu or not allowed or allowed[1] != str(cpu):
                            raise RuntimeError("actual worker affinity differs from frozen CPU selection")
                flow_rows = rows(diagnostic, "flow.runtime ")
                occupancy = sum(int(v["entries"]) for v in rows(diagnostic, "flow.pool "))
                capacity = sum(int(v["capacity"]) for v in flow_rows)
                if len(flow_rows) != 2 or not capacity or occupancy > capacity // 10:
                    raise RuntimeError("Flow table is already busy before pressure: " + str(occupancy))
                if any(int(v["capacity_misses"]) for v in flow_rows):
                    raise RuntimeError("Flow capacity miss before pressure")
                peer_key = "0" * 24 + socket.inet_aton(manifest["peer_host"]).hex()
                expected_uid = manifest["uid"] if profile == "root" else 2000
                attributed = [v for v in rows(diagnostic, "flow.entry ")
                              if v.get("protocol") == "6" and int(v.get("uid", -1)) == expected_uid
                              and ((v.get("key_a") == peer_key and int(v.get("port_a", 0)) == manifest["peer_port"])
                                   or (v.get("key_b") == peer_key and int(v.get("port_b", 0)) == manifest["peer_port"]))]
                if fresh_lifetime and not attributed:
                    raise RuntimeError("warmup lacks a VPP FlowEntry attributed to the actual traffic UID and peer")
                (cell / "warm-flow-evidence.json").write_text(json.dumps(attributed, indent=2) + "\n")
                peer_before = peer_query(manifest["peer_host"], manifest["peer_port"], case_id, "R")
                peer_since = time.monotonic()
                remote_cpu = run_remote + "/" + profile + "-" + case + "-cpu.jsonl"
                remote_perf = run_remote + "/" + profile + "-" + case + ".perf.data"
                monitor_ms = manifest["cell_ms"] + 750
                background = shlex.join([helper, "monitor", str(pid), str(monitor_ms)]) + " > " + shlex.quote(remote_cpu) + " 2>&1 < /dev/null & echo monitor=$!"
                if manifest["profiling"]:
                    perf = ["/system/bin/simpleperf", "record", "-p", str(pid), "--duration", str(monitor_ms / 1000), "-e", "cpu-clock", "-f", "199", "-g", "--clockid", "monotonic", "-o", remote_perf]
                    if callgraph == "fp":
                        perf.remove("-g")
                        perf.extend(["--call-graph", "fp"])
                    if mmap_pages is not None:
                        perf.extend(["-m", str(mmap_pages)])
                    if manifest.get("trace_offcpu"):
                        perf.append("--trace-offcpu")
                    background += "; " + shlex.join(perf) + " > " + shlex.quote(remote_perf + ".log") + " 2>&1 < /dev/null & echo profiler=$!"
                sampler_text = device.root(background)
                (cell / "samplers.txt").write_text(sampler_text)
                sampler_pids = properties(sampler_text)
                if not sampler_pids.get("monitor", "").isdigit() or (manifest["profiling"] and not sampler_pids.get("profiler", "").isdigit()):
                    raise RuntimeError("invalid sampler process identity")
                cpu_paths = []
                if manifest.get("system_cpu_accounting"):
                    cpu_paths = ["/proc/uptime", "/proc/stat"]
                    for worker in layout:
                        task = f"/proc/{pid}/task/{worker['tid']}"
                        cpu_paths.extend([task + "/stat", task + "/schedstat", task + "/status"])
                    cpu_paths.extend([f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/stats/time_in_state"
                                      for cpu in range(8)])
                    accounting_command = "for path in " + shlex.join(cpu_paths) + "; do printf 'PATH %s\\n' \"$path\"; cat \"$path\"; done; cat /proc/uptime"
                    (cell / "system-cpu-before.txt").write_text(device.root(accounting_command, check=False))
                argv = [helper, "client", manifest["peer_host"], str(manifest["peer_port"]), str(case_id), case, str(manifest["cell_ms"]), str(manifest["threads"]), str(manifest["flows_per_thread"])]
                if tcp_source_port is not None:
                    argv.extend([str(tcp_source_port), "1"])
                if client_cpu_mask is not None:
                    script = "cat /proc/self/status; echo BENCH_CLIENT_JSON; exec " + shlex.join(argv)
                    argv = ["/system/bin/taskset", client_cpu_mask, "/system/bin/sh", "-c", script]
                command = [*client_prefix, shlex.quote(shlex.join(argv))] if profile == "root" else [*client_prefix, *argv]
                if client_cpu_mask is not None:
                    command = ["shell", shlex.join(argv)]
                value = device.command(*command, timeout=manifest["cell_ms"] / 1000 + 2)
                if cpu_paths:
                    (cell / "system-cpu-after.txt").write_text(device.root(accounting_command, check=False))
                if client_cpu_mask is not None:
                    affinity, value = value.split("\nBENCH_CLIENT_JSON\n", 1)
                    (cell / "client-affinity.txt").write_text(affinity + "\n")
                    actual_mask = re.search(r"^Cpus_allowed:\s*([0-9a-fA-F,]+)$", affinity, re.M)
                    if not actual_mask or int(actual_mask[1].replace(",", ""), 16) != int(client_cpu_mask, 16):
                        raise RuntimeError("actual client CPU affinity differs from frozen mask")
                (cell / "client.json").write_text(value)
                client = json.loads(value)
                if tcp_source_port is not None and (client["fixed_source_port_base"] != tcp_source_port or client["fixed_source_port_stride"] != 1):
                    raise RuntimeError("traffic helper did not use the frozen TCP source ports")
                if client["uid"] != (manifest["uid"] if profile == "root" else 2000):
                    raise RuntimeError("traffic helper UID is outside the intended capture profile")
                after = device.cli(profile, commands)
                (cell / "after-cli.txt").write_text(after)
                peer = peer_query(manifest["peer_host"], manifest["peer_port"], case_id)
                peer["measurement_cpu_seconds"] = peer["peer_cpu_seconds"] - peer_before["peer_cpu_seconds"]
                peer["measurement_wall_seconds"] = time.monotonic() - peer_since
                peer["cpu_percent_one_core"] = peer["measurement_cpu_seconds"] / peer["measurement_wall_seconds"] * 100
                (cell / "peer.json").write_text(json.dumps(peer, indent=2) + "\n")
                cpu_raw = device.root("cat " + shlex.quote(remote_cpu))
                (cell / "cpu.jsonl").write_text(cpu_raw)
                cpu = monitor_summary(cpu_raw, client)
                # Stop the owned profiler normally so its raw data is flushed before VPP exits.
                stop_commands = []
                for name, sample_pid in sampler_pids.items():
                    if sample_pid.isdigit():
                        stop_commands.append("kill -" + ("INT " if name == "profiler" else "TERM ") + sample_pid + " 2>/dev/null || true")
                device.root("; ".join(stop_commands))
                if manifest.get("profiler_await_exit") and manifest["profiling"]:
                    sample_pid = sampler_pids["profiler"]
                    # Wait for the owned record process to finish flushing, so
                    # perf.log and perf.data describe the same completed file.
                    device.root("n=0; while [ -r /proc/" + sample_pid + "/stat ]; do "
                                "[ \"$(cut -d ' ' -f 3 /proc/" + sample_pid + "/stat)\" = Z ] && break; "
                                "[ $n -lt 150 ] || exit 81; n=$((n+1)); sleep 0.05; done")
                sampler_pids = {}
                if manifest["profiling"]:
                    log = device.root("cat " + shlex.quote(remote_perf + ".log"))
                    (cell / "perf.log").write_text(log)
                try:
                    if vpn_only:
                        validate_vpn_window(running["generation"], client, diagnostic, after)
                    validate_capture_window(profile, client, diagnostic, after)
                except RuntimeError:
                    if profile == 'root':
                        (cell / 'capture-failure-kernel.txt').write_text(device.root(
                            'cat /proc/net/netfilter/nfnetlink_queue; iptables -t mangle -nvL',
                            check=False, cleanup=True))
                    raise
                stopped_lifetime = fresh_each_case or case in ("tcp-new", "udp-new")
                if stopped_lifetime:
                    if vpn_only:
                        if retained_log is None:
                            retained_log = run_remote + "/" + case + "-native.log"
                            device.retain_vpn_log(retained_log)
                    device.action("--ez", "runtimeStop", "true")
                    final = device.wait_state("stopped")
                    device.wait_process_gone("libvpp_runtime.so")
                    # The visible stopped projection can precede the Android
                    # Service's final onDestroy/query callbacks. Only after
                    # native exit, close the test app before the next lifetime.
                    device.command("shell", "am", "force-stop", PACKAGE)
                    device.wait_process_gone(PACKAGE + ":runtime")
                    active = False
                    (cell / "stopped.json").write_text(json.dumps(final, indent=2) + "\n")
                    if vpn_only:
                        native_stop = device.read_retained_vpn_log(retained_log)
                        (cell / "native-stop.txt").write_text(native_stop)
                        retained_log = None
                        validate_vpn_stop(native_stop, running["generation"])
                if profile == "root" and stopped_lifetime:
                    tail = device.command("shell", "run-as", PACKAGE, "tail", "-n", "12", "files/product-state/s242-last-stop.log")
                    (cell / "native-stop.txt").write_text(tail)
                    audit = rows(tail, "s242 event=stop_native_zero ")
                    if len(audit) != 1 or audit[0].get("generation") != running["generation"] or any(audit[0].get(k) != "0" for k in ("ready_mask", "graph_enabled", "graph_accepting", "pending", "buffers", "obligations", "handoffs", "completion_frames")):
                        raise RuntimeError("Root native stop audit does not settle this generation")
                    cleanup_audit = device.command("shell", "run-as", PACKAGE, "cat", "files/product-state/s176-root-nfqueue-cleanup.properties")
                    (cell / "root-residue.properties").write_text(cleanup_audit)
                    if properties(cleanup_audit).get("productRootNfqueueResidueClean") != "true":
                        raise RuntimeError("Root capture hooks/queues remain after normal stop")
                result["cases"].append({"profile": profile, "case": case, "generation": running["generation"],
                                        "vpp_pid": pid, "wall_seconds": time.monotonic() - started,
                                        "client": client, "peer": peer, "cpu": cpu,
                                        "worker_layout": layout,
                                        "score": score(client, peer, cpu, after, diagnostic),
                                        "perf_remote": remote_perf if manifest["profiling"] else None})
                (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
                score_value = result["cases"][-1]["score"]
                print(profile, case, json.dumps({key: score_value[key] for key in
                      ("delivered_mbps", "completed_cps", "input_unique_udp_tuples_per_second", "p99_upper_us", "latency_samples", "flow_capacity_misses", "root_unadmitted_accepts")}), flush=True)
        if len(result["cases"]) == len(profiles) * len(cases):
            result["status"] = "COMPLETE"
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
        if vpn_only and active and retained_log is None:
            try:
                (output / "native-start-failure.txt").write_text(device.command(
                    "shell", "run-as", PACKAGE, "cat", "files/profiles/vpn/vpp/logs/vpp-stdout.log",
                    check=False, cleanup=True))
            except Exception as evidence_error:
                result["errors"].append("native startup evidence: " + str(evidence_error))
    finally:
        if sampler_pids:
            try:
                device.root("; ".join("kill -" + ("INT " if name == "profiler" else "TERM ") + pid + " 2>/dev/null || true"
                                      for name, pid in sampler_pids.items() if pid.isdigit()), cleanup=True)
            except Exception as error:
                result["errors"].append("sampler cleanup: " + str(error))
        if active:
            try:
                device.action("--ez", "runtimeStop", "true", cleanup=True)
                device.wait_state("stopped", cleanup=True)
                device.wait_process_gone("libvpp_runtime.so", cleanup=True)
                device.command("shell", "am", "force-stop", PACKAGE, cleanup=True)
                device.wait_process_gone(PACKAGE + ":runtime", cleanup=True)
            except Exception as error:
                result["errors"].append("cleanup: " + str(error))
        if initial is not None and initial.get("state") == "stopped":
            try:
                result["final_runtime"] = device.state(cleanup=True)
                result["final_processes"] = device.command("shell", "pidof", "libvpp_runtime.so", check=False, cleanup=True).strip()
                actual_rules = device.root("sha256sum " + manifest["rules_path"], cleanup=True).split()[0]
                result["rules_unchanged"] = actual_rules == manifest["rules_sha256"]
                if result["final_runtime"].get("state") != "stopped" or result["final_runtime"].get("mayBeActive") != "false" or result["final_processes"] or not result["rules_unchanged"]:
                    result["errors"].append("final cleanup or rules identity failed")
            except Exception as error:
                result["errors"].append("final audit: " + str(error))
        if retained_log is not None:
            try:
                (cell / "native-failure.txt").write_text(
                    device.read_retained_vpn_log(retained_log, cleanup=True))
            except Exception as error:
                result["errors"].append("native failure evidence: " + str(error))
        result["elapsed_seconds"] = time.monotonic() - entry
        if result["elapsed_seconds"] > 120 or result["errors"]:
            result["status"] = "INCOMPLETE"
        result["offline_perf_collection"] = "retained on device; pull and render separately after the timed run"
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"status": result["status"], "elapsed_seconds": result["elapsed_seconds"], "cases": len(result["cases"]), "errors": result["errors"], "output": str(output)}, indent=2))
    return 0 if result["status"] == "COMPLETE" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    prep = sub.add_parser("prepare", help="one-time build/upload, outside the daily 120-second budget")
    prep.add_argument("--serial", default=SERIAL)
    prep.add_argument("--output", type=Path, required=True)
    prep.add_argument("--clang", type=Path, default=NDK_CLANG)
    prep.add_argument("--peer", required=True)
    prep.add_argument("--bind", default="0.0.0.0")
    prep.add_argument("--port", type=int, default=40720)
    prep.add_argument("--cell-ms", type=int, choices=(5000, 6000, 8000, 10000, 20000), default=5000,
                      help="fixed measurement window, frozen in the manifest before B0")
    prep.add_argument("--no-profile", action="store_true")
    prep.add_argument("--suite", choices=("root-vpn-v1", *VPN_SUITES), default="root-vpn-v1",
                      help="VPN suites freeze their workloads; ordinary-vpn-tcp-fixed-v1 measures only fixed TCP download")
    measure = sub.add_parser("run")
    measure.add_argument("--manifest", type=Path, required=True)
    measure.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "prepare":
        prepare(args)
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
