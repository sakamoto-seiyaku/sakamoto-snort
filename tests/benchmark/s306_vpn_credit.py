#!/usr/bin/env python3
"""Run a bounded 32/48/48/32 primary-credit probe on one Product VPN APK."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

import pixel_quick as quick
from s304_vpn_topology import install, save


ROOT = Path(__file__).resolve().parents[2]
SCHEDULE = (("B32-1", 32), ("B48-1", 48), ("B48-2", 48), ("B32-2", 32))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--restore-apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offcpu", action="store_true",
                        help="one separate 32-credit sched trace window")
    parser.add_argument("--repeat32", action="store_true",
                        help="two 32-credit windows for a single-variable candidate")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    prepared = json.loads(args.prepared.read_text())
    if (prepared.get("suite") != quick.VPN_UDP_SUITE
            or prepared.get("cell_ms") != 5000
            or prepared.get("profiling") is not False
            or prepared.get("threads") != 4
            or prepared.get("flows_per_thread") != 16
            or prepared.get("udp_offered_rate") != 8000
            or prepared.get("udp_burst_size") != 1
            or prepared.get("collector_sha256") != quick.digest(quick.__file__)):
        raise RuntimeError("prepared workload or collector differs from S304 paced UDP")
    device = quick.Device(prepared["serial"], output, control_timeout=15)
    initial = device.state()
    save(output / "initial-runtime.json", initial)
    if initial.get("state") != "stopped" or initial.get("mayBeActive") != "false":
        raise RuntimeError("Product runtime must be stopped")
    wifi = device.command("shell", "cmd", "wifi", "status")
    (output / "initial-wifi.txt").write_text(wifi)
    if 'Wifi is connected to "Openwrt_5G"' not in wifi:
        raise RuntimeError("Pixel is not on the controlled LAN")
    quick.peer_query(prepared["peer_host"], prepared["peer_port"], 0)
    if args.offcpu and args.repeat32:
        raise ValueError("select one campaign shape")
    schedule = ((("B32-offcpu", 32),) if args.offcpu else
                (("B32-1", 32), ("B32-2", 32)) if args.repeat32 else SCHEDULE)
    report = dict(schema="s306-vpn-credit/v1", status="INCOMPLETE",
                  started_utc_ns=time.time_ns(),
                  prepared=str(args.prepared.resolve()),
                  runner_sha256=quick.digest(__file__),
                  schedule=[dict(label=name, credits=credits) for name, credits in schedule],
                  runs=[], errors=[])
    save(output / "campaign.json", report)
    try:
        installed, apk_hash = install(device, args.apk, output / "install", prepared["uid"])
        for label, credits in schedule:
            manifest = dict(prepared, apk=installed, apk_sha256=apk_hash,
                            worker_cpu_ids=[1, 2], tun_io_cpu_id=3,
                            client_cpu_mask="10", system_cpu_accounting=True,
                            minimum_native_buffers=2048,
                            expected_native_buffer_count=2048,
                            expected_native_buffer_data_bytes=10240,
                            campaign_label=label, prepared_utc_ns=time.time_ns())
            manifest["primary_handoff_credits"] = credits
            if args.offcpu:
                manifest.update(profiling=True, trace_offcpu=True,
                                profiler_callgraph="fp", profiler_mmap_pages=4096,
                                profiler_await_exit=True)
            path = output / ("manifest-" + label + ".json")
            save(path, manifest)
            run = output / ("run-" + label)
            with (output / ("run-" + label + ".log")).open("w") as log:
                code = subprocess.run([sys.executable,
                                       str(ROOT / "tests/benchmark/pixel_quick.py"),
                                       "run", "--manifest", str(path), "--output", str(run)],
                                      stdout=log, stderr=subprocess.STDOUT).returncode
            result = json.loads((run / "result.json").read_text())
            report["runs"].append(dict(label=label, credits=credits,
                                       returncode=code, status=result["status"],
                                       result=str(run / "result.json")))
            save(output / "campaign.json", report)
            print(label, result["status"], result.get("errors"), flush=True)
            if code or result["status"] != "COMPLETE":
                report["errors"].append(label + ": collector incomplete; raw attempt retained")
                break
        if not report["errors"] and len(report["runs"]) == len(schedule):
            report["status"] = "COMPLETE"
    except Exception as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        try:
            # Recover a failed collector before the installer enforces stopped state.
            device.action("--ez", "runtimeStop", "true", cleanup=True)
            device.wait_state("stopped", cleanup=True)
            device.wait_process_gone("libvpp_runtime.so", cleanup=True)
            device.command("shell", "am", "force-stop", quick.PACKAGE, cleanup=True)
            device.wait_process_gone(quick.PACKAGE + ":runtime", cleanup=True)
            installed, apk_hash = install(device, args.restore_apk,
                                          output / "install-restore", prepared["uid"])
            report["restored_apk_sha256"] = apk_hash
            report["restored_installed_path"] = installed
            report["final_runtime"] = device.state()
            report["final_wifi"] = device.command("shell", "cmd", "wifi", "status")
            report["final_vpp_pid"] = device.command(
                "shell", "pidof", "libvpp_runtime.so", check=False).strip()
            if report["final_runtime"].get("state") != "stopped" or report["final_vpp_pid"]:
                report["errors"].append("final Product runtime is not stopped")
        except Exception as error:
            report["errors"].append("restoration: " + type(error).__name__ + ": " + str(error))
        report["completed_utc_ns"] = time.time_ns()
        save(output / "campaign.json", report)
    print(json.dumps(dict(status=report["status"], errors=report["errors"],
                          output=str(output)), indent=2))
    return 0 if report["status"] == "COMPLETE" and not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
