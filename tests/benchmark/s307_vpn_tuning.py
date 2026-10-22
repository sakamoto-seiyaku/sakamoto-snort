#!/usr/bin/env python3
"""Run explicit bounded VPN tuning cells, retaining every attempt and restoring APK."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pixel_quick as quick
from s304_vpn_topology import install, save


ROOT = Path(__file__).resolve().parents[2]
ALLOWED = {"label", "apk", "credits", "rate", "owners", "case", "mechanism", "capture_batch"}


def cells(plan, prepared):
    if (prepared.get("udp_fixed_source_port_base") != 25000
            or prepared.get("threads") != 4 or prepared.get("flows_per_thread") != 16
            or prepared.get("udp_burst_size") != 1
            or prepared.get("collector_sha256") != quick.digest(quick.__file__)):
        raise ValueError("requires original S304 tuples, helper layout and current collector")
    labels = set()
    for cell in plan:
        if (set(cell) - ALLOWED or not cell.get("label")
                or cell["label"] in labels or "/" in cell["label"]
                or cell["label"] in (".", "..")
                or cell.get("credits") not in (32, 48)
                or cell.get("owners", 2) not in (1, 2, 3)
                or cell.get("case", "udp-fixed") not in ("udp-fixed", "tcp-fixed")
                or cell.get("rate", 8000) not in (4000, 8000, 12000, 16000)
                or ("capture_batch" in cell and
                    (type(cell["capture_batch"]) is not int or not 1 <= cell["capture_batch"] <= 64))
                or not Path(cell.get("apk", "")).is_file()):
            raise ValueError("unsupported or duplicate tuning cell: " + repr(cell))
        labels.add(cell["label"])
    if not labels:
        raise ValueError("empty tuning plan")
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--restore-apk", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepared = json.loads(args.prepared.read_text())
    plan = cells(json.loads(args.plan.read_text()), prepared)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(args.plan, output / "plan.json")
    device = quick.Device(prepared["serial"], output, control_timeout=15)
    report = dict(schema="s307-vpn-tuning/v1", status="INCOMPLETE",
                  started_utc_ns=time.time_ns(), prepared=str(args.prepared.resolve()),
                  plan_sha256=quick.digest(args.plan), runner_sha256=quick.digest(__file__),
                  collector_sha256=quick.digest(quick.__file__), runs=[], errors=[])
    save(output / "campaign.json", report)
    try:
        initial = device.state()
        save(output / "initial-runtime.json", initial)
        wifi = device.command("shell", "cmd", "wifi", "status")
        (output / "initial-wifi.txt").write_text(wifi)
        if (initial.get("state") != "stopped" or initial.get("mayBeActive") != "false"
                or 'Wifi is connected to "Openwrt_5G"' not in wifi):
            raise RuntimeError("requires stopped runtime on saved controlled LAN")
        quick.peer_query(prepared["peer_host"], prepared["peer_port"], 0)
    except Exception as error:
        report["errors"].append("preflight: " + type(error).__name__ + ": " + str(error))
        report["completed_utc_ns"] = time.time_ns()
        save(output / "campaign.json", report)
        print(json.dumps(report, indent=2))
        return 1
    current_apk = None
    try:
        for index, cell in enumerate(plan):
            label = cell["label"]
            apk = Path(cell["apk"]).resolve()
            if apk != current_apk:
                installed, apk_hash = install(device, apk, output / ("install-" + label), prepared["uid"])
                current_apk = apk
            case = cell.get("case", "udp-fixed")
            owner_count = cell.get("owners", 2)
            manifest = dict(prepared, apk=installed, apk_sha256=apk_hash,
                            suite=quick.VPN_UDP_SUITE if case == "udp-fixed" else quick.VPN_TCP_SUITE,
                            profiles=["vpn"], cases=[case], cell_ms=5000 if case == "udp-fixed" else 20000,
                            worker_cpu_ids=[1, 2, 1][:owner_count], tun_io_cpu_id=3,
                            client_cpu_mask="10", system_cpu_accounting=True,
                            profiling=False, minimum_native_buffers=2048,
                            expected_native_buffer_count=2048, expected_native_buffer_data_bytes=10240,
                            campaign_label=label, primary_handoff_credits=cell["credits"],
                            udp_offered_rate=cell.get("rate", 8000), prepared_utc_ns=time.time_ns())
            # Older experimental APKs predate this CLI. Omission requests their
            # native default, never a setting inherited from a prepared arm.
            manifest.pop("vpn_capture_batch_size", None)
            if "capture_batch" in cell:
                manifest["vpn_capture_batch_size"] = cell["capture_batch"]
            if case == "tcp-fixed":
                for key in ("udp_fixed_source_port_base", "udp_offered_rate", "udp_burst_size"):
                    manifest.pop(key, None)
                manifest["tcp_fixed_source_port_base"] = 26000 + index * 100
            path = output / ("manifest-" + label + ".json")
            save(path, manifest)
            run = output / ("run-" + label)
            with (output / ("run-" + label + ".log")).open("w") as log:
                code = subprocess.run([sys.executable, str(ROOT / "tests/benchmark/pixel_quick.py"),
                                       "run", "--manifest", str(path), "--output", str(run)],
                                      stdout=log, stderr=subprocess.STDOUT).returncode
            result = json.loads((run / "result.json").read_text())
            report["runs"].append(dict(cell, returncode=code, status=result["status"],
                                       result=str(run / "result.json")))
            save(output / "campaign.json", report)
            print(label, result["status"], result.get("errors"), flush=True)
            if code or result["status"] != "COMPLETE":
                report["errors"].append(label + ": collector incomplete; raw attempt retained")
                break
        if not report["errors"] and len(report["runs"]) == len(plan):
            report["status"] = "COMPLETE"
    except Exception as error:
        report["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        try:
            device.action("--ez", "runtimeStop", "true", cleanup=True)
            device.wait_state("stopped", cleanup=True)
            device.wait_process_gone("libvpp_runtime.so", cleanup=True)
            device.command("shell", "am", "force-stop", quick.PACKAGE, cleanup=True)
            device.wait_process_gone(quick.PACKAGE + ":runtime", cleanup=True)
            installed, apk_hash = install(device, args.restore_apk, output / "install-restore", prepared["uid"])
            report.update(restored_apk_sha256=apk_hash, restored_installed_path=installed,
                          final_runtime=device.state(),
                          final_wifi=device.command("shell", "cmd", "wifi", "status"),
                          final_vpp_pid=device.command("shell", "pidof", "libvpp_runtime.so", check=False).strip())
            if report["final_runtime"].get("state") != "stopped" or report["final_vpp_pid"]:
                report["errors"].append("final Product runtime is not stopped")
        except Exception as error:
            report["errors"].append("restoration: " + type(error).__name__ + ": " + str(error))
        report["completed_utc_ns"] = time.time_ns()
        save(output / "campaign.json", report)
    print(json.dumps(dict(status=report["status"], errors=report["errors"], output=str(output)), indent=2))
    return 0 if report["status"] == "COMPLETE" and not report["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
