#!/usr/bin/env python3
"""Exercise campaign overrides and recovery around a failed real collector call."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import s307_vpn_tuning as tuning


def campaign(folder, *, fail=False, wifi="Openwrt_5G", profile=False):
    events, manifests = [], []
    apk, restore = folder / "candidate.apk", folder / "restore.apk"
    apk.write_bytes(b"candidate")
    restore.write_bytes(b"restore")
    prepared = dict(serial="test", uid=12345, peer_host="127.0.0.1", peer_port=41723,
                    threads=4, flows_per_thread=16, udp_fixed_source_port_base=25000,
                    udp_burst_size=1, primary_handoff_credits=48, vpn_capture_batch_size=64,
                    profiling=True, trace_offcpu=True, profiler_callgraph="dwarf",
                    collector_sha256=tuning.quick.digest(tuning.quick.__file__))
    plan = [dict(label="control", apk=str(apk), credits=32, capture_batch=1),
            dict(label="tcp", apk=str(apk), credits=48, capture_batch=64, case="tcp-fixed"),
            dict(label="native-default", apk=str(apk), credits=32)]
    if profile:
        plan[1]["profile"] = "offcpu"
    (folder / "prepared.json").write_text(json.dumps(prepared))
    (folder / "plan.json").write_text(json.dumps(plan))

    class Device:
        def __init__(self, *args, **kwargs):
            pass

        def state(self):
            return dict(state="stopped", mayBeActive="false")

        def command(self, *args, **kwargs):
            events.append("command:" + " ".join(map(str, args)))
            return f'Wifi is connected to "{wifi}"' if "wifi" in args else ""

        def action(self, *args, **kwargs):
            events.append("stop")

        def wait_state(self, *args, **kwargs):
            events.append("stopped")

        def wait_process_gone(self, name, **kwargs):
            events.append("gone:" + name)

    def install(device, path, output, uid):
        events.append("install:" + Path(path).name)
        return "/data/test.apk", tuning.quick.digest(path)

    def collect(command, **kwargs):
        manifests.append(json.loads(Path(command[command.index("--manifest") + 1]).read_text()))
        if fail:
            raise RuntimeError("injected collector failure")
        output = Path(command[command.index("--output") + 1])
        output.mkdir()
        cases = []
        if manifests[-1]["profiling"]:
            (output / "vpn-tcp-fixed").mkdir()
            cases = [dict(profile="vpn", case="tcp-fixed", perf_remote="/data/test.perf.data")]
        (output / "result.json").write_text(json.dumps(dict(status="COMPLETE", errors=[], cases=cases)))
        return type("Completed", (), dict(returncode=0))()

    argv = ["s307_vpn_tuning.py", "--plan", str(folder / "plan.json"),
            "--prepared", str(folder / "prepared.json"), "--restore-apk", str(restore),
            "--output", str(folder / "output")]
    with patch.object(tuning.quick, "Device", Device), patch.object(tuning.quick, "peer_query"), \
            patch.object(tuning, "install", install), patch.object(tuning.subprocess, "run", collect), \
            patch.object(tuning.sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()):
        status = tuning.main()
    return status, events, manifests, json.loads((folder / "output/campaign.json").read_text())


with tempfile.TemporaryDirectory(prefix="s307-campaign-check-") as temporary:
    root = Path(temporary)
    success = root / "success"
    success.mkdir()
    code, events, manifests, report = campaign(success)
    assert code == 0 and report["status"] == "COMPLETE" and not report["errors"]
    assert manifests[0]["primary_handoff_credits"] == 32 and manifests[0]["vpn_capture_batch_size"] == 1
    assert manifests[0]["udp_fixed_source_port_base"] == 25000
    assert manifests[1]["suite"] == tuning.quick.VPN_TCP_SUITE
    assert manifests[1]["tcp_fixed_source_port_base"] == 26100
    assert not any(key.startswith("udp_") for key in manifests[1])
    assert "vpn_capture_batch_size" not in manifests[2]
    assert tuning.quick.digest(success / "output/plan.json") == report["plan_sha256"]
    assert events.count("install:candidate.apk") == 1
    failure = root / "failure"
    failure.mkdir()
    code, events, manifests, report = campaign(failure, fail=True)
    assert code == 1 and "injected collector failure" in report["errors"][0]
    assert events.index("stop") < events.index("stopped") < events.index("gone:libvpp_runtime.so")
    assert events.index("gone:libvpp_runtime.so") < events.index("install:restore.apk")
    assert report["final_runtime"]["state"] == "stopped" and not report["final_vpp_pid"]
    preflight = root / "preflight"
    preflight.mkdir()
    code, events, manifests, report = campaign(preflight, wifi="CU_7WFb_5G")
    assert code == 1 and report["errors"][0].startswith("preflight:")
    assert not any(event.startswith("install:") for event in events)
    assert not manifests
    profiled = root / "profiled"
    profiled.mkdir()
    code, events, manifests, report = campaign(profiled, profile=True)
    assert code == 0
    assert not manifests[0]["profiling"] and not manifests[0]["trace_offcpu"]
    assert manifests[1]["profiling"] and manifests[1]["trace_offcpu"]
    assert manifests[1]["profiler_callgraph"] == "fp"
    assert not manifests[2]["profiling"] and not manifests[2]["trace_offcpu"]
    assert any(event.startswith("command:pull /data/test.perf.data") for event in events)
print("PASS S307 inherited overrides, TCP isolation, partial campaign recovery, retained preflight failure")
