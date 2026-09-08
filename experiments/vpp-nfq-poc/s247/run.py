#!/usr/bin/env python3
"""Run one bounded S247 cell on the explicitly selected Pixel 6a."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import time

HERE = Path(__file__).resolve().parent
POC = HERE.parent
WORK = POC / "work/s247"
spec = importlib.util.spec_from_file_location("s247_device", POC / "s245-s246/run.py")
device = importlib.util.module_from_spec(spec)
spec.loader.exec_module(device)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pattern", choices=("single", "delay", "burst", "sync", "stop"))
    parser.add_argument("--pbuf", type=int, choices=(1, 2, 4), default=4)
    parser.add_argument("--credit", type=int, choices=(1, 2, 4), default=4)
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    mode = 1 if args.pattern == "delay" else 10 if args.pattern in ("sync", "stop") else 0
    burst = 3 if args.pattern == "burst" else 1
    stop_overlap = int(args.pattern == "stop")
    out = POC / "evidence" / ("s247-" + time.strftime("%Y%m%d-%H%M%S") +
        f"-{args.pattern}-p{args.pbuf}-c{args.credit}")
    out.mkdir(parents=True)
    print(out, flush=True)
    apk = WORK / "app/build/outputs/snort-vpn-lite-debug.apk"
    manifest = dict(pattern=args.pattern, pbuf_limit=args.pbuf, credit_limit=args.credit,
        burst=burst, stop_overlap=stop_overlap, serial=device.SERIAL,
        started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),
        source_manifest_sha256=hashlib.sha256((WORK / "artifact-source-sha256.json").read_bytes()).hexdigest())
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "device.txt").write_text(device.adb("shell", "getprop ro.build.fingerprint; uname -a"))
    before = device.adb("shell", "ps -A -o PID,NAME,ARGS")
    (out / "process-before.txt").write_text(before)
    if device.has_vpp(before):
        raise RuntimeError("A VPP process is already running; preserve it")
    if args.install:
        (out / "install.txt").write_text(device.adb("install", "-r", apk, timeout=60))
    device.adb("shell", "pm", "grant", device.PACKAGE, "android.permission.POST_NOTIFICATIONS", check=False)
    device.app_shell("mkdir -p files/logs files/vpp/logs")
    device.app_shell("printf '%s' " + str(mode) + " > files/s245-mode")
    config = f"{args.pbuf} {args.credit} {burst} {stop_overlap}"
    device.app_shell("printf '%s' " + shlex.quote(config) + " > files/s247-config")
    device.app_shell("rm -f files/logs/s247-app.log files/logs/s245-app.log files/vpp/logs/vpp-stdout.log files/vpp/logs/vpp-cli.log")
    package = device.adb("shell", "dumpsys", "package", device.PACKAGE)
    (out / "package.txt").write_text(package)
    code_path = re.search(r"codePath=(\S+)", package).group(1)
    names = ("libvpppoc.so", "libhev-socks5-tunnel.so", "libhev_external_driver_poc_plugin.so", "libvpnfdprobe.so")
    installed = device.app_shell("sha256sum " + " ".join(shlex.quote(code_path + "/lib/arm64/" + n) for n in names))
    (out / "installed-native-sha256.txt").write_text(installed)
    if any(hashlib.sha256((WORK / "app/build/jni/lib/arm64-v8a" / n).read_bytes()).hexdigest() not in installed for n in names):
        raise RuntimeError("Installed artifact mismatch")
    try:
        (out / "start.txt").write_text(device.activity("--ez", "start", "true", "--es", "mode", "vpp-oi3-controlled",
            "--es", "allowedPackage", device.PACKAGE, "--ez", "enableIpv6", "false"))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            time.sleep(0.5)
            app = device.read_log("logs/s247-app.log")
            runtime = device.read_log("vpp/logs/vpp-stdout.log")
            if "received signal" in runtime or "unknown input" in runtime:
                print("Runtime error; stopping and preserving evidence", flush=True)
                break
            if "event=app_done" in app:
                print("\n".join(l for l in app.splitlines() if "event=app_result" in l), flush=True)
                break
        (out / "show.txt").write_text(device.activity("--es", "oi3Control", "show"))
        (out / "stop-control.txt").write_text(device.activity("--es", "oi3Control", "stop"))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if "oi3_cleanup" in device.read_log("vpp/logs/vpp-stdout.log"):
                break
            time.sleep(0.5)
    finally:
        for name, remote in {"app.log": "logs/s247-app.log", "vpp.log": "vpp/logs/vpp-stdout.log",
                             "cli.log": "vpp/logs/vpp-cli.log", "broker.log": "vpp/logs/vpp-oi3-broker.log"}.items():
            (out / name).write_text(device.read_log(remote))
        (out / "stop.txt").write_text(device.activity("--ez", "stop", "true"))
        time.sleep(2)
        (out / "broker-after-stop.log").write_text(device.read_log("vpp/logs/vpp-oi3-broker.log"))
        device.adb("shell", "am", "force-stop", device.PACKAGE)
        time.sleep(1)
        after = device.adb("shell", "ps -A -o PID,NAME,ARGS")
        (out / "process-after.txt").write_text(after)
        if device.has_vpp(after):
            raise RuntimeError("VPP residue after stop")
    print("Stopped; raw S247 evidence requires verification", flush=True)


if __name__ == "__main__":
    main()
