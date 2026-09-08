#!/usr/bin/env python3
"""Bounded Pixel cells. Every device operation goes through repo-local dev/adb."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import shlex
import subprocess
import time

HERE = Path(__file__).resolve().parent
POC = HERE.parent
REPO = POC.parent.parent
WORK = POC / "work/s245-s246"
ADB = REPO / "dev/adb"
SERIAL = "28201JEGR0XPAJ"
PACKAGE = "com.sakamoto.snort.vpnlite"


def adb(*args, check=True, timeout=30):
    p = subprocess.run([str(ADB), "-s", SERIAL, *map(str, args)],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    output = p.stdout.decode(errors="replace").replace("\r", "")
    if check and p.returncode:
        raise RuntimeError(output)
    return output


def app_shell(command, check=True):
    return adb("shell", "run-as " + PACKAGE + " sh -c " + shlex.quote(command), check=check)


def activity(*args):
    return adb("shell", "am", "start", "-W", "-n", PACKAGE + "/.MainActivity", *args)


def read_log(path):
    return app_shell("cat " + shlex.quote("files/" + path), check=False)


def has_vpp(processes):
    return any("libvpppoc.so" in line or line.split()[1:2] in (["vpp"], ["vpp_main"])
               for line in processes.splitlines())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", type=int, choices=range(11))
    parser.add_argument("--install", action="store_true")
    args = parser.parse_args()
    run_dir = POC / "evidence" / ("s245-s246-" + time.strftime("%Y%m%d-%H%M%S") + "-mode" + str(args.mode))
    run_dir.mkdir(parents=True)
    print(run_dir, flush=True)
    apk = WORK / "app/build/outputs/snort-vpn-lite-debug.apk"
    manifest = {"mode": args.mode, "serial": SERIAL, "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
                "artifact_manifest_sha256": hashlib.sha256((WORK / "artifact-source-sha256.json").read_bytes()).hexdigest(),
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (run_dir / "device.txt").write_text(adb("shell", "getprop ro.build.fingerprint; uname -a"))
    before = adb("shell", "ps -A -o PID,NAME,ARGS")
    (run_dir / "process-before.txt").write_text(before)
    if has_vpp(before):
        raise RuntimeError("A VPP process is already active; preserve it and inspect ownership")
    if args.install:
        (run_dir / "install.txt").write_text(adb("install", "-r", apk, timeout=60))
    adb("shell", "pm", "grant", PACKAGE, "android.permission.POST_NOTIFICATIONS", check=False)
    app_shell("mkdir -p files/logs files/vpp/logs")
    app_shell("printf '%s' " + shlex.quote(str(args.mode)) + " > files/s245-mode")
    app_shell("rm -f files/logs/s245-app.log files/logs/vpp-oi3-controlled-app.log files/vpp/logs/vpp-stdout.log files/vpp/logs/vpp-cli.log files/vpp/logs/vpp-protect.log")
    package = adb("shell", "dumpsys", "package", PACKAGE)
    (run_dir / "package.txt").write_text(package)
    code_path = re.search(r"codePath=(\S+)", package).group(1)
    names = ("libvpppoc.so", "libhev-socks5-tunnel.so", "libhev_external_driver_poc_plugin.so", "libvpnfdprobe.so")
    installed = app_shell("sha256sum " + " ".join(shlex.quote(code_path + "/lib/arm64/" + name) for name in names))
    (run_dir / "installed-native-sha256.txt").write_text(installed)
    intended = {name: hashlib.sha256((WORK / "app/build/jni/lib/arm64-v8a" / name).read_bytes()).hexdigest() for name in names}
    if any(digest not in installed for digest in intended.values()):
        raise RuntimeError("Installed artifact hashes differ from the current build")
    try:
        (run_dir / "start.txt").write_text(activity("--ez", "start", "true", "--es", "mode", "vpp-oi3-controlled",
            "--es", "allowedPackage", PACKAGE, "--ez", "enableIpv6", "false"))
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            time.sleep(1)
            app_log = read_log("logs/s245-app.log")
            runtime_log = read_log("vpp/logs/vpp-stdout.log")
            if "received signal" in runtime_log or "unknown input" in runtime_log:
                print("Runtime startup failure: preserving and stopping", flush=True)
                break
            if "seq=3" in app_log:
                print(app_log.strip(), flush=True)
                break
        (run_dir / "show.txt").write_text(activity("--es", "oi3Control", "show"))
        (run_dir / "stop-control.txt").write_text(activity("--es", "oi3Control", "stop"))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            time.sleep(0.5)
            if "oi3_cleanup" in read_log("vpp/logs/vpp-stdout.log"):
                break
    finally:
        for name, path in {
            "app.log": "logs/s245-app.log", "app-controlled.log": "logs/vpp-oi3-controlled-app.log",
            "vpp.log": "vpp/logs/vpp-stdout.log", "cli.log": "vpp/logs/vpp-cli.log",
            "protect.log": "vpp/logs/vpp-protect.log", "hev.log": "vpp/logs/vpp-hev.log",
            "broker.log": "vpp/logs/vpp-oi3-broker.log",
        }.items():
            (run_dir / name).write_text(read_log(path))
        (run_dir / "stop.txt").write_text(activity("--ez", "stop", "true"))
        time.sleep(2)
        (run_dir / "broker-after-stop.log").write_text(read_log("vpp/logs/vpp-oi3-broker.log"))
        adb("shell", "am", "force-stop", PACKAGE)
        time.sleep(1)
        after = adb("shell", "ps -A -o PID,NAME,ARGS")
        (run_dir / "process-after.txt").write_text(after)
        (run_dir / "logcat.txt").write_text(adb("logcat", "-d", "-t", "400", check=False))
        if has_vpp(after):
            raise RuntimeError("VPP process remains after bounded stop")
    print("Cell stopped; raw evidence saved. Acceptance requires verifier review.", flush=True)


if __name__ == "__main__":
    main()
