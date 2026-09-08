#!/usr/bin/env python3
"""Bounded Pixel Product APK acceptance: VPN not-ready, Root start/stop."""
import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
SERIAL = "28201JEGR0XPAJ"
PACKAGE = "com.sakamoto.snort.androidruntime"
parser = argparse.ArgumentParser()
parser.add_argument("--apk", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)

def adb(*parts, check=True):
    r = subprocess.run([str(ROOT / "dev/adb"), "-s", SERIAL, *parts], text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    if check and r.returncode:
        raise RuntimeError(r.stdout)
    return r.stdout.replace("\r", "")

def save(name, value):
    (args.output / name).write_text(value)
    return value

def app(path, check=True):
    return adb("shell", "run-as", PACKAGE, "cat", path, check=check)

def action(*parts):
    return adb("shell", "am", "start", "-n", PACKAGE + "/.DebugControlActivity", *parts)

def wait(label, required):
    until = time.monotonic() + 30
    while time.monotonic() < until:
        s = save(label + ".poll.properties", app("files/runtime-state/snapshot.properties", False))
        d = dict(line.split("=", 1) for line in s.splitlines() if "=" in line and not line.startswith("#"))
        if all(d.get(k) == v for k, v in required.items()):
            save(label + ".properties", s)
            return d
        if d.get("errorCode") == "root_authorization_required" and required.get("profile") == "root":
            raise RuntimeError("Restore this app's KernelSU Superuser grant before Root acceptance")
        time.sleep(0.4)
    raise RuntimeError(label + " did not reach " + repr(required))

result = {"serial": SERIAL, "apk_sha256": hashlib.sha256(args.apk.read_bytes()).hexdigest()}
try:
    save("device.txt", adb("shell", "getprop", "ro.product.device") + adb("shell", "uname", "-a"))
    save("before.properties", app("files/runtime-state/snapshot.properties", False))
    save("install.txt", adb("install", "-r", str(args.apk.resolve())))
    package = save("package.txt", adb("shell", "dumpsys", "package", PACKAGE))
    native_dir = re.search(r"codePath=(\S+)", package).group(1) + "/lib/arm64"
    with zipfile.ZipFile(args.apk) as z:
        expected = {Path(name).name: hashlib.sha256(z.read(name)).hexdigest()
                    for name in z.namelist() if name.startswith("lib/arm64-v8a/") and name.endswith(".so")}
    installed = save("installed-native-sha256.txt", adb("shell", "sha256sum", *[native_dir + "/" + name for name in sorted(expected)]))
    actual = {Path(line.split()[1]).name: line.split()[0] for line in installed.splitlines()}
    assert expected == actual, "installed native payload differs from APK"
    result["native_sha256"] = expected
    adb("shell", "pm", "grant", PACKAGE, "android.permission.POST_NOTIFICATIONS", check=False)
    save("vpn-start.txt", action("--ez", "runtimeStart", "true", "--es", "runtimeProfile", "vpn"))
    wait("vpn-not-ready", {"profile":"vpn", "errorCode":"vpn_flow_stack_not_ready", "mayBeActive":"false", "protectionRunning":"false", "adapterReadiness":"unavailable"})
    save("vpn-process.txt", adb("shell", "ps", "-A", "-o", "PID,NAME,ARGS"))
    save("vpn-links.txt", adb("shell", "ip", "link"))
    save("root-start.txt", action("--ez", "runtimeStart", "true", "--es", "runtimeProfile", "root"))
    wait("root-running", {"profile":"root", "state":"running", "coreHealth":"ok", "protectionRunning":"true", "adapterReadiness":"root-nfqueue"})
    save("root-status.properties", app("files/product-state/s176-root-nfqueue-output.properties"))
    save("root-process.txt", adb("shell", "ps", "-A", "-o", "PID,NAME,ARGS"))
    save("stop.txt", action("--ez", "runtimeStop", "true"))
    wait("stopped", {"state":"stopped", "mayBeActive":"false", "errorCode":""})
    cleanup = save("cleanup.properties", app("files/product-state/s176-root-nfqueue-cleanup.properties"))
    assert "productRootNfqueueResidueClean=true" in cleanup
    after = save("process-after.txt", adb("shell", "ps", "-A", "-o", "PID,NAME,ARGS"))
    for text in ((args.output / "vpn-process.txt").read_text(), after):
        assert not any("libvpp_runtime.so" in line for line in text.splitlines())
    result["status"] = "PASS"
except Exception as e:
    result.update(status="HOLD", error=str(e))
    save("failure-stop.txt", action("--ez", "runtimeStop", "true"))
finally:
    save("service-log.txt", app("files/logs/runtime-service.log", False))
    save("result.json", json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
raise SystemExit(result["status"] != "PASS")
