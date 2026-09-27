#!/usr/bin/env python3
"""Physical Pixel VPN Start/Query/Stop through the diagnostic Activity UI."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
PKG = "com.sakamoto.snort.androidruntime"
p = argparse.ArgumentParser()
p.add_argument("--serial-from", type=Path, required=True)
p.add_argument("--build", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
(out / "runner.py").write_bytes(Path(__file__).read_bytes())
serial = json.loads(a.serial_from.read_text())["serial"]
build = json.loads(a.build.read_text())
spec = importlib.util.spec_from_file_location("chain", ROOT / "tests/evidence/product_chain.py")
chain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chain)
assert chain.source_files() == build["files"]
result = dict(status="HOLD", task="T28", profile="vpn", scenario="ui-start-query-stop",
              source_sha256=build["source_sha256"], apk_sha256=build["apk_sha256"],
              build=str(a.build.resolve()), started_ns=time.time_ns(), ui_taps=[])

def save(name, value):
    (out / name).write_bytes(value if isinstance(value, bytes) else value.encode())
    return value

def adb(*args, check=True, binary=False):
    r = subprocess.run([str(ROOT / "dev/adb"), "-s", serial, *map(str, args)],
                       capture_output=True, timeout=45)
    with (out / "operations.jsonl").open("a") as f:
        f.write(json.dumps(dict(at_ns=time.time_ns(), argv=list(map(str, args)),
                                exit_code=r.returncode)) + "\n")
    if check and r.returncode:
        raise RuntimeError((r.stdout + r.stderr).decode(errors="replace"))
    return r.stdout if binary else (r.stdout + r.stderr).decode(errors="replace").replace("\r", "")

def state():
    text = adb("shell", "run-as", PKG, "cat", "files/runtime-state/snapshot.properties")
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)

def history_hashes():
    names = ("files/observation/overall.sqlite3", "files/observation/overall.json")
    return {name: adb("shell", "run-as", PKG, "sha256sum", name).split()[0] for name in names}

def launch():
    adb("shell", "am", "start", "-n", PKG + "/.DebugControlActivity")

def dump(label):
    adb("shell", "uiautomator", "dump", "/sdcard/t28-vpn-ui.xml")
    xml = save(label + ".xml", adb("shell", "cat", "/sdcard/t28-vpn-ui.xml"))
    return list(ET.fromstring(xml).iter("node"))

def bounds(node):
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
    if not match: return None
    x1, y1, x2, y2 = map(int, match.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2

def tap(label, name):
    height = int(re.search(r"(\d+)x(\d+)", adb("shell", "wm", "size"))[2])
    launch()
    if name in ("Start", "Stop"):
        for _ in range(5): adb("shell", "input", "swipe", 500, height // 4, 500, height * 3 // 4, 250)
    for attempt in range(16):
        nodes = dump(f"{label}-before-{attempt}")
        for node in nodes:
            if node.get("text") == name or node.get("content-desc") == name:
                point = bounds(node)
                if point and 0 <= point[1] < height:
                    adb("shell", "input", "tap", *point)
                    result["ui_taps"].append(dict(label=label, target=name, point=point))
                    return
        adb("shell", "input", "swipe", 500, height * 3 // 4, 500, height // 4, 400)
    raise AssertionError(name + " button not visible")

def ensure_vpn_selected():
    nodes = dump("profile-before")
    if any(n.get("class") == "android.widget.CheckedTextView" and n.get("text") == "VPN"
           for n in nodes): return
    spinner = next(n for n in nodes if n.get("class") == "android.widget.Spinner")
    adb("shell", "input", "tap", *bounds(spinner))
    option = next(n for n in dump("profile-options") if n.get("text") == "VPN" and bounds(n))
    adb("shell", "input", "tap", *bounds(option))
    assert any(n.get("class") == "android.widget.CheckedTextView" and n.get("text") == "VPN"
               for n in dump("profile-selected"))

def await_state():
    end = time.monotonic() + 40
    last = {}
    while time.monotonic() < end:
        last = state()
        if last.get("profile") == "vpn" and (last.get("state") in ("running", "error")
                or last.get("state") == "stopped" and last.get("errorCode") not in ("", "none")):
            return last
        time.sleep(.2)
    return last

def raw_query(label):
    nonce = "t28-vpn-ui-" + str(time.time_ns())
    name = "files/product-state/observation-" + nonce + ".json"
    adb("shell", "am", "start", "-n", PKG + "/.DebugControlActivity",
        "--es", "observationNonce", nonce, "--ei", "observationOperation", 0)
    end = time.monotonic() + 20
    while time.monotonic() < end:
        raw = adb("shell", "run-as", PKG, "cat", name, check=False)
        try: value = json.loads(raw)
        except json.JSONDecodeError: value = None
        if value is not None:
            save(label + ".json", json.dumps(value, indent=2) + "\n")
            adb("shell", "run-as", PKG, "rm", "-f", name)
            return value
        time.sleep(.2)
    raise AssertionError("typed query deadline")

try:
    before = state()
    assert before["state"] == "stopped" and before["mayBeActive"] == "false"
    save("before.properties", "\n".join(f"{k}={v}" for k, v in before.items()) + "\n")
    original = history_hashes()
    save("before-original-hashes.json", json.dumps(original, indent=2) + "\n")
    package = adb("shell", "dumpsys", "package", PKG)
    code_path = re.search(r"codePath=(\S+)", package)[1]
    assert adb("shell", "sha256sum", code_path + "/base.apk").split()[0] == build["apk_sha256"]
    launch()
    ensure_vpn_selected()
    tap("vpn-start", "Start")
    for attempt in range(6):
        nodes = dump(f"vpn-authorization-{attempt}")
        choice = next((n for n in nodes if n.get("text") in ("OK", "Allow", "Connect")
                       and bounds(n) and n.get("clickable") == "true"), None)
        if choice is None: break
        adb("shell", "input", "tap", *bounds(choice))
        result["ui_taps"].append(dict(label="vpn-authorization", target=choice.get("text")))
        time.sleep(.5)
    running = await_state()
    result["after_start"] = running
    save("after-start.properties", "\n".join(f"{k}={v}" for k, v in running.items()) + "\n")
    available = running["state"] == "running"
    if not available:
        assert running["state"] == "stopped" and running["errorCode"] == "vpn_flow_stack_not_ready"
        assert running["protectionRunning"] == "false" and running["adapter"] == "unavailable"
    result["normal_vpn_available"] = available
    tap("vpn-query", "Query health and flows")
    end = time.monotonic() + 20
    projection = ""
    while time.monotonic() < end:
        nodes = dump("vpn-query-result")
        projection = next((n.get("text", "") for n in nodes if n.get("content-desc") == "Health and flow result"), "")
        if projection.startswith("Runtime / VPP / Rust health") or projection.startswith("Health query error:"): break
        time.sleep(.2)
    assert projection.startswith("Runtime / VPP / Rust health") if available else projection.startswith("Health query error:"), projection
    save("projection.txt", projection)
    save("vpn-query-result.png", adb("exec-out", "screencap", "-p", binary=True))
    typed = raw_query("typed-after-start")
    assert typed["runtime"]["profile"] == "vpn"
    if available:
        assert typed["runtime"]["state"] == "running"
        assert typed["vpp"]["generation"] == typed["health"]["generation"] == typed["current_flows"]["generation"]
        assert typed["consumer"]["query_fresh"]
        assert "Current flows:" in projection and "VPP: generation=" in projection
        result["generation"] = typed["vpp"]["generation"]
    else:
        assert typed["error"] == "management_unavailable" and typed["runtime"]["state"] == "stopped"
        assert typed["runtime"]["errorCode"] == "vpn_flow_stack_not_ready"
        assert "management_unavailable" in projection
        result["generation"] = int(running["generation"])
    tap("vpn-stop", "Stop")
    end = time.monotonic() + 30
    while time.monotonic() < end:
        stopped = state()
        if stopped.get("state") == "stopped" and stopped.get("mayBeActive") == "false": break
        time.sleep(.2)
    assert stopped["state"] == "stopped" and stopped["mayBeActive"] == "false"
    save("after-stop.properties", "\n".join(f"{k}={v}" for k, v in stopped.items()) + "\n")
    assert history_hashes() == original
    result["status"] = "RAW_COMPLETE"
finally:
    if state().get("mayBeActive") != "false":
        adb("shell", "am", "start", "-n", PKG + "/.DebugControlActivity", "--ez", "runtimeStop", "true", check=False)
    adb("shell", "am", "force-stop", PKG, check=False)
    result["service_process_absent"] = not adb("shell", "pidof", PKG + ":runtime", check=False).strip()
    if not result["service_process_absent"]: result["status"] = "HOLD"
    result["completed_ns"] = time.time_ns()
    save("result.json", json.dumps(result, indent=2) + "\n")
print(json.dumps({k:result[k] for k in ("status", "generation", "ui_taps")}, indent=2))
