#!/usr/bin/env python3
"""Exercise retired debug authoring intents without changing the Java policy source."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
PKG = "com.sakamoto.snort.androidruntime"
ACTIVITY = PKG + "/.DebugControlActivity"

parser = argparse.ArgumentParser()
parser.add_argument("--serial-from", type=Path, required=True)
parser.add_argument("--build", type=Path, required=True)
parser.add_argument("--baseline", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)
serial = json.loads(args.serial_from.read_text())["serial"]
build = json.loads(args.build.read_text())
baseline = json.loads(args.baseline.read_text())
digest = lambda content: hashlib.sha256(content).hexdigest()


def adb(*words, check=True):
    run = subprocess.run([str(ROOT / "dev/adb"), "-s", serial, *words],
                         capture_output=True, timeout=45)
    if check and run.returncode:
        raise RuntimeError((run.stdout + run.stderr).decode(errors="replace"))
    return run.stdout


def app(path):
    return adb("exec-out", "run-as", PKG, "cat", path)


def capture(name, expected):
    remote = "/sdcard/t29-legacy-authoring.xml"
    for attempt in range(8):
        adb("shell", "input", "swipe", "500", "1900", "500", "300", "180")
        adb("shell", "uiautomator", "dump", remote)
        xml = adb("exec-out", "cat", remote)
        if expected.encode() in xml:
            (out / (name + ".xml")).write_bytes(xml)
            adb("shell", "screencap", "-p", "/sdcard/t29-legacy-authoring.png")
            (out / (name + ".png")).write_bytes(
                adb("exec-out", "cat", "/sdcard/t29-legacy-authoring.png"))
            return
        time.sleep(.2)
    raise AssertionError("retired action was not visible: " + expected)


package = adb("shell", "dumpsys", "package", PKG).decode(errors="replace")
code_path = re.search(r"codePath=(\S+)", package)[1]
installed = adb("shell", "sha256sum", code_path + "/base.apk").decode().split()[0]
assert installed == build["apk_sha256"]
assert digest(Path(build["apk"]).read_bytes()) == installed
assert b"state=stopped" in app("files/runtime-state/snapshot.properties")

# Let the Activity finish its ordinary initial profile selection before the
# byte-for-byte ProductStore baseline. The debug intents then use onNewIntent.
adb("shell", "am", "start", "-n", ACTIVITY)
last_policy = app("files/product-state/product.properties")
stable_samples = 0
for _ in range(40):
    time.sleep(.2)
    current_policy = app("files/product-state/product.properties")
    stable_samples = stable_samples + 1 if current_policy == last_policy else 0
    last_policy = current_policy
    if stable_samples >= 10:
        break
assert stable_samples >= 10, "initial profile selection did not settle"
policy_before = digest(last_policy)
ordinary_paths = ("files/observation/overall.sqlite3", "files/observation/overall.json")
ordinary_before = {path: digest(app(path)) for path in ordinary_paths}
assert ordinary_before == baseline["ordinary_history_hashes"]

cases = (
    ("l4", "debugSetL4RuleSubject", "android.uid:12632",
     "Legacy debug L4 rule request retired. Use Complete direct rules."),
    ("bind", "debugBindApplicationSubject", "android.uid:12632",
     "Legacy debug application binding request retired. Use VPP rule configuration."),
    ("unbind", "debugUnbindApplicationSubject", "android.uid:12632",
     "Legacy debug application binding request retired. Use VPP rule configuration."),
)
for name, key, value, message in cases:
    adb("shell", "am", "start", "-n", ACTIVITY, "--es", key, value)
    capture(name, message)
    assert digest(app("files/product-state/product.properties")) == policy_before
    assert {path: digest(app(path)) for path in ordinary_paths} == ordinary_before

adb("shell", "rm", "/sdcard/t29-legacy-authoring.xml",
    "/sdcard/t29-legacy-authoring.png")
answer = dict(status="PASS", source_sha256=build["source_sha256"],
              apk_sha256=installed, serial=serial, cases=[row[0] for row in cases],
              product_store_sha256=policy_before,
              product_store_byte_identical=True,
              ordinary_history_hashes=ordinary_before,
              ordinary_history_unchanged=True,
              runner_sha256=digest(Path(__file__).read_bytes()))
(out / "result.json").write_text(json.dumps(answer, indent=2) + "\n")
print(json.dumps(answer, indent=2))
