#!/usr/bin/env python3
"""Stopped-device T27 readback without opening or modifying ordinary history."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PKG = "com.sakamoto.snort.androidruntime"
p = argparse.ArgumentParser()
p.add_argument("--serial-from", type=Path, required=True)
p.add_argument("--build", type=Path, required=True)
p.add_argument("--root-run", type=Path, required=True)
p.add_argument("--vpn-run", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=False)
serial = json.loads(a.serial_from.read_text())["serial"]
build = json.loads(a.build.read_text())


def adb(*args, binary=False, check=True):
    result = subprocess.run([str(ROOT / "dev/adb"), "-s", serial, *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        raise RuntimeError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
    return result.stdout if binary else (result.stdout + result.stderr).decode(errors="replace").replace("\r", "")


def save(name, value):
    (out / name).write_bytes(value if isinstance(value, bytes) else value.encode())
    return value


def digest(value):
    return hashlib.sha256(value).hexdigest()


state = save("state.properties", adb("shell", "run-as", PKG,
    "cat", "files/runtime-state/snapshot.properties"))
properties = dict(line.split("=", 1) for line in state.splitlines() if "=" in line and not line.startswith("#"))
assert properties["state"] == "stopped" and properties["mayBeActive"] == "false"
assert properties["profile"] == "vpn"
assert not adb("shell", "pidof", PKG + ":runtime", check=False).strip()
processes = save("processes.txt", adb("shell", "su", "-c", shlex.quote("ps -A -o PID,UID,ARGS")))
assert "libvpp_runtime.so" not in processes
root = save("root-grant.txt", adb("shell", "run-as", PKG, "su", "-c", "id"))
assert "uid=0" in root
hooks = save("hooks.txt", adb("shell", "su", "-c",
    shlex.quote("iptables-save; ip6tables-save")))
assert "NFQUEUE" not in hooks and "SAKAMOTO" not in hooks
assert adb("shell", "run-as", PKG, "sh", "-c",
    shlex.quote("test ! -e files/observation/t27-test.enabled && echo absent")).strip() == "absent"

original_paths = ("files/observation/overall.sqlite3", "files/observation/overall.json")
device_hashes = {}
for name in original_paths:
    content = adb("exec-out", "run-as", PKG, "cat", name, binary=True)
    device_hashes[name] = digest(content)
    if name.endswith(".sqlite3"):
        (out / "overall.sqlite3").write_bytes(content)

for run in (a.root_run, a.vpn_run):
    before = json.loads((run / "before-original-hashes.json").read_text())
    after = json.loads((run / "after-original-hashes.json").read_text())
    assert before == after == device_hashes
db = sqlite3.connect(out / "overall.sqlite3")
integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
rows = db.execute("SELECT kind,COUNT(*) FROM observation GROUP BY kind ORDER BY kind").fetchall()
db.close()
assert integrity == "ok"

package = save("package.txt", adb("shell", "dumpsys", "package", PKG))
code_path = re.search(r"codePath=(\S+)", package)[1]
installed = save("installed-apk.txt", adb("shell", "sha256sum", code_path + "/base.apk"))
installed_hash = installed.split()[0]
assert installed_hash == build["apk_sha256"]

summary = {"status":"PASS", "serial":serial,
    "source_sha256":build["source_sha256"], "apk_sha256":installed_hash,
    "stopped_generation":int(properties["generation"]),
    "root_grant":True,"vpp_absent":True,"owned_nfqueue_hooks_absent":True,
    "test_selector_removed":True,"ordinary_history_hashes":device_hashes,
    "sqlite_integrity":integrity,"sqlite_rows":rows,
    "database_and_index_bytes":(out / "overall.sqlite3").stat().st_size,
    "root_and_vpn_original_history_unchanged":True}
save("summary.json", json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
