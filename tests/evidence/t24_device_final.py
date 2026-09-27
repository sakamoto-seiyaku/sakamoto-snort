#!/usr/bin/env python3
"""Read back the stopped Pixel state after serial Root and VPN acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PKG = "com.sakamoto.snort.androidruntime"
p = argparse.ArgumentParser()
p.add_argument("--serial-from", type=Path, required=True)
p.add_argument("--build", type=Path, required=True)
p.add_argument("--root-run", type=Path, required=True)
p.add_argument("--vpn-run", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
serial = json.loads(a.serial_from.read_text())["serial"]
build = json.loads(a.build.read_text())
root_run = json.loads((a.root_run / "result.json").read_text())
vpn_run = json.loads((a.vpn_run / "result.json").read_text())
assert root_run["status"] == vpn_run["status"] == "RAW_COMPLETE"
assert root_run["source_sha256"] == vpn_run["source_sha256"] == build["source_sha256"]
def adb(*args, binary=False):
    completed = subprocess.run([str(ROOT / "dev/adb"), "-s", serial, *map(str,args)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return completed.stdout if binary else completed.stdout.decode(errors="replace").replace("\r", "")
def root(command):
    return adb("shell","su","-c",command)
def props(text):
    return dict(line.split("=",1) for line in text.splitlines() if "=" in line and not line.startswith("#"))
state = props(adb("shell","run-as",PKG,"cat","files/runtime-state/snapshot.properties"))
assert state["state"] == "stopped" and state["mayBeActive"] == "false"
assert int(state["generation"]) >= vpn_run["lifetimes"][-1]["generation"]
assert "uid=0" in adb("shell","run-as",PKG,"su","-c","id")
package = adb("shell","dumpsys","package",PKG)
code_path = re.search(r"codePath=(\S+)", package).group(1)
installed_apk_sha = adb("shell","sha256sum",code_path+"/base.apk").split()[0]
assert installed_apk_sha == build["apk_sha256"]
legacy_sha = adb("shell","run-as",PKG,"sha256sum","files/observation/overall.json").split()[0]
assert legacy_sha == "75a715a4ce1fd64679631baca1c0d398de3186bf95dad5cdcfa6beabbb9091c4"
database = adb("exec-out","run-as",PKG,"cat","files/observation/overall.sqlite3",binary=True)
with tempfile.TemporaryDirectory(prefix="t24-device-db-") as temporary:
    path = Path(temporary) / "overall.sqlite3"
    path.write_bytes(database)
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    rows = db.execute("SELECT kind,count(*) FROM observation GROUP BY kind").fetchall()
    meta = json.loads(db.execute("SELECT value FROM observation WHERE kind=0 AND key='' ").fetchone()[0])
    db.close()
assert sum(count for kind,count in rows if kind != 0) >= 1222
assert meta["blocked_totals"]["packets"][0] >= 18
processes = root("ps -A -o PID,UID,ARGS")
assert "libvpp_runtime.so" not in processes
hooks = root("iptables-save")
assert not any("--queue-num " + str(i) in hooks for i in range(176,180))
for run in (a.root_run,a.vpn_run):
    restore = json.loads((run / "t24-restore-empty-apply.json").read_text())
    restart = json.loads((run / "restart-configuration-before-apply.json").read_text())
    assert restore["result"] == 0 and restore["configuration"]["rules"] == []
    assert restart["configuration"]["rules"] == []
result = dict(status="PASS", checked_ns=time.time_ns(), source_sha256=build["source_sha256"],
    apk_sha256=installed_apk_sha, stopped_generation=int(state["generation"]),
    legacy_json_sha256=legacy_sha, sqlite_sha256=hashlib.sha256(database).hexdigest(),
    sqlite_rows=rows, blocked_packets=meta["blocked_totals"]["packets"],
    kernel_su_grant=True, vpp_absent=True, owned_nfqueue_hooks_absent=True,
    restored_empty_configurations=["root","vpn"])
a.output.write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps(result,indent=2))
