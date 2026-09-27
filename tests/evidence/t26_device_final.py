#!/usr/bin/env python3
"""Read back the stopped Pixel after T26 Root and controlled VPN runs."""
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
parser = argparse.ArgumentParser()
for flag in ("serial-from", "build", "root-run", "vpn-run", "baseline-db", "output-dir"):
    parser.add_argument("--" + flag, type=Path, required=True)
args = parser.parse_args()
out = args.output_dir.resolve()
out.mkdir(parents=True, exist_ok=False)
serial = json.loads(args.serial_from.read_text())["serial"]
build = json.loads(args.build.read_text())
runs = [json.loads((path / "result.json").read_text()) for path in (args.root_run, args.vpn_run)]
assert [run["profile"] for run in runs] == ["root", "vpn"]
assert all(run["status"] == "RAW_COMPLETE" and run["source_sha256"] == build["source_sha256"] for run in runs)


def adb(*parts, binary=False):
    result = subprocess.run([str(ROOT / "dev/adb"), "-s", serial, *map(str, parts)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout if binary else result.stdout.decode(errors="replace").replace("\r", "")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def properties(text):
    return dict(line.split("=", 1) for line in text.splitlines()
                if "=" in line and not line.startswith("#"))


state_text = adb("shell", "run-as", PKG, "cat", "files/runtime-state/snapshot.properties")
(out / "state.properties").write_text(state_text)
state = properties(state_text)
assert state["state"] == "stopped" and state["mayBeActive"] == "false"
assert int(state["generation"]) >= runs[-1]["lifetimes"][-1]["generation"]
assert "uid=0" in adb("shell", "run-as", PKG, "su", "-c", "id")
package = adb("shell", "dumpsys", "package", PKG)
code_path = re.search(r"codePath=(\S+)", package).group(1)
apk_sha = adb("shell", "sha256sum", code_path + "/base.apk").split()[0]
assert apk_sha == build["apk_sha256"]
legacy_sha = adb("shell", "run-as", PKG, "sha256sum", "files/observation/overall.json").split()[0]
assert legacy_sha == "75a715a4ce1fd64679631baca1c0d398de3186bf95dad5cdcfa6beabbb9091c4"
wal = adb("shell", "run-as", PKG, "sh", "-c",
          shlex.quote("if [ -f files/observation/overall.sqlite3-wal ]; then stat -c %s files/observation/overall.sqlite3-wal; else echo 0; fi"))
assert int(wal.strip()) == 0
database = adb("exec-out", "run-as", PKG, "cat", "files/observation/overall.sqlite3", binary=True)
(out / "overall.sqlite3").write_bytes(database)
with sqlite3.connect(out / "overall.sqlite3") as db:
    integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    rows = db.execute("SELECT kind,count(*) FROM observation GROUP BY kind").fetchall()
    actual = {str(kind) + ":" + key: digest(bytes(value)) for kind, key, value in
              db.execute("SELECT kind,key,value FROM observation WHERE kind<>0")}
assert integrity == "ok"
with sqlite3.connect(args.baseline_db) as db:
    baseline = {str(kind) + ":" + key: digest(bytes(value)) for kind, key, value in
                db.execute("SELECT kind,key,value FROM observation WHERE kind<>0")}
assert len(baseline) == 1422
changed = [key for key, value in baseline.items() if actual.get(key) != value]
assert not changed
processes = adb("shell", "su", "-c", "ps -A -o PID,UID,ARGS")
hooks = adb("shell", "su", "-c", "iptables-save")
(out / "processes.txt").write_text(processes)
(out / "hooks.txt").write_text(hooks)
assert "libvpp_runtime.so" not in processes
assert not any("--queue-num " + str(queue) in hooks for queue in range(176, 180))
for path in (args.root_run, args.vpn_run):
    saved = json.loads((path / "restart-configuration-before-apply.json").read_text())
    assert saved["result"] == 0 and saved["configuration"]["rules"] == []
result = dict(status="PASS", source_sha256=build["source_sha256"],
              apk_sha256=apk_sha, stopped_generation=int(state["generation"]),
              legacy_json_sha256=legacy_sha, sqlite_sha256=digest(database),
              sqlite_integrity=integrity, sqlite_rows=rows,
              prior_rows=len(baseline), prior_rows_exact=True,
              total_nonmetadata_rows=len(actual), root_grant=True,
              vpp_absent=True, owned_nfqueue_hooks_absent=True,
              restored_empty_configurations={"root": True, "vpn": True})
(out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
