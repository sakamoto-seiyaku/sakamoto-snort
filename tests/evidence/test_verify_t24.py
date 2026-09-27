#!/usr/bin/env python3
"""Adversarial alterations prove T24's oracle checks semantics beyond file seals."""
import argparse
import json
from pathlib import Path
from verify_t24 import verify

def mutate(directory):
    directory = Path(directory)
    result = json.loads((directory / "result.json").read_text())
    kind = result.get("kind", "linux")
    prefix = "t24-" if kind == "android" else ""
    log_name = "first-vpp.log" if kind == "android" else "vpp.log"
    log = (directory / log_name).read_text()
    drop_line = next(line for line in log.splitlines()
        if line.startswith("s209 event=l4 ") and "actual_action=2" in line)
    token = next(field.split("=",1)[1] for field in drop_line.split() if field.startswith("token="))
    assert "position=1" in drop_line
    traffic = json.loads((directory / (prefix+"drop-a-traffic.json")).read_text())
    blocked_payload = traffic["exchanges"][0]["payload"]
    cases = {}
    cases["pre-placement"] = {log_name: log.replace(drop_line, drop_line.replace("position=1","position=2"),1)}
    cases["flow-created-on-drop"] = {log_name: log + f"\ns208 event=observe token={token} status=0\n"}
    cases["blocked-delivered"] = {"endpoint.jsonl": (directory/"endpoint.jsonl").read_text()
        + json.dumps({"payload":blocked_payload}) + "\n"}
    snapshot_name = prefix+"drop-a.json"
    snapshot = json.loads((directory/snapshot_name).read_text())
    row = next(r for r in snapshot["consumer"]["overview"]["blocked_records"]
               if r and r["ports"][0] == (44500 if kind=="android" else 43500))
    row["packets"][0] += 1
    cases["blocked-counter"] = {snapshot_name: json.dumps(snapshot)}
    if kind == "linux":
        idle = json.loads((directory/"idle-retired.json").read_text())
        ended = next(r for r in idle["consumer"]["overview"]["blocked_records"]
            if r and r["ports"][0] == 43500)
        ended["end_reason"] = 0
        cases["idle-end-reason"] = {"idle-retired.json": json.dumps(idle)}
        pressure = json.loads((directory/"pressure.json").read_text())
        pressure["consumer"]["persistent"]["blocked"]["packets"][0] += 1
        cases["capacity-loss-arithmetic"] = {"pressure.json": json.dumps(pressure)}
    output = {}
    for name, overrides in cases.items():
        verdict = verify(directory, overrides, check_seals=False)
        assert verdict["status"] == "HOLD" and verdict["error"], (name, verdict)
        output[name] = verdict["error"]
    return dict(status="PASS", kind=kind, cases=output)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("directory", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = mutate(a.directory)
    a.output.write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result,indent=2))
