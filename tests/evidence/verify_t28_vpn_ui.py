#!/usr/bin/env python3
"""Independently check the normal VPN diagnostic UI's explicit refusal path."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

p = argparse.ArgumentParser()
p.add_argument("--run", type=Path, required=True)
p.add_argument("--readback", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
run = a.run.resolve()
readback = json.loads(a.readback.read_text())
result = json.loads((run / "result.json").read_text())
build = json.loads(Path(result["build"]).read_text())
assert result["status"] == "RAW_COMPLETE" and result["scenario"] == "ui-start-query-stop"
assert result["source_sha256"] == build["source_sha256"] == readback["source_sha256"]
assert result["apk_sha256"] == build["apk_sha256"] == readback["apk_sha256"]
assert hashlib.sha256((run / "runner.py").read_bytes()).hexdigest() == hashlib.sha256(
    (Path(__file__).resolve().parents[1] / "device/t28-vpn-ui-control.py").read_bytes()).hexdigest()
assert [row["target"] for row in result["ui_taps"]] == ["Start", "Query health and flows", "Stop"]
assert not result["normal_vpn_available"] and result["service_process_absent"]
assert result["after_start"]["state"] == "stopped"
assert result["after_start"]["errorCode"] == "vpn_flow_stack_not_ready"
assert result["after_start"]["adapter"] == "unavailable"
assert result["after_start"]["protectionRunning"] == "false"
assert result["after_start"]["mayBeActive"] == "false"
raw = json.loads((run / "typed-after-start.json").read_text())
assert raw["error"] == "management_unavailable" and raw.get("current_flows") is None
assert raw["runtime"]["errorCode"] == "vpn_flow_stack_not_ready"
assert raw["runtime"]["state"] == "stopped" and raw["runtime"]["protectionRunning"] == "false"
assert (run / "projection.txt").read_text() == "Health query error: management_unavailable"
xml = ET.parse(run / "vpn-query-result.xml")
assert any(node.get("content-desc") == "Health and flow result"
           and node.get("text") == "Health query error: management_unavailable"
           for node in xml.iter("node"))
assert (run / "vpn-query-result.png").stat().st_size > 1000
before = json.loads((run / "before-original-hashes.json").read_text())
assert before == readback["ordinary_history_hashes"]
assert readback["status"] == "PASS" and readback["vpp_absent"]
assert readback["owned_nfqueue_hooks_absent"] and readback["test_selector_removed"]
answer = dict(status="VALID_EXPECTED_UNAVAILABLE", source_sha256=build["source_sha256"],
              apk_sha256=build["apk_sha256"], ui_taps=[row["target"] for row in result["ui_taps"]],
              error_code=raw["runtime"]["errorCode"], original_history_unchanged=True,
              verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
a.output.write_text(json.dumps(answer, indent=2) + "\n")
print(json.dumps(answer, indent=2))
