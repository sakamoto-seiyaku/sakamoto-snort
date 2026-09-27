#!/usr/bin/env python3
"""Close T28's source, Host, Android, review-fix and stopped-device witnesses."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("chain", ROOT / "tests/evidence/product_chain.py")
chain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chain)
p = argparse.ArgumentParser()
p.add_argument("--evidence", type=Path, required=True)
p.add_argument("--dirty-baseline", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
ev = a.evidence.resolve()
read = lambda name: json.loads((ev / name).read_text())
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
host = read("linux-build-final4b/build.json")
pixel = read("pixel-build-final4/build.json")
files = chain.source_files()
assert files == host["files"] == pixel["files"]
source_hash = hashlib.sha256(chain.encode(files)).hexdigest()
assert source_hash == host["source_sha256"] == pixel["source_sha256"]
for name, value in files.items():
    if value is not None:
        for directory in ("linux-build-final4b", "pixel-build-final4"):
            assert digest(ev / directory / "source" / name) == value, (directory, name)
assert digest(ev / "linux-build-final4b/dirty.diff") == host["dirty_diff_sha256"]
assert digest(ev / "pixel-build-final4/dirty.diff") == pixel["dirty_diff_sha256"]
for name, value in host["artifact_hashes"].items():
    assert digest(Path(host["artifact"]) / name) == value, name
assert digest(pixel["apk"]) == pixel["apk_sha256"]
with zipfile.ZipFile(pixel["apk"]) as archive:
    installed = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                 for name in archive.namelist() if name.startswith("lib/arm64-v8a/") and name.endswith(".so")}
assert installed == pixel["native_sha256"]

baseline = read("linux-dashboard-final4b-verification.json")
assert baseline["status"] == "VALID" and baseline["actual_packet_paths"] == 12
assert baseline["actual_policy_drops"] == 2 and len(baseline["mutations_rejected"]) == 11
tiers = {}
expected = {"r1": (176, 5, 1002), "r2": (442, 24, 1007),
            "r3": (433, 23, 1011), "r4": (560, 24, 1016)}
for tier, (packets, drops, stopped_protocol) in expected.items():
    verdict = read(f"linux-{tier}-dashboard-final4-verification.json")
    assert verdict["status"] == "VALID" and verdict["source_sha256"] == source_hash
    assert verdict["actual_packet_paths"] == packets and verdict["actual_policy_drops"] == drops
    assert verdict["stop_sample"]["protocol"] == stopped_protocol
    assert verdict["stop_sample"]["lpi_stop"] == 1
    tiers[tier] = dict(packet_paths=packets, policy_drops=drops,
                       stop_sample=verdict["stop_sample"])
physical = read("pixel-dashboard-final4-verification.json")
assert physical["status"] == "VALID" and physical["source_sha256"] == source_hash
assert physical["apk_sha256"] == pixel["apk_sha256"]
for profile in ("root", "vpn"):
    row = physical["profiles"][profile]
    assert len(row["generations"]) == 5 and row["allowed_exchanges"] == 5
    assert row["actual_drops"] == 2 and row["selected_rule_packets"] == 5
    assert all(value.isdigit() for value in row["winner_ids"])
ui = read("pixel-vpn-ui-final4c-verification.json")
assert ui["status"] == "VALID_EXPECTED_UNAVAILABLE" and ui["source_sha256"] == source_hash
assert ui["ui_taps"] == ["Start", "Query health and flows", "Stop"]
assert ui["error_code"] == "vpn_flow_stack_not_ready"
device = read("device-final4c-readback/summary.json")
predecessor = json.loads((ROOT / "build-output/t27-20260927/device-readback-verified/summary.json").read_text())
assert device["status"] == "PASS" and device["source_sha256"] == source_hash
assert device["apk_sha256"] == pixel["apk_sha256"]
assert device["ordinary_history_hashes"] == predecessor["ordinary_history_hashes"]
assert device["vpp_absent"] and device["owned_nfqueue_hooks_absent"]
assert device["test_selector_removed"] and device["root_grant"]
assert device["sqlite_integrity"] == "ok" and device["root_and_vpn_original_history_unchanged"]
assert sum(count for kind, count in device["sqlite_rows"] if kind != 0) == 1575
assert "android runtime contract: PASS" in (ev / "android-contract-final4.log").read_text()
assert "100% tests passed, 0 tests failed out of 51" in (ev / "host-ctest-final4b.log").read_text()
rust = (ev / "rust-tests-final4.log").read_text()
assert "test result: FAILED" not in rust
assert sum(int(line.split("ok. ")[1].split(" passed")[0]) for line in rust.splitlines()
           if line.startswith("test result: ok.")) == 73
dirty = json.loads(a.dirty_baseline.read_text())
assert len(dirty) == 34
for name, entry in dirty.items():
    assert digest(ROOT / name) == entry["sha256"], name

answer = dict(status="VALID", source_sha256=source_hash, apk_sha256=pixel["apk_sha256"],
              linux=dict(actual_packet_paths=12, actual_policy_drops=2,
                         semantic_mutations_rejected=11, protocol_tiers=tiers),
              pixel=physical["profiles"], normal_vpn_ui=ui["status"],
              stopped_device_generation=device["stopped_generation"],
              original_history_unchanged=True, preserved_dirty_paths=len(dirty),
              rust_tests_passed=73, host_ctest_passed=51,
              verifier_sha256=digest(__file__))
a.output.write_text(json.dumps(answer, indent=2) + "\n")
print(json.dumps({key: answer[key] for key in ("status", "source_sha256", "apk_sha256",
                                         "stopped_device_generation", "preserved_dirty_paths")}, indent=2))
