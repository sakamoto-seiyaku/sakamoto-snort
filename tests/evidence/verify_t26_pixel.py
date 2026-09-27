#!/usr/bin/env python3
"""Independent selected-packet and Query projection verifier for T26 Pixel."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import xml.etree.ElementTree as ET

p = argparse.ArgumentParser()
p.add_argument("--run", type=Path, required=True)
p.add_argument("--build", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
run = a.run.resolve()
build = json.loads(a.build.read_text())
result = json.loads((run / "result.json").read_text())
assert result["status"] == "RAW_COMPLETE" and result["task"] == "T26"
assert result["source_sha256"] == build["source_sha256"]
assert result["build_sha256"] == hashlib.sha256(a.build.read_bytes()).hexdigest()
assert result["apk_sha256"] == build["apk_sha256"]
assert result["native_sha256"] == build["native_sha256"]
assert (run / "installed-apk.txt").read_text().split()[0] == build["apk_sha256"]
installed = {Path(line.split()[1]).name: line.split()[0]
             for line in (run / "installed-native.txt").read_text().splitlines()}
assert installed == build["native_sha256"]
for path, expected in result["files"].items():
    assert hashlib.sha256((run / path).read_bytes()).hexdigest() == expected, path

baseline = sqlite3.connect(result["baseline_db"])
baseline_hashes = {str(kind) + ":" + key: hashlib.sha256(bytes(value)).hexdigest()
                   for kind, key, value in baseline.execute("SELECT kind,key,value FROM observation WHERE kind<>0")}
baseline.close()
assert len(baseline_hashes) == result["preexisting_rows_preserved"] == 1422
assert hashlib.sha256(Path(result["baseline_db"]).read_bytes()).hexdigest() == result["baseline_sha256"]
for name in ("before", "first", "restart"):
    hashes = json.loads((run / (name + "-store-hashes.json")).read_text())
    assert all(hashes.get(key) == value for key, value in baseline_hashes.items()), name

labels = ("original", "renamed", "condition", "deleted")
names = (*labels, "first-baseline", "original-ended", "renamed-ended", "ui-history-readback", "final", "restart-baseline")
snapshots = {name: json.loads((run / (name + ".json")).read_text()) for name in names}
configs = {item["label"]: item for item in result["configurations"]}
documents = {name: json.loads((run / (name + "-input.json")).read_text()) for name in labels}
traffic = {name: json.loads((run / (name + "-traffic.json")).read_text()) for name in labels}
endpoint = [json.loads(line) for line in (run / "endpoint.jsonl").read_text().splitlines()]
endpoint_payloads = [item["payload"] for item in endpoint if "payload" in item]
host_wire = (run / "host.pcap").read_bytes()
device_wire = (run / "device.pcap").read_bytes()
trace = (run / "first-vpp.log").read_text()


def check(views, packets=traffic):
    checks = []
    baseline_totals = views["first-baseline"]["consumer"]["persistent"]["packets"]
    versions = {}
    for index, name in enumerate(labels):
        phase = packets[name]
        doc = documents[name]
        expected_action = 2 if name == "condition" else 1
        expected_reply = expected_action == 1
        assert phase["sent"] == (1 if name == "deleted" else 2)
        assert phase["received"] == (phase["sent"] if expected_reply else 0)
        if name != "deleted":
            source_rule = doc["rules"][0]
            fields = source_rule["definition"].split()
            assert len(fields) == 17 and fields[7:10] == ["17", "0", str(expected_action)]
            assert fields[16] == "0e01"
            assert fields[10:12] == (["0.0.0.0/0", "0.0.0.0/0"] if name == "condition" else ["*", "*"])
            assert fields[12:14] == (["44500", "44500"] if name == "condition" else ["0", "65535"])
            version = int(configs[name]["versions"][0])
            versions[name] = version
            assert int(json.loads((run / (name + "-apply.json")).read_text())["configuration"]["rules"][0]["definition"].split()[0]) == version
        else:
            assert doc["rules"] == [] and configs[name]["versions"] == []
        for exchange in phase["exchanges"]:
            assert exchange["sourcePort"] == 44500
            assert exchange["echoed"] == expected_reply
            assert (exchange["payload"] in endpoint_payloads) == expected_reply
            count = 2 if expected_reply else 0
            assert host_wire.count(bytes.fromhex(exchange["payload"])) == count
            seen_device = device_wire.count(bytes.fromhex(exchange["payload"]))
            if expected_reply:
                assert seen_device >= 2
            elif result["profile"] == "vpn":
                assert seen_device >= 1  # Captured at TUN before policy DROP.
            else:
                assert seen_device == 0  # Root NFQUEUE DROP precedes dummy egress.
        q = views[name]["consumer"]["persistent"]
        assert views[name]["consumer"]["query_fresh"] is True
        expected_orig = baseline_totals[0] + (2 * (index + 1) if index < 3 else 7)
        expected_reply_total = baseline_totals[1] + ([2, 4, 4, 5][index])
        # The physical device may finish an unrelated, pre-existing flow while
        # this run is active. The selected rule windows below remain exact.
        assert q["packets"][0] >= expected_orig
        assert q["packets"][1] >= expected_reply_total
        if name == "deleted":
            assert q["history_source"]["status"] == "unavailable"
            assert "configuration" not in q["history_source"]
            continue
        rows = [row for row in q["rule_windows"].values()
                if row["attribution"]["winner"] == versions[name]]
        assert rows
        assert sum(row["counts"]["packets"][0] for row in rows) == 2
        assert sum(row["counts"]["bytes"][0] for row in rows) == sum(
            len(bytes.fromhex(x["payload"])) + 28 for x in phase["exchanges"])
        for row in rows:
            ref = row["attribution"]
            interpreted = row["interpretation"]
            assert ref["name"] == interpreted["name"] == name + "-request"
            assert ref["uid"] == result["uid"]
            assert ref["policy_revision"] == configs[name]["revision"]
            assert ref["policy_hash"] == configs[name]["snapshot_hash"]
            assert ref["actual_action"] == interpreted["actual_action"] == expected_action
            assert interpreted["version"] == str(versions[name])
            assert interpreted["logical_identity"] == f"{versions[name] >> 16:012x}"
            assert interpreted["revision"] == versions[name] & 65535
            assert interpreted["conditions"] == {"status": "available", "source_rule_index": 0}
        source = q["history_source"]
        assert source["status"] == "available"
        assert int(source["revision"]) == configs[name]["revision"]
        assert int(source["hash"]) == configs[name]["snapshot_hash"]
        assert source["configuration"]["rules"][0]["definition"].split()[0] == str(versions[name])
        native = [line for line in trace.splitlines() if "s209 event=l4 " in line
                  and f"rule={versions[name]} " in line and f"actual_action={expected_action} " in line]
        assert len(native) == 2, (name, native)
        checks.append(name + ": endpoint/pcap/native/query/source")
    assert versions["original"] >> 16 == versions["renamed"] >> 16 == versions["condition"] >> 16
    assert [versions[name] & 65535 for name in labels[:-1]] == [1, 2, 3]
    final = views["deleted"]["consumer"]["persistent"]
    for name in labels[:-1]:
        rows = [row for row in final["rule_windows"].values()
                if row["attribution"]["winner"] == versions[name]]
        assert rows and sum(row["counts"]["packets"][0] for row in rows) == 2
        assert all(row["interpretation"]["version"] == str(versions[name])
                   and row["interpretation"]["name"] == name + "-request"
                   and row["interpretation"]["conditions"]["status"] == "unavailable"
                   and row["interpretation"]["actual_action"] == (2 if name == "condition" else 1)
                   for row in rows)
    for name in ("original", "renamed"):
        assert any(recent["record"]["attribution"][0]["interpretation"]["version"] == str(versions[name])
                   and recent["record"]["attribution"][0]["interpretation"]["segment_counts"]["packets"] == 2
                   for recent in final["recent"].values())
    restarted = views["restart-baseline"]["consumer"]["persistent"]
    for field in ("packets", "bytes", "rule_windows", "recent"):
        assert restarted[field] == views["final"]["consumer"]["persistent"][field]
    assert restarted["history_source"]["status"] == "unavailable"
    assert all(item["process_absent"] and item["service_process_absent"] for item in result["lifetimes"])
    assert re.search(r"s203 event=admit .*src_port=44500", trace)
    assert sum(channel["basic_packets"][1] for channel in views["condition"]["health"]["channels"]) >= 2
    checks.append("END, delete, UI Query and service restart retain old interpretation")
    return checks, versions


checks, versions = check(snapshots)
ui = result["ui_projection"]
assert ui["source_status"] == "unavailable"
assert ui["query_path"] == "ui-history-readback.json"
ui_raw = snapshots["ui-history-readback"]["consumer"]
assert ui_raw["query_fresh"] is True
assert ui_raw["persistent"]["rule_windows"] == snapshots["deleted"]["consumer"]["persistent"]["rule_windows"]
assert ui_raw["persistent"]["history_source"]["status"] == "unavailable"
xml = ET.fromstring((run / "ui-history.xml").read_text())
shown = [node.get("text", "") for node in xml.iter("node") if node.get("content-desc") == "History result"]
assert shown and shown[0] == ui["text"]
for name in ("original", "renamed"):
    assert f"v{versions[name]} · {name}-request" in ui["text"]
assert "condition-request" in ui["text"] and "conditions unavailable" in ui["text"]
assert (run / "ui-history.png").read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
checks.append("actual UI button/XML projection matches the Query file; screenshot is auxiliary")

mutations = []
for label, change in (
    ("old_name", lambda q: next(row for row in q["deleted"]["consumer"]["persistent"]["rule_windows"].values() if row["attribution"]["winner"] == versions["original"])["interpretation"].__setitem__("name", "latest")),
    ("old_version", lambda q: next(row for row in q["deleted"]["consumer"]["persistent"]["rule_windows"].values() if row["attribution"]["winner"] == versions["original"])["interpretation"].__setitem__("version", "1")),
    ("old_condition", lambda q: next(row for row in q["deleted"]["consumer"]["persistent"]["rule_windows"].values() if row["attribution"]["winner"] == versions["original"])["interpretation"]["conditions"].__setitem__("status", "available")),
    ("count", lambda q: next(row for row in q["deleted"]["consumer"]["persistent"]["rule_windows"].values() if row["attribution"]["winner"] == versions["condition"])["counts"].__setitem__("packets", [9, 0])),
    ("action", lambda q: next(row for row in q["condition"]["consumer"]["persistent"]["rule_windows"].values() if row["attribution"]["winner"] == versions["condition"])["attribution"].__setitem__("actual_action", 1)),
    ("source_index", lambda q: next(row for row in q["condition"]["consumer"]["persistent"]["rule_windows"].values() if row["attribution"]["winner"] == versions["condition"])["interpretation"]["conditions"].__setitem__("source_rule_index", 1)),
):
    changed = copy.deepcopy(snapshots)
    change(changed)
    try:
        check(changed)
    except AssertionError:
        mutations.append(label)
    else:
        raise AssertionError("semantic mutation survived: " + label)

answer = {"status": "VALID", "profile": result["profile"], "run": str(run),
          "source_sha256": build["source_sha256"], "apk_sha256": build["apk_sha256"],
          "packet_paths": 12, "actual_policy_drops": 2,
          "baseline_rows_preserved": len(baseline_hashes), "checks": checks,
          "mutations_rejected": mutations,
          "verifier_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
a.output.write_text(json.dumps(answer, indent=2) + "\n")
print(json.dumps({k: answer[k] for k in ("status", "profile", "packet_paths", "actual_policy_drops", "baseline_rows_preserved", "mutations_rejected")}, indent=2))
