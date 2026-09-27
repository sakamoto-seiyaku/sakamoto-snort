#!/usr/bin/env python3
"""Independent selected-packet oracle for T26 Linux historical interpretation."""
import argparse
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re

parser = argparse.ArgumentParser()
parser.add_argument("--run", type=Path, required=True)
parser.add_argument("--build", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
run = args.run.resolve()
build = json.loads(args.build.read_text())
result = json.loads((run / "result.json").read_text())
assert result["status"] == "RAW_COMPLETE" and result["task"] == "T26"
assert result["build_sha256"] == hashlib.sha256(args.build.read_bytes()).hexdigest()
assert result["source_sha256"] == build["source_sha256"]
for name, expected in result["files"].items():
    assert hashlib.sha256((run / name).read_bytes()).hexdigest() == expected, name

labels = ("original", "renamed", "condition", "deleted")
snapshots = {name: json.loads((run / (name + ".json")).read_text())
             for name in (*labels, "original-ended", "renamed-ended", "restarted")}
configs = {row["label"]: row for row in result["configurations"]}
documents = {name: json.loads((run / (name + "-input.json")).read_text()) for name in labels}
traffic = {name: json.loads((run / (name + "-traffic.json")).read_text()) for name in labels}
wire = (run / "wire.pcap").read_bytes()
endpoint = [json.loads(line) for line in (run / "endpoint.jsonl").read_text().splitlines()]
endpoint_payloads = [row["payload"] for row in endpoint if "payload" in row]
trace = (run / "vpp-27801.log").read_text()


def request_matches(rule, exchange):
    """Reference evaluation for this fixture's static IPv4/UDP request fields."""
    fields = rule["definition"].split()
    assert len(fields) == 17 and fields[7:9] == ["17", "0"]
    assert fields[2:5] == ["4294967295"] * 3
    assert fields[16] == "0e01"  # tracked UDP POST prerequisite in this fixture
    source = ipaddress.ip_address("10.225.0.1")
    destination = ipaddress.ip_address("10.225.0.2")
    def cidr_matches(value, text):
        return text == "*" or value in ipaddress.ip_network(text, strict=False)
    return (cidr_matches(source, fields[10]) and cidr_matches(destination, fields[11])
            and int(fields[12]) <= exchange["sourcePort"] <= int(fields[13])
            and int(fields[14]) <= 42151 <= int(fields[15]))


def check(snapshots, traffic, endpoint_payloads, wire):
    checks = []
    versions = {}
    for name in labels[:-1]:
        doc = documents[name]
        source_rule = doc["rules"][0]
        phase = traffic[name]
        version = int(configs[name]["versions"][0])
        versions[name] = version
        assert source_rule["name"] == name + "-request"
        assert int(json.loads((run / (name + "-apply.txt")).read_text().split("import.response=")[-1])["configuration"]["rules"][0]["definition"].split()[0]) == version
        expected_action = int(source_rule["definition"].split()[9])
        assert expected_action == (2 if name == "condition" else 1)
        assert len(phase["exchanges"]) == 2 and phase["sent"] == 2
        for exchange in phase["exchanges"]:
            assert request_matches(source_rule, exchange)
            echo = expected_action == 1
            assert exchange["echoed"] == echo
            assert (exchange["payload"] in endpoint_payloads) == echo
            assert wire.count(bytes.fromhex(exchange["payload"])) == (2 if echo else 0)
        q = snapshots[name]["consumer"]["persistent"]
        rows = [row for row in q["rule_windows"].values()
                if row["attribution"]["winner"] == version]
        assert len(rows) == 1
        row = rows[0]
        assert row["attribution"]["name"] == source_rule["name"]
        assert row["attribution"]["policy_revision"] == configs[name]["revision"]
        assert row["attribution"]["policy_hash"] == configs[name]["snapshot_hash"]
        assert row["attribution"]["actual_action"] == expected_action
        assert row["counts"]["packets"] == [2, 0]
        expected_bytes = sum(len(bytes.fromhex(x["payload"])) + 28 for x in phase["exchanges"])
        assert row["counts"]["bytes"] == [expected_bytes, 0]
        interpretation = row["interpretation"]
        assert interpretation["version"] == str(version)
        assert interpretation["logical_identity"] == f"{version >> 16:012x}"
        assert interpretation["revision"] == version & 65535
        assert interpretation["name"] == source_rule["name"]
        assert interpretation["actual_action"] == expected_action
        assert interpretation["conditions"] == {"status": "available", "source_rule_index": 0}
        source = q["history_source"]
        assert source["status"] == "available"
        assert int(source["revision"]) == configs[name]["revision"]
        assert int(source["hash"]) == configs[name]["snapshot_hash"]
        assert source["configuration"]["rules"][0]["definition"].split()[0] == str(version)
        native = [line for line in trace.splitlines() if "s209 event=l4 " in line
                  and f"rule={version} " in line and f"actual_action={expected_action} " in line]
        assert len(native) == 2, (name, native)
        checks.append(name + ": independent packets/config/native/window/source")
    assert versions["original"] >> 16 == versions["renamed"] >> 16 == versions["condition"] >> 16
    assert [versions[name] & 65535 for name in labels[:-1]] == [1, 2, 3]
    assert documents["condition"]["rules"][0]["definition"].split()[10] == "10.225.0.1/32"
    assert documents["original"]["rules"][0]["definition"].split()[10] == "*"

    deleted = traffic["deleted"]
    assert deleted["sent"] == deleted["received"] == 1
    assert not documents["deleted"]["rules"] and not configs["deleted"]["versions"]
    for exchange in deleted["exchanges"]:
        assert exchange["payload"] in endpoint_payloads
        assert wire.count(bytes.fromhex(exchange["payload"])) == 2
    final = snapshots["deleted"]["consumer"]["persistent"]
    assert final["packets"] == [7, 5]
    assert final["history_source"]["status"] == "unavailable"
    assert "configuration" not in final["history_source"]
    assert final["rule_metadata_count"] >= 3 and final["rule_metadata_conflicts"] == 0
    for name in labels[:-1]:
        rows = [r for r in final["rule_windows"].values()
                if r["attribution"]["winner"] == versions[name]]
        assert len(rows) == 1
        assert rows[0]["interpretation"]["name"] == name + "-request"
        assert rows[0]["interpretation"]["conditions"]["status"] == "unavailable"
        assert rows[0]["counts"]["packets"] == [2, 0]
    for name in ("original", "renamed"):
        ended = snapshots[name + "-ended"]["consumer"]["persistent"]
        assert any(r["record"]["attribution"][0]["interpretation"]["version"] == str(versions[name])
                   for r in ended["recent"].values())
    recent = list(final["recent"].values())
    assert len(recent) == 2
    for name in ("original", "renamed"):
        assert any(r["record"]["attribution"][0]["interpretation"]["name"] == name + "-request"
                   and r["record"]["attribution"][0]["interpretation"]["segment_counts"]["packets"] == 2
                   for r in recent)
    restarted = snapshots["restarted"]["consumer"]["persistent"]
    assert restarted["rule_windows"] == final["rule_windows"]
    assert restarted["recent"] == final["recent"]
    assert restarted["packets"] == final["packets"]
    assert restarted["history_source"]["status"] == "unavailable"
    assert result["history_reopened"] and all(x["process_absent"] for x in result["lifetimes"])
    assert re.search(r"s203 event=capture .*queue=176", trace)
    checks.append("deletion and restart: old names/actions/counts, unavailable conditions, END")
    return checks


checks = check(snapshots, traffic, endpoint_payloads, wire)
mutations = []
# Mutations bypass file hashes to prove that the selected semantic oracle rejects them.
for label, change in (
    ("old_name", lambda q: next(r for r in q["deleted"]["consumer"]["persistent"]["rule_windows"].values() if r["attribution"]["name"] == "original-request")["interpretation"].__setitem__("name", "latest")),
    ("old_version", lambda q: next(r for r in q["deleted"]["consumer"]["persistent"]["rule_windows"].values() if r["attribution"]["name"] == "original-request")["interpretation"].__setitem__("version", "1")),
    ("old_conditions", lambda q: next(r for r in q["deleted"]["consumer"]["persistent"]["rule_windows"].values() if r["attribution"]["name"] == "original-request")["interpretation"]["conditions"].__setitem__("status", "available")),
    ("count", lambda q: next(r for r in q["deleted"]["consumer"]["persistent"]["rule_windows"].values() if r["attribution"]["name"] == "condition-request")["counts"].__setitem__("packets", [3, 0])),
    ("action", lambda q: next(r for r in q["condition"]["consumer"]["persistent"]["rule_windows"].values() if r["attribution"]["name"] == "condition-request")["attribution"].__setitem__("actual_action", 1)),
    ("source_index", lambda q: next(r for r in q["condition"]["consumer"]["persistent"]["rule_windows"].values() if r["attribution"]["name"] == "condition-request")["interpretation"]["conditions"].__setitem__("source_rule_index", 1)),
):
    changed = copy.deepcopy(snapshots)
    change(changed)
    try:
        check(changed, traffic, endpoint_payloads, wire)
    except AssertionError:
        mutations.append(label)
    else:
        raise AssertionError("semantic mutation survived: " + label)

answer = {"status":"VALID", "run":str(run), "build":str(args.build.resolve()),
          "source_sha256":build["source_sha256"], "checks":checks,
          "actual_packet_paths":12, "actual_policy_drops":2,
          "mutations_rejected":mutations, "verifier_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
args.output.write_text(json.dumps(answer, indent=2) + "\n")
print(json.dumps({k:answer[k] for k in ("status","actual_packet_paths","actual_policy_drops","mutations_rejected")}, indent=2))
