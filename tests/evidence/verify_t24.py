#!/usr/bin/env python3
"""Independent real-packet oracle for T24; no Product aggregation code is used."""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def rows(text, prefix):
    return [dict(token.split("=", 1) for token in line.split() if "=" in token)
            for line in text.splitlines() if line.startswith(prefix)]
def payloads(path):
    raw = subprocess.check_output(["tshark", "-r", str(path), "-Y", "udp.port==42151",
        "-T", "fields", "-e", "udp.payload"], text=True, stderr=subprocess.DEVNULL)
    return Counter(line.strip().replace(":", "") for line in raw.splitlines() if line.strip())
def basic_drop(value):
    return sum(value["health"]["channels"][i]["basic_packets"][1] for i in (0,2))
def main_record(value, field, port):
    matches = [r for r in value["consumer"]["overview"][field]
               if r and r["ports"][0] == port]
    assert len(matches) == 1, (field, port, len(matches))
    return matches[0]

def verify(directory, overrides=None, check_seals=True):
    directory = Path(directory)
    overrides = overrides or {}
    def read(name):
        return overrides[name] if name in overrides else (directory / name).read_text()
    def data(name):
        return json.loads(read(name))
    try:
        result = data("result.json")
        kind = result.get("kind", "linux")
        assert result["status"] == "RAW_COMPLETE" and result["completed_ns"] > result["started_ns"]
        if check_seals:
            for name, expected in result["files"].items():
                assert digest(directory / name) == expected, "collector seal: " + name
        build_file = Path(result["build"])
        build = json.loads(build_file.read_text())
        assert digest(build_file) == result["build_sha256"]
        assert result["source_sha256"] == build["source_sha256"]
        assert build["completed_ns"] < result["started_ns"]
        spec = importlib.util.spec_from_file_location("chain", ROOT / "tests/evidence/product_chain.py")
        chain = importlib.util.module_from_spec(spec); spec.loader.exec_module(chain)
        assert chain.source_files() == build["files"], "Product source drift"
        assert hashlib.sha256(chain.encode(build["files"])).hexdigest() == build["source_sha256"]
        for name, wanted in build["files"].items():
            if wanted is not None:
                assert digest(build_file.parent / "source" / name) == wanted, "source witness " + name
        if kind == "linux":
            for name, wanted in build["artifact_hashes"].items():
                assert digest(Path(build["artifact"]) / name) == wanted, "Host binary " + name
        else:
            assert digest(build["apk"]) == build["apk_sha256"] == result["apk_sha256"]
            with zipfile.ZipFile(build["apk"]) as archive:
                entries = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                           for name in archive.namelist() if name.startswith("lib/arm64-v8a/") and name.endswith(".so")}
            assert entries == result["native_sha256"] == build["native_sha256"]
            assert read("installed-apk.txt").split()[0] == build["apk_sha256"]
            assert {Path(line.split()[1]).name: line.split()[0] for line in read("installed-native.txt").splitlines()} == entries

        if kind == "linux":
            assert "0 packets dropped by kernel" in read("capture.log")
            assert "42151" not in read("final-hooks.txt")
            assert data("final-database.json")["integrity"] == "ok"
            log = read("vpp.log")
            initial = data("baseline.json")
            final = data("pressure.json")
            port = 43500
            capture = directory / "wire.pcap"
        else:
            assert result["scenario"] == "blocked"
            assert all(life["process_absent"] and life["service_process_absent"] for life in result["lifetimes"])
            assert read("legacy-before-sha256.txt") == read("legacy-after-sha256.txt")
            assert result["preexisting_rows_preserved"] == len(data("before-store.json"))-1
            assert "state=stopped" in read("cleanup-state.txt") and "mayBeActive=false" in read("cleanup-state.txt")
            assert "0 packets dropped by kernel" in read("device-capture.log")
            assert "0 packets dropped by kernel" in read("host-capture.log")
            assert not any("libvpp_runtime.so" in line for line in read("cleanup-processes.txt").splitlines())
            assert data("first-store.json")["0:"]["blocked_totals"]["packets"][0] >= 0
            assert data("t24-restore-empty-apply.json")["configuration"]["rules"] == []
            assert data("restart-baseline.json")["consumer"]["persistent"]["blocked"] == data("final.json")["consumer"]["persistent"]["blocked"]
            log = read("first-vpp.log")
            initial = data("first-baseline.json")
            final = data("final.json")
            port = 44500
            capture = directory / "host.pcap"

        configs = {}
        for config in result["configurations"]:
            input_name = config.get("input", config["label"]+"-input.json")
            response_name = config.get("response", config["label"]+"-apply.txt")
            document = data(input_name)
            response_text = read(response_name)
            response = json.loads(response_text.split("import.response=",1)[1]) if response_name.endswith(".txt") else json.loads(response_text)
            assert response["result"] == 0
            assert response["saved_revision"] == response["active_revision"] == config["revision"]
            assert response["configuration"]["bindings"] == document["bindings"]
            active = response["configuration"]["rules"]
            if config.get("drop", config.get("pre", False)):
                assert len(active) == 1 and len(document["rules"]) == 1
                fields = active[0]["definition"].split()
                assert fields[9] == "2" and fields[-1] == "0603", "actual PRE device OUTPUT rule"
                assert active[0]["source"] == "t24-pre-drop"
                assert len(response["configuration"]["bindings"]) == 2
                configs[config["label"]] = dict(drop=True, revision=config["revision"],
                    version=int(fields[0]), name=active[0]["name"])
            else:
                assert not active and not response["configuration"]["bindings"]
                configs[config["label"]] = dict(drop=False, revision=config["revision"])

        expected = {}
        sent_drop = sent_allow = 0
        for phase in result["phases"]:
            name = phase["label"]
            traffic = data(phase["traffic"])
            config = configs[phase["configuration"]]
            if "exchanges" in traffic:
                assert traffic["sent"] == len(traffic["exchanges"])
                for packet in traffic["exchanges"]:
                    payload = packet["payload"]
                    assert payload not in expected and len(bytes.fromhex(payload)) > 0
                    assert packet["echoed"] == (not config["drop"]), (name, packet["echoed"])
                    expected[payload] = dict(phase=name, port=packet["sourcePort"], config=config)
            else:
                assert kind == "linux" and name == "pressure"
                assert traffic["sent"] == traffic["sockets"] == 3000
                for i in range(traffic["sent"]):
                    payload = (i.to_bytes(4,"big") + b"T24" + b"x"*49).hex()
                    assert payload not in expected
                    expected[payload] = dict(phase=name, port=traffic["firstPort"]+i, config=config)
            if config["drop"]: sent_drop += traffic["sent"]
            else: sent_allow += traffic["sent"]

        admits = {row["token"]: row for row in rows(log,"s216 stage=admit ")
                  if row.get("protocol") == "17" and (row.get("src_port") == "42151" or row.get("dst_port") == "42151")}
        terminals = {row["token"]: row for row in rows(log,"s216 stage=terminal ")
                     if row.get("protocol") == "17" and (row.get("src_port") == "42151" or row.get("dst_port") == "42151")}
        decisions = {row["token"]: row for row in rows(log,"s209 event=l4 ")}
        flow_observes = {row["token"] for row in rows(log,"s208 event=observe ")}
        assert admits.keys() == terminals.keys(), "one terminal per admitted UDP packet"
        request_tokens = defaultdict(list)
        reply_tokens = defaultdict(list)
        for token, admit in admits.items():
            raw = bytes.fromhex(admit["raw"])
            offset = int(admit["transport_offset"])
            packet_length = int(admit["packet_length"])
            assert len(raw) == packet_length and raw[0] >> 4 == 4 and raw[9] == 17
            assert int.from_bytes(raw[2:4],"big") == packet_length
            assert int.from_bytes(raw[offset+4:offset+6],"big") == packet_length-offset
            payload = raw[offset+8:].hex()
            assert payload in expected, "unexpected packet on the controlled target"
            info = expected[payload]
            assert int(admit["src_port"] if admit["dst_port"] == "42151" else admit["dst_port"]) == info["port"]
            assert packet_length == len(bytes.fromhex(payload))+28
            assert terminals[token]["generation"] == admit["generation"]
            assert terminals[token]["packet_length"] == admit["packet_length"]
            if admit["dst_port"] == "42151":
                request_tokens[payload].append(token)
                if info["config"]["drop"]:
                    assert terminals[token]["intent"] == "2", "PRE packet must be dropped"
                    assert token not in flow_observes, "PRE DROP created or queried FlowEntry"
                    decision = decisions[token]
                    assert decision["position"] == "1" and decision["actual_action"] == "2", "PRE DROP decision placement"
                    assert int(decision["rule"]) == info["config"]["version"]
                    assert int(decision["revision"]) == info["config"]["revision"]
                else:
                    assert terminals[token]["intent"] == "1" and token in flow_observes
            else:
                reply_tokens[payload].append(token)
                assert not info["config"]["drop"]
                assert terminals[token]["intent"] == "1" and token in flow_observes
        assert len(request_tokens) == len(expected)
        assert all(len(request_tokens[payload]) == 1 for payload in expected), "exactly one VPP request per send"
        assert all(len(reply_tokens[payload]) == (0 if info["config"]["drop"] else 1)
                   for payload, info in expected.items()), "only allowed requests have one VPP reply"

        endpoint = Counter(json.loads(line)["payload"] for line in read("endpoint.jsonl").splitlines()
                           if '"payload"' in line)
        host_capture = payloads(capture)
        for payload, info in expected.items():
            if info["config"]["drop"]:
                assert endpoint[payload] == 0 and host_capture[payload] == 0, "blocked packet reached endpoint"
            else:
                assert endpoint[payload] == 1 and host_capture[payload] >= 2, "allowed exchange missing independently"
        assert sum(endpoint.values()) == sent_allow
        assert basic_drop(final)-basic_drop(initial) == sent_drop, "basic DROP lost or gained a packet"
        missed = sum(final["health"]["blocked_capacity_misses"])
        previous_missed = sum(initial["health"]["blocked_capacity_misses"])
        missed -= previous_missed
        observed = final["consumer"]["persistent"]["blocked"]["packets"][0]
        observed -= initial["consumer"]["persistent"]["blocked"]["packets"][0]
        assert sent_drop == observed + missed, "cumulative blocked packets, loss and basic count disagree"
        assert final["consumer"]["persistent"]["blocked"]["bytes"][0] > 0
        assert final["health"]["blocked_capacity"] == 1024
        assert final["consumer"]["persistent"]["persistence"]["pending"] is False
        assert all(channel["full"] == 0 for channel in final["health"]["channels"])

        prefix = "t24-" if kind == "android" else ""
        allow_a = data(prefix+"allow-a.json")
        drop_a = data(prefix+"drop-a.json")
        allow_b = data(prefix+"allow-b.json")
        drop_b = data(prefix+"drop-b.json")
        f0 = main_record(allow_a,"records",port)
        f1 = main_record(drop_a,"records",port)
        f2 = main_record(allow_b,"records",port)
        f3 = main_record(drop_b,"records",port)
        identity = lambda r: (r["owner"],r["slot"],r["incarnation"])
        assert identity(f0) == identity(f1) == identity(f2) == identity(f3)
        assert f0["packets"] == f1["packets"] and f2["packets"] == f3["packets"]
        assert f2["packets"][0] > f1["packets"][0]
        b1 = main_record(drop_a,"blocked_records",port)
        b2 = main_record(allow_b,"blocked_records",port)
        b3 = main_record(drop_b,"blocked_records",port)
        assert identity(b1) == identity(b2) == identity(b3)
        assert b1["packets"] == b2["packets"] == [3,0] and b3["packets"] == [5,0], "blocked cumulative identity"
        assert b1["attribution"][0]["winner"] != b3["attribution"][0]["winner"]
        assert b1["blocked"] and not f1["blocked"]
        if kind == "linux":
            idle = data("idle-retired.json")
            idle_record = main_record(idle,"blocked_records",port)
            assert idle_record["ended"] is True and idle_record["end_reason"] == 2, "idle END reason"
            reused = main_record(data("tuple-reuse.json"),"blocked_records",port)
            assert reused["incarnation"] > b3["incarnation"] and reused["sequence"] == 1
            assert missed == result["pressure"]["capacity_misses"] > 0
            assert result["pressure"]["basic_delta"] == 3000
            assert result["pressure"]["blocked_delta"] + missed == 3000
            assert final["consumer"]["persistent"]["coverage"]["incomplete"] is True
            phase = next(row for row in result["phases"] if row["label"] == "pressure")
            before, after = phase["before"], phase["after"]
            hz = before["ticks_per_second"]
            assert hz == after["ticks_per_second"] and hz > 0
            cost = dict(vpp_cpu_ms=(after["vpp"]["cpu_ticks"]-before["vpp"]["cpu_ticks"])*1000/hz,
                rust_cpu_ms=(after["rust"]["cpu_ticks"]-before["rust"]["cpu_ticks"])*1000/hz,
                rust_write_bytes=after["rust"]["write_bytes"]-before["rust"]["write_bytes"],
                vpp_hwm_kib=after["vpp"]["hwm_kib"], rust_hwm_kib=after["rust"]["hwm_kib"],
                sender_ms=(data("pressure-traffic.json")["endMonoNs"]-data("pressure-traffic.json")["startMonoNs"])/1e6)
            assert all(value >= 0 for value in cost.values())
        else:
            assert missed == 0 and observed == 9
            cost = None
        return dict(status="VALID", kind=kind, profile=result["profile"],
            source_sha256=result["source_sha256"], result_sha256=digest(directory/"result.json"),
            sent_allow=sent_allow, sent_drop=sent_drop, vpp_packets=len(admits),
            blocked_observed=observed, capacity_misses=missed, endpoint_exchanges=sum(endpoint.values()),
            host_capture_packets=sum(host_capture.values()), cost=cost)
    except (AssertionError, KeyError, ValueError, IndexError, OSError) as error:
        return dict(status="HOLD", error=str(error))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("directory", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    verdict = verify(a.directory)
    a.output.write_text(json.dumps(verdict,indent=2)+"\n")
    print(json.dumps(verdict,indent=2))
    if verdict["status"] != "VALID": raise SystemExit(1)
