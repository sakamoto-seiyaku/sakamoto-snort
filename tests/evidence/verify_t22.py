#!/usr/bin/env python3
"""Independent T22 packet, cumulative, durable-window and recovery verifier.

Collector assertions and RAW_COMPLETE are not acceptance verdicts. Semantic
mutations are rehashed before verification, so file seals alone cannot pass them.
"""
import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]

def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def rows(text, prefix):
    return [dict(part.split("=", 1) for part in line.split() if "=" in part)
            for line in text.splitlines() if line.startswith(prefix)]
def flow(snapshot, port, incarnation=None):
    matches = [r for r in snapshot["consumer"]["overview"]["records"] if r
               and r["ports"][0] == port
               and (r["incarnation"] == incarnation if incarnation is not None else not r["ended"])]
    assert len(matches) == 1, "unique current Flow identity"
    return matches[0]
def persistent(snapshot): return snapshot["consumer"]["persistent"]
def add(left, right): return [a+b for a,b in zip(left, right)]
def sample(value, generation):
    assert "error" not in value and value["persistent_history"] is True
    h = value["health"]
    assert h["generation"] == generation and h["version"] == 2
    assert h["owners"] == 2 and h["flow_capacity"] == 1024 and h["mapping_bytes"] == 332544
    for i, channel in enumerate(h["channels"]):
        assert channel["capacity"] == 512 and channel["occupancy"] <= 512
        assert channel["oversize"] == channel["notify_errors"] == 0
        if i % 2: assert channel["attempted"] == 0, "debug capacity is independent"
    if value["consumer"] is None: return
    consumer = value["consumer"]
    assert consumer["malformed"] == 0 and consumer["error"] is None
    assert consumer["overview"]["generation"] == generation
    for record in consumer["overview"]["records"]:
        if record:
            assert record["generation"] == generation and record["activity_utc_us"] > 0
            assert record["last_seen"] >= record["first_seen"]
    summary = persistent(value)
    assert summary["schema"] == 1 and summary["storage"] == "atomic_json_snapshot"
    assert summary["coverage"]["scope"] == "observed_flows"
    assert summary["minute_query_limit"] == 2880 and not summary["minute_query_truncated"]
    assert all(int(key) % 60 == 0 for key in summary["minutes"]), "UTC aligned minutes"
    for field in ("packets", "bytes"):
        totals = [sum(bucket[field][direction] for bucket in summary["minutes"].values()) for direction in (0,1)]
        assert totals == summary[field], "maintained minute/totals conservation"

def native_packets(text, generation, port, source, payloads):
    trace = rows(text, "s216 ")
    stages = []
    for stage in ("admit", "policy", "terminal"):
        relevant = [r for r in trace if r["stage"] == stage and str(port) in (r["src_port"], r["dst_port"])]
        assert len(relevant) == len(payloads)*2, "actual native packet count"
        assert sum(int(r["packet_length"]) for r in relevant) == sum(payloads.values())*2
        assert {int(r["generation"]) for r in relevant} == {generation}
        assert {r["source"] for r in relevant} == source
        identities = {r["token"]:(r["packet_length"], r["src_port"], r["dst_port"],
                                  r["src"], r["dst"], r["source"]) for r in relevant}
        assert len(identities) == len(relevant), "unique native obligations"
        stages.append(identities)
        if stage == "admit":
            for direction in ("src_port", "dst_port"):
                actual = {bytes.fromhex(r["raw"])[int(r["transport_offset"])+8:int(r["packet_length"])].hex():
                          int(r["packet_length"]) for r in relevant if r[direction] == str(port)}
                assert actual == payloads, "native admission payload identity"
        if stage == "terminal": assert {r["intent"] for r in relevant} == {"1"}
    assert stages[0] == stages[1] == stages[2], "native cross-stage identity"

def verify(directory, overrides=None):
    directory = Path(directory); overrides = overrides or {}
    def read(name): return overrides[name] if name in overrides else (directory/name).read_text()
    def data(name): return json.loads(read(name))
    try:
        result = data("result.json")
        assert result["status"] == "RAW_COMPLETE" and result["completed_ns"] > result["started_ns"]
        for name, expected in result["files"].items():
            actual = hashlib.sha256(overrides[name].encode()).hexdigest() if name in overrides else digest(directory/name)
            assert actual == expected, "run file closure: "+name
        build_path = Path(result["build"]); build = json.loads(build_path.read_text())
        assert digest(build_path) == result["build_sha256"]
        assert build["source_sha256"] == result["source_sha256"]
        encoded = json.dumps(build["files"], sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(encoded).hexdigest() == build["source_sha256"]
        spec = importlib.util.spec_from_file_location("t22_chain", ROOT/"tests/evidence/product_chain.py")
        chain = importlib.util.module_from_spec(spec); spec.loader.exec_module(chain)
        assert chain.source_files() == build["files"], "current Product source differs"
        for name, expected in build["files"].items():
            if expected is not None: assert digest(build_path.parent/"source"/name) == expected, "source snapshot"
        assert digest(build_path.parent/"dirty.diff") == build["dirty_diff_sha256"]
        assert build["completed_ns"] < result["started_ns"], "source build precedes actual run"
        for item in result["snapshots"]: sample(data(item["label"]+".json"), item["generation"])

        if result["kind"] == "linux":
            for name, expected in build["artifact_hashes"].items():
                assert digest(Path(build["artifact"])/name) == expected, "Host artifact"
            assert result["profile"] == "root" and result["source"] == "NFQ_CAPTURED"
            generations = [life["generation"] for life in result["lifetimes"]]
            assert generations == [27301, 27302] and all(life["process_absent"] for life in result["lifetimes"])
            # Independent worked traffic oracle, including two successfully
            # forwarded echo pairs whose observations cannot be recovered.
            expected = {"created":(1,32), "tail":(3,40), "reused":(1,32),
                        "save-failed":(2,36), "save-recovered":(1,44),
                        "write-interrupted":(1,32), "unrecoverable":(1,32), "new-generation":(3,48)}
            traffic = {item["label"]:item for item in result["traffic"]}
            assert set(traffic) == set(expected)
            endpoint = [json.loads(line) for line in read("endpoint.jsonl").splitlines()]
            endpoint_payloads = {entry["payload"]:entry["payload_bytes"]+28 for entry in endpoint}
            assert len(endpoint) == len(endpoint_payloads) == 13 and sum(endpoint_payloads.values()) == 872
            by_generation = {g:{} for g in generations}
            for label,(count,size) in expected.items():
                item = traffic[label]
                assert (item["count"],item["payload_bytes"],item["ip_bytes"]) == (count,size,size+28)
                assert len(item["payloads"]) == len(set(item["payloads"])) == count
                assert item["started_ns"] < item["completed_ns"]
                for payload in item["payloads"]:
                    assert len(bytes.fromhex(payload)) == size and endpoint_payloads[payload] == size+28
                    by_generation[item["generation"]][payload] = size+28
            assert {**by_generation[27301], **by_generation[27302]} == endpoint_payloads
            for g,payloads in by_generation.items():
                native_packets(read(f"vpp-{g}.log"), g, 42132, {"NFQ_CAPTURED"}, payloads)
                assert "stop_native_zero" in read(f"vpp-{g}.log")
                assert "\"rules\":[]" in read(f"g{g}-configuration.txt").replace(" ", ""), "known empty configuration"
            cases = {"baseline":(0,0,0), "quiet":(1,60,0), "end-tail":(4,264,1),
                     "reused":(5,324,1), "save-failed":(5,324,1), "save-recovered":(8,524,1),
                     "late-end":(8,524,2), "restart":(8,524,2), "new-generation":(11,752,2), "final":(11,752,3)}
            snapshots = {name:data(name+".json") for name in cases}
            for name,(packets,byte_count,ended) in cases.items():
                summary = persistent(snapshots[name])
                assert summary["packets"] == [packets]*2 and summary["bytes"] == [byte_count]*2, name
                assert summary["ended"] == ended, "persisted lifecycle: "+name
            first = flow(snapshots["quiet"],42132)
            end = flow(snapshots["end-tail"],42132,first["incarnation"])
            assert first["addresses"] == [10,222,0,1,10,222,0,2] and first["uid"] == 12001
            assert end["ended"] and end["packets"] == [4,4] and end["bytes"] == [264,264]
            assert end["sequence"] == first["sequence"]+1, "combined END tail"
            assert flow(snapshots["reused"],42132)["incarnation"] > first["incarnation"]
            for name,label in [("quiet","created"),("reused","reused"),("save-recovered","save-recovered"),("new-generation","new-generation")]:
                record = flow(snapshots[name],42132); item = traffic[label]
                assert item["started_ns"] <= record["activity_utc_us"]*1000 <= item["completed_ns"], "real activity UTC"
                assert str(record["activity_utc_us"]//60_000_000*60) in persistent(snapshots[name])["minutes"]
            before_end = flow(snapshots["save-recovered"],42132)
            late_end = flow(snapshots["late-end"],42132,before_end["incarnation"])
            assert late_end["ended"] and late_end["activity_utc_us"] == before_end["activity_utc_us"]
            assert result["late_end_ns"]//60_000_000_000 > late_end["activity_utc_us"]//60_000_000
            assert persistent(snapshots["late-end"])["minutes"] == persistent(snapshots["save-recovered"])["minutes"], "END receive minute did not move traffic"
            failed = persistent(snapshots["save-failed"])
            assert failed["save_error"] and failed["coverage"]["incomplete"]
            assert persistent(snapshots["save-recovered"])["save_error"] is None
            assert persistent(snapshots["restart"])["coverage"]["recoveries"] == 1
            assert persistent(snapshots["restart"])["coverage"]["incomplete"]
            assert persistent(snapshots["final"])["baselines"] == 2
            assert "\nState:\tT" in read("consumer-interrupted-status.txt"), "actual consumer stopped mid-write"
            try: json.loads(read("interrupted-pending.json"))
            except json.JSONDecodeError: pass
            else: raise AssertionError("interrupted snapshot must actually be incomplete")
            assert data("committed-before-kill.json")["totals"] == {"packets":[8,8],"bytes":[524,524]}
            committed = data("final-store.json")
            assert committed["totals"] == {"packets":[11,11],"bytes":[752,752]}
            assert committed["open_session"] is False and committed["gaps"] > 0
            assert result["final_store_mode"] == "0o600"
            assert hashlib.sha256(read("final-store.json").encode()).hexdigest() == result["final_store_sha256"]
            syncs = read("fsync-witness.txt").splitlines()
            parent_sync = "fsync result=0 path="+str(directory.resolve())
            first_file = "fsync result=0 path="+str(directory.resolve()/"observation/overall.pending")
            assert syncs.index(parent_sync) < syncs.index(first_file), "directory entry durable before snapshot"
            coverage = "Linux real packets, write failure, partial-write kill, UTC END placement and persistent generation recovery"
        else:
            assert result["kind"] == "android"
            assert [life["profile"] for life in result["lifetimes"]] == ["root","vpn"]
            assert len({life["generation"] for life in result["lifetimes"]}) == 2
            assert len({life["app_pid"] for life in result["lifetimes"]}) == 2, "actual service process recovery"
            assert digest(build["apk"]) == build["apk_sha256"] == result["apk_sha256"]
            assert read("installed-apk.txt").split()[0] == build["apk_sha256"]
            installed = {Path(line.split()[1]).name:line.split()[0] for line in read("installed-native.txt").splitlines()}
            assert installed == build["native_sha256"] == result["native_sha256"]
            with zipfile.ZipFile(build["apk"]) as apk:
                assert {Path(name).name:hashlib.sha256(apk.read(name)).hexdigest() for name in apk.namelist()
                        if name.startswith("lib/arm64-v8a/") and name.endswith(".so")} == installed
            assert "bluejay" in read("device.txt")
            assert "0 packets dropped by kernel" in read("device-capture.log")
            assert "0 packets dropped by kernel" in read("host-capture.log")
            captures = {}
            for name in ("device.pcap","host.pcap"):
                command = ["tshark","-r",str(directory/name),"-Y","udp.port==42121","-T","fields"]
                for field in ("ip.src","ip.dst","udp.srcport","udp.dstport","ip.len","udp.payload"): command.extend(["-e",field])
                captures[name] = [line.split("\t") for line in subprocess.check_output(command,text=True).splitlines()]
            endpoint = [json.loads(line) for line in read("endpoint.jsonl").splitlines() if '"kind": "echo"' in line]
            operations = [json.loads(line) for line in read("operations.jsonl").splitlines()]
            preceding = data("before-store.json")
            preceding = preceding["totals"] if preceding is not None else {"packets":[0,0],"bytes":[0,0]}
            for life in result["lifetimes"]:
                profile,generation = life["profile"],life["generation"]
                port = 42122 if profile == "root" else 42123
                plan = next(item["plan"] for item in result["plans"] if item["profile"] == profile)
                flood = plan["observationFlood"]
                assert flood == 100, "declared bounded representative load"
                assert life["process_absent"] and life["mapping_released"] and life["service_process_absent"]
                assert "state=stopped" in read(profile+"-stopped-latest.properties")
                assert "sakamoto-observation" not in read(profile+"-app-stopped-maps.txt")
                baseline = persistent(data(profile+"-baseline.json"))
                assert baseline["packets"] == preceding["packets"] and baseline["bytes"] == preceding["bytes"], "restored persistent baseline"
                assert life["baseline_packets"] == baseline["packets"] and life["baseline_bytes"] == baseline["bytes"]
                quiet = data(profile+"-quiet.json"); first = flow(quiet,port)
                probe = data(profile+"-observation_created.json")
                local = probe["local"].lstrip("/").rsplit(":",1)[0]
                assert first["addresses"] == list(ipaddress.ip_address(local).packed+ipaddress.ip_address(result["endpoint"]).packed)
                assert first["uid"] == result["uid"] and first["packets"] == [1,1] and first["bytes"] == [60,60]
                end = flow(data(profile+"-end-tail.json"),port,first["incarnation"])
                assert end["ended"] and end["packets"] == [4,4] and end["bytes"] == [264,264]
                reuse = flow(data(profile+"-reused.json"),port)
                assert reuse["incarnation"] > first["incarnation"]
                for suffix in ("before","after"):
                    activity = read(profile+"-background-"+suffix+".txt")
                    resumed = [line for line in activity.splitlines() if "topResumedActivity=" in line or "mResumedActivity=" in line]
                    assert resumed and all("com.sakamoto.snort.androidruntime" not in line for line in resumed), "foreground UI remained closed"
                background_operations = [operation for operation in operations
                    if life["background_started_ns"] <= operation["started_ns"] <= life["background_completed_ns"]]
                assert background_operations and not any(operation["argv"][:3] == ["shell","am","start"]
                    for operation in background_operations), "no UI query drove background ingestion"
                background = data(profile+"-background-store.json")
                assert background["totals"]["packets"] == add(baseline["packets"],[105,105])
                assert background["totals"]["bytes"] == add(baseline["bytes"],[6324,6324])
                assert persistent(data(profile+"-background-query.json"))["packets"] == background["totals"]["packets"]
                final = persistent(data(profile+"-final.json"))
                assert final["packets"] == add(baseline["packets"],[106,106])
                assert final["bytes"] == add(baseline["bytes"],[6384,6384])
                assert final["save_error"] is None
                stopped = data(profile+"-stopped-store.json")
                assert stopped["open_session"] is False and stopped["gaps"] > 0, "disconnect coverage boundary"
                assert stopped["totals"] == {field:final[field] for field in ("packets","bytes")}
                preceding = stopped["totals"]
                finished = data(profile+"-finished.json")
                assert finished["sent"] == finished["received"] == 106 and not finished.get("error")
                marker = plan["nonce"].encode()[:22]
                matching = [entry for entry in endpoint if marker in bytes.fromhex(entry["payload"])]
                payloads = {entry["payload"]:entry["bytes"]+28 for entry in matching}
                assert len(matching) == len(payloads) == 106 and sum(payloads.values()) == 6384
                for name,packets in captures.items():
                    for direction in (0,1):
                        selected = [packet for packet in packets if len(packet) == 6 and marker in bytes.fromhex(packet[5])
                                    and packet[3 if direction == 0 else 2] == "42121"
                                    and (name == "host.pcap" or packet[0 if direction == 0 else 1] == local)]
                        assert {packet[5]:int(packet[4]) for packet in selected} == payloads, "two-end captured payload identity"
                native_packets(read(profile+"-vpp.log"),generation,port,
                               {"NFQ_CAPTURED"} if profile == "root" else {"TUN_CAPTURED","FLOW_STACK_RETURN"},payloads)
            coverage = "Android Root+VPN real persistent minutes, closed foreground ingestion and actual service process recovery"
        return dict(status="PASS", coverage=coverage, source_sha256=build["source_sha256"],
                    run=str(directory), verifier_sha256=digest(__file__))
    except (AssertionError,OSError,KeyError,ValueError,StopIteration,subprocess.CalledProcessError) as error:
        return dict(status="HOLD", error=str(error), run=str(directory), verifier_sha256=digest(__file__))

def mutations(directory):
    directory = Path(directory); original = json.loads((directory/"result.json").read_text())
    cases = []
    def consistent_overcount(value):
        summary = persistent(value)
        latest = max(summary["minutes"],key=int)
        summary["packets"][0] += 1; summary["bytes"][0] += 60
        summary["minutes"][latest]["packets"][0] += 1
        summary["minutes"][latest]["bytes"][0] += 60
    if original["kind"] == "linux":
        cases = [
            ("lost-baseline", "restart.json", lambda v:v["consumer"]["persistent"].update(packets=[0,0])),
            ("duplicate-accounting", "final.json", lambda v:v["consumer"]["persistent"].update(bytes=[1016,1016])),
            ("overcount-with-consistent-buckets", "final.json", consistent_overcount),
            ("hidden-recovery-gap", "restart.json", lambda v:v["consumer"]["persistent"]["coverage"].update(incomplete=False)),
            ("wrong-END-time", "late-end.json", lambda v:next(r for r in v["consumer"]["overview"]["records"] if r).update(activity_utc_us=original["late_end_ns"]//1000)),
            ("non-atomic-durable-total", "final-store.json", lambda v:v["totals"].update(packets=[12,11])),
        ]
    else:
        cases = [
            ("lost-service-baseline", "vpn-baseline.json", lambda v:v["consumer"]["persistent"].update(packets=[0,0])),
            ("overcount-with-consistent-buckets", "vpn-final.json", consistent_overcount),
            ("missing-background-consumption", "root-background-store.json", lambda v:v["totals"].update(packets=[0,0])),
            ("hidden-shutdown-gap", "root-stopped-store.json", lambda v:v.update(gaps=0)),
            ("wrong-generation", "root-quiet.json", lambda v:v["health"].update(generation=1)),
            ("missing-delivery", "vpn-finished.json", lambda v:v.update(received=0)),
        ]
    rejected = []
    for label,name,mutate in cases:
        value = json.loads((directory/name).read_text()); mutate(value)
        text = json.dumps(value); seal = copy.deepcopy(original)
        seal["files"][name] = hashlib.sha256(text.encode()).hexdigest()
        if name == "final-store.json": seal["final_store_sha256"] = seal["files"][name]
        result = verify(directory,{name:text,"result.json":json.dumps(seal)})
        assert result["status"] == "HOLD", "insensitive verifier: "+label
        rejected.append(dict(case=label,reason=result["error"]))
    trace = "vpp-27301.log" if original["kind"] == "linux" else "root-vpp.log"
    raw_cases = [
        ("substituted-terminal-identity",trace,lambda text:re.sub(
            r"(?m)^(s216 stage=terminal [^\n]*? token=)(\d+)",
            lambda match:match[1]+str(int(match[2])+100000000),text,count=1)),
        ("substituted-endpoint-payload","endpoint.jsonl",lambda text:re.sub(
            r'("payload"\s*:\s*")([0-9a-f])',
            lambda match:match[1]+("f" if match[2] != "f" else "e"),text,count=1)),
    ]
    for label,name,mutate in raw_cases:
        old = (directory/name).read_text(); text = mutate(old)
        assert text != old, "mutation did not alter evidence"
        seal = copy.deepcopy(original); seal["files"][name] = hashlib.sha256(text.encode()).hexdigest()
        result = verify(directory,{name:text,"result.json":json.dumps(seal)})
        assert result["status"] == "HOLD", "insensitive verifier: "+label
        rejected.append(dict(case=label,reason=result["error"]))
    return rejected

if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("run",type=Path)
    parser.add_argument("--mutations",action="store_true"); parser.add_argument("--output",type=Path)
    args = parser.parse_args(); result = verify(args.run)
    if args.mutations and result["status"] == "PASS": result["mutations_rejected"] = mutations(args.run)
    if args.output: args.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    raise SystemExit(result["status"] != "PASS")
