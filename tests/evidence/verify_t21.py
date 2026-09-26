#!/usr/bin/env python3
"""Independent T21 source/artifact, packet and observation evidence verifier.

The collectors' RAW_COMPLETE flag is only an input, never a PASS verdict.
Android representative acceptance does not claim that its normal queue filled.
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


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rows(text, prefix):
    return [dict(item.split("=", 1) for item in line.split() if "=" in item)
            for line in text.splitlines() if line.startswith(prefix)]


def verify(directory, overrides=None):
    directory = Path(directory)
    overrides = overrides or {}
    def read(name):
        return overrides.get(name, (directory / name).read_text())
    def data(name):
        return json.loads(read(name))
    def flow(snapshot, port, incarnation=None):
        found = [r for r in snapshot["consumer"]["overview"]["records"] if r
                 and r["ports"][0] == port and
                 (r["incarnation"] == incarnation if incarnation is not None else not r["ended"])]
        assert len(found) == 1, ("flow identity", port, incarnation)
        return found[0]
    def basic(snapshot, field):
        return sum(snapshot["health"]["channels"][i][field][0] for i in (0, 2))
    def sample(snapshot, generation, stable=False):
        assert snapshot["persistent_history"] is False
        h = snapshot["health"]
        assert h["generation"] == generation and h["version"] == 1
        assert h["owners"] == 2 and h["flow_capacity"] == 1024
        assert h["mapping_bytes"] == 316160
        for i, c in enumerate(h["channels"]):
            assert c["capacity"] == 512 and c["occupancy"] <= 512
            assert c["notify_errors"] == c["oversize"] == 0
            if stable:
                assert c["attempted"] == c["published"] + c["full"]
                assert c["published"] == c["consumed"] + c["occupancy"]
            if i % 2:
                assert c["attempted"] == 0, "reserved debug isolation"
        if snapshot["consumer"] is not None:
            assert snapshot["consumer"]["overview"]["generation"] == generation
            assert snapshot["consumer"]["malformed"] == 0
            for r in snapshot["consumer"]["overview"]["records"]:
                if r: assert r["generation"] == generation
    try:
        result = data("result.json")
        assert result["status"] == "RAW_COMPLETE", "collector incomplete"
        assert result["completed_ns"] > result["started_ns"]
        for name, expected in result["files"].items():
            actual = hashlib.sha256(overrides[name].encode()).hexdigest() if name in overrides else digest(directory/name)
            assert actual == expected, "run file closure: " + name
        build_path = Path(result["build"])
        b = json.loads(build_path.read_text())
        assert digest(build_path) == result["build_sha256"], "build identity"
        assert b["source_sha256"] == result["source_sha256"]
        encoded = json.dumps(b["files"], sort_keys=True, separators=(",", ":")).encode()
        assert hashlib.sha256(encoded).hexdigest() == b["source_sha256"]
        spec = importlib.util.spec_from_file_location("t21_chain", ROOT/"tests/evidence/product_chain.py")
        chain = importlib.util.module_from_spec(spec); spec.loader.exec_module(chain)
        assert chain.source_files() == b["files"], "current Product differs from build"
        for name, expected in b["files"].items():
            if expected is not None:
                assert digest(build_path.parent/"source"/name) == expected, "source snapshot: " + name
        assert digest(build_path.parent/"dirty.diff") == b["dirty_diff_sha256"]
        assert b["completed_ns"] < result["started_ns"], "build before execution"
        if "lifetimes" not in result:
            for name, expected in b["artifact_hashes"].items():
                assert digest(Path(b["artifact"])/name) == expected, "Host artifact: " + name
            g = result["generation"]
            assert result["source"] == "NFQ_CAPTURED" and result["profile"] == "root"
            assert result["process_absent"]
            timeout = data("pending-timeout.json")
            assert timeout["eof"] and 1 <= timeout["elapsed"] < 4
            assert '"connected":0' in read("unclaimed-query.txt").replace(" ", "")
            snaps = {name: data(name + ".json") for name in set(result["snapshots"])}
            for name, s in snaps.items(): sample(s, g, stable=name in ("baseline", "quiet-flush", "paused", "full", "resumed"))
            q = flow(snaps["quiet-flush"], 42122)
            assert q["packets"] == [1, 1] and q["bytes"] == [60, 60]
            assert q["addresses"] == [10, 221, 0, 1, 10, 221, 0, 2]
            assert q["family"] == 4 and q["protocol"] == 17 and q["uid"] == 12001
            ended = flow(snaps["end-tail"], 42122, q["incarnation"])
            assert ended["ended"] and ended["packets"] == [4, 4] and ended["bytes"] == [264, 264]
            assert ended["sequence"] == q["sequence"] + 1, "END carries unexported tail"
            assert flow(snaps["tuple-reuse"], 42122)["incarnation"] > q["incarnation"]
            assert rows(read("before-flush-flows.txt"), "flow.timer ") == rows(read("after-flush-flows.txt"), "flow.timer ")
            full = snaps["full"]
            assert full["consumer"]["overview"]["accepted"] == snaps["paused"]["consumer"]["overview"]["accepted"]
            assert sum(c["full"] for c in full["health"]["channels"]) > 0
            assert basic(full, "basic_packets") == 4810 and basic(full, "basic_bytes") == 288648
            assert snaps["resumed"]["consumer"]["overview"]["incomplete"]
            assert all(c["occupancy"] == 0 for c in snaps["resumed"]["health"]["channels"])
            assert len(read("burst.jsonl").splitlines()) == 2400
            pools = rows(read("capacity-flows.txt"), "flow.runtime ")
            assert len(pools) == 2 and all(int(p["high_watermark"]) == 1024 and int(p["capacity_misses"]) > 0 for p in pools)
            def api(name):
                return json.loads(next(l.split("=", 1)[1] for l in read(name).splitlines() if l.startswith("observation.response=")))
            dead = api("consumer-dead.txt"); sample(dead, g, stable=True)
            assert dead["health"]["connected"] == 0 and basic(dead, "basic_packets") == 4812
            bypass = api("bypass-health.txt"); sample(bypass, g, stable=True)
            assert basic(bypass, "basic_packets") == 4876 and basic(bypass, "basic_bytes") == 292608
            assert len(read("bypass.jsonl").splitlines()) == 32
            before = rows(read("bypass-before.txt"), "primary.status ")[0]
            after = rows(read("bypass-after.txt"), "primary.status ")[0]
            assert int(after["rejected"]) > int(before["rejected"])
            endpoints = [json.loads(l) for l in read("endpoint.jsonl").splitlines()]
            assert len(endpoints) == 2438 and sum(e["bytes"] + 28 for e in endpoints)*2 == 292608
            assert "stop_native_zero" in read("vpp.log")
            coverage = "Linux real NFQUEUE; full queues, Flow capacity, consumer death, pending-peer expiry, handoff bypass"
        else:
            assert {x["profile"] for x in result["lifetimes"]} == {"root", "vpn"}
            assert len({x["generation"] for x in result["lifetimes"]}) == 2
            assert digest(b["apk"]) == b["apk_sha256"] == result["apk_sha256"]
            assert read("installed-apk.txt").split()[0] == b["apk_sha256"]
            installed = {Path(l.split()[1]).name: l.split()[0] for l in read("installed-native.txt").splitlines()}
            assert installed == b["native_sha256"] == result["native_sha256"]
            with zipfile.ZipFile(b["apk"]) as z:
                assert {Path(n).name: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()
                        if n.startswith("lib/arm64-v8a/") and n.endswith(".so")} == installed
            assert "bluejay" in read("device.txt")
            assert "0 packets dropped by kernel" in read("device-capture.log")
            assert "0 packets dropped by kernel" in read("host-capture.log")
            captures = {}
            for name in ("device.pcap", "host.pcap"):
                fields = ("ip.src", "ip.dst", "udp.srcport", "udp.dstport", "ip.len", "udp.payload")
                command = ["tshark", "-r", str(directory/name), "-Y", "udp.port==42121", "-T", "fields"]
                for field in fields: command.extend(["-e", field])
                captures[name] = [line.split("\t") for line in subprocess.check_output(command, text=True).splitlines()]
            endpoint = [json.loads(l) for l in read("endpoint.jsonl").splitlines() if '"kind": "echo"' in l]
            for life in result["lifetimes"]:
                profile, g = life["profile"], life["generation"]
                port = 42122 if profile == "root" else 42123
                plan = next(x["plan"] for x in result["plans"] if x["profile"] == profile)
                flood = plan["observationFlood"]
                assert life["process_absent"] and life["mapping_released"]
                assert "state=stopped" in read(profile+"-stopped-latest.properties")
                assert "sakamoto-observation" in read(profile+"-app-live-maps.txt")
                assert "sakamoto-observation" in read(profile+"-vpp-live-maps.txt")
                assert "sakamoto-observation" not in read(profile+"-app-stopped-maps.txt")
                assert read(profile+"-socket-mode.txt").strip().split(":")[-1] == "600"
                for entry in result["snapshots"]:
                    if entry["profile"] == profile:
                        assert entry["generation"] == g
                        sample(data(entry["label"]+".json"), g)
                quiet = data(profile+"-quiet.json"); q = flow(quiet, port)
                assert q["packets"] == [1, 1] and q["bytes"] == [60, 60]
                probe = data(profile+"-observation_created.json")
                local = probe["local"].lstrip("/").rsplit(":", 1)[0]
                assert q["addresses"] == list(ipaddress.ip_address(local).packed + ipaddress.ip_address(result["endpoint"]).packed)
                assert q["uid"] == result["uid"] and q["protocol"] == 17 and q["family"] == 4
                ended = flow(data(profile+"-end-tail.json"), port, q["incarnation"])
                assert ended["ended"] and ended["packets"] == [4, 4] and ended["bytes"] == [264, 264]
                assert ended["last_seen"] >= q["last_seen"]
                assert rows(read(profile+"-before-flush.txt"), "flow.timer ") == rows(read(profile+"-after-flush.txt"), "flow.timer ")
                reuse = flow(data(profile+"-reused.json"), port)
                assert reuse["incarnation"] > q["incarnation"]
                paused = data(profile+"-paused.json"); full = data(profile+"-full.json")
                assert full["consumer"]["overview"]["accepted"] == paused["consumer"]["overview"]["accepted"]
                if result["requires_full_queue"]:
                    assert sum(c["full"] for c in full["health"]["channels"]) > sum(c["full"] for c in paused["health"]["channels"])
                    assert life["end_only_tail_packets"] > 0
                tail = flow(data(profile+"-full-end-tail.json"), port, reuse["incarnation"])
                assert tail["ended"] and tail["packets"] == [flood+1]*2 and tail["bytes"] == [(flood+1)*60]*2
                last = flow(data(profile+"-last-reuse.json"), port)
                assert last["incarnation"] > reuse["incarnation"]
                final = flow(data(profile+"-final.json"), port, last["incarnation"])
                assert final["ended"] and final["packets"] == [1, 1] and final["bytes"] == [60, 60]
                finished = data(profile+"-finished.json")
                assert finished["sent"] == finished["received"] == flood + 6 and not finished.get("error")
                matching = [e for e in endpoint if plan["nonce"].encode()[:22] in bytes.fromhex(e["payload"])]
                assert len(matching) == flood+6
                endpoint_payloads = {e["payload"]: e["bytes"]+28 for e in matching}
                assert len(endpoint_payloads) == flood+6
                marker = plan["nonce"].encode()[:22]
                for capture, packets in captures.items():
                    # Android any-interface capture can see the same outgoing
                    # datagram more than once. Unique numbered payloads prove
                    # endpoint delivery; native obligation identities below
                    # independently establish exact Product packet accounting.
                    for direction in (0, 1):
                        chosen = [p for p in packets if len(p) == 6 and marker in bytes.fromhex(p[5])
                                  and p[3 if direction == 0 else 2] == "42121"
                                  and (capture == "host.pcap" or p[0 if direction == 0 else 1] == local)]
                        unique = {p[5]: int(p[4]) for p in chosen}
                        assert len(unique) == flood+6, (capture, profile, direction, "captured delivery")
                        assert sum(unique.values()) == (flood+6)*60+24
                        assert unique == endpoint_payloads, (capture, profile, direction, "payload identities")
                trace = rows(read(profile+"-vpp.log"), "s216 ")
                stage_identities = []
                for stage in ("admit", "policy", "terminal"):
                    relevant = [r for r in trace if r["stage"] == stage and str(port) in (r["src_port"], r["dst_port"])]
                    assert len(relevant) == (flood+6)*2
                    assert sum(int(r["packet_length"]) for r in relevant) == (flood+6)*120+48
                    assert {int(r["generation"]) for r in relevant} == {g}
                    assert len({r["token"] for r in relevant}) == (flood+6)*2
                    stage_identities.append({r["token"]: (r["packet_length"], r["src_port"], r["dst_port"],
                        r["src"], r["dst"], r["source"]) for r in relevant})
                    assert {r["source"] for r in relevant} == ({"NFQ_CAPTURED"} if profile == "root" else {"TUN_CAPTURED", "FLOW_STACK_RETURN"})
                    if stage == "admit":
                        for source_field in ("src_port", "dst_port"):
                            directional = [r for r in relevant if r[source_field] == str(port)]
                            payloads = {bytes.fromhex(r["raw"])[int(r["transport_offset"])+8:int(r["packet_length"])].hex():
                                        int(r["packet_length"]) for r in directional}
                            assert payloads == endpoint_payloads, "native admission payload identities"
                    if stage == "terminal": assert {r["intent"] for r in relevant} == {"1"}
                assert stage_identities[0] == stage_identities[1] == stage_identities[2], "native cross-stage identities"
            coverage = "Android Root+VPN representative traffic/quiet flush/END/reuse, pause/resume, FD and mapping release"
        return dict(status="PASS", coverage=coverage, source_sha256=b["source_sha256"], run=str(directory), verifier_sha256=digest(__file__))
    except (AssertionError, OSError, KeyError, ValueError, StopIteration) as error:
        return dict(status="HOLD", error=str(error), run=str(directory))


def mutations(directory):
    """Rehash mutated raw JSON, so failure must also survive a valid file seal."""
    directory = Path(directory)
    result = json.loads((directory/"result.json").read_text())
    assert "lifetimes" in result
    cases = [
        ("wrong-generation", "root-quiet.json", lambda s: s["health"].update(generation=1)),
        ("wrong-direction-total", "root-quiet.json", lambda s: next(r for r in s["consumer"]["overview"]["records"] if r)["packets"].__setitem__(1, 0)),
        ("zero-address", "root-quiet.json", lambda s: next(r for r in s["consumer"]["overview"]["records"] if r).update(addresses=[0]*8)),
        ("missing-END", "root-end-tail.json", lambda s: next(r for r in s["consumer"]["overview"]["records"] if r).update(ended=False)),
        ("tail-under-count", "root-end-tail.json", lambda s: next(r for r in s["consumer"]["overview"]["records"] if r).update(bytes=[60,60])),
        ("wrong-owner-count", "vpn-quiet.json", lambda s: s["health"].update(owners=1)),
        ("notification-error", "vpn-quiet.json", lambda s: s["health"]["channels"][0].update(notify_errors=1)),
        ("debug-interference", "vpn-quiet.json", lambda s: s["health"]["channels"][1].update(attempted=1)),
        ("delivery-missing", "vpn-finished.json", lambda s: s.update(received=0)),
    ]
    rejected = []
    for label, name, mutate in cases:
        value = json.loads((directory/name).read_text()); mutate(value)
        text = json.dumps(value)
        seal = copy.deepcopy(result); seal["files"][name] = hashlib.sha256(text.encode()).hexdigest()
        check = verify(directory, {name:text, "result.json":json.dumps(seal)})
        assert check["status"] == "HOLD", label
        rejected.append(label)
    raw_cases = [
        ("substituted-terminal-token", "root-vpp.log", lambda s: re.sub(
            r"(?m)^(s216 stage=terminal [^\n]*? token=)(\d+)",
            lambda m: m[1]+str(int(m[2])+100000000), s, count=1)),
        ("substituted-endpoint-payload", "endpoint.jsonl", lambda s: s.replace("3030303030303030", "3030303030303939", 1)),
    ]
    for label, name, mutate in raw_cases:
        text = mutate((directory/name).read_text())
        seal = copy.deepcopy(result); seal["files"][name] = hashlib.sha256(text.encode()).hexdigest()
        assert verify(directory, {name:text, "result.json":json.dumps(seal)})["status"] == "HOLD", label
        rejected.append(label)
    return rejected


if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("run", type=Path)
    p.add_argument("--output", type=Path); p.add_argument("--mutations", action="store_true")
    a = p.parse_args(); report = verify(a.run)
    if a.mutations and report["status"] == "PASS": report["rejected_mutations"] = mutations(a.run)
    text = json.dumps(report, indent=2)+"\n"
    if a.output: a.output.write_text(text)
    print(text, end="")
    raise SystemExit(report["status"] != "PASS")
