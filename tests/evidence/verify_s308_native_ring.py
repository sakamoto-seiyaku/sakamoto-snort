#!/usr/bin/env python3
"""Check S308's external-pause native ring fault from retained raw evidence."""
import argparse
from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import struct
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/benchmark"))
import pixel_quick as quick


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(raw, prefix):
    return [dict(re.findall(r"(\w+)=([^\s]+)", line))
            for line in raw.splitlines() if line.startswith(prefix)]


def one(raw, prefix):
    found = rows(raw, prefix)
    assert len(found) == 1, (prefix, len(found))
    return found[0]


def identities(values, key="token"):
    return Counter((row[key], row["buffer"]) for row in values)


def verify(path, apk):
    result = json.loads((path / "result.json").read_text())
    assert result["status"] == "PASS", result
    generation = str(result["generation"])
    owners = result["owner_count"]
    assert owners in (1, 3) and result["owner"] == owners - 1
    assert result["apk_sha256"] == digest(apk)
    with zipfile.ZipFile(apk) as archive:
        native = {Path(name).name: hashlib.sha256(archive.read(name)).hexdigest()
                  for name in archive.namelist()
                  if name.startswith("lib/arm64-v8a/") and name.endswith(".so")}
    assert result["native_sha256"] == native
    installed = json.loads((path / "install/identity.json").read_text())
    assert installed["apk_sha256"] == result["apk_sha256"]
    assert installed["native_sha256"] == native
    assert result["restored_apk_sha256"] == "cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110"
    assert result["final_state"]["state"] == "stopped"
    assert result["final_state"]["mayBeActive"] == "false"

    before = (path / "before.txt").read_text()
    topology = quick.rows(before, "topology.profile=")[0]
    assert topology["owner_count"] == str(owners)
    assert topology["actual_vpp_workers"] == str(owners + 1)
    assert f"topology.tun_io_lane=0 worker={owners} thread_index={owners + 1}" in before
    assert f"capacity.configured generation={generation} credits=48 primary_slots=64 completion_slots=2" in before

    probe = (path / "ptrace-probe.txt").read_text()
    assert one(probe, "event=paused ")["generation"] == generation
    assert one(probe, "event=resumed ")["result"] == "PASS"
    for trace in (probe, (path / "pause-and-ring.txt").read_text()):
        resumed_trace = one(trace, "event=resumed ")
        assert all(resumed_trace[key] == "1" for key in ("seized", "stopped", "detach_success"))
        status = dict(re.findall(r"event=task_status phase=(before|paused|after) TracerPid:\s*(\d+)", trace))
        assert status["before"] == status["after"] == "0" and int(status["paused"]) > 0
        assert re.search(r"event=task_status phase=paused State:\s*t ", trace)
        debt = one(trace, "event=original_debts ")
        assert all(debt[key] == "0" for key in ("obligations", "buffers", "handoffs", "frames"))
    raw = (path / "pause-and-ring.txt").read_text()
    empty = one(raw, "event=before ")
    paused = one(raw, "event=paused ")
    resumed = one(raw, "event=resumed ")
    assert empty["generation"] == paused["generation"] == generation
    assert empty["pid"] == paused["pid"] and empty["tid"] == paused["tid"]
    assert empty["owners"] == str(owners) and empty["originals_debt"] == "0"
    assert empty["slots"] == "2" and empty["head"] == empty["tail"]
    assert resumed["result"] == "PASS" and resumed["full"] == "1"
    assert int(resumed["elapsed_ns"]) <= 2_000_000_000
    full = rows(raw, "event=snapshot ")
    assert full and all(row["head"] == empty["head"] for row in full)
    assert any(int(row["tail"]) - int(row["head"]) == 1
               and row["slots"] == "2" and row["valid"] == "1"
               and 0 < int(row["vectors"]) <= 64
               and int(row["deferred"]) > int(empty["deferred"])
               and int(row["pending"]) > 0 for row in full)
    drained = one((path / "queue-drained.txt").read_text(), "event=before ")
    assert drained["generation"] == generation and drained["fq"] == empty["fq"]
    assert drained["head"] == drained["tail"]
    assert int(drained["head"]) > int(empty["head"])

    responses = json.loads((path / "server-responses.json").read_text())
    assert len(responses) == len(set(responses)) == 65
    assert all(value.startswith(result["nonce"] + ":0") for value in responses)
    log = (path / "vpp.log").read_text()
    copies = rows(log, "s237 event=return_copy ")
    completions = rows(log, "s213 event=completion source=FLOW_STACK_RETURN ")
    credits = rows(log, "s239 event=return_credit_released ")
    writes = rows(log, "s298 event=write_wire ")
    assert all(len(values) == 65 for values in (copies, completions, credits, writes))
    assert all(row["generation"] == generation for row in copies + completions + credits + writes)
    expected = identities(copies)
    assert len(expected) == 65 and all(count == 1 for count in expected.values())
    assert expected == identities(completions) == identities(credits) == identities(writes)
    tokens = {row["token"] for row in copies}
    frees = [row for row in rows(log, "s203 event=buffer_free ")
             if row["obligation"] in tokens]
    assert expected == identities(frees, "obligation")
    assert all(row["owner"] == str(owners - 1) and row["after_native_free"] == "1"
               and row["thread"] == str(owners + 1) for row in credits)
    assert all(row["thread"] == str(owners) and row["tls"] == str(owners)
               and row["uid"] == str(installed["uid"]) and row["context"] == "1"
               for row in copies)
    assert all(row["thread"] == str(owners + 1)
               and row["transport_outcome"] == "TUN_WRITE_SUCCEEDED"
               and row["write_errno"] == "0" for row in completions)
    payloads = []
    completion_by_token = {row["token"]: row for row in completions}
    for row in writes:
        packet = bytes.fromhex(row["raw"])
        ihl = (packet[0] & 15) * 4
        assert packet[0] >> 4 == 4 and packet[9] == 17 and ihl >= 20
        assert struct.unpack_from("!H", packet, 2)[0] == len(packet)
        assert ipaddress.ip_address(packet[12:16]) == ipaddress.ip_address(result["endpoint"])
        assert ipaddress.ip_address(packet[16:20]) == ipaddress.ip_address("10.111.0.2")
        source, destination, length = struct.unpack_from("!HHH", packet, ihl)
        assert source == result["endpoint_port"] and destination == result["source_port"]
        assert ihl + length == len(packet)
        assert int(row["bytes"]) == int(row["requested"]) == len(packet)
        assert int(completion_by_token[row["token"]]["write_result"]) == len(packet)
        payloads.append(packet[ihl + 8:].decode())
    assert Counter(payloads) == Counter(responses)
    # The initial N1 probe requested one application echo; its independent
    # guarantee ends at65 native TUN writes. Later held-open clients also
    # retain endpoint receipt evidence, checked separately rather than inferred.
    client_receipts = None
    client_path = path / "client.txt"
    if client_path.exists():
        client = client_path.read_text()
        sent = one(client, "event=client_sent ")
        assert sent["uid"] == str(installed["uid"])
        assert sent["port"] == str(result["source_port"]) and sent["nonce"] == result["nonce"]
        received = rows(client, "event=client_received ")
        assert Counter(int(row["index"]) for row in received) == Counter(range(65))
        assert one(client, "event=client_complete ")["unique"] == "65"
        client_receipts = 65

    after = (path / "after.txt").read_text()
    primary = quick.rows(after, "primary.status ")[0]
    assert primary["generation"] == generation
    assert int(primary["deferred"]) > 0 and int(primary["retries"]) > 0
    assert primary["pending_returns"] == primary["handoff_debt"] == "0"
    tun = quick.rows(after, "tun.status ")[0]
    assert tun["generation"] == generation
    assert all(tun[key] == "0" for key in ("pending", "frames", "buffers", "obligations"))
    returns = quick.rows(after, "tun.return ")
    assert len(returns) == owners
    assert all(row["in_use"] == "0" for row in returns)
    quick.validate_vpn_stop((path / "native-stop.log").read_text(), generation, owners)
    return dict(path=str(path), owners=owners, generation=generation,
                returns=65, client_receipts=client_receipts, native_ring_full=True, stopped=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--apk", type=Path, required=True)
    args = parser.parse_args()
    for path in args.paths:
        print(json.dumps(verify(path, args.apk), sort_keys=True))
    print("S308 actual native ring occupancy, independent packet writes/free/credit and stop: PASS")


if __name__ == "__main__":
    main()
