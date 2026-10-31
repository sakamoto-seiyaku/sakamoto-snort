#!/usr/bin/env python3
"""Ordinary Root/VPN App DTLS ClientHello SNI is filtered by its real name (SAKAMOTO-327).

The ClientHello datagrams are real OpenSSL 3.0 DTLS client flights (tests/host/fixtures). Oracle: which
datagrams reach an independent UDP echo peer, what the App receives, and the Product's `flow.sni`/`flow.lpi`
status of the very flow."""
import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


http = load("s327_http", "tests/device/s325-http.py")
peer_module = load("s327_udp_peer", "tests/device/helpers/s327_udp_peer.py")
routing, base, shared, PKG = http.routing, http.base, http.shared, http.PKG
PEER_PORT = 18443
DTLS_BIT = 1 << 19
QUIC_BIT = 1 << 3
FIXTURES = ROOT / "tests/host/fixtures"


def fixture(name):
    return [bytes.fromhex(line) for line in (FIXTURES / (name + ".hex")).read_text().split()]


def flow_sni(device, label, source):
    raw = device.save(label + "-flows.txt", device.cli(label + "-flows", "show product flows"))
    tables = {"flow.entry ": {}, "flow.sni ": {}, "flow.lpi ": {}}
    for line in raw.splitlines():
        for prefix, table in tables.items():
            if line.startswith(prefix):
                row = base.props(line.replace(" ", "\n"))
                table[(row["worker"], row["slot"], row["incarnation"])] = row
    found = [(key, row) for key, row in tables["flow.entry "].items()
             if row["protocol"] == "17" and {int(row["port_a"]), int(row["port_b"])} == {source, PEER_PORT}]
    assert found, (source, raw[-2000:])
    key, entry = max(found, key=lambda item: int(item[0][2]))
    return dict(entry=entry, sni=tables["flow.sni "][key], lpi=tables["flow.lpi "][key], key=list(key))


def exchange(device, peer, result, label, steps, *, family=4):
    """steps: [(datagram, pause_ms)]."""
    source = device.reserve_source_port(label)
    cursor = peer.cursor()
    nonce = "s327-" + label + "-" + str(time.time_ns())
    endpoint = device.args.endpoint4 if family == 4 else device.args.endpoint6
    plan = dict(nonce=nonce, endpoint=endpoint, port=PEER_PORT, source=source, bindDefault=True,
                udpSteps=[dict(send=data.hex(), pauseMs=pause) for data, pause in steps], udpTimeoutMs=1500,
                udpGate=True, udpAfterMs=4000)
    device.save(label + "-plan.json", json.dumps(plan, indent=2) + "\n")
    device.save(label + "-launch.txt", device.action("--es", "t12ProbePlan", shlex.quote(json.dumps(plan))))
    path = "files/product-state/t12-" + nonce + ".json"
    wait = 20 + len(steps) * 4
    client = device.wait(label + "-client", path, lambda value: value.get("phase") in ("udp_done", "finished"),
                         timeout=wait, json_value=True)
    assert not client.get("error"), client
    flow = flow_sni(device, label, source)
    sent = {data.hex() for data, _ in steps}
    arrived = [row["hex"] for row in peer.datagrams(cursor) if row["hex"] in sent]
    case = dict(label=label, family=family, source_port=source, client=client, flow=flow,
                sent=[data.hex() for data, _ in steps], arrived=arrived, status="OBSERVED")
    device.save(label + "-client-foreground.txt", device.action())
    device.wait(label + "-closed", path, lambda value: value.get("phase") == "finished", timeout=wait, json_value=True)
    result["cases"].append(case)
    device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")
    return case


def answered(case):
    return [item["status"] == "answered" and item.get("replyHex") == case["sent"][item["index"]]
            for item in case["client"]["udpReplies"]]


def delivered(case, index):
    return case["sent"][index] in case["arrived"]


def cases(device, peer, result):
    http.http_rules(device, "dtls-rules")
    vpn = device.args.profile == "vpn"
    # VPN learns a new flow's App UID asynchronously; App-bound rules apply from the next datagrams on.
    # Every case therefore sends the real ClientHello, then (after the UID wait) OpenSSL's own
    # retransmission of it, then an application marker datagram.
    pause = 1500 if vpn else 200

    for family in (4, 6):
        named, allowed = fixture("dtls12_named"), fixture("dtls12_allowed")
        marker = ("s327-allow-" + str(family)).encode()
        case = exchange(device, peer, result, f"dtls-allow-ipv{family}",
                        [(allowed[0], 0), (allowed[1], pause), (marker, 0)], family=family)
        assert answered(case) == [True, True, True], case["client"]
        sni, lpi = case["flow"]["sni"], case["flow"]["lpi"]
        assert sni["result"] == "1" and sni["name"] == "allowed.http.test" and sni["stop"] == "1", sni
        assert int(lpi["protocols"]) & DTLS_BIT and not int(lpi["protocols"]) & QUIC_BIT, lpi
        case["status"] = "PASS"

        marker = ("s327-deny-" + str(family)).encode()
        case = exchange(device, peer, result, f"dtls-deny-ipv{family}",
                        [(named[0], 0), (named[1], pause), (marker, 0)], family=family)
        sni = case["flow"]["sni"]
        assert sni["result"] == "1" and sni["name"] == "blocked.http.test", sni
        assert answered(case)[1:] == [False, False] and not delivered(case, 1) and not delivered(case, 2), case
        if not vpn:
            assert answered(case)[0] is False and not delivered(case, 0), case   # the named hello itself is refused
        case["first_hello_delivered"] = delivered(case, 0)
        case["status"] = "PASS"

    fragments = fixture("dtls12_fragmented")
    case = exchange(device, peer, result, "dtls-fragmented-deny",
                    [(fragments[0], 0), (fragments[1], pause), (b"s327-fragmented", 0)])
    # Pending recognition holds nothing: the first fragment carries no complete name and is forwarded.
    assert answered(case)[0] is True and delivered(case, 0), case
    assert case["flow"]["sni"]["name"] == "blocked.http.test", case["flow"]["sni"]
    assert answered(case)[1:] == [False, False] and not delivered(case, 1) and not delivered(case, 2), case
    case["status"] = "PASS"

    noname = fixture("dtls12_noname")
    case = exchange(device, peer, result, "dtls-no-sni",
                    [(noname[0], 0), (noname[1], pause), (b"s327-no-sni", 0)])
    assert answered(case) == [True, True, True], case["client"]
    assert case["flow"]["sni"]["result"] == "2" and case["flow"]["sni"]["stop"] == "1", case["flow"]["sni"]
    case["status"] = "PASS"

    old = fixture("dtls10_named")
    case = exchange(device, peer, result, "dtls10-deny", [(old[0], 0), (old[1], pause), (b"s327-dtls10", 0)])
    assert case["flow"]["sni"]["name"] == "blocked.http.test", case["flow"]["sni"]
    assert answered(case)[1:] == [False, False], case["client"]
    case["status"] = "PASS"

    label_only = bytes([23, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4])
    case = exchange(device, peer, result, "dtls-label-is-not-a-name", [(label_only, 0), (label_only, pause)])
    # A DTLS record envelope without a ClientHello is a protocol label, never a name.
    assert answered(case) == [True, True], case["client"]
    assert case["flow"]["sni"]["result"] == "0", case["flow"]["sni"]
    case["status"] = "PASS"

    http.http_rules(device, "dtls-rules-allow-all", deny=False)
    case = exchange(device, peer, result, "dtls-allow-all-after-rule-removal",
                    [(named[0], 0), (named[1], pause), (b"s327-after-removal", 0)])
    assert answered(case) == [True, True, True], case["client"]
    case["status"] = "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("apk", "stage", "backup", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--endpoint4", required=True)
    parser.add_argument("--endpoint6", required=True)
    parser.add_argument("--owners", choices=("1", "3"), default="1")
    parser.add_argument("--profile", choices=("root", "vpn"), default="root")
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--installed", action="store_true")
    parser.add_argument("--budget-seconds", type=int, default=900)
    parser.add_argument("--replace-preserved", type=Path)
    parser.add_argument("--cc", default="/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang")
    args = parser.parse_args()
    args.upstream_port = 15353
    args.matrix = "dtls"
    for field in ("apk", "stage", "backup", "output"):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((args.backup / "manifest.json").read_text())
    assert baseline["status"] == "PASS" and baseline["all_nodes_archived_exact"]
    device = (base.RootDevice if args.profile == "root" else base.Device)(args)
    device.capture_deadline = time.monotonic() + args.budget_seconds
    device.owners = int(args.owners)
    result = dict(status="HOLD", task="SAKAMOTO-327", cases=[], runs=[],
                  apk_sha256=base.digest(args.apk), source_sha256=base.digest(Path(__file__)),
                  started_monotonic_ns=time.monotonic_ns())
    peers = []
    try:
        out = args.output / "peer-udp"
        out.mkdir()
        peers.append(peer_module.UdpEchoPeer([args.endpoint4, args.endpoint6], out,
                                             device.capture_deadline, port=PEER_PORT))
        result["native"] = device.install()
        result["root_grant"] = device.save("postinstall-root-grant.txt",
            device.adb("shell", "run-as", PKG, "su", "-c", "id"))
        assert "uid=0" in result["root_grant"], "verify KernelSU grant before Root acceptance"
        device.wire_packet_limit = 8192
        device.wire_start()
        result["runs"].append(base.start_run(device, device.owners))
        cases(device, peers[0], result)
        if args.profile == "root":
            base.root.finish_run(device, result, "dtls")
            base.preserve_sqlite_history(device, "dtls", result["runs"][-1]["sqlite_after_stop"])
        else:
            base.finish_run(device, result, "dtls")
        device.wire_stop()
        result["status"] = "PASS_ACTUAL_APP_" + args.profile.upper() + "_DTLS"
    except BaseException as error:
        result.update(error=repr(error), traceback=traceback.format_exc())
    finally:
        errors = []
        try:
            device.begin_capture_cleanup()
        except BaseException as error:
            errors.append("reserve: " + repr(error))
        envelope = shared.CleanupEnvelope(90, [("wire", 20), ("stop", 35), ("reader", 5), ("peer", 20), ("trace", 10)])

        def finish(name, action):
            try:
                with envelope.phase(device, name):
                    action()
            except BaseException as error:
                errors.append(name + ": " + repr(error))
        if device.witnesses:
            finish("wire", device.wire_stop)
        if (device.stop_owed or device.active) and getattr(device, "stop_retry_authorized", True):
            finish("stop", lambda: device.stop("failure-cleanup"))
        if device.reader or getattr(device, "prepared_stop_capture", None):
            finish("reader", lambda: device.settle_reader("final"))
        finish("peer", lambda: [peer.close() for peer in reversed(peers)])
        finish("trace", device.close_trace)
        if errors:
            result["cleanup_errors"] = errors
            result["status"] = "HOLD"
        result["completed_monotonic_ns"] = time.monotonic_ns()
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result.get(key) for key in ("status", "error", "cleanup_errors")}))
    return 0 if result["status"].startswith("PASS_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
