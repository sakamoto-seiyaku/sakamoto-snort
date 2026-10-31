#!/usr/bin/env python3
"""Ordinary Root/VPN App SOCKS4/4a/5 requests are filtered by their requested target (SAKAMOTO-326).

Oracle: which requests actually reach an independent finite SOCKS peer on the host (which never connects
outward), what the App receives, and the Product's own `flow.socks`/`flow.http` status of the very flow."""
import argparse
import ipaddress
import importlib.util
import json
from pathlib import Path
import shlex
import struct
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


http = load("s326_http", "tests/device/s325-http.py")
peer_module = load("s326_socks_peer", "tests/device/helpers/s326_socks_peer.py")
routing, base, shared, PKG = http.routing, http.base, http.shared, http.PKG
PEER_PORT = 18081
COMMAND_REASON = "7"


def greeting(*methods):
    return bytes([5, len(methods), *methods])


def password(user=b"name", secret=b"secret"):
    return bytes([1, len(user)]) + user + bytes([len(secret)]) + secret


def s5(host=None, *, address=None, port=443, command=1):
    if host is not None:
        target = bytes([3, len(host)]) + host.encode()
    else:
        packed = ipaddress.ip_address(address).packed
        target = bytes([1 if len(packed) == 4 else 4]) + packed
    return bytes([5, command, 0]) + target + struct.pack("!H", port)


def s4(*, address=None, host=None, port=80, command=1, user=b"u"):
    if host is not None:
        return struct.pack("!BBH", 4, command, port) + b"\0\0\0\x09" + user + b"\0" + host.encode() + b"\0"
    return struct.pack("!BBH", 4, command, port) + ipaddress.ip_address(address).packed + user + b"\0"


def flow_target(device, label, source):
    raw = device.save(label + "-flows.txt", device.cli(label + "-flows", "show product flows"))
    entries, rows, socks = {}, {}, {}
    for line in raw.splitlines():
        for prefix, table in (("flow.entry ", entries), ("flow.http ", rows), ("flow.socks ", socks)):
            if line.startswith(prefix):
                row = base.props(line.replace(" ", "\n"))
                table[(row["worker"], row["slot"], row["incarnation"])] = row
    found = [(key, row) for key, row in entries.items()
             if row["protocol"] == "6" and {int(row["port_a"]), int(row["port_b"])} == {source, PEER_PORT}]
    assert found, (source, raw[-2000:])
    key, entry = max(found, key=lambda item: int(item[0][2]))
    assert rows[key]["mode"] == "3" and key in socks, (rows.get(key), socks.get(key))
    return dict(entry=entry, http=rows[key], socks=socks[key], key=list(key))


def exchange(device, peer, result, label, steps, *, mark, connect_delay_ms=None):
    """steps: [(bytes, expected reply length)]. mark identifies this case's requests at the peer."""
    source = device.reserve_source_port(label)
    cursor = peer.cursor()
    nonce = "s326-" + label + "-" + str(time.time_ns())
    plan = dict(nonce=nonce, endpoint=device.args.endpoint4, port=PEER_PORT, source=source, bindDefault=True,
                socksSteps=[dict(send=data.hex(), expect=expect) for data, expect in steps], socksTimeoutMs=2500,
                socksHoldMs=2000, socksGate=True, socksAfterMs=6000,
                socksConnectDelayMs=connect_delay_ms if connect_delay_ms is not None else
                (1500 if device.args.profile == "vpn" else 0))
    device.save(label + "-plan.json", json.dumps(plan, indent=2) + "\n")
    device.save(label + "-launch.txt", device.action("--es", "t12ProbePlan", shlex.quote(json.dumps(plan))))
    path = "files/product-state/t12-" + nonce + ".json"
    wait = 25 + len(steps) * 4
    client = device.wait(label + "-client", path, lambda value: value.get("phase") in ("socks_done", "finished"),
                         timeout=wait, json_value=True)
    assert not client.get("error"), client
    flow = flow_target(device, label, source)
    mine = lambda rows: [row for row in rows if mark(row)]
    case = dict(label=label, source_port=source, client=client, peer=mine(peer.requests(cursor)), flow=flow,
                sent=[data.hex() for data, _ in steps], status="OBSERVED")
    device.save(label + "-client-foreground.txt", device.action())
    device.wait(label + "-closed", path, lambda value: value.get("phase") == "finished", timeout=wait, json_value=True)
    time.sleep(1.5)
    case["peer_after_close"] = mine(peer.requests(cursor))
    result["cases"].append(case)
    device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")
    return case


def statuses(case):
    return [item["status"] for item in case["client"]["socksReplies"]]


def by_host(name):
    return lambda row: row.get("host") == name


def by_port(port):
    return lambda row: row.get("port") == port


def cases(device, peer, result):
    rules = lambda label, deny=True: http.http_rules(device, label, deny=deny)
    rules("socks-rules")
    # The deny lists are "blocked.http.test" (exact) and "*.deny.http.test" (descendants).

    case = exchange(device, peer, result, "socks5-allow", [(greeting(0), 2), (s5("allowed.http.test", port=4431), 10),
                    (b"ping", 4)], mark=by_port(4431))
    assert statuses(case) == ["answered"] * 3 and len(case["peer"]) == 1, case
    assert case["peer"][0]["host"] == "allowed.http.test" and case["peer"][0]["version"] == "5", case["peer"]
    row, socks = case["flow"]["http"], case["flow"]["socks"]
    assert socks["version"] == "5" and socks["confirmed"] == "1" and socks["command"] == "1", socks
    assert row["current"] == "allowed.http.test" and row["current_port"] == "4431" and row["denied_valid"] == "0", row
    assert row["stop"] == "6", row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "socks5-deny", [(greeting(0), 2), (s5("blocked.http.test", port=4432), 10)],
                    mark=by_port(4432))
    assert statuses(case) == ["answered", "timeout"] and not case["peer"], case
    assert case["flow"]["http"]["denied"] == "blocked.http.test" and case["flow"]["socks"]["confirmed"] == "1", case["flow"]
    case["status"] = "PASS"

    case = exchange(device, peer, result, "socks5-password-deny-descendant",
                    [(greeting(2), 2), (password(), 2), (s5("api.deny.http.test", port=4433), 10)], mark=by_port(4433))
    assert statuses(case) == ["answered", "answered", "timeout"] and not case["peer"], case
    assert case["flow"]["socks"]["method"] == "2" and case["flow"]["http"]["denied"] == "api.deny.http.test", case["flow"]
    case["status"] = "PASS"

    case = exchange(device, peer, result, "socks5-ipv6-target", [(greeting(0), 2),
                    (s5(address="2001:db8::53", port=4434), 10)], mark=by_port(4434))
    assert statuses(case) == ["answered", "answered"] and case["peer"][0]["address"] == "2001:db8::53", case
    row = case["flow"]["http"]
    assert row["current_kind"] == "3" and row["current_port"] == "4434" and row["current"] == "-", row
    assert row["current_address"].lower().startswith("20010db8") and row["denied_valid"] == "0", row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "socks4-ipv4-target", [(s4(address="192.0.2.7", port=4435), 8)],
                    mark=by_port(4435))
    assert statuses(case) == ["answered"] and case["peer"][0]["address"] == "192.0.2.7", case
    row, socks = case["flow"]["http"], case["flow"]["socks"]
    assert socks["version"] == "4" and socks["socks4a"] == "0" and socks["confirmed"] == "1", socks
    assert row["current_kind"] == "2" and row["current_address"].lower().startswith("c0000207"), row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "socks4a-allow", [(s4(host="fine.http.test", port=4436), 8), (b"data", 4)],
                    mark=by_port(4436))
    assert statuses(case) == ["answered", "answered"] and case["peer"][0]["host"] == "fine.http.test", case
    assert case["flow"]["socks"]["socks4a"] == "1" and case["flow"]["http"]["current"] == "fine.http.test", case["flow"]
    case["status"] = "PASS"

    case = exchange(device, peer, result, "socks4a-deny", [(s4(host="blocked.http.test", port=4437), 8)],
                    mark=by_port(4437))
    assert statuses(case) == ["timeout"] and not case["peer"], case
    assert case["flow"]["http"]["denied"] == "blocked.http.test", case["flow"]
    case["status"] = "PASS"

    case = exchange(device, peer, result, "socks5-udp-associate-no-target",
                    [(greeting(0), 2), (s5(address="10.0.0.1", port=4438, command=3), 10)], mark=by_port(4438))
    assert statuses(case) == ["answered", "answered"], case
    row = case["flow"]["http"]
    assert row["current_kind"] == "0" and row["current_reason"] == COMMAND_REASON and row["denied_valid"] == "0", row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "socks-proxy-endpoint-is-not-the-target",
                    [(greeting(0), 2), (s5("allowed.http.test", port=4439), 10)], mark=by_port(4439))
    # The connection's own endpoint is the outer proxy; only the request names the target.
    entry = case["flow"]["entry"]
    assert PEER_PORT in (int(entry["port_a"]), int(entry["port_b"])), entry
    assert case["flow"]["http"]["current"] == "allowed.http.test" and case["flow"]["http"]["current_port"] == "4439"
    case["status"] = "PASS"

    rules("socks-rules-allow-all", deny=False)
    case = exchange(device, peer, result, "socks-allow-all-after-rule-removal",
                    [(greeting(0), 2), (s5("blocked.http.test", port=4440), 10)], mark=by_port(4440))
    assert statuses(case) == ["answered", "answered"] and len(case["peer"]) == 1, case
    assert case["flow"]["http"]["denied_valid"] == "0", case["flow"]
    case["status"] = "PASS"

    time.sleep(6)
    refused = (4432, 4433, 4437)
    result["late_arrivals"] = [row for row in peer.requests() if row.get("port") in refused]


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
    args.matrix = "socks"
    for field in ("apk", "stage", "backup", "output"):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((args.backup / "manifest.json").read_text())
    assert baseline["status"] == "PASS" and baseline["all_nodes_archived_exact"]
    device = (base.RootDevice if args.profile == "root" else base.Device)(args)
    device.capture_deadline = time.monotonic() + args.budget_seconds
    device.owners = int(args.owners)
    result = dict(status="HOLD", task="SAKAMOTO-326", cases=[], runs=[],
                  apk_sha256=base.digest(args.apk), source_sha256=base.digest(Path(__file__)),
                  started_monotonic_ns=time.monotonic_ns())
    peers = []
    try:
        out = args.output / "peer-socks"
        out.mkdir()
        peers.append(peer_module.SocksPeer([args.endpoint4, args.endpoint6], out,
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
            base.root.finish_run(device, result, "socks")
            base.preserve_sqlite_history(device, "socks", result["runs"][-1]["sqlite_after_stop"])
        else:
            base.finish_run(device, result, "socks")
        device.wire_stop()
        result["status"] = "PASS_ACTUAL_APP_" + args.profile.upper() + "_SOCKS"
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
