#!/usr/bin/env python3
"""Ordinary Root/VPN App cleartext HTTP/1.x requests are filtered per request target (SAKAMOTO-325).

Oracle: which request heads actually reach an independent finite HTTP peer on the host, what the
App receives and the Product's own `flow.http` status of the very flow. The shared wire witness only
captures DNS ports, so it is recorded but never used as evidence here."""
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


routing = load("s325_routing", "tests/device/s321-dns-routing.py")
peer_module = load("s325_http_peer", "tests/device/helpers/s325_http_peer.py")
base, shared, PKG = routing.base, routing.shared, routing.PKG
PEER_PORT = 18080
DENY_EXPRESSION = "1100110102"     # DOMAIN_LIST 0 OR DOMAIN_LIST 1
STOP = dict(running=0, not_http=1, malformed=2, head_limit=3, version=4, framing=5, tunnel=6, sequence=7)
KIND = dict(none=0, name=1, ipv4=2, ipv6=3)
REASON = dict(ok=0, no_host=1, duplicate_host=2, bad_authority=3, userinfo=4, scheme=5, form=6)


def http_rules(device, label, *, deny=True):
    baseline = device.query_rules(label + "-before")
    lines = ["lists 2", "domain 0 exact blocked.http.test", "domain 1 descendants deny.http.test"]
    if deny:
        lines += ["0 0 4294967295 4294967295 4294967295 10 0 0 0 2 * * 0 65535 0 65535 " + DENY_EXPRESSION,
                  "group 10", "edge 10 1 0", f"bind 1 {device.uid} 2 10 0"]
    index = int(deny)
    lines += ["0 0 4294967295 4294967295 4294967295 1000 0 0 0 1 * * 0 65535 0 65535",
              "group 20", f"edge 20 1 {index}", f"bind 2 {device.uid} 2 20 0"]
    request = device.out / (label + "-rules.txt")
    request.write_text("\n".join(lines) + "\n")
    remote = "/data/local/tmp/s325-rules.txt"
    device.adb("push", request, remote)
    command = f'am start -n {PKG}/.DebugControlActivity --es completeRuleText "$(cat {remote})"'
    device.save(label + "-prefill.txt", device.adb("shell", "sh", "-c", shlex.quote(command)))
    device.adb("shell", "rm", remote)
    old = base.props(device.app("files/product-state/complete-rule-config.properties")).get("queryElapsedMillis")
    device.tap(label + "-replace", "Replace all rules")
    status = device.applied(label, old)
    assert int(status["count"]) == int(status["activeCount"]) == 1 + index, status
    return status


def request(path, host=None, *, target=None, extra=""):
    """path is already unique to the case: /<label>/<name>"""
    line = target or path
    text = f"GET {line} HTTP/1.1\r\n"
    if host is not None:
        text += f"Host: {host}\r\n"
    return (text + extra + "\r\n").encode()


def flow_http(device, label, source):
    raw = device.save(label + "-flows.txt", device.cli(label + "-flows", "show product flows"))
    entries, https = {}, {}
    for line in raw.splitlines():
        if line.startswith(("flow.entry ", "flow.http ")):
            row = base.props(line.replace(" ", "\n"))
            key = (row["worker"], row["slot"], row["incarnation"])
            (entries if line.startswith("flow.entry ") else https)[key] = row
    found = [(key, row) for key, row in entries.items()
             if row["protocol"] == "6" and {int(row["port_a"]), int(row["port_b"])} == {source, PEER_PORT}]
    assert found, (source, raw[-2000:])
    key, entry = max(found, key=lambda item: int(item[0][2]))
    row = https[key]
    assert row["mode"] == "1", row
    return dict(entry=entry, http=row, key=list(key))


def exchange(device, peer, result, label, requests, *, splits=None, stop_on_timeout=True, timeout_ms=2500):
    source = device.reserve_source_port(label)
    before_wire = device.wire_coverage(label + "-before")
    cursor = peer.cursor()
    nonce = "s325-" + label + "-" + str(time.time_ns())
    plan = dict(nonce=nonce, endpoint=device.args.endpoint4, port=PEER_PORT, source=source, bindDefault=True,
                httpRequests=[item.hex() for item in requests], httpDelayMs=200, httpTimeoutMs=timeout_ms,
                httpStopOnTimeout=stop_on_timeout, httpHoldMs=2000, httpGate=True, httpAfterMs=2500)
    if splits:
        plan["httpSplit"] = splits
    device.save(label + "-plan.json", json.dumps(plan, indent=2) + "\n")
    device.save(label + "-launch.txt", device.action("--es", "t12ProbePlan", shlex.quote(json.dumps(plan))))
    path = "files/product-state/t12-" + nonce + ".json"
    wait = 20 + len(requests) * (timeout_ms // 1000 + 2)
    # The App still owns its socket here: this is the window in which refusals are judged.
    client = device.wait(label + "-client", path, lambda value: value.get("phase") in ("http_done", "finished"),
                         timeout=wait, json_value=True)
    assert not client.get("error"), client
    after_wire = device.wire_coverage(label + "-after")
    wire = {name: rows[len(before_wire[name]):] for name, rows in after_wire.items()}
    mine = lambda rows: [row for row in rows if "/" + label + "/" in row["request_line"]]
    case = dict(label=label, source_port=source, client=client, peer=mine(peer.requests(cursor)), wire=wire,
                flow=flow_http(device, label, source), physical_interface=device.physical_interface,
                sent=[item.decode("latin-1") for item in requests], status="OBSERVED")
    # After the App closes its socket, retransmissions of refused bytes no longer carry a socket
    # owner and the uid-owner NFQUEUE rule cannot capture them. Record, never judge, what follows.
    device.wait(label + "-closed", path, lambda value: value.get("phase") == "finished", timeout=wait, json_value=True)
    time.sleep(1.5)
    case["peer_after_close"] = mine(peer.requests(cursor))
    result["cases"].append(case)
    device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")
    return case


def statuses(case):
    return [item["status"] for item in case["client"]["httpResponses"]]


def hosts(case):
    """The target each arrived request names: its absolute-form authority, else its Host."""
    names = []
    for item in case["peer"]:
        target = item["request_line"].split(" ")[1]
        names.append(target.split("/")[2] if target.startswith("http://") else item["host"])
    return names


def http_row(case):
    return case["flow"]["http"]


def cases(device, peer, result):
    http_rules(device, "http-rules")

    case = exchange(device, peer, result, "http-allow", [request("/http-allow/allow", "allowed.http.test")])
    assert statuses(case) == ["answered"] and hosts(case) == ["allowed.http.test"], case
    row = http_row(case)
    assert row["current_valid"] == "1" and row["current"] == "allowed.http.test" and row["current_kind"] == "1"
    assert row["denied_valid"] == "0" and row["requests"] == "1" and row["stop"] == "0", row
    assert row["current_reason"] == "0" and row["current_index"] == "0", row
    case["status"] = "PASS"

    head = request("/http-split-head/split", "split.http.test")
    case = exchange(device, peer, result, "http-split-head", [head], splits=[len(head) // 2])
    assert statuses(case) == ["answered"] and hosts(case) == ["split.http.test"], case
    assert http_row(case)["current"] == "split.http.test" and http_row(case)["requests"] == "1"
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-successive-allowed", [
        request("/http-successive-allowed/one", "one.http.test"),
        request("http://two.http.test/http-successive-allowed/two", target="http://two.http.test/http-successive-allowed/two")])
    assert statuses(case) == ["answered", "answered"] and hosts(case) == ["one.http.test", "two.http.test"], case
    row = http_row(case)
    assert row["requests"] == "2" and row["current"] == "two.http.test" and row["current_index"] == "1", row
    assert row["denied_valid"] == "0", row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-deny-first", [request("/http-deny-first/blocked", "blocked.http.test")])
    assert statuses(case) == ["timeout"] and not case["peer"], case
    row = http_row(case)
    assert row["denied_valid"] == "1" and row["denied"] == "blocked.http.test", row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-deny-descendant", [request("/http-deny-descendant/d", "sub.deny.http.test")])
    assert statuses(case) == ["timeout"] and not case["peer"], case
    assert http_row(case)["denied"] == "sub.deny.http.test", http_row(case)
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-deny-blocks-rest-of-connection", [
        request("/http-deny-blocks-rest-of-connection/first", "allowed.http.test"), request("/http-deny-blocks-rest-of-connection/refused", "blocked.http.test"),
        request("/http-deny-blocks-rest-of-connection/later", "allowed.http.test")], stop_on_timeout=False)
    assert statuses(case) == ["answered", "timeout", "timeout"], case
    assert hosts(case) == ["allowed.http.test"], case           # only the request before the refusal arrived
    row = http_row(case)
    assert row["denied_valid"] == "1" and row["denied"] == "blocked.http.test", row
    assert int(row["requests"]) >= 2, row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-absolute-target-wins-over-host", [
        request("/http-absolute-target-wins-over-host/x", "allowed.http.test", target="http://blocked.http.test/http-absolute-target-wins-over-host/x")])
    assert statuses(case) == ["timeout"] and not case["peer"], case
    assert http_row(case)["denied"] == "blocked.http.test", http_row(case)
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-absolute-target-allowed-despite-host", [
        request("/http-absolute-target-allowed-despite-host/x", "blocked.http.test", target="http://fine.http.test/http-absolute-target-allowed-despite-host/x")])
    assert statuses(case) == ["answered"] and http_row(case)["current"] == "fine.http.test", case
    assert http_row(case)["denied_valid"] == "0"
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-ip-target", [request("/http-ip-target/ip", "192.0.2.7:8080")])
    assert statuses(case) == ["answered"], case
    row = http_row(case)
    assert row["current_kind"] == "2" and row["current_port"] == "8080" and row["current"] == "-", row
    assert row["current_address"].lower().startswith("c0000207"), row     # the requested IP, not the proxy/peer address
    assert row["denied_valid"] == "0", row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-duplicate-host-unavailable", [
        request("/http-duplicate-host-unavailable/dup", "allowed.http.test", extra="Host: blocked.http.test\r\n")])
    assert statuses(case) == ["answered"], case                # no usable target: no domain decision
    row = http_row(case)
    assert row["current_kind"] == "0" and row["current_reason"] == str(REASON["duplicate_host"]), row
    assert row["denied_valid"] == "0", row
    case["status"] = "PASS"

    case = exchange(device, peer, result, "http-connect-ends-http-parsing", [
        b"CONNECT tunnel.http.test:443 HTTP/1.1\r\nHost: tunnel.http.test:443\r\n\r\n"])
    row = http_row(case)
    assert row["current"] == "tunnel.http.test" and row["stop"] == str(STOP["tunnel"]), row
    case["status"] = "PASS"

    http_rules(device, "http-rules-allow-all", deny=False)
    case = exchange(device, peer, result, "http-allow-all-after-rule-removal", [
        request("/http-allow-all-after-rule-removal/was-blocked", "blocked.http.test")])
    assert statuses(case) == ["answered"] and hosts(case) == ["blocked.http.test"], case
    assert http_row(case)["denied_valid"] == "0", http_row(case)
    case["status"] = "PASS"

    # Informational: what the peer eventually saw of the refused requests, after every socket closed.
    time.sleep(6)
    refused = ("http-deny-first", "http-deny-descendant", "http-deny-blocks-rest-of-connection",
               "http-absolute-target-wins-over-host")
    result["late_arrivals"] = [row["request_line"] for row in peer.requests()
                               if any("/" + name + "/" in row["request_line"] for name in refused)
                               and not any(row in case["peer"] for case in result["cases"])]


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
    args.matrix = "http"
    for field in ("apk", "stage", "backup", "output"):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((args.backup / "manifest.json").read_text())
    assert baseline["status"] == "PASS" and baseline["all_nodes_archived_exact"]
    device = (base.RootDevice if args.profile == "root" else base.Device)(args)
    device.capture_deadline = time.monotonic() + args.budget_seconds
    device.owners = int(args.owners)
    result = dict(status="HOLD", task="SAKAMOTO-325", cases=[], runs=[],
                  apk_sha256=base.digest(args.apk), source_sha256=base.digest(Path(__file__)),
                  started_monotonic_ns=time.monotonic_ns())
    peers = []
    try:
        out = args.output / "peer-http"
        out.mkdir()
        peers.append(peer_module.HttpPeer([args.endpoint4, args.endpoint6], out,
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
            base.root.finish_run(device, result, "http")
            base.preserve_sqlite_history(device, "http", result["runs"][-1]["sqlite_after_stop"])
        else:
            base.finish_run(device, result, "http")
        device.wire_stop()
        result["status"] = "PASS_ACTUAL_APP_" + args.profile.upper() + "_HTTP"
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
