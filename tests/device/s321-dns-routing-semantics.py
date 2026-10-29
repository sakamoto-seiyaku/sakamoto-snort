#!/usr/bin/env python3
"""S321 real routing/cache views and preserved local DNS transport."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("s321_routing", ROOT / "tests/device/s321-dns-routing.py")
routing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(routing)
base, shared, fixtures, PKG = routing.base, routing.shared, routing.fixtures, routing.PKG


def network_resolvers(device):
    evidence = device.current_network_evidence
    connectivity = (device.out / evidence["connectivity_file"]).read_text()
    network = evidence["identity"][-1]
    agents = [line for line in connectivity.splitlines() if f"NetworkAgentInfo{{network{{{network}}}" in line]
    assert len(agents) == 1
    dns = re.search(r"DnsAddresses:\s*\[([^\]]*)\]", agents[0])
    assert dns, "actual selected network did not advertise resolver addresses"
    return [str(ipaddress.ip_address(value.strip("/")))
            for value in re.split(r"[,\s]+", dns[1].strip()) if value.strip("/")]


class OriginalNetworkCapture:
    def wire_start(self):
        self.verify_test_network("original-resolver-capture", baseline=True)
        self.extra_wire_addresses = network_resolvers(self)
        assert len(self.extra_wire_addresses) <= 6
        self.save("original-network-capture-addresses.json", json.dumps(self.extra_wire_addresses) + "\n")
        return super().wire_start()


class RootDevice(OriginalNetworkCapture, base.RootDevice):
    pass


class Device(OriginalNetworkCapture, base.Device):
    pass


class MdnsPeer:
    """Owned multicast fixture, sharing mDNS's ordinary group binding."""
    def __init__(self, address, out, deadline):
        self.out, self.deadline = out, deadline
        self.stop_event = threading.Event()
        self.rows, self.error, self.query, self.reply = [], None, None, None
        self.channel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.channel.bind(("", 5353))
        self.channel.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
        self.membership = socket.inet_aton("224.0.0.251") + socket.inet_aton(address)
        self.channel.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, self.membership)
        self.channel.settimeout(.1)
        self.stream = (out / "peer.jsonl").open("x")
        self.thread = threading.Thread(target=self.run, name="s321-mdns-fixture")
        self.thread.start()

    def emit(self, row):
        assert len(self.rows) < 4096
        row = dict(row, host_monotonic_ns=time.monotonic_ns())
        self.rows.append(row)
        self.stream.write(json.dumps(row) + "\n")
        self.stream.flush()

    def run(self):
        try:
            while not self.stop_event.is_set():
                assert time.monotonic() < self.deadline
                try:
                    wire, remote = self.channel.recvfrom(4096)
                except socket.timeout:
                    continue
                self.emit(dict(kind="received", source=list(remote), wire_hex=wire.hex(),
                               planned=wire == self.query))
                if wire == self.query:
                    assert self.channel.sendto(self.reply, remote) == len(self.reply)
                    self.emit(dict(kind="response", destination=list(remote), wire_hex=self.reply.hex()))
        except BaseException as error:
            self.error = error
        finally:
            self.channel.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, self.membership)
            self.channel.close()

    def close(self):
        self.stop_event.set()
        self.thread.join(2)
        assert not self.thread.is_alive() and self.channel.fileno() == -1
        self.stream.close()
        assert self.error is None, self.error


def configure(device, label, *, routes="route 0 0 1", exceptions=""):
    """Normal UI transaction and independent complete saved/active readback."""
    text = (f"upstream 0 udp primary.test {device.args.endpoint4} 15353\n"
            f"upstream 1 udp backup.test {device.args.endpoint4} 15354\n" + routes
            + ("\n" + exceptions if exceptions else ""))
    previous = device.query_rules(label + "-before")
    device.save(label + "-request.txt", text + "\n")
    device.save(label + "-action.txt", device.action("--es", "dnsUpstream", shlex.quote(text),
                "--el", "expectedSavedRevision", previous["savedRevision"]))
    applied = device.wait(label + "-applied", "files/product-state/complete-rule-config.properties",
                         lambda value: value.get("queryElapsedMillis") not in (None, previous.get("queryElapsedMillis")))
    device.valid_config(applied)
    observed = device.query_rules(label + "-independent")
    dns = lambda value: {key: item for key, item in value.items() if key.startswith("dns.")}
    assert dns(applied) == dns(observed)
    for prefix in ("dns", "dns.active"):
        assert observed[prefix + ".enabled"] == "1"
        assert observed[prefix + ".endpointCount"] == "2"
        assert observed[prefix + ".routeCount"] == str(len(routes.splitlines()))
        assert observed[prefix + ".exceptionCount"] == str(len(exceptions.splitlines()))
        for line in routes.splitlines():
            _, index, *candidates = line.split()
            assert observed[prefix + ".route." + index + ".candidates"] == ",".join(candidates)
    device.verify_saved_source(label)
    selected_port = 15353 + int(routes.splitlines()[0].split()[2])
    device.selected_dns = dict(endpoint=(device.args.endpoint4, selected_port), route_revision=None,
                               active_revision=int(observed["activeRevision"]))
    device.proxy_ready(label + "-ready")
    return observed


def question(device, name):
    device.next_identifier += 1
    return fixtures.question(device.next_identifier, name)


def observe_exchange(device, peers, result, label, query, answer, *, selected=15353,
                     resolver="1.1.1.1", cached=False, drop_primary=False, attempts=None):
    primary, backup = peers
    for peer in peers:
        peer.register(query, answer, drop=drop_primary and peer is primary)
    cursors = [peer.cursor() for peer in peers]
    source = device.reserve_source_port(label)
    before = device.wire_coverage(label + "-before")
    began = time.monotonic_ns()
    nonce = device.launch_queries(label, resolver, source, [query], timeout=12000)
    client = device.client(label, nonce)
    identifier = int.from_bytes(query[:2], "big")
    select = lambda value: [row for row in shared.dns_rows(value) if row["generation"] == device.generation
                           and row["source_port"] == source and row["id"] == identifier and row["proxy_flags"] & 1]
    observation = device.observation_matching(label, lambda value: any(row["stage"] == 4 for row in select(value)))
    records = select(observation)
    device.verify_test_source(label, records)
    device.expected_durable.extend(records)
    device.required_durable.append(dict(generation=device.generation, id=identifier, source=source, proxy=True, stages=[1, 4]))
    after = device.wire_coverage(label + "-after")
    wire = {name: rows[len(before[name]):] for name, rows in after.items()}
    case = dict(label=label, kind="exchange", status="OBSERVED", ordinary_app=True,
                query=query.hex(), expected=answer.hex(), client=client, records=records, wire=wire,
                selected=selected, source_port=source, resolver=resolver, cached=cached,
                expected_attempts=attempts if attempts is not None else [selected],
                peer={str(peer.port): peer.received(query, after=cursor) for peer, cursor in zip(peers, cursors)},
                started_monotonic_ns=began, completed_monotonic_ns=time.monotonic_ns())
    result["cases"].append(case)
    device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")
    return case


def validate_exchange(case):
    assert not case["client"].get("error")
    exchange, = case["client"]["dnsExchanges"]
    assert exchange["sentHex"] == case["query"]
    base.verify_data_reply(bytes.fromhex(exchange["replyHex"]), bytes.fromhex(case["expected"]),
                           bytes.fromhex(case["query"]), 0, cached=case["cached"])
    final = [row for row in case["records"] if row["stage"] in (2, 4)]
    assert len(final) == 2 and all(row["upstream_port"] == case["selected"] for row in final), final
    started = [row for row in case["records"] if row["stage"] == 5 and row["proxy_result"] == 12]
    assert [row["upstream_port"] for row in started] == case["expected_attempts"], started
    assert bool(final[0]["proxy_flags"] & 16) == case["cached"]
    for port, rows in case["peer"].items():
        expected = int(port) in case["expected_attempts"]
        assert (1 <= len(rows) <= 2) if expected else not rows, (case["label"], port, rows)
    if case["selected"] == 53:
        assert all(row.get("resolver_id", 0) == 0 and row["resolution_route"] == 4294967295 for row in final)
    case["status"] = "PASS"


def candidate_cache(device, peers, result):
    configure(device, "cache-config")
    first = question(device, "cache-primary.s321.test")
    second = question(device, "cache-backup.s321.test")
    queries = [first, second, base.duplicate(first, 40), base.duplicate(second, 40)]
    answers = [base.ttl_reply(query) for query in queries]
    peers[0].register(first, answers[0])
    peers[0].register(second, answers[1], drop=True)
    peers[1].register(first, answers[0])
    peers[1].register(second, answers[1])
    source = device.reserve_source_port("candidate-cache")
    cursors = [peer.cursor() for peer in peers]
    before = device.wire_coverage("candidate-cache-before")
    nonce = device.launch_queries("candidate-cache", "1.1.1.1", source, queries, timeout=12000)
    client = device.client("candidate-cache", nonce)
    ids = {int.from_bytes(query[:2], "big") for query in queries}
    select = lambda value: [row for row in shared.dns_rows(value) if row["generation"] == device.generation
                           and row["source_port"] == source and row["id"] in ids and row["proxy_flags"] & 1]
    observation = device.observation_matching("candidate-cache", lambda value:
        len([row for row in select(value) if row["stage"] == 4]) == 4)
    records = select(observation)
    device.verify_test_source("candidate-cache", records)
    device.expected_durable.extend(records)
    for identifier in ids:
        device.required_durable.append(dict(generation=device.generation, id=identifier, source=source, proxy=True, stages=[1, 4]))
    after = device.wire_coverage("candidate-cache-after")
    case = dict(label="candidate-own-cache-before-health", kind="candidate-cache", status="OBSERVED",
                ordinary_app=True, queries=[query.hex() for query in queries], answers=[answer.hex() for answer in answers],
                client=client, records=records, source_port=source,
                peer={str(peer.port): {"primary_question": peer.received(first, after=cursor),
                                       "backup_question": peer.received(second, after=cursor)} for peer, cursor in zip(peers, cursors)},
                wire={name: rows[len(before[name]):] for name, rows in after.items()})
    result["cases"].append(case)
    device.save("candidate-cache-observed.json", json.dumps(case, indent=2) + "\n")
    # UI/readback time is not used as the cooldown oracle. The actual record
    # timestamp bounds the idle interval; no packet is sent by this wait.
    primary_before = peers[0].received(second, after=cursors[0])
    time.sleep(5.1)
    assert peers[0].received(second, after=cursors[0]) == primary_before
    recovered = base.duplicate(second, 80)
    peers[0].register(recovered, base.ttl_reply(recovered))
    observe_exchange(device, peers, result, "demand-restores-primary", recovered, base.ttl_reply(recovered))


def validate_candidate_cache(case):
    assert not case["client"].get("error") and len(case["client"]["dnsExchanges"]) == 4
    origins = {}
    for index, (exchange, query_hex, expected_hex, port, cached) in enumerate(zip(
            case["client"]["dnsExchanges"], case["queries"], case["answers"],
            [15353, 15354, 15353, 15354], [False, False, True, True])):
        query = bytes.fromhex(query_hex)
        records = [row for row in case["records"] if row["id"] == int.from_bytes(query[:2], "big")]
        response, = [row for row in records if row["stage"] == 2]
        delivered, = [row for row in records if row["stage"] == 4]
        assert response["upstream_port"] == delivered["upstream_port"] == port
        assert response["resolver_id"] == delivered["resolver_id"] == (1 if port == 15353 else 2)
        assert bool(response["proxy_flags"] & 16) == cached
        if index < 2:
            origins[port] = response["mono_us"]
        age = response["mono_us"] - origins[port]
        base.verify_data_reply(bytes.fromhex(exchange["replyHex"]), bytes.fromhex(expected_hex), query,
                               age / 1e6, cached=cached, cache_age_us=age if cached else None)
    assert len(case["peer"]["15353"]["primary_question"]) == 1
    assert 1 <= len(case["peer"]["15353"]["backup_question"]) <= 2
    assert not case["peer"]["15354"]["primary_question"]
    assert len(case["peer"]["15354"]["backup_question"]) == 1
    case["status"] = "PASS"


def original_network(device, peers, result):
    label = "explicit-original-network-resolver"
    device.verify_test_network(label + "-precondition")
    evidence = device.current_network_evidence
    addresses = network_resolvers(device)
    candidates = [address for address in addresses if ":" not in address and ipaddress.ip_address(address).is_private]
    assert candidates, "actual selected network has no explicit IPv4 LAN resolver"
    resolver = candidates[0]
    # The advertised resolver is an external precondition, not this fixture.
    # Use its actual authoritative localhost answer without a WAN recursion
    # dependency. The cold recursive reserved-name attempt remains separate
    # deadline/late-response evidence, not a qualified positive response.
    query = bytearray(question(device, "localhost"))
    query[2:4] = bytes(2)
    query = bytes(query)
    cursors = [peer.cursor() for peer in peers]
    source = device.reserve_source_port(label)
    before = device.wire_coverage(label + "-before")
    nonce = device.launch_queries(label, resolver, source, [query], timeout=12000)
    client = device.client(label, nonce)
    identifier = int.from_bytes(query[:2], "big")
    select = lambda value: [row for row in shared.dns_rows(value) if row["generation"] == device.generation
                           and row["source_port"] == source and row["id"] == identifier and row["proxy_flags"] & 1]
    observation = device.observation_matching(label, lambda value: any(row["stage"] == 4 for row in select(value)))
    records = select(observation)
    device.expected_durable.extend(records)
    device.required_durable.append(dict(generation=device.generation, id=identifier, source=source, proxy=True, stages=[1, 4]))
    after = device.wire_coverage(label + "-after")
    case = dict(label=label, kind="original-network", status="OBSERVED", ordinary_app=True,
                resolver=resolver, resolver_scope="Actual advertised selected-network resolver; its answer is not controlled by this test",
                query_profile="Nonrecursive localhost A; advertised resolver availability independently prequalified",
                network_evidence=evidence, client=client, records=records, query=query.hex(), source_port=source,
                candidates=[peer.received(query, after=cursor) for peer, cursor in zip(peers, cursors)],
                physical_interface=device.physical_interface,
                wire={name: rows[len(before[name]):] for name, rows in after.items()})
    result["cases"].append(case)
    device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")


def mdns(device, peer, peers, result):
    label = "multicast-mdns-original-network"
    query = bytearray(question(device, "s321-printer.local"))
    query[2:4] = bytes(2)
    query = bytes(query)
    answer = bytearray(base.ttl_reply(query))
    answer[2:4] = b"\x84\x00"
    peer.query, peer.reply = query, bytes(answer)
    source = device.reserve_source_port(label)
    before = device.wire_coverage(label + "-before")
    cursors = [item.cursor() for item in peers]
    executable = device.out / "s321-mdns-query"
    subprocess.run([device.args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(ROOT / "tests/device/helpers/s321_mdns_query.c"), "-o", str(executable)], check=True)
    remote = "/data/local/tmp/s321-mdns-query"
    device.adb("push", str(executable), remote)
    device.adb("shell", "chmod", "700", remote)
    try:
        raw = device.save(label + "-client.json", device.adb("shell", remote, str(source), query.hex(), check=False))
        client = json.loads(raw)
    finally:
        device.adb("shell", "rm", "-f", remote)
    after = device.wire_coverage(label + "-after")
    observation = device.observation(label + "-observation")
    records = [row for row in shared.dns_rows(observation) if row["generation"] == device.generation and row["source_port"] == source]
    case = dict(label=label, kind="mdns", status="OBSERVED", ordinary_app=False,
                caller_scope="actual bounded shell UID socket, not Android resolver IPC or ordinary UI App",
                client=client, expected=bytes(answer).hex(), peer=[row for row in peer.rows if row.get("planned")],
                candidate_peers=[item.received(query, after=cursor) for item, cursor in zip(peers, cursors)],
                records=records, physical_interface=device.physical_interface,
                wire={name: rows[len(before[name]):] for name, rows in after.items()})
    result["cases"].append(case)
    device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")


def semantics(device, peers, mdns_peer, result):
    device.rules("semantics-allow")
    candidate_cache(device, peers, result)
    configure(device, "valid-rcode-config")
    for rcode in (0, 3, 5, 2):
        query = question(device, f"rcode-{rcode}.s321.test")
        answer = base.negative_reply(query, rcode=rcode)
        observe_exchange(device, peers, result, f"valid-rcode-{rcode}", query, answer)
    configure(device, "exception-config", routes="route 0 0\nroute 1 1",
              exceptions="exception descendants corp.test route 1\nexception descendants branch.corp.test route 0\n"
                         "exception exact host.branch.corp.test route 1")
    for name, port in [("printer.corp.test", 15354), ("branch.corp.test", 15353),
                       ("host.branch.corp.test", 15354), ("notcorp.test", 15353),
                       ("printer.local", 15353)]:
        query = question(device, name)
        observe_exchange(device, peers, result, name.replace(".", "-"), query, base.ttl_reply(query), selected=port)
    # The same name on the same network gets a different answer after resolver
    # routing changes; an older candidate cache cannot cross the new view.
    query = question(device, "view-change.s321.test")
    observe_exchange(device, peers, result, "view-before", query, base.ttl_reply(query))
    configure(device, "view-change-config", routes="route 0 1")
    changed = base.duplicate(query, 1)
    answer = base.ttl_reply(changed)[:-1] + b"\x2d"
    observe_exchange(device, peers, result, "view-after", changed, answer, selected=15354)
    original_network(device, peers, result)
    mdns(device, mdns_peer, peers, result)


def validate(case):
    if case["kind"] == "exchange":
        validate_exchange(case)
    elif case["kind"] == "candidate-cache":
        validate_candidate_cache(case)
    elif case["kind"] == "original-network":
        assert not case["client"].get("error") and not any(case["candidates"])
        exchange, = case["client"]["dnsExchanges"]
        reply = bytes.fromhex(exchange["replyHex"])
        query = bytes.fromhex(case["query"])
        assert exchange["sentHex"] == query.hex() and reply[:2] == query[:2]
        final = [row for row in case["records"] if row["stage"] in (2, 4)]
        assert len(final) == 2
        assert all(row["upstream_port"] == 53 and row["resolution_route"] == 4294967295
                   and row.get("resolver_id", 0) == 0 for row in final)
        outgoing = [row for row in case["wire"][case["physical_interface"]] if row.get("kind") == "udp"
                    and row["destination"] == case["resolver"] and row["destination_port"] == 53
                    and row["payload_hex"][4:] == query.hex()[4:]]
        incoming = [row for row in case["wire"][case["physical_interface"]] if row.get("kind") == "udp"
                    and row["source"] == case["resolver"] and row["source_port"] == 53
                    and row["payload_hex"][4:] == reply.hex()[4:]]
        assert outgoing and incoming, "actual original-network reply requires independent matching wire"
        assert all(row["proxy_result"] == 1 for row in final)
        case["status"] = "PASS"
    else:
        assert case["client"]["error"] == 0 and case["client"]["reply_hex"] == case["expected"], case
        assert len({(tuple(row["source"]), row["wire_hex"]) for row in case["peer"]}) == 1
        assert not any(case["candidate_peers"])
        assert not any(row["proxy_flags"] & 1 for row in case["records"])
        assert any(row.get("kind") == "udp" and row["destination"] == "224.0.0.251"
                   and row["destination_port"] == 5353 and row["payload_hex"] == case["client"]["query_hex"]
                   for row in case["wire"][case["physical_interface"]]), case
        case["status"] = "PASS"


def main(*, mdns_runner=mdns, mdns_peer_factory=MdnsPeer, case_validator=validate):
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("apk", "stage", "backup", "output"):
        parser.add_argument("--" + field, type=Path, required=True)
    for field in ("endpoint4", "endpoint6"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--owners", default="1", choices=("1", "3"))
    parser.add_argument("--profile", default="root", choices=("root", "vpn"))
    parser.add_argument("--matrix", default="semantics", choices=("semantics", "mdns", "original"))
    parser.add_argument("--mdns-family", default="both", choices=("both", "4", "6"))
    parser.add_argument("--installed", action="store_true")
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--replace-preserved", type=Path)
    parser.add_argument("--cc", default="/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang")
    args = parser.parse_args()
    assert args.matrix != "semantics" or args.owners == "1", "candidate-cache sequencing uses one actual owner"
    assert args.mdns_family == "both" or mdns_peer_factory is not MdnsPeer, "family selection requires the network mDNS driver"
    args.upstream_port = 15353
    for field in ("apk", "stage", "backup", "output"):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(exist_ok=False)
    device = (RootDevice if args.profile == "root" else Device)(args)
    device.capture_deadline, device.owners = time.monotonic() + 1200, int(args.owners)
    result = dict(status="HOLD", task="SAKAMOTO-321", matrix=args.matrix, cases=[], runs=[],
                  apk_sha256=base.digest(args.apk), source_sha256=base.digest(Path(__file__)),
                  started_monotonic_ns=time.monotonic_ns())
    peers, mdns_peer = [], None
    try:
        for port in (15353, 15354):
            out = args.output / ("peer-" + str(port))
            out.mkdir()
            peers.append(routing.peer_module.Peer([args.endpoint4, args.endpoint6], out, device.capture_deadline, port=port))
        out = args.output / "peer-mdns"
        out.mkdir()
        mdns_peer = mdns_peer_factory(args.endpoint4, out, device.capture_deadline)
        result["native"] = device.install()
        device.wire_start()
        result["runs"].append(base.start_run(device, device.owners))
        if args.matrix == "semantics":
            semantics(device, peers, mdns_peer, result)
        elif args.matrix == "original":
            device.rules("original-network-allow")
            configure(device, "original-network-config")
            original_network(device, peers, result)
        else:
            device.rules("mdns-allow")
            configure(device, "mdns-config")
            mdns_runner(device, mdns_peer, peers, result)
        if args.profile == "root":
            base.root.finish_run(device, result, "semantics")
            base.preserve_sqlite_history(device, "semantics", result["runs"][-1]["sqlite_after_stop"])
        else:
            base.finish_run(device, result, "semantics")
        device.wire_stop()
        for case in result["cases"]:
            case_validator(case)
        result["status"] = "PASS_ACTUAL_" + args.profile.upper() + "_SEMANTICS_AND_LOCAL_TRANSPORT"
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
        finish("peer", lambda: ([peer.close() for peer in reversed(peers)], mdns_peer.close() if mdns_peer else None))
        finish("trace", device.close_trace)
        if errors:
            result["cleanup_errors"] = errors
        result["completed_monotonic_ns"] = time.monotonic_ns()
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result.get(key) for key in ("status", "error", "cleanup_errors")}))
    return 0 if result["status"].startswith("PASS_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
