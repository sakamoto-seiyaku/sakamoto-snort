#!/usr/bin/env python3
"""Ordinary UI/App ordered DNS routing through Product and its normal store."""
import argparse
import importlib.util
import ipaddress
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


base = load("s321_previous", "tests/device/s319-dns-cache.py")
peer_module = load("s321_peer", "tests/device/helpers/s316_dns_peer.py")
shared, fixtures = base.shared, base.fixtures
PKG = base.PKG


def configure(device, label, text, *, exceptions=0):
    previous = device.query_rules(label + "-before")
    device.save(label + "-request.txt", text + "\n")
    device.save(label + "-action.txt", device.action(
        "--es", "dnsUpstream", shlex.quote(text),
        "--el", "expectedSavedRevision", previous["savedRevision"]))
    applied = device.wait(label + "-applied", "files/product-state/complete-rule-config.properties",
                          lambda value: value.get("queryElapsedMillis") not in
                          (None, previous.get("queryElapsedMillis")))
    device.valid_config(applied)
    # A separate public query must report the same complete saved/active source.
    observed = device.query_rules(label + "-independent-query")
    assert {key: value for key, value in applied.items() if key.startswith("dns.")} == {
        key: value for key, value in observed.items() if key.startswith("dns.")}
    assert observed["dns.enabled"] == observed["dns.active.enabled"] == "1"
    for prefix in ("dns", "dns.active"):
        assert observed[prefix + ".endpointCount"] == "2"
        assert observed[prefix + ".routeCount"] == "1"
        assert observed[prefix + ".exceptionCount"] == str(exceptions)
        assert observed[prefix + ".endpoint.0.identity"] == "primary.test"
        assert observed[prefix + ".endpoint.1.identity"] == "backup.test"
        assert observed[prefix + ".route.0.candidates"] == "0,1"
    device.verify_saved_source(label)
    address = next(line.split()[4] for line in text.splitlines() if line.startswith("upstream 0 "))
    device.selected_dns = dict(endpoint=(address, 15353),
                               route_revision=None, active_revision=int(observed["activeRevision"]))
    return observed


def configuration_text(device, family=4, transport="udp", *, exceptions=""):
    address = device.args.endpoint4 if family == 4 else device.args.endpoint6
    return (f"upstream 0 {transport} primary.test {address} 15353\n"
            f"upstream 1 {transport} backup.test {address} 15354\n"
            "route 0 0 1" + ("\n" + exceptions if exceptions else ""))


def routed_exchange(device, primary, backup, result, label, *, family=4, protocol=17,
                    transport="udp", primary_drop=True, expected_port=15354,
                    query=None, answer=None, expected_cached=False):
    """Observe one actual App exchange before checking its business assertion."""
    query = query or device.question(label)
    answer = answer or base.ttl_reply(query)
    primary.register(query, answer, protocol=transport, drop=primary_drop)
    backup.register(query, answer, protocol=transport)
    # The data cache is FlowOwner-local: a cache hit must use the tuple (source port) of the
    # exchange that filled the cache, or with N>1 it may land on an owner without that entry.
    filled = getattr(device, "cache_source_port", None)
    source = filled if expected_cached and filled and protocol == 17 else device.reserve_source_port(label)
    if not expected_cached:
        device.cache_source_port = source
    before = device.wire_coverage(label + "-before")
    cursors = [peer.cursor() for peer in (primary, backup)]
    resolver = "1.1.1.1" if family == 4 else "2606:4700:4700::1111"
    began = time.monotonic_ns()
    client = None
    nonce = None
    try:
        if protocol == 6:
            device.forbid_original_tcp(label, before, source, resolver)
            nonce = device.launch_tcp(label, resolver, source, [query], hold=True, timeout=12000)
            client = device.wait(label + "-reads", "files/product-state/t12-" + nonce + ".json",
                                 lambda value: value.get("phase") in ("dns_tcp_read_complete", "finished"),
                                 timeout=20, json_value=True)
        else:
            nonce = device.launch_queries(label, resolver, source, [query], timeout=12000)
            client = device.client(label, nonce)
        identifier = int.from_bytes(query[:2], "big")
        select = lambda value: [row for row in shared.dns_rows(value)
                                if row["generation"] == device.generation and row["source_port"] == source
                                and row["protocol"] == protocol and row["id"] == identifier
                                and row["proxy_flags"] & 1]
        observation = device.observation_matching(label, lambda value:
            any(row["stage"] == 4 for row in select(value)), timeout=15)
        records = select(observation)
        device.verify_test_source(label, records)
        device.expected_durable.extend(records)
        device.required_durable.append(dict(generation=device.generation, id=identifier,
                                            source=source, proxy=True, stages=[1, 4]))
        after = device.wire_coverage(label + "-after")
        wire = {name: rows[len(before[name]):] for name, rows in after.items()}
        case = dict(label=label, status="OBSERVED", generation=device.generation, ordinary_app=True,
                    family=family, protocol=protocol, upstream_transport=transport,
                    source_port=source, original_resolver=resolver, query=query.hex(),
                    expected_reply=answer.hex(), expected_port=expected_port,
                    expected_cached=expected_cached, client=client, records=records,
                    primary=primary.received(query, protocol=transport, after=cursors[0]),
                    backup=backup.received(query, protocol=transport, after=cursors[1]), wire=wire,
                    return_interface=device.tun_interface if device.args.profile == "vpn" else "lo",
                    physical_interface=device.physical_interface,
                    started_monotonic_ns=began, completed_monotonic_ns=time.monotonic_ns())
        result["cases"].append(case)
        device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")
        return case
    finally:
        if protocol == 6 and nonce:
            device.release_probe(label, nonce)
            device.active_probe = None
            if client and client.get("phase") == "dns_tcp_read_complete":
                assert device.client(label, nonce)["dnsExchanges"] == client["dnsExchanges"]


def validate_routed(case, *, primary_port=15353, primary_failed_before_dns=False, cache_age_us=None):
    client = case["client"]
    assert not client.get("error") and len(client["dnsExchanges"]) == 1, client
    exchange, = client["dnsExchanges"]
    assert exchange.get("sentHex") == case["query"], exchange
    actual = bytes.fromhex(exchange.get("replyHex", ""))
    expected, query = bytes.fromhex(case["expected_reply"]), bytes.fromhex(case["query"])
    base.verify_data_reply(actual, expected, query, 0, cached=case["expected_cached"], cache_age_us=cache_age_us)
    final = [row for row in case["records"] if row["stage"] in (2, 4)]
    assert len(final) == 2 and all(row["upstream_port"] == case["expected_port"] for row in final), final
    assert all(row["proxy_flags"] & (16 if case["expected_cached"] else 4) for row in final), final
    selected = 0 if case["expected_port"] == primary_port else 1
    attempts = [row for row in case["records"] if row["stage"] == 5]
    if case["expected_cached"]:
        assert not case["primary"] and not case["backup"] and not attempts, case
    else:
        assert len(case["primary"] if selected == 0 else case["backup"]) >= 1, case
        if selected == 0: assert not case["backup"], case
        elif primary_failed_before_dns:
            assert not case["primary"], case
            failures = [row for row in attempts if row["proxy_result"] == 13 and row["resolver_id"] == 1]
            assert len(failures) == 1 and failures[0]["tls_state"] == 3 and failures[0]["tls_error"] != 0, failures
        else: assert 1 <= len(case["primary"]) <= 2, case
        started = [row for row in attempts if row["proxy_result"] == 12]
        assert [row["upstream_port"] for row in started] == ([primary_port] if selected == 0 else [primary_port, primary_port + 1]), started
        assert len({row["upstream_attempt"] for row in started}) == len(started), started
        assert all(row["request_attempt"] and row["resolver_id"] == (1 if row["upstream_port"] == primary_port else 2)
                   and row.get("resolution_route", 0) == 0 for row in attempts), attempts
    assert all(row["adapter_profile"] in (1, 2) and
               ((row["caller"] == 0 and row["uid"] == 4294967295) or
                (row["caller"] == 1 and row["uid"] == client["uid"])) for row in case["records"])
    returned = case["wire"][case["return_interface"]]
    if case["protocol"] == 6:
        assert base.previous.stream(returned, 53, case["source_port"]) == struct.pack("!H", len(actual)) + actual
    else:
        packets = [row for row in returned if row.get("kind") == "udp" and row["source_port"] == 53
                   and row["destination_port"] == case["source_port"] and row["payload_hex"] == actual.hex()]
        assert packets, case
        if any(row["adapter_profile"] == 2 for row in case["records"]):
            base.previous.vpn.legal_return(packets[0], query, actual, case["original_resolver"],
                                           case["source_port"], client["local"])
        else:
            shared.legal_return_packet(packets[0], query, actual, case["original_resolver"], case["source_port"])
    assert not any(row.get("kind") in ("udp", "tcp") and row["source_port"] == case["source_port"]
                   and row["destination_port"] == 53
                   and ipaddress.ip_address(row["destination"]) == ipaddress.ip_address(case["original_resolver"])
                   for row in case["wire"][case["physical_interface"]]), case
    case["status"] = "PASS"


def smoke(device, primary, backup, result):
    device.rules("ordered-smoke-allow")
    covered = set()
    for family in (4, 6):
        for protocol in (17, 6):
            transport = "udp" if protocol == 17 else "tcp"
            label = f"ordered-n{device.owners}-{family}-{transport}"
            configure(device, label, configuration_text(device, family, transport))
            device.proxy_ready(label + "-ready")
            case = routed_exchange(device, primary, backup, result, label, family=family,
                                   protocol=protocol, transport=transport)
            covered.update(row["owner"] for row in case["records"] if row["stage"] == 4)
    # Exercise actual owner distribution without claiming a particular hash.
    for index in range(12):
        if covered == set(range(device.owners)):
            break
        label = f"ordered-n{device.owners}-owner-{index}"
        configure(device, label, configuration_text(device))
        device.proxy_ready(label + "-ready")
        case = routed_exchange(device, primary, backup, result, label)
        covered.update(row["owner"] for row in case["records"] if row["stage"] == 4)
    result["actual_owner_coverage"] = sorted(covered)
    assert covered == set(range(device.owners)), covered


def minimal(device, primary, backup, result):
    label = "ordered-primary-timeout-backup-success"
    device.rules(label + "-allow")
    text = (f"upstream 0 udp primary.test {device.args.endpoint4} 15353\n"
            f"upstream 1 udp backup.test {device.args.endpoint4} 15354\nroute 0 0 1")
    configuration = configure(device, label, text)
    ready = device.proxy_ready(label + "-ready")
    query = device.question(label)
    answer, _ = fixtures.answer(query, "ordinary")
    primary.register(query, answer, drop=True)
    backup.register(query, answer)
    source = device.reserve_source_port(label)
    before = device.wire_coverage(label + "-before")
    primary_cursor, backup_cursor = primary.cursor(), backup.cursor()
    started = time.monotonic_ns()
    nonce = device.launch_queries(label, "1.1.1.1", source, [query], timeout=12000)
    client = device.client(label, nonce)
    identifier = int.from_bytes(query[:2], "big")
    selected = lambda value: [row for row in shared.dns_rows(value)
                              if row["generation"] == device.generation
                              and row["source_port"] == source and row["id"] == identifier
                              and row["proxy_flags"] & 1]
    observation = device.observation_matching(label, lambda value:
        any(row["stage"] == 4 for row in selected(value)), timeout=15)
    records = selected(observation)
    device.expected_durable.extend(records)
    device.required_durable.append(dict(generation=device.generation, id=identifier,
                                        source=source, proxy=True, stages=[1, 4]))
    after = device.wire_coverage(label + "-after")
    wire = {name: rows[len(before[name]):] for name, rows in after.items()}
    case = dict(label=label, status="OBSERVED", generation=device.generation,
                ordinary_app=True, source_port=source, query=query.hex(), expected_reply=answer.hex(),
                client=client, configuration=configuration, ready=ready, records=records,
                primary=primary.received(query, after=primary_cursor),
                backup=backup.received(query, after=backup_cursor), wire=wire,
                started_monotonic_ns=started, completed_monotonic_ns=time.monotonic_ns())
    result["cases"].append(case)
    device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")
    return case


def validate_minimal(case):
    client = case["client"]
    assert len(client["dnsExchanges"]) == 1, client
    exchange = client["dnsExchanges"][0]
    assert exchange.get("sentHex") == case["query"], exchange
    assert exchange.get("replyHex") == case["expected_reply"], (
        "primary transport timeout must select configured backup and return its answer",
        exchange.get("replyHex"), case["expected_reply"])
    assert 1 <= len(case["primary"]) <= 2 and len(case["backup"]) == 1, case
    final = [row for row in case["records"] if row["stage"] in (2, 4)]
    assert len(final) == 2 and all(row["upstream_port"] == 15354 for row in final), final
    assert all(row["proxy_result"] == 1 and row["rcode"] == 0 for row in final), final
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
    parser.add_argument("--replace-preserved", type=Path)
    parser.add_argument("--matrix", choices=("minimal", "smoke"), default="minimal")
    parser.add_argument("--cc", default="/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang")
    args = parser.parse_args()
    args.upstream_port = 15353
    for field in ("apk", "stage", "backup", "output"):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((args.backup / "manifest.json").read_text())
    assert baseline["status"] == "PASS" and baseline["all_nodes_archived_exact"]
    device = (base.RootDevice if args.profile == "root" else base.Device)(args)
    device.capture_deadline = time.monotonic() + 1200
    device.owners = int(args.owners)
    result = dict(status="HOLD", task="SAKAMOTO-321", cases=[], runs=[],
                  apk_sha256=base.digest(args.apk), source_sha256=base.digest(Path(__file__)),
                  started_monotonic_ns=time.monotonic_ns())
    peers = []
    try:
        for port in (15353, 15354):
            out = args.output / ("peer-" + str(port))
            out.mkdir()
            peers.append(peer_module.Peer([args.endpoint4, args.endpoint6], out,
                                           device.capture_deadline, port=port))
        result["native"] = device.install()
        result["root_grant"] = device.save("postinstall-root-grant.txt",
            device.adb("shell", "run-as", PKG, "su", "-c", "id"))
        assert "uid=0" in result["root_grant"], "verify KernelSU grant before Root acceptance"
        device.wire_start()
        result["runs"].append(base.start_run(device, device.owners))
        if args.matrix == "minimal":
            minimal(device, *peers, result)
        else:
            smoke(device, *peers, result)
        if args.profile == "root":
            base.root.finish_run(device, result, "minimal")
            base.preserve_sqlite_history(device, "minimal", result["runs"][-1]["sqlite_after_stop"])
        else:
            base.finish_run(device, result, "minimal")
        device.wire_stop()
        for case in result["cases"]:
            (validate_minimal if args.matrix == "minimal" else validate_routed)(case)
        result["status"] = "PASS_ACTUAL_APP_" + args.profile.upper() + "_" + args.matrix.upper()
    except BaseException as error:
        result.update(error=repr(error), traceback=traceback.format_exc())
    finally:
        errors = []
        try:
            device.begin_capture_cleanup()
        except BaseException as error:
            errors.append("reserve: " + repr(error))
        envelope = base.shared.CleanupEnvelope(90, [("wire", 20), ("stop", 35),
                                                   ("reader", 5), ("peer", 20), ("trace", 10)])
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
        result["completed_monotonic_ns"] = time.monotonic_ns()
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result.get(key) for key in ("status", "error", "cleanup_errors")}))
    return 0 if result["status"].startswith("PASS_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
