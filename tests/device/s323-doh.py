#!/usr/bin/env python3
"""Ordinary Root/VPN App queries use authenticated DoH (HTTPS POST, HTTP/1.1) and normal SQLite."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import shlex
import ssl
import time
import threading
import traceback

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


routing = load("s323_routing", "tests/device/s321-dns-routing.py")
tls_peer = load("s323_peer", "tests/device/helpers/s323_doh_peer.py")
device_tls_peer = load("s323_device_peer", "tests/device/helpers/s323_device_doh_peer.py")
base, shared, PKG = routing.base, routing.shared, routing.PKG


class DoT:
    def wait(self, label, path, predicate, *args, **options):
        before=self.out/(label.removesuffix("-running")+"-before-start-state.properties")
        baseline=base.props(before.read_text())if label.endswith("-running")and before.exists()else{}
        def condition(value):
            fresh_error=value.get("updatedAtMillis")not in(None,baseline.get("updatedAtMillis"))
            if label.endswith("-running") and path == "files/runtime-state/snapshot.properties" and fresh_error and (value.get("state") == "error" or (value.get("state") == "stopped" and value.get("errorCode"))):
                raise AssertionError("ordinary startup failed: " + repr(value))
            return predicate(value)
        return super().wait(label, path, condition, *args, **options)

    def wire_start(self):
        # A DoH matrix with TLS handshakes exceeds the legacy 1024-packet witness. The S319 base
        # selects its 8192-packet capacity budget by matrix name, so present that name for the start.
        matrix, self.args.matrix = self.args.matrix, "capacity"
        try:
            return super().wire_start()
        finally:
            self.args.matrix = matrix

    def action(self, *extras):
        # The isolated offline fixture CA is an explicit debug-only platform
        # dependency. The selected profile still uses its ordinary Start path.
        if "runtimeStart" in extras:
            extras = (*extras, "--ez", "debugDnsTestTrust", "true")
        return super().action(*extras)

    def proxy_ready(self, label, enabled=True):
        if not getattr(self, "dot_selected", False):
            return super().proxy_ready(label, enabled)
        def ready(_value):
            raw = self.cli(label + "-proxy", "show product dns proxy")
            proxy = [base.props(line.replace(" ", "\n")) for line in raw.splitlines()
                     if "dns.proxy owner=" in line]
            tls = [base.props(line.replace(" ", "\n")) for line in raw.splitlines()
                   if "dns.tls owner=" in line]
            if len(proxy) != self.owners or len(tls) != self.owners:
                return False
            self.last_dot_ready = dict(proxy=proxy, tls=tls)
            return all(int(row["generation"]) == self.generation and row["route_ready"] == "1"
                       and row["enabled"] == "1" and row["stopping"] == "0"
                       and int(row["profile"]) == (2 if self.args.profile == "vpn" else 1)
                       and int(row["port"]) == self.selected_dns["endpoint"][1]
                       and ((self.selected_dns["bootstrap"] and row["upstream"] == "unselected")
                            or (not self.selected_dns["bootstrap"] and ipaddress.ip_address(row["upstream"]) == ipaddress.ip_address(self.selected_dns["endpoint"][0])))
                       for row in proxy) and all(int(row["trust_certificates"]) == 1 for row in tls)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if ready(None):
                return self.last_dot_ready
            time.sleep(.1)
        raise AssertionError("current DoT route/trust preparation missing: " + repr(getattr(self, "last_dot_ready", None)))


class RootDevice(DoT, base.RootDevice):
    pass


class VpnDevice(DoT, base.Device):
    pass


PATH = "/dns-query"
# product_dns_proxy.h HTTP failure classes and product_dns_alpn.h states.
FRAMING, STATUS, REDIRECT, CONTENT_TYPE, ENCODING, HEADER_LIMIT, BODY_LIMIT, EMPTY, TRAILING, CLOSED, AGE, ALPN = range(1, 13)
ALPN_NONE, ALPN_HTTP11, ALPN_ABSENT, ALPN_REFUSED = range(4)


def authority(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def configure(device, label, family, *, bootstrap=None, identities=None):
    bootstrap = device.args.matrix == "bootstrap" if bootstrap is None else bootstrap
    address = "-" if bootstrap else device.args.endpoint4 if family == 4 else device.args.endpoint6
    identities = identities or (("localhost",)*2 if bootstrap else ("dot.test",)*2)
    port = 1853 if bootstrap else 15353
    text = (f"upstream 0 doh https://{authority(identities[0], port)}{PATH} {address}\n"
            f"upstream 1 doh https://{authority(identities[1], port+1)}{PATH} {address}\nroute 0 0 1")
    before = device.query_rules(label + "-before")
    device.save(label + "-source.txt", text)
    device.save(label + "-set.txt", device.action("--es", "dnsUpstream", shlex.quote(text),
                "--el", "expectedSavedRevision", before["savedRevision"]))
    applied = device.wait(label + "-applied", "files/product-state/complete-rule-config.properties",
                          lambda row: row.get("queryElapsedMillis") not in (None, before.get("queryElapsedMillis")))
    device.valid_config(applied)
    current = device.query_rules(label + "-independent-query")
    assert {k: v for k, v in current.items() if k.startswith("dns.")} == {
        k: v for k, v in applied.items() if k.startswith("dns.")}
    literal = lambda host: ":" in host or all(part.isdigit() for part in host.split("."))
    for prefix in ("dns", "dns.active"):
        assert current[prefix + ".enabled"] == "1"
        assert current[prefix + ".endpointCount"] == "2"
        assert current[prefix + ".route.0.candidates"] == "0,1"
        for index in (0, 1):
            # The readback shows the TLS service identity only (host); the request path is
            # verified at the peer from the actual HTTP request target.
            assert current[f"{prefix}.endpoint.{index}.identity"] == identities[index].lower()
            assert current[f"{prefix}.endpoint.{index}.transport"] == "4"
            assert current[f"{prefix}.endpoint.{index}.port"] == str(port + index)
            assert current[f"{prefix}.endpoint.{index}.family"] == str(0 if bootstrap else family)
    device.verify_saved_source(label)
    device.dot_selected = True
    device.selected_dns = dict(endpoint=("127.0.0.1" if bootstrap else address, port), route_revision=None,
                               active_revision=int(current["activeRevision"]), bootstrap=bootstrap, identities=identities)
    return current


def install_trust(device):
    nonce = "s322-ca-" + str(time.monotonic_ns())
    remote = "/data/local/tmp/" + nonce + ".crt"
    source = device.args.certificates / "ca.crt"
    expected = base.digest(source)
    existing = device.adb("shell", "run-as", PKG, "sha256sum", "files/dns-test-trust/ca.crt", check=False)
    if existing.split() and existing.split()[0] == expected:
        return dict(scope="explicit debug-only offline CA fixture; production defaults use read-only system roots",
                    sha256=expected, private_directory="files/dns-test-trust", exact_readonly_fixture_reused=True)
    assert "No such file" in existing, "existing CA fixture has a different identity"
    device.save("fixture-ca-push.txt", device.adb("push", str(source), remote))
    actual = device.adb("shell", "sha256sum", remote).split()[0]
    assert actual == expected
    device.save("fixture-ca-install.txt", device.adb("shell", "run-as", PKG, "sh", "-c", shlex.quote(
        "mkdir -p files/dns-test-trust && cat " + remote +
        " > files/dns-test-trust/ca.crt && chmod 444 files/dns-test-trust/ca.crt")))
    assert device.adb("shell", "run-as", PKG, "sha256sum", "files/dns-test-trust/ca.crt").split()[0] == expected
    assert device.adb("shell", "sha256sum", remote).split()[0] == expected
    device.save("fixture-ca-remove-staging.txt", device.adb("shell", "rm", remote))
    return dict(scope="explicit debug-only offline CA fixture; production defaults use read-only system roots",
                sha256=expected, private_directory="files/dns-test-trust", staging_removed=True)


def check_http_request(row, identity):
    http, port = row["http"], row["resolver"][1]
    assert http["method"] == "POST" and http["target"] == PATH, http
    assert http["content_type"] == "application/dns-message" and http["accept"] == "application/dns-message", http
    assert http["host"].lower() == authority(identity, port).lower(), http
    assert http["alpn"] in ("http/1.1", None), http
    return True


def verify_exchange(device, primary, backup, result, label, family=4, protocol=17,
                    *, bootstrap=False, identities=None, failover=False, query=None, expected_cached=False,
                    cache_origin_us=None):
    if query is None:
        configure(device,label,family,bootstrap=bootstrap,identities=identities)
    ready=device.proxy_ready(label+"-ready")
    port=1853 if bootstrap else 15353
    case=routing.routed_exchange(device,primary,backup,result,label,family=family,protocol=protocol,
        transport="tcp",primary_drop=False,expected_port=port+int(failover),query=query,expected_cached=expected_cached)
    case.update(trust_fixture=True,encrypted_upstream=True,prepared=ready)
    age=None
    if expected_cached:
        # Cached TTL aging is measured from the origin response record of the same source.
        response,=[row for row in case["records"] if row["stage"]==2]
        age=response["mono_us"]-cache_origin_us
    routing.validate_routed(case,primary_port=port,primary_failed_before_dns=failover,cache_age_us=age)
    assert all(row["upstream_transport"]==4 for row in case["records"])
    physical=case["wire"][device.physical_interface]
    tls_wire=case["wire"]["lo"] if bootstrap else physical
    payloads=[bytes.fromhex(row["payload_hex"])for row in tls_wire if row.get("kind")=="tcp"
              and row["destination_port"]==case["expected_port"]and row.get("payload_hex")]
    question=bytes.fromhex(case["query"])
    if not expected_cached: assert payloads and any(payload[0]in(20,21,22,23)for payload in payloads)
    else: assert not payloads and not case["primary"] and not case["backup"]
    assert not any(question[2:]in bytes.fromhex(row.get("payload_hex",""))for row in physical), "application DNS escaped encryption"
    assert not any(row.get("kind")=="udp"and row["destination_port"]in(port,port+1)for row in physical)
    actual=[row for row in case["records"]if row["stage"]in(2,4)]
    identity=device.selected_dns["identities"][int(failover)]
    assert all(row["transport_metadata"]==1 and row["service_identity"]==identity
               and row["tls_state"]==(4 if expected_cached else 2)
               and row.get("authorization_state",0)==(0 if expected_cached else 2)
               and row.get("trust_source",0)==(0 if expected_cached else 2)
               and row.get("tls_error",0)==0 for row in actual)
    if expected_cached:
        assert all(row.get("connection_family",0)==0 and row.get("bootstrap_state",0)==0 for row in actual)
        # Cached data creates no HTTP or ALPN claim.
        assert all(row.get("http_status",0)==0 and row.get("http_error",0)==0 and row.get("alpn_state",0)==0
                   and row.get("http_age",0)==0 for row in actual)
    else:
        # The DoH oracle is the normal observation: final HTTP 200, no HTTP error, negotiated http/1.1
        # (a bootstrap Android peer may also omit ALPN, which is recorded as absent).
        allowed = (ALPN_HTTP11,) if not bootstrap else (ALPN_HTTP11, ALPN_ABSENT)
        assert all(row.get("http_status")==200 and row.get("http_error",0)==0
                   and row.get("alpn_state",0) in allowed for row in actual), actual
        served=case["primary"] if not failover else case["backup"]
        assert served and all(check_http_request(row,identity) for row in served), served
    if bootstrap and not expected_cached:
        assert all(row["upstream_family"]==0 and row["connection_family"]==4
                   and row["connection_address"]==[127,0,0,1]+[0]*12
                   and row["bootstrap_state"]==2 and row["bootstrap_port"]==53
                   and row["bootstrap_ifindex"]>0 for row in actual)
        discovered=[row for row in physical if row.get("kind")=="udp"and row["destination_port"]==53
                    and row["payload_hex"][24:]=="096c6f63616c686f73740000010001"]
        assert discovered
        case["bootstrap_wire"]=discovered
        case["qualification"]="Advertised original-network DNS and independent self-hosted Android TLS peer; ordinary App query"
    case["tls_status"]=device.cli(label+"-tls-after","show product dns proxy")
    device.save(label+"-validated.json",json.dumps(case,indent=2)+"\n")
    return case


def smoke(device,primary,backup,result,*,bootstrap=False,prior_cases=()):
    device.rules("doh-allow"+("-bootstrap"if bootstrap else ""))
    qualified=[case for case in prior_cases if bool(case.get("bootstrap_wire"))==bootstrap]
    covered={row["owner"]for case in qualified for row in case["records"]if row["stage"]==4}
    completed={(case["family"],case["protocol"])for case in qualified}
    combinations=[(4,17)]if device.args.matrix in("minimal","bootstrap")else[(f,p)for f in(4,6)for p in(17,6)]
    combinations=[pair for pair in combinations if pair not in completed]
    for index in range(len(combinations)+12):
        if index>=len(combinations)and covered==set(range(device.owners)):break
        family,protocol=combinations[index]if index<len(combinations)else(4,17)
        label=f"doh-{device.args.profile}-n{device.owners}-v{family}-p{protocol}"+("-bootstrap"if bootstrap else "")
        if index>=len(combinations):label+="-owner-"+str(index)
        case=verify_exchange(device,primary,backup,result,label,family,protocol,bootstrap=bootstrap)
        covered.update(row["owner"]for row in case["records"]if row["stage"]==4)
    assert covered==set(range(device.owners)),covered
    result["bootstrap_owner_coverage"if bootstrap else "actual_owner_coverage"]=sorted(covered)


def all_failed(device,primary,backup,result,label,family,protocol):
    configure(device,label,family,identities=("wrong.test",)*2)
    device.proxy_ready(label+"-ready")
    case=routing.routed_exchange(device,primary,backup,result,label,family=family,protocol=protocol,
        transport="tcp",primary_drop=False,expected_port=15354)
    client=case["client"];assert not client.get("error")and len(client["dnsExchanges"])==1,client
    exchange,=client["dnsExchanges"];query=bytes.fromhex(case["query"]);reply=bytes.fromhex(exchange["replyHex"])
    assert reply[:2]==query[:2]and reply[3]&15==2 and reply[4:12]==query[4:6]+bytes(6)
    assert reply[12:]==query[12:]and not case["primary"]and not case["backup"]
    records=case["records"];failed=[row for row in records if row["stage"]==5 and row["proxy_result"]==13]
    assert[row["resolver_id"]for row in failed]==[1,2],failed
    assert all(row["service_identity"]=="wrong.test"and row["tls_state"]==3 and row["tls_error"]!=0
               and row["authorization_state"]==2 and row["trust_source"]==2 for row in failed)
    assert all(row["upstream_transport"]==4 and row["proxy_flags"]&20==0 for row in records)
    assert any(row["stage"]==4 and row["proxy_result"]==3 and row["reply_rcode"]==2 for row in records)
    assert not any(query[2:]in bytes.fromhex(row.get("payload_hex",""))for row in case["wire"][device.physical_interface])
    returned=case["wire"][case["return_interface"]]
    if protocol==6:assert base.previous.stream(returned,53,case["source_port"])==len(reply).to_bytes(2,"big")+reply
    else:
        packets=[row for row in returned if row.get("kind")=="udp"and row["source_port"]==53
                 and row["destination_port"]==case["source_port"]and row["payload_hex"]==reply.hex()]
        assert packets
        if device.args.profile=="vpn":base.previous.vpn.legal_return(packets[0],query,reply,case["original_resolver"],case["source_port"],client["local"])
        else:shared.legal_return_packet(packets[0],query,reply,case["original_resolver"],case["source_port"])
    case.update(status="PASS",qualification="Both configured encrypted identities failed; legal local SERVFAIL, zero upstream application DNS")
    device.save(label+"-validated.json",json.dumps(case,indent=2)+"\n")


def extra_cases(device,primary,backup,result):
    for family,protocol in((4,17),(6,6)):
        label=f"doh-ip-identity-{family}-{protocol}"
        identity=device.args.endpoint4 if family==4 else device.args.endpoint6
        verify_exchange(device,primary,backup,result,label,family,protocol,identities=(identity,)*2)
        verify_exchange(device,primary,backup,result,f"doh-identity-failover-{family}-{protocol}",family,protocol,
                        identities=("wrong.test","dot.test"),failover=True)
        all_failed(device,primary,backup,result,f"doh-all-encrypted-failed-{family}-{protocol}",family,protocol)
    label="doh-normal-cache"
    query=device.question(label)
    configure(device,label,4)
    first=verify_exchange(device,primary,backup,result,label,query=query)
    origin,=[row["mono_us"] for row in first["records"] if row["stage"]==2]
    second=(int.from_bytes(query[:2],"big")+1).to_bytes(2,"big")+query[2:]
    verify_exchange(device,primary,backup,result,label+"-hit",query=second,expected_cached=True,cache_origin_us=origin)


def patched(reply, age):
    """The reply the App must see: every RR TTL reduced by the HTTP Age, floored at zero."""
    out = bytearray(reply)
    for offset, kind, ttl, data, n, section in base.message_layout(reply):
        out[offset:offset+4] = max(0, ttl - age).to_bytes(4, "big")
    return bytes(out)


def doh_exchange(device, primary, backup, label, mode, *, expected_port, query=None, answer=None,
                 backup_mode="ok", expected_cached=False, result):
    configure(device, label, 4)
    primary.mode, backup.mode = mode, backup_mode
    try:
        return routing.routed_exchange(device, primary, backup, result, label, family=4, protocol=17,
            transport="tcp", primary_drop=False, expected_port=expected_port, query=query, answer=answer,
            expected_cached=expected_cached)
    finally:
        primary.mode = backup.mode = "ok"


def final_rows(case):
    rows = [row for row in case["records"] if row["stage"] in (2, 4)]
    assert len(rows) == 2, rows
    return rows


def no_plaintext(device, case):
    question = bytes.fromhex(case["query"])
    physical = case["wire"][device.physical_interface]
    assert not any(question[2:] in bytes.fromhex(row.get("payload_hex", "")) for row in physical), "application DNS escaped encryption"
    assert not any(row.get("kind") == "udp" and row["destination_port"] in (15353, 15354) for row in physical)


def age_cases(device, primary, backup, result):
    ttl = 60
    for suffix, age in (("age", 20), ("age-exceeds-ttl", 600)):
        label = "doh-" + suffix
        query = device.question(label)
        reply = base.ttl_reply(query, ttl)
        expected = patched(reply, age)
        assert expected != reply
        case = doh_exchange(device, primary, backup, label, f"age={age}", expected_port=15353,
                            query=query, answer=reply, result=result)
        case["expected_reply"] = expected.hex()
        routing.validate_routed(case, primary_port=15353)
        rows = final_rows(case)
        assert all(row.get("http_age") == age and row.get("http_status") == 200 and row.get("http_error", 0) == 0
                   and row.get("alpn_state") == ALPN_HTTP11 for row in rows), rows
        assert all(check_http_request(row, "dot.test") for row in case["primary"])
        case["status"] = "PASS"
        # The same name again: aged data is cached only while TTL minus Age remains.
        second = (int.from_bytes(query[:2], "big") + 1).to_bytes(2, "big") + query[2:]
        hit = age < ttl
        origin, = [row["mono_us"] for row in case["records"] if row["stage"] == 2]
        configure(device, label + "-again", 4)
        primary.mode = "ok" if hit else f"age={age}"
        try:
            again = routing.routed_exchange(device, primary, backup, result, label + "-again", family=4, protocol=17,
                transport="tcp", primary_drop=False, expected_port=15353, query=second, answer=reply,
                expected_cached=hit)
        finally:
            primary.mode = "ok"
        again["expected_reply"] = expected.hex()
        if hit:
            response, = [row["mono_us"] for row in again["records"] if row["stage"] == 2]
            routing.validate_routed(again, primary_port=15353, cache_age_us=response - origin)
            assert not again["primary"] and not again["backup"]
            assert all(row.get("http_status", 0) == 0 and row.get("http_age", 0) == 0 for row in final_rows(again))
        else:
            # TTL reached zero: nothing was cached, the second query asks the upstream again.
            routing.validate_routed(again, primary_port=15353)
            assert len(again["primary"]) == 1 and all(row.get("http_age") == age for row in final_rows(again))
        again["status"] = "PASS"


def shape_cases(device, primary, backup, result):
    for mode in ("chunked", "split", "close_delimited"):
        label = "doh-" + mode.replace("_", "-")
        case = doh_exchange(device, primary, backup, label, mode, expected_port=15353, result=result)
        routing.validate_routed(case, primary_port=15353)
        rows = final_rows(case)
        assert all(row.get("http_status") == 200 and row.get("http_error", 0) == 0 for row in rows), rows
        assert case["primary"] and all(check_http_request(row, "dot.test") for row in case["primary"])
        no_plaintext(device, case)
        case["status"] = "PASS"


HTTP_FAILURES = (
    ("status404", STATUS, 404, ALPN_HTTP11),
    ("redirect", REDIRECT, 301, ALPN_HTTP11),
    ("wrongtype", CONTENT_TYPE, 200, ALPN_HTTP11),
    ("early_close", CLOSED, 0, ALPN_HTTP11),
    ("alpn_refuse", ALPN, 0, ALPN_REFUSED),
)


def attempts(case):
    return [row for row in case["records"] if row["stage"] == 5 and row["proxy_result"] == 13]


# A failed candidate is skipped until its bounded cooldown ends (5 s, up to 30 s after consecutive
# failures); each failure case must again try the primary, so wait the cooldown out first.
COOLDOWN_SECONDS = 32


def http_failover(device, primary, backup, result):
    for mode, error, status, alpn in HTTP_FAILURES:
        time.sleep(COOLDOWN_SECONDS)
        label = "doh-fail-" + mode.replace("_", "-")
        case = doh_exchange(device, primary, backup, label, mode, expected_port=15354, result=result)
        client = case["client"]
        assert not client.get("error") and len(client["dnsExchanges"]) == 1, client
        actual = bytes.fromhex(client["dnsExchanges"][0]["replyHex"])
        expected, query = bytes.fromhex(case["expected_reply"]), bytes.fromhex(case["query"])
        base.verify_data_reply(actual, expected, query, 0)
        rows = final_rows(case)
        assert all(row["upstream_port"] == 15354 and row["resolver_id"] == 2 and row["upstream_transport"] == 4
                   and row.get("http_status") == 200 and row.get("http_error", 0) == 0
                   and row.get("alpn_state") == ALPN_HTTP11 and row["proxy_flags"] & 4 for row in rows), rows
        failed, = attempts(case)
        assert failed["resolver_id"] == 1 and failed["upstream_transport"] == 4, failed
        assert failed.get("http_error", 0) == error and failed.get("http_status", 0) == status, failed
        assert failed.get("alpn_state", 0) == alpn, failed
        assert len(case["primary"]) == (0 if mode == "alpn_refuse" else 1) and len(case["backup"]) == 1, case["primary"]
        no_plaintext(device, case)
        case.update(status="PASS", qualification=f"HTTP failure class {error}, backup served, no plaintext")


def all_http_failed(device, primary, backup, result):
    time.sleep(COOLDOWN_SECONDS)
    label = "doh-all-http-failed"
    case = doh_exchange(device, primary, backup, label, "status404", expected_port=15354, backup_mode="status404", result=result)
    client = case["client"]
    assert not client.get("error") and len(client["dnsExchanges"]) == 1, client
    exchange, = client["dnsExchanges"]
    query, reply = bytes.fromhex(case["query"]), bytes.fromhex(exchange["replyHex"])
    assert reply[:2] == query[:2] and reply[3] & 15 == 2 and reply[4:12] == query[4:6] + bytes(6) and reply[12:] == query[12:]
    failed = attempts(case)
    assert [row["resolver_id"] for row in failed] == [1, 2], failed
    assert all(row.get("http_error", 0) == STATUS and row.get("http_status") == 404 and row.get("alpn_state") == ALPN_HTTP11
               and row["upstream_transport"] == 4 for row in failed), failed
    assert len(case["primary"]) == 1 and len(case["backup"]) == 1
    assert any(row["stage"] == 4 and row["proxy_result"] == 3 and row["reply_rcode"] == 2 for row in case["records"])
    no_plaintext(device, case)
    case.update(status="PASS", qualification="Every configured DoH candidate failed: legal local SERVFAIL, zero plaintext")


def doh_cases(device, primary, backup, result):
    age_cases(device, primary, backup, result)
    shape_cases(device, primary, backup, result)
    http_failover(device, primary, backup, result)
    all_http_failed(device, primary, backup, result)


def pending_stop(device,primary,backup,result):
    label="doh-handshake-stop"
    # The case before this one failed both candidates; the primary stays skipped for its bounded
    # cooldown, and the gated handshake must start on the primary, so wait the cooldown out first.
    time.sleep(COOLDOWN_SECONDS)
    configure(device,label,4);device.proxy_ready(label+"-ready")
    gate=threading.Event();primary.handshake_gate=backup.handshake_gate=gate
    query=device.question(label);answer=base.ttl_reply(query)
    for peer in(primary,backup):peer.register(query,answer,protocol="tcp")
    cursor=[len(peer.messages)for peer in(primary,backup)]
    source=device.reserve_source_port(label)
    device.prepare_stop_capture(label)
    nonce=device.launch_queries(label,"1.1.1.1",source,[query],timeout=12000,preserve_ui=True)
    deadline=time.monotonic()+2
    while time.monotonic()<deadline:
        with primary.lock:connected=any(row["kind"]=="connected"for row in primary.messages[cursor[0]:])
        if connected:break
        time.sleep(.005)
    assert connected and not primary.received(query,protocol="tcp")and not backup.received(query,protocol="tcp")
    device.required_durable.append(dict(generation=device.generation,id=int.from_bytes(query[:2],"big"),source=source,proxy=True,stages=[1,3]))
    if device.args.profile=="root":
        run=base.root.finish_run(device,result,label,pending=True)
        base.preserve_sqlite_history(device,label,run["sqlite_after_stop"])
    else:run=base.finish_run(device,result,label,pending=True)
    # Product Stop leaves the debug App cached; Android may freeze its process and the
    # probe thread with it. Bring the App back before reading its own result.
    device.save(label+"-client-foreground.txt",device.action())
    client=device.wait(label+"-client","files/product-state/t12-"+nonce+".json",lambda row:row.get("phase")=="finished",timeout=40,json_value=True)
    assert not any(row.get("replyHex")for row in client["dnsExchanges"]),client
    records=[row for row in run["sqlite_after_stop"]["current_generation_records"]if row["id"]==int.from_bytes(query[:2],"big")
             and row["source_port"]==source and row["proxy_flags"]&1]
    assert any(row["stage"]==3 and row["proxy_result"]==8 for row in records),records
    assert all(row.get("tls_state",0)!=2 for row in records)
    assert not primary.received(query,protocol="tcp")and not backup.received(query,protocol="tcp")
    result["cases"].append(dict(status="PASS",label=label,generation=device.generation,source_port=source,
        query=query.hex(),records=records,client=client,qualification="Ordinary Stop while actual TLS peer withholds handshake; no application DNS before authentication"))
    gate.set()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("apk", "stage", "backup", "output", "certificates"):
        parser.add_argument("--" + field, type=Path, required=True)
    parser.add_argument("--endpoint4", required=True)
    parser.add_argument("--endpoint6", required=True)
    parser.add_argument("--owners", choices=("1", "3"), default="1")
    parser.add_argument("--profile", choices=("root", "vpn"), default="root")
    parser.add_argument("--matrix", choices=("minimal", "bootstrap", "full", "doh", "handshake-stop"), default="minimal")
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--installed", action="store_true")
    parser.add_argument("--budget-seconds", type=int, default=900)
    parser.add_argument("--replace-preserved", type=Path)
    parser.add_argument("--cc", default="/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang")
    args = parser.parse_args()
    args.upstream_port = 15353
    for field in ("apk", "stage", "backup", "output", "certificates"):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    original = json.loads((args.backup / "manifest.json").read_text())
    assert original["status"] == "PASS" and original["all_nodes_archived_exact"]
    device = (RootDevice if args.profile == "root" else VpnDevice)(args)
    device.capture_deadline = time.monotonic() + args.budget_seconds
    device.owners = int(args.owners)
    result = dict(status="HOLD", task="SAKAMOTO-323", cases=[], runs=[],
                  apk_sha256=base.digest(args.apk), source_sha256=base.digest(Path(__file__)),
                  started_monotonic_ns=time.monotonic_ns())
    peers = []
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(["http/1.1"])  # the host peer is an HTTP/1.1 DoH server
        context.load_cert_chain(args.certificates / "leaf.crt", args.certificates / "leaf.key")
        for port in ((15353,15354,1853,1854) if args.matrix == "full" else (1853,1854) if args.matrix == "bootstrap" else (15353,15354)):
            out = args.output / ("peer-" + str(port));out.mkdir()
            if port in (1853,1854):
                peer = device_tls_peer.Peer(device, out, args.certificates, port=port)
                peers.append(peer);peer.start_peer()
            else:
                peers.append(tls_peer.Peer([args.endpoint4, args.endpoint6], out,
                    device.capture_deadline, context, port=port))
        result["native"] = device.install()
        result["root_grant"] = device.save("postinstall-root-grant.txt",
            device.adb("shell", "run-as", PKG, "su", "-c", "id"))
        assert "uid=0" in result["root_grant"], "verify KernelSU grant before treating authorization as Product failure"
        result["trust"] = install_trust(device)
        if args.matrix in ("bootstrap","full"): device.extra_wire_addresses = ["127.0.0.1","192.168.4.11","fd76:d462:c4e3::a11"]
        device.wire_start()
        result["runs"].append(base.start_run(device, device.owners))
        if args.matrix == "full":
            smoke(device,*peers[:2],result)
            smoke(device,*peers[2:],result,bootstrap=True)
            extra_cases(device,*peers[:2],result)
            doh_cases(device,*peers[:2],result)
            pending_stop(device,*peers[:2],result)
        elif args.matrix=="handshake-stop":
            device.rules("doh-allow")
            pending_stop(device,*peers[:2],result)
        elif args.matrix=="doh":
            device.rules("doh-allow-cases")
            doh_cases(device,*peers[:2],result)
        else:smoke(device,*peers,result,bootstrap=args.matrix=="bootstrap")
        if args.matrix in ("full","handshake-stop"):pass
        elif args.profile == "root":
            base.root.finish_run(device, result, "doh")
            base.preserve_sqlite_history(device, "doh", result["runs"][-1]["sqlite_after_stop"])
        else:
            base.finish_run(device, result, "doh")
        device.wire_stop()
        result["status"] = "PASS_ACTUAL_APP_" + args.profile.upper() + "_" + args.matrix.upper()
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
