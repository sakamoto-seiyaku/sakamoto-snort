#!/usr/bin/env python3
"""Ordinary Root/VPN App queries admit domain-IP association facts (SAKAMOTO-324).

Evidence is the normal stage-2 observation row (assoc_* fields) and the Product's
`dns.assoc` status line. Two-hour expiry, capacity eviction and the read-only
qualification hook are Host-only: waiting two hours or filling 1024 pairs on the
phone is not part of this matrix."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


routing = load("s324_routing", "tests/device/s321-dns-routing.py")
base, shared, fixtures, PKG = routing.base, routing.shared, routing.fixtures, routing.PKG
peer_module = routing.peer_module

REASON = dict(NOT_ELIGIBLE=1, NO_ADDRESS=2, UNUSABLE_ONLY=3, OVER_LIMIT=4)


def reply(query, answers=(), *, authority=(), additional=(), rcode=0):
    """A complete response with the Question and any EDNS OPT of the query kept."""
    _, _, end = fixtures.decode_question(query)
    opt = query[end:]
    flags = 0x8180 | (int.from_bytes(query[2:4], "big") & 0x10) | rcode
    count = len(additional) + (1 if opt else 0)
    return (query[:2] + struct.pack("!5H", flags, 1, len(answers), len(authority), count)
            + query[12:end] + b"".join(answers) + b"".join(authority) + b"".join(additional) + opt)


def a_record(owner, address, ttl=60):
    return fixtures.rr(owner, 1, ipaddress.ip_address(address).packed, ttl)


def aaaa_record(owner, address, ttl=60):
    return fixtures.rr(owner, 28, ipaddress.ip_address(address).packed, ttl)


def cname_record(owner, target, ttl=60):
    return fixtures.rr(owner, 5, fixtures.name(target), ttl)


def assoc_status(device, label):
    raw = device.save(label + "-assoc-status.txt", device.cli(label + "-assoc", "show product dns proxy"))
    rows = [base.props(line.replace(" ", "\n")) for line in raw.splitlines() if line.startswith("dns.assoc ")]
    assert len(rows) == device.owners, raw
    for row in rows:
        assert int(row["generation"]) == device.generation, row
        assert int(row["entry_limit"]) == 1024 and int(row["window_us"]) == 7200 * 10**6, row
        assert row["enforcement"] == "0", row
        assert int(row["bytes"]) > 0 and int(row["entries"]) <= 1024, row
    return rows


def answer_rows(case):
    """Stage-2 records of the answer: one per connected name (QName first)."""
    rows = [r for r in case["records"] if r["stage"] == 2]
    assert rows and sorted(r.get("name_index", 0) for r in rows) == list(range(len(rows))), rows
    return sorted(rows, key=lambda r: r.get("name_index", 0))


def answer_row(case):
    return answer_rows(case)[0]


def exchange(device, primary, backup, result, label, query, answer, *, family=4, protocol=17,
             expected_cached=False, cache_origin_us=None):
    transport = "udp" if protocol == 17 else "tcp"
    case = routing.routed_exchange(device, primary, backup, result, label, family=family, protocol=protocol,
                                   transport=transport, primary_drop=False, expected_port=15353,
                                   query=query, answer=answer, expected_cached=expected_cached)
    age = None
    if expected_cached:
        age = answer_row(case)["mono_us"] - cache_origin_us
    # The shared validator expects one stage-2 and one stage-4 record, i.e. the QName row.
    view = dict(case, records=[r for r in case["records"] if r.get("name_index", 0) == 0])
    routing.validate_routed(view, primary_port=15353, cache_age_us=age)
    case["status"] = view["status"]
    case["status_after"] = assoc_status(device, label)
    return case


def check(case, *, admitted=0, refreshed=0, skipped=0, reason=0):
    row = answer_row(case)
    # Every per-name row of one answer reports the same admission of that answer.
    keys = ("assoc_admitted", "assoc_refreshed", "assoc_skipped", "assoc_reason")
    assert all([r.get(k, 0) for k in keys] == [row.get(k, 0) for k in keys] for r in answer_rows(case)), case["records"]
    got = dict(admitted=row.get("assoc_admitted", 0), refreshed=row.get("assoc_refreshed", 0),
               skipped=row.get("assoc_skipped", 0), reason=row.get("assoc_reason", 0))
    want = dict(admitted=admitted, refreshed=refreshed, skipped=skipped, reason=reason)
    assert got == want, (case["label"], got, want)
    # The return row is written before admission and must carry no association claim.
    assert all(not any(r.get(k) for k in ("assoc_admitted", "assoc_refreshed", "assoc_skipped", "assoc_reason"))
               for r in case["records"] if r["stage"] != 2), case["records"]
    case["association"] = got


def assoc_cases(device, primary, backup, result):
    device.rules("assoc-allow")
    routing.configure(device, "assoc-config", routing.configuration_text(device, 4, "udp"))
    device.proxy_ready("assoc-ready")
    start, = assoc_status(device, "assoc-start")
    keys = ("entries", "admitted", "refreshed", "rejected", "skipped", "evicted", "expired", "view_dropped")
    baseline = {key: int(start[key]) for key in keys}
    if device.args.profile == "root":
        assert not any(baseline.values()), start
    # The VPN carries every lookup of the phone: background lookups may already be in the table.
    result["association_baseline"] = baseline

    label = "assoc-admit"
    query = device.question(label)
    name = fixtures.decode_question(query)[0]
    first = exchange(device, primary, backup, result, label, query, reply(query, [a_record(name, "192.0.2.44")]))
    check(first, admitted=1)
    origin = answer_row(first)["mono_us"]

    label = "assoc-cache-refresh"
    second = (int.from_bytes(query[:2], "big") + 1).to_bytes(2, "big") + query[2:]
    hit = exchange(device, primary, backup, result, label, second, reply(query, [a_record(name, "192.0.2.44")]),
                   expected_cached=True, cache_origin_us=origin)
    check(hit, refreshed=1)

    label = "assoc-cname"
    query = device.question(label)
    name = fixtures.decode_question(query)[0]
    alias = "edge-" + label + ".cdn.test"
    case = exchange(device, primary, backup, result, label, query,
                    reply(query, [cname_record(name, alias), a_record(alias, "192.0.2.45")]))
    check(case, admitted=2)   # QName and the connected CNAME both reach the address

    label = "assoc-hints-ignored"
    query = device.question(label)
    name = fixtures.decode_question(query)[0]
    case = exchange(device, primary, backup, result, label, query,
                    reply(query, [a_record(name, "192.0.2.46"), a_record("unrelated.test", "192.0.2.47")],
                          additional=[a_record(name, "192.0.2.48")]))
    check(case, admitted=1)   # one owner-connected answer record; stray owner and additional data ignored

    label = "assoc-nxdomain"
    query = device.question(label)
    case = exchange(device, primary, backup, result, label, query, base.negative_reply(query, 3))
    check(case, reason=REASON["NOT_ELIGIBLE"])

    label = "assoc-nodata"
    query = device.question(label)
    case = exchange(device, primary, backup, result, label, query, base.negative_reply(query, 0))
    check(case, reason=REASON["NO_ADDRESS"])

    label = "assoc-unusable-address"
    query = device.question(label)
    name = fixtures.decode_question(query)[0]
    case = exchange(device, primary, backup, result, label, query, reply(query, [a_record(name, "127.0.0.1")]))
    check(case, skipped=1, reason=REASON["UNUSABLE_ONLY"])

    final, = assoc_status(device, "assoc-final")
    counts = {key: int(final[key]) - baseline[key] for key in keys}
    # 1 (admit) + 2 (CNAME) + 1 (hints) pairs; one cache refresh; one ineligible answer; one unusable address.
    mine = dict(entries=4, admitted=4, refreshed=1, rejected=1, skipped=1, evicted=0, expired=0, view_dropped=0)
    if device.args.profile == "root":
        assert counts == mine, (final, baseline)
    else:
        # Background lookups may add pairs of their own during the test. Nothing may be lost or double
        # counted, and the test's own contribution is fixed by the per-case rows above; the extras
        # are listed from the complete durable store after Stop.
        assert counts["evicted"] == counts["expired"] == counts["view_dropped"] == 0, (final, baseline)
        assert counts["entries"] == counts["admitted"] >= mine["admitted"], (final, baseline)
        assert counts["refreshed"] >= 1 and counts["rejected"] >= 1 and counts["skipped"] >= 1, (final, baseline)
        result["foreign_pairs_during_test"] = counts["admitted"] - mine["admitted"]
    result["association_status"] = final

    # IPv6 over a proxied TCP session on a fresh configuration (a new Product proxy).
    label = "assoc-aaaa-tcp"
    routing.configure(device, label + "-config", routing.configuration_text(device, 6, "tcp"))
    device.proxy_ready(label + "-ready")
    query = device.question(label, qtype=28)
    name = fixtures.decode_question(query)[0]
    record = aaaa_record(name, "2001:db8::53")
    case = exchange(device, primary, backup, result, label, query, reply(query, [record]),
                    family=6, protocol=6)
    check(case, admitted=1)
    status, = assoc_status(device, label + "-final")
    if device.args.profile == "root":
        assert int(status["entries"]) == 1 and int(status["admitted"]) == 1, status
    else:
        assert int(status["entries"]) == int(status["admitted"]) >= 1, status   # plus any background lookups


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
    args.matrix = "assoc"
    for field in ("apk", "stage", "backup", "output"):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((args.backup / "manifest.json").read_text())
    assert baseline["status"] == "PASS" and baseline["all_nodes_archived_exact"]
    device = (base.RootDevice if args.profile == "root" else base.Device)(args)
    device.capture_deadline = time.monotonic() + args.budget_seconds
    device.owners = int(args.owners)
    result = dict(status="HOLD", task="SAKAMOTO-324", cases=[], runs=[],
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
        assoc_cases(device, *peers, result)
        if args.profile == "root":
            base.root.finish_run(device, result, "assoc")
            base.preserve_sqlite_history(device, "assoc", result["runs"][-1]["sqlite_after_stop"])
        else:
            base.finish_run(device, result, "assoc")
        stopped = result["runs"][-1]["sqlite_after_stop"]
        admissions = {}
        for row in stopped["current_generation_records"]:
            if row.get("stage") == 2 and row.get("proxy_flags", 0) & 1 and row.get("assoc_admitted"):
                admissions[row["token"]] = (row["name"], row["assoc_admitted"], row["uid"])
        result["durable_admissions"] = sorted(admissions.values())
        result["durable_foreign_admissions"] = sorted(
            value for value in admissions.values() if not value[0].endswith(".qname.test") and ".cdn.test" not in value[0])
        # The test's own five answers (1 + 2 + 1 + 1) must all be durable, whatever else the phone looked up.
        own = sum(value[1] for value in admissions.values() if value[0].endswith(".qname.test") or ".cdn.test" in value[0])
        assert own >= 5, result["durable_admissions"]
        device.wire_stop()
        result["status"] = "PASS_ACTUAL_APP_" + args.profile.upper() + "_ASSOC"
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
