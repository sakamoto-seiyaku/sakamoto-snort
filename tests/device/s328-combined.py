#!/usr/bin/env python3
"""SAKAMOTO-328: delivered DNS and connection-domain capabilities together in one Product session.

One installation, one Product runtime per run, real ordinary App traffic. Run 1 executes, in order and
without restarting: original-path association with DNS replacement off, proxied DNS association after
enabling replacement (a view change), cleartext HTTP targets, SOCKS targets and DTLS/TLS/QUIC SNI, each
group replacing the whole rule set (hot rules) on the running Product. A normal Stop must leave no
runtime process, queue, hook or owned route. Run 2 starts a fresh generation on the same installation and
repeats a representative subset, proving the previous generation's facts (association table, refused
targets) do not carry over and the capabilities work again after restart. With --owners 3 the flows of
both runs are spread over the FlowOwners and every owner must have carried at least one case flow."""
import argparse
import importlib.util
import json
from pathlib import Path
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assoc = load("s328_assoc", "tests/device/s324-assoc.py")
http = load("s328_http", "tests/device/s325-http.py")
socks = load("s328_socks", "tests/device/s326-socks.py")
dtls = load("s328_dtls", "tests/device/s327-dtls.py")
routing, base, shared, PKG = http.routing, http.base, http.shared, http.PKG


def owners_seen(result):
    """FlowOwners that carried a case flow, from the Product's own flow tables."""
    seen = set()
    for case in result["cases"]:
        entry = (case.get("flow") or {}).get("entry")
        if entry:
            seen.add(int(entry["worker"]))
        for row in case.get("records", []):
            if "owner" in row:
                seen.add(int(row["owner"]))
    return seen


def resources_zero(device, label):
    """After a normal Stop nothing of the Product may remain on the device."""
    processes = device.save(label + "-processes.txt", device.root("ps -A -o PID,UID,ARGS"))
    assert not any(len(f := line.split()) >= 3 and Path(f[2]).name == "libvpp_runtime.so"
                   for line in processes.splitlines()), "runtime process left after Stop"
    queues = device.save(label + "-queues.txt", device.root("cat /proc/net/netfilter/nfnetlink_queue"))
    assert not queues.strip(), queues
    hooks = device.save(label + "-hooks.txt", device.root(
        "iptables-save -t mangle; ip6tables-save -t mangle; iptables-save -t nat"))
    assert "SAKAMOTO_PRODUCT_" not in hooks, "Product hook left after Stop"
    rules6 = device.save(label + "-rules6.txt", device.root("ip -6 rule show"))
    assert "1396985427" not in rules6, rules6
    state = base.props(device.app("files/runtime-state/snapshot.properties"))
    assert state["state"] == "stopped" and state["mayBeActive"] == "false", state
    return dict(processes_absent=True, queues_empty=True, hooks_absent=True, owned_rule_absent=True,
                generation=state["generation"])


def run_one(device, peers, result):
    http_peer, socks_peer, udp_peer, dns_primary, dns_backup = peers
    # Rules saved by an earlier run persist on the installed App; start from a known allow-all.
    http.http_rules(device, "run1-baseline-allow", deny=False)
    assoc.original_cases(device, result)
    assoc.assoc_cases(device, dns_primary, dns_backup, result)
    # Replacement off again: the remaining groups use their own peers on the original path.
    device.upstream("combined-dns-off")
    http.cases(device, http_peer, result)
    socks.cases(device, socks_peer, result)
    dtls.cases(device, udp_peer, result)


def run_two(device, peers, result, previous_generation):
    http_peer, socks_peer, udp_peer, _, _ = peers
    http.http_rules(device, "run2-baseline-allow", deny=False)
    start, = assoc.assoc_status(device, "run2-start")
    assert int(start["generation"]) > previous_generation, start
    # A new generation starts new tables: nothing expired or dropped from an earlier view. On VPN the
    # phone's own lookups may already have added pairs; Root carries only the test App.
    assert int(start["expired"]) == 0 and int(start["view_dropped"]) == 0 and int(start["evicted"]) == 0, start
    if device.args.profile == "root":
        assert int(start["entries"]) == 0 and int(start["admitted"]) == 0, start
    device.upstream("run2-dns-off")
    case = assoc.original_exchange(device, result, "run2-original-a-udp", "example.com")
    rows = [r for r in case["records"] if r["stage"] == 2]
    assert rows and rows[0]["generation"] == device.generation and rows[0].get("assoc_admitted", 0) >= 1, rows
    case["status"] = "PASS"
    http.http_rules(device, "run2-http-rules")
    case = http.exchange(device, http_peer, result, "run2-http-deny", [http.request("/run2-http-deny/x", "blocked.http.test")])
    assert http.statuses(case) == ["timeout"] and not case["peer"], case
    assert case["flow"]["http"]["denied"] == "blocked.http.test", case["flow"]
    case["status"] = "PASS"
    case = http.exchange(device, http_peer, result, "run2-http-allow", [http.request("/run2-http-allow/x", "allowed.http.test")])
    assert http.statuses(case) == ["answered"] and case["flow"]["http"]["denied_valid"] == "0", case
    case["status"] = "PASS"
    case = socks.exchange(device, socks_peer, result, "run2-socks5-deny",
                          [(socks.greeting(0), 2), (socks.s5("blocked.http.test", port=4501), 10)], mark=socks.by_port(4501))
    assert socks.statuses(case) == ["answered", "timeout"] and not case["peer"], case
    case["status"] = "PASS"
    dtls.sni_rules(device, "run2-sni-rules")
    named = dtls.fixture("dtls12_named")
    pause = 1500 if device.args.profile == "vpn" else 200
    case = dtls.exchange(device, udp_peer, result, "run2-dtls-deny", [(named[0], 0), (named[1], pause), (b"s328-run2", 0)])
    assert dtls.answered(case)[1:] == [False, False] and case["flow"]["sni"]["name"] == "blocked.http.test", case
    case["status"] = "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("apk", "stage", "backup", "output", "certificates"):
        parser.add_argument("--" + field, type=Path, required=field != "certificates")
    parser.add_argument("--endpoint4", required=True)
    parser.add_argument("--endpoint6", required=True)
    parser.add_argument("--owners", choices=("1", "3"), default="1")
    parser.add_argument("--profile", choices=("root", "vpn"), default="root")
    parser.add_argument("--trace", action="store_true")
    parser.add_argument("--installed", action="store_true")
    parser.add_argument("--budget-seconds", type=int, default=5400)
    parser.add_argument("--replace-preserved", type=Path)
    parser.add_argument("--cc", default="/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang")
    args = parser.parse_args()
    args.upstream_port = 15353
    args.matrix = "combined"
    for field in ("apk", "stage", "backup", "output"):
        setattr(args, field, getattr(args, field).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((args.backup / "manifest.json").read_text())
    assert baseline["status"] == "PASS" and baseline["all_nodes_archived_exact"]
    device = (base.RootDevice if args.profile == "root" else base.Device)(args)
    device.capture_deadline = time.monotonic() + args.budget_seconds
    device.owners = int(args.owners)
    result = dict(status="HOLD", task="SAKAMOTO-328", cases=[], runs=[], owners=device.owners,
                  apk_sha256=base.digest(args.apk), source_sha256=base.digest(Path(__file__)),
                  started_monotonic_ns=time.monotonic_ns())
    peers = []
    try:
        deadline = device.capture_deadline
        addresses = [args.endpoint4, args.endpoint6]
        for name in ("peer-http", "peer-socks", "peer-udp", "peer-tcp", "peer-15353", "peer-15354"):
            (args.output / name).mkdir()
        http_peer = http.peer_module.HttpPeer(addresses, args.output / "peer-http", deadline, port=http.PEER_PORT)
        socks_peer = socks.peer_module.SocksPeer(addresses, args.output / "peer-socks", deadline, port=socks.PEER_PORT)
        udp_peer = dtls.peer_module.UdpEchoPeer(addresses, args.output / "peer-udp", deadline, port=dtls.PEER_PORT)
        device.tcp_peer = dtls.peer_module.TcpEchoPeer([args.endpoint4], args.output / "peer-tcp", deadline, port=dtls.TCP_PORT)
        dns_primary = assoc.peer_module.Peer(addresses, args.output / "peer-15353", deadline, port=15353)
        dns_backup = assoc.peer_module.Peer(addresses, args.output / "peer-15354", deadline, port=15354)
        peers = [http_peer, socks_peer, udp_peer, device.tcp_peer, dns_primary, dns_backup]
        result["native"] = device.install()
        result["root_grant"] = device.save("postinstall-root-grant.txt",
            device.adb("shell", "run-as", PKG, "su", "-c", "id"))
        assert "uid=0" in result["root_grant"], "verify KernelSU grant before Root acceptance"
        device.wire_packet_limit = 16384
        device.wire_start()
        case_peers = (http_peer, socks_peer, udp_peer, dns_primary, dns_backup)

        result["runs"].append(base.start_run(device, device.owners))
        run_one(device, case_peers, result)
        first_generation = device.generation
        if args.profile == "root":
            base.root.finish_run(device, result, "run1")
        else:
            base.finish_run(device, result, "run1")
        result["run1_resources"] = resources_zero(device, "run1-after-stop")
        result["run1_owners"] = sorted(owners_seen(result))
        run1_cases = len(result["cases"])

        result["runs"].append(base.start_run(device, device.owners))
        run_two(device, case_peers, result, first_generation)
        if args.profile == "root":
            base.root.finish_run(device, result, "run2")
        else:
            base.finish_run(device, result, "run2")
        result["run2_resources"] = resources_zero(device, "run2-after-stop")
        device.wire_stop()

        assert all(case["status"] == "PASS" for case in result["cases"]), [
            case["label"] for case in result["cases"] if case["status"] != "PASS"]
        result["run1_cases"], result["run2_cases"] = run1_cases, len(result["cases"]) - run1_cases
        result["owners_seen"] = sorted(owners_seen(result))
        assert set(result["owners_seen"]) == set(range(device.owners)), result["owners_seen"]
        result["status"] = "PASS_ACTUAL_APP_" + args.profile.upper() + "_N" + args.owners + "_COMBINED"
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
        print(json.dumps({key: result.get(key) for key in ("status", "error", "cleanup_errors", "owners_seen")}))
    return 0 if result["status"].startswith("PASS_") else 1


if __name__ == "__main__":
    raise SystemExit(main())
