#!/usr/bin/env python3
"""Actual standard-port IPv4 and scoped IPv6 mDNS network preservation."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("s321_semantics", ROOT / "tests/device/s321-dns-routing-semantics.py")
semantics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(semantics)


class NetworkPeer:
    def __init__(self, family, interface, address, out, deadline):
        self.family, self.interface, self.deadline = family, interface, deadline
        self.rows, self.query, self.reply, self.error = [], None, None, None
        self.stop_event = threading.Event()
        self.stream = (out / f"ipv{family}.jsonl").open("x")
        self.channel = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
        self.channel.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == 4:
            self.channel.bind(("", 5353))
            self.membership = socket.inet_aton("224.0.0.251") + socket.inet_aton(address)
            self.channel.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, self.membership)
            self.channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(address))
            self.channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            self.channel.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
            self.multicast = ("224.0.0.251", 5353)
        else:
            self.channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.channel.bind(("::", 5353))
            self.membership = socket.inet_pton(socket.AF_INET6, "ff02::fb") + struct.pack("@I", interface)
            self.channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, self.membership)
            self.channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, interface)
            self.channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            self.channel.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
            self.multicast = ("ff02::fb", 5353, 0, interface)
        self.channel.settimeout(.1)
        self.thread = threading.Thread(target=self.run, name=f"s321-mdns-ipv{family}")
        self.thread.start()

    def emit(self, row):
        assert len(self.rows) < 4096
        row = dict(row, family=self.family, host_monotonic_ns=time.monotonic_ns())
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
                self.emit(dict(kind="received", source=list(remote), wire_hex=wire.hex(), planned=wire == self.query))
                if wire == self.query:
                    destination = self.multicast if remote[1] == 5353 else remote
                    assert self.channel.sendto(self.reply, destination) == len(self.reply)
                    self.emit(dict(kind="response", destination=list(destination), wire_hex=self.reply.hex()))
        except BaseException as error:
            self.error = error
        finally:
            self.channel.close()

    def close(self):
        self.stop_event.set()
        self.thread.join(2)
        assert not self.thread.is_alive() and self.channel.fileno() == -1
        self.stream.close()
        assert self.error is None, self.error


class NetworkPeers:
    def __init__(self, address, out, deadline):
        raw = subprocess.run(["ip", "-j", "addr", "show"], check=True, text=True, capture_output=True).stdout
        interfaces = json.loads(raw)
        selected = [row for row in interfaces if any(value.get("local") == address for value in row["addr_info"])]
        assert len(selected) == 1
        self.identity, = selected
        (out / "fixture-interface.json").write_text(json.dumps(self.identity, indent=2) + "\n")
        self.peers = []
        try:
            for family in (4, 6):
                self.peers.append(NetworkPeer(family, self.identity["ifindex"], address, out, deadline))
        except BaseException:
            self.close()
            raise

    def close(self):
        for peer in reversed(self.peers):
            peer.close()


def run(device, network_peers, candidates, result):
    executable = device.out / "s321-mdns-network-query"
    subprocess.run([device.args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    str(ROOT / "tests/device/helpers/s321_mdns_network_query.c"), "-o", str(executable)], check=True)
    remote = "/data/local/tmp/s321-mdns-network-query"
    device.adb("push", executable, remote)
    device.adb("shell", "chmod", "700", remote)
    try:
        for family, standard, interface in [(4, True, "-"), (6, False, device.physical_interface)]:
            if device.args.mdns_family not in ("both", str(family)):
                continue
            label = f"mdns-ipv{family}-" + ("standard-port" if standard else "explicit-network-scope")
            query = bytearray(semantics.question(device, label + ".local"))
            query[2:4] = bytes(2)
            if standard:
                query[:2] = bytes(2)
            query = bytes(query)
            answer = bytearray(semantics.base.ttl_reply(query))
            answer[2:4] = b"\x84\x00"
            peer = network_peers.peers[0 if family == 4 else 1]
            peer.query, peer.reply = query, bytes(answer)
            source = 5353 if standard else device.reserve_source_port(label)
            before = device.wire_coverage(label + "-before")
            cursors = [item.cursor() for item in candidates]
            raw = device.save(label + "-client.json", device.adb("shell", remote, str(family), str(source), interface,
                                                               query.hex(), check=False))
            client = json.loads(raw)
            case = dict(label=label, kind="mdns-network", status="OBSERVED", family=family, standard=standard,
                        ordinary_app=False, caller_scope="actual shell UID socket; IPv6 explicitly selects actual Wi-Fi scope",
                        client=client, expected=bytes(answer).hex(), peer=[row for row in peer.rows if row.get("planned")],
                        candidates=[item.received(query, after=cursor) for item, cursor in zip(candidates, cursors)],
                        physical_interface=device.physical_interface,
                        tun_interface=getattr(device, "tun_interface", None))
            result["cases"].append(case)
            device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")
            after = device.wire_coverage(label + "-after")
            observation = device.observation(label + "-observation")
            case["records"] = [row for row in semantics.shared.dns_rows(observation)
                               if row["generation"] == device.generation and row["source_port"] == source]
            case["wire"] = {name: rows[len(before[name]):] for name, rows in after.items()}
            device.save(label + "-observed.json", json.dumps(case, indent=2) + "\n")
    finally:
        device.adb("shell", "rm", "-f", remote)


def validate(case):
    assert case["client"]["error"] == 0 and case["client"]["reply_hex"] == case["expected"], case
    assert not any(case["candidates"]) and not any(row["proxy_flags"] & 1 for row in case["records"])
    assert case["peer"] and len({(tuple(row["source"]), row["wire_hex"]) for row in case["peer"]}) == 1
    physical = case["wire"][case["physical_interface"]]
    assert any(row.get("kind") == "udp" and row["destination"] == case["client"]["destination"]
               and row["destination_port"] == 5353 and row["payload_hex"] == case["client"]["query_hex"]
               for row in physical)
    assert any(row.get("kind") == "udp" and row["source_port"] == 5353
               and row["payload_hex"] == case["expected"] for row in physical)
    if case["tun_interface"]:
        tunnel = case["wire"][case["tun_interface"]]
        original = [row for row in tunnel if row.get("kind") == "udp"
                    and row["destination"] == case["client"]["destination"]
                    and row["payload_hex"] == case["client"]["query_hex"]]
        returned = [row for row in tunnel if row.get("kind") == "udp" and row["source_port"] == 5353
                    and row["destination_port"] == case["client"]["source_port"] and row["payload_hex"] == case["expected"]]
        actual_ingress = [row for row in physical if row.get("kind") == "udp" and row["source_port"] == 5353
                          and row["payload_hex"] == case["expected"]]
        assert len(returned) <= len(actual_ingress), ("self-return must not create additional TUN responses", returned, actual_ingress)
        case["actual_path"] = dict(tun_original_queries=len(original), tun_returned=len(returned),
                                   physical_responses=len(actual_ingress),
                                   scope="actual TUN transport" if original else "explicit original-network scope; no TUN ingress observed")
    case["status"] = "PASS"


if __name__ == "__main__":
    raise SystemExit(semantics.main(mdns_runner=run, mdns_peer_factory=NetworkPeers, case_validator=validate))
