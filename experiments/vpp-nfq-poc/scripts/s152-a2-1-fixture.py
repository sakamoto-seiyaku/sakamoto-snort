#!/usr/bin/env python3
"""Bounded WSL2/LAN oracle for the S152 A2-1 UID resolver join.

The fixture deliberately provides only local TCP/UDP listeners.  It does not
resolve, proxy, or fall back to a public endpoint.  Readiness is durable in
the JSONL log as one bind event for every registered family/protocol/port.
"""

from __future__ import annotations

import argparse
import json
import signal
import socket
import threading
import time
from pathlib import Path
from typing import List


class Fixture:
    def __init__(self, bind4: str, bind6: str, tcp_port: int,
                 udp_port: int, log_path: Path) -> None:
        self.bind4 = bind4
        self.bind6 = bind6
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.log_path = log_path
        self.stop_event = threading.Event()
        self.log_lock = threading.Lock()
        self.sockets: List[socket.socket] = []

    def log(self, event: str, **fields: object) -> None:
        record = {
            "schema": "s152-a2-1-fixture/v1",
            "event": event,
            "monotonic_ns": time.monotonic_ns(),
            **fields,
        }
        with self.log_lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
                stream.flush()

    def bind(self, family: int, protocol: str, host: str,
             port: int) -> socket.socket:
        sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        sock = socket.socket(family, sock_type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port, 0, 0))
        else:
            sock.bind((host, port))
        if protocol == "tcp":
            sock.listen(32)
        sock.settimeout(0.25)
        self.sockets.append(sock)
        self.log(
            "ready",
            family="ip4" if family == socket.AF_INET else "ip6",
            protocol=protocol,
            host=host,
            port=port,
        )
        return sock

    def tcp_loop(self, sock: socket.socket, family: str) -> None:
        while not self.stop_event.is_set():
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(0.25)
                local = conn.getsockname()
                self.log(
                    "tcp_connection",
                    family=family,
                    local=f"{local[0]}:{local[1]}",
                    peer=f"{peer[0]}:{peer[1]}",
                )
                # The resolver join needs a real SYN/SYN-ACK/accept path, not
                # a public connect outcome.  A short deterministic response is
                # enough to keep the listener observable without making this
                # fixture an application protocol oracle.
                try:
                    conn.sendall(b"s152-a2-1\n")
                except OSError:
                    pass

    def udp_loop(self, sock: socket.socket, family: str) -> None:
        while not self.stop_event.is_set():
            try:
                payload, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            local = sock.getsockname()
            self.log(
                "udp_datagram",
                family=family,
                local=f"{local[0]}:{local[1]}",
                peer=f"{peer[0]}:{peer[1]}",
                payload_len=len(payload),
            )
            try:
                sock.sendto(b"s152-a2-1", peer)
            except OSError:
                pass

    def run(self) -> None:
        sockets = [
            (socket.AF_INET, "ip4", self.bind4, "tcp", self.tcp_port),
            (socket.AF_INET, "ip4", self.bind4, "udp", self.udp_port),
            (socket.AF_INET6, "ip6", self.bind6, "tcp", self.tcp_port),
            (socket.AF_INET6, "ip6", self.bind6, "udp", self.udp_port),
        ]
        try:
            for family, _label, host, protocol, port in sockets:
                self.bind(family, protocol, host, port)
        except OSError as error:
            self.log("bind_failure", error=repr(error))
            self.stop_event.set()
            self.close()
            raise

        threads: List[threading.Thread] = []
        for sock, (_family, label, _host, protocol, _port) in zip(
                self.sockets, sockets):
            target = self.tcp_loop if protocol == "tcp" else self.udp_loop
            thread = threading.Thread(
                target=target, args=(sock, label), daemon=True,
                name=f"s152-a2-1-{label}-{protocol}",
            )
            thread.start()
            threads.append(thread)
        self.log("fixture_ready", families=["ip4", "ip6"],
                 protocols=["tcp", "udp"], tcp_port=self.tcp_port,
                 udp_port=self.udp_port, public_internet_claim=False)
        while not self.stop_event.wait(0.25):
            pass
        self.close()
        for thread in threads:
            thread.join(timeout=1.0)

    def close(self) -> None:
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                pass
        self.sockets.clear()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind4", required=True)
    parser.add_argument("--bind6", required=True)
    parser.add_argument("--tcp-port", required=True, type=int)
    parser.add_argument("--udp-port", required=True, type=int)
    parser.add_argument("--log", required=True, type=Path)
    args = parser.parse_args()
    fixture = Fixture(args.bind4, args.bind6, args.tcp_port,
                      args.udp_port, args.log)

    def stop(_signum: int, _frame: object) -> None:
        fixture.stop_event.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    fixture.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
