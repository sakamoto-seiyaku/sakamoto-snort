#!/usr/bin/env python3
"""Finite UDP echo peer for the S327 device qualification: records every datagram and echoes it."""
import json
from pathlib import Path
import socket
import threading
import time


class UdpEchoPeer:
    def __init__(self, addresses, out, deadline, *, port):
        self.out, self.deadline = Path(out), deadline
        self.log, self.lock, self.stop = [], threading.Lock(), threading.Event()
        self.sockets, self.threads = [], []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            server = socket.socket(family, socket.SOCK_DGRAM)
            server.bind((address, port))
            server.settimeout(0.2)
            self.sockets.append(server)
            thread = threading.Thread(target=self.serve, args=(server,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def serve(self, server):
        while not self.stop.is_set() and time.monotonic() < self.deadline:
            try:
                data, peer = server.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                row = dict(index=len(self.log), mono_ns=time.monotonic_ns(), peer=list(peer[:2]), hex=data.hex())
                self.log.append(row)
                (self.out / "datagrams.jsonl").open("a").write(json.dumps(row) + "\n")
            try:
                server.sendto(data, peer)
            except OSError:
                pass

    def datagrams(self, after=0):
        with self.lock:
            return list(self.log[after:])

    def cursor(self):
        with self.lock:
            return len(self.log)

    def close(self):
        self.stop.set()
        for server in self.sockets:
            try:
                server.close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(timeout=2)
