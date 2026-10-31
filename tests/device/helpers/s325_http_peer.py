#!/usr/bin/env python3
"""Finite cleartext HTTP/1.1 peer for the S325 device qualification.

It records exactly which request heads reach it and answers each complete
request with a small keep-alive response. It never interprets policy: a request
the Product refuses simply never arrives, which is the evidence."""
import json
from pathlib import Path
import socket
import threading
import time


class HttpPeer:
    def __init__(self, addresses, out, deadline, *, port):
        self.out, self.port, self.deadline = Path(out), port, deadline
        self.log = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.sockets, self.threads = [], []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            server = socket.socket(family, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((address, port))
            server.listen(32)
            server.settimeout(0.2)
            self.sockets.append(server)
            thread = threading.Thread(target=self.accept, args=(server,), daemon=True)
            thread.start()
            self.threads.append(thread)

    def accept(self, server):
        while not self.stop.is_set() and time.monotonic() < self.deadline:
            try:
                connection, peer = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self.serve, args=(connection, peer), daemon=True)
            thread.start()
            self.threads.append(thread)

    def record(self, **fields):
        with self.lock:
            fields.update(index=len(self.log), mono_ns=time.monotonic_ns())
            self.log.append(fields)
            (self.out / "requests.jsonl").open("a").write(json.dumps(fields) + "\n")

    def serve(self, connection, peer):
        connection.settimeout(0.5)
        buffered = b""
        count = 0
        try:
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                while b"\r\n\r\n" not in buffered:
                    try:
                        data = connection.recv(65536)
                    except socket.timeout:
                        if self.stop.is_set() or time.monotonic() >= self.deadline:
                            return
                        continue
                    if not data:
                        self.record(event="closed", peer=list(peer[:2]), requests=count)
                        return
                    buffered += data
                head, _, buffered = buffered.partition(b"\r\n\r\n")
                text = head.decode("latin-1")
                lines = text.split("\r\n")
                fields = {}
                for line in lines[1:]:
                    name, _, value = line.partition(":")
                    fields.setdefault(name.strip().lower(), value.strip())
                length = int(fields.get("content-length", "0") or 0)
                while len(buffered) < length:
                    buffered += connection.recv(65536)
                buffered = buffered[length:]
                count += 1
                self.record(event="request", peer=list(peer[:2]), request_line=lines[0],
                            host=fields.get("host"), head_bytes=len(head) + 4, body_bytes=length)
                body = b"ok"
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                                   + str(len(body)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + body)
        except (OSError, ValueError):
            return
        finally:
            connection.close()

    def requests(self, after=0):
        with self.lock:
            return [row for row in self.log[after:] if row["event"] == "request"]

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
