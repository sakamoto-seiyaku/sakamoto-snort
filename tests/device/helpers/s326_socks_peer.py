#!/usr/bin/env python3
"""Finite SOCKS4/4a/5 peer for the S326 device qualification.

It speaks the real negotiation (SOCKS5 method selection with optional
username/password, SOCKS4 reply), records each request it receives, answers
success without opening any outward connection, and then echoes tunnel bytes.
A request the Product refuses never arrives, which is the evidence."""
import ipaddress
import json
from pathlib import Path
import socket
import struct
import threading
import time


class SocksPeer:
    def __init__(self, addresses, out, deadline, *, port):
        self.out, self.deadline = Path(out), deadline
        self.log, self.lock, self.stop = [], threading.Lock(), threading.Event()
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

    @staticmethod
    def read(connection, count):
        data = b""
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def read_until_nul(self, connection, limit=256):
        data = b""
        while True:
            byte = self.read(connection, 1)
            if byte == b"\0":
                return data
            data += byte
            if len(data) > limit:
                raise ValueError("field above bound")

    def serve(self, connection, peer):
        connection.settimeout(10)
        try:
            version = self.read(connection, 1)[0]
            if version == 4:
                command, port = struct.unpack("!BH", self.read(connection, 3))
                address = self.read(connection, 4)
                user = self.read_until_nul(connection)
                host = None
                if address[:3] == b"\0\0\0" and address[3]:
                    host = self.read_until_nul(connection).decode("latin-1")
                self.record(event="request", version="4a" if host else "4", command=command, port=port,
                            host=host, address=None if host else str(ipaddress.ip_address(address)),
                            user=user.decode("latin-1"), peer=list(peer[:2]))
                connection.sendall(b"\x00\x5a" + struct.pack("!H", port) + b"\0\0\0\0")
            elif version == 5:
                methods = self.read(connection, self.read(connection, 1)[0])
                if 2 in methods and 0 not in methods:
                    connection.sendall(b"\x05\x02")
                    _, ulen = self.read(connection, 2)
                    self.read(connection, ulen)
                    self.read(connection, self.read(connection, 1)[0])
                    connection.sendall(b"\x01\x00")
                elif 0 in methods:
                    connection.sendall(b"\x05\x00")
                else:
                    connection.sendall(b"\x05\xff")
                    return
                _, command, _, kind = self.read(connection, 4)
                if kind == 1:
                    host, address = None, str(ipaddress.ip_address(self.read(connection, 4)))
                elif kind == 4:
                    host, address = None, str(ipaddress.ip_address(self.read(connection, 16)))
                else:
                    host, address = self.read(connection, self.read(connection, 1)[0]).decode("latin-1"), None
                port = struct.unpack("!H", self.read(connection, 2))[0]
                self.record(event="request", version="5", command=command, port=port, host=host,
                            address=address, peer=list(peer[:2]))
                connection.sendall(b"\x05\x00\x00\x01\0\0\0\0\0\0")
            else:
                return
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                try:
                    data = connection.recv(65536)
                except socket.timeout:
                    continue
                if not data:
                    return
                self.record(event="tunnel", bytes=len(data), peer=list(peer[:2]))
                connection.sendall(data)
        except (OSError, EOFError, ValueError):
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
