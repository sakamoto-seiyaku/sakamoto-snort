#!/usr/bin/env python3
"""Real socket peer for the T21 observation evidence, with explicit IP sizes."""
import argparse
import json
import socket
import sys
import time

p = argparse.ArgumentParser()
p.add_argument("mode", choices=["server", "client", "burst"])
p.add_argument("--host", required=True)
p.add_argument("--peer")
p.add_argument("--port", type=int, default=42121)
p.add_argument("--source-port", type=int, default=42122)
p.add_argument("--count", type=int, default=1)
p.add_argument("--size", type=int, default=32)
a = p.parse_args()
family = socket.AF_INET6 if ":" in a.host else socket.AF_INET

def report(**fields):
    print(json.dumps(fields), flush=True)

def client(port, count, size):
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.bind((a.host, port))
        for i in range(count):
            payload = (f"t21-{port}-{i}-".encode() + b"x" * size)[:size]
            s.sendto(payload, (a.peer, a.port))
            reply, _ = s.recvfrom(65536)
            assert reply == payload
        report(kind="client", source_port=port, count=count, payload_bytes=size,
               ip_bytes=size + (48 if family == socket.AF_INET6 else 28), completed_ns=time.time_ns())

if a.mode == "server":
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.bind((a.host, a.port))
        report(kind="ready", family=family, address=a.host, port=a.port)
        while True:
            data, peer = s.recvfrom(65536)
            s.sendto(data, peer)
            report(kind="echo", source_port=peer[1], bytes=len(data), payload=data.hex())
elif a.mode == "burst":
    # A bounded batch keeps enough flows concurrent to exercise Flow capacity,
    # without turning an echo round trip into the admission pacing clock.
    for start in range(0, a.count, 16):
        pending = []
        try:
            for i in range(start, min(start + 16, a.count)):
                port = a.source_port + i
                s = socket.socket(family, socket.SOCK_DGRAM)
                s.settimeout(5)
                s.bind((a.host, port))
                payload = (f"t21-{port}-0-".encode() + b"x" * a.size)[:a.size]
                pending.append((s, port, payload))
                s.sendto(payload, (a.peer, a.port))
            for s, port, payload in pending:
                reply, _ = s.recvfrom(65536)
                assert reply == payload
                report(kind="client", source_port=port, count=1, payload_bytes=a.size,
                       ip_bytes=a.size + (48 if family == socket.AF_INET6 else 28), completed_ns=time.time_ns())
        finally:
            for s, _, _ in pending: s.close()
else:
    for line in sys.stdin:
        count, size = map(int, line.split())
        client(a.source_port, count, size)
