#!/usr/bin/env python3
"""Numbered real datagrams for persistent-window evidence; no Product emulation."""
import argparse
import hashlib
import json
import socket
import sys
import time

p = argparse.ArgumentParser()
p.add_argument("mode", choices=["server", "client"])
p.add_argument("--host", required=True)
p.add_argument("--peer")
p.add_argument("--port", type=int, default=42131)
p.add_argument("--source-port", type=int, default=42132)
a = p.parse_args()

def report(**fields):
    print(json.dumps(fields), flush=True)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind((a.host, a.port if a.mode == "server" else a.source_port))
    if a.mode == "server":
        report(kind="ready", address=a.host, port=a.port)
        while True:
            payload, peer = sock.recvfrom(65536)
            sock.sendto(payload, peer)
            report(kind="echo", source=peer[0], source_port=peer[1],
                   payload=payload.hex(), payload_bytes=len(payload), completed_ns=time.time_ns())
    else:
        sock.settimeout(5)
        for line in sys.stdin:
            count, size, nonce = line.split()
            count, size = int(count), int(size)
            started = time.time_ns()
            payloads = []
            for sequence in range(count):
                payload = (hashlib.sha256(f"{nonce}:{sequence}".encode()).digest() + b"x" * size)[:size]
                sock.sendto(payload, (a.peer, a.port))
                response, peer = sock.recvfrom(65536)
                assert response == payload and peer == (a.peer, a.port)
                payloads.append(payload.hex())
            report(kind="client", nonce=nonce, count=count, source_port=a.source_port,
                   payload_bytes=size, ip_bytes=size+28, payloads=payloads,
                   started_ns=started, completed_ns=time.time_ns())
