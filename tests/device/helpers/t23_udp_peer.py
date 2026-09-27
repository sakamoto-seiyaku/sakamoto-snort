#!/usr/bin/env python3
"""Real UDP traffic only; JSON commands and payloads are independent of policy."""
import argparse
import hashlib
import json
import socket
import sys
import time

p = argparse.ArgumentParser()
p.add_argument("mode", choices=("server", "client"))
p.add_argument("--host", required=True)
p.add_argument("--peer")
p.add_argument("--port", type=int, default=42151)
p.add_argument("--source", type=int, default=43500)
a = p.parse_args()
def emit(value): print(json.dumps(value), flush=True)
if a.mode == "server":
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((a.host, a.port)); emit({"ready": True})
        while True:
            data, peer = sock.recvfrom(65536); received = time.time_ns()
            sock.sendto(data, peer)
            emit({"source": peer[0], "sourcePort": peer[1], "payload": data.hex(),
                  "receivedUtcNs": received, "repliedUtcNs": time.time_ns()})
else:
    sockets = []
    sequence = 0
    def new(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((a.host, port)); sock.connect((a.peer, a.port)); sock.settimeout(.4)
        return sock
    try:
        sockets = [new(a.source+i) for i in range(128)]
        emit({"ready": True, "source": a.source})
        for line in sys.stdin:
            command = json.loads(line)
            if command.get("quit"): break
            count = command["count"]; size = command.get("size", 64)
            assert 0 <= count <= 4096 and 32 <= size <= 1024
            began = time.monotonic_ns(); rows = []
            for i in range(count):
                short = command.get("short", False)
                sock = new(a.source+128+i) if short else sockets[i % command.get("sockets", 1)]
                payload = (hashlib.sha256((command["nonce"]+":"+str(sequence)).encode()).digest()+b"x"*size)[:size]
                sequence += 1
                start = time.monotonic_ns(); wall = time.time_ns(); sock.send(payload)
                echoed = False
                try:
                    while time.monotonic_ns()-start < 400_000_000:
                        if sock.recv(2048) == payload: echoed = True; break
                except socket.timeout: pass
                rows.append({"id": sequence-1, "sentMonoNs": start, "sentUtcNs": wall,
                    "endMonoNs": time.monotonic_ns(), "sourcePort": sock.getsockname()[1],
                    "payload": payload.hex(), "echoed": echoed})
                if short: sock.close()
                if command.get("delayMs"): time.sleep(command["delayMs"]/1000)
            emit({"label": command["label"], "startedMonoNs": began,
                  "completedMonoNs": time.monotonic_ns(), "sent": count,
                  "received": sum(r["echoed"] for r in rows), "exchanges": rows})
    finally:
        for sock in sockets: sock.close()
