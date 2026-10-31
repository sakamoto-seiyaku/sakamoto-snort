#!/usr/bin/env python3
"""Capture the first ClientHello flight of a real OpenSSL DTLS client (no server answers).

Usage: capture_dtls_hello.py OUT.json -- openssl s_client arguments (without -connect).
Records every datagram for 2.5 s, which includes OpenSSL's own timeout retransmission."""
import json
import socket
import subprocess
import sys
import time

out = sys.argv[1]
extra = sys.argv[sys.argv.index("--") + 1:]
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 0))
server.settimeout(0.1)
port = server.getsockname()[1]
client = subprocess.Popen(["openssl", "s_client", *extra, "-connect", f"127.0.0.1:{port}"],
                          stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
datagrams, end = [], time.monotonic() + 2.5
while time.monotonic() < end:
    try:
        data, _ = server.recvfrom(65536)
        datagrams.append(data.hex())
    except socket.timeout:
        pass
client.kill()
client.wait()
json.dump(dict(command=["openssl", "s_client", *extra], openssl=subprocess.check_output(["openssl", "version"], text=True).strip(),
               datagrams=datagrams), open(out, "w"), indent=2)
print(out, len(datagrams), [len(d) // 2 for d in datagrams])
