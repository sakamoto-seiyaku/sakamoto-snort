#!/usr/bin/env python3
"""Capture the ClientHello bytes a real OpenSSL TLS client sends over TCP (no server reply).

Usage: capture_tls_hello.py OUT.hex -- openssl s_client arguments (without -connect)."""
import socket
import subprocess
import sys
import time

out = sys.argv[1]
extra = sys.argv[sys.argv.index("--") + 1:]
server = socket.socket()
server.bind(("127.0.0.1", 0))
server.listen(1)
port = server.getsockname()[1]
client = subprocess.Popen(["openssl", "s_client", *extra, "-connect", f"127.0.0.1:{port}"],
                          stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
connection, _ = server.accept()
connection.settimeout(0.3)
data, end = b"", time.monotonic() + 2
while time.monotonic() < end:
    try:
        chunk = connection.recv(65536)
        if not chunk:
            break
        data += chunk
    except socket.timeout:
        if data:
            break
client.kill()
client.wait()
open(out, "w").write(data.hex() + "\n")
print(out, len(data))
