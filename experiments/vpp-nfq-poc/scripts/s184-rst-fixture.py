#!/usr/bin/env python3
"""Bounded LAN TCP reset fixture for the S184 real-refusal slice."""

import json
import socket
import struct
import sys
import time


bind_host = sys.argv[1]
port = int(sys.argv[2])
log_path = sys.argv[3]


def log(event, **fields):
    fields["event"] = event
    fields["monotonic_ns"] = time.monotonic_ns()
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(fields, sort_keys=True) + "\n")
        handle.flush()


listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((bind_host, port))
listener.listen(8)
log("tcp_rst_ready", bind_host=bind_host, port=port)

try:
    while True:
        connection, peer = listener.accept()
        log("tcp_rst_connection", peer=f"{peer[0]}:{peer[1]}", port=port)
        # SO_LINGER(0) makes close emit a TCP RST instead of a FIN.  This is
        # deliberately a post-SYN reset fixture; the app/native records must
        # show whether the owner path classifies it as transport refusal.
        connection.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_LINGER,
            struct.pack("ii", 1, 0),
        )
        connection.close()
        log("tcp_rst_sent", peer=f"{peer[0]}:{peer[1]}", port=port)
except KeyboardInterrupt:
    pass
finally:
    listener.close()
