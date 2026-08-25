#!/usr/bin/env python3
import socket
import sys
import time

bind_host = sys.argv[1]
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((bind_host, port))
print(f"fixture listening {bind_host}:{port}", flush=True)
rx = 0
tx = 0
total_bytes = 0
while True:
    data, addr = sock.recvfrom(65535)
    rx += 1
    total_bytes += len(data)
    print(f"{time.time():.6f} RX {addr[0]}:{addr[1]} bytes={len(data)} "
          f"total={rx} bytes_total={total_bytes}", flush=True)
    sent = sock.sendto(data, addr)
    tx += 1
    print(f"{time.time():.6f} TX {addr[0]}:{addr[1]} bytes={sent} "
          f"total={tx}", flush=True)
