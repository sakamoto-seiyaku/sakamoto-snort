#!/usr/bin/env python3
"""Small external TCP/UDP echo peer for ordinary Android VPN app traffic."""
import argparse
import json
import selectors
import socket
import time


def emit(kind, **fields):
    print(json.dumps({"kind": kind, "monotonic_ns": time.monotonic_ns(), **fields}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--tcp-port", type=int, required=True)
    parser.add_argument("--udp-port", type=int, required=True)
    args = parser.parse_args()
    selector = selectors.DefaultSelector()
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for sock in (tcp, udp):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((args.host, args.tcp_port))
    tcp.listen(16)
    udp.bind((args.host, args.udp_port))
    tcp.setblocking(False)
    udp.setblocking(False)
    selector.register(tcp, selectors.EVENT_READ, "listen")
    selector.register(udp, selectors.EVENT_READ, "udp")
    emit("ready", host=args.host, tcp_port=args.tcp_port, udp_port=args.udp_port)
    while True:
        for key, _ in selector.select():
            if key.data == "listen":
                conn, address = tcp.accept()
                conn.setblocking(False)
                selector.register(conn, selectors.EVENT_READ, "tcp")
                emit("tcp_accept", peer=address)
            elif key.data == "udp":
                data, address = udp.recvfrom(2048)
                udp.sendto(data, address)
                emit("udp_echo", peer=address, length=len(data), payload_hex=data.hex())
            else:
                conn = key.fileobj
                data = conn.recv(2048)
                if data:
                    conn.sendall(data)
                    emit("tcp_echo", peer=conn.getpeername(), length=len(data),
                         payload_hex=data.hex())
                else:
                    selector.unregister(conn)
                    conn.close()


if __name__ == "__main__":
    main()
