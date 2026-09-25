#!/usr/bin/env python3
"""T07 endpoint traffic only: ordinary kernel TCP/UDP sockets, no policy APIs."""
import argparse
import json
import socket
import sys
import threading
import time


def emit(**fields):
    print(json.dumps(dict(time_ns=time.time_ns(), **fields)), flush=True)


def server(host, port):
    tcp = socket.socket()
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((host, port)); tcp.listen()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((host, port))

    def echo(connection, peer):
        emit(kind='tcp_connect', peer=peer)
        try:
            while True:
                data = connection.recv(65536)
                if not data:
                    break
                emit(kind='tcp_recv', peer=peer, data=data.hex())
                connection.sendall(data)
        except OSError as error:
            emit(kind='tcp_error', peer=peer, error=str(error))
        finally:
            connection.close()
            emit(kind='tcp_close', peer=peer)

    def datagrams():
        while True:
            data, peer = udp.recvfrom(65536)
            emit(kind='udp_recv', peer=peer, data=data.hex())
            udp.sendto(data, peer)

    threading.Thread(target=datagrams, daemon=True).start()
    emit(kind='ready', host=host, port=port)
    while True:
        connection, peer = tcp.accept()
        threading.Thread(target=echo, args=(connection, peer), daemon=True).start()


def client(protocol, host, port, source_host, source_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if protocol == 'tcp':
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.bind((source_host, source_port)); sock.settimeout(5)
    sock.connect((host, port))
    emit(kind='connected', local=sock.getsockname(), peer=sock.getpeername())
    for line in sys.stdin:
        request = json.loads(line)
        if request['op'] == 'close':
            break
        data = request.get('data', '').encode()
        if request['op'] == 'send':
            sock.sendall(data)
            emit(kind='sent', data=data.hex())
        sock.settimeout(request.get('timeout', 0.8))
        expected = request.get('length', len(data))
        received = b''
        try:
            while len(received) < expected:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                received += chunk
        except socket.timeout:
            emit(kind='timeout', data=received.hex())
        else:
            emit(kind='received', data=received.hex())
    sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=['server', 'client'])
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp')
    parser.add_argument('--source-host', default='127.0.0.1')
    parser.add_argument('--source-port', type=int, default=0)
    args = parser.parse_args()
    if args.role == 'server':
        server(args.host, args.port)
    else:
        client(args.protocol, args.host, args.port, args.source_host, args.source_port)
