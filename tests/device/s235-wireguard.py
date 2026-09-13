#!/usr/bin/env python3
"""Disposable real WireGuard configuration via its installed Linux UAPI.

This is test network setup, not Product classification or packet injection.
Requires a rootless user namespace; never touches the host network namespace.
Private keys are freshly generated test material supplied on stdin, not logged.
"""
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys


def attribute(kind, data):
    length = 4+len(data)
    return struct.pack('HH', length, kind)+data+b'\0'*((-length) % 4)


def attributes(data):
    while data:
        length, kind = struct.unpack_from('HH', data)
        assert 4 <= length <= len(data)
        yield kind & 0x3fff, data[4:length]
        data = data[(length+3) & ~3:]


def configure(config):
    mapping = Path('/proc/self/uid_map').read_text().split()
    assert os.getuid() == 0 and len(mapping) == 3 and mapping[0] == '0' and mapping[1] != '0' and mapping[2] == '1'
    assert config['interface'].startswith('s235')
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16) as bus:
        bus.bind((0, 0)); bus.settimeout(3)
        body = struct.pack('BBH', 3, 1, 0)+attribute(2, b'wireguard\0')
        bus.send(struct.pack('IHHII', 16+len(body), 0x10, 1, 1, 0)+body)
        reply = bus.recv(65536)
        assert struct.unpack_from('H', reply, 4)[0] != 2, 'WireGuard family unavailable'
        family = struct.unpack('H', dict(attributes(reply[20:]))[1])[0]
        allowed = b''
        for address in config['allowed']:
            network = ipaddress.ip_network(address)
            af = socket.AF_INET if network.version == 4 else socket.AF_INET6
            entry = attribute(1, struct.pack('H', af))+attribute(2, network.network_address.packed)
            entry += attribute(3, struct.pack('B', network.prefixlen))
            allowed += attribute(0x8000, entry)
        endpoint = struct.pack('H', socket.AF_INET)+struct.pack('!H', config['peer_port'])
        endpoint += socket.inet_aton(config['peer_address'])+b'\0'*8
        peer = attribute(1, bytes.fromhex(config['peer_public']))
        peer += attribute(3, struct.pack('I', 2))+attribute(4, endpoint)+attribute(0x8000 | 9, allowed)
        device = attribute(2, config['interface'].encode()+b'\0')
        device += attribute(3, bytes.fromhex(config['private']))+attribute(5, struct.pack('I', 1))
        device += attribute(6, struct.pack('H', config['port']))+attribute(0x8000 | 8, attribute(0x8000, peer))
        body = struct.pack('BBH', 1, 1, 0)+device
        bus.send(struct.pack('IHHII', 16+len(body), family, 1 | 4, 2, 0)+body)
        reply = bus.recv(65536)
        assert struct.unpack_from('H', reply, 4)[0] == 2 and struct.unpack_from('i', reply, 16)[0] == 0, 'WireGuard configuration rejected'
    print(json.dumps(dict(event='wireguard_configured', interface=config['interface'],
          namespace=os.readlink('/proc/self/ns/net'), port=config['port'], allowed=config['allowed'])), flush=True)


if __name__ == '__main__':
    if sys.argv[1:] == ['--keeper']:
        print(json.dumps(dict(event='namespace_keeper', pid=os.getpid(), namespace=os.readlink('/proc/self/ns/net'))), flush=True)
        while True: signal.pause()
    else: configure(json.load(sys.stdin))
