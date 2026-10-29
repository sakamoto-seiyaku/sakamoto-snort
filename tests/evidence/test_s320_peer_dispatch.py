#!/usr/bin/env python3
"""Exercise real independent Linux peer sockets and the shared evidence readers."""
import copy
import importlib.util
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

peer_module = load('linux_peer', 'tests/device/helpers/s316_dns_peer.py')
sequential = load('sequential_dispatch', 'tests/device/helpers/s319_dns_dispatch.py')
coalescing = load('coalescing_dispatch', 'tests/evidence/s320_dns_coalescing_verify.py')

def query(identity, suffix):
    return struct.pack('!HHHHHH', identity, 0x100, 1, 0, 0, 0) + bytes([len(suffix)]) + suffix + b'\0\0\1\0\1'

def reply(q):
    return q[:2] + b'\x81\x80' + q[4:]

def read_exact(channel, count):
    result = b''
    while len(result) < count:
        data = channel.recv(count - len(result))
        assert data
        result += data
    return result

class LinuxPeerAndReaders(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='s320-peer-')
        self.out = Path(self.temp.name)
        for _ in range(16):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1', 0))
                self.port = probe.getsockname()[1]
            if self.port not in (53053,53054):break
        else:raise AssertionError('no separate ephemeral test port')
        self.peer = peer_module.Peer(['127.0.0.1', '::1'], self.out, time.monotonic()+30, self.port)

    def tearDown(self):
        self.peer.close()
        self.temp.cleanup()

    def test_real_udp_tcp_both_families_and_port_bound_readers(self):
        for address, family, index in [('127.0.0.1', socket.AF_INET, 1), ('::1', socket.AF_INET6, 2)]:
            q = query(0x1000+index, b'udp')
            self.peer.register(q, reply(q))
            cursor = self.peer.cursor()
            with socket.socket(family, socket.SOCK_DGRAM) as channel:
                channel.settimeout(2)
                channel.sendto(q, (address, self.port))
                self.assertEqual(channel.recvfrom(4096)[0], reply(q))
            received = self.peer.received(q, after=cursor)
            self.assertEqual(len(received), 1)
            self.assertIn('host_monotonic_ns', received[0])
            first = received[0]
            # The physical-row fixture is synthetic. The peer receipt and UDP
            # exchange above came from real kernel sockets in this test.
            wire = [dict(kind='udp', source=first['peer'][0], source_port=first['peer'][1],
                         destination=first['resolver'][0], destination_port=self.port,
                         payload_hex=first['request_hex'], mono_ns=1,
                         timestamp_scope='userspace_after_recv')]
            qualified = coalescing.qualify_exchange_wire(q, received, wire, [], expected_port=self.port)
            self.assertEqual(qualified['logical_exchanges'], 1)
            self.assertEqual(sequential.qualify_udp_dispatches(q, received, wire, [], expected_port=self.port)['logical_dispatches'], 1)
            for reader in (coalescing.qualify_exchange_wire, sequential.qualify_udp_dispatches):
                with self.assertRaises(AssertionError):
                    reader(q, received, wire, [], expected_port=self.port+1)
                bad = copy.deepcopy(received); bad[0]['resolver'][0] = '192.0.2.99'
                with self.assertRaises(AssertionError):
                    reader(q, bad, wire, [], expected_port=self.port)
            # No selected-port receipt must not conceal the same Question
            # escaping to the historical test port instead.
            escaped=copy.deepcopy(wire);escaped[0]['destination_port']=53053
            with self.assertRaises(AssertionError):
                sequential.qualify_udp_dispatches(q,[],escaped,[],expected_port=self.port)

            qtcp = query(0x2000+index, b'tcp')
            self.peer.register(qtcp, reply(qtcp), protocol='tcp', split=True)
            with socket.socket(family, socket.SOCK_STREAM) as channel:
                channel.settimeout(2); channel.connect((address, self.port))
                framed=struct.pack('!H',len(qtcp))+qtcp
                channel.sendall(framed[:1]); channel.sendall(framed[1:]); channel.shutdown(socket.SHUT_WR)
                size=int.from_bytes(read_exact(channel,2),'big')
                self.assertEqual(read_exact(channel,size),reply(qtcp))
                self.assertEqual(channel.recv(1),b'')

    def test_gate_and_silence_settle_independently(self):
        gate=self.out/'release'; q=query(0x3001,b'gate')
        self.peer.register(q, reply(q), gate=gate)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.settimeout(.1); channel.sendto(q,('127.0.0.1',self.port))
            with self.assertRaises(TimeoutError):channel.recvfrom(4096)
            gate.touch();channel.settimeout(2);self.assertEqual(channel.recvfrom(4096)[0],reply(q))
        silent=query(0x3002,b'silent');self.peer.register(silent,reply(silent),drop=True)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            channel.settimeout(.1);channel.sendto(silent,('127.0.0.1',self.port))
            with self.assertRaises(TimeoutError):channel.recvfrom(4096)

    def test_retry_uses_actual_peer_clock_and_bounded_native_fixture(self):
        q=query(0x4001,b'retry'); self.peer.register(q,reply(q));cursor=self.peer.cursor()
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as channel:
            channel.settimeout(2)
            for _ in range(2):
                channel.sendto(q,('127.0.0.1',self.port))
                self.assertEqual(channel.recvfrom(4096)[0],reply(q))
        received=self.peer.received(q,after=cursor)
        self.assertEqual(len(received),2)
        first=received[0]
        wire=[dict(kind='udp',source=first['peer'][0],source_port=first['peer'][1],
                   destination=first['resolver'][0],destination_port=self.port,
                   payload_hex=first['request_hex'],mono_ns=number,
                   timestamp_scope='userspace_after_recv') for number in (1,2)]
        # These native and physical rows deliberately exercise the reader;
        # only the peer receipts above are actual observations in this test.
        identity=dict(generation=1,owner=0,incarnation=1,transport_session=1,
                      request_attempt=1,token=1,id=0x4001,source_port=1234,
                      protocol=17,network_revision=1,route_revision=1)
        records=[dict(identity,stage=1,mono_us=10),
                 dict(identity,stage=2,name_index=0,mono_us=1600010,proxy_flags=5,upstream_session=3),
                 dict(identity,stage=4,mono_us=1600011,proxy_flags=5,upstream_session=3)]
        for reader in (coalescing.qualify_exchange_wire,sequential.qualify_udp_dispatches):
            qualified=reader(q,received,wire,records,expected_port=self.port)
            retry=qualified['bounded_retry'] if 'bounded_retry' in qualified else qualified['bounded_retries'][0]
            self.assertEqual(retry['peer_observation_clock'],'host_monotonic_ns')
            self.assertGreaterEqual(retry['peer_observation_gap_ns'],0)
            self.assertNotIn('peer_observation_gap_ms',retry)
            with self.assertRaises(AssertionError):
                reader(q,received+[copy.deepcopy(received[-1])],wire,records,expected_port=self.port)
        windows=sequential.peer_observation_gap({'received_mono_ms':10},{'received_mono_ms':13})
        self.assertEqual(windows['peer_observation_gap_ms'],3)
        with self.assertRaises(AssertionError):
            sequential.peer_observation_gap({'received_mono_ms':10},{'host_monotonic_ns':13})

    def test_udp_only_peer_does_not_bind_or_claim_tcp(self):
        # Keep an independently owned TCP listener on the same port. The
        # UDP-only fixture must not touch it or present TCP as available.
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as tcp_owner:
            tcp_owner.bind(('127.0.0.1',0));tcp_owner.listen(1)
            port=tcp_owner.getsockname()[1];out=self.out/'udp-only';out.mkdir()
            peer=peer_module.Peer(['127.0.0.1','::1'],out,time.monotonic()+10,port,transports=('udp',))
            try:
                self.assertEqual(peer.messages[0]['transports'],['udp'])
                q=query(0x5001,b'onlyudp');peer.register(q,reply(q))
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                    client.settimeout(2);client.sendto(q,('127.0.0.1',port))
                    self.assertEqual(client.recvfrom(4096)[0],reply(q))
                with self.assertRaises(AssertionError):peer.register(q,reply(q),protocol='tcp')
                self.assertGreaterEqual(tcp_owner.fileno(),0)
            finally:peer.close()

if __name__ == '__main__':
    unittest.main()
