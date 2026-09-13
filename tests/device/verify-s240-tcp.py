#!/usr/bin/env python3
"""Independently verify real Pixel TCP Direct bytes, ownership and lifetimes.

No Product parser, TCP implementation or runner PASS label is an oracle. Raw
inner packets are decoded here, compared with the real kernel peer, and replayed
through the pinned OVS tracker. Parallel worker records are ordered per owner;
the globally interleaved log is not treated as a cross-worker happens-before.
"""
import argparse
import collections
import ctypes
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def records(text):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line), _index=index,
                 _prefix=line.split()[0])
            for index, line in enumerate(text.splitlines())
            if re.match(r's\d+ |event=', line)]


def select(events, **values):
    return [e for e in events if all(e.get(k) == str(v) for k, v in values.items())]


def one(events, **values):
    found = select(events, **values)
    assert len(found) == 1, ('event cardinality', values, len(found))
    return found[0]


def unique(events, key='token'):
    result = {e[key]: e for e in events}
    assert len(result) == len(events), ('duplicate', key)
    return result


def checksum(data):
    data += b'\0' * (len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def decode(raw):
    """This corpus uses unfragmented TCP4/6 without IPv6 extension headers."""
    family = raw[0] >> 4
    if family == 4:
        offset = (raw[0] & 15) * 4
        assert 20 <= offset <= len(raw) and raw[9] == 6
        assert struct.unpack_from('!H', raw, 2)[0] == len(raw)
        assert struct.unpack_from('!H', raw, 6)[0] & 0x3fff == 0
        assert checksum(raw[:offset]) == 0, 'IPv4 header checksum'
        src, dst = raw[12:16], raw[16:20]
        pseudo = src + dst + struct.pack('!BBH', 0, 6, len(raw) - offset)
    else:
        assert family == 6 and len(raw) >= 60 and raw[6] == 6
        offset = 40
        assert struct.unpack_from('!H', raw, 4)[0] + 40 == len(raw)
        src, dst = raw[8:24], raw[24:40]
        pseudo = src + dst + struct.pack('!I3xB', len(raw) - offset, 6)
    assert checksum(pseudo + raw[offset:]) == 0, 'TCP checksum'
    sport, dport, seq, ack = struct.unpack_from('!HHII', raw, offset)
    header = (raw[offset + 12] >> 4) * 4
    assert 20 <= header <= len(raw) - offset
    scale, known, cursor = 0, 0, offset + 20
    while cursor < offset + header:
        kind = raw[cursor]
        if kind == 0:
            break
        if kind == 1:
            cursor += 1
            continue
        assert cursor + 2 <= offset + header
        length = raw[cursor + 1]
        assert length >= 2 and cursor + length <= offset + header
        if kind == 3 and length == 3:
            known, scale = 1, min(14, raw[cursor + 2])
        cursor += length
    return dict(l3=1, l4=1, family=family, protocol=6, icmp_known=0,
                src=src.rjust(16, b'\0').hex(), dst=dst.rjust(16, b'\0').hex(),
                src_port=sport, dst_port=dport, tcp_seq=seq, tcp_ack=ack,
                tcp_window=struct.unpack_from('!H', raw, offset + 14)[0],
                tcp_flags=raw[offset + 13], wscale=scale, wscale_known=known,
                l3_length=offset, transport_offset=offset, l4_length=header,
                transport_length=len(raw) - offset, packet_length=len(raw),
                payload=raw[offset + header:])


class Replay:
    def __init__(self, library):
        self.ref = ctypes.CDLL(str(library))
        self.ref.oracle_create.restype = ctypes.c_void_p
        self.ref.oracle_destroy.argtypes = [ctypes.c_void_p]
        self.ref.oracle_step.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                                        ctypes.POINTER(ctypes.c_uint32)]
        self.states = {}

    def close(self):
        for state in self.states.values():
            self.ref.oracle_destroy(state['context'])

    def step(self, identity, packet, assignment, event):
        state = self.states.setdefault(identity, {})
        if not state:
            state.update(context=self.ref.oracle_create(), orientation=None,
                         incarnation=0, flags=[0, 0])
            assert state['context']
        had_entry = state['orientation'] is not None
        side = int(had_entry and state['orientation'] != assignment['source_is_a'])
        incoming = (ctypes.c_uint32 * 8)(*(packet[k] for k in
                    ('tcp_flags', 'tcp_seq', 'tcp_ack', 'tcp_window')),
                    len(packet['payload']), packet['wscale_known'], packet['wscale'], side)
        result = (ctypes.c_uint32 * 15)()
        self.ref.oracle_step(state['context'], incoming, result)
        update = {11: 2, 12: 3, 14: 1}[result[0]]
        expected = dict(update=update, ct_state=update, timeout=result[2] - 37 if result[2] else 0,
                        refresh=result[1], replacement=result[4], close=result[4])
        assert all(int(event[k]) == v for k, v in expected.items()), ('OVS result', event, expected)
        previous = state['incarnation'] if result[4] else 0
        assert int(event['previous_incarnation']) == previous
        if result[4]:
            state['flags'] = [0, 0]
        created = bool(result[3] and (not had_entry or result[4]))
        assert int(event['created']) == created
        if created:
            state['orientation'], side = assignment['source_is_a'], 0
            assert int(event['incarnation']) > state['incarnation']
            state['incarnation'] = int(event['incarnation'])
        assert int(event['incarnation']) == (state['incarnation'] if result[3] else 0)
        assert int(event['flow_dir']) == (side + 1 if result[3] else 0)
        if update != 3:
            state['flags'][side] |= packet['tcp_flags']
        for peer, label in enumerate(('orig', 'reply')):
            actual = tuple(int(event[label + '_' + k]) for k in ('seqlo', 'seqhi', 'maxwin', 'scale', 'state'))
            assert actual == tuple(result[5 + peer * 5:10 + peer * 5]), ('OVS peer', event)
            assert int(event[label + '_flags']) == state['flags'][peer]


def verify_run(directory, record, run, library, endpoint_connections):
    folder = directory / record['label']
    generation = str(record['generation'])
    events = records((folder / 'native-stop.log').read_text())
    assert events and all(e['generation'] == generation for e in events if 'generation' in e)
    by_token = collections.defaultdict(list)
    for e in events:
        if 'token' in e or 'obligation' in e:
            by_token[e.get('token', e.get('obligation'))].append(e)
    admitted = unique(select(events, _prefix='s216', stage='admit'))
    captured = unique(select(events, _prefix='s213', event='capture'))
    copies = unique(select(events, _prefix='s237', event='return_copy'))
    wires = unique(select(events, _prefix='s240', event='return_wire'))
    inputs = unique(select(events, _prefix='s237', event='input_copy'))
    assert captured and copies and captured.keys().isdisjoint(copies)
    assert admitted.keys() == captured.keys() | copies.keys()
    assert copies.keys() == wires.keys()
    for prefix, key, value, token_key in (
            ('s216', 'stage', 'policy', 'token'), ('s216', 'stage', 'terminal', 'token'),
            ('s203', 'event', 'admit', 'obligation'), ('s203', 'event', 'terminal', 'obligation'),
            ('s204', 'event', 'completion_publish', 'token'),
            ('s204', 'event', 'completion_consume', 'token'),
            ('s213', 'event', 'completion', 'token'), ('s203', 'event', 'buffer_free', 'obligation')):
        assert unique(select(events, _prefix=prefix, **{key: value}), token_key).keys() == admitted.keys()
    live_buffers, heap = {}, {}
    for event in events:
        if ((event['_prefix'], event.get('event')) in
                (('s213', 'capture'), ('s237', 'return_copy'))):
            assert event['buffer'] not in live_buffers, 'overlapping native buffer lifetimes'
            live_buffers[event['buffer']] = event['token']
        if event['_prefix'] == 's203' and event.get('event') == 'buffer_free':
            assert live_buffers.pop(event['buffer']) == event['obligation']
        if event['_prefix'] in ('s237', 's240'):
            if 'owner' in event:
                assert int(event['owner']) in (0, 1)
                assert int(event['thread']) == int(event['owner']) + 1
            if 'tls' in event:
                assert event['tls'] == event['thread']
            identity = (event.get('owner'), event.get('object'))
            if event.get('event') == 'pbuf_alloc':
                assert identity not in heap, 'overlapping pbuf lifetimes'
                heap[identity] = event['kind']
            elif event.get('event') == 'pbuf_free':
                assert heap.pop(identity) == event['kind'], 'pbuf freed by different owner'
    assert not live_buffers and not heap, 'unsettled buffer/pbuf'
    oracle = module('owner240verify', 'tests/device/s207-owner-oracle.py')
    packet_facts, assignments, identities, flow_packets = {}, {}, {}, collections.defaultdict(list)
    coverage = set()
    stable = ('source generation buffer owner l3 l4 family protocol packet_length l3_length '
              'l4_length transport_offset transport_length src dst src_port dst_port tcp_seq '
              'tcp_ack tcp_window tcp_flags wscale wscale_known uid ifindex context availability '
              'direction provenance completion_kind queue_generation packet_id origin_lane').split()
    dropped = set()
    for token, packet in admitted.items():
        related = by_token[token]
        policy = one(related, _prefix='s216', stage='policy')
        terminal = one(related, _prefix='s216', stage='terminal')
        publish = one(related, _prefix='s204', event='completion_publish')
        consume = one(related, _prefix='s204', event='completion_consume')
        complete = one(related, _prefix='s213', event='completion')
        freed = one(related, _prefix='s203', event='buffer_free')
        owner = int(packet['owner'])
        assert int(policy['thread']) == int(terminal['thread']) == owner + 1
        assert consume['thread'] == complete['thread'] == freed['thread'] == '1'
        assert int(consume['producer_thread']) == int(complete['producer']) == owner + 1
        chain = [packet, policy, terminal, publish, consume, complete, freed]
        assert all(a['_index'] < b['_index'] for a, b in zip(chain, chain[1:]))
        assert all(e['buffer'] == packet['buffer'] for e in chain)
        for e in (policy, terminal):
            assert all(e[k] == packet[k] for k in stable), ('metadata changed', token)
        assert publish['frame_bytes'] == '32' and packet['origin_lane'] == consume['lane'] == '0'
        is_return = token in copies
        assert packet['source'] == ('FLOW_STACK_RETURN' if is_return else 'TUN_CAPTURED')
        assert int(packet['thread']) == (owner + 1 if is_return else 1)
        assert packet['direction'] == ('1' if is_return else '3')
        assert packet['provenance'] == ('3' if is_return else '2')
        raw_record = wires[token] if is_return else captured[token]
        assert raw_record['_index'] < packet['_index'] and raw_record['buffer'] == packet['buffer']
        assert packet['raw'] == raw_record['raw']
        assert len(bytes.fromhex(packet['raw'])) == int(raw_record['bytes']) == int(packet['packet_length'])
        drop = complete['policy_drop'] == '1'
        if drop:
            assert is_return and terminal['intent'] == '2'
            assert complete['transport_outcome'] == 'NOT_ATTEMPTED'
            assert not select(related, _prefix='s222')
            dropped.add(token)
        else:
            assert terminal['intent'] == '1'
        if packet['protocol'] != '6':
            assert not is_return and packet['family'] == '6' and packet['protocol'] == '58'
            assert packet['icmp_type'] in ('133', '143'), 'unexpected background traffic'
            assert token not in inputs and complete['transport_outcome'] == 'UNSUPPORTED'
            continue
        facts = decode(bytes.fromhex(packet['raw']))
        assert all(packet[k] == str(v) for k, v in facts.items() if k != 'payload'), ('raw TCP facts', token)
        assignment = oracle.assignment(facts)
        assert assignment['owner'] == owner
        for stage in ('admit', 'policy', 'terminal'):
            witness = one(related, _prefix='s207', stage=stage)
            assert all(str(v) == witness[k] for k, v in assignment.items())
        identity = tuple(assignment[k] for k in ('key_family', 'key_a', 'key_b', 'port_a', 'port_b'))
        packet_facts[token], assignments[token], identities[token] = facts, assignment, identity
        flow_packets[(facts['family'], facts['dst_port'] if is_return else facts['src_port'])].append(packet)
        coverage.add((facts['family'], owner, is_return))
        assert int(packet['uid']) == run['uid']
        if is_return:
            assert token not in inputs and complete['flow_stack_result'] == '0'
            credit = one(related, _prefix='s239', event='return_credit_released')
            # The origin consumer calls vlib_buffer_free, releases the credit,
            # then emits its accounting/free line. Both witnesses follow I/O.
            assert complete['_index'] < credit['_index'] < freed['_index'] and credit['after_native_free'] == '1'
            assert credit['buffer'] == packet['buffer'] and int(credit['owner']) == owner
            assert credit['capacity'] == '128'
            if not drop:
                assert complete['transport_outcome'] == 'TUN_WRITE_SUCCEEDED'
        else:
            copied = inputs[token]
            assert copied['buffer'] == packet['buffer'] and copied['bytes'] == packet['packet_length']
            assert policy['_index'] < copied['_index'] < terminal['_index'] and copied['result'] == '0'
            assert complete['flow_stack_result'] == '1' and complete['transport_outcome'] == 'ADMITTED'
        updates = select(related, _prefix='s222', event='tcp_update')
        assert len(updates) == (0 if drop else 1)
        if updates:
            assert packet['_index'] < updates[0]['_index'] < policy['_index']
            assert updates[0]['owner'] == packet['owner'] and updates[0]['thread'] == policy['thread']
    assert coverage == {(f, o, r) for f in (4, 6) for o in (0, 1) for r in (False, True)}
    assert inputs.keys() == {t for t in packet_facts if t in captured}
    replay = Replay(library)
    try:
        for e in select(events, _prefix='s222', event='tcp_update'):
            token = e['token']
            replay.step(identities[token], packet_facts[token], assignments[token], e)
    finally:
        replay.close()
    session_flows, flow_sessions = {}, {}
    for owner in (0, 1):
        own_copies = [e for e in copies.values() if int(e['thread']) == owner + 1]
        outputs = select(events, _prefix='s237', event='output', owner=owner)
        assert len(own_copies) == len(outputs)
        for copied, output in zip(own_copies, outputs):
            token = copied['token']
            wire, packet = wires[token], admitted[token]
            assert copied['_index'] < wire['_index'] < output['_index'] < packet['_index'], 'inline graph'
            assert copied['serial'] == wire['serial'] and copied['bytes'] == output['bytes']
            assert output['result'] == '0' and int(output['session']) > 0
            assert all(packet[k] == copied[k] for k in ('uid', 'availability', 'context'))
            facts = packet_facts[token]
            session = (owner, output['session'])
            flow = (facts['family'], facts['dst_port'])
            assert session_flows.setdefault(session, flow) == flow, 'session changed tuple'
            assert flow_sessions.setdefault(flow, session) == session, 'transport silently replaced'
            replies = select(events, _prefix='s237', event='broker_reply', thread=owner + 1, session=session[1])
            reply = one(replies)
            known = reply['_index'] < copied['_index']
            assert int(copied['availability']) == (5 if known else 1)
            assert copied['context'] == ('1' if known else '0')
            assert copied['epoch'] == (reply['epoch'] if known else '0')
        own = select(events, _prefix='s237', owner=owner)
        begin = one(own, event='quiesce_begin')
        destroyed = one(own, event='owner_destroyed')
        stopped = one(own, event='owner_stopped')
        assert begin['_index'] < destroyed['_index'] < stopped['_index']
        assert destroyed['bytes'] == destroyed['kind'] == '0'
        assert all(stopped[k] == '0' for k in ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
        assert stopped['timer_fd'] == stopped['broker_fd'] == '-1'
        assert stopped['sockets_created'] == stopped['sockets_closed']
        assert int(stopped['sockets_created']) == len(select(own, event='socket_created'))
        assert not [e for e in outputs + own_copies if e['_index'] > begin['_index']], 'output after quiesce'
        # TCP abort may allocate/free its own RST pbuf after the output gate closes.
        assert not [e for e in own if e['_index'] > begin['_index'] and e.get('event') == 'socket_created']
    brokers = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in (folder / 'broker.log').read_text().splitlines()
               if 's237 broker ' in line]
    brokers = select(brokers, generation=generation)
    assert len(brokers) == len(session_flows)
    expected_flows = {(p['family'], p['source']) for probe in record['probes'] for p in probe['plan']}
    assert flow_packets.keys() == flow_sessions.keys() == expected_flows
    assert len(select(events, _prefix='s237', event='session_created')) == len(expected_flows)
    for session, flow in session_flows.items():
        owner, sid = session
        own = select(events, _prefix='s237', thread=owner + 1, session=sid)
        created = one(own, event='session_created')
        pcb = one(own, event='tcp_pcb_created')
        destroyed = one(own, event='tcp_pcb_destroyed')
        socket = one(own, event='socket_created')
        reply = one(own, event='broker_reply')
        handshake = one(own, event='tcp_handshake')
        attempt = one(own, event='tcp_connect_attempt')
        ready = one(own, event='tcp_connect_ready')
        closing = one(own, event='session_closing')
        assert created['_index'] < pcb['_index'] < destroyed['_index']
        assert pcb['object'] == destroyed['object']
        assert created['_index'] < socket['_index'] < reply['_index'] < attempt['_index'] < ready['_index']
        assert handshake['_index'] < attempt['_index'] and socket['_index'] < closing['_index']
        assert int(socket['result']) >= 0 and socket['result'] == closing['result']
        assert int(attempt['bytes']) == (16 if flow[0] == 4 else 28)  # sockaddr length, not fd.
        assert socket['object'] == closing['object'] == attempt['object']
        assert reply['success'] == reply['known'] == '1' and reply['result'] == '0'
        broker = one(brokers, owner=owner, session=sid)
        assert broker['flags'] == '7' and broker['error'] == '0' and broker['context'] == reply['context'] == '1'
        assert broker['epoch'] == reply['epoch'] and int(reply['epoch']) > 0
        packets = flow_packets[flow]
        assert all(int(p['owner']) == owner for p in packets)
        port = packet_facts[packets[0]['token']]['dst_port']
        refused = port == run['endpoint_port'] + 2
        server_reset = port == run['endpoint_port'] + 1
        # An accepted peer can reset before our first writable SO_ERROR query.
        # Only that separately witnessed reset endpoint may report ECONNRESET
        # here; normal echoes still require successful connection readiness.
        assert ready['result'] in (('111',) if refused else ('0', '104') if server_reset else ('0',))
        connect_failed = ready['result'] != '0'
        failures = select(own, event='tcp_connect_failed')
        assert len(failures) == int(connect_failed)
        if failures: assert failures[0]['result'] == ready['result']
        assert len(select(own, event='tcp_connected')) == int(not connect_failed)
    used_connections, echo_bytes = set(), 0
    for probe in record['probes']:
        report = json.loads((folder / (probe['label'] + '.json')).read_text())
        assert not report.get('error') and report['nonce'] == probe['nonce'] and report['uid'] == run['uid']
        assert report['plan'] == probe['plan'] and len(report['flows']) == 4
        assert {(p['family'], p['owner']) for p in probe['plan']} == {(f, o) for f in (4, 6) for o in (0, 1)}
        for index, (config, outcome) in enumerate(zip(probe['plan'], report['flows'])):
            assert not outcome.get('error') and outcome['nonce'] == probe['nonce'] and outcome['index'] == index
            assert outcome['source'] == config['source'] and outcome['mode'] == config['mode']
            packets = flow_packets[(config['family'], config['source'])]
            directions = [[p for p in packets if (p['source'] == 'FLOW_STACK_RETURN') == returning]
                          for returning in (False, True)]
            for returning, selected in enumerate(directions):
                for p in selected:
                    f = packet_facts[p['token']]
                    assert f['family'] == config['family']
                    remote, local = ('src', 'dst') if returning else ('dst', 'src')
                    assert f[remote] == ipaddress.ip_address(config['address']).packed.rjust(16, b'\0').hex()
                    assert f[remote + '_port'] == config['port'] and f[local + '_port'] == config['source']
                assert any(packet_facts[p['token']]['tcp_flags'] & 2 for p in selected), 'missing handshake'
            rounds = 0 if config['mode'] == 'refusal' else 1 if config['mode'] == 'hold' else 3
            expected = b''
            for round_index in range(rounds):
                prefix = f"{probe['nonce']}_{index}:{round_index}:".encode()
                expected += prefix + bytes([ord('a') + index]) * (config['bytes'] - len(prefix))
            for returning, selected in enumerate(directions):
                # The refusal probe writes byte 42 after the inner handshake.
                # A reset can win that write race; no returned data is allowed.
                allowed_streams = (b'', b'\x2a') if not rounds and not returning else (expected,)
                maximum = max(map(len, allowed_streams))
                syn = next(packet_facts[p['token']] for p in selected if packet_facts[p['token']]['tcp_flags'] & 2)
                start, stream = (syn['tcp_seq'] + 1) & 0xffffffff, {}
                for p in selected:
                    facts = packet_facts[p['token']]
                    offset = (facts['tcp_seq'] - start) & 0xffffffff
                    for position, byte in enumerate(facts['payload'], offset):
                        assert position < maximum, 'unexpected application byte'
                        assert stream.setdefault(position, byte) == byte, 'inconsistent retransmission'
                assert set(stream) == set(range(len(stream))), 'TCP stream gap'
                assert bytes(stream[k] for k in range(len(stream))) in allowed_streams, 'wire stream mismatch'
            assert outcome['echoes'] == rounds
            if rounds:
                assert outcome['echoBytes'] == len(expected)
                matches = [(k, v) for k, v in endpoint_connections.items() if v['data'] == expected]
                assert len(matches) == 1, 'not one actual kernel connection'
                connection, peer = matches[0]
                assert connection not in used_connections
                used_connections.add(connection)
                assert int(peer['accept']['family']) == config['family'] and int(peer['accept']['destination_port']) == config['port']
                assert peer['sent'] == len(expected)
                echo_bytes += len(expected)
                if config['mode'] in ('fin', 'policy'):
                    assert outcome['remoteEof'] and outcome['outcome'] == 'echo_closed'
                    assert all(any(packet_facts[p['token']]['tcp_flags'] & 1 for p in d) for d in directions)
                if config['mode'] == 'rst':
                    assert any(packet_facts[p['token']]['tcp_flags'] & 4 for p in directions[0])
            else:
                assert outcome['outcome'] in ('refused_error', 'refused_eof')
                assert any(packet_facts[p['token']]['tcp_flags'] & 4 for p in directions[1])
            if probe['label'] == 'syn-retransmit':
                syns = [p for p in directions[0] if packet_facts[p['token']]['tcp_flags'] == 2]
                assert len(syns) >= 2 and len({p['tcp_seq'] for p in syns}) == 1
                times = [int(captured[p['token']]['mono_ns']) for p in syns]
                assert max(times) - min(times) > 500000000, 'not a timed SYN retry'
                assert any(p['token'] in dropped for p in directions[1])
            if config['mode'] == 'policy':
                assert outcome['timeouts'] >= 1
                lost = [p for p in directions[1] if p['token'] in dropped and packet_facts[p['token']]['payload']]
                assert lost, 'no actual return DATA drop'
                assert any(a['_index'] < b['_index'] and a['tcp_seq'] == b['tcp_seq']
                           and b['token'] not in dropped and packet_facts[a['token']]['payload'] == packet_facts[b['token']]['payload']
                           for a in lost for b in directions[1]), 'no same-stream data retry/recovery'
    if run['case'] == 'matrix' and record['label'] == 'normal':
        assert {p['label'] for p in record['probes']} == {
            'fin', 'client-rst', 'connect-refusal', 'server-rst', 'syn-retransmit', 'return-policy', 'active-stop'}
        assert len(dropped) > 0
        for label in ('syn-drop', 'syn-recover', 'data-drop', 'data-recover'):
            assert 'policy rc=0' in (folder / (label + '-policy.txt')).read_text()
    else:
        assert len(record['probes']) == 1 and record['probes'][0]['label'] == 'fin' and not dropped
    cli = (folder / 'before-stop.txt').read_text()
    def cli_one(prefix):
        return one([dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in cli.splitlines() if line.startswith(prefix)])
    tun = cli_one('tun.status ')
    assert int(tun['captured']) == len(captured) and int(tun['completed']) == len(admitted)
    assert int(tun['policy_drops']) == len(dropped)
    assert all(tun[k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations', 'errors', 'rejected'))
    count = cli_one('tun.copies ')
    assert int(count['calls']) == len(copies) and int(count['bytes']) == sum(int(e['bytes']) for e in copies.values())
    for owner in (0, 1):
        own_inputs = [e for e in inputs.values() if int(e['owner']) == owner]
        rows = [dict(re.findall(r'(\w+)=([^\s]+)', line)) for line in cli.splitlines() if line.startswith('flow_stack.copies ')]
        count = one(rows, owner=owner)
        assert int(count['calls']) == len(own_inputs) and int(count['bytes']) == sum(int(e['bytes']) for e in own_inputs)
        # Last observed CT entries persist after normal HEV transport closure.
        observed = select(events, _prefix='s208', event='observe', owner=owner)
        begin = one(events, _prefix='s237', event='quiesce_begin', owner=owner)
        assert int(observed[-1]['active']) == len(session_flows) // 2 > int(begin['sessions'])
        assert int(begin['sessions']) == (2 if any(p['label'] == 'active-stop' for p in record['probes']) else 0)
    stop = one(events, _prefix='s213', event='stop')
    assert all(stop[k] == '0' for k in ('pending', 'buffers', 'frames', 'obligations', 'pregraph_returns'))
    assert stop['tun_fd'] == '-1' and int(stop['captured']) == len(captured) and int(stop['completed']) == len(admitted)
    common = module('s237state', 'tests/device/verify-s237.py')
    state = common.props((folder / 'stopped.properties').read_text())
    assert state['state'] == 'stopped' and state['mayBeActive'] == 'false' and state['errorCode'] == ''
    assert state['generation'] == generation and 'libvpp_runtime.so' not in (folder / 'processes-after.txt').read_text()
    return dict(label=record['label'], generation=int(generation), sessions=len(session_flows),
                tcp_packets=len(packet_facts), tracker_updates=len(select(events, _prefix='s222', event='tcp_update')),
                captured=len(captured), returns=len(copies), policy_drops=len(dropped), echo_bytes=echo_bytes,
                pbuf_allocations=len(select(events, _prefix='s237', event='pbuf_alloc'))), used_connections


def verify(build_path, directory, ovs):
    common = module('s237build', 'tests/device/verify-s237.py')
    build = common.verify_build(build_path)
    run = json.loads((directory / 'result.json').read_text())
    assert not run.get('error') and not run.get('cleanup_error') and not run.get('cleanup_errors')
    assert run['build_sha256'] == digest(build_path) and run['apk_sha256'] == build['apk_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert run['serial'] == '28201JEGR0XPAJ' and 'aarch64' in (directory / 'device.txt').read_text()
    assert (directory / 'installed-apk.txt').read_text().split()[0] == build['apk_sha256']
    installed = {Path(line.split()[1]).name: line.split()[0] for line in (directory / 'installed-native.txt').read_text().splitlines()}
    assert installed == build['native_sha256']
    assert run['test_inputs']
    for name, value in run['test_inputs'].items():
        assert digest(directory / 'test-source' / name) == value
    assert digest(directory / 'tcp-endpoint') == run['endpoint_sha256']
    if 'policy_helper_witness' in run:
        witness_path = Path(run['policy_helper_witness']['path'])
        assert digest(witness_path) == run['policy_helper_witness']['sha256']
        witness = json.loads(witness_path.read_text())
        assert witness['platform'] == 'pixel' and witness['build_sha256'] == digest(build_path)
        assert witness['source_sha256'] == build['source_sha256']
        assert run['policy_helper_sha256'] == witness['files']['s217-policy']
        assert digest(witness_path.parent / 's217-policy') == run['policy_helper_sha256']
        for name, expected in witness['sources'].items():
            assert digest(ROOT / name) == expected
    else:
        assert run['policy_helper_sha256'] == build['s221_helpers']['helpers/s217-policy']
    peers = records((directory / 'endpoint.log').read_text())
    one(peers, event='stopped', live_sockets=0)
    connections = {}
    for e in peers:
        if e.get('event') == 'accept':
            assert e['connection'] not in connections
            connections[e['connection']] = dict(accept=e, data=b'', sent=0, closed=False)
        elif e.get('event') in ('read', 'write', 'close', 'server_reset'):
            peer = connections[e['connection']]
            assert not peer['closed']
            if e['event'] == 'read':
                raw = bytes.fromhex(e['raw'])
                assert int(e['offset']) == len(peer['data']) and int(e['bytes']) == len(raw)
                peer['data'] += raw
            elif e['event'] == 'write':
                assert int(e['offset']) == peer['sent']
                peer['sent'] += int(e['bytes'])
                assert peer['sent'] <= len(peer['data'])
            else:
                peer['closed'] = True
                peer['close_event'] = e['event']
                if e['event'] == 'close':
                    assert int(e['received']) == len(peer['data']) and int(e['sent']) == peer['sent']
    assert connections and all(p['closed'] for p in connections.values())
    assert run['case'] in ('matrix', 'smoke')
    assert [r['label'] for r in run['runs']] == (['normal', 'restart'] if run['case'] == 'matrix' else ['normal'])
    assert len({r['generation'] for r in run['runs']}) == len(run['runs'])
    summaries, used = [], set()
    with tempfile.TemporaryDirectory(prefix='s240-verify-') as temporary:
        library = Path(temporary) / 'ovs.so'
        subprocess.run(['python3', str(ROOT / 'tests/host/product_flow_tcp_ovs_test.py'),
                        '--ovs', str(ovs), '--library-output', str(library)], check=True, stdout=subprocess.PIPE)
        for record in run['runs']:
            summary, selected = verify_run(directory, record, run, library, connections)
            assert used.isdisjoint(selected)
            used.update(selected)
            summaries.append(summary)
    resets = {k for k, p in connections.items() if not p['data']}
    assert used | resets == connections.keys() and used.isdisjoint(resets)
    assert len(resets) == (4 if run['case'] == 'matrix' else 0)
    assert all(int(connections[k]['accept']['destination_port']) == run['endpoint_port'] + 1 for k in resets)
    assert all(connections[k]['close_event'] == 'server_reset' for k in resets)
    assert all(sum(int(connections[k]['accept']['family']) == family for k in resets) ==
               (2 if run['case'] == 'matrix' else 0) for family in (4, 6))
    return dict(status='PASS', scope='real-Pixel-W2-TCP4-TCP6-Direct-' + run['case'],
                runs=summaries, source_sha256=build['source_sha256'], apk_sha256=build['apk_sha256'],
                verifier_sha256=digest(__file__))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--ovs', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.build, args.run, args.ovs), indent=2))
