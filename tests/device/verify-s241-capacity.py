#!/usr/bin/env python3
"""Independent S241 packet/resource/outcome verifier, not a runner PASS parser."""
import argparse
import collections
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


tcp = module('tcp241', 'tests/device/verify-s240-tcp.py')
common = module('common241', 'tests/device/verify-s237.py')
oracle = module('oracle241', 'tests/device/s207-owner-oracle.py')
records, select, one, unique = tcp.records, tcp.select, tcp.one, tcp.unique
FAULTS = ('NONE', 'SESSION_CAPACITY', 'PCB_CAPACITY', 'SOCKET_CAPACITY', 'PACKET_CREDIT',
          'PBUF_CAPACITY', 'ALLOCATION', 'SOCKET_CREATE', 'BROKER_SUBMIT', 'BROKER_TIMEOUT',
          'PROTECT', 'BIND', 'AUTHORIZATION', 'CONNECT_REFUSED', 'NETWORK_UNREACHABLE',
          'CONNECT', 'SOCKET_IO', 'OUTPUT_CAPACITY', 'OUTPUT_REJECTED')
EXPECTED = {'session-capacity': 'SESSION_CAPACITY', 'pcb-capacity': 'PCB_CAPACITY',
            'socket-capacity': 'SOCKET_CAPACITY', 'packet-credit': 'PACKET_CREDIT',
            'pbuf-capacity': 'PBUF_CAPACITY', 'protect': 'PROTECT', 'bind': 'BIND',
            'refusal': 'CONNECT_REFUSED', 'unreachable': 'NETWORK_UNREACHABLE',
            'drop': 'NONE', 'flow-capacity': 'NONE'}
LIMITS = {'session-capacity': '1,258,256,1024,8192', 'pcb-capacity': '256,3,256,1024,8192',
          'socket-capacity': '256,258,1,1024,8192', 'packet-credit': '256,258,256,1,8192',
          'pbuf-capacity': '256,258,256,1024,8', 'drop': '1,258,256,1024,8192'}


def cli_rows(text, prefix):
    return [dict(re.findall(r'(\w+)=([^\s]+)', line))
            for line in text.replace('\0', '').splitlines() if line.startswith(prefix + ' ')]


def udp_decode(raw):
    family = raw[0] >> 4
    if family == 4:
        offset = (raw[0] & 15) * 4
        assert raw[9] == 17 and offset >= 20 and len(raw) >= offset + 8
        assert struct.unpack_from('!H', raw, 2)[0] == len(raw)
        assert not (struct.unpack_from('!H', raw, 6)[0] & 0x3fff)
        assert tcp.checksum(raw[:offset]) == 0
        src, dst = raw[12:16], raw[16:20]
        pseudo = src + dst + struct.pack('!BBH', 0, 17, len(raw) - offset)
    else:
        assert family == 6 and raw[6] == 17 and len(raw) >= 48
        offset = 40
        assert struct.unpack_from('!H', raw, 4)[0] + 40 == len(raw)
        src, dst = raw[8:24], raw[24:40]
        pseudo = src + dst + struct.pack('!I3xB', len(raw) - offset, 17)
    sport, dport, length, checksum = struct.unpack_from('!HHHH', raw, offset)
    assert length == len(raw) - offset
    assert (family == 4 and checksum == 0) or tcp.checksum(pseudo + raw[offset:]) == 0
    return dict(l3=1, l4=1, family=family, protocol=17, icmp_known=0,
        src=src.rjust(16, b'\0').hex(), dst=dst.rjust(16, b'\0').hex(), src_port=sport, dst_port=dport,
        l3_length=offset, l4_length=8, transport_offset=offset, transport_length=length,
        packet_length=len(raw), payload=raw[offset + 8:])


def endpoint_connections(directory):
    events = records((directory / 'tcp-endpoint.log').read_text())
    one(events, event='ready'); one(events, event='stopped', live_sockets=0)
    connections = {}
    for e in events:
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
                assert e['event'] == 'close', 'unexpected peer reset'
                assert int(e['received']) == len(peer['data']) and int(e['sent']) == peer['sent']
    assert all(p['closed'] for p in connections.values())
    return connections


def verify_case(directory, card, run, peers):
    folder = directory / card['label']
    generation, case = str(card['generation']), card['case']
    target = card['expected']['owner']
    assert target in (0, 1)
    assert case in EXPECTED and card['family'] in (4, 6) and card['protocol'] in ('tcp', 'udp')
    assert card['limits'] == LIMITS.get(case, '256,258,256,1024,8192')
    assert card['flow_entries'] == (1 if case == 'flow-capacity' else 1024)
    assert card['label'] == f"{card['protocol']}{card['family']}-{case}"
    assert card['expected'] == dict(fault=EXPECTED[case], owner=target, no_spill=True,
        preserve_existing=True, policy_drop=case == 'drop', processing_bypass=case == 'flow-capacity', zero_residue=True)
    labels = [p['label'] for p in card['probes']]
    assert labels == (['pressure', 'new-flow-recovery'] if card['protocol'] == 'tcp' else
                      ['warm', 'pressure', 'same-flow-recovery', 'new-flow-recovery']), 'missing required recovery probe'
    assert all(p['protocol'] == card['protocol'] and all(f['family'] == card['family'] for f in p['plan'])
               for p in card['probes'])
    pressure_probe = next(p for p in card['probes'] if p['label'] == 'pressure')
    assert [p['owner'] for p in pressure_probe['plan']] == ([target, target, 1 - target]
        if card['protocol'] == 'tcp' and case not in ('packet-credit', 'pbuf-capacity') else [target, 1 - target])
    assert [p['owner'] for p in card['probes'][-1]['plan']] == [target]
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
    assert admitted.keys() == captured.keys() | copies.keys() and copies.keys() == wires.keys()
    for prefix, key, value, token_key in (
        ('s216', 'stage', 'policy', 'token'), ('s216', 'stage', 'terminal', 'token'),
        ('s203', 'event', 'admit', 'obligation'), ('s203', 'event', 'terminal', 'obligation'),
        ('s204', 'event', 'completion_publish', 'token'), ('s204', 'event', 'completion_consume', 'token'),
        ('s213', 'event', 'completion', 'token'), ('s203', 'event', 'buffer_free', 'obligation')):
        assert unique(select(events, _prefix=prefix, **{key: value}), token_key).keys() == admitted.keys(), (card['label'], key, value)
    live_buffers, pbufs = {}, {}
    for e in events:
        if (e['_prefix'], e.get('event')) in (('s213', 'capture'), ('s237', 'return_copy')):
            assert e['buffer'] not in live_buffers, 'overlapping VPP allocation'
            live_buffers[e['buffer']] = e['token']
        elif e['_prefix'] == 's203' and e.get('event') == 'buffer_free':
            assert live_buffers.pop(e['buffer']) == e['obligation'], 'wrong/duplicate VPP free'
        if e['_prefix'] in ('s237', 's240'):
            if 'owner' in e:
                assert int(e['owner']) in (0, 1) and int(e['thread']) == int(e['owner']) + 1
            if 'tls' in e: assert e['tls'] == e['thread'], 'callback TLS differs from owner'
            identity = (e.get('owner'), e.get('object'))
            if e.get('event') == 'pbuf_alloc':
                assert identity not in pbufs, 'overlapping pbuf allocation'
                pbufs[identity] = e['kind']
            elif e.get('event') == 'pbuf_free':
                assert pbufs.pop(identity) == e['kind'], 'wrong-owner pbuf free'
    assert not live_buffers and not pbufs, 'unsettled native resources'
    packets, flow_packets, dropped, bypassed, rejected = {}, collections.defaultdict(list), set(), set(), set()
    stable = ('source generation buffer owner l3 l4 family protocol packet_length l3_length l4_length '
              'transport_offset transport_length src dst src_port dst_port uid ifindex context availability '
              'direction provenance completion_kind queue_generation packet_id origin_lane').split()
    for token, packet in admitted.items():
        related, returning = by_token[token], token in copies
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
        assert all(a['_index'] < b['_index'] for a, b in zip(chain, chain[1:])), 'settlement ordering'
        assert all(e['buffer'] == packet['buffer'] for e in chain)
        assert all(e[k] == packet[k] for e in (policy, terminal) for k in stable), 'packet facts changed'
        assert publish['frame_bytes'] == '32' and packet['origin_lane'] == consume['lane'] == '0'
        assert packet['source'] == ('FLOW_STACK_RETURN' if returning else 'TUN_CAPTURED')
        assert int(packet['thread']) == (owner + 1 if returning else 1)
        assert packet['direction'] == ('1' if returning else '3') and packet['provenance'] == ('3' if returning else '2')
        raw = wires[token] if returning else captured[token]
        assert raw['_index'] < packet['_index'] and raw['raw'] == packet['raw']
        assert len(bytes.fromhex(packet['raw'])) == int(raw['bytes']) == int(packet['packet_length'])
        if complete['policy_drop'] == '1':
            assert case == 'drop' and not returning and terminal['intent'] == '2'
            assert complete['policy_verdict'] == 'DROP' and complete['transport_outcome'] == 'NOT_ATTEMPTED'
            assert token not in inputs and not select(related, _prefix='s222') and not select(related, _prefix='s223'), 'DROP entered transport/tracker'
            early = one(related, _prefix='s208', event='early_drop')
            assert early['created'] == early['reused'] == early['decision'] == '0'
            decision = one(related, _prefix='s203', event='policy')
            assert decision['verdict'] == '2' and int(decision['rule']) in (24100, 24101)
            dropped.add(token)
        elif terminal['intent'] == '3':
            assert case == 'flow-capacity' and complete['processing_bypass_reason'] == '4'
            assert complete['policy_verdict'] == 'NOT_EVALUATED', 'processing bypass forged ALLOW'
            miss = one(related, _prefix='s208', event='capacity_bypass')
            assert miss['created'] == miss['reused'] == miss['decision'] == '0'
            assert not select(related, _prefix='s222'), 'flow capacity fabricated tracker state'
            bypassed.add(token)
        else:
            assert terminal['intent'] == '1' and complete['policy_verdict'] == 'ALLOW'
        if packet['protocol'] not in ('6', '17'):
            assert not returning and packet['family'] == '6' and packet['protocol'] == '58'
            assert packet['icmp_type'] in ('133', '143') and complete['transport_outcome'] == 'UNSUPPORTED'
            assert token not in inputs
            continue
        facts = (tcp.decode if packet['protocol'] == '6' else udp_decode)(bytes.fromhex(packet['raw']))
        assert all(packet[k] == str(v) for k, v in facts.items() if k != 'payload'), ('raw packet facts', token)
        assignment = oracle.assignment(facts)
        assert assignment['owner'] == owner
        for stage in ('admit', 'policy', 'terminal'):
            witness = one(related, _prefix='s207', stage=stage)
            assert all(str(v) == witness[k] for k, v in assignment.items()), 'canonical owner changed'
        packets[token] = facts
        flow_packets[(facts['family'], facts['dst_port'] if returning else facts['src_port'])].append(packet)
        assert int(packet['uid']) == run['uid'] and int(packet['availability']) & 1
        if returning:
            assert token not in inputs and complete['flow_stack_result'] == '0'
            assert complete['transport_outcome'] == 'TUN_WRITE_SUCCEEDED'
            credit = one(related, _prefix='s239', event='return_credit_released')
            assert complete['_index'] < credit['_index'] < freed['_index']
            assert credit['after_native_free'] == '1' and credit['capacity'] == '128'
            assert int(credit['owner']) == owner and credit['buffer'] == packet['buffer']
        elif token not in dropped:
            copied = inputs[token]
            assert copied['buffer'] == packet['buffer'] and copied['bytes'] == packet['packet_length']
            assert policy['_index'] < copied['_index'] < terminal['_index']
            assert copied['result'] in ('0', '1') and int(complete['flow_stack_result']) == int(copied['result']) + 1
            assert complete['transport_outcome'] == ('ADMITTED' if copied['result'] == '0' else 'INPUT_REJECTED')
            if copied['result'] == '1': rejected.add(token)
    assert inputs.keys() == {t for t in packets if t in captured and t not in dropped}
    assert bool(dropped) == (case == 'drop') and bool(bypassed) == (case == 'flow-capacity')
    assert bool(rejected) == (case in ('session-capacity', 'pcb-capacity', 'packet-credit', 'pbuf-capacity'))

    # Associate dependency transport sessions with independently decoded return
    # tuples. Allocation intervals, not reused addresses, establish ownership.
    sessions, flow_sessions = {}, {}
    broker_rows = [dict(re.findall(r'(\w+)=([^\s]+)', line))
        for line in (folder / 'broker.log').read_text().splitlines() if 's237 broker ' in line]
    broker_rows = select(broker_rows, generation=generation)
    before_stop = (folder / 'before-stop.txt').read_text()
    for owner in (0, 1):
        own = select(events, _prefix='s237', owner=owner)
        accepted_outputs = select(own, event='output', result=0)
        own_copies = [e for e in copies.values() if int(e['thread']) == owner + 1]
        assert len(accepted_outputs) == len(own_copies)
        for copied, output in zip(own_copies, accepted_outputs):
            token = copied['token']; packet = admitted[token]; facts = packets[token]
            assert copied['_index'] < wires[token]['_index'] < output['_index'] < packet['_index'], 'recursive graph execution'
            assert copied['serial'] == wires[token]['serial'] and copied['bytes'] == output['bytes']
            session, flow_key = (owner, output['session']), (facts['family'], facts['dst_port'])
            if output['session'] == '0':
                # lwIP can answer a late ACK with a stateless RST after the
                # failed candidate's PCB was destroyed. It has synchronous
                # input identity only, never a guessed session/broker epoch.
                assert card['protocol'] == 'tcp' and owner == target
                assert case in ('socket-capacity', 'protect', 'bind', 'refusal', 'unreachable')
                assert facts['tcp_flags'] & 4 and not facts['payload']
                prior = flow_sessions[flow_key]
                closing = one(own, event='session_closing', session=prior[1])
                assert closing['_index'] < output['_index']
                assert select(own, event='transport_failure', session=prior[1])
                synchronous = next(e for e in own if e.get('event') == 'input_copy' and e['_index'] > output['_index'])
                incoming = packets[synchronous['token']]
                assert incoming['src'] == facts['dst'] and incoming['dst'] == facts['src']
                assert incoming['src_port'] == facts['dst_port'] and incoming['dst_port'] == facts['src_port']
                assert copied['availability'] == '1' and copied['context'] == copied['epoch'] == '0'
                continue
            assert int(output['session']) > 0
            assert sessions.setdefault(session, flow_key) == flow_key
            assert flow_sessions.setdefault(flow_key, session) == session, 'existing transport replaced'
            replies = select(events, _prefix='s237', event='broker_reply', thread=owner + 1, session=session[1])
            known = bool(replies and replies[0]['_index'] < copied['_index'] and replies[0]['success'] == '1')
            assert int(copied['availability']) == (5 if known else 1)
            assert copied['context'] == ('1' if known else '0')
            assert copied['epoch'] == (replies[0]['epoch'] if known else '0')
        begin, destroyed, stopped = (one(own, event=n) for n in ('quiesce_begin', 'owner_destroyed', 'owner_stopped'))
        reclaimed = one(own, event='pcbs_reclaimed')
        assert begin['_index'] < reclaimed['_index'] < destroyed['_index'] < stopped['_index']
        assert reclaimed['bytes'] == reclaimed['result'] == destroyed['bytes'] == destroyed['kind'] == '0'
        assert all(stopped[k] == '0' for k in ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
        assert stopped['timer_fd'] == stopped['broker_fd'] == '-1'
        assert int(stopped['sockets_created']) == int(stopped['sockets_closed']) == len(select(own, event='socket_created'))
        assert not [e for e in accepted_outputs + own_copies if e['_index'] > begin['_index']]
        assert not [e for e in own if e['_index'] > begin['_index'] and e.get('event') == 'socket_created']
        failure_events = select(own, event='transport_failure')
        assert all(FAULTS[int(e['kind'])] == EXPECTED[case] and owner == target for e in failure_events), 'unexpected transport failure'
        health = one(cli_rows(before_stop, 'flow_stack.health'), owner=owner)
        assert int(health['failures']) == len(failure_events)
        assert health['state'] == ('error' if failure_events else 'ok')
        assert health['reason'] == (EXPECTED[case] if failure_events else 'NONE')
        assert health['retained_for_generation'] == '1'
        assert int(health['last_ms']) >= int(health['first_ms']) >= int(bool(failure_events))
        for kind, name in enumerate(FAULTS[1:], 1):
            count = one(cli_rows(before_stop, 'flow_stack.failure'), owner=owner, reason=name)
            assert int(count['count']) == len(select(failure_events, kind=kind))
        if owner == target: assert bool(failure_events) == (EXPECTED[case] != 'NONE')
        for created in select(own, event='session_created'):
            sid = created['session']
            closing = one(own, event='session_closing', session=sid)
            sockets = select(own, event='socket_created', session=sid)
            replies = select(events, _prefix='s237', event='broker_reply', thread=owner + 1, session=sid)
            attempts = select(own, event='tcp_connect_attempt', session=sid) + select(own, event='udp_connected', session=sid)
            assert created['_index'] < closing['_index'] and len(sockets) <= 1 and len(replies) <= 1
            if sockets:
                socket_created = sockets[0]
                assert socket_created['object'] == closing['object'] and socket_created['result'] == closing['result']
                assert socket_created['_index'] < closing['_index'] and int(socket_created['result']) >= 0
                reply = one(replies)
                java = one(broker_rows, owner=owner, session=sid)
                assert java['error'] == reply['error'] and java['epoch'] == reply['epoch']
                if reply['success'] == '1':
                    assert java['flags'] == '7' and java['error'] == '0'
                    assert all(reply['_index'] < e['_index'] for e in attempts), 'unprotected connect/send'
                    if card['protocol'] == 'tcp':
                        assert len(attempts) == 1, 'missing or repeated native connect'
                        handshake = one(own, event='tcp_handshake', session=sid)
                        assert handshake['_index'] < attempts[0]['_index']
                    else:
                        unreachable = select(own, event='transport_failure', session=sid,
                                             kind=FAULTS.index('NETWORK_UNREACHABLE'))
                        assert len(attempts) == (0 if unreachable else 1)
                else:
                    assert case in ('protect', 'bind') and owner == target and not attempts
                    assert java['diagnostic'] == java['error'] == ('2' if case == 'protect' else '3')
                    assert java['flags'] == ('0' if case == 'protect' else '1')
            else:
                assert case == 'socket-capacity' and owner == target and closing['result'] == '-1' and not attempts and not replies
        for label in ('warm', 'pressure', 'recovered', 'before-stop'):
            text = (folder / (label + '.txt')).read_text()
            assert 'unknown input' not in text and 'unknown command' not in text, 'invalid diagnostic command'
            runtime = one(cli_rows(text, 'flow.runtime'), worker=owner)
            assert int(runtime['capacity']) == card['flow_entries']
            capacity = one(cli_rows(text, 'flow_stack.limits'), owner=owner)
            resources = one(cli_rows(text, 'flow_stack.resources'), owner=owner)
            assert tuple(int(capacity[k]) for k in ('sessions', 'pcbs', 'sockets', 'packets', 'pbufs')) == tuple(map(int, card['limits'].split(',')))
            assert int(resources['pcb_peak']) <= int(capacity['pcbs']) and int(resources['socket_peak']) <= int(capacity['sockets'])
            assert int(resources['pbuf_peak']) <= int(capacity['pbufs'])
            assert int(resources['pcb_allocations']) - int(resources['pcb_frees']) == int(resources['pcbs'])
    if case in ('packet-credit', 'pbuf-capacity'):
        pressure = (folder / 'pressure.txt').read_text()
        resources = one(cli_rows(pressure, 'flow_stack.resources'), owner=target)
        assert int(resources['input_pbufs']) == (1 if case == 'packet-credit' else 8), 'not actual retained-capacity exhaustion'
        assert 'ms=0' in (folder / 'resume.txt').read_text()
    if EXPECTED[case] != 'NONE':
        health = one(cli_rows((folder / 'pressure.txt').read_text(), 'flow_stack.health'), owner=target)
        assert health['state'] == 'error' and health['reason'] == EXPECTED[case] and int(health['failures']) > 0
    if case == 'flow-capacity':
        pressure = (folder / 'pressure.txt').read_text()
        assert int(one(cli_rows(pressure, 'flow.health'), worker=target)['capacity_misses']) > 0
    if card.get('completion_slots', 128) != 128:
        assert card['completion_slots'] == 2 and card['protocol'] == 'udp' and case == 'drop' and target == 1
        deferred = [e for e in select(events, _prefix='s210', event='completion_deferred') if e['token'] in dropped]
        assert deferred and all(e['intent'] == '2' and e['thread'] == '2' for e in deferred), 'no actual retained DROP completion pressure'
        assert len(unique(deferred)) == len(deferred)
        for retained in deferred:
            token = retained['token']
            assert retained['buffer'] == admitted[token]['buffer']
            assert retained['capacity'] == '512' and 0 < int(retained['pending']) <= 512
            transferred = one(by_token[token], _prefix='s205', event='completion_return_accepted')
            retries = select(by_token[token], _prefix='s205', event='completion_return_retry')
            assert retries and retained['_index'] < retries[0]['_index'] < transferred['_index']
            assert all(e['buffer'] == retained['buffer'] and e['thread'] == '2' and e['target_thread'] == '1'
                       for e in retries + [transferred])
        assert 'completion_slots=2' in (folder / 'completion-capacity.txt').read_text()
        assert 'completion_slots=128' in (folder / 'completion-recovery.txt').read_text()
    if case == 'unreachable':
        assert 'unreachable' in (folder / 'unreachable-route.txt').read_text()
        assert not (folder / 'route-restored.txt').read_text().strip(), 'test route was not removed'
    if card['protocol'] == 'udp' and case in ('session-capacity', 'pcb-capacity', 'socket-capacity', 'drop'):
        idle = (folder / 'idle-released.txt').read_text()
        for owner in (0, 1):
            state = one(cli_rows(idle, 'flow_stack.status'), owner=owner)
            assert state['sessions'] == state['inputs'] == state['pbufs'] == '0'
            assert state['sockets_created'] == state['sockets_closed']

    used, echoed = set(), 0
    for probe in card['probes']:
        report = json.loads((folder / (probe['label'] + '.json')).read_text())
        assert not report.get('error') and report['nonce'] == probe['nonce'] and report['uid'] == run['uid']
        assert len(report['flows']) == len(probe['plan'])
        if card['protocol'] == 'tcp': assert report['plan'] == probe['plan']
        for index, (config, outcome) in enumerate(zip(probe['plan'], report['flows'])):
            assert not outcome.get('error') and outcome['source'] == config['source']
            selected = flow_packets[(config['family'], config['source'])]
            assert selected and all(int(p['owner']) == config['owner'] for p in selected)
            for packet in selected:
                facts, returning = packets[packet['token']], packet['source'] == 'FLOW_STACK_RETURN'
                remote, local = ('src', 'dst') if returning else ('dst', 'src')
                assert facts[remote] == ipaddress.ip_address(config['address']).packed.rjust(16, b'\0').hex()
                assert facts[remote + '_port'] == config['port'] and facts[local + '_port'] == config['source']
            if card['protocol'] == 'tcp':
                assert outcome['nonce'] == probe['nonce'] and outcome['index'] == index and outcome['mode'] == config['mode']
                success = config['mode'] != 'failure'
                expected = b''
                for round_index in range(3 if success else 0):
                    prefix = f"{probe['nonce']}_{index}:{round_index}:".encode()
                    expected += prefix + bytes([ord('a') + index]) * (config['bytes'] - len(prefix))
                for returning in (False, True):
                    direction = [packets[e['token']] for e in selected if (e['source'] == 'FLOW_STACK_RETURN') == returning]
                    syns = [p for p in direction if p['tcp_flags'] & 2]
                    assert not success or syns, 'missing real handshake'
                    streams = (expected,) if success else (b'',) if returning else (b'', b'\x2a')
                    assembled = {}
                    start = ((syns[0]['tcp_seq'] + 1) & 0xffffffff) if syns else 0
                    for packet in direction:
                        for position, byte in enumerate(packet['payload'], (packet['tcp_seq'] - start) & 0xffffffff):
                            assert position < max(map(len, streams))
                            assert assembled.setdefault(position, byte) == byte, 'inconsistent retransmission'
                    assert set(assembled) == set(range(len(assembled)))
                    assert bytes(assembled[i] for i in range(len(assembled))) in streams, 'wire/application stream mismatch'
                assert outcome['echoes'] == (3 if success else 0)
                if success:
                    assert outcome['echoBytes'] == len(expected) and outcome['remoteEof'] and outcome['outcome'] == 'echo_closed'
                    matches = [(k, p) for k, p in peers.items() if p['data'] == expected]
                    assert len(matches) == 1, 'actual kernel peer bytes disagree'
                    connection, peer = matches[0]
                    assert connection not in used and peer['sent'] == len(expected)
                    assert int(peer['accept']['family']) == config['family'] and int(peer['accept']['destination_port']) == config['port']
                    used.add(connection); echoed += len(expected)
                else:
                    assert outcome['outcome'] in ('failed_eof', 'failed_error', 'failed_timeout')
            else:
                assert outcome['sent'] == config['packets'] and not outcome['wrong'] and not outcome['duplicates']
                assert len(outcome['outcomes']) == config['packets']
                peer_log = (directory / f"udp{config['family']}-endpoint.log").read_text()
                for packet_index, status in enumerate(outcome['outcomes']):
                    payload = f"{probe['nonce']}_{index}:{packet_index}".encode()
                    matching = [p for p in selected if packets[p['token']]['payload'] == payload]
                    ingress = [p for p in matching if p['source'] == 'TUN_CAPTURED']
                    returning = [p for p in matching if p['source'] == 'FLOW_STACK_RETURN']
                    assert len(ingress) == 1 and len(returning) == int(status == 'echo')
                    receipt = peer_log.count('nonce=' + payload[1:].decode() + ' echo=1\n')
                    assert receipt == int(status == 'echo'), 'kernel UDP peer and app disagree'
                assert outcome['echoes'] == outcome['outcomes'].count('echo')
                if probe['label'] != 'pressure' or config['owner'] != target or case == 'flow-capacity':
                    assert outcome['echoes'] == outcome['sent']
                elif case in ('packet-credit', 'pbuf-capacity'):
                    assert 0 < outcome['echoes'] < outcome['sent']
                else:
                    assert not outcome['echoes']
    tun = one(cli_rows(before_stop, 'tun.status'))
    assert int(tun['captured']) == len(captured) and int(tun['completed']) == len(admitted)
    assert int(tun['policy_drops']) == len(dropped)
    assert all(tun[k] == '0' for k in ('pending', 'frames', 'buffers', 'obligations', 'errors', 'rejected'))
    stop = one(events, _prefix='s213', event='stop')
    assert all(stop[k] == '0' for k in ('pending', 'buffers', 'frames', 'obligations', 'pregraph_returns'))
    assert stop['tun_fd'] == '-1' and int(stop['captured']) == len(captured) and int(stop['completed']) == len(admitted)
    state = common.props((folder / 'stopped.properties').read_text())
    assert state['state'] == 'stopped' and state['mayBeActive'] == 'false' and state['errorCode'] == '' and state['generation'] == generation
    assert 'libvpp_runtime.so' not in (folder / 'processes-after.txt').read_text()
    return dict(label=card['label'], generation=int(generation), captured=len(captured), returns=len(copies),
                bypassed=len(bypassed), policy_drops=len(dropped), input_rejected=len(rejected),
                completion_deferred=len(select(events, _prefix='s210', event='completion_deferred')),
                transport_failures=len(select(events, _prefix='s237', event='transport_failure')), echo_bytes=echoed), used


def verify(build_path, directory):
    build_path, directory = Path(build_path), Path(directory)
    build = common.verify_build(build_path)
    run = json.loads((directory / 'result.json').read_text())
    assert not run.get('error') and not run.get('cleanup_errors')
    assert run['build_sha256'] == tcp.digest(build_path) and run['apk_sha256'] == build['apk_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['finished_ns']
    assert run['serial'] == '28201JEGR0XPAJ' and 'aarch64' in (directory / 'device.txt').read_text()
    assert (directory / 'installed-apk.txt').read_text().split()[0] == build['apk_sha256']
    installed = {Path(l.split()[1]).name: l.split()[0] for l in (directory / 'installed-native.txt').read_text().splitlines()}
    assert installed == build['native_sha256']
    assert run['test_inputs']
    for name, digest in run['test_inputs'].items():
        assert tcp.digest(directory / 'test-source' / name) == digest
    for protocol, digest in run['endpoint_sha256'].items():
        assert tcp.digest(directory / (protocol + '-endpoint')) == digest
    assert tcp.digest(directory / 's241-policy') == run['policy_helper']['sha256']
    assert (directory / 'helper-installed.txt').read_text().split()[0] == run['policy_helper']['sha256']
    peers, used, summaries = endpoint_connections(directory), set(), []
    assert run['runs'] and len({r['generation'] for r in run['runs']}) == len(run['runs'])
    for card in run['runs']:
        summary, connections = verify_case(directory, card, run, peers)
        assert used.isdisjoint(connections)
        used.update(connections); summaries.append(summary)
    assert used == peers.keys(), 'unattributed kernel connection'
    return dict(status='PASS', scope='specified S241 cases only', runs=summaries,
        source_sha256=build['source_sha256'], apk_sha256=build['apk_sha256'], verifier_sha256=tcp.digest(__file__),
        dependency_sha256={n: tcp.digest(ROOT / n) for n in ('tests/device/verify-s240-tcp.py',
            'tests/device/verify-s237.py', 'tests/device/s207-owner-oracle.py')})


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    result = verify(args.build, args.run)
    text = json.dumps(result, indent=2)
    if args.output: args.output.write_text(text + '\n')
    print(text)
