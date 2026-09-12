#!/usr/bin/env python3
"""Verify active-flow lifecycle bytes and ownership without trusting runner PASS.

Normal native drain and abrupt process reclaim remain separate evidence classes.
No underlay-switch or UDP mapping-rebuild claim is made by this verifier.
"""
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


common = module('active_build243', 'tests/device/verify-s237.py')
tcp = module('active_tcp243', 'tests/device/verify-s240-tcp.py')
oracle = module('active_owner243', 'tests/device/s207-owner-oracle.py')


def decode(raw):
    family = raw[0] >> 4
    protocol = raw[9] if family == 4 else raw[6]
    if protocol == 6:
        return tcp.decode(raw)
    assert protocol == 17
    offset = (raw[0] & 15) * 4 if family == 4 else 40
    src, dst = (raw[12:16], raw[16:20]) if family == 4 else (raw[8:24], raw[24:40])
    sport, dport, length, checksum = struct.unpack_from('!HHHH', raw, offset)
    assert offset + length == len(raw) and length >= 8
    if family == 4:
        assert tcp.checksum(raw[:offset]) == 0 and struct.unpack_from('!H', raw, 2)[0] == len(raw)
        pseudo = src + dst + struct.pack('!BBH', 0, 17, length)
    else:
        assert family == 6 and struct.unpack_from('!H', raw, 4)[0] + 40 == len(raw) and checksum
        pseudo = src + dst + struct.pack('!I3xB', length, 17)
    assert not checksum or tcp.checksum(pseudo + raw[offset:]) == 0
    return dict(family=family, protocol=17, l3=1, l4=1, icmp_known=0,
                src=src.rjust(16, b'\0').hex(), dst=dst.rjust(16, b'\0').hex(),
                src_port=sport, dst_port=dport, payload=raw[offset + 8:])


def epoch(directory, filename, generation, probes, run, peers, orderly, underlay=False):
    events = tcp.records((directory / filename).read_text())
    assert events and all(e['generation'] == str(generation) for e in events if 'generation' in e)
    admitted = tcp.unique(tcp.select(events, _prefix='s216', stage='admit'))
    captured = tcp.unique(tcp.select(events, _prefix='s213', event='capture'))
    copies = tcp.unique(tcp.select(events, _prefix='s237', event='return_copy'))
    wires = tcp.unique(tcp.select(events, _prefix='s240', event='return_wire'))
    assert copies and captured and copies.keys().isdisjoint(captured)
    by_token = collections.defaultdict(list)
    for e in events:
        if 'token' in e or 'obligation' in e:
            by_token[e.get('token', e.get('obligation'))].append(e)
    facts_by_flow = collections.defaultdict(lambda: [[], []])
    if orderly:
        assert admitted.keys() == copies.keys() | captured.keys() and copies.keys() == wires.keys()
        for prefix, key, value, token in (
                ('s216', 'stage', 'policy', 'token'), ('s216', 'stage', 'terminal', 'token'),
                ('s204', 'event', 'completion_publish', 'token'), ('s204', 'event', 'completion_consume', 'token'),
                ('s213', 'event', 'completion', 'token'), ('s203', 'event', 'buffer_free', 'obligation')):
            assert tcp.unique(tcp.select(events, _prefix=prefix, **{key: value}), token).keys() == admitted.keys()
    for token, packet in admitted.items():
        related = by_token[token]
        if not orderly and not tcp.select(related, _prefix='s203', event='buffer_free'):
            continue  # Abrupt crash may leave unfinished obligations for OS process reclaim.
        policy = tcp.one(related, _prefix='s216', stage='policy')
        terminal = tcp.one(related, _prefix='s216', stage='terminal')
        complete = tcp.one(related, _prefix='s213', event='completion')
        freed = tcp.one(related, _prefix='s203', event='buffer_free')
        owner = int(packet['owner'])
        assert int(policy['thread']) == int(terminal['thread']) == owner + 1
        assert complete['thread'] == freed['thread'] == '1' and int(complete['producer']) == owner + 1
        assert packet['_index'] < policy['_index'] < terminal['_index'] < complete['_index'] < freed['_index']
        assert all(e['buffer'] == packet['buffer'] for e in (policy, terminal, complete, freed))
        returning = token in copies
        raw = wires[token] if returning else captured[token]
        assert raw['raw'] == packet['raw'] and raw['buffer'] == packet['buffer']
        assert packet['source'] == ('FLOW_STACK_RETURN' if returning else 'TUN_CAPTURED')
        assert packet['direction'] == ('1' if returning else '3') and packet['origin_lane'] == '0'
        assert packet['queue_generation'] == str(generation)
        if packet['protocol'] not in ('6', '17'):
            assert not returning and packet['protocol'] == '58'
            continue
        facts = decode(bytes.fromhex(raw['raw']))
        assert oracle.owner(facts) == owner
        assert all(str(facts[k]) == packet[k] for k in ('family', 'protocol', 'src', 'dst', 'src_port', 'dst_port'))
        assert int(packet['uid']) == run['uid'] and int(packet['availability']) & 1
        dropping = complete['policy_drop'] == '1'
        if dropping:
            assert underlay and not returning and terminal['intent'] == '2'
            assert complete['policy_verdict'] == 'DROP' and complete['transport_outcome'] == 'NOT_ATTEMPTED'
            assert not tcp.select(related, _prefix='s237', event='input_copy')
            assert not tcp.select(related, _prefix='s223')
            assert tcp.one(related, _prefix='s208', event='early_drop')['created'] == '0'
        else:
            assert terminal['intent'] == '1' and complete['policy_drop'] == '0'
        if returning:
            assert complete['transport_outcome'] == 'TUN_WRITE_SUCCEEDED'
            credit = tcp.one(related, _prefix='s239', event='return_credit_released')
            assert complete['_index'] < credit['_index'] < freed['_index']
            assert int(credit['owner']) == owner and credit['after_native_free'] == '1'
        elif not dropping:
            copied = tcp.one(related, _prefix='s237', event='input_copy')
            assert copied['owner'] == packet['owner'] and copied['tls'] == copied['thread']
            assert copied['result'] == '0' and complete['transport_outcome'] == 'ADMITTED'
        identity = (facts['protocol'], facts['family'], facts['dst_port'] if returning else facts['src_port'])
        facts_by_flow[identity][int(returning)].append(facts)
    coverage, expected_identities = set(), set()
    for probe in probes:
        report = json.loads((directory / (probe['label'] + '-result.json')).read_text())
        assert report['nonce'] == probe['nonce'] and not report.get('error') and len(report['flows']) == 4
        for index, (config, outcome) in enumerate(zip(probe['plan'], report['flows'])):
            identity = (probe['protocol'], config['family'], config['source'])
            expected_identities.add(identity)
            directions = facts_by_flow[identity]
            assert all(directions) and not outcome.get('error') and outcome['source'] == config['source']
            rounds = 2 if config.get('underlaySequence') else (
                1 if config.get('mode') == 'hold' or config.get('holdAfterFirst') else 3)
            assert outcome['echoes'] == rounds
            coverage.add((probe['protocol'], config['family'], config['owner']))
            local = ipaddress.ip_address('10.111.0.2' if config['family'] == 4 else 'fd00:111:111::2').packed.rjust(16, b'\0').hex()
            remote = ipaddress.ip_address(config['address']).packed.rjust(16, b'\0').hex()
            for returning, selected in enumerate(directions):
                assert all(oracle.owner(p) == config['owner'] for p in selected)
                assert all((p['src'], p['dst']) == ((remote, local) if returning else (local, remote)) for p in selected)
                assert all(p['src_port' if returning else 'dst_port'] == config['port'] for p in selected)
            if probe['protocol'] == 6:
                expected = b''.join((prefix := f"{probe['nonce']}_{index}:{r}:".encode())
                                   + bytes([ord('a') + index]) * (config['bytes'] - len(prefix)) for r in range(rounds))
                for selected in directions:
                    syn = next(p for p in selected if p['tcp_flags'] & 2)
                    base, stream = (syn['tcp_seq'] + 1) & 0xffffffff, {}
                    for packet in selected:
                        for position, byte in enumerate(packet['payload'], (packet['tcp_seq'] - base) & 0xffffffff):
                            assert position < len(expected) and stream.setdefault(position, byte) == byte
                    assert set(stream) == set(range(len(expected)))
                    assert bytes(stream[i] for i in range(len(expected))) == expected
                matches = [p for p in peers.values() if p['data'] == expected]
                assert len(matches) == 1 and matches[0]['sent'] == len(expected) and matches[0]['closed']
                assert int(matches[0]['accept']['family']) == config['family']
                assert int(matches[0]['accept']['destination_port']) == config['port']
            else:
                sequence = config.get('underlaySequence')
                drop_sequence = config.get('underlayDrop')
                assert not sequence or underlay
                sent = [f"{probe['nonce']}_{index}:{r}".encode() for r in range(4 if drop_sequence else 3 if sequence else rounds)]
                expected = [sent[0], sent[-1]] if sequence else sent
                assert [p['payload'] for p in directions[0]] == sent
                assert [p['payload'] for p in directions[1]] == expected
                if sequence:
                    assert outcome['outcomes'] == (['echo', 'timeout', 'timeout', 'echo'] if drop_sequence else ['echo', 'timeout', 'echo'])
                    assert outcome['sent'] == len(sent)
                peer = (directory / ('udp-endpoint-' + str(config['family']) + '.log')).read_text()
                assert all(peer.count('nonce=' + data[1:].decode() + ' echo=1\n') == 1 for data in expected)
                if sequence:
                    assert all('nonce=' + data[1:].decode() + ' echo=1\n' not in peer for data in sent[1:-1])
    assert set(facts_by_flow) == expected_identities
    assert coverage == {(p, f, o) for p in (6, 17) for f in (4, 6) for o in (0, 1)}
    bound_flows = {}
    for owner in (0, 1):
        own_copies = [c for c in copies.values() if int(c['thread']) == owner + 1]
        outputs = tcp.select(events, _prefix='s237', event='output', owner=owner, result=0)
        assert len(outputs) == len(own_copies)
        for copy, output in zip(own_copies, outputs):
            facts = decode(bytes.fromhex(wires[copy['token']]['raw']))
            identity = (facts['protocol'], facts['family'], facts['dst_port'])
            session = (owner, output['session'])
            assert bound_flows.setdefault(session, identity) == identity
            reply = tcp.one(events, _prefix='s237', event='broker_reply', thread=owner + 1, session=output['session'])
            assert reply['success'] == '1' and reply['error'] == '0' and int(reply['epoch']) > 0
            known = reply['_index'] < copy['_index']
            assert copy['epoch'] == (reply['epoch'] if known else '0')
            assert copy['_index'] < output['_index'] < admitted[copy['token']]['_index']
    assert len(bound_flows) == (20 if underlay else 8) and set(bound_flows.values()) == expected_identities
    if orderly:
        buffers, pbufs = {}, {}
        for e in events:
            if (e['_prefix'], e.get('event')) in (('s213', 'capture'), ('s237', 'return_copy')):
                assert e['buffer'] not in buffers
                buffers[e['buffer']] = e['token']
            if e['_prefix'] == 's203' and e.get('event') == 'buffer_free':
                assert buffers.pop(e['buffer']) == e['obligation']
            if e['_prefix'] == 's237' and e.get('event') in ('pbuf_alloc', 'pbuf_free'):
                assert int(e['thread']) == int(e['owner']) + 1 and e['tls'] == e['thread']
                key = (e['owner'], e['object'])
                if e['event'] == 'pbuf_alloc':
                    assert key not in pbufs
                    pbufs[key] = e['kind']
                else:
                    assert pbufs.pop(key) == e['kind']
        assert not buffers and not pbufs
        stop = tcp.one(events, _prefix='s213', event='stop')
        assert stop['tun_fd'] == '-1'
        assert all(stop[k] == '0' for k in ('pending', 'buffers', 'frames', 'obligations', 'pregraph_returns'))
        assert int(stop['captured']) == len(captured) and int(stop['completed']) == len(admitted)
        for owner in (0, 1):
            end = tcp.one(events, _prefix='s237', event='owner_stopped', owner=owner)
            assert all(end[k] == '0' for k in ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
            assert end['sockets_created'] == end['sockets_closed'] == ('12' if underlay else '4')
            assert end['timer_fd'] == end['broker_fd'] == '-1'
            destroyed = tcp.one(events, _prefix='s237', event='owner_destroyed', owner=owner)
            assert destroyed['_index'] < end['_index'] < stop['_index']
    return dict(generation=generation, orderly_native_drain=orderly, test_flows=len(expected_identities),
                captured=len(captured), returned=len(copies))


def verify(build_path, directory):
    build = common.verify_build(build_path)
    run = json.loads((directory / 'result.json').read_text())
    assert run['scope'] == 'real-Pixel-W2-active-TCP-UDP-lifecycle'
    assert not any(run.get(k) for k in ('error', 'cleanup_errors', 'product_source_changed', 'test_source_changed', 'endpoint_forced_stop'))
    assert run['build_sha256'] == common.digest(build_path) and run['apk_sha256'] == build['apk_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert run['serial'] == '28201JEGR0XPAJ' and 'aarch64' in (directory / 'device.txt').read_text()
    assert (directory / 'installed-apk.txt').read_text().split()[0] == build['apk_sha256']
    installed = {Path(line.split()[1]).name: line.split()[0]
                 for line in (directory / 'installed-native.txt').read_text().splitlines()}
    assert installed == build['native_sha256'] and run['test_inputs']
    for name, digest in run['test_inputs'].items():
        assert common.digest(directory / 'test-source' / name) == digest
    for name, digest in run['endpoints'].items():
        assert common.digest(directory / name) == digest
    peers = {}
    for event in tcp.records((directory / 'tcp-endpoint-4.log').read_text()):
        if event['event'] == 'accept':
            assert event['connection'] not in peers
            peers[event['connection']] = dict(accept=event, data=b'', sent=0, closed=False)
        elif event['event'] == 'read':
            peer = peers[event['connection']]
            assert int(event['offset']) == len(peer['data']) and not peer['closed']
            data = bytes.fromhex(event['raw'])
            assert len(data) == int(event['bytes'])
            peer['data'] += data
        elif event['event'] == 'write':
            peer = peers[event['connection']]
            assert int(event['offset']) == peer['sent'] and not peer['closed']
            peer['sent'] += int(event['bytes'])
        elif event['event'] == 'close':
            peer = peers[event['connection']]
            assert not peer['closed'] and event['reason'] != 'stop', 'transport only closed when peer fixture stopped'
            assert int(event['received']) == len(peer['data']) and int(event['sent']) == peer['sent']
            peer['closed'] = True
    assert peers and all(p['closed'] for p in peers.values())
    assert 'event=stopped live_sockets=0' in (directory / 'tcp-endpoint-4.log').read_text()
    reports = []
    for record in run['runs']:
        case = record['case']
        checkpoint = directory / case / 'recovery-service.log'
        service = (checkpoint if checkpoint.exists() else directory / 'service.log').read_text()
        assert case in ('stop', 'crash', 'broker0', 'broker1')
        generation, replacement = record['generation'], record['replacement_generation']
        assert replacement == generation + 1
        initial_state = common.props((directory / case / 'initial.properties').read_text())
        replacement_state = common.props((directory / case / 'replacement.properties').read_text())
        for value, expected in [(initial_state, generation), (replacement_state, replacement)]:
            assert value['generation'] == str(expected) and value['state'] == 'running' and value['mayBeActive'] == 'true'
            assert value['protectionRunning'] == 'false' and not value['errorCode']
        held = [p for p in record['probes'] if '/held-' in p['label']]
        fresh = [p for p in record['probes'] if '/fresh-' in p['label']]
        assert len(held) == len(fresh) == 2 and len(record['probes']) == 4
        for probe in held:
            phases = json.loads((directory / (probe['label'] + '-holding.json')).read_text())
            assert len(phases) == 4 and all(p['phase'] == 'holding' and p['echoes'] == 1 for p in phases)
        active = [common.fields(line) for line in (directory / case / 'active.txt').read_text().splitlines()
                  if line.startswith('flow_stack.status ')]
        assert len(active) == 2 and {a['owner'] for a in active} == {'0', '1'}
        assert all(a['sessions'] == '4' and a['generation'] == str(generation) for a in active)
        old_file = case + ('/old-native-stop.log' if case == 'stop' else '/old-native-failure.log')
        old = epoch(directory, old_file, generation, held, run, peers, case != 'crash')
        new = epoch(directory, case + '/replacement-native-stop.log', replacement, fresh, run, peers, True)
        close_log = (directory / case / 'service.log').read_text().splitlines()
        for closed_generation in ([generation] if case != 'crash' else []) + [replacement]:
            indexes = [i for i, line in enumerate(close_log) if
                       f's243 network_subscription_closed generation={closed_generation} native_tun_drain=true' in line]
            assert len(indexes) == 1, 'platform closure lacks successful native drain'
            starts = [i for i, line in enumerate(close_log[:indexes[0]]) if
                      f'product_core=running generation={closed_generation} ' in line]
            assert len(starts) == 1, 'missing generation-scoped lifecycle start'
            prior_drains = [line for line in close_log[starts[0]:indexes[0]] if 's213 native_tun_drain=' in line]
            assert len(prior_drains) == 1 and prior_drains[0].endswith('native_tun_drain=true'), 'network facts cleared before drain'
        if case != 'stop':
            assert len(re.findall(r's243 recovery=starting old_generation=' + str(generation) + r'\b', service)) == 1
        if case.startswith('broker'):
            assert 's243 broker_fault=channel_close owner=' + case[-1] + ' generation=' + str(generation) in service
        if case == 'crash':
            assert not tcp.select(tcp.records((directory / old_file).read_text()), _prefix='s237', event='owner_stopped')
            assert re.search(r'os_reclaim_after_exit .*generation=' + str(generation) + r' native_drain_claimed=0', service)
            assert str(record['crashed_pid']) in (directory / case / 'process-before.txt').read_text()
        for stem, gen in [('replacement', replacement)] + ([('old', generation)] if case == 'stop' else []):
            state = common.props((directory / case / (stem + '-stopped.properties')).read_text())
            assert state['generation'] == str(gen) and state['state'] == 'stopped' and state['mayBeActive'] == 'false'
            assert not state['errorCode'] and 'libvpp_runtime.so' not in (directory / case / (stem + '-process-after.txt')).read_text()
        reports.append(dict(case=case, old=old, replacement=new))
    assert reports and len({r['case'] for r in reports}) == len(reports)
    assert len(peers) == len(reports) * 8
    return dict(status='PASS', scope='active-lifecycle-only-no-underlay-claim', runs=reports)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.build, args.run), indent=2))
