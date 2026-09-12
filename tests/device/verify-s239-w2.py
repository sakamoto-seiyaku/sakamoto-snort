#!/usr/bin/env python3
"""Independently join real app payloads, canonical graph and native lifetimes."""
import argparse
import collections
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def fields(line):
    return dict(re.findall(r'(\w+)=([^\s]+)', line))


def rows(text, prefix):
    return [fields(line) for line in text.splitlines() if line.startswith(prefix)]


def verify(build_path, directory):
    base = module('s237', 'tests/device/verify-s237.py')
    oracle = module('oracle', 'tests/device/s207-owner-oracle.py')
    build = base.verify_build(build_path)
    run = json.loads((directory / 'result.json').read_text())
    assert not run.get('error') and not run.get('cleanup_error')
    assert run['build_sha256'] == base.digest(build_path)
    assert run['apk_sha256'] == build['apk_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['finished_ns']
    assert run['serial'] == '28201JEGR0XPAJ'
    assert (directory / 'installed-apk.txt').read_text().split()[0] == build['apk_sha256']
    installed = {Path(line.split()[1]).name: line.split()[0]
                 for line in (directory / 'installed-native.txt').read_text().splitlines()}
    assert installed == build['native_sha256']
    for name, digest in run['test_inputs'].items():
        assert base.digest(directory / 'test-source' / name) == digest
    assert base.digest(directory / 'udp-endpoint') == run['endpoint_sha256']
    generation = str(run['generation'])
    trace = (directory / 'native-stop.log').read_text()
    events = []
    for index, line in enumerate(trace.splitlines()):
        if line.startswith(('s203 ', 's204 ', 's205 ', 's210 ', 's213 ', 's216 ', 's237 ', 's239 ')):
            event = fields(line)
            event['_index'], event['_prefix'] = index, line.split()[0]
            events.append(event)
            if 'generation' in event:
                assert event['generation'] == generation, 'cross-generation event'
    assert events
    native = collections.defaultdict(list)
    live_pbufs, sessions, callbacks = {}, {}, collections.Counter()
    for event in events:
        token = event.get('token', event.get('obligation'))
        if token:
            native[token].append(event)
        if event['_prefix'] != 's237':
            continue
        if 'owner' in event and 'thread' in event:
            assert int(event['thread']) == int(event['owner']) + 1, event
            if 'tls' in event:
                assert event['thread'] == event['tls'], event
                callbacks[int(event['owner'])] += 1
        if event.get('event') == 'pbuf_alloc':
            assert event['object'] not in live_pbufs
            live_pbufs[event['object']] = (event['owner'], event['kind'])
        elif event.get('event') == 'pbuf_free':
            assert live_pbufs.pop(event['object']) == (event['owner'], event['kind'])
        elif event.get('event') == 'socket_created':
            key = (event['owner'], event['session'])
            assert key not in sessions
            sessions[key] = event['object']
        elif event.get('event') == 'session_closing':
            assert sessions[(event['owner'], event['session'])] == event['object']
    assert not live_pbufs and all(callbacks[o] > 0 for o in (0, 1))
    # Include kernel-generated ICMP control traffic, not just the UDP oracle.
    for token, related in native.items():
        admitted = [e for e in related if e['_prefix'] == 's216' and e.get('stage') == 'admit']
        if not admitted:
            continue
        assert len(admitted) == 1, 'duplicate admission'
        completed = [e for e in related if e.get('event') == 'completion_consume']
        freed = [e for e in related if e.get('event') == 'buffer_free']
        assert len(completed) == len(freed) == 1, 'exactly-once native settlement'
        assert completed[0]['buffer'] == freed[0]['buffer'] == admitted[0]['buffer']
    stopped = [e for e in events if e.get('event') == 'owner_stopped']
    assert len(stopped) == 2 and {e['owner'] for e in stopped} == {'0', '1'}
    for event in stopped:
        assert all(event[k] == '0' for k in ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
        assert event['sockets_created'] == event['sockets_closed'] == '2'
        assert event['timer_fd'] == event['broker_fd'] == '-1'
    assert len(sessions) == 4, 'unexpected socket replacement or cross-owner session key'
    assert len([e for e in events if e.get('event') == 'owner_destroyed'
                and e.get('bytes') == e.get('kind') == '0']) == 2
    assert 'libvpp_runtime.so' not in (directory / 'processes-after.txt').read_text()
    assert base.props((directory / 'stopped.properties').read_text())['mayBeActive'] == 'false'

    wanted, app_echoes = {}, set()
    for probe in run['probes']:
        report = json.loads((directory / (probe['name'] + '.json')).read_text())
        assert report['nonce'] == probe['nonce'] and report['uid'] == run['uid']
        assert len(report['flows']) == len(probe['plan'])
        for index, (config, flow) in enumerate(zip(probe['plan'], report['flows'])):
            assert 'error' not in flow and flow['sent'] == config['packets']
            assert flow['source'] == config['source'] and flow['wrong'] == flow['duplicates'] == 0
            assert len(flow['outcomes']) == flow['sent']
            assert flow['echoes'] == flow['outcomes'].count('echo')
            for packet, outcome in enumerate(flow['outcomes']):
                payload = probe['nonce'] + '_' + str(index) + ':' + str(packet)
                wanted[payload] = config
                if outcome == 'echo':
                    app_echoes.add(payload)
                else:
                    assert outcome == 'timeout' and probe['name'] == 'quota' and index == 0
    packets = [e for e in events if e.get('stage') == 'admit' and e['_prefix'] == 's216'
               and e.get('protocol') == '17']
    seen = collections.defaultdict(set)
    primary_drops, returns = 0, 0
    for packet in packets:
        raw = bytes.fromhex(packet['raw'])
        payload = raw[int(packet['transport_offset']) + 8:].decode('ascii')
        assert payload in wanted, 'unregistered UDP payload'
        config = wanted[payload]
        facts = {k: int(v) if k not in ('src', 'dst') else v for k, v in packet.items()
                 if k in ('l3', 'l4', 'family', 'protocol', 'src', 'dst', 'src_port', 'dst_port', 'icmp_known')}
        owner = oracle.owner(facts)
        assert owner == config['owner'] == int(packet['owner'])
        assert int(packet['family']) == config['family']
        assert {int(packet['src_port']), int(packet['dst_port'])} == {config['source'], config['port']}
        source = packet['source']
        assert payload not in seen[source], 'duplicate native packet'
        seen[source].add(payload)
        related = native[packet['token']]

        def single(key, value, optional=False, prefix=None):
            selected = [e for e in related if e.get(key) == value
                        and (prefix is None or e['_prefix'] == prefix)]
            assert len(selected) == 1 or (optional and not selected), (packet['token'], key, value, selected)
            return selected[0] if selected else None

        policy = single('stage', 'policy', optional=True, prefix='s216')
        terminal = single('stage', 'terminal', prefix='s216')
        completion = single('event', 'completion_consume')
        outcome = single('event', 'completion', prefix='s213')
        freed = single('event', 'buffer_free')
        assert all(e['buffer'] == packet['buffer'] for e in (terminal, completion, freed))
        assert completion['thread'] == freed['thread'] == '1'
        assert packet['_index'] < terminal['_index'] < completion['_index'] < freed['_index']
        if policy:
            assert policy['buffer'] == packet['buffer']
            assert int(policy['thread']) == int(terminal['thread']) == owner + 1
        else:
            assert source == 'TUN_CAPTURED' and outcome['drop_reason'] == '5'
            primary_drops += 1
        if source == 'FLOW_STACK_RETURN':
            returns += 1
            copied = single('event', 'return_copy')
            credit = single('event', 'return_credit_released')
            assert int(copied['thread']) == owner + 1 and copied['thread'] == copied['tls']
            assert copied['buffer'] == credit['buffer'] == packet['buffer']
            assert int(packet['token']) >> 62 == owner + 2
            # The credit trace is emitted after native free, before the shared
            # post-free bookkeeping trace; do not confuse log order with free.
            assert copied['_index'] < packet['_index']
            assert completion['_index'] < credit['_index'] < freed['_index']
            assert credit['owner'] == str(owner) and credit['capacity'] == '128'
            assert credit['after_native_free'] == '1'
            assert outcome['transport_outcome'] == 'TUN_WRITE_SUCCEEDED'
        elif policy:
            copied = single('event', 'input_copy')
            assert copied['buffer'] == packet['buffer'] and int(copied['owner']) == owner
            assert copied['thread'] == copied['tls'] == str(owner + 1)
            assert copied['_index'] < completion['_index']
    assert seen['TUN_CAPTURED'] == set(wanted), 'incomplete original packet trace'
    assert seen['FLOW_STACK_RETURN'] == app_echoes, 'return/app conservation'
    endpoint_payloads = set()
    for family in (4, 6):
        for event in rows((directory / f'endpoint{family}.log').read_text(), 'received '):
            payload = 'E' + event['nonce']
            assert payload in wanted and wanted[payload]['family'] == family
            assert event['echo'] == '1' and payload not in endpoint_payloads
            endpoint_payloads.add(payload)
    assert app_echoes <= endpoint_payloads <= set(wanted)
    if run['case'] == 'doze':
        assert not run.get('power_cleanup_error')
        assert not primary_drops and seen['FLOW_STACK_RETURN'] == set(wanted)
        assert (directory / 'idle-confirmed.txt').read_text().strip() == 'IDLE'
        assert (directory / 'idle-end.txt').read_text().strip() == 'IDLE'
        assert 'mDeviceIdleMode=true' in (directory / 'power-idle.txt').read_text()
        assert 'mDeviceIdleMode=false' in (directory / 'power-restored.txt').read_text()
        assert 'mWakefulness=Awake' in (directory / 'power-restored.txt').read_text()
    elif run['case'] == 'notify':
        assert not primary_drops and seen['FLOW_STACK_RETURN'] == set(wanted)
        assert run.get('notification_trace'), 'missing native notification trace'
    elif run['case'] == 'concurrent':
        assert not primary_drops and seen['FLOW_STACK_RETURN'] == set(wanted)
        probe = json.loads((directory / 'concurrent.json').read_text())['flows']
        assert max(f['startMs'] for f in probe) - min(f['startMs'] for f in probe) < 1000
        assert all(f['lastEchoMs'] > probe[0]['endMs'] + 60000 for f in probe[1:])
        during = rows((directory / 'during.txt').read_text(), 'flow_stack.status ')
        after = rows((directory / 'after.txt').read_text(), 'flow_stack.status ')
        assert all(e['sessions'] == '2' for e in during) and len(during) == 2
        assert {e['owner']: e['sessions'] for e in after} == {'0': '1', '1': '2'}
        assert {e['owner']: e['sockets_closed'] for e in after} == {'0': '1', '1': '0'}
    else:
        selected = int(run['case'][-1])
        held = {int(e['owner']): e for e in rows((directory / 'held.txt').read_text(), 'tun.return ')}
        assert held[selected]['capacity'] == held[selected]['in_use'] == '128'
        assert held[1-selected]['in_use'] == '0'
        stacks = {int(e['owner']): e for e in rows((directory / 'held.txt').read_text(), 'flow_stack.status ')}
        assert int(stacks[selected]['output_rejected']) > 0
        assert int(stacks[1-selected]['sent']) == int(stacks[1-selected]['outputs']) == 26
        if run['case'].startswith('quota'):
            probe = json.loads((directory / 'quota.json').read_text())['flows']
            assert probe[0]['echoes'] == 128 and probe[1]['echoes'] == 20
            assert probe[1]['endMs'] < probe[0]['lastEchoMs']
        else:
            after = {int(e['owner']): e for e in rows((directory / 'after.txt').read_text(), 'tun.return ')}
            assert after[selected]['in_use'] == '128', 'hold expired before stop request'
            quiesce = [e for e in events if e.get('event') == 'quiesce_begin' and int(e['owner']) == selected]
            assert len(quiesce) == 1
            released = [e for e in events if e.get('event') == 'return_credit_released'
                        and int(e['owner']) == selected and e['_index'] > quiesce[0]['_index']]
            assert len(released) == 128, 'held returns not settled by actual stop drain'
            assert released[-1]['in_use'] == '0'
    return dict(status='PASS', scope='w2-udp-ownership-credit-lifecycle-not-performance',
                case=run['case'], generation=run['generation'], originals=len(wanted), returns=returns,
                primary_handoff_drops=primary_drops, endpoint_received=len(endpoint_payloads),
                apk_sha256=build['apk_sha256'], verifier_sha256=base.digest(__file__))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.build, args.run), indent=2))
