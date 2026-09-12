#!/usr/bin/env python3
"""Independent real-Pixel underlay/UDP replacement acceptance; no mobile claim."""
import argparse
import json
from pathlib import Path
import re
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('underlay_active243', ROOT / 'tests/device/verify-s243-active.py')
active = importlib.util.module_from_spec(spec)
spec.loader.exec_module(active)
common, tcp = active.common, active.tcp


def verify(build_path, directory):
    build = common.verify_build(build_path)
    run = json.loads((directory / 'result.json').read_text())
    assert run['scope'] == 'real-Pixel-W2-active-TCP-UDP-lifecycle'
    assert not any(run.get(k) for k in ('error', 'cleanup_errors', 'product_source_changed', 'test_source_changed', 'endpoint_forced_stop'))
    assert run['build_sha256'] == common.digest(build_path) and run['apk_sha256'] == build['apk_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert run['serial'] == '28201JEGR0XPAJ' and 'aarch64' in (directory / 'device.txt').read_text()
    assert (directory / 'installed-apk.txt').read_text().split()[0] == build['apk_sha256']
    assert {Path(line.split()[1]).name: line.split()[0]
            for line in (directory / 'installed-native.txt').read_text().splitlines()} == build['native_sha256']
    for name, digest in run['test_inputs'].items():
        assert common.digest(directory / 'test-source' / name) == digest
    for name, digest in run['endpoints'].items():
        assert common.digest(directory / name) == digest
    assert len(run['runs']) == 1
    record = run['runs'][0]
    assert record['case'] == 'underlay' and record['sim_state'] == 'ABSENT' and record['wifi_before'] == '1'
    generation = record['generation']
    assert record['replacement_generation'] == generation
    probes = record['probes']
    assert len(probes) == 4
    underlay_drop = any(c.get('underlayDrop') for p in probes for c in p['plan'])
    if underlay_drop:
        assert [p['drop'] for p in record['policies']] == [True, False]
        assert common.digest(directory / 's243-policy') == run['policy_helper']['sha256']
        assert (directory / 'helper-installed.txt').read_text().split()[0] == run['policy_helper']['sha256']
        assert all('policy rc=0' in (directory / ('underlay/policy-' + name + '.txt')).read_text()
                   for name in ('drop', 'clear'))
    for name in ('initial.properties', 'after-replacement.properties'):
        state = common.props((directory / 'underlay' / name).read_text())
        assert state['generation'] == str(generation) and state['state'] == 'running' and state['mayBeActive'] == 'true'
        assert state['protectionRunning'] == 'false' and not state['errorCode']
    peers = {}
    for e in tcp.records((directory / 'tcp-endpoint-4.log').read_text()):
        if e['event'] == 'accept':
            assert e['connection'] not in peers
            peers[e['connection']] = dict(accept=e, data=b'', sent=0, closed=False)
        elif e['event'] == 'read':
            peer = peers[e['connection']]
            assert int(e['offset']) == len(peer['data']) and not peer['closed']
            data = bytes.fromhex(e['raw'])
            assert len(data) == int(e['bytes'])
            peer['data'] += data
        elif e['event'] == 'write':
            peer = peers[e['connection']]
            assert int(e['offset']) == peer['sent'] and not peer['closed']
            peer['sent'] += int(e['bytes'])
        elif e['event'] == 'close':
            peer = peers[e['connection']]
            assert not peer['closed'] and int(e['received']) == len(peer['data']) and int(e['sent']) == peer['sent']
            peer.update(closed=True, close_reason=e['reason'])
    assert len(peers) == 8 and all(p['closed'] for p in peers.values())
    # A down Wi-Fi link need not deliver a final RST to the remote peer. Fresh
    # connections on the new network must nevertheless finish normally.
    fresh_tcp = next(p for p in probes if '/fresh-tcp' in p['label'])
    assert all(p['close_reason'] != 'stop' for p in peers.values()
               if p['data'].startswith(fresh_tcp['nonce'].encode()))
    path = 'underlay/replacement-native-stop.log'
    summary = active.epoch(directory, path, generation, probes, run, peers, True, underlay=True)
    events = tcp.records((directory / path).read_text())
    copies = tcp.unique(tcp.select(events, _prefix='s237', event='return_copy'))
    wires = tcp.unique(tcp.select(events, _prefix='s240', event='return_wire'))
    original = tcp.unique(tcp.select(events, _prefix='s213', event='capture'))
    inv = tcp.select(events, _prefix='s243', event='underlay_invalidation')
    assert len(inv) == 2 and {e['owner'] for e in inv} == {'0', '1'}
    assert all(e['epoch'] == '1' and e['result'] == '0' and int(e['thread']) == int(e['owner']) + 1
               and e['tls'] == e['thread'] for e in inv)
    for owner in (0, 1):
        own = tcp.select(events, _prefix='s237', owner=owner)
        retired = tcp.select(own, event='session_closing', session='1') + tcp.select(own, event='session_closing', session='2')
        assert len(retired) == 2
        for session in ('1', '2', '3', '4'):
            close = tcp.one(own, event='session_closing', session=session)
            causes = tcp.select(own, event='underlay_invalidated', session=session)
            if session in ('3', '4'):
                assert len(causes) == 1 and causes[0]['_index'] < close['_index']
            else:
                causes += tcp.select(own, event='transport_failure', session=session)
                assert causes and min(e['_index'] for e in causes) < close['_index']
                assert tcp.one(own, event='tcp_pcb_destroyed', session=session)['_index'] > close['_index']
            later = tcp.one(own, event='session_created', session='7')
            assert close['_index'] < later['_index']
        unavailable = tcp.select(events, _prefix='s237', event='broker_reply', thread=owner + 1, error=5)
        assert len(unavailable) == 2 and {e['session'] for e in unavailable} == {'5', '6'}
        assert all(e['success'] == '0' and e['epoch'] == '0' and e['result'] == '0' for e in unavailable)
        assert not any(e.get('session') in ('5', '6') for e in tcp.select(own, event='udp_connected'))
        later = tcp.select(events, _prefix='s237', event='broker_reply', thread=owner + 1, epoch=2)
        assert len(later) == 6 and all(e['success'] == '1' and e['result'] == '0' for e in later)
        own_copies = [e for e in copies.values() if int(e['thread']) == owner + 1]
        own_outputs = tcp.select(own, event='output', result=0)
        assert len(own_copies) == len(own_outputs)
        session_by_payload = {}
        for copy, output in zip(own_copies, own_outputs):
            packet = active.decode(bytes.fromhex(wires[copy['token']]['raw']))
            if packet['protocol'] == 17:
                session_by_payload[packet['payload']] = (output['session'], copy['epoch'])
        probe = next(p for p in probes if '/held-udp' in p['label'])
        for index, config in enumerate(probe['plan']):
            if config['owner'] != owner:
                continue
            prefix = f"{probe['nonce']}_{index}:".encode()
            first, fresh = session_by_payload[prefix + b'0'], session_by_payload[prefix + (b'3' if underlay_drop else b'2')]
            assert first[0] != fresh[0] and first[1] == '1' and fresh[1] == '2'
            # VPP's UDP FlowEntry remains the same incarnation across all
            # three application datagrams; no network-driven FlowEnd/recreate.
            updates = []
            for token, capture in original.items():
                raw = bytes.fromhex(capture['raw'])
                if (raw[9] if raw[0] >> 4 == 4 else raw[6]) != 17:
                    continue
                packet = active.decode(raw)
                if packet['payload'].startswith(prefix):
                    if underlay_drop and packet['payload'] == prefix + b'2':
                        completion = tcp.one(events, _prefix='s213', event='completion', token=token)
                        assert completion['policy_drop'] == '1' and completion['transport_outcome'] == 'NOT_ATTEMPTED'
                    else:
                        updates.append(tcp.one(events, _prefix='s223', event='udp_update', token=token))
            assert len(updates) == 3 and updates[0]['created'] == '1'
            assert all(u['incarnation'] == updates[0]['incarnation'] and u['slot'] == updates[0]['slot']
                       and u['replacement'] == u['close'] == '0' for u in updates)
            assert all(u['created'] == '0' for u in updates[1:])
    for stem, sessions in [('active', '4'), ('lost', '0')]:
        states = [common.fields(line) for line in (directory / 'underlay' / (stem + '.txt')).read_text().splitlines()
                  if line.startswith('flow_stack.status ')]
        assert len(states) == 2 and all(v['generation'] == str(generation) and v['sessions'] == sessions for v in states)
    before = (directory / 'underlay/networks-before.txt').read_text()
    lost = (directory / 'underlay/networks-lost.txt').read_text()
    restored = (directory / 'underlay/networks-restored.txt').read_text()
    wifi = r'NetworkAgentInfo\{network\{(\d+)\}.*?ni\{WIFI CONNECTED'
    first, fresh = re.findall(wifi, before), re.findall(wifi, restored)
    assert len(first) == len(fresh) == 1 and first != fresh and not re.findall(wifi, lost)
    assert 'CELLULAR CONNECTED' not in lost
    stopped = common.props((directory / 'underlay/replacement-stopped.properties').read_text())
    assert stopped['generation'] == str(generation) and stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false'
    assert not stopped['errorCode'] and 'libvpp_runtime.so' not in (directory / 'underlay/replacement-process-after.txt').read_text()
    service = (directory / 'underlay/service.log').read_text().splitlines()
    starts = [i for i, line in enumerate(service) if f'product_core=running generation={generation} ' in line]
    closes = [i for i, line in enumerate(service) if f's243 network_subscription_closed generation={generation} native_tun_drain=true' in line]
    assert len(starts) == len(closes) == 1
    drains = [line for line in service[starts[0]:closes[0]] if 's213 native_tun_drain=' in line]
    assert len(drains) == 1 and drains[0].endswith('native_tun_drain=true')
    return dict(status='PASS', scope='real-WiFi-loss-new-Network-no-mobile-claim',
                same_socket_policy_drop_checked=underlay_drop, **summary)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.build, args.run), indent=2))
