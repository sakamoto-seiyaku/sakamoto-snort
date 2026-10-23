#!/usr/bin/env python3
"""Independent raw control qualification; never rewrites a runner's result."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re


def props(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]


def frames(packets, resolver, source, outgoing):
    selected = [p for p in packets if p.get('kind') == 'tcp'
                and p['destination' if outgoing else 'source'] == resolver
                and p['source_port' if outgoing else 'destination_port'] == source]
    syn = [p for p in selected if p['flags'] & 2]
    assert syn, ('wire handshake absent', resolver, source, outgoing)
    start = (syn[0]['sequence'] + 1) & 0xffffffff
    positions = {}
    for packet in selected:
        for offset, byte in enumerate(bytes.fromhex(packet['payload_hex'])):
            at = (packet['sequence'] + bool(packet['flags'] & 2) + offset - start) & 0xffffffff
            assert at < 2**31
            assert at not in positions or positions[at] == byte, 'conflicting raw TCP overlap'
            positions[at] = byte
    wire = bytearray()
    while len(wire) in positions:
        wire.append(positions[len(wire)])
    output, cursor = [], 0
    while cursor + 2 <= len(wire):
        size = int.from_bytes(wire[cursor:cursor + 2], 'big')
        assert cursor + 2 + size <= len(wire), 'incomplete control wire frame'
        output.append(wire[cursor + 2:cursor + 2 + size].hex())
        cursor += size + 2
    assert cursor == len(wire)
    return output


def qualify(run, allow_hold):
    result = json.loads((run / 'result.json').read_text())
    assert result['status'] == 'PASS' or (allow_hold and result['status'] == 'HOLD')
    assert not any(key.endswith('cleanup_error') for key in result)
    installed = (run / 'installed-apk.txt').read_text().split()[0]
    assert installed == result['apk_sha256']
    peer = rows(run / 'peer.log')
    wire = rows(run / 'final-underlay.jsonl')
    assert wire[0]['kind'] == 'ready' and wire[-1]['kind'] == 'stopped'
    ready, = [row for row in peer if row.get('kind') == 'ready']
    cleanup = json.loads((run / 'peer-cleanup.json').read_text())
    assert cleanup['process_id'] == ready['process_id'] and cleanup['process_exit'] == 0
    assert cleanup['actual_remote'] == {'process_present': False, 'endpoints': []}
    stopped, = [row for row in peer if row.get('kind') == 'stopped']
    assert stopped['pending'] == stopped['connections'] == 0
    assert stopped['received'] == stopped['exchanged'] + stopped['cancelled']
    profile = result['profile']
    assert profile == 'vpn', 'this verifier qualifies only the pinned N1 VPN controls'
    plans = sorted(run.glob('n*-v*-split-plan.json'))
    assert len(plans) == 2 and {p.name for p in plans} == {'n1-v4-split-plan.json','n1-v6-split-plan.json'}
    groups = []
    for plan_path in plans:
        label = plan_path.name.removesuffix('-plan.json')
        plan = json.loads(plan_path.read_text())
        app = json.loads((run / (label + '-client.json')).read_text())
        assert app['phase'] == 'finished' and not app.get('error')
        assert app['plan'] == plan and len(app['dnsExchanges']) == 3
        assert [row['sentHex'] for row in app['dnsExchanges']] == plan['dnsTcpQueries']
        requests = plan['dnsTcpQueries']
        received = [row for row in peer if row.get('kind') == 'received'
                    and row.get('request_hex') in requests]
        replies = [row for row in peer if row.get('kind') == 'exchange'
                   and row.get('request_hex') in requests]
        assert len(received) == len(replies) == 3
        assert [row['request_hex'] for row in received] == requests
        assert [row['request_hex'] for row in replies] == requests
        assert all(row['resolver'] == [plan['endpoint'], 53] for row in received + replies)
        assert all(bytes.fromhex(row['reply_hex'])[:2] == bytes.fromhex(row['request_hex'])[:2]
                   and bytes.fromhex(row['reply_hex'])[2] & 128 for row in replies)
        assert [row.get('replyHex') for row in app['dnsExchanges']] == [row['reply_hex'] for row in replies]
        assert not any(row.get('timedOut') for row in app['dnsExchanges'])
        connection, = {row['connection'] for row in received}
        connected, = [row for row in peer if row.get('kind') == 'connected' and row['connection'] == connection]
        port = int(connected['peer'].rsplit(':', 1)[1])
        assert frames(wire, plan['endpoint'], port, True) == requests
        assert frames(wire, plan['endpoint'], port, False) == [row['reply_hex'] for row in replies]
        normal = json.loads((run / (label + '-observation.json')).read_text())['consumer']
        assert normal['malformed'] == 0 and normal['query_fresh'] is True
        assert normal['persistent']['storage'] == 'sqlite'
        generation = int(props(run / (label.split('-')[0] + '-running.properties'))['generation'])
        records = [row['record'] for row in normal['persistent']['dns']['recent'].values()
                   if row['record']['generation'] == generation and row['record']['source_port'] == plan['source']
                   and row['record']['coverage'] == 1 and not row['record']['tcp_continuation']]
        assert len(records) == 6, ('normal complete query/reply rows absent', label, len(records))
        policy = props(run / (label.split('-')[0] + '-allow-applied.properties'))
        assert policy['activeRevision'] == policy['savedRevision'] and policy['result'] == '0'
        for index, request in enumerate(requests):
            identifier = int.from_bytes(bytes.fromhex(request)[:2], 'big')
            query, = [row for row in records if row['stage'] == 1 and row['id'] == identifier]
            reply, = [row for row in records if row['stage'] == 2 and row['id'] == identifier]
            assert query['caller'] == reply['caller']
            assert query['caller'] == 1 or (profile == 'vpn' and index == 0 and query['caller'] == 0)
            assert reply['query_token'] == query['token'] and reply['query_incarnation'] == query['incarnation']
            assert reply['query_policy_revision'] == query['policy_revision']
            assert reply['query_policy_hash'] == query['policy_hash'] and reply['correlation'] == 1
            if profile == 'vpn':
                assert reply['transport_session'] and reply['underlay_epoch']
            for row in (query, reply):
                assert row['protocol'] == 6 and row['adapter_profile'] == (2 if profile == 'vpn' else 1)
                assert row['actual_action'] == 1 and row['incarnation'] > 0 and row['delivery'] == 0
                assert row['message_sequence'] == index + 1
                assert row['policy_revision'] == int(policy['activeRevision'])
                assert str(ipaddress.ip_address(bytes(row['resolver_address'][:4 if row['family'] == 4 else 16]))) == plan['endpoint']
                assert row['uid'] == (result['uid'] if row['caller'] == 1 else 4294967295)
                assert row['domain_available'] == bool(row['caller'])
        groups.append(dict(label=label, generation=generation, family=records[0]['family'],
                           complete_records=6, app_source_port=plan['source'], direct_source_port=port))
    assert {group['family'] for group in groups} == {4, 6}
    state_path, = list(run.glob('*-stopped.properties'))
    state = props(state_path)
    assert state['state'] == 'stopped' and state['mayBeActive'] == 'false'
    log_path = state_path.with_name(state_path.name.replace('-stopped.properties', '-stop.log'))
    log = log_path.read_text()
    generation = int(state['generation'])
    assert {group['generation'] for group in groups} == {generation}, 'control/stop generation mismatch'
    assert f's213 event=stop generation={generation} pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1' in log
    owners = int(groups[0]['label'].split('-')[0][1:])
    for owner in range(owners):
        assert re.search(rf'dns event=stop generation={generation} owner={owner} requests=0 codec_live_bytes=0 active_operations=0 tcp_active=0 tcp_owned_bytes=0', log)
        if profile == 'vpn':
            match = re.search(rf's237 event=owner_stopped generation={generation} owner={owner} .*sessions=0 inputs=0 pbufs=0 sockets_created=(\d+) sockets_closed=(\d+) timer_fd=-1 broker_fd=-1 buffers=0 obligations=0 frames=0', log)
            assert match and match[1] == match[2]
    processes = state_path.with_name(state_path.name.replace('-stopped.properties', '-processes-after.txt')).read_text()
    assert not any('libvpp_runtime.so' in line or re.search(r'\btail\b.*vpp-stdout', line) for line in processes.splitlines())
    witness_processes = (run / 'witness-process-after.txt').read_text()
    assert not any('/data/local/tmp/s313-wire' in line for line in witness_processes.splitlines())
    return dict(status='PASS_WITH_TERMINAL_HOLD' if result['status'] == 'HOLD' else 'PASS',
                scope='Only the two actual dual-stack N1 original VPN TCP normal-observation controls; no full milestone claim',
                raw_runner_status=result['status'], raw_runner_error=result.get('error'),
                apk_sha256=installed, groups=groups,
                inputs={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(run.iterdir()) if p.is_file()})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('run', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--allow-terminal-hold', action='store_true')
    args = parser.parse_args()
    try:
        report = qualify(args.run, args.allow_terminal_hold)
    except Exception as error:
        report = dict(status='FAIL', error=repr(error))
        raise
    finally:
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: value for key, value in report.items() if key not in ('inputs','raw_runner_error')}, indent=2))
