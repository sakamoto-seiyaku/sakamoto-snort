#!/usr/bin/env python3
"""Recheck the frozen S310 Android Root UDP evidence without operating a device."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def props(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-output', type=Path, default=Path('build-output'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    ordinary = args.build_output / 's310-qualified-root-wire-20261022'
    fixture = args.build_output / 's310-qualified-unknown-fixtures-20261022'
    evidence = args.build_output / 's310-dns-root-udp-20261022'
    restored = evidence / 'restoration-resume'
    first, second, restore = (read(ordinary / 'result.json'), read(fixture / 'result.json'),
                              read(restored / 'receipt.json'))
    assert first['status'] == 'HOLD' and second['status'] == restore['status'] == 'PASS'
    assert first['apk_sha256'] == second['apk_sha256']
    assert first['native_sha256'] == second['native_sha256']
    assert len(first['cases']) == 15 and len(second['cases']) == 2
    for folder, result in ((ordinary, first), (fixture, second)):
        assert digest(folder / 'runner.py') == result['runner_sha256']
        for owners in {run['owners'] for run in result['runs']}:
            assert 'metadata.udp_check roundtrip=1 bounds_guard=1 variants=3 ip_padding_excluded=5 buffer_return=1' in (
                folder / f'n{owners}-topology.txt').read_text()

    peers = [json.loads(line) for line in (ordinary / 'resolver.jsonl').read_text().splitlines()]
    expected = {'rank-allow': [1], 'business-port': [1], 'sni-or': [1], 'not': [1],
                'observe': [0], 'logical-or': [0, 0], 'logical-not': [0],
                'malformed-pass': [2], 'malformed-generic-drop': [2],
                'short-generic-or': [0], 'empty-list-not': [0]}
    checks = []
    for case in first['cases']:
        label, plan = case['label'], case['plan']
        config_label = label.split('-v')[0] + '-block' if label.startswith(('n1-', 'n3-')) else label
        status = props(ordinary / (config_label + '-applied.properties'))
        assert digest(ordinary / (config_label + '-source.conf')) == (
            ordinary / (config_label + '-source-sha256.txt')).read_text().split()[0]
        client = read(ordinary / (label + '-client.json'))
        assert not client.get('error') and client['phase'] == 'finished'
        observation = read(ordinary / (label + '-observation.json'))
        assert observation['consumer']['query_fresh'] is True
        persisted = observation['consumer']['persistent']['dns']['recent'].values()
        indices = ([1, 0, 1] if '-v4-' in label else [0, 1]) if label.startswith(('n1-', 'n3-')) else expected[label]
        assert len(case['dns_records']) == len(plan['dnsQueries'])
        for index, (wire, denied, rule) in enumerate(zip(plan['dnsQueries'], case['denied'], indices)):
            query = bytes.fromhex(wire)
            identifier = int.from_bytes(query[:2], 'big') if len(query) >= 4 else 0
            record, = [r for r in case['dns_records'] if r['id'] == identifier]
            assert any(row['record'] == record for row in persisted)
            exchange = client['dnsExchanges'][index]
            received = [r for r in peers if r.get('request_hex') == wire]
            if denied:
                assert exchange['timedOut'] is True and not received
            else:
                peer, = received
                assert peer['resolver'] == [plan['endpoint'], 53]
                assert peer['peer'][1] == plan['source']
                assert exchange['replyHex'] == peer['reply_hex']
            assert record['caller'] == 1 and record['uid'] == first['uid']
            assert record['source_port'] == plan['source'] and record['resolver_port'] == 53
            raw_address = bytes(record['resolver_address'][:4 if record['family'] == 4 else 16])
            assert str(ipaddress.ip_address(raw_address)) == plan['endpoint']
            assert record['policy_revision'] == case['revision'] == int(status['activeRevision'])
            assert record['winner'] == int(status[f'rule.{rule}.version'])
            assert record['declared_action'] == int(status[f'rule.{rule}.action'])
            assert record['actual_action'] == (2 if denied else 1) and record['delivery'] == 0
            assert record['coverage'] == (2 if label.startswith(('malformed-', 'short-')) else 1)
            checks.append({'label': label, 'index': index, 'wire_and_observation': True})
        native = (ordinary / (label + '-native.txt')).read_text()
        assert 'codec_live_bytes=0 active_operations=0' in native
        assert 'pending=0 frames=0 buffers=0 obligations=0' in native
    assert len(checks) == 22

    peers = [json.loads(line) for line in (fixture / 'resolver.jsonl').read_text().splitlines()]
    for case in second['cases']:
        label, denied = case['label'], case['denied']
        record, = case['dns_records']
        client = read(fixture / (label + '-socket.json'))
        assert client['uid'] == record['uid'] == 2000
        assert client['source_port'] == record['source_port'] == (49702 if denied else 49701)
        assert record['caller'] == 0 and record['domain_available'] is False
        assert record['actual_action'] == (2 if denied else 1) and record['delivery'] == 0
        persisted = read(fixture / (label + '-observation.json'))['consumer']['persistent']['dns']['recent'].values()
        assert any(row['record'] == record for row in persisted)
        assert digest(fixture / 's310_dns_query.c') == case['client_source_sha256']
        assert digest(fixture / 's310-dns-query') == case['client_sha256']
        wire = (fixture / (label + '-request.bin')).read_bytes().hex()
        received = [r for r in peers if r.get('request_hex') == wire]
        if denied:
            assert client['timed_out'] is True and not received
        else:
            peer, = received
            assert peer['peer'][1] == client['source_port'] and peer['reply_hex'] == client['reply_hex']
        counters = (fixture / (label + '-capture-counters.txt')).read_text()
        counter, = [line for line in counters.splitlines() if 'S310_UNKNOWN_FIXTURE' in line]
        assert counter.startswith('[1:58] -A OUTPUT ')
        for field in ('--uid-owner 2000', '--dport 53', '--sport ' + str(client['source_port']),
                      '-j NFQUEUE --queue-num 176 --queue-bypass'):
            assert field in counter
        assert 'S310_UNKNOWN_FIXTURE' not in (fixture / (label + '-capture-after.txt')).read_text()

    assert first['runs'][0]['process_absent'] and second['runs'][0]['process_absent']
    assert props(ordinary / 'cleanup-stopped.properties')['mayBeActive'] == 'false'
    final = (fixture / 'n3-final.txt').read_text()
    assert 'codec_live_bytes=0 active_operations=0' in final
    assert 'pending=0 frames=0 buffers=0 obligations=0' in final
    for folder, owners in ((ordinary, 1), (fixture, 3)):
        assert 'event=stop_native_zero' in (folder / f'n{owners}-stop.log').read_text()
    maximum = max(r['generation'] for result in (first, second) for r in result['runs'])
    assert restore['preserved_generation'] == maximum == 2588
    assert restore['members_verified_before_swap'] == 4858
    for key in ('critical_state_hashes_verified', 'frequency_unchanged', 'native_process_absent',
                'owned_hooks_and_queues_absent', 'stage_removed'):
        assert restore[key] is True
    assert restore['stopped_profile'] == 'vpn' and restore['wifi'] == 'Openwrt_5G'
    assert set(restore['intentional_content_changes']) == {
        'files/runtime-state/snapshot.properties', 'files/product-state/product-core-generation.properties'}
    assert all(row['before'] == 2579 and row['after'] == maximum
               for row in restore['intentional_content_changes'].values())
    assert read(evidence / 'restoration' / 'expected-members.json') == read(restored / 'observed-stage-members.json')
    report = {'status': 'PASS_WITH_EXPLICIT_LIMITS', 'task': 'SAKAMOTO-310',
              'ordinary_case_groups': 15, 'ordinary_queries': 22, 'system_uid_fixture_queries': 2,
              'apk_sha256': first['apk_sha256'], 'native_sha256': first['native_sha256'],
              'raw_ordinary_status_preserved': first['status'],
              'fixture_scope': 'known system socket UID; not netd IPC',
              'source_commit': 'd0b569777defea4e237a4bb1892fe45de6349ff7',
              'restoration_generation': maximum, 'checks': checks,
              'inputs': {str(path): digest(path) for path in (
                  ordinary / 'result.json', fixture / 'result.json', restored / 'receipt.json')},
              'verifier_sha256': digest(Path(__file__))}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
