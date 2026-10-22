#!/usr/bin/env python3
"""Independently recheck frozen S311 VPN UDP wire, decisions and restoration."""
import argparse
import hashlib
import ipaddress
import json
import re
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
    parser.add_argument('--wire', type=Path, required=True)
    parser.add_argument('--stops', type=Path, nargs='+', required=True)
    parser.add_argument('--evidence', type=Path, default=Path('build-output/s311-dns-vpn-udp-20261022'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--without-restoration', action='store_true',
                        help='Intermediate wire-only check; cannot qualify ticket completion')
    args = parser.parse_args()
    wire, evidence = args.wire, args.evidence
    result = read(wire / 'result.json')
    # The original collector retained an intentionally strict aggregate HOLD:
    # cold .test client deadlines expired despite successful later public
    # queries. It also read historical stop archives. Qualify each raw case
    # below and join only the missing stop proofs from an identical artifact.
    assert result['status'] == 'HOLD' and result['error'] == 'AssertionError()'
    assert 'assert all(case.get(\'transport_complete\'' in (wire / 'runner.py').read_text()
    stop_results = [(folder, read(folder / 'result.json')) for folder in args.stops]
    for folder, stop_result in stop_results:
        assert stop_result['status'] == 'PASS' and stop_result['wire_stopped']
        assert not stop_result.get('cleanup_error')
        assert stop_result['apk_sha256'] == result['apk_sha256']
        assert stop_result['native_sha256'] == result['native_sha256']
        assert digest(folder / 'runner.py') == stop_result['runner_sha256']
    stop_runs = [(folder, run) for folder, receipt in stop_results for run in receipt['runs']]
    assert result['wire_stopped'] and not result.get('cleanup_error')
    assert digest(wire / 'runner.py') == result['runner_sha256']
    assert result['serial'] == '28201JEGR0XPAJ'
    assert {run['owners'] for run in result['runs']} == {1, 3}
    for helper, identities in result['helpers'].items():
        assert digest(wire / helper) == identities['binary_sha256']
        source = 's311_dns_' + ('wire' if helper.endswith('wire') else 'query') + '.c'
        assert digest(wire / source) == identities['source_sha256']
    native = {Path(line.split()[1]).name: line.split()[0]
              for line in (wire / 'installed-native.txt').read_text().splitlines()}
    assert native == result['native_sha256']
    assert (wire / 'installed-apk.txt').read_text().split()[0] == result['apk_sha256']
    assert digest(evidence / 'pretest/manifest.json') == result['backup_manifest_sha256']

    peers = [json.loads(line) for line in (wire / 'resolver.jsonl').read_text().splitlines()]
    underlay = [json.loads(line) for line in (wire / 'underlay-final.jsonl').read_text().splitlines()
                if line.startswith('{')]
    assert underlay[0]['kind'] == 'ready' and underlay[-1]['kind'] == 'stopped'
    expected = {
        'n1-lan4': ([None, 1, 0, 1], [False, False, True, False]),
        'n3-lan4': ([None, 1, 0, 1], [False, False, True, False]),
        'n1-lan6': ([None, 0, 1], [False, True, False]),
        'n3-lan6': ([None, 0, 1], [False, True, False]),
        'rank-allow': ([None, 1], [False, False]),
        'business-port': ([None, 1], [False, False]),
        'sni-or': ([None, 1], [False, False]),
        'not': ([None, 1], [False, False]),
        'observe': ([None, 0], [False, False]),
        'logical-or': ([None, 0], [False, True]),
        'logical-not': ([None, 0], [False, True]),
        'logical-empty-not': ([None, 0], [False, True]),
        'malformed-block': ([None, 2], [False, False]),
        'malformed-generic-drop': ([None, 2], [False, True]),
        'malformed-unknown-generic': ([None, 0], [False, True]),
        'public4': ([None, 0, 2], [False, True, False]),
        'public6': ([None, 0, 2], [False, True, False]),
    }
    cases = {case['label']: case for case in result['cases']}
    assert set(cases) == {*expected, 'system-resolver', 'known-system-pass', 'known-system-generic-drop'}
    checks, limits = [], []
    for label, (winners, denied) in expected.items():
        case = cases[label]
        plan = case['plan']
        client = read(wire / (label + '-client.json'))
        observation = read(wire / (label + '-observation.json'))
        assert observation['consumer']['query_fresh'] is True
        persisted = [row['record'] for row in observation['consumer']['persistent']['dns']['recent'].values()]
        assert not client.get('error') and client['phase'] == 'finished'
        assert case['denied'] == denied and case['expected_rule_indices'] == winners
        assert len(case['dns_records']) == len(winners) == len(plan['dnsQueries'])
        status = case['configuration']
        assert status['savedRevision'] == status['activeRevision'] == str(case['revision'])
        for index, (hex_wire, blocked, winner) in enumerate(zip(plan['dnsQueries'], denied, winners)):
            query = bytes.fromhex(hex_wire)
            identifier = int.from_bytes(query[:2], 'big') if len(query) >= 4 else 0
            record, = [record for record in case['dns_records'] if record['id'] == identifier]
            assert record in persisted
            assert record['caller'] == (1 if index else 0)
            assert record['uid'] == (result['uid'] if index else 4294967295)
            assert record['availability'] & 9 == (9 if index else 0)
            assert record['domain_available'] is (index != 0 and not label.startswith('malformed-'))
            assert record['coverage'] == (2 if index and label.startswith('malformed-') else 1)
            assert record['source_port'] == plan['source'] and record['resolver_port'] == 53
            address = str(ipaddress.ip_address(bytes(record['resolver_address'][:4 if record['family'] == 4 else 16])))
            assert address == plan['endpoint'] == case['address']
            assert record['policy_revision'] == case['revision'] and record['delivery'] == 0
            assert record['winner'] == (int(status[f'rule.{winner}.version']) if winner is not None else 0)
            assert record['actual_action'] == (2 if blocked else 1)
            if winner is not None:
                assert record['declared_action'] == int(status[f'rule.{winner}.action'])
                assert record['mode'] == (1 if label == 'observe' and index else 0)
            exchange = client['dnsExchanges'][index]
            assert exchange['sentHex'] == hex_wire
            sent = [row for row in underlay if row.get('destination') == address
                    and row.get('destination_port') == 53 and row.get('payload_hex') == hex_wire]
            received = [row for row in underlay if row.get('source') == address and row.get('source_port') == 53
                        and row.get('payload_hex') == exchange.get('replyHex')]
            peer = [row for row in peers if row['request_hex'] == hex_wire]
            if blocked:
                assert exchange['timedOut'] is True and not sent and not peer
            elif case['public'] and not received:
                assert sent and exchange['timedOut'] is True
                late = [row for row in underlay if row.get('source') == address
                        and row.get('source_port') == 53
                        and bytes.fromhex(row.get('payload_hex', ''))[:2] == query[:2]]
                assert late and all(bytes.fromhex(row['payload_hex'])[2] & 0x80 for row in late)
                limits.append({'label': label, 'query': index, 'underlay_sent': True,
                               'late_rcodes': [bytes.fromhex(row['payload_hex'])[3] & 15 for row in late],
                               'scope': 'cold .test client timed out; actual late wire response, no delivery claim'})
            else:
                assert sent and received and exchange['replyHex']
                reply = bytes.fromhex(exchange['replyHex'])
                assert reply[:2] == query[:2] and reply[2] & 0x80
                if not case['public']:
                    peer, = peer
                    assert peer['resolver'] == [address, 53] and peer['reply_hex'] == exchange['replyHex']
            checks.append({'case': label, 'query': index, 'caller': record['caller'], 'blocked': blocked})
        native_status = (wire / (label + '-native.txt')).read_text()
        assert 'dns.profile=original-udp enabled=1' in native_status
        assert 'codec_live_bytes=0 active_operations=0' in native_status

    for label, blocked in [('known-system-pass', False), ('known-system-generic-drop', True)]:
        case = cases[label]
        client = read(wire / (label + '-client.json'))
        observed = read(wire / (label + '-observation.json'))
        persisted = [row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()]
        assert client['uid'] == 2000 and len(case['dns_records']) == 2
        for index, record in enumerate(case['dns_records']):
            assert record in persisted and record['caller'] == 0 and not record['domain_available']
            assert record['uid'] == (2000 if index else 4294967295)
            assert record['availability'] & 9 == (1 if index else 0)
            assert record['actual_action'] == (2 if index and blocked else 1)
            status = case['configuration']
            assert record['winner'] == (int(status[f'rule.{0 if blocked else 2}.version']) if index else 0)
            exchange = client['exchanges'][index]
            if index and blocked:
                assert exchange['timed_out']
            else:
                assert exchange['reply_hex']
        checks.append({'case': label, 'source': 'known system-UID real socket fixture, not netd IPC'})
    system = cases['system-resolver']
    client = read(wire / 'system-resolver-client.json')
    assert system['actual_result'] == client and system['plan']['systemDnsName'] == 'blocked.test'
    assert all(record['caller'] == 0 and not record['domain_available']
               and record['actual_action'] == 1 for record in system['dns_records'])
    assert 'ETIMEDOUT' in client['systemDnsError'] and not client.get('systemDnsAnswerHex')
    limits.append({'case': 'system-resolver', 'scope': 'actual Android API query/Unknown policy only; resolver timed out'})
    checks.append({'case': 'system-resolver', 'source': 'actual Android DnsResolver API'})
    for run in result['runs']:
        prefix = f'n{run["owners"]}'
        state = props(wire / (prefix + '-running.properties'))
        stopped = props(wire / (prefix + '-stopped.properties'))
        assert state['profile'] == 'vpn' and state['protectionRunning'] == 'true'
        assert state['generation'] == str(run['generation'])
        assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == 'false'
        assert run['process_absent']
    assert len(stop_runs) == 2 and {run['owners'] for _, run in stop_runs} == {1, 3}
    for folder, run in stop_runs:
        prefix = f'n{run["owners"]}'
        stop_path = folder / (prefix + '-stop.log')
        assert digest(stop_path) == run['stop_log_sha256']
        stop = stop_path.read_text()
        assert ('s213 event=stop generation=' + str(run['generation'])
                + ' pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1') in stop
        owner_stops = []
        for line in stop.splitlines():
            if line.startswith('s237 event=owner_stopped '):
                fields = dict(re.findall(r'(\w+)=([^\s]+)', line))
                if fields['generation'] == str(run['generation']): owner_stops.append(fields)
        assert len(owner_stops) == run['owners']
        assert {int(row['owner']) for row in owner_stops} == set(range(run['owners']))
        for row in owner_stops:
            assert all(row[key] == '0' for key in ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
            assert row['sockets_created'] == row['sockets_closed']
            assert row['timer_fd'] == row['broker_fd'] == '-1'
        assert run['process_absent']
        checks.append({'case': prefix + '-normal-stop', 'generation': run['generation'],
                       'native_resource_zero': True, 'same_apk_and_native': True})
    report = {'status': 'WIRE_ONLY' if args.without_restoration else 'PASS_WITH_EXPLICIT_LIMITS', 'checks': checks,
              'limits': limits, 'apk_sha256': result['apk_sha256'], 'native_sha256': native}
    if not args.without_restoration:
        restore = read(evidence / 'restoration-resume/receipt.json')
        assert restore['status'] == 'PASS' and restore['native_process_absent']
        assert restore['members_verified_before_swap'] > 0 and restore['stage_removed']
        assert restore['preserved_generation'] >= max([run['generation'] for run in result['runs']] + [run['generation'] for _, run in stop_runs])
        assert restore['critical_state_hashes_verified'] and restore['frequency_unchanged']
        assert restore['owned_hooks_and_queues_absent']
        assert restore['stopped_profile'] == 'vpn' and restore['wifi'] == 'Openwrt_5G'
        report['restoration_sha256'] = digest(evidence / 'restoration-resume/receipt.json')
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'checks': len(checks), 'limits': limits}))


if __name__ == '__main__':
    main()
