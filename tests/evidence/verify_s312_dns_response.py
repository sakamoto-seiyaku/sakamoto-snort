#!/usr/bin/env python3
"""Offline recheck of original S312 UDP response decisions and retained failures."""
import argparse
import copy
import hashlib
import ipaddress
import json
import re
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def props(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def json_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]


def question(wire):
    at, labels = 12, []
    while wire[at]:
        size = wire[at]; at += 1
        labels.append(wire[at:at + size].decode('ascii')); at += size
    return '.'.join(labels), int.from_bytes(wire[at + 1:at + 3], 'big')


def hot_case(folder, result):
    """Recover the proved hot case whose later control-caller assertion failed.

    The original HOLD is immutable. Its actual request/answer/UI/SQLite inputs
    go through the same independent checks as normally completed case rows.
    """
    label = 'n1-current-policy'
    plan = read(folder / (label + '-plan.json'))
    observed = read(folder / (label + '-observation.json'))
    rows = [row['record'] for row in observed['consumer']['persistent']['dns']['recent'].values()]
    generation = result['runs'][0]['generation']
    records = []
    client = read(folder / (label + '-client.json'))
    peers = json_lines(folder / 'peer.log')
    for index, wire in enumerate(plan['dnsQueries']):
        identifier = int(wire[:4], 16)
        query, = [row for row in rows if row['generation'] == generation
                  and row['stage'] == 1 and row['source_port'] == plan['source'] and row['id'] == identifier]
        replies = sorted([row for row in rows if row['generation'] == generation
                          and row['stage'] == 2 and row['source_port'] == plan['source'] and row['id'] == identifier],
                         key=lambda row: row['name_index'])
        peer, = [row for row in peers if row.get('kind') == 'exchange' and row['request_hex'] == wire]
        records.append(dict(query=query, responses=replies, request_hex=wire,
                            reply_hex=peer['reply_hex'], denied=index == 1))
    assert client['phase'] == 'finished' and not client.get('error')
    return dict(label=label, profile='vpn', generation=generation, owner_count=1,
                address=plan['endpoint'], source_port=plan['source'], variant='alias', public=False,
                policy=props(folder / 'n1-old-hot-applied.properties'),
                response_policy=props(folder / (label + '-hot-applied.properties')), records=records)


def verify_case(folder, result, case, observed=None):
    label, profile = case['label'], case['profile']
    kind = label.split('-', 1)[1]
    hot = kind == 'current-policy'
    observed = observed or read(folder / (label + '-observation.json'))
    assert observed['consumer']['query_fresh'] is True
    store = observed['consumer']['persistent']
    assert store['storage'] == 'sqlite'
    recent = [row['record'] for row in store['dns']['recent'].values()]
    client = read(folder / (label + '-client.json'))
    assert client['phase'] == 'finished' and not client.get('error')
    plan = read(folder / (label + '-plan.json'))
    assert plan['source'] == case['source_port'] and plan['endpoint'] == case['address']
    underlay = json_lines(folder / (label + '-underlay.jsonl'))
    peers = json_lines(folder / 'peer.log')
    old, current = case['policy'], case['response_policy']
    for status in (old, current):
        matches = [path for path in folder.glob('*-applied.properties')
                   if props(path).get('activeRevision') == status['activeRevision']]
        assert matches and any(props(path) == status for path in matches)
    if hot:
        assert int(current['activeRevision']) > int(old['activeRevision'])
    assert len(case['records']) == 3
    for index, item in enumerate(case['records']):
        wire, reply = bytes.fromhex(item['request_hex']), bytes.fromhex(item['reply_hex'])
        name, qtype = question(wire)
        query = item['query']
        answers = item['responses']
        assert wire.hex() == plan['dnsQueries'][index] == client['dnsExchanges'][index]['sentHex']
        assert query in recent and answers and all(row in recent for row in answers)
        assert query['id'] == int.from_bytes(wire[:2], 'big') and query['qtype'] == qtype
        assert query['name'] == name and query['qclass'] == 1 and query['coverage'] == 1
        caller = 0 if profile == 'vpn' and (index == 0 or (hot and index == 2)) else 1
        assert query['caller'] == caller and bool(caller) == bool(query['availability'] & 8)
        query_status = current if hot and index == 2 else old
        response_status = old if hot and index == 0 else current
        assert query['policy_revision'] == int(query_status['activeRevision'])
        assert query['winner'] == (int(query_status['rule.2.version']) if caller else 0)
        assert query['actual_action'] == 1 and query['direction'] == 3
        active_variant = case['variant'] if index == 1 or (profile == 'vpn' and index == 0
                         and not case['public'] and case['variant'] != 'short') else 'ordinary'
        coverage, chain = {'overflow': (4, 3), 'loop': (2, 1), 'tc': (5, 0),
                           'malformed': (2, 0), 'short': (2, 0)}.get(active_variant, (1, 0))
        unmatched = active_variant in ('malformed', 'short') and not case['public']
        reply_caller = 0 if unmatched else caller
        denied = index == 1 and (kind in ('v4-alias-drop', 'v6-alias-drop', 'rank-qname',
                 'or', 'current-policy', 'long'))
        declared_drop = denied or (kind == 'observe' and index == 1)
        winner = 1 if kind == 'rank-qname' else (0 if kind in ('v4-alias-drop', 'v6-alias-drop',
                 'alias-allow', 'or', 'observe', 'current-policy', 'long') else 2)
        if index != 1 or coverage != 1:
            winner, denied, declared_drop = 2, False, False
        assert item['denied'] == denied
        expected_names = [name]
        if active_variant in ('alias', 'loop'):
            expected_names += ['alias.test']
        if active_variant in ('long', 'overflow'):
            count = 32 if active_variant == 'long' else 33
            expected_names += [f'chain{i}.test' for i in range(count - 1)] + ['alias.test']
            expected_names = expected_names[:33]
        if unmatched:
            expected_names = ['']
        if not case['public']:
            assert [row['name'] for row in answers] == expected_names
        for ordinal, record in enumerate(answers):
            assert record['generation'] == case['generation'] and record['stage'] == 2
            assert record['direction'] == 1 and record['delivery'] == 0
            assert record['source_port'] == case['source_port'] and record['resolver_port'] == 53
            address = ipaddress.ip_address(case['address'])
            assert bytes(record['resolver_address'][:len(address.packed)]) == address.packed
            assert record['coverage'] == coverage and record['chain_status'] == chain
            assert record['caller'] == reply_caller and record['correlation'] == (2 if unmatched else 1)
            assert record['name_index'] == ordinal and record['name_source'] == int(ordinal != 0)
            assert record['candidate_count'] == (0 if unmatched else len(answers))
            assert record['policy_revision'] == int(response_status['activeRevision'])
            assert record['actual_action'] == (2 if denied else 1)
            assert record['domain_available'] == bool(reply_caller and coverage == 1)
            membership = {'qname.test': 1, 'alias.test': 2}.get(record['name'], 0)
            assert record['domain_lists'] == (membership if record['domain_available'] else 0)
            if reply_caller:
                assert record['uid'] == result['uid']
                assert record['winner'] == int(response_status[f'rule.{winner}.version'])
                assert record['declared_action'] == (2 if declared_drop else 1)
            if kind == 'observe' and index == 1:
                assert record['mode'] == 1
            if unmatched:
                assert record['query_token'] == 0
            else:
                assert record['query_token'] == query['token'] and record['uid'] == query['uid']
                assert record['query_incarnation'] == query['incarnation']
                assert record['query_policy_revision'] == query['policy_revision']
                assert record['query_policy_hash'] == query['policy_hash'] and record['query_winner'] == query['winner']
                if profile == 'vpn':
                    assert record['transport_session'] and record['underlay_epoch']
            assert record['codec_peak_bytes'] <= 512 * 1024
        assert any(row.get('destination') == case['address'] and row.get('destination_port') == 53
                   and row.get('payload_hex') == wire.hex() for row in underlay)
        assert any(row.get('source') == case['address'] and row.get('source_port') == 53
                   and row.get('payload_hex') == reply.hex() for row in underlay)
        if not case['public']:
            peer, = [row for row in peers if row.get('kind') == 'exchange' and row['request_hex'] == wire.hex()]
            assert peer['reply_hex'] == reply.hex() and peer['sent_bytes'] == len(reply)
            assert peer['resolver'] == [case['address'], 53]
        exchange = client['dnsExchanges'][index]
        if denied:
            assert exchange.get('timedOut') is True and not exchange.get('replyHex')
        else:
            assert exchange.get('replyHex') == reply.hex()
    return dict(profile=profile, owners=case['owner_count'], generation=case['generation'], label=label, messages=3)


def verify_stop(folder, result):
    for run in result['runs']:
        path = folder / (f'n{run["owners"]}-stop.log')
        if not path.exists():
            path = folder / 'failure-cleanup-stop.log'
        text = path.read_text()
        for owner in range(run['owners']):
            assert (f'dns event=stop generation={run["generation"]} owner={owner} requests=0 '
                    'codec_live_bytes=0 active_operations=0') in text
        if result['profile'] == 'vpn':
            assert (f's213 event=stop generation={run["generation"]} pending=0 buffers=0 '
                    'frames=0 obligations=0 tun_fd=-1') in text
            for owner in range(run['owners']):
                rows = [line for line in text.splitlines()
                        if f's237 event=owner_stopped generation={run["generation"]} owner={owner} ' in line]
                assert rows
                for line in rows:
                    facts = {key: int(value) for key, value in re.findall(r'(\w+)=(-?\d+)', line)}
                    assert all(facts[key] == 0 for key in ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
                    assert facts['sockets_created'] == facts['sockets_closed']
                    assert facts['timer_fd'] == facts['broker_fd'] == -1
        else:
            assert (f's242 event=stop_native_zero generation={run["generation"]} ready_mask=0 '
                    'graph_enabled=0 graph_accepting=0 pending=0 buffers=0 obligations=0 '
                    'handoffs=0 completion_frames=0') in text
        processes = folder / (f'n{run["owners"]}-processes-after.txt')
        if not processes.exists():
            processes = folder / 'failure-cleanup-processes-after.txt'
        assert not any(len(parts := line.split()) >= 3 and Path(parts[2]).name == 'libvpp_runtime.so'
                       for line in processes.read_text().splitlines())
    stopped, = [row for row in json_lines(folder / 'peer.log') if row.get('kind') == 'stopped']
    if result['status'] == 'PASS':
        assert stopped['pending'] == 0
    else:
        # The retained failed hot-UI run cancelled its unreleased peer fixture
        # by closing/reaping the owned peer. This is not Product DNS work.
        assert stopped['pending'] == 0 or (stopped['pending'] == 1 and 'hot-applied deadline' in result['error'])
    assert any(row.get('kind') == 'stopped' for row in json_lines(folder / 'underlay-final.jsonl'))
    assert not any(key.endswith('cleanup_error') for key in result)
    return stopped['pending']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runs', type=Path, nargs='+', required=True)
    parser.add_argument('--historical', type=Path, required=True)
    parser.add_argument('--hot-supplement', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, default=Path('build-output/s312-dns-response-20261022'))
    parser.add_argument('--restoration', type=Path)
    parser.add_argument('--without-restoration', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    native = read(Path('build-output/s312-native-cache-r2-20261022/result.json'))['records'][-1]['native_sha256']
    apk = read(Path('build-output/s312-apk-cache-r2-20261022/result.json'))['records'][-1]['apk_sha256']
    checks, inputs, coverage, cancelled_fixtures = [], {}, set(), 0
    folders = args.runs + [args.historical, args.hot_supplement]
    negative = None
    for folder in folders:
        result = read(folder / 'result.json')
        assert digest(folder / 'runner.py') == result['runner_sha256']
        assert result['native_sha256']['libproduct_core_plugin.so'] == native['libproduct_core_plugin.so']
        if folder != args.historical:
            assert result['apk_sha256'] == apk and result['native_sha256'] == native
        else:
            assert result['profile'] == 'root' and len(result['cases']) == 9 and result['status'] == 'HOLD'
        cases = [hot_case(folder, result)] if folder == args.hot_supplement else result['cases']
        for case in cases:
            checks.append(verify_case(folder, result, case))
            coverage.add((case['profile'], case['owner_count'], case['label'].split('-', 1)[1]))
            if negative is None and case['records'][1]['denied']:
                negative = folder, result, case
        cancelled_fixtures += verify_stop(folder, result)
        inputs.update({str(path): digest(path) for path in folder.iterdir() if path.is_file()})
    n1 = {'v4-alias-drop', 'v6-alias-drop', 'alias-allow', 'rank-qname', 'and', 'or',
          'sni-or', 'business-port', 'observe', 'current-policy', 'short'}
    n3 = {'v4-alias-drop', 'v6-alias-drop', 'long', 'overflow', 'loop', 'unrelated', 'tc',
          'malformed', 'short', 'nxdomain', 'public4', 'public6'} | {f'rr{n}' for n in (1, 28, 16, 15, 33, 65, 65000)}
    for profile in ('root', 'vpn'):
        for owners, expected in ((1, n1), (3, n3)):
            assert expected <= {kind for p, n, kind in coverage if p == profile and n == owners}
    folder, result, original = negative
    forged = copy.deepcopy(original)
    snapshot = read(folder / (original['label'] + '-observation.json'))
    token = forged['records'][1]['responses'][0]['token']
    for record in forged['records'][1]['responses']:
        record['winner'] += 1
    for row in snapshot['consumer']['persistent']['dns']['recent'].values():
        if row['record']['generation'] == original['generation'] and row['record']['token'] == token:
            row['record']['winner'] += 1
    try:
        verify_case(folder, result, forged, snapshot)
    except AssertionError:
        pass
    else:
        raise AssertionError('verifier accepted a forged winner in both case and persistent observation')
    if not args.without_restoration:
        assert args.restoration
        restored = read(args.restoration)
        assert restored['status'] == 'PASS' and restored['members_verified_before_swap'] == 4858
        assert restored['preserved_generation'] >= max(check['generation'] for check in checks)
        assert restored['original_apk_sha256'] == 'cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110'
        processes = (args.restoration.parent / 'after-processes.txt').read_text()
        assert not any('s312-wire' in line or 'tar -tf -' in line for line in processes.splitlines())
        assert not any(len(parts := line.split()) >= 3 and Path(parts[2]).name == 'libvpp_runtime.so'
                       for line in processes.splitlines())
        inputs[str(args.restoration)] = digest(args.restoration)
    report = dict(status='WIRE_ONLY_PASS' if args.without_restoration else 'PASS_WITH_EXPLICIT_LIMITS',
                  task='SAKAMOTO-312', checks=checks, groups=len(checks), messages=sum(c['messages'] for c in checks),
                  distinct_groups=len(coverage), final_apk_sha256=apk, final_native_sha256=native,
                  cancelled_owned_peer_fixtures_in_retained_failed_run=cancelled_fixtures,
                  historical_scope='Nine Root N1 rule groups use the earlier decoder, with byte-identical packet plugin; final errors/hot/stop use corrected decoder.',
                  limits=['Controlled Pixel Root OUTPUT captures debug App UID; no netd IPC or general release claim.',
                          'Public destination wire is observed, not authenticated resolver-provider identity.',
                          'Request-table capacity/expiry/late generations use shared Host seams; actual adapters exercise chain capacity and stop.'],
                  negative_wrong_winner_rejected=True, inputs=inputs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'groups', 'messages', 'distinct_groups')}))


if __name__ == '__main__':
    main()
