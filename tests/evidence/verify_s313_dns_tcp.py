#!/usr/bin/env python3
"""Offline S313 verifier: independently join App, peer, wire and normal history.

This verifier never imports the runner or Product DNS parser. Raw captures remain
the authority; the runner's derived records and winners must agree with them.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def properties(path):
    return dict(line.split('=', 1) for line in path.read_text().splitlines()
                if line and not line.startswith('#') and '=' in line)


def json_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()
            if line.startswith('{')]


def tcp_messages(rows, source, outgoing):
    selected = [r for r in rows if r.get('kind') == 'tcp'
                and r['source_port' if outgoing else 'destination_port'] == source
                and r['destination_port' if outgoing else 'source_port'] == 53]
    syn = [r for r in selected if r['flags'] & 2]
    assert syn, ('actual SYN absent', source, outgoing)
    origin = (syn[0]['sequence'] + 1) % 2**32
    data = {}
    for row in selected:
        offset = (row['sequence'] + bool(row['flags'] & 2) - origin) % 2**32
        for index, byte in enumerate(bytes.fromhex(row['payload_hex'])):
            position = offset + index
            assert position < 2**31, 'wire sequence outside observed session'
            assert position not in data or data[position] == byte, 'wire byte conflict'
            data[position] = byte
    contiguous = bytearray()
    while len(contiguous) in data:
        contiguous.append(data[len(contiguous)])
    messages, cursor = [], 0
    while cursor + 2 <= len(contiguous):
        size = int.from_bytes(contiguous[cursor:cursor + 2], 'big')
        if cursor + 2 + size > len(contiguous): break
        messages.append(contiguous[cursor + 2:cursor + 2 + size].hex())
        cursor += size + 2
    return messages, bytes(contiguous), len(contiguous) - cursor


def semantics(label):
    """Literal acceptance expectations, independent of recorded result fields."""
    if '-boundary-long-' in label: return True, False, 0, False
    if '-query-drop-' in label: return True, True, 0, False
    if '-alias-drop-observe-' in label: return False, False, 0, True
    if '-alias-drop-' in label: return True, False, 0, False
    if '-alias-allow-' in label: return False, False, 0, False
    if '-rank-qname-' in label: return True, False, 1, False
    if '-sni-or-' in label: return False, False, 2, False
    if re.search(r'-(or|not)-v[46]$', label): return True, False, 0, False
    if '-hot-' in label: return True, False, 0, False
    return False, False, 2, False


def boundary_coverage(label):
    if '-coalesced-short-' in label: return 2, 0
    for variant, coverage, chain in (('loop', 2, 1), ('overflow', 4, 3),
                                    ('tc', 5, 0), ('short', 2, 0), ('malformed', 2, 0)):
        if f'-boundary-{variant}-' in label: return coverage, chain
    return 1, 0


def verify_policy(directory, path, label, uid):
    status = properties(path)
    assert status['savedRevision'] == status['activeRevision'] and status['result'] == '0'
    assert status['count'] == status['activeCount'] == '3'
    variant = 'allow'
    for name in ('query-drop', 'alias-drop', 'alias-allow', 'rank-qname',
                 'sni-or', 'business-port', 'and', 'or', 'not'):
        if f'-{name}-' in label: variant = name; break
    if '-boundary-' in label or '-hot-' in label or '-coalesced-' in label: variant = 'alias-drop'
    bases = {'allow': '1102', 'query-drop': '1100', 'alias-drop': '1101',
             'alias-allow': '1101', 'rank-qname': '1101', 'and': '1100110101',
             'or': '1100110102', 'not': '110103', 'sni-or': '1001110102',
             'business-port': '11010cbb01bb0101'}
    direction = 3 if variant == 'query-drop' else 1
    allow_alias = variant in ('alias-allow', 'rank-qname')
    expressions = [bases[variant] + f'06{direction:02x}01',
                   ('1100' if allow_alias else '1102') + f'06{direction:02x}01', '']
    ranks = [20, 10, 100] if variant == 'rank-qname' else [10, 20, 100]
    actions = [1, 2, 1] if allow_alias else [2, 1, 1]
    for index, expression in enumerate(expressions):
        row = list(map(int, status[f'rule.{index}.wire'].split(',')))
        compiled = b''.join(word.to_bytes(4, 'big') for word in row[27:])[:row[26]].hex()
        assert compiled == expression and row[5] == ranks[index] and row[10] == actions[index]
    mode = int('-observe-' in label)
    assert status['binding.0'] == f'1,{uid},2,10,{mode}'
    prefix = path.name.removesuffix('-applied.properties')
    ack = json.loads((directory / (prefix + '-config-ack.json')).read_text())
    source = directory / (prefix + '-source.conf')
    assert ack['revision'] == int(status['activeRevision']) and ack['source_sha256'] == sha(source)
    assert (directory / (prefix + '-source-sha256.txt')).read_text().split()[0] == sha(source)
    return status


def required_labels():
    labels = set()
    for owners in (1, 3):
        groups = (('query-drop', 'alias-drop', 'alias-allow', 'rank-qname',
                   'and', 'or', 'not', 'sni-or', 'business-port', 'alias-drop-observe')
                  if owners == 1 else ('query-drop', 'alias-drop', 'and', 'alias-drop-observe'))
        for index, group in enumerate(groups):
            labels.update(f'n{owners}-g{index}-{group}-v{family}' for family in (4, 6))
        for kind in ((1, 28, 16, 15, 33, 65, 65000) if owners == 1 else (65,)):
            labels.update(f'n{owners}-rr{kind}-v{family}' for family in (4, 6))
        for kind in ('pipeline', 'continuous', 'hot'):
            labels.update(f'n{owners}-{kind}-v{family}' for family in (4, 6))
    return labels


def required_boundaries():
    labels = set()
    for owners, variants in ((1, ('long', 'overflow', 'loop', 'unrelated', 'tc',
                                  'malformed', 'short', 'nxdomain')), (3, ('long', 'short'))):
        labels.update(f'n{owners}-boundary-{variant}-v{family}'
                      for variant in variants for family in (4, 6))
    return labels


def verify(directory, allow_hold=False):
    result = json.loads((directory / 'result.json').read_text())
    retained_hold = result['status'] == 'HOLD'
    if retained_hold:
        assert allow_hold and result.get('error') == "RuntimeError('normal UI action unavailable: Query all rules')", directory
        assert result['cases'], 'a failed control action alone qualifies no cases'
    else:
        assert result['status'] == 'PASS', directory
    assert not any(k.endswith('cleanup_error') for k in result), directory
    inputs = {str(p): sha(p) for p in directory.iterdir() if p.is_file()}
    peer = json_lines(directory / 'peer.log')
    plans = {r['request_hex']: r['reply_hex']
             for r in json.loads((directory / 'peer-plan.json').read_text())['responses']}
    settled = [r for r in peer if r.get('kind') in ('exchange', 'cancelled')]
    received = [r for r in peer if r.get('kind') == 'received']
    identity = lambda r: (r['connection'], r['request'])
    assert len(set(map(identity, received))) == len(received)
    assert len(set(map(identity, settled))) == len(settled)
    assert set(map(identity, received)) == set(map(identity, settled))
    stopped, = [r for r in peer if r.get('kind') == 'stopped']
    assert stopped['pending'] == stopped['connections'] == 0
    assert stopped['received'] == stopped['exchanged'] + stopped['cancelled'] == len(received)
    assert sorted(r['connection'] for r in peer if r.get('kind') == 'connected') == sorted(
        r['connection'] for r in peer if r.get('kind') == 'connection_closed')
    cleanup = json.loads((directory / 'peer-cleanup.json').read_text())
    assert cleanup['process_exit'] == 0 and not cleanup['actual_remote']['process_present']
    assert not any(r['OwningProcess'] == cleanup['process_id']
                   for r in cleanup['actual_remote']['endpoints'])
    assert not re.search(r'\bs313-wire\b', (directory / 'witness-process-after.txt').read_text())
    for run in result['runs']:
        owners, generation = run['owners'], run['generation']
        assert run['profile'] == 'root'
        label = f'n{owners}'
        if 'stop_log_sha256' in run:
            assert run['process_absent']
            stop_path = directory / (label + '-stop.log')
            assert sha(stop_path) == run['stop_log_sha256']
        else:
            assert retained_hold
            label = 'finally'
            stop_path = directory / 'finally-stop.log'
        state = properties(directory / (label + '-stopped.properties'))
        assert state['state'] == 'stopped' and state['mayBeActive'] == 'false'
        assert int(state['generation']) == generation
        log = stop_path.read_text()
        for owner in range(owners):
            assert re.search(rf'dns event=stop generation={generation} owner={owner} '
                             r'requests=0 codec_live_bytes=0 active_operations=0 '
                             r'tcp_active=0 tcp_owned_bytes=0', log)
        zero = [line for line in log.splitlines() if 'event=stop_native_zero ' in line]
        assert zero
        fields = dict(re.findall(r'(\w+)=(\d+)', zero[-1]))
        assert int(fields['generation']) == generation
        assert all(fields[name] == '0' for name in ('ready_mask', 'graph_enabled', 'graph_accepting',
                   'pending', 'buffers', 'obligations', 'handoffs', 'completion_frames'))
        assert not (directory / (label + '-queues-after.txt')).read_text().strip()
        assert 'SAKAMOTO_PRODUCT_' not in (directory / (label + '-hooks-after.txt')).read_text()
        assert not re.search(r'\blibvpp_runtime\.so\b',
                             (directory / (label + '-processes-after.txt')).read_text())
    summaries = []
    for case in result['cases']:
        label, source = case['label'], case['source_port']
        denied, query_drop, winner, observe = semantics(label)
        assert (case['denied'], case['query_drop'], case['winner']) == (denied, query_drop, winner), label
        plan = json.loads((directory / (label + '-plan.json')).read_text())
        requests = plan['dnsTcpQueries'] * plan['dnsTcpRepeat']
        replies = [plans[request] for request in requests]
        copies = 2 if '-coalesced-short-' in label else 1
        assert case.get('reply_copies', 1) == copies
        client = json.loads((directory / (label + '-client-open.json')).read_text())
        finished_path = directory / (label + '-client.json')
        finished = json.loads(finished_path.read_text())
        assert client['phase'] == 'dns_tcp_read_complete' and not client.get('error')
        assert finished['dnsExchanges'] == client['dnsExchanges'] and not finished.get('error')
        assert case['app_sha256'] == sha(finished_path)
        assert source == plan['source'] and case['address'] == plan['endpoint']
        assert len(client['dnsExchanges']) == len(requests)
        target = 1 if len(plan['dnsTcpQueries']) == 3 else 0
        for index, row in enumerate(client['dnsExchanges']):
            assert row['sentHex'] == requests[index]
            if denied and index >= target:
                assert row.get('timedOut') and 'replyHex' not in row
            else:
                assert row.get('replyHex') == replies[index] and not row.get('timedOut')
        accepted = target if query_drop else target + 1 if denied else len(requests)
        # Only events frozen before ordinary Socket.close qualify the UID-scoped
        # Product capture. Kernel post-close retransmissions are outside that claim.
        frozen = case['active_socket_frozen_ns']
        captured = json_lines(directory / (label + '-underlay.jsonl'))
        outbound, out_wire, out_tail = tcp_messages(captured, source, True)
        inbound, in_wire, in_tail = tcp_messages(captured, source, False)
        out_bytes, in_bytes = len(out_wire), len(in_wire)
        wire_replies = [reply for reply in replies[:accepted] for _ in range(copies)]
        assert outbound == requests[:accepted] and inbound == wire_replies
        framed = lambda values: b''.join(len(bytes.fromhex(value)).to_bytes(2, 'big')
                                         + bytes.fromhex(value) for value in values)
        assert in_tail == 0 and in_wire == framed(wire_replies)
        if query_drop:
            # Split writes preceding first-provable rejection have already left
            # the kernel. They must be an exact, incomplete prefix of that query.
            assert out_wire == framed(requests)[:out_bytes]
            assert len(framed(requests[:accepted])) <= out_bytes < len(framed(requests[:accepted + 1]))
        else:
            assert out_tail == 0 and out_wire == framed(requests[:accepted])
        assert case['wire_out']['frames'] == outbound and case['wire_in']['frames'] == inbound
        assert case['wire_out']['contiguous_bytes'] == out_bytes
        assert case['wire_out']['trailing_bytes'] == out_tail
        # The peer snapshot itself is retained in the case with its capture time;
        # each row must also occur in the independent raw log.
        seen = case['peer_messages']; sent = case['peer_replies']
        assert all(r in peer for r in seen + sent)
        assert [r['request_hex'] for r in seen] == requests[:accepted]
        assert [r['reply_hex'] for r in sent] == replies[:accepted]
        assert frozen > 0 and seen and sent
        observation = json.loads((directory / (label + '-observation.json')).read_text())
        assert observation['consumer']['query_fresh'] is True
        records = [row['record'] for row in observation['consumer']['persistent']['dns']['recent'].values()
                   if row['record']['generation'] == case['generation']
                   and row['record']['source_port'] == source]
        assert records == case['records'] and records
        query_records = records
        if case.get('query_records'):
            query_path = directory / (label + '-query-observation.json')
            query_observation = json.loads(query_path.read_text())
            assert query_observation['consumer']['query_fresh'] is True
            query_records = [row['record'] for row in query_observation['consumer']['persistent']['dns']['recent'].values()
                             if row['record']['generation'] == case['generation']
                             and row['record']['source_port'] == source]
            assert query_records == case['query_records']
            captures = json.loads((directory / (label + '-observation-captures.json')).read_text())
            assert captures and sha(directory / captures[-1]) == sha(directory / (label + '-observation.json'))
            assert all(json.loads((directory / name).read_text())['consumer']['query_fresh'] is True
                       for name in captures)
            assert query_path.stat().st_mtime_ns <= (directory / (label + '.gate')).stat().st_mtime_ns
        matching = [p for p in directory.glob('*-applied.properties') if properties(p) == case['policy']]
        assert matching, ('policy acknowledgement absent', label)
        status = verify_policy(directory, matching[0], label, result['uid'])
        assert case['policy'] == status
        if '-hot-' not in label: assert case['query_policy'] == status
        expected_coverage, expected_chain = boundary_coverage(label)
        assert case['coverage'] == expected_coverage
        target_id = (0 if '-boundary-short-' in label or '-coalesced-short-' in label else
                     int.from_bytes(bytes.fromhex(plan['dnsTcpQueries'][target])[:2], 'big'))
        stage = 1 if query_drop else 2
        decisions = [r for r in records if r['coverage'] == expected_coverage and not r['tcp_continuation']
                     and r['id'] == target_id and r['stage'] == stage]
        assert decisions, ('normal complete decision absent', label)
        for record in records:
            assert record['protocol'] == 6 and record['adapter_profile'] == 1
            assert record['family'] == (6 if ':' in plan['endpoint'] else 4)
            assert 0 <= record['owner'] < case['owner_count'] and record['incarnation'] > 0
            if record['coverage'] == 1:
                assert record['caller'] == 1 and record['uid'] == result['uid']
            if record['coverage'] >= 6:
                assert not record['domain_available'] and not record['name']
        for record in decisions:
            assert record['actual_action'] == (2 if denied else 1)
            assert record['winner'] == int(status[f'rule.{winner}.version'])
            assert record['policy_revision'] == int(status['activeRevision'])
            assert record['chain_status'] == expected_chain
            if observe: assert record['mode'] == 1 and record['declared_action'] == 2
            if stage == 2 and expected_coverage == 1 and plan['dnsTcpRepeat'] == 1:
                query, = [r for r in query_records if r['stage'] == 1 and r['coverage'] == 1
                           and not r['tcp_continuation'] and r['id'] == target_id
                           and r['message_sequence'] == record['message_sequence']]
                assert record['correlation'] == 1 and record['query_token'] == query['token']
                assert record['query_incarnation'] == query['incarnation']
                assert record['query_policy_revision'] == query['policy_revision']
                assert query['policy_revision'] == int(case['query_policy']['activeRevision'])
                if '-hot-' in label: assert record['policy_revision'] > query['policy_revision']
        if denied and len(plan['dnsTcpQueries']) == 3:
            assert any(r['tcp_continuation'] and r['actual_action'] == 2 for r in records)
        if '-continuous-' in label:
            assert len(requests) == 280 and out_bytes > 65535 and in_bytes > 65535
        if '-boundary-long-' in label:
            assert all(r['candidate_count'] == 33 for r in decisions)
            assert any(r['name'] == 'alias.test' and r['name_index'] == 32 and r['name_source'] == 1
                       for r in decisions)
        if '-boundary-overflow-' in label:
            assert all(r['candidate_count'] == 33 and not r['domain_available'] for r in decisions)
        if '-boundary-unrelated-' in label:
            assert all(r['candidate_count'] == 1 and r['name'] == 'qname.test' for r in decisions)
        if '-boundary-short-' in label or '-boundary-malformed-' in label:
            following = int.from_bytes(bytes.fromhex(plan['dnsTcpQueries'][2])[:2], 'big')
            assert any(r['stage'] == 2 and r['id'] == following and r['coverage'] == 1
                       and not r['tcp_continuation'] and r['actual_action'] == 1 for r in records)
        if '-coalesced-short-' in label:
            assert len(decisions) == 2 and {r['message_sequence'] for r in decisions} == {1, 2}
            assert len({r['token'] for r in decisions}) == 1
            assert abs(decisions[0]['tcp_sequence'] - decisions[1]['tcp_sequence']) == 5
            assert any(r.get('kind') == 'tcp' and r['destination_port'] == source
                       and r['payload_hex'] == framed(wire_replies).hex() for r in captured)
            assert len(sent) == 1 and sent[0]['frame_copies'] == 2
        summaries.append(dict(label=label, generation=case['generation'], messages=len(requests),
                              source_port=source, outbound_bytes=out_bytes, inbound_bytes=in_bytes,
                              normal_records=len(records), policy_revision=int(status['activeRevision'])))
    return result, summaries, inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directories', nargs='+', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-full', action='store_true')
    parser.add_argument('--require-boundaries', action='store_true')
    parser.add_argument('--require-coalesced', action='store_true')
    parser.add_argument('--allow-terminal-ui-hold', action='store_true',
                        help='qualify completed cases from the retained exact UI failure; never rewrites its result')
    args = parser.parse_args()
    cases, inputs, artifacts, retained_failures = [], {}, set(), []
    for directory in args.directories:
        result, rows, hashes = verify(directory.resolve(), args.allow_terminal_ui_hold)
        cases.extend(rows); inputs.update(hashes)
        if result['status'] == 'HOLD':
            retained_failures.append(dict(directory=str(directory), error=result['error'],
                                          qualified_cases=[row['label'] for row in rows]))
        artifacts.add((result['apk_sha256'], tuple(sorted(result['native_sha256'].items()))))
    assert len(artifacts) == 1, 'different artifacts cannot compose one final matrix'
    labels = [row['label'] for row in cases]
    assert len(set(labels)) == len(labels), 'duplicate qualification cases'
    if args.require_full: assert required_labels() <= set(labels), sorted(required_labels() - set(labels))
    if args.require_boundaries:
        assert required_boundaries() <= set(labels), sorted(required_boundaries() - set(labels))
    if args.require_coalesced:
        required = {f'n{owners}-coalesced-short-v{family}' for owners in (1, 3) for family in (4, 6)}
        assert set(labels) == required, sorted(required - set(labels))
    args.output.write_text(json.dumps(dict(status='PASS', scope='ordinary App / captured Root UID only',
        retained_control_failures=retained_failures,
        cases=cases, required_cases=len(required_labels()), inputs=inputs), indent=2) + '\n')
    print(f'PASS {len(cases)} cases, {sum(r["messages"] for r in cases)} messages; {len(inputs)} raw inputs')


if __name__ == '__main__': main()
