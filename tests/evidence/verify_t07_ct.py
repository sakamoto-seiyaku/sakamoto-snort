#!/usr/bin/env python3
"""Independent T07 source/packet/CT/Rank/completion evidence verifier.

No Product compiler, tracker or plan is loaded. The bounded traffic oracle is
calibrated for these fresh normal TCP handshakes and bidirectional UDP sessions;
it is not a second general TCP implementation or broader device qualification.
"""
import argparse
from collections import defaultdict
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


source_reader = module('t07_source', ROOT/'tests/evidence/verify_t06_expressions.py')
reference = module('t07_reference', ROOT/'tests/host/product_static_reference_test.py')
build_reader = module('t07_build', ROOT/'tests/evidence/verify_t01_rule.py')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def props(path):
    return dict(line.split('=', 1) for line in Path(path).read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def records(text, prefix):
    return [(index, dict(word.split('=', 1) for word in line.split()[1:] if '=' in word))
            for index, line in enumerate(text.splitlines()) if line.startswith(prefix)]


def one(rows, **identity):
    selected = [(index, row) for index, row in rows
                if all(row.get(key) == str(value) for key, value in identity.items())]
    assert len(selected) == 1, ('unique event', identity, len(selected))
    return selected[0]


def packet(admit):
    raw = bytes.fromhex(admit['raw'])
    assert raw[0] >> 4 == 4 and raw[9] in (6, 17), 'representative IPv4 TCP/UDP scope'
    offset = (raw[0] & 15)*4
    length = struct.unpack_from('!H', raw, 2)[0]
    assert offset >= 20 and len(raw) <= length and int(admit['packet_length']) == length
    sport, dport = struct.unpack_from('!HH', raw, offset)
    source, destination = (str(ipaddress.ip_address(raw[a:b])) for a, b in ((12, 16), (16, 20)))
    assert (int(admit['src_port']), int(admit['dst_port'])) == (sport, dport), 'current port projection'
    assert bytes.fromhex(admit['src'])[-4:] == raw[12:16] and bytes.fromhex(admit['dst'])[-4:] == raw[16:20], 'current IP projection'
    flags = raw[offset+13] if raw[9] == 6 else 0
    header = (raw[offset+12] >> 4)*4 if raw[9] == 6 else 8
    assert len(raw) >= offset+header
    if raw[9] == 6:
        assert flags == int(admit['tcp_flags'])
        assert struct.unpack_from('!II', raw, offset+4) == (int(admit['tcp_seq']), int(admit['tcp_ack']))
    available = int(admit['availability'])
    facts = dict(uid=int(admit['uid']) if available & 1 else None, family=4, protocol=raw[9],
                 direction=int(admit['direction']) if int(admit['direction']) in (1, 3) else None,
                 network=int(admit['context']) if available & 4 else None,
                 interface=int(admit['ifindex']) if available & 2 else None,
                 src=source, dst=destination, sport=sport, dport=dport)
    return facts, flags, raw[offset+header:]


def configurations(directory, run, pixel):
    answer = {}
    for entry in run['configurations']:
        path = directory/entry['source']
        source = source_reader.source(path)
        assert source['revision'] == entry['revision'], 'source revision identity'
        source_reader.query_source(source, props(directory/entry['query']), pixel)
        label = entry['label']
        expected_expression = '0d020e0101' if '-state-' in label or label.startswith('race-') else '0e02'
        mode = 1 if label.endswith(('-observe', '-recover')) else 0
        priority = 0 if label.endswith('static-first') else 100
        protocol = 17 if label.startswith(('udp-', 'race-')) else 6
        assert entry['expression'] == expected_expression and entry['mode'] == mode
        assert entry['static_priority'] == priority and entry['protocol'] == protocol
        dynamic, static = source['rules']
        assert dynamic['expression'].hex() == expected_expression, 'agreed CT/direction condition'
        assert dynamic['uid'] == 0xffffffff and dynamic['priority'] == 10 and dynamic['action'] == 2
        assert static['priority'] == priority and static['action'] == 1 and not static['expression']
        assert all(rule['protocol'] == protocol and rule['direction'] == 0 for rule in source['rules'])
        assert source['groups'] == [10] and source['edges'] == [(10, 1, 0)]
        uid = run['uid'] if pixel else 12001
        assert static['uid'] == uid and source['bindings'] == [(1, uid, 2, 10, mode)], 'source attribution and mode'
        key = (entry.get('profile', 'root'), source['revision'])
        assert key not in answer
        answer[key] = (source, source_reader.snapshot_hash(path))
    assert len(answer) == (14 if pixel else 17), 'complete configuration sequence'
    return answer


def verify_trace(text, profile, generation, ports, configs, uid):
    prefixes = {
        'acquire': 's209 event=acquire ', 'release': 's209 event=release ',
        'match': 's209 event=l4 ', 'flow': 's208 event=observe ',
        'tcp': 's222 event=tcp_update ', 'udp': 's223 event=udp_update ',
        'free': 's203 event=buffer_free ', 'verdict': 's242 event=verdict_syscall ',
        'completion': 's213 event=completion ', 'copy': 's237 event=input_copy ',
    }
    rows = {name: records(text, prefix) for name, prefix in prefixes.items()}
    selected = []
    for admit_index, admit in records(text, 's216 stage=admit '):
        if int(admit.get('protocol', 0)) not in (6, 17):
            continue
        facts, flags, payload = packet(admit)
        if not ({facts['sport'], facts['dport']} & set(ports) and 40610 in (facts['sport'], facts['dport'])):
            continue
        assert admit['generation'] == str(generation), 'packet/runtime generation'
        token = admit['token']
        acquire_index, acquire = one(rows['acquire'], token=token, generation=generation)
        match_index, match = one(rows['match'], token=token, generation=generation)
        release_index, release = one(rows['release'], token=token, generation=generation)
        flow_index, flow = one(rows['flow'], token=token, generation=generation)
        tracker_index, tracker = one(rows['tcp' if facts['protocol'] == 6 else 'udp'], token=token, generation=generation)
        assert acquire_index < flow_index < tracker_index < release_index, 'one protected owner observation'
        assert int(flow['worker']) == int(admit['owner']) == int(acquire['worker'])
        assert int(flow['thread']) == int(flow['worker'])+1 and flow['pool_worker'] == flow['worker']
        assert tracker['owner'] == admit['owner'] and flow['status'] == '0'
        identity = tuple(acquire[name] for name in ('generation', 'revision', 'snapshot_hash'))
        assert tuple(match[name] for name in ('generation', 'revision', 'snapshot_hash')) == identity, 'matcher mixed snapshot'
        assert tuple(flow[name] for name in ('generation', 'revision', 'snapshot_hash')) == identity, 'Flow mixed snapshot'
        assert tuple(release[name] for name in ('generation', 'revision', 'snapshot_hash')) == identity, 'release mixed snapshot'
        assert tuple(release['content_'+name] for name in ('generation', 'revision', 'hash')) == identity, 'retired bank mutated'
        config, expected_hash = configs[(profile, int(match['revision']))]
        assert int(match['snapshot_hash']) == expected_hash, 'saved-source snapshot hash'
        selected.append(dict(admit=admit, facts=facts, flags=flags, payload=payload, token=token,
                             match=match, flow=flow, tracker=tracker, acquire=acquire, release=release,
                             flow_index=flow_index, match_index=match_index, tracker_index=tracker_index,
                             config=config))
    assert selected, 'real packet evidence missing'
    sessions = {}
    totals = defaultdict(int)
    for value in sorted(selected, key=lambda p: p['flow_index']):
        facts, flags = value['facts'], value['flags']
        endpoints = ((facts['src'], facts['sport']), (facts['dst'], facts['dport']))
        key = (facts['protocol'], tuple(sorted(endpoints)))
        tracker, flow, match = value['tracker'], value['flow'], value['match']
        if key not in sessions:
            assert flow['created'] == '1' and tracker['created'] == '1', 'fresh tracked session'
            if facts['protocol'] == 6:
                assert flags == 2, 'TCP oracle requires a captured fresh SYN'
            sessions[key] = dict(origin=endpoints, reply=False, incarnation=tracker['incarnation'],
                                 packets=0, revisions=set(), states=set(), directions=set(), drops=0,
                                 source_port=next(port for port in ports if port in (facts['sport'], facts['dport'])))
        session = sessions[key]
        direction = 1 if endpoints == session['origin'] else 2
        assert direction == 1 or endpoints == session['origin'][::-1], 'reply endpoints'
        session['reply'] |= direction == 2
        # Fresh normal TCP: SYN is NEW; SYN+ACK and the remaining valid
        # ACK/data/close sequence are ESTABLISHED. UDP becomes established
        # on the first reverse datagram. These expectations do not read CT output.
        state = (1 if flags == 2 else 2) if facts['protocol'] == 6 else (2 if session['reply'] else 1)
        if facts['uid'] == uid:
            assert tracker['ct_state'] == str(state) and tracker['flow_dir'] == str(direction), 'independent CT facts'
            assert match['ct_state'] == str(state) and match['flow_dir'] == str(direction), 'matcher facts availability'
            assert value['tracker_index'] < value['match_index'], 'affected complete view must be post-flow'
        else:
            assert facts['uid'] is None, 'unexpected application subject'
            assert match['ct_state'] == match['flow_dir'] == '0'
        assert tracker['incarnation'] == session['incarnation'], 'policy update changed Flow identity'
        session['packets'] += 1
        assert int(flow['packets']) == session['packets'], 'observation missing, duplicated or rolled back'
        assert int(tracker['orig_packets'])+int(tracker['reply_packets']) == session['packets']
        assert int(flow['flow_dir']) == direction and int(flow['device_dir']) == facts['direction']
        facts.update(ct=state, flowdir=direction)
        expected = reference.ordered_reference(source_reader.logical_rules(value['config'], facts['uid']), facts)
        for wanted, actual in [('rule_id', 'rule'), ('action', 'action'), ('actual_action', 'actual_action')]:
            assert int(match[actual]) == expected[wanted], ('logical reference', actual, value['token'])
        if expected['rule_id']:
            for wanted, actual in [('winner_rank', 'rank'), ('mode', 'mode')]:
                assert int(match[actual]) == expected[wanted], ('logical attribution', actual)
            totals['logical_hits'] += 1
        assert int(match['candidates']) == len(source_reader.effective(value['config'], facts['uid']))
        assert match['status'] == '0', 'incomplete matching is not NoMatch'
        drop = expected['actual_action'] == 2
        totals['actual_drops'] += drop
        totals['packets'] += 1
        session['revisions'].add(int(match['revision'])); session['states'].add(state)
        session['directions'].add(direction); session['drops'] += drop
        one(rows['free'], obligation=value['token'])
        if profile == 'root':
            assert value['admit']['source'] == 'NFQ_CAPTURED'
            _, verdict = one(rows['verdict'], token=value['token'], generation=generation)
            assert verdict['packet'] == value['admit']['packet_id'] and int(verdict['result']) >= 0
            assert int(verdict['verdict']) == int(not drop), 'actual NFQUEUE verdict'
        else:
            source = value['admit']['source']
            assert source in ('TUN_CAPTURED', 'FLOW_STACK_RETURN')
            _, completion = one(rows['completion'], token=value['token'], source=source)
            assert int(completion['policy_drop']) == int(drop), 'actual VPN completion'
            copies = [row for _, row in rows['copy'] if row.get('token') == value['token']]
            assert len(copies) == int(source == 'TUN_CAPTURED' and not drop), 'normal owner-local forwarding, no test bypass'
            if copies:
                assert copies[0]['result'] == '0' and copies[0]['owner'] == value['admit']['owner']
        value['expected'] = expected
    assert {s['source_port'] for s in sessions.values()} == set(ports), 'all real sessions'
    for session in sessions.values():
        assert session['states'] == {1, 2} and session['directions'] == {1, 2}, 'state/direction transitions'
    return selected, sessions, dict(totals)


def query_observation(query, pixel, trace):
    """A query must correspond to a real prefix of logical packet accounting."""
    names = ('logicalHits','actualDrops','winnerVersion','winnerRevision','winnerAction','verdict') if pixel else (
        'query.logical_hits','query.actual_drops','query.winner_version','query.winner_revision','query.winner_action','query.verdict')
    wanted = tuple(int(query[name]) for name in names)
    hits = drops = 0
    for _, row in records(trace, 's209 event=l4 '):
        if int(row['rule']):
            hits += 1
            drops += row['actual_action'] == '2'
            observed = (hits,drops,int(row['rule']),int(row['revision']),int(row['action']),int(row['actual_action']))
            if observed == wanted:
                return
    assert wanted[:5] == (0,0,0,0,0), 'query winner/action/counters lack a matching packet prefix'


def verify(directory):
    directory = Path(directory)
    run = json.loads((directory/'result.json').read_text())
    pixel = 'serial' in run
    assert run['status'] == 'RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build = build_reader.verify_product_build(run['build'])
    assert digest(run['build']) == run['build_sha256'] and build['source_sha256'] == run['source_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert digest(directory/'runner.py') == run['runner_sha256'] and digest(directory/'socket-peer.py') == run['peer_sha256']
    configs = configurations(directory, run, pixel)
    endpoints = [json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoints[0]['kind'] == 'ready' and endpoints[0]['port'] == 40610
    summary = {}
    if pixel:
        assert digest(build['apk']) == build['apk_sha256'] == (directory/'installed-apk.txt').read_text().split()[0]
        installed = {Path(line.split()[1]).name: line.split()[0]
                     for line in (directory/'installed-native.txt').read_text().splitlines()}
        assert installed == build['native_sha256'], 'installed artifact closure'
        assert [c['label'] for c in run['cases']] == [f'{p}-{c}' for p in ('root', 'vpn') for c in ('state', 'direction', 'static-first')]
        streams = defaultdict(bytes)
        for event in endpoints:
            if event['kind'] == 'tcp_recv':
                streams[tuple(event['peer'])] += bytes.fromhex(event['data'])
        for life in run['lifetimes']:
            profile = life['profile']; generation = life['generation']
            running = props(directory/(profile+'-running.properties'))
            stopped = props(directory/(profile+'-stopped.properties'))
            assert running['generation'] == str(generation) and running['profile'] == profile and running['state'] == 'running'
            assert running['protectionRunning'] == ('true' if profile == 'root' else 'false')
            assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == stopped['protectionRunning'] == 'false' and life['process_absent']
            assert not (directory/(profile+'-queues-after.txt')).read_text().strip()
            assert 'SAKAMOTO' not in (directory/(profile+'-hooks-after.txt')).read_text()
            process = (directory/(profile+'-process.txt')).read_text()
            uids = next(line for line in process.splitlines() if line.startswith('Uid:')).split()[1:]
            assert set(map(int, uids)) == {0 if profile == 'root' else run['uid']}, 'actual runtime UID'
            trace = (directory/(profile+'-stop.log')).read_text()
            if profile == 'root':
                zero = [row for _, row in records(trace, 's242 event=stop_native_zero ')]
                assert zero and all(zero[-1][key] == '0' for key in ('pending','buffers','obligations','handoffs','completion_frames'))
            else:
                stopped_owners = [row for _, row in records(trace, 's237 event=owner_stopped ')]
                assert len(stopped_owners) == 2 and {row['owner'] for row in stopped_owners} == {'0','1'}
                for row in stopped_owners:
                    assert all(row[key] == '0' for key in ('sessions','inputs','pbufs','buffers','obligations','frames'))
                    assert row['sockets_created'] == row['sockets_closed'] and row['timer_fd'] == row['broker_fd'] == '-1'
            cases = [case for case in run['cases'] if case['profile'] == profile]
            packets, sessions, totals = verify_trace(trace, profile, generation, [case['port'] for case in cases], configs, run['uid'])
            summary[profile] = totals
            for case in cases:
                report = json.loads((directory/(case['label']+'-result.json')).read_text())
                assert report['nonce'] == case['nonce'] and report['uid'] == run['uid'] and report['plan'] == case['plan']
                flow = report['flows'][0]
                assert not report.get('error') and not flow.get('error')
                assert flow['source'] == case['port'] and flow['echoes'] == 3 and flow['echoBytes'] == 768
                assert flow['remoteEof'] and flow['outcome'] == 'echo_closed'
                expected_data = b''
                for round_number in range(3):
                    prefix = f"{case['nonce']}_0:{round_number}:".encode()
                    expected_data += prefix+b'a'*(256-len(prefix))
                assert list(streams.values()).count(expected_data) == 1, 'independent complete endpoint payload'
                observed = [p for p in packets if case['port'] in (p['facts']['sport'], p['facts']['dport'])]
                assert any(case['nonce'].encode() in p['payload'] for p in observed), 'application payload on actual graph'
                session = next(s for s in sessions.values() if s['source_port'] == case['port'])
                query = props(directory/case['query'])
                query_observation(query, True, trace)
                assert int(query['logicalHits']) >= sum(bool(p['expected']['rule_id']) for p in observed)
                if case['mode'] == 'policy':
                    assert flow['timeouts'] >= 1 and session['drops'] > 0
                    first = json.loads((directory/(case['label']+'-first_echo.json')).read_text())
                    blocked = json.loads((directory/(case['label']+'-return_timeout.json')).read_text())
                    assert first['echoes'] == blocked['echoes'] == 1 and blocked['timeouts'] >= 1
                    assert first['connectedMs'] == blocked['connectedMs'] == flow['connectedMs']
                    assert first['local'] == blocked['local'] == flow['local'], 'same real TCP socket across updates'
                    assert {case[name] for name in ('initial_revision', 'blocked_revision', 'recovered_revision')} <= session['revisions']
                    dropped = [p for p in observed if p['expected']['actual_action'] == 2]
                    assert all(int(p['match']['revision']) == case['blocked_revision'] for p in dropped)
                    assert any(case['nonce'].encode() in p['payload'] for p in dropped), 'condition blocks real data'
                    assert any(int(p['match']['revision']) == case['recovered_revision'] and p['expected']['actual_action'] == 1
                               and case['nonce'].encode() in p['payload'] for p in observed), 'same-flow recovery packet'
                    q = props(directory/case['blocked_query']); before = props(directory/case['before'])
                    query_observation(q, True, trace); query_observation(before, True, trace)
                    assert int(q['actualDrops']) > int(before['actualDrops']), 'query distinguishes actual CT drops'
                else:
                    assert not flow['timeouts'] and not session['drops']
                    assert all(p['expected']['winner_rank'] == 1 and p['expected']['action'] == 1 for p in observed), 'static high Rank must win'
    else:
        artifact = Path(run['artifact'])
        for name, expected in build['artifact_hashes'].items():
            assert digest(artifact/name) == expected, 'Product artifact closure'
        assert digest(artifact/'product-vpp-artifact.properties') == run['manifest_sha256']
        session_helper = run['rule_session']
        assert digest(session_helper['path']) == session_helper['sha256']
        assert digest(directory/'rule-session.c') == session_helper['source_sha256']
        helper_path = Path(session_helper['path'])
        helper_build = json.loads(helper_path.with_name('t07-rule-session-build.json').read_text())
        assert helper_build['binary_sha256'] == session_helper['sha256'] and helper_build['source_sha256'] == session_helper['source_sha256']
        assert helper_build['core_sha256'] == build['control_hashes']['control/libsakamoto_product_core.so']
        assert digest(helper_path.with_name('libsakamoto_product_core.so')) == helper_build['core_sha256']
        assert 'NFQUEUE' not in (directory/'hooks-after.txt').read_text()
        assert props(directory/'first-stopped.txt')['absent'] == 'True'
        assert 'root.stop=ok' in (directory/'first-stop.txt').read_text()
        assert str(artifact/'bin/vpp') in (directory/'first-process.txt').read_text()
        trace = (directory/'first-vpp.log').read_text()
        packets, sessions, totals = verify_trace(trace, 'root', run['generation'], [43100, 43101, 43102, 43200, 43201, 43202, 43300], configs, 12001)
        summary['linux'] = totals
        q = props(directory/'final-query.txt')
        query_observation(q, False, trace)
        assert int(q['query.logical_hits']) == totals['logical_hits'] and int(q['query.actual_drops']) == totals['actual_drops'], 'query accounting joins actual decisions'
        assert len(run['cases']) == 16
        for case in run['cases']:
            query_observation(props(directory/case['query']), False, trace)
            query_observation(props(directory/case['before']), False, trace)
            response = case['response']
            assert (response['kind'] == 'received') == case['delivered']
            if case['delivered']:
                assert bytes.fromhex(response['data']) == case['nonce'].encode()
                assert any(case['nonce'].encode() in bytes.fromhex(e.get('data', '')) for e in endpoints), 'independent endpoint delivery'
            else:
                assert response['kind'] == 'timeout' and not response['data']
                dropped = [p for p in packets if case['nonce'].encode() in p['payload'] and p['expected']['actual_action'] == 2]
                assert dropped and all(int(p['match']['revision']) == case['revision'] for p in dropped), 'expected current CT drop'
        for port in (43100, 43101, 43200, 43201):
            session = next(s for s in sessions.values() if s['source_port'] == port)
            assert session['drops'] > 0 and len(session['revisions']) >= 3, 'retained Flow across live updates'
        for port in (43102, 43202):
            session = next(s for s in sessions.values() if s['source_port'] == port)
            assert session['drops'] == 0
        race = run['race']
        held = [p for p in packets if race['nonce'].encode() in p['payload']]
        assert len(held) == 1 and held[0]['expected']['actual_action'] == 2, 'held old view verdict'
        assert int(held[0]['match']['revision']) == race['old_revision'] < race['new_revision']
        assert int(held[0]['release']['published_sequence']) > int(held[0]['acquire']['sequence']), 'real publication during reader lifetime'
        publication = json.loads((directory/'race-session-publication.json').read_text())
        assert int(held[0]['acquire']['mono_ns']) < publication['started_ns'] < publication['completed_ns'] < int(held[0]['release']['mono_ns'])
        assert publication['active_revision'] == publication['saved_revision'] == race['new_revision']
        assert not any(race['nonce'].encode() in bytes.fromhex(e.get('data', '')) for e in endpoints)
        zero = [r for _, r in records(trace, 's242 event=stop_native_zero ')]
        assert any(all(r.get(k) == '0' for k in ('pending', 'buffers', 'obligations', 'handoffs', 'completion_frames')) for r in zero), 'native debt cleanup'
    return dict(status='PASS', scope='T07 representative CT TCP/UDP' if not pixel else 'T07 Pixel IPv4 TCP Root/VPN',
                run=str(directory), totals=summary, source_sha256=run['source_sha256'], verifier_sha256=digest(__file__))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('directory'); parser.add_argument('--output')
    args = parser.parse_args()
    try:
        result = verify(args.directory)
    except (AssertionError, KeyError, ValueError, OSError, IndexError, StopIteration) as error:
        result = dict(status='HOLD', error=str(error), run=args.directory, verifier_sha256=digest(__file__))
    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    if result['status'] != 'PASS':
        raise SystemExit(1)
