#!/usr/bin/env python3
"""Independent T08 source/packet/CT/Rank/completion evidence verifier.

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


source_reader = module('t08_source', ROOT/'tests/evidence/verify_t06_expressions.py')
reference = module('t08_reference', ROOT/'tests/host/product_static_reference_test.py')
build_reader = module('t08_build', ROOT/'tests/evidence/verify_t01_rule.py')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def props(path):
    return dict(line.split('=', 1) for line in Path(path).read_text().splitlines()
                if '=' in line and not line.startswith('#'))


def records(text, prefix):
    return [(index, dict(word.split('=', 1) for word in line.split()[1:] if '=' in word))
            for index, line in enumerate(text.splitlines()) if line.startswith(prefix)]


def claimed_probe_tokens(text, run, profile='root'):
    """Select only the representative endpoint traffic, excluding port reuse."""
    pixel='serial' in run
    ports={str(case['port']) for case in run['cases'] if case.get('profile','root')==profile}
    return {row['token'] for _,row in records(text,'s216 stage=admit ')
            if row.get('uid')==str(run['uid'] if pixel else 12001)
            and ((row.get('src_port') in ports and row.get('dst_port')=='40610')
                 or (row.get('dst_port') in ports and row.get('src_port')=='40610'))
            and row.get('protocol') in (('6',) if pixel else ('6','17'))}


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
        path = directory/entry['source']; source = source_reader.source(path)
        assert source['revision'] == entry['revision']
        source_reader.query_source(source, props(directory/entry['query']), pixel)
        scenario = entry['scenario']; mode = entry['mode']
        assert scenario in ('chain','early-drop','static-first')
        expected = ([(10,2,'0d020ca09ea09e01',0),(20,1,'0ca09ea19e',0),
                     (30,2,'0ca19ea29e',mode),(40,1,'',0)] if scenario == 'chain' else
                    [(0,2,'',mode),(10,2,'0e02',0)] if scenario == 'early-drop' else
                    [(0,1,'',0),(10,2,'0e02',0)])
        assert len(source['rules']) == len(expected)
        uid = run['uid'] if pixel else 12001
        for index,(rule,(priority,action,expression,effective_mode)) in enumerate(zip(source['rules'],expected)):
            assert rule['priority']==priority and rule['action']==action and rule['expression'].hex()==expression
            assert rule['uid']==0xffffffff and rule['protocol']==entry['protocol'] and rule['direction']==0
            assert source['bindings'][index]==(index+1,uid,1,index,effective_mode)
        assert not source['groups'] and not source['edges']
        key=(entry.get('profile','root'),source['revision']);assert key not in answer
        answer[key]=(source,source_reader.snapshot_hash(path),scenario)
    assert len(answer)==(14 if pixel else 17), 'complete configuration sequence'
    return answer


def verify_trace(text, profile, generation, ports, configs, uid, baseline=False):
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
        if int(admit.get('protocol', 0)) not in (6, 17) or bytes.fromhex(admit['raw'])[0] >> 4 != 4:
            continue
        facts, flags, payload = packet(admit)
        if not ({facts['sport'], facts['dport']} & set(ports) and 40610 in (facts['sport'], facts['dport'])):
            continue
        assert admit['generation'] == str(generation), 'packet/runtime generation'
        token = admit['token']
        acquire_index, acquire = one(rows['acquire'], token=token, generation=generation)
        match_index, match = one(rows['match'], token=token, generation=generation)
        release_index, release = one(rows['release'], token=token, generation=generation)
        flow_rows = [(i,r) for i,r in rows['flow'] if r.get('token')==token and r.get('generation')==str(generation)]
        tracker_rows = [(i,r) for i,r in rows['tcp' if facts['protocol']==6 else 'udp'] if r.get('token')==token and r.get('generation')==str(generation)]
        assert len(flow_rows)==len(tracker_rows)<=1, 'exactly zero or one Flow observation'
        flow_index,flow=flow_rows[0] if flow_rows else (None,None)
        tracker_index,tracker=tracker_rows[0] if tracker_rows else (None,None)
        identity=tuple(acquire[name] for name in ('generation','revision','snapshot_hash'))
        assert tuple(match[name] for name in ('generation','revision','snapshot_hash'))==identity
        assert tuple(release[name] for name in ('generation','revision','snapshot_hash'))==identity
        assert tuple(release['content_'+name] for name in ('generation','revision','hash'))==identity
        assert acquire_index < match_index < release_index
        if flow:
            assert acquire_index < flow_index < tracker_index < release_index
            assert int(flow['worker'])==int(admit['owner'])==int(acquire['worker'])
            assert int(flow['thread'])==int(flow['worker'])+1 and flow['pool_worker']==flow['worker']
            assert tracker['owner']==admit['owner'] and flow['status']=='0'
            assert tuple(flow[name] for name in ('generation','revision','snapshot_hash'))==identity
        config,expected_hash,scenario=configs[(profile,int(match['revision']))]
        assert int(match['snapshot_hash'])==expected_hash
        selected.append(dict(admit=admit,facts=facts,flags=flags,payload=payload,token=token,
            match=match,flow=flow,tracker=tracker,acquire=acquire,release=release,
            flow_index=flow_index,match_index=match_index,tracker_index=tracker_index,
            config=config,scenario=scenario))
    assert selected, 'real packet evidence missing'
    sessions = {}
    totals = defaultdict(int)
    for value in sorted(selected, key=lambda p: p['match_index']):
        facts, flags = value['facts'], value['flags']
        endpoints = ((facts['src'], facts['sport']), (facts['dst'], facts['dport']))
        key = (facts['protocol'], tuple(sorted(endpoints)))
        tracker, flow, match = value['tracker'], value['flow'], value['match']
        if key not in sessions:
            assert flow and flow['created']=='1' and tracker['created']=='1', 'fresh tracked session'
            if facts['protocol']==6: assert flags==2, 'captured fresh SYN'
            sessions[key]=dict(origin=endpoints,reply=False,incarnation=tracker['incarnation'],
                packets=0,revisions=set(),states=set(),directions=set(),drops=0,early_drops=0,
                source_port=next(port for port in ports if port in (facts['sport'],facts['dport'])))
        session=sessions[key]
        direction=1 if endpoints==session['origin'] else 2
        assert direction==1 or endpoints==session['origin'][::-1]
        state=(1 if flags==2 else 2) if facts['protocol']==6 else (2 if session['reply'] or direction==2 else 1)
        position=2 if baseline and facts['uid']==uid else (1 if baseline else int(match['position']))
        if facts['uid']==uid:
            wanted_position=2 if baseline or value['scenario']=='chain' else 1
            assert position==wanted_position, 'whole-rule placement including indirect propagation'
        if flow:
            session['reply'] |= direction==2
            assert tracker['ct_state']==str(state) and tracker['flow_dir']==str(direction)
            assert tracker['incarnation']==session['incarnation'], 'Flow identity survived updates'
            session['packets']+=1
            assert int(flow['packets'])==session['packets'], 'early DROP must not refresh existing Flow counters'
            assert int(tracker['orig_packets'])+int(tracker['reply_packets'])==session['packets']
            assert int(flow['flow_dir'])==direction and int(flow['device_dir'])==facts['direction']
            if position==2:
                assert value['tracker_index'] < value['match_index']
                assert match['ct_state']==str(state) and match['flow_dir']==str(direction)
            else:
                assert value['match_index'] < value['flow_index']
                assert match['ct_state']==match['flow_dir']=='0'
        else:
            assert position==1 and match['actual_action']=='2', 'only true early DROP skips Flow'
            assert match['ct_state']==match['flow_dir']=='0'
            session['early_drops']+=1
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


def unchanged_flow_query(directory, before, after, port, protocol=6, uid=None):
    """True early DROP preserves existing entry, tracker and expiry deadline."""
    def selected(name):
        text=(directory/name).read_text()
        entries=[row for _,row in records(text,'flow.entry ')
                 if {str(port),'40610'} == {row['port_a'],row['port_b']}
                 and row['protocol']==str(protocol) and (uid is None or row['uid']==str(uid))]
        assert len(entries)==1, 'authoritative existing Flow query'
        entry=entries[0]
        other={prefix: [row for _,row in records(text,prefix)
                       if row['worker']==entry['worker'] and row['slot']==entry['slot']]
               for prefix in ('flow.timer ','flow.tcp ')}
        assert len(other['flow.timer '])==1
        # Other live flows may reorder the shared timer heap. Deadline, timeout
        # and incarnation must stay fixed; the internal array position need not.
        other['flow.timer ']=[{k:value for k,value in row.items() if k!='heap_position'}
                              for row in other['flow.timer ']]
        return entry,other
    assert selected(before)==selected(after), 'early DROP changed Flow/CT/activity/expiry/attribution'


def verify(directory):
    directory = Path(directory)
    run = json.loads((directory/'result.json').read_text())
    pixel = 'serial' in run
    run['baseline'] = run['source_sha256'] == '6f129ee294adae922746ebbbe5cad78b19a3cfde49dbcf48a314aae519382930'
    assert run['status'] == 'RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    if run.get('baseline') or run['source_sha256'] == '43bae86c42a14f1c6370338cd3896a5dc906f1b922b5a3de7440adbc37872133':
        build_path=Path(run['build']);build=json.loads(build_path.read_text())
        assert build['source_sha256']==run['source_sha256'], 'pinned T07/T08 comparator'
        assert hashlib.sha256(json.dumps(build['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()==build['source_sha256']
        for name,expected in build['files'].items():
            if expected is not None: assert digest(build_path.parent/'source'/name)==expected
    else: build = build_reader.verify_product_build(run['build'])
    assert digest(run['build']) == run['build_sha256'] and build['source_sha256'] == run['source_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert digest(directory/'runner.py') == run['runner_sha256'] and digest(directory/'socket-peer.py') == run['peer_sha256']
    if not run.get('baseline'):
        assert digest(directory/'rule-request-helper.py') == run['rule_helper_sha256'], 'request helper identity'
    configs = configurations(directory, run, pixel)
    endpoints = [json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoints[0]['kind'] == 'ready' and endpoints[0]['port'] == 40610
    summary = {}
    if pixel:
        assert digest(build['apk']) == build['apk_sha256'] == (directory/'installed-apk.txt').read_text().split()[0]
        installed = {Path(line.split()[1]).name: line.split()[0]
                     for line in (directory/'installed-native.txt').read_text().splitlines()}
        assert installed == build['native_sha256'], 'installed artifact closure'
        assert [c['label'] for c in run['cases']] == [f'{p}-{c}' for p in ('root', 'vpn') for c in ('chain', 'early-drop', 'static-first')]
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
            packets, sessions, totals = verify_trace(trace, profile, generation, [case['port'] for case in cases], configs, run['uid'], run.get('baseline',False))
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
                    if case['label'].endswith('early-drop') and not run.get('baseline'):
                        assert session['early_drops']>0
                        unchanged_flow_query(directory,case['label']+'-initial-flow.txt',
                                             case['label']+'-blocked-flow.txt',case['port'],6,run['uid'])
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
        helper_build = json.loads(helper_path.with_name('t08-rule-session-build.json').read_text())
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
        assert all(next(s for s in sessions.values() if s['source_port']==port)['early_drops']>0 for port in (43101,43201,43300))
        for protocol,port in [('tcp',43101),('udp',43201)]:
            unchanged_flow_query(directory,protocol+'-early-drop-initial-flow.txt',
                                 protocol+'-early-drop-blocked-flow.txt',port,6 if protocol=='tcp' else 17,12001)
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
    return dict(status='PASS', scope='T08 representative placement TCP/UDP' if not pixel else 'T08 Pixel IPv4 TCP Root/VPN',
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
