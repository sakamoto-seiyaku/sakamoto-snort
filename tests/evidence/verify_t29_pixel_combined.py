#!/usr/bin/env python3
"""Independent Product/packet/UI oracle for T29's Root and controlled VPN run."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

p = argparse.ArgumentParser()
p.add_argument('--run', type=Path, required=True)
p.add_argument('--build', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--require-ui', action='store_true')
a = p.parse_args()
run, build_path = a.run.resolve(), a.build.resolve()
digest = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
read = lambda name: (run / name).read_text()
data = lambda name: json.loads(read(name))
props = lambda name: dict(line.split('=', 1) for line in read(name).splitlines() if '=' in line and not line.startswith('#'))
rows = lambda name, prefix: [dict(part.split('=', 1) for part in line.split()[1:] if '=' in part)
                              for line in read(name).splitlines() if line.startswith(prefix)]
events = lambda name: [json.loads(line) for line in read(name).splitlines() if line.startswith('{')]
build = json.loads(build_path.read_text())
result = data('result.json')
assert result['status'] == 'RAW_COMPLETE' and result['process_absent']
assert not result.get('cleanup_error') and not result.get('cleanup_config_error')
assert result['task'] == 'T29' and result['ordinary_history_unchanged'] is True
assert result['source_sha256'] == build['source_sha256']
assert result['build_sha256'] == digest(build_path) and result['runner_sha256'] == digest(run / 'runner.py')
assert digest(build['apk']) == build['apk_sha256'] == read('installed-apk.txt').split()[0]
with zipfile.ZipFile(build['apk']) as archive:
    native = {Path(name).name:hashlib.sha256(archive.read(name)).hexdigest()
              for name in archive.namelist() if name.startswith('lib/arm64-v8a/') and name.endswith('.so')}
assert native == build['native_sha256']
installed = {Path(line.split()[1]).name:line.split()[0] for line in read('installed-native.txt').splitlines()}
assert installed == native
assert data('before-ordinary-hashes.json') == data('after-ordinary-hashes.json')
assert result['cleared_profiles'] == ['root', 'vpn']
assert len(result['lifetimes']) == 2 and len({x['generation'] for x in result['lifetimes']}) == 2
assert [x['profile'] for x in result['capacity_rejections']] == ['root','vpn']
assert len({x['nonce'] for x in result['capacity_rejections']}) == 2
for rejected in result['capacity_rejections']:
    response = data(rejected['result'])
    assert response['nonce'] == rejected['nonce'] and response['phase'] == 'finished'
    assert response['error'] == rejected['error'] == 'protocol_probe_capacity'
assert '0 packets dropped by kernel' in read('host-capture.log')
assert '0 packets dropped by kernel' in read('device-capture.log')

def packets(name):
    fields = ('ip.src','ip.dst','udp.srcport','udp.dstport','udp.payload')
    cmd = ['tshark','-r',str(run / (name + '.pcap')),'-Y','udp.port==5004 or udp.port==40650','-T','fields']
    for field in fields:cmd += ['-e',field]
    text = subprocess.check_output(cmd,text=True,stderr=subprocess.DEVNULL)
    return [line.split('\t') for line in text.splitlines() if line.count('\t') == 4]
host, device = packets('host'), packets('device')
host_payloads = {row[4] for row in host}
device_payloads = {row[4] for row in device}
rtp_endpoint = events('endpoint.jsonl')
quic_endpoint = events('quic-endpoint.jsonl')
profiles = {}
for profile, quic_port, rtp_port in (('root',46330,46310),('vpn',46430,46410)):
    assert not any(row[2] == str(rtp_port+40) for row in host+device)
    life = next(x for x in result['lifetimes'] if x['profile'] == profile)
    assert life['process_absent']
    generation = life['generation']
    state = props(profile + '-running.properties')
    assert int(state['generation']) == generation and state['profile'] == profile
    assert state['protectionRunning'] == ('true' if profile == 'root' else 'false')
    if profile == 'vpn':assert state['adapterReadiness'] == 'unavailable'
    configs = [x for x in result['configurations'] if x['profile'] == profile]
    assert len(configs) == 3
    revisions = [x['revision'] for x in configs]
    assert revisions == list(range(revisions[0], revisions[0] + 3))
    queried = [props(x['query']) for x in configs]
    for cfg, query in zip(configs, queried):
        assert int(query['savedRevision']) == int(query['activeRevision']) == cfg['revision']
        assert query['result'] == '0' and query['activeCount'] == query['effectiveRules'] == '4'
        assert query['domain.0.name'] == 'example.test'
        assert '0d020ff903000001' in read(cfg['label']+'-request.txt')
        assert (run / cfg['source']).read_bytes().startswith(b'SKRULE')
    rtp_rule, quic_rule = queried[0]['rule.0.version'], queried[0]['rule.3.version']
    assert all(q['rule.0.version'] == rtp_rule and q['rule.3.version'] == quic_rule for q in queried)
    assert rtp_rule != quic_rule

    identities = {}
    checks = [(profile+'-quic-ready',quic_port,revisions[0],1,quic_rule),
              (profile+'-quic-budget',quic_port,revisions[1],1,quic_rule),
              (profile+'-rtp-added',rtp_port,revisions[0],1,rtp_rule),
              (profile+'-rtp-blocked',rtp_port,revisions[1],2,rtp_rule),
              (profile+'-rtp-budget',rtp_port,revisions[2],1,rtp_rule)]
    for label, port, revision, action, winner in checks:
        flow = [r for r in rows(label+'-flow.txt','flow.entry ')
                if str(port) in (r['port_a'],r['port_b'])]
        assert len(flow) == 1,(label,flow)
        item = flow[0]
        assert int(item['policy_generation']) == generation and int(item['revision']) == revision
        assert int(item['decision']) == action and item['rule'] == winner
        kind = 'quic' if port == quic_port else 'rtp'
        identity = (item['worker'],item['slot'],item['incarnation'])
        identities.setdefault(kind, identity)
        assert identities[kind] == identity
        if kind == 'quic':
            sni = props(label+'-sni.properties')
            assert sni['code'] == '0' and sni['result'] == '1' and sni['name'] == 'example.test'
            assert 'id=1004 key=quic' in read(label+'-flow.txt')
        else:
            text = read(label+'-flow.txt')
            assert 'id=1016 key=stun' in text and 'id=1017 key=rtp' in text
            assert 'name=-' in text  # An RTP heuristic is not valid SNI evidence.
    assert int(props(profile+'-rtp-blocked-query.properties')['actualDrops']) == 1
    assert int(props(profile+'-rtp-budget-query.properties')['actualDrops']) == 1

    rtp_case = next(x for x in result['sessions'] if x['profile'] == profile)
    command = [e for e in rtp_endpoint if e['kind'] == 'command' and e['nonce'] == rtp_case['nonce']]
    replies = [e for e in rtp_endpoint if e['kind'] == 'reply' and e['nonce'] == rtp_case['nonce']]
    assert len(command) == len(replies) == 29
    assert {e['index'] for e in command} == {-1, *range(28)}
    assert all(e['data'] in host_payloads and e['data'] in device_payloads for e in command+replies)
    blocked = rtp_case['plan']['realtime']['requests'][3]
    assert sum(row[4] == blocked for row in host) == 1  # Recovery reached the endpoint; DROP did not.
    inner = [row for row in device if row[4] == blocked and row[2] == str(rtp_port) and row[3] == '5004']
    # tcpdump -i any can observe one Root IP datagram more than once as it
    # traverses NFQUEUE. Distinguish those capture copies by the IP ID.
    id_fields = subprocess.check_output(
        ['tshark', '-r', str(run/'device.pcap'), '-Y',
         f'udp.srcport=={rtp_port} and udp.dstport==5004', '-T', 'fields',
         '-e', 'udp.payload', '-e', 'ip.id'], text=True, stderr=subprocess.DEVNULL)
    datagram_ids = [fields[1] for line in id_fields.splitlines()
                    if (fields := line.split('\t'))[0] == blocked and len(fields) == 2]
    assert len(datagram_ids) == len(inner)
    assert len(set(datagram_ids)) == (2 if profile == 'vpn' else 1)
    assert data(profile+'-rtp-blocked.json')['blockedTimeout'] is True
    assert data(profile+'-rtp-budget_done.json')['echoes'] == 25
    quic_case = next(x for x in result['quic_sessions'] if x['profile'] == profile)
    echoes = [e for e in quic_endpoint if e['kind'] == 'echo' and quic_case['nonce'] in bytes.fromhex(e['hex']).decode(errors='ignore')]
    assert len(echoes) == 25
    assert all(e['hex'] in host_payloads and e['hex'] in device_payloads for e in echoes)
    assert data(profile+'-quic-budget_done.json')['echoes'] == 25
    assert 'state=stopped' in read(profile+'-stopped.properties')
    assert 'NFQUEUE' not in read(profile+'-hooks-after.txt')
    assert 'libvpp_runtime.so' not in read(profile+'-processes-after.txt') if (run/(profile+'-processes-after.txt')).exists() else True
    assert data(profile+'-empty-reply.json')['configuration']['rules'] == []
    profile_answer = dict(generation=generation,revisions=revisions,quic_winner=quic_rule,
                          rtp_winner=rtp_rule,flow_identities=identities,
                          rtp_endpoint_exchanges=len(command),quic_echoes=len(echoes),policy_drops=1,
                          blocked_payload_capture_frames=len(inner),
                          blocked_payload_ip_datagrams=len(set(datagram_ids)))
    windows = data(profile+'-combined-selected-dashboard.json')['consumer']['persistent']
    expected_explanations = [(rtp_rule,revisions[0],1,1,'unavailable'),
                             (rtp_rule,revisions[1],0,2,'unavailable'),
                             (rtp_rule,revisions[2],1,1,'available'),
                             (quic_rule,revisions[0],1,1,'unavailable'),
                             (quic_rule,revisions[1],1,1,'unavailable')]
    identities_by_winner = {}
    for winner,revision,mode,actual,availability in expected_explanations:
        matches = [v for v in windows['rule_windows'].values()
                   if str(v['attribution']['winner']) == winner
                   and v['attribution']['policy_generation'] == generation
                   and v['attribution']['policy_revision'] == revision]
        assert matches, (profile,winner,revision)
        for effect in matches:
            attr, explanation = effect['attribution'], effect['interpretation']
            assert attr['mode'] == mode and attr['declared_action'] == 2
            assert attr['actual_action'] == explanation['actual_action'] == actual
            assert str(explanation['version']) == winner
            assert explanation['conditions']['status'] == availability
            if availability == 'available':
                assert explanation['conditions']['source_rule_index'] == 0
            else:
                assert explanation['conditions']['reason'] == 'matching_source_unavailable'
            identities_by_winner.setdefault(winner,set()).add(explanation['logical_identity'])
    assert all(len(names) == 1 for names in identities_by_winner.values())
    profile_answer['rule_explanations_checked'] = len(expected_explanations)
    if a.require_ui:
        item = next(x for x in result['ui_dashboard'] if x['profile'] == profile)
        raw = data(item['selected'])
        assert raw['vpp']['generation'] == generation
        assert raw['vpp']['policy_active_revision'] == str(revisions[2])
        assert any(row['worker'] == int(identities['rtp'][0]) and row['slot'] == int(identities['rtp'][1])
                   for row in raw['current_flows']['entries'])
        assert 'Runtime / VPP / Rust health' in item['projection'] and profile in item['projection']
        assert '<hierarchy' in read(item['xml'])
        assert (run/item['image']).read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
        ids = {v['protocol_id'] for v in windows['protocol_windows'].values() if v['layer'] == 'l7'}
        assert {1004,1016,1017} <= ids
        assert any(v['attribution']['actual_action'] == 2 and
                   str(v['attribution']['winner']) == rtp_rule for v in windows['rule_windows'].values())
        profile_answer['multi_label_ids'] = sorted(ids)
        profile_answer['ui_evidence'] = item['image']
    profiles[profile] = profile_answer

answer = dict(status='VALID',source_sha256=build['source_sha256'],apk_sha256=build['apk_sha256'],
              profiles=profiles,ordinary_history_unchanged=True,
              capture_kernel_drops=0,verifier_sha256=digest(__file__))
a.output.write_text(json.dumps(answer,indent=2)+'\n')
print(json.dumps(answer,indent=2))
