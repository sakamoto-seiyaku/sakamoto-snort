#!/usr/bin/env python3
"""Independent T02 source/API/packet evidence verification; no device operations."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def props(path): return dict(line.split('=', 1) for line in Path(path).read_text().splitlines() if '=' in line and not line.startswith('#'))
def rows(text, prefix): return [dict(part.split('=', 1) for part in line.split()[1:] if '=' in part) for line in text.splitlines() if line.startswith(prefix)]
def source(path):
    raw = Path(path).read_bytes()
    assert raw[:8] == b'SKRULE02', 'source schema'
    revision, count, retained_count = struct.unpack_from('<QII', raw, 8)
    assert count <= 256 and retained_count <= 4096
    assert len(raw) == 24 + 8 * retained_count + 112 * count, 'complete source length'
    retained = struct.unpack_from('<' + 'Q' * retained_count, raw, 24)
    assert len(set(v >> 16 for v in retained)) == retained_count
    assert all(v >> 16 and v & 65535 for v in retained)
    result = []
    names = 'uid network_context ifindex priority order family protocol direction action source_prefix destination_prefix source_port_first source_port_last destination_port_first destination_port_last reserved'.split()
    for i in range(count):
        value = struct.unpack_from('<QQ16I16s16s', raw, 24 + 8 * retained_count + i * 112)
        rule = dict(zip(names, value[2:18]), version=value[0], base_version=value[1], source=value[18].hex(), destination=value[19].hex())
        assert rule['version'] in retained and rule['base_version'] == 0
        result.append(rule)
    return dict(revision=revision, count=count, retained=list(retained), rules=result)

def verify(directory):
    directory = Path(directory)
    run = json.loads((directory/'result.json').read_text())
    assert run['status'] == 'RAW_COMPLETE'
    spec = importlib.util.spec_from_file_location('t01_verify', ROOT/'tests/evidence/verify_t01_rule.py')
    chain = importlib.util.module_from_spec(spec); spec.loader.exec_module(chain)
    build = chain.verify_product_build(run['build'])
    assert digest(run['build']) == run['build_sha256'] and build['source_sha256'] == run['source_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert digest(directory/'runner.py') == run['runner_sha256']
    assert run['process_absent']
    if run.get('serial'):
        return verify_pixel(directory, run, build)
    artifact = Path(run['artifact'])
    for name, value in build['artifact_hashes'].items(): assert digest(artifact/name) == value, name
    assert 'NFQUEUE' not in (directory/'hooks-after.txt').read_text()
    expected_phases = ['allow', 'drop', 'save-failure', 'compile-failure', 'recover', 'restart']
    assert [(c['phase'], c['family']) for c in run['cases']] == [(p, f) for p in expected_phases for f in (4, 6)]
    endpoint = json.loads((directory/'endpoint.json').read_text())
    for lifetime in ['first', 'restart']:
        trace = (directory/(lifetime+'-vpp.log')).read_text()
        assert props(directory/(lifetime+'-stopped.txt'))['absent'] == 'True'
        assert 'root.stop=ok' in (directory/(lifetime+'-stop.txt')).read_text()
        zero = rows(trace, 's242 event=stop_native_zero ')
        assert zero and all(zero[-1][k] == '0' for k in ('pending', 'buffers', 'obligations', 'handoffs', 'completion_frames'))
    for phase in expected_phases[:-1]:
        config = source(directory/(phase+'-source.conf'))
        query = props(directory/(phase+'-apply.txt'))
        assert config['revision'] == int(query['config.saved_revision'])
        assert config['count'] == (129 if phase == 'compile-failure' else 2)
        for i, rule in enumerate(config['rules'][:2]):
            assert rule['uid'] == run['policy_uid'] and rule['family'] == (4 if i == 0 else 6)
            assert rule['protocol'] == 17 and rule['direction'] == 3
            assert rule['action'] == (2 if phase in ['drop', 'save-failure'] else 1)
            assert rule['version'] == int(query[f'config.rule.{i}.version'])
    save_failed = props(directory/'save-failure-apply.txt'); compile_failed = props(directory/'compile-failure-apply.txt')
    assert save_failed['config.result'] == save_failed['config.save_error'] == '3'
    assert (directory/'save-failure-source.conf').read_bytes() == (directory/'drop-source.conf').read_bytes()
    assert compile_failed['config.result'] == compile_failed['config.compile_error'] == '5'
    assert compile_failed['config.compiler_status'] == '2' and compile_failed['config.save_error'] == '0'
    assert int(compile_failed['config.saved_revision']) > int(compile_failed['config.active_revision'])
    for case in run['cases']:
        delivered = case['phase'] in ['allow', 'recover', 'restart']
        assert case['delivered'] == delivered and (case['nonce'] in endpoint) == delivered
        query = props(directory/case['query'])
        assert int(query['config.saved_revision']) == case['saved_revision']
        assert int(query['config.active_revision']) == case['revision']
        assert int(query['query.winner_version']) == case['rule_version']
        assert int(query['query.winner_revision']) == case['revision']
        assert int(query['query.winner_action']) == (1 if delivered else 2)
        trace = (directory/(case['lifetime']+'-vpp.log')).read_text()
        packet_evidence(trace, case, run['policy_uid'])
    return dict(status='PASS', platform='linux', packets=len(run['cases']), source_sha256=run['source_sha256'])

def packet_evidence(trace, case, uid):
    packets = []
    for p in rows(trace, 's216 stage=admit '):
        raw = bytes.fromhex(p.get('raw', ''))
        if not raw or raw[0] >> 4 != case['family']: continue
        offset = (raw[0] & 15) * 4 if case['family'] == 4 else 40
        if len(raw) < offset + 8 or raw[offset+8:] != case['nonce'].encode(): continue
        if p.get('direction') != '3' or int(p.get('generation', '0')) != case['generation']: continue
        assert p['uid'] == str(uid) and int(p['availability']) & 1
        assert struct.unpack_from('!HH', raw, offset) == (32000, 40608)
        assert (raw[9] if case['family'] == 4 else raw[6]) == 17
        if case['family'] == 4: assert raw[12:20] == bytes([127,0,0,1,127,0,0,2])
        else: assert raw[8:24] == raw[24:40] == bytes(15)+b'\1'
        packets.append(p)
    assert len(packets) == 1, ('unique real packet', case)
    p = packets[0]; token = p['token']; generation = str(case['generation'])
    decisions = [r for r in rows(trace, 's209 event=l4 ') if r.get('token') == token and r.get('generation') == generation]
    assert len(decisions) == 1 and decisions[0]['rule'] == str(case['rule_version']) and decisions[0]['revision'] == str(case['revision'])
    assert decisions[0]['action'] == str(1 if case['delivered'] else 2)
    verdicts = [r for r in rows(trace, 's242 event=verdict_syscall ') if r.get('token') == token and r.get('generation') == generation]
    assert len(verdicts) == 1 and verdicts[0]['verdict'] == str(int(case['delivered'])) and int(verdicts[0]['result']) >= 0
    assert verdicts[0]['packet'] == p['packet_id']
    freed = [r for r in rows(trace, 's203 event=buffer_free ') if r.get('obligation') == token]
    assert len(freed) == 1

def verify_pixel(directory, run, build):
    assert not run.get('error') and not run.get('cleanup_error')
    assert digest(build['apk']) == build['apk_sha256']
    assert (directory/'installed-apk.txt').read_text().split()[0] == build['apk_sha256']
    installed = {Path(line.split()[1]).name: line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
    assert installed == build['native_sha256']
    assert digest(directory/'echo') == run['endpoint_build']['binary_sha256']
    assert digest(directory/'echo.c') == run['endpoint_build']['source_sha256']
    assert [(life['label'], life['profile']) for life in run['lifetimes']] == [
        ('root', 'root'), ('root-restart', 'root'), ('vpn', 'vpn'), ('root-return', 'root')]
    for life in run['lifetimes']:
        label = life['label']; running = props(directory/(label+'-running.properties'))
        assert running['state'] == 'running' and running['profile'] == life['profile']
        assert running['generation'] == str(life['generation'])
        assert running['protectionRunning'] == ('true' if life['profile'] == 'root' else 'false')
        process = (directory/(label+'-process.txt')).read_text()
        uid_line = next(line for line in process.splitlines() if line.startswith('Uid:'))
        assert set(map(int, uid_line.split()[1:])) == {0 if life['profile'] == 'root' else run['uid']}
        stopped = props(directory/(label+'-stopped.properties'))
        assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == stopped['protectionRunning'] == 'false'
        assert life['process_absent']
        assert not (directory/(label+'-queues-after.txt')).read_text().strip()
        assert 'SAKAMOTO' not in (directory/(label+'-hooks-after.txt')).read_text()
        trace = (directory/(label+'-stop.log')).read_text()
        zero = rows(trace, 's242 event=stop_native_zero ')
        if life['profile'] == 'root':
            assert zero and zero[-1]['generation'] == str(life['generation'])
            assert all(zero[-1][k] == '0' for k in ('pending', 'buffers', 'obligations', 'handoffs', 'completion_frames'))
    for path in directory.glob('*-owner.txt'):
        assert path.read_text().strip() == f"{run['uid']}:{run['uid']}:600", ('source permissions', path)
    root_bytes = (directory/'root-final-source.conf').read_bytes()
    for label in ['root-stopped', 'root-restored', 'root-restart-stopped', 'vpn-read']:
        assert (directory/(label+'-source.conf')).read_bytes() == root_bytes, label
    vpn_bytes = (directory/'vpn-final-source.conf').read_bytes()
    for label in ['vpn-stopped', 'root-return-read', 'root-return-stopped']:
        assert (directory/(label+'-source.conf')).read_bytes() == vpn_bytes, label
    assert source(directory/'vpn-final-source.conf')['revision'] > source(directory/'root-final-source.conf')['revision']
    for phase in ['allow', 'drop', 'compile-failure', 'recover', 'vpn-drop', 'vpn-allow']:
        saved = source(directory/(phase+'-source.conf')); query = props(directory/(phase+'-apply.properties'))
        assert saved['revision'] == int(query['savedRevision'])
        assert saved['count'] == int(query['count']) == (129 if phase == 'compile-failure' else 2)
        expected_action = 2 if phase in ['drop', 'vpn-drop'] else 1
        for i, rule in enumerate(saved['rules']):
            wire = list(map(int, query[f'rule.{i}.wire'].split(',')))
            assert len(wire) == 26 and wire[0] == rule['version'] and wire[1] == 0
            assert wire[2] == rule['uid'] and wire[7] == rule['family'] and wire[8] == rule['protocol']
            assert wire[10] == rule['action']
            assert b''.join(v.to_bytes(4, 'big') for v in wire[18:22]).hex() == rule['source']
            assert b''.join(v.to_bytes(4, 'big') for v in wire[22:26]).hex() == rule['destination']
            if i < 2: assert rule['uid'] == run['uid'] and rule['action'] == expected_action
        captures = [directory/(phase+'-before.xml'), *directory.glob(phase+'-scroll*.xml')]
        expected_text = (directory/(phase+'-request.txt')).read_text().rstrip('\n')
        assert any(any(n.get('text') == 'Replace all rules' and n.get('enabled') == 'true' for n in ET.parse(path).iter('node')) for path in captures)
        assert any(any(n.get('content-desc') == 'Complete direct rules' and n.get('text') == expected_text for n in ET.parse(path).iter('node')) for path in captures)
        assert (directory/(phase+'-result.png')).read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
        if phase == 'compile-failure':
            assert query['result'] == query['compileError'] == '5' and query['saveError'] == '0' and query['compilerStatus'] == '2'
            assert int(query['savedRevision']) > int(query['activeRevision'])
        else: assert query['result'] == query['saveError'] == query['compileError'] == '0' and query['savedRevision'] == query['activeRevision']
    expected = [(p, f) for p in ['allow', 'drop', 'compile-failure', 'recover', 'restart'] for f in (4, 6)] + [('vpn-drop', 4), ('vpn-allow', 4)]
    assert [(c['phase'], c['family']) for c in run['cases']] == expected
    lan = json.loads((directory/'lan-endpoint.json').read_text())
    for case in run['cases']:
        delivered = case['phase'] in ['allow', 'recover', 'restart', 'vpn-allow']
        assert case['delivered'] == delivered
        assert int(case['nonce'].rsplit('-', 1)[1]) > run['started_ns']
        query = props(directory/case['query'])
        assert int(query['savedRevision']) == case['saved_revision'] and int(query['activeRevision']) == case['revision']
        assert int(query['winnerVersion']) == case['rule_version'] and int(query['winnerRevision']) == case['revision']
        assert int(query['winnerAction']) == (1 if delivered else 2)
        probe = props(directory/case['probe']); assert probe['nonce'] == case['nonce'] and int(probe['uid']) == run['uid']
        trace = (directory/(case['lifetime']+'-stop.log')).read_text()
        if case['profile'] == 'root':
            assert (probe['result'] == 'udp_echo_matched') == delivered
            assert (case['nonce'] in (directory/case['endpoint']).read_text()) == delivered
            packet_evidence(trace, case, run['uid'])
        else:
            assert (probe['packet.0'] == 'echo') == delivered and (case['nonce']+':0' in lan) == delivered
            vpn_packet_evidence(trace, case, run['uid'])
    vpn_trace = (directory/'vpn-stop.log').read_text()
    stops = rows(vpn_trace, 's237 event=owner_stopped ')
    assert len(stops) == 2 and {s['owner'] for s in stops} == {'0', '1'}
    for stopped in stops:
        assert stopped['generation'] == str(next(l['generation'] for l in run['lifetimes'] if l['profile'] == 'vpn'))
        assert all(stopped[k] == '0' for k in ('sessions', 'inputs', 'pbufs', 'buffers', 'obligations', 'frames'))
        assert stopped['sockets_created'] == stopped['sockets_closed'] and stopped['timer_fd'] == stopped['broker_fd'] == '-1'
    return dict(status='PASS', platform='pixel', root_packets=10, vpn_packets=2,
                lifetimes=4, source_sha256=run['source_sha256'], scope='T02 representative configuration acceptance; controlled VPN protectionRunning=false')

def vpn_packet_evidence(trace, case, uid):
    payload = (case['nonce']+':0').encode()
    admitted = [p for p in rows(trace, 's216 stage=admit source=TUN_CAPTURED ') if p.get('family') == '4' and p.get('protocol') == '17'
                and bytes.fromhex(p.get('raw', ''))[28:] == payload]
    assert len(admitted) == 1
    packet = admitted[0]; raw = bytes.fromhex(packet['raw']); token = packet['token']
    assert packet['uid'] == str(uid) and packet['generation'] == str(case['generation']) and int(packet['availability']) & 1
    assert raw[12:20] == bytes([10,111,0,2,192,168,4,5]) and struct.unpack_from('!HH', raw, 20) == (42001,40609)
    decisions = [r for r in rows(trace, 's209 event=l4 ') if r.get('token') == token]
    assert len(decisions) == 1 and decisions[0]['rule'] == str(case['rule_version']) and decisions[0]['revision'] == str(case['revision'])
    assert decisions[0]['action'] == str(1 if case['delivered'] else 2)
    completions = [r for r in rows(trace, 's213 event=completion source=TUN_CAPTURED ') if r.get('token') == token]
    assert len(completions) == 1 and completions[0]['policy_drop'] == str(int(not case['delivered']))
    assert len([r for r in rows(trace, 's203 event=buffer_free ') if r.get('obligation') == token]) == 1
    copies = [r for r in rows(trace, 's237 event=input_copy ') if r.get('token') == token]
    if not case['delivered']:
        assert not copies
        return
    assert len(copies) == 1 and copies[0]['result'] == '0' and copies[0]['owner'] == packet['owner']
    assert int(copies[0]['thread']) == int(packet['owner'])+1
    returned = [p for p in rows(trace, 's216 stage=admit source=FLOW_STACK_RETURN ') if p.get('family') == '4' and p.get('protocol') == '17'
                and bytes.fromhex(p.get('raw', ''))[28:] == payload]
    assert len(returned) == 1
    token = returned[0]['token']
    completions = [r for r in rows(trace, 's213 event=completion source=FLOW_STACK_RETURN ') if r.get('token') == token]
    assert len(completions) == 1 and completions[0]['policy_drop'] == '0'
    assert len([r for r in rows(trace, 's203 event=buffer_free ') if r.get('obligation') == token]) == 1


if __name__ == '__main__':
    p = argparse.ArgumentParser(); p.add_argument('directory', type=Path); args = p.parse_args()
    result = verify(args.directory); result.update(verifier_sha256=digest(__file__), directory=str(args.directory))
    print(json.dumps(result, indent=2))
