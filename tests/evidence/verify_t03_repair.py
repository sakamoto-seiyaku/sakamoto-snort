#!/usr/bin/env python3
"""Read-only T03 source, startup, online-repair and packet evidence verifier."""
import argparse
import importlib.util
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
previous = module('t02_evidence', ROOT/'tests/evidence/verify_t02_rules.py')
chain = module('t01_evidence', ROOT/'tests/evidence/verify_t01_rule.py')
props, rows, source, digest = previous.props, previous.rows, previous.source, previous.digest

def zero_root(trace, generation):
    stopped = rows(trace, 's242 event=stop_native_zero ')
    assert any(s['generation'] == str(generation) and all(s[k] == '0' for k in
               ('pending', 'buffers', 'obligations', 'handoffs', 'completion_frames')) for s in stopped)

def verify(directory):
    directory = Path(directory)
    run = json.loads((directory/'result.json').read_text())
    assert run['status'] == 'RAW_COMPLETE' and run['process_absent']
    assert not run.get('error') and not run.get('cleanup_error')
    build = chain.verify_product_build(run['build'])
    assert digest(run['build']) == run['build_sha256'] and build['source_sha256'] == run['source_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert digest(directory/'runner.py') == run['runner_sha256']
    result = verify_pixel(directory, run, build) if run.get('serial') else verify_linux(directory, run, build)
    return dict(status='PASS', source_sha256=run['source_sha256'], **result)

def verify_linux(d, run, build):
    for name, expected in build['artifact_hashes'].items(): assert digest(Path(run['artifact'])/name) == expected
    assert 'NFQUEUE' not in (d/'hooks-after.txt').read_text()
    for life, generation in [('first', 25401), ('restart', 25402)]:
        assert props(d/(life+'-stopped.txt'))['absent'] == 'True'
        assert 'root.stop=ok' in (d/(life+'-stop.txt')).read_text()
        zero_root((d/(life+'-vpp.log')).read_text(), generation)
    invalid = source(d/'compile-failure-source.conf')
    assert invalid['count'] == 129
    assert (d/'compile-failure-source.conf').read_bytes() == (d/'restart-source.conf').read_bytes()
    failed = props(d/'compile-failure-apply.txt')
    assert failed['config.compile_error'] == failed['config.result'] == '5'
    assert int(failed['config.saved_revision']) == invalid['revision'] > int(failed['config.active_revision'])
    for label in ['not-ready', 'retry-not-ready']:
        status = props(d/(label+'-query.txt'))
        assert status['config.active_revision'] == status['query.policy_active_revision'] == '0'
        assert status['config.count'] == '129' and int(status['config.saved_revision']) == invalid['revision']
        assert status['config.compile_error'] == '5' and status['query.core_ready'] == 'true'
        assert status['query.adapter_available'] == status['query.protection_running'] == 'false'
        assert 'NFQUEUE' not in (d/(label+'-hooks.txt')).read_text()
        lanes = rows((d/(label+'-graph.txt')).read_text(), 'root.lane ')
        assert len(lanes) == 4 and all(l['fd'] == '-1' and l['ready'] == l['captured'] == '0' for l in lanes)
    retry = props(d/'retry.txt')
    assert retry['config.result'] == retry['config.compile_error'] == '5'
    assert int(retry['config.saved_revision']) == invalid['revision'] and retry['config.count'] == '129'
    repaired = source(d/'repair-source.conf')
    assert repaired['count'] == 2 and repaired['revision'] == invalid['revision'] + 1
    assert repaired['rules'] == invalid['rules'][:2]
    ready = props(d/'repaired-ready.txt')
    assert ready['query.adapter_available'] == ready['query.protection_running'] == 'true'
    assert ready['config.saved_revision'] == ready['config.active_revision'] == str(repaired['revision'])
    endpoint = json.loads((d/'endpoint.json').read_text())
    assert len(run['uncontrolled']) == 4
    restart_trace = (d/'restart-vpp.log').read_text()
    for ordinary in run['uncontrolled']:
        assert ordinary['nonce'] in endpoint and ordinary['generation'] == 25402
        assert ordinary['nonce'].encode().hex() not in restart_trace
    expected = [(p, f) for p in ['drop', 'compile-failure', 'repair', 'repaired-drop'] for f in [4, 6]]
    assert [(c['phase'], c['family']) for c in run['cases']] == expected
    for c in run['cases']:
        delivered = c['phase'] == 'repair'
        assert c['delivered'] == delivered and (c['nonce'] in endpoint) == delivered
        active_source = source(d/(('drop' if c['phase'] == 'compile-failure' else c['phase'])+'-source.conf'))
        active_rule = active_source['rules'][0 if c['family'] == 4 else 1]
        assert active_source['revision'] == c['revision'] and active_rule['version'] == c['rule_version']
        assert active_rule['uid'] == run['policy_uid'] and active_rule['action'] == (1 if delivered else 2)
        q = props(d/c['query'])
        assert int(q['config.saved_revision']) == c['saved_revision']
        assert int(q['config.active_revision']) == c['revision']
        assert int(q['query.winner_version']) == c['rule_version'] and int(q['query.winner_revision']) == c['revision']
        assert int(q['query.winner_action']) == (1 if delivered else 2)
        previous.packet_evidence((d/(c['lifetime']+'-vpp.log')).read_text(), c, run['policy_uid'])
    return dict(platform='linux', captured_packets=8, uncaptured_echoes=4, lifetimes=2)

def clicked_request(d, label):
    expected = (d/(label+'-request.txt')).read_text().rstrip('\n')
    paths = [d/(label+'-before.xml'), *d.glob(label+'-scroll*.xml')]
    assert any(any(n.get('text') == 'Replace all rules' and n.get('enabled') == 'true' for n in ET.parse(p).iter('node')) for p in paths)
    assert any(any(n.get('content-desc') == 'Complete direct rules' and n.get('text') == expected for n in ET.parse(p).iter('node')) for p in paths)
    assert (d/(label+'-result.png')).read_bytes().startswith(b'\x89PNG\r\n\x1a\n')

def verify_pixel(d, run, build):
    assert digest(build['apk']) == build['apk_sha256'] == (d/'installed-apk.txt').read_text().split()[0]
    assert {Path(line.split()[1]).name:line.split()[0] for line in (d/'installed-native.txt').read_text().splitlines()} == build['native_sha256']
    assert digest(d/'echo') == run['endpoint_build']['binary_sha256'] and digest(d/'echo.c') == run['endpoint_build']['source_sha256']
    assert [(l['label'],l['profile']) for l in run['lifetimes']] == [(p+'-'+s,p) for p in ['root','vpn'] for s in ['seed','unrepaired','repair']]
    lan = json.loads((d/'lan-endpoint.json').read_text())
    for life in run['lifetimes']:
        label, profile = life['label'], life['profile']
        state = props(d/(label+('-running' if life['initially_ready'] else '-management')+'.properties'))
        assert state['generation'] == str(life['generation']) and state['profile'] == profile
        assert state['mayBeActive'] == 'true' and life['process_absent']
        if not life['initially_ready']:
            assert state['state'] == 'error' and state['errorCode'] == 'rule_configuration_not_active'
            assert state['protectionRunning'] == 'false' and state['coreHealth'] == 'ok'
            ready = props(d/(label+'-readiness.properties'))
            assert ready['generation'] == state['generation'] and ready['managementReady'] == 'true'
            assert ready['policyReady'] == ready['adapterReady'] == ready['captureStarted'] == ready['protectionRunning'] == 'false'
            assert ready['activeRevision'] == '0' and ready['compileError'] == '5'
            assert not (d/(label+'-queues.txt')).read_text().strip() and 'SAKAMOTO' not in (d/(label+'-hooks.txt')).read_text()
            assert '/dev/tun' not in (d/(label+'-fds.txt')).read_text()
            tun = rows((d/(label+'-native.txt')).read_text(), 'tun.status ')
            assert tun and tun[-1]['attached'] == tun[-1]['enabled'] == tun[-1]['captured'] == '0'
            ordinary = next(c for c in run['uncontrolled'] if c['label'] == label)
            probe = props(d/(label+'-ordinary-network.properties'))
            assert probe['nonce'] == ordinary['nonce'] and probe['result'] == 'udp_echo_matched'
            if profile == 'vpn': assert ordinary['nonce'] in lan
            else: assert ordinary['nonce'] in (d/(label+'-ordinary-endpoint.txt')).read_text()
            assert ordinary['nonce'].encode().hex() not in (d/(label+'-stop.log')).read_text()
        process = (d/(label+'-process.txt')).read_text()
        uid_line = next(line for line in process.splitlines() if line.startswith('Uid:'))
        assert set(map(int,uid_line.split()[1:])) == {0 if profile == 'root' else run['uid']}
        stopped = props(d/(label+'-stopped.properties'))
        assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == stopped['protectionRunning'] == 'false'
        assert 'SAKAMOTO' not in (d/(label+'-hooks-after.txt')).read_text() and not (d/(label+'-queues-after.txt')).read_text().strip()
        trace = (d/(label+'-stop.log')).read_text()
        if profile == 'root': zero_root(trace,life['generation'])
        elif life['initially_ready'] or label.endswith('-repair'):
            stops = rows(trace,'s237 event=owner_stopped ')
            assert len(stops) == 2 and {s['owner'] for s in stops} == {'0','1'}
            for s in stops:
                assert s['generation'] == str(life['generation'])
                assert all(s[k] == '0' for k in ('sessions','inputs','pbufs','buffers','obligations','frames'))
                assert s['sockets_created'] == s['sockets_closed'] and s['timer_fd'] == s['broker_fd'] == '-1'
    for path in d.glob('*-owner.txt'): assert path.read_text().strip() == f"{run['uid']}:{run['uid']}:600"
    for profile in ['root','vpn']:
        invalid_path = d/(profile+'-invalid-source.conf'); invalid = source(invalid_path)
        assert invalid['count'] == 129
        for suffix in ['seed-stopped','unrepaired','unrepaired-stopped','repair','retry','retried']:
            assert (d/(profile+'-'+suffix+'-source.conf')).read_bytes() == invalid_path.read_bytes()
        failed = props(d/(profile+'-compile-failure-apply.properties'))
        retry = props(d/(profile+'-retry-apply.properties'))
        assert failed['result'] == failed['compileError'] == retry['result'] == retry['compileError'] == '5'
        assert int(failed['savedRevision']) > int(failed['activeRevision']) and retry['activeRevision'] == '0'
        assert failed['savedRevision'] == retry['savedRevision'] == str(invalid['revision'])
        repaired = source(d/(profile+'-repair-apply-source.conf'))
        assert repaired['count'] == 2 and repaired['rules'] == invalid['rules'][:2] and repaired['revision'] == invalid['revision']+1
        before = props(d/(profile+'-repaired-not-started.properties'))
        readiness = props(d/(profile+'-repaired-readiness.properties'))
        assert before['errorCode'] == 'capture_not_started' and before['protectionRunning'] == 'false'
        assert readiness['policyReady'] == 'true' and readiness['captureStarted'] == readiness['protectionRunning'] == 'false'
        running = props(d/(profile+'-repair-running.properties'))
        assert running['generation'] == before['generation'] and running['state'] == 'running'
        assert running['protectionRunning'] == ('true' if profile == 'root' else 'false')
        for suffix in ['drop','compile-failure','retry','repair-apply','recovered-drop','final-allow']:
            clicked_request(d,profile+'-'+suffix)
    expected = [(p+'-'+s,f) for p in ['root','vpn'] for s in ['drop','compile-failure','recovered','recovered-drop'] for f in ([4,6] if p == 'root' else [4])]
    assert [(c['phase'],c['family']) for c in run['cases']] == expected
    for c in run['cases']:
        delivered = c['phase'].endswith('-recovered'); assert c['delivered'] == delivered
        phase = c['phase'].removeprefix(c['profile']+'-')
        active_label = c['profile']+'-'+('drop' if phase == 'compile-failure' else 'repair-apply' if phase == 'recovered' else phase)
        active_source = source(d/(active_label+'-source.conf'))
        active_rule = active_source['rules'][0 if c['family'] == 4 else 1]
        assert active_source['revision'] == c['revision'] and active_rule['version'] == c['rule_version']
        assert active_rule['uid'] == run['uid'] and active_rule['action'] == (1 if delivered else 2)
        q=props(d/c['query']);probe=props(d/c['probe'])
        assert int(q['savedRevision']) == c['saved_revision'] and int(q['activeRevision']) == c['revision']
        assert int(q['winnerVersion']) == c['rule_version'] and int(q['winnerRevision']) == c['revision']
        assert int(q['winnerAction']) == (1 if delivered else 2)
        assert probe['nonce'] == c['nonce'] and int(probe['uid']) == run['uid']
        trace=(d/(c['lifetime']+'-stop.log')).read_text()
        if c['profile'] == 'root':
            assert (probe['result']=='udp_echo_matched') == delivered and (c['nonce'] in (d/c['endpoint']).read_text()) == delivered
            previous.packet_evidence(trace,c,run['uid'])
        else:
            assert (probe['packet.0']=='echo') == delivered and (c['nonce']+':0' in lan) == delivered
            previous.vpn_packet_evidence(trace,c,run['uid'])
    return dict(platform='pixel', root_packets=8, vpn_packets=4, uncaptured_echoes=4, lifetimes=6,
                scope='T03 representative lifecycle acceptance; controlled VPN protectionRunning=false')

if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory');args=parser.parse_args()
    print(json.dumps(verify(args.directory),indent=2))
