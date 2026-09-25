#!/usr/bin/env python3
"""Independently verify T05 source, ordinary winners and real packet completion."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
groups = module('t04_source', ROOT/'tests/evidence/verify_t04_groups.py')
chain = module('t01_chain', ROOT/'tests/evidence/verify_t01_rule.py')
source, effective, props, rows = groups.source, groups.effective, groups.props, groups.rows
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def snapshot_hash(path):
    value = 14695981039346656037
    for byte in Path(path).read_bytes(): value = ((value ^ byte) * 1099511628211) & ((1<<64)-1)
    return value or 1

def reference(config, packet):
    raw = bytes.fromhex(packet['raw'])
    assert raw[0] >> 4 == 4 and raw[9] == 17
    offset = (raw[0] & 15)*4
    sp, dp = struct.unpack_from('!HH', raw, offset)
    view = sorted(effective(config, int(packet['uid'])),
                  key=lambda item: (item[0]['priority'], item[0]['order'], item[0]['version'] >> 16))
    for rank, (rule, mode) in enumerate(view, 1):
        if rule['family'] not in (0, 4) or rule['protocol'] not in (0, 17): continue
        if rule['direction'] not in (0, int(packet['direction'])): continue
        available = int(packet['availability'])
        if rule['network_context'] != 0xffffffff and (not available & 4 or rule['network_context'] != int(packet['context'])): continue
        if rule['ifindex'] != 0xffffffff and (not available & 2 or rule['ifindex'] != int(packet['ifindex'])): continue
        if not (rule['source_port_first'] <= sp <= rule['source_port_last'] and rule['destination_port_first'] <= dp <= rule['destination_port_last']): continue
        if rule['family'] and any(ipaddress.ip_address(raw[at:at+4]) not in ipaddress.ip_network(
                (str(ipaddress.ip_address(rule[field][:4])), rule[field+'_prefix']), strict=False)
                for field, at in [('source', 12), ('destination', 16)]): continue
        return rule, mode, rank, len(view)
    raise AssertionError('controlled case must have an ordinary winner')

def packet_evidence(trace, case, config, config_path, pixel):
    payload = (case['nonce'] + (':0' if case.get('profile') == 'vpn' else '')).encode()
    packets = [p for p in rows(trace, 's216 stage=admit ')
               if p.get('direction') == '3' and bytes.fromhex(p.get('raw', ''))[28:] == payload]
    assert len(packets) == 1, 'unique actual packet'
    p = packets[0]; token = p['token']; generation = str(case['generation'])
    assert p['generation'] == generation and p['uid'] == str(case['uid']) and int(p['availability']) & 1
    raw = bytes.fromhex(p['raw'])
    if pixel:
        expected_context = 4 if case['profile'] == 'vpn' else 0 if case['phase'] == 'root-outside' else 1
        assert str(ipaddress.ip_address(raw[16:20])) == case['host']
        assert struct.unpack_from('!HH', raw, 20) == (42001 if case['profile'] == 'vpn' else 32000, 40609)
    else:
        expected_context = 2 if case['phase'] == 'outside' else 1
        assert raw[12:20] == bytes([127,0,0,1,127,0,0,2])
        assert struct.unpack_from('!HH', raw, 20) == (32000 + (case['uid'] == 12002), 40608)
        assert p['ifindex'] == '1'
    assert int(p['context']) == expected_context
    assert bool(int(p['availability']) & 4) == bool(expected_context)
    rule, mode, rank, count = reference(config, p)
    assert rule['version'] == case['rule_version'] and mode == case['mode']
    assert rule['action'] == case['declared_action'] == 2
    outbound_allowed = case['delivered'] or case.get('return_drop',False)
    assert (mode == 1 or rule['action'] == 1) == outbound_allowed
    matches = [r for r in rows(trace, 's209 event=l4 ') if r.get('token') == token and r.get('generation') == generation]
    assert len(matches) == 1, 'one ordinary lookup'
    m = matches[0]
    assert int(m['rule']) == rule['version'] and int(m['revision']) == config['revision'] == case['revision']
    assert int(m['snapshot_hash']) == snapshot_hash(config_path), 'source and runtime snapshot identity'
    assert m['action'] == '2' and int(m['mode']) == mode and int(m['actual_action']) == (1 if outbound_allowed else 2)
    assert m['status'] == '0' and int(m['candidates']) == count and int(m['rank']) == rank
    assert not [r for r in rows(trace, 's209 event=gate ') if r.get('token') == token], 'no Gate execution'
    assert len([r for r in rows(trace, 's203 event=buffer_free ') if r.get('obligation') == token]) == 1
    if case.get('profile') == 'vpn':
        assert p['source'] == 'TUN_CAPTURED' and raw[12:16] == bytes([10,111,0,2])
        completions = [r for r in rows(trace, 's213 event=completion source=TUN_CAPTURED ') if r.get('token') == token]
        assert len(completions) == 1 and int(completions[0]['policy_drop']) == int(not outbound_allowed)
        copies = [r for r in rows(trace, 's237 event=input_copy ') if r.get('token') == token]
        assert len(copies) == int(outbound_allowed)
        if copies:
            assert copies[0]['result'] == '0' and copies[0]['owner'] == p['owner']
            returned = [r for r in rows(trace, 's216 stage=admit source=FLOW_STACK_RETURN ') if bytes.fromhex(r.get('raw', ''))[28:] == payload]
            assert len(returned) == 1
            completed = [r for r in rows(trace, 's213 event=completion source=FLOW_STACK_RETURN ') if r.get('token') == returned[0]['token']]
            assert len(completed) == 1 and int(completed[0]['policy_drop']) == int(case.get('return_drop',False))
            if case.get('return_drop'):
                returned_rule, returned_mode, returned_rank, returned_count = reference(config, returned[0])
                assert returned[0]['context']=='1' and returned[0]['direction']=='1'
                assert returned_rule['version']==case['return_rule_version'] and returned_rule['action']==2 and returned_mode==0
                decisions=[r for r in rows(trace,'s209 event=l4 ') if r.get('token')==returned[0]['token']]
                assert len(decisions)==1
                decision=decisions[0]
                assert int(decision['rule'])==returned_rule['version'] and decision['action']=='2' and decision['actual_action']=='2' and decision['mode']=='0'
                assert int(decision['revision'])==config['revision'] and int(decision['snapshot_hash'])==snapshot_hash(config_path)
                assert int(decision['rank'])==returned_rank and int(decision['candidates'])==returned_count
    else:
        assert p['source'] == 'NFQ_CAPTURED'
        verdicts = [r for r in rows(trace, 's242 event=verdict_syscall ') if r.get('token') == token and r.get('generation') == generation]
        assert len(verdicts) == 1 and verdicts[0]['packet'] == p['packet_id'] and int(verdicts[0]['result']) >= 0
        assert int(verdicts[0]['verdict']) == int(case['delivered'])

def query_source(config, query, pixel):
    prefix = '' if pixel else 'config.'
    key = lambda java, native: prefix + (java if pixel else native)
    assert int(query[key('savedRevision','saved_revision')]) == config['revision'] == int(query[key('activeRevision','active_revision')])
    assert query[key('result','result')] == '0'
    assert int(query[key('count','count')]) == len(config['rules'])
    assert int(query[key('groupCount','group_count')]) == len(config['groups'])
    assert int(query[key('edgeCount','edge_count')]) == len(config['edges'])
    assert int(query[key('bindingCount','binding_count')]) == len(config['bindings'])
    for i, rule in enumerate(config['rules']):
        for field in ['version','uid','family','protocol','action']:
            assert int(query[f'{prefix}rule.{i}.{field}']) == rule[field]
        if pixel:
            wire = list(map(int, query[f'rule.{i}.wire'].split(',')))
            fields = 'uid network_context ifindex priority order family protocol direction action source_prefix destination_prefix source_port_first source_port_last destination_port_first destination_port_last reserved'.split()
            assert len(wire) == 26 and wire[0] == rule['version'] and wire[1] == 0
            assert wire[2:18] == [rule[f] for f in fields]
            assert b''.join(v.to_bytes(4,'big') for v in wire[18:22]) == rule['source']
            assert b''.join(v.to_bytes(4,'big') for v in wire[22:26]) == rule['destination']
    for kind in ['edge','binding']:
        for i, value in enumerate(config[kind+'s']): assert query[f'{prefix}{kind}.{i}'] == ','.join(map(str,value))

def verify(directory):
    d = Path(directory); run = json.loads((d/'result.json').read_text()); pixel = 'serial' in run
    assert run['status'] == 'RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build = chain.verify_product_build(run['build'])
    assert digest(run['build']) == run['build_sha256'] and build['source_sha256'] == run['source_sha256']
    assert build['completed_ns'] < run['started_ns'] < run['completed_ns']
    assert digest(d/'runner.py') == run['runner_sha256']
    if pixel:
        assert (d/'installed-apk.txt').read_text().split()[0] == build['apk_sha256'] == digest(build['apk'])
        assert {Path(l.split()[1]).name:l.split()[0] for l in (d/'installed-native.txt').read_text().splitlines()} == build['native_sha256']
        assert digest(d/'echo') == run['endpoint_build']['binary_sha256'] and digest(d/'echo.c') == run['endpoint_build']['source_sha256']
        expected = ['root-shared','root-disabled','root-outside','root-enabled','vpn-shared','vpn-wifi-return','vpn-outside','vpn-disabled','vpn-enabled']
        assert [c['phase'] for c in run['cases']] == expected
        for life in run['lifetimes']:
            label = life['label']; running = props(d/(label+'-running.properties')); stopped = props(d/(label+'-stopped.properties'))
            assert running['generation'] == str(life['generation']) and running['profile'] == life['profile']
            assert running['state'] == 'running' and running['protectionRunning'] == ('true' if label == 'root' else 'false')
            assert stopped['state'] == 'stopped' and stopped['mayBeActive'] == stopped['protectionRunning'] == 'false' and life['process_absent']
            process = (d/(label+'-process.txt')).read_text()
            assert set(map(int,next(l for l in process.splitlines() if l.startswith('Uid:')).split()[1:])) == {0 if label == 'root' else run['uid']}
            assert not (d/(label+'-queues-after.txt')).read_text().strip() and 'SAKAMOTO' not in (d/(label+'-hooks-after.txt')).read_text()
        assert (d/'root-final-source.conf').read_bytes() == (d/'vpn-read-source.conf').read_bytes()
        outside = source(d/'vpn-outside-source.conf')['rules'][2]
        assert outside['uid']==run['uid'] and outside['network_context']==2
        returned = source(d/'vpn-wifi-return-source.conf')['rules'][2]
        assert returned['uid']==run['uid'] and returned['network_context']==1 and returned['direction']==0
        for owner in d.glob('*-owner.txt'): assert owner.read_text().strip() == f"{run['uid']}:{run['uid']}:600"
        for phase in ['root-disabled','root-enabled','vpn-wifi-return','vpn-wifi-enabled','vpn-outside','vpn-outside-enabled','vpn-disabled','vpn-enabled']:
            q = props(d/(phase+'-apply.properties')); config = source(d/(phase+'-source.conf')); query_source(config,q,True)
            operation = (d/(phase+'-operation.txt')).read_text()
            assert 'Error' not in operation
            if phase.endswith('enabled'):
                context = 'vpn' if phase=='vpn-enabled' else 'mobile' if phase=='vpn-outside-enabled' else 'wifi'
                captures = [d/(phase+'-before.xml'), *d.glob(phase+'-scroll*.xml')]
                assert any(any(n.get('text')=='Open '+context and n.get('enabled')=='true'
                               for n in ET.parse(file).iter('node')) for file in captures)
                assert operation == 'UI tap: Open '+context+'\n'
                selected=props(d/(phase+'-select.properties'))
                assert int(selected['count'])==3 and int(selected['savedRevision'])+1==config['revision']
                assert any(any(('uid '+str(run['uid'])) in n.get('text','')
                               for n in ET.parse(file).iter('node')) for file in captures)
            assert (d/(phase+'-result.png')).read_bytes().startswith(b'\x89PNG')
        for profile in ['root','vpn']:
            base = source(d/(profile+'-shared-source.conf')); disabled = source(d/(profile+'-disabled-source.conf')); enabled = source(d/(profile+'-enabled-source.conf'))
            assert disabled['rules'][:2] == enabled['rules'] == base['rules']
            assert len(disabled['rules']) == 3 and len(enabled['rules']) == 2
            switch = disabled['rules'][2]
            assert (switch['uid'],switch['network_context'],switch['priority'],switch['order'],switch['family'],switch['protocol'],switch['direction'],switch['action']) == (run['uid'],1 if profile == 'root' else 4,0,0,0,0,0,2)
            assert base['groups'] == disabled['groups'] == enabled['groups']
            assert base['edges'] == disabled['edges'] == enabled['edges']
            assert base['bindings'] == disabled['bindings'] == enabled['bindings']
    else:
        assert run['policy_uids'] == [12001,12002]
        for name, value in build['artifact_hashes'].items(): assert digest(Path(run['artifact'])/name) == value
        assert digest(d/'network-publish') == run['network_helper']['binary_sha256']
        assert digest(d/'network-helper.c') == run['network_helper']['source_sha256']
        assert 'NFQUEUE' not in (d/'hooks-after.txt').read_text()
        assert [(c['phase'],c['uid']) for c in run['cases']] == [(p,u) for p in ['shared','disabled','outside','enabled','observe-switch','restart'] for u in [12001,12002]]
        for life in ['first','restart']:
            assert props(d/(life+'-stopped.txt'))['absent'] == 'True'
            assert 'root.stop=ok' in (d/(life+'-stop.txt')).read_text()
        for phase in ['shared','disabled','enabled','disabled-again','observe-switch']:
            query_source(source(d/(phase+'-source.conf')),props(d/(phase+'-apply.txt')),False)
        base = source(d/'shared-source.conf'); disabled = source(d/'disabled-source.conf'); enabled = source(d/'enabled-source.conf')
        assert disabled['rules'][:4] == enabled['rules'] == base['rules']
        assert len(disabled['rules']) == 5 and len(enabled['rules']) == 4
        assert (d/'disabled-source.conf').read_bytes() == (d/'outside-source.conf').read_bytes()
        for key in ['groups','edges','bindings']: assert base[key] == disabled[key] == enabled[key]
        switch = disabled['rules'][4]
        assert (switch['uid'],switch['network_context'],switch['ifindex'],switch['priority'],switch['order'],switch['family'],switch['protocol'],switch['direction'],switch['action']) == (12001,1,1,0,0,0,0,3,2)
        ordinary = source(d/'observe-switch-source.conf'); previous = source(d/'disabled-again-source.conf')
        assert ordinary['rules'][4]['version'] == previous['rules'][4]['version']+1
        assert ordinary['rules'][4]['uid'] == 0xffffffff
        assert (d/'observe-switch-source.conf').read_bytes() == (d/'restart-source.conf').read_bytes()
    for case in run['cases']:
        assert bool(case.get('return_drop',False)) == (case['phase']=='vpn-wifi-return')
        dropped = case['phase'] in ['root-disabled','vpn-disabled','vpn-wifi-return'] if pixel else case['phase']=='disabled' and case['uid']==12001
        assert case['delivered'] == (not dropped) and case['mode'] == int(not dropped or case.get('return_drop',False))
        assert int(case['nonce'].rsplit('-',1)[1]) > run['started_ns']
        config_path = d/case['source_file']; config = source(config_path)
        q, before = props(d/case['query']), props(d/case['before'])
        prefix = '' if pixel else 'query.'
        key = lambda java, native: prefix+(java if pixel else native)
        assert int(q[key('winnerVersion','winner_version')]) == case.get('query_winner_version',case['rule_version'])
        assert int(q[key('winnerRevision','winner_revision')]) == case['revision']
        assert int(q[key('winnerAction','winner_action')]) == case['declared_action']
        assert int(q[key('logicalHits','logical_hits')]) == int(before[key('logicalHits','logical_hits')])+1+int(case.get('return_drop',False))
        assert int(q[key('actualDrops','actual_drops')]) == int(before[key('actualDrops','actual_drops')])+int(dropped)
        probe = props(d/case['probe']) if pixel else json.loads((d/case['probe']).read_text())
        assert str(probe['uid']) == str(case['uid']) and probe['nonce'] == case['nonce']
        if pixel:
            delivered = probe.get('packet.0') == 'echo' if case['profile']=='vpn' else probe.get('result') == 'udp_echo_matched'
            endpoint = (d/case['endpoint']).read_text() if case.get('host')=='127.0.0.2' else json.loads((d/'lan-endpoint.json').read_text())
            assert delivered == case['delivered']
            assert ((case['nonce']+(':0' if case['profile']=='vpn' else '')) in endpoint) == (delivered or case.get('return_drop',False))
        else:
            assert (probe['received']==case['nonce']) == case['delivered'] == (case['nonce'] in json.loads((d/'endpoint.json').read_text()))
        trace = (d/(case['lifetime']+('-stop.log' if pixel else '-vpp.log'))).read_text()
        packet_evidence(trace,case,config,config_path,pixel)
    for label in (['root'] if pixel else ['first','restart']):
        zero = rows((d/(label+('-stop.log' if pixel else '-vpp.log'))).read_text(),'s242 event=stop_native_zero ')
        assert zero and all(zero[-1][k]=='0' for k in ['pending','buffers','obligations','handoffs','completion_frames'])
    if pixel:
        stops = rows((d/'vpn-stop.log').read_text(),'s237 event=owner_stopped ')
        assert len(stops)==2 and {s['owner'] for s in stops}=={'0','1'}
        for stop in stops:
            assert all(stop[k]=='0' for k in ['sessions','inputs','pbufs','buffers','obligations','frames'])
            assert stop['sockets_created']==stop['sockets_closed'] and stop['timer_fd']==stop['broker_fd']=='-1'
    return dict(status='PASS',platform='pixel' if pixel else 'linux',packets=len(run['cases']),source_sha256=run['source_sha256'])

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('directory',type=Path); args=parser.parse_args()
    result=verify(args.directory)
    result.update(verifier_sha256=digest(__file__),directory=str(args.directory))
    print(json.dumps(result,indent=2))
