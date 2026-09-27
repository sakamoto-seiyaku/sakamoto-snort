#!/usr/bin/env python3
"""Independent Pixel packet, typed-query, UI and stopped-state checks for T28."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('chain',ROOT/'tests/evidence/product_chain.py')
chain=importlib.util.module_from_spec(spec);spec.loader.exec_module(chain)
def read(path):return json.loads(Path(path).read_text())
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def verify(build_file,root_path,vpn_path):
    build_file=Path(build_file).resolve();build=read(build_file)
    assert build['source_sha256']==hashlib.sha256(chain.encode(build['files'])).hexdigest()
    assert build['files']==chain.source_files()
    assert digest(build['apk'])==build['apk_sha256']
    predecessor=ROOT/'build-output/t27-20260927/device-readback-verified/summary.json'
    expected_original=read(predecessor)['ordinary_history_hashes']
    checks={};mutations=[]
    for profile,path in (('root',Path(root_path).resolve()),('vpn',Path(vpn_path).resolve())):
        result=read(path/'result.json')
        assert result['status']=='RAW_COMPLETE' and result['task']=='T28'
        assert result['profile']==profile and result['scenario']=='dashboard'
        assert result['source_sha256']==build['source_sha256']
        assert result['build_sha256']==digest(build_file)
        assert result['apk_sha256']==build['apk_sha256']
        assert result['native_sha256']==build['native_sha256']
        for name,expected in result['files'].items():assert digest(path/name)==expected,name
        assert len(result['lifetimes'])==5
        assert all(row['process_absent'] and row['service_process_absent'] for row in result['lifetimes'])
        assert read(path/'before-original-hashes.json')==read(path/'after-original-hashes.json')==expected_original
        assert result['pressure_reclaimed'] is True
        assert len(result['ui_keepalives'])>=1
        assert result['selected_rule_packets']==2+len(result['ui_keepalives'])
        assert any(row['target']=='Query health and flows' for row in result['ui_taps'])
        assert any(row['target']=='Next flows' for row in result['ui_taps'])
        assert any(row['target']=='Stop' for row in result['ui_taps'])
        if profile=='root':assert any(row['target']=='Start' for row in result['ui_taps'])

        wire=(path/'host.pcap').read_bytes()
        traffic=[]
        for name in ['allow-traffic.json',*(label+'-traffic.json' for label in result['ui_keepalives'])]:
            data=read(path/name);assert data['sent']==data['received'] and data['sent']>0
            for exchange in data['exchanges']:
                assert exchange['echoed'] and wire.count(bytes.fromhex(exchange['payload']))==2
                traffic.append(exchange)
        drop=read(path/'drop-traffic.json')
        assert [drop['sent'],drop['received']]==[2,0]
        for exchange in drop['exchanges']:
            assert not exchange['echoed'] and bytes.fromhex(exchange['payload']) not in wire

        observed=read(path/'allow.json')
        sampled=read(path/'allow-slot.json')
        ui_raw=read(path/result['ui_dashboard']['raw'])
        assert sampled['runtime']['profile']==profile
        assert sampled['runtime']['state']=='running'
        assert sampled['runtime']['protectionRunning']==('true' if profile=='root' else 'false')
        assert sampled['vpp']['generation']==sampled['policy_source']['generation']==sampled['health']['generation']
        assert sampled['vpp']['policy_active_revision']==sampled['policy_source']['active_revision']
        assert sampled['policy_source']['save_error']==sampled['policy_source']['compile_error']==0
        assert sampled['consumer']['query_fresh'] and sampled['consumer']['store_error'] is None
        assert sampled['current_flows']['count']<=16 and sampled['current_flows']['scanned']<=256
        assert sampled['current_flows']['allocated_bytes'][0]>0
        identity=result['live_flow_query'];rows=[e for e in sampled['current_flows']['entries']
            if e['worker']==identity['worker'] and e['slot']==identity['slot']
            and e['incarnation']==identity['incarnation']]
        assert len(rows)==1
        live=rows[0]
        previous=next(r for r in observed['consumer']['overview']['records']
            if r and r['owner']==live['worker'] and r['slot']==live['slot'])
        assert live['uid']==previous['attribution'][0]['uid']==result['uid']
        assert live['network']==previous['attribution'][0]['network']
        assert live['packets']==previous['packets'] and live['bytes']==previous['bytes']
        assert live['first_seen_monotonic_us']<=live['last_seen_monotonic_us']
        assert len(live['protocol_labels'])==int(live['protocol_set']).bit_count()
        assert live['attribution'][0]['name']=='allow-request'
        assert live['attribution'][1]['name']=='allow-reply'
        for side in (0,1):
            assert live['attribution'][side]['winner']==str(previous['attribution'][side]['winner'])
            assert live['attribution'][side]['winner'].isdigit()

        xml=ET.parse(path/'ui-allow-result.xml')
        projection=next(node.attrib.get('text','') for node in xml.iter('node')
            if node.attrib.get('content-desc')=='Health and flow result')
        assert projection==result['ui_dashboard']['projection']
        assert 'Flow '+str(live['worker'])+':'+str(live['slot']) in projection
        assert 'allow-request' in projection and 'allow-reply' in projection
        assert 'Store space:' in projection and 'allocated bytes=' in projection
        assert 'LPI stop=' in projection and 'SNI result=' in projection
        for side in (0,1):assert 'winner='+live['attribution'][side]['winner'] in projection
        assert (path/'ui-allow-result.png').stat().st_size>1000
        assert ui_raw['vpp']['policy_active_revision']==sampled['vpp']['policy_active_revision']
        dropped=read(path/'drop.json')
        assert dropped['vpp']['policy_drops']>=2
        assert sum(c['basic_packets'][1] for c in dropped['health']['channels'])>=2
        counts=dropped['consumer']['persistent']['rule_windows'].values()
        assert sum(row['counts']['packets'][0] for row in counts
            if row['attribution']['name']=='allow-request')==result['selected_rule_packets']
        for label in ('initial','pressure','hour','day','expired'):
            stopped=read(path/(label+'-stopped-query.json'))
            assert stopped['error']=='management_unavailable'
            assert stopped['runtime']['state']=='stopped'
            assert stopped['runtime']['protectionRunning']=='false'
        final=read(path/'expired-baseline.json')['consumer']['persistent']
        assert final['coverage']['evicted']['packets'][0]>=result['selected_rule_packets']
        assert final['save_error'] is None
        checks[profile]=dict(generations=[r['generation'] for r in result['lifetimes']],
            allowed_exchanges=len(traffic),actual_drops=2,selected_rule_packets=result['selected_rule_packets'],
            flow_worker=live['worker'],flow_slot=live['slot'],winner_ids=[a['winner'] for a in live['attribution']],
            coverage_gaps=final['coverage']['gaps'],evicted=final['coverage']['evicted']['packets'])
    return dict(status='VALID',source_sha256=build['source_sha256'],apk_sha256=build['apk_sha256'],
        profiles=checks,verifier_sha256=digest(__file__))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--build',required=True,type=Path)
    parser.add_argument('--root',required=True,type=Path);parser.add_argument('--vpn',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    answer=verify(args.build,args.root,args.vpn)
    args.output.write_text(json.dumps(answer,indent=2)+'\n')
    print(json.dumps({k:answer[k] for k in ('status','source_sha256','apk_sha256','profiles')},indent=2))
