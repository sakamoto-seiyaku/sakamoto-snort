#!/usr/bin/env python3
"""Join real R2/R3/R4 packet oracles to the typed current-flow dashboard."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module
supplemental=load('supplemental',ROOT/'tests/evidence/verify_t25_supplemental.py')
windows=load('protocol_catalog_oracle',ROOT/'tests/evidence/verify_t25_protocol_windows.py')
catalog=windows.catalog()
active=list(catalog.items())

def check(run_path,scope):
    run_path=Path(run_path).resolve()
    packet=windows.verify(run_path) if scope=='r1' else supplemental.verify(run_path,scope)
    result=json.loads((run_path/'result.json').read_text())
    build=json.loads(Path(result['build']).read_text())
    assert result['source_sha256']==build['source_sha256']
    files=sorted(run_path.glob('*-live-dashboard.json'))
    assert files,'no typed live dashboard captures'
    facts=set();checked=0;page_samples=[]
    for path in files:
        reply=json.loads(path.read_text())
        assert reply['health']['generation']==reply['vpp']['generation']==result['generation']
        assert reply['policy_source']['generation']==result['generation']
        assert reply['vpp']['policy_active_revision']==reply['policy_source']['active_revision']
        assert reply['consumer']['query_fresh'] is True
        page=reply['current_flows']
        assert page['generation']==result['generation'] and page['source']=='vpp'
        assert page['count']<=16 and page['scanned']<=256
        assert page['count']==len(page['entries'])
        assert all(0<=page['active'][i]<=page['capacity'][i] for i in (0,1))
        assert all(page['capacity_misses'][i]>=0 and page['allocated_bytes'][i]>=0 for i in (0,1))
        for entry in page['entries']:
            assert entry['worker'] in (0,1) and entry['slot']<page['capacity'][entry['worker']]
            assert entry['incarnation'].isdigit() and int(entry['incarnation'])>0
            assert entry['first_seen_monotonic_us']<=entry['last_seen_monotonic_us']
            assert len(entry['packets'])==len(entry['bytes'])==2
            mask=int(entry['protocol_set'])
            expected=[{'id':id,'key':key} for bit,(id,key) in enumerate(active) if mask & (1<<bit)]
            assert entry['protocol_labels']==expected,(path,entry['protocol_labels'],expected)
            assert entry['protocols_available'] or mask==0
            for item in entry['attribution']:
                if not item['available']:continue
                assert item['winner'].isdigit() and item['policy_hash'].isdigit()
                amask=int(item['protocol_set'])
                assert item['protocols_available'] or amask==0
                assert item['protocol_labels']==[{'id':id,'key':key} for bit,(id,key) in enumerate(active) if amask & (1<<bit)]
            facts.update(row['id'] for row in expected)
            checked+=1
        page_samples.append(path.name)
    required={1002,1003,1004,1006} if scope=='r1' else supplemental.SCOPE[scope][1]
    assert required<=facts,('exercised catalog labels missing from live typed Flow',sorted(required-facts))
    return dict(status='VALID',scope=scope,source_sha256=build['source_sha256'],
        actual_packet_paths=packet['total_packets'],actual_policy_drops=packet['actual_drops'],
        live_entries=checked,live_labels=sorted(facts),dashboard_pages=len(files),
        packet_oracle=packet,verifier_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        samples=page_samples)

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('scope',choices=['r1',*sorted(supplemental.SCOPE)])
    parser.add_argument('run',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    verdict=check(args.run,args.scope)
    args.output.write_text(json.dumps(verdict,indent=2)+'\n')
    print(json.dumps({k:verdict[k] for k in ('status','scope','actual_packet_paths','actual_policy_drops','live_entries','live_labels')},indent=2))
