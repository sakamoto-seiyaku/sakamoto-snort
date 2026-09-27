#!/usr/bin/env python3
"""Root/VPN protocol publication joined to real packets and Rust windows."""
import argparse
from collections import defaultdict
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
t12=module('t12_oracle',ROOT/'tests/evidence/verify_t12_lpi.py')
windows=module('t25_windows',ROOT/'tests/evidence/verify_t25_protocol_windows.py')

def label_counts(query,uid,protocol_id):
    rows=query['protocol_windows'].values()
    return [sum(row['counts']['packets'][side] for row in rows if
        row['uid']==uid and row['layer']=='l7' and row['protocol_id']==protocol_id)
        for side in (0,1)]

def same_scope(query,labels):
    for row in query['protocol_windows'].values():
        minute,uid,action=row['minute'],row['uid'],row['actual_action']
        denominator=query['application_windows'][f'{minute:020}:{uid}:{action}']['counts']
        assert row['denominator']==denominator
        for kind in ('packets','bytes'):
            for side in (0,1):
                total=denominator[kind][side]
                ratio=row['counts'][kind][side]/total if total else None
                assert row['share'][kind][side]==ratio
        if row['layer']=='l7':assert labels[row['protocol_id']]==row['key']
        elif row['layer']=='l4':assert row['protocol_id'] in (1,6,17,58)
        else:assert row['layer'] in ('l7_none','l7_unavailable')

def flow_record(snapshot,entry,port,generation):
    records=[record for record in snapshot['consumer']['overview']['records'] if record
        and record['generation']==generation and port in record['ports']
        and record['owner']==int(entry['worker']) and record['slot']==int(entry['slot'])
        and record['incarnation']==int(entry['incarnation'])]
    assert len(records)==1,'wire Flow and Rust record identity differ'
    record=records[0]
    assert record['protocol'] in (6,17)
    return record

def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text())
    assert run['status']=='RAW_COMPLETE' and run['observation'] is True and run['mdns'] is True
    assert not run.get('error') and not run.get('cleanup_error') and not run.get('restoration_error')
    build=t12.base.build_reader.verify_product_build(run['build'])
    assert build['source_sha256']==run['source_sha256']
    assert windows.digest(build['apk'])==build['apk_sha256']==(directory/'installed-apk.txt').read_text().split()[0]
    installed={Path(line.split()[1]).name:line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
    assert installed==build['native_sha256']
    assert windows.digest(directory/'runner.py')==run['runner_sha256']
    assert windows.digest(directory/'protocol-peer.py')==run['peer_sha256']
    assert windows.digest(directory/'fixtures.json')==run['fixtures_sha256']
    configs=t12.configs(directory,run,True)
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoint[0]['kind']=='ready' and endpoint[0]['udp_port']==5353
    labels=windows.catalog();result={}
    for life in run['lifetimes']:
        profile,generation=life['profile'],life['generation']
        assert life['process_absent']
        state=t12.props(directory/(profile+'-stopped.properties'))
        assert state['state']=='stopped' and state['mayBeActive']=='false'
        assert not (directory/(profile+'-queues-after.txt')).read_text().strip()
        assert 'SAKAMOTO' not in (directory/(profile+'-hooks-after.txt')).read_text()
        restoration=json.loads((directory/(profile+'-restore.json')).read_text())
        assert restoration['result']==0 and restoration['stage']=='vpp'
        cases=[case for case in run['cases'] if case['profile']==profile]
        assert [case['phase'] for case in cases]==['first','added','blocked','budget']*2
        trace=(directory/(profile+'-stop.log')).read_text()
        packets,sessions,summary,_=t12.verify_trace(trace,profile,generation,
            sorted({case['port'] for case in cases}),configs,run['uid'])
        t12.endpoint_delivery(directory,run,True,profile,endpoint,packets)
        baseline=json.loads((directory/(profile+'-baseline-observation.json')).read_text())
        prior=baseline['consumer']['persistent'];same_scope(prior,labels)
        assert baseline['consumer']['query_fresh'] is True
        phase={};flows={}
        for case in cases:
            entry=t12.flow_query(directory,case,packets,configs,run['uid'],False,True)
            snapshot=json.loads((directory/case['observation']).read_text())
            assert snapshot['consumer']['query_fresh'] is True
            assert snapshot['health']['generation']==generation
            assert snapshot['health']['connected']==1
            query=snapshot['consumer']['persistent'];same_scope(query,labels)
            assert query['protocol_query_truncated'] is False
            assert query['legacy_protocol_unavailable']==prior['legacy_protocol_unavailable']
            assert query['coverage']['gaps']==prior['coverage']['gaps']
            record=flow_record(snapshot,entry,case['port'],generation)
            assert any(a['protocols_available'] for a in record['attribution'])
            mask=sum(1<<(id-1001) for id in ({1002} if case['protocol']=='tcp' else {1006}))
            if case['phase']!='first':mask|=1<<(1003-1001 if case['protocol']=='tcp' else 1004-1001)
            assert any(a['protocol_set']==mask for a in record['attribution'])
            assert all(a['protocol_set'] & ~mask==0 for a in record['attribution'])
            phase[case['label']]=query
            flows[case['label']]=record
        for protocol,old_id,new_id in [('tcp',1002,1003),('udp',1006,1004)]:
            first=phase[profile+'-'+protocol+'-first']
            added=phase[profile+'-'+protocol+'-added']
            first_flow=flows[profile+'-'+protocol+'-first']
            added_flow=flows[profile+'-'+protocol+'-added']
            assert first_flow['owner']==added_flow['owner'] and first_flow['slot']==added_flow['slot']
            assert first_flow['incarnation']==added_flow['incarnation']
            old_first=[label_counts(first,run['uid'],old_id)[i]-label_counts(prior,run['uid'],old_id)[i] for i in (0,1)]
            new_first=[label_counts(first,run['uid'],new_id)[i]-label_counts(prior,run['uid'],new_id)[i] for i in (0,1)]
            new_added=[label_counts(added,run['uid'],new_id)[i]-label_counts(prior,run['uid'],new_id)[i] for i in (0,1)]
            assert sum(old_first)>0 and new_first==[0,0] and sum(new_added)>0
            # A newly published label can cover only packets after first's
            # actual observed boundary; it cannot inherit the older prefix.
            assert all(0<=new_added[i]<=added_flow['packets'][i]-first_flow['packets'][i] for i in (0,1))
        restored=json.loads((directory/(profile+'-restored-observation.json')).read_text())
        assert restored['consumer']['query_fresh'] is True
        assert restored['consumer']['persistent']['legacy_protocol_unavailable']==prior['legacy_protocol_unavailable']
        result[profile]=dict(generation=generation,packets=summary['packets'],
            actual_drops=summary['actual_drops'],published_changes=summary['published_changes'],
            protocol_rows=restored['consumer']['persistent']['protocol_window_count'],
            new_packets=[restored['consumer']['persistent']['packets'][i]-prior['packets'][i] for i in (0,1)])
    assert set(result)=={'root','vpn'}
    return dict(status='VALID',source_sha256=run['source_sha256'],apk_sha256=build['apk_sha256'],
        runner_sha256=run['runner_sha256'],verifier_sha256=windows.digest(__file__),
        profiles=result)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();result=verify(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
