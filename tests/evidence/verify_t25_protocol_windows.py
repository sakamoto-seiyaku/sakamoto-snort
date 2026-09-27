#!/usr/bin/env python3
"""Independent packet-to-protocol-window oracle for the controlled T12 workload.

The packet/recognition oracle reads actual wire bytes and endpoint handshakes
through verify_t12_lpi, then derives window arithmetic without Product records.
"""
import argparse
from collections import defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('t12_oracle',ROOT/'tests/evidence/verify_t12_lpi.py')
t12=importlib.util.module_from_spec(spec);spec.loader.exec_module(t12)

def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def catalog():
    result={}
    for line in (ROOT/'resources/application-protocol-catalog/catalog.tsv').read_text().splitlines():
        if line.startswith('#') or not line:continue
        ident,key,status,*_=line.split('\t')
        if status=='active':result[int(ident)]=key
    return result

def add(target,key,side,packets,bytes_):
    value=target[key]
    value['packets'][side]+=packets
    value['bytes'][side]+=bytes_

def counts():return {'packets':[0,0],'bytes':[0,0]}

def expected_for_snapshot(snapshot,packets):
    q=snapshot['consumer']['persistent']
    # Recent END history retains flows after the bounded live overview slot
    # is reused. Deduplicate a still-visible ended Flow by its full identity.
    records={}
    for value in q['recent'].values():
        record=value['record']
        if not record['blocked']:
            identity=(record['generation'],record['owner'],record['slot'],record['incarnation'])
            records[identity]=record
    for record in snapshot['consumer']['overview']['records']:
        if record:
            identity=(record['generation'],record['owner'],record['slot'],record['incarnation'])
            records[identity]=record
    chosen=[]
    for record in records.values():
        matching=[p for p in packets if
            int(p['flow']['worker'])==record['owner'] and
            int(p['flow']['slot'])==record['slot'] and
            int(p['lpi']['incarnation'])==record['incarnation']]
        amount=sum(record['packets'])
        assert len(matching)>=amount and amount>0,'overview/trace Flow prefix absent'
        assert int(matching[amount-1]['flow']['packets'])==amount,'Flow prefix changed after query'
        chosen.extend(matching[:amount])
    totals=counts();applications=defaultdict(counts);rules=defaultdict(counts)
    protocols=defaultdict(counts);l7_unknown=counts()
    for packet in chosen:
        side=int(packet['flow']['flow_dir'])-1
        assert side in (0,1)
        size=int(packet['admit']['packet_length'])
        fact=packet['facts'];uid=fact['uid'] if fact['uid'] is not None else 0xffffffff
        action=packet['expected']['actual_action'] or 1
        winner=packet['expected']['rule_id']
        add({'total':totals},'total',side,1,size)
        add(applications,(uid,action),side,1,size)
        if winner:add(rules,(uid,action,winner),side,1,size)
        add(protocols,(uid,action,'l4',fact['protocol']),side,1,size)
        labels=fact['lpi']
        if labels is None:
            add(protocols,(uid,action,'l7_unavailable',0),side,1,size)
            add({'unknown':l7_unknown},'unknown',side,1,size)
        elif not labels:
            add(protocols,(uid,action,'l7_none',0),side,1,size)
        else:
            for ident in labels:add(protocols,(uid,action,'l7',ident),side,1,size)
    return chosen,totals,applications,rules,protocols,l7_unknown

def actual_groups(rows,identity):
    result=defaultdict(counts)
    for row in rows.values():
        key=identity(row)
        for side in (0,1):
            add(result,key,side,row['counts']['packets'][side],row['counts']['bytes'][side])
    return dict(result)

def verify_snapshot(snapshot,expected,labels):
    chosen,totals,applications,rules,protocols,l7_unknown=expected
    assert snapshot['consumer']['query_fresh'] is True
    q=snapshot['consumer']['persistent']
    assert q['packets']==totals['packets'] and q['bytes']==totals['bytes'],'overall double count'
    assert q['coverage']['gaps']==0 and q['attribution_unknown']['packets']==[0,0]
    assert q['l4_unknown']==counts() and q['l7_unknown']==l7_unknown
    assert actual_groups(q['application_windows'],lambda r:(r['uid'],r['actual_action']))==dict(applications),'application totals'
    assert actual_groups(q['rule_windows'],lambda r:(r['attribution']['uid'],r['attribution']['actual_action'],r['attribution']['winner']))==dict(rules),'rule totals'
    rows=q['protocol_windows']
    assert actual_groups(rows,lambda r:(r['uid'],r['actual_action'],r['layer'],r['protocol_id']))==dict(protocols),'protocol windows'
    assert q['protocol_window_count']==len(rows) and q['protocol_query_truncated'] is False
    for row in rows.values():
        minute,uid,action=row['minute'],row['uid'],row['actual_action']
        app=q['application_windows'][f'{minute:020}:{uid}:{action}']['counts']
        assert row['denominator']==app,'cross-scope protocol denominator'
        for kind in ('packets','bytes'):
            for side in (0,1):
                total=app[kind][side]
                expected_share=row['counts'][kind][side]/total if total else None
                actual=row['share'][kind][side]
                assert actual==expected_share,'wrong directional protocol share'
        if row['layer']=='l7':assert labels.get(row['protocol_id'])==row['key'],'unstable catalog label'
        elif row['layer']=='l4':assert row['protocol_id'] in (6,17)
        else:assert row['layer'] in ('l7_none','l7_unavailable') and row['protocol_id']==0 and row['key']==''
    return len(chosen)

def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text())
    assert run['status']=='RAW_COMPLETE' and run.get('observation') is True
    assert run['process_absent'] and not run.get('error')
    build=t12.base.build_reader.verify_product_build(run['build'])
    assert build['source_sha256']==run['source_sha256']
    assert digest(directory/'runner.py')==run['runner_sha256']
    assert digest(directory/'observation-client.py')==run['observation_client_sha256']
    assert digest(directory/'socket-peer.py')==run['peer_sha256']
    configs=t12.configs(directory,run,False)
    trace=(directory/'first-vpp.log').read_text()
    packets,sessions,trace_summary,_=t12.verify_trace(trace,'root',run['generation'],
        sorted({case['port'] for case in run['cases']}),configs,12001)
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    t12.endpoint_delivery(directory,run,False,'root',endpoint,packets)
    assert any(event['kind']=='tls_handshake' for event in endpoint)
    assert any(event['kind']=='quic_event' and event['event']=='HandshakeCompleted' for event in endpoint)
    expected_names=catalog();snapshots={};overlap=False
    for case in run['cases']:
        snapshot=json.loads((directory/case['observation']).read_text())
        expected=expected_for_snapshot(snapshot,packets)
        count=verify_snapshot(snapshot,expected,expected_names)
        snapshots[case['label']]=dict(packets=count,protocol_rows=len(snapshot['consumer']['persistent']['protocol_windows']))
        q=snapshot['consumer']['persistent']
        by_scope=defaultdict(lambda: [0,0])
        for row in q['protocol_windows'].values():
            if row['layer']=='l7':
                key=(row['minute'],row['uid'],row['actual_action'])
                for side in (0,1):by_scope[key][side]+=row['counts']['packets'][side]
        for (minute,uid,action),value in by_scope.items():
            denominator=q['application_windows'][f'{minute:020}:{uid}:{action}']['counts']['packets']
            overlap |= any(value[side]>denominator[side] for side in (0,1))
    assert overlap,'multi-label shares never exceeded 100% in the real workload'
    first=json.loads((directory/'tcp-first-observation.json').read_text())['consumer']['persistent']
    added=json.loads((directory/'tcp-added-observation.json').read_text())['consumer']['persistent']
    assert not any(r['protocol_id']==1003 for r in first['protocol_windows'].values())
    assert any(r['protocol_id']==1003 and r['layer']=='l7' for r in added['protocol_windows'].values())
    first=json.loads((directory/'udp-first-observation.json').read_text())['consumer']['persistent']
    added=json.loads((directory/'udp-added-observation.json').read_text())['consumer']['persistent']
    assert any(r['protocol_id']==1006 and r['layer']=='l7' for r in first['protocol_windows'].values())
    assert not any(r['protocol_id']==1004 and r['layer']=='l7' for r in first['protocol_windows'].values())
    assert any(r['protocol_id']==1004 and r['layer']=='l7' for r in added['protocol_windows'].values())
    cost=None
    if run.get('resources'):
        first,last=run['resources'][0],run['resources'][-1]
        baseline=json.loads((directory/'baseline-observation.json').read_text())
        final=json.loads((directory/'final-observation.json').read_text())
        def channels(value,field):return sum(c[field] for c in value['health']['channels'])
        assert first['ticks_per_second']==last['ticks_per_second']
        assert channels(final,'full')==0
        assert channels(final,'oversize')==0
        cost=dict(duration_seconds=(last['mono_ns']-first['mono_ns'])/1e9,
            vpp_cpu_seconds=(last['vpp']['cpu_ticks']-first['vpp']['cpu_ticks'])/first['ticks_per_second'],
            rust_cpu_seconds=(last['rust']['cpu_ticks']-first['rust']['cpu_ticks'])/first['ticks_per_second'],
            rust_write_bytes=last['rust']['write_bytes']-first['rust']['write_bytes'],
            vpp_hwm_kib=last['vpp']['hwm_kib'],rust_hwm_kib=last['rust']['hwm_kib'],
            flow_export_attempts=channels(final,'attempted')-channels(baseline,'attempted'),
            published=channels(final,'published')-channels(baseline,'published'),
            notifications=channels(final,'notifications')-channels(baseline,'notifications'),
            mapping_bytes=final['health']['mapping_bytes'],
            sqlite_commits=final['consumer']['persistent']['persistence']['commits'],
            protocol_rows=final['consumer']['persistent']['protocol_window_count'])
    return dict(status='VALID',source_sha256=run['source_sha256'],runner_sha256=run['runner_sha256'],
        verifier_sha256=digest(__file__),trace_sha256=digest(directory/'first-vpp.log'),
        total_packets=trace_summary['packets'],actual_drops=trace_summary['actual_drops'],
        published_changes=trace_summary['published_changes'],multi_label_over_100pct=overlap,
        snapshots=snapshots,cost=cost)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();result=verify(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
