#!/usr/bin/env python3
"""T11 independent cache/guard evidence, composed with the real CT/packet oracle."""
import argparse
from collections import defaultdict
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
base=module('t11_ct',ROOT/'tests/evidence/verify_t07_ct.py')


def verify_cache_trace(text,profile,generation,configs,uid):
    records=base.records
    admits={r['token']:r for _,r in records(text,'s216 stage=admit ') if r['generation']==str(generation)}
    acquires={r['token']:r for _,r in records(text,'s209 event=acquire ') if r['generation']==str(generation)}
    finals={r['token']:r for _,r in records(text,'s209 event=l4 ') if r['generation']==str(generation)}
    trackers={r['token']:r for prefix in ('s222 event=tcp_update ','s223 event=udp_update ')
              for _,r in records(text,prefix) if r['generation']==str(generation)}
    rows=records(text,'t11 event=cache ')
    assert rows,'cache query witnesses missing'
    seen=set();owner_counts=defaultdict(lambda:[0,0]);counts=defaultdict(int);last={}
    per_token=defaultdict(list)
    for _,row in rows:
        assert row['generation']==str(generation) and row['status']=='0'
        admit=admits[row['token']];acquire=acquires[row['token']]
        owner=admit['owner']
        identity=tuple(row[n] for n in ('generation','revision','snapshot_hash'))
        assert identity==tuple(acquire[n] for n in ('generation','revision','snapshot_hash')),'cache mixed snapshot'
        source,source_hash=configs[(profile,int(row['revision']))]
        assert int(row['snapshot_hash'])==source_hash
        hit=int(row['hit']);assert hit in (0,1)
        owner_counts[owner][0 if hit else 1]+=1
        assert [int(row['hits']),int(row['misses'])]==owner_counts[owner],'cache hit/miss accounting'
        counts['hits' if hit else 'misses']+=1
        per_token[row['token']].append(row);last[owner]=row
        raw=bytes.fromhex(admit['raw'])
        if raw[0]>>4!=4 or raw[9] not in (6,17):
            # Bootstrap traffic still contributes truthful diagnostics, but is
            # not promoted into the representative IPv4 TCP/UDP semantic claim.
            counts['outside_scope_queries']+=1
            continue
        facts,flags,payload=base.packet(admit)
        logical=base.source_reader.logical_rules(source,facts['uid'])
        # Native managed rules use the existing fixed policy reason identity.
        for rule in logical:rule['reason']=1
        position=int(row['position']);assert position in (1,2)
        # These two-rule requests deliberately have overlapping envelopes.
        # Dynamic first => both POST; static-first => the static whole winner PRE.
        static_first=source['rules'][1]['priority']==0
        all_rules=logical
        if position==1:
            logical=[r for r in logical if r['priority']==0] if static_first else []
            facts.update(ct=None,flowdir=None)
            assert row['incarnation']=='0','PRE looked up a Flow'
        else:
            tracker=trackers[row['token']]
            assert row['incarnation']==tracker['incarnation'],'facts not bound to current Flow instance'
            facts.update(ct=int(tracker['ct_state']),flowdir=int(tracker['flow_dir']))
            logical=[r for r in logical if r['priority']!=0] if static_first else logical
        expected=base.reference.ordered_reference(logical,facts)
        # Rank is always from the complete effective application, even in PRE.
        if expected['rule_id']:
            ordered=sorted(all_rules,key=lambda r:(r['priority'],r['order'],r['id']))
            expected['winner_rank']=next(i+1 for i,r in enumerate(ordered) if r['id']==expected['rule_id'])
        for a,b in [('rule_id','rule'),('winner_rank','rank'),('mode','mode'),('action','declared'),
                    ('actual_action','actual'),('reason_id','reason'),('priority','priority'),('order','order')]:
            assert int(row[b])==expected[a],('cache complete logical result',a,row['token'])
        assert int(row['evaluation'])==bool(expected['rule_id'])
        guarded=dict(facts)
        if not all_rules:guarded.update(ct=None,flowdir=None)
        key=(owner,identity,row['incarnation'],position,tuple(sorted(guarded.items())))
        if hit:assert key in seen,'hit without compatible earlier complete query'
        seen.add(key)
        counts[('match' if expected['rule_id'] else 'no_match')+('_hits' if hit else '_misses')]+=1
    assert counts['hits']>0 and counts['misses']>0 and counts['match_hits']>0 and counts['no_match_hits']>0
    for token,queries in per_token.items():
        assert [int(q['position']) for q in queries] in ([1],[1,2]),'one complete query per position'
        final=finals[token];query=queries[-1]
        for a,b in [('rule','rule'),('rank','rank'),('mode','mode'),('declared','action'),('actual','actual_action')]:
            assert query[a]==final[b],'hit bypassed common final attribution'
    return dict(counts),last,per_token


def verify(directory):
    directory=Path(directory)
    baseline=base.verify(directory)
    run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    assert run.get('cache_validation'),'collector cache mode missing'
    configs=base.configurations(directory,run,pixel)
    if pixel:
        # Controlled VPN startup can emit bootstrap traffic before this run's
        # first edit. Bind it to the inherited saved source and initial query.
        for profile,name in (('root','before-source.conf'),('vpn','root-stopped-source.conf')):
            path=directory/name;source=base.source_reader.source(path)
            base.source_reader.query_source(source,base.props(directory/(profile+'-query.properties')),True)
            configs[(profile,source['revision'])]=(source,base.source_reader.snapshot_hash(path))
    summaries={}
    lives=run['lifetimes'] if pixel else [dict(profile='root',generation=run['generation'])]
    for life in lives:
        profile=life['profile'];generation=life['generation']
        trace=(directory/(profile+'-stop.log' if pixel else 'first-vpp.log')).read_text()
        counts,last,queries=verify_cache_trace(trace,profile,generation,configs,run['uid'] if pixel else 12001)
        counters=run['cache_counters'][profile] if pixel else run['cache_reuse']['counters']
        witness=directory/(profile+'-cache-counters.txt' if pixel else 'cache-final-flow.txt')
        observed=[r for _,r in base.records(witness.read_text(),'policy.cache ')]
        assert observed==counters and len(counters)==2,'readable owner cache status'
        for row in counters:
            assert row['capacity']=='128' and int(row['occupied'])<=128
            assert int(row['storage_bytes'])==21536,'complete fixed cache allocation'
            if row['worker'] in last:
                end=last[row['worker']]
                assert row['hits']==end['hits'] and row['misses']==end['misses'],'CLI counters join query witnesses'
            assert int(row['misses'])==int(row['occupied'])+int(row['replacements'])
        summaries[profile]=counts
        if not pixel:
            reuse=run['cache_reuse'];old,new=reuse['old'],reuse['new']
            assert old['worker']==new['worker'] and old['slot']==new['slot'] and old['incarnation']!=new['incarnation']
            assert int(old['packets'])==6 and int(new['packets'])==4,'cumulative counts reset only for a new Flow instance'
            assert 'flow-end.close=queued' in (directory/'cache-close.txt').read_text()
            closes=[r for _,r in base.records(trace,'s225 event=controlled_close ')]
            assert any(r['owner']==old['worker'] and r['slot']==old['slot'] and r['incarnation']==old['incarnation'] and r['status']=='0' for r in closes)
            endpoints=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
            for case in reuse['cases']:
                assert case['delivered'] and case['response']['kind']=='received'
                nonce=case['nonce'].encode();assert bytes.fromhex(case['response']['data'])==nonce
                assert any(nonce==bytes.fromhex(e.get('data','')) for e in endpoints),'reuse actual endpoint'
                base.query_observation(base.props(directory/case['before']),False,trace)
                base.query_observation(base.props(directory/case['query']),False,trace)
            reuse_sessions={}; reuse_hits=0
            tracker_rows={r['token']:r for _,r in base.records(trace,'s223 event=udp_update ')}
            for _,admit in base.records(trace,'s216 stage=admit '):
                if '43400' not in (admit['src_port'],admit['dst_port']):continue
                facts,flags,payload=base.packet(admit)
                tracker=tracker_rows[admit['token']]
                key=(admit['owner'],tracker['incarnation'])
                endpoints=((facts['src'],facts['sport']),(facts['dst'],facts['dport']))
                if key not in reuse_sessions:
                    assert tracker['created']=='1' and facts['sport']==43400
                    reuse_sessions[key]=dict(origin=endpoints,reply=False,packets=0)
                session=reuse_sessions[key]
                direction=1 if endpoints==session['origin'] else 2
                assert direction==1 or endpoints==session['origin'][::-1]
                session['reply'] |= direction==2
                state=2 if session['reply'] else 1
                session['packets']+=1
                assert tracker['ct_state']==str(state) and tracker['flow_dir']==str(direction),'fresh/reused UDP CT oracle'
                assert int(tracker['orig_packets'])+int(tracker['reply_packets'])==session['packets']
                assert tracker['slot']==old['slot'] and admit['owner']==old['worker']
                q=queries[admit['token']][-1]
                assert q['position']=='2' and q['actual']=='1' and q['evaluation']=='1'
                reuse_hits+=1
            assert sorted(s['packets'] for s in reuse_sessions.values())==[4,6] and reuse_hits==10
            summaries[profile]['reuse_packets']=reuse_hits
            # A new incarnation in the same physical slot must miss on its first
            # post-flow query even while pre-flow packet queries can still hit.
            fresh=[r for qs in queries.values() for r in qs if r['incarnation']==new['incarnation'] and r['position']=='2']
            # Incarnations are owner-local, not globally unique.
            fresh=[r for r in fresh if next(a for _,a in base.records(trace,'s209 event=acquire ') if a['token']==r['token'])['worker']==new['worker']]
            assert fresh and fresh[0]['hit']=='0'
            assert any(r['hit']=='1' for r in fresh),'new Flow can warm independently'
    return dict(status='PASS',scope='T11 representative complete-result cache and CT lifecycle',
                source_sha256=run['source_sha256'],packet_validation=baseline,cache=summaries,
                verifier_sha256=base.digest(__file__),base_verifier_sha256=base.digest(ROOT/'tests/evidence/verify_t07_ct.py'))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory');p.add_argument('--output');args=p.parse_args()
    try: result=verify(args.directory)
    except (AssertionError,KeyError,ValueError,OSError,IndexError,StopIteration) as error:
        result=dict(status='HOLD',error=str(error),run=args.directory)
    if args.output:Path(args.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    if result['status']!='PASS':raise SystemExit(1)
