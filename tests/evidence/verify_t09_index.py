#!/usr/bin/env python3
"""Independently join T09 resource/query witnesses to real packet decisions."""
import argparse
import json
from pathlib import Path
import statistics
import verify_t08_placement as v

def verify(directory):
    directory=Path(directory)
    verified=v.verify(directory)
    run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    configs=v.configurations(directory,run,pixel)
    resources={}
    for path in directory.glob('*-index.txt'):
        rows=v.records(path.read_text(),'policy.index ')
        assert len(rows)==1, ('missing resource query',path.name)
        row=rows[0][1]
        identity=(int(row['generation']),int(row['revision']),int(row['hash']))
        matches=[s for (_,revision),(s,h,_) in configs.items() if revision==identity[1] and h==identity[2]]
        assert len(matches)==1, 'resource source identity'
        assert int(row['entries'])==len(matches[0]['rules']), 'whole-rule index entries'
        assert 1<=int(row['masks'])<=int(row['entries'])
        assert int(row['view_bytes'])==38160, 'native immutable view layout'
        assert 16<=int(row['max_query_work'])<=400, 'published complete-query bound'
        resources[identity]=row
    assert resources and any(int(r['masks'])<int(r['entries']) for r in resources.values()), 'same-mask sharing observed'
    lifetimes=run['lifetimes'] if pixel else [dict(profile='root',generation=run['generation'])]
    total_queries=0;durations=[];work=[]
    for life in lifetimes:
        profile=life['profile'];generation=life['generation']
        trace=(directory/(profile+'-stop.log' if pixel else 'first-vpp.log')).read_text()
        ports=[c['port'] for c in run['cases'] if c['profile']==profile] if pixel else [43100,43101,43102,43200,43201,43202,43300]
        packets,_,_=v.verify_trace(trace,profile,generation,ports,configs,run['uid'] if pixel else 12001)
        query_rows=v.records(trace,'t09 event=query ')
        for packet in packets:
            match=packet['match'];token=match['token']
            queries=[row for _,row in query_rows if row['token']==token and int(row['generation'])==generation]
            assert len(queries) in (1,2), 'complete packet query sequence'
            assert [int(q['position']) for q in queries]==([1] if len(queries)==1 else [1,2]), 'unique whole-rule position'
            assert (int(queries[0]['rule'])!=0)==(len(queries)==1), 'PRE complete winner or POST continuation'
            assert queries[-1]['rule']==match['rule'] and queries[-1]['rank']==match['rank'], 'final query winner'
            for query in queries:
                assert query['revision']==match['revision'] and query['snapshot_hash']==match['snapshot_hash'], 'query snapshot identity'
                assert int(query['status'])==0
                assert (int(query['rule'])==0)==(int(query['rank'])==0), 'NoMatch has no winner Rank'
                assert 0<=int(query['subject_probes'])<=16
                assert 0<=int(query['residuals'])<=int(query['keys'])<=128
                assert 0<=int(query['masks'])<=128
                amount=sum(int(query[k]) for k in ('subject_probes','residuals','keys','masks'))
                identity=(int(query['generation']),int(query['revision']),int(query['snapshot_hash']))
                assert identity in resources, 'query resource witness'
                assert amount<=int(resources[identity]['max_query_work'])<=400, 'query work bound'
                assert int(query['query_ns'])>=0
                work.append(amount);durations.append(int(query['query_ns']));total_queries+=1
    return dict(status='PASS',scope='T09 real packet index/Rank/resource representative acceptance',
        source_sha256=verified['source_sha256'],packets=verified['totals'],queries=total_queries,
        resource_snapshots=len(resources),max_query_work=max(work),query_ns_median=statistics.median(durations),
        query_ns_max=max(durations),verifier_sha256=v.digest(__file__))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args();result=verify(args.directory);text=json.dumps(result,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text)
