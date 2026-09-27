#!/usr/bin/env python3
"""Independent scale/resource check over T30 Product-run evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

p=argparse.ArgumentParser()
p.add_argument('--evidence',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
root=a.evidence.resolve()

cases=(('linux-baseline-c','linux-samples-c','linux',4,1),
       ('linux-scaled-c','linux-samples-d','linux',64,65),
       ('linux-supplement-f','linux-samples-f','linux',64,65),
       ('pixel-baseline-b','pixel-samples-b','pixel',4,1),
       ('pixel-scaled-d','pixel-samples-d','pixel',64,65))

def read(path):return Path(path).read_text()
def data(path):return json.loads(read(path))
def props(text):return dict(line.split('=',1) for line in text.splitlines()
                            if '=' in line and not line.startswith('#'))
def cli_lines(path,prefix):
    return [dict(part.split('=',1) for part in line.split()[1:] if '=' in part)
            for line in read(path).splitlines() if line.startswith(prefix+' ')]
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def process_summary(rows,label,pid=None):
    values=[]
    for row in rows:
        if row.get('pids',{}).get(label) is None:continue
        if pid is not None and row['pids'][label]!=pid:continue
        item=row.get('processes',{}).get(label,{})
        if 'VmRSS' in item:values.append(item)
    assert len(values)>=8,(label,pid,len(values))
    def delta(*keys):
        return sum(values[-1].get(key,0)-values[0].get(key,0) for key in keys)
    return dict(samples=len(values),pid=pid or next(row['pids'][label] for row in rows
                   if row.get('pids',{}).get(label) is not None),
                rss_peak_kib=max(v['VmRSS'] for v in values),
                hwm_peak_kib=max(v['VmHWM'] for v in values),
                cpu_ticks=delta('utime_ticks','stime_ticks'),
                context_switches=delta('voluntary_ctxt_switches','nonvoluntary_ctxt_switches'),
                write_bytes=delta('write_bytes'))

summary={}
for name,sample_name,platform,rule_count,domain_count in cases:
    run=root/name;sample=root/sample_name
    raw=data(run/'result.json');oracle=data(root/(name+'-verification.json'))
    capture=data(sample/'result.json')
    assert raw['status']=='RAW_COMPLETE' and raw['process_absent']
    assert not raw.get('cleanup_error') and not raw.get('cleanup_config_error')
    assert oracle['status']=='VALID' and capture['returncode']==0
    assert raw['source_sha256']==oracle['source_sha256']
    assert raw['runner_sha256']==digest(run/'runner.py')
    assert capture['collector_sha256']==digest(sample/'collector.py')
    assert raw.get('ordinary_history_unchanged',True) is True
    configurations=[];resources=[]
    for config in raw['configurations']:
        q=props(read(run/config['query']))
        count_key='activeCount' if platform=='pixel' else 'config.active_count'
        domain_key='domainEntryCount' if platform=='pixel' else 'config.domain_entry_count'
        assert int(q[count_key])==rule_count and int(q[domain_key])==domain_count
        request=read(run/(config['label']+'-request.txt'))
        assert request.count('domain 0 exact ') == domain_count
        if rule_count==64:
            assert 'cost-063.example.test' in request
            assert '60059 60059' in request
        configurations.append(dict(label=config['label'],revision=config['revision'],
                                   rules=int(q[count_key]),domains=int(q[domain_key])))
        path=run/(config['label']+'-resources.txt')
        if path.exists():
            indices=cli_lines(path,'policy.index');plans=cli_lines(path,'policy.plan')
            snapshots=cli_lines(path,'policy.snapshot')
            assert len(indices)==len(plans)==len(snapshots)==1
            index,plan,snapshot=indices[0],plans[0],snapshots[0]
            assert int(index['revision'])==int(plan['revision'])==int(snapshot['revision'])==config['revision']
            assert int(plan['publication_peak_bytes'])<=int(plan['publication_limit_bytes'])
            assert int(index['entries'])==rule_count
            budget=cli_lines(path,'rule.budget')
            if budget:assert int(budget[0]['peak_bytes'])<=int(budget[0]['limit_bytes'])
            resources.append(dict(label=config['label'],index=index,plan=plan,
                                  snapshot=snapshot,budget=budget[0] if budget else None))
    assert len(configurations)==(3 if platform=='linux' else 6)
    samples=[json.loads(line) for line in read(sample/'samples.jsonl').splitlines()]
    assert len(samples)>=25 and all(x['monotonic_ns']<y['monotonic_ns']
                                  for x,y in zip(samples,samples[1:]))
    processes={}
    if platform=='linux':
        processes['vpp']=process_summary(samples,'vpp')
        processes['consumer']=process_summary(samples,'consumer')
    else:
        for life in raw['lifetimes']:
            processes[life['profile']+'-vpp']=process_summary(samples,'vpp',life['pid'])
        processes['runtime']=process_summary(samples,'runtime')
        assert oracle['ordinary_history_unchanged'] is True
        assert all(x['rtp_endpoint_exchanges']==29 and x['quic_echoes']==25
                   and x['policy_drops']==1 for x in oracle['profiles'].values())
    ops=[json.loads(line) for line in read(run/'cost-operations.jsonl').splitlines()]
    apply_ms=[(x['completed_ns']-x['started_ns'])/1e6 for x in ops
              if x['operation'] in ('rule-replace-all','replace-all-ui')]
    assert len(apply_ms)==(3 if platform=='linux' else 6)
    query_ms=[(x['completed_ns']-x['started_ns'])/1e6 for x in ops
              if x['operation']=='rule-query']
    if platform=='linux':assert len(query_ms)>=8
    store_peaks=[sum(row['store_files'].values()) for row in samples
                 if row.get('store_files')]
    flow_names=(('rtp-recovered-flow.txt',) if platform=='linux' else
                ('root-rtp-budget-flow.txt','vpn-rtp-budget-flow.txt'))
    flow_stats=[]
    for flow_name in flow_names:
        path=run/flow_name
        cache=cli_lines(path,'policy.cache');pool=cli_lines(path,'flow.runtime')
        lpi=cli_lines(path,'flow.lpi');sni=cli_lines(path,'flow.sni')
        assert len(cache)==len(pool)==2 and len(lpi)>=2 and len(sni)>=2
        assert all(int(x['capacity_misses'])==0 for x in pool)
        assert sum(int(x['hits']) for x in cache)>0
        flow_stats.append(dict(label=flow_name,cache=cache,flow_pool=pool,
                               lpi=lpi,sni=sni))
    battery={}
    if platform=='pixel':
        for end in ('before','after'):
            text=read(sample/(end+'-battery.txt'))
            battery[end]={'temperature_deci_c':next((int(line.partition(':')[2].strip())
                for line in text.splitlines() if line.strip().startswith('temperature:')),None),
                'status':next((line.partition(':')[2].strip() for line in text.splitlines()
                    if line.strip().startswith('status:')),None)}
    summary[name]=dict(platform=platform,source_sha256=raw['source_sha256'],
        duration_seconds=round((raw['completed_ns']-raw['started_ns'])/1e9,3),
        configurations=configurations,resource_snapshots=resources,
        processes=processes,samples=len(samples),
        apply_ms=[round(x,3) for x in apply_ms],apply_median_ms=round(statistics.median(apply_ms),3),
        query_ms=[round(x,3) for x in query_ms],
        query_median_ms=round(statistics.median(query_ms),3) if query_ms else None,
        sampled_store_peak_bytes=max(store_peaks,default=None),
        flow_stats=flow_stats,battery=battery,
        independent_verifier_sha256=oracle['verifier_sha256'])

stress=data(root.parent/'t29-20260927/pixel-stress-f-recheck.json')
assert stress['status']=='VALID' and stress['ordinary_history_unchanged'] is True
assert all(x['channel_full_delta']>0 and x['sent']==10006 for x in stress['profiles'].values())
assert summary['linux-scaled-c']['sampled_store_peak_bytes'] is not None
assert summary['pixel-scaled-d']['sampled_store_peak_bytes'] is not None
answer=dict(status='VALID',cases=summary,prior_pressure=dict(source_sha256=stress['source_sha256'],
    profiles={key:dict(channel_full_delta=value['channel_full_delta'],
                       sent=value['sent'],flow_packets=value['full_flow_packets'])
              for key,value in stress['profiles'].items()}),
    verifier_sha256=digest(__file__))
a.output.write_text(json.dumps(answer,indent=2)+'\n')
print(json.dumps(dict(status='VALID',cases={name:dict(duration_seconds=value['duration_seconds'],
    apply_median_ms=value['apply_median_ms'],sampled_store_peak_bytes=value['sampled_store_peak_bytes'])
    for name,value in summary.items()}),indent=2))
