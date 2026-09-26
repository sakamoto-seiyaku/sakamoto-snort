#!/usr/bin/env python3
"""Derive descriptive E01 metrics, not acceptance thresholds or causal winners."""
import argparse,json,statistics
from pathlib import Path

def percentile(xs,p):
    if not xs:return None
    xs=sorted(xs);return xs[min(len(xs)-1,int((len(xs)-1)*p))]
def integer(value):return int(str(value).split()[0])
def metrics(directory):
    directory=Path(directory);result=json.loads((directory/'result.json').read_text());android=result['kind']=='android';rows=[]
    for index,arm in enumerate(result['arms']):
        prefix=directory/f"{index:02d}-{arm['config']['arm']}";phases=[]
        for phase in arm['phases']:
            name=phase['name'];resource=json.loads((prefix/(name+'-resources.json')).read_text())
            traffic=json.loads((prefix/('e01_'+name+'.json' if android else name+'-traffic.json')).read_text())
            if android:traffic=traffic['e01']
            before=json.loads((prefix/(name+'-before.json')).read_text());after=json.loads((prefix/(name+'-settled.json')).read_text())
            row={'name':name,'sent':traffic['sent'],'echoed':traffic['received'],'workload_seconds':(traffic['completedMonoNs']-traffic['startedMonoNs'])/1e9}
            rtt=[(r['endMonoNs']-r['sentMonoNs'])/1e6 for r in traffic['exchanges'] if r['echoed']]
            row['rtt_ms']={'p50':percentile(rtt,.5),'p99':percentile(rtt,.99),'max':max(rtt) if rtt else None}
            for who in ('vpp','rust'):
                x,y=resource['before'][who],resource['after'][who];hz=result.get('clock_ticks',100) if android else resource['before']['clock_ticks']
                cpu=lambda v:v['stats'][0]['cpu_ticks'] if android else v['cpu_ticks']
                fields=lambda v:v['fields'] if android else v['status']
                io=lambda v:v['fields'] if android else v['io']
                row[who+'_cpu_ms']=(cpu(y)-cpu(x))*1000/hz
                row[who+'_rss_kib']=integer(fields(y)['VmRSS']);row[who+'_hwm_kib']=integer(fields(y)['VmHWM'])
                row[who+'_write_bytes']=int(io(y)['write_bytes'])-int(io(x)['write_bytes'])
                row[who+'_read_bytes']=int(io(y)['read_bytes'])-int(io(x)['read_bytes'])
                row[who+'_voluntary_switches']=sum(v['voluntary'] for v in y.get('threads',{}).values())-sum(v['voluntary'] for v in x.get('threads',{}).values())
                row[who+'_involuntary_switches']=sum(v['involuntary'] for v in y.get('threads',{}).values())-sum(v['involuntary'] for v in x.get('threads',{}).values())
            def consumer_cpu(v):
                if android:return sum(t['cpu_ticks'] for t in v['stats'][1:] if t['name'].startswith('flow-observ'))
                return sum(t['cpu_ticks'] for t in v['threads'].values() if t['name'].startswith('flow-observ'))
            row['consumer_thread_cpu_ms']=(consumer_cpu(resource['after']['rust'])-consumer_cpu(resource['before']['rust']))*1000/hz
            c0,c1=before['consumer'],after['consumer'];e0,e1=c0['e01'],c1['e01']
            row.update(store_batches=e1['batches']-e0['batches'],store_records=e1['records']-e0['records'],store_elapsed_ms=(e1['consume_ns']-e0['consume_ns'])/1e6,store_query_ms=(e1['query_ns']-e0['query_ns'])/1e6,
                waits=c1['waits']-c0['waits'],notifications=sum(x['notifications'] for x in after['health']['channels'])-sum(x['notifications'] for x in before['health']['channels']),
                basic_packets=sum(x['basic_packets'][0] for x in after['health']['channels']),observed_packets=sum(c1['overview']['packets']),persistent_packets=sum(c1['persistent']['packets']) if c1['persistent'] else None,
                full=sum(x['full'] for x in after['health']['channels']),final_snapshot_bytes=((prefix/'observation'/('e01-'+arm['config']['name']+'.json')) if not android else (prefix/'final-store.json')).stat().st_size if (prefix/'final-store.json').exists() else 0)
            phases.append(row)
        final=json.loads((prefix/'final.json').read_text());e=final['consumer']['e01'];samples=e['samples']
        normal=[x for x in phases if x['name'] not in ('pause','recovery')]
        summary={k:sum(x[k] for x in normal) for k in ['sent','echoed','vpp_cpu_ms','rust_cpu_ms','consumer_thread_cpu_ms','rust_write_bytes','store_batches','store_records','store_elapsed_ms','store_query_ms','waits','notifications']}
        summary['store_batch_ms']={'p50':percentile([s[1]/1e6 for s in samples],.5),'p99':percentile([s[1]/1e6 for s in samples],.99),'max':e['max_consume_ns']/1e6}
        summary['batch_max_activity_age_ms']={'p50':percentile([s[2]/1000 for s in samples],.5),'p99':percentile([s[2]/1000 for s in samples],.99)}
        summary['peak_sampled_rust_rss_kib']=max(x['rust_rss_kib'] for x in phases)
        summary['peak_rust_hwm_kib']=max(x['rust_hwm_kib'] for x in phases)
        fresh=prefix/'freshness-polls.json'
        if fresh.exists():
            f=json.loads(fresh.read_text());t=json.loads((prefix/'freshness-traffic.json').read_text());polls=f['polls']
            if polls:summary['last_freshness_poll_ms']=(polls[-1]['query_completed_mono_ns']-t['exchanges'][0]['sentMonoNs'])/1e6
        rows.append({'arm':arm['config']['arm'],'generation':arm['generation'],'synthetic_seed_baselines':arm.get('synthetic_seed_baselines',0),'consumer_ready_wait_ms':arm.get('consumer_ready_wait_ns',0)/1e6,'summary':summary,'phases':phases})
    return {'kind':result['kind'],'profile':result.get('profile','root'),'source_sha256':result['source_sha256'],'notes':['Descriptive observations only; no performance gate.','Rust process on Android is RuntimeService; consumer thread is reported separately.','Kernel I/O accounting is not measured NAND energy or write wear.','Store elapsed includes copy/delta/serialization/fsync/rename; query elapsed is separate.','Activity-age percentiles are per-batch maximums, not per-record delivery percentiles.','Store sample list is a bounded prefix of at most 4096 batches.'],'arms':rows}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();v=metrics(a.directory);a.output.write_text(json.dumps(v,indent=2)+'\n');print(json.dumps({'kind':v['kind'],'arms':len(v['arms'])}))
