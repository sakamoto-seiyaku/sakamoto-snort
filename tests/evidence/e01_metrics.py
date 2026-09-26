#!/usr/bin/env python3
"""Descriptive E01 metrics with distinct traffic and closed settlement windows."""
import argparse,json
from pathlib import Path

def percentile(xs,p):
    if not xs:return None
    xs=sorted(xs);return xs[min(len(xs)-1,int((len(xs)-1)*p))]
def integer(value):return int(str(value).split()[0])
def resource_delta(before,after,android,hz):
    row={}
    for who in ('vpp','rust'):
        x,y=before[who],after[who]
        assert x['pid']==y['pid']
        cpu=lambda v:v['stats'][0]['cpu_ticks'] if android else v['cpu_ticks']
        fields=lambda v:v['fields'] if android else v['status']
        io=lambda v:v['fields'] if android else v['io']
        row[who+'_cpu_ms']=(cpu(y)-cpu(x))*1000/hz
        row[who+'_rss_kib']=integer(fields(y)['VmRSS'])
        row[who+'_hwm_kib']=integer(fields(y)['VmHWM'])
        for field in ('write_bytes','read_bytes'):row[who+'_'+field]=int(io(y)[field])-int(io(x)[field])
        old_threads,new_threads=x.get('threads',{}),y.get('threads',{})
        common=old_threads.keys() & new_threads.keys()
        for field in ('voluntary','involuntary'):
            row[who+'_'+field+'_switches']=sum(new_threads[tid][field]-old_threads[tid][field] for tid in common)
        row[who+'_thread_turnover']={'entered':len(new_threads.keys()-old_threads.keys()),'exited':len(old_threads.keys()-new_threads.keys())}
    def consumer_cpu(v):
        if android:return sum(t['cpu_ticks'] for t in v['stats'][1:] if t['name'].startswith('flow-observ'))
        return sum(t['cpu_ticks'] for t in v['threads'].values() if t['name'].startswith('flow-observ'))
    row['consumer_thread_cpu_ms']=(consumer_cpu(after['rust'])-consumer_cpu(before['rust']))*1000/hz
    return row

def counters(before,after):
    c0,c1=before['consumer'],after['consumer'];e0,e1=c0['e01'],c1['e01']
    return dict(store_batches=e1['batches']-e0['batches'],store_records=e1['records']-e0['records'],
        store_elapsed_ms=(e1['consume_ns']-e0['consume_ns'])/1e6,store_query_ms=(e1['query_ns']-e0['query_ns'])/1e6,
        waits=c1['waits']-c0['waits'],notifications=sum(x['notifications'] for x in after['health']['channels'])-sum(x['notifications'] for x in before['health']['channels']))

def metrics(directory):
    directory=Path(directory);result=json.loads((directory/'result.json').read_text());android=result['kind']=='android';rows=[]
    for index,arm in enumerate(result['arms']):
        prefix=directory/f"{index:02d}-{arm['config']['arm']}"
        def data(name):return json.loads((prefix/name).read_text())
        phases=[];resource_samples=[]
        for phase_index,phase in enumerate(arm['phases']):
            name=phase['name'];resource=data(name+'-resources.json');resource_samples.extend([resource['before'],resource['after']])
            hz=result.get('clock_ticks',100) if android else resource['before']['clock_ticks']
            traffic=data('e01_'+name+'.json' if android else name+'-traffic.json')
            if android:traffic=traffic['e01']
            before=data(name+'-before.json');settled=data(name+'-settled.json')
            row={'name':name,'sent':traffic['sent'],'echoed':traffic['received'],
                'workload_seconds':(traffic['completedMonoNs']-traffic['startedMonoNs'])/1e9}
            rtt=[(r['endMonoNs']-r['sentMonoNs'])/1e6 for r in traffic['exchanges'] if r['echoed']]
            row['rtt_ms']={'p50':percentile(rtt,.5),'p99':percentile(rtt,.99),'max':max(rtt) if rtt else None}
            # Traffic-only snapshots deliberately remain separate: deferred
            # refresh/write CPU is not attributed to this shorter interval.
            row['traffic_window']=resource_delta(resource['before'],resource['after'],android,hz)
            direct=prefix/(name+'-resources-settled.json')
            if direct.exists():
                end=json.loads(direct.read_text());end_state=settled
                method='direct resource sample after settling and normal API query'
            elif phase_index+1<len(arm['phases']):
                next_name=arm['phases'][phase_index+1]['name']
                end=data(next_name+'-resources.json')['before'];end_state=data(next_name+'-before.json')
                method='retained next-phase pre-send sample; includes settling, diagnostic queries and phase control'
            else:end=None
            if end is not None:
                resource_samples.append(end)
                row['closed_window']={**resource_delta(resource['before'],end,android,hz),**counters(before,end_state),'method':method}
            else:row['closed_window']=None
            row.update(basic_packets=sum(x['basic_packets'][0] for x in settled['health']['channels']),
                observed_packets=sum(settled['consumer']['overview']['packets']),
                persistent_packets=sum(settled['consumer']['persistent']['packets']) if settled['consumer']['persistent'] else None,
                full=sum(x['full'] for x in settled['health']['channels']))
            phases.append(row)
        final=data('final.json');e=final['consumer']['e01'];samples=e['samples']
        normal=[x for x in phases if x['name'] not in ('pause','recovery')]
        assert all(x['closed_window'] is not None for x in normal),'missing closed cost interval'
        keys=['vpp_cpu_ms','rust_cpu_ms','consumer_thread_cpu_ms','rust_write_bytes','store_batches','store_records','store_elapsed_ms','store_query_ms','waits','notifications']
        summary={k:sum(x['closed_window'][k] for x in normal) for k in keys}
        summary.update(sent=sum(x['sent'] for x in normal),echoed=sum(x['echoed'] for x in normal))
        summary['closed_window_methods']=sorted(set(x['closed_window']['method'] for x in normal))
        summary['all_run_store_batch_ms']={'p50':percentile([s[1]/1e6 for s in samples],.5),'p99':percentile([s[1]/1e6 for s in samples],.99),'max':e['max_consume_ns']/1e6}
        summary['all_run_batch_max_activity_age_ms']={'p50':percentile([s[2]/1000 for s in samples],.5),'p99':percentile([s[2]/1000 for s in samples],.99)}
        summary['peak_sampled_rust_rss_kib']=max(integer(s['rust']['fields' if android else 'status']['VmRSS']) for s in resource_samples)
        summary['peak_rust_hwm_kib']=max(integer(s['rust']['fields' if android else 'status']['VmHWM']) for s in resource_samples)
        store=(prefix/'observation'/('e01-'+arm['config']['name']+'.json')) if not android else prefix/'final-store.json'
        summary['final_snapshot_bytes']=store.stat().st_size if store.exists() else 0
        fresh=prefix/'freshness-polls.json'
        if fresh.exists():
            f=data('freshness-polls.json');t=data('freshness-traffic.json');polls=f['polls']
            reached=bool(polls) and polls[-1]['overview_packets']>=f['target'] and (not arm['config']['store'] or (polls[-1]['persistent_packets'] is not None and polls[-1]['persistent_packets']>=f['target']))
            summary['freshness']={'target_reached':reached,'last_poll_ms':(polls[-1]['query_completed_mono_ns']-t['exchanges'][0]['sentMonoNs'])/1e6 if polls else None}
        rows.append({'arm':arm['config']['arm'],'generation':arm['generation'],'synthetic_seed_baselines':arm.get('synthetic_seed_baselines',0),'consumer_ready_wait_ms':arm.get('consumer_ready_wait_ns',0)/1e6,'summary':summary,'phases':phases})
    return {'kind':result['kind'],'profile':result.get('profile','root'),'source_sha256':result['source_sha256'],
        'notes':['Descriptive observations only; no performance gate.','Closed windows include deferred refresh/persistence and explicitly identified diagnostic/control work.','Traffic-only CPU snapshots are separate and cannot be paired with settled store counters.','Android Rust process means RuntimeService; consumer thread is also reported separately.','Kernel I/O accounting is not NAND energy or wear.','Activity ages include delayed state-only END records and are not delivery-latency percentiles.','Context-switch deltas use only threads present at both boundaries; turnover is reported and counts are not wakeup totals.','At most 4096 store batch samples are retained.'], 'arms':rows}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    value=metrics(a.directory);a.output.write_text(json.dumps(value,indent=2)+'\n');print(json.dumps({'kind':value['kind'],'arms':len(value['arms'])}))
