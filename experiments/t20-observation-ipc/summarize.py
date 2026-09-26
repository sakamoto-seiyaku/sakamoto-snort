#!/usr/bin/env python3
"""Describe the retained repetitions without inventing acceptance thresholds."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics

p=argparse.ArgumentParser();p.add_argument('verification',type=Path);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();v=json.loads(a.verification.read_text());assert v['status'] in ['PASS','VERIFIED_WITH_UNMET_GATES']
def distribution(values):
    return {'min':min(values),'median':statistics.median(values),'max':max(values),'values':values}
fields={
    'producer_cpu_ms':('producer_timing','cpu_ns',1e6),
    'producer_wall_ms':('producer_timing','wall_ns',1e6),
    'queue_p99_us':('producer_timing','attempt_p99_ns',1e3),
    'export_p99_us':('producer_timing','export_p99_ns',1e3),
    'export_max_us':('producer_timing','export_max_ns',1e3),
    'producer_idle_cpu_ms':('producer_timing','idle_cpu_ns',1e6),
    'consumer_cpu_ms':('consumer_result','cpu_ns',1e6),
    'consumer_wall_ms':('consumer_result','wall_ns',1e6),
    'latency_p50_us':('consumer_result','latency_p50_ns',1e3),
    'latency_p95_us':('consumer_result','latency_p95_ns',1e3),
    'latency_p99_us':('consumer_result','latency_p99_ns',1e3),
    'latency_max_us':('consumer_result','latency_max_ns',1e3),
    'wait_calls':('consumer','waits',1),'signals_read':('consumer','signals_read',1),
    'consumer_rss_kib':('consumer','current_rss_kib',1),
    'producer_rss_kib':('producer','current_rss_kib',1),
    'consumer_virtual_kib':('consumer','virtual_kib',1),
    'producer_virtual_kib':('producer','virtual_kib',1),
    'consumer_voluntary_switches':('consumer','voluntary_switches',1),
    'consumer_involuntary_switches':('consumer','involuntary_switches',1)}
summary={}
for name in dict.fromkeys(r['name'] for r in v['reports']):
    summary[name]={}
    for candidate in ['aeron','vpp','minimal']:
        records=[r for r in v['reports'] if r['name']==name and r['candidate']==candidate]
        assert len(records)==3
        values={key:distribution([r[role][field]/scale for r in records]) for key,(role,field,scale) in fields.items() if all(role in r for r in records)}
        if all('consumer_result' in r for r in records):
            values['combined_cpu_ms']=distribution([(r['producer_timing']['cpu_ns']+r['consumer_result']['cpu_ns'])/1e6 for r in records])
        for c in range(2):
            for field in ['accepted','dropped','bytes','prewait']:
                values[f'channel{c}_{field}']=distribution([r['producer']['channels'][c][field] for r in records])
        values['shared_bytes']=distribution([r['producer']['shared_bytes'] for r in records])
        values['offered_records_per_second']=distribution([r['producer_timing']['count']*1e9/r['producer_timing']['wall_ns'] for r in records])
        summary[name][candidate]=values
result={'status':v['status'],'unmet_gates':v.get('unmet_gates',[]),'verification_sha256':hashlib.sha256(a.verification.read_bytes()).hexdigest(),'repetitions':3,'summary':summary}
a.output.write_text(json.dumps(result,indent=2)+'\n')
for name,candidates in summary.items():
    for candidate,d in candidates.items():
        def median(key):return round(d[key]['median'],3) if key in d else None
        print(name,candidate,{key:median(key) for key in ['producer_cpu_ms','consumer_cpu_ms','export_p99_us','latency_p99_us','wait_calls','channel0_accepted','channel0_dropped']})
