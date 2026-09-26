#!/usr/bin/env python3
"""Synthetic valid historical zero-contribution baselines, not real Flow evidence."""
import argparse,json
from pathlib import Path

def state(count):
    assert 0<=count<=100000
    baselines={}
    for i in range(count):
        generation=1+i//2048;owner=(i//1024)%2;slot=i%1024
        record={'generation':generation,'owner':owner,'slot':slot,'incarnation':1,'sequence':1,
            'first_seen':1,'last_seen':1,'activity_utc_us':1700000000000000,'clock_changed':False,
            'packets':[0,0],'bytes':[0,0],'ended':False,'uid':12001,'network':0,'family':4,'protocol':17,
            'origin_device_direction':3,'last_device_direction':3,'last_flow_direction':0,'end_reason':0,
            'ports':[43000,42141],'addresses':[10,224,0,1,10,224,0,2],'policy_revision':1,'winner':0}
        baselines[f'{generation}:{owner}:{slot}']={'record':record,'first_end_us':None}
    return {'schema':1,'baselines':baselines,'recent':{},'minutes':{},'totals':{'packets':[0,0],'bytes':[0,0]},
        'ended':0,'accepted':count,'rejected':0,'gaps':0,'clock_changes':0,'open_session':False,
        'recoveries':0,'first_activity_us':None,'last_activity_us':None}
def write(path,count):
    path=Path(path);path.write_text(json.dumps(state(count),separators=(',',':')));path.chmod(0o600)
    return path.stat().st_size
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--count',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps({'synthetic_baselines':a.count,'bytes':write(a.output,a.count)}))
