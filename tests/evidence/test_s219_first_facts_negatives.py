#!/usr/bin/env python3
"""Reject first-arrival substitution, unknown merging and false fragment evidence."""
import argparse,json,re,shutil,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
def verify(run):return subprocess.run(['python3',str(ROOT/'tests/device/verify-s219-first-facts.py'),'--build',str(a.build),'--run',str(run)],capture_output=True,text=True)
checked=verify(a.run);assert checked.returncode==0,checked.stdout+checked.stderr
record=json.loads((a.run/'result.json').read_text());cases={c['label']:c for c in record['cases']}
def first(label):return str(212000000+next(p['case'] for p in cases[label]['packets'] if p['offset']==0))
def field(prefix,token,key,value):
 def mutate(s):return re.sub(r'('+re.escape(prefix)+r'[^\n]*token='+token+r' [^\n]*\b'+key+r'=)\d+',lambda m:m[1]+str(value),s,count=1)
 return mutate
late=first('4-known-late');unknown=first('4-unknown-late');different=first('4-different-late');snapshot=cases['4-snapshot-change'];after=str(212000000+snapshot['packets'][1]['case'])
mutations={
 'first_arrival_substituted':('vpp.log',field('s212 event=native_success ',late,'uid',0)),
 'unknown_first_merged':('vpp.log',field('s212 event=native_success ',unknown,'uid',21900)),
 'later_context_overwrite':('vpp.log',field('s212 event=native_success ',different,'context',1)),
 'opaque_ifindex_lost':('vpp.log',field('s216 stage=admit ',late,'ifindex',0)),
 'provenance_overwrite':('vpp.log',field('s216 stage=policy ',different,'provenance',2)),
 'snapshot_not_updated':('vpp.log',field('s219 event=controlled_fragment ',after,'snapshot_revision',snapshot['snapshot_before'])),
 'original_packet_id_replaced':('vpp.log',field('s212 event=completion_publish ',late,'packet',999)),
 'missing_native_success':('vpp.log',lambda s:re.sub(r'^s212 event=native_success [^\n]*\n','',s,count=1,flags=re.M)),
 'duplicate_completion':('vpp.log',lambda s:s+'\n'+next(l for l in s.splitlines() if l.startswith('s212 event=completion_publish '))+'\n'),
 'missing_physical_free':('vpp.log',lambda s:re.sub(r'^s203 event=buffer_free [^\n]*\n','',s,count=1,flags=re.M)),
 'fabricated_nfq_source':('result.json',lambda s:s.replace('"source": "GRAPH_INJECTED"','"source": "NFQ_CAPTURED"')),
 'missing_first_not_timeout':('vpp.log',field('s212 event=completion_publish ',str(212000000+cases['4-no-first']['packets'][0]['case']),'drop_reason',0)),
}
results=[]
for name,(filename,mutate) in mutations.items():
 with tempfile.TemporaryDirectory(prefix='s219-negative-') as tmp:
  dest=Path(tmp)/'run';shutil.copytree(a.run,dest);path=dest/filename;old=path.read_text();new=mutate(old);assert old!=new,name;path.write_text(new)
  checked=verify(dest);assert checked.returncode!=0,name
  result=json.loads((dest/'verification.json').read_text());assert result['status']=='HOLD' and result['errors'],name
  results.append(dict(name=name,rejected=True,errors=result['errors']))
a.output.write_text(json.dumps(results,indent=2)+'\n');print(f'PASS: {len(results)} first-facts evidence mutations rejected')
