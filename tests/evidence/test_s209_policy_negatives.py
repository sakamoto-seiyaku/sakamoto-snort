#!/usr/bin/env python3
"""Semantic S209 evidence corruptions must fail independently of source binding."""
import argparse,importlib.util,json,re,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('verify',ROOT/'tests/device/verify-s209-policy.py');v=importlib.util.module_from_spec(s);s.loader.exec_module(v)
p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
positive=v.verify(a.run,a.build,'linux');assert positive['status']=='PASS',positive['errors']
a.output.mkdir(parents=True,exist_ok=False);results=[]
cases=[
 ('bank-content','vpp.log','s209 event=release ','content_hash','acquired bank content survives release'),
 ('cache-generation','vpp.log','s208 event=observe ','policy_generation','decision cache carries complete acquired identity'),
 ('gate-omission','vpp.log','s209 event=gate ','rule','Gate evaluates acquired content'),
 ('l4-wrong-view','vpp.log','s209 event=l4 ','rule','L4 evaluates acquired content'),
 ('premature-reuse','vpp.log','s209 event=publish ','reuse_begin_ns','bank never overwritten while packet holds reader'),
 ('stale-acquisition','vpp.log','s209 event=acquire ','sequence','no stale snapshot acquisition after publication'),
 ('packet-lock','runtime.txt','policy.snapshot ','packet_lock_acquisitions','no packet writer-lock acquisition'),
]
for name,filename,prefix,field,expected in cases:
 clone=a.output/name;shutil.copytree(a.run,clone);target=clone/'g0'/filename;lines=target.read_text().splitlines(True)
 for i,line in enumerate(lines):
  if not line.startswith(prefix):continue
  d=dict(x.split('=',1) for x in line.split()[1:] if '=' in x)
  if name in ('gate-omission','l4-wrong-view') and d['rule']=='0':continue
  if name=='premature-reuse' and d['snapshot_hash']!='203':continue
  if name=='stale-acquisition' and int(d['sequence'])<=2:continue
  old=d[field]
  value='0' if name=='gate-omission' else '1' if name=='premature-reuse' else str(int(old)-2) if name=='stale-acquisition' else str(int(old)+1)
  lines[i]=re.sub(r'(?<!\S)'+field+r'=[^\s]+',field+'='+value,line,count=1);break
 else:raise AssertionError('no mutation target '+name)
 target.write_text(''.join(lines));result=v.verify(clone,a.build,'linux')
 assert result['status']=='HOLD' and any(expected in e for e in result['errors']),(name,result['errors'])
 results.append(dict(case=name,status=result['status'],expected_rejection=expected,errors=result['errors']))
(a.output/'results.json').write_text(json.dumps(results,indent=2)+'\n');print('S209 seven semantic evidence corruptions rejected')
