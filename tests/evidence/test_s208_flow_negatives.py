#!/usr/bin/env python3
"""Reject plausible but corrupted S208 flow evidence without altering originals."""
import argparse, importlib.util, json, re, shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('verify',ROOT/'tests/device/verify-s208-flow.py');v=importlib.util.module_from_spec(s);s.loader.exec_module(v)
p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
positive=v.verify(a.run,a.build,'linux');assert positive['status']=='PASS',positive['errors']
a.output.mkdir(parents=True,exist_ok=False);results=[]
for name,filename,prefix,field,expected in [
 ('stored-origin','runtime.txt','flow.entry ','origin_is_a','actual stored entry origin_is_a'),
 ('foreign-pool','vpp.log','s208 event=observe ','pool_worker','current-worker pool'),
 ('drop-mutation','vpp.log','s208 event=early_drop ','event','early DROP has no entry'),
 ('reset-counters','r3-flows.txt','flow.entry ','packets','counters continue across revision'),
 ('wrong-full-key','runtime.txt','flow.entry ','key_a','actual stored entry key_a')]:
 clone=a.output/name;shutil.copytree(a.run,clone);target=clone/'g0'/filename;lines=target.read_text().splitlines(True)
 for i,line in enumerate(lines):
  if line.startswith(prefix):
   old=re.search(r'(?:^| )'+field+r'=([^ ]+)',line)[1]
   value=('observe' if field=='event' else '0' if field=='packets' else ('0' if old=='1' else '1') if field in ('origin_is_a','pool_worker') else 'f'+old[1:])
   lines[i]=line.replace(field+'='+old,field+'='+value,1);break
 else:raise AssertionError('missing mutation target '+name)
 target.write_text(''.join(lines));result=v.verify(clone,a.build,'linux')
 assert result['status']=='HOLD' and any(expected in e for e in result['errors']),(name,result)
 results.append(dict(case=name,status=result['status'],expected_rejection=expected,errors=result['errors']))
(a.output/'results.json').write_text(json.dumps(results,indent=2)+'\n');print('S208 five semantic evidence corruptions rejected')
