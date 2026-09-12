#!/usr/bin/env python3
"""Reject corruptions of the real TCP semantic and native ownership witness."""
import argparse
import importlib.util
from pathlib import Path
import re
import tempfile

ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True)
p.add_argument('--ovs',type=Path,required=True);a=p.parse_args()
spec=importlib.util.spec_from_file_location('verify',ROOT/'tests/device/verify-s222-tcp.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
assert v.verify(a.build,a.run,a.ovs)['status']=='PASS'
original=(a.run/'normal/vpp.log').read_text()
mutations={
 'wrong-owner-thread':re.sub(r'(s222 event=tcp_update[^\n]*? thread=)1\b',r'\g<1>2',original,count=1),
 'wrong-window':re.sub(r'(s222 event=tcp_update[^\n]*? orig_maxwin=)\d+',r'\g<1>0',original,count=1),
 'missing-update':re.sub(r'^s222 event=tcp_update[^\n]*\n','',original,count=1,flags=re.M),
 'duplicate-free':re.sub(r'(^s203 event=buffer_free[^\n]*\n)',r'\1\1',original,count=1,flags=re.M),
 'implicit-drop':re.sub(r'(s216 stage=terminal[^\n]*? intent=)1\b',r'\g<1>2',original,count=1),
 'invalid-mutated-state':re.sub(r'(s222 event=tcp_update[^\n]*? ct_state=3[^\n]*? orig_seqlo=)(\d+)',lambda m:m[1]+str((int(m[2])+1)&0xffffffff),original,count=1),
 'cross-generation':re.sub(r'(s222 event=tcp_update[^\n]*? generation=)\d+',r'\g<1>1',original,count=1),
}
for name,text in mutations.items():
 assert text!=original,name
 with tempfile.TemporaryDirectory(prefix='s222-negative-') as temporary:
  directory=Path(temporary)
  for source in a.run.iterdir():
   if source.name!='normal':(directory/source.name).symlink_to(source.resolve(),target_is_directory=source.is_dir())
  (directory/'normal').mkdir()
  for source in (a.run/'normal').iterdir():
   if source.name!='vpp.log':(directory/'normal'/source.name).symlink_to(source.resolve())
  (directory/'normal/vpp.log').write_text(text)
  try:v.verify(a.build,directory,a.ovs)
  except AssertionError:pass
  else:raise AssertionError('accepted corruption '+name)
 print('PASS rejected',name)
