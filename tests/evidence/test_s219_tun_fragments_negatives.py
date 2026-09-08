#!/usr/bin/env python3
"""Reject first-arrival substitution, unknown merging and false fragment evidence."""
import argparse,json,re,shutil,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
def verify(run):return subprocess.run(['python3',str(ROOT/'tests/device/verify-s219-tun-fragments.py'),'--build',str(a.build),'--run',str(run)],capture_output=True,text=True)
checked=verify(a.run);assert checked.returncode==0,checked.stdout+checked.stderr
mutations={
 'wrong_native_tun_kind':('g0-vpp.log',lambda s:re.sub(r'(s212 event=fragment_ingress [^\n]*kind=)3',r'\g<1>2',s,count=1)),
 'wrong_typed_completion':('g0-vpp.log',lambda s:re.sub(r'(s212 event=completion_publish [^\n]*kind=)3',r'\g<1>2',s,count=1)),
 'missing_original_completion':('g0-vpp.log',lambda s:re.sub(r'^s213 event=completion [^\n]*\n','',s,count=1,flags=re.M)),
 'missing_native_success':('g0-vpp.log',lambda s:re.sub(r'^s212 event=native_success [^\n]*\n','',s,count=1,flags=re.M)),
 'fabricated_tun_source':('g0-vpp.log',lambda s:s.replace('event=capture source=TUN_CAPTURED','event=capture source=GRAPH_INJECTED',1)),
 'corrupt_materialized_transport':('g0-vpp.log',lambda s:re.sub(r'(s216 stage=admit [^\n]*src_port=)454\d+',r'\g<1>9999',s,count=1)),
}
results=[]
for name,(filename,mutate) in mutations.items():
 with tempfile.TemporaryDirectory(prefix='s219-negative-') as tmp:
  dest=Path(tmp)/'run';shutil.copytree(a.run,dest);path=dest/filename;old=path.read_text();new=mutate(old);assert old!=new,name;path.write_text(new)
  checked=verify(dest);assert checked.returncode!=0,name
  result=json.loads((dest/'verification.json').read_text());assert result['status']=='HOLD' and result['errors'],name
  results.append(dict(name=name,rejected=True,errors=result['errors']))
a.output.write_text(json.dumps(results,indent=2)+'\n');print(f'PASS: {len(results)} real-TUN fragment evidence mutations rejected')
