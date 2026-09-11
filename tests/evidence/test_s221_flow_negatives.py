#!/usr/bin/env python3
"""Corrupt independent S221 evidence copies; every corruption must be HOLD."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('verify',ROOT/'tests/device/verify-s221-flow.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
assert not module.has_native_process('12 sh sh -c audit executable=/data/app/pkg/libvpp_runtime.so')
assert module.has_native_process('13 vpp_main /data/app/pkg/libvpp_runtime.so -c startup.conf')
assert module.verify(a.run)['status']=='PASS','negative controls require a passing positive baseline'

def change_json(folder,name,change):
    path=folder/name;value=json.loads(path.read_text());change(value);path.write_text(json.dumps(value))
def change_text(folder,name,change):
    path=folder/name;before=path.read_text();after=change(before)
    assert before!=after,name+' corruption was not applied';path.write_text(after)
def remove_line(text,prefix):
    lines=text.splitlines(keepends=True);index=next(i for i,line in enumerate(lines) if line.startswith(prefix))
    del lines[index];return ''.join(lines)
def replace_line(text,prefix,old,new):
    lines=text.splitlines(keepends=True);index=next(i for i,line in enumerate(lines) if line.startswith(prefix) and old in line)
    lines[index]=lines[index].replace(old,new,1);return ''.join(lines)
def remove_endpoint_case(folder):
    result=json.loads((folder/'result.json').read_text())
    case=next(c for c in result['runs'][0]['cases'] if not c['blocked'] and c['protocol'] in ('tcp','udp'))
    def remove(text):
        lines=text.splitlines(keepends=True)
        index=next(i for i,line in enumerate(lines) if case['nonce']+'-1' in line)
        del lines[index];return ''.join(lines)
    change_text(folder,'normal/endpoint.log',remove)

mutations={
    'wrong-source':lambda f:change_json(f,'result.json',lambda j:j.update(source='GRAPH_INJECTED')),
    'wrong-build':lambda f:change_json(f,'result.json',lambda j:j.update(build_sha256='0'*64)),
    'missing-observe':lambda f:change_text(f,'normal/vpp.log',lambda s:remove_line(s,'s208 event=observe ')),
    'duplicate-completion':lambda f:change_text(f,'normal/vpp.log',lambda s:s+next(l for l in s.splitlines(True) if l.startswith('s204 event=completion_consume '))),
    'wrong-owner':lambda f:change_text(f,'normal/vpp.log',lambda s:replace_line(s,'s208 event=observe ','worker=0','worker=1')),
    'false-hash-hit':lambda f:change_text(f,'normal/vpp.log',lambda s:re.sub(r'(s208 event=observe [^\n]*stored_hash=)\d+',r'\g<1>0',s,count=1)),
    'capacity-is-drop':lambda f:change_text(f,'small/vpp.log',lambda s:replace_line(s,'s210 event=origin_completion ','intent=3','intent=2')),
    'drop-is-bypass':lambda f:change_text(f,'small/vpp.log',lambda s:replace_line(s,'s210 event=origin_completion ','intent=2','intent=3')),
    'stop-flow-residue':lambda f:change_text(f,'small/closed.txt',lambda s:replace_line(s,'flow.pool ','entries=0','entries=1')),
    'stop-buffer-residue':lambda f:change_text(f,'small/closed.txt',lambda s:replace_line(s,'completion.status ','buffers=0','buffers=1')),
    'missing-protocol':lambda f:change_text(f,'normal/final.txt',lambda s:remove_line(s,'flow.protocol ')),
    'missing-vlib-owner':lambda f:change_text(f,'normal/final.txt',lambda s:remove_line(s,'product-packet-policy ')),
    'wrong-typed-key':lambda f:change_text(f,'normal/final.txt',lambda s:replace_line(s,'flow.entry ','port_b=40621','port_b=40622')),
    'missing-endpoint':remove_endpoint_case,
    'surviving-process':lambda f:change_json(f,'small/stop.json',lambda j:j.update(process_absent=False)),
    'missing-restart':lambda f:change_json(f,'result.json',lambda j:j['runs'].pop()),
    'failed-collision':lambda f:change_text(f,'normal/collision-check.txt',lambda s:s.replace('failed_step=0','failed_step=17',1)),
    'wrong-collision-worker':lambda f:change_text(f,'normal/collision-check.txt',lambda s:s.replace('thread=1','thread=0',1)),
    'collision-source-mislabeled':lambda f:change_text(f,'normal/collision-check.txt',lambda s:s.replace('FLOW_RUNTIME_INJECTED','NFQ_CAPTURED')),
    'collision-resources-survive':lambda f:change_text(f,'normal/collision-check.txt',lambda s:s.replace('runtimes=0','runtimes=1')),
}
reports={}
for name,mutate in mutations.items():
    with tempfile.TemporaryDirectory(prefix='s221-negative-') as temporary:
        copy=Path(temporary)/'run';shutil.copytree(a.run,copy)
        mutate(copy);report=module.verify(copy)
        assert report['status']=='HOLD',(name,report)
        reports[name]=report
        (a.output/(name+'.json')).write_text(json.dumps(report,indent=2)+'\n')
    print(name,'HOLD as required',flush=True)
(a.output/'verification.json').write_text(json.dumps(dict(status='PASS',negative_count=len(reports),
    test_sha256=module.digest(__file__),verifier_sha256=module.digest(module.__file__)),indent=2)+'\n')
