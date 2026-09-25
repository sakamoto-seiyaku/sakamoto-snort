#!/usr/bin/env python3
"""Reject altered T12 witnesses without changing original device evidence."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

spec=importlib.util.spec_from_file_location('verifier',Path(__file__).with_name('verify_t12_lpi.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)


def run(directory):
    directory=Path(directory).resolve();assert v.verify(directory)['status']=='PASS'
    original=json.loads((directory/'result.json').read_text());pixel='serial' in original
    log='root-stop.log' if pixel else 'first-vpp.log'
    rejected=[]
    with tempfile.TemporaryDirectory(prefix='sakamoto-t12-negative-') as tmp:
        copy=Path(tmp)/'evidence'
        shutil.copytree(directory,copy,ignore=shutil.ignore_patterns('*.png','*.xml','configuration'))
        assert v.verify(copy)['status']=='PASS', 'copied positive fixture must remain valid'
        def trial(name,filename,transform):
            path=copy/filename;before=path.read_bytes()
            path.write_bytes(transform(before))
            try:
                try:v.verify(copy)
                except (AssertionError,KeyError,ValueError,OSError,IndexError,StopIteration):rejected.append(name)
                else:raise AssertionError('altered witness accepted: '+name)
            finally:path.write_bytes(before)
        def field(data,prefix,key,predicate=lambda row:True):
            lines=data.decode().splitlines();done=False
            for i,line in enumerate(lines):
                if not line.startswith(prefix):continue
                row=dict(w.split('=',1) for w in line.split()[1:] if '=' in w)
                if not predicate(row):continue
                lines[i]=re.sub(r'(?<= )'+key+r'=\d+',key+'='+str(int(row[key])+1),line,count=1);done=True;break
            assert done,(prefix,key)
            return ('\n'.join(lines)+'\n').encode()
        for key in ('generation','revision','snapshot_hash','incarnation','position','hit','status',
                    'evaluation','rule','rank','mode','declared','actual','reason','priority','order','hits','misses'):
            trial('cache-'+key,log,lambda b,key=key:field(b,'t11 event=cache ',key,
                  lambda r:r['position']=='2' and r['evaluation']=='1'))
        for key in ('incarnation','available','protocols','attempts','bytes','stop'):
            trial('producer-'+key,log,lambda b,key=key:field(b,'t12 event=lpi ',key,
                  lambda r:r['available']=='1'))
        def remove(data):
            lines=data.decode().splitlines();i=next(i for i,l in enumerate(lines) if l.startswith('t12 event=lpi '))
            del lines[i];return ('\n'.join(lines)+'\n').encode()
        trial('missing-producer-observation',log,remove)
        counter='root-final.txt' if pixel else 'final-counters.txt'
        for key in ('capacity','occupied','storage_bytes','hits','misses','replacements'):
            trial('readable-cache-'+key,counter,lambda b,key=key:field(b,'policy.cache ',key))
        queried='root-tcp-budget-flow.txt' if pixel else 'tcp-budget-flow.txt'
        for key in ('available','protocols','attempts','stop'):
            trial('readable-fact-'+key,queried,lambda b,key=key:field(b,'flow.lpi ',key,
                  lambda r:r['available']=='1'))
        trial('wrong-catalog-key',queried,lambda b:b.replace(b'key=tls',b'key=http',1))
        def changed_run(data,key,value):
            run=json.loads(data);run[key]=value;return (json.dumps(run)+'\n').encode()
        trial('wrong-build-binding','result.json',lambda b:changed_run(b,'build_sha256','0'*64))
        def endpoint_change(data,kind,key=None,value=None,remove=False):
            events=[json.loads(line) for line in data.decode().splitlines()]
            selected=[e for e in events if e['kind']==kind];assert selected
            if remove:events=[e for e in events if e['kind']!=kind]
            else:selected[0][key]=value
            return ('\n'.join(json.dumps(e) for e in events)+'\n').encode()
        response='mdns_response' if original.get('mdns') else 'dns_response'
        trial('missing-endpoint-receives','endpoint.jsonl',lambda b:endpoint_change(b,'udp_receive',remove=True))
        trial('wrong-endpoint-response-peer','endpoint.jsonl',lambda b:endpoint_change(b,response,'peer',['203.0.113.99',9]))
        trial('wrong-endpoint-response-payload','endpoint.jsonl',lambda b:endpoint_change(b,response,'data','00'))
        trial('missing-endpoint-response','endpoint.jsonl',lambda b:endpoint_change(b,response,remove=True))
        trial('missing-recovery-echo','endpoint.jsonl',lambda b:endpoint_change(b,'udp_echo',remove=True))
        trial('wrong-recovery-echo-payload','endpoint.jsonl',lambda b:endpoint_change(b,'udp_echo','data','00'))
        if not pixel:
            trial('missing-client-delivery','udp-client.json',lambda b:b'[]')
        return dict(status='PASS',rejected=len(rejected),categories=rejected,run=str(directory),
                    verifier_sha256=v.digest(Path(__file__).with_name('verify_t12_lpi.py')),
                    harness_sha256=v.digest(__file__))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory');p.add_argument('--output');a=p.parse_args()
    result=run(a.directory)
    if a.output:Path(a.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
