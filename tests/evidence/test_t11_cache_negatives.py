#!/usr/bin/env python3
"""Reject altered T11 witnesses without changing original device evidence."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

spec=importlib.util.spec_from_file_location('verifier',Path(__file__).with_name('verify_t11_cache.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)


def run(directory):
    directory=Path(directory).resolve();assert v.verify(directory)['status']=='PASS'
    original=json.loads((directory/'result.json').read_text());pixel='serial' in original
    log='root-stop.log' if pixel else 'first-vpp.log'
    rejected=[]
    with tempfile.TemporaryDirectory(prefix='sakamoto-t11-negative-') as tmp:
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
        def omit(data):
            lines=data.decode().splitlines();index=next(i for i,l in enumerate(lines) if l.startswith('t11 event=cache '))
            del lines[index];return ('\n'.join(lines)+'\n').encode()
        def duplicate(data):
            lines=data.decode().splitlines();index=next(i for i,l in enumerate(lines) if l.startswith('t11 event=cache '))
            lines.insert(index,lines[index]);return ('\n'.join(lines)+'\n').encode()
        trial('missing-cache-query',log,omit);trial('duplicate-cache-query',log,duplicate)
        counter='root-cache-counters.txt' if pixel else 'cache-final-flow.txt'
        for key in ('capacity','occupied','storage_bytes','hits','misses','replacements'):
            trial('readable-cache-'+key,counter,lambda b,key=key:field(b,'policy.cache ',key))
        def changed_run(data,key,value):
            run=json.loads(data);run[key]=value;return (json.dumps(run)+'\n').encode()
        trial('missing-cache-validation','result.json',lambda b:changed_run(b,'cache_validation',False))
        trial('wrong-build-binding','result.json',lambda b:changed_run(b,'build_sha256','0'*64))
        if not pixel:
            def stale(data):
                run=json.loads(data);run['cache_reuse']['new']['incarnation']=run['cache_reuse']['old']['incarnation']
                return (json.dumps(run)+'\n').encode()
            trial('stale-reused-Flow-instance','result.json',stale)
        return dict(status='PASS',rejected=len(rejected),categories=rejected,run=str(directory),
                    verifier_sha256=v.base.digest(Path(__file__).with_name('verify_t11_cache.py')),
                    harness_sha256=v.base.digest(__file__))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory');p.add_argument('--output');a=p.parse_args()
    result=run(a.directory)
    if a.output:Path(a.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
