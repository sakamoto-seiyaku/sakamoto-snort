#!/usr/bin/env python3
"""Require the critical T13 witnesses; retain accepted originals unchanged."""
import argparse,importlib.util,json,re,shutil,tempfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('v',Path(__file__).with_name('verify_t13_sni.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
def run(directory):
    directory=Path(directory);assert v.verify(directory)['status']=='PASS'
    original=json.loads((directory/'result.json').read_text());pixel='serial' in original
    log='root-before-stop.log' if pixel else 'first-vpp.log';rejected=[]
    with tempfile.TemporaryDirectory(prefix='t13-negative-') as tmp:
        copy=Path(tmp)/'evidence';shutil.copytree(directory,copy,ignore=shutil.ignore_patterns('*.png','*.xml','configuration'))
        assert v.verify(copy)['status']=='PASS'
        def trial(label,file,edit):
            path=copy/file;before=path.read_bytes();after=edit(before);assert after!=before,label
            path.write_bytes(after)
            try:
                try:v.verify(copy)
                except (AssertionError,KeyError,ValueError,OSError,IndexError,StopIteration):rejected.append(label)
                else:raise AssertionError('tampered witness accepted: '+label)
            finally:path.write_bytes(before)
        def field(raw,prefix,key,predicate=lambda r:True):
            lines=raw.decode().splitlines()
            for i,line in enumerate(lines):
                if not line.startswith(prefix):continue
                row=dict(x.split('=',1) for x in line.split()[1:] if '=' in x)
                if not predicate(row):continue
                lines[i]=re.sub(r'(?<= )'+key+r'=\d+',key+'='+str(int(row[key])+1),line,count=1)
                return ('\n'.join(lines)+'\n').encode()
            raise AssertionError((prefix,key))
        cases=[c for c in original['cases'] if c.get('profile','root')=='root']
        named=next(c for c in cases if c['mode']=='named' and c['phase']=='ready')
        absent=next(c for c in cases if c['mode']=='absent' and c['phase']=='ready')
        expired=next(c for c in cases if c['phase']=='expired')
        for case in (named,absent,expired):
            trial('query-result-'+case['mode'],case['sni'],lambda b:b.replace(b'result=',b'result=9',1))
        for key in ('generation','incarnation','attempts','bytes','work'):
            field_name=('' if pixel else 'sni.')+key
            trial('query-'+key,named['sni'],lambda b,key=field_name:b.replace((key+'=').encode(),(key+'=9').encode(),1))
        trial('query-name',named['sni'],lambda b:b.replace(b'example.test',b'wrong.test',1))
        trial('query-missing',absent['sni'],lambda b:b'')
        trial('parser-no-absence-from-error',log,lambda b:field(b,'t13 event=sni ','result',lambda r:r['stop']=='2'))
        for key in ('result','incarnation'):
            trial('parser-'+key,log,lambda b,key=key:field(b,'t13 event=sni ',key,lambda r:r['result']=='1'))
        trial('parser-row-missing',log,lambda b:re.sub(rb'^t13 event=sni .*result=1 .*\n',b'',b,count=1,flags=re.M))
        for key in ('rule','rank','mode','declared','actual','reason','priority','order','incarnation','hit'):
            trial('complete-cache-'+key,log,lambda b,key=key:field(b,'t11 event=cache ',key,
                lambda r:r['position']=='2' and r['evaluation']=='1'))
        trial('actual-drop',log,lambda b:field(b,'s242 event=verdict_syscall ','verdict',lambda r:r['verdict']=='0'))
        trial('retained-packet',log,lambda b:re.sub(rb'^(s216 stage=terminal .* mono_ns=)([0-9]+)',
              lambda m:m[1]+str(int(m[2])+5_000_000_000).encode(),b,count=1,flags=re.M))
        trial('endpoint-handshake-missing','endpoint.jsonl',lambda b:b'\n'.join(line for line in b.splitlines() if b'"kind": "handshake"' not in line)+b'\n')
        trial('endpoint-name','endpoint.jsonl',lambda b:b.replace(b'"name": "example.test"',b'"name": "wrong.test"',1))
        trial('endpoint-absence','endpoint.jsonl',lambda b:b.replace(b'"name": null',b'"name": "invented.test"',1))
        trial('build-binding','result.json',lambda b:json.dumps(json.loads(b)|dict(build_sha256='0'*64)).encode())
        trial('missing-wire','result.json',lambda b:json.dumps(json.loads(b)|dict(cases=[])).encode())
    return dict(status='PASS',rejected=len(rejected),cases=rejected)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    text=json.dumps(run(a.directory),indent=2)+'\n'
    if a.output:a.output.write_text(text)
    print(text,end='')
