#!/usr/bin/env python3
"""Missing/altered T16 witnesses must fail the independent reader."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

spec=importlib.util.spec_from_file_location('verify',Path(__file__).with_name('verify_t16_sni.py'))
verify=importlib.util.module_from_spec(spec);spec.loader.exec_module(verify)

def run(directory,profile=None):
    directory=Path(directory);assert verify.verify(directory)['status']=='PASS'
    original=json.loads((directory/'result.json').read_text());pixel='serial' in original
    profile=profile or (original['lifetimes'][0]['profile'] if pixel else 'root')
    assert profile in ([life['profile'] for life in original['lifetimes']] if pixel else ['root'])
    log=profile+'-before-stop.log' if pixel else 'first-vpp.log'
    cases=[case for case in original['cases'] if case.get('profile','root')==profile]
    rejected=[]
    with tempfile.TemporaryDirectory(prefix='t16-negative-') as tmp:
        copy=Path(tmp)/'evidence'
        shutil.copytree(directory,copy,ignore=shutil.ignore_patterns('*.png','*.xml','configuration'))
        assert verify.verify(copy)['status']=='PASS'
        def trial(name,file,edit):
            path=copy/file;before=path.read_bytes();after=edit(before);assert after!=before,name
            path.write_bytes(after)
            try:
                try:verify.verify(copy)
                except (AssertionError,KeyError,ValueError,OSError,IndexError,StopIteration):rejected.append(name)
                else:raise AssertionError('tampered witness accepted: '+name)
            finally:path.write_bytes(before)
        def field(raw,prefix,key,predicate=lambda row:True,increment=1):
            lines=raw.decode().splitlines()
            for i,line in enumerate(lines):
                if not line.startswith(prefix):continue
                row=dict(item.split('=',1) for item in line.split()[1:] if '=' in item)
                if not predicate(row):continue
                lines[i]=re.sub(r'(?<= )'+key+r'=\d+',key+'='+str(int(row[key])+increment),line,count=1)
                return ('\n'.join(lines)+'\n').encode()
            raise AssertionError((prefix,key))
        named=next(case for case in cases if case['mode']=='named' and case['phase']=='ready')
        for mode in (verify.DOMAIN_EXPECTED if original.get("domain_policy") else verify.EXPECTED):
            case=next(case for case in cases if case['mode']==mode and case['phase']=='ready')
            trial('typed-result-'+mode,case['sni'],lambda b:b.replace(b'result=',b'result=9',1))
            if mode in ('conflict','ranges','offset','timeout','packets'):
                trial('typed-reason-'+mode,case['sni'],lambda b:b.replace(b'stop=',b'stop=9',1))
        for key in ('generation','incarnation','attempts','bytes','work','protocols'):
            prefix=('' if pixel else 'sni.')+key
            trial('query-'+key,named['sni'],lambda b,key=prefix:b.replace((key+'=').encode(),(key+'=9').encode(),1))
        trial('query-name',named['sni'],lambda b:b.replace(b'example.test',b'wrong.test',1))
        trial('query-missing',named['sni'],lambda b:b'')
        for key in ('result','stop','incarnation','bytes','work'):
            trial('parser-'+key,log,lambda b,key=key:field(b,'t13 event=sni ',key,lambda r:r['result']=='1'))
        trial('parser-row-missing',log,lambda b:re.sub(rb'^t13 event=sni .*result=1 .*\n',b'',b,count=1,flags=re.M))
        for key in ('rule','rank','mode','declared','actual','reason','priority','order','incarnation','hit'):
            trial('complete-cache-'+key,log,lambda b,key=key:field(b,'t11 event=cache ',key,
                lambda r:r['position']=='2' and r['evaluation']=='1'))
        trial('initial-wire-missing',log,lambda b:re.sub(rb'^s216 stage=admit .*transport_length=1208 .*\n',b'',b,count=1,flags=re.M))
        if profile=='root':
            trial('actual-drop',log,lambda b:field(b,'s242 event=verdict_syscall ','verdict',lambda r:r['verdict']=='0'))
        else:
            trial('actual-drop',log,lambda b:field(b,'s213 event=completion ','policy_drop',lambda r:r['policy_drop']=='1'))
        ports={str(case['port']) for case in cases}
        selected_tokens={row['token'] for _,row in verify.records((copy/log).read_text(),'s216 stage=admit ')
                         if {row.get('src_port'),row.get('dst_port')}&ports}
        assert selected_tokens
        trial('retained-packet',log,lambda b:field(b,'s216 stage=terminal ','mono_ns',
            lambda row:row['token'] in selected_tokens,5_000_000_000))
        trial('endpoint-protocol-missing','endpoint.jsonl',lambda b:b'\n'.join(line for line in b.splitlines() if b'"event": "ProtocolNegotiated"' not in line)+b'\n')
        for key in ('retained','contiguous','ranges','span','anchored','largest_pn'):
            trial('assembly-'+key,log,lambda b,key=key:field(b,'t16 event=quic_crypto ',key,lambda r:int(r['retained'])>0))
        trial('assembly-row-missing',log,lambda b:re.sub(rb'^t16 event=quic_crypto .*\n',b'',b,count=1,flags=re.M))
        trial('endpoint-flight-missing','endpoint.jsonl',lambda b:b'\n'.join(line for line in b.splitlines() if b'"kind": "quic_response"' not in line)+b'\n')
        trial('fixture-wire','fixtures.json',lambda b:b.replace(b'"preludeHex": "',b'"preludeHex": "00',1))
        trial('build-binding','result.json',lambda b:json.dumps(json.loads(b)|dict(build_sha256='0'*64)).encode())
        trial('missing-cases','result.json',lambda b:json.dumps(json.loads(b)|dict(cases=[])).encode())
        if pixel:
            trial('missing-profile','result.json',lambda b:json.dumps(json.loads(b)|dict(lifetimes=[])).encode())
        counters=profile+'-final.txt' if pixel else 'final-counters.txt'
        trial('resource-reservation',counters,lambda b:b.replace(b'entry_bytes=9024',b'entry_bytes=9025',1))
    return dict(status='PASS',rejected=len(rejected),cases=rejected)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);parser.add_argument('--output',type=Path)
    parser.add_argument('--profile',choices=['root','vpn'])
    args=parser.parse_args();text=json.dumps(run(args.directory,args.profile),indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text,end='')
