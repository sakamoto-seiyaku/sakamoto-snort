#!/usr/bin/env python3
"""Reject altered R3 witnesses without changing original device evidence."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile

spec=importlib.util.spec_from_file_location('verifier',Path(__file__).with_name('verify_r3_tunnels.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)


def run(directory):
    directory=Path(directory).resolve();assert v.verify(directory)['status']=='PASS'
    original=json.loads((directory/'result.json').read_text());pixel='serial' in original
    log='root-stop.log' if pixel else 'first-vpp.log'
    rejected=[]
    with tempfile.TemporaryDirectory(prefix='sakamoto-r3-negative-') as tmp:
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
        ports={case['port'] for case in original['cases'] if case.get('profile','root')=='root'}
        admits=v.records((copy/log).read_text(),'s216 stage=admit ')
        token=next(row['token'] for _,row in admits if int(row['src_port']) in ports or int(row['dst_port']) in ports)
        for key in ('generation','revision','snapshot_hash','incarnation','position','hit','status',
                    'evaluation','rule','rank','mode','declared','actual','reason','priority','order','hits','misses'):
            trial('cache-'+key,log,lambda b,key=key:field(b,'t11 event=cache ',key,
                  lambda r:r['token']==token and r['position']=='2' and r['evaluation']=='1'))
        trial('actual-native-verdict',log,lambda b:field(b,'s242 event=verdict_syscall ','verdict',lambda r:r['token']==token))
        trial('once-flow-packet-accounting',log,lambda b:field(b,'s208 event=observe ','packets',lambda r:r['token']==token))
        for key in ('incarnation','available','protocols','attempts','bytes','stop'):
            trial('producer-'+key,log,lambda b,key=key:field(b,'t12 event=lpi ',key,
                  lambda r:int(r['protocols'])&2048))
        def remove(data):
            lines=data.decode().splitlines();i=next(i for i,l in enumerate(lines) if l.startswith('t12 event=lpi ') and (' token='+token+' ') in l)
            del lines[i];return ('\n'.join(lines)+'\n').encode()
        trial('missing-producer-observation',log,remove)
        counter='root-final.txt' if pixel else 'final-counters.txt'
        for key in ('capacity','occupied','storage_bytes','hits','misses','replacements'):
            trial('readable-cache-'+key,counter,lambda b,key=key:field(b,'policy.cache ',key))
        for key in ('capacity','entry_bytes','allocated_bytes'):
            trial('readable-flow-resource-'+key,counter,lambda b,key=key:field(b,'flow.runtime ',key))
        queried='root-udp-budget-flow.txt' if pixel else 'wireguard-budget-flow.txt'
        for key in ('available','protocols','attempts','stop'):
            trial('readable-fact-'+key,queried,lambda b,key=key:field(b,'flow.lpi ',key,
                  lambda r:int(r['protocols'])&2048))
        trial('wrong-catalog-key',queried,lambda b:b.replace(b'key=wireguard',b'key=http',1))
        def changed_run(data,key,value):
            run=json.loads(data);run[key]=value;return (json.dumps(run)+'\n').encode()
        trial('wrong-build-binding','result.json',lambda b:changed_run(b,'build_sha256','0'*64))
        if not pixel:
            def omit_openvpn_and_duplicate_socks(data):
                run=json.loads(data)
                kept=[case for case in run['cases'] if case['application']!='openvpn_tcp']
                kept += [dict(case,client='socks-copy') for case in run['cases'] if case['application']=='socks5']
                run['cases']=kept
                return (json.dumps(run)+'\n').encode()
            shutil.copy2(copy/'socks5-client.json',copy/'socks-copy-client.json')
            trial('missing-openvpn-duplicated-socks','result.json',omit_openvpn_and_duplicate_socks)
            (copy/'socks-copy-client.json').unlink()
        def endpoint_change(data,kind,key=None,value=None,remove=False):
            events=[json.loads(line) for line in data.decode().splitlines()]
            selected=[e for e in events if e['kind']==kind];assert selected
            if remove:events=[e for e in events if e['kind']!=kind]
            else:selected[0][key]=value
            return ('\n'.join(json.dumps(e) for e in events)+'\n').encode()
        for kind in ('command','reply','authenticated_handshake','proxy_connected','target_received','target_sent','inner_icmp'):
            trial('missing-endpoint-'+kind,'endpoint.jsonl',lambda b,kind=kind:endpoint_change(b,kind,remove=True))
        trial('wrong-endpoint-peer','endpoint.jsonl',lambda b:endpoint_change(b,'command','peer',['203.0.113.99',9]))
        trial('wrong-endpoint-command','endpoint.jsonl',lambda b:endpoint_change(b,'command','data','00'))
        trial('wrong-endpoint-reply','endpoint.jsonl',lambda b:endpoint_change(b,'reply','data','00'))
        if pixel:
            trial('reused-probe-nonce','root-udp-nonce-check.txt',lambda b:b'used\n')
            report='root-tcp-finished.json'
            trial('missing-client-delivery',report,lambda b:changed_run(b,'echoes',0))
            trial('wrong-client-session',report,lambda b:changed_run(b,'nonce','different'))
            trial('missing-client-timeout',report,lambda b:changed_run(b,'blockedTimeout',False))
            trial('wrong-client-proxy',report,lambda b:changed_run(b,'proxyConnected',False))
            trial('wrong-client-handshake','root-udp-finished.json',lambda b:changed_run(b,'handshakeResponse',False))
        else:
            trial('missing-client-delivery','wireguard-client.json',lambda b:b'[]')
            trial('wrong-inner-icmp','endpoint.jsonl',lambda b:endpoint_change(b,'inner_icmp','text','wrong'))
            trial('wrong-proxy-target','endpoint.jsonl',lambda b:endpoint_change(b,'target_received','data','00'))
        return dict(status='PASS',rejected=len(rejected),categories=rejected,run=str(directory),
                    verifier_sha256=v.digest(Path(__file__).with_name('verify_r3_tunnels.py')),
                    harness_sha256=v.digest(__file__))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory');p.add_argument('--output');a=p.parse_args()
    result=run(a.directory)
    if a.output:Path(a.output).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
