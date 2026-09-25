#!/usr/bin/env python3
"""Reject omitted or altered critical T14 witnesses without editing originals."""
import argparse,importlib.util,json,re,shutil,struct,tempfile
from pathlib import Path
spec=importlib.util.spec_from_file_location('v',Path(__file__).with_name('verify_t14_sni.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

def run(directory,profile=None):
    directory=Path(directory);assert v.verify(directory,profile)['status']=='PASS'
    original=json.loads((directory/'result.json').read_text());pixel='serial' in original
    selected=profile or ('vpn' if pixel else 'root')
    if pixel and profile is None and any(l['profile']=='root' for l in original['lifetimes']):selected='root'
    log=selected+'-before-stop.log' if pixel else 'first-vpp.log';rejected=[]
    cases=[c for c in original['cases'] if c.get('profile','root')==selected]
    positive=next(c for c in cases if c['phase']=='complete' and c['mode'] in ('reorder','segmented'))
    prefix=next(c for c in cases if c['phase']=='prefix')
    selected_admit=next(r for _,r in v.records((directory/log).read_text(),'s216 stage=admit ')
        if r.get('src_port')==str(positive['port']))
    token=selected_admit['token']
    def parsed(raw):return json.loads(raw)
    with tempfile.TemporaryDirectory(prefix='t14-negative-') as tmp:
        copy=Path(tmp)/'evidence';shutil.copytree(directory,copy,ignore=shutil.ignore_patterns('*.png','*.xml','configuration'))
        def trial(label,file,edit):
            path=copy/file;before=path.read_bytes();after=edit(before);assert after!=before,label
            path.write_bytes(after)
            try:
                try:v.verify(copy,profile)
                except (AssertionError,KeyError,ValueError,OSError,IndexError,StopIteration,struct.error):rejected.append(label)
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
        for key in ('generation','worker','slot','incarnation','result','stop','attempts','bytes','work'):
            name=('' if pixel else 'sni.')+key
            trial('typed-'+key,positive['sni'],lambda b,name=name:b.replace((name+'=').encode(),(name+'=9').encode(),1))
        trial('typed-name',positive['sni'],lambda b:b.replace(b'example.test',b'wrong.test',1))
        trial('typed-missing',positive['sni'],lambda b:b'')
        trial('query-phase-missing','result.json',lambda b:json.dumps(parsed(b)|{'cases':[c for c in parsed(b)['cases'] if c['label']!=positive['label']]}).encode())
        for key in ('result','bytes','attempts','work'):
            trial('SNI-'+key,log,lambda b,key=key:field(b,'t13 event=sni ',key,lambda r:r['result']=='1'))
        trial('SNI-row-missing',log,lambda b:re.sub(rb'^t13 event=sni .*result=1 .*\n',b'',b,count=1,flags=re.M))
        for key in ('bytes0','contiguous0','ranges0','span0'):
            trial('cache-'+key,log,lambda b,key=key:field(b,'t14 event=tcp_cache ',key,lambda r:int(r['bytes0'])>0))
        trial('metadata-query',prefix['flow'],lambda b:field(b,'flow.tcp_cache ','ranges0',lambda r:int(r['bytes0'])>0))
        for key in ('rule','rank','mode','declared','actual','reason','priority','order','incarnation','hit','hits','misses'):
            trial('complete-cache-'+key,log,lambda b,key=key:field(b,'t11 event=cache ',key,
                lambda r:r['position']=='2' and r['evaluation']=='1' and (key!='hit' or r['hit']=='1')))
        port=positive['port']
        trial('wire-sequence',log,lambda b:field(b,'s216 stage=admit ','tcp_seq',lambda r:r.get('src_port')==str(port)))
        trial('wire-packet-missing',log,lambda b:re.sub(rb'^s216 stage=admit [^\n]*src_port='+str(port).encode()+rb' [^\n]*\n',b'',b,count=1,flags=re.M))
        trial('buffer-release-missing',log,lambda b:re.sub(rb'^s203 event=buffer_free [^\n]*obligation='+token.encode()+rb'(?: |\n)[^\n]*\n',b'',b,count=1,flags=re.M))
        trial('held-packet',log,lambda b:re.sub(rb'^(s216 stage=terminal [^\n]*token='+token.encode()+rb' [^\n]* mono_ns=)([0-9]+)',
            lambda m:m[1]+str(int(m[2])+6_000_000_000).encode(),b,count=1,flags=re.M))
        def remove_receipt(raw):
            decoder=json.JSONDecoder();text=raw.decode();events=[];at=0;removed=False
            while at<len(text):
                while at<len(text) and text[at].isspace():at+=1
                if at==len(text):break
                event,at=decoder.raw_decode(text,at)
                match=event['kind']=='raw_received' and (selected!='root' or event['peer'][1]==port)
                if match and not removed:removed=True
                else:events.append(event)
            assert removed
            return ('\n'.join(json.dumps(e) for e in events)+'\n').encode()
        trial('endpoint-receipt-missing','endpoint.jsonl',remove_receipt)
        trial('helper-binary-binding','wire-helper',lambda b:b+b'changed')
        trial('source-snapshot',original['configurations'][0]['source'],lambda b:b[:-1])
        raw_sessions=[s for s in original['sessions'] if s.get('raw') or s.get('mode') in ('reorder','bytes','sparse','span','packets')]
        if raw_sessions:
            hook_port=raw_sessions[0]['port']
            trial('test-hook-survived','raw-hooks-after.txt' if pixel else 'hooks-after.txt',
                lambda b:b+f'\n-A OUTPUT -p tcp --sport {hook_port} --dport 40641 --tcp-flags RST RST -j DROP\n'.encode())
        if pixel:
            if selected=='root':trial('actual-drop',log,lambda b:field(b,'s242 event=verdict_syscall ','verdict',lambda r:r['verdict']=='0'))
            else:trial('actual-drop',log,lambda b:field(b,'s213 event=completion ','policy_drop',lambda r:r['policy_drop']=='1'))
            expired=next(c for c in cases if c['phase']=='expired')
            trial('timeout-CT-activity',expired['flow'],lambda b:field(b,'flow.entry ','packets',lambda r:r['slot']==expired['identity'][1] and r['worker']==expired['identity'][0]))
            trial('timeout-CT-deadline',expired['flow'],lambda b:field(b,'flow.timer ','deadline_us',lambda r:r['slot']==expired['identity'][1] and r['worker']==expired['identity'][0]))
            concurrent=next(c for c in cases if c['mode']=='concurrent' and c['phase']=='prefix')
            trial('concurrent-attempt-missing',concurrent['flow'],lambda b:re.sub(rb'^flow.sni [^\n]*cache_bytes=20 [^\n]*\n',b'',b,count=1,flags=re.M))
        return dict(status='PASS',profile=selected,rejected=len(rejected),mutations=rejected)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--profile-scope',choices=['root','vpn']);p.add_argument('--output',type=Path)
    a=p.parse_args();text=json.dumps(run(a.directory,a.profile_scope),indent=2)+'\n'
    if a.output:a.output.write_text(text)
    print(text,end='')
