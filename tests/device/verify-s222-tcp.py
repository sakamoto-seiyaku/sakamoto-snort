#!/usr/bin/env python3
"""Verify raw NFQUEUE TCP evidence, replaying every update through pinned OVS."""
import argparse
import collections
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]
def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def fields(line): return dict(re.findall(r'(\w+)=([^\s]+)',line))
def rows(text,prefix): return [fields(line) for line in text.splitlines() if line.startswith(prefix)]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

def verify(build_path,directory,ovs):
    chain=module('chain','tests/evidence/product_chain.py');owner_oracle=module('owner','tests/device/s207-owner-oracle.py')
    build=json.loads(build_path.read_text());run=json.loads((directory/'result.json').read_text())
    assert chain.source_files()==build['files'] and run['source_sha256']==build['source_sha256']
    assert hashlib.sha256(chain.encode(build['files'])).hexdigest()==build['source_sha256']
    assert digest(build_path.parent/'dirty.diff')==build['dirty_diff_sha256']
    for name,value in build['files'].items():
        if value is not None: assert digest(build_path.parent/'source'/name)==value
    assert run['build_sha256']==digest(build_path) and not run.get('error') and not run.get('cleanup_errors')
    assert build['completed_ns']<run['started_ns']<run['completed_ns'] and run['source']=='NFQ_CAPTURED'
    for name,value in run['test_inputs'].items(): assert digest(directory/'test-source'/name)==value
    helpers=build_path.parent/'s222-helper';helper=json.loads((helpers/'helper.json').read_text())
    assert digest(helpers/'helper.json')==run['helper_sha256'] and helper['build_sha256']==digest(build_path)
    for name,value in helper['files'].items(): assert digest(helpers/name)==value
    if run['platform']=='pixel':
        assert digest(build['apk'])==build['apk_sha256']
        assert (directory/'installed-apk.txt').read_text().split()[0]==build['apk_sha256']
        native={Path(line.split()[1]).name:line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
        assert native==build['native_sha256']
        with zipfile.ZipFile(build['apk']) as apk:
            assert apk.read('assets/product-tcp-notices.txt')==(ROOT/'src/product/NOTICE.tcp').read_bytes()
    else:
        assert run['platform']=='linux' and build['host_evidence'] is False
        for name,value in build['artifact_hashes'].items(): assert digest(Path(build['artifact'])/name)==value
        assert (Path(build['artifact'])/'share/licenses/sakamoto/NOTICE.tcp').read_bytes()==(ROOT/'src/product/NOTICE.tcp').read_bytes()
        mapping=(directory/'uid-map.txt').read_text().split()
        assert mapping[0]=='0' and mapping[1]!='0' and mapping[2]=='1'
    if run['platform']=='pixel': assert not (directory/'queues-after.txt').read_text().strip()
    assert len(run['runs'])==2 and run['runs'][0]['generation']!=run['runs'][1]['generation']
    summary=[]
    with tempfile.TemporaryDirectory(prefix='s222-verifier-') as temporary:
        library=Path(temporary)/'oracle.so'
        subprocess.run(['python3',str(ROOT/'tests/host/product_flow_tcp_ovs_test.py'),'--ovs',str(ovs),
                        '--library-output',str(library)],check=True)
        ref=ctypes.CDLL(str(library));ref.oracle_create.restype=ctypes.c_void_p
        ref.oracle_destroy.argtypes=[ctypes.c_void_p]
        ref.oracle_step.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32)]
        for record in run['runs']:
            folder=directory/record['label'];generation=str(record['generation'])
            trace=(folder/'vpp.log').read_text();events=[];by_token=collections.defaultdict(list)
            for index,line in enumerate(trace.splitlines()):
                if not line.startswith(('s203 ','s204 ','s207 ','s208 ','s216 ','s222 ')): continue
                event=fields(line);event['_index']=index;event['_prefix']=line.split()[0];events.append(event)
                if 'generation' in event: assert event['generation']==generation,'mixed generation'
                token=event.get('token',event.get('obligation'))
                if token: by_token[token].append(event)
            admitted={e['token']:e for e in events if e['_prefix']=='s216' and e.get('stage')=='admit'}
            assert admitted and len(admitted)==sum(e['_prefix']=='s216' and e.get('stage')=='admit' for e in events)
            contexts={};histories={};orientations={};incarnations={};packets_by_port=collections.defaultdict(list)
            coverage=set();invalid=0;replacements=0
            try:
                for event in events:
                    if event['_prefix']!='s222' or event.get('event')!='tcp_update': continue
                    packet=admitted[event['token']];related=by_token[event['token']]
                    assert packet['source']=='NFQ_CAPTURED' and packet['protocol']=='6' and packet['l3']==packet['l4']=='1'
                    facts={k:int(packet[k]) if k not in ('src','dst') else packet[k] for k in
                           ('l3','l4','family','protocol','src','dst','src_port','dst_port','icmp_known')}
                    assignment=owner_oracle.assignment(facts);owner=assignment['owner']
                    assert int(packet['owner'])==int(event['owner'])==int(event['worker'])==owner
                    assert int(event['thread'])==owner+1
                    coverage.add((facts['family'],owner,int(packet['worker'])==owner))
                    raw=bytes.fromhex(packet['raw']);offset=(raw[0]&15)*4 if facts['family']==4 else 40
                    assert int(packet['transport_offset'])==offset
                    header=(raw[offset+12]>>4)*4;flags=raw[offset+13]
                    seq,ack=struct.unpack_from('!II',raw,offset+4);window=struct.unpack_from('!H',raw,offset+14)[0]
                    assert (seq,ack,window,flags)==tuple(int(packet[k]) for k in ('tcp_seq','tcp_ack','tcp_window','tcp_flags'))
                    assert header==int(packet['l4_length']) and int(packet['transport_length'])==int(packet['packet_length'])-offset
                    scale_known=0;scale=0;cursor=offset+20
                    while cursor<offset+header:
                        kind=raw[cursor]
                        if kind==0: break
                        if kind==1: cursor+=1;continue
                        length=raw[cursor+1]
                        assert length>=2 and cursor+length<=offset+header
                        if kind==3 and length==3: scale_known=1;scale=min(raw[cursor+2],14)
                        cursor+=length
                    assert (scale_known,scale)==(int(packet['wscale_known']),int(packet['wscale']))
                    identity=tuple(assignment[k] for k in ('key_family','key_protocol','key_a','key_b','port_a','port_b'))
                    if identity not in contexts: contexts[identity]=ref.oracle_create();histories[identity]=[0,0]
                    had_entry=identity in orientations
                    side=int(had_entry and assignment['source_is_a']!=orientations[identity])
                    incoming=(ctypes.c_uint32*8)(flags,seq,ack,window,int(packet['transport_length'])-header,scale_known,scale,side)
                    expected=(ctypes.c_uint32*15)();ref.oracle_step(contexts[identity],incoming,expected)
                    update={11:2,12:3,14:1}[expected[0]];ct_state={11:2,12:3,14:1}[expected[0]]
                    timeout=expected[2]-41+4 if expected[2] else 0
                    assert (int(event['update']),int(event['ct_state']),int(event['timeout']),int(event['refresh']))==(update,ct_state,timeout,expected[1]),event
                    replacement=expected[4];replacements+=replacement;invalid+=update==3
                    assert int(event['replacement'])==int(event['close'])==replacement
                    if replacement:
                        assert int(event['previous_incarnation'])==incarnations[identity]
                        histories[identity]=[0,0]
                    else: assert event['previous_incarnation']=='0'
                    created=bool(expected[3] and (not had_entry or replacement))
                    assert int(event['created'])==created
                    if created:
                        orientations[identity]=assignment['source_is_a'];side=0
                        assert int(event['incarnation'])>incarnations.get(identity,0)
                        incarnations[identity]=int(event['incarnation'])
                    if expected[3]:
                        assert int(event['incarnation'])==incarnations[identity] and int(event['flow_dir'])==side+1
                    else: assert event['incarnation']=='0' and event['flow_dir']=='0'
                    if update!=3: histories[identity][side]|=flags
                    for peer,label in enumerate(('orig','reply')):
                        actual=tuple(int(event[label+'_'+field]) for field in ('seqlo','seqhi','maxwin','scale','state'))
                        assert actual==tuple(expected[5+peer*5:10+peer*5]),(event,actual,list(expected))
                        assert int(event[label+'_flags'])==histories[identity][peer]
                    def one(key,value,prefix=None):
                        found=[e for e in related if e.get(key)==value and (prefix is None or e['_prefix']==prefix)]
                        assert len(found)==1,(event['token'],key,value,len(found));return found[0]
                    policy=one('stage','policy','s216');terminal=one('stage','terminal','s216')
                    completion=one('event','completion_consume');freed=one('event','buffer_free');verdict=one('event','verdict')
                    assert all(e['buffer']==packet['buffer'] for e in (event,policy,terminal,completion,freed))
                    assert policy['thread']==terminal['thread']==event['thread']
                    assert completion['thread']==freed['thread']==packet['thread']
                    assert packet['_index']<event['_index']<policy['_index']<terminal['_index']<completion['_index']<freed['_index']
                    assert terminal['intent']=='1' and verdict['verdict']=='1','INVALID must not imply DROP'
                    packets_by_port[(facts['family'],min(facts['src_port'],facts['dst_port']) if max(facts['src_port'],facts['dst_port'])==40622 else max(facts['src_port'],facts['dst_port']))].append((packet,event))
                assert len(admitted)==sum(e.get('event')=='tcp_update' for e in events)
                for case_index,case in enumerate(record['cases']):
                    selected=packets_by_port[(case['family'],case['source'])];assert selected,case
                    assert all(int(e['owner'])==case['owner'] for _,e in selected)
                    if case['mode']=='invalid-new':
                        assert all(e['ct_state']=='3' and e['incarnation']=='0' for _,e in selected)
                    else:
                        client=(folder/f'client-{case_index}.log').read_text()
                        assert len(rows(client,'received '))==3 and 'client_closed ' in client
                        assert all(e['nonce'].startswith(case['nonce']+':') for e in rows(client,'received '))
                    if case['mode']=='invalid': assert sum(e['ct_state']=='3' for _,e in selected)>=4
                    if case['mode']=='reuse': assert any(e['replacement']=='1' for _,e in selected)
                    if case['mode']=='rst': assert any(int(p['tcp_flags'])&4 for p,_ in selected)
                    if case['mode']=='midstream':
                        first,update=selected[0]
                        assert not(int(first['tcp_flags'])&2) and update['orig_scale']==update['reply_scale']=='64'
                    if case['mode']=='retransmit':
                        syn=[p for p,_ in selected if p['direction']=='3' and int(p['tcp_flags'])==2 and int(p['src_port'])==case['source']]
                        assert len(syn)>=2 and syn[0]['tcp_seq']==syn[1]['tcp_seq']
                        assert int(syn[1]['mono_ns'])-int(syn[0]['mono_ns'])>500000000,'not a real timed SYN retransmission'
                assert {(f,o) for f,o,_ in coverage}=={(4,0),(4,1),(6,0),(6,1)}
                if record['label']=='normal': assert {local for _,_,local in coverage}=={False,True} and invalid>=12 and replacements==4
                final=(folder/'final.txt').read_text();closed=(folder/'closed.txt').read_text()
                lanes=rows(final,'root.lane ')
                assert len(lanes)==4 and sum(int(l['captured']) for l in lanes)==len(admitted)
                assert all(l['captured']==l['submitted']==l['verdicts']==l['succeeded'] and l['failed']=='0' and l['pending']=='0' for l in lanes)
                assert all(l['fd']=='-1' and l['pending']=='0' and l['ready']=='0' for l in rows(closed,'root.lane '))
                assert all(x['entries']=='0' for x in rows(closed,'flow.pool '))
                assert all(x[k]=='0' for x in rows(closed,'completion.status ') for k in ('pending','frames','buffers','obligations'))
                assert json.loads((folder/'stop.json').read_text())['process_absent']
                if run['platform']=='linux':
                    available=json.loads((folder/'queues-free.json').read_text())
                    assert available=={str(q):0 for q in range(176,180)}
                summary.append(dict(label=record['label'],generation=record['generation'],packets=len(admitted),invalid=invalid,replacements=replacements,coverage=sorted(coverage)))
            finally:
                for context in contexts.values(): ref.oracle_destroy(context)
    return dict(status='PASS',platform=run['platform'],scope='real-NFQUEUE-TCP-tracker-not-VPN-TCP-transport',runs=summary,
                source_sha256=build['source_sha256'],verifier_sha256=digest(__file__))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--run',type=Path,required=True)
    p.add_argument('--ovs',type=Path,required=True);a=p.parse_args()
    print(json.dumps(verify(a.build,a.run,a.ovs),indent=2))
