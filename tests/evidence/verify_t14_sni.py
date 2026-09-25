#!/usr/bin/env python3
"""Independent T14 wire-set, complete-winner, query, completion and peer oracle.

Expected Hello outcomes come from literal fixtures or a real TLS endpoint. The
reassembly oracle uses a byte-position dictionary, not Product range insertion,
and never imports or calls Product parser/recognition/compiled matcher code.
"""
import argparse, hashlib, importlib.util, json, shlex
from collections import defaultdict
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('t14_base',ROOT/'tests/evidence/verify_t12_lpi.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
records,one,props,digest=t.records,t.one,t.props,t.digest

def json_events(path):
    # Concurrent endpoint threads may write two complete JSON values before
    # either newline. Decode the complete stream; never discard malformed data.
    text=Path(path).read_text();decoder=json.JSONDecoder();values=[];at=0
    while at<len(text):
        while at<len(text) and text[at].isspace():at+=1
        if at==len(text):break
        value,end=decoder.raw_decode(text,at);values.append(value);at=end
    return values

def no_test_hooks(text,sessions):
    ports={str(s['port']) for s in sessions if s.get('raw') or s.get('mode') in ('reorder','bytes','sparse','span','packets')}
    for line in text.splitlines():
        words=shlex.split(line)
        if '--sport' not in words or '--dport' not in words:continue
        source=words[words.index('--sport')+1];destination=words[words.index('--dport')+1]
        assert not (source in ports and destination=='40641' and '-j' in words
            and words[words.index('-j')+1]=='DROP'),'test RST suppression hook survived cleanup'

class WireOracle:
    def __init__(self,fixture,mode):
        self.fixture,self.mode=fixture,mode
        self.base=[None,None];self.data=[{},{}];self.prefix=[0,0]
        self.attempts=self.bytes=self.work=self.result=self.stop=0
        self.started=None;self.duplicates=self.gaps=0
    def observe(self,side,sequence,flags,payload,now):
        if self.stop:return
        if self.started is not None and now-self.started>=5_000_000_000:
            self.stop=7;self.data=[{},{}];return
        sequence=(sequence+bool(flags&2))&0xffffffff
        if not payload:
            if flags&2 and self.base[side] is None:self.base[side]=sequence
            return
        if self.started is None:self.started=now
        self.attempts+=1
        if self.base[side] is None:self.base[side]=sequence
        offset=(sequence-self.base[side])&0xffffffff
        if offset>=4096 or offset+len(payload)>4096:
            self.stop=5
        else:
            self.work+=len(payload)
            before=self.data[side]
            if any(at in before and before[at]!=byte for at,byte in enumerate(payload,offset)):
                self.stop=4
            else:
                candidate=before|dict(enumerate(payload,offset))
                ranges=sum(at-1 not in candidate for at in candidate)
                if ranges>16:self.stop=5
                else:
                    unique=len(candidate)-len(before)
                    self.duplicates+=unique<len(payload)
                    self.gaps+=offset>self.prefix[side]
                    self.bytes+=unique;self.data[side]=candidate
                    contiguous=0
                    while contiguous in candidate:contiguous+=1
                    if contiguous>self.prefix[side]:
                        self.prefix[side]=contiguous;self.work+=contiguous
                        prefix=bytes(candidate[i] for i in range(contiguous))
                        # Workload contracts, not a general TLS parser: explicit
                        # literal wire equality or endpoint-authenticated TLS.
                        if len(prefix)>=5 and int.from_bytes(prefix[3:5],'big')>4091:self.stop=5
                        elif self.fixture is not None and contiguous>=len(self.fixture):
                            assert prefix[:len(self.fixture)]==self.fixture,'fixture bytes differ'
                            self.result=2 if self.mode in ('bytes','concurrent') else 1
                            self.work+=len(self.fixture)-5;self.stop=1
                        elif self.fixture is None and len(prefix)>=9:
                            record=int.from_bytes(prefix[3:5],'big')
                            if len(prefix)>=5+record:
                                assert prefix[:3] in (b'',b'') and prefix[5]==1
                                self.result=1;self.stop=1
                                self.work+=4+int.from_bytes(prefix[6:9],'big')
        if not self.stop and self.attempts==20:self.stop=6
        if self.stop:self.data=[{},{}]
    def cache(self):
        answer={}
        for side,data in enumerate(self.data):
            contiguous=0
            while contiguous in data:contiguous+=1
            answer.update({f'bytes{side}':len(data),f'contiguous{side}':contiguous,
                f'ranges{side}':sum(at-1 not in data for at in data),f'span{side}':max(data,default=-1)+1})
        return answer

def configurations(directory,run,pixel):
    answer={};uid=run['uid'] if pixel else 12001
    for item in run['configurations']:
        path=directory/item['source'];source=t.source.source(path)
        t.source.query_source(source,props(directory/item['query']),pixel)
        assert source['revision']==item['revision']
        assert [r['expression'] for r in source['rules'][:3]]==[b'',b'',b'']
        assert [r['priority'] for r in source['rules'][:3]]==[10,20,100]
        assert [r['action'] for r in source['rules'][:3]]==[2,2,1]
        assert len(source['rules'])==3+('ack_drop_port' in item)
        if 'ack_drop_port' in item:
            rule=source['rules'][3]
            assert rule['priority']==0 and rule['action']==2 and rule['uid']==uid and not rule['expression']
        logical=sorted(t.logical_rules(source,uid),key=lambda r:r['priority'])
        if 'ack_drop_port' in item:logical=logical[1:]
        assert [r['mode'] for r in logical]==[item['mode'],item['mode'],0]
        answer[(item.get('profile','root'),item['revision'])]=(source,t.source.snapshot_hash(path))
    return answer

def trace(text,life,sessions,fixtures,configs):
    profile,generation=life['profile'],life['generation']
    by_port={s['port']+i:s for s in sessions for i in range(s.get('count',1))}
    prefixes={'admit':'s216 stage=admit ','terminal':'s216 stage=terminal ',
        'acquire':'s209 event=acquire ','release':'s209 event=release ','match':'s209 event=l4 ',
        'flow':'s208 event=observe ','tcp':'s222 event=tcp_update ','lpi':'t12 event=lpi ',
        'sni':'t13 event=sni ','bytes':'t14 event=tcp_cache ','cache':'t11 event=cache ',
        'free':'s203 event=buffer_free ','verdict':'s242 event=verdict_syscall ',
        'completion':'s213 event=completion ','copy':'s237 event=input_copy '}
    rows={key:records(text,prefix) for key,prefix in prefixes.items()}
    counter_history={}
    for _,q in rows['cache']:
        _,acquire=one(rows['acquire'],token=q['token'],generation=q['generation'])
        assert q['hit'] in ('0','1') and q['status']=='0'
        worker=acquire['worker'];previous=counter_history.get(worker,(0,0))
        counters=(int(q['hits']),int(q['misses']))
        assert counters==(previous[0]+int(q['hit']=='1'),previous[1]+int(q['hit']=='0')),'one cache query counter increment'
        counter_history[worker]=counters
    selected=[]
    for index,admit in rows['admit']:
        ports={int(admit.get('src_port',0)),int(admit.get('dst_port',0))}&by_port.keys()
        if not ports:continue
        assert len(ports)==1
        port=ports.pop();facts,flags,payload=t.base.packet(admit)
        assert len(bytes.fromhex(admit['raw']))==int(admit['packet_length']),'complete current packet witness'
        assert int(admit['generation'])==generation and facts['protocol']==6
        token=admit['token'];events={};indices={}
        for name in ('acquire','release','match','terminal'):
            indices[name],events[name]=one(rows[name],token=token,generation=generation)
        match=events['match'];identity=tuple(events['acquire'][k] for k in ('generation','revision','snapshot_hash'))
        assert indices['acquire']<indices['match']<indices['release']
        for name in ('match','release'):assert tuple(events[name][k] for k in ('generation','revision','snapshot_hash'))==identity
        assert tuple(events['release']['content_'+k] for k in ('generation','revision','hash'))==identity
        config,wanted_hash=configs[(profile,int(match['revision']))]
        assert int(match['snapshot_hash'])==wanted_hash
        pre_drop=match['position']=='1' and match['actual_action']=='2'
        for name in ('flow','tcp','lpi','sni','bytes'):
            found=[(i,r) for i,r in rows[name] if r.get('token')==token and r.get('generation')==str(generation)]
            assert len(found)==int(not pre_drop),(name,token,'pre-flow DROP must not feed reconstruction')
            if found:indices[name],events[name]=found[0]
        selected.append(dict(admit=admit,facts=facts,flags=flags,payload=payload,token=token,port=port,
            events=events,indices=indices,config=config,identity=identity,pre_drop=pre_drop))
    assert selected,'packet witnesses missing'
    flows={};totals=defaultdict(int);guards={};cache_peaks=defaultdict(int);delays=[]
    for value in sorted(selected,key=lambda p:p['indices']['match']):
        facts=value['facts'];port=value['port'];e=value['events'];ix=value['indices'];match=e['match']
        session=by_port[port];side=int(facts['sport']!=port)
        if not value['pre_drop']:
            flow,lpi,sni,tcp=e['flow'],e['lpi'],e['sni'],e['tcp']
            if port not in flows:
                assert value['flags']==2 and flow['created']=='1'
                mode=session.get('application',session['mode'] if 'mode' in session else None)
                fixture=bytes.fromhex(fixtures[session['fixture']+'Hex']) if 'fixture' in session else None
                flows[port]=dict(oracle=WireOracle(fixture,mode),packets=0,wire_bytes=0,
                    lpi_attempts=0,lpi_bytes=0,lpi_stop=0,protocols=set(),worker=flow['worker'],
                    slot=flow['slot'],incarnation=lpi['incarnation'])
            state=flows[port];oracle=state['oracle']
            assert flow['status']==lpi['status']=='0'
            assert flow['worker']==value['admit']['owner']==e['acquire']['worker']==state['worker']
            assert flow['pool_worker']==flow['worker'] and int(flow['thread'])==int(flow['worker'])+1
            assert flow['slot']==state['slot']==lpi['slot']==sni['slot']
            assert lpi['incarnation']==sni['incarnation']==tcp['incarnation']==state['incarnation']
            assert ix['acquire']<ix['sni']<ix['lpi']<ix['flow']<ix['match']<ix['release']
            assert tuple(flow[k] for k in ('generation','revision','snapshot_hash'))==value['identity']
            state['packets']+=1;state['wire_bytes']+=int(value['admit']['packet_length'])
            assert int(flow['packets'])==state['packets'] and int(flow['bytes'])==state['wire_bytes'],'wire business accounting'
            assert int(tcp['orig_packets'])+int(tcp['reply_packets'])==state['packets']
            ct=1 if value['flags']==2 else 2
            assert int(tcp['ct_state'])==ct and int(tcp['flow_dir'])==side+1
            oracle.observe(side,int(value['admit']['tcp_seq']),value['flags'],value['payload'],int(value['admit']['mono_ns']))
            for field in ('result','stop','attempts','bytes','work'):
                assert int(sni[field])==getattr(oracle,field),('independent SNI',port,value['token'],field,sni,getattr(oracle,field))
            assert sni['name']==('example.test' if oracle.result==1 else '-')
            expected_cache=oracle.cache()
            for field,wanted in expected_cache.items():
                assert int(e['bytes'][field])==wanted,('cache metadata/span',field,value['token'])
                cache_peaks[field]=max(cache_peaks[field],wanted)
            assert int(sni['cache_bytes'])==expected_cache['bytes0']+expected_cache['bytes1']
            payload=value['payload']
            if oracle.result:state['protocols'].add(1003)
            if payload and not state['lpi_stop']:
                if state['lpi_bytes']+len(payload)>32768:state['lpi_stop']=2
                else:
                    state['lpi_attempts']+=1;state['lpi_bytes']+=len(payload)
                    if payload.startswith((b'\x16\x03\x01',b'\x16\x03\x03')):
                        state['protocols'].add(1003)
                    if state['lpi_attempts']==20:state['lpi_stop']=1
                    elif state['lpi_bytes']==32768:state['lpi_stop']=2
            mask=sum(1<<(p-1001) for p in state['protocols'])
            assert int(lpi['protocols'])==mask and int(lpi['available'])==bool(mask),('published protocol facts',port,lpi,mask)
            for field,key in [('attempts','lpi_attempts'),('bytes','lpi_bytes'),('stop','lpi_stop')]:assert int(lpi[field])==state[key]
            facts.update(ct=ct,flowdir=side+1,lpi=set(state['protocols']) if mask else None,
                sni={0:None,1:'name',2:'absent'}[oracle.result])
            totals['flow_packets']+=1
        else:
            facts.update(ct=None,flowdir=None,lpi=None,sni=None)
            totals['pre_flow_drops']+=1
        rules=t.logical_rules(value['config'],facts['uid'])
        expected=t.reference.ordered_reference(rules,facts)
        for actual,wanted in [('rule','rule_id'),('rank','winner_rank'),('action','action'),('mode','mode'),('actual_action','actual_action')]:
            assert int(match[actual])==expected[wanted],('complete ordered winner',value['token'],actual,expected,match)
        queries=[r for _,r in rows['cache'] if r['token']==value['token'] and r['generation']==str(generation)]
        assert len(queries)==(1 if value['pre_drop'] else 2)
        assert {q['position'] for q in queries}==({'1'} if value['pre_drop'] else {'1','2'})
        for q in queries:
            assert q['status']=='0' and tuple(q[k] for k in ('generation','revision','snapshot_hash'))==value['identity']
            result=expected if value['pre_drop'] or q['position']=='2' else dict(rule_id=0,winner_rank=0,action=0,actual_action=0,mode=0,reason_id=0,priority=0,order=0)
            for actual,wanted in [('rule','rule_id'),('rank','winner_rank'),('declared','action'),('actual','actual_action'),('mode','mode'),('reason','reason_id'),('priority','priority'),('order','order')]:
                assert int(q[actual])==result[wanted],('complete cached winner',value['token'],actual)
            assert int(q['evaluation'])==bool(result['rule_id'])
            assert q['incarnation']==(flows[port]['incarnation'] if q['position']=='2' else '0')
            guarded={k:v for k,v in facts.items() if k not in ('ct','flowdir','lpi','sni')}
            guarded['protocols']=sorted(facts['lpi'] or []) if q['position']=='2' and rules else []
            guarded['sni']=facts['sni'] if q['position']=='2' and rules else None
            guard=(e['acquire']['worker'],value['identity'],q['incarnation'],q['position'],json.dumps(guarded,sort_keys=True))
            if q['hit']=='1':assert guards.get(guard)==result,('cache hit without identical prior complete guard/result',value['token'],guard,result)
            guards[guard]=result;totals['cache_hits' if q['hit']=='1' else 'cache_misses']+=1
        drop=expected['actual_action']==2
        one(rows['free'],obligation=value['token'])
        if profile=='root':
            assert value['admit']['source']=='NFQ_CAPTURED'
            _,verdict=one(rows['verdict'],token=value['token'],generation=generation)
            assert verdict['packet']==value['admit']['packet_id'] and int(verdict['result'])>=0
            assert int(verdict['verdict'])==int(not drop)
        else:
            source=value['admit']['source'];assert source in ('TUN_CAPTURED','FLOW_STACK_RETURN')
            _,completion=one(rows['completion'],token=value['token'],source=source)
            assert int(completion['policy_drop'])==drop
            copies=[r for _,r in rows['copy'] if r.get('token')==value['token']]
            assert len(copies)==int(source=='TUN_CAPTURED' and not drop)
            if copies:assert copies[0]['result']=='0' and copies[0]['owner']==e['acquire']['worker']
        delay=int(e['terminal']['mono_ns'])-int(value['admit']['mono_ns'])
        assert 0<=delay<5_000_000_000,'parser held an original packet'
        delays.append(delay);totals['packets']+=1;totals['actual_drops']+=drop
    assert set(flows)==set(by_port)
    totals['max_admit_to_terminal_us']=max(delays)/1000
    totals['cache_peaks']=dict(cache_peaks)
    totals['duplicate_payloads']=sum(f['oracle'].duplicates for f in flows.values())
    totals['gapped_payloads']=sum(f['oracle'].gaps for f in flows.values())
    return selected,flows,dict(totals)

def query(directory,case,packets,pixel):
    q=props(directory/case['sni']);prefix='' if pixel else 'sni.'
    get=lambda key:q[prefix+key]
    assert get('code')=='0' and int(get('generation'))==case['generation']
    assert [get('worker'),get('slot'),get('incarnation')]==case['identity']
    text=(directory/case['flow']).read_text()
    _,entry=one(records(text,'flow.entry '),worker=case['identity'][0],slot=case['identity'][1],incarnation=case['identity'][2])
    assert str(case['port']) in (entry['port_a'],entry['port_b'])
    _,sni=one(records(text,'flow.sni '),worker=entry['worker'],slot=entry['slot'],incarnation=entry['incarnation'])
    _,cache=one(records(text,'flow.tcp_cache '),worker=entry['worker'],slot=entry['slot'],incarnation=entry['incarnation'])
    assert cache['reserved']=='8340' and cache['range_limit']=='16' and cache['span_limit']=='4096'
    for key in ('result','stop','attempts','bytes','work'):assert sni[key]==get(key),('typed query counter',key)
    assert sni['cache_bytes']==get('cacheBytes' if pixel else 'cache_bytes')
    assert sni['name']==(get('name') or '-')
    expected_result=0 if case['phase'] in ('prefix','expired') else {
        'reorder':1,'bytes':2,'sparse':0,'span':0,'packets':0,
        'segmented':1,'retransmit':1,'exhausted':0,'timeout':0,'concurrent':2,'named':1}[case['mode']]
    expected_stop=0 if case['phase']=='prefix' else 7 if case['phase']=='expired' else {
        'sparse':5,'span':5,'packets':6,'exhausted':5,'timeout':7}.get(case['mode'],1)
    assert int(get('result'))==expected_result and int(get('stop'))==expected_stop,'required query phase outcome'
    matched=[p for p in packets if not p['pre_drop'] and p['events']['flow']['worker']==entry['worker']
        and p['events']['flow']['slot']==entry['slot'] and p['events']['lpi']['incarnation']==entry['incarnation']
        and p['events']['flow']['packets']==entry['packets']]
    assert len(matched)==1
    packet=matched[0];observed=packet['events']['sni']
    for key in ('packets','bytes','first_seen','last_seen'):
        assert entry[key]==packet['events']['flow'][key],'query must retain real packet activity'
    for key in ('result','attempts','bytes','work'):assert sni[key]==observed[key]
    assert entry['rule']==packet['events']['match']['rule']
    if case['phase']=='expired':
        assert sni['stop']=='7' and sni['cache_bytes']=='0'
        assert all(cache[k]=='0' for k in ('bytes0','bytes1','contiguous0','contiguous1','ranges0','ranges1','span0','span1'))
    else:
        assert sni['stop']==observed['stop'] and sni['cache_bytes']==observed['cache_bytes']
        for key in ('bytes0','bytes1','contiguous0','contiguous1','ranges0','ranges1','span0','span1'):
            assert cache[key]==packet['events']['bytes'][key]
    lpi=packet['events']['lpi']
    assert get('protocols')==lpi['protocols'] and get('protocolsAvailable' if pixel else 'protocols_available')==lpi['available']
    if not case.get('fast'):
        path=case['label']+'-stale-sni.properties' if pixel else case['label']+'-stale.txt'
        assert props(directory/path).get('code' if pixel else 'sni.code')!='0'
    return entry

def verify(directory,profile_scope=None):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    if profile_scope is None:
        assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    else:
        assert pixel and profile_scope in ('root','vpn')
        assert not run.get('cleanup_error')
    build=t.base.build_reader.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns']
    for name,key in [('runner.py','runner_sha256'),('wire-helper','helper_sha256'),('wire-helper.c','helper_source_sha256'),
        ('fixtures.json','fixtures_sha256'),('protocol-peer.py' if pixel else 'socket-peer.py','peer_sha256')]:
        assert digest(directory/name)==run[key],('bound input',name)
    fixtures=json.loads((directory/'fixtures.json').read_text());configs=configurations(directory,run,pixel)
    endpoint=json_events(directory/'endpoint.jsonl')
    assert endpoint[0]['kind']=='ready' and endpoint[0]['port']==40641
    if pixel:
        assert digest(build['apk'])==build['apk_sha256']==(directory/'installed-apk.txt').read_text().split()[0]
        installed={Path(line.split()[1]).name:line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
        assert installed==build['native_sha256']
        assert (directory/'installed-helper.txt').read_text().split()[0]==run['helper_sha256']
        lives=run['lifetimes']
        if profile_scope is not None:lives=[life for life in lives if life['profile']==profile_scope]
        assert lives and len({life['profile'] for life in lives})==len(lives)
        assert all(life.get('process_absent') for life in lives),'only completed profile lifetimes may be scoped'
        no_test_hooks((directory/'raw-hooks-after.txt').read_text(),run['sessions'])
    else:
        for name,h in build['artifact_hashes'].items():assert digest(Path(run['artifact'])/name)==h
        assert digest(Path(run['artifact'])/'product-vpp-artifact.properties')==run['manifest_sha256']
        assert 'NFQUEUE' not in (directory/'hooks-after.txt').read_text()
        no_test_hooks((directory/'hooks-after.txt').read_text(),run['sessions'])
        assert props(directory/'final-stopped.txt')['absent']=='True'
        lives=[dict(profile='root',generation=run['generation'])]
    summaries={}
    for life in lives:
        profile=life['profile'];sessions=[s for s in run['sessions'] if s.get('profile','root')==profile]
        cases=[c for c in run['cases'] if c.get('profile','root')==profile]
        modes={s.get('application',s.get('mode')) for s in sessions}
        required={'segmented','retransmit','exhausted','timeout','concurrent','named'} if pixel else set()
        if profile=='root':required|={'reorder','bytes','sparse','span','packets'}
        assert modes==required and len(sessions)==len(required),'complete representative session matrix'
        for session in sessions:
            mode=session.get('application',session.get('mode'))
            wanted={'ready','blocked','recovered'} if mode=='named' else {'complete'}
            if mode in ('reorder','bytes','sparse','span','packets','timeout','concurrent'):wanted.add('prefix')
            if mode=='timeout':wanted.add('expired')
            matching=[c for c in cases if c['client']==session['label']]
            assert len(matching)==len(wanted) and {c['phase'] for c in matching}==wanted,'required typed query phases'
        log=directory/(profile+'-before-stop.log' if pixel else 'first-vpp.log')
        packets,flows,summary=trace(log.read_text(),life,sessions,fixtures,configs)
        entries={c['label']:query(directory,c,packets,pixel) for c in cases}
        for session in sessions:
            mode=session.get('application',session.get('mode'))
            if mode=='named':
                sni=[e for e in endpoint if e['kind']=='sni' and session['started_ns']<=e['time_ns']<=session['completed_ns']]
                assert len(sni)==1 and sni[0]['name']=='example.test'
                peer=sni[0]['peer']
                assert any(e['kind']=='handshake' and e['peer']==peer and e['version']=='TLSv1.2' for e in endpoint)
                message=(session['nonce']+':blocked\n').encode().hex()
                delivered=[e for e in endpoint if e['kind']=='received' and e['hex']==message]
                assert len(delivered)==1
                blocked=json.loads((directory/(session['label']+'-blocked.json')).read_text())
                recovered=json.loads((directory/(session['label']+'-budget_done.json')).read_text())
                assert blocked['blockedTimeout'] and recovered['echoes']==25
                continue
            wire=fixtures[session['fixture']+'Hex']
            candidates=[e for e in endpoint if e['kind']=='raw_received' and e['hex']==wire]
            if profile=='root':
                candidates=[e for e in candidates if session['port']<=e['peer'][1]<session['port']+session.get('count',1)]
            else:
                candidates=[e for e in candidates if session['started_ns']<=e['time_ns']<=session['completed_ns']]
            assert len(candidates)==session.get('count',1),'actual endpoint delivery per TCP stream'
            assert all(e['sha256']==hashlib.sha256(bytes.fromhex(wire)).hexdigest() for e in candidates)
            if session.get('raw') or not pixel:
                client=directory/(session['label']+'-client.jsonl')
                events=[json.loads(line) for line in client.read_text().splitlines()]
                assert sum(e['kind']=='endpoint_receipt' for e in events)==1
            else:
                receipt=json.loads((directory/(session['label']+'-raw_ready.json')).read_text())
                assert receipt['endpointReceipts']==session.get('count',1)
            if mode in ('reorder','retransmit'):
                assert flows[session['port']]['oracle'].duplicates>0,'actual duplicate payload missing'
            if mode=='reorder':assert flows[session['port']]['oracle'].gaps>0
        counters=(directory/(profile+'-final.txt' if pixel else 'final-counters.txt')).read_text()
        runtime=records(counters,'flow.runtime ');assert len(runtime)==2
        for _,row in runtime:
            assert row['capacity']=='1024' and row['entry_bytes']=='9016' and row['allocated_bytes']=='9253192'
            assert row['capacity_misses']=='0'
        for _,row in records(counters,'policy.cache '):assert row['storage_bytes']=='23584' and row['capacity']=='128'
        completions=records(counters,'completion.status ');assert len(completions)==1
        assert all(completions[0][1][key]=='0' for key in ('pending','frames','buffers','obligations')),'native buffer conservation'
        if pixel:
            assert summary['actual_drops']>0 and summary['pre_flow_drops']>0
            before=next(c for c in cases if c['mode']=='timeout' and c['phase']=='prefix')
            after=next(c for c in cases if c['mode']=='timeout' and c['phase']=='expired')
            assert entries[before['label']]['packets']==entries[after['label']]['packets']
            assert entries[before['label']]['incarnation']==entries[after['label']]['incarnation']
            for key in ('bytes','first_seen','last_seen','orig_packets','reply_packets','orig_bytes','reply_bytes'):
                assert entries[before['label']][key]==entries[after['label']][key],'parser timeout changed Flow accounting/activity'
            timers=[]
            for case in (before,after):
                _,timer=one(records((directory/case['flow']).read_text(),'flow.timer '),
                    worker=case['identity'][0],slot=case['identity'][1],incarnation=case['identity'][2])
                timers.append(timer)
            assert all(timers[0][key]==timers[1][key] for key in ('deadline_us','timeout')),'parser timeout refreshed CT'
            concurrent=next(c for c in cases if c['mode']=='concurrent' and c['phase']=='prefix')
            text=(directory/concurrent['flow']).read_text();active=[]
            for _,row in records(text,'flow.entry '):
                if not concurrent['port']<=int(row['port_a'])<concurrent['port']+48 and not concurrent['port']<=int(row['port_b'])<concurrent['port']+48:continue
                _,sni=one(records(text,'flow.sni '),worker=row['worker'],slot=row['slot'],incarnation=row['incarnation'])
                assert sni['stop']=='0' and sni['result']=='0' and sni['cache_bytes']=='20'
                active.append(sni)
            assert len(active)==48,'no independent 32-parser admission cap'
            summary['simultaneous_attempts']=len(active);summary['simultaneous_cache_bytes']=sum(int(s['cache_bytes']) for s in active)
            running=props(directory/(profile+'-running.properties'));stopped=props(directory/(profile+'-stopped.properties'))
            assert running['generation']==str(life['generation']) and running['state']=='running'
            assert running['protectionRunning']==('true' if profile=='root' else 'false')
            assert stopped['state']=='stopped' and stopped['mayBeActive']=='false' and life['process_absent']
        summaries[profile]=summary
    return dict(status='PASS',source_sha256=run['source_sha256'],profiles=summaries,
        excluded_run_failure=run.get('error') if profile_scope is not None else None,
        scope='T14 current Product TCP reconstruction, complete rule/cache/API/native completion and actual endpoint receipts')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    p.add_argument('--profile-scope',choices=['root','vpn'])
    a=p.parse_args();answer=verify(a.directory,a.profile_scope)
    text=json.dumps(answer,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    print(text,end='')
