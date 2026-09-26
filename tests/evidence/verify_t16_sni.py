#!/usr/bin/env python3
"""Independent QUIC wire/library, full winner/cache, API and completion joins."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
t13=module('t15_t13',ROOT/'tests/evidence/verify_t13_sni.py')
t=t13.t
peer=module('t16_peer',ROOT/'tests/device/helpers/t16_quic_peer.py')
records,one,props,digest=t.records,t.one,t.props,t.digest
EXPECTED={'named':(1,1,'example.test'),'absent':(2,1,''),'conflict':(0,2,''),
          'ranges':(0,5,''),'offset':(0,5,''),'timeout':(0,7,''),'packets':(0,6,''),
          'named_cutoff':(1,1,'example.test'),'absent_cutoff':(2,1,'')}

DOMAIN_EXPECTED=dict(named=(1,1,'example.test'),named_child=(1,1,'a.example.test'),
    named_boundary=(1,1,'badexample.test'),named_suffix=(1,1,'example.test.evil'),
    named_alabel=(1,1,'xn--bcher-kva.example'),absent=(2,1,''),conflict=(0,2,''),named_cutoff=(1,1,'example.test'))
ALL_EXPECTED=EXPECTED|DOMAIN_EXPECTED

def decrypt(packet,expected=0):
    segments=[];pn=expected
    while packet:
        buf=peer.Buffer(data=packet);header=peer.pull_quic_header(buf,host_cid_length=8)
        pair=peer.CryptoPair();pair.setup_initial(header.destination_cid,is_client=False,version=1)
        _header,payload,pn=pair.decrypt_packet(packet[:header.packet_length],buf.tell(),pn)
        stream=peer.Buffer(data=payload)
        while not stream.eof():
            kind=stream.pull_uint_var()
            if kind in (0,1):continue
            assert kind==6
            offset,size=stream.pull_uint_var(),stream.pull_uint_var()
            segments.append((offset,stream.pull_bytes(size)))
        packet=packet[header.packet_length:]
    return segments,pn

def fixture_oracle(fixtures):
    assert fixtures['aioquic']=='1.3.0' and set(fixtures['cases']) in (set(EXPECTED),set(ALL_EXPECTED))
    assert len(bytes.fromhex(fixtures['preludeHex']))==20
    assert fixtures['preludeHex'].startswith('000100002112a442')
    assert fixtures['preludeReplyHex']=='0101'+fixtures['preludeHex'][4:]
    for mode,case in fixtures['cases'].items():
        assert (case['result'],case['stop'],case['name'])==ALL_EXPECTED[mode]
        assert len(case['sequence'])>1 or mode=='timeout'
        data={};pn=0
        for encoded in case['sequence']:
            segments,pn=decrypt(bytes.fromhex(encoded),pn)
            for offset,chunk in segments:
                for i,byte in enumerate(chunk):
                    if not case['raw']:assert data.get(offset+i,byte)==byte
                    data[offset+i]=byte
        if not case['raw']:
            assert sorted(data)==list(range(len(data)))
            hello=bytes(data[i] for i in range(len(data)))
            decoded=peer.pull_client_hello(peer.Buffer(data=hello))
            assert (decoded.server_name or '')==ALL_EXPECTED[mode][2]
            assert hello.hex()==case['oracle']['cryptoHex']
        else:
            first,_=decrypt(bytes.fromhex(case['sequence'][0]))
            if mode in ('conflict','timeout','packets'):assert first==[(0,peer.wire.hello('Example.TEST')[:20])]
            if mode=='ranges':assert first==[(i*2+1,b'x') for i in range(32)]
            if mode=='offset':assert first==[(4095,b'x')]

def ranges(data):
    return sum(i-1 not in data for i in data)

def observe(session,facts,payload,length,side):
    if not length or session['stop']:return
    if session['bytes']+length>32768:session['stop']=2;return
    session['attempts']+=1;session['bytes']+=length
    if length==20 and payload[:8] in (bytes.fromhex('000100002112a442'),bytes.fromhex('010100002112a442')):
        session['protocols'].add(1016)
    # Workload-specific header recognition, never sufficient for SNI. All
    # submitted v1 test Initials have this envelope, including auth failures.
    if length>=1200 and payload[0]&0xf0==0xc0 and payload[1:5]==b'\0\0\0\1':
        session['protocols'].add(1004)
    if session['attempts']==20:session['stop']=1
    elif session['bytes']==32768:session['stop']=2

def features(text,cases,fixtures):
    rows=records(text,'t13 event=sni ');crypto_rows=records(text,'t16 event=quic_crypto ')
    modes={case['port']:case['mode'] for case in cases}
    def feature(value,session,facts):
        index,row=one(rows,token=value['token'],generation=value['admit']['generation'])
        assert index<value['indices']['lpi']<value['indices']['match']
        assert all(row[k]==value['lpi'][k] for k in ('worker','slot','incarnation'))
        _,assembly=one(crypto_rows,token=value['token'],generation=value['admit']['generation'])
        mode=modes[session['source_port']];fixture=fixtures['cases'][mode]
        payload=value['payload'];client=facts['sport']==session['source_port']
        state=session.setdefault('assembly',dict(data={},attempts=0,bytes=0,work=0,result=0,stop=0,name='',pn=0,sequence=0))
        if not state['stop']:
            if mode=='timeout' and state['attempts'] and int(value['admit']['mono_ns'])-state['start_ns']>=5_000_000_000:
                state['stop']=7;state['data'].clear()
            else:
                if not state['attempts']:state['start_ns']=int(value['admit']['mono_ns'])
                state['attempts']+=1;state['work']+=len(payload)
                if client and payload[0]&0xc0==0xc0:
                    assert state['sequence']<len(fixture['sequence'])
                    assert payload.hex()==fixture['sequence'][state['sequence']], 'unexpected protected wire/order'
                    state['sequence']+=1
                    segments,state['pn']=decrypt(payload,state['pn'])
                    for offset,data in segments:
                        if offset+len(data)>4096:state['stop']=5;break
                        state['work']+=len(data)
                        if any(state['data'].get(offset+i,b)!=b for i,b in enumerate(data)):
                            state['stop']=2;break
                        merged=state['data']|{offset+i:b for i,b in enumerate(data)}
                        if ranges(merged)>32:state['stop']=5;break
                        state['bytes']+=len(merged)-len(state['data']);state['data']=merged
                    contiguous=0
                    while contiguous in state['data']:contiguous+=1
                    if not state['stop'] and contiguous>=4:
                        prefix=bytes(state['data'][i] for i in range(contiguous))
                        wanted=int.from_bytes(prefix[1:4],'big')+4
                        if contiguous>=wanted:
                            hello=peer.pull_client_hello(peer.Buffer(data=prefix))
                            state['result']=1 if hello.server_name else 2;state['name']=(hello.server_name or '').lower()
                            state['work']+=wanted;state['stop']=1
                if not state['stop'] and state['attempts']==20:state['stop']=6
                if state['stop']:state['data'].clear()
        assert int(row['result'])==state['result'] and int(row['stop'])==state['stop'],(mode,row,state)
        assert row['name']==(state['name'] or '-')
        assert int(row['cache_bytes'])==len(state['data'])==int(assembly['retained'])
        assert int(assembly['ranges'])==ranges(state['data'])
        contiguous=0
        while contiguous in state['data']:contiguous+=1
        assert int(assembly['contiguous'])==contiguous
        assert int(assembly['span'])==(max(state['data'])+1 if state['data'] else 0)
        anchored=bool(state['sequence'] and not state['stop'])
        assert int(assembly['anchored'])==int(anchored)
        assert int(assembly['largest_pn'])==(state['pn'] if anchored else 0)
        for key in ('attempts','bytes','work'):assert int(row[key])==state[key],(mode,key,row,state)
        session['sni']='name' if state['result']==1 else 'absent' if state['result']==2 else None
        facts['sni']=session['sni'];value['sni']=row;value['assembly']=assembly
        if value['config'].get('domain_count'):
            facts.update(name=state['name'],domain_source=t13.domains.source_lists(value['config']))
    return feature

def query(directory,case,packets,pixel):
    q=props(directory/case['sni']);prefix='' if pixel else 'sni.'
    get=lambda key:q[prefix+key]
    assert get('code')=='0' and int(get('generation'))==case['generation']
    assert [get('worker'),get('slot'),get('incarnation')]==case['identity']
    result,stop,name=ALL_EXPECTED[case['mode']]
    assert (int(get('result')),int(get('stop')),get('name'))==(result,stop,name)
    assert int(get('protocols'))==32776
    assert get('protocolsAvailable' if pixel else 'protocols_available')=='1'
    assert get('cacheBytes' if pixel else 'cache_bytes')=='0'
    _,entry=one(records((directory/case['flow']).read_text(),'flow.entry '),
        worker=case['identity'][0],slot=case['identity'][1],incarnation=case['identity'][2])
    matches=[p for p in packets if p['flow']['slot']==entry['slot'] and p['flow']['worker']==entry['worker']
             and p['lpi']['incarnation']==entry['incarnation'] and p['flow']['packets']==entry['packets']]
    assert len(matches)==1 and matches[0]['match']['rule']==entry['rule']
    for key in ('result','stop','attempts','bytes','work'):
        if case['mode']=='timeout' and key=='stop':continue
        assert matches[0]['sni'][key]==get(key),('typed SNI does not match packet-prefix fact',key)
    _,assembly=one(records((directory/case['flow']).read_text(),'flow.quic_crypto '),
        worker=case['identity'][0],slot=case['identity'][1],incarnation=case['identity'][2])
    assert all(assembly[key]=='0' for key in ('retained','contiguous','ranges','span','anchored','largest_pn'))
    if case['mode']=='timeout':
        assert get('stop')=='7' and get('result')=='0'

    stale=props(directory/(case['label']+'-stale-sni.properties' if pixel else case['label']+'-stale.txt'))
    assert stale.get('code' if pixel else 'sni.code')!='0'

def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build=t.base.build_reader.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns']
    assert any(n.startswith('third_party/mbedtls/') for n in build['files']),'crypto source absent from closure'
    assert digest(directory/'runner.py')==run['runner_sha256']
    assert digest(directory/('protocol-peer.py' if pixel else 'socket-peer.py'))==run['peer_sha256']
    assert digest(directory/'fixtures.json')==run['fixtures_sha256']
    fixtures=json.loads((directory/'fixtures.json').read_text());fixture_oracle(fixtures)
    configs=t13.configurations(directory,run,pixel)
    if run.get("domain_policy"):t13.domains.build_binding(directory,run,build,props)
    expected_modes=DOMAIN_EXPECTED if run.get("domain_policy") else EXPECTED
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoint[0]['kind']=='ready' and endpoint[0]['port']==40650 and endpoint[0]['aioquic']=='1.3.0'
    assert not any(e['kind']=='quic_error' for e in endpoint)
    if pixel:
        assert digest(build['apk'])==build['apk_sha256']==(directory/'installed-apk.txt').read_text().split()[0]
        installed={Path(line.split()[1]).name:line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
        assert installed==build['native_sha256']
        assert props(Path(run['build']).parent/'stage/product-stage.properties')['quicCrypto']=='mbedtls-3.6.7-aes-gcm-sha256-static-c'
        lives=run['lifetimes']
        assert [life['profile'] for life in lives]==run.get('requested_profiles',['root','vpn'])
        assert all(life['profile'] in ('root','vpn') for life in lives)
    else:
        for name,h in build['artifact_hashes'].items():assert digest(Path(run['artifact'])/name)==h
        manifest=Path(run['artifact'])/'product-vpp-artifact.properties'
        assert digest(manifest)==run['manifest_sha256']
        assert props(manifest)['quic.crypto']=='mbedtls-3.6.7-aes-gcm-sha256-static-c'
        assert 'NFQUEUE' not in (directory/'hooks-after.txt').read_text()
        assert props(directory/'final-stopped.txt')['absent']=='True'
        lives=[dict(profile='root',generation=run['generation'])]
    summary={}
    for life in lives:
        profile=life['profile'];generation=life['generation'];uid=run['uid'] if pixel else 12001
        cases=[c for c in run['cases'] if c.get('profile','root')==profile]
        assert {case['mode'] for case in cases}==set(expected_modes)
        ports=sorted({case['port'] for case in cases});assert len(ports)==len(expected_modes)
        text=(directory/(profile+'-before-stop.log' if pixel else 'first-vpp.log')).read_text()
        packets,sessions,totals,_=t.verify_trace(text,profile,generation,ports,configs,uid,observe,
                                               features(text,cases,fixtures))
        for case in cases:query(directory,case,packets,pixel)
        if run.get("domain_policy"):totals["list_only_winner_changes"]=t13.domains.transitions(cases,packets,configs,profile)
        for mode in expected_modes:
            ready=next(case for case in cases if case['mode']==mode and case['phase']=='ready')
            recovered=next(case for case in cases if case['mode']==mode and case['phase']=='recovered')
            assert ready['identity']==recovered['identity'],'policy updates replaced Flow identity'
            nonce=ready['nonce'];fixture=fixtures['cases'][mode]
            echoes=[e for e in endpoint if e['kind']=='echo' and bytes.fromhex(e['hex']).startswith(('T15-'+nonce+':').encode())]
            changed=run.get('domain_policy') and not mode.endswith('_cutoff') and (mode.startswith('named') or mode=='absent')
            wanted_echoes={'T15-'+nonce+':'+str(i) for i in range(25)}
            if changed and pixel:wanted_echoes.add('T15-'+nonce+':domain-change')
            assert len(echoes)==(26 if changed and pixel else 50 if changed else 25)
            assert {bytes.fromhex(e['hex']).decode() for e in echoes}==wanted_echoes
            remote=echoes[0]['peer'];assert all(e['peer']==remote for e in echoes)
            if profile=='root':assert remote[1]==ready['port']
            arrivals=[e for e in endpoint if e['kind']=='received' and e['peer']==remote and e['hex'] in fixture['sequence']]
            wanted=fixture['sequence'][:-1] if mode.endswith('_cutoff') else fixture['sequence']
            assert [e['hex'] for e in arrivals]==wanted,('endpoint CRYPTO sequence',mode)
            if not fixture['raw'] and not mode.endswith('_cutoff'):
                assert any(e['kind']=='quic_event' and e['peer']==remote and e['event']=='ProtocolNegotiated' for e in endpoint)
                assert any(e['kind']=='quic_response' and e['peer']==remote for e in endpoint)
            observed=[p for p in packets if ready['port'] in (p['facts']['sport'],p['facts']['dport'])]
            initial=next(p for p in observed if p['facts']['sport']==ready['port'] and p['payload'].hex()==fixture['sequence'][-1])
            assert initial['expected']['actual_action']==(2 if mode.endswith('_cutoff') else 1)
            if expected_modes[mode][0]:
                assert initial['expected']['action']==2 and initial['sni']['stop']=='1'
                _,cached=one(records(text,'t11 event=cache '),token=initial['token'],generation=generation,position=2)
                assert cached['hit']=='0'
                partial=[p for p in observed if p['facts']['sport']==ready['port'] and p['payload'].hex() in fixture['sequence'][:-1]]
                assert partial and all(p['sni']['result']=='0' and p['expected']['actual_action']==1 for p in partial)
                assert any(int(p['sni']['cache_bytes'])>0 for p in partial)
            if pixel:
                report=json.loads((directory/(ready['client']+'-finished.json')).read_text())
                session=next(s for s in run['sessions'] if s['label']==ready['client'])
                assert report['nonce']==nonce and report['uid']==uid and report['plan']==session['plan']
                assert report['echoes']==25 and not report.get('error')
                if not mode.endswith('_cutoff') and (mode.startswith('named') or mode=='absent'):assert report['blockedTimeout']
                if mode=='timeout':assert report['timeoutWaitNs']>=5_100_000_000
                if not fixture['raw']:
                    assert all(any(e['kind']=='quic_response' and e['peer']==remote and e['hex']==reply for e in endpoint) for reply in report['sequenceReplies'])
            else:
                events=json.loads((directory/(ready['client']+'-client.json')).read_text())
                assert events[0]['kind']=='quic_ready' and events[-1]['kind']=='closed'
                if not mode.endswith('_cutoff') and (mode.startswith('named') or mode=='absent'):assert any(e['kind']=='timeout' for e in events)
        terminal=records(text,'s216 stage=terminal ');delays=[]
        for packet in packets:
            _,done=one(terminal,token=packet['token'],generation=generation)
            delay=int(done['mono_ns'])-int(packet['admit']['mono_ns'])
            assert 0<=delay<5_000_000_000,'packet waited for parser lifetime'
            delays.append(delay)
        if pixel:
            running=props(directory/(profile+'-running.properties'));stopped=props(directory/(profile+'-stopped.properties'))
            assert running['generation']==str(generation) and running['state']=='running'
            assert running['protectionRunning']==('true' if profile=='root' else 'false')
            assert stopped['state']=='stopped' and stopped['mayBeActive']=='false' and life['process_absent']
        counters=(directory/(profile+'-final.txt' if pixel else 'final-counters.txt')).read_text()
        runtime_rows=records(counters,'flow.runtime ');assert len(runtime_rows)==2
        for _,row in runtime_rows:
            assert row['capacity']=='1024' and row['entry_bytes']=='9024'
            assert row['allocated_bytes']=='9261384' and row['capacity_misses']=='0'
        for _,row in records(counters,'policy.cache '):
            assert row['storage_bytes']==('24608' if run.get('domain_policy') else '23584') and row['capacity']=='128'
        totals['maximum_admit_to_terminal_us']=max(delays)/1000
        totals['peak_crypto_retained']=max(int(p['assembly']['retained']) for p in packets)
        totals['peak_crypto_ranges']=max(int(p['assembly']['ranges']) for p in packets)
        totals['peak_sni_work']=max(int(p['sni']['work']) for p in packets)
        summary[profile]=totals
    return dict(status='PASS',scope='QUIC v1 multi-Initial assembly (not completed handshake), STUN coexistence, full winner/cache/query/completion',
                source_sha256=run['source_sha256'],profiles=summary)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args();value=verify(args.directory);text=json.dumps(value,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text,end='')
