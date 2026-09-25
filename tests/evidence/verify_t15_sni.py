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
peer=module('t15_peer',ROOT/'tests/device/helpers/t15_quic_peer.py')
records,one,props,digest=t.records,t.one,t.props,t.digest
EXPECTED={'named':(1,1,'example.test'),'absent':(2,1,''),'malformed':(0,2,''),
          'version':(0,9,''),'authentication':(0,10,''),'incomplete':(0,11,''),
          'named_cutoff':(1,1,'example.test'),'absent_cutoff':(2,1,'')}

def fixture_oracle(fixtures):
    assert fixtures['aioquic']=='1.3.0' and set(fixtures['cases'])==set(EXPECTED)
    assert len(bytes.fromhex(fixtures['preludeHex']))==20
    assert fixtures['preludeHex'].startswith('000100002112a442')
    assert fixtures['preludeReplyHex']=='0101'+fixtures['preludeHex'][4:]
    samples={name:wire for name,wire,*_ in peer.wire.cases()}
    raw={'malformed':'malformed-name','version':'version','authentication':'authentication-300','incomplete':'gap'}
    for mode,case in fixtures['cases'].items():
        assert (case['result'],case['stop'],case['name'])==EXPECTED[mode]
        data=bytes.fromhex(case['hex'])
        if mode in raw:
            assert case['raw'] and data==samples[raw[mode]]
        else:
            assert not case['raw']
            oracle=peer.decode_initial(data)
            assert oracle==case['oracle'] and (oracle['name'] or '')==EXPECTED[mode][2]

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
    rows=records(text,'t13 event=sni ');modes={case['port']:case['mode'] for case in cases}
    def feature(value,session,facts):
        index,row=one(rows,token=value['token'],generation=value['admit']['generation'])
        assert index<value['indices']['lpi']<value['indices']['match']
        assert all(row[k]==value['lpi'][k] for k in ('worker','slot','incarnation'))
        mode=modes[session['source_port']];fixture=fixtures['cases'][mode]
        payload=value['payload'];client=facts['sport']==session['source_port']
        if 'initial_token' not in session:
            if client and len(payload)>=1200:
                assert payload.hex()==fixture['hex'],'actual protected wire differs from independent Initial'
                session['initial_token']=value['token']
                session['sni_result'],session['sni_stop'],session['sni_name']=EXPECTED[mode]
                session['sni']='name' if fixture['result']==1 else 'absent' if fixture['result']==2 else None
                # A complete datagram is processed before this packet's match;
                # no result from a later packet is used to explain this winner.
                session['sni_attempts']=5;session['sni_bytes']=1280
                hello_bytes=len(bytes.fromhex(fixture['oracle']['cryptoHex'])) if fixture['result'] else (65 if mode=='malformed' else 0)
                session['sni_work']=1280+hello_bytes
            else:
                expected=fixtures['preludeHex'] if client else fixtures['preludeReplyHex']
                assert payload.hex()==expected,'unexplained pre-Initial traffic'
                session['sni_attempts']=session.get('sni_attempts',0)+1
                session['sni_bytes']=session['sni_work']=20*session['sni_attempts']
        assert int(row['result'])==session.get('sni_result',0)
        assert int(row['stop'])==session.get('sni_stop',0)
        assert row['name']==(session.get('sni_name') or '-') and row['cache_bytes']=='0'
        for key in ('attempts','bytes','work'):
            assert int(row[key])==session['sni_'+key],('SNI bounded work',mode,key,row)
        facts['sni']=session.get('sni');value['sni']=row
    return feature

def query(directory,case,packets,pixel):
    q=props(directory/case['sni']);prefix='' if pixel else 'sni.'
    get=lambda key:q[prefix+key]
    assert get('code')=='0' and int(get('generation'))==case['generation']
    assert [get('worker'),get('slot'),get('incarnation')]==case['identity']
    result,stop,name=EXPECTED[case['mode']]
    assert (int(get('result')),int(get('stop')),get('name'))==(result,stop,name)
    assert int(get('protocols'))==(32768 if case['mode']=='version' else 32776)
    assert get('protocolsAvailable' if pixel else 'protocols_available')=='1'
    assert get('cacheBytes' if pixel else 'cache_bytes')=='0'
    _,entry=one(records((directory/case['flow']).read_text(),'flow.entry '),
        worker=case['identity'][0],slot=case['identity'][1],incarnation=case['identity'][2])
    matches=[p for p in packets if p['flow']['slot']==entry['slot'] and p['flow']['worker']==entry['worker']
             and p['lpi']['incarnation']==entry['incarnation'] and p['flow']['packets']==entry['packets']]
    assert len(matches)==1 and matches[0]['match']['rule']==entry['rule']
    for key in ('result','stop','attempts','bytes','work'):
        assert matches[0]['sni'][key]==get(key),('typed SNI does not match packet-prefix fact',key)
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
        assert {case['mode'] for case in cases}==set(EXPECTED)
        ports=sorted({case['port'] for case in cases});assert len(ports)==8
        text=(directory/(profile+'-before-stop.log' if pixel else 'first-vpp.log')).read_text()
        packets,sessions,totals,_=t.verify_trace(text,profile,generation,ports,configs,uid,observe,
                                               features(text,cases,fixtures))
        for case in cases:query(directory,case,packets,pixel)
        for mode in EXPECTED:
            ready=next(case for case in cases if case['mode']==mode and case['phase']=='ready')
            recovered=next(case for case in cases if case['mode']==mode and case['phase']=='recovered')
            assert ready['identity']==recovered['identity'],'policy updates replaced Flow identity'
            nonce=ready['nonce'];fixture=fixtures['cases'][mode]
            echoes=[e for e in endpoint if e['kind']=='echo' and bytes.fromhex(e['hex']).startswith(('T15-'+nonce+':').encode())]
            assert len(echoes)==25
            assert {bytes.fromhex(e['hex']).decode() for e in echoes}=={'T15-'+nonce+':'+str(i) for i in range(25)}
            remote=echoes[0]['peer'];assert all(e['peer']==remote for e in echoes)
            if profile=='root':assert remote[1]==ready['port']
            arrivals=[e for e in endpoint if e['kind']=='received' and e['peer']==remote and e['hex']==fixture['hex']]
            if mode.endswith('_cutoff'):
                assert not arrivals,'same Initial was delivered despite synchronous DROP'
            else:
                assert len(arrivals)==1
                if not fixture['raw']:
                    initial=[e for e in endpoint if e['kind']=='initial' and e['peer']==remote]
                    assert len(initial)==1 and (initial[0]['name'] or '')==EXPECTED[mode][2]
                    assert initial[0]['hex']==fixture['hex']
                    assert any(e['kind']=='quic_event' and e['peer']==remote and e['event']=='ProtocolNegotiated' for e in endpoint)
                    assert any(e['kind']=='quic_response' and e['peer']==remote for e in endpoint)
            observed=[p for p in packets if ready['port'] in (p['facts']['sport'],p['facts']['dport'])]
            initial=next(p for p in observed if p['payload'].hex()==fixture['hex'])
            assert initial['expected']['actual_action']==(2 if mode.endswith('_cutoff') else 1)
            if EXPECTED[mode][0]:
                assert initial['expected']['action']==2 and initial['sni']['stop']=='1'
                # STUN already warmed a fallback result for this application;
                # adding QUIC/SNI must miss the prior post-flow cache entry.
                _,cached=one(records(text,'t11 event=cache '),token=initial['token'],generation=generation,position=2)
                assert cached['hit']=='0'
            if pixel:
                report=json.loads((directory/(ready['client']+'-finished.json')).read_text())
                session=next(s for s in run['sessions'] if s['label']==ready['client'])
                assert report['nonce']==nonce and report['uid']==uid and report['plan']==session['plan']
                assert report['echoes']==25 and not report.get('error')
                if mode.endswith('_cutoff'):assert report['initialTimeout']
                elif mode in ('named','absent'):
                    assert report['blockedTimeout']
                    assert any(e['kind']=='quic_response' and e['peer']==remote and e['hex']==report['initialReplyHex'] for e in endpoint)
            else:
                events=json.loads((directory/(ready['client']+'-client.json')).read_text())
                assert events[0]['kind']=='quic_ready' and events[-1]['kind']=='closed'
                if mode.endswith('_cutoff'):assert events[0]['initial_timeout']
                elif mode in ('named','absent'):assert any(e['kind']=='timeout' for e in events)
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
            assert row['capacity']=='1024' and row['entry_bytes']=='9016'
            assert row['allocated_bytes']=='9253192' and row['capacity_misses']=='0'
        for _,row in records(counters,'policy.cache '):
            assert row['storage_bytes']=='23584' and row['capacity']=='128'
        totals['maximum_admit_to_terminal_us']=max(delays)/1000
        summary[profile]=totals
    return dict(status='PASS',scope='QUIC v1 Initial exchange (not completed handshake), STUN coexistence, full winner/cache/query/completion',
                source_sha256=run['source_sha256'],profiles=summary)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('directory',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args();value=verify(args.directory);text=json.dumps(value,indent=2)+'\n'
    if args.output:args.output.write_text(text)
    print(text,end='')
