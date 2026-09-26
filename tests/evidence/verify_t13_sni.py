#!/usr/bin/env python3
"""Independent T13 saved-source, wire, typed-query and endpoint verification."""
import argparse,importlib.util,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('t13_base',ROOT/'tests/evidence/verify_t12_lpi.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
records,one,props,digest=t.records,t.one,t.props,t.digest
domains=t.module('t18_domains',ROOT/'tests/evidence/domain_evidence.py')

def configurations(directory,run,pixel):
    answer={}
    for item in run['configurations']:
        path=directory/item['source'];source=t.source.source(path)
        t.source.query_source(source,props(directory/item['query']),pixel)
        assert source['revision']==item['revision']
        if run.get('domain_policy'): domains.configuration(source,item)
        else: assert [r['expression'] for r in source['rules']]==[b'\x10\x01',b'\x10\x01\x03',b'']
        assert [r['priority'] for r in source['rules']]==[10,20,100]
        assert [r['action'] for r in source['rules']]==[2,2,1]
        rules=sorted(t.logical_rules(source,run['uid'] if pixel else 12001),key=lambda r:r['priority'])
        assert [r['mode'] for r in rules]==[item['mode'],item['mode'],0]
        answer[(item.get('profile','root'),item['revision'])]=(source,t.source.snapshot_hash(path))
    return answer

def observe(session,facts,payload,length,side):
    if not length or session['stop']:return
    if session['bytes']+length>32768:session['stop']=2;return
    session['attempts']+=1;session['bytes']+=length
    # Exact representative workload expectation: every tested first client
    # payload starts with this TLS header, including the two invalid cases.
    # This is deliberately separate from completed ClientHello/SNI evidence.
    if side==1 and session['attempts']==1:
        assert payload[:3] in (b'\x16\x03\x01',b'\x16\x03\x03')
        session['protocols'].add(1003)
    if session['attempts']==20:session['stop']=1
    elif session['bytes']==32768:session['stop']=2

def feature_oracle(text,cases,fixtures):
    rows=records(text,'t13 event=sni ')
    modes={c['port']:c['mode'] for c in cases}
    def feature(value,session,facts):
        index,row=one(rows,token=value['token'],generation=value['admit']['generation'])
        assert index<value['indices']['lpi']<value['indices']['match']
        assert all(row[k]==value['lpi'][k] for k in ('worker','slot','incarnation'))
        mode=modes[session['source_port']]
        payload=value['payload'];client=facts['sport']==session['source_port']
        if payload and client and 'first_payload' not in session:
            session['first_payload']=payload
            if mode in ('named','absent'):
                # Complete first record and handshake must be present in this
                # representative trace. Endpoint's actual TLS stack below
                # independently accepts it and reports the sent name/absence.
                assert len(payload)>=9 and len(payload)>=5+int.from_bytes(payload[3:5],'big')
                assert payload[5]==1 and 4+int.from_bytes(payload[6:9],'big')<=int.from_bytes(payload[3:5],'big')
                session['sni']='name' if mode=='named' else 'absent'
            else:
                assert payload.hex()==fixtures[mode+'Hex'];session['sni']=None
        wanted={None:0,'name':1,'absent':2}[session.get('sni')]
        assert int(row['result'])==wanted,('SNI fact',mode,value['token'],row)
        assert row['name']==('example.test' if wanted==1 else '-')
        if wanted:assert row['stop']=='1' and row['cache_bytes']=='0'
        if mode=='malformed' and 'first_payload' in session:assert row['stop']=='2' and row['cache_bytes']=='0'
        if mode=='truncated':assert row['stop'] in ('0','7','8')
        facts['sni']=session.get('sni');value['sni']=row
        if value['config'].get('domain_count'):
            facts.update(name='example.test' if wanted==1 else '',domain_source=domains.source_lists(value['config']))
    return feature

def query(directory,case,packets,pixel):
    q=props(directory/case['sni']);prefix='' if pixel else 'sni.'
    get=lambda k:q[prefix+k]
    assert get('code')=='0' and int(get('generation'))==case['generation']
    assert [get('worker'),get('slot'),get('incarnation')]==case['identity']
    expected={'named':1,'absent':2,'malformed':0,'truncated':0}[case['mode']]
    assert int(get('result'))==expected and get('name')==('example.test' if expected==1 else '')
    assert get('protocols')=='4' and get('protocolsAvailable' if pixel else 'protocols_available')=='1'
    cache=get('cacheBytes' if pixel else 'cache_bytes')
    if expected:assert get('stop')=='1' and cache=='0'
    if case['mode']=='malformed':assert get('stop')=='2' and cache=='0'
    if case['phase']=='expired':assert get('stop')=='7' and cache=='0'
    text=(directory/case['flow']).read_text()
    _,entry=one(records(text,'flow.entry '),worker=case['identity'][0],slot=case['identity'][1],incarnation=case['identity'][2])
    _,sni=one(records(text,'flow.sni '),worker=entry['worker'],slot=entry['slot'],incarnation=entry['incarnation'])
    assert sni['result']==get('result') and sni['stop']==get('stop')
    assert sni['name']==(get('name') or '-')
    for key in ('attempts','bytes','work'):
        assert sni[key]==get(key),('typed producer counter',key)
    assert sni['cache_bytes']==cache
    matches=[p for p in packets if p['flow']['slot']==entry['slot'] and p['flow']['worker']==entry['worker']
             and p['lpi']['incarnation']==entry['incarnation'] and p['flow']['packets']==entry['packets']]
    assert len(matches)==1 and matches[0]['match']['rule']==entry['rule']
    stale=props(directory/(case['label']+'-stale-sni.properties' if pixel else case['label']+'-stale.txt'))
    assert stale.get('code' if pixel else 'sni.code')!='0'
    return entry

def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build=t.base.build_reader.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns']
    assert digest(directory/'runner.py')==run['runner_sha256']
    assert digest(directory/('protocol-peer.py' if pixel else 'socket-peer.py'))==run['peer_sha256']
    assert digest(directory/'fixtures.json')==run['fixtures_sha256']
    fixtures=json.loads((directory/'fixtures.json').read_text())
    configs=configurations(directory,run,pixel)
    if run.get('domain_policy'):domains.build_binding(directory,run,build,props)
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoint[0]['kind']=='ready' and endpoint[0]['port']==40640
    if pixel:
        assert digest(build['apk'])==build['apk_sha256']==(directory/'installed-apk.txt').read_text().split()[0]
        installed={Path(line.split()[1]).name:line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
        assert installed==build['native_sha256']
        lives=run['lifetimes'];assert [l['profile'] for l in lives]==['root','vpn']
    else:
        for name,h in build['artifact_hashes'].items():assert digest(Path(run['artifact'])/name)==h
        assert digest(Path(run['artifact'])/'product-vpp-artifact.properties')==run['manifest_sha256']
        assert 'NFQUEUE' not in (directory/'hooks-after.txt').read_text()
        assert props(directory/'final-stopped.txt')['absent']=='True'
        lives=[dict(profile='root',generation=run['generation'])]
    summary={}
    for life in lives:
        profile=life['profile'];generation=life['generation'];uid=run['uid'] if pixel else 12001
        cases=[c for c in run['cases'] if c.get('profile','root')==profile]
        ports=sorted({c['port'] for c in cases});assert len(ports)==4
        log=directory/(profile+'-before-stop.log' if pixel else 'first-vpp.log');text=log.read_text()
        packets,sessions,totals,_=t.verify_trace(text,profile,generation,ports,configs,uid,observe,
                                               feature_oracle(text,cases,fixtures))
        entries={c['label']:query(directory,c,packets,pixel) for c in cases}
        if run.get('domain_policy'):totals['list_only_winner_changes']=domains.transitions(cases,packets,configs,profile)
        ready=next(c for c in cases if c['mode']=='truncated' and c['phase']=='ready')
        expired=next(c for c in cases if c['mode']=='truncated' and c['phase']=='expired')
        assert entries[ready['label']]['packets']==entries[expired['label']]['packets'],'timeout must not need another packet'
        assert entries[ready['label']]['incarnation']==entries[expired['label']]['incarnation']
        if pixel:
            running=props(directory/(profile+'-running.properties'));stopped=props(directory/(profile+'-stopped.properties'))
            assert running['generation']==str(generation) and running['state']=='running'
            assert running['protectionRunning']==('true' if profile=='root' else 'false')
            assert stopped['state']=='stopped' and stopped['mayBeActive']=='false' and life['process_absent']
        # Independent successful TLS endpoint and application delivery witnesses.
        for mode in ('named','absent'):
            case=next(c for c in cases if c['mode']==mode and c['phase']=='recovered')
            payload=(case['nonce']+':blocked\n').encode().hex()
            receives=[e for e in endpoint if e['kind']=='received' and e['hex']==payload]
            assert len(receives)==1,'one recovered blocked payload must reach the endpoint'
            peer=receives[0]['peer']
            sni=[e for e in endpoint if e['kind']=='sni' and e['peer']==peer]
            assert len(sni)==1 and sni[0]['name']==('example.test' if mode=='named' else None)
            assert any(e['kind']=='handshake' and e['peer']==peer and e['version']=='TLSv1.2' for e in endpoint)
            if profile=='root':assert peer[1]==case['port']
            if pixel:
                blocked=json.loads((directory/(case['client']+'-blocked.json')).read_text())
                recovered=json.loads((directory/(case['client']+'-budget_done.json')).read_text())
                assert blocked['blockedTimeout'] and recovered['echoes']==25 and recovered['nonce']==case['nonce']
            else:
                client=json.loads((directory/(case['client']+'-client.json')).read_text())
                assert client[0]['kind']=='tls_ready' and client[-1]['kind']=='closed'
                timeout=next(e for e in client if e['kind']=='timeout')
                assert receives[0]['time_ns']>timeout['time_ns'],'endpoint received before policy recovery'
                assert any(e['kind']=='received' and e['hex']==payload for e in client)
        for mode in ('malformed','truncated'):
            case=next(c for c in cases if c['mode']==mode)
            assert any(e['kind']=='raw_received' and e['hex']==fixtures[mode+'Hex'] and
                       (profile!='root' or e['peer'][1]==case['port']) for e in endpoint)
        counters=(directory/(profile+'-final.txt' if pixel else 'final-counters.txt')).read_text()
        runtime_rows=records(counters,'flow.runtime ');assert len(runtime_rows)==2
        for _,row in runtime_rows:
            assert int(row['capacity'])==1024 and int(row['entry_bytes'])==(9024 if run.get('domain_policy') else 8888)
            assert int(row['allocated_bytes'])==(9261384 if run.get('domain_policy') else 9122120) and row['capacity_misses']=='0'
        for _,row in records(counters,'policy.cache '):
            assert row['storage_bytes']==('24608' if run.get('domain_policy') else '23584') and row['capacity']=='128'
        # Packet terminal intent and completed native outcome are both required.
        # The five-second parser deadline is not a packet holding window.
        terminal=records(text,'s216 stage=terminal ')
        delays=[]
        for packet in packets:
            _,done=one(terminal,token=packet['token'],generation=generation)
            delay=int(done['mono_ns'])-int(packet['admit']['mono_ns'])
            assert 0<=delay<5_000_000_000,'packet waited for the SNI timeout'
            delays.append(delay)
        totals['maximum_admit_to_terminal_us']=max(delays)/1000
        summary[profile]=totals
    return dict(status='PASS',scope='T13 real TLS names/absence and invalid-prefix unavailability; full winner/API/completion/endpoint joins',
                source_sha256=run['source_sha256'],profiles=summary)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();value=verify(a.directory);text=json.dumps(value,indent=2)+'\n'
    if a.output:a.output.write_text(text)
    print(text,end='')
