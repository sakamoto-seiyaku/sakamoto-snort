#!/usr/bin/env python3
"""Independent R4 evidence reader: exact workload transcripts, full logical
winners, native outcomes, endpoint delivery, source and runtime identity.
No Product detector is used to generate expected protocol facts."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('r2_trace',ROOT/'tests/evidence/verify_t12_lpi.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
base=t.base
records,one,props,digest=t.records,t.one,t.props,t.digest
NAMES={1016:'stun',1017:'rtp',1018:'rtcp',1019:'sip',1020:'dtls'}
PORTS={'stun_udp':3479,'stun_tcp':3480,'rtp_udp':5004,'rtp_tcp':5006,
       'rtcp_udp':5005,'rtcp_tcp':5007,'sip_udp':5060,'sip_tcp':5061,'dtls_udp':4444}
TARGETS={'stun_udp':1016,'stun_tcp':1016,'rtp_udp':1017,'rtp_tcp':1017,
         'rtcp_udp':1018,'rtcp_tcp':1018,'sip_udp':1019,'sip_tcp':1019,'dtls_udp':1020}

def workload(case,fixtures,host):
    """Independent exact known transcripts; no Product or test-peer import."""
    import hashlib
    import struct
    app=case['application'];label=case['nonce']
    assert any(f['application']==app and f['nonce']==label for f in fixtures['sessions'])
    identity=hashlib.sha256(label.encode()).digest()
    def binding(i,reply):
        transaction=hashlib.sha256((label+':'+str(i)).encode()).digest()[:12]
        software=bytes.fromhex('8022')+len(label).to_bytes(2,'big')+label.encode()
        software+=b'\0'*((-len(label))%4)
        # Diagnostic XOR-MAPPED-ADDRESS: family IPv4, port5004, 192.0.2.1.
        if reply:software+=bytes.fromhex('002000080001329ee112a643')
        return (b'\x01\x01' if reply else b'\0\x01')+len(software).to_bytes(2,'big')+bytes.fromhex('2112a442')+transaction+software
    def message(i,reply):
        kind=app.split('_')[0]
        if kind=='stun':return binding(i,reply)
        if kind=='rtp':
            return (
                bytes([128,0])+((1000 if reply else 100)+i).to_bytes(2,'big')+(160*i).to_bytes(4,'big')+
                (identity[4:8] if reply else identity[:4])+bytes([255 if reply else 127])*160)
        if kind=='rtcp':
            if reply:return bytes.fromhex('80c90001')+identity[4:8]
            return bytes.fromhex('80c80006')+identity[:4]+b''.join(x.to_bytes(4,'big') for x in (0xe0000000+i,0,160*i,i+1,160*(i+1)))
        if kind=='sip':
            line='SIP/2.0 200 OK' if reply else 'OPTIONS sip:peer@example.test SIP/2.0'
            return (line+'\r\nVia: SIP/2.0/UDP client.test;branch=z9hG4bK'+label+str(i)+
              '\r\nFrom: <sip:client@example.test>;tag=r4\r\nTo: <sip:peer@example.test>\r\nCall-ID: '+label+
              '\r\nCSeq: '+str(i+1)+' OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n').encode()
        assert kind=='dtls'
        cookie=hashlib.sha256(b'r4-cookie'+identity).digest()[:16]
        if reply:body=bytes.fromhex('fefd10')+cookie;typ=3
        else:
            body=bytes.fromhex('fefd')+identity+b'\0'+(b'\x10'+cookie if i else b'\0')+bytes.fromhex('0002002f0100');typ=1
        handshake=bytes([typ])+len(body).to_bytes(3,'big')+i.to_bytes(2,'big')+bytes(3)+len(body).to_bytes(3,'big')+body
        return bytes.fromhex('16fefd0000')+i.to_bytes(6,'big')+len(handshake).to_bytes(2,'big')+handshake
    def wire(data):
        return len(data).to_bytes(2,'big')+data if app.endswith('tcp') and not app.startswith('sip') else data
    count=3 if app.startswith('rtp_') else 4 if app.startswith('rtcp_') else 1
    sends=[message(i,False) for i in range(count+25)]
    receives=[message(i,True) for i in range(count+25)]
    bootstrap=binding(99,False) if app.startswith(('rtp_','rtcp_')) else None
    bootstrap_reply=binding(99,True) if bootstrap else None
    return dict(sends=sends,receives=receives,wire_sends=[wire(x) for x in sends],
                wire_receives=[wire(x) for x in receives],count=count,
                bootstrap=bootstrap,bootstrap_reply=bootstrap_reply,
                wire_bootstrap=wire(bootstrap) if bootstrap else None,
                wire_bootstrap_reply=wire(bootstrap_reply) if bootstrap else None)

def oracle(run,fixtures,host):
    definitions={c['port']:(c,workload(c,fixtures,host)) for c in run['cases']}
    def observe(session,facts,payload,length,side):
        case,w=definitions[session['source_port']]
        client=facts['sport']==case['port']
        known=w['wire_sends'] if client else w['wire_receives']
        bootstrap=w['wire_bootstrap'] if client else w['wire_bootstrap_reply']
        if length:assert payload in known or payload==bootstrap,('unknown wire message',case['application'],payload.hex())
        if not length or session['stop']:return
        assert len(payload)==length,'complete payload witness required'
        if session['bytes']+length>32768:session['stop']=2;return
        session['attempts']+=1;session['bytes']+=length
        if bootstrap and payload==bootstrap:session['protocols'].add(1016)
        else:
            app=case['application'];target=TARGETS[app]
            if target==1017:
                # Three distinct ordered sample-block indices from one endpoint.
                # This is an exact workload oracle, not a generic RTP detector.
                index=known.index(payload)
                progression=session.setdefault('media_indices',{}).setdefault(side,[])
                if not progression or index>progression[-1]:progression.append(index)
                if len(progression)>=3:session['protocols'].add(1017)
            elif target==1018:
                counts=session.setdefault('reports',{});counts[side]=counts.get(side,0)+1
                if counts[side]>=4:session['protocols'].add(1018)
            else:session['protocols'].add(target)
        if session['attempts']==20:session['stop']=1
        elif session['bytes']==32768:session['stop']=2
    return observe

def flow_query(directory,case,packets):
    text=(directory/case['flow']).read_text()
    entries=[r for _,r in records(text,'flow.entry ') if case['port'] in (int(r['port_a']),int(r['port_b']))]
    media=case['application'].startswith(('rtp_','rtcp_'))
    if case['phase']=='first' and case['protocol']=='udp' and not media:
        assert not entries,'unstarted UDP socket must not invent a Flow'
        return None
    assert len(entries)==1;entry=entries[0]
    _,lpi=one(records(text,'flow.lpi '),worker=entry['worker'],slot=entry['slot'],incarnation=entry['incarnation'])
    expected={1016} if media else set()
    if case['phase']!='first':expected.add(TARGETS[case['application']])
    assert int(lpi['protocols'])==sum(1<<(p-1001) for p in expected) and int(lpi['available'])==bool(expected),'query protocol facts'
    found={int(r['id']):r['key'] for _,r in records(text,'flow.protocol_fact ')
           if r['worker']==entry['worker'] and r['slot']==entry['slot'] and r['incarnation']==entry['incarnation']}
    assert found=={p:NAMES[p] for p in expected},'stable catalog mapping'
    if case['phase']=='budget':assert lpi['attempts']=='20' and lpi['stop']=='1' and lpi['stop_reason']=='packet_budget'
    matching=[p for p in packets if p['lpi']['worker']==entry['worker'] and p['lpi']['incarnation']==entry['incarnation']
              and p['flow']['slot']==entry['slot'] and p['flow']['packets']==entry['packets']]
    assert len(matching)==1;packet=matching[0]
    assert entry['rule']==packet['match']['rule'] and entry['revision']==packet['match']['revision'],'query winner attribution'
    assert all(lpi[k]==packet['lpi'][k] for k in ('available','protocols','attempts','bytes','stop','outcome')),'query prefix'
    return entry

def endpoints(directory,run,pixel,profile,events,packets,fixtures):
    sessions=[s for s in run['sessions'] if s['profile']==profile] if pixel else [s for s in run['cases'] if s['phase']=='budget']
    assert len(sessions)==(1 if pixel else 9)
    host=run['endpoint'] if pixel else '127.0.0.2'
    for session in sessions:
        label=session['nonce'];app=session['application'];w=workload(session,fixtures,host)
        start=session.get('started_ns',run['started_ns']);end=session.get('completed_ns',run['completed_ns'])
        if pixel:
            assert (directory/(session['label']+'-nonce-check.txt')).read_text().strip()=='fresh','probe reused a prior gate/report'
            report=json.loads((directory/(session['label']+'-finished.json')).read_text())
            assert report['nonce']==label and report['uid']==run['uid'] and report['plan']==session['plan'] and not report.get('error')
            assert report['phase']=='finished' and report['blockedTimeout'] and report['echoes']==25
            assert report['bindingResponse'] and report['mediaResponses']==3
        else:
            client=json.loads((directory/(session['client']+'-client.json')).read_text())
            assert client[0]['kind']=='connected' and client[-1]['kind']=='closed'
            end=client[-1]['time_ns'];start=client[0]['time_ns']
            assert len([e for e in client if e['kind']=='timeout'])==1
            assert not any(e['kind']=='client_error' for e in client)
            first=[e for e in client if e['kind']=='first_ready'];assert len(first)==1
            assert first[0]['data']==(w['bootstrap_reply'].hex() if w['bootstrap_reply'] else None)
            added=[e for e in client if e['kind']=='added_ready'];assert len(added)==1
            assert added[0]['data']==[v.hex() for v in w['receives'][:w['count']]]
            received=[e for e in client if e['kind']=='received'];assert [e['count'] for e in received]==[1,24]
            assert [data for e in received for data in e['data']]==[v.hex() for v in w['receives'][w['count']:]],'client recovery delivery'
        window=[e for e in events if start<=e['time_ns']<=end and e.get('application')==app and e.get('nonce')==label]
        assert not any(e['kind']=='error' for e in events),'endpoint protocol failure'
        commands=[e for e in window if e['kind']=='command']
        requests=([w['bootstrap']] if w['bootstrap'] else [])+w['sends']
        responses=([w['bootstrap_reply']] if w['bootstrap'] else [])+w['receives']
        assert [e['data'] for e in commands]==[data.hex() for data in requests],'endpoint requests missing/changed'
        assert len({e['time_ns'] for e in commands})==len(commands),'duplicated endpoint witnesses'
        peers={tuple(e['peer']) for e in commands};assert len(peers)==1,'endpoint peer binding'
        peer=next(iter(peers));replies=[e for e in window if e['kind']=='reply']
        assert len(replies)==len(responses) and [e['data'] for e in replies]==[data.hex() for data in responses],'endpoint response missing/changed'
        assert all(tuple(e['peer'])==peer for e in window if 'peer' in e),'endpoint dialogue peer'
        assert all(a['time_ns']<=b['time_ns'] for a,b in zip(commands,replies)),'endpoint causal response'
        if profile=='root':assert peer[1]==session['port']
        observed=[p for p in packets if session['port'] in (p['facts']['sport'],p['facts']['dport'])]
        assert observed and any(p['expected']['actual_action']==2 for p in observed),'actual rule drops absent'
        for value in w['wire_sends']+w['wire_receives']+([w['wire_bootstrap'],w['wire_bootstrap_reply']] if w['bootstrap'] else []):
            assert any(p['payload']==value for p in observed),'wire endpoint delivery witness absent'

def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build=base.build_reader.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns']
    assert digest(directory/'runner.py')==run['runner_sha256']
    assert digest(directory/('protocol-peer.py' if pixel else 'socket-peer.py'))==run['peer_sha256']
    assert digest(directory/'fixtures.json')==run['fixtures_sha256']
    fixtures=json.loads((directory/'fixtures.json').read_text())
    observe=oracle(run,fixtures,run['endpoint'] if pixel else '127.0.0.2')
    configurations=t.configs(directory,run,pixel)
    # Required *distinct* workloads, never a raw case-count coverage claim.
    profiles=('root','vpn') if pixel else ('root',)
    required={'rtp_udp'} if pixel else set(PORTS)
    assert all(case.get('profile','root') in profiles for case in run['cases'])
    for profile in profiles:
        grouped={}
        for case in run['cases']:
            if case.get('profile','root')!=profile:continue
            grouped.setdefault(case['client'],[]).append(case)
        assert len(grouped)==len(required),'missing or duplicate workload session'
        assert {values[0]['application'] for values in grouped.values()}==required,'required protocol workloads absent'
        assert len({values[0]['port'] for values in grouped.values()})==len(required),'workload flow port reused'
        assert len({values[0]['nonce'] for values in grouped.values()})==len(required),'workload nonce reused'
        for values in grouped.values():
            assert [v['phase'] for v in values]==['first','added','blocked','budget'],'workload phase closure'
            assert len({(v['application'],v['port'],v['nonce'],v['generation']) for v in values})==1,'workload identity drift'
        if pixel:
            sessions=[s for s in run['sessions'] if s['profile']==profile]
            assert len(sessions)==1
            for values in grouped.values():
                case=values[0];session=next(s for s in sessions if s['label']==case['client'])
                assert (case['client'],case['port'],case['nonce'],case['generation'],case['application'])==(session['label'],session['port'],session['nonce'],session['generation'],session['application']),'app and graph session binding'
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoint[0]['kind']=='ready'
    assert endpoint[0]['ports']==({key:PORTS[key] for key in ('rtp_udp',)} if pixel else PORTS)
    if pixel:
        assert digest(build['apk'])==build['apk_sha256']==(directory/'installed-apk.txt').read_text().split()[0]
        installed={Path(line.split()[1]).name:line.split()[0] for line in (directory/'installed-native.txt').read_text().splitlines()}
        assert installed==build['native_sha256']
        lifetimes=run['lifetimes'];assert [l['profile'] for l in lifetimes]==['root','vpn']
    else:
        for name,h in build['artifact_hashes'].items():assert digest(Path(run['artifact'])/name)==h
        assert digest(Path(run['artifact'])/'product-vpp-artifact.properties')==run['manifest_sha256']
        assert 'NFQUEUE' not in (directory/'hooks-after.txt').read_text()
        assert props(directory/'final-stopped.txt')['absent']=='True'
        lifetimes=[dict(profile='root',generation=run['generation'])]
    summary={}
    for life in lifetimes:
        profile=life['profile'];generation=life['generation'];uid=run['uid'] if pixel else 12001
        if pixel:
            running=props(directory/(profile+'-running.properties'));stopped=props(directory/(profile+'-stopped.properties'))
            assert running['generation']==str(generation) and running['profile']==profile and running['state']=='running'
            assert running['protectionRunning']==('true' if profile=='root' else 'false')
            assert stopped['state']=='stopped' and stopped['mayBeActive']==stopped['protectionRunning']=='false' and life['process_absent']
            assert not (directory/(profile+'-queues-after.txt')).read_text().strip()
            assert 'SAKAMOTO' not in (directory/(profile+'-hooks-after.txt')).read_text()
            trace=(directory/(profile+'-stop.log')).read_text()
            if profile=='root':
                zeros=[r for _,r in records(trace,'s242 event=stop_native_zero ')];assert zeros
                assert all(zeros[-1][k]=='0' for k in ('pending','buffers','obligations','handoffs','completion_frames'))
            else:
                owners=[r for _,r in records(trace,'s237 event=owner_stopped ')];assert len(owners)==2
                for row in owners:
                    assert all(row[k]=='0' for k in ('sessions','inputs','pbufs','buffers','obligations','frames'))
                    assert row['sockets_created']==row['sockets_closed'] and row['timer_fd']==row['broker_fd']=='-1'
        else:trace=(directory/'first-vpp.log').read_text()
        cases=[c for c in run['cases'] if c.get('profile','root')==profile]
        ports=sorted({c['port'] for c in cases})
        packets,sessions,summary[profile],history=t.verify_trace(trace,profile,generation,ports,configurations,uid,observe)
        endpoints(directory,run,pixel,profile,endpoint,packets,fixtures)
        resources=records((directory/(profile+'-final.txt' if pixel else 'final-counters.txt')).read_text(),'flow.runtime ')
        assert len(resources)==2 and {r['worker'] for _,r in resources}=={'0','1'}
        for _,row in resources:
            assert int(row['entry_bytes'])==392 and int(row['capacity'])==1024
            assert int(row['allocated_bytes'])==422216 and int(row['capacity_misses'])==0
            assert 0<=int(row['high_watermark'])<=1024
        summary[profile]['flow_resources']=[row for _,row in resources]
        counters=records((directory/(profile+'-final.txt' if pixel else 'final-counters.txt')).read_text(),'policy.cache ')
        assert len(counters)==2 and {r['worker'] for _,r in counters}=={'0','1'}
        for _,row in counters:
            assert int(row['capacity'])==128 and int(row['storage_bytes'])==23584
            assert (int(row['hits']),int(row['misses'])) in (history[row['worker']] or [(0,0)])
            assert 0<=int(row['occupied'])<=128 and int(row['replacements'])==int(row['misses'])-int(row['occupied'])
        groups={}
        for case in cases:
            entry=flow_query(directory,case,packets)
            base.query_observation(props(directory/case['query']),pixel,trace)
            groups.setdefault(case['client'],[]).append((entry,case))
        for values in groups.values():
            assert [c['phase'] for _,c in values]==['first','added','blocked','budget']
            assert len({(e['worker'],e['slot'],e['incarnation']) for e,_ in values if e})==1
            attempts=[int(one(records((directory/c['flow']).read_text(),'flow.lpi '),worker=e['worker'],slot=e['slot'],incarnation=e['incarnation'])[1]['attempts']) for e,c in values if e]
            assert attempts==sorted(attempts) and attempts[-1]==20
            session=next(s for s in sessions.values() if s['source_port']==values[0][1]['port'])
            assert session['drops']>0
    return dict(status='PASS',source_sha256=run['source_sha256'],profiles=summary,
      scope='STUN binding to PCMU RTP on Root/controlled VPN' if pixel else 'STUN binding, RTP PCMU, RTCP reports, SIP OPTIONS and DTLS cookie messages; no complete DTLS handshake',
      verifier_sha256=digest(__file__))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    result=verify(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
