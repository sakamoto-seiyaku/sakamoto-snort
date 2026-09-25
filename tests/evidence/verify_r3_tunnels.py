#!/usr/bin/env python3
"""Independent R3 evidence reader: exact workload transcripts, full logical
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
NAMES={1011:'openvpn',1012:'wireguard',1013:'socks4',1014:'socks5',1015:'rdp'}
PORTS={'openvpn_udp':1195,'openvpn_tcp':1196,'wireguard':51821,'socks4':1084,'socks5':1085,'rdp_tcp':3390,'rdp_udp':3389}
TARGETS={'openvpn_udp':1011,'openvpn_tcp':1011,'wireguard':1012,'socks4':1013,'socks5':1014,'rdp_tcp':1015,'rdp_udp':1015}

def workload(case,fixtures,host):
    """Exact independent test dialogue, not general detection or provider output."""
    import hashlib
    import socket
    import struct
    app=case['application'];label=case['nonce'];index=hashlib.sha256(label.encode()).digest()[:8]
    if app=='wireguard':
        f=next(f for f in fixtures['wireguard'] if f['label']==label)
        return dict(request=bytes.fromhex(f['initial']),reply=bytes.fromhex(f['response']),
          sends=[bytes.fromhex(pair['request']) for pair in f['pairs']],
          receives=[bytes.fromhex(pair['reply']) for pair in f['pairs']],fixture=f)
    if app.startswith('openvpn'):
        request=bytes([56])+index+bytes(5)
        reply=bytes([64])+hashlib.sha256(index).digest()[:8]+bytes([1])+bytes(4)+index+bytes(4)
        if app.endswith('tcp'):request=struct.pack('!H',14)+request;reply=struct.pack('!H',26)+reply
        return dict(request=request,reply=reply,sends=[request]*26,receives=[reply]*26)
    if app=='rdp_udp':
        request=bytes.fromhex('ffffffff00400001')+index[:4]+bytes.fromhex('04b004b0')
        reply=index[:4]+bytes.fromhex('00400003')+hashlib.sha256(request).digest()[:4]+bytes.fromhex('04b004b0')
        return dict(request=request,reply=reply,sends=[request]*26,receives=[reply]*26)
    if app=='rdp_tcp':
        sends=[]
        for i in range(26):
            cookie=('Cookie: mstshash='+label+':'+str(i)+'\r\n').encode()
            n=19+len(cookie)
            sends.append(bytes([3,0])+n.to_bytes(2,'big')+bytes([n-5])+bytes.fromhex('e00000000000')+cookie+bytes.fromhex('0100080001000000'))
        reply=bytes.fromhex('030000130ed000001234000200080001000000')
        return dict(request=sends[0],reply=reply,sends=sends,receives=[reply]*26)
    target=socket.inet_aton(host)+struct.pack('!H',40619)
    messages=[(label+':'+str(i)+'\n').encode() for i in range(26)]
    if app=='socks4':
        request=b'\x04\x01'+target[4:]+target[:4]+label.encode()+b'\0'
        reply=b'\0\x5a'+target[4:]+target[:4]
        return dict(request=request,reply=reply,sends=messages,receives=messages)
    assert app=='socks5'
    return dict(request=b'\x05\x02\0\x80',reply=b'\x05\0',sends=messages,receives=messages,
                connect_request=b'\x05\x01\0\x01'+target,connect_reply=b'\x05\0\0\x01'+target)

def oracle(run,fixtures,host):
    definitions={c['port']:(c,workload(c,fixtures,host)) for c in run['cases']}
    def observe(session,facts,payload,length,side):
        case,w=definitions[session['source_port']]
        if length:
            client=facts['sport']==case['port']
            allowed=[w['request'],*w['sends']]+([w['connect_request']] if 'connect_request' in w else []) if client else [w['reply'],*w['receives']]+([w['connect_reply']] if 'connect_reply' in w else [])
            assert payload in allowed and len(payload)==length,('unexpected wire workload',case['application'],payload.hex())
        if not length or session['stop']:return
        if session['bytes']+length>32768:session['stop']=2;return
        session['attempts']+=1;session['bytes']+=length
        if client and payload==w['request']:session['request_seen']=side
        if not client and payload==w['reply']:
            assert session.get('request_seen')==1 and side==2,'known dialogue lacks request/opposite reply'
            session['protocols'].add(TARGETS[case['application']])
        if session['attempts']==20:session['stop']=1
        elif session['bytes']==32768:session['stop']=2
    return observe

def flow_query(directory,case,packets):
    text=(directory/case['flow']).read_text()
    entries=[r for _,r in records(text,'flow.entry ') if case['port'] in (int(r['port_a']),int(r['port_b']))]
    if case['phase']=='first' and case['protocol']=='udp':
        assert not entries,'unstarted UDP socket must not invent a Flow'
        return None
    assert len(entries)==1;entry=entries[0]
    _,lpi=one(records(text,'flow.lpi '),worker=entry['worker'],slot=entry['slot'],incarnation=entry['incarnation'])
    expected=set() if case['phase']=='first' else {TARGETS[case['application']]}
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
    assert len(sessions)==(2 if pixel else 7)
    host=run['endpoint'] if pixel else '127.0.0.2'
    for session in sessions:
        label=session['nonce'];app=session['application'];w=workload(session,fixtures,host)
        start=session.get('started_ns',run['started_ns']);end=session.get('completed_ns',run['completed_ns'])
        if pixel:
            assert (directory/(session['label']+'-nonce-check.txt')).read_text().strip()=='fresh','probe reused a prior gate/report'
            report=json.loads((directory/(session['label']+'-finished.json')).read_text())
            assert report['nonce']==label and report['uid']==run['uid'] and report['plan']==session['plan'] and not report.get('error')
            assert report['phase']=='finished' and report['blockedTimeout'] and report['echoes']==25
            assert report['proxyConnected'] if app=='socks5' else report['handshakeResponse']
        else:
            client=json.loads((directory/(session['client']+'-client.json')).read_text())
            assert client[0]['kind']=='connected' and client[-1]['kind']=='closed'
            end=client[-1]['time_ns'];start=client[0]['time_ns']
            assert len([e for e in client if e['kind']=='timeout'])==1
            assert not any(e['kind']=='client_error' for e in client)
            assert len([e for e in client if e['kind']=='first_ready'])==1
            added=[e for e in client if e['kind']=='added_ready'];assert len(added)==1 and added[0]['data']==w['receives'][0].hex()
            received=[e for e in client if e['kind']=='received'];assert [e['count'] for e in received]==[1,24]
            assert [data for e in received for data in e['data']]==[data.hex() for data in w['receives'][1:]],'client recovery delivery'
        window=[e for e in events if start<=e['time_ns']<=end and e.get('application')==app]
        assert not any(e['kind']=='error' for e in window),'endpoint protocol failure'
        commands=[e for e in window if e['kind']=='command']
        requests=[w['request'],*w['sends']] if app=='wireguard' else w['sends']
        responses=[w['reply'],*w['receives']] if app=='wireguard' else w['receives']
        assert [e['data'] for e in commands]==[data.hex()[4:] if app=='openvpn_tcp' else data.hex() for data in requests],'endpoint requests missing/changed'
        assert len({e['time_ns'] for e in commands})==len(commands),'duplicated endpoint witnesses'
        peers={tuple(e['peer']) for e in commands};assert len(peers)==1,'endpoint peer binding'
        peer=next(iter(peers));replies=[e for e in window if e['kind']=='reply']
        assert len(replies)==len(responses) and [e['data'] for e in replies]==[data.hex() for data in responses],'endpoint response missing/changed'
        assert all(tuple(e['peer'])==peer for e in window if 'peer' in e),'endpoint dialogue peer'
        assert all(a['time_ns']<=b['time_ns'] for a,b in zip(commands,replies)),'endpoint causal response'
        if profile=='root':assert peer[1]==session['port']
        observed=[p for p in packets if session['port'] in (p['facts']['sport'],p['facts']['dport'])]
        assert observed and any(p['expected']['actual_action']==2 for p in observed),'actual rule drops absent'
        for value in (w['request'],w['reply']):assert any(p['payload']==value for p in observed),'wire negotiation witness absent'
        for value in w['sends']+w['receives']:assert any(p['payload']==value for p in observed),'wire endpoint delivery witness absent'
        if app.startswith('socks'):
            for kind,key in [('negotiation_request','request'),('negotiation_reply','reply')]+([('connect_request','connect_request'),('connect_reply','connect_reply')] if app=='socks5' else []):
                rows=[e for e in window if e['kind']==kind];assert len(rows)==1 and rows[0]['data']==w[key].hex(),'proxy negotiation witness'
            relays=[e for e in window if e['kind']=='proxy_connected'];assert len(relays)==1
            assert relays[0]['target']==[host,40619]
            target_peer=tuple(relays[0]['relay'])
            for kind,expected in [('target_received',w['sends']),('target_sent',w['receives'])]:
                target=[e for e in events if start<=e['time_ns']<=end and e['kind']==kind and tuple(e['peer'])==target_peer]
                assert [e['data'] for e in target]==[value.hex() for value in expected],'actual proxy target delivery'
        if app=='wireguard':
            handshakes=[e for e in window if e['kind']=='authenticated_handshake'];assert len(handshakes)==1 and handshakes[0]['label']==label
            inner=[e for e in window if e['kind']=='inner_icmp']
            assert [e['text'] for e in inner]==[label+':'+str(i) for i in range(26)],'authenticated inner ICMP delivery'
            # Re-check cryptographic authenticity from the recorded fixture and
            # endpoint bytes. This is a test endpoint, never a Product detector.
            import sys
            sys.path.insert(0,str(ROOT/'tests/device/helpers'))
            import r3_wireguard as wg
            f=w['fixture'];peer_crypto=wg.Responder(bytes.fromhex(f['server_private']),bytes.fromhex(f['client_public']),
                bytes.fromhex(f['responder_ephemeral']),f['server_index'])
            assert peer_crypto.initiation(w['request'])==w['reply']
            for i,request in enumerate(w['sends']):
                text,response=peer_crypto.data(request)
                assert text==label+':'+str(i) and response==w['receives'][i]

def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build=base.build_reader.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns']
    assert digest(directory/'runner.py')==run['runner_sha256']
    assert digest(directory/('protocol-peer.py' if pixel else 'socket-peer.py'))==run['peer_sha256']
    assert digest(directory/'fixtures.json')==run['fixtures_sha256']
    assert digest(directory/'wireguard-peer.py')==run['crypto_peer_sha256']
    fixtures=json.loads((directory/'fixtures.json').read_text())
    observe=oracle(run,fixtures,run['endpoint'] if pixel else '127.0.0.2')
    configurations=t.configs(directory,run,pixel)
    # Required *distinct* workloads, never a raw case-count coverage claim.
    profiles=('root','vpn') if pixel else ('root',)
    required={'socks5','wireguard'} if pixel else set(PORTS)
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
            assert len(sessions)==2
            for values in grouped.values():
                case=values[0];session=next(s for s in sessions if s['label']==case['client'])
                assert (case['client'],case['port'],case['nonce'],case['generation'],case['application'])==(session['label'],session['port'],session['nonce'],session['generation'],session['application']),'app and graph session binding'
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoint[0]['kind']=='ready'
    assert endpoint[0]['ports']==({key:PORTS[key] for key in ('socks5','wireguard')} if pixel else PORTS)
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
            assert int(row['entry_bytes'])==360 and int(row['capacity'])==1024
            assert int(row['allocated_bytes'])==389448 and int(row['capacity_misses'])==0
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
      scope='SOCKS5 actual CONNECT relay and WireGuard authenticated exchange on Root/controlledVPN' if pixel else 'SOCKS4/5 actual CONNECT relay; WireGuard authenticated exchange; OpenVPN TCP/UDP reset and RDP TCP/UDP negotiation fragments',
      verifier_sha256=digest(__file__))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    result=verify(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
