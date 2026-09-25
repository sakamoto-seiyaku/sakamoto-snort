#!/usr/bin/env python3
"""Independent R2 source/wire/session/query/action verifier.

This oracle knows the exact test dialogues, not the Product detector algorithm.
A literal cleartext banner identifies its known workload; explicit AUTH/234 and
an independently framed TLS ClientHello must occur before FTPS is expected.
Successful peer TLS and complete endpoint request/response joins are mandatory.
"""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('r2_trace',ROOT/'tests/evidence/verify_t12_lpi.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
base=t.base
records,one,props,digest=t.records,t.one,t.props,t.digest
NAMES={1003:'tls',1007:'smtp',1008:'ftp-control',1009:'ftp-data',1010:'ftps'}
SMTP=b'220 mail.example.test ESMTP R2 ready\r\n'
FTP=b'220 file.example.test FTPd R2 ready\r\n'


def observe(session,facts,payload,length,side):
    if not length or session['stop']:return
    if session['bytes']+length>32768:session['stop']=2;return
    session['attempts']+=1;session['bytes']+=length
    assert facts['protocol']==6
    if payload==SMTP:session['protocols'].add(1007)
    if payload==FTP:session['protocols'].add(1008)
    if payload==b'AUTH TLS\r\n':session['auth_side']=side
    if payload==b'234 Ready for TLS\r\n':
        assert session.get('auth_side') in (1,2) and side!=session['auth_side']
        session['upgrade']=True
    # Workload's OpenSSL/Conscrypt ClientHello/ServerHello record, independently
    # checked against wire lengths. No call to Product or LPI generates facts.
    if len(payload)>=9 and payload[:3] in (b'\x16\x03\x01',b'\x16\x03\x03') and payload[5] in (1,2):
        record=int.from_bytes(payload[3:5],'big');hello=int.from_bytes(payload[6:9],'big')
        assert 4<=record<=length-5 and 0<=hello<=record-4
        if 990 in (facts['sport'],facts['dport']):session['protocols'].update((1003,1010))
        elif session.get('upgrade') and side==session['auth_side']:
            session['protocols'].update((1003,1010))
    if 20 in (facts['sport'],facts['dport']):
        assert payload.startswith(b'R2-file:'),'unexpected FTP data payload'
        session['protocols'].add(1009)
    if session['attempts']==20:session['stop']=1
    elif session['bytes']==32768:session['stop']=2


def flow_query(directory,case,packets):
    text=(directory/case['flow']).read_text()
    entries=[r for _,r in records(text,'flow.entry ') if case['port'] in (int(r['port_a']),int(r['port_b']))]
    assert len(entries)==1;entry=entries[0]
    _,lpi=one(records(text,'flow.lpi '),worker=entry['worker'],slot=entry['slot'],incarnation=entry['incarnation'])
    application=case['application'];first=case['phase']=='first'
    expected={'smtp':{1007},'ftp':{1008},'explicit':{1008} if first else {1003,1008,1010},
              'implicit':set() if first else {1003,1010},'data':set() if first else {1009}}[application]
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


def endpoints(directory,run,pixel,profile,events,packets):
    sessions=[s for s in run['sessions'] if s['profile']==profile] if pixel else [s for s in run['cases'] if s['phase']=='budget']
    assert len(sessions)==(1 if pixel else 5)
    for session in sessions:
        nonce=session['nonce'];application='explicit' if pixel else session['application']
        start=int(nonce.rsplit('-',1)[1]);end=session.get('completed_ns',run['completed_ns'])
        if pixel:
            report=json.loads((directory/(session['label']+'-finished.json')).read_text())
            assert report['nonce']==nonce and report['uid']==run['uid'] and report['plan']==session['plan'] and not report.get('error')
            assert report['phase']=='finished' and report['blockedTimeout'] and report['echoes']==25
            assert report['ftpBanner']==FTP.decode() and report['ftpUpgrade']=='234 Ready for TLS\r\n'
            assert report['tlsProtocol']=='TLSv1.2' and report['cipher']
            arguments=[nonce+':blocked']+[nonce+':'+str(i) for i in range(24)]
        else:
            client=json.loads((directory/(session['client']+'-client.json')).read_text())
            assert client[0]['kind']=='connected' and client[-1]['kind']=='closed'
            end=client[-1]['time_ns']
            assert len([e for e in client if e['kind']=='timeout'])==1
            assert not any(e['kind']=='client_error' for e in client)
            assert len([e for e in client if e['kind']=='first_ready'])==1
            assert len([e for e in client if e['kind']=='added_ready'])==1
            received=[e for e in client if e['kind']=='received']
            assert [e['count'] for e in received]==[1,24],'client recovery delivery'
            arguments=[nonce+':'+str(i) for i in range(25)]
        window=[e for e in events if start<=e['time_ns']<=end and e.get('application')==application]
        requests=[('NOOP '+arg+'\r\n').encode().hex() for arg in arguments]
        replies=[(('250 ' if application=='smtp' else '200 ')+arg+'\r\n').encode().hex() for arg in arguments]
        commands=[e for e in window if e['kind']=='command' and e['data'] in requests]
        assert len(commands)==25 and sorted(e['data'] for e in commands)==sorted(requests),'endpoint requests missing/changed'
        peers={tuple(e['peer']) for e in commands};assert len(peers)==1,'endpoint peer binding'
        peer=next(iter(peers))
        peer_events=[e for e in window if tuple(e.get('peer',()))==peer]
        responses=[e for e in peer_events if e['kind']=='reply' and e['data'] in replies]
        assert len(responses)==25 and sorted(e['data'] for e in responses)==sorted(replies),'endpoint response missing/changed'
        # Reject a dialogue witness with an unrelated/missing peer, including
        # setup commands before the nonce-bearing NOOP recovery messages.
        assert all(tuple(e.get('peer',()))==peer for e in window if e['kind'] in ('connect','command','reply','tls_handshake','close')), 'endpoint dialogue peer'
        # The beginning and successful protocol setup belong to that same socket.
        assert len([e for e in peer_events if e['kind']=='connect'])==1
        banner=SMTP if application=='smtp' else FTP
        assert any(e['kind']=='reply' and e['data']==banner.hex() for e in peer_events),'endpoint banner'
        if not pixel:
            greeting=(b'EHLO ' if application=='smtp' else b'USER ')+nonce.encode()+b'\r\n'
            greeting_reply=(b'250 ' if application=='smtp' else b'331 ')+nonce.encode()+b'\r\n'
            assert any(e['kind']=='command' and e['data']==greeting.hex() for e in peer_events),'endpoint greeting command'
            assert any(e['kind']=='reply' and e['data']==greeting_reply.hex() for e in peer_events),'endpoint greeting reply'
        if application in ('explicit','implicit'):
            assert len([e for e in peer_events if e['kind']=='tls_handshake' and e['version']=='TLSv1.2'])==1,'TLS endpoint handshake'
            if application=='explicit':
                assert any(e['kind']=='command' and e['data']==b'AUTH TLS\r\n'.hex() for e in peer_events)
                assert any(e['kind']=='reply' and e['data']==b'234 Ready for TLS\r\n'.hex() for e in peer_events)
        if not pixel:
            expected=[]
            if application=='data':
                chunks=[e for e in window if e['kind']=='file_chunk' and e['nonce']==nonce]
                assert [e['index'] for e in chunks]==list(range(26)),'complete RETR chunks'
                for i,e in enumerate(chunks):
                    assert e['data']==('R2-file:'+nonce+':'+str(i)+'\r\n').encode().hex()
                    assert tuple(e['control_peer'])==peer and tuple(e['peer'])==tuple(client[0]['local'])
                assert any(e['kind']=='command' and e['data']==('RETR '+nonce+'\r\n').encode().hex() for e in peer_events),'RETR missing'
                expected=[e['data'] for e in chunks[1:]]
                assert client[0]['peer'][1]==20
            else:
                assert tuple(client[0]['local'])==peer
                expected=replies
                if application not in ('implicit',):
                    assert next(e for e in client if e['kind']=='first_ready')['data']==(SMTP if application=='smtp' else FTP).hex()
            assert [h for e in received for h in e['data']]==expected,'client received bytes'
        observed=[p for p in packets if session['port'] in (p['facts']['sport'],p['facts']['dport'])]
        assert observed and any(p['expected']['actual_action']==2 for p in observed),'real policy drops'
        if application in ('smtp','ftp','explicit'):
            assert any(p['payload']==(SMTP if application=='smtp' else FTP) for p in observed),'wire banner'
        if application=='explicit':
            assert any(p['payload']==b'AUTH TLS\r\n' for p in observed)
            assert any(p['payload']==b'234 Ready for TLS\r\n' for p in observed)
        if application in ('smtp','ftp','data'):
            # Cleartext endpoint bytes bind the classified wire flow directly.
            assert any(nonce.encode() in p['payload'] for p in observed),'wire endpoint nonce'
        if profile=='root' and application!='data':assert peer[1]==session['port']


def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build=base.build_reader.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns']
    assert digest(directory/'runner.py')==run['runner_sha256']
    assert digest(directory/('protocol-peer.py' if pixel else 'socket-peer.py'))==run['peer_sha256']
    assert digest(directory/'fixtures.json')==run['fixtures_sha256']
    configurations=t.configs(directory,run,pixel)
    # Required *distinct* workloads, never a raw case-count coverage claim.
    profiles=('root','vpn') if pixel else ('root',)
    required={'explicit'} if pixel else {'smtp','ftp','explicit','implicit','data'}
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
            case=next(iter(grouped.values()))[0];session=sessions[0]
            assert (case['client'],case['port'],case['nonce'],case['generation'])==(session['label'],session['port'],session['nonce'],session['generation']),'app and graph session binding'
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoint[0]['kind']=='ready'
    assert endpoint[0]['ports']==({'explicit':40612} if pixel else {'smtp':2525,'ftp':2121,'explicit':40612,'implicit':990,'data':40613})
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
        endpoints(directory,run,pixel,profile,endpoint,packets)
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
            assert len({(e['worker'],e['slot'],e['incarnation']) for e,_ in values})==1
            attempts=[int(one(records((directory/c['flow']).read_text(),'flow.lpi '),worker=e['worker'],slot=e['slot'],incarnation=e['incarnation'])[1]['attempts']) for e,c in values]
            assert attempts==sorted(attempts) and attempts[-1]==20
            session=next(s for s in sessions.values() if s['source_port']==values[0][1]['port'])
            assert session['drops']>0
    return dict(status='PASS',source_sha256=run['source_sha256'],profiles=summary,
      scope='FTP AUTH TLS1.2 on Root and controlled VPN' if pixel else 'SMTP, FTP control, TCP20 paced PASV RETR, explicit AUTH TLS1.2, implicit990 TLS1.2',
      verifier_sha256=digest(__file__))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    result=verify(a.directory)
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
