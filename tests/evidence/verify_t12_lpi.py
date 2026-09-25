#!/usr/bin/env python3
"""Independent T12 wire/source/Flow/cache/winner/completion evidence reader.

The protocol oracle is deliberately limited to this recorded HTTP→TLS and
DNS→QUIC workload. It uses wire signatures plus successful peer protocol
handshakes, not libprotoident or compiled Product plans. It is not a general
alternative detector or a claim about arbitrary protocol recognition accuracy.
"""
import argparse
from collections import defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
base=module('t12_base',ROOT/'tests/evidence/verify_t07_ct.py')
source=base.source_reader
reference=base.reference
records,one,props,digest=base.records,base.one,base.props,base.digest

def logical_rules(config,uid):
    rules=source.logical_rules(config,uid)
    # Native management source assigns its one rule-match reason, independently
    # of the synthetic reason IDs used by the Host reference adapter.
    for rule in rules:rule['reason']=1
    return rules

def configs(directory,run,pixel):
    answer={}
    for value in run['configurations']:
        path=directory/value['source'];config=source.source(path)
        source.query_source(config,props(directory/value['query']),pixel)
        assert config['revision']==value['revision']
        raw=bytes([15])+value['target'].to_bytes(4,'little')
        assert config['rules'][0]['expression']==raw and config['rules'][1]['expression']==raw+b'\x03'
        assert [r['priority'] for r in config['rules']]==[10,20,100]
        assert [r['action'] for r in config['rules']]==[2,2,1]
        assert all(r['protocol']==value['protocol'] for r in config['rules'])
        effective=sorted(logical_rules(config,run['uid'] if pixel else 12001),key=lambda r:r['priority'])
        assert [r['mode'] for r in effective]==[value['mode'],1,0]
        answer[(value.get('profile','root'),value['revision'])]=(config,source.snapshot_hash(path))
    return answer

def protocol_observation(session,facts,payload,length,side):
    if not length or session['stop']:return
    if session['bytes']+length>32768:
        session['stop']=2;return
    session['attempts']+=1;session['bytes']+=length
    if facts['protocol']==6:
        if payload.startswith((b'GET ',b'HTTP')):session['protocols'].add(1002)
        # Both sides of this actual TLS 1.2 handshake have valid record headers.
        # The oracle never infers TLS from HTTP, port number or a category.
        if len(payload)>=5 and payload[0] in (20,21,22,23) and payload[1:3] in (b'\x03\x01',b'\x03\x03'):
            record=int.from_bytes(payload[3:5],'big')
            if 0<record<=18432:session['tls_sides'].add(side)
        if session['tls_sides']=={1,2}:session['protocols'].add(1003)
    else:
        if 53 in (facts['sport'],facts['dport']) and len(payload)>=12 and payload[:2]==b'\x12\x0c' and payload[2:4] in (b'\x01\x00',b'\x81\x80'):
            session['protocols'].add(1001)
        # Workload-specific RFC6762 literals, independently hand encoded.
        query=bytes.fromhex('000000000001000000000000076578616d706c65056c6f63616c0000010001')
        reply=bytes.fromhex('000084000001000100000000076578616d706c65056c6f63616c0000010001c00c00018001000000780004c0000201')
        if 5353 in (facts['sport'],facts['dport']) and payload in (query,reply):
            session['protocols'].add(1006)
        if length>=1200 and len(payload)>=5 and payload[0]&0xf0==0xc0 and payload[1:5]==b'\0\0\0\1':
            session['protocols'].add(1004)
    if session['attempts']==20:session['stop']=1
    elif session['bytes']==32768:session['stop']=2

def verify_trace(text,profile,generation,ports,configurations,uid):
    prefixes={'acquire':'s209 event=acquire ','release':'s209 event=release ',
      'match':'s209 event=l4 ','flow':'s208 event=observe ','tcp':'s222 event=tcp_update ',
      'udp':'s223 event=udp_update ','lpi':'t12 event=lpi ','cache':'t11 event=cache ',
      'free':'s203 event=buffer_free ','verdict':'s242 event=verdict_syscall ',
      'completion':'s213 event=completion ','copy':'s237 event=input_copy '}
    rows={key:records(text,prefix) for key,prefix in prefixes.items()}
    counter_history=defaultdict(list)
    for _,query in rows['cache']:
        _,acquire=one(rows['acquire'],token=query['token'],generation=query['generation'])
        worker=acquire['worker'];previous=counter_history[worker][-1] if counter_history[worker] else (0,0)
        assert query['hit'] in ('0','1') and query['status']=='0'
        counts=(int(query['hits']),int(query['misses']))
        assert counts==(previous[0]+int(query['hit']=='1'),previous[1]+int(query['hit']=='0')),'owner cache counter progression'
        counter_history[worker].append(counts)
    selected=[]
    for _,admit in records(text,'s216 stage=admit '):
        if int(admit.get('protocol',0)) not in (6,17):continue
        facts,flags,payload=base.packet(admit)
        if not ({facts['sport'],facts['dport']}&set(ports)):continue
        assert int(admit['generation'])==generation
        token=admit['token'];events={};indices={}
        for name in ('acquire','release','match','flow','lpi','tcp' if facts['protocol']==6 else 'udp'):
            indices[name],events[name]=one(rows[name],token=token,generation=generation)
        tracker=events['tcp' if facts['protocol']==6 else 'udp']
        flow,match,lpi=events['flow'],events['match'],events['lpi']
        assert indices['acquire']<indices['lpi']<indices['flow']<indices['match']<indices['release']
        assert flow['worker']==admit['owner']==events['acquire']['worker']==lpi['worker']
        assert flow['pool_worker']==flow['worker'] and int(flow['thread'])==int(flow['worker'])+1
        assert tracker['incarnation']==lpi['incarnation'] and flow['slot']==lpi['slot']
        identity=tuple(events['acquire'][key] for key in ('generation','revision','snapshot_hash'))
        for name in ('flow','match','release'):
            assert tuple(events[name][key] for key in ('generation','revision','snapshot_hash'))==identity,'single packet snapshot'
        assert tuple(events['release']['content_'+key] for key in ('generation','revision','hash'))==identity
        config,expected_hash=configurations[(profile,int(match['revision']))]
        assert int(match['snapshot_hash'])==expected_hash,'saved source identity'
        assert flow['status']==match['status']==lpi['status']=='0'
        selected.append(dict(admit=admit,facts=facts,flags=flags,payload=payload,token=token,
          flow=flow,match=match,lpi=lpi,tracker=tracker,config=config,indices=indices,identity=identity))
    assert selected,'real packet trace absent'
    sessions={};totals=defaultdict(int);past_guards={}
    for value in sorted(selected,key=lambda p:p['indices']['lpi']):
        facts=value['facts'];flow=value['flow'];lpi=value['lpi'];tracker=value['tracker'];match=value['match']
        endpoints=((facts['src'],facts['sport']),(facts['dst'],facts['dport']))
        key=(facts['protocol'],tuple(sorted(endpoints)))
        if key not in sessions:
            assert flow['created']=='1'
            if facts['protocol']==6:assert value['flags']==2,'fresh SYN required'
            sessions[key]=dict(origin=endpoints,worker=flow['worker'],incarnation=lpi['incarnation'],slot=lpi['slot'],
              packets=0,attempts=0,bytes=0,stop=0,protocols=set(),tls_sides=set(),reply=False,revisions=set(),drops=0,
              source_port=next(p for p in ports if p in (facts['sport'],facts['dport'])))
        session=sessions[key]
        side=1 if endpoints==session['origin'] else 2
        assert side==1 or endpoints==session['origin'][::-1]
        session['reply']|=side==2
        state=(1 if value['flags']==2 else 2) if facts['protocol']==6 else (2 if session['reply'] else 1)
        assert int(tracker['ct_state'])==state and int(tracker['flow_dir'])==side,'independent CT/direction'
        assert lpi['incarnation']==session['incarnation'] and flow['worker']==session['worker'] and flow['slot']==session['slot'],'Flow identity changed'
        session['packets']+=1
        assert int(flow['packets'])==session['packets'],'Flow packet accounting'
        length=int(value['admit']['transport_length'])-int(value['admit']['l4_length'])
        old=set(session['protocols'])
        protocol_observation(session,facts,value['payload'],length,side)
        mask=sum(1<<(p-1001) for p in session['protocols'])
        assert int(lpi['protocols'])==mask and int(lpi['available'])==bool(mask),('wire protocol facts',value['token'],session['protocols'],lpi)
        assert int(lpi['attempts'])==session['attempts'] and int(lpi['bytes'])==session['bytes'],'bounded producer work'
        assert int(lpi['stop'])==session['stop'],'honest producer stop reason'
        if old!=session['protocols']:assert lpi['outcome']=='3'
        assert int(lpi['outcome']) in (0,1,2,3)
        facts.update(ct=state,flowdir=side,lpi=set(session['protocols']) if mask else None)
        rules=logical_rules(value['config'],facts['uid'])
        expected=reference.ordered_reference(rules,facts)
        for actual,wanted in [('rule','rule_id'),('rank','winner_rank'),('action','action'),('mode','mode'),('actual_action','actual_action')]:
            assert int(match[actual])==expected[wanted],('reference winner',value['token'],actual,expected,match)
        assert match['position']=='2' and int(match['candidates'])==len(rules)
        queries=[row for _,row in rows['cache'] if row.get('token')==value['token'] and row.get('generation')==str(generation)]
        assert len(queries)==2 and {q['position'] for q in queries}=={'1','2'}
        for query in queries:
            assert tuple(query[k] for k in ('generation','revision','snapshot_hash'))==value['identity']
            post=query['position']=='2'
            assert query['incarnation']==(session['incarnation'] if post else '0'),'cache Flow identity'
            assert int(query['evaluation'])==bool(expected['rule_id'] if post else 0),'complete cache evaluation'
            wanted=expected if post else dict(rule_id=0,winner_rank=0,action=0,actual_action=0,mode=0,reason_id=0,priority=0,order=0)
            for actual,want in [('rule','rule_id'),('rank','winner_rank'),('declared','action'),('actual','actual_action'),('mode','mode'),('reason','reason_id'),('priority','priority'),('order','order')]:
                assert int(query[actual])==wanted[want],('complete cache result',actual,value['token'])
            guarded={k:v for k,v in facts.items() if k not in ('ct','flowdir','lpi')}
            guarded['lpi']=sorted(session['protocols']) if post and rules else []
            guarded['available']=bool(mask) if post and rules else False
            guard=(session['worker'],value['identity'],query['incarnation'],query['position'],json.dumps(guarded,sort_keys=True))
            if query['hit']=='1':
                assert guard in past_guards and past_guards[guard]==wanted,'cache hit lacks identical complete prior guard/result'
                totals['cache_hits']+=1
            else:totals['cache_misses']+=1
            past_guards[guard]=wanted
        drop=expected['actual_action']==2
        one(rows['free'],obligation=value['token'])
        if profile=='root':
            assert value['admit']['source']=='NFQ_CAPTURED'
            _,verdict=one(rows['verdict'],token=value['token'],generation=generation)
            assert verdict['packet']==value['admit']['packet_id'] and int(verdict['result'])>=0
            assert int(verdict['verdict'])==int(not drop),'actual NFQUEUE verdict'
        else:
            provenance=value['admit']['source'];assert provenance in ('TUN_CAPTURED','FLOW_STACK_RETURN')
            _,completion=one(rows['completion'],token=value['token'],source=provenance)
            assert int(completion['policy_drop'])==drop,'actual VPN completion'
            copies=[row for _,row in rows['copy'] if row.get('token')==value['token']]
            assert len(copies)==int(provenance=='TUN_CAPTURED' and not drop)
            if copies:assert copies[0]['result']=='0' and copies[0]['owner']==flow['worker']
        session['revisions'].add(int(match['revision']));session['drops']+=drop
        totals['packets']+=1;totals['actual_drops']+=drop
        totals['published_changes']+=old!=session['protocols'];value['expected']=expected
    assert {s['source_port'] for s in sessions.values()}==set(ports)
    assert totals['cache_hits'] and totals['cache_misses'] and totals['actual_drops']
    return selected,sessions,dict(totals),counter_history

def flow_query(directory,case,packets,configurations,uid,dns_published,mdns=False):
    text=(directory/case['flow']).read_text()
    candidates=[r for _,r in records(text,'flow.entry ') if case['port'] in (int(r['port_a']),int(r['port_b']))]
    assert len(candidates)==1;entry=candidates[0]
    _,lpi=one(records(text,'flow.lpi '),worker=entry['worker'],slot=entry['slot'],incarnation=entry['incarnation'])
    protocol=case['protocol'];phase=case['phase']
    expected=set() if phase=='unavailable' else ({1002} if protocol=='tcp' else ({1006} if mdns else ({1001} if dns_published else set())))
    if phase in ('added','blocked','budget'):expected.add(1003 if protocol=='tcp' else 1004)
    assert int(lpi['protocols'])==sum(1<<(p-1001) for p in expected) and int(lpi['available'])==bool(expected),'query full published set'
    found={int(r['id']):r['key'] for _,r in records(text,'flow.protocol_fact ')
           if r['worker']==entry['worker'] and r['slot']==entry['slot'] and r['incarnation']==entry['incarnation']}
    names={1001:'dns',1002:'http',1003:'tls',1004:'quic',1005:'ssh',1006:'mdns'}
    assert found=={p:names[p] for p in expected},'stable catalog query mapping'
    if phase in ('budget','unavailable'):
        assert lpi['attempts']=='20' and lpi['stop']=='1' and lpi['stop_reason']=='packet_budget'
    observed=[p for p in packets if p['lpi']['worker']==entry['worker'] and p['lpi']['incarnation']==entry['incarnation']
              and p['flow']['slot']==entry['slot'] and p['flow']['packets']==entry['packets']]
    assert len(observed)==1
    packet=observed[0]
    assert entry['rule']==packet['match']['rule'] and entry['revision']==packet['match']['revision'],'Flow winner query attribution'
    assert all(lpi[k]==packet['lpi'][k] for k in ('available','protocols','attempts','bytes','stop','outcome')),'query does not match live packet prefix'
    return entry

def endpoint_delivery(directory,run,pixel,profile,endpoint,packets):
    """Join the independent socket witnesses to this run's UDP nonce and peer.

    VPN may translate its source port. The unique echo payload binds that
    endpoint socket to the app session, then its earlier DNS exchange is joined
    using the same peer and session time window. No Product classifier is used.
    """
    mdns=run.get('mdns',False)
    query=bytes.fromhex('000000000001000000000000076578616d706c65056c6f63616c0000010001') if mdns else bytes.fromhex('120c01000001000000000000076578616d706c6504746573740000010001')
    reply=bytes.fromhex('000084000001000100000000076578616d706c65056c6f63616c0000010001c00c00018001000000780004c0000201') if mdns else query[:2]+b'\x81\x80'+query[4:]
    if pixel:
        sessions=[s for s in run['sessions'] if s['profile']==profile and s['protocol']=='udp']
    else:
        sessions=[c for c in run['cases'] if c['protocol']=='udp' and c['phase']=='budget']
    assert len(sessions)==1
    for session in sessions:
        nonce=session['nonce'];echo=('T12-opaque-'+nonce).encode().hex()
        begin=int(nonce.rsplit('-',1)[1]);end=session.get('completed_ns',run['completed_ns'])
        if not pixel:
            events=json.loads((directory/(session['client']+'-client.json')).read_text())
            assert events[0]['kind']=='connected' and events[-1]['kind']=='closed'
            end=events[-1]['time_ns']
        window=[e for e in endpoint if begin<=e['time_ns']<=end]
        assert all(e['data']==echo for e in window if e['kind']=='udp_echo'),'recovery endpoint payload mismatch'
        echoes=[e for e in window if e['kind']=='udp_echo' and e['data']==echo]
        assert len(echoes)>=24, 'recovered UDP endpoint echo witnesses absent'
        peers={tuple(e['peer']) for e in echoes};assert len(peers)==1,'ambiguous endpoint socket'
        peer=next(iter(peers))
        if profile=='root':assert peer[1]==session['port'],'root endpoint source port'
        receives=[e for e in window if e['kind']=='udp_receive' and tuple(e['peer'])==peer]
        assert all(e['data'] in (query.hex(),echo) or (bytes.fromhex(e['data']) and bytes.fromhex(e['data'])[0]&0x80) for e in receives),'unexpected endpoint control payload'
        assert any(e['data']==query.hex() for e in receives),'DNS/mDNS query not received by endpoint'
        responses=[e for e in window if e['kind']==('mdns_response' if mdns else 'dns_response')]
        assert len(responses)>0 and all(tuple(e['peer'])==peer and e['data']==reply.hex() for e in responses),'DNS/mDNS endpoint response identity/payload'
        assert sum(e['data']==echo for e in receives)>=24,'recovery endpoint receives absent'
        observed=[p for p in packets if session['port'] in (p['facts']['sport'],p['facts']['dport'])]
        assert any(p['payload']==query for p in observed) and any(p['payload']==reply for p in observed),'DNS/mDNS wire query/reply pair absent'
        if not pixel:
            assert tuple(events[0]['local'])==peer and events[0]['peer'][1]==(5353 if mdns else 53)
            assert any(e['kind']==('mdns_ready' if mdns else 'dns_ready') and e['data']==reply.hex() for e in events),'client DNS/mDNS delivery absent'
            assert any(e['kind']=='timeout' for e in events),'client block timeout absent'
            assert any(e['kind']=='received' and e['count']==24 and e['data']==echo for e in events),'client recovery delivery absent'

def verify(directory):
    directory=Path(directory);run=json.loads((directory/'result.json').read_text());pixel='serial' in run
    assert run['status']=='RAW_COMPLETE' and run['process_absent'] and not run.get('error') and not run.get('cleanup_error')
    build=base.build_reader.verify_product_build(run['build'])
    assert digest(run['build'])==run['build_sha256'] and build['source_sha256']==run['source_sha256']
    assert build['completed_ns']<run['started_ns']<run['completed_ns']
    assert digest(directory/'runner.py')==run['runner_sha256']
    assert digest(directory/('protocol-peer.py' if pixel else 'socket-peer.py'))==run['peer_sha256']
    assert digest(directory/'fixtures.json')==run['fixtures_sha256']
    configurations=configs(directory,run,pixel)
    endpoint=[json.loads(line) for line in (directory/'endpoint.jsonl').read_text().splitlines()]
    assert endpoint[0]['kind']=='ready'
    mdns=run.get('mdns',False)
    assert endpoint[0]['udp_port']==(5353 if mdns else (40611 if pixel else 53))
    if mdns:
        assert any(e['kind']=='mdns_response' for e in endpoint), 'mDNS endpoint reply absent'
    dns_published=endpoint[0]['udp_port']==53
    assert any(e['kind']=='tls_handshake' and e['version']=='TLSv1.2' for e in endpoint)
    assert any(e['kind']=='quic_event' and e['event']=='ProtocolNegotiated' for e in endpoint),'authenticated QUIC ClientHello not accepted by peer'
    if not pixel:assert any(e['kind']=='quic_event' and e['event']=='HandshakeCompleted' for e in endpoint)
    summary={}
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
                stopped_owners=[r for _,r in records(trace,'s237 event=owner_stopped ')];assert len(stopped_owners)==2
                for row in stopped_owners:
                    assert all(row[k]=='0' for k in ('sessions','inputs','pbufs','buffers','obligations','frames'))
                    assert row['sockets_created']==row['sockets_closed'] and row['timer_fd']==row['broker_fd']=='-1'
        else:trace=(directory/'first-vpp.log').read_text()
        cases=[c for c in run['cases'] if c.get('profile','root')==profile]
        ports=sorted({c['port'] for c in cases})
        packets,sessions,summary[profile],counter_history=verify_trace(trace,profile,generation,ports,configurations,uid)
        endpoint_delivery(directory,run,pixel,profile,endpoint,packets)
        counter_file=profile+'-final.txt' if pixel else 'final-counters.txt'
        cache_rows=records((directory/counter_file).read_text(),'policy.cache ')
        assert len(cache_rows)==2 and {r['worker'] for _,r in cache_rows}=={'0','1'}
        for _,row in cache_rows:
            assert int(row['capacity'])==128 and int(row['storage_bytes'])==23584
            assert (int(row['hits']),int(row['misses'])) in counter_history[row['worker']], 'cache query counter prefix'
            assert 0<=int(row['occupied'])<=128
            assert int(row['replacements'])==int(row['misses'])-int(row['occupied'])
        queries={}
        for case in cases:
            entry=flow_query(directory,case,packets,configurations,uid,dns_published,mdns)
            query=props(directory/case['query']);base.query_observation(query,pixel,trace)
            queries.setdefault(case['client'],[]).append((entry,case))
        for name,values in queries.items():
            if name=='unavailable':continue
            assert [c['phase'] for _,c in values]==['first','added','blocked','budget']
            assert len({(e['worker'],e['slot'],e['incarnation']) for e,_ in values})==1,'publication reset Flow identity'
            attempts=[int(one(records((directory/c['flow']).read_text(),'flow.lpi '),worker=e['worker'],slot=e['slot'],incarnation=e['incarnation'])[1]['attempts']) for e,c in values]
            assert attempts==sorted(attempts) and attempts[-1]==20,'budget reset or nontermination'
            session=next(s for s in sessions.values() if s['source_port']==values[0][1]['port'])
            assert session['drops']>0
        if pixel:
            for session in (s for s in run['sessions'] if s['profile']==profile):
                report=json.loads((directory/(session['label']+'-finished.json')).read_text())
                assert report['nonce']==session['nonce'] and report['uid']==uid and report['plan']==session['plan'] and not report.get('error')
                assert report['blockedTimeout'] and report['echoes']==(25 if session['protocol']=='tcp' else 24)
                if session['protocol']=='tcp':assert report['tlsProtocol']=='TLSv1.2'
                else:assert report['quicReplyBytes']>0 and report['dnsReplyBytes']>=12
    return dict(status='PASS',source_sha256=run['source_sha256'],profiles=summary,
      mdns=mdns, protocol_scope=('HTTP/TLS1.2; '+('mDNS direct-unicast query/answer; ' if mdns else ('nonstandard-port DNS unavailable; ' if pixel else 'DNS query/answer; '))+('QUICv1 authenticated Initial exchange' if pixel else 'QUICv1 full handshake')),
      verifier_sha256=digest(__file__))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
    try:result=verify(a.directory)
    except (AssertionError,KeyError,ValueError,OSError,IndexError) as error:
        result=dict(status='HOLD',error=str(error));print(json.dumps(result,indent=2));raise
    if a.output:a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
