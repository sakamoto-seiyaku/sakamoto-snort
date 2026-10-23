#!/usr/bin/env python3
"""Reconstruct scoped S314 evidence from raw App/peer/wire/normal/lifecycle files.

Case descriptors select expected cases and outcomes. Runner PASS and its copied
record, peer and stream summaries are never evidence inputs. Incomplete terminal
runs retain their status and can contribute only individually reconstructed cases.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def props(path):
    return dict(line.split('=',1) for line in path.read_text().splitlines() if '=' in line and not line.startswith('#'))


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.startswith('{')]


def source_port_selection(run,case):
    path=run/(case['label']+'-source-port.json')
    if not path.exists():return
    selection=read(path);tables=run/(case['label']+'-source-ports-before.txt')
    assert digest(tables)==selection['tables_sha256']
    occupied=set();headers=0
    for line in tables.read_text().splitlines():
        fields=line.split()
        if not fields:continue
        if fields[:2]==['sl','local_address']:headers+=1;continue
        assert fields[0].endswith(':')and fields[0][:-1].isdigit()and len(fields)>=10
        endpoint=fields[1].split(':');assert len(endpoint)==2 and len(endpoint[0])in(8,32)and len(endpoint[1])==4
        bytes.fromhex(endpoint[0]);occupied.add(int(endpoint[1],16))
    assert headers==4 and occupied==set(selection['occupied'])
    assert selection['selected']==case['source_port']and 20000<=case['source_port']<40000
    assert case['source_port']not in occupied and case['source_port']not in selection['previously_reserved']


def dns_name(wire, cursor):
    labels=[];visited=set();end=None
    while True:
        assert cursor<len(wire)and cursor not in visited,'invalid DNS name'
        visited.add(cursor);size=wire[cursor];cursor+=1
        if size&0xc0==0xc0:
            assert cursor<len(wire)
            if end is None:end=cursor+1
            cursor=((size&63)<<8)|wire[cursor];continue
        assert size<=63 and cursor+size<=len(wire)
        if not size:return '.'.join(labels).lower(),end if end is not None else cursor
        labels.append(wire[cursor:cursor+size].decode('ascii').lower());cursor+=size
        assert sum(len(label)+1 for label in labels)<=254


def connected_names(reply_hex):
    wire=bytes.fromhex(reply_hex);assert len(wire)>=12 and wire[2]&128
    assert int.from_bytes(wire[4:6],'big')==1
    question,cursor=dns_name(wire,12);cursor+=4;edges={}
    for _ in range(int.from_bytes(wire[6:8],'big')):
        owner,cursor=dns_name(wire,cursor);assert cursor+10<=len(wire)
        kind=int.from_bytes(wire[cursor:cursor+2],'big');size=int.from_bytes(wire[cursor+8:cursor+10],'big');cursor+=10
        assert cursor+size<=len(wire)
        if kind==5:
            target,end=dns_name(wire,cursor);assert end==cursor+size
            assert owner not in edges or edges[owner]==target
            edges[owner]=target
        cursor+=size
    names=[question]
    while names[-1]in edges:
        target=edges[names[-1]];assert target not in names,'cyclic complete reply'
        names.append(target);assert len(names)<=33,'overflow complete reply'
    return names,wire[3]&15


def edns_options(wire_hex):
    wire=bytes.fromhex(wire_hex);cursor=12
    for _ in range(int.from_bytes(wire[4:6],'big')):
        _,cursor=dns_name(wire,cursor);cursor+=4
    options=[]
    for section in (6,8,10):
        for _ in range(int.from_bytes(wire[section:section+2],'big')):
            owner,cursor=dns_name(wire,cursor);assert cursor+10<=len(wire)
            kind=int.from_bytes(wire[cursor:cursor+2],'big');size=int.from_bytes(wire[cursor+8:cursor+10],'big');cursor+=10
            assert cursor+size<=len(wire)
            if kind==41:
                assert section==10 and not owner
                at=cursor
                while at<cursor+size:
                    assert at+4<=cursor+size
                    code=int.from_bytes(wire[at:at+2],'big');length=int.from_bytes(wire[at+2:at+4],'big');at+=4
                    assert at+length<=cursor+size
                    options.append((code,wire[at:at+length].hex()));at+=length
            cursor+=size
    assert cursor==len(wire)
    return options


def tcp_frames(packets,address,port,outgoing):
    selected=[p for p in packets if p.get('kind')=='tcp' and p['destination' if outgoing else 'source']==address
        and p['source_port' if outgoing else 'destination_port']==port]
    syn=[p for p in selected if p['flags']&2]
    assert syn,('wire handshake missing',address,port,outgoing)
    start=(syn[0]['sequence']+1)&0xffffffff;positions={}
    for packet in selected:
        for offset,byte in enumerate(bytes.fromhex(packet['payload_hex'])):
            at=(packet['sequence']+bool(packet['flags']&2)+offset-start)&0xffffffff
            assert at<2**31
            assert at not in positions or positions[at]==byte,'conflicting TCP wire overlap'
            positions[at]=byte
    data=bytearray()
    while len(data) in positions:data.append(positions[len(data)])
    assert len(data)==len(positions),'disconnected observed TCP bytes after a gap'
    result=[];cursor=0
    while cursor+2<=len(data):
        size=int.from_bytes(data[cursor:cursor+2],'big')
        if cursor+2+size>len(data):break
        result.append(data[cursor+2:cursor+2+size].hex());cursor+=size+2
    return result,len(data)-cursor


def normal(run,label,generation,source,*,allow_empty=False):
    data=read(run/(label+'-observation.json'))
    consumer=data['consumer'];runtime=data['runtime']
    assert consumer['query_fresh']is True and consumer['malformed']==0
    assert all(consumer[key]is None for key in ('error','query_error','store_error'))
    assert consumer['persistent']['storage']=='sqlite'and consumer['persistent']['save_error']is None
    assert runtime['state']=='running'and runtime['protectionRunning']=='true'and int(runtime['generation'])==generation
    if not allow_empty:assert consumer['persistent']['dns']['recent']
    return [row['record'] for row in data['consumer']['persistent']['dns']['recent'].values()
        if row['record']['generation']==generation and row['record']['source_port']==source]


def trace_cleanup(run):
    source=run/'source-s314_adb_trace.py'
    if not source.exists():return
    trace=read(run/'adb-trace.json')
    assert trace['status']=='COMPLETE_REMOTE_WITNESSES'and trace['owned_actor_absent']is True
    assert trace['remote_directory_removed']is True and trace['helper_sha256']==digest(source)
    operations=[json.loads(line)for line in(run/'operations.jsonl').read_text().splitlines()]
    after=(run/'adb-trace-processes-after.txt').read_text()
    assert trace['nonce']not in after
    final_pids={int(parts[0])for line in after.splitlines()if(parts:=line.split())and parts[0].isdigit()}
    for item in trace['operations']:
        host=item['host_operation'];assert host in operations and host['local_reaped']is True
        assert host['argv']==item['original_argv']and all(isinstance(value,str)for value in host['argv'])
        assert host['completed_monotonic_ns']>=host['started_monotonic_ns']
        assert(run/host['stdout_path']).is_file()and(run/host['stderr_path']).is_file()
        label=item['label'];raw=(run/(label+'-remote-meta.stdout')).read_bytes().decode(errors='replace')
        assert item['remote_meta']['code']==0 and item['remote_meta']['text']==raw
        assert item['remote_out']['code']==0 and item['remote_out']['text']==(run/(label+'-remote-out.stdout')).read_bytes().decode(errors='replace')
        lines=raw.splitlines();assert len(lines)%2==0
        values=dict(zip(lines[::2],lines[1::2]));assert len(values)*2==len(lines)
        assert set(values)=={'begin','wrapper_stat','wrapper_uid','child_stat','child_uid','end','exit'}
        assert re.fullmatch(r'\d+',values['exit'])and 0<=int(values['exit'])<=255
        assert 0<=float(values['begin'].split()[0])<=float(values['end'].split()[0])<float('inf')
        assert item['witness']['exit_code']==int(values['exit'])and item['witness']['gaps']==[]
        for actor in('wrapper','child'):
            stat=values[actor+'_stat'];pid=int(stat.split(' ',1)[0]);start=int(stat.rsplit(') ',1)[1].split()[19])
            uid=int(values[actor+'_uid'].split()[2]);assert pid>0 and start>0
            if pid in final_pids:
                reads=[op for op in operations if op.get('trace_kind')=='trace-owned-identity'and f'/proc/{pid}/stat'in' '.join(op['argv'])]
                assert reads,'reused final PID lacks independent identity read'
                current=(run/reads[-1]['stdout_path']).read_text().splitlines()
                assert current==['ABSENT']or(int(current[0].rsplit(') ',1)[1].split()[19]),int(current[1].split()[2]))!=(start,uid)
    assert any(op.get('trace_kind')=='trace-owned-directory-cleanup'and op['code']==0
        and op['argv']==['exec-out','rm','-rf',trace['remote_directory']]for op in operations)


def route_cleanup(run):
    source=run/'source-s314_adb_route.py'
    if not source.exists():return
    route=read(run/'adb-route-receipt.json')
    assert route['status']=='COMPLETE_TASK_LOCAL_ROUTE'and not route['errors']
    assert route['remaining_sockets']==0 and route['live_threads']==[]
    assert route['source_sha256']==digest(source)
    assert route['log_sha256']==digest(run/'adb-route-connections.jsonl')
    assert route['upstream']==['127.0.0.1',5037]
    assert route['endpoint'][0]=='127.0.0.1'and 0<route['endpoint'][1]<65536
    assert 0<route['accepted']<=route['max_connections']<=4096
    assert 0<route['peak_active']<=route['max_active']<=16
    assert 0<route['connect_timeout']<=.5 and 1<=route['max_connect_attempts']<=6
    assert route['connection_lifetime']==65,'matrix route must retain its bounded Device scope'
    connections={}
    for row in rows(run/'adb-route-connections.jsonl'):
        connections.setdefault(row['connection'],[]).append(row)
    assert set(connections)==set(range(1,route['accepted']+1))
    for items in connections.values():
        attempts=[item for item in items if item['event']=='connect-attempt']
        assert 1<=len(attempts)<=route['max_connect_attempts']
        assert [item['attempt']for item in attempts]==list(range(1,len(attempts)+1))
        assert all(item['forwarded_request_bytes']==0 and item['endpoint']==route['upstream']
            and item['completed_monotonic_ns']>=item['started_monotonic_ns']for item in attempts)
        assert all(item['status']=='connect-failed'for item in attempts[:-1])
        if attempts[-1]['status']=='connected':
            closed,=[item for item in items if item['event']=='stream-closed']
            assert closed['forwarded_request_bytes']>=0 and closed['returned_bytes']>=0
            assert closed['buffer_limit_per_direction']==65536 and closed['reason']!='task-close'
        else:
            assert attempts[-1]['status']=='connect-failed'
            missing,=[item for item in items if item['event']=='no-upstream']
            assert missing['forwarded_request_bytes']==0


def lifecycle(run,result,apk,native):
    assert result['apk_sha256']==apk and (run/'installed-apk.txt').read_text().split()[0]==apk
    installed_native={Path(line.split()[1]).name:line.split()[0] for line in (run/'installed-native.txt').read_text().splitlines() if line.strip()}
    assert installed_native==native,'installed native payload differs from pinned APK'
    assert not any(key.endswith('cleanup_error') for key in result),result
    trace_cleanup(run)
    route_cleanup(run)
    assert result['status'] in ('PASS','HOLD','PASS_WITH_EXPLICIT_LIMITS')
    stops={}
    for path in run.glob('*-stopped.properties'):
        state=props(path);generation=int(state['generation'])
        assert state['state']=='stopped'and state['mayBeActive']=='false'
        prefix=path.name.removesuffix('-stopped.properties');log=(run/(prefix+'-stop.log')).read_text()
        running=[props(p) for p in run.glob('*-running.properties') if int(props(p)['generation'])==generation]
        assert len(running)==1 and running[0]['profile']==result['profile']
        owners=[int(n)for n in re.findall(rf'dns event=stop generation={generation} owner=(\d+) requests=0 codec_live_bytes=0 active_operations=0 tcp_active=0 tcp_owned_bytes=0',log)]
        assert owners and sorted(set(owners))==list(range(len(set(owners))))
        if result['profile']=='vpn':
            assert f's213 event=stop generation={generation} pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1'in log
            for owner in set(owners):
                match=re.search(rf's237 event=owner_stopped generation={generation} owner={owner} .*sessions=0 inputs=0 pbufs=0 sockets_created=(\d+) sockets_closed=(\d+) timer_fd=-1 broker_fd=-1 buffers=0 obligations=0 frames=0',log)
                assert match and match[1]==match[2]
        if result['profile']=='root':
            assert f's242 event=stop_native_zero generation={generation} ready_mask=0 graph_enabled=0 graph_accepting=0 pending=0 buffers=0 obligations=0 handoffs=0 completion_frames=0'in log
            assert not (run/(prefix+'-queues-after.txt')).read_text().strip()
            hooks=(run/(prefix+'-hooks-after.txt')).read_text()
            assert 'NFQUEUE'not in hooks and 'SAKAMOTO'not in hooks and 'S314_UNKNOWN_FIXTURE'not in hooks
        processes=(run/(prefix+'-processes-after.txt')).read_text()
        assert not any('libvpp_runtime.so'in line or re.search(r'\btail\b.*vpp-stdout',line)for line in processes.splitlines())
        stops[generation]=len(set(owners))
    assert stops,'no qualified actual stop'
    wire=rows(run/('underlay-final.jsonl'if result.get('protocol')=='udp'else 'final-underlay.jsonl'))
    assert wire[0]['kind']=='ready'and wire[-1]['kind']=='stopped'
    after=(run/'witness-process-after.txt').read_text()
    witness_paths=('/data/local/tmp/s313-wire','/data/local/tmp/s312-wire')
    assert not any(any(path in line for path in witness_paths)for line in after.splitlines())
    peer=rows(run/'peer.log')if(run/'peer.log').exists()else []
    if peer:
        ready,=[r for r in peer if r.get('kind')=='ready'];stopped,=[r for r in peer if r.get('kind')=='stopped']
        cleanup=read(run/'peer-cleanup.json');remote=cleanup['actual_remote'];pid=ready['process_id']
        assert cleanup['process_id']==pid and cleanup['process_exit']==0 and not remote['process_present']
        assert not any(r['OwningProcess']==pid for r in remote['endpoints'])
        assert stopped['pending']==0
        if 'connections'in stopped:
            assert stopped['connections']==0 and stopped['received']==stopped['exchanged']+stopped['cancelled']
    return stops,peer


def root_active_tcp(run,label,plan,app,packets,address,port,accepted,got,replies):
    """Qualify held-App capture, retaining the debug-UID post-close limit."""
    opened=read(run/(label+'-client-open.json'))
    assert plan['dnsTcpHoldAfterReads']is True
    assert opened['phase']=='dns_tcp_read_complete'and not opened.get('error')
    assert opened['plan']==plan and opened['dnsExchanges']==app['dnsExchanges']
    assert opened['uid']==app['uid']and opened['nonce']==app['nonce']==plan['nonce']
    operations=rows(run/'operations.jsonl')
    release='files/product-state/t12-release-'+plan['nonce']+'-dns_tcp_read_complete'
    release_index,=[i for i,row in enumerate(operations)if row['argv'][-1:]==[release]and 'touch'in row['argv']]
    assert operations[release_index].get('code')==0
    before=operations[:release_index];after=operations[release_index+1:]
    app_path='files/product-state/t12-'+plan['nonce']+'.json'
    last_open=max(i for i,row in enumerate(before)if row['argv'][-2:]==['cat',app_path]and row.get('code')==0)
    assert any(row['argv'][-2:]==['cat',app_path]and row.get('code')==0 for row in after)
    assert any(row['argv']==['exec-out','cat','/data/local/tmp/s313-wire.jsonl']and row.get('code')==0 for row in before[last_open+1:])
    final=rows(run/'final-underlay.jsonl')
    assert final[:len(packets)]==packets,'active wire is not a prefix of final wire'
    selected=lambda p:p.get('kind')=='tcp'and p['destination']==address and p['source_port']==port and p['destination_port']==53
    syn_sequence,={p['sequence']for p in packets if selected(p)and p['flags']&2}
    origin=(syn_sequence+1)&0xffffffff;positions={};extra=0
    for index,packet in enumerate(final):
        if not selected(packet):continue
        for offset,byte in enumerate(bytes.fromhex(packet['payload_hex'])):
            position=(packet['sequence']+bool(packet['flags']&2)+offset-origin)&0xffffffff
            assert position<2**31
            if position in positions:assert positions[position]==byte
            elif index>=len(packets):
                assert packet['flags']&1,'new post-capture Root bytes arrived before socket FIN'
                extra+=1
            positions[position]=byte
    full_out,trailing=tcp_frames(final,address,port,True)
    assert not trailing and full_out==[r['request_hex']for r in got]
    assert len(got)>=accepted and len(replies)==len(got)
    return dict(scope='ACTIVE_SOCKET_SNAPSHOT_ONLY',post_close_new_outgoing_bytes=extra,
        post_close_complete_queries=len(got)-accepted,
        limit='Root debug-App UID capture excludes orphaned Android packets after App socket close; final peer/wire retain pre-stop post-close exposure, with no post-close inbound completeness claim')


def check_tcp(run,case,result,stops,peer):
    label=case['label'];generation=case['generation'];source=case['source_port'];address=case['address']
    assert stops[generation]==case['owner_count']
    plan=read(run/(label+'-plan.json'));app=read(run/(label+'-client.json'))
    fixture_hold=case.get('collector_release_hold',False)
    if fixture_hold:
        assert app['phase']=='finished'and app.get('error')=='java.lang.IllegalStateException: release deadline dns_tcp_read_complete'
        opened=read(run/(label+'-client-open.json'))
        assert opened['phase']=='dns_tcp_read_complete'and not opened.get('error')
        assert opened['plan']==app['plan']and opened['dnsExchanges']==app['dnsExchanges']
        app=opened
    assert app['phase']==('dns_tcp_read_complete'if fixture_hold else 'finished')and not app.get('error')and app['plan']==plan
    assert app['uid']==result['uid']and plan['endpoint']==address and plan['source']==source and plan['port']==53
    expected=plan['dnsTcpQueries']*plan['dnsTcpRepeat'];exchanges=app['dnsExchanges']
    assert len(exchanges)==len(expected)and [r['sentHex']for r in exchanges]==expected
    # Expected action comes from the explicit case descriptor, never a PASS row.
    denied=case['denied'];query_drop=case['query_drop']
    target_index=1 if result['profile']=='vpn'or len(plan['dnsTcpQueries'])>1 else 0
    accepted=target_index if query_drop else target_index+1 if denied else len(expected)
    requests=[r for r in peer if r.get('kind')=='received'and r['request_hex']in expected]
    connections={r['connection']for r in requests};assert len(connections)==1
    connection,=connections
    got=[r for r in requests if r['connection']==connection]
    replies=[r for r in peer if r.get('kind')=='exchange'and r['connection']==connection]
    peer_prefix=run/(label+'-peer-active.jsonl')
    if peer_prefix.exists():
        active_peer=rows(peer_prefix)
        assert active_peer==peer[:len(active_peer)]
        assert [r['request_hex']for r in active_peer if r.get('kind')=='received'and r['connection']==connection]==expected[:accepted]
        assert len([r for r in active_peer if r.get('kind')=='exchange'and r['connection']==connection])==accepted
    root_scope=None
    if result['profile']=='root'and denied:
        assert [r['request_hex']for r in got]==expected[:len(got)]and len(got)<=len(expected)
    else:assert [r['request_hex']for r in got]==expected[:accepted]
    assert all(r['resolver']==[address,53]for r in got+replies)
    if not(result['profile']=='root'and denied):assert len(replies)==accepted
    connected,=[r for r in peer if r.get('kind')=='connected'and r['connection']==connection]
    port=int(connected['peer'].rsplit(':',1)[1]);assert result['profile']!='root'or port==source
    packets=rows(run/(label+'-underlay.jsonl'))
    if result['profile']=='root'and denied:
        root_scope=root_active_tcp(run,label,plan,app,packets,address,port,accepted,got,replies)
        got=got[:accepted];replies=replies[:accepted]
    outbound,trailing_out=tcp_frames(packets,address,port,True)
    inbound,trailing_in=tcp_frames(packets,address,port,False)
    assert outbound==expected[:accepted]
    expected_reply=[r['reply_hex']for r in replies]
    assert inbound==[wire for index,wire in enumerate(expected_reply)
        for _ in range(case.get('reply_copies',1)if index%len(plan['dnsTcpQueries'])==target_index else 1)]
    assert not trailing_in
    if not query_drop:assert not trailing_out
    if '-continuous-'in label:
        assert not plan['dnsTcpPipeline']and len(expected)==128 and not app.get('deadlineReached')
        assert sum(len(bytes.fromhex(wire))+2 for wire in outbound)>65535
        assert sum(len(bytes.fromhex(wire))+2 for wire in inbound)>65535
        target_options=edns_options(plan['dnsTcpQueries'][target_index])
        assert (65002,'00'*1024)in target_options
        assert edns_options(expected_reply[target_index])==target_options
    for index,exchange in enumerate(exchanges):
        if denied and index>=target_index:assert exchange.get('timedOut')and not exchange.get('replyHex')
        else:assert exchange.get('replyHex')==expected_reply[index]and not exchange.get('timedOut')
    records=normal(run,label,generation,source);assert records
    running=props(next(p for p in run.glob('*-running.properties')if int(props(p)['generation'])==generation))
    assert running['profile']==result['profile']
    revisions={int(props(p)['activeRevision']):props(p)for p in run.glob('*-applied.properties')}
    status=revisions[int(case['policy']['activeRevision'])]
    assert int(status['generation'])==generation and status==case['policy']
    target_id=0 if case['variant']=='short'else int.from_bytes(bytes.fromhex(plan['dnsTcpQueries'][target_index])[:2],'big')
    target=[r for r in records if r['coverage']==case['coverage']and not r['tcp_continuation']
        and r['id']==target_id and r['stage']==(1 if query_drop else 2)]
    assert target
    for record in records:
        assert record['protocol']==6 and record['family']==(6 if ':'in address else 4)
        assert record['adapter_profile']==(2 if result['profile']=='vpn'else 1)and record['incarnation']>0
        assert 0<=record['owner']<stops[generation]and record['delivery']==0
        assert record['resolver_port']==53 and str(ipaddress.ip_address(bytes(record['resolver_address'][:4 if record['family']==4 else 16])))==address
        if record['coverage']==1:
            warm_id=int.from_bytes(bytes.fromhex(plan['dnsTcpQueries'][0])[:2],'big')
            if result['profile']=='vpn'and record['id']==warm_id and record['caller']==0:
                assert record['uid']==4294967295 and not record['domain_available']
            else:assert record['caller']==1 and record['uid']==result['uid']
    query_records=list(records)
    query_paths=sorted(run.glob(label+'-query-capture-*-observation.json'))
    if query_paths:query_records+=normal(run,query_paths[-1].name.removesuffix('-observation.json'),generation,source)
    for record in target:
        assert record['actual_action']==(2 if denied else 1)
        assert record['winner']==int(status[f"rule.{case['winner']}.version"])
        assert record['policy_revision']==int(status['activeRevision'])and record['chain_status']==case['chain_status']
        if 'observe'in label:assert record['mode']==1 and record['declared_action']==2
        if record['stage']==2 and record['coverage']==1:
            assert record['correlation']==1 and record['query_token']and record['query_incarnation']==record['incarnation']
            if result['profile']=='vpn':assert record['transport_session']and record['underlay_epoch']
            if plan['dnsTcpRepeat']==1 or '-continuous-'in label:
                unique={json.dumps(q,sort_keys=True):q for q in query_records}
                query,=[q for q in unique.values() if q['stage']==1 and q['coverage']==1 and not q['tcp_continuation']
                    and q['id']==target_id and q['message_sequence']==record['message_sequence']]
                assert record['query_token']==query['token']and record['query_incarnation']==query['incarnation']
                for field in ('policy_generation','policy_revision','policy_hash','winner'):
                    assert record['query_'+field]==query[field]
    if case['coverage']==1 and not query_drop:
        names,rcode=connected_names(expected_reply[target_index])
        by_message={}
        for record in target:by_message.setdefault(record['message_sequence'],[]).append(record)
        for candidates in by_message.values():
            candidates.sort(key=lambda record:record['name_index'])
            assert [record['name']for record in candidates]==names
            for index,record in enumerate(candidates):
                assert record['name_index']==index and record['name_source']==bool(index)
                assert record['candidate_count']==len(names)and record['rcode']==rcode
                assert record['domain_available']and record['domain_lists']=={'qname.test':1,'alias.test':2}.get(record['name'],0)
    if case.get('reply_copies')==2:
        assert len(target)==2 and {r['message_sequence']for r in target}=={target_index+1,target_index+2}
        assert len({r['token']for r in target})==1
        raw=bytes.fromhex(expected_reply[target_index]);framed=(len(raw).to_bytes(2,'big')+raw)*2
        assert any(p.get('kind')=='tcp'and p['destination_port']==port and p['payload_hex']==framed.hex()for p in packets)
    return dict(label=label,profile=result['profile'],protocol='tcp',family=6 if ':'in address else 4,
        generation=generation,owners=case['owner_count'],messages=len(expected),normal_records=len(records),
        app_source=source,direct_source=port,query_drop=query_drop,denied=denied,
        trailing_forwarded_query_prefix=trailing_out,source=str(run),collector_release_hold=fixture_hold,
        active_socket_snapshot_claim=not fixture_hold,root_capture_scope=root_scope,
        independent_peer_prefix_frozen=peer_prefix.exists())


def case_policy(run,case):
    revision=int(case['policy']['activeRevision'])
    matches=[status for path in run.glob('*-applied.properties')
        if int((status:=props(path))['activeRevision'])==revision and status['result']=='0'
        and status['savedRevision']==status['activeRevision']]
    # A later rejected apply legitimately still reports the previous active
    # revision. It cannot qualify as that earlier successful acknowledgement.
    matching=[status for status in matches if status==case['policy']]
    assert matching,'no successful exact acknowledgement for the desired case policy'
    status=matching[0]
    assert status['result']=='0'and status['activeRevision']==status['savedRevision']
    assert int(status['generation'])==case['generation']
    return status


def common_record(record,case,result,stops,protocol,*,generic_policy=False):
    assert record['generation']==case['generation']and record['source_port']==case['source_port']
    assert record['protocol']==protocol and record['family']==(6 if ':'in case['address']else 4)
    assert record['adapter_profile']==(2 if result['profile']=='vpn'else 1)
    assert 0<=record['owner']<stops[case['generation']]and record['delivery']==0
    assert record['token']>0
    assert (record['slot']==4294967295)==(record['incarnation']==0)
    # Classify packet coverage before trusting its claimed Flow identity.
    if generic_policy and protocol==6 and record['coverage']!=1:
        assert record['incarnation']==0
    if record['incarnation']==0:
        assert generic_policy
        assert record['stage']==1 and record['direction']==3 and record['actual_action']==2
        assert record['caller']==0 and not record['domain_available']
        if record['coverage']==1:
            assert protocol!=6 or record['message_sequence']>0
        else:
            # A retransmission outside retained TCP history has packet-level
            # coverage, not a new question or an invented Flow/session identity.
            assert protocol==6 and record['coverage']==11 and record['packet_direction']==3
            assert record['uid']==record['packet_uid']==2000
            assert record['availability']&9==1 and record['packet_availability']&9==1
            assert not record['name']
            assert all(record[field]==0 for field in ('id','query_flags','qtype','qclass',
                'codec_peak_bytes','message_sequence','tcp_continuation','candidate_count',
                'name_index','name_source','chain_status','matched_requests','retransmits',
                'correlation','query_token','query_incarnation','query_policy_generation',
                'query_policy_revision','query_policy_hash','query_winner','transport_session',
                'underlay_epoch','domain_lists','rcode'))
    else:assert record['incarnation']>0
    assert record['resolver_port']==53
    assert str(ipaddress.ip_address(bytes(record['resolver_address'][:4 if record['family']==4 else 16])))==case['address']


def query_link(query,response):
    assert response['correlation']==1 and response['query_token']==query['token']
    assert response['query_incarnation']==query['incarnation']
    for field in ('policy_generation','policy_revision','policy_hash','winner'):
        assert response['query_'+field]==query[field]


def packet_with(packets,address,wire,outgoing,protocol='udp'):
    return [packet for packet in packets if packet.get('kind')==protocol
        and packet['destination'if outgoing else 'source']==address
        and packet['destination_port'if outgoing else 'source_port']==53 and packet.get('payload_hex')==wire]


def check_udp(run,case,result,stops,peer):
    label=case['label'];generation=case['generation'];source=case['source_port'];address=case['address']
    assert stops[generation]==case['owner_count']
    status=case_policy(run,case);plan=read(run/(label+'-plan.json'));app=read(run/(label+'-client.json'))
    assert app['phase']=='finished'and not app.get('error')and app['plan']==plan and app['uid']==result['uid']
    assert plan['endpoint']==address and plan['source']==source and plan['port']==53
    requests=plan['dnsQueries'];exchanges=app['dnsExchanges'];assert len(requests)==len(exchanges)==3
    assert [row['sentHex']for row in exchanges]==requests
    packets=rows(run/(label+'-underlay.jsonl'));records=normal(run,label,generation,source)
    assert records
    for record in records:common_record(record,case,result,stops,17)
    query_drop=case.get('kind')=='udp-query-drop'
    denied=query_drop or ('alias-drop'in label and 'observe'not in label)
    for index,request in enumerate(requests):
        identifier=int.from_bytes(bytes.fromhex(request)[:2],'big')
        query,=[row for row in records if row['stage']==1 and row['id']==identifier]
        assert query['coverage']==1 and query['policy_revision']==int(status['activeRevision'])
        if index:assert query['caller']==1 and query['uid']==result['uid']and query['domain_available']
        received=[row for row in peer if row.get('kind')=='received'and row['request_hex']==request]
        replies=[row for row in peer if row.get('kind')=='exchange'and row['request_hex']==request]
        outgoing=packet_with(packets,address,request,True)
        blocked=denied and index==1
        if query_drop and index==1:
            assert query['actual_action']==2 and query['winner']==int(status['rule.0.version'])
            assert exchanges[index].get('timedOut')and not exchanges[index].get('replyHex')
            assert not received and not replies and not outgoing
            assert not any(row['stage']==2 and row['id']==identifier for row in records)
            continue
        assert query['actual_action']==1 and len(received)==len(replies)==1 and outgoing
        reply=replies[0]['reply_hex'];assert replies[0]['resolver']==received[0]['resolver']==[address,53]
        assert packet_with(packets,address,reply,False)
        if blocked:assert exchanges[index].get('timedOut')and not exchanges[index].get('replyHex')
        else:assert exchanges[index].get('replyHex')==reply and not exchanges[index].get('timedOut')
        names,rcode=connected_names(reply)
        answers=sorted([row for row in records if row['stage']==2 and row['id']==identifier],key=lambda row:row['name_index'])
        assert [row['name']for row in answers]==names
        for ordinal,response in enumerate(answers):
            query_link(query,response)
            assert response['coverage']==1 and response['actual_action']==(2 if blocked else 1)
            assert response['caller']==query['caller']and response['candidate_count']==len(names)
            assert response['name_index']==ordinal and response['name_source']==bool(ordinal)and response['rcode']==rcode
            assert response['domain_available']==bool(query['caller'])
            assert response['domain_lists']==({'qname.test':1,'alias.test':2}.get(response['name'],0)if query['caller']else 0)
            assert response['policy_revision']==int(status['activeRevision'])
            if index==1:assert response['winner']==int(status['rule.0.version'if denied or 'alias-allow'in label else 'rule.2.version'])
            if result['profile']=='vpn':assert response['transport_session']and response['underlay_epoch']
    return dict(label=label,profile=result['profile'],protocol='udp',family=6 if ':'in address else 4,
        generation=generation,owners=case['owner_count'],messages=3,normal_records=len(records),
        query_drop=query_drop,denied=denied,source=str(run))


def check_unknown(run,case,result,stops,peer):
    label=case['label'];generation=case['generation'];source=case['source_port'];address=case['address']
    protocol=result['protocol'];assert stops[generation]==case['owner_count'];status=case_policy(run,case)
    assert status['binding.0'].split(',')[1]=='2000'
    denied=case['kind']=='unknown-generic-drop'
    compiled=list(map(int,status['rule.0.wire'].split(',')))
    expression=b''.join(word.to_bytes(4,'big')for word in compiled[27:])[:compiled[26]].hex()
    assert expression==('0603'if denied else'1100060301')
    assert compiled[5]==10 and compiled[8]==(6 if protocol=='tcp'else 17)and compiled[10]==2
    assert status['binding.0']=='1,2000,2,10,0'and status['domain.0.name']=='qname.test'
    ready,client=rows(run/(label+'-client.jsonl'))
    assert ready['phase']=='ready'and client['phase']=='finished'and ready['pid']==client['pid']
    assert ready['uid']==client['uid']==2000 and ready['source_port']==client['source_port']==source
    commands=[row['argv']for row in rows(run/'operations.jsonl')if row.get('argv',[])[:2]==['shell','/data/local/tmp/s314-unknown']
        and row['argv'][2:5]==[protocol,address,str(source)]]
    command,=commands;requests=command[5:];assert len(requests)==2
    for request in requests:
        wire=bytes.fromhex(request);assert int.from_bytes(wire[4:6],'big')==1 and not(wire[2]&128)
        name,end=dns_name(wire,12);assert name=='qname.test'and wire[end:end+4]==b'\0\1\0\1'
    assert len(client['exchanges'])==2
    after=(run/(label+'-finally-helper-after.txt')).read_text()
    assert not any(line.split()and(line.split()[0]==str(client['pid'])or '/data/local/tmp/s314-unknown'in line)for line in after.splitlines())
    if result['profile']=='root':
        capture=(run/(label+'-capture-active.txt')).read_text()
        assert all(value in capture for value in ('S314_UNKNOWN_FIXTURE',address,'--uid-owner 2000',f'--sport {source}',f'-p {protocol}','--queue-num 176'))
        assert 'S314_UNKNOWN_FIXTURE'not in(run/(label+'-capture-after.txt')).read_text()
    packets=rows(run/(label+'-underlay.jsonl'))
    records=normal(run,label,generation,source)
    runtime,=re.findall(r'dns\.profile=original enabled=1 generation=(\d+) policy_revision=(\d+) snapshot_hash=(\d+)',
        (run/(label+'-after.txt')).read_text())
    assert tuple(map(int,runtime[:2]))==(generation,int(status['activeRevision']))
    request_ids={int.from_bytes(bytes.fromhex(request)[:2],'big')for request in requests}
    for record in records:
        common_record(record,case,result,stops,6 if protocol=='tcp'else 17,
            generic_policy=denied)
        if denied and record['actual_action']==2:
            assert record['policy_generation']==generation and record['policy_revision']==int(status['activeRevision'])
            assert record['policy_hash']==int(runtime[2]) and record['winner']==int(status['rule.0.version'])
            assert record['declared_action']==2 and record['mode']==0
            assert record['packet_uid']==2000 and record['packet_availability']&1
        if record['coverage']==1:
            assert record['caller']==0 and not record['domain_available']
            assert record['id']in request_ids and record['name']=='qname.test'and record['qtype']==record['qclass']==1
    requests_seen=[row for row in peer if row.get('kind')=='received'and row['request_hex']in requests]
    replies=[row for row in peer if row.get('kind')=='exchange'and row['request_hex']in requests]
    generic_capture=None;generic_flow=None;generic_scope=None;cold_allowed=[]
    if denied:
        last=client['exchanges'][1]
        assert last['timed_out']and last['errno']==110 and not last['reply_hex']
        if result['profile']=='root':
            assert all(row['timed_out']and row['errno']==110 and not row['reply_hex']for row in client['exchanges'])
            if protocol=='udp':assert client['connect_errno']==0 and all(row['sent']for row in client['exchanges'])
            else:assert client['connect_errno']==110 and not any(row['sent']for row in client['exchanges'])
        elif client['connect_errno']:
            assert protocol=='tcp'and client['connect_errno']==110 and not any(row['sent']for row in client['exchanges'])
        else:assert all(row['sent']for row in client['exchanges'])
        generic_scope='TRANSPORT_CONNECT_ONLY'if client['connect_errno']else'TRANSPORT_FLOW_ONLY'
        for index,(request,exchange)in enumerate(zip(requests,client['exchanges'])):
            identifier=int.from_bytes(bytes.fromhex(request)[:2],'big')
            received=[row for row in requests_seen if row['request_hex']==request]
            answered=[row for row in replies if row['request_hex']==request]
            queries=[row for row in records if row['stage']==1 and row['id']==identifier and row['coverage']==1 and not row['tcp_continuation']]
            responses=[row for row in records if row['stage']==2 and row['id']==identifier and row['coverage']==1 and not row['tcp_continuation']]
            if exchange['reply_hex']:
                # The existing VPN UID contract permits a cold packet with
                # no UID fact. This is separate from DNS-caller Unknown.
                assert result['profile']=='vpn'and index==0 and exchange['sent']and not exchange['timed_out']and exchange['errno']==0
                query,=queries;response,=responses
                assert query['uid']==query['packet_uid']==4294967295 and not(query['packet_availability']&1)
                assert query['winner']==0
                for record in(query,response):
                    assert record['actual_action']==1 and record['incarnation']>0
                    assert record['policy_revision']==int(status['activeRevision'])
                assert response['uid']in(2000,4294967295)and response['packet_uid']in(2000,4294967295)
                assert bool(response['availability']&1)==(response['uid']==2000)
                assert bool(response['packet_availability']&1)==(response['packet_uid']==2000)
                assert response['winner']==(int(status['rule.2.version'])if response['packet_uid']==2000 else 0)
                query_link(query,response)
                got,=received;reply,=answered
                assert got['resolver']==reply['resolver']==[address,53]and reply['reply_hex']==exchange['reply_hex']
                cold_allowed.append(index)
                if protocol=='udp':
                    assert packet_with(packets,address,request,True)and packet_with(packets,address,exchange['reply_hex'],False)
            else:
                assert exchange['timed_out']and exchange['errno']==110 and not received and not answered and not responses
                if protocol=='udp':assert not packet_with(packets,address,request,True)
                else:assert not any(bytes.fromhex(request)in bytes.fromhex(packet.get('payload_hex',''))
                    for packet in packets if packet.get('kind')=='tcp'and packet['destination']==address and packet['destination_port']==53)
                if protocol=='udp'or queries:
                    query,=queries
                    assert query['packet_uid']==2000 and query['packet_availability']&1
                    if protocol=='udp':assert query['uid']==2000 and query['availability']&1
                    else:
                        assert query['uid']in(2000,4294967295)
                        assert bool(query['availability']&1)==(query['uid']==2000)
                    assert query['actual_action']==2 and query['winner']==int(status['rule.0.version'])
                    assert query['policy_revision']==int(status['activeRevision'])
                    if index==1:generic_scope='DNS_MESSAGE_AND_FLOW'
        if protocol=='tcp'and replies:
            connection,={row['connection']for row in requests_seen}
            connected,=[row for row in peer if row.get('kind')=='connected'and row['connection']==connection]
            port=int(connected['peer'].rsplit(':',1)[1])
            assert tcp_frames(packets,address,port,True)==([requests[i]for i in cold_allowed],0)
            assert tcp_frames(packets,address,port,False)==([client['exchanges'][i]['reply_hex']for i in cold_allowed],0)
        overview=read(run/(label+'-observation.json'))['consumer']['overview']
        destination=list(ipaddress.ip_address(address).packed)
        flows=[row for row in overview['blocked_records']if row and
            row['generation']==generation and row['protocol']==(6 if protocol=='tcp'else 17)and
            row['ports']==[source,53]and row['addresses'][len(destination):]==destination]
        flow,=flows
        generic_flow=dict(packets=flow['packets'][0],bytes=flow['bytes'][0],
            scope='Asynchronous normal flow snapshot; not a final packet-count total')
        assert flow['uid']==2000 and flow['blocked']and flow['owner']<stops[generation]
        assert flow['policy_revision']==int(status['activeRevision'])and flow['winner']==int(status['rule.0.version'])
        attribution=flow['attribution'][0]
        assert attribution['valid']and attribution['uid']==2000 and attribution['actual_action']==2
        assert attribution['declared_action']==2 and attribution['policy_generation']==generation
        assert attribution['policy_revision']==int(status['activeRevision'])and attribution['winner']==int(status['rule.0.version'])
        assert flow['packets'][0]>0 and flow['bytes'][0]>0 and flow['packets'][1]==flow['bytes'][1]==0
        if result['profile']=='root':
            def tagged_count(suffix):
                line,=[line for line in(run/(label+suffix)).read_text().splitlines()if 'S314_UNKNOWN_FIXTURE'in line]
                assert all(value in line for value in(address,'--uid-owner 2000',f'--sport {source}',f'-p {protocol}','--queue-num 176'))
                match=re.match(r'\[(\d+):(\d+)\] ',line);assert match
                return tuple(map(int,match.groups()))
            before=tagged_count('-capture-active.txt');after=tagged_count('-capture-counters.txt')
            delta=tuple(a-b for a,b in zip(after,before))
            generic_capture=dict(packets=delta[0],bytes=delta[1])
            if protocol=='udp':assert delta==(flow['packets'][0],flow['bytes'][0])
            else:
                assert delta[0]>=flow['packets'][0]and delta[1]>=flow['bytes'][0]
                assert not any(packet.get('kind')=='tcp'and packet['destination']==address
                    and packet['destination_port']==53 and packet['source_port']==source for packet in packets)
        counter='policy_drops'if result['profile']=='vpn'else 'policy_qualified_matched_drop_succeeded'
        def number(path):
            values=re.findall(rf'\b{counter}=(\d+)',path.read_text());assert values
            return sum(map(int,values))
        drop_delta=number(run/(label+'-after.txt'))-number(run/(label+'-before.txt'))
        assert drop_delta>0
        if generic_capture:assert drop_delta==generic_capture['packets']
    else:
        assert client['connect_errno']==0 and len(requests_seen)==len(replies)==2
        assert [row['request_hex']for row in requests_seen]==requests
        assert [row['reply_hex']for row in replies]==[row['reply_hex']for row in client['exchanges']]
        assert all(row['resolver']==[address,53]for row in requests_seen+replies)
        for request,reply in zip(requests,replies):
            identifier=int.from_bytes(bytes.fromhex(request)[:2],'big')
            query,=[row for row in records if row['stage']==1 and row['id']==identifier and row['coverage']==1 and not row['tcp_continuation']]
            response,=[row for row in records if row['stage']==2 and row['id']==identifier and row['coverage']==1 and not row['tcp_continuation']]
            assert query['actual_action']==response['actual_action']==1
            query_link(query,response)
        assert any(row['uid']==2000 for row in records)
        if protocol=='tcp':
            connection,={row['connection']for row in requests_seen}
            connected,=[row for row in peer if row.get('kind')=='connected'and row['connection']==connection]
            port=int(connected['peer'].rsplit(':',1)[1])
            assert tcp_frames(packets,address,port,True)==(requests,0)
            assert tcp_frames(packets,address,port,False)==([row['reply_hex']for row in replies],0)
        else:
            assert all(packet_with(packets,address,request,True)for request in requests)
            assert all(packet_with(packets,address,row['reply_hex'],False)for row in replies)
    return dict(label=label,profile=result['profile'],protocol=protocol,family=6 if ':'in address else 4,
        generation=generation,owners=case['owner_count'],messages=sum(row['sent']for row in client['exchanges']),normal_records=len(records),
        planned_messages=2,helper_queries_sent=sum(row['sent']for row in client['exchanges']),
        packet_coverage_records=sum(row['coverage']!=1 for row in records),
        completed_dns_exchanges=sum(bool(row['reply_hex'])for row in client['exchanges']),
        generic_normal_flow_snapshot=generic_flow,generic_root_capture=generic_capture,
        generic_denial_scope=generic_scope,cold_packet_uid_unavailable_allowed_ordinals=cold_allowed,
        unknown_caller=True,independent_generic_drop=denied,source=str(run))


def check_public(run,case,result,stops,peer):
    assert not peer
    label=case['label'];generation=case['generation'];source=case['source_port'];address=case['address']
    assert stops[generation]==case['owner_count']
    case_policy(run,case)
    plan=read(run/(label+'-plan.json'));app=read(run/(label+'-client.json'))
    assert app['phase']=='finished'and app['plan']==plan and app['uid']==result['uid']
    assert plan['endpoint']==address and plan['source']==source and plan['port']==53
    requests=plan['dnsTcpQueries'];assert len(requests)==3 and plan['dnsTcpRepeat']==1
    for request,kind in zip(requests,(1,28,16)):
        wire=bytes.fromhex(request);name,cursor=dns_name(wire,12)
        assert name=='example.com'and wire[4:6]==b'\x00\x01'
        assert int.from_bytes(wire[cursor:cursor+2],'big')==kind and wire[cursor+2:cursor+4]==b'\x00\x01'
    counter='policy_drops'if result['profile']=='vpn'else 'policy_qualified_matched_drop_succeeded'
    def total(path):
        values=re.findall(rf'\b{counter}=(\d+)',path.read_text());assert values
        return sum(map(int,values))
    assert total(run/(label+'-after.txt'))==total(run/(label+'-before.txt'))
    exchanges=app.get('dnsExchanges',[])
    complete=not app.get('error')and len(exchanges)==3 and all(
        row.get('replyHex')and not row.get('timedOut')for row in exchanges)
    assert case['transport_complete']==complete
    records=normal(run,label,generation,source,allow_empty=not complete)
    for record in records:
        common_record(record,case,result,stops,6)
        assert record['actual_action']==1
    packets=rows(run/(label+'-underlay.jsonl'))
    outgoing=[p for p in packets if p.get('kind')=='tcp'and p['destination']==address and p['destination_port']==53]
    direct=None
    if complete:
        assert [row['sentHex']for row in exchanges]==requests
        candidates=[]
        for port in {p['source_port']for p in outgoing}:
            try:frames,trailing=tcp_frames(packets,address,port,True)
            except AssertionError:continue
            if frames==requests and not trailing:candidates.append(port)
        direct,=candidates
        assert result['profile']!='root'or direct==source
        replies=[row['replyHex']for row in exchanges]
        assert tcp_frames(packets,address,direct,False)==(replies,0)
        for request,reply in zip(requests,replies):
            identifier=int.from_bytes(bytes.fromhex(request)[:2],'big')
            assert bytes.fromhex(reply)[:2]==bytes.fromhex(request)[:2]
            names,_=connected_names(reply)
            assert names[0]=='example.com'
            query,=[r for r in records if r['stage']==1 and r['id']==identifier and r['coverage']==1 and not r['tcp_continuation']]
            response,=[r for r in records if r['stage']==2 and r['id']==identifier and r['coverage']==1 and not r['tcp_continuation']and r['name_index']==0]
            query_link(query,response)
            assert response['caller']==query['caller']
    return dict(label=label,profile=result['profile'],protocol='tcp',family=6 if ':'in address else 4,
        generation=generation,owners=case['owner_count'],messages=3 if complete else 0,
        normal_records=len(records),public_transport_complete=complete,
        public_wire_outgoing_packets=len(outgoing),direct_source=direct,policy_drop_delta=0,
        limit=None if complete else 'Permitted public transport incomplete; no successful DNS exchange or policy DROP inferred',
        identity_limit='Original public destination wire is not resolver-provider authentication',source=str(run))


def qualify(plan_path,runs,held_cases=()):
    plan=read(plan_path);apk=plan['apk_sha256'];assert digest(Path(plan['apk']))==apk
    with zipfile.ZipFile(plan['apk']) as archive:
        native={Path(name).name:hashlib.sha256(archive.read(name)).hexdigest()for name in archive.namelist()
            if name.startswith('lib/arm64-v8a/')and name.endswith('.so')}
    groups=[];receipts=[]
    for run in runs:
        result=read(run/'result.json');stops,peer=lifecycle(run,result,apk,native)
        for case in result['cases']:
            source_port_selection(run,case)
            if case.get('kind')=='public-tcp':check=check_public
            elif case.get('kind','').startswith('unknown-'):check=check_unknown
            elif result.get('protocol')=='udp':check=check_udp
            else:
                assert 'kind'not in case
                check=check_tcp
            groups.append(check(run,case,result,stops,peer))
        receipts.append(dict(source=str(run),raw_status=result['status'],raw_error=result.get('error'),
            qualified_groups=len(result['cases']),input_hashes={p.name:digest(p)for p in sorted(run.iterdir())if p.is_file()}))
    for path in held_cases:
        descriptor=read(path);run=Path(descriptor['source']);result=read(run/'result.json')
        assert result['status']=='HOLD'and descriptor['case']['collector_release_hold']is True
        stops,peer=lifecycle(run,result,apk,native)
        groups.append(check_tcp(run,descriptor['case'],result,stops,peer))
        receipts.append(dict(source=str(run),raw_status=result['status'],qualified_groups=1,
            explicit_limit='External DNS behavior and clean stop proved; timely fixture release and active-socket snapshot not claimed',
            descriptor=str(path),descriptor_sha256=digest(path)))
    identities=[(g['profile'],g['protocol'],g['label'])for g in groups];assert len(set(identities))==len(identities),'duplicate case scope'
    return dict(status='PASS_SCOPED',scope='Only individually reconstructed supplied groups; full milestone requires separate coverage closure',
        apk_sha256=apk,groups=groups,runs=receipts)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs',type=Path,nargs='+');parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--held-case',type=Path,action='append',default=[])
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    try:report=qualify(args.plan,args.runs,args.held_case)
    except Exception as error:
        report=dict(status='FAIL',error=repr(error));raise
    finally:args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(status=report['status'],groups=len(report.get('groups',[])))))
