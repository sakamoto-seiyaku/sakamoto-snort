#!/usr/bin/env python3
"""Independently verify S223 UDP transitions and actual endpoint/owner/completion ledgers."""
import argparse
from collections import Counter,defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import zipfile

ROOT=Path(__file__).resolve().parents[2]
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def rows(text,prefix):
    return [dict(part.split('=',1) for part in line.split()[1:] if '=' in part)
            for line in text.splitlines() if line.startswith(prefix)]
def has_native_process(text,names=('libvpp_runtime.so',)):
    for line in text.splitlines():
        fields=line.split(None,2)
        if len(fields)==3 and fields[0].isdigit() and fields[2].split():
            if Path(fields[2].split()[0]).name in names:return True
    return False
def entry_key(e):
    common=(int(e['kind']),int(e['family']),int(e['protocol']),e['key_a'],e['key_b'])
    return common+((int(e['query_class']),int(e['identifier'])) if int(e['kind'])==3
                   else (int(e['port_a']),int(e['port_b'])))
def packet_key(f):
    family=int(f['family']);protocol=int(f['protocol'])
    if protocol in (6,17):
        endpoints=sorted([(f['src'],int(f['src_port'])),(f['dst'],int(f['dst_port']))])
        return (2,family,protocol,endpoints[0][0],endpoints[1][0],endpoints[0][1],endpoints[1][1])
    a,b=sorted([f['src'],f['dst']])
    return (3,family,protocol,a,b,1,int(f['icmp_id']))

def verify(directory,build_override=None):
    directory=Path(directory);errors=[];summaries=[]
    def require(ok,message):
        if not ok and len(errors)<100:errors.append(message)
    try:
        result=json.loads((directory/'result.json').read_text())
        require(result['status']=='RAW_COMPLETE','collector not complete')
        require(result['source']=='NFQ_CAPTURED','not real NFQUEUE source')
        platform=result['platform'];require(platform in ('linux','pixel'),'platform')
        build_path=Path(build_override or result['build']);build=json.loads(build_path.read_text())
        require(digest(build_path)==result['build_sha256'],'wrong build witness')
        require(result['source_sha256']==build['source_sha256'],'source identity')
        require(build['completed_ns']<result['started_ns']<result['completed_ns'],'build/run order')
        require(digest(ROOT/f'tests/device/s223-{platform}-udp.py')==result['runner_sha256'],'collector source changed')
        files=build['files'];encoded=json.dumps(files,sort_keys=True,separators=(',',':')).encode()
        require(hashlib.sha256(encoded).hexdigest()==build['source_sha256'],'source closure')
        require(digest(build_path.parent/'dirty.diff')==build['dirty_diff_sha256'],'source diff changed')
        for name,value in files.items():
            if value is not None:
                require(digest(build_path.parent/'source'/name)==value,'source snapshot '+name)
                require(digest(ROOT/name)==value,'current source '+name)
        for name,value in build['s221_helpers'].items():require(digest(build_path.parent/name)==value,'helper '+name)
        for name,value in build['s221_helper_inputs'].items():
            require(digest(ROOT/name)==value and digest(build_path.parent/'source'/name)==value,'helper source '+name)
        helper_path=build_path.parent/'s223-helper/helper.json'
        helper=json.loads(helper_path.read_text())
        require(digest(helper_path)==result['helper_manifest_sha256'],'UDP helper witness')
        require(helper['build_sha256']==digest(build_path) and helper['source_sha256']==build['source_sha256'],'UDP helper build binding')
        for name,value in helper['files'].items():require(digest(helper_path.parent/name)==value,'UDP helper '+name)
        require(digest(ROOT/'tests/device/helpers/s223-udp.c')==helper['files']['s223-udp.c'],'UDP helper source changed')
        require(digest(ROOT/'tests/evidence/build_s223_helper.py')==helper['files']['build_s223_helper.py'],'UDP helper builder changed')
        if platform=='linux':
            require(build['host_evidence'] is False,'Host evidence fixture artifact')
            for name,value in build['artifact_hashes'].items():require(digest(Path(build['artifact'])/name)==value,'artifact '+name)
            require('Linux' in (directory/'kernel.txt').read_text(),'kernel evidence')
            mapping=(directory/'uid-map.txt').read_text().split()
            require(len(mapping)==3 and mapping[0]=='0' and mapping[1]!='0' and mapping[2]=='1','isolated user namespace')
        else:
            require(result['serial']=='28201JEGR0XPAJ' and 'bluejay' in (directory/'device.txt').read_text(),'Pixel identity')
            require(result['apk_sha256']==build['apk_sha256']==digest(build['apk']),'APK identity')
            require((directory/'installed-apk-sha256.txt').read_text().split()[0]==build['apk_sha256'],'installed APK')
            installed={Path(l.split()[1]).name:l.split()[0] for l in (directory/'installed-native-sha256.txt').read_text().splitlines()}
            with zipfile.ZipFile(build['apk']) as apk:
                expected={Path(n).name:hashlib.sha256(apk.read(n)).hexdigest() for n in apk.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
            require(installed==expected==build['native_sha256']==result['native_sha256'],'installed native closure')
            for name in ('s217-policy',):
                require((directory/(name+'-installed.txt')).read_text().split()[0]==build['s221_helpers']['helpers/'+name],'device helper '+name)
            require((directory/'s223-udp-installed.txt').read_text().split()[0]==helper['files']['s223-udp'],'installed UDP endpoint')
            require(result['wifi_before']==result['wifi_after'],'Wi-Fi not restored')
            require('state=running' in (directory/'app-running.properties').read_text(),'RuntimeService running')
            stopped=(directory/'app-stopped.properties').read_text()
            require('state=stopped' in stopped and 'mayBeActive=false' in stopped,'RuntimeService stopped')
            require('productRootNfqueueResidueClean=true' in (directory/'app-cleanup.properties').read_text(),'RuntimeService residue')
            require(not has_native_process((directory/'processes-after.txt').read_text(),
                ('libvpp_runtime.so','s223-udp')),'surviving VPP/endpoint process')
            require('SAKAMOTO_S223_' not in (directory/'hooks-after.txt').read_text(),'surviving test hooks')
        require([r['label'] for r in result['runs']]==['output','input'],'required runs')
        generations=set()
        for run in result['runs']:
            label=run['label'];folder=directory/label;generation=str(run['generation']);capacity=run['capacity']
            def check(ok,message):require(ok,label+': '+message)
            check(generation not in generations,'generation reused');generations.add(generation)
            check(run.get('raw_complete') is True,'run incomplete')
            final=(folder/'final.txt').read_text();closed=(folder/'closed.txt').read_text();trace=(folder/'vpp.log').read_text()
            pools=rows(final,'flow.pool ');runtime=rows(final,'flow.runtime ');entries=rows(final,'flow.entry ')
            lanes=rows(final,'root.lane ');completion=rows(final,'completion.status ');primary=rows(final,'primary.status ')
            check(len(pools)==len(runtime)==2 and {x['worker'] for x in pools}=={'0','1'},'two runtime snapshots')
            check(len(lanes)==4 and {int(x['queue']) for x in lanes}==set(range(176,180)), 'exact queue lanes')
            check({int(x['lane']) for x in lanes}==set(range(4)),'exact lane identities')
            captured=sum(int(x['captured']) for x in lanes)
            for lane in lanes:
                check(lane['generation']==generation,'lane generation')
                check(int(lane['worker'])==int(lane['lane'])%2 and int(lane['thread'])==int(lane['worker'])+1,'lane confinement')
                check(lane['captured']==lane['submitted']==lane['verdicts']==lane['succeeded']==lane['returns'],'native conservation')
                check(all(lane[k]=='0' for k in ('pending','failed','duplicate')),'lane residue/failure')
            check(len(completion)==1 and int(completion[0]['verdicts'])==captured,'completion count')
            if completion:check(all(completion[0][k]=='0' for k in ('pending','frames','buffers','obligations','duplicate','stale')),'completion residue')
            check(len(primary)==1 and primary[0]['published']==primary[0]['received'],'handoff conservation')
            if primary:check(all(primary[0][k]=='0' for k in ('rejected','owner_failures','pending_returns','handoff_debt')),'handoff residue')
            stages={
                'facts':rows(trace,'s216 stage=admit '),
                'observe':rows(trace,'s208 '),
                'publish':rows(trace,'s204 event=completion_publish '),
                'consume':rows(trace,'s204 event=completion_consume '),
                'origin':rows(trace,'s210 event=origin_completion '),
                'free':rows(trace,'s203 event=buffer_free '),
            }
            indexed={}
            for name,values in stages.items():
                by_token={}
                for value in values:
                    token=value.get('token',value.get('obligation'))
                    check(token not in by_token,name+' duplicate token');by_token[token]=value
                    if name!='free':check(value.get('generation')==generation,name+' generation')
                    if 'source' in value:check(value['source']=='NFQ_CAPTURED',name+' wrong source')
                indexed[name]=by_token
                check(len(values)==captured,name+' trace count vs actual captured')
            check(all(set(values)==set(indexed['facts']) for values in indexed.values()),'packet ledger token sets')
            vectors={};thread=None
            for line in final.splitlines():
                match=re.match(r'Thread (\d+) ',line)
                if match:thread=int(match[1])
                match=re.match(r'(product-packet-(?:admit|policy|origin-completi\S*))\s+active\s+\d+\s+(\d+)',line)
                if match:vectors[thread,match[1]]=int(match[2])
            for worker in (0,1):
                owner_packets=sum(int(x['worker'])==worker for x in stages['observe'])
                origin_packets=sum(int(x['captured']) for x in lanes if int(x['worker'])==worker)
                check(vectors.get((worker+1,'product-packet-policy'))==owner_packets,'actual owner VLIB vectors')
                check(vectors.get((worker+1,'product-packet-admit'),0)==origin_packets,'actual ingress VLIB vectors')
                completion_vectors=sum(value for (t,name),value in vectors.items() if t==worker+1 and name.startswith('product-packet-origin-completi'))
                check(completion_vectors==origin_packets,'actual origin VLIB vectors')
            tracker_rows=rows(trace,'s223 event=udp_update ')
            tracker={x['token']:x for x in tracker_rows}
            expected_tokens={token for token,o in indexed['observe'].items() if o['event']=='observe'}
            check(len(tracker)==len(tracker_rows) and set(tracker)==expected_tokens,'one UDP update per observed packet, none on DROP')
            counts=Counter();protocol_counts=Counter();flow_ledger={};keys_by_slot={};coverage=set();bypasses=0
            transitions=Counter();placement=set();reverse_first=0
            for token,observation in indexed['observe'].items():
                facts=indexed['facts'][token];origin=indexed['origin'][token]
                publish=indexed['publish'][token];consume=indexed['consume'][token];freed=indexed['free'][token]
                key=packet_key(facts);worker=int(observation['worker']);lane=int(facts['origin_lane'])
                check(int(observation['thread'])==worker+1 and observation['worker']==observation['owner']==observation['pool_worker']==facts['owner'],'owner-local mutation')
                check(worker==int(observation['hash'])%2,'existing owner hash consumed')
                check(origin['lane']==consume['lane']==publish['lane']==facts['origin_lane'],'original lane retained')
                check(origin['packet']==consume['packet']==publish['packet']==facts['packet_id'],'original packet ID retained')
                check(int(origin['thread'])==lane%2+1 and origin['thread']==consume['thread']==freed['thread'],'completion origin confinement')
                check(publish['thread']==observation['thread']==consume['producer_thread'],'completion producer is owner')
                check(all(value['buffer']==facts['buffer'] for value in (observation,origin,publish,consume,freed)),'one buffer carrier')
                check(publish['intent']==consume['intent']==origin['intent'],'terminal intent retained')
                event=observation['event'];counts[worker,event]+=1;protocol_counts[worker,int(facts['protocol']),event]+=1
                if event=='early_drop':
                    check(origin['intent']=='2' and origin['verdict']=='0' and origin['drop_reason'] in ('7','8') and origin['bypass_reason']=='0','early DROP not bypassed')
                    check(observation['created']==observation['reused']=='0' and observation['slot']=='4294967295','DROP does not lookup/create')
                elif event=='capacity_bypass':
                    bypasses+=1
                    check(origin['intent']=='3' and origin['verdict']=='1' and origin['drop_reason']=='0' and origin['bypass_reason']=='4','flow capacity returns NF_ACCEPT')
                    check(observation['status']=='6' and observation['created']==observation['reused']=='0' and observation['slot']=='4294967295','capacity miss creates no facts')
                    check(key not in flow_ledger,'existing flow incorrectly bypassed')
                else:
                    check(event=='observe' and observation['status']=='0','unexpected runtime mutation error')
                    check(origin['intent']=='1' and origin['verdict']=='1' and origin['drop_reason']==origin['bypass_reason']=='0','ordinary pass completion')
                    slot=int(observation['slot']);check(0<=slot<capacity,'slot bounds')
                    check(observation['hash']==observation['stored_hash'] and int(observation['stored_kind'])==key[0],'stored typed identity')
                    created=observation['created']=='1';check(created!=(observation['reused']=='1'),'create/hit partition')
                    if created:
                        check(key not in flow_ledger and (worker,slot) not in keys_by_slot,'duplicate entry/slot overwrite')
                        flow_ledger[key]=dict(worker=worker,slot=slot,packets=0,bytes=0,orig=int(observation['source_is_a']),sides=[0,0],side_bytes=[0,0],phase=0,revision=None,serial=None)
                        keys_by_slot[worker,slot]=key
                    ledger=flow_ledger[key]
                    check(ledger['worker']==worker and ledger['slot']==slot,'flow owner or slot changed')
                    side=int(observation['source_is_a'])!=ledger['orig']
                    check(int(observation['flow_dir'])==1+side and int(observation['origin_is_a'])==ledger['orig'],'stable ORIG/REPLY')
                    ledger['packets']+=1;ledger['bytes']+=int(facts['packet_length']);ledger['sides'][side]+=1;ledger['side_bytes'][side]+=int(facts['packet_length'])
                    check(int(observation['packets'])==ledger['packets'] and int(observation['bytes'])==ledger['bytes'],'entry accounting')
                    u=tracker[token]
                    check(all(u[k]==observation[k] for k in ('generation','token','buffer','thread','worker','owner','slot','created','invalidated','flow_dir')),'tracker bound to observation')
                    check(u['source']=='NFQ_CAPTURED','tracker source')
                    # Literal S223 spec transition table, independent of Product code.
                    direction=1+side;old=ledger['phase']
                    expected={(0,1):1,(1,1):2,(1,2):3,(2,1):2,(2,2):3,(3,1):3,(3,2):3}.get((old,direction))
                    check(expected is not None and int(u['phase'])==expected,'UDP transition')
                    ct,update,timeout={1:(1,1,1),2:(1,1,2),3:(2,2,3)}[expected]
                    check((int(u['ct_state']),int(u['update']),int(u['timeout']))==(ct,update,timeout),'OVS NEW/VALID/timeout mapping')
                    check(u['refresh']=='1' and u['close']==u['replacement']=='0','UDP refresh/close intent')
                    check([int(u[k]) for k in ('orig_packets','reply_packets')]==ledger['sides'],'tracker side counters')
                    revision=observation['revision']
                    check(int(u['invalidated'])==int(not created and ledger['revision']!=revision),'policy identity lazy invalidation')
                    if created:ledger['serial']=u['incarnation'];reverse_first+=int(observation['source_is_a']=='0')
                    check(u['incarnation']==ledger['serial'],'tracker incarnation stable')
                    ledger['phase']=expected;ledger['revision']=revision
                    transitions[old,direction,expected]+=1
                    placement.add((int(facts['family']),worker,int(facts['worker'])!=worker))
                    check(int(facts['direction'])==(3 if label=='output' else 1),'single hook device direction')
                    if not created:counts[worker,'hit']+=1
                    else:counts[worker,'create']+=1
            check(len(entries)==len(flow_ledger),'final entry count')
            final_keys=set();buckets=defaultdict(list)
            bucket_count=1
            while bucket_count<capacity*2:bucket_count*=2
            for entry in entries:
                key=entry_key(entry);check(key not in final_keys,'duplicate final typed key');final_keys.add(key)
                ledger=flow_ledger[key];worker=int(entry['worker'])
                check(worker==ledger['worker'] and int(entry['slot'])==ledger['slot'],'final slot identity')
                check(int(entry['packets'])==ledger['packets'] and int(entry['bytes'])==ledger['bytes'],'final counters')
                check([int(entry[k]) for k in ('orig_packets','reply_packets')]==ledger['sides'],'per-side packets')
                check([int(entry[k]) for k in ('orig_bytes','reply_bytes')]==ledger['side_bytes'],'per-side bytes')
                check(entry['policy_generation']==generation and int(entry['incarnation'])>0,'entry generation/lifetime')
                states=[u for u in rows(final,'flow.udp ') if u['worker']==entry['worker'] and u['slot']==entry['slot']]
                check(len(states)==1 and int(states[0]['phase'])==ledger['phase'] and states[0]['incarnation']==ledger['serial'],'final UDP state')
                check(entry['flow_origin_dir']==entry['device_dir']==('3' if label=='output' else '1'),'device/flow direction independence')
                coverage.add((int(entry['family']),int(entry['protocol']),worker))
                h=int(entry['hash']);buckets[worker,(h^(h>>32)^(h>>16))&(bucket_count-1)].append(key)
            collisions=sum(len(keys)-1 for keys in buckets.values() if len(keys)>1)
            for pool in pools:
                worker=int(pool['worker']);active=sum(e['worker']==pool['worker'] for e in entries)
                check(int(pool['entries'])==int(pool['allocations'])==active==counts[worker,'create'],'shared allocation count')
                check(int(pool['reused'])==counts[worker,'hit'],'hit count')
                check(int(pool['early_drops'])==counts[worker,'early_drop'],'early DROP count')
                check(int(pool['capacity_drops'])==counts[worker,'capacity_bypass'],'capacity miss count')
                check(all(pool[k]=='0' for k in ('wrong_owner','revision_mismatches','unavailable')),'mutation failures/unavailable')
            for snapshot in runtime:
                check(int(snapshot['capacity'])==capacity and snapshot['generation']==generation,'startup capacity/generation')
                check(int(snapshot['high_watermark'])==sum(e['worker']==snapshot['worker'] for e in entries),'high watermark')
                check(int(snapshot['allocated_bytes'])>int(snapshot['entry_bytes'])*capacity,'preallocated index/pool memory')
            per_protocol=rows(final,'flow.protocol ')
            check(len(per_protocol)==6 and {(x['worker'],x['protocol']) for x in per_protocol}==
                  {(worker,protocol) for worker in ('0','1') for protocol in ('tcp','udp','icmp_query')},'exact per-protocol snapshots')
            for counter in per_protocol:
                worker=int(counter['worker']);protocols={'tcp':(6,),'udp':(17,),'icmp_query':(1,58)}[counter['protocol']]
                matching=[e for e in entries if int(e['worker'])==worker and int(e['protocol']) in protocols]
                check(int(counter['active'])==int(counter['creates'])==len(matching),'per-protocol shared occupancy')
                check(int(counter['hits'])==sum(protocol_counts[worker,p,'observe'] for p in protocols)-len(matching),'per-protocol hits')
                check(int(counter['capacity_misses'])==sum(protocol_counts[worker,p,'capacity_bypass'] for p in protocols),'per-protocol capacity misses')
            check(coverage=={(family,17,worker) for family in (4,6) for worker in (0,1)},'dual-stack owner coverage')
            check({(family,remote) for family,worker,remote in placement}
                  =={(family,remote) for family in (4,6) for remote in (False,True)},'dual-stack actual local and remote owner paths')
            check(bypasses==0,'unexpected capacity bypass')
            check(reverse_first>0,'real reverse endpoint first-observed ORIG')
            check(set(transitions)=={(0,1,1),(1,1,2),(1,2,3),(2,1,2),(2,2,3),(3,1,3),(3,2,3)},'all UDP transitions covered')
            for name,phase,packets in [('first',1,1),('same',2,3),('revision',2,4),('bidir',3,6),('gate',3,6),('recovered',3,8)]:
                snapshot=(folder/(name+'.txt')).read_text()
                es=rows(snapshot,'flow.entry ');us=rows(snapshot,'flow.udp ')
                for family in (4,6):
                    for port in range(31000,31008):
                        matches=[e for e in es if int(e['family'])==family and port in (int(e['port_a']),int(e['port_b']))]
                        check(len(matches)==1,'phase snapshot identity')
                        e=matches[0];u=next(u for u in us if u['worker']==e['worker'] and u['slot']==e['slot'])
                        check(int(u['phase'])==phase and int(e['packets'])==packets,'phase snapshot '+name)
            endpoint=(folder/'endpoint.log').read_text()
            for index,case in enumerate(run['cases']):
                client=(folder/f'client-{index}.txt').read_text();nonce=case['nonce'];raw=nonce.encode().hex()
                packets=[f for f in indexed['facts'].values() if raw in f['raw']]
                check(bool(packets),'endpoint nonce missing from actual packet facts')
                outcomes=[indexed['origin'][f['token']] for f in packets]
                if case['blocked']:
                    check(case['returncode']!=0 and not rows(client,'endpoint ') and nonce not in endpoint,'blocked endpoint delivered')
                    check(all(o['verdict']=='0' and o['intent']=='2' for o in outcomes),'blocked nonce bypassed')
                else:
                    check(case['returncode']==0 and len(rows(client,'endpoint '))==case['count'],'endpoint response count')
                    check(all(o['verdict']=='1' and o['intent']=='1' for o in outcomes),'allowed nonce not accepted')
                    check(len(packets)==case['count']*(2 if case['echo'] else 1),'single-hook exact datagram count')
                    for sequence in range(case['count']):
                        suffix=nonce+'-'+str(sequence)
                        check(sum(x['nonce']==suffix for x in rows(endpoint,'received '))==1,'one independent endpoint receive')
                    for row in rows(client,'endpoint '):
                        check(row['sent']=='1' and int(row['received'])==int(case['echo']),'client echo/send intent')
                    if case['phase'] in ('single-only','same-only'):
                        key=packet_key(packets[0]);check(flow_ledger[key]['phase']==(1 if case['phase']=='single-only' else 2),'finite one-sided state')
                    if case['phase']=='reverse-first':
                        first=indexed['observe'][packets[0]['token']]
                        check(first['created']=='1' and first['source_is_a']=='0' and first['flow_dir']=='1','reverse first defines ORIG')
            nonces={case['nonce'] for case in run['cases']}
            check(all(any(n.encode().hex() in f['raw'] for n in nonces) for f in indexed['facts'].values()),'unexpected captured traffic')
            check('root.stop=ok' in (folder/'stop.txt').read_text(),'native stop failed')
            closed_pools=rows(closed,'flow.pool ');closed_lanes=rows(closed,'root.lane ')
            check(len(closed_pools)==2 and all(x['entries']=='0' and x['flushes']=='1' for x in closed_pools),'FlowRuntime stop residue')
            check(not rows(closed,'flow.entry ') and all(x['active']=='0' for x in rows(closed,'flow.protocol ')),'typed/protocol stop residue')
            check(len(closed_lanes)==4 and all(x['ready']=='0' and x['fd']=='-1' and x['pending']=='0' for x in closed_lanes),'lane stop residue')
            closed_completion=rows(closed,'completion.status ')
            check(len(closed_completion)==1 and all(closed_completion[0][k]=='0' for k in ('pending','frames','buffers','obligations','duplicate','stale')),'stop completion residue')
            stop=json.loads((folder/'stop.json').read_text());check(stop['process_absent'] is True,'native process survived')
            if platform=='linux':
                busy=json.loads((folder/'queues-busy.json').read_text());free=json.loads((folder/'queues-free.json').read_text())
                check(set(busy)==set(free)==set(map(str,range(176,180))),'queue probe identity')
                check(all(v in (-1,-16) for v in busy.values()) and all(v==0 for v in free.values()),'exclusive queues not released')
                check('NFQUEUE' not in (folder/'hooks-after.txt').read_text(),'namespace hooks survived')
            else:
                free=(folder/'queues-free.txt').read_text()
                check(not any(int(line.split()[0]) in range(176,180) for line in free.splitlines() if line.strip()),'kernel queues survived')
                check('SAKAMOTO_S223_' not in (folder/'hooks-after.txt').read_text(),'private hooks survived')
            check(bool((folder/'fds-before.txt').read_text()) and bool((folder/'fds-closed.txt').read_text()),'fd closure evidence missing')
            summaries.append(dict(label=label,captured=captured,entries=len(entries),capacity_bypasses=bypasses,
                                  bucket_collision_excess=collisions,coverage=sorted(coverage),reverse_first=reverse_first,
                                  transitions={str(k):v for k,v in transitions.items()},placement=sorted(placement)))
    except (OSError,KeyError,ValueError,TypeError,IndexError,StopIteration) as error:
        errors.append('incomplete evidence: '+repr(error))
    return dict(status='HOLD' if errors else 'PASS',errors=errors,runs=summaries,
                verifier_sha256=digest(__file__),run=str(directory))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--build',type=Path);p.add_argument('--output',type=Path)
    a=p.parse_args();result=verify(a.run,a.build)
    if a.output:
        with a.output.open('x') as file:json.dump(result,file,indent=2);file.write('\n')
    print(json.dumps(result,indent=2));raise SystemExit(result['status']!='PASS')
