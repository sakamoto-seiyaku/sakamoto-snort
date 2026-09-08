"""Independent per-packet ownership and per-flow conservation oracle for S208."""
import collections, importlib.util, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
base=module('s208_base',ROOT/'tests/device/verify-s206-root-lanes.py')
ao=module('s208_assignment',ROOT/'tests/device/s207-owner-oracle.py')
rows=base.rows

def verify(trace,runtime,flow_dump,generation,fault_tokens=()):
    errors=[];coverage=set();states={};slots={};pool_addresses={};totals={w:dict(alloc=0,reuse=0,drop=0) for w in (0,1)}
    records=base.records(trace);captures=[d for d in records if d.get('event')=='capture']
    tokens={d['obligation'] for d in captures};by_token=collections.defaultdict(list)
    assignments=rows(trace,'s207 ');mutations=rows(trace,'s208 ')
    expected_vectors=collections.Counter();lane_counts=collections.Counter();remote_count=0;return_count=0
    fault_tokens=set(fault_tokens)
    def require(ok,message):
        if not ok:errors.append(message)
    require(len(captures)==len(tokens)>0,'one identity per captured packet')
    for d in records:
        token=d.get('token',d.get('obligation'))
        if token in tokens:by_token[token].append(d)
    # Flow updates are ordered by their actual owner-side records, not by origin
    # token numbers or host send order.
    facts_by_token={}
    for token,packet in by_token.items():
        events=[d for d in packet if 'event' in d];by={d['event']:d for d in events}
        cap=by['capture'];lane=int(cap['lane']);arrival=lane%2;owner=int(by['admit']['owner']);remote=arrival!=owner
        fault=token in fault_tokens;returned=remote and not fault
        remote_count+=remote;return_count+=returned;lane_counts[lane]+=1
        execution=arrival if fault else owner
        origin_thread=str(arrival+1);policy_thread=str(execution+1)
        names=['capture','frame_accept','admit','owner_delivery','policy','terminal','completion_publish','completion_consume','verdict','buffer_free']
        if remote:names+=['primary_publish','primary_accepted','primary_dequeue']
        if returned:names+=['completion_return_publish','completion_return_accepted']
        require(collections.Counter(d['event'] for d in events)==collections.Counter(names),'one native lifecycle '+token)
        order=['capture','frame_accept','admit']+(['primary_publish','primary_dequeue'] if remote else [])+['owner_delivery','policy','terminal','completion_publish']+(['completion_return_publish'] if returned else [])+['completion_consume','verdict','buffer_free']
        actual_order=[d['event'] for d in events]
        require(all(actual_order.index(x)<actual_order.index(y) for x,y in zip(order,order[1:])),'causal execution order '+token)
        require(cap['thread']==cap['tls']==cap['polling_thread']==origin_thread and cap['queue']==str(176+lane),'actual origin lane '+token)
        require(by['owner_delivery']['match']==str(int(not fault)) and by['owner_delivery']['actual_worker']==str(execution),'actual owner delivery '+token)
        if fault:require(remote and by['policy']['stage']==by['policy']['verdict']==by['policy']['rule']=='0' and by['verdict']['verdict']=='0','misdelivery skips policy evaluation and drops '+token)
        for d in events:
            thread=policy_thread if d['event'] in ('primary_dequeue','owner_delivery','policy','terminal','completion_publish','completion_return_publish','completion_return_accepted') else origin_thread
            require(d['thread']==thread,'worker '+token+' '+d['event'])
            if 'buffer' in d:require(d['buffer']==cap['buffer'],'retained native buffer '+token)
            if 'generation' in d:require(d['generation']==str(generation),'generation '+token)
            if 'packet' in d:require(d['packet']==cap['packet'],'packet identity '+token)
            if 'lane' in d:require(d['lane']==str(lane),'origin identity '+token)
        require(by['admit']['parse']==by['admit']['assignment']=='1','one parse/assignment '+token)
        if remote:
            require(by['primary_publish']['target_thread']==policy_thread and by['primary_publish']['primary']=='1' and by['primary_publish']['corrective']=='0','single primary target '+token)
        if returned:require(by['completion_return_publish']['target_thread']==by['completion_return_accepted']['target_thread']==origin_thread,'one origin return '+token)
        intent='1' if by['verdict']['verdict']=='1' else '2'
        require(by['policy']['verdict']==('0' if fault else intent) and by['terminal']['intent']==by['completion_publish']['intent']==by['completion_consume']['intent']==intent,'policy/terminal/verdict correspondence '+token)
        require(by['completion_publish']['frame_bytes']=='32' and by['completion_consume']['producer_thread']==policy_thread,'completion carrier '+token)
        facts=[d for d in packet if 'stage' in d and 'event' not in d]
        require([d['stage'] for d in facts]==['admit','policy','terminal'],'facts stage order '+token)
        raw=base.oracle.facts(facts[0]['raw']);assignment=ao.assignment(raw)
        times=[int(d['mono_ns']) for d in facts]+[int(by['completion_consume']['mono_ns'])]
        require(times[0]>0 and times==sorted(times),'native monotonic order '+token)
        require(assignment['owner']==owner and raw['family']==(4 if lane<2 else 6),'independent canonical owner/family '+token)
        for d in facts:
            require(d['source']=='NFQ_CAPTURED','actual kernel source '+token)
            for k,v in raw.items():require(d[k]==str(v),'parsed facts '+token+' '+k)
            for k in ('uid','ifindex','context','availability','direction','provenance','completion_kind','queue_generation','packet_id','origin_lane'):
                require(d[k]==facts[0][k],'immutable platform/completion '+token+' '+k)
        saved=[d for d in assignments if d['token']==token]
        require([d['stage'] for d in saved]==['admit','policy','terminal'],'assignment stage order '+token)
        for d in saved:
            for k,v in assignment.items():require(d[k]==str(v),'saved assignment '+token+' '+k)
        facts_by_token[token]=(raw,assignment,facts[0],by)
        coverage.add((raw['family'],raw['protocol'],lane,owner))
        for thread,node in ((arrival+1,'admit'),(execution+1,'policy'),(execution+1,'terminal'),(arrival+1,'origin-completi')):
            expected_vectors[(thread,'product-packet-'+node)]+=1
    require(fault_tokens<=tokens,'all requested faults captured')
    require(len(mutations)==len(tokens)-len(fault_tokens) and not any(d['token'] in fault_tokens for d in mutations),'one FlowEntry seam per eligible wire packet; no wrong-worker mutation')
    for event in mutations:
        token=event['token'];raw,a,platform,by=facts_by_token[token];owner=a['owner'];t=totals[owner]
        key=tuple((k,str(v)) for k,v in a.items() if k not in ('source_is_a','owner','hash','valid'))
        require(event['source']=='NFQ_CAPTURED' and event['generation']==str(generation),'flow provenance '+token)
        require(event['thread']==str(owner+1) and event['worker']==event['owner']==event['pool_worker']==str(owner),'current-worker pool '+token)
        require(event['buffer']==by['capture']['buffer'] and event['hash']==str(a['hash']),'same packet assignment at mutation '+token)
        require(pool_addresses.get(owner,event['pool'])==event['pool'],'one stable private pool '+token);pool_addresses[owner]=event['pool']
        if by['verdict']['verdict']=='0':
            t['drop']+=1
            require(event['event']=='early_drop' and event['status']=='7' and event['slot']=='4294967295','early DROP has no entry '+token)
            require(all(event[k]=='0' for k in ('created','reused','invalidated','stored_hash','stored_kind','packets','bytes')),'no early-DROP mutation '+token)
        else:
            require(event['event']=='observe' and event['status']=='0' and event['stored_kind']=='2' and event['stored_hash']==str(a['hash']),'stored typed assignment '+token)
            created=key not in states
            require(event['created']==str(int(created)) and event['reused']==str(int(not created)),'first actual creation '+token)
            if created:
                require((owner,event['slot']) not in slots,'unique live slot '+token)
                slots[(owner,event['slot'])]=key;t['alloc']+=1
                states[key]=dict(owner=owner,pool=event['pool'],slot=event['slot'],origin=a['source_is_a'],origin_dir=int(platform['direction']),uid=int(platform['uid']) if int(platform['availability'])&1 else 4294967295,context=int(platform['context']) if int(platform['availability'])&4 else 4294967295,packets=0,bytes=0,first=event['first_seen'],last=0,revision=event['revision'],snapshot=event['snapshot_hash'],assignment=a,history=[])
            else:t['reuse']+=1
            state=states[key]
            invalidated=not created and (state['revision'],state['snapshot'])!=(event['revision'],event['snapshot_hash'])
            require(event['invalidated']==str(int(invalidated)),'lazy policy epoch invalidation '+token)
            state['packets']+=1;state['bytes']+=raw['packet_length']
            direction=1 if a['source_is_a']==state['origin'] else 2
            for k,v in dict(slot=state['slot'],origin_is_a=state['origin'],flow_origin_dir=state['origin_dir'],device_dir=platform['direction'],flow_dir=direction,packets=state['packets'],bytes=state['bytes'],first_seen=state['first']).items():
                require(event[k]==str(v),'flow conservation '+token+' '+k)
            require(int(event['last_seen'])>=state['last'],'monotonic last-seen '+token)
            require(event['decision']==('1' if int(event['revision']) else '0'),'cache only applied policy view '+token)
            state.update(last=int(event['last_seen']),revision=event['revision'],snapshot=event['snapshot_hash'],last_dir=int(platform['direction']),flow_dir=direction,rule=by['policy']['rule'])
            state['history'].append(dict(event))
        require(event['active']==str(sum(s['owner']==owner for s in states.values())),'actual active entry count '+token)
        require(event['allocations']==str(t['alloc']) and event['reuse_count']==str(t['reuse']) and event['early_drops']==str(t['drop']),'worker mutation counters '+token)
    require(len(set(pool_addresses.values()))==len(pool_addresses),'distinct pools across workers')
    thread=None;actual_vectors={}
    for line in runtime.splitlines():
        m=re.match(r'Thread (\d+) ',line)
        if m:thread=int(m[1])
        m=re.match(r'(product-packet-[a-z-]+)\s+active\s+(\d+)\s+(\d+)',line)
        if m:actual_vectors[(thread,m[1])]=int(m[3])
    require(actual_vectors==dict(expected_vectors),'native VLIB vector conservation')
    require("unknown node name: 'product-packet-owner-guard'" in runtime,'no Owner Guard node')
    completion=rows(runtime,'completion.status ')[0];primary=rows(runtime,'primary.status ')[0]
    for k,v in dict(pending=0,frames=0,buffers=0,obligations=0,verdicts=len(tokens),duplicate=0,stale=0,local=len(tokens)-return_count,remote=return_count,frame_bytes=32).items():require(completion[k]==str(v),'completion '+k)
    for k,v in dict(published=remote_count,received=remote_count,rejected=0,owner_checks=len(tokens),owner_failures=len(fault_tokens),returns=return_count,pending_returns=0,handoff_debt=0,credit0=32,credit1=32,flows=len(states)).items():require(primary[k]==str(v),'primary/flow '+k)
    for lane in rows(runtime,'root.lane '):
        number=int(lane['lane'])
        require(lane['worker']==str(number%2) and lane['family']==str(4 if number<2 else 6),'frozen family placement')
        if lane_counts[number]:
            thread=re.search(r'^'+str(number%2+1)+r'\s+vpp_wk_\d+\s+workers\s+\d+\s+other \(0\)\s+(\d+)',runtime,re.M)
            require(thread is not None and lane['cpu']==thread[1] and lane['callback_thread']==lane['callback_tls']==lane['thread']==str(number%2+1),'actual callback CPU/thread')
        for k in ('captured','submitted','verdicts','succeeded','returns'):require(lane[k]==str(lane_counts[number]),'origin conservation '+str(number)+' '+k)
        require(lane['pending']==lane['failed']==lane['duplicate']=='0','origin debt')
    pools=rows(flow_dump,'flow.pool ');entries=rows(flow_dump,'flow.entry ')
    require(len(entries)==len(states),'actual table contains exactly observed identities')
    for pool in pools:
        owner=int(pool['worker']);t=totals[owner]
        require(pool['entries']==str(sum(s['owner']==owner for s in states.values())) and pool['allocations']==str(t['alloc']) and pool['reused']==str(t['reuse']) and pool['early_drops']==str(t['drop']),'actual final pool counters')
        require(pool['wrong_owner']==pool['capacity_drops']=='0','no mutation error')
    for entry in entries:
        key=slots[(int(entry['worker']),entry['slot'])];state=states[key];a=state['assignment']
        wanted=dict(kind=2,family=a['key_family'],protocol=a['key_protocol'],hash=a['hash'],key_a=a['key_a'],key_b=a['key_b'],port_a=a['port_a'],port_b=a['port_b'],origin_is_a=state['origin'],flow_origin_dir=state['origin_dir'],uid=state['uid'],context=state['context'],packets=state['packets'],bytes=state['bytes'],first_seen=state['first'],last_seen=state['last'],revision=state['revision'],snapshot_hash=state['snapshot'])
        for k,v in wanted.items():require(entry[k]==str(v),'actual stored entry '+k)
    return dict(errors=errors,coverage=sorted(coverage),packets=len(tokens),states=states,by_token=facts_by_token)
