#!/usr/bin/env python3
"""Verify actual Linux NFQUEUE bytes, workers, verdicts and build/stop closure."""
import argparse, collections, hashlib, importlib.util, json, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
base=module('s206',ROOT/'tests/device/verify-s206-root-lanes.py')
oracle=base.oracle;chain=base.chain;rows=base.rows;records=base.records;digest=base.digest

def verify(directory,build):
 out=Path(directory);errors=[];coverage=set();latency=[];packet_count=0
 def require(ok,message):
  if not ok:errors.append(message)
 try:
  r=json.loads((out/'result.json').read_text());bp=Path(build);b=json.loads(bp.read_text())
  require(r['status']=='RAW_COMPLETE','runner incomplete')
  require(b['host_evidence'] is False,'real Product build mode')
  require(b['files']==chain.source_files(),'current source differs from built source')
  require(hashlib.sha256(chain.encode(b['files'])).hexdigest()==b['source_sha256'],'source hash closure')
  require(digest(bp.parent/'dirty.diff')==b['dirty_diff_sha256'],'dirty diff closure')
  for name,h in b['files'].items():
   if h is not None:require(digest(bp.parent/'source'/name)==h,'source snapshot '+name)
  for name,h in b['build_inputs'].items():
   require(digest(bp.parent/'source'/name)==h==digest(ROOT/name),'build input '+name)
  artifact=Path(b['artifact'])
  for name,h in b['artifact_hashes'].items():require(digest(artifact/name)==h,'Linux artifact '+name)
  for name,h in b['control_hashes'].items():require(digest(bp.parent/name)==h,'actual policy client '+name)
  require(digest(artifact/'product-vpp-artifact.properties')==r['artifact_manifest_sha256'],'executed artifact binding')
  require('SAKAMOTO_PRODUCT_HOST_EVIDENCE:BOOL=OFF' in (artifact/'plugin-build/CMakeCache.txt').read_text(),'default Product graph compile')
  require(b'product-packet-owner-guard' not in (artifact/'lib/vpp_plugins/product_core_plugin.so').read_bytes(),'no Owner Guard')
  require(b['started_ns']<b['completed_ns']<r['started_ns']<r['completed_ns'],'fresh build/run ordering')
  require('Linux' in (out/'kernel.txt').read_text() and 'uid=0' in (out/'kernel.txt').read_text(),'real Linux namespace endpoint')
  require(len(r['generations'])==len(set(r['generations']))>0,'unique fresh generations')
  for index,generation_int in enumerate(r['generations']):
   generation=str(generation_int);label='g'+str(index);run=out/label
   trace=(run/'vpp.log').read_text();all_records=records(trace)
   captures=[d for d in all_records if d.get('event')=='capture'];tokens={d['obligation'] for d in captures}
   require(len(tokens)==len(captures)>0,'unique captured identity '+label)
   by_token=collections.defaultdict(list)
   for d in all_records:
    token=d.get('token',d.get('obligation'))
    if token in tokens:by_token[token].append(d)
   expected_vectors=collections.Counter();lane_counts=collections.Counter();remotes=0
   for token,items in by_token.items():
    events=[d for d in items if 'event' in d];names=[d['event'] for d in events];by={d['event']:d for d in events}
    cap=by['capture'];lane=int(cap['lane']);arrival=lane%2;owner=int(by['admit']['owner']);remote=arrival!=owner;remotes+=remote
    family=4 if lane<2 else 6;origin_thread=str(arrival+1);policy_thread=str(owner+1);lane_counts[lane]+=1
    coverage.add((family,int(by['admit']['protocol']),lane,owner,int(by['verdict']['verdict'])))
    require(int(cap['queue'])==176+lane and cap['thread']==cap['tls']==cap['polling_thread']==origin_thread,'actual lane capture binding '+token)
    expected=['capture','frame_accept','admit','owner_delivery','policy','terminal','completion_publish','completion_consume','verdict','buffer_free']
    if remote:expected+=['primary_publish','primary_accepted','primary_dequeue','completion_return_publish','completion_return_accepted']
    require(collections.Counter(names)==collections.Counter(expected),'exact one assignment/handoff/completion '+label+' '+token)
    order=['capture','frame_accept','admit']+(['primary_publish','primary_dequeue'] if remote else [])+['owner_delivery','policy','terminal','completion_publish']+(['completion_return_publish'] if remote else [])+['completion_consume','verdict','buffer_free']
    require(all(names.index(x)<names.index(y) for x,y in zip(order,order[1:])),'causal execution order '+token)
    for d in events:
     thread=policy_thread if d['event'] in ['primary_dequeue','owner_delivery','policy','terminal','completion_publish','completion_return_publish','completion_return_accepted'] else origin_thread
     require(d['thread']==thread,'actual worker '+token+' '+d['event'])
     if 'buffer' in d:require(d['buffer']==cap['buffer'],'same native buffer '+token)
     if 'generation' in d:require(d['generation']==generation,'generation preserved '+token)
     if 'packet' in d:require(d['packet']==cap['packet'],'packet identity preserved '+token)
     if 'lane' in d:require(d['lane']==str(lane),'origin lane preserved '+token)
    require(by['admit']['parse']==by['admit']['assignment']=='1','one parser/selector '+token)
    require(by['owner_delivery']['owner']==by['owner_delivery']['actual_worker']==str(owner) and by['owner_delivery']['match']=='1','canonical owner executes policy '+token)
    require(by['verdict']['verdict'] in ('0','1') and by['verdict']['owner']==str(owner),'origin-only verdict '+token)
    wanted_intent='1' if by['verdict']['verdict']=='1' else '2'
    require(by['policy']['verdict']==wanted_intent and by['policy']['rule']==('0' if wanted_intent=='1' else '230'),'real policy result '+token)
    require(by['completion_publish']['frame_bytes']=='32' and by['completion_consume']['producer_thread']==policy_thread,'same completion frame '+token)
    require(by['completion_publish']['intent']==by['completion_consume']['intent']==wanted_intent,'completion intent preserved '+token)
    if remote:
     require(by['primary_publish']['owner']==str(owner) and by['primary_publish']['target_thread']==policy_thread,'one correct primary target '+token)
     require(by['primary_publish']['primary']=='1' and by['primary_publish']['corrective']=='0' and by['primary_dequeue']['corrective']=='0','no corrective hop '+token)
     require(by['completion_return_publish']['target_thread']==by['completion_return_accepted']['target_thread']==origin_thread,'return targets origin worker '+token)
    facts=[d for d in items if 'stage' in d and 'event' not in d]
    require([d['stage'] for d in facts]==['admit','policy','terminal'],'three real graph stages '+token)
    raw=oracle.facts(facts[0]['raw']);require(oracle.owner(raw)==owner,'independent canonical owner '+token)
    require(raw['family']==family and raw['protocol'] in (6,17),'lane family envelope '+token)
    for d in facts:
     require(d['source']=='NFQ_CAPTURED' and d['owner']==str(owner),'immutable captured owner '+token)
     for k in ['uid','ifindex','context','availability','direction','provenance','completion_kind','queue_generation','packet_id','origin_lane']:
      require(d[k]==facts[0][k],'platform/completion roundtrip '+token+' '+k)
     for k,v in raw.items():require(d[k]==str(v),'wire facts '+token+' '+k)
    times=[int(d['mono_ns']) for d in facts]+[int(by['completion_consume']['mono_ns'])]
    require(times[0]>0 and times==sorted(times),'native monotonic order '+token)
    latency.append({'generation':generation,'lane':lane,'owner':owner,'milliseconds':round((times[-1]-times[0])/1e6,3)})
    for thread,node in [(arrival+1,'admit'),(owner+1,'policy'),(owner+1,'terminal'),(arrival+1,'origin-completion')]:expected_vectors[(thread,'product-packet-'+node)]+=1
   runtime=(run/'runtime.txt').read_text();thread=None;vectors={}
   for line in runtime.splitlines():
    m=re.match(r'Thread (\d+) ',line)
    if m:thread=int(m[1])
    m=re.match(r'(product-packet-[a-z-]+)\s+active\s+(\d+)\s+(\d+)',line)
    if m:vectors[(thread,'product-packet-origin-completion' if m[1]=='product-packet-origin-completi' else m[1])]=int(m[3])
   require(vectors==dict(expected_vectors),'actual VLIB vector conservation '+label)
   require("unknown node name: 'product-packet-owner-guard'" in runtime,'Owner Guard absent '+label)
   completion=rows(runtime,'completion.status ')[0];primary=rows(runtime,'primary.status ')[0];lanes=rows(runtime,'root.lane ')
   for k,v in dict(generation=generation,pending=0,frames=0,buffers=0,obligations=0,verdicts=len(tokens),duplicate=0,stale=0,local=len(tokens)-remotes,remote=remotes,frame_bytes=32).items():require(completion[k]==str(v),'completion ledger '+label+' '+k)
   for k,v in dict(generation=generation,published=remotes,received=remotes,rejected=0,owner_checks=len(tokens),owner_failures=0,returns=remotes,pending_returns=0,handoff_debt=0,credit0=32,credit1=32).items():require(primary[k]==str(v),'primary ledger '+label+' '+k)
   for node,event in [('product-packet-policy','policy'),('product-packet-origin-completion','completion_consume')]:
    identity=re.search(r'node '+node+r', type internal, state active, index (\d+)',runtime)
    require(identity is not None,'native node identity '+node)
    if identity:require(all(d['node']==identity[1] for d in all_records if d.get('event')==event),'actual node index '+node)
   initial=rows((run/'initial.txt').read_text(),'root.lane ')
   require(len(initial)==4 and len({d['fd'] for d in initial})==4 and all(d['ready']=='1' for d in initial),'four independent sockets '+label)
   for d in lanes:
    lane=int(d['lane']);require(d['worker']==str(lane%2) and d['family']==str(4 if lane<2 else 6) and d['family_lane']==str(lane%2),'frozen family placement '+label)
    if lane_counts[lane]:
     actual_thread=re.search(r'^'+str(lane%2+1)+r'\s+vpp_wk_\d+\s+workers\s+\d+\s+other \(0\)\s+(\d+)',runtime,re.M)
     require(d['callback_thread']==d['callback_tls']==d['thread']==str(lane%2+1) and actual_thread is not None and d['cpu']==actual_thread[1],'actual selected thread/CPU '+label+' '+str(lane))
    for k in ('captured','submitted','verdicts','succeeded','returns'):require(int(d[k])==lane_counts[lane],'lane conservation '+label+' '+str(lane)+' '+k)
    require(d['pending']==d['failed']==d['duplicate']=='0','lane zero debts '+label)
    require(d['ready']=='1' and int(d['fd'])>=0,'active independent fd '+label)
   packet_count+=len(tokens)
   require(all(v in (-1,-16) for v in json.loads((run/'queues-busy.json').read_text()).values()),'live queues refuse foreign binding '+label)
   require(all(v==0 for v in json.loads((run/'queues-free.json').read_text()).values()),'all queues rebind after close '+label)
   closed=rows((run/'closed.txt').read_text(),'root.lane ')
   require(len(closed)==4 and all(d['fd']=='-1' and d['ready']==d['pending']=='0' for d in closed),'closed independent lanes '+label)
   before=dict(l.split(' ',1) for l in (run/'fds-before.txt').read_text().splitlines())
   after=dict(l.split(' ',1) for l in (run/'fds-closed.txt').read_text().splitlines())
   for d in initial:
    require(before[d['fd']].startswith('socket:[') and before[d['fd']] not in after.values(),'actual origin socket gone '+label)
   stop=json.loads((run/'stop.json').read_text());require(stop['process_absent'] is True,'process exit '+label)
   hooks=(run/'hooks.txt').read_text();clean=(run/'hooks-after.txt').read_text()
   for span in ('176:177','178:179'):
    for hook in ('INPUT','OUTPUT'):
     for proto in ('udp','tcp'):
      require(any(l.startswith('-A '+hook+' ') and '-p '+proto+' ' in l and '--queue-balance '+span in l for l in hooks.splitlines()),'ordinary hook rule '+label+' '+span+' '+hook+' '+proto)
   require(not any(l.startswith('-A ') for l in clean.splitlines()),'hooks removed '+label)
   cases=[c for c in r['cases'] if c['generation']==generation_int]
   require(len(cases)==2 and {c['blocked'] for c in cases}=={True,False},'allow and drop endpoint cases '+label)
   for c in cases:
    require(c['delivered']==(not c['blocked']) and c['endpoint']==([] if c['blocked'] else [c['nonce']]),'independent endpoint result '+label)
    require(int(c['nonce'].rsplit('-',1)[1])>r['started_ns'],'fresh endpoint nonce '+label)
    matched=[]
    for token,items in by_token.items():
     admit=next(d for d in items if d.get('stage')=='admit' and 'event' not in d)
     verdict=next(d for d in items if d.get('event')=='verdict')
     if admit['src_port']==str(c['source_port']) and admit['dst_port']=='40606' and admit['direction']=='3' and verdict['verdict']==str(int(not c['blocked'])):
      matched.append(admit)
    require(bool(matched),'actual OUTPUT matching endpoint case '+label)
    require(all(int(d['owner'])==c['owner'] and int(d['origin_lane'])==c['lane'] and int(d['family'])==c['family'] and int(d['protocol'])==c['protocol'] for d in matched),'case lane/owner binding '+label)
    if not c['blocked'] or c['protocol']==17:
     require(any(c['nonce'].encode().hex() in d['raw'] for d in matched),'wire nonce binding '+label)
    else:
     require(all(int(d['tcp_flags'])==2 for d in matched),'blocked real TCP SYN '+label)
  require(coverage=={(4 if lane<2 else 6,proto,lane,owner,verdict) for lane in range(4) for proto in (6,17) for owner in (0,1) for verdict in (0,1)},'dual-stack protocol/lane/owner/allow-drop coverage')
 except (OSError,KeyError,ValueError,StopIteration,IndexError) as e:errors.append('incomplete evidence '+repr(e))
 return dict(status='HOLD' if errors else 'PASS',errors=errors,coverage=sorted(coverage),packets=packet_count,generations=len(r.get('generations',[])),verifier_sha256=digest(__file__))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path);a=p.parse_args();r=verify(a.run,a.build);text=json.dumps(r,indent=2)+'\n'
 if a.output:a.output.write_text(text)
 print(text);raise SystemExit(r['status']!='PASS')
