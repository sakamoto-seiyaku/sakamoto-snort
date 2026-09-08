#!/usr/bin/env python3
"""Verify one real Primary Handoff and the same Completion Frame returning to origin."""
import argparse, collections, hashlib, importlib.util, json, re, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
oracle=module('s216_oracle',ROOT/'tests/device/verify-s216-metadata.py')
chain=module('product_chain',ROOT/'tests/evidence/product_chain.py')
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def props(p):return dict(l.split('=',1) for l in Path(p).read_text().splitlines() if '=' in l)
def records(text):
 return [dict(part.split('=',1) for part in line.split()[1:] if '=' in part) for line in text.splitlines() if line.startswith(('s203 ','s204 ','s205 ','s216 '))]
def rows(text,prefix):
 return [dict(x.split('=',1) for x in l.split()[1:] if '=' in x) for l in text.splitlines() if l.startswith(prefix)]
def verify(directory,request):
 out=Path(directory);errors=[];coverage=set();latency=[]
 def require(ok,message):
  if not ok:errors.append(message)
 try:
  r=json.loads((out/'result.json').read_text());q=json.loads(Path(request).read_text());bp=Path(q['build']);b=json.loads(bp.read_text())
  require(r['status']=='RAW_COMPLETE','runner incomplete')
  require(r['source']=='NFQ_CAPTURED' and r['scope']==q['scope']=='dual-stack-q2-w2','wire scope')
  require(q['task']=='SAKAMOTO-206' and q['family']==[4,6],'request scope')
  require(q['run_dir']==str(out.resolve()) and r['serial']==q['serial'],'run/device binding')
  require(digest(bp)==q['build_sha256'],'build witness changed')
  require(chain.source_files()==b['files'],'current source differs from build')
  require(hashlib.sha256(chain.encode(b['files'])).hexdigest()==b['source_sha256'],'source hash')
  require(digest(bp.parent/'dirty.diff')==b['dirty_diff_sha256'],'dirty source witness')
  for name,h in b['files'].items():
   if h is not None:require(digest(bp.parent/'source'/name)==h,'source snapshot '+name)
  require(b['started_ns']<b['completed_ns']<q['created_ns'],'source/build/request order')
  require(digest(b['apk'])==b['apk_sha256']==r['apk_sha256'],'artifact hash')
  require((out/'installed-apk-sha256.txt').read_text().split()[0]==b['apk_sha256'],'installed APK')
  installed={Path(l.split()[1]).name:l.split()[0] for l in (out/'installed-native-sha256.txt').read_text().splitlines()}
  require(installed==b['native_sha256']==r['native_sha256'],'native closure')
  with zipfile.ZipFile(b['apk']) as z:
   require(b'product-packet-owner-guard' not in z.read('lib/arm64-v8a/libproduct_core_plugin.so'),'Owner Guard in Product')
   require({Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}==installed,'APK native closure')
  stage=props(bp.parent/'stage/product-stage.properties')
  require(len(r['generations'])==len(set(r['generations']))==4,'four fresh generations')
  require(len(r['drain_probes'])==1,'in-flight lane closure proof')
  quiesce=(out/'g0-quiesce.txt').read_text()
  require(re.search(r'root.lane_close lane=0 state=draining pending=[1-9][0-9]*',quiesce) is not None,'busy origin lane retains its fd')
  for d in r['drain_probes']:
   require(int(d['nonce'].rsplit('-',1)[1])>q['created_ns'],'fresh drain nonce')
   require(d['result'] in ('udp_echo_matched','udp_datagram_failed'),'drain probe observation')
  for index,generation in enumerate(r['generations']):
   label='g'+str(index);running=props(out/(label+'.properties'))
   require(running['generation']==generation and running['artifact']==stage['artifactId'] and running['version']==stage['vppRevision'],'running identity '+label)
   require(running['adapterReadiness']==q['adapter_readiness']=='root-nfqueue-udp-dualstack-q2w2','readiness scope '+label)
   trace=(out/(label+'-before-stop-vpp-stdout.log')).read_text();all_records=records(trace)
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
    coverage.add((family,lane,owner))
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
    require(by['verdict']['verdict']=='1' and by['verdict']['owner']==str(owner),'origin-only ACCEPT '+token)
    require(by['completion_publish']['frame_bytes']=='32' and by['completion_consume']['producer_thread']==policy_thread,'same completion frame '+token)
    require(by['completion_publish']['intent']==by['completion_consume']['intent']=='1','completion intent preserved '+token)
    if remote:
     require(by['primary_publish']['owner']==str(owner) and by['primary_publish']['target_thread']==policy_thread,'one correct primary target '+token)
     require(by['primary_publish']['primary']=='1' and by['primary_publish']['corrective']=='0' and by['primary_dequeue']['corrective']=='0','no corrective hop '+token)
     require(by['completion_return_publish']['target_thread']==by['completion_return_accepted']['target_thread']==origin_thread,'return targets origin worker '+token)
    facts=[d for d in items if 'stage' in d and 'event' not in d]
    require([d['stage'] for d in facts]==['admit','policy','terminal'],'three real graph stages '+token)
    raw=oracle.facts(facts[0]['raw']);require(oracle.owner(raw)==owner,'independent canonical owner '+token)
    require(raw['family']==family and raw['protocol']==17,'lane family envelope '+token)
    for d in facts:
     require(d['source']=='NFQ_CAPTURED' and d['owner']==str(owner),'immutable captured owner '+token)
     for k in ['uid','ifindex','context','availability','direction','provenance','completion_kind','queue_generation','packet_id','origin_lane']:
      require(d[k]==facts[0][k],'platform/completion roundtrip '+token+' '+k)
     for k,v in raw.items():require(d[k]==str(v),'wire facts '+token+' '+k)
    times=[int(d['mono_ns']) for d in facts]+[int(by['completion_consume']['mono_ns'])]
    require(times[0]>0 and times==sorted(times),'native monotonic order '+token)
    latency.append({'generation':generation,'lane':lane,'owner':owner,'milliseconds':round((times[-1]-times[0])/1e6,3)})
    for thread,node in [(arrival+1,'admit'),(owner+1,'policy'),(owner+1,'terminal'),(arrival+1,'origin-completion')]:expected_vectors[(thread,'product-packet-'+node)]+=1
   runtime=(out/(label+'-before-stop-vpp-runtime.txt')).read_text();thread=None;vectors={}
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
   initial=rows((out/(label+'-initial.txt')).read_text(),'root.lane ')
   require(len(initial)==4 and len({d['fd'] for d in initial})==4 and all(d['ready']=='1' for d in initial),'four independent sockets '+label)
   for d in lanes:
    lane=int(d['lane']);require(d['worker']==str(lane%2) and d['family']==str(4 if lane<2 else 6) and d['family_lane']==str(lane%2),'frozen family placement '+label)
    if lane_counts[lane]:require(d['callback_thread']==d['callback_tls']==d['thread']==str(lane%2+1) and int(d['cpu'])==lane%2+1,'real thread/CPU '+label+' '+str(lane))
    for k in ('captured','submitted','verdicts','succeeded','returns'):require(int(d[k])==lane_counts[lane],'lane conservation '+label+' '+str(lane)+' '+k)
    require(d['pending']==d['failed']==d['duplicate']=='0','lane zero debts '+label)
    require(d['ready']==str(int(lane!=index)) and (d['fd']=='-1')==(lane==index),'isolated closed fd '+label)
   hooks=(out/(label+'-hooks.txt')).read_text()
   for tool,family,queue_range in [('iptables',4,'176:177'),('ip6tables',6,'178:179')]:
    for chain_name in ('SAKAMOTO_PRODUCT_S176_OUTPUT','SAKAMOTO_PRODUCT_S178_INPUT'):
     require(any(l.startswith('-A '+chain_name+' ') and '--queue-balance '+queue_range in l for l in hooks.splitlines()),'shared family INPUT/OUTPUT range '+label+' '+queue_range+' '+chain_name)
   survivor={(c['lane'],c['owner']) for c in r['cases'] if c['generation']==generation and '-survivor' in c['label']}
   require(survivor=={(lane,owner) for lane in range(4) if lane!=index for owner in (0,1)},'all survivor local/remote traffic '+label)
   for suffix in ['after-close','after-stop']:
    queues=(out/(label+'-kernel-queues-'+suffix+'.txt')).read_text()
    active={int(l.split()[0]) for l in queues.splitlines() if l.split() and l.split()[0].isdigit()}
    require((176+index not in active) if suffix=='after-close' else not active.intersection(range(176,180)),'kernel queue cleanup '+label+' '+suffix)
   require('SAKAMOTO_PRODUCT_' not in (out/(label+'-hooks-after-stop.txt')).read_text(),'both-family hook cleanup '+label)
   require('productRootNfqueueResidueClean=true' in (out/(label+'-cleanup.properties')).read_text(),'supervisor cleanup '+label)
   require('libvpp_runtime.so' not in (out/(label+'-process-after.txt')).read_text(),'native process cleanup '+label)
  require(coverage=={(4 if lane<2 else 6,lane,owner) for lane in range(4) for owner in (0,1)},'dual-stack every-lane local/remote coverage')
  for c in r['cases']:
   require(int(c['nonce'].rsplit('-',1)[1])>q['created_ns'],'fresh nonce '+c['label'])
   probe=props(out/(c['label']+'-probe.properties'));require(probe['nonce']==c['nonce'] and probe['result']=='udp_echo_matched','app endpoint success '+c['label'])
   idx=r['generations'].index(c['generation']);endpoint=(out/('g'+str(idx)+'-before-stop-endpoint.log')).read_text()
   require(sum(c['nonce'] in l for l in endpoint.splitlines())==1,'one actual endpoint echo '+c['label'])
   require(c['packets']==3,'OUTPUT and both INPUT captures '+c['label'])
 except (OSError,KeyError,ValueError,StopIteration,IndexError) as e:errors.append('incomplete evidence '+repr(e))
 return dict(status='HOLD' if errors else 'PASS',errors=errors,coverage=sorted(coverage),diagnostic_latency_ms=latency,verifier_sha256=digest(__file__))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--request',type=Path,required=True);p.add_argument('--output',type=Path);a=p.parse_args();r=verify(a.run,a.request);text=json.dumps(r,indent=2)+'\n'
 if a.output:a.output.write_text(text)
 print(text);raise SystemExit(r['status']!='PASS')
