#!/usr/bin/env python3
"""S207 Pixel real wire assignment, immutable metadata and stop verification."""
import argparse, collections, hashlib, importlib.util, json, re, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
base=module('s206',ROOT/'tests/device/verify-s206-root-lanes.py')
oracle=base.oracle;chain=base.chain;rows=base.rows;records=base.records;digest=base.digest;props=base.props
assignment_oracle=module('owner_oracle',ROOT/'tests/device/s207-owner-oracle.py')
diagnostics=module('diagnostic_verify',ROOT/'tests/device/s207-diagnostic-verify.py')
oracle.owner=assignment_oracle.owner

def verify(directory,build):
 out=Path(directory);errors=[];coverage=set();latency=[];packet_count=0
 def require(ok,message):
  if not ok:errors.append(message)
 try:
  r=json.loads((out/'result.json').read_text());bp=Path(build);b=json.loads(bp.read_text())
  require(r['status']=='RAW_COMPLETE' and r['scope']=='canonical-owner-tcp-udp-echo','runner scope/completion')
  require(r['source']=='NFQ_CAPTURED' and r['profile']=='root' and r['serial']=='28201JEGR0XPAJ','actual capture/device/profile')
  require(b['files']==chain.source_files(),'current source differs from built source')
  require(hashlib.sha256(chain.encode(b['files'])).hexdigest()==b['source_sha256'],'source hash closure')
  require(digest(bp.parent/'dirty.diff')==b['dirty_diff_sha256'],'dirty diff closure')
  for name,h in b['files'].items():
   if h is not None:require(digest(bp.parent/'source'/name)==h,'source snapshot '+name)
  require(digest(b['apk'])==b['apk_sha256']==r['apk_sha256'],'fresh built APK')
  require((out/'installed-apk-sha256.txt').read_text().split()[0]==b['apk_sha256'],'installed APK')
  installed={Path(l.split()[1]).name:l.split()[0] for l in (out/'installed-native-sha256.txt').read_text().splitlines()}
  require(installed==b['native_sha256']==r['native_sha256'],'installed native closure')
  with zipfile.ZipFile(b['apk']) as z:
   require({Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}==installed,'APK native closure')
   require(all(name not in z.read('lib/arm64-v8a/libproduct_core_plugin.so') for name in (b'product-packet-owner-guard',b'product_packet_owner_guard',b'product_packet_owner_from_facts')),'no legacy Owner Guard/selector')
  stage=props(bp.parent/'stage/product-stage.properties')
  require(len(r['generations'])==len(set(r['generations']))>0,'fresh generations')
  require(r['wifi_before']==r['wifi_after'],'Wi-Fi restored')
  for index,generation in enumerate(r['generations']):
   label='g'+str(index);running=props(out/(label+'.properties'))
   require(running['generation']==generation and running['artifact']==stage['artifactId'] and running['version']==stage['vppRevision'],'running source artifact '+label)
   require(running['adapterReadiness']=='root-nfqueue-tcp-udp-echo-dualstack-q2w2','readiness '+label)
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
    coverage.add((family,int(by['admit']['protocol']),lane,owner))
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
    require(raw['family']==family and raw['protocol'] in (1,6,17,58),'lane family envelope '+token)
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
    require(d['ready']=='1' and int(d['fd'])>=0,'active four lanes '+label)
   assignment_rows=rows(trace,'s207 ')
   identity_by_flow=collections.defaultdict(list)
   for token,items in by_token.items():
    facts_rows=[d for d in items if d.get('stage')=='admit' and 'event' not in d]
    d=facts_rows[0];expected_assignment=assignment_oracle.assignment(oracle.facts(d['raw']))
    saved=[x for x in assignment_rows if x['token']==token]
    require([x['stage'] for x in saved]==['admit','policy','terminal'],'saved assignment stage order '+label+' '+token)
    for row in saved:
     for key,value in expected_assignment.items():require(row[key]==str(value),'typed assignment '+label+' '+token+' '+key)
    semantic=tuple((k,str(v)) for k,v in expected_assignment.items() if k!='source_is_a')
    identity_by_flow[semantic].append(d)
   for identity,packets in identity_by_flow.items():
    require({d['direction'] for d in packets}>={'1','3'},'real INPUT/OUTPUT for one assignment '+label)
    if int(packets[0]['protocol']) in (1,58):
     require(len({d['icmp_seq'] for d in packets})>=2,'Echo sequence excluded from session identity '+label)
     require({d['icmp_type'] for d in packets}==({'0','8'} if packets[0]['family']=='4' else {'128','129'}),'normalized Echo request/reply '+label)
    else:
     endpoint_pairs={(d['src'],d['src_port'],d['dst'],d['dst_port']) for d in packets}
     require(all((dst,dp,src,sp) in endpoint_pairs for src,sp,dst,dp in endpoint_pairs),'reverse transport packet same assignment '+label)
   require(primary.get('flows')=='0','zero actual flow entries '+label)
   packet_count+=len(tokens)
   require('metadata.check roundtrip=1 data_guard=1 length_guard=1 generation_guard=1 buffer_return=1' in (out/(label+'-initial.txt')).read_text(),'inline key/hash roundtrip '+label)
   if index==0:
    errors.extend(diagnostics.verify(json.loads((out/(label+'-diagnostic-cases.json')).read_text()),(out/(label+'-diagnostic-vpp.log')).read_text(),runtime,(out/(label+'-diagnostic-runtime.txt')).read_text()))
   closed=rows((out/(label+'-closed.txt')).read_text(),'root.lane ')
   require(len(closed)==4 and all(d['fd']=='-1' and d['ready']==d['pending']=='0' for d in closed),'all lanes closed '+label)
   before=(out/(label+'-fds-before.txt')).read_text();after=(out/(label+'-fds-closed.txt')).read_text()
   for d in initial:
    fd=re.search(r'\s'+d['fd']+r' -> (socket:\[\d+\])',before)
    require(fd is not None and fd[1] not in after,'original fd closed '+label)
   require(not (out/(label+'-kernel-queues-after-stop.txt')).read_text().strip(),'kernel queue residue '+label)
   require('SAKAMOTO_PRODUCT_' not in (out/(label+'-hooks-after-stop.txt')).read_text(),'hook residue '+label)
   require('productRootNfqueueResidueClean=true' in (out/(label+'-cleanup.properties')).read_text(),'supervisor stop residue '+label)
   require('libvpp_runtime.so' not in (out/(label+'-process-after.txt')).read_text(),'runtime process gone '+label)
   hooks=(out/(label+'-hooks.txt')).read_text()
   for span in ('176:177','178:179'):
    for hook in ('SAKAMOTO_PRODUCT_S176_OUTPUT','SAKAMOTO_PRODUCT_S178_INPUT'):
     for proto in ('udp','tcp','icmp' if span=='176:177' else 'ipv6-icmp'):
      require(any(l.startswith('-A '+hook+' ') and '-p '+proto+' ' in l and '--queue-balance '+span in l for l in hooks.splitlines()),'ordinary TCP/UDP/Echo hooks '+label)
   cases=[c for c in r['cases'] if c['generation']==generation]
   require(len(cases)==1,'one wire flow per generation '+label)
   c=cases[0]
   require(int(c['nonce'].rsplit('-',1)[1])>b['completed_ns'],'fresh nonce '+label)
   if c['protocol'] in (6,17):
    probe=props(out/(label+'-probe.properties'))
    require(probe['nonce']==c['nonce'] and probe['result']==('udp_echo_matched' if c['protocol']==17 else 'tcp_echo_matched'),'app echo '+label)
    endpoint=(out/(label+'-before-stop-endpoint.log')).read_text()
    require(sum(c['nonce'] in l for l in endpoint.splitlines())==1,'independent endpoint nonce '+label)
   else:require('2 received' in (out/(label+'-ping.txt')).read_text(),'real Echo reply '+label)
   matched=[d for d in all_records if d.get('stage')=='admit' and 'event' not in d and (c['nonce'].encode().hex() if c['protocol'] in (6,17) else c['pattern']) in d.get('raw','') and d['direction']=='3']
   require(bool(matched) and all(int(d['origin_lane'])==c['lane'] and int(d['owner'])==c['owner'] and int(d['family'])==c['family'] and int(d['protocol'])==c['protocol'] for d in matched),'wire endpoint assignment binding '+label)
  require(coverage=={(4 if lane<2 else 6,proto,lane,owner) for lane in range(4) for proto in (6,17,1 if lane<2 else 58) for owner in (0,1)},'dual-stack all protocol/lane/owner coverage')
 except (OSError,KeyError,ValueError,StopIteration,IndexError) as e:errors.append('incomplete evidence '+repr(e))
 return dict(status='HOLD' if errors else 'PASS',errors=errors,coverage=sorted(coverage),packets=packet_count,generations=len(r.get('generations',[])),verifier_sha256=digest(__file__))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path);a=p.parse_args();r=verify(a.run,a.build);text=json.dumps(r,indent=2)+'\n'
 if a.output:a.output.write_text(text)
 print(text);raise SystemExit(r['status']!='PASS')
