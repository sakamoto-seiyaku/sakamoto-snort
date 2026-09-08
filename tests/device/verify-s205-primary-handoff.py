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
def verify(directory,request=None):
 out=Path(directory);errors=[];latency=[]
 def require(ok,message):
  if not ok:errors.append(message)
 try:
  r=json.loads((out/'result.json').read_text());require(r['status']=='RAW_COMPLETE','runner incomplete')
  require(r['source']=='NFQ_CAPTURED' and r['scope']=='single-lane-primary-handoff','wire/local scope')
  require(r['negative_scope']=='forced owner delivery mismatch drops without another handoff','closed-path scope')
  if request:
   q=json.loads(Path(request).read_text());bp=Path(q['build']);b=json.loads(bp.read_text())
   require(str(out.resolve())==q['run_dir'],'request run directory')
   require(q['task']=='SAKAMOTO-205','request task')
   require(digest(bp)==q['build_sha256'],'build witness')
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
    require(b'product-packet-owner-guard' not in z.read('lib/arm64-v8a/libproduct_core_plugin.so'),'legacy Owner Guard registered in product')
    require({Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}==installed,'APK native closure')
   stage=props(bp.parent/'stage/product-stage.properties')
   for label in ['first','restart']:
    running=props(out/(label+'.properties'))
    require(running['artifact']==stage['artifactId'] and running['version']==stage['vppRevision'],'running artifact '+label)
    require(running['adapterReadiness']=='root-nfqueue-udp4-owner-directed','readiness scope '+label)
   for key in ['local_nonce','remote_nonce','remote_repeat_nonce','misroute_nonce','recover_nonce','restart_nonce']:
    require(int(r[key].rsplit('-',1)[1])>q['created_ns'],'fresh packet '+key)
   require(r['serial']==q['serial'],'device identity')
  require(r['generation']!=r['restart_generation'],'fresh restart generation')
  for label,count,probe_count,generation in [('before-stop',5,2,r['generation']),('restart-before-stop',1,0,r['restart_generation'])]:
   trace=(out/(label+'-vpp-stdout.log')).read_text();all_records=records(trace)
   captures=[d for d in all_records if d.get('source')=='NFQ_CAPTURED' and d.get('event')=='capture']
   tokens={d['obligation'] for d in captures};require(len(tokens)==count,'real captured obligation count '+label)
   grouped=collections.defaultdict(list)
   for d in all_records:
    token=d.get('token',d.get('obligation'))
    if token in tokens and d.get('source') in [None,'NFQ_CAPTURED']:grouped[token].append(d)
   for token,items in grouped.items():
    events=[d for d in items if 'event' in d];names=[d['event'] for d in events]
    captured=next(d for d in events if d['event']=='capture');packet=int(captured['packet'])
    local=count==5 and packet==1;fault=count==5 and packet==4;remote=not local
    producer='1' if local or fault else '2'
    expected=['capture','frame_accept','admit','owner_delivery','policy','terminal','completion_publish','completion_consume','verdict','buffer_free']
    if remote:expected+=['primary_publish','primary_accepted','primary_dequeue']
    if producer=='2':expected+=['completion_return_publish','completion_return_accepted']
    require(collections.Counter(names)==collections.Counter(expected),'one visit/one handoff/completion '+label+' '+token)
    by={d['event']:d for d in events}
    order=['capture','frame_accept','admit']+(['primary_publish','primary_dequeue'] if remote else [])+['owner_delivery','policy','terminal','completion_publish']+(['completion_return_publish'] if producer=='2' else [])+['completion_consume','verdict','buffer_free']
    require(all(names.index(x)<names.index(y) for x,y in zip(order,order[1:])),'causal native event order '+token)
    require(by['admit']['parse']=='1' and by['admit']['assignment']=='1','single parse/selector '+token)
    require(by['admit']['owner']==('0' if local else '1'),'sole canonical owner '+token)
    for d in events:
     event=d['event'];thread='1'
     if event in ['primary_dequeue','owner_delivery','policy','terminal','completion_publish','completion_return_publish','completion_return_accepted']:thread=producer
     require(d['thread']==thread,'actual execution thread '+token+' '+event)
     if 'buffer' in d:require(d['buffer']==captured['buffer'],'retained native buffer '+token)
     if 'generation' in d:require(d['generation']==generation,'generation carried '+token)
     if 'packet' in d:require(d['packet']==str(packet),'packet ID carried '+token)
     if 'lane' in d:require(d['lane']=='0','origin lane '+token)
    if remote:
     require(by['primary_publish']['owner']=='1' and by['primary_publish']['target_thread']==producer,'selected target / explicit fault '+token)
     require(by['primary_publish']['primary']=='1' and by['primary_publish']['corrective']=='0','one primary/no corrective '+token)
     require(by['primary_dequeue']['owner']=='1' and by['primary_dequeue']['corrective']=='0','owner assignment retained '+token)
     require(names.index('primary_publish')<names.index('primary_accepted'),'primary accepted after publish '+token)
    require(by['owner_delivery']['owner']==('0' if local else '1') and by['owner_delivery']['actual_worker']==str(int(producer)-1),'receiver uses current worker '+token)
    require(by['owner_delivery']['match']==('0' if fault else '1'),'delivery validation '+token)
    require(by['policy']['stage']==('0' if fault else '2'),'policy skipped only for implementation delivery error '+token)
    if fault:require(by['policy']['verdict']=='0' and by['policy']['rule']=='0','mismatch is runtime drop, not policy verdict')
    require(by['completion_publish']['frame_bytes']=='32','same S204 frame '+token)
    require(by['completion_consume']['producer_thread']==producer,'actual terminal producer '+token)
    require(by['completion_publish']['intent']==by['completion_consume']['intent']==('2' if fault else '1'),'intent preserved '+token)
    require(by['verdict']['verdict']==('0' if fault else '1'),'origin-only native verdict '+token)
    if producer=='2':
     require(by['completion_return_publish']['target_thread']=='1' and by['completion_return_accepted']['target_thread']=='1','return to origin '+token)
    facts=[d for d in items if 'stage' in d and 'event' not in d]
    require([d['stage'] for d in facts]==['admit','policy','terminal'],'actual three packet nodes '+token)
    raw=oracle.facts(facts[0]['raw']);require(raw['src_port']==(30001 if local else 30000),'controlled owner flow '+token)
    require(oracle.owner(raw)==int(by['admit']['owner']),'canonical selection matches raw packet '+token)
    for d in facts:
     require(d['owner']==by['admit']['owner'],'immutable owner assignment '+token)
     require(d['thread']==('1' if d['stage']=='admit' else producer),'facts on actual worker '+token)
     for k in ['uid','ifindex','context','availability','direction','provenance','completion_kind','queue_generation','packet_id','origin_lane']:
      require(d[k]==facts[0][k],'platform/obligation roundtrip '+token+' '+k)
     for k,v in raw.items():require(d[k]==str(v),'packet facts '+token+' '+k)
    if 'mono_ns' in facts[0] and 'mono_ns' in by['completion_consume']:
     times=[int(d['mono_ns']) for d in facts]+[int(by['completion_consume']['mono_ns'])]
     require(times[0]>0 and times==sorted(times),'native monotonic event order '+token)
     latency.append(dict(generation=generation,packet=packet,producer_thread=producer,admit_to_policy_ms=round((times[1]-times[0])/1e6,3),policy_to_terminal_ms=round((times[2]-times[1])/1e6,3),terminal_to_origin_ms=round((times[3]-times[2])/1e6,3),admit_to_origin_ms=round((times[3]-times[0])/1e6,3)))
   replays=[d for d in all_records if d.get('source')=='COMPLETION_REPLAY']
   require(sum(d.get('event')=='completion_consume' for d in replays)==probe_count,'replay native consume '+label)
   require(sum(d.get('event')=='buffer_free' for d in replays)==probe_count,'replay carriers returned '+label)
   rejects=[d for d in replays if d.get('event')=='completion_reject'];require(len(rejects)==probe_count,'replay rejects '+label)
   if probe_count:
    require([d['reason'] for d in rejects]==['duplicate','stale_generation_or_lane'],'duplicate/stale partition')
    require(rejects[0]['packet']=='2' and rejects[1]['packet']=='3','remote completed identity replay')
    require(int(rejects[1]['generation'])==int(generation)^(1<<32),'64-bit generation preserved')
    require(rejects[-1]['duplicate']=='1' and rejects[-1]['stale']=='1','replay counters')
   runtime=(out/(label+'-vpp-runtime.txt')).read_text();thread=None;vectors={}
   for line in runtime.splitlines():
    m=re.match(r'Thread (\d+) ',line)
    if m:thread=int(m[1])
    m=re.match(r'(product-packet-[a-z-]+)\s+active\s+(\d+)\s+(\d+)',line)
    if m:vectors[(thread,'product-packet-origin-completion' if m[1]=='product-packet-origin-completi' else m[1])]=int(m[3])
   expected={(1,'product-packet-admit'):count,(1,'product-packet-origin-completion'):count+probe_count,(2,'product-packet-policy'):3 if count==5 else 1,(2,'product-packet-terminal'):3 if count==5 else 1}
   if count==5:expected.update({(1,'product-packet-policy'):2,(1,'product-packet-terminal'):2})
   require(vectors==expected,'actual per-worker VLIB vectors '+label)
   require("unknown node name: 'product-packet-owner-guard'" in runtime,'Owner Guard absent '+label)
   for name,event in [('product-packet-policy','primary_dequeue'),('product-packet-origin-completion','completion_consume')]:
    identity=re.search(r'node '+name+r', type internal, state active, index (\d+)',runtime)
    require(identity is not None,'native node identity '+name)
    if identity:require(all(d['node']==identity[1] for d in all_records if d.get('event')==event),'actual receiver node index '+name)
   def status(name,prefix):
    line=next(l for l in (out/(label+'-'+name+'.txt')).read_text().splitlines() if l.startswith(prefix+' '));return dict(x.split('=',1) for x in line.split()[1:])
   completion=status('completion','completion.status')
   for k,v in dict(generation=generation,pending=0,frames=0,buffers=0,obligations=0,verdicts=count,duplicate=probe_count//2,stale=probe_count//2,local=2 if count==5 else 0,remote=3 if count==5 else 1,frame_bytes=32).items():require(completion[k]==str(v),'completion ledger '+label+' '+k)
   primary=status('primary','primary.status')
   for k,v in dict(generation=generation,published=4 if count==5 else 1,received=4 if count==5 else 1,rejected=0,owner_checks=count,owner_failures=1 if count==5 else 0,returns=3 if count==5 else 1,deferred=0,retries=0,pending_returns=0,handoff_debt=0,credit0=32,credit1=32).items():require(primary[k]==str(v),'primary/return ledger '+label+' '+k)
  for label,key,delivered in [('local','local_nonce',True),('remote','remote_nonce',True),('remote-repeat','remote_repeat_nonce',True),('misroute','misroute_nonce',False),('recover','recover_nonce',True),('restart','restart_nonce',True)]:
   probe=props(out/(label+'-probe.properties'));endpoint=(out/(label+'-endpoint.log')).read_text()
   require(probe['nonce']==r[key],'app nonce '+label)
   require((r[key] in endpoint)==delivered,'endpoint delivery '+label)
  for label in ['first','restart']:
   require('productRootNfqueueResidueClean=true' in (out/(label+'-cleanup.properties')).read_text(),'hook/fd residue '+label)
   require('libvpp_runtime.so' not in (out/(label+'-process-after.txt')).read_text(),'process residue '+label)
 except (OSError,KeyError,ValueError,StopIteration,IndexError) as e:errors.append('incomplete evidence '+str(e))
 return dict(status='HOLD' if errors else 'PASS',errors=errors,diagnostic_latency_ms=latency,verifier_sha256=digest(__file__),facts_oracle_sha256=digest(ROOT/'tests/device/verify-s216-metadata.py'))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--request',type=Path);p.add_argument('--output',type=Path);a=p.parse_args();r=verify(a.run,a.request);text=json.dumps(r,indent=2)+'\n'
 if a.output:a.output.write_text(text)
 print(text);raise SystemExit(r['status']!='PASS')
