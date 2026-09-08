#!/usr/bin/env python3
"""Verify real origin-lane Completion Frame ordering, identity and settlement."""
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
 return [dict(part.split('=',1) for part in line.split()[1:] if '=' in part) for line in text.splitlines() if line.startswith(('s203 ','s204 ','s216 '))]
def verify(directory,request=None):
 out=Path(directory);errors=[]
 def require(ok,message):
  if not ok:errors.append(message)
 try:
  r=json.loads((out/'result.json').read_text());require(r['status']=='RAW_COMPLETE','runner incomplete')
  require(r['source']=='NFQ_CAPTURED' and r['scope']=='single-lane-owner-local','wire/local scope')
  require(r['negative_scope']=='remote-owner unsupported packet closes on arrival; not remote policy acceptance','closed-path scope')
  if request:
   q=json.loads(Path(request).read_text());bp=Path(q['build']);b=json.loads(bp.read_text())
   require(str(out.resolve())==q['run_dir'],'request run directory')
   require(q['task']=='SAKAMOTO-204','request task')
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
    require({Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}==installed,'APK native closure')
   stage=props(bp.parent/'stage/product-stage.properties')
   for label in ['first','restart']:
    running=props(out/(label+'.properties'))
    require(running['artifact']==stage['artifactId'] and running['version']==stage['vppRevision'],'running artifact '+label)
    require(running['adapterReadiness']=='root-nfqueue-udp4-owner-local','readiness scope '+label)
   for key in ['allow_nonce','second_nonce','recover_nonce','unsupported_remote_nonce','restart_nonce']:
    require(int(r[key].rsplit('-',1)[1])>q['created_ns'],'fresh packet '+key)
   require(r['serial']==q['serial'],'device identity')
  require(r['generation']!=r['restart_generation'],'fresh restart generation')
  for label,count,probe_count,generation in [('before-stop',4,2,r['generation']),('restart-before-stop',1,0,r['restart_generation'])]:
   trace=(out/(label+'-vpp-stdout.log')).read_text();all_records=records(trace)
   real=[d for d in all_records if d.get('source')=='NFQ_CAPTURED']
   grouped=collections.defaultdict(list)
   for d in real:
    token=d.get('token',d.get('obligation'));require(token is not None,'missing obligation token')
    grouped[token].append(d)
   require(len(grouped)==count,'real obligation count '+label)
   for token,items in grouped.items():
    events=[d for d in items if 'event' in d];names=[d['event'] for d in events]
    captured=next(d for d in events if d['event']=='capture');packet=int(captured['packet'])
    closed=count==4 and packet==4
    expected=['capture','frame_accept','admit']+([] if closed else ['policy'])+['terminal','completion_publish','completion_consume','verdict','buffer_free']
    require(names==expected,'native completion order '+label+' '+token)
    by_event={d['event']:d for d in events}
    require(by_event['admit']['parse']=='1' and by_event['admit']['assignment']=='1','one parser/selector '+token)
    require(by_event['admit']['owner']==('1' if closed else '0'),'selected owner '+token)
    for d in events:
     require(d.get('thread')=='1','origin/producer thread '+token)
     if 'buffer' in d:require(d['buffer']==captured['buffer'],'same native buffer through completion '+token)
     if 'generation' in d:require(d['generation']==generation,'generation carried '+token)
     if 'packet' in d:require(d['packet']==str(packet),'packet ID carried '+token)
     if 'lane' in d:require(d['lane']=='0','origin lane '+token)
    require(by_event['completion_publish']['frame_bytes']=='32','bounded typed frame '+token)
    require(by_event['completion_consume']['producer_thread']=='1','local producer '+token)
    require(by_event['completion_publish']['intent']==by_event['completion_consume']['intent']==('2' if closed else '1'),'intent preserved '+token)
    require(by_event['verdict']['verdict']==('0' if closed else '1'),'native verdict '+token)
    fact_records=[d for d in items if 'stage' in d and 'event' not in d]
    require([d['stage'] for d in fact_records]==(['admit','terminal'] if closed else ['admit','policy','terminal']),'real parser/policy/terminal facts '+token)
    raw=oracle.facts(fact_records[0]['raw'])
    for d in fact_records:
     for k,v in raw.items():require(d[k]==str(v),'packet facts '+token+' '+k)
   replays=[d for d in all_records if d.get('source')=='COMPLETION_REPLAY']
   require(sum(d.get('event')=='completion_consume' for d in replays)==probe_count,'replay native consume '+label)
   require(sum(d.get('event')=='buffer_free' for d in replays)==probe_count,'replay carriers returned '+label)
   rejects=[d for d in replays if d.get('event')=='completion_reject']
   require(len(rejects)==probe_count,'replay rejected '+label)
   if probe_count:
    require([d['reason'] for d in rejects]==['duplicate','stale_generation_or_lane'],'explicit duplicate/stale partition')
    require(rejects[0]['packet']=='1' and rejects[1]['packet']=='2','non-last duplicate identity')
    require(int(rejects[1]['generation'])==int(generation)^(1<<32),'full 64-bit stale generation')
    require(rejects[-1]['duplicate']=='1' and rejects[-1]['stale']=='1','rejection counters')
   runtime=(out/(label+'-vpp-runtime.txt')).read_text();thread=None;vectors={}
   identity=re.search(r'node product-packet-origin-completion, type internal, state active, index (\d+)',runtime)
   if request:
    require(identity is not None,'full completion node identity '+label)
    if identity:require(all(d['node']==identity[1] for d in all_records if d.get('event')=='completion_consume'),'actual completion node index '+label)
    require('product-packet-terminal (' in runtime,'native terminal-to-completion edge '+label)

   for line in runtime.splitlines():
    m=re.match(r'Thread (\d+) ',line)
    if m:thread=int(m[1])
    m=re.match(r'(product-packet-[a-z-]+)\s+active\s+(\d+)\s+(\d+)',line)
    if m:
     require(1<=int(m[2])<=int(m[3]),'real node calls '+m[1]);vectors[(thread,'product-packet-origin-completion' if m[1]=='product-packet-origin-completi' else m[1])]=int(m[3])
   require(vectors=={(1,'product-packet-'+name):n for name,n in [('admit',count),('policy',count-1 if count==4 else count),('terminal',count),('origin-completion',count+probe_count)]},'actual VLIB completion node vectors '+label)
   cli=(out/(label+'-completion.txt')).read_text()
   line=next(l for l in cli.splitlines() if l.startswith('completion.status '));status=dict(x.split('=',1) for x in line.split()[1:])
   for k,v in dict(generation=generation,pending=0,frames=0,buffers=0,obligations=0,verdicts=count,duplicate=probe_count//2,stale=probe_count//2,local=count,remote=0,frame_bytes=32).items():require(status[k]==str(v),'completion ledger '+label+' '+k)
  for label,key,delivered in [('allow','allow_nonce',True),('second','second_nonce',True),('recover','recover_nonce',True),('remote-closed','unsupported_remote_nonce',False),('restart','restart_nonce',True)]:
   probe=props(out/(label+'-probe.properties'));endpoint=(out/(label+'-endpoint.log')).read_text()
   require(probe['nonce']==r[key],'app nonce '+label)
   require((r[key] in endpoint)==delivered,'endpoint delivery '+label)
  for label in ['first','restart']:
   require('productRootNfqueueResidueClean=true' in (out/(label+'-cleanup.properties')).read_text(),'hook/fd residue '+label)
   require('libvpp_runtime.so' not in (out/(label+'-process-after.txt')).read_text(),'process residue '+label)
 except (OSError,KeyError,ValueError,StopIteration,IndexError) as e:errors.append('incomplete evidence '+str(e))
 return dict(status='HOLD' if errors else 'PASS',errors=errors,verifier_sha256=digest(__file__),facts_oracle_sha256=digest(ROOT/'tests/device/verify-s216-metadata.py'))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--request',type=Path);p.add_argument('--output',type=Path);a=p.parse_args();r=verify(a.run,a.request);text=json.dumps(r,indent=2)+'\n'
 if a.output:a.output.write_text(text)
 print(text);raise SystemExit(r['status']!='PASS')
