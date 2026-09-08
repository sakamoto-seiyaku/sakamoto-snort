#!/usr/bin/env python3
"""S208 source, actual transport, owner-local flow state, and stop acceptance."""
import argparse, hashlib, importlib.util, json, re, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('flow',ROOT/'tests/device/s208-flow-verify.py')
flow=importlib.util.module_from_spec(spec);spec.loader.exec_module(flow)
base=flow.base;chain=base.chain;digest=base.digest;rows=base.rows

def verify(out,bp,platform):
 out=Path(out);bp=Path(bp);errors=[];coverage=set();packets=0;flows=0;r={}
 def require(ok,msg):
  if not ok:errors.append(msg)
 try:
  r=json.loads((out/'result.json').read_text());b=json.loads(bp.read_text())
  require(r['status']=='RAW_COMPLETE','runner incomplete')
  require(b['files']==chain.source_files(),'current product source changed')
  require(hashlib.sha256(chain.encode(b['files'])).hexdigest()==b['source_sha256'],'source hash')
  require(digest(bp.parent/'dirty.diff')==b['dirty_diff_sha256'],'dirty diff')
  for name,h in b['files'].items():
   if h is not None:require(digest(bp.parent/'source'/name)==h,'snapshot '+name)
  pixel=platform=='pixel'
  if pixel:
   require(r['source']=='NFQ_CAPTURED' and r['profile']=='root' and r['serial']=='28201JEGR0XPAJ','device provenance')
   require(digest(b['apk'])==b['apk_sha256']==r['apk_sha256']==(out/'installed-apk-sha256.txt').read_text().split()[0],'built/installed APK')
   installed={Path(l.split()[1]).name:l.split()[0] for l in (out/'installed-native-sha256.txt').read_text().splitlines()}
   require(installed==b['native_sha256']==r['native_sha256'],'installed native entries')
   with zipfile.ZipFile(b['apk']) as z:
    require({Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}==installed,'APK native entries')
   require(r['wifi_before']==r['wifi_after'],'Wi-Fi restoration')
   require(int(r['generations'][0])>int(base.props(out/'before.properties')['generation']),'fresh device generation')
   stage=base.props(bp.parent/'stage/product-stage.properties')
  else:
   require(b['host_evidence'] is False,'default product graph')
   artifact=Path(b['artifact'])
   for n,h in b['artifact_hashes'].items():require(digest(artifact/n)==h,'artifact '+n)
   for n,h in b['control_hashes'].items():require(digest(bp.parent/n)==h,'policy client '+n)
   for n,h in b['build_inputs'].items():require(digest(bp.parent/'source'/n)==h==digest(ROOT/n),'build input '+n)
   require(digest(artifact/'product-vpp-artifact.properties')==r['artifact_manifest_sha256'],'executed artifact')
   require('SAKAMOTO_PRODUCT_HOST_EVIDENCE:BOOL=OFF' in (artifact/'plugin-build/CMakeCache.txt').read_text(),'actual default compile')
   require(b['started_ns']<b['completed_ns']<r['started_ns']<r['completed_ns'],'fresh build/run')
   require('uid=0' in (out/'kernel.txt').read_text(),'namespace endpoint')
  require(len(r['generations'])==len(set(r['generations']))==len(r['cases'])>0,'unique generations')
  for i,c in enumerate(r['cases']):
   label='g'+str(i);generation=c['generation'];prefix=out/label
   def read(name):return (out/(label+'-'+name) if pixel else prefix/name).read_text()
   trace=read('before-stop-vpp-stdout.log' if pixel else 'vpp.log')
   runtime=read('before-stop-vpp-runtime.txt' if pixel else 'runtime.txt')
   final=read('flow-final.txt') if pixel else runtime
   x=flow.verify(trace,runtime,final,generation);errors.extend(label+': '+e for e in x['errors']);packets+=x['packets'];flows+=len(x['states'])
   if pixel:
    running=base.props(out/(label+'.properties'))
    require(running['generation']==str(generation) and running['artifact']==stage['artifactId'] and running['version']==stage['vppRevision'],'running source '+label)
   states=list(x['states'].values());require(len(states)==1,'one live transport identity '+label)
   state=states[0];history=state['history'];a=state['assignment']
   require({d['flow_dir'] for d in history}=={'1','2'},'actual forward/reverse '+label)
   require({d['device_dir'] for d in history}>={'1','3'},'INPUT/OUTPUT independent of flow direction '+label)
   require(any(d['invalidated']=='1' for d in history),'lazy revision re-evaluation '+label)
   port=str(c['source_port']);matched=[(raw,assignment,facts,by) for raw,assignment,facts,by in x['by_token'].values() if str(raw['src_port'])==port or str(raw['dst_port'])==port]
   require(bool(matched),'matching actual socket '+label)
   first=matched[0]
   require(int(first[2]['origin_lane'])==c['lane'] and first[1]['owner']==c['owner'],'reported lane/owner '+label)
   coverage.add((c['family'],c['protocol'],c['mode'],c['lane'],c['owner']))
   revisions=c['revisions'] if pixel else [2,3]
   require(revisions[1]>revisions[0],'successor revision '+label)
   previous=None
   for phase,revision in enumerate(revisions):
    snapshot=read(('r'+str(phase) if pixel else 'r'+str(revision))+'-flows.txt')
    entries=rows(snapshot,'flow.entry ');require(len(entries)==1,'actual phase table '+label)
    entry=entries[0];require(entry['revision']==str(revision),'phase revision '+label)
    if previous:
     for k in ('worker','slot','hash','kind','key_a','key_b','port_a','port_b','origin_is_a','flow_origin_dir','uid','context','first_seen'):require(entry[k]==previous[k],'identity retained across revision '+label+' '+k)
     require(int(entry['packets'])>int(previous['packets']) and int(entry['bytes'])>int(previous['bytes']),'counters continue across revision '+label)
    previous=entry
    nonce=c['nonces'][phase];wire=[by for raw,aa,facts,by in matched if nonce.encode().hex() in facts['raw']]
    require(int(nonce.rsplit('-',1)[1])>b['completed_ns'],'nonce created after build '+label)
    require(len(wire)>=2 and all(d['verdict']['verdict']=='1' for d in wire),'same socket nonce delivered through kernel '+label)
    if pixel:require(read('echo-'+str(phase)+'.txt')==nonce,'independent received nonce '+label)
   if not pixel:
    expected=c['nonces'] if c['mode']=='normal' else c['nonces'][1:]
    require(json.loads(read('endpoint.json'))==[n.encode().hex() for n in expected],'server receives only allowed nonces '+label)
   if c['mode']=='normal':
    require(all(d['entries']==d['allocations']=='0' for d in rows(read('drop-flows.txt'),'flow.pool ')),'DROP before first entry '+label)
    drop_port=c.get('drop_port',c['source_port'])
    require(any(by['verdict']['verdict']=='0' and raw['src_port']==drop_port for raw,aa,facts,by in x['by_token'].values()),'actual early DROP '+label)
   else:
    require(c['protocol']==6 and all(not (raw['tcp_flags']&2) for raw,aa,facts,by in matched),'midstream first capture without SYN '+label)
    if not pixel:require(not any(l.startswith('-A ') for l in read('before-hooks.txt').splitlines()),'connection predates hooks '+label)
   closed=read('closed.txt');require('root.stop=ok' in read('close.txt'),'native stop completed '+label)
   require(all(d['entries']=='0' for d in rows(closed,'flow.pool ')) and rows(closed,'primary.status ')[0]['flows']=='0','native pools flushed on stop '+label)
   lanes=rows(closed,'root.lane ');require(len(lanes)==4 and all(d['fd']=='-1' and d['ready']==d['pending']=='0' for d in lanes),'all queue lanes closed '+label)
   initial=rows(read('initial.txt'),'root.lane ');require(len(initial)==4 and len({d['fd'] for d in initial})==4,'independent live fds '+label)
   before=read('fds-before.txt');after=read('fds-closed.txt')
   for lane in initial:
    line=next(l for l in before.splitlines() if ((' '+lane['fd']+' -> ') in l if pixel else l.startswith(lane['fd']+' ')))
    inode=re.search(r'socket:\[\d+\]',line);require(inode is not None and inode[0] not in after,'actual queue socket removed '+label)
   if pixel:
    require(not any(l.startswith('-A SAKAMOTO_PRODUCT_') for l in read('quiesced-hooks.txt').splitlines()),'capture hooks quiesced before final snapshot '+label)
    require(base.props(out/(label+'-stopped.properties'))['state']=='stopped','Android stopped '+label)
    require('productRootNfqueueResidueClean=true' in read('cleanup.properties'),'Android cleanup '+label)
    require(not read('kernel-queues-after-stop.txt').strip(),'kernel queues absent '+label)
    require('libvpp_runtime.so' not in read('process-after.txt'),'runtime process absent '+label)
    require('SAKAMOTO' not in read('hooks-after-stop.txt'),'product hooks absent '+label)
   else:
    require(all(v==0 for v in json.loads(read('queues-free.json')).values()),'queue rebind after stop '+label)
    require(all(v in (-1,-16) for v in json.loads(read('queues-busy.json')).values()),'live queue exclusive '+label)
    require(json.loads(read('stop.json'))['process_absent'] is True,'process absent '+label)
    require(not any(l.startswith('-A ') for l in read('hooks-after.txt').splitlines()),'hooks removed '+label)
  require(coverage=={(family,proto,mode,lane,owner) for family in (4,6) for proto,mode in ((17,'normal'),(6,'normal'),(6,'midstream')) for lane in ((0,1) if family==4 else (2,3)) for owner in (0,1)},'complete dual-stack/transport/midstream/lane/owner coverage')
 except (OSError,KeyError,ValueError,IndexError,StopIteration) as e:errors.append('incomplete evidence '+repr(e))
 return dict(status='HOLD' if errors else 'PASS',errors=errors,packets=packets,flows=flows,generations=len(r.get('generations',[])),coverage=sorted(coverage),verifier_sha256=digest(__file__),flow_verifier_sha256=digest(ROOT/'tests/device/s208-flow-verify.py'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--build',type=Path,required=True);p.add_argument('--platform',choices=['linux','pixel'],required=True);p.add_argument('--output',type=Path);a=p.parse_args();r=verify(a.run,a.build,a.platform);text=json.dumps(r,indent=2)+'\n'
 if a.output:a.output.write_text(text)
 print(text);raise SystemExit(r['status']!='PASS')
