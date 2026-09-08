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
   label='g'+str(i);prefix=out/label
   def read(name):return (out/(label+'-'+name)).read_text()
   trace=read('before-stop-vpp-stdout.log');runtime=read('before-stop-vpp-runtime.txt');final=read('flow-final.txt')
   x=flow.verify(trace,runtime,final,c['generation']);errors.extend(label+': '+e for e in x['errors']);packets+=x['packets'];flows+=len(x['states'])
   require(len(x['states'])==1,'one incoming TCP identity '+label);state=next(iter(x['states'].values()))
   require(state['origin_dir']==1 and state['uid']==4294967295,'INPUT first creation preserves initially unknown UID '+label)
   require({d['flow_dir'] for d in state['history']}=={'1','2'},'app reply reuses incoming flow '+label)
   first=next(iter(x['by_token'].values()));require(first[2]['direction']=='1' and not (int(first[2]['availability'])&1),'first real capture is unattributed INPUT '+label)
   require(all(raw['protocol']==6 and not (raw['tcp_flags']&2) for raw,aa,facts,by in x['by_token'].values()),'midstream connection predates capture '+label)
   require(not any('SAKAMOTO' in l for l in read('before-start-hooks.txt').splitlines()),'no hooks at connect '+label)
   require(read('echo.txt')==c['nonce'] and base.props(out/(label+'-listener.properties'))['result']=='tcp_echo_matched','both endpoints confirm nonce '+label)
   require(sum(c['nonce'].encode().hex() in facts['raw'] for raw,aa,facts,by in x['by_token'].values())>=2,'actual kernel nonce '+label)
   require(int(c['nonce'].rsplit('-',1)[1])>b['completed_ns'],'nonce created after build '+label)
   coverage.add(c['family'])
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
    require(json.loads(read('stop.json'))['process_absent'] is True,'process absent '+label)
    require(not any(l.startswith('-A ') for l in read('hooks-after.txt').splitlines()),'hooks removed '+label)
  require(coverage=={4,6},'dual-stack incoming-first coverage')
 except (OSError,KeyError,ValueError,IndexError,StopIteration) as e:errors.append('incomplete evidence '+repr(e))
 return dict(status='HOLD' if errors else 'PASS',errors=errors,packets=packets,flows=flows,generations=len(r.get('generations',[])),coverage=sorted(coverage),verifier_sha256=digest(__file__),flow_verifier_sha256=digest(ROOT/'tests/device/s208-flow-verify.py'))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('run',type=Path);p.add_argument('--build',type=Path,required=True);p.add_argument('--platform',choices=['linux','pixel'],required=True);p.add_argument('--output',type=Path);a=p.parse_args();r=verify(a.run,a.build,a.platform);text=json.dumps(r,indent=2)+'\n'
 if a.output:a.output.write_text(text)
 print(text);raise SystemExit(r['status']!='PASS')
