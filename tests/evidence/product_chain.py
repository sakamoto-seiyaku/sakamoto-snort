#!/usr/bin/env python3
"""S244: bind a bounded real-device claim to current source and installed binaries."""
import argparse,hashlib,importlib.util,json,os,re,shutil,subprocess,time,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SCHEMA='sakamoto-product-evidence/v1'
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def encode(d):return json.dumps(d,sort_keys=True,separators=(',',':')).encode()
def write(p,d):Path(p).write_text(json.dumps(d,indent=2)+'\n')
def source_files():
 # Include dependency source, reviewed fork patches, and staging/build logic:
 # changing any of these invalidates an earlier installed-binary claim.
 names=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z','src/product','app/android-runtime','crates/product-core','Cargo.toml','Cargo.lock','.cargo','third_party/hev','third_party/libprotoident','third_party/mbedtls','third_party/rax','resources/application-protocol-catalog','tools/generate_application_protocol_catalog.py','tools/product'],cwd=ROOT,text=True).split('\0')
 return {n:digest(ROOT/n) if (ROOT/n).is_file() else None for n in sorted(set(names)) if n}
def source_snapshot(out):
 files=source_files()
 for name,h in files.items():
  if h is not None:
   p=out/'source'/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,p)
 (out/'dirty.diff').write_bytes(subprocess.check_output(['git','diff','--binary'],cwd=ROOT))
 return {'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'files':files,'source_sha256':hashlib.sha256(encode(files)).hexdigest(),'dirty_diff_sha256':digest(out/'dirty.diff')}
def build(out):
 out=Path(out).resolve();out.mkdir(parents=True,exist_ok=False)
 m={'schema':SCHEMA,'started_ns':time.time_ns(),**source_snapshot(out)}
 env=dict(os.environ,SAKAMOTO_VPP_STAGE_DIR=os.environ.get('SAKAMOTO_VPP_STAGE_DIR','/tmp/sakamoto-s181-clean-vpp-stage.current'),SAKAMOTO_VPP_SOURCE_DIR=str(ROOT/'build-output/pinned-vpp-clean'),SAKAMOTO_ANDROID_PRODUCT_STAGE_DIR=str(out/'stage'),SAKAMOTO_ANDROID_VERSION_STATE_FILE=str(out/'version-code'),SAKAMOTO_VPP_PYTHONPATH=os.environ.get('SAKAMOTO_VPP_PYTHONPATH','/usr/lib/python3/dist-packages'),SAKAMOTO_ANDROID_APK_OUTPUT_DIR=str(out/'apk'))
 for mode in ['stage-only','apk-only']:
  with (out/(mode+'.log')).open('w') as f:r=subprocess.run(['bash',str(ROOT/'app/android-runtime/scripts/build-debug-apk.sh'),'--'+mode],cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT)
  if r.returncode:raise RuntimeError((out/(mode+'.log')).read_text()[-5000:])
  print(mode+' complete',flush=True)
 assert source_files()==m['files'],'source changed during build'
 apk=out/'apk/sakamoto-runtime-debug.apk'
 with zipfile.ZipFile(apk) as z:m['native_sha256']={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 m.update(completed_ns=time.time_ns(),apk=str(apk),apk_sha256=digest(apk),product_stage_sha256=digest(out/'stage/product-stage.properties'),vpp_stage_sha256=digest(Path(env['SAKAMOTO_VPP_STAGE_DIR'])/'android-vpp-stage.properties'))
 write(out/'build.json',m);return m

def request(build_file,run_dir,out):
 b=json.loads(Path(build_file).read_text())
 assert source_files()==b['files'],'build does not match current product source'
 r={'schema':SCHEMA,'created_ns':time.time_ns(),'task':'SAKAMOTO-244','build':str(Path(build_file).resolve()),'build_sha256':digest(build_file),'run_dir':str(Path(run_dir).resolve()),'expected_source':'NFQ_CAPTURED','profile':'root','family':4,'protocol':17,'serial':'28201JEGR0XPAJ','adapter_readiness':'root-nfqueue-udp4-owner-local'}
 write(out,r);return r

def props(p):return dict(l.split('=',1) for l in Path(p).read_text().splitlines() if '=' in l and not l.startswith('#'))
def verify(request_file,run_override=None):
 q=json.loads(Path(request_file).read_text());out=Path(run_override or q['run_dir']);errors=[]
 def require(ok,message):
  if not ok:errors.append(message)
 try:
  require(q['schema']==SCHEMA,'request schema')
  require(q['expected_source']=='NFQ_CAPTURED' and q['profile']=='root' and q['family']==4 and q['protocol']==17,'unsupported claim scope')
  bp=Path(q['build']);b=json.loads(bp.read_text())
  require(digest(bp)==q['build_sha256'],'build witness changed')
  require(b['files']==source_files(),'current source differs from build')
  require(hashlib.sha256(encode(b['files'])).hexdigest()==b['source_sha256'],'source hash closure')
  require(digest(bp.parent/'dirty.diff')==b['dirty_diff_sha256'],'dirty source diff missing/changed')
  for n,h in b['files'].items():
   if h is not None:require(digest(bp.parent/'source'/n)==h,'source snapshot '+n)
  require(b['started_ns']<b['completed_ns']<q['created_ns'],'build/run order')
  require(digest(b['apk'])==b['apk_sha256'],'build APK changed')
  require(digest(bp.parent/'stage/product-stage.properties')==b['product_stage_sha256'],'product stage changed')
  stage=props(bp.parent/'stage/product-stage.properties')
  r=json.loads((out/'result.json').read_text())
  require(r.get('apk_sha256')==b['apk_sha256'],'stale/wrong APK identity')
  require((out/'installed-apk-sha256.txt').read_text().split()[0]==b['apk_sha256'],'installed APK hash closure')
  require(r.get('native_sha256')==b['native_sha256'],'native identity differs from build')
  installed={Path(l.split()[1]).name:l.split()[0] for l in (out/'installed-native-sha256.txt').read_text().splitlines()}
  require(installed==b['native_sha256'],'installed native hash closure')
  with zipfile.ZipFile(b['apk']) as z:
   native={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
   require(native==installed,'APK entries differ from installed native files')
   plugin=z.read('lib/arm64-v8a/libproduct_core_plugin.so')
   require(b'poc-handcrafted-direct-bridge' not in plugin and b'vpn-tun-hev-lwip' not in plugin,'POC implementation/readiness in product plugin')
  require(r.get('scope')=='single-lane-owner-local','owner scope overstated')
  for field in ['source','profile','family','protocol','serial']:
   expected=q['expected_source'] if field=='source' else q[field]
   require(r.get(field)==expected,'claim '+field+' mismatch')
  require('bluejay' in (out/'device.txt').read_text() and 'Linux' in (out/'device.txt').read_text(),'actual device/kernel evidence')
  for name in ['first.properties','restart.properties']:
   d=props(out/name);require(d.get('adapterReadiness')==q['adapter_readiness'],'POC/wrong readiness')
   require(d.get('artifact')==stage.get('artifactId') and d.get('version')==stage.get('vppRevision'),'running artifact/revision identity')
  for key in ['allow_nonce','drop_nonce','recover_nonce','unsupported_remote_nonce','restart_nonce']:
   nonce=r.get(key,'');stamp=nonce.rsplit('-',1)[-1]
   require(stamp.isdigit() and int(stamp)>q['created_ns'],'stale run/nonce '+key)
  spec=importlib.util.spec_from_file_location('s203_verify',ROOT/'tests/device/verify-s203-root-graph.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
  packet=v.verify(out);errors.extend('node/settlement: '+e for e in packet['errors'])
  for prefix,count in [('before-stop',4),('restart-before-stop',1)]:
   generation=str(r['generation'] if count==4 else r['restart_generation'])
   state=props(out/('first.properties' if count==4 else 'restart.properties'))
   status=props(out/(prefix+'-status.properties'))
   require(state.get('generation')==generation and status.get('root_nfqueue_generation')==generation,'runtime/NFQ generation binding')
   trace=(out/(prefix+'-vpp-stdout.log')).read_text()
   trace_generations=re.findall(r'^s203 event=admit .*?generation=(\d+)',trace,re.M)
   require(len(trace_generations)==count and set(trace_generations)=={generation},'node trace belongs to another generation')
   text=(out/(prefix+'-vpp-runtime.txt')).read_text();thread=None;seen={}
   for line in text.splitlines():
    m=re.match(r'Thread (\d+) ',line)
    if m:thread=int(m[1])
    m=re.match(r'(product-packet-(?:admit|policy|terminal))\s+active\s+(\d+)\s+(\d+)',line)
    if m:seen[(thread,m[1])]=(int(m[2]),int(m[3]))
   for node,wanted in [('admit',count),('policy',count-1 if count==4 else count),('terminal',count)]:
    require(seen.get((1,'product-packet-'+node))==(wanted,wanted),'actual VLIB vector counters '+prefix+' '+node)
   require(all(thread==1 for thread,node in seen),'packet node executed on wrong thread')
  for label,key,ordinal,delivery in [('allow','allow_nonce',1,True),('drop','drop_nonce',2,False),('recover','recover_nonce',3,True),('remote-closed','unsupported_remote_nonce',4,False),('restart','restart_nonce',1,True)]:
   app=props(out/(label+'-probe.properties'))
   status=props(out/(label+'-status.properties'))
   require(app.get('nonce')==r[key],'app nonce bound to request case '+label)
   require(status.get('origin_verdict_attempts')==str(ordinal),'per-case NFQUEUE sequence '+label)
   trace=(out/(label+'-vpp-stdout.log')).read_text()
   captured=re.findall(r'^s203 event=capture .*?packet=(\d+)',trace,re.M)
   require(len(captured)==ordinal and captured[-1]==status.get('last_packet_id'),'capture/packet ID binding '+label)
   endpoint=(out/(label+'-endpoint.log')).read_text()
   require((r[key] in endpoint)==delivery,'per-case endpoint binding '+label)
 except (OSError,KeyError,ValueError,AssertionError) as e:errors.append('incomplete evidence: '+str(e))
 return {'schema':SCHEMA,'status':'HOLD' if errors else 'PASS','errors':errors,'request_sha256':digest(request_file),'run_dir':str(out),'verifier_sha256':digest(__file__),'packet_verifier_sha256':digest(ROOT/'tests/device/verify-s203-root-graph.py')}

if __name__=='__main__':
 p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
 a=sub.add_parser('build');a.add_argument('output')
 a=sub.add_parser('request');a.add_argument('--build',required=True);a.add_argument('--run-dir',required=True);a.add_argument('--output',required=True)
 a=sub.add_parser('verify');a.add_argument('request');a.add_argument('--output')
 args=p.parse_args()
 if args.command=='build':result=build(args.output)
 elif args.command=='request':result=request(args.build,args.run_dir,args.output)
 else:
  result=verify(args.request)
  if args.output:write(args.output,result)
 print(json.dumps({k:v for k,v in result.items() if k not in ['files','native_sha256']},indent=2))
 if result.get('status')=='HOLD':raise SystemExit(1)
