#!/usr/bin/env python3
"""S219 controlled first-offset platform facts through actual Pixel native reassembly."""
import threading
import argparse, importlib.util, hashlib, os, selectors, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SERIAL="28201JEGR0XPAJ"; PKG="com.sakamoto.snort.androidruntime"
a=argparse.ArgumentParser();a.add_argument('--apk',type=Path,required=True);a.add_argument('--reference-run',type=Path);a.add_argument('--policy-helper',type=Path,required=True);a.add_argument('--output',type=Path,required=True);args=a.parse_args();args.output.mkdir(parents=True,exist_ok=False)
def save(n,t): (args.output/n).write_text(t);return t
def adb(*p,check=True):
 r=subprocess.run([str(ROOT/'dev/adb'),'-s',SERIAL,*p],text=True,errors="replace",stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
 if check and r.returncode:raise RuntimeError(r.stdout)
 return r.stdout.replace('\r','')
def app(p):return adb('shell','run-as',PKG,'cat',p,check=False)
def props(s):return dict(l.split('=',1) for l in s.splitlines() if '=' in l and not l.startswith('#'))
def action(*p):return adb('shell','am','start','-n',PKG+'/.DebugControlActivity',*p)
def wait(label,path,match):
 end=time.monotonic()+75;next_query=0
 while time.monotonic()<end:
  if path in (GATE,STATUS) and time.monotonic()>=next_query:
   action("--ez","debugRefresh","true");next_query=time.monotonic()+1
  s=save(label+'.poll',app(path));d=props(s)
  if label in ('first','restart') or (path==STATE and d.get('state')=='starting'):
   bootstrap=save(label+'-bootstrap.log',adb('shell','su','-c',shlex.quote('cat /data/user/0/'+PKG+'/files/profiles/root/vpp/logs/vpp-stdout.log'),check=False))
   with (args.output/(label+'-bootstrap-history.log')).open('a') as history:history.write(bootstrap+'\n')
  if all(d.get(k)==v for k,v in match.items()):save(label+'.properties',s);return d
  if d.get('errorCode')=='root_authorization_required':raise RuntimeError('Restore KernelSU app grant')
  time.sleep(.35)
 raise RuntimeError(label+' timeout: '+str(d))
STATE='files/runtime-state/snapshot.properties';STATUS='files/product-state/s176-root-nfqueue-output.properties';GATE='files/product-state/s189-root-network-gate.properties'
def start(label):
 for _ in range(40):
  services=save(label+'-services-before-start.txt',adb('shell','dumpsys','activity','services',PKG))
  if not any('ServiceRecord{' in l and '.RuntimeService' in l for l in services.splitlines()):break
  time.sleep(.2)
 else:raise RuntimeError('previous idle control query has not retired')
 save(label+'.start.txt',action('--ez','runtimeStart','true','--es','runtimeProfile','root'))
 return wait(label,STATE,{'state':'running','adapterReadiness':'root-nfqueue-tcp-udp-echo-dualstack-q2w2','protectionRunning':'true'})
def logs(label):
 base='/data/user/0/'+PKG+'/files/profiles/root/vpp/'
 for name in ['logs/vpp-stdout.log','logs/vpp.log','runtime/startup.conf','owner.properties']:
  save(label+'-'+Path(name).name,adb('shell','su','-c',shlex.quote('cat '+shlex.quote(base+name)),check=False))
 if 'before-stop' in label or label=='failure':
  command="printf 'show product root lanes\\nshow product completion\\nshow product primary\\nshow runtime\\nshow threads\\nshow node product-packet-origin-completion\\nshow node product-packet-policy\\nshow node product-packet-owner-guard\\nquit\\n' | toybox nc -U -w 2 -q 1 "+shlex.quote(base+'runtime/cli.sock')
  save(label+'-vpp-runtime.txt',adb('shell','su','-c',shlex.quote(command),check=False))
  save(label+'-post-cli-vpp-stdout.log',adb('shell','su','-c',shlex.quote('cat '+shlex.quote(base+'logs/vpp-stdout.log')),check=False))
 save(label+'-status.properties',app(STATUS));save(label+'-gate.properties',app(GATE));save(label+'-l4.properties',app('files/product-state/s192-root-vpn-l4-matrix.properties'))
 save(label+'-endpoint.log',adb('shell','cat','/data/local/tmp/s231-echo.log',check=False))
def stop(label):
 save(label+'.stop.txt',action('--ez','runtimeStop','true'))
 wait(label+'-stopped',STATE,{'state':'stopped','mayBeActive':'false','errorCode':''})
 s=save(label+'-cleanup.properties',app('files/product-state/s176-root-nfqueue-cleanup.properties'))
 assert 'productRootNfqueueResidueClean=true' in s
 s=save(label+'-process-after.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS'))
 assert not any('libvpp_runtime.so' in l for l in s.splitlines())
BASE='/data/user/0/'+PKG+'/files/profiles/root/vpp/'
HOSTS={4:['127.0.0.'+str(i) for i in range(1,9)],6:['fd20:6210::'+str(i) for i in range(1,9)]}
def root(command,check=True):
 command=re.sub(r'\b(ip6?tables) (?!-w(?: |$))',r'\1 -w 5 ',command)
 return adb('shell','su','-c',shlex.quote(command),check=check)
def cli(label,commands):
 command="printf '%s\\n' "+' '.join(shlex.quote(c) for c in ['set terminal pager off']+commands+['quit'])+' | toybox nc -U -w 2 -q 1 '+shlex.quote(BASE+'runtime/cli.sock')
 return save(label+'.txt',root(command))
def rows(text,prefix):
 return [dict(x.split('=',1) for x in line.split()[1:] if '=' in x) for line in text.splitlines() if line.startswith(prefix)]
def snapshot(label):
 response=cli(label,['show product root lanes','show product completion','show product primary'])
 return rows(response,'root.lane '),rows(response,'completion.status ')[0]
def drained(label):
 end=time.monotonic()+30
 while time.monotonic()<end:
  lanes,d=snapshot(label)
  if all(d.get(k)=='0' for k in ('pending','frames','buffers','obligations')):return lanes,d
  time.sleep(.2)
 raise RuntimeError('drain timeout '+str(d))

def quiesce(label):
 commands=['set -e']+[tool+' -t mangle -F '+chain for tool in ('iptables','ip6tables') for chain in ('SAKAMOTO_PRODUCT_S176_OUTPUT','SAKAMOTO_PRODUCT_S178_INPUT')]
 save(label+'-quiesce.txt',root('; '.join(commands)))
 save(label+'-quiesced-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
 last=None;since=time.monotonic();deadline=since+30
 while time.monotonic()<deadline:
  lanes,d=snapshot(label+'-quiesce-drain');counts=tuple(x['captured'] for x in lanes)
  if counts!=last or any(d[k]!='0' for k in ('pending','frames','buffers','obligations')):since=time.monotonic()
  elif time.monotonic()-since>=2.2:return
  last=counts;time.sleep(.2)
 raise RuntimeError('capture quiescence timed out')

class ControlClient:
 def __init__(self):
  self.p=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'shell','-T','su','-c',shlex.quote('toybox nc -U '+BASE+'runtime/cli.sock')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.selector=selectors.DefaultSelector();self.selector.register(self.p.stdout,selectors.EVENT_READ)
 def call(self,command_text,marker):
  self.p.stdin.write((command_text+'\n').encode());self.p.stdin.flush();response=b'';deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   if not self.selector.select(.5):continue
   chunk=os.read(self.p.stdout.fileno(),65536)
   if not chunk:raise RuntimeError('control EOF '+repr(response))
   response+=chunk;text=response.decode(errors='replace').replace('\r','')
   start=text.find(marker)
   if start>=0 and '\n' in text[start:]:return text
   if 'rejected' in text or 'unknown input' in text or 'requires an active empty graph' in text:raise RuntimeError(text)
  raise RuntimeError('persistent control timeout '+repr(response))
 def close(self):
  try:self.p.stdin.write(b'quit\n');self.p.stdin.flush();self.p.stdin.close()
  except BrokenPipeError:pass
  try:self.p.wait(timeout=5)
  except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(timeout=5)
  self.selector.close()

spec=importlib.util.spec_from_file_location('matrix',ROOT/'tests/device/s219-fragment-matrix.py');vectors=importlib.util.module_from_spec(spec);spec.loader.exec_module(vectors)
result=dict(status='HOLD',started_ns=time.time_ns(),source='GRAPH_INJECTED',platform='pixel',serial=SERIAL,apk_sha256=hashlib.sha256(args.apk.read_bytes()).hexdigest(),cases=[])
active=False;control=None;wifi=adb('shell','settings','get','global','wifi_on').strip()
def wait_reassembly(label,empty=True):
 deadline=time.monotonic()+15
 while time.monotonic()<deadline:
  text=save(label+'-status.txt',control.call('show product reassembly','reassembly.status'))
  value=rows(text,'reassembly.status ')[0]
  if (all(value[k]=='0' for k in ('contexts','originals','retained')) if empty else int(value['contexts'])>0):return
  time.sleep(.05)
 raise RuntimeError('native reassembly did not reach '+label)
def revision():
 log=app('files/profiles/root/vpp/logs/vpp-stdout.log');published=rows(log,'s232 event=snapshot_publish ')
 return int(published[-1]['revision']) if published else 0
try:
 adb('shell','svc','wifi','disable')
 save('install.txt',adb('install','-r',str(args.apk.resolve())))
 package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 with zipfile.ZipFile(args.apk) as z:expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 installed=save('installed-native-sha256.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]));assert expected=={Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()};result['native_sha256']=expected
 assert save('installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 result['policy_helper_sha256']=hashlib.sha256(args.policy_helper.read_bytes()).hexdigest()
 adb('push',str(args.policy_helper.resolve()),'/data/local/tmp/s219-policy');adb('shell','chmod','755','/data/local/tmp/s219-policy')
 save('device.txt',adb('shell','uname','-a'));active=True;result['generation']=start('first')['generation'];quiesce('first')
 cli('trace-limit',['product packet-trace limit 4096','trace add product-packet-admit 64']);control=ControlClient()
 for index,case in enumerate(vectors.matrix()):
  label=case['label'];wait_reassembly(label+'-before')
  timeout=100 if case['no_first'] else 10000
  save(label+'-config.txt',control.call(f'product reassembly configure timeout-ms {timeout} contexts 64','reassembly.configured'))
  mode=1+index%2;policy_revision=21900+index
  policy=root(f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s219-policy {BASE}runtime/api.sock {result["generation"]} /data/local/tmp/s219-policy-{result["generation"]} {policy_revision} {mode} 21900 31')
  save(label+'-policy.txt',policy);assert 'policy rc=0' in policy
  case['mode']=mode;case['policy_revision']=policy_revision;case['snapshot_before']=revision()
  for n,entry in enumerate(case['packets']):
   if n and case['snapshot_change']:
    wait_reassembly(label+'-held',False)
    save(label+'-snapshot-change.txt',action('--ez','debugNetworkSnapshotMissing','true' if case['family']==4 else 'false'))
    deadline=time.monotonic()+15
    while revision()<=case['snapshot_before'] and time.monotonic()<deadline:time.sleep(.1)
    case['snapshot_after']=revision();assert case['snapshot_after']>case['snapshot_before']
   values=' '.join(str(entry['facts'][k]) for k in ('uid','ifindex','context','availability','direction','provenance'))
   command=f'product reassembly inject {entry["case"]} {entry["hex"]} worker {entry["worker"]} facts {values}'
   save(f'inject-{entry["case"]}.txt',control.call(command,'reassembly.inject=accepted'))
  wait_reassembly(label+'-complete');result['cases'].append(case)
 control.close();control=None;drained('complete-drain')
 cli('runtime',['show product reassembly','show product completion','show product primary','show runtime','show threads','show trace'])
 save('vpp.log',app('files/profiles/root/vpp/logs/vpp-stdout.log'));save('android-events.log',adb('logcat','-d','-s','SakamotoNetwork:I','*:S'))
 logs('before-stop');stop('complete');active=False
 save('android-events-after-stop.log',adb('logcat','-d','-s','SakamotoNetwork:I','*:S'));result['status']='RAW_COMPLETE'
except Exception as error:
 result['error']=repr(error);logs('failure');raise
finally:
 if control:
  try:control.close()
  except Exception:pass
 if active:
  try:stop('cleanup')
  except Exception as error:result['cleanup_error']=repr(error)
 adb('shell','svc','wifi','enable' if wifi=='1' else 'disable',check=False)
 result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
