#!/usr/bin/env python3
"""S229 actual native reassembly error and retained-handoff branches on Pixel."""
import threading
import argparse, importlib.util, hashlib, os, selectors, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SERIAL="28201JEGR0XPAJ"; PKG="com.sakamoto.snort.androidruntime"
a=argparse.ArgumentParser();a.add_argument('--apk',type=Path,required=True);a.add_argument('--reference-run',type=Path);a.add_argument('--policy-helper',type=Path,required=True);a.add_argument('--activity-helper',type=Path);a.add_argument('--suite',choices=['basic','geometry','ingress-handoff','sendout-handoff','policy-return'],required=True);a.add_argument('--output',type=Path,required=True);args=a.parse_args();args.output.mkdir(parents=True,exist_ok=False)
def save(n,t): (args.output/n).write_text(t);return t
def adb(*p,check=True):
 r=subprocess.run([str(ROOT/'dev/adb'),'-s',SERIAL,*p],text=True,errors="replace",stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
 if check and r.returncode:raise RuntimeError(r.stdout)
 return r.stdout.replace('\r','')
def app(p):return adb('shell','run-as',PKG,'cat',p,check=False)
class PressureTrace:
 """One bounded device stream avoids ADB round trips inside a 500ms hold."""
 def __init__(self):
  self.lines=[]
  command=f'exec 3<{BASE}logs/vpp-stdout.log; while test -S {BASE}runtime/cli.sock; do cat <&3; sleep 0.01; done; cat <&3'
  self.process=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'shell','run-as',PKG,'sh','-c',shlex.quote(command)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  def consume():
   for line in self.process.stdout:
    if line.startswith(('s209 event=hold_', 's212 event=fragment_ingress ', 's212 event=native_finalize_prepare ')):
     self.lines.append(line)
  self.reader=threading.Thread(target=consume,daemon=True);self.reader.start()
 def snapshot(self):return ''.join(self.lines)
 def close(self):
  try:self.process.wait(timeout=5)
  except subprocess.TimeoutExpired:self.process.terminate();self.process.wait(timeout=5)
  self.reader.join(timeout=5)
  assert not self.reader.is_alive(), 'pressure trace reader survived cleanup'
def hold_trace():return pressure_trace.snapshot()
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

spec=importlib.util.spec_from_file_location('scenarios',ROOT/'tests/device/s229-reassembly-scenarios.py');scenarios=importlib.util.module_from_spec(spec);spec.loader.exec_module(scenarios)
result=dict(status='HOLD',started_ns=time.time_ns(),source='GRAPH_INJECTED',platform='pixel',serial=SERIAL,suite=args.suite,apk_sha256=hashlib.sha256(args.apk.read_bytes()).hexdigest())
active=False;control=None;activity=None;activity_output=None;pressure_trace=None;wifi=adb('shell','settings','get','global','wifi_on').strip();revision=22900
try:
 adb('shell','svc','wifi','disable');save('install.txt',adb('install','-r',str(args.apk.resolve())))
 package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 with zipfile.ZipFile(args.apk) as z:expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 installed=save('installed-native-sha256.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]));assert expected=={Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()};result['native_sha256']=expected
 assert save('installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 result['policy_helper_sha256']=hashlib.sha256(args.policy_helper.read_bytes()).hexdigest()
 adb('push',str(args.policy_helper.resolve()),'/data/local/tmp/s229-policy');adb('shell','chmod','755','/data/local/tmp/s229-policy')
 save('device.txt',adb('shell','uname','-a'));active=True;result['generation']=start('first')['generation'];quiesce('first')
 save('background-ui.txt',adb('shell','input','keyevent','KEYCODE_HOME'));time.sleep(.6)
 cli('initial-native',['product packet-trace limit 4096','trace add product-packet-admit 64','show product reassembly','show product primary']);control=ControlClient()
 pressure_trace=PressureTrace()
 def policy(blocked):
  global revision
  revision+=1
  response=root(f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s229-policy {BASE}runtime/api.sock {result["generation"]} /data/local/tmp/s229-policy-{result["generation"]} {revision} {int(blocked)} 22900 1')
  save(f'policy-{revision}.txt',response);assert 'policy rc=0' in response
 def await_hold(token,event='hold_begin'):
  deadline=time.monotonic()+2
  while time.monotonic()<deadline:
   trace=hold_trace()
   if any(f'event={event} ' in line and f'token={token} ' in line for line in trace.splitlines()):
    if event=='hold_begin':assert f's209 event=hold_end token={token} ' not in trace,'hold ended before pressure could be sent'
    return
   time.sleep(.005)
  raise RuntimeError('worker did not enter diagnostic hold')
 runner=scenarios.Scenarios(control.call,save,policy,await_hold);result['cases']=runner.cases;result['holds']=runner.holds
 if args.activity_helper:
  result['activity_helper_sha256']=hashlib.sha256(args.activity_helper.read_bytes()).hexdigest()
  adb('push',str(args.activity_helper.resolve()),'/data/local/tmp/s229-local-activity');adb('shell','chmod','755','/data/local/tmp/s229-local-activity')
  uid=adb('shell','run-as',PKG,'id','-u').strip();result['activity_uid']=int(uid)
  save('activity-hook.txt',root(f'iptables -t mangle -A SAKAMOTO_PRODUCT_S176_OUTPUT -p udp -d 127.0.0.0/8 --dport 40638 -m owner --uid-owner {uid} -j NFQUEUE --queue-balance 176:177'))
  def activity_hold(family,worker):
   global activity,activity_output
   previous={e['token'] for e in rows(hold_trace(),'s209 event=hold_begin ')}
   activity_output=(args.output/f'{family}-local-activity.txt').open('w')
   activity=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'shell','su','-c',shlex.quote(f'/data/local/tmp/s229-local-activity {uid}')],stdout=activity_output,stderr=subprocess.STDOUT)
   time.sleep(.12)
   save(f'{family}-activity-hold-arm.txt',control.call(f'product policy hold-next {1-worker} 300000\nproduct policy hold-next {worker} 500000',f'worker={worker} us=500000'))
   deadline=time.monotonic()+2
   while time.monotonic()<deadline:
    trace=hold_trace()
    observed=[e for e in rows(trace,'s209 event=hold_begin ') if e['token'] not in previous]
    if {int(e['thread']) for e in observed}=={1,2}:
     assert all(f's209 event=hold_end token={e["token"]} ' not in trace for e in observed),'activity holds did not overlap'
     return [dict(e,family=family,source='NFQ_CAPTURED') for e in observed]
    time.sleep(.005)
   raise RuntimeError('both actual NFQUEUE workers did not enter hold')
  def activity_finish():
   global activity,activity_output
   activity.wait(timeout=5);assert activity.returncode==0,'local activity failed';activity=None
   activity_output.close();activity_output=None
   drained('activity-drained')
  runner.activity_hold=activity_hold;runner.activity_finish=activity_finish
 if args.suite=='basic':runner.basic()
 elif args.suite=='geometry':runner.geometry()
 else:runner.pressure(args.suite)
 control.close();control=None;drained('complete-drain')
 cli('runtime',['show product reassembly','show product completion','show product primary','show product root lanes','show runtime','show threads','show trace'])
 save('vpp.log',app('files/profiles/root/vpp/logs/vpp-stdout.log'));logs('before-stop');stop('complete');active=False
 save('android-events-after-stop.log',adb('logcat','-d','-s','SakamotoNetwork:I','*:S'));result['status']='RAW_COMPLETE'
except Exception as error:result['error']=repr(error);logs('failure');raise
finally:
 if activity:
  try:activity.wait(timeout=5)
  except subprocess.TimeoutExpired:activity.terminate();activity.wait(timeout=5)
 if activity_output:activity_output.close()
 if control:
  try:control.close()
  except Exception:pass
 if active:
  try:stop('cleanup')
  except Exception as error:result['cleanup_error']=repr(error)
 if pressure_trace:
  try:pressure_trace.close()
  except Exception as error:result['cleanup_error']=repr(error)
 adb('shell','svc','wifi','enable' if wifi=='1' else 'disable',check=False)
 result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
