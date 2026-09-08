#!/usr/bin/env python3
"""S232: controlled publication rejection tears down the generation and restarts cleanly."""
import threading
import argparse, importlib.util, hashlib, os, selectors, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SERIAL="28201JEGR0XPAJ"; PKG="com.sakamoto.snort.androidruntime"
a=argparse.ArgumentParser();a.add_argument('--apk',type=Path,required=True);a.add_argument('--reference-run',type=Path);a.add_argument('--policy-helper',type=Path);a.add_argument('--peer4',required=True);a.add_argument('--peer6',required=True);a.add_argument('--output',type=Path,required=True);args=a.parse_args();args.output.mkdir(parents=True,exist_ok=False)
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
   if 'rejected' in text or 'unknown input' in text or 'requires an active empty graph' in text or 'expected mode 0..6' in text:raise RuntimeError(text)
  raise RuntimeError('persistent control timeout '+repr(response))
 def close(self):
  try:self.p.stdin.write(b'quit\n');self.p.stdin.flush();self.p.stdin.close()
  except BrokenPipeError:pass
  try:self.p.wait(timeout=5)
  except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(timeout=5)
  self.selector.close()

result=dict(status='HOLD',started_ns=time.time_ns(),apk_sha256=hashlib.sha256(args.apk.read_bytes()).hexdigest())
active=False
try:
 package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 assert save('installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 helper=args.policy_helper.resolve();result['helper_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()
 adb('push',str(helper),'/data/local/tmp/s232-network-publish');adb('shell','chmod','755','/data/local/tmp/s232-network-publish')
 active=True;result['generation']=start('first')['generation'];quiesce('first')
 # Force the next real Android publication to encounter a rejected revision.
 response=root(f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s232-network-publish {BASE}runtime/api.sock {result["generation"]} 100000')
 save('controlled-publish.txt',response);assert 'code=0' in response
 save('trigger.txt',action('--ez','debugNetworkSnapshotMissing','true'))
 state=wait('publication-error',STATE,{'state':'error','mayBeActive':'false','errorCode':'platform_network_publish_failed'})
 save('cleanup.properties',app('files/product-state/s176-root-nfqueue-cleanup.properties'))
 assert 'productRootNfqueueResidueClean=true' in (args.output/'cleanup.properties').read_text()
 active=False
 save('events-after-failure.log',adb('logcat','-d','-s','SakamotoNetwork:I','*:S'))
 processes=save('processes-after-failure.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS'))
 assert not any('libvpp_runtime.so' in l for l in processes.splitlines())
 active=True;restarted=start('restart');result['restart_generation']=restarted['generation'];assert int(restarted['generation'])>int(result['generation'])
 time.sleep(.5)
 log=save('restart-vpp.log',root('cat '+BASE+'logs/vpp-stdout.log'))
 publishes=rows(log,'s232 event=snapshot_publish ')
 assert publishes and publishes[0]['revision']=='1' and publishes[0]['count']=='0'
 assert any(int(e['count'])>0 for e in publishes)
 stop('complete');active=False
 save('android-events.log',adb('logcat','-d','-s','SakamotoNetwork:I','*:S'))
 assert 'event=subscription_stopped thread_alive=false' in (args.output/'android-events.log').read_text()
 result['status']='PASS'
except Exception as error:
 result['error']=repr(error);logs('failure');raise
finally:
 if active:
  try:stop('cleanup')
  except Exception as error:result['cleanup_error']=repr(error)
 result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
