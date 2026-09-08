#!/usr/bin/env python3
"""S217: actual NFQUEUE attributes and controlled attribute faults on Pixel."""
import threading
import argparse, importlib.util, hashlib, os, selectors, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SERIAL="28201JEGR0XPAJ"; PKG="com.sakamoto.snort.androidruntime"
a=argparse.ArgumentParser();a.add_argument('--apk',type=Path,required=True);a.add_argument('--reference-run',type=Path);a.add_argument('--suite',choices=['main','errors'],default='main');a.add_argument('--output',type=Path,required=True);args=a.parse_args();args.output.mkdir(parents=True,exist_ok=False)
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

spec=importlib.util.spec_from_file_location('plan',ROOT/'tests/device/s217-facts-plan.py')
plan=importlib.util.module_from_spec(spec);spec.loader.exec_module(plan)
NET='/data/local/tmp/s217-net'
result=dict(status='HOLD',started_ns=time.time_ns(),cases=[],platform='pixel',serial=SERIAL,
 apk_sha256=hashlib.sha256(args.apk.read_bytes()).hexdigest())
active=False;echo_pid=None;control=None;revision=21700
wifi=adb('shell','settings','get','global','wifi_on').strip()
def clear():
 root(' && '.join(t+' -t mangle -F '+chain for t in ('iptables','ip6tables')
  for chain in ('SAKAMOTO_PRODUCT_S176_OUTPUT','SAKAMOTO_PRODUCT_S178_INPUT')))
def probe(family,hook,c,protocol=17):
 global revision
 label=f'{family}-{hook}-{c["name"]}-{protocol}';revision+=1
 deadline=time.monotonic()+12;retries=0
 while True:
  try:
   response=control.call('product root facts-fault '+str(c['fault']),'root.facts_fault=');break
  except RuntimeError as error:
   if 'expected mode 0..6' not in str(error) or time.monotonic()>deadline:raise
   retries+=1;time.sleep(.1)
 save(label+'-fault.txt',response+f'\nempty_graph_retries={retries}\n')
 response=root(f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s217-policy {BASE}runtime/api.sock {result["generation"]} /data/local/tmp/s217-policy-state {revision} {c["mode"]} {c["uid"]} 1')
 save(label+'-policy.txt',response);assert 'policy rc=0' in response
 nonce='s217-'+label+'-'+str(time.time_ns())
 response=root(f'{NET} probe {c.get("client_uid",result["uid"])} {family} {protocol} '+('127.0.0.1' if family==4 else '::1')+f' 40631 {nonce}'+(' drop' if c['blocked'] else ''))
 save(label+'-probe.txt',response);assert ('probe.blocked' if c['blocked'] else 'probe uid=') in response
 end=time.monotonic()+10
 while True:
  text=control.call('show product completion','completion.status ');d=rows(text,'completion.status ')[0]
  if all(d[k]=='0' for k in ('pending','frames','buffers','obligations')):break
  if time.monotonic()>end:raise RuntimeError('completion drain timeout')
  time.sleep(.05)
 save(label+'-drain.txt',text)
 result['cases'].append(dict(c,family=family,hook=hook,protocol=protocol,label=label,nonce=nonce,revision=revision))
try:
 adb('shell','svc','wifi','disable');save('install.txt',adb('install','-r',str(args.apk.resolve())))
 package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 with zipfile.ZipFile(args.apk) as z:expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 installed=save('installed-native-sha256.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]))
 assert expected=={Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()};result['native_sha256']=expected
 assert save('installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 result['uid']=adb('shell','run-as',PKG,'id','-u').strip()
 helpers={'s217-net':ROOT/'build-output/s231-fragments/pixel-net','s217-policy':ROOT/'build-output/s217-facts/pixel-policy-v3','s217-echo':ROOT/'build-output/s207-owner/echo'}
 result['helper_sha256']={n:hashlib.sha256(p.read_bytes()).hexdigest() for n,p in helpers.items()}
 for name,path in helpers.items():adb('push',str(path),'/data/local/tmp/'+name);adb('shell','chmod','755','/data/local/tmp/'+name)
 echo_pid=adb('shell','/data/local/tmp/s217-echo 40631 127.0.0.1 ::1 > /data/local/tmp/s217-echo.log 2>&1 & echo $!').strip();assert echo_pid.isdigit()
 active=True;result['generation']=start('first')['generation'];quiesce('first')
 cli('trace-limit',['product packet-trace limit 4096']);control=ControlClient()
 for family in (4,6):
  for hook in ('OUTPUT','INPUT'):
   clear();tool='iptables' if family==4 else 'ip6tables';span='176:177' if family==4 else '178:179'
   chain='SAKAMOTO_PRODUCT_S176_OUTPUT' if hook=='OUTPUT' else 'SAKAMOTO_PRODUCT_S178_INPUT'
   for protocol in ('udp','tcp'):
    root(f'{tool} -t mangle -A {chain} '+('-o' if hook=='OUTPUT' else '-i')+f' lo -p {protocol} '+('--dport' if hook=='OUTPUT' else '--sport')+f' 40631 -j NFQUEUE --queue-balance {span}')
   save(f'{family}-{hook}-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
   baseline=dict(name='baseline',fault=0,mode=0,uid=int(result['uid']),blocked=False)
   probe(family,hook,baseline)
   text=root('cat '+BASE+'logs/vpp-stdout.log');save(f'{family}-{hook}-baseline.log',text)
   facts=[f for f in rows(text,'s217 event=nfq_facts ') if f['raw_hook']==('3' if hook=='OUTPUT' else '1')];assert facts
   observed=facts[-1];uid=int(observed['raw_uid']) if observed['raw_uid_present']=='1' else int(result['uid'])
   for case in plan.cases(uid,observed['raw_uid_present']=='1',int(observed['normalized_ifindex'])):probe(family,hook,case)
   if hook=='OUTPUT':probe(family,hook,dict(name='native-uid-zero',fault=0,mode=1,uid=0,client_uid=0,blocked=True))
   probe(family,hook,baseline,6)
 clear();control.close();control=None;drained('final-drain')
 logs('before-stop');save('vpp.log',root('cat '+BASE+'logs/vpp-stdout.log'))
 cli('runtime',['show product root lanes','show product completion','show product flows','show product reassembly'])
 stop('complete');active=False;result['status']='RAW_COMPLETE'
except Exception as error:
 result['error']=repr(error);logs('failure');raise
finally:
 if control:
  try:control.close()
  except Exception:pass
 if active:
  try:clear();stop('cleanup')
  except Exception as error:result['cleanup_error']=repr(error)
 if echo_pid:adb('shell','kill',echo_pid,check=False)
 if wifi=='1':adb('shell','svc','wifi','enable',check=False)
 result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
