#!/usr/bin/env python3
"""S210: real Pixel NFQUEUE capacity bypass and retained DROP completion."""
import threading
import argparse, importlib.util, hashlib, os, selectors, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SERIAL="28201JEGR0XPAJ"; PKG="com.sakamoto.snort.androidruntime"
a=argparse.ArgumentParser();a.add_argument('--apk',type=Path,required=True);a.add_argument('--reference-run',type=Path);a.add_argument('--output',type=Path,required=True);args=a.parse_args();args.output.mkdir(parents=True,exist_ok=False)
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
 save(label+'-endpoint.log',adb('shell','cat','/data/local/tmp/s210-echo.log',check=False))
def stop(label):
 save(label+'.stop.txt',action('--ez','runtimeStop','true'))
 wait(label+'-stopped',STATE,{'state':'stopped','mayBeActive':'false','errorCode':''})
 s=save(label+'-cleanup.properties',app('files/product-state/s176-root-nfqueue-cleanup.properties'))
 assert 'productRootNfqueueResidueClean=true' in s
 s=save(label+'-process-after.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS'))
 assert not any('libvpp_runtime.so' in l for l in s.splitlines())
BASE='/data/user/0/'+PKG+'/files/profiles/root/vpp/'
HOSTS={4:['127.0.0.'+str(i) for i in range(1,9)],6:['fd20:6210::'+str(i) for i in range(1,9)]}
def root(command,check=True):return adb('shell','su','-c',shlex.quote(command),check=check)
def cli(label,commands):
 command="printf '%s\\n' "+' '.join(shlex.quote(c) for c in commands+['quit'])+' | toybox nc -U -w 2 -q 1 '+shlex.quote(BASE+'runtime/cli.sock')
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
   if 'rejected' in text or 'unknown input' in text:raise RuntimeError(text)
  raise RuntimeError('persistent control timeout '+repr(response))
 def close(self):
  try:self.p.stdin.write(b'quit\n');self.p.stdin.flush();self.p.stdin.close()
  except BrokenPipeError:pass
  try:self.p.wait(timeout=5)
  except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(timeout=5)
  self.selector.close()


class DatagramClient:
 def __init__(self, host, family, generation):
  self.prefix=f's210-{generation}'
  self.lines=[]
  command=f'/data/local/tmp/s210-udp-client {result["uid"]} {family} {host} 40610 {self.prefix}'
  self.p=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'shell','-T','su','-c',shlex.quote(command)],
                          stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
  def read():
   for line in self.p.stdout:self.lines.append(line.decode(errors='replace').replace('\r','').rstrip('\n'))
  self.reader=threading.Thread(target=read);self.reader.start()
  self.until(lambda: any(l.startswith('client.ready ') for l in self.lines))
  self.ready=rows('\n'.join(self.lines),'client.ready ')[0]
  assert self.ready['uid']==self.ready['euid']==result['uid']
 def until(self, condition, timeout=15):
  end=time.monotonic()+timeout
  while time.monotonic()<end:
   if condition():return
   if self.p.poll() is not None:raise RuntimeError('client exited '+repr(self.lines))
   time.sleep(.01)
  raise RuntimeError('client timeout '+repr(self.lines[-10:]))
 def send(self, phase, count):
  self.p.stdin.write(f'send {phase} {count} 0\n'.encode());self.p.stdin.flush()
  self.until(lambda: f'client.sent phase={phase} count={count}' in self.lines)
  return [f'{self.prefix}-{phase}-{i}' for i in range(count)]
 def received(self):return [l.split('=',1)[1] for l in self.lines if l.startswith('client.received nonce=')]
 def collect(self, names):self.until(lambda: all(n in self.received() for n in names))
 def close(self):
  try:self.p.stdin.write(b'quit\n');self.p.stdin.flush();self.p.stdin.close()
  except BrokenPipeError:pass
  try:self.p.wait(timeout=5)
  except subprocess.TimeoutExpired:
   root('kill -TERM '+self.ready['pid'],check=False)
   self.p.terminate();self.p.wait(timeout=5)
  self.reader.join(2)


result=dict(status='HOLD',source='NFQ_CAPTURED',profile='root',scope='primary-capacity-retained-completion',
            started_ns=time.time_ns(),serial=SERIAL,apk_sha256=hashlib.sha256(args.apk.read_bytes()).hexdigest(),cases=[],generations=[])
active=False;added=[];clients=[];publisher=None;echo_pid=None
wifi=adb('shell','settings','get','global','wifi_on').strip()
try:
 adb('shell','svc','wifi','disable');time.sleep(2)
 save('device.txt',adb('shell','getprop','ro.product.device')+adb('shell','uname','-a'))
 save('before.properties',app(STATE));save('install.txt',adb('install','-r',str(args.apk.resolve())))
 package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 with zipfile.ZipFile(args.apk) as z:expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 installed=save('installed-native-sha256.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]))
 assert expected=={Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()}
 result['native_sha256']=expected
 assert save('installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 result['uid']=adb('shell','run-as',PKG,'id','-u').strip()
 adb('shell','pm','grant',PKG,'android.permission.POST_NOTIFICATIONS',check=False)
 for address in HOSTS[6]:root('ip -6 addr add '+address+'/128 dev lo nodad');added.append(address)
 helpers={'s210-udp-client':ROOT/'build-output/s210-capacity/udp-client',
          's210-policy':ROOT/'build-output/s210-capacity/policy-client',
          's210-echo':ROOT/'build-output/s207-owner/echo'}
 result['helper_sha256']={n:hashlib.sha256(p.read_bytes()).hexdigest() for n,p in helpers.items()}
 for name,path in helpers.items():adb('push',str(path),'/data/local/tmp/'+name);adb('shell','chmod','755','/data/local/tmp/'+name)
 echo_pid=adb('shell','/data/local/tmp/s210-echo 40610 '+' '.join(HOSTS[4]+HOSTS[6])+' > /data/local/tmp/s210-echo.log 2>&1 & echo $!').strip()
 assert echo_pid.isdigit()
 for family in (4,6):
  for owner in (0,1):
   index=len(result['cases']);label=f'g{index}';active=True;running=start(label)
   generation=running['generation'];result['generations'].append(generation)
   publisher=ControlClient()
   assert 'packet.trace_limit=4096' in cli(label+'-trace-limit',['product packet-trace limit 4096'])
   initial=cli(label+'-initial',['show product root lanes','show product flows','show product primary','show threads'])
   revision=int(rows(initial,'policy.snapshot ')[0]['revision'])+1
   save(label+'-allow.txt',publisher.call(f'product policy publish {revision} 101 {result["uid"]} 10000','policy.publish=ok'))
   # Restrict only this generation's Product test chains to diagnostic OUTPUT.
   commands=[tool+' -t mangle -F '+chain for tool in ('iptables','ip6tables')
             for chain in ('SAKAMOTO_PRODUCT_S176_OUTPUT','SAKAMOTO_PRODUCT_S178_INPUT')]
   tool,span=('iptables','176:177') if family==4 else ('ip6tables','178:179')
   commands.append(f'{tool} -t mangle -A SAKAMOTO_PRODUCT_S176_OUTPUT -p udp --dport 40610 -m owner --uid-owner {result["uid"]} -j NFQUEUE --queue-balance {span}')
   save(label+'-narrow-hooks.txt',root(' && '.join(commands)))
   save(label+'-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
   case=dict(generation=generation,family=family,protocol=17,owner=owner,uid=int(result['uid']),
             sent=[],received=[],phases={},warm=[],revision=revision)
   selected=None
   def send(client,phase,count=1):
    names=client.send(phase,count);case['sent'].extend(names);case['phases'].setdefault(phase,[]).extend(names);return names
   def configure(phase,credits=32,primary=64,completion=128):
    drained(label+'-'+phase+'-drain')
    response=cli(label+'-'+phase,[f'product capacity credits {credits} primary-slots {primary} completion-slots {completion}'])
    assert 'capacity.configured' in response,response
   for attempt in range(32):
    c=DatagramClient(HOSTS[family][attempt%8],family,generation);clients.append(c)
    names=send(c,f'warm-{attempt}');c.collect(names)
    trace=save(label+f'-warm-{attempt}.log',root('cat '+BASE+'logs/vpp-stdout.log'))
    facts=[d for d in rows(trace,'s216 ') if d.get('stage')=='admit' and names[0].encode().hex() in d.get('raw','')]
    assert len(facts)==1,facts
    fact=facts[0];case['warm'].append(dict(nonce=names[0],port=int(c.ready['port']),host=HOSTS[family][attempt%8],
                                        owner=int(fact['owner']),origin=int(fact['worker']),pid=int(c.ready['pid'])))
    if int(fact['owner'])==owner and int(fact['worker'])!=owner:
     selected=c;case['selected']=case['warm'][-1];break
   assert selected is not None,'no actual remote flow found'
   configure('credit',credits=0);selected.collect(send(selected,'credit',8))
   configure('credit-off');selected.collect(send(selected,'credit-recovery',8))
   configure('enqueue',primary=2)
   save(label+'-hold.txt',publisher.call(f'product policy hold-next {owner} 500000','policy.hold=armed'))
   held=send(selected,'held')
   # The native sender's completion marker arrives while the actual first
   # packet is held. No per-command quit/barrier pauses the other worker.
   burst=send(selected,'enqueue',48);selected.collect(held+burst)
   configure('enqueue-off');selected.collect(send(selected,'enqueue-recovery',8))
   configure('completion',completion=2)
   policy_command=f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s210-policy {BASE}runtime/api.sock {generation} /data/local/tmp/s210-policy-state {revision+1} 1 {result["uid"]}'
   reply=save(label+'-drop.txt',root(policy_command));assert 'policy rc=0' in reply,reply
   for attempt in range(4):
    send(selected,f'drop-{attempt}',32);drained(label+f'-drop-{attempt}-drain')
    trace=save(label+f'-drop-{attempt}.log',root('cat '+BASE+'logs/vpp-stdout.log'))
    if 's210 event=completion_deferred' in trace:break
   assert 's210 event=completion_deferred' in trace,'return pressure not observed'
   configure('completion-off')
   save(label+'-allow-again.txt',publisher.call(f'product policy publish {revision+2} 303 {result["uid"]} 30000','policy.publish=ok'))
   selected.collect(send(selected,'completion-recovery',8))
   quiesce(label)
   cli(label+'-runtime',['show product root lanes','show product completion','show product primary','show product flows',
                        'show runtime','show threads','show node product-packet-policy','show node product-packet-origin-completion',
                        'show node product-packet-owner-guard'])
   save(label+'-vpp.log',root('cat '+BASE+'logs/vpp-stdout.log'))
   for j,c in enumerate(clients):
    case['received'].extend(c.received());c.close();save(label+f'-client-{j}.log','\n'.join(c.lines)+'\n')
   clients=[];publisher.close();publisher=None
   save(label+'-case.json',json.dumps(case,indent=2));result['cases'].append(case)
   save(label+'-endpoint.log',adb('shell','cat','/data/local/tmp/s210-echo.log'))
   runtime=(args.output/(label+'-runtime.txt')).read_text()
   actual_pid=re.search(r'^0\s+vpp_main\s+(\d+)',runtime,re.M).group(1)
   save(label+'-fds-before.txt',root('ls -l /proc/'+actual_pid+'/fd'))
   logs(label+'-before-stop')
   assert 'root.stop=ok' in cli(label+'-close',['product root stop'])
   cli(label+'-closed',['show product root lanes','show product completion','show product primary','show product flows'])
   save(label+'-fds-closed.txt',root('ls -l /proc/'+actual_pid+'/fd'))
   stop(label);active=False
   save(label+'-nfqueue-after.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
   save(label+'-hooks-after.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
   print('completed',generation,family,owner,flush=True)
 result['status']='RAW_COMPLETE'
except Exception as error:
 result['error']=repr(error)
 if active:logs('failure')
 raise
finally:
 for c in clients:c.close()
 if publisher is not None:publisher.close()
 if active:stop('finally')
 if echo_pid:adb('shell','kill',echo_pid,check=False)
 for address in added:root('ip -6 addr del '+address+'/128 dev lo',check=False)
 if wifi=='1':adb('shell','svc','wifi','enable')
 result['wifi_before']=wifi;result['wifi_after']=adb('shell','settings','get','global','wifi_on').strip()
 result['completed_ns']=time.time_ns()
 save('final-wifi.txt',result['wifi_after']+'\n')
 save('final-processes.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS'))
 save('result.json',json.dumps(result,indent=2)+'\n')
