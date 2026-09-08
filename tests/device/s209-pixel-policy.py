#!/usr/bin/env python3
"""S209: real Pixel W2 traffic with concurrent immutable policy publication."""
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
 save(label+'-endpoint.log',adb('shell','cat','/data/local/tmp/s208-echo.log',check=False))
def stop(label):
 save(label+'.stop.txt',action('--ez','runtimeStop','true'))
 wait(label+'-stopped',STATE,{'state':'stopped','mayBeActive':'false','errorCode':''})
 s=save(label+'-cleanup.properties',app('files/product-state/s176-root-nfqueue-cleanup.properties'))
 assert 'productRootNfqueueResidueClean=true' in s
 s=save(label+'-process-after.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS'))
 assert not any('libvpp_runtime.so' in l for l in s.splitlines())
BASE='/data/user/0/'+PKG+'/files/profiles/root/vpp/'
HOSTS={4:['127.0.0.'+str(i) for i in range(1,9)],6:['fd20:6207::'+str(i) for i in range(1,9)]}
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

class Client:
 def __init__(self,host,port,protocol):
  # Android toybox's outbound path ignores -p/-s. Observe the kernel tuple.
  options=['-6' if ':' in host else '-4','-w','30','-q','1']
  if protocol==17:options.append('-u')
  table='tcp' if protocol==6 else 'udp';table+='6' if ':' in host else ''
  before=root('cat /proc/net/'+table)
  prior={l.split()[9] for l in before.splitlines()[1:] if len(l.split())>9}
  self.p=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'shell','-T','run-as',PKG,'toybox','nc',*options,host,'40608'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.selector=selectors.DefaultSelector();self.selector.register(self.p.stdout,selectors.EVENT_READ)
  deadline=time.monotonic()+25
  while time.monotonic()<deadline:
   self.socket_table=root('cat /proc/net/'+('tcp' if protocol==6 else 'udp')+('6' if ':' in host else ''))
   sockets=[l.split() for l in self.socket_table.splitlines()[1:] if len(l.split())>7]
   sockets=[d for d in sockets if d[7]==result['uid'] and d[9] not in prior and int(d[2].split(':')[1],16)==40608 and d[3]=='01']
   if len(sockets)==1:
    record=sockets[0];self.port=int(record[1].split(':')[1],16)
    def address(value):
     raw=bytes.fromhex(value.split(':')[0]);raw=b''.join(raw[i:i+4][::-1] for i in range(0,len(raw),4));return raw.rjust(16,b'\0').hex()
    self.source_ip=address(record[1]);self.destination_ip=address(record[2]);break
   if self.p.poll() is not None:raise RuntimeError('nc connect failed '+self.p.stderr.read().decode(errors='replace'))
   time.sleep(.2)
  else:raise RuntimeError('kernel socket did not establish '+self.socket_table)
 def send(self,value):self.p.stdin.write(value.encode());self.p.stdin.flush()
 def receive(self,value,timeout=35):
  deadline=time.monotonic()+timeout;response=b'';raw_response=b''
  while len(response)<len(value) and time.monotonic()<deadline:
   if not self.selector.select(min(1,max(0,deadline-time.monotonic()))):continue
   part=os.read(self.p.stdout.fileno(),4096)
   if not part:raise RuntimeError('nc closed '+self.p.stderr.read().decode(errors='replace'))
   raw_response+=part;response=raw_response.replace(b'\r\n',b'\n')
  self.last_response_raw=raw_response
  return response
 def close(self):
  try:self.p.stdin.close()
  except BrokenPipeError:pass
  try:self.p.wait(timeout=5)
  except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(timeout=5)
  self.selector.close()

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


spec=importlib.util.spec_from_file_location('owner_oracle',ROOT/'tests/device/s207-owner-oracle.py')
oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
result=dict(adb_stdout_newline='CRLF normalized to LF; kernel wire payload retains LF',status='HOLD',source='NFQ_CAPTURED',profile='root',scope='immutable-policy-snapshot',serial=SERIAL,apk_sha256=hashlib.sha256(args.apk.read_bytes()).hexdigest(),cases=[],generations=[])
pid=None;added=[];active=False;clients={};candidate=None;publisher=None
wifi=adb('shell','settings','get','global','wifi_on').strip()
try:
 adb('shell','svc','wifi','disable');time.sleep(2)
 save('device.txt',adb('shell','getprop','ro.product.device')+adb('shell','uname','-a'))
 save('before.properties',app(STATE));save('install.txt',adb('install','-r',str(args.apk.resolve())))
 package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 with zipfile.ZipFile(args.apk) as z:expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 installed=save('installed-native-sha256.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]));assert expected=={Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()}
 result['native_sha256']=expected;assert save('installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 result['uid']=adb('shell','run-as',PKG,'id','-u').strip();adb('shell','pm','grant',PKG,'android.permission.POST_NOTIFICATIONS',check=False)
 for address in HOSTS[6]:root('ip -6 addr add '+address+'/128 dev lo nodad');added.append(address)
 helper=ROOT/'build-output/s207-owner/echo';result['echo_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()
 adb('push',str(helper),'/data/local/tmp/s207-echo');adb('shell','chmod','755','/data/local/tmp/s207-echo')
 pid=adb('shell','/data/local/tmp/s207-echo 40608 '+' '.join(HOSTS[4]+HOSTS[6])+' > /data/local/tmp/s208-echo.log 2>&1 & echo $!').strip();assert pid.isdigit()
 for family in (4,6):
  for protocol in (17,6):
   index=len(result['cases']);label='g'+str(index);active=True;running=start(label)
   result['generations'].append(running['generation'])
   initial=cli(label+'-initial',['show product root lanes','show threads','show product flows'])
   base_revision=int(rows(initial,'policy.snapshot ')[0]['revision'])+1
   publisher=ControlClient()
   assert 'packet.trace_limit=4096' in cli(label+'-trace-limit',['product packet-trace limit 4096'])
   save(label+'-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
   case=dict(generation=running['generation'],uid=int(result['uid']),family=family,protocol=protocol,publications=[],ports={},nonces={0:[],1:[]},received={0:[],1:[]},hold_nonces={},warm_probes=[])
   send_locks={o:threading.Lock() for o in (0,1)};errors=[]
   def publish(revision,hash_value,rule):
    started=time.monotonic_ns();answer=save(label+'-publish-'+str(len(case['publications']))+'.txt',publisher.call(f'product policy publish {revision} {hash_value} {result["uid"]} {rule}','policy.publish=ok'))
    assert 'policy.publish=ok' in answer,answer
    case['publications'].append(dict(revision=revision,hash=hash_value,rule=rule,started_ns=started,completed_ns=time.monotonic_ns()))
   def send(owner,phase):
    with send_locks[owner]:
     nonce=f's209-{case["generation"]}-{owner}-{phase}-{time.time_ns()}'
     case['nonces'][owner].append(nonce);clients[owner].send(nonce+'\n');return nonce
   def read_one(owner,nonce):
    response=clients[owner].receive(nonce+'\n');assert response==(nonce+'\n').encode(),(nonce,response);case['received'][owner].append(nonce)
   publish(base_revision,101,10000)
   for attempt in range(64):
    host=HOSTS[family][attempt%len(HOSTS[family])];candidate=Client(host,0,protocol)
    assignment=oracle.assignment(dict(l3=1,l4=1,family=family,protocol=protocol,src=candidate.source_ip,dst=candidate.destination_ip,src_port=candidate.port,dst_port=40608,icmp_known=0))
    owner=assignment['owner'];nonce=f's209-{case["generation"]}-{owner}-warm-{attempt}-{time.time_ns()}'
    candidate.send(nonce+'\n');response=candidate.receive(nonce+'\n');save(label+'-warm-stdout-'+str(attempt)+'.hex',candidate.last_response_raw.hex());assert response==(nonce+'\n').encode(),repr(response)
    case['nonces'][owner].append(nonce);case['received'][owner].append(nonce)
    trace=save(label+'-warm-trace.log',root('cat '+BASE+'logs/vpp-stdout.log'))
    facts=[d for d in rows(trace,'s216 ') if d.get('stage')=='admit' and nonce.encode().hex() in d.get('raw','')]
    assert facts and int(facts[0]['owner'])==owner
    lane=int(facts[0]['origin_lane']);case['warm_probes'].append(dict(owner=owner,port=candidate.port,lane=lane,host=host,nonce=nonce))
    save(label+'-socket-'+str(attempt)+'.txt',candidate.socket_table)
    if owner not in clients and lane%2==owner:
     clients[owner]=candidate;case['ports'][owner]=candidate.port;candidate=None
    else:candidate.close();candidate=None
    if set(clients)=={0,1}:break
   assert set(clients)=={0,1},case['warm_probes']
   drained(label+'-warm-drain');cli(label+'-warm',['show product flows'])
   # Keep the other real socket active through the bounded old-reader hold.
   feed=[]
   def feed_other():
    try:
     for n in range(16):feed.append(send(1,'hold-feed-'+str(n)));time.sleep(.05)
    except Exception as e:errors.append(repr(e))
   feeder=threading.Thread(target=feed_other);feeder.start()
   assert 'policy.hold=armed' in save(label+'-hold-arm.txt',publisher.call('product policy hold-next 0 500000','policy.hold=armed'))
   case['hold_nonces']['old']=send(0,'held')
   deadline=time.monotonic()+8
   while True:
    trace=save(label+'-hold-observed.log',root('cat '+BASE+'logs/vpp-stdout.log'))
    if 's209 event=hold_begin' in trace:break
    assert time.monotonic()<deadline,'held wire packet did not reach owner';time.sleep(.01)
   publish(base_revision+1,202,20000)
   case['hold_nonces']['new']=send(1,'during-hold')
   publish(base_revision+1,203,21000)
   feeder.join(3);assert not feeder.is_alive() and not errors
   read_one(0,case['hold_nonces']['old'])
   # Several echo lines can share one TCP/adb read, so consume complete lines.
   expected_other=len(case['nonces'][1]);pending=b'';deadline=time.monotonic()+35
   while len(case['received'][1])<expected_other:
    assert time.monotonic()<deadline,'hold feed echo timeout'
    if not clients[1].selector.select(.5):continue
    data=os.read(clients[1].p.stdout.fileno(),4096);assert data,'hold feed EOF';pending+=data
    while b'\n' in pending:line,pending=pending.split(b'\n',1);case['received'][1].append(line.decode().removesuffix('\r'))
   assert not pending and case['received'][1]==case['nonces'][1]
   drained(label+'-held-drain');cli(label+'-after-hold',['show product flows'])
   receive_targets={o:len(case['received'][o])+33 for o in (0,1)}
   def receiver(owner):
    pending=b'';deadline=time.monotonic()+65
    try:
     while len(case['received'][owner])<receive_targets[owner]:
      assert time.monotonic()<deadline,'steady receiver timeout'
      if not clients[owner].selector.select(.5):continue
      data=os.read(clients[owner].p.stdout.fileno(),4096);assert data,'steady EOF';pending+=data
      while b'\n' in pending:line,pending=pending.split(b'\n',1);case['received'][owner].append(line.decode().removesuffix('\r'))
    except Exception as e:errors.append(repr(e))
   def sender(owner):
    try:
     for n in range(32):send(owner,'steady-'+str(n));time.sleep(.25)
    except Exception as e:errors.append(repr(e))
   receivers=[threading.Thread(target=receiver,args=(o,)) for o in (0,1)];senders=[threading.Thread(target=sender,args=(o,)) for o in (0,1)]
   case['steady_started_ns']=time.monotonic_ns()
   for t in receivers+senders:t.start()
   for n in range(24):publish(base_revision+2+n,(n+3)*100+1,(n+3)*10000);time.sleep(.12)
   for t in senders:t.join(15);assert not t.is_alive()
   for o in (0,1):send(o,'tail')
   for t in receivers:t.join(40);assert not t.is_alive()
   case['steady_completed_ns']=time.monotonic_ns();assert not errors,errors
   assert all(case['received'][o]==case['nonces'][o] for o in (0,1))
   publisher.close();publisher=None
   for c in clients.values():c.close()
   clients.clear();time.sleep(.2);drained(label+'-after-close');quiesce(label)
   logs(label+'-before-stop');cli(label+'-flow-final',['show product flows'])
   save(label+'-case.json',json.dumps(case,indent=2));result['cases'].append(case)
   runtime=(args.output/(label+'-before-stop-vpp-runtime.txt')).read_text();actual_pid=re.search(r'^0\s+vpp_main\s+(\d+)',runtime,re.M).group(1)
   save(label+'-fds-before.txt',root('ls -l /proc/'+actual_pid+'/fd'))
   assert 'root.stop=ok' in cli(label+'-close',['product root stop'])
   cli(label+'-closed',['show product root lanes','show product completion','show product primary','show product flows'])
   save(label+'-fds-closed.txt',root('ls -l /proc/'+actual_pid+'/fd'));stop(label);active=False
   save(label+'-kernel-queues-after-stop.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
   save(label+'-hooks-after-stop.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
   print('completed',case['generation'],family,protocol,flush=True)
 result['status']='RAW_COMPLETE'
except Exception as e:
 result['error']=repr(e)
 try:logs('failure')
 except Exception:pass
 raise
finally:
 if publisher is not None:
  try:publisher.close()
  except Exception:pass
 if candidate is not None:
  try:candidate.close()
  except Exception:pass
 for c in clients.values():
  try:c.close()
  except Exception:pass
 if active:
  try:stop('failure')
  except Exception as e:result['cleanup_error']=repr(e)
 if pid and pid.isdigit():adb('shell','kill',pid,check=False)
 for address in added:root('ip -6 addr del '+address+'/128 dev lo',check=False)
 if wifi=='1':adb('shell','svc','wifi','enable')
 result['wifi_before']=wifi;result['wifi_after']=adb('shell','settings','get','global','wifi_on').strip()
 save('result.json',json.dumps(result,indent=2)+'\n');print('status',result['status'],'wifi',result['wifi_after'],flush=True)
