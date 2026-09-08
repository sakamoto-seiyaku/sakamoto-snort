#!/usr/bin/env python3
"""S208: actual Pixel persistent TCP/UDP owner-local FlowEntry acceptance."""
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
  self.p=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'shell','-T','run-as',PKG,'toybox','nc',*options,host,'40608'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.selector=selectors.DefaultSelector();self.selector.register(self.p.stdout,selectors.EVENT_READ)
  deadline=time.monotonic()+25
  while time.monotonic()<deadline:
   self.socket_table=root('cat /proc/net/'+('tcp' if protocol==6 else 'udp')+('6' if ':' in host else ''))
   sockets=[l.split() for l in self.socket_table.splitlines()[1:] if len(l.split())>7]
   sockets=[d for d in sockets if d[7]==result['uid'] and int(d[2].split(':')[1],16)==40608 and d[3]=='01']
   if len(sockets)==1:self.port=int(sockets[0][1].split(':')[1],16);break
   if self.p.poll() is not None:raise RuntimeError('nc connect failed '+self.p.stderr.read().decode(errors='replace'))
   time.sleep(.2)
  else:raise RuntimeError('kernel socket did not establish '+self.socket_table)
 def send(self,value):self.p.stdin.write(value.encode());self.p.stdin.flush()
 def receive(self,value,timeout=35):
  deadline=time.monotonic()+timeout;response=b''
  while len(response)<len(value) and time.monotonic()<deadline:
   if not self.selector.select(min(1,max(0,deadline-time.monotonic()))):continue
   part=os.read(self.p.stdout.fileno(),4096)
   if not part:raise RuntimeError('nc closed '+self.p.stderr.read().decode(errors='replace'))
   response+=part
  return response
 def close(self):
  try:self.p.stdin.close()
  except BrokenPipeError:pass
  try:self.p.wait(timeout=5)
  except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(timeout=5)
  self.selector.close()

def policy(label,family=None,protocol=None,blocked=False):
 before=rows(cli(label+'-before',['show product flows']),'flow.pool ')[0]
 if family is None:save(label+'-request.txt',action('--ez','debugApplyEmptyPolicy','true'))
 else:
  save(label+'-request.txt',action('--es','debugSetL4RuleSubject','android.uid:'+result['uid'],'--es','debugSetL4RuleFamily','ipv4' if family==4 else 'ipv6','--es','debugSetL4RuleSourceCidr','0.0.0.0/0' if family==4 else '::/0','--es','debugSetL4RuleDestinationCidr','0.0.0.0/0' if family==4 else '::/0','--ei','debugSetL4RuleSourcePortFirst','0','--ei','debugSetL4RuleSourcePortLast','65535','--ei','debugSetL4RuleDestinationPortFirst','40608','--ei','debugSetL4RuleDestinationPortLast','40608','--ei','debugSetL4RuleIpProtocol',str(protocol),'--es','debugSetL4RuleDirection','output','--es','debugSetL4RuleAction','drop' if blocked else 'allow','--ei','debugSetL4RulePriority','0','--ei','debugSetL4RuleOrder','0'))
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  response=cli(label+'-after',['show product flows']);after=rows(response,'flow.pool ')[0]
  if (after['revision'],after['snapshot_hash'])!=(before['revision'],before['snapshot_hash']):return int(after['revision'])
  time.sleep(.2)
 raise RuntimeError('policy revision did not advance '+app('files/product-state/s192-root-vpn-l4-matrix.properties'))

def drop_probe(label,host,port,protocol):
 nonce='s208-'+label+'-'+str(time.time_ns())
 if protocol==17:
  save(label+'-request.txt',action('--ez','debugUdpTraffic','true','--es','debugUdpHost',host,'--ei','debugUdpPort','40608','--ei','debugUdpSourcePort',str(port),'--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true','--ez','debugTrafficBindToVpn','false','--ei','debugUdpTimeoutMillis','200'))
  d=wait(label+'-probe','files/debug/udp-traffic-probe.properties',{'nonce':nonce});assert d['result']=='udp_datagram_failed',(label,d)
 else:
  save(label+'-request.txt',action('--ez','debugTraffic','true','--es','debugTrafficHost',host,'--ei','debugTrafficPort','40608','--ei','debugTrafficSourcePort',str(port),'--es','debugTrafficNonce',nonce,'--ez','debugTrafficBindToVpn','false','--ei','debugTrafficTimeoutMillis','200'))
  d=wait(label+'-probe','files/debug/traffic-probe.properties',{'nonce':nonce});assert d['result']=='tcp_connect_failed',(label,d)
 drained(label+'-drained');return nonce

result={'status':'HOLD','source':'NFQ_CAPTURED','profile':'root','scope':'owner-local-flowentry','serial':SERIAL,'apk_sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest(),'cases':[],'generations':[]}
pid=None;added=[];wifi=adb('shell','settings','get','global','wifi_on').strip();active=False;client=None
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
 for address in HOSTS[6]:
  root('ip -6 addr add '+address+'/128 dev lo nodad');added.append(address)
 adb('push',str(ROOT/'build-output/s207-owner/echo'),'/data/local/tmp/s207-echo');adb('shell','chmod','755','/data/local/tmp/s207-echo')
 pid=adb('shell','/data/local/tmp/s207-echo 40608 '+' '.join(HOSTS[4]+HOSTS[6])+' > /data/local/tmp/s208-echo.log 2>&1 & echo $!').strip();assert pid.isdigit(),pid
 reference=json.loads((args.reference_run/'result.json').read_text()) if args.reference_run else None
 for family in (4,6):
  for protocol,mode in ((17,'normal'),(6,'normal'),(6,'midstream')):
   coverage=set();candidates=[]
   if reference:
    selected={}
    for c in reference['cases']:
     if c['family']==family and c['protocol']==protocol:selected.setdefault((c['lane'],c['owner']),(c['host'],c['port']%2))
    candidates=list(selected.values())
   candidates=list(dict.fromkeys(candidates+[(h,p) for h in HOSTS[family] for p in (0,1)]))*4
   for host,parity in candidates:
    index=len(result['generations']);label='g'+str(index);port=0
    if mode=='midstream':
     client=Client(host,port,protocol);time.sleep(.4)
     save(label+'-before-start-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    active=True;running=start(label);result['generations'].append(running['generation'])
    drop_port=10000+int(running['generation'])*8+parity
    cli(label+'-initial',['show product root lanes','show threads','show product flows'])
    save(label+'-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    case=dict(generation=running['generation'],family=family,protocol=protocol,mode=mode,host=host,source_port=port,nonces=[],revisions=[])
    if mode=='normal':
     case['drop_revision']=policy(label+'-drop-policy',family,protocol,True)
     case['drop_port']=drop_port
     case['drop_nonce']=drop_probe(label+'-drop',host,drop_port,protocol)
     pools=rows(cli(label+'-drop-flows',['show product flows']),'flow.pool ')
     assert all(d['entries']==d['allocations']=='0' for d in pools) and sum(int(d['early_drops']) for d in pools)>0,pools
     case['revisions'].append(policy(label+'-allow-policy',family,protocol,False))
    else:case['revisions'].append(policy(label+'-allow-policy',family,protocol,False))
    if client is None:client=Client(host,port,protocol)
    port=client.port;case['source_port']=port;save(label+'-kernel-socket.txt',client.socket_table)
    for phase in (0,1):
     if phase==1:case['revisions'].append(policy(label+'-successor-policy'))
     nonce='s208-'+label+'-r'+str(phase)+'-'+str(time.time_ns());case['nonces'].append(nonce)
     client.send(nonce);response=client.receive(nonce);save(label+'-echo-'+str(phase)+'.txt',response.decode(errors='replace'));assert response==nonce.encode(),(nonce,response)
     drained(label+'-r'+str(phase)+'-drain')
     cli(label+'-r'+str(phase)+'-flows',['show product flows','show product primary','show product completion'])
    client.close();client=None;time.sleep(.2);drained(label+'-after-close')
    quiesce(label);logs(label+'-before-stop');cli(label+'-flow-final',['show product flows'])
    trace=(args.output/(label+'-before-stop-vpp-stdout.log')).read_text()
    facts=[d for d in rows(trace,'s216 ') if d.get('stage')=='admit' and d['source']=='NFQ_CAPTURED' and int(d['protocol'])==protocol and (int(d['src_port'])==port or int(d['dst_port'])==port)]
    assert facts
    case['lane']=int(facts[0]['origin_lane']);case['owner']=int(facts[0]['owner']);coverage.add((case['lane'],case['owner']));result['cases'].append(case)
    runtime=(args.output/(label+'-before-stop-vpp-runtime.txt')).read_text();actual_pid=re.search(r'^0\s+vpp_main\s+(\d+)',runtime,re.M).group(1)
    save(label+'-fds-before.txt',root('ls -l /proc/'+actual_pid+'/fd'))
    response=cli(label+'-close',['product root stop']);assert 'root.stop=ok' in response,response
    cli(label+'-closed',['show product root lanes','show product completion','show product primary','show product flows'])
    save(label+'-fds-closed.txt',root('ls -l /proc/'+actual_pid+'/fd'))
    stop(label);active=False
    save(label+'-kernel-queues-after-stop.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
    save(label+'-hooks-after-stop.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    print(label,family,protocol,mode,sorted(coverage),flush=True)
    target={(lane,owner) for lane in ((0,1) if family==4 else (2,3)) for owner in (0,1)}
    if coverage==target:break
   assert coverage==target,(family,protocol,mode,coverage)
 result['status']='RAW_COMPLETE'
except Exception as e:
 result['error']=repr(e)
 try:logs('failure')
 except Exception:pass
 raise
finally:
 if client is not None:
  try:client.close()
  except Exception:pass
 if active:
  try:stop('failure')
  except Exception as e:result['cleanup_error']=repr(e)
 if pid and pid.isdigit():adb('shell','kill',pid,check=False)
 for address in added:root('ip -6 addr del '+address+'/128 dev lo',check=False)
 if wifi=='1':adb('shell','svc','wifi','enable',check=False)
 result['wifi_before']=wifi;result['wifi_after']=adb('shell','settings','get','global','wifi_on').strip()
 save('result.json',json.dumps(result,indent=2)+'\n');print('status',result['status'],'cases',len(result['cases']),'wifi',result['wifi_after'],flush=True)
