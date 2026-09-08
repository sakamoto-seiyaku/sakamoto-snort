#!/usr/bin/env python3
"""S231: real Pixel kernel fragment visibility."""
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


NET='/data/local/tmp/s231-net'
def pull_binary(remote, local):
 # The repo wrapper translates existing WSL paths for Windows adb. Create the
 # destination first so binary pull uses that supported path conversion.
 local.touch()
 adb('pull',remote,str(local.resolve()))
 expected=root('sha256sum '+shlex.quote(remote)).split()[0]
 assert hashlib.sha256(local.read_bytes()).hexdigest()==expected,'binary transfer hash'
 return expected
result=dict(status='HOLD',started_ns=time.time_ns(),source='NFQ_CAPTURED',profile='root',
            serial=SERIAL,apk_sha256=hashlib.sha256(args.apk.read_bytes()).hexdigest(),cases=[],generations=[])
wifi=adb('shell','settings','get','global','wifi_on').strip()
active=False;link=False;rules=[];echo_pid=None;capture_pid=None
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
 helpers={'s231-net':ROOT/'build-output/s231-fragments/pixel-net','s231-policy':ROOT/'build-output/s210-capacity/policy-client',
          's231-echo':ROOT/'build-output/s207-owner/echo'}
 result['helper_sha256']={n:hashlib.sha256(p.read_bytes()).hexdigest() for n,p in helpers.items()}
 for n,p in helpers.items():adb('push',str(p),'/data/local/tmp/'+n);adb('shell','chmod','755','/data/local/tmp/'+n)
 save('rules-before.txt',root('ip -4 rule show; ip -6 rule show'))
 root('ip link add s231tx type veth peer name s231rx');link=True
 for name in ('s231tx','s231rx'):root(f'ip link set {name} mtu 1280 up')
 root('ip addr add 198.18.231.2/24 dev s231rx')
 root('ip -6 addr add fd20:6231::2/64 dev s231rx nodad')
 # Android does not put this interface's automatic IPv6 prefix route in main.
 # Supply the exact test-only route selected by the destination rule below.
 root('ip -6 route add fd20:6231::/64 dev s231rx table main metric 1')
 mac=re.search(r'link/ether\s+([0-9a-f:]+)',root('ip link show dev s231tx')).group(1)
 root(f'ip neigh add 198.18.231.1 lladdr {mac} dev s231rx nud permanent')
 root(f'ip -6 neigh add fd20:6231::1 lladdr {mac} dev s231rx nud permanent')
 for family,prefix in ((4,'198.18.231.0/24'),(6,'fd20:6231::/64')):
  before=root(f'ip -{family} rule show');assert not re.search(r'^9987:',before,re.M)
  rule=f'ip -{family} rule add pref 9987 to {prefix} lookup main';root(rule);rules.append(rule.replace(' add ',' del '))
 save('link.txt',root('ip -d link show; ip addr show; ip route show table main; ip -6 route show table main; ip -4 rule show; ip -6 rule show'))
 save('route-targets.txt',root('ip -4 route get 198.18.231.1 oif s231rx; ip -6 route get fd20:6231::1 oif s231rx'))
 save('netfilter-before.txt',root('cat /proc/modules; cat /proc/net/nf_conntrack; cat /proc/sys/net/netfilter/nf_conntrack_count',check=False))
 echo_pid=adb('shell','/data/local/tmp/s231-echo 40631 127.0.0.1 ::1 198.18.231.2 fd20:6231::2 > /data/local/tmp/s231-echo.log 2>&1 & echo $!').strip()
 assert echo_pid.isdigit()
 for family in (4,6):
  for hook in ('INPUT','OUTPUT'):
   index=len(result['cases']);label=f'g{index}';active=True;running=start(label)
   generation=running['generation'];result['generations'].append(generation)
   assert 'packet.trace_limit=4096' in cli(label+'-trace-limit',['product packet-trace limit 4096'])
   initial=cli(label+'-initial',['show product root lanes','show product flows','show product primary','show threads'])
   revision=int(rows(initial,'policy.snapshot ')[0]['revision'])+1
   case=dict(generation=generation,family=family,hook=hook,uid=int(result['uid']),fragments=[],probes=[],peer_controls=[])
   tool,span=('iptables','176:177') if family==4 else ('ip6tables','178:179')
   local,peer=('198.18.231.2','198.18.231.1') if family==4 else ('fd20:6231::2','fd20:6231::1')
   def policy(phase,revision,blocked):
    command=f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s231-policy {BASE}runtime/api.sock {generation} /data/local/tmp/s231-policy-state {revision} {blocked} {result["uid"]}'
    reply=save(label+'-'+phase+'.txt',root(command));assert 'policy rc=0' in reply,reply
   def clear():
    commands=[t+' -t mangle -F '+chain for t in ('iptables','ip6tables')
              for chain in ('SAKAMOTO_PRODUCT_S176_OUTPUT','SAKAMOTO_PRODUCT_S178_INPUT')]
    root(' && '.join(commands))
   def stable(phase,seconds=1):
    end=time.monotonic()+20;since=time.monotonic();last=None
    while time.monotonic()<end:
     lanes,d=snapshot(label+'-'+phase);counts=tuple(r['captured'] for r in lanes)
     if counts!=last or any(d[k]!='0' for k in ('pending','frames','buffers','obligations')):since=time.monotonic()
     elif time.monotonic()-since>=seconds:return
     last=counts;time.sleep(.15)
    raise RuntimeError('stable drain timeout '+str(d))
   def probe(phase,protocol,blocked=False):
    nonce=f's231-{generation}-{phase}-{protocol}'
    command=f'{NET} probe {result["uid"]} {family} {protocol} '+('127.0.0.1' if family==4 else '::1')+f' 40631 {nonce}'+(' drop' if blocked else '')
    reply=save(label+'-'+phase+'-'+str(protocol)+'.txt',root(command))
    assert ('probe.blocked' if blocked else 'probe uid=') in reply,reply
    case['probes'].append(dict(nonce=nonce,protocol=protocol,phase=phase,expected='drop' if blocked else 'echo'))
   def baseline(phase):
    clear()
    commands=[]
    for proto in ('udp','tcp'):
     commands.append(f'{tool} -t mangle -A SAKAMOTO_PRODUCT_S176_OUTPUT -o lo -p {proto} --dport 40631 -m owner --uid-owner {result["uid"]} -j NFQUEUE --queue-balance {span}')
     commands.append(f'{tool} -t mangle -A SAKAMOTO_PRODUCT_S178_INPUT -i lo -p {proto} --sport 40631 -j NFQUEUE --queue-balance {span}')
    root(' && '.join(commands));save(label+'-'+phase+'-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    for protocol in (17,6):probe(phase,protocol)
    stable(phase+'-drain')
   policy('allow',revision,0);baseline('before');clear()
   source,destination=(peer,local) if hook=='INPUT' else (local,peer)
   chain='SAKAMOTO_PRODUCT_S178_INPUT' if hook=='INPUT' else 'SAKAMOTO_PRODUCT_S176_OUTPUT'
   placement='-i s231rx' if hook=='INPUT' else '-o s231rx -m owner --uid-owner '+result['uid']
   root(f'{tool} -t mangle -A {chain} {placement} -s {source} -d {destination} -j NFQUEUE --queue-balance {span}')
   save(label+'-fragment-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
   save(label+'-snmp-before.txt',root('cat /proc/net/snmp; cat /proc/net/snmp6'))
   remote_pcap=f'/data/local/tmp/s231-{label}-wire.pcap';remote_log=f'/data/local/tmp/s231-{label}-capture.log'
   cap_if='s231rx' if hook=='INPUT' else 's231tx'
   capture_pid=root(f'{NET} capture {cap_if} {remote_pcap} > {remote_log} 2>&1 & echo $!').strip();assert capture_pid.isdigit()
   deadline=time.monotonic()+5
   while 'capture.ready' not in root('cat '+remote_log):
    assert time.monotonic()<deadline;time.sleep(.1)
   if hook=='INPUT':
    nonce=f's231-{generation}-peer-before';identity=23000+index*10
    save(label+'-peer-before.txt',root(f'{NET} inject-whole {result["uid"]} {family} s231tx s231rx {source} {destination} {identity} 0 {nonce}'))
    case['peer_controls'].append(dict(nonce=nonce,id=identity));stable('peer-before-drain')
   for reverse in (0,1):
    identity=(23100+index*10+reverse) if family==4 else (0x23100000+index*10+reverse)
    mode='inject' if hook=='INPUT' else 'raw';nonce=f's231-{generation}-{hook}-raw-{reverse}'
    tx,rx=('s231tx','s231rx') if hook=='INPUT' else ('s231rx','s231tx')
    reply=root(f'{NET} {mode} {result["uid"]} {family} {tx} {rx} {source} {destination} {identity} {reverse} {nonce}')
    save(label+f'-raw-{reverse}.txt',reply)
    case['fragments'].append(dict(mode=mode,id=identity,reverse=reverse,nonce=nonce,source=source,destination=destination))
    stable(f'raw-{reverse}-drain')
   if hook=='INPUT':
    nonce=f's231-{generation}-peer-after';identity=23001+index*10
    save(label+'-peer-after.txt',root(f'{NET} inject-whole {result["uid"]} {family} s231tx s231rx {source} {destination} {identity} 0 {nonce}'))
    case['peer_controls'].append(dict(nonce=nonce,id=identity))
   else:
    nonce=f's231-{generation}-kernel-fragment'
    save(label+'-kernel-send.txt',root(f'{NET} kernel {result["uid"]} {family} s231rx {local} {peer} {nonce}'));case['kernel_nonce']=nonce
   stable('fragment-drain',seconds=4.2)
   root('kill -TERM '+capture_pid)
   deadline=time.monotonic()+5
   while 'capture.closed' not in root('cat '+remote_log):
    assert time.monotonic()<deadline;time.sleep(.1)
   capture_pid=None
   save(label+'-capture.log',root('cat '+remote_log))
   save(label+'-pcap-sha256.txt',pull_binary(remote_pcap,args.output/(label+'-wire.pcap'))+'\n')
   save(label+'-snmp-after.txt',root('cat /proc/net/snmp; cat /proc/net/snmp6'))
   save(label+'-conntrack.txt',root('cat /proc/net/nf_conntrack; cat /proc/sys/net/netfilter/nf_conntrack_count',check=False))
   baseline('after');policy('drop-policy',revision+1,1);probe('drop',17,True);stable('drop-drain')
   policy('allow-recovery',revision+2,0);probe('recovery',17);quiesce(label)
   cli(label+'-runtime',['show product root lanes','show product completion','show product primary','show product flows','show runtime','show threads'])
   save(label+'-vpp.log',root('cat '+BASE+'logs/vpp-stdout.log'))
   save(label+'-case.json',json.dumps(case,indent=2));result['cases'].append(case)
   save(label+'-endpoint.log',adb('shell','cat','/data/local/tmp/s231-echo.log'))
   runtime=(args.output/(label+'-runtime.txt')).read_text();actual_pid=re.search(r'^0\s+vpp_main\s+(\d+)',runtime,re.M).group(1)
   save(label+'-fds-before.txt',root('ls -l /proc/'+actual_pid+'/fd'))
   logs(label+'-before-stop');assert 'root.stop=ok' in cli(label+'-close',['product root stop'])
   cli(label+'-closed',['show product root lanes','show product completion','show product primary','show product flows'])
   save(label+'-fds-closed.txt',root('ls -l /proc/'+actual_pid+'/fd'))
   stop(label);active=False
   save(label+'-nfqueue-after.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
   save(label+'-hooks-after.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
   print('completed',generation,family,hook,flush=True)
 result['status']='RAW_COMPLETE'
except Exception as error:
 result['error']=repr(error)
 if active:
  try:logs('failure')
  except Exception:pass
 raise
finally:
 try:
  if capture_pid:root('kill -TERM '+capture_pid,check=False)
  if active:
   try:stop('finally')
   except Exception as error:result['cleanup_error']=repr(error)
  if echo_pid:adb('shell','kill',echo_pid,check=False)
  for rule in rules:root(rule,check=False)
  if link:root('ip link del s231tx',check=False)
  save('links-after.txt',root('ip -d link show'))
  save('rules-after.txt',root('ip -4 rule show; ip -6 rule show'))
  save('routes-after.txt',root('ip route show table main; ip -6 route show table main'))
 finally:
  if wifi=='1':adb('shell','svc','wifi','enable')
  result['wifi_before']=wifi;result['wifi_after']=adb('shell','settings','get','global','wifi_on').strip()
  result['completed_ns']=time.time_ns();save('final-wifi.txt',result['wifi_after']+'\n')
  save('final-processes.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS'))
  save('result.json',json.dumps(result,indent=2)+'\n')
