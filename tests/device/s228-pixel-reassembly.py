#!/usr/bin/env python3
"""S228: native graph-injected IPv6 fragment ownership on Pixel."""
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
   if 'rejected' in text or 'unknown input' in text or 'requires an active empty graph' in text:raise RuntimeError(text)
  raise RuntimeError('persistent control timeout '+repr(response))
 def close(self):
  try:self.p.stdin.write(b'quit\n');self.p.stdin.flush();self.p.stdin.close()
  except BrokenPipeError:pass
  try:self.p.wait(timeout=5)
  except subprocess.TimeoutExpired:self.p.terminate();self.p.wait(timeout=5)
  self.selector.close()

def fragments(ident, sport=41212, size=24, step=16):
 import socket, struct
 src=socket.inet_pton(socket.AF_INET6,'fd20:6228::1')
 dst=socket.inet_pton(socket.AF_INET6,'fd20:6228::2')
 payload=struct.pack('!HHHH',sport,6212,size+8,0)+bytes(i%256 for i in range(size))
 pseudo=src+dst+struct.pack('!I3xB',len(payload),17)
 data=pseudo+payload
 if len(data)%2:data+=b'\0'
 value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
 while value>>16:value=(value&65535)+(value>>16)
 checksum=(~value)&65535
 payload=payload[:6]+struct.pack('!H',checksum or 65535)+payload[8:]
 result=[]
 for offset in range(0,len(payload),step):
  chunk=payload[offset:offset+step];more=offset+len(chunk)<len(payload)
  header=struct.pack('!IHBB16s16s',6<<28,8+len(chunk),44,64,src,dst)
  fragment=struct.pack('!BBHI',17,0,offset|int(more),ident)
  result.append((header+fragment+chunk).hex())
 return result

result=dict(status='HOLD',started_ns=time.time_ns(),source='GRAPH_INJECTED',
 serial=SERIAL,apk_sha256=hashlib.sha256(args.apk.read_bytes()).hexdigest(),cases=[])
active=False;control=None
wifi=adb('shell','settings','get','global','wifi_on').strip()
try:
 adb('shell','svc','wifi','disable')
 save('install.txt',adb('install','-r',str(args.apk.resolve())))
 package=save('package.txt',adb('shell','dumpsys','package',PKG))
 native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 with zipfile.ZipFile(args.apk) as z:
  expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 installed=save('installed-native-sha256.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]))
 assert expected=={Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()}
 result['native_sha256']=expected
 assert save('installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 active=True;result['generation']=start('first')['generation'];quiesce('first')
 cli('enable-native-trace',['trace add product-packet-admit 32'])
 control=ControlClient()
 save('configure.txt',control.call('product reassembly configure timeout-ms 10000 contexts 64','reassembly.configured'))
 save('policy.txt',control.call('product policy publish 21201 21201 21200 21200','policy.publish=ok'))
 case_id=0
 def inject(label, packets, workers=None):
  global case_id
  entries=[]
  for n,packet in enumerate(packets):
   case_id+=1;arrival=workers[n] if workers else n%2
   response=control.call(f'product reassembly inject {case_id} {packet} worker {arrival} uid 21200','reassembly.inject=accepted')
   save(f'inject-{case_id}.txt',response);entries.append(dict(case=case_id,hex=packet,worker=arrival))
  result['cases'].append(dict(label=label,packets=entries))
 if args.suite=='main':
  for index in range(8):
   worker=(index//2)%2;reverse=index>=4
   packets=fragments(21200+index,sport=41212+index)
   if reverse:packets.reverse()
   cases=[]
   for n,packet in enumerate(packets):
    case_id+=1;arrival=(worker+n)%2
    text=control.call(f'product reassembly inject {case_id} {packet} worker {arrival} uid 21200','reassembly.inject=accepted')
    save(f'inject-{case_id}.txt',text);cases.append(dict(case=case_id,hex=packet,worker=arrival))
   result['cases'].append(dict(index=index,reverse=reverse,packets=cases))
   time.sleep(.2)
  inject('six-originals',fragments(21220,41232,88))
  duplicate=fragments(21221,41233)
  inject('exact-duplicate',[duplicate[0],duplicate[0],duplicate[1]])
  time.sleep(.3)
  save('success-status.txt',control.call('show product reassembly','reassembly.status'))
  save('timeout-config.txt',control.call('product reassembly configure timeout-ms 100 contexts 64','reassembly.configured'))
  timeout_begin=time.monotonic()
  inject('timeout',fragments(21222,41234)[:1],[0])
  while True:
   text=control.call('show product reassembly','reassembly.status')
   save('timeout-status.txt',text)
   if 'contexts=0 originals=0 retained=0' in text:break
   if time.monotonic()-timeout_begin>10:raise RuntimeError('native timeout did not settle within 10s')
   time.sleep(.1)
  result['timeout_observed_seconds']=time.monotonic()-timeout_begin
  save('capacity-config.txt',control.call('product reassembly configure timeout-ms 10000 contexts 1','reassembly.configured'))
  first=fragments(21223,41235);second=fragments(21224,41236)
  inject('capacity',[first[0],second[0],first[1]],[0,0,0]);time.sleep(.3)
  bad=bytearray.fromhex(fragments(21225)[0]);bad[4:6]=(1000).to_bytes(2,'big')
  inject('malformed-length',[bad.hex()],[1]);time.sleep(.2)
  inject('atomic',fragments(21227,size=8),[1]);time.sleep(.2)
  inject('stop',fragments(21226)[:1],[0]);time.sleep(.2)
  save('before-flush.txt',control.call('show product reassembly','reassembly.status'))
  save('flush.txt',control.call('product root stop','root.stop='));time.sleep(.3)
 else:
  pair=fragments(21240);bad=bytearray.fromhex(pair[0]);bad[-1]^=255
  inject('conflict',[pair[0],bad.hex()]);time.sleep(.3)
  inject('one-byte-final',fragments(21241,size=9));time.sleep(.3)
  inject('oversize',fragments(21242,size=2200,step=208));time.sleep(.3)
  # Publish an explicit gate DROP through the real typed Product API.
  helper=ROOT/'build-output/s210-capacity/policy-client'
  result['policy_helper_sha256']=hashlib.sha256(helper.read_bytes()).hexdigest()
  adb('push',str(helper),'/data/local/tmp/s212-policy');adb('shell','chmod','755','/data/local/tmp/s212-policy')
  response=root(f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s212-policy {BASE}runtime/api.sock {result["generation"]} /data/local/tmp/s212-policy-state 21202 1 21200')
  save('drop-policy.txt',response);assert 'policy rc=0' in response
  inject('policy-drop',fragments(21243));time.sleep(.3)
 control.close();control=None
 drained('complete-drain')
 save('reassembly-status.txt',cli('reassembly',['show product reassembly','show runtime','show trace','show product flows','show product completion']))
 logs('before-stop')
 stop('complete');active=False
 result['status']='CAPTURED'
except Exception as error:
 result['error']=str(error)
 logs('failure')
 raise
finally:
 if control:
  try:control.close()
  except Exception:pass
 if active:
  try:stop('cleanup')
  except Exception as error:result['cleanup_error']=str(error)
 if wifi=='1':adb('shell','svc','wifi','enable',check=False)
 result['completed_ns']=time.time_ns()
 save('result.json',json.dumps(result,indent=2)+'\n')
