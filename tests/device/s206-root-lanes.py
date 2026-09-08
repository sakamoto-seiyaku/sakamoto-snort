#!/usr/bin/env python3
"""S206: real dual-stack Q2/W2 and independent origin lane closure."""
import argparse, hashlib, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SERIAL="28201JEGR0XPAJ"; PKG="com.sakamoto.snort.androidruntime"
a=argparse.ArgumentParser();a.add_argument('--apk',type=Path,required=True);a.add_argument('--output',type=Path,required=True);args=a.parse_args();args.output.mkdir(parents=True,exist_ok=False)
def save(n,t): (args.output/n).write_text(t);return t
def adb(*p,check=True):
 r=subprocess.run([str(ROOT/'dev/adb'),'-s',SERIAL,*p],text=True,errors="replace",stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=30)
 if check and r.returncode:raise RuntimeError(r.stdout)
 return r.stdout.replace('\r','')
def app(p):return adb('shell','run-as',PKG,'cat',p,check=False)
def props(s):return dict(l.split('=',1) for l in s.splitlines() if '=' in l and not l.startswith('#'))
def action(*p):return adb('shell','am','start','-n',PKG+'/.DebugControlActivity',*p)
def wait(label,path,match):
 end=time.monotonic()+30;next_query=0
 while time.monotonic()<end:
  if path in (GATE,STATUS) and time.monotonic()>=next_query:
   action("--ez","debugRefresh","true");next_query=time.monotonic()+1
  s=save(label+'.poll',app(path));d=props(s)
  if label in ('first','restart'):
   bootstrap=save(label+'-bootstrap.log',adb('shell','su','-c',shlex.quote('cat /data/user/0/'+PKG+'/files/profiles/root/vpp/logs/vpp-stdout.log'),check=False))
   with (args.output/(label+'-bootstrap-history.log')).open('a') as history:history.write(bootstrap+'\n')
  if all(d.get(k)==v for k,v in match.items()):save(label+'.properties',s);return d
  if d.get('errorCode')=='root_authorization_required':raise RuntimeError('Restore KernelSU app grant')
  time.sleep(.35)
 raise RuntimeError(label+' timeout: '+str(d))
STATE='files/runtime-state/snapshot.properties';STATUS='files/product-state/s176-root-nfqueue-output.properties';GATE='files/product-state/s189-root-network-gate.properties'
def start(label):
 save(label+'.start.txt',action('--ez','runtimeStart','true','--es','runtimeProfile','root'))
 return wait(label,STATE,{'state':'running','adapterReadiness':'root-nfqueue-udp-dualstack-q2w2','protectionRunning':'true'})
def logs(label):
 base='/data/user/0/'+PKG+'/files/profiles/root/vpp/'
 for name in ['logs/vpp-stdout.log','logs/vpp.log','runtime/startup.conf','owner.properties']:
  save(label+'-'+Path(name).name,adb('shell','su','-c',shlex.quote('cat '+shlex.quote(base+name)),check=False))
 if 'before-stop' in label or label=='failure':
  command="printf 'show product root lanes\\nshow product completion\\nshow product primary\\nshow runtime\\nshow threads\\nshow node product-packet-origin-completion\\nshow node product-packet-policy\\nshow node product-packet-owner-guard\\nquit\\n' | toybox nc -U -w 2 -q 1 "+shlex.quote(base+'runtime/cli.sock')
  save(label+'-vpp-runtime.txt',adb('shell','su','-c',shlex.quote(command),check=False))
  save(label+'-post-cli-vpp-stdout.log',adb('shell','su','-c',shlex.quote('cat '+shlex.quote(base+'logs/vpp-stdout.log')),check=False))
 save(label+'-status.properties',app(STATUS));save(label+'-gate.properties',app(GATE));save(label+'-l4.properties',app('files/product-state/s192-root-vpn-l4-matrix.properties'))
 save(label+'-endpoint.log',adb('shell','cat','/data/local/tmp/s206-echo.log',check=False))
def stop(label):
 save(label+'.stop.txt',action('--ez','runtimeStop','true'))
 wait(label+'-stopped',STATE,{'state':'stopped','mayBeActive':'false','errorCode':''})
 s=save(label+'-cleanup.properties',app('files/product-state/s176-root-nfqueue-cleanup.properties'))
 assert 'productRootNfqueueResidueClean=true' in s
 s=save(label+'-process-after.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS'))
 assert not any('libvpp_runtime.so' in l for l in s.splitlines())
BASE='/data/user/0/'+PKG+'/files/profiles/root/vpp/'
HOSTS={4:['127.0.0.'+str(i) for i in range(1,9)],6:['fd20:6206::'+str(i) for i in range(1,9)]}
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
def probe(label,host,port):
 nonce='s206-'+label+'-'+str(time.time_ns())
 save(label+'.request.txt',action('--ez','debugUdpTraffic','true','--es','debugUdpHost',host,'--ei','debugUdpPort','40606','--ei','debugUdpSourcePort',str(port),'--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true','--ez','debugTrafficBindToVpn','false','--ei','debugUdpTimeoutMillis','20000'))
 d=wait(label+'-probe','files/debug/udp-traffic-probe.properties',{'nonce':nonce})
 assert d['result']=='udp_echo_matched',(label,d)
 drained(label+'-settled')
 trace=save(label+'-trace.log',root('cat '+shlex.quote(BASE+'logs/vpp-stdout.log')))
 facts=[x for x in rows(trace,'s216 ') if x.get('stage')=='admit' and nonce.encode().hex() in x.get('raw','')]
 assert facts,(label,'no captured packet')
 output=next(x for x in facts if x['direction']=='3')
 case={'label':label,'nonce':nonce,'host':host,'port':port,'generation':output['generation'],'lane':int(output['origin_lane']),'owner':int(output['owner']),'packets':len(facts)}
 result['cases'].append(case)
 print(label,'lane',case['lane'],'owner',case['owner'],flush=True)
 return case
result={'status':'HOLD','source':'NFQ_CAPTURED','profile':'root','scope':'dual-stack-q2-w2','serial':SERIAL,'apk_sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest(),'cases':[],'generations':[],'closures':[],'drain_probes':[]}
pid=None;added=[]
try:
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
 adb('push',str(ROOT/'build-output/s206-lanes/udp-echo'),'/data/local/tmp/s206-echo');adb('shell','chmod','755','/data/local/tmp/s206-echo')
 pid=adb('shell','/data/local/tmp/s206-echo 40606 '+' '.join(HOSTS[4]+HOSTS[6])+' > /data/local/tmp/s206-echo.log 2>&1 & echo $!').strip();assert pid.isdigit(),pid
 choices={}
 for closing in range(4):
  label='g'+str(closing);running=start(label);result['generations'].append(running['generation'])
  cli(label+'-initial',['show product root lanes','show threads'])
  save(label+'-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
  if closing==0:
   for family in (4,6):
    for host in HOSTS[family]:
     for port in (30000,30001):
      case=probe(label+'-f'+str(family)+'-h'+host.rsplit(':',1)[-1].rsplit('.',1)[-1]+'-p'+str(port),host,port)
      choices.setdefault((case['lane'],case['owner']),(host,port))
     if all((lane,owner) in choices for lane in ((0,1) if family==4 else (2,3)) for owner in (0,1)):break
    assert all((lane,owner) in choices for lane in ((0,1) if family==4 else (2,3)) for owner in (0,1)),('missing family coverage',family,choices)
   cli(label+'-matrix-complete',['show product root lanes','show product completion','show runtime','show threads'])
  drained(label+'-before-close')
  if closing==0:
   host,port=choices[(closing,1)]
   nonce='s206-'+label+'-drain-'+str(time.time_ns())
   action('--ez','debugUdpTraffic','true','--es','debugUdpHost',host,'--ei','debugUdpPort','40606','--ei','debugUdpSourcePort',str(port),'--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true','--ez','debugTrafficBindToVpn','false','--ei','debugUdpTimeoutMillis','20000')
   end=time.monotonic()+10
   while time.monotonic()<end:
    trace=save(label+'-inflight-trace.log',root('cat '+shlex.quote(BASE+'logs/vpp-stdout.log')))
    if nonce.encode().hex() in trace:break
    time.sleep(.05)
   else:raise RuntimeError('in-flight packet was not captured')
   response=cli(label+'-quiesce',['product root lane close '+str(closing)])
   assert 'state=draining pending=' in response,response
   drained(label+'-quiesced-ledgers')
  response=cli(label+'-close',['product root lane close '+str(closing)])
  assert 'state=closed pending=0' in response,response
  save(label+'-kernel-queues-after-close.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
  closed_lanes,_=snapshot(label+'-after-close')
  assert closed_lanes[closing]['fd']=='-1' and closed_lanes[closing]['ready']=='0'
  if closing==0:
   probe_result=wait(label+'-drain-probe','files/debug/udp-traffic-probe.properties',{'nonce':nonce})
   result['drain_probes'].append({'nonce':nonce,'generation':running['generation'],'result':probe_result['result']})
  for lane in range(4):
   if lane==closing:continue
   for owner in (0,1):
    host,port=choices[(lane,owner)]
    case=probe(label+'-survivor'+str(lane)+'-owner'+str(owner),host,port)
    assert (case['lane'],case['owner'])==(lane,owner),case
  lanes,status=drained(label+'-final-ledgers')
  result['closures'].append({'generation':running['generation'],'closed_lane':closing,'lanes':lanes,'completion':status})
  threads=cli(label+'-threads-before-stop',['show threads'])
  actual_pid=re.search(r'^0\s+vpp_main\s+(\d+)',threads,re.M).group(1)
  save(label+'-fds-before-stop.txt',root('ls -l /proc/'+actual_pid+'/fd'))
  logs(label+'-before-stop');stop(label)
  save(label+'-kernel-queues-after-stop.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
  save(label+'-hooks-after-stop.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
 result['choices']={str(k):v for k,v in choices.items()}
 result['status']='RAW_COMPLETE'
except Exception as e:
 result['error']=repr(e)
 try:logs('failure')
 except Exception as ce:result['capture_error']=str(ce)
 try:stop('failure')
 except Exception as ce:result['cleanup_error']=str(ce)
finally:
 if pid and pid.isdigit():adb('shell','kill',pid,check=False)
 for address in added:root('ip -6 addr del '+address+'/128 dev lo',check=False)
 save('service.log',app('files/logs/runtime-service.log'));save('result.json',json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));raise SystemExit(result['status']!='RAW_COMPLETE')
