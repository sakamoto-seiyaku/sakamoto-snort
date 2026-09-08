#!/usr/bin/env python3
"""S207: actual Pixel TCP/UDP/Echo canonical owner assignment."""
import argparse, importlib.util, hashlib, json, re, shlex, subprocess, time, zipfile
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
 save(label+'-endpoint.log',adb('shell','cat','/data/local/tmp/s207-echo.log',check=False))
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
def probe(label,host,port,protocol):
 nonce='s207-'+label+'-'+str(time.time_ns());pattern=hashlib.sha256(nonce.encode()).hexdigest()[:32]
 if protocol==17:
  save(label+'.request.txt',action('--ez','debugUdpTraffic','true','--es','debugUdpHost',host,'--ei','debugUdpPort','40607','--ei','debugUdpSourcePort',str(port),'--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true','--ez','debugTrafficBindToVpn','false','--ei','debugUdpTimeoutMillis','30000'))
  d=wait(label+'-probe','files/debug/udp-traffic-probe.properties',{'nonce':nonce});assert d['result']=='udp_echo_matched',(label,d)
 elif protocol==6:
  save(label+'.request.txt',action('--ez','debugTraffic','true','--es','debugTrafficHost',host,'--ei','debugTrafficPort','40607','--ei','debugTrafficSourcePort',str(port),'--es','debugTrafficNonce',nonce,'--ez','debugTrafficBindToVpn','false','--ei','debugTrafficTimeoutMillis','30000'))
  d=wait(label+'-probe','files/debug/traffic-probe.properties',{'nonce':nonce});assert d['result']=='tcp_echo_matched',(label,d)
 else:
  family=4 if protocol==1 else 6
  reply=save(label+'-ping.txt',adb('shell','run-as',PKG,'ping' if family==4 else 'ping6','-I','127.0.0.1' if family==4 else '::1','-c','2','-i','0.2','-W','30','-p',pattern,host))
  assert '2 received' in reply,(label,reply)
 drained(label+'-settled');time.sleep(.3);drained(label+'-settled-again')
 trace=save(label+'-trace.log',root('cat '+shlex.quote(BASE+'logs/vpp-stdout.log')))
 facts=[x for x in rows(trace,'s216 ') if x.get('stage')=='admit' and (nonce.encode().hex() if protocol in (6,17) else pattern) in x.get('raw','')]
 assert facts,(label,'no captured payload')
 output=next(x for x in facts if x['direction']=='3')
 case={'label':label,'nonce':nonce,'pattern':pattern,'host':host,'port':port,'protocol':protocol,'family':int(output['family']),'generation':output['generation'],'lane':int(output['origin_lane']),'owner':int(output['owner']),'payload_packets':len(facts)}
 result['cases'].append(case)
 print(label,'protocol',protocol,'lane',case['lane'],'owner',case['owner'],flush=True)
 return case
result={'status':'HOLD','source':'NFQ_CAPTURED','profile':'root','scope':'canonical-owner-tcp-udp-echo','serial':SERIAL,'apk_sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest(),'cases':[],'generations':[]}
pid=None;added=[];wifi=adb('shell','settings','get','global','wifi_on').strip();active=False
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
 pid=adb('shell','/data/local/tmp/s207-echo 40607 '+' '.join(HOSTS[4]+HOSTS[6])+' > /data/local/tmp/s207-echo.log 2>&1 & echo $!').strip();assert pid.isdigit(),pid
 reference=json.loads((args.reference_run/'result.json').read_text()) if args.reference_run else None
 if reference:result['selection_reference_sha256']=hashlib.sha256((args.reference_run/'result.json').read_bytes()).hexdigest()
 for family in (4,6):
  for protocol in (17,6,1 if family==4 else 58):
   coverage=set();candidates=[];host_coverage={}
   if reference:
    selected={}
    for c in reference['cases']:
     if c['family']==family and c['protocol']==protocol:
      selected.setdefault((c['lane'],c['owner']), (c['host'],c['port']))
    if protocol in (6,17):candidates=list(selected.values())
    else:
     hosts=list(dict.fromkeys(h for h,p in selected.values()))
     candidates=[(h,31000+i) for h in hosts for i in range(8)]
   candidates=list(dict.fromkeys(candidates+[(HOSTS[family][i//4],31000+i%4) for i in range(32)]))
   for host,port in candidates:
    if protocol in (1,58) and len(host_coverage.get(host,set()))>=2:continue
    index=len(result['generations']);label='g'+str(index)
    active=True;running=start(label);result['generations'].append(running['generation'])
    cli(label+'-initial',['show product root lanes','show threads','product metadata check'])
    save(label+'-hooks.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    case=probe(label,host,port,protocol);coverage.add((case['lane'],case['owner']));host_coverage.setdefault(host,set()).add(case['owner'])
    drained(label+'-before-close')
    logs(label+'-before-stop')
    runtime=(args.output/(label+'-before-stop-vpp-runtime.txt')).read_text()
    actual_pid=re.search(r'^0\s+vpp_main\s+(\d+)',runtime,re.M).group(1)
    save(label+'-fds-before.txt',root('ls -l /proc/'+actual_pid+'/fd'))
    if index==0:
     spec=importlib.util.spec_from_file_location('diagnostics',ROOT/'tests/device/s207-diagnostic-cases.py');diagnostics=importlib.util.module_from_spec(spec);spec.loader.exec_module(diagnostics)
     cases=diagnostics.cases();save(label+'-diagnostic-cases.json',json.dumps(cases,indent=2))
     for diag in cases:cli(label+'-diagnostic-inject-'+str(diag['case']),[f"product metadata inject {diag['case']} {diag['raw']} worker {diag['worker']}"])
     drained(label+'-diagnostic-drain')
     cli(label+'-diagnostic-runtime',['show product primary','show product completion','show runtime'])
     save(label+'-diagnostic-vpp.log',root('cat '+shlex.quote(BASE+'logs/vpp-stdout.log')))
    cli(label+'-close',[f'product root lane close {i}' for i in range(4)])
    cli(label+'-closed',['show product root lanes','show product completion'])
    save(label+'-fds-closed.txt',root('ls -l /proc/'+actual_pid+'/fd'))
    stop(label);active=False
    save(label+'-kernel-queues-after-stop.txt',root('cat /proc/net/netfilter/nfnetlink_queue'))
    save(label+'-hooks-after-stop.txt',root('iptables-save -t mangle; ip6tables-save -t mangle'))
    target={(lane,owner) for lane in ((0,1) if family==4 else (2,3)) for owner in (0,1)}
    if coverage==target:break
   assert coverage==target,(family,protocol,coverage)
 result['status']='RAW_COMPLETE'
except Exception as e:
 result['error']=repr(e)
 try:logs('failure')
 except Exception:pass
 raise
finally:
 if active:
  try:stop('failure')
  except Exception as e:result['cleanup_error']=repr(e)
 if pid and pid.isdigit():adb('shell','kill',pid,check=False)
 for address in added:root('ip -6 addr del '+address+'/128 dev lo',check=False)
 if wifi=='1':adb('shell','svc','wifi','enable',check=False)
 result['wifi_before']=wifi;result['wifi_after']=adb('shell','settings','get','global','wifi_on').strip()
 save('result.json',json.dumps(result,indent=2)+'\n')
 print('status',result['status'],'cases',len(result['cases']),'wifi',result['wifi_after'],flush=True)
