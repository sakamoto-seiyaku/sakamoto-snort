#!/usr/bin/env python3
"""S204: owner-local native Completion Frame and duplicate/stale replay rejection."""
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
 return wait(label,STATE,{'state':'running','adapterReadiness':'root-nfqueue-udp4-owner-local','protectionRunning':'true'})
def logs(label):
 base='/data/user/0/'+PKG+'/files/profiles/root/vpp/'
 for name in ['logs/vpp-stdout.log','logs/vpp.log','runtime/startup.conf','owner.properties']:
  save(label+'-'+Path(name).name,adb('shell','su','-c',shlex.quote('cat '+shlex.quote(base+name)),check=False))
 if 'before-stop' in label or label=='failure':
  command="printf 'show runtime\\nshow threads\\nshow node product-packet-origin-completion\\nquit\\n' | toybox nc -U -w 2 -q 1 "+shlex.quote(base+'runtime/cli.sock')
  save(label+'-vpp-runtime.txt',adb('shell','su','-c',shlex.quote(command),check=False))
 save(label+'-status.properties',app(STATUS));save(label+'-gate.properties',app(GATE));save(label+'-l4.properties',app('files/product-state/s192-root-vpn-l4-matrix.properties'))
 save(label+'-endpoint.log',adb('shell','cat','/data/local/tmp/s203-echo.log',check=False))
def probe(label,port,expect):
 nonce='s204-'+label+'-'+str(time.time_ns())
 save(label+'.request.txt',action('--ez','debugUdpTraffic','true','--es','debugUdpHost','127.0.0.1','--ei','debugUdpPort','40403','--ei','debugUdpSourcePort',str(port),'--es','debugUdpNonce',nonce,'--ez','debugUdpExpectReply','true','--ez','debugTrafficBindToVpn','false','--ei','debugUdpTimeoutMillis','1500'))
 d=wait(label+'-probe','files/debug/udp-traffic-probe.properties',{'nonce':nonce})
 assert d['result']==expect,(label,d)
 ordinal={'allow':1,'drop':2,'second':2,'recover':3,'remote-closed':4,'restart':1}[label]
 generation=result.get('restart_generation') if label=='restart' else result['generation']
 wait(label+'-settlement',STATUS,{'origin_verdict_attempts':str(ordinal),'root_nfqueue_generation':generation})
 logs(label)
 return nonce
def stop(label):
 save(label+'.stop.txt',action('--ez','runtimeStop','true'))
 wait(label+'-stopped',STATE,{'state':'stopped','mayBeActive':'false','errorCode':''})
 s=save(label+'-cleanup.properties',app('files/product-state/s176-root-nfqueue-cleanup.properties'))
 assert 'productRootNfqueueResidueClean=true' in s
 s=save(label+'-process-after.txt',adb('shell','ps','-A','-o','PID,NAME,ARGS'))
 assert not any('libvpp_runtime.so' in l for l in s.splitlines())
result={'status':'HOLD','source':'NFQ_CAPTURED','profile':'root','family':4,'protocol':17,'scope':'single-lane-owner-local','serial':SERIAL,'apk_sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest()};pid=None
try:
 save('device.txt',adb('shell','getprop','ro.product.device')+adb('shell','uname','-a'))
 save('before.properties',app(STATE));save('install.txt',adb('install','-r',str(args.apk.resolve())))
 package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 with zipfile.ZipFile(args.apk) as z:expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 installed=save('installed-native-sha256.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]))
 assert expected=={Path(l.split()[1]).name:l.split()[0] for l in installed.splitlines()}
 result['native_sha256']=expected
 installed_apk=save('installed-apk-sha256.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk'))
 assert installed_apk.split()[0]==result['apk_sha256'],'installed APK differs from requested artifact'
 uid=adb('shell','run-as',PKG,'id','-u').strip();result['uid']=uid
 adb('shell','pm','grant',PKG,'android.permission.POST_NOTIFICATIONS',check=False)
 adb('push',str(ROOT/'build-output/s203-graph/udp-echo'),'/data/local/tmp/s203-echo');adb('shell','chmod','755','/data/local/tmp/s203-echo')
 pid=adb('shell','/data/local/tmp/s203-echo 40403 > /data/local/tmp/s203-echo.log 2>&1 & echo $!').strip()
 assert pid.isdigit(),pid
 first=start('first');result['generation']=first['generation']
 action('--es','debugSetNetworkGateSubject','android.uid:'+uid,'--es','debugSetNetworkGateContext','wifi','--ez','debugSetNetworkGateBlocked','false')
 wait('initial-gate-open',GATE,{'gate_blocked':'false','generation':first['generation'],'errorCode':''});time.sleep(.4)
 base='/data/user/0/'+PKG+'/files/profiles/root/vpp/runtime/cli.sock'
 def cli(label,commands):
  command="printf '%s\\n' "+' '.join(shlex.quote(c) for c in commands+['quit'])+' | toybox nc -U -w 2 -q 1 '+shlex.quote(base)
  return save(label+'.txt',adb('shell','su','-c',shlex.quote(command)))
 def completion_status(label,verdicts,duplicate,stale):
  end=time.monotonic()+10
  while time.monotonic()<end:
   response=cli(label,['show product completion'])
   line=next((l for l in response.splitlines() if l.startswith('completion.status ')), '')
   d=dict(x.split('=',1) for x in line.split()[1:] if '=' in x)
   if all(d.get(k)==str(v) for k,v in dict(pending=0,frames=0,buffers=0,obligations=0,verdicts=verdicts,duplicate=duplicate,stale=stale).items()):return d
   time.sleep(.2)
  raise RuntimeError('Completion status mismatch: '+str(d))
 result['allow_nonce']=probe('allow',30001,'udp_echo_matched')
 result['second_nonce']=probe('second',30001,'udp_echo_matched')
 response=cli('replay-duplicate',['product completion replay 1 duplicate'])
 assert 'completion.replay=accepted' in response,response
 response=cli('replay-stale',['product completion replay 2 stale'])
 assert 'completion.replay=accepted' in response,response
 completion_status('after-replay',2,1,1)
 result['recover_nonce']=probe('recover',30001,'udp_echo_matched')
 result['unsupported_remote_nonce']=probe('remote-closed',30000,'udp_datagram_failed')
 result['negative_scope']='remote-owner unsupported packet closes on arrival; not remote policy acceptance'
 completion_status('before-stop-completion',4,1,1)
 logs('before-stop');stop('first')
 second=start('restart');result['restart_generation']=second['generation']
 assert second['generation']!=first['generation']
 result['restart_nonce']=probe('restart',30001,'udp_echo_matched')
 completion_status('restart-before-stop-completion',1,0,0)
 logs('restart-before-stop');stop('restart')
 result['status']='RAW_COMPLETE'
except Exception as e:
 result['error']=str(e)
 try:logs('failure')
 except Exception as capture_error:result['capture_error']=str(capture_error)
 try:stop('failure')
 except Exception as cleanup_error:result['cleanup_error']=str(cleanup_error)
finally:
 if pid and pid.isdigit():adb('shell','kill',pid,check=False)
 save('service.log',app('files/logs/runtime-service.log'));save('result.json',json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2));raise SystemExit(result['status']!='RAW_COMPLETE')
