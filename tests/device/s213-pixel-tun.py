#!/usr/bin/env python3
"""Real Android-app UDP -> real TUN -> shared owner-local policy DROP."""
import argparse, hashlib, importlib.util, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];PKG='com.sakamoto.snort.androidruntime';SERIAL='28201JEGR0XPAJ'
p=argparse.ArgumentParser();p.add_argument('--apk',type=Path,required=True);p.add_argument('--policy-helper',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
def save(name,text): (a.output/name).write_text(text);return text
def adb(*args,check=True):
 r=subprocess.run([str(ROOT/'dev/adb'),'-s',SERIAL,*args],capture_output=True,text=True,errors='replace',timeout=30)
 if check and r.returncode:raise RuntimeError(r.stdout+r.stderr)
 return (r.stdout+r.stderr).replace('\r','')
def root(cmd,check=True):return adb('shell','su','-c',shlex.quote(cmd),check=check)
def app(path):return adb('shell','run-as',PKG,'cat',path,check=False)
def props(text):return dict(l.split('=',1) for l in text.splitlines() if '=' in l and not l.startswith('#'))
def rows(text,prefix):return [dict(re.findall(r'(\w+)=([^\s]+)',l)) for l in text.splitlines() if l.startswith(prefix)]
def action(*args):return adb('shell','am','start','-n',PKG+'/.DebugControlActivity',*args)
STATE='files/runtime-state/snapshot.properties';BASE='/data/user/0/'+PKG+'/files/profiles/vpn/vpp/'
def wait(name,path,expected):
 deadline=time.monotonic()+60
 while time.monotonic()<deadline:
  text=save(name+'.poll',app(path));d=props(text)
  if all(d.get(k)==v for k,v in expected.items()):save(name+'.properties',text);return d
  time.sleep(.2)
 raise RuntimeError(name+': '+str(d))
def cli(name,commands):
 cmd="printf '%s\\n' "+' '.join(shlex.quote(c) for c in ['set terminal pager off',*commands,'quit'])+' | toybox nc -U -w 2 -q 1 '+BASE+'runtime/cli.sock'
 return save(name+'.txt',root(cmd))
def no_process(name):
 text=save(name+'-processes.txt',adb('shell','ps','-A','-o','PID,UID,ARGS'))
 assert not any('libvpp_runtime.so' in l for l in text.splitlines())
def stop(name):
 save(name+'-stop.txt',action('--ez','runtimeStop','true'))
 wait(name+'-stopped',STATE,dict(state='stopped',mayBeActive='false',errorCode=''))
 no_process(name)
def ordinary_rejected(name,resume=False):
 save(name+'-request.txt',action('--ez','runtimeResume' if resume else 'runtimeStart','true',*(() if resume else ('--es','runtimeProfile','vpn'))))
 wait(name,STATE,dict(state='error',profile='vpn',mayBeActive='false',errorCode='vpn_flow_stack_not_ready',protectionRunning='false'))
 no_process(name)
spec=importlib.util.spec_from_file_location('oracle',ROOT/'tests/device/s207-owner-oracle.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
ports=[]
for port in range(42000,42100):
 d=dict(l3=1,l4=1,family=4,protocol=17,src=(bytes(12)+bytes([10,111,0,2])).hex(),dst=(bytes(12)+bytes([198,18,213,1])).hex(),src_port=port,dst_port=40633,icmp_known=0)
 if oracle.owner(d)==0:ports.append(port)
ports=ports[:8]
result=dict(status='HOLD',started_ns=time.time_ns(),platform='pixel',serial=SERIAL,generations=[],apk_sha256=hashlib.sha256(a.apk.read_bytes()).hexdigest());active=False
try:
 save('install.txt',adb('install','-r',str(a.apk.resolve())))
 pkg=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',pkg).group(1)+'/lib/arm64'
 with zipfile.ZipFile(a.apk) as z:expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 hashes=save('installed-native.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]))
 assert expected=={Path(l.split()[1]).name:l.split()[0] for l in hashes.splitlines()};result['native_sha256']=expected
 assert save('installed-apk.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 result['uid']=int(adb('shell','run-as',PKG,'id','-u').strip())
 save('device.txt',adb('shell','uname','-a'));save('vpn-permission.txt',adb('shell','appops','get',PKG,'ACTIVATE_VPN'))
 result['helper_sha256']=hashlib.sha256(a.policy_helper.read_bytes()).hexdigest()
 adb('push',str(a.policy_helper.resolve()),'/data/local/tmp/s213-policy');adb('shell','chmod','755','/data/local/tmp/s213-policy')
 ordinary_rejected('ordinary-before')
 for index in range(2):
  label=f'g{index}';active=True
  for _ in range(50):
   services=adb('shell','dumpsys','activity','services',PKG)
   if not any('ServiceRecord{' in l and '.RuntimeService' in l for l in services.splitlines()):break
   time.sleep(.2)
  else:raise RuntimeError('previous control service did not retire')
  save(label+'-start.txt',action('--ez','debugVpnGraphValidation','true'))
  state=wait(label+'-running',STATE,dict(state='running',profile='vpn',adapterReadiness='unavailable',protectionRunning='false',errorCode=''))
  generation=int(state['generation']);wait(label+'-attached','files/product-state/s213-tun-graph.properties',dict(generation=str(generation),tunAttached='1',adapterAvailable='false',protectionRunning='false',uidSource='CONTROLLED_TEST_PROVIDER'))
  cli(label+'-trace-limit',['product packet-trace limit 4096'])
  initial=save(label+'-initial.log',app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
  interface=re.search(r's213 event=attach .* interface=(\S+)',initial).group(1)
  processes=save(label+'-processes-before.txt',adb('shell','ps','-A','-o','PID,UID,ARGS'))
  vpp=[l.split() for l in processes.splitlines() if 'libvpp_runtime.so' in l and 'startup.conf' in l];assert len(vpp)==1 and int(vpp[0][1])==result['uid'];pid=int(vpp[0][0])
  save(label+'-fds-before.txt',root(f'ls -l /proc/{pid}/fd'))
  epoch=dict(generation=generation,interface=interface,pid=pid,cases=[]);result['generations'].append(epoch)
  for case_index,port in enumerate(ports):
   mode=1 if case_index<4 else 4;revision=21300+case_index+index*20
   policy=root(f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s213-policy {BASE}runtime/api.sock {generation} /data/local/tmp/s213-policy-{generation} {revision} {mode} {result["uid"]} 1')
   save(f'{label}-c{case_index}-policy.txt',policy);assert 'policy rc=0' in policy
   nonce=f's213_{label}_{case_index}_{time.time_ns()}'
   save(f'{label}-c{case_index}-send.txt',action('--es','s213ProbeNonce',nonce,'--ei','s213ProbePort',str(port)))
   probe=wait(f'{label}-c{case_index}-probe','files/product-state/s213-probe.properties',dict(nonce=nonce,sourcePort=str(port),uid=str(result['uid']),outcome='timeout'))
   deadline=time.monotonic()+15
   while time.monotonic()<deadline:
    text=cli(f'{label}-c{case_index}-drain',['show product tun'])
    status=rows(text,'tun.status ')[0]
    if all(status[k]=='0' for k in ('pending','frames','buffers','obligations')):break
    time.sleep(.2)
   else:raise RuntimeError('TUN completion did not drain')
   epoch['cases'].append(dict(nonce=nonce,port=port,mode=mode,revision=revision,probe=probe))
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   response=cli(label+'-native-stop',['product tun stop'])
   if 'tun.stop result=0 pending=0 fd=-1' in response:break
   time.sleep(.2)
  else:raise RuntimeError('native TUN stop did not settle')
  save(label+'-vpp.log',app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
  cli(label+'-final',['show product tun','show product completion','show product primary','show product reassembly','show product flows','show runtime','show threads'])
  save(label+'-fds-after-drain.txt',root(f'ls -l /proc/{pid}/fd'))
  stop(label);active=False
  link=save(label+'-interface-after.txt',root('ip link show dev '+shlex.quote(interface),check=False))
  assert 'does not exist' in link or 'Cannot find device' in link
  if index==0:ordinary_rejected('ordinary-resume',True)
 result['status']='RAW_COMPLETE'
except Exception as error:
 result['error']=repr(error)
 save('failure-state.txt',app(STATE));save('failure-vpp.log',app('files/profiles/vpn/vpp/logs/vpp-stdout.log'));raise
finally:
 if active:
  try:stop('cleanup')
  except Exception as error:result['cleanup_error']=repr(error)
 result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
