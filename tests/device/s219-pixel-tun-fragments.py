#!/usr/bin/env python3
"""S219 real kernel-fragmented UDP through native TUN reassembly."""
import argparse, hashlib, importlib.util, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];PKG='com.sakamoto.snort.androidruntime';SERIAL='28201JEGR0XPAJ'
p=argparse.ArgumentParser();p.add_argument('--apk',type=Path,required=True);p.add_argument('--policy-helper',type=Path,required=True);p.add_argument('--endpoint',type=Path,required=True);p.add_argument('--capacity',action='store_true',help='S229 real TUN bundle capacity, then allow/completion recovery with transport unavailable');p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
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
  if d.get('state')=='starting':save(name+'-bootstrap.log',app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
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
targets=[]
for family in (4,6):
 import ipaddress
 for mode in (1,2):
  for owner in (0,1):
   for port in range(45400+(mode*20+owner*10),45500):
    src=ipaddress.ip_address('10.111.0.2' if family==4 else 'fd00:111:111::2').packed
    dst=ipaddress.ip_address('198.18.213.1' if family==4 else 'fd00:198::1').packed
    d=dict(l3=1,l4=1,family=family,protocol=17,src=(bytes(12)+src if family==4 else src).hex(),dst=(bytes(12)+dst if family==4 else dst).hex(),src_port=port,dst_port=40633,icmp_known=0)
    if oracle.owner(d)==owner:break
   targets.append(dict(family=family,mode=mode,owner=owner,port=port))
if a.capacity:
 # Capacity/recovery both install an explicit empty default-pass bundle.
 # Mode 2 is the S218 L4 DROP mode, not an allow/recovery request.
 targets=[dict(t,mode=0,payload_bytes=6000 if t['owner']==0 else 1800,phase='capacity' if t['owner']==0 else 'recovery') for t in targets if t['mode']==2]
wifi=adb('shell','settings','get','global','wifi_on').strip()
result=dict(status='HOLD',started_ns=time.time_ns(),platform='pixel',serial=SERIAL,generations=[],apk_sha256=hashlib.sha256(a.apk.read_bytes()).hexdigest());active=False
def snapshot(label,context,minimum=0):
 deadline=time.monotonic()+45
 while time.monotonic()<deadline:
  native_log=save(label+'-snapshot.log',app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
  android_log=save(label+'-android.log',adb('logcat','-d','-s','SakamotoNetwork:I','*:S'))
  events=rows(native_log,'s232 event=snapshot_publish ')
  if events:
   last=events[-1];revision=int(last['revision'])
   matching=[line for line in android_log.splitlines() if f" revision={revision} " in line and f" event_elapsed_ns={last['event_elapsed_ns']} " in line and ' code=0' in line]
   if revision>minimum and matching:
    match=re.search(r'interfaces=\{([^}]*)\}',matching[-1]);mapping=dict(re.findall(r'(\d+)=(\d+)',match.group(1))) if match else {}
    if int(mapping.get(str(interface_index),0))==context:return revision
  time.sleep(.25)
 raise RuntimeError('network snapshot did not reach '+label)
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
 adb('push',str(a.policy_helper.resolve()),'/data/local/tmp/s218-policy');adb('shell','chmod','755','/data/local/tmp/s218-policy')
 result['endpoint_sha256']=hashlib.sha256(a.endpoint.read_bytes()).hexdigest()
 adb('push',str(a.endpoint.resolve()),'/data/local/tmp/s219-tun-udp');adb('shell','chmod','755','/data/local/tmp/s219-tun-udp')
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
  links=save(label+'-interfaces-before.txt',root('ip -o link'))
  interface_index=int(re.search(r'^([0-9]+): '+re.escape(interface)+r':',links,re.M).group(1))
  save(label+'-connectivity-before.txt',adb('shell','dumpsys','connectivity'))
  current_revision=snapshot(label+'-initial',4)
  epoch=dict(generation=generation,interface=interface,interface_index=interface_index,pid=pid,cases=[]);result['generations'].append(epoch)
  for case_index,target in enumerate(targets):
   mode=target['mode'];port=target['port'];revision=21950+case_index+index*20
   if a.capacity:
    originals=4 if target['phase']=='capacity' else 32
    cli(f'{label}-c{case_index}-reassembly-config',
        [f'product reassembly configure timeout-ms 10000 contexts 64 originals {originals}'])
   policy=root(f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s218-policy {BASE}runtime/api.sock {generation} /data/local/tmp/s219-tun-policy-{generation} {revision} {mode} {result["uid"]} 1')
   save(f'{label}-c{case_index}-policy.txt',policy);assert 'policy rc=0' in policy
   nonce=f'{"s229" if a.capacity else "s219"}_{label}_{case_index}_{time.time_ns()}'
   payload=target.get('payload_bytes',1800)
   probe=save(f'{label}-c{case_index}-probe.txt',root(f'/data/local/tmp/s219-tun-udp {result["uid"]} {target["family"]} {port} {nonce} {payload}'))
   assert 'outcome=timeout' in probe
   deadline=time.monotonic()+15
   while time.monotonic()<deadline:
    text=cli(f'{label}-c{case_index}-drain',['show product tun','show product reassembly'])
    state=rows(text,'tun.status ')[0];reassembly=rows(text,'reassembly.status ')[0]
    if all(state[k]=='0' for k in ('pending','frames','buffers','obligations')) and all(reassembly[k]=='0' for k in ('contexts','originals','retained')):break
    time.sleep(.1)
   else:raise RuntimeError('TUN fragments did not settle')
   epoch['cases'].append(dict(target,nonce=nonce,revision=revision,context=4,snapshot_revision=current_revision))
  cli(label+'-final',['show product tun','show product completion','show product primary','show product reassembly','show product flows','show runtime','show threads'])
  # Hold the native log inode across supervisor unlink; exit with the actual
  # app-owned VPP PID, so there is no lingering tail process on the device.
  monitor_command=f'exec 3<{BASE}logs/vpp-stdout.log; while test -d /proc/{pid}; do cat <&3; sleep 0.1; done; cat <&3'
  with (a.output/(label+'-vpp.log')).open('w') as output:
   monitor=subprocess.Popen([str(ROOT/'dev/adb'),'-s',SERIAL,'shell','run-as',PKG,'sh','-c',shlex.quote(monitor_command)],stdout=output,stderr=subprocess.STDOUT,text=True)
   deadline=time.monotonic()+15
   while (a.output/(label+'-vpp.log')).stat().st_size==0 and monitor.poll() is None and time.monotonic()<deadline:time.sleep(.1)
   if monitor.poll() is not None:raise RuntimeError('native log monitor failed before stop')
   try:
    stop(label);active=False
    monitor.wait(timeout=15)
   finally:
    if monitor.poll() is None:monitor.terminate();monitor.wait(timeout=5)
  save(label+'-android-events.log',adb('logcat','-d','-s','SakamotoNetwork:I','*:S'))
  save(label+'-fds-after-drain.txt',root(f'ls -l /proc/{pid}/fd',check=False))
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
 adb('shell','svc','wifi','enable' if wifi=='1' else 'disable',check=False)
 result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
