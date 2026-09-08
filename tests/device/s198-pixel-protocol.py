#!/usr/bin/env python3
"""Real TUN dual-stack TCP/UDP policy and other-protocol transport outcomes."""
import argparse, hashlib, importlib.util, json, re, shlex, subprocess, time, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];PKG='com.sakamoto.snort.androidruntime';SERIAL='28201JEGR0XPAJ'
p=argparse.ArgumentParser();p.add_argument('--apk',type=Path,required=True);p.add_argument('--policy-helper',type=Path,required=True);p.add_argument('--icmp-helper',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
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
  if path==STATE and d.get('state')=='starting':
   native=app('files/profiles/vpn/vpp/logs/vpp-stdout.log')
   if 'No such file' not in native:
    save(name+'-bootstrap.log',native)
    with (a.output/(name+'-bootstrap-history.log')).open('a') as history:history.write(native+'\n')
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
import ipaddress,struct
spec=importlib.util.spec_from_file_location('oracle',ROOT/'tests/device/s207-owner-oracle.py');oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
def addresses(family):return ('10.111.0.2','198.18.198.1') if family==4 else ('fd00:111:111::2','fd00:198::1')
def raw_address(value):
 raw=ipaddress.ip_address(value).packed;return bytes(16-len(raw))+raw
def key(family,protocol,port=0,identifier=0):
 source,destination=addresses(family)
 return dict(l3=1,l4=1 if protocol in (6,17) else 2,family=family,protocol=protocol,src=raw_address(source).hex(),dst=raw_address(destination).hex(),src_port=port,dst_port=40634 if protocol in (6,17) else 0,icmp_known=int(protocol in (1,58)),icmp_code=0,icmp_type=8 if family==4 else 128,icmp_id=identifier)
def matched(log,case):
 result=[]
 for c in rows(log,'s213 event=capture '):
  raw=bytes.fromhex(c['raw']);family=raw[0]>>4;offset=(raw[0]&15)*4 if family==4 else 40;proto=raw[9] if family==4 else raw[6]
  if family!=case['family'] or proto!=case['protocol']:continue
  if proto==6:
   if len(raw)<offset+20:continue
   sport,dport=struct.unpack_from('!HH',raw,offset)
   if sport==case['port'] and dport==40634:result.append(c)
  elif case['nonce'].encode() in raw:result.append(c)
 return result
result=dict(status='HOLD',started_ns=time.time_ns(),platform='pixel',serial=SERIAL,generations=[],apk_sha256=hashlib.sha256(a.apk.read_bytes()).hexdigest());active=False
try:
 save('install.txt',adb('install','-r',str(a.apk.resolve())))
 package=save('package.txt',adb('shell','dumpsys','package',PKG));native=re.search(r'codePath=(\S+)',package).group(1)+'/lib/arm64'
 with zipfile.ZipFile(a.apk) as z:expected={Path(n).name:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if n.startswith('lib/arm64-v8a/') and n.endswith('.so')}
 hashes=save('installed-native.txt',adb('shell','sha256sum',*[native+'/'+n for n in sorted(expected)]))
 assert expected=={Path(l.split()[1]).name:l.split()[0] for l in hashes.splitlines()};result['native_sha256']=expected
 assert save('installed-apk.txt',adb('shell','sha256sum',native.removesuffix('/lib/arm64')+'/base.apk')).split()[0]==result['apk_sha256']
 result['uid']=int(adb('shell','run-as',PKG,'id','-u').strip());save('device.txt',adb('shell','uname','-a'))
 result['helper_sha256']={name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in [('policy',a.policy_helper),('icmp',a.icmp_helper)]}
 for name,path in [('s198-policy',a.policy_helper),('s198-icmp',a.icmp_helper)]:adb('push',str(path.resolve()),'/data/local/tmp/'+name);adb('shell','chmod','755','/data/local/tmp/'+name)
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
  initial=save(label+'-initial.log',app('files/profiles/vpn/vpp/logs/vpp-stdout.log'));interface=re.search(r's213 event=attach .* interface=(\S+)',initial).group(1)
  processes=save(label+'-processes-before.txt',adb('shell','ps','-A','-o','PID,UID,ARGS'));vpp=[l.split() for l in processes.splitlines() if 'libvpp_runtime.so' in l and 'startup.conf' in l];assert len(vpp)==1 and int(vpp[0][1])==result['uid'];pid=int(vpp[0][0])
  save(label+'-fds-before.txt',root(f'ls -l /proc/{pid}/fd'))
  epoch=dict(generation=generation,pid=pid,interface=interface,cases=[],injected=[]);result['generations'].append(epoch)
  socket_table=save(label+'-existing-sockets.txt',root('cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6'))
  occupied={int(v,16) for v in re.findall(r'^\s*\d+:\s+\S+:([0-9A-Fa-f]{4})\s+',socket_table,re.M)}
  scenarios=[];port=44000+index*100
  for family in (4,6):
   for protocol in (17,6):
    for mode in (1,2):
     while port in occupied or oracle.owner(key(family,protocol,port))!=0:port+=1
     scenarios.append(dict(family=family,protocol=protocol,mode=mode,port=port,blocked=True));port+=1
   identifier=19800+index*10
   while oracle.owner(key(family,1 if family==4 else 58,identifier=identifier))!=0:identifier+=1
   for mode in (1,0):scenarios.append(dict(family=family,protocol=1 if family==4 else 58,mode=mode,port=0,identifier=identifier,blocked=bool(mode)))
  for case_index,case in enumerate(scenarios):
   revision=19800+index*100+case_index;nonce=f's198_{label}_{case_index}_{time.time_ns()}';case.update(revision=revision,nonce=nonce,sequence=case_index)
   text=root(f'LD_LIBRARY_PATH={shlex.quote(native)} /data/local/tmp/s198-policy {BASE}runtime/api.sock {generation} /data/local/tmp/s198-policy-{generation} {revision} {case["mode"]} {result["uid"]} {case["family"]} {case["protocol"]} {case["port"]}')
   save(f'{label}-c{case_index}-policy.txt',text);assert 'policy rc=0' in text
   if case['protocol'] in (6,17):
    save(f'{label}-c{case_index}-send.txt',action('--es','s198ProbeNonce',nonce,'--ei','s198ProbePort',str(case['port']),'--ei','s198ProbeFamily',str(case['family']),'--ei','s198ProbeProtocol',str(case['protocol'])))
    case['probe']=wait(f'{label}-c{case_index}-probe','files/product-state/s198-probe.properties',dict(nonce=nonce,sourcePort=str(case['port']),family=str(case['family']),protocol=str(case['protocol']),uid=str(result['uid']),outcome='timeout'))
   else:
    text=root(f'/data/local/tmp/s198-icmp {result["uid"]} {case["family"]} {case["identifier"]} {case_index} {nonce}')
    save(f'{label}-c{case_index}-icmp.txt',text);assert 'icmp_endpoint uid='+str(result['uid']) in text
   deadline=time.monotonic()+15
   while time.monotonic()<deadline:
    log=app('files/profiles/vpn/vpp/logs/vpp-stdout.log');captures=matched(log,case);completed={e['token'] for e in rows(log,'s213 event=completion ')}
    status=rows(cli(f'{label}-c{case_index}-drain',['show product tun']),'tun.status ')[0]
    if captures and all(c['token'] in completed for c in captures) and all(status[k]=='0' for k in ('pending','frames','buffers','obligations')):break
    time.sleep(.2)
   else:raise RuntimeError('real TUN case did not complete: '+str(case))
   case['tokens']=[c['token'] for c in captures];epoch['cases'].append(case)
  # Invalid L3 cannot be emitted as an ordinary kernel app packet. These
  # separately labelled graph carriers supplement the actual TUN matrix.
  v4=bytearray.fromhex('4500001800000000401100000a6f0002c612c60130399eba')
  invalid=bytearray(v4[:20]);invalid[0]=0x44;invalid[2:4]=(20).to_bytes(2,'big')
  ext=bytearray.fromhex('6000000000100040')+raw_address('fd00:111:111::2')+raw_address('fd00:198::1')+bytearray.fromhex('110000000000000030399eba00080000')
  bad6=bytearray(ext[:40]);bad6[4:6]=(1000).to_bytes(2,'big')
  for ident,name,raw in [(1,'invalid_l3',invalid),(2,'short_udp',v4),(3,'unwalked_ipv6_extension',ext),(4,'truncated_ipv6',bad6)]:
   save(f'{label}-inject-{ident}.txt',cli(f'{label}-inject-{ident}',[f'product metadata inject {ident} {raw.hex()} worker 0']))
   epoch['injected'].append(dict(case=ident,name=name,raw=raw.hex(),token=str(216000000+ident)))
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   response=cli(label+'-native-stop',['product tun stop'])
   if 'tun.stop result=0 pending=0 fd=-1' in response:break
   time.sleep(.2)
  else:raise RuntimeError('native TUN stop did not settle')
  save(label+'-vpp.log',app('files/profiles/vpn/vpp/logs/vpp-stdout.log'))
  cli(label+'-final',['show product tun','show product completion','show product primary','show product reassembly','show product flows','show runtime','show threads'])
  save(label+'-fds-after-drain.txt',root(f'ls -l /proc/{pid}/fd'));stop(label);active=False
  link=save(label+'-interface-after.txt',root('ip link show dev '+shlex.quote(interface),check=False));assert 'does not exist' in link or 'Cannot find device' in link
  if index==0:ordinary_rejected('ordinary-resume',True)
 result['status']='RAW_COMPLETE'
except Exception as error:
 result['error']=repr(error);save('failure-state.txt',app(STATE));save('failure-vpp.log',app('files/profiles/vpn/vpp/logs/vpp-stdout.log'));raise
finally:
 if active:
  try:stop('cleanup')
  except Exception as error:result['cleanup_error']=repr(error)
 result['completed_ns']=time.time_ns();save('result.json',json.dumps(result,indent=2)+'\n')
