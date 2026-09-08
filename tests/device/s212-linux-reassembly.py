#!/usr/bin/env python3
"""S212 real Linux original-fragment completion; invoke inside a disposable user/net namespace."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time
import importlib.util

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--artifact', type=Path, required=True)
parser.add_argument('--vppctl', type=Path, required=True)
parser.add_argument('--policy-client', type=Path, default=ROOT/'build-output/s230-policy')
args = parser.parse_args()
args.output = args.output.resolve()
args.artifact = args.artifact.resolve()
args.output.mkdir(parents=True, exist_ok=False)
env = dict(os.environ, LD_LIBRARY_PATH=str(args.artifact/'lib'))

def command(*argv, check=True):
    if argv[0] in ('iptables','ip6tables'):
        argv = (argv[0], '-w', '5', *argv[1:])
    p = subprocess.run(list(map(str, argv)), env=env, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    if check and p.returncode:
        raise RuntimeError(p.stdout)
    return p.stdout

def save(path, text):
    path.write_text(text)
    return text

def rows(text, prefix):
    return [dict(x.split('=', 1) for x in line.split()[1:] if '=' in x)
            for line in text.splitlines() if line.startswith(prefix)]

def queue_bind(queue):
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as s:
        s.bind((0, 0)); s.settimeout(2)
        payload = struct.pack('!BBH', 0, 0, queue)
        payload += struct.pack('HH', 8, 1) + struct.pack('!BBH', 1, 0, 2)
        s.send(struct.pack('IHHII', 16+len(payload), 0x302, 5, 1, 0)+payload)
        reply = s.recv(4096)
        assert struct.unpack_from('H', reply, 4)[0] == 2
        return struct.unpack_from('i', reply, 16)[0]

class ControlClient:
 def __init__(self,path):
  self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.settimeout(5);self.socket.connect(str(path))
 def call(self,command_text,marker):
  self.socket.sendall((command_text+'\n').encode());response=b''
  while True:
   chunk=self.socket.recv(65536)
   if not chunk:raise RuntimeError('control EOF '+repr(response))
   response+=chunk;text=response.decode(errors='replace').replace('\r','')
   start=text.find(marker)
   if start>=0 and '\n' in text[start:]:return text
   if 'rejected' in text or 'unknown input' in text:raise RuntimeError(text)
 def close(self):
  try:self.socket.sendall(b'quit\n')
  except OSError:pass
  self.socket.close()


NET = ROOT/'build-output/s231-fragments/linux-net'
ECHO = ROOT/'build-output/s231-fragments/linux-echo'
result = dict(status='HOLD', started_ns=time.time_ns(), cases=[],
              helper_sha256={str(p.name):hashlib.sha256(p.read_bytes()).hexdigest() for p in (NET,ECHO)})
save(args.output/'kernel.txt',command('uname','-a')+command('id')+'netns='+os.readlink('/proc/self/ns/net')+'\n')
uid_map=Path('/proc/self/uid_map').read_text().split()
assert os.getuid()==0 and uid_map[0]=='0' and uid_map[1]!='0' and uid_map[2]=='1'
save(args.output/'uid-map.txt',' '.join(uid_map)+'\n')
result['artifact_manifest_sha256']=hashlib.sha256((args.artifact/'product-vpp-artifact.properties').read_bytes()).hexdigest()
link=False
try:
 command('ip','link','set','lo','up')
 command('ip','link','add','s231tx','type','veth','peer','name','s231rx');link=True
 for name in ('s231tx','s231rx'):command('ip','link','set',name,'mtu','1280','up')
 command('ip','addr','add','198.18.231.2/24','dev','s231rx')
 command('ip','-6','addr','add','fd20:6231::2/64','dev','s231rx','nodad')
 mac=json.loads(command('ip','-j','link','show','dev','s231tx'))[0]['address']
 command('ip','neigh','add','198.18.231.1','lladdr',mac,'dev','s231rx','nud','permanent')
 command('ip','-6','neigh','add','fd20:6231::1','lladdr',mac,'dev','s231rx','nud','permanent')
 save(args.output/'link.txt',command('ip','-d','link','show')+command('ip','addr','show')+command('ip','route','show')+command('ip','-6','route','show'))
 save(args.output/'netfilter-before.txt',command('cat','/proc/modules',check=False)+command('cat','/proc/net/nf_conntrack',check=False)+command('cat','/proc/sys/net/netfilter/nf_conntrack_count',check=False))
 for family in (4,):
  for hook in ('OUTPUT',):
   index=len(result['cases']);generation=21210+index;run=args.output/f'g{index}';run.mkdir()
   runtime=ROOT/f'build-output/product-vpp-runtime-s212-{args.output.name}-{index}'
   launch=dict(env,PRODUCT_ARTIFACT_DIR=str(args.artifact),PRODUCT_RUNTIME_DIR=str(runtime),PRODUCT_GENERATION=str(generation),
               PRODUCT_WORKER_COUNT='2',SAKAMOTO_RUNTIME_PROFILE='root',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
   log=(run/'vpp.log').open('w');process=subprocess.Popen(['bash',str(ROOT/'tools/product/run-host-vpp.sh')],env=launch,stdout=log,stderr=subprocess.STDOUT)
   echo_log=(run/'endpoint.log').open('w');echo=subprocess.Popen([str(ECHO),'40631','127.0.0.1','::1','198.18.231.2','fd20:6231::2'],stdout=echo_log,stderr=subprocess.STDOUT)
   capture=None;capture_log=None
   case=dict(generation=generation,family=family,hook=hook,uid=0,fragments=[],probes=[],peer_controls=[])
   tool,span=('iptables','176:177') if family==4 else ('ip6tables','178:179')
   local,peer=('198.18.231.2','198.18.231.1') if family==4 else ('fd20:6231::2','fd20:6231::1')
   def cli(label,*commands):return save(run/(label+'.txt'),''.join(command(args.vppctl,'-s',runtime/'cli.sock',c) for c in commands))
   def drain(label,stable=.15):
    deadline=time.monotonic()+12;last=None;since=time.monotonic()
    while time.monotonic()<deadline:
     text=cli(label,'show product root lanes','show product completion');d=rows(text,'completion.status ')[0]
     counts=tuple(l['captured'] for l in rows(text,'root.lane '))
     if counts!=last or any(d[k]!='0' for k in ('pending','frames','buffers','obligations')):since=time.monotonic()
     elif time.monotonic()-since>=stable:return
     last=counts;time.sleep(.04)
    raise RuntimeError('drain timeout '+str(d))
   def clear():
    for t in ('iptables','ip6tables'):command(t,'-t','mangle','-F')
   def baseline(phase):
    clear()
    for protocol in ('tcp','udp'):
     command(tool,'-t','mangle','-A','OUTPUT','-o','lo','-p',protocol,'--dport','40631','-m','owner','--uid-owner','0','-j','NFQUEUE','--queue-balance',span)
     command(tool,'-t','mangle','-A','INPUT','-i','lo','-p',protocol,'--sport','40631','-j','NFQUEUE','--queue-balance',span)
    save(run/(phase+'-hooks.txt'),command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    for protocol in (17,6):
     nonce=f's231-{generation}-{phase}-{protocol}'
     output=save(run/(phase+'-'+str(protocol)+'.txt'),command(NET,'probe',0,family,protocol,'127.0.0.1' if family==4 else '::1',40631,nonce))
     assert 'probe uid=0' in output
     case['probes'].append(dict(nonce=nonce,protocol=protocol,phase=phase,expected='echo'))
    drain(phase+'-drain')
   try:
    for _ in range(150):
     if (runtime/'cli.sock').exists():break
     if process.poll() is not None:raise RuntimeError((run/'vpp.log').read_text())
     time.sleep(.03)
    initial=cli('initial','show product root lanes','show product primary','show threads')
    assert len(rows(initial,'root.lane '))==4 and all(r['ready']=='1' for r in rows(initial,'root.lane '))
    save(run/'queues-busy.json',json.dumps({q:queue_bind(q) for q in range(176,180)}))
    assert 'packet.trace_limit=4096' in cli('trace-limit','product packet-trace limit 4096')
    save(run/'allow.txt',command(args.policy_client,runtime/'api.sock',generation,run/'policy',1,0))
    baseline('before')
    clear()
    source,destination=(peer,local) if hook=='INPUT' else (local,peer)
    placement=['-i','s231rx'] if hook=='INPUT' else ['-o','s231rx','-m','owner','--uid-owner','0']
    command(tool,'-t','mangle','-A',hook,*placement,'-s',source,'-d',destination,'-j','NFQUEUE','--queue-balance',span)
    save(run/'fragment-hooks.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    save(run/'snmp-before.txt',command('cat','/proc/net/snmp')+command('cat','/proc/net/snmp6'))
    capture_log=(run/'capture.log').open('w')
    capture=subprocess.Popen([str(NET),'capture','s231rx' if hook=='INPUT' else 's231tx',str(run/'wire.pcap')],stdout=capture_log,stderr=subprocess.STDOUT)
    deadline=time.monotonic()+3
    while 'capture.ready' not in (run/'capture.log').read_text():
     assert capture.poll() is None and time.monotonic()<deadline
     time.sleep(.01)
    if hook=='INPUT':
     nonce=f's231-{generation}-peer-before';identity=23000+index*10
     save(run/'peer-before.txt',command(NET,'inject-whole',0,family,'s231tx','s231rx',source,destination,identity,0,nonce))
     case['peer_controls'].append(dict(nonce=nonce,id=identity));drain('peer-before-drain')
    def make_fragments(identity, payload_size=24, step=16):
     payload=struct.pack('!HHHH',41212+identity%8,40631,payload_size+8,0)+bytes(i%256 for i in range(payload_size))
     packets=[]
     for offset in range(0,len(payload),step):
      data=payload[offset:offset+step]
      header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(data),identity,
        offset//8|(0x2000 if offset+len(data)<len(payload) else 0),64,17,0,
        socket.inet_aton(source),socket.inet_aton(destination))
      packets.append(header+data)
     return packets
    def send_fragments(label,packets,settle=True):
     with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW) as raw:
      raw.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
      for packet in packets:
       assert raw.sendto(packet,(destination,0))==len(packet)
     case['fragments'].append(dict(label=label,packets=[p.hex() for p in packets]))
     if settle:drain(label+'-drain',stable=.2)
     cli(label+'-reassembly','show product reassembly')
    cli('configure','product reassembly configure timeout-ms 500 contexts 64')
    for index in range(4):
     packets=make_fragments(21200+index)
     if index%2:packets.reverse()
     send_fragments('success-'+str(index),packets)
    send_fragments('six-originals',make_fragments(21220,88))
    send_fragments('one-byte-final',make_fragments(21219,9))
    packets=make_fragments(21221)
    send_fragments('duplicate',[packets[0],packets[0],packets[1]])
    packets=make_fragments(21222)
    bad=bytearray(packets[0]);bad[-1]^=255
    send_fragments('conflict',[packets[0],bytes(bad)])
    send_fragments('timeout',make_fragments(21223)[:1])
    # Native finalization capacity must bypass safely retained original NFQ
    # packets when a complete datagram exceeds the contiguous Product parser.
    send_fragments('oversize',make_fragments(21224,2200,512))
    send_fragments('bundle-capacity',make_fragments(21227,256,8))
    save(run/'fragment-drop-policy.txt',command(args.policy_client,runtime/'api.sock',generation,run/'policy',2,1))
    send_fragments('policy-drop',make_fragments(21225))
    save(run/'fragment-allow-policy.txt',command(args.policy_client,runtime/'api.sock',generation,run/'policy',3,0))
    if hook=='INPUT':
     nonce=f's231-{generation}-peer-after';identity=23001+index*10
     save(run/'peer-after.txt',command(NET,'inject-whole',0,family,'s231tx','s231rx',source,destination,identity,0,nonce))
     case['peer_controls'].append(dict(nonce=nonce,id=identity))
    drain('fragment-drain',stable=1)
    capture.terminate();capture.wait(timeout=3);capture_log.close();capture=None;capture_log=None
    save(run/'snmp-after.txt',command('cat','/proc/net/snmp')+command('cat','/proc/net/snmp6'))
    save(run/'conntrack.txt',command('cat','/proc/net/nf_conntrack',check=False)+command('cat','/proc/sys/net/netfilter/nf_conntrack_count',check=False))
    baseline('after')
    save(run/'drop-policy.txt',command(args.policy_client,runtime/'api.sock',generation,run/'policy',4,1))
    nonce=f's231-{generation}-policy-drop'
    response=save(run/'drop-probe.txt',command(NET,'probe',0,family,17,'127.0.0.1' if family==4 else '::1',40631,nonce,'drop'))
    assert 'probe.blocked' in response
    case['probes'].append(dict(nonce=nonce,protocol=17,phase='drop',expected='drop'))
    drain('drop-drain')
    save(run/'allow-recovery.txt',command(args.policy_client,runtime/'api.sock',generation,run/'policy',5,0))
    nonce=f's231-{generation}-policy-recovery'
    save(run/'recovery-probe.txt',command(NET,'probe',0,family,17,'127.0.0.1' if family==4 else '::1',40631,nonce))
    case['probes'].append(dict(nonce=nonce,protocol=17,phase='recovery',expected='echo'))
    clear();drain('before-stop-cases')
    cli('capacity-config','product reassembly configure timeout-ms 10000 contexts 1')
    command(tool,'-t','mangle','-A',hook,*placement,'-s',source,'-d',destination,'-j','NFQUEUE','--queue-balance',span)
    send_fragments('capacity-stop',[make_fragments(21240+i)[0] for i in range(3)],settle=False)
    time.sleep(.1)
    cli('before-flush','show product reassembly','show product completion')
    clear();cli('flush','product root stop');drain('final-drain')
    cli('runtime','show product root lanes','show product completion','show product primary','show product flows','show product reassembly','show runtime','show threads')
    save(run/'case.json',json.dumps(case,indent=2));result['cases'].append(case)
   finally:
    if capture is not None:capture.terminate();capture.wait(timeout=3)
    if capture_log is not None:capture_log.close()
    clear()
    echo.terminate();echo.wait(timeout=3);echo_log.close()
    try:
     if process.poll() is None and (runtime/'cli.sock').exists():
      drain('stop-drain')
      save(run/'fds-before.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
      assert 'root.stop=ok' in cli('close','product root stop')
      cli('closed','show product root lanes','show product completion','show product primary','show product flows')
      save(run/'fds-closed.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
      free={q:queue_bind(q) for q in range(176,180)};save(run/'queues-free.json',json.dumps(free));assert all(v==0 for v in free.values())
    finally:
     if process.poll() is None:
      process.terminate()
      try:process.wait(timeout=10)
      except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
     log.close()
    save(run/'stop.json',json.dumps(dict(pid=process.pid,process_absent=not Path(f'/proc/{process.pid}').exists())))
    save(run/'hooks-after.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
   print('completed',generation,family,hook,flush=True)
 result['status']='RAW_COMPLETE'
except Exception as error:
 result['error']=repr(error)
 raise
finally:
 if link:command('ip','link','del','s231tx')
 save(args.output/'links-after.txt',command('ip','-d','link','show'))
 result['completed_ns']=time.time_ns();save(args.output/'result.json',json.dumps(result,indent=2)+'\n')
