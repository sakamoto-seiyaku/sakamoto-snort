#!/usr/bin/env python3
"""Real Linux Product acceptance; invoke inside a disposable user/net namespace."""
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


spec=importlib.util.spec_from_file_location('owner_oracle',ROOT/'tests/device/s207-owner-oracle.py')
oracle=importlib.util.module_from_spec(spec);spec.loader.exec_module(oracle)
result=dict(status='HOLD',started_ns=time.time_ns(),cases=[],generations=[])
save(args.output/'kernel.txt',command('uname','-a')+command('id')+'netns='+os.readlink('/proc/self/ns/net')+'\n')
uid_map=Path('/proc/self/uid_map').read_text().split()
assert os.getuid()==0 and len(uid_map)==3 and uid_map[0]=='0' and uid_map[1]!='0' and uid_map[2]=='1'
save(args.output/'uid-map.txt',' '.join(uid_map)+'\n')
assert 'product.host.evidence=OFF' in (args.artifact/'product-vpp-artifact.properties').read_text()
result['artifact_manifest_sha256']=hashlib.sha256((args.artifact/'product-vpp-artifact.properties').read_bytes()).hexdigest()
command('ip','link','set','lo','up')
for i in range(1,9):command('ip','-6','addr','add',f'fd20:6209::{i}/128','dev','lo','nodad')

try:
 for family in (4,6):
  for protocol in (17,6):
   index=len(result['cases']);generation=20910+index
   run=args.output/f'g{index}';run.mkdir()
   runtime=ROOT/f'build-output/product-vpp-runtime-s209-{args.output.name}-{index}'
   host='127.0.0.2' if family==4 else 'fd20:6209::2';local='127.0.0.1' if family==4 else '::1'
   af=socket.AF_INET if family==4 else socket.AF_INET6
   def address(value):return socket.inet_pton(af,value).rjust(16,b'\0').hex()
   hosts=[f'127.0.0.{i}' if family==4 else f'fd20:6209::{i}' for i in range(1,9)]
   ports={};candidates={0:[],1:[]}
   for port in (36000,36001,36256,36257,36512,36513,36768,36769):
    for target in hosts:
     a=oracle.assignment(dict(l3=1,l4=1,family=family,protocol=protocol,src=address(local),dst=address(target),src_port=port,dst_port=40608,icmp_known=0))
     ports.setdefault(a['owner'],port);candidates[a['owner']].append((target,port))
   assert set(ports)=={0,1}
   launch=dict(env,PRODUCT_ARTIFACT_DIR=str(args.artifact),PRODUCT_RUNTIME_DIR=str(runtime),PRODUCT_GENERATION=str(generation),PRODUCT_WORKER_COUNT='2',SAKAMOTO_RUNTIME_PROFILE='root',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
   log=(run/'vpp.log').open('w');process=subprocess.Popen(['bash',str(ROOT/'tools/product/run-host-vpp.sh')],env=launch,stdout=log,stderr=subprocess.STDOUT)
   server=None;servers=[];publisher=None;clients={};connections=[];threads=[];hooks=False;done=threading.Event();endpoint=[];errors=[]
   base_revision=2 if index==0 else 1
   case=dict(generation=generation,uid=0,family=family,protocol=protocol,ports=ports,publications=[],nonces={0:[],1:[]},received={0:[],1:[]},hold_nonces={})
   def cli(label,*commands):return save(run/(label+'.txt'),''.join(command(args.vppctl,'-s',runtime/'cli.sock',c) for c in commands))
   def drain(label):
    for _ in range(150):
     d=rows(cli(label,'show product completion'),'completion.status ')[0]
     if all(d[k]=='0' for k in ('pending','frames','buffers','obligations')):return
     time.sleep(.02)
    raise RuntimeError('drain timeout '+str(d))
   def publish(revision,hash_value,rule):
    started=time.monotonic_ns();answer=save(run/('publish-'+str(len(case['publications']))+'.txt'),publisher.call(f'product policy publish {revision} {hash_value} 0 {rule}','policy.publish=ok'))
    assert 'policy.publish=ok' in answer,answer
    case['publications'].append(dict(revision=revision,hash=hash_value,rule=rule,started_ns=started,completed_ns=time.monotonic_ns()))
   def send(owner,phase):
    nonce=f's209-{generation}-{owner}-{phase}-{time.time_ns()}'
    case['nonces'][owner].append(nonce);clients[owner].sendall((nonce+'\n').encode());return nonce
   def read_one(owner):
    value=b''
    while b'\n' not in value:value+=clients[owner].recv(4096)
    assert value.count(b'\n')==1,value
    line=value.decode().strip();case['received'][owner].append(line);return line
   try:
    for _ in range(150):
     if (runtime/'cli.sock').exists():break
     if process.poll() is not None:raise RuntimeError((run/'vpp.log').read_text())
     time.sleep(.03)
    for _ in range(150):
     lanes=rows(cli('initial','show product root lanes','show threads'),'root.lane ')
     if len(lanes)==4 and all(d['ready']=='1' for d in lanes):break
     time.sleep(.03)
    assert len(lanes)==4 and all(d['ready']=='1' for d in lanes)
    save(run/'queues-busy.json',json.dumps({q:queue_bind(q) for q in range(176,180)}))
    assert 'packet.trace_limit=4096' in cli('trace-limit','product packet-trace limit 4096')
    publisher=ControlClient(runtime/'cli.sock')
    for target in hosts:
     server=socket.socket(af,socket.SOCK_DGRAM if protocol==17 else socket.SOCK_STREAM);server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind((target,40608));server.settimeout(.1);servers.append(server)
     if protocol==6:server.listen(4)
    def echo_connection(conn):
     pending=b'';conn.settimeout(.1);conn.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
     try:
      while not done.is_set():
       try:
        data=conn.recv(4096)
        if not data:break
        pending+=data
        while b'\n' in pending:
         line,pending=pending.split(b'\n',1);endpoint.append(line.decode())
        conn.sendall(data)
       except TimeoutError:continue
     except Exception as e:errors.append(repr(e))
     finally:conn.close()
    def echo(server):
     try:
      while not done.is_set():
       try:
        if protocol==17:
         data,peer=server.recvfrom(4096);endpoint.extend(data.decode().splitlines());server.sendto(data,peer)
        else:
         conn,_=server.accept();connections.append(conn);t=threading.Thread(target=echo_connection,args=(conn,));threads.append(t);t.start()
       except TimeoutError:continue
     except Exception as e:errors.append(repr(e))
    for server in servers:
     listener=threading.Thread(target=echo,args=(server,));threads.append(listener);listener.start()
    hooks=True
    for tool,span in (('iptables','176:177'),('ip6tables','178:179')):
     for hook in ('INPUT','OUTPUT'):
      for proto in ('tcp','udp'):
       extra=['-m','owner','--uid-owner','0'] if hook=='OUTPUT' else []
       command(tool,'-t','mangle','-A',hook,'-p',proto,*extra,'-j','NFQUEUE','--queue-balance',span)
    save(run/'hooks.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    if index==0:
     save(run/'gate-drop-api.txt',command(args.policy_client,runtime/'api.sock',generation,run/'policy',1,1))
     nonce=f's209-{generation}-gate-drop-{time.time_ns()}'
     with socket.socket(af,socket.SOCK_DGRAM) as probe:
      probe.bind((local,39000));probe.settimeout(.2);probe.sendto((nonce+'\n').encode(),(hosts[0],40608))
      try:probe.recv(4096);raise RuntimeError('Gate DROP delivered')
      except TimeoutError:pass
     drain('gate-drop-drain');dropped=cli('gate-drop-flows','show product flows')
     assert all(p['entries']==p['allocations']=='0' for p in rows(dropped,'flow.pool ')) and not endpoint
     case['drop_policy']=dict(revision=1,hash=1,rule=230,mode='gate-drop',nonce=nonce)
    publish(base_revision,101,10000)
    case['warm_probes']=[]
    for owner in (0,1):
     for target,port in candidates[owner][:32]:
      c=socket.socket(af,socket.SOCK_DGRAM if protocol==17 else socket.SOCK_STREAM);c.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);c.settimeout(8)
      if protocol==6:c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
      c.bind((local,port));c.connect((target,40608));clients[owner]=c
      nonce=send(owner,'warm');assert read_one(owner)==nonce
      facts=[d for d in rows((run/'vpp.log').read_text(),'s216 ') if d.get('stage')=='admit' and nonce.encode().hex() in d.get('raw','')]
      assert facts and int(facts[0]['owner'])==owner
      lane=int(facts[0]['origin_lane']);case['warm_probes'].append(dict(owner=owner,port=port,host=target,lane=lane,nonce=nonce))
      if lane%2==owner:ports[owner]=port;break
      c.close();del clients[owner]
     else:raise RuntimeError('local lane/owner warm coverage unavailable')
    cli('warm','show product flows');drain('warm-drain')
    assert 'policy.hold=armed' in save(run/'hold-arm.txt',publisher.call('product policy hold-next 0 250000','policy.hold=armed'))
    case['hold_nonces']['old']=send(0,'held')
    deadline=time.monotonic()+4
    while 's209 event=hold_begin' not in (run/'vpp.log').read_text():
     assert time.monotonic()<deadline,'held wire packet did not reach owner';time.sleep(.001)
    publish(base_revision+1,202,20000)
    case['hold_nonces']['new']=send(1,'during-hold')
    publish(base_revision+1,203,21000)
    assert read_one(0)==case['hold_nonces']['old'];assert read_one(1)==case['hold_nonces']['new']
    drain('held-drain');cli('after-hold','show product flows')
    receive_targets={o:len(case['received'][o])+40 for o in (0,1)}
    def receiver(owner):
     pending=b''
     try:
      while len(case['received'][owner])<receive_targets[owner]:
       data=clients[owner].recv(4096)
       if not data:raise RuntimeError('client EOF')
       pending+=data
       while b'\n' in pending:
        line,pending=pending.split(b'\n',1);case['received'][owner].append(line.decode())
     except Exception as e:errors.append(repr(e))
    def sender(owner):
     try:
      for n in range(40):send(owner,'steady-'+str(n));time.sleep(.12)
     except Exception as e:errors.append(repr(e))
    receivers=[threading.Thread(target=receiver,args=(o,)) for o in (0,1)];senders=[threading.Thread(target=sender,args=(o,)) for o in (0,1)]
    case['steady_started_ns']=time.monotonic_ns()
    for t in receivers+senders:t.start()
    for n in range(24):publish(base_revision+2+n,(n+3)*100+1,(n+3)*10000);time.sleep(.16)
    for t in senders+receivers:t.join(10);assert not t.is_alive(),'traffic thread stalled'
    case['steady_completed_ns']=time.monotonic_ns()
    assert not errors,errors
    assert all(case['received'][o]==case['nonces'][o] for o in (0,1))
    for c in clients.values():c.close()
    clients.clear();time.sleep(.1);done.set()
    for t in threads:t.join(2);assert not t.is_alive()
    for server in servers:server.close()
    servers.clear();server=None
    assert not errors,errors
    assert sorted(endpoint)==sorted(case['nonces'][0]+case['nonces'][1])
    save(run/'endpoint.json',json.dumps(endpoint))
    for tool in ('iptables','ip6tables'):command(tool,'-t','mangle','-F')
    save(run/'quiesced-hooks.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    drain('quiesce-drain');time.sleep(.2)
    cli('runtime','show product root lanes','show product completion','show product primary','show product flows','show runtime','show threads','show node product-packet-policy','show node product-packet-origin-completion','show node product-packet-owner-guard')
    save(run/'case.json',json.dumps(case,indent=2));result['cases'].append(case)
   finally:
    if publisher is not None:publisher.close()
    done.set()
    for c in clients.values():c.close()
    for t in threads:t.join(2)
    for server in servers:server.close()
    if hooks:
     for tool in ('iptables','ip6tables'):command(tool,'-t','mangle','-F')
    try:
     if process.poll() is None and (runtime/'cli.sock').exists():
      drain('stop-drain');save(run/'fds-before.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
      assert 'root.stop=ok' in cli('close','product root stop')
      cli('closed','show product root lanes','show product completion','show product primary','show product flows')
      free={q:queue_bind(q) for q in range(176,180)};save(run/'queues-free.json',json.dumps(free));assert all(v==0 for v in free.values())
      save(run/'fds-closed.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
    finally:
     if process.poll() is None:
      process.terminate()
      try:process.wait(timeout=10)
      except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
     log.close()
    assert not Path(f'/proc/{process.pid}').exists()
    save(run/'stop.json',json.dumps(dict(pid=process.pid,process_absent=True)));save(run/'hooks-after.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
   result['generations'].append(generation);print('completed',generation,family,protocol,flush=True)
 result['status']='RAW_COMPLETE'
except Exception as e:result['error']=repr(e);raise
finally:
 result['completed_ns']=time.time_ns();save(args.output/'result.json',json.dumps(result,indent=2)+'\n')
