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

result = dict(status='HOLD', started_ns=time.time_ns(), cases=[], generations=[])
save(args.output/'kernel.txt', command('uname', '-a')+command('id')+
     'netns='+os.readlink('/proc/self/ns/net')+'\n')
assert os.getuid() == 0
uid_map = Path('/proc/self/uid_map').read_text().split()
assert len(uid_map) == 3 and uid_map[0] == '0' and uid_map[1] != '0' and uid_map[2] == '1', 'run in a rootless user/network namespace'
save(args.output/'uid-map.txt', ' '.join(uid_map)+'\n')
assert 'product.host.evidence=OFF' in (args.artifact/'product-vpp-artifact.properties').read_text()
result['artifact_manifest_sha256'] = hashlib.sha256((args.artifact/'product-vpp-artifact.properties').read_bytes()).hexdigest()
command('ip', 'link', 'set', 'lo', 'up')
for i in range(1, 9):
    command('ip', '-6', 'addr', 'add', f'fd20:6208::{i}/128', 'dev', 'lo', 'nodad')

try:
 for family in (4,6):
  for mode in ('degenerate','misroute'):
   index=len(result['generations']);generation=20890+index
   run=args.output/f'g{index}';run.mkdir()
   runtime=ROOT/f'build-output/product-vpp-runtime-x208-{args.output.name[-1]}-{index}'
   launch=dict(env,PRODUCT_ARTIFACT_DIR=str(args.artifact),PRODUCT_RUNTIME_DIR=str(runtime),PRODUCT_GENERATION=str(generation),PRODUCT_WORKER_COUNT='2',SAKAMOTO_RUNTIME_PROFILE='root',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID='0',SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES='4')
   log=(run/'vpp.log').open('w');process=subprocess.Popen(['bash',str(ROOT/'tools/product/run-host-vpp.sh')],env=launch,stdout=log,stderr=subprocess.STDOUT)
   def cli(label,*commands):return save(run/(label+'.txt'),''.join(command(args.vppctl,'-s',runtime/'cli.sock',c) for c in commands))
   def drain(label):
    for _ in range(150):
     d=rows(cli(label,'show product completion'),'completion.status ')[0]
     if all(d[k]=='0' for k in ('pending','frames','buffers','obligations')):return
     time.sleep(.02)
    raise RuntimeError('drain timeout '+str(d))
   def policy(revision,blocked):save(run/f'policy-{revision}.txt',command(args.policy_client,runtime/'api.sock',generation,run/'policy',revision,int(blocked)))
   client=None;server=None;thread=None;stop_server=threading.Event();received=[];case=dict(family=family,mode=mode,generation=generation,nonces=[])
   try:
    for _ in range(100):
     if (runtime/'cli.sock').exists():break
     if process.poll() is not None:raise RuntimeError((run/'vpp.log').read_text())
     time.sleep(.05)
    initial=cli('initial','show product root lanes','show threads')
    assert len(rows(initial,'root.lane '))==4
    for tool,span in (('iptables','176:177'),('ip6tables','178:179')):
     for hook in ('INPUT','OUTPUT'):
      extra=['-m','owner','--uid-owner','0'] if hook=='OUTPUT' else []
      command(tool,'-t','mangle','-A',hook,'-p','udp',*extra,'-j','NFQUEUE','--queue-balance',span)
    save(run/'hooks.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
    af=socket.AF_INET if family==4 else socket.AF_INET6;local='127.0.0.1' if family==4 else '::1'
    if mode=='degenerate':
     policy(1,False);port=40610
     client=socket.socket(af,socket.SOCK_DGRAM);client.settimeout(3);client.bind((local,port));client.connect((local,port))
     for revision in (1,2):
      if revision==2:policy(2,False)
      nonce=f's208-extra-{generation}-{revision}-{time.time_ns()}';case['nonces'].append(nonce)
      client.send(nonce.encode());response=client.recv(4096);assert response==nonce.encode()
      save(run/f'echo-{revision}.txt',response.decode());drain('drain')
      cli(f'r{revision}-flows','show product flows')
     case.update(host=local,source_port=port)
    else:
     host='127.0.0.2' if family==4 else 'fd20:6208::2'
     server=socket.socket(af,socket.SOCK_DGRAM);server.bind((host,40611));server.settimeout(.1)
     def echo():
      while not stop_server.is_set():
       try:data,peer=server.recvfrom(4096);received.append(data.hex());server.sendto(data,peer)
       except TimeoutError:continue
     thread=threading.Thread(target=echo);thread.start();policy(1,True)
     for attempt in range(32):
      port=35000+attempt;client=socket.socket(af,socket.SOCK_DGRAM);client.settimeout(.2);client.bind((local,port));client.connect((host,40611))
      nonce=f's208-extra-{generation}-scan-{attempt}-{time.time_ns()}';client.send(nonce.encode())
      try:client.recv(4096);raise RuntimeError('DROP delivered')
      except TimeoutError:pass
      drain('scan-drain');trace=(run/'vpp.log').read_text()
      fact=next(d for d in rows(trace,'s216 ') if d.get('stage')=='admit' and nonce.encode().hex() in d['raw'])
      if int(fact['origin_lane'])%2!=int(fact['owner']):break
      client.close();client=None
     assert client is not None
     case.update(host=host,source_port=port,lane=int(fact['origin_lane']),owner=int(fact['owner']))
     assert all(d['entries']=='0' for d in rows(cli('before-fault-flows','show product flows'),'flow.pool '))
     policy(2,False);assert 'primary.misroute_next=armed' in cli('arm','product primary misroute-next')
     nonce=f's208-extra-{generation}-fault-{time.time_ns()}';case['fault_nonce']=nonce;client.send(nonce.encode())
     try:client.recv(4096);raise RuntimeError('misrouted packet delivered')
     except TimeoutError:pass
     drain('fault-drain');assert all(d['entries']=='0' for d in rows(cli('fault-flows','show product flows'),'flow.pool '))
     nonce=f's208-extra-{generation}-recover-{time.time_ns()}';case['nonces'].append(nonce);client.settimeout(3);client.send(nonce.encode());response=client.recv(4096);assert response==nonce.encode();save(run/'echo.txt',response.decode());drain('recover-drain')
    client.close();client=None;stop_server.set()
    if thread is not None:thread.join(2);assert not thread.is_alive()
    if server is not None:server.close();server=None
    save(run/'endpoint.json',json.dumps(received));save(run/'case.json',json.dumps(case,indent=2));result['cases'].append(case)
    cli('runtime','show product root lanes','show product completion','show product primary','show product flows','show runtime','show threads','show node product-packet-policy','show node product-packet-origin-completion','show node product-packet-owner-guard')
   finally:
    if client is not None:client.close()
    stop_server.set()
    if thread is not None:thread.join(2)
    if server is not None:server.close()
    try:
     for tool in ('iptables','ip6tables'):command(tool,'-t','mangle','-F')
     if process.poll() is None and (runtime/'cli.sock').exists():
      drain('stop-drain');save(run/'fds-before.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
      assert 'root.stop=ok' in cli('close','product root stop')
      cli('closed','show product root lanes','show product completion','show product primary','show product flows')
      save(run/'queues-free.json',json.dumps({q:queue_bind(q) for q in range(176,180)}))
      save(run/'fds-closed.txt','\n'.join(f'{p.name} {os.readlink(p)}' for p in Path(f'/proc/{process.pid}/fd').iterdir()))
    finally:
     if process.poll() is None:
      process.terminate()
      try:process.wait(timeout=10)
      except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
     log.close()
    save(run/'stop.json',json.dumps(dict(pid=process.pid,process_absent=not Path(f'/proc/{process.pid}').exists())))
    save(run/'hooks-after.txt',command('iptables-save','-t','mangle')+command('ip6tables-save','-t','mangle'))
   result['generations'].append(generation);print(family,mode,generation,flush=True)
 result['status']='RAW_COMPLETE'
finally:
 result['completed_ns']=time.time_ns();save(args.output/'result.json',json.dumps(result,indent=2)+'\n')
